mod config;
mod ssh;

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};

use futures_util::{SinkExt, StreamExt};
use reqwest_websocket::Message;
use ssh_key::{Algorithm, HashAlg, PublicKey};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use self::config::{AgentConfig, RunLock, validate_max_sessions};
use self::ssh::OperatorAllowlist;
use crate::config::Paths;
use crate::identity::ensure_agent;

use crate::error::RevttyError;
use crate::pairing::PairingCode;
use crate::protocol::{
    AgentRotateRequest, CONTROL_PROTOCOL_VERSION, ControlMessage, EnrollRequest, EnrollResponse,
    ProbeResult, SESSION_ERROR_PREFIX, SessionRejectReason,
};
use crate::token::SecretToken;
use crate::transport::{
    check_relay_health, connect_websocket, http_url, relay_client, valid_name, websocket_error,
};

const RECONNECT_BASE_MILLIS: u64 = 1_000;
const RECONNECT_CAP_MILLIS: u64 = 30_000;
const RECONNECT_JITTER_PERCENT: u64 = 20;
/// Bound on waiting for shell teardowns at shutdown; below the 15 s after which the shipped
/// service definitions kill the agent (systemd's `TimeoutStopSec`, launchd's `ExitTimeOut`).
const SHELL_SHUTDOWN_WAIT: Duration = Duration::from_secs(10);
/// Writing one frame to the relay; a write that cannot complete means the path is dead.
const CONTROL_SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// One HTTP request of a credential rotation; a relay that does not answer leaves the
/// rotation to be finished on a later attempt.
const ROTATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the running agent rereads its operator list: a revoked operator's sessions are
/// closed, and new ones refused, within this time.
const OPERATORS_RELOAD_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
struct ControlTimeouts {
    heartbeat: Duration,
    /// No frame at all from the relay for this long means the path is dead. The relay
    /// answers the WebSocket ping sent with every heartbeat.
    relay_idle: Duration,
}

const CONTROL_TIMEOUTS: ControlTimeouts = ControlTimeouts {
    heartbeat: Duration::from_secs(15),
    relay_idle: Duration::from_secs(45),
};

type SessionTasks = Arc<Mutex<HashMap<String, SessionTask>>>;

/// A session's task, which holds its slot, and the way to cancel it (`cancel_session`).
struct SessionTask {
    task: JoinHandle<()>,
    cancel: oneshot::Sender<()>,
}

/// Asks the task of `session_id` to end its session, returning whether it was tracked. The
/// task gives its slot back once the SSH session is over; aborting the task instead would give
/// it back while russh, in a task of its own, kept running the session.
async fn cancel_session(session_tasks: &SessionTasks, session_id: &str) -> bool {
    let Some(session) = session_tasks.lock().await.remove(session_id) else {
        return false;
    };
    let _ = session.cancel.send(());
    true
}

#[derive(Debug, Default)]
struct ReconnectBackoff {
    failures: u32,
}

impl ReconnectBackoff {
    fn reset(&mut self) {
        self.failures = 0;
    }

    fn next_delay(&mut self) -> Duration {
        let failures = self.failures;
        self.failures = self.failures.saturating_add(1);

        Duration::from_millis(reconnect_delay_millis(failures, jitter_sample(failures)))
    }
}

fn reconnect_base_millis(failures: u32) -> u64 {
    let multiplier = 1_u64 << failures.min(31);
    RECONNECT_BASE_MILLIS
        .saturating_mul(multiplier)
        .min(RECONNECT_CAP_MILLIS)
}

fn reconnect_delay_millis(failures: u32, sample: u64) -> u64 {
    let base = reconnect_base_millis(failures);
    let spread = base.saturating_mul(RECONNECT_JITTER_PERCENT) / 100;
    let floor = base.saturating_sub(spread);

    floor + sample % (spread + 1)
}

fn jitter_sample(failures: u32) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut value = (now as u64)
        ^ ((now >> 64) as u64)
        ^ (u64::from(std::process::id()) << 32)
        ^ u64::from(failures);

    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value
}

/// Enrolls with a plain enrollment `token`, or with a `pairing_code` from `revtty pair`.
pub async fn enroll(
    relay: &str,
    token: Option<&str>,
    pairing_code: Option<&str>,
    max_sessions: usize,
) -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    enroll_with(
        &relay_client()?,
        &paths,
        relay,
        token,
        pairing_code,
        max_sessions,
    )
    .await
}

async fn enroll_with(
    client: &reqwest::Client,
    paths: &Paths,
    relay: &str,
    token: Option<&str>,
    pairing_code: Option<&str>,
    max_sessions: usize,
) -> Result<(), RevttyError> {
    validate_max_sessions(max_sessions)?;
    // Settled before anything is sent: only the token inside a pairing code goes to the
    // relay, never its secret.
    let pairing = match (token, pairing_code) {
        (Some(token), None) => {
            if token.contains('.') {
                return Err(RevttyError::message(
                    "--token was given a pairing code; pass it with --pairing-code, which keeps \
                     its secret from the relay",
                ));
            }
            None
        }
        (None, Some(code)) => Some(PairingCode::parse(code)?),
        _ => {
            return Err(RevttyError::message(
                "pass either --token or --pairing-code",
            ));
        }
    };
    let token = match &pairing {
        Some(code) => code.token(),
        None => token.unwrap_or_default(),
    };

    let identity = ensure_agent(paths)?;
    let host_key_proof = pairing
        .as_ref()
        .map(|code| code.secret().host_key_proof(&identity.fingerprint))
        .transpose()?;
    let url = http_url(relay, "/v1/enroll")?;
    let request = EnrollRequest {
        token: token.to_owned(),
        host_key: identity.public_key.clone(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        host_key_proof,
    };

    let response = client
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|error| {
            RevttyError::runtime(
                "send enrollment request",
                crate::error::with_sources(&error),
            )
        })?;

    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        return Err(RevttyError::message(format!(
            "enrollment rejected ({status}){}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }

    let enrolled: EnrollResponse = response
        .json()
        .await
        .map_err(|error| RevttyError::runtime("decode enrollment response", error))?;

    if !valid_name(&enrolled.name) {
        return Err(RevttyError::message(
            "relay returned an invalid enrolled agent name",
        ));
    }

    let operator_key = PublicKey::from_openssh(&enrolled.operator_key)
        .map_err(|error| RevttyError::runtime("parse enrolled operator key", error))?;
    if operator_key.algorithm() != Algorithm::Ed25519 {
        return Err(RevttyError::message("v1 requires an Ed25519 operator key"));
    }
    // The agent will accept shells from this key: with a pairing code it must be the key the
    // code was made for, whatever the relay says.
    let operator_fingerprint = operator_key.fingerprint(HashAlg::Sha256).to_string();
    let operator_source = match &pairing {
        Some(code) => {
            if !code.vouches_for(&enrolled.name, &operator_fingerprint)? {
                return Err(RevttyError::message(
                    "the relay enrolled this machine for an operator or a name the pairing code \
                     was not made for; nothing was saved. The relay has used up the enrollment: \
                     investigate it, then enroll this machine again with a new `revtty relay \
                     enroll --replace` and `revtty pair`",
                ));
            }
            "verified by pairing code"
        }
        None => "as reported by the relay, not verified",
    };

    AgentConfig::new(
        relay.trim_end_matches('/').to_owned(),
        enrolled.agent_id,
        enrolled.name.clone(),
        enrolled.control_token,
        enrolled.operator_key,
        max_sessions,
    )
    .save(paths)?;

    println!("agent      {}", enrolled.name);
    println!("host       {}", identity.fingerprint);
    println!("operator   {operator_fingerprint} ({operator_source})");
    println!(
        "identity   {}",
        if identity.created {
            "created"
        } else {
            "existing"
        }
    );
    println!("sessions   {max_sessions}");
    println!("config     {}", AgentConfig::path(paths).display());
    Ok(())
}

pub async fn run() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let Some(_running) = RunLock::try_acquire(&paths)? else {
        return Err(RevttyError::message(
            "another `revtty agent run` is using this configuration",
        ));
    };
    let mut config = AgentConfig::load(&paths)?;

    if !valid_name(&config.name) {
        return Err(RevttyError::message(
            "stored agent name is invalid; re-enroll this agent",
        ));
    }
    // A relay URL this version refuses, such as plain HTTP to another host enrolled by an
    // earlier one, fails on every retry: stop instead of reconnecting forever.
    http_url(&config.relay, "/").map_err(|error| {
        RevttyError::message(format!(
            "relay in {}: {error}",
            AgentConfig::path(&paths).display()
        ))
    })?;

    let allowlist = watch_operators(
        paths.clone(),
        OperatorAllowlist::parse(config.operators_revision, &config.operators)?,
    );
    let client = relay_client()?;
    let mut backoff = ReconnectBackoff::default();
    let session_slots = Arc::new(Semaphore::new(config.max_sessions));
    let session_tasks: SessionTasks = Arc::new(Mutex::new(HashMap::new()));
    let (shutdown_signal, _) = watch::channel(false);
    let (shell_guard, mut shell_guards) = mpsc::channel::<()>(1);
    let shell_shutdown = ssh::ShellShutdown::new(shutdown_signal.subscribe(), &shell_guard);
    // Service managers stop with SIGTERM (launchd always, systemd unless told otherwise); it
    // takes the same path as Ctrl-C instead of killing the agent with its shells running.
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|error| RevttyError::runtime("listen for SIGTERM", error))?;

    let stopped = loop {
        let control = async {
            // Until an interrupted rotation is finished, it is not known which credential
            // the relay accepts.
            if config.pending_control_token.is_some() {
                finish_pending_rotation(&client, &paths)
                    .await
                    .map_err(|error| {
                        RevttyError::message(format!(
                            "finishing an interrupted credential rotation: {error}"
                        ))
                    })?;
                config = AgentConfig::load(&paths)?;
            }

            run_control_once(
                &client,
                &config,
                &allowlist,
                &mut backoff,
                &session_slots,
                &session_tasks,
                &shell_shutdown,
                CONTROL_TIMEOUTS,
            )
            .await
        };

        tokio::select! {
            result = control => {
                if let Err(error) = result {
                    tracing::warn!("control connection lost: {error}");
                }
            }
            signal = tokio::signal::ctrl_c() => break signal,
            _ = terminate.recv() => break Ok(()),
        }

        let delay = backoff.next_delay();
        tracing::info!("reconnecting in {:.1}s", delay.as_secs_f64());

        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            signal = tokio::signal::ctrl_c() => break signal,
            _ = terminate.recv() => break Ok(()),
        }
    };

    // Stop every shell and wait for the teardowns before returning lets the runtime shut
    // down: supervisors still running at that point would be dropped mid-teardown.
    shutdown_signal.send_replace(true);
    drop(shell_guard);
    if tokio::time::timeout(SHELL_SHUTDOWN_WAIT, shell_guards.recv())
        .await
        .is_err()
    {
        tracing::warn!(
            "shell teardown did not finish within {}s",
            SHELL_SHUTDOWN_WAIT.as_secs()
        );
    }

    stopped.map_err(|error| RevttyError::runtime("wait for a stop signal", error))
}

/// Rereads the operator list from `agent.toml` on its own schedule, independent of the relay
/// connection and its backoff, and publishes every change.
fn watch_operators(paths: Paths, initial: OperatorAllowlist) -> watch::Receiver<OperatorAllowlist> {
    let (publisher, allowlist) = watch::channel(initial);

    tokio::spawn(async move {
        let mut reload = tokio::time::interval(OPERATORS_RELOAD_INTERVAL);
        reload.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut unreadable = false;

        loop {
            reload.tick().await;
            let loaded = AgentConfig::load(&paths).and_then(|config| {
                OperatorAllowlist::parse(config.operators_revision, &config.operators)
            });

            match loaded {
                Ok(next) => {
                    unreadable = false;
                    let (revision, count) = (next.revision, next.operators.len());
                    let published = publisher.send_if_modified(|current| {
                        let changed = current.revision != next.revision
                            || current.operators != next.operators;
                        if changed {
                            *current = next;
                        }
                        changed
                    });
                    if published {
                        tracing::info!("operator list revision {revision}: {count} operators");
                    }
                }
                // The last valid list stays in force: replacing it with nothing would close
                // every session, including the one an operator would use to repair the file.
                Err(error) if !unreadable => {
                    unreadable = true;
                    tracing::warn!(
                        "cannot reload the operator list from agent.toml; keeping the previous one: {error}"
                    );
                }
                Err(_) => {}
            }
        }
    });

    allowlist
}

#[allow(clippy::too_many_arguments)]
async fn run_control_once(
    client: &reqwest::Client,
    config: &AgentConfig,
    allowlist: &watch::Receiver<OperatorAllowlist>,
    backoff: &mut ReconnectBackoff,
    session_slots: &Arc<Semaphore>,
    session_tasks: &SessionTasks,
    shell_shutdown: &ssh::ShellShutdown,
    timeouts: ControlTimeouts,
) -> Result<(), RevttyError> {
    let relay = config.relay.as_str();
    let name = config.name.as_str();
    let token = config.control_token.as_str();
    let max_sessions = config.max_sessions;
    let mut operator_changes = allowlist.clone();
    let path = format!("/v1/agent/{name}");
    let websocket = connect_websocket(client, relay, &path, token).await?;
    let (mut sender, mut receiver) = websocket.split();

    send_control(
        &mut sender,
        ControlMessage::Hello {
            version: CONTROL_PROTOCOL_VERSION,
            name: name.to_owned(),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            active_sessions: max_sessions.saturating_sub(session_slots.available_permits()),
            max_sessions,
        },
    )
    .await?;
    send_operators_report(&mut sender, &mut operator_changes).await?;

    tracing::info!("agent {name} connected to {relay}");

    let mut heartbeat = tokio::time::interval(timeouts.heartbeat);
    heartbeat.tick().await;
    let idle = tokio::time::sleep(timeouts.relay_idle);
    tokio::pin!(idle);
    let mut watching_operators = true;

    loop {
        tokio::select! {
            changed = operator_changes.changed(), if watching_operators => {
                if changed.is_ok() {
                    send_operators_report(&mut sender, &mut operator_changes).await?;
                } else {
                    watching_operators = false;
                }
            }
            _ = heartbeat.tick() => {
                session_tasks
                    .lock()
                    .await
                    .retain(|_, session| !session.task.is_finished());

                send_control(
                    &mut sender,
                    ControlMessage::Heartbeat {
                        version: CONTROL_PROTOCOL_VERSION,
                        active_sessions: max_sessions
                            .saturating_sub(session_slots.available_permits()),
                    },
                )
                .await?;
                // The relay's pong proves the path back is alive even when it has nothing
                // to send.
                send_frame(&mut sender, Message::Ping(Default::default()), "send control ping")
                    .await?;
            }
            () = &mut idle => {
                return Err(RevttyError::message(format!(
                    "relay sent nothing for {}s",
                    timeouts.relay_idle.as_secs()
                )));
            }
            message = receiver.next() => {
                idle.as_mut()
                    .reset(tokio::time::Instant::now() + timeouts.relay_idle);

                match message {
                    Some(Ok(Message::Text(text))) => {
                        if let Some(detail) = text.strip_prefix(SESSION_ERROR_PREFIX) {
                            return Err(RevttyError::message(format!(
                                "relay rejected the control connection: {detail}"
                            )));
                        }

                        // A newer relay may send messages this agent does not know; dropping
                        // the connection for them would only loop through reconnects.
                        let control: ControlMessage = match serde_json::from_str(&text) {
                            Ok(control) => control,
                            Err(error) => {
                                tracing::warn!(
                                    "ignoring unrecognized control message ({})",
                                    describe_undecodable(&error)
                                );
                                continue;
                            }
                        };

                        match control {
                            ControlMessage::ProbeOffer {
                                version,
                                session_id,
                                tunnel_token,
                            } => {
                                if version != CONTROL_PROTOCOL_VERSION {
                                    reject_incompatible_offer(&mut sender, session_id).await?;
                                    continue;
                                }

                                let Some(permit) =
                                    reserve_session(&mut sender, session_slots, &session_id).await?
                                else {
                                    continue;
                                };

                                let client = client.clone();
                                let relay = relay.to_owned();
                                let name = name.to_owned();
                                let allowlist = allowlist.clone();
                                let task_session_id = session_id.clone();
                                let shell_shutdown = shell_shutdown.clone();
                                let (cancel, cancelled) = oneshot::channel();

                                // Over SSH, as a shell: the agent checks the operator against
                                // its own list and proves its host key.
                                let task = tokio::spawn(async move {
                                    let _permit = permit;
                                    let probed = match probe_answer(&name) {
                                        Ok(answer) => {
                                            ssh::serve(
                                                &client,
                                                &relay,
                                                &tunnel_token,
                                                &task_session_id,
                                                allowlist,
                                                shell_shutdown,
                                                ssh::SessionKind::Probe(answer),
                                                cancelled,
                                            )
                                            .await
                                        }
                                        Err(error) => Err(error),
                                    };
                                    if let Err(error) = probed {
                                        tracing::warn!("probe {task_session_id} failed: {error}");
                                    }
                                });

                                session_tasks
                                    .lock()
                                    .await
                                    .insert(session_id, SessionTask { task, cancel });
                            }
                            offer @ (ControlMessage::ShellOffer { .. }
                            | ControlMessage::ExecOffer { .. }) => {
                                // The two differ only in what their SSH session runs.
                                let (kind, label) =
                                    if matches!(offer, ControlMessage::ExecOffer { .. }) {
                                        (ssh::SessionKind::Exec, "exec")
                                    } else {
                                        (ssh::SessionKind::Shell, "shell")
                                    };
                                let (ControlMessage::ShellOffer {
                                    version,
                                    session_id,
                                    tunnel_token,
                                }
                                | ControlMessage::ExecOffer {
                                    version,
                                    session_id,
                                    tunnel_token,
                                }) = offer
                                else {
                                    continue;
                                };
                                if version != CONTROL_PROTOCOL_VERSION {
                                    reject_incompatible_offer(&mut sender, session_id).await?;
                                    continue;
                                }

                                let Some(permit) =
                                    reserve_session(&mut sender, session_slots, &session_id).await?
                                else {
                                    continue;
                                };

                                let client = client.clone();
                                let relay = relay.to_owned();
                                let allowlist = allowlist.clone();
                                let task_session_id = session_id.clone();
                                let shell_shutdown = shell_shutdown.clone();
                                let (cancel, cancelled) = oneshot::channel();

                                let task = tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Err(error) = ssh::serve(
                                        &client,
                                        &relay,
                                        &tunnel_token,
                                        &task_session_id,
                                        allowlist,
                                        shell_shutdown,
                                        kind,
                                        cancelled,
                                    )
                                    .await
                                    {
                                        tracing::warn!("{label} {task_session_id} failed: {error}");
                                    }
                                });

                                session_tasks
                                    .lock()
                                    .await
                                    .insert(session_id, SessionTask { task, cancel });
                            }
                            ControlMessage::SessionCancel {
                                version,
                                session_id,
                            } if version == CONTROL_PROTOCOL_VERSION => {
                                let tracked = cancel_session(session_tasks, &session_id).await;
                                if tracked {
                                    tracing::info!("session cancelled by relay: {session_id}");
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        send_frame(&mut sender, Message::Pong(data), "send control pong").await?;
                    }
                    // The answer to a heartbeat ping: the relay accepted the hello and the
                    // operator list, kept the connection for a heartbeat and the path works
                    // both ways. Only now has reconnecting worked; a relay that accepts the
                    // upgrade and then closes keeps the backoff growing.
                    Some(Ok(Message::Pong(_))) => backoff.reset(),
                    Some(Ok(Message::Close { .. })) | None => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        return Err(RevttyError::runtime(
                            "receive control message",
                            websocket_error(error),
                        ));
                    }
                }
            }
        }
    }
}

/// Where a control message failed to decode, without any of its content: serde's own
/// message quotes received values, which may include tunnel tokens.
fn describe_undecodable(error: &serde_json::Error) -> String {
    format!(
        "{:?} error at line {}, column {}",
        error.classify(),
        error.line(),
        error.column()
    )
}

async fn reserve_session(
    sender: &mut futures_util::stream::SplitSink<
        reqwest_websocket::WebSocket,
        reqwest_websocket::Message,
    >,
    session_slots: &Arc<Semaphore>,
    session_id: &str,
) -> Result<Option<OwnedSemaphorePermit>, RevttyError> {
    match session_slots.clone().try_acquire_owned() {
        Ok(permit) => {
            send_control(
                sender,
                ControlMessage::SessionAccept {
                    version: CONTROL_PROTOCOL_VERSION,
                    session_id: session_id.to_owned(),
                },
            )
            .await?;
            Ok(Some(permit))
        }
        Err(_) => {
            send_control(
                sender,
                ControlMessage::SessionReject {
                    version: CONTROL_PROTOCOL_VERSION,
                    session_id: session_id.to_owned(),
                    reason: SessionRejectReason::Busy,
                },
            )
            .await?;
            Ok(None)
        }
    }
}

async fn reject_incompatible_offer(
    sender: &mut futures_util::stream::SplitSink<
        reqwest_websocket::WebSocket,
        reqwest_websocket::Message,
    >,
    session_id: String,
) -> Result<(), RevttyError> {
    send_control(
        sender,
        ControlMessage::SessionReject {
            version: CONTROL_PROTOCOL_VERSION,
            session_id,
            reason: SessionRejectReason::IncompatibleVersion,
        },
    )
    .await
}

/// Tells the relay which operators this agent accepts, as of the latest published list.
async fn send_operators_report(
    sender: &mut futures_util::stream::SplitSink<
        reqwest_websocket::WebSocket,
        reqwest_websocket::Message,
    >,
    allowlist: &mut watch::Receiver<OperatorAllowlist>,
) -> Result<(), RevttyError> {
    let (revision, operators) = {
        let current = allowlist.borrow_and_update();
        (current.revision, current.operators.clone())
    };

    send_control(
        sender,
        ControlMessage::OperatorsReport {
            version: CONTROL_PROTOCOL_VERSION,
            revision,
            operators,
        },
    )
    .await
}

async fn send_control(
    sender: &mut futures_util::stream::SplitSink<
        reqwest_websocket::WebSocket,
        reqwest_websocket::Message,
    >,
    message: ControlMessage,
) -> Result<(), RevttyError> {
    let text = serde_json::to_string(&message)
        .map_err(|error| RevttyError::runtime("encode control message", error))?;

    send_frame(sender, Message::Text(text), "send control message").await
}

async fn send_frame(
    sender: &mut futures_util::stream::SplitSink<
        reqwest_websocket::WebSocket,
        reqwest_websocket::Message,
    >,
    frame: Message,
    context: &str,
) -> Result<(), RevttyError> {
    match tokio::time::timeout(CONTROL_SEND_TIMEOUT, sender.send(frame)).await {
        Ok(sent) => sent.map_err(|error| RevttyError::runtime(context, websocket_error(error))),
        Err(_) => Err(RevttyError::message(format!(
            "{context}: no progress for {}s",
            CONTROL_SEND_TIMEOUT.as_secs()
        ))),
    }
}

/// What a probe session answers to `PROBE_COMMAND`.
fn probe_answer(name: &str) -> Result<String, RevttyError> {
    let result = ProbeResult {
        name: name.to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };

    serde_json::to_string(&result)
        .map_err(|error| RevttyError::runtime("encode probe result", error))
}

pub fn pty_test() -> Result<(), RevttyError> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| RevttyError::runtime("open local PTY", error))?;

    let mut command = CommandBuilder::new("/bin/echo");
    command.arg("revtty-pty-ok");

    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| RevttyError::runtime("spawn PTY smoke command", error))?;
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| RevttyError::runtime("clone PTY reader", error))?;

    let reader_thread = std::thread::spawn(move || -> std::io::Result<String> {
        let mut output = String::new();
        reader.read_to_string(&mut output)?;
        Ok(output)
    });

    let writer = pair
        .master
        .take_writer()
        .map_err(|error| RevttyError::runtime("take PTY writer", error))?;

    if cfg!(target_os = "macos") {
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(writer);

    let status = child
        .wait()
        .map_err(|error| RevttyError::runtime("wait for PTY smoke command", error))?;
    drop(pair.master);

    let output = reader_thread
        .join()
        .map_err(|_| RevttyError::message("PTY reader thread panicked"))?
        .map_err(|error| RevttyError::runtime("read PTY output", error))?;

    if !status.success() || !output.contains("revtty-pty-ok") {
        return Err(RevttyError::message("local PTY smoke test failed"));
    }

    println!("pty      ok");
    println!("os       {}", std::env::consts::OS);
    println!("arch     {}", std::env::consts::ARCH);
    Ok(())
}

pub fn status() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let config = AgentConfig::load(&paths)?;
    let identity = ensure_agent(&paths)?;

    println!("agent      {}", config.name);
    // A URL `agent run` refuses is not shown: it may hold a password.
    match http_url(&config.relay, "/") {
        Ok(_) => println!("relay      {}", config.relay),
        Err(error) => println!("relay      refused: {error}"),
    }
    println!("id         {}", config.agent_id);
    println!("host       {}", identity.fingerprint);
    println!("sessions   {}", config.max_sessions);
    println!("config     {}", AgentConfig::path(&paths).display());
    Ok(())
}

pub async fn rotate_credential() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    match rotate_control_credential(&relay_client()?, &paths).await? {
        Rotation::Rotated => {
            println!("credential rotated; the relay no longer accepts the previous one");
            Ok(())
        }
        Rotation::Unsupported => Err(RevttyError::message(
            "the relay does not support credential rotation; the credential is unchanged",
        )),
    }
}

enum Rotation {
    Rotated,
    Unsupported,
}

/// What became of a rotation an earlier run left unfinished.
enum PendingRotation {
    None,
    Completed,
    Abandoned { unsupported: bool },
}

/// How the relay answered a request authenticated with one agent credential.
enum CredentialAnswer {
    Accepted,
    Rejected,
    /// A relay that predates the endpoint.
    Unsupported,
}

/// Replaces the agent's control credential with a new one it generates itself, so the relay
/// only ever learns the hash of a credential the agent has already saved.
async fn rotate_control_credential(
    client: &reqwest::Client,
    paths: &Paths,
) -> Result<Rotation, RevttyError> {
    let Some(_stopped) = RunLock::try_acquire(paths)? else {
        let stop = if cfg!(target_os = "macos") {
            "with launchd: sudo launchctl kill SIGTERM system/io.lambdabytes.revtty-agent.USER"
        } else {
            "with systemd: sudo systemctl stop revtty-agent@USER"
        };
        return Err(RevttyError::message(format!(
            "the agent is running; stop it first ({stop}), rotate, then start it again"
        )));
    };

    // A rotation that stopped halfway is finished, or abandoned, before another starts.
    if let PendingRotation::Abandoned { unsupported: true } =
        finish_pending_rotation(client, paths).await?
    {
        return Ok(Rotation::Unsupported);
    }

    let config = AgentConfig::load(paths)?;
    // Confirming the current credential is a no-op on a relay that supports rotation, and a
    // 404 on one that does not: nothing is written before it is known which.
    match post_with_credential(
        client,
        &config.relay,
        &format!("/v1/agent/{}/rotate/confirm", config.name),
        &config.control_token,
        None,
    )
    .await?
    {
        CredentialAnswer::Accepted => {}
        CredentialAnswer::Unsupported => return Ok(Rotation::Unsupported),
        CredentialAnswer::Rejected => {
            return Err(RevttyError::message(
                "the relay rejected this agent's credential; re-enroll the agent",
            ));
        }
    }

    let next = SecretToken::generate("rva")?;
    // Saved before the relay hears of it: from here on, an interruption leaves it for
    // `finish_pending_rotation`.
    AgentConfig::update(paths, |stored| {
        stored.pending_control_token = Some(next.expose().to_owned());
        Ok(())
    })?;

    let request = AgentRotateRequest {
        next_hash: URL_SAFE_NO_PAD.encode(next.hash()),
    };
    let begun = post_with_credential(
        client,
        &config.relay,
        &format!("/v1/agent/{}/rotate", config.name),
        &config.control_token,
        Some(&request),
    )
    .await
    .map_err(unfinished_rotation)?;

    match begun {
        CredentialAnswer::Accepted => {}
        CredentialAnswer::Unsupported | CredentialAnswer::Rejected => {
            AgentConfig::update(paths, |stored| {
                if stored.pending_control_token.as_deref() == Some(next.expose()) {
                    stored.pending_control_token = None;
                }
                Ok(())
            })?;
            return match begun {
                CredentialAnswer::Unsupported => Ok(Rotation::Unsupported),
                _ => Err(RevttyError::message(
                    "the relay rejected this agent's credential; re-enroll the agent",
                )),
            };
        }
    }

    match finish_pending_rotation(client, paths)
        .await
        .map_err(unfinished_rotation)?
    {
        PendingRotation::Completed => Ok(Rotation::Rotated),
        _ => Err(RevttyError::message(
            "the relay did not take the new credential; the current one still works",
        )),
    }
}

fn unfinished_rotation(error: RevttyError) -> RevttyError {
    RevttyError::message(format!(
        "{error}; the next `revtty agent run` or `revtty agent rotate-credential` finishes the \
         rotation"
    ))
}

/// Finishes or abandons a rotation that stopped before its end. The relay decides: once it
/// confirmed the pending credential (also when only its answer was lost) it accepts that one,
/// and the current one until then.
async fn finish_pending_rotation(
    client: &reqwest::Client,
    paths: &Paths,
) -> Result<PendingRotation, RevttyError> {
    let config = AgentConfig::load(paths)?;
    let Some(pending) = config.pending_control_token.clone() else {
        return Ok(PendingRotation::None);
    };

    let confirmed = post_with_credential(
        client,
        &config.relay,
        &format!("/v1/agent/{}/rotate/confirm", config.name),
        &pending,
        None,
    )
    .await?;
    let outcome = match confirmed {
        CredentialAnswer::Accepted => PendingRotation::Completed,
        CredentialAnswer::Unsupported => PendingRotation::Abandoned { unsupported: true },
        // The relay never took the pending credential, unless this agent was re-enrolled or
        // removed since: then the current one is refused too.
        CredentialAnswer::Rejected => match post_with_credential(
            client,
            &config.relay,
            &format!("/v1/agent/{}/check", config.name),
            &config.control_token,
            None,
        )
        .await?
        {
            CredentialAnswer::Accepted => PendingRotation::Abandoned { unsupported: false },
            _ => {
                return Err(RevttyError::message(
                    "the relay accepts neither this agent's credential nor the one it was \
                     rotating to; re-enroll the agent",
                ));
            }
        },
    };

    AgentConfig::update(paths, |stored| {
        // Only the rotation this answer is about.
        if stored.pending_control_token.as_deref() == Some(pending.as_str()) {
            if matches!(outcome, PendingRotation::Completed) {
                stored.control_token = pending.clone();
            }
            stored.pending_control_token = None;
        }
        Ok(())
    })?;
    Ok(outcome)
}

async fn post_with_credential(
    client: &reqwest::Client,
    relay: &str,
    path: &str,
    token: &str,
    body: Option<&AgentRotateRequest>,
) -> Result<CredentialAnswer, RevttyError> {
    let mut request = client
        .post(http_url(relay, path)?)
        .bearer_auth(token)
        .timeout(ROTATION_REQUEST_TIMEOUT);
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().await.map_err(|error| {
        RevttyError::runtime("reach the relay", crate::error::with_sources(&error))
    })?;

    match response.status() {
        status if status.is_success() => Ok(CredentialAnswer::Accepted),
        reqwest::StatusCode::UNAUTHORIZED => Ok(CredentialAnswer::Rejected),
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED => {
            Ok(CredentialAnswer::Unsupported)
        }
        status => Err(RevttyError::message(format!("the relay answered {status}"))),
    }
}

pub fn operator_list() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let config = AgentConfig::load(&paths)?;

    println!("revision   {}", config.operators_revision);
    for encoded in &config.operators {
        let key = PublicKey::from_openssh(encoded)
            .map_err(|error| RevttyError::runtime("parse operator key", error))?;
        let fingerprint = key.fingerprint(HashAlg::Sha256);
        match key.comment() {
            "" => println!("operator   {fingerprint}"),
            comment => println!("operator   {fingerprint} {comment}"),
        }
    }
    Ok(())
}

pub fn operator_add(key_path: &Path) -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let encoded = if key_path == Path::new("-") {
        std::io::read_to_string(std::io::stdin())
            .map_err(|error| RevttyError::runtime("read operator public key from stdin", error))?
    } else {
        std::fs::read_to_string(key_path)
            .map_err(|error| RevttyError::runtime("read operator public key", error))?
    };
    let (fingerprint, revision) = AgentConfig::update(&paths, |config| {
        let fingerprint = config.add_operator(&encoded)?;
        Ok((fingerprint, config.operators_revision))
    })?;

    println!("added      {fingerprint}");
    println!("revision   {revision}");
    print_reload_note();
    Ok(())
}

pub fn operator_revoke(fingerprint: &str) -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let revision = AgentConfig::update(&paths, |config| {
        config.revoke_operator(fingerprint)?;
        Ok(config.operators_revision)
    })?;

    println!("revoked    {fingerprint}");
    println!("revision   {revision}");
    print_reload_note();
    Ok(())
}

fn print_reload_note() {
    println!(
        "A running agent applies the change within {}s; a revoked operator's open sessions are closed.",
        OPERATORS_RELOAD_INTERVAL.as_secs()
    );
}

pub async fn doctor() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let config = AgentConfig::load(&paths)?;
    let identity = ensure_agent(&paths)?;

    if !valid_name(&config.name) {
        return Err(RevttyError::message("persisted agent name is invalid"));
    }
    if config.agent_id.trim().is_empty() || config.control_token.trim().is_empty() {
        return Err(RevttyError::message(
            "persisted agent configuration is incomplete",
        ));
    }

    // Whoever can change these files can impersonate the agent or take its shells.
    crate::config::check_private_file(&AgentConfig::path(&paths))?;
    crate::config::check_private_file(&identity.private_key_path)?;
    crate::config::check_not_writable_by_others(&paths.config_dir)?;
    crate::config::check_not_writable_by_others(&paths.state_dir)?;

    if config.pending_control_token.is_some() {
        return Err(RevttyError::message(
            "a credential rotation was interrupted; `revtty agent run` or `revtty agent \
             rotate-credential` finishes it",
        ));
    }

    let client = relay_client()?;
    check_relay_health(&client, &config.relay).await?;
    check_agent_credential(&client, &config).await?;

    println!("agent      configured");
    println!("name       {}", config.name);
    println!("host key   {}", identity.fingerprint);
    println!("protocol   v{}", crate::protocol::CONTROL_PROTOCOL_VERSION);
    println!("sessions   {}", config.max_sessions);
    println!("operators  {}", config.operators.len());
    println!("relay      {} reachable", config.relay);
    println!("credential accepted by the relay");
    println!("config     {}", AgentConfig::path(&paths).display());
    Ok(())
}

async fn check_agent_credential(
    client: &reqwest::Client,
    config: &AgentConfig,
) -> Result<(), RevttyError> {
    let url = http_url(&config.relay, &format!("/v1/agent/{}/check", config.name))?;
    let response = client
        .post(url)
        .bearer_auth(&config.control_token)
        .send()
        .await
        .map_err(|error| {
            RevttyError::runtime("check agent credential", crate::error::with_sources(&error))
        })?;

    match response.status() {
        status if status.is_success() => Ok(()),
        reqwest::StatusCode::UNAUTHORIZED => Err(RevttyError::message(
            "the relay rejected this agent's credential; re-enroll the agent",
        )),
        status => Err(RevttyError::message(format!(
            "agent credential check failed ({status})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use axum::extract::ws::{Message as RelayMessage, WebSocketUpgrade};
    use axum::routing::get;
    use ssh_key::{Algorithm, PrivateKey};
    use tokio::sync::{Mutex, Semaphore, mpsc, oneshot, watch};

    use super::config::AgentConfig;
    use super::config::RunLock;
    use super::ssh::OperatorAllowlist;
    use super::{
        ControlTimeouts, OPERATORS_RELOAD_INTERVAL, PendingRotation, RECONNECT_JITTER_PERCENT,
        ReconnectBackoff, Rotation, SessionTask, SessionTasks, cancel_session,
        describe_undecodable, enroll_with, finish_pending_rotation, pty_test,
        reconnect_base_millis, reconnect_delay_millis, rotate_control_credential, run_control_once,
        ssh, watch_operators,
    };
    use crate::config::Paths;
    use crate::pairing::{PairingCode, PairingSecret};
    use crate::protocol::{CONTROL_PROTOCOL_VERSION, ControlMessage, SESSION_ERROR_PREFIX};
    use crate::token::SecretToken;

    const FAST_CONTROL_TIMEOUTS: ControlTimeouts = ControlTimeouts {
        heartbeat: Duration::from_millis(50),
        relay_idle: Duration::from_millis(300),
    };

    #[derive(Clone, Copy)]
    enum FakeRelay {
        /// Accepts the control channel, then never reads or writes again.
        Silent,
        /// Answers the hello with an explicit rejection.
        Rejecting,
        /// Sends a message type this agent does not know, keeps answering pings, then
        /// closes the connection.
        Extending,
        /// Keeps sending messages this agent does not know without ever reading, so that the
        /// agent's pings go unanswered, then closes the connection.
        Deaf,
        /// Drops the connection without a close frame, as a relay that dies does.
        Vanishing,
        /// Offers a probe whose data tunnel never gets an answer, then keeps answering pings.
        OfferingDeadTunnel,
        /// As `OfferingDeadTunnel`, and cancels the session shortly after the offer.
        CancellingDeadTunnel,
        /// As `OfferingDeadTunnel`, with an exec offer.
        OfferingDeadExecTunnel,
    }

    async fn fake_relay(behaviour: FakeRelay) -> String {
        let app = axum::Router::new().route(
            "/v1/agent/{name}",
            get(move |ws: WebSocketUpgrade| async move {
                ws.on_upgrade(move |mut socket| async move {
                    let _hello = socket.recv().await;
                    if let FakeRelay::Vanishing = behaviour {
                        return;
                    }
                    if let FakeRelay::Deaf = behaviour {
                        let future = r#"{"type":"future_offer","version":1,"session_id":"s"}"#;
                        for _ in 0..16 {
                            if socket
                                .send(RelayMessage::Text(future.into()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        let _ = socket.send(RelayMessage::Close(None)).await;
                        return;
                    }
                    if let FakeRelay::OfferingDeadTunnel
                    | FakeRelay::CancellingDeadTunnel
                    | FakeRelay::OfferingDeadExecTunnel = behaviour
                    {
                        let session_id = "dead-tunnel".to_owned();
                        let tunnel_token = "rvs_test".to_owned();
                        let offer = serde_json::to_string(&match behaviour {
                            FakeRelay::OfferingDeadExecTunnel => ControlMessage::ExecOffer {
                                version: CONTROL_PROTOCOL_VERSION,
                                session_id,
                                tunnel_token,
                            },
                            _ => ControlMessage::ProbeOffer {
                                version: CONTROL_PROTOCOL_VERSION,
                                session_id,
                                tunnel_token,
                            },
                        })
                        .expect("encode session offer");
                        let _ = socket.send(RelayMessage::Text(offer.into())).await;
                        if let FakeRelay::CancellingDeadTunnel = behaviour {
                            // Not reading meanwhile leaves the agent's pings unanswered: well
                            // below `FAST_CONTROL_TIMEOUTS.relay_idle`, or the agent drops the
                            // control connection before the cancellation reaches it.
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            let cancel = serde_json::to_string(&ControlMessage::SessionCancel {
                                version: CONTROL_PROTOCOL_VERSION,
                                session_id: "dead-tunnel".to_owned(),
                            })
                            .expect("encode session cancel");
                            let _ = socket.send(RelayMessage::Text(cancel.into())).await;
                        }
                        while socket.recv().await.is_some() {}
                        return;
                    }
                    if let FakeRelay::Rejecting = behaviour {
                        let rejection = format!(
                            "{SESSION_ERROR_PREFIX}incompatible control protocol version 1"
                        );
                        let _ = socket.send(RelayMessage::Text(rejection.into())).await;
                    }
                    if let FakeRelay::Extending = behaviour {
                        let future = r#"{"type":"future_offer","version":1,"session_id":"s"}"#;
                        let _ = socket.send(RelayMessage::Text(future.into())).await;
                        // Keep reading, which answers the agent's pings, for a while.
                        let _ = tokio::time::timeout(Duration::from_millis(800), async {
                            while socket.recv().await.is_some() {}
                        })
                        .await;
                        let _ = socket.send(RelayMessage::Close(None)).await;
                        return;
                    }
                    // Keep the connection open without ever polling it again.
                    let _socket = socket;
                    std::future::pending::<()>().await;
                })
            }),
        );
        // An upgrade request that is never answered, as from a frozen relay.
        let app = app.route(
            "/v1/session/{session_id}",
            get(std::future::pending::<axum::http::StatusCode>),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake relay");
        let address = listener.local_addr().expect("fake relay address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve fake relay");
        });
        format!("ws://{address}")
    }

    async fn run_against(
        relay: &str,
        backoff: &mut ReconnectBackoff,
    ) -> Result<Result<(), crate::error::RevttyError>, ()> {
        run_with_slots(
            relay,
            backoff,
            Arc::new(Semaphore::new(4)),
            Duration::from_secs(5),
        )
        .await
    }

    async fn run_with_slots(
        relay: &str,
        backoff: &mut ReconnectBackoff,
        session_slots: Arc<Semaphore>,
        limit: Duration,
    ) -> Result<Result<(), crate::error::RevttyError>, ()> {
        let operator_key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
            .expect("operator key")
            .public_key()
            .to_openssh()
            .expect("encode operator key");
        let config = AgentConfig::new(
            relay.to_owned(),
            "agent-id".to_owned(),
            "fake-agent".to_owned(),
            "rva_test".to_owned(),
            operator_key,
            4,
        );
        let allowlist = watch::channel(
            OperatorAllowlist::parse(config.operators_revision, &config.operators)
                .expect("operator allowlist"),
        )
        .1;
        let (shutdown, _) = watch::channel(false);
        let (guard, _guards) = mpsc::channel(1);
        let shell_shutdown = ssh::ShellShutdown::new(shutdown.subscribe(), &guard);

        tokio::time::timeout(
            limit,
            run_control_once(
                &reqwest::Client::new(),
                &config,
                &allowlist,
                backoff,
                &session_slots,
                &Arc::new(Mutex::new(HashMap::new())),
                &shell_shutdown,
                FAST_CONTROL_TIMEOUTS,
            ),
        )
        .await
        .map_err(|_| ())
    }

    #[tokio::test]
    async fn silent_relay_ends_control_connection() {
        let relay = fake_relay(FakeRelay::Silent).await;
        let started = tokio::time::Instant::now();

        let outcome = run_against(&relay, &mut ReconnectBackoff::default()).await;

        assert!(
            matches!(outcome, Ok(Err(_))),
            "agent stayed attached to a silent relay"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn relay_rejection_ends_control_connection_with_its_reason() {
        let relay = fake_relay(FakeRelay::Rejecting).await;

        let outcome = run_against(&relay, &mut ReconnectBackoff::default()).await;

        let Ok(Err(error)) = outcome else {
            panic!("agent ignored the relay's rejection");
        };
        assert!(
            error
                .to_string()
                .contains("incompatible control protocol version"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn reconnect_backoff_grows_and_caps() {
        let expected = [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000];

        for (failures, expected_millis) in expected.into_iter().enumerate() {
            assert_eq!(
                reconnect_base_millis(failures as u32),
                expected_millis,
                "unexpected delay at failure {failures}"
            );
        }
    }

    #[test]
    fn reconnect_jitter_stays_bounded() {
        for failures in 0..10 {
            let base = reconnect_base_millis(failures);
            let spread = base * RECONNECT_JITTER_PERCENT / 100;
            let floor = base - spread;

            assert_eq!(reconnect_delay_millis(failures, 0), floor);

            let high = reconnect_delay_millis(failures, u64::MAX);
            assert!(high >= floor);
            assert!(high <= base);
        }
    }

    #[test]
    fn reconnect_backoff_reset_restarts_sequence() {
        let mut backoff = ReconnectBackoff::default();
        let first = backoff.next_delay();
        let second = backoff.next_delay();

        assert!(first <= std::time::Duration::from_secs(1));
        assert!(second >= std::time::Duration::from_millis(1_600));

        backoff.reset();
        let reset = backoff.next_delay();
        assert!(reset <= std::time::Duration::from_secs(1));
    }

    #[test]
    fn portable_pty_smoke_test() {
        pty_test().expect("portable PTY smoke test");
    }

    #[tokio::test]
    async fn unknown_control_message_does_not_drop_the_connection() {
        let relay = fake_relay(FakeRelay::Extending).await;

        let outcome = run_against(&relay, &mut ReconnectBackoff::default()).await;

        // The relay closed the connection itself after the unknown message; the agent did
        // not give up on it.
        assert!(
            matches!(outcome, Ok(Ok(()))),
            "agent dropped its control connection over an unknown message: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_relay_that_refuses_the_hello_keeps_the_backoff_growing() {
        let relay = fake_relay(FakeRelay::Rejecting).await;
        let mut backoff = ReconnectBackoff { failures: 3 };

        let outcome = run_against(&relay, &mut backoff).await;

        assert!(matches!(outcome, Ok(Err(_))), "{outcome:?}");
        // Sending the hello and the operator list proved nothing: the relay closed the
        // connection without accepting them, so the next attempt must not come after 1 s.
        assert_eq!(backoff.failures, 3);
    }

    #[tokio::test]
    async fn frames_without_pongs_do_not_reset_the_backoff() {
        let relay = fake_relay(FakeRelay::Deaf).await;
        let mut backoff = ReconnectBackoff { failures: 3 };

        let outcome = run_against(&relay, &mut backoff).await;

        assert!(matches!(outcome, Ok(Ok(()))), "{outcome:?}");
        assert_eq!(backoff.failures, 3);
    }

    #[tokio::test]
    async fn a_relay_answering_heartbeat_pings_resets_the_backoff() {
        let relay = fake_relay(FakeRelay::Extending).await;
        let mut backoff = ReconnectBackoff { failures: 3 };

        let outcome = run_against(&relay, &mut backoff).await;

        assert!(matches!(outcome, Ok(Ok(()))), "{outcome:?}");
        assert_eq!(backoff.failures, 0);
    }

    #[tokio::test]
    async fn a_lost_control_connection_reports_its_cause() {
        let relay = fake_relay(FakeRelay::Vanishing).await;

        let outcome = run_against(&relay, &mut ReconnectBackoff::default()).await;

        let Ok(Err(error)) = outcome else {
            panic!("the agent did not notice the lost connection: {outcome:?}");
        };
        // reqwest-websocket's own message stops at "tungstenite error". The loss shows on the
        // next read, or on a write when the agent was still sending its operator list.
        let error = error.to_string();
        assert!(
            ["without closing handshake", "Broken pipe", "reset by peer"]
                .iter()
                .any(|cause| error.contains(cause)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_tunnel_that_never_attaches_gives_its_session_slot_back() {
        let relay = fake_relay(FakeRelay::OfferingDeadTunnel).await;
        let slots = Arc::new(Semaphore::new(1));
        let control = tokio::spawn({
            let slots = slots.clone();
            async move {
                run_with_slots(
                    &relay,
                    &mut ReconnectBackoff::default(),
                    slots,
                    Duration::from_secs(30),
                )
                .await
            }
        });

        let reserved = wait_until(Duration::from_secs(5), || slots.available_permits() == 0).await;
        assert!(
            reserved,
            "the agent did not take a session slot for the offer"
        );
        // The handshake bound, not the relay, ends the attempt and with it the reservation.
        let released = wait_until(Duration::from_secs(14), || slots.available_permits() == 1).await;
        control.abort();
        assert!(
            released,
            "a tunnel stuck in its handshake kept its session slot"
        );
    }

    #[tokio::test]
    async fn an_exec_offer_is_accepted_as_a_session() {
        let relay = fake_relay(FakeRelay::OfferingDeadExecTunnel).await;
        let slots = Arc::new(Semaphore::new(1));
        let control = tokio::spawn({
            let slots = slots.clone();
            async move {
                run_with_slots(
                    &relay,
                    &mut ReconnectBackoff::default(),
                    slots,
                    Duration::from_secs(30),
                )
                .await
            }
        });

        // A slot is taken only for an offer the agent accepts.
        let reserved = wait_until(Duration::from_secs(5), || slots.available_permits() == 0).await;
        control.abort();
        assert!(
            reserved,
            "the agent did not take a session slot for an exec offer"
        );
    }

    #[tokio::test]
    async fn cancelling_a_session_asks_its_task_instead_of_aborting_it() {
        let session_tasks: SessionTasks = Arc::default();
        let (cancel, cancelled) = oneshot::channel();
        let (report, reported) = oneshot::channel();
        let task = tokio::spawn(async move {
            // A session task reacts to the cancellation; an aborted one never reports.
            let _ = report.send(cancelled.await.is_ok());
        });
        session_tasks
            .lock()
            .await
            .insert("s1".to_owned(), SessionTask { task, cancel });

        assert!(!cancel_session(&session_tasks, "unknown").await);
        assert!(cancel_session(&session_tasks, "s1").await);
        assert!(session_tasks.lock().await.is_empty());
        let reported = tokio::time::timeout(Duration::from_secs(2), reported)
            .await
            .expect("the session task never saw the cancellation");
        assert_eq!(reported, Ok(true), "the session task was aborted");
    }

    #[tokio::test]
    async fn a_session_cancelled_before_its_tunnel_opens_gives_its_slot_back_at_once() {
        let relay = fake_relay(FakeRelay::CancellingDeadTunnel).await;
        let slots = Arc::new(Semaphore::new(1));
        let control = tokio::spawn({
            let slots = slots.clone();
            async move {
                run_with_slots(
                    &relay,
                    &mut ReconnectBackoff::default(),
                    slots,
                    Duration::from_secs(30),
                )
                .await
            }
        });

        let reserved = wait_until(Duration::from_secs(5), || slots.available_permits() == 0).await;
        assert!(
            reserved,
            "the agent did not take a session slot for the offer"
        );
        // Well before the 10 s handshake bound that would end the attempt otherwise.
        let released = wait_until(Duration::from_secs(3), || slots.available_permits() == 1).await;
        control.abort();
        assert!(
            released,
            "a session the relay cancelled kept its slot until its handshake bound"
        );
    }

    async fn wait_until(limit: Duration, condition: impl Fn() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        while tokio::time::Instant::now() < deadline {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        condition()
    }

    #[test]
    fn undecodable_control_message_is_logged_without_its_content() {
        let message = r#"{"type":"probe_offer","version":"rvs_SECRET_MARKER","session_id":"s","tunnel_token":"t"}"#;
        let error = serde_json::from_str::<crate::protocol::ControlMessage>(message)
            .err()
            .expect("message does not decode");

        // serde's own message would leak the value.
        assert!(error.to_string().contains("rvs_SECRET_MARKER"));
        assert!(
            !describe_undecodable(&error).contains("SECRET_MARKER"),
            "diagnostic leaks received content"
        );
    }

    fn operator_key() -> String {
        PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
            .expect("operator key")
            .public_key()
            .to_openssh()
            .expect("encode operator key")
    }

    #[test]
    fn operators_report_stays_small_whatever_the_comments() {
        // Control characters, which JSON expands sixfold, in the longest comments.
        let operators = (0..crate::protocol::MAX_OPERATORS)
            .map(|_| {
                let mut key =
                    PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
                        .expect("operator key");
                key.set_comment("\u{1}".repeat(4096));
                key.public_key().to_openssh().expect("encode operator key")
            })
            .collect::<Vec<_>>();
        let allowlist = OperatorAllowlist::parse(1, &operators).expect("operator allowlist");

        let report = serde_json::to_string(&crate::protocol::ControlMessage::OperatorsReport {
            version: crate::protocol::CONTROL_PROTOCOL_VERSION,
            revision: allowlist.revision,
            operators: allowlist.operators.clone(),
        })
        .expect("encode report");
        assert!(report.len() < 16 * 1024, "report of {} bytes", report.len());
        assert!(!report.contains("\\u0001"), "comments were reported");
    }

    #[tokio::test]
    async fn operator_watch_keeps_the_last_valid_list_and_publishes_changes() {
        let root = std::env::temp_dir().join(format!("revtty-watch-{}", uuid::Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        let first = operator_key();
        let enrolled = AgentConfig::new(
            "ws://127.0.0.1:9".to_owned(),
            "agent-id".to_owned(),
            "watched-agent".to_owned(),
            "rva_test".to_owned(),
            first.clone(),
            4,
        );
        enrolled.save(&paths).expect("save agent config");
        let mut allowlist = watch_operators(
            paths.clone(),
            OperatorAllowlist::parse(enrolled.operators_revision, &enrolled.operators)
                .expect("operator allowlist"),
        );

        // A configuration broken by hand does not empty the list.
        std::fs::write(AgentConfig::path(&paths), "operators = [").expect("break config");
        tokio::time::sleep(OPERATORS_RELOAD_INTERVAL * 2).await;
        assert!(
            !allowlist.has_changed().expect("operator watch running"),
            "an unreadable configuration replaced the operator list"
        );
        assert_eq!(allowlist.borrow().operators, vec![first.clone()]);

        let mut repaired = enrolled;
        repaired
            .add_operator(&operator_key())
            .expect("add operator");
        repaired.save(&paths).expect("save repaired config");
        tokio::time::timeout(OPERATORS_RELOAD_INTERVAL * 2, allowlist.changed())
            .await
            .expect("operator change not published")
            .expect("operator watch running");
        assert_eq!(allowlist.borrow().revision, 2);
        assert_eq!(allowlist.borrow().operators.len(), 2);

        std::fs::remove_dir_all(root).expect("clean watch test directory");
    }

    /// The relay side of credential rotation as the relay implements it, with knobs to lose
    /// its answers after acting.
    #[derive(Default)]
    struct FakeRotation {
        current: String,
        next_hash: Option<String>,
        lose_rotate_answer: bool,
        lose_confirm_answer: bool,
    }

    type SharedRotation = Arc<std::sync::Mutex<FakeRotation>>;

    fn bearer(headers: &axum::http::HeaderMap) -> String {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default()
            .to_owned()
    }

    async fn rotation_relay(state: SharedRotation, supported: bool) -> String {
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::post;
        use base64::Engine as _;

        let check = {
            let state = Arc::clone(&state);
            move |headers: HeaderMap| async move {
                if bearer(&headers) == state.lock().expect("fake relay").current {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }
        };
        let rotate = {
            let state = Arc::clone(&state);
            move |headers: HeaderMap,
                  axum::Json(request): axum::Json<crate::protocol::AgentRotateRequest>| async move {
                let mut state = state.lock().expect("fake relay");
                if bearer(&headers) != state.current {
                    return StatusCode::UNAUTHORIZED;
                }
                state.next_hash = Some(request.next_hash);
                if state.lose_rotate_answer {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::NO_CONTENT
                }
            }
        };
        let confirm = {
            let state = Arc::clone(&state);
            move |headers: HeaderMap| async move {
                let mut state = state.lock().expect("fake relay");
                let token = bearer(&headers);
                let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(crate::token::hash_token(&token));
                if state.next_hash.as_deref() == Some(hash.as_str()) {
                    state.current = token;
                    state.next_hash = None;
                    if state.lose_confirm_answer {
                        return StatusCode::INTERNAL_SERVER_ERROR;
                    }
                    StatusCode::NO_CONTENT
                } else if token == state.current {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }
        };

        let mut app = axum::Router::new().route("/v1/agent/{name}/check", post(check));
        if supported {
            app = app
                .route("/v1/agent/{name}/rotate", post(rotate))
                .route("/v1/agent/{name}/rotate/confirm", post(confirm));
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake relay");
        let address = listener.local_addr().expect("fake relay address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve fake relay");
        });
        format!("http://{address}")
    }

    /// An enrolled agent configuration whose relay is `relay`, and its relay-side state.
    async fn rotating_agent(supported: bool) -> (std::path::PathBuf, Paths, SharedRotation) {
        let root = std::env::temp_dir().join(format!("revtty-rotate-{}", uuid::Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        let state = SharedRotation::default();
        state.lock().expect("fake relay").current = "rva_current".to_owned();
        let relay = rotation_relay(Arc::clone(&state), supported).await;
        AgentConfig::new(
            relay,
            "agent-id".to_owned(),
            "rotating-agent".to_owned(),
            "rva_current".to_owned(),
            operator_key(),
            4,
        )
        .save(&paths)
        .expect("save agent config");
        (root, paths, state)
    }

    #[tokio::test]
    async fn rotation_switches_the_agent_to_a_credential_it_generated() {
        let (root, paths, relay) = rotating_agent(true).await;

        let rotated = rotate_control_credential(&reqwest::Client::new(), &paths)
            .await
            .expect("rotate credential");

        assert!(matches!(rotated, Rotation::Rotated));
        let config = AgentConfig::load(&paths).expect("load agent config");
        assert_ne!(config.control_token, "rva_current");
        assert!(config.pending_control_token.is_none());
        assert_eq!(
            relay.lock().expect("fake relay").current,
            config.control_token
        );
        std::fs::remove_dir_all(root).expect("clean rotation test directory");
    }

    #[tokio::test]
    async fn rotation_finishes_after_a_lost_answer() {
        for lose_confirm in [false, true] {
            let (root, paths, relay) = rotating_agent(true).await;
            {
                let mut relay = relay.lock().expect("fake relay");
                relay.lose_rotate_answer = !lose_confirm;
                relay.lose_confirm_answer = lose_confirm;
            }
            let client = reqwest::Client::new();

            let interrupted = rotate_control_credential(&client, &paths).await;
            let error = interrupted
                .err()
                .expect("rotation with a lost answer succeeded");
            assert!(
                error.to_string().contains("finishes the rotation"),
                "{error}"
            );
            let config = AgentConfig::load(&paths).expect("load agent config");
            assert_eq!(config.control_token, "rva_current");
            let pending = config
                .pending_control_token
                .expect("pending credential kept");

            // As the next `agent run` does before connecting.
            {
                let mut relay = relay.lock().expect("fake relay");
                relay.lose_rotate_answer = false;
                relay.lose_confirm_answer = false;
            }
            let finished = finish_pending_rotation(&client, &paths)
                .await
                .expect("finish rotation");
            assert!(matches!(finished, PendingRotation::Completed));
            let config = AgentConfig::load(&paths).expect("load agent config");
            assert_eq!(config.control_token, pending, "lose_confirm={lose_confirm}");
            assert!(config.pending_control_token.is_none());
            assert_eq!(relay.lock().expect("fake relay").current, pending);
            std::fs::remove_dir_all(root).expect("clean rotation test directory");
        }
    }

    #[tokio::test]
    async fn pending_rotation_the_relay_never_took_is_abandoned() {
        let (root, paths, relay) = rotating_agent(true).await;
        AgentConfig::update(&paths, |config| {
            config.pending_control_token = Some("rva_never_sent".to_owned());
            Ok(())
        })
        .expect("leave a pending credential");

        let finished = finish_pending_rotation(&reqwest::Client::new(), &paths)
            .await
            .expect("finish rotation");

        assert!(matches!(
            finished,
            PendingRotation::Abandoned { unsupported: false }
        ));
        let config = AgentConfig::load(&paths).expect("load agent config");
        assert_eq!(config.control_token, "rva_current");
        assert!(config.pending_control_token.is_none());
        assert_eq!(relay.lock().expect("fake relay").current, "rva_current");
        std::fs::remove_dir_all(root).expect("clean rotation test directory");
    }

    #[tokio::test]
    async fn rotation_against_a_relay_without_it_changes_nothing() {
        let (root, paths, _relay) = rotating_agent(false).await;
        // A configuration written by hand, in the format before operator lists.
        let config = AgentConfig::load(&paths).expect("load agent config");
        let legacy = format!(
            "# written by hand\nrelay = \"{}\"\nagent_id = \"agent-id\"\nname = \"rotating-agent\"\n\
             control_token = \"rva_current\"\noperator_key = \"{}\"\n",
            config.relay, config.operators[0]
        );
        std::fs::write(AgentConfig::path(&paths), &legacy).expect("write legacy config");
        let before = std::fs::read_to_string(AgentConfig::path(&paths)).expect("read config");

        let rotated = rotate_control_credential(&reqwest::Client::new(), &paths)
            .await
            .expect("rotate against an older relay");

        assert!(matches!(rotated, Rotation::Unsupported));
        assert_eq!(
            std::fs::read_to_string(AgentConfig::path(&paths)).expect("read config"),
            before
        );
        std::fs::remove_dir_all(root).expect("clean rotation test directory");
    }

    #[tokio::test]
    async fn rotation_request_to_a_silent_relay_is_bounded() {
        // Accepts connections and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent relay");
        let address = listener.local_addr().expect("silent relay address");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let started = tokio::time::Instant::now();
        let answer = super::post_with_credential(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            "/v1/agent/silent-agent/rotate/confirm",
            "rva_pending",
            None,
        )
        .await;

        assert!(answer.is_err(), "a silent relay answered");
        assert!(started.elapsed() < super::ROTATION_REQUEST_TIMEOUT + Duration::from_secs(2));
    }

    #[tokio::test]
    async fn rotation_waits_for_the_agent_to_stop() {
        let (root, paths, relay) = rotating_agent(true).await;
        let running = RunLock::try_acquire(&paths)
            .expect("lock run state")
            .expect("no agent running yet");

        let refused = rotate_control_credential(&reqwest::Client::new(), &paths).await;

        let error = refused.err().expect("rotated under a running agent");
        assert!(
            error.to_string().contains("the agent is running"),
            "{error}"
        );
        assert_eq!(relay.lock().expect("fake relay").current, "rva_current");
        assert!(
            AgentConfig::load(&paths)
                .expect("load agent config")
                .pending_control_token
                .is_none()
        );
        drop(running);
        std::fs::remove_dir_all(root).expect("clean rotation test directory");
    }

    /// The relay side of enrollment, answering with whatever `name` and `operator_key` it is
    /// set to, and keeping every request body it receives.
    #[derive(Default)]
    struct FakeEnrollment {
        name: String,
        operator_key: String,
        bodies: Vec<String>,
    }

    type SharedEnrollment = Arc<std::sync::Mutex<FakeEnrollment>>;

    async fn enrollment_relay(state: SharedEnrollment) -> String {
        use axum::http::StatusCode;
        use axum::routing::post;

        let enroll = move |body: String| async move {
            let mut state = state.lock().expect("fake relay");
            state.bodies.push(body);
            (
                StatusCode::CREATED,
                axum::Json(crate::protocol::EnrollResponse {
                    agent_id: "agent-id".to_owned(),
                    name: state.name.clone(),
                    control_token: "rva_enrolled".to_owned(),
                    operator_key: state.operator_key.clone(),
                }),
            )
        };
        let app = axum::Router::new().route("/v1/enroll", post(enroll));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake relay");
        let address = listener.local_addr().expect("fake relay address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve fake relay");
        });
        format!("http://{address}")
    }

    /// An agent not enrolled yet, and a relay that enrolls it as `name` for `operator_key`.
    async fn enrolling_agent(
        name: &str,
        operator_key: &str,
    ) -> (std::path::PathBuf, Paths, SharedEnrollment, String) {
        let root = std::env::temp_dir().join(format!("revtty-enroll-{}", uuid::Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        let state = SharedEnrollment::default();
        {
            let mut state = state.lock().expect("fake relay");
            state.name = name.to_owned();
            state.operator_key = operator_key.to_owned();
        }
        let relay = enrollment_relay(Arc::clone(&state)).await;
        (root, paths, state, relay)
    }

    fn pairing_code(name: &str, operator_key: &str) -> PairingCode {
        let fingerprint = ssh_key::PublicKey::from_openssh(operator_key)
            .expect("parse operator key")
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        PairingCode::new(
            SecretToken::generate("rve").expect("token").expose(),
            PairingSecret::generate().expect("pairing secret"),
            name,
            &fingerprint,
        )
        .expect("pairing code")
    }

    #[tokio::test]
    async fn a_pairing_code_keeps_its_secret_and_proves_the_host_key() {
        let operator = operator_key();
        let (root, paths, relay_state, relay) = enrolling_agent("paired-agent", &operator).await;
        let code = pairing_code("paired-agent", &operator);
        let encoded = code.encode();

        enroll_with(
            &reqwest::Client::new(),
            &paths,
            &relay,
            None,
            Some(&encoded),
            4,
        )
        .await
        .expect("enroll with a pairing code");

        let config = AgentConfig::load(&paths).expect("load agent config");
        assert_eq!(config.operators, vec![operator]);
        let bodies = relay_state.lock().expect("fake relay").bodies.clone();
        assert_eq!(bodies.len(), 1);
        let body = &bodies[0];
        let tag = encoded.rsplit('.').next().expect("tag");
        assert!(
            !body.contains(&code.secret().expose()[4..]) && !body.contains(tag),
            "the relay received the code's secret or tag: {body}"
        );
        let request: crate::protocol::EnrollRequest =
            serde_json::from_str(body).expect("decode enrollment request");
        assert_eq!(request.token, code.token());
        let identity = crate::identity::ensure_agent(&paths).expect("agent identity");
        let proof = request.host_key_proof.expect("host key proof sent");
        assert!(
            code.secret()
                .host_key_proof_matches(&identity.fingerprint, &proof)
                .expect("verify proof")
        );
        std::fs::remove_dir_all(root).expect("clean enrollment test directory");
    }

    #[tokio::test]
    async fn an_answer_the_pairing_code_does_not_vouch_for_saves_nothing() {
        let client = reqwest::Client::new();
        let operator = operator_key();
        // The relay names another operator, or enrolls the machine under another name.
        for (name, answered) in [
            ("paired-agent", operator_key()),
            ("other-agent", operator.clone()),
        ] {
            let (root, paths, _relay_state, relay) = enrolling_agent(name, &answered).await;
            let code = pairing_code("paired-agent", &operator).encode();
            let refused = enroll_with(&client, &paths, &relay, None, Some(&code), 4).await;
            assert!(
                refused.is_err_and(|error| error.to_string().contains("nothing was saved")),
                "{name}"
            );
            assert!(!AgentConfig::path(&paths).exists(), "{name}");
            std::fs::remove_dir_all(root).expect("clean enrollment test directory");
        }

        // Enrolling again: the configuration in place stays as it was.
        let (root, paths, relay_state, relay) = enrolling_agent("paired-agent", &operator).await;
        let code = pairing_code("paired-agent", &operator).encode();
        enroll_with(&client, &paths, &relay, None, Some(&code), 4)
            .await
            .expect("first enrollment");
        let before = std::fs::read(AgentConfig::path(&paths)).expect("read agent config");
        relay_state.lock().expect("fake relay").operator_key = operator_key();
        let code = pairing_code("paired-agent", &operator).encode();
        let refused = enroll_with(&client, &paths, &relay, None, Some(&code), 4).await;
        assert!(refused.is_err());
        assert_eq!(
            std::fs::read(AgentConfig::path(&paths)).expect("read agent config"),
            before
        );
        std::fs::remove_dir_all(root).expect("clean enrollment test directory");
    }

    #[tokio::test]
    async fn a_misused_pairing_code_is_refused_before_any_request() {
        let operator = operator_key();
        let (root, paths, relay_state, relay) = enrolling_agent("paired-agent", &operator).await;
        let code = pairing_code("paired-agent", &operator);
        let secret = code.secret().expose()[4..].to_owned();
        let encoded = code.encode();
        let damaged = encoded[..encoded.len() - 3].to_owned();

        // Passed as a token, the whole code would reach the relay; damaged, it is not quoted.
        for (token, pairing) in [
            (Some(encoded.as_str()), None),
            (None, Some(damaged.as_str())),
        ] {
            let refused =
                enroll_with(&reqwest::Client::new(), &paths, &relay, token, pairing, 4).await;
            let error = refused
                .expect_err("enrolled with a misused code")
                .to_string();
            assert!(!error.contains(&secret), "{error}");
        }
        assert!(
            relay_state.lock().expect("fake relay").bodies.is_empty(),
            "a request reached the relay"
        );
        assert!(!AgentConfig::path(&paths).exists());
        if root.exists() {
            std::fs::remove_dir_all(root).expect("clean enrollment test directory");
        }
    }
}
