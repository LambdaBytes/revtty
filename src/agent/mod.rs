mod config;
mod ssh;

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

use futures_util::{SinkExt, StreamExt};
use reqwest_websocket::Message;
use ssh_key::{Algorithm, HashAlg, PublicKey};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use self::config::{AgentConfig, validate_max_sessions};
use self::ssh::OperatorAllowlist;
use crate::config::Paths;
use crate::identity::ensure_agent;

use crate::error::RevttyError;
use crate::protocol::{
    CONTROL_PROTOCOL_VERSION, ControlMessage, EnrollRequest, EnrollResponse, ProbeResult,
    SESSION_ERROR_PREFIX, SessionRejectReason,
};
use crate::transport::{check_relay_health, connect_websocket, http_url, valid_name};

const RECONNECT_BASE_MILLIS: u64 = 1_000;
const RECONNECT_CAP_MILLIS: u64 = 30_000;
const RECONNECT_JITTER_PERCENT: u64 = 20;
/// Bound on waiting for shell teardowns at shutdown; below systemd's `TimeoutStopSec=15s`.
const SHELL_SHUTDOWN_WAIT: Duration = Duration::from_secs(10);
/// Writing one frame to the relay; a write that cannot complete means the path is dead.
const CONTROL_SEND_TIMEOUT: Duration = Duration::from_secs(10);
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

type SessionTasks = Arc<Mutex<HashMap<String, JoinHandle<()>>>>;

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

pub async fn enroll(relay: &str, token: &str, max_sessions: usize) -> Result<(), RevttyError> {
    validate_max_sessions(max_sessions)?;
    let paths = Paths::discover()?;
    let identity = ensure_agent(&paths)?;
    let url = http_url(relay, "/v1/enroll")?;
    let request = EnrollRequest {
        token: token.to_owned(),
        host_key: identity.public_key.clone(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };

    let response = reqwest::Client::new()
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|error| RevttyError::runtime("send enrollment request", error))?;

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

    AgentConfig::new(
        relay.trim_end_matches('/').to_owned(),
        enrolled.agent_id,
        enrolled.name.clone(),
        enrolled.control_token,
        enrolled.operator_key,
        max_sessions,
    )
    .save(&paths)?;

    println!("agent      {}", enrolled.name);
    println!("host       {}", identity.fingerprint);
    println!(
        "identity   {}",
        if identity.created {
            "created"
        } else {
            "existing"
        }
    );
    println!("sessions   {max_sessions}");
    println!("config     {}", AgentConfig::path(&paths).display());
    Ok(())
}

pub async fn run() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let config = AgentConfig::load(&paths)?;

    if !valid_name(&config.name) {
        return Err(RevttyError::message(
            "stored agent name is invalid; re-enroll this agent",
        ));
    }

    let allowlist = watch_operators(
        paths.clone(),
        OperatorAllowlist::parse(config.operators_revision, &config.operators)?,
    );
    let client = reqwest::Client::new();
    let mut backoff = ReconnectBackoff::default();
    let session_slots = Arc::new(Semaphore::new(config.max_sessions));
    let session_tasks: SessionTasks = Arc::new(Mutex::new(HashMap::new()));
    let (shutdown_signal, _) = watch::channel(false);
    let (shell_guard, mut shell_guards) = mpsc::channel::<()>(1);
    let shell_shutdown = ssh::ShellShutdown::new(shutdown_signal.subscribe(), &shell_guard);

    let stopped = loop {
        let control = run_control_once(
            &client,
            &config,
            &allowlist,
            &mut backoff,
            &session_slots,
            &session_tasks,
            &shell_shutdown,
            CONTROL_TIMEOUTS,
        );

        tokio::select! {
            result = control => {
                if let Err(error) = result {
                    eprintln!("control connection lost: {error}");
                }
            }
            signal = tokio::signal::ctrl_c() => break signal,
        }

        let delay = backoff.next_delay();
        eprintln!("reconnecting in {:.1}s", delay.as_secs_f64());

        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            signal = tokio::signal::ctrl_c() => break signal,
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
        eprintln!(
            "shell teardown did not finish within {}s",
            SHELL_SHUTDOWN_WAIT.as_secs()
        );
    }

    stopped.map_err(|error| RevttyError::runtime("wait for Ctrl-C", error))
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
                        eprintln!("operator list revision {revision}: {count} operators");
                    }
                }
                // The last valid list stays in force: replacing it with nothing would close
                // every session, including the one an operator would use to repair the file.
                // The cause is not logged, since a parse error quotes the file, which holds
                // the control credential; `revtty agent operator list` shows it.
                Err(_) if !unreadable => {
                    unreadable = true;
                    eprintln!(
                        "cannot reload the operator list from agent.toml; keeping the previous one (run `revtty agent operator list` for the cause)"
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

    backoff.reset();
    eprintln!("agent {name} connected to {relay}");

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
                    .retain(|_, task| !task.is_finished());

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
                                eprintln!(
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
                                let task_session_id = session_id.clone();

                                let task = tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Err(error) = send_probe(
                                        &client,
                                        &relay,
                                        &tunnel_token,
                                        &task_session_id,
                                        &name,
                                    )
                                    .await
                                    {
                                        eprintln!("probe {task_session_id} failed: {error}");
                                    }
                                });

                                session_tasks.lock().await.insert(session_id, task);
                            }
                            ControlMessage::ShellOffer {
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
                                let allowlist = allowlist.clone();
                                let task_session_id = session_id.clone();
                                let shell_shutdown = shell_shutdown.clone();

                                let task = tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Err(error) = ssh::serve(
                                        &client,
                                        &relay,
                                        &tunnel_token,
                                        &task_session_id,
                                        allowlist,
                                        shell_shutdown,
                                    )
                                    .await
                                    {
                                        eprintln!("shell {task_session_id} failed: {error}");
                                    }
                                });

                                session_tasks.lock().await.insert(session_id, task);
                            }
                            ControlMessage::SessionCancel {
                                version,
                                session_id,
                            } if version == CONTROL_PROTOCOL_VERSION => {
                                if let Some(task) = session_tasks.lock().await.remove(&session_id) {
                                    task.abort();
                                    eprintln!("session cancelled by relay: {session_id}");
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        send_frame(&mut sender, Message::Pong(data), "send control pong").await?;
                    }
                    Some(Ok(Message::Close { .. })) | None => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        return Err(RevttyError::runtime("receive control message", error));
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
        Ok(sent) => sent.map_err(|error| RevttyError::runtime(context, error)),
        Err(_) => Err(RevttyError::message(format!(
            "{context}: no progress for {}s",
            CONTROL_SEND_TIMEOUT.as_secs()
        ))),
    }
}

async fn send_probe(
    client: &reqwest::Client,
    relay: &str,
    tunnel_token: &str,
    session_id: &str,
    name: &str,
) -> Result<(), RevttyError> {
    let path = format!("/v1/session/{session_id}");
    let mut websocket = connect_websocket(client, relay, &path, tunnel_token).await?;

    let result = ProbeResult {
        name: name.to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };

    let text = serde_json::to_string(&result)
        .map_err(|error| RevttyError::runtime("encode probe result", error))?;

    websocket
        .send(Message::Text(text))
        .await
        .map_err(|error| RevttyError::runtime("send probe result", error))?;

    websocket
        .close(reqwest_websocket::CloseCode::Normal, None)
        .await
        .map_err(|error| RevttyError::runtime("close probe session", error))
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
    println!("relay      {}", config.relay);
    println!("id         {}", config.agent_id);
    println!("host       {}", identity.fingerprint);
    println!("sessions   {}", config.max_sessions);
    println!("config     {}", AgentConfig::path(&paths).display());
    Ok(())
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
    let encoded = std::fs::read_to_string(key_path)
        .map_err(|error| RevttyError::runtime("read operator public key", error))?;
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

    let client = reqwest::Client::new();
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
    use tokio::sync::{Mutex, Semaphore, mpsc, watch};

    use super::config::AgentConfig;
    use super::ssh::OperatorAllowlist;
    use super::{
        ControlTimeouts, OPERATORS_RELOAD_INTERVAL, RECONNECT_JITTER_PERCENT, ReconnectBackoff,
        describe_undecodable, pty_test, reconnect_base_millis, reconnect_delay_millis,
        run_control_once, ssh, watch_operators,
    };
    use crate::config::Paths;
    use crate::protocol::SESSION_ERROR_PREFIX;

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
    }

    async fn fake_relay(behaviour: FakeRelay) -> String {
        let app = axum::Router::new().route(
            "/v1/agent/{name}",
            get(move |ws: WebSocketUpgrade| async move {
                ws.on_upgrade(move |mut socket| async move {
                    let _hello = socket.recv().await;
                    if let FakeRelay::Rejecting = behaviour {
                        let rejection = format!(
                            "{SESSION_ERROR_PREFIX}incompatible control protocol version 1"
                        );
                        let _ = socket.send(RelayMessage::Text(rejection.into())).await;
                    }
                    if let FakeRelay::Extending = behaviour {
                        let future = r#"{"type":"exec_offer","version":1,"session_id":"s"}"#;
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake relay");
        let address = listener.local_addr().expect("fake relay address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve fake relay");
        });
        format!("ws://{address}")
    }

    async fn run_against(relay: &str) -> Result<Result<(), crate::error::RevttyError>, ()> {
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
            Duration::from_secs(5),
            run_control_once(
                &reqwest::Client::new(),
                &config,
                &allowlist,
                &mut ReconnectBackoff::default(),
                &Arc::new(Semaphore::new(4)),
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

        let outcome = run_against(&relay).await;

        assert!(
            matches!(outcome, Ok(Err(_))),
            "agent stayed attached to a silent relay"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn relay_rejection_ends_control_connection_with_its_reason() {
        let relay = fake_relay(FakeRelay::Rejecting).await;

        let outcome = run_against(&relay).await;

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

        let outcome = run_against(&relay).await;

        // The relay closed the connection itself after the unknown message; the agent did
        // not give up on it.
        assert!(
            matches!(outcome, Ok(Ok(()))),
            "agent dropped its control connection over an unknown message: {outcome:?}"
        );
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
}
