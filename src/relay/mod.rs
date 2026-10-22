use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::{Future, IntoFuture};
use std::path::Path as FsPath;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use ssh_key::{Algorithm, HashAlg, PublicKey, SshSig};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use uuid::Uuid;

use crate::error::RevttyError;
use crate::protocol::{
    AgentListResponse, AgentRotateRequest, AgentStatusResponse, CONTROL_PROTOCOL_VERSION,
    ControlMessage, EnrollRequest, EnrollResponse, OPERATOR_AUTH_NAMESPACE, OperatorAuthRequest,
    OperatorAuthResponse, OperatorChallengeResponse, OperatorListRequest, SESSION_ERROR_PREFIX,
    SESSION_NOT_ACCEPTED, SessionRejectReason, operator_auth_message, operator_list_auth_message,
};
use crate::storage::{OperatorsReportOutcome, ReportedOperator, RotationConfirmation, Store};
use crate::token::{SecretToken, hash_token};
use crate::transport::valid_name;

const CONTROL_QUEUE_DEPTH: usize = 16;
const AUDIT_QUEUE_DEPTH: usize = 1024;
const MAX_MESSAGE_SIZE: usize = 64 * 1024;
const OPERATOR_CHALLENGE_TTL: Duration = Duration::from_secs(30);
const OPERATOR_SESSION_TTL: Duration = Duration::from_secs(30);
const MAX_PENDING_OPERATOR_AUTH: usize = 4096;

#[derive(Clone, Copy)]
struct RelayTimeouts {
    /// No frame at all from an agent's control channel for this long drops the agent; it
    /// sends a heartbeat every 15 s, so this is three missed heartbeats.
    agent_idle: Duration,
    /// A newly connected agent must identify itself with `Hello` within this time.
    agent_hello: Duration,
    /// Writing one message to an agent's control channel.
    control_send: Duration,
    /// From the operator's request, including queueing the offer, until the agent decides.
    agent_accept: Duration,
    /// From the agent's acceptance until its data tunnel attaches.
    data_tunnel: Duration,
    /// How often the relay checks that the agents it serves are still enrolled, closing the
    /// connections of removed or re-enrolled ones.
    removal_sweep: Duration,
    /// From SIGINT or SIGTERM until the relay has finished the requests in flight, ended its
    /// connections and written their audit records.
    shutdown: Duration,
}

const RELAY_TIMEOUTS: RelayTimeouts = RelayTimeouts {
    agent_idle: Duration::from_secs(45),
    agent_hello: Duration::from_secs(10),
    control_send: Duration::from_secs(10),
    agent_accept: Duration::from_secs(5),
    data_tunnel: Duration::from_secs(10),
    removal_sweep: Duration::from_secs(5),
    shutdown: Duration::from_secs(5),
};

/// A session transition and when it happened (Unix seconds): the write may run later.
enum AuditEvent {
    Requested {
        id: String,
        agent_name: String,
        kind: &'static str,
        operator_fingerprint: String,
        at: i64,
    },
    Accepted {
        id: String,
        at: i64,
    },
    Paired {
        id: String,
        at: i64,
    },
    Ended {
        id: String,
        outcome: String,
        at: i64,
    },
    /// Answered once every record queued before it is handled, with how many of those since
    /// the previous flush could not be written.
    Flush(oneshot::Sender<usize>),
}

/// Session audit records, written in order by one background task so the session path
/// never waits on SQLite. Audit is best effort: a full queue drops a record with a warning
/// instead of stalling sessions. A relay that stops writes what is queued first; one that
/// is killed loses it, and its next start marks those sessions interrupted.
#[derive(Clone)]
struct AuditLog {
    events: mpsc::Sender<AuditEvent>,
}

impl AuditLog {
    fn start(store: Store) -> Self {
        let (events, mut queue) = mpsc::channel(AUDIT_QUEUE_DEPTH);

        tokio::spawn(async move {
            let mut unwritten = 0;
            while let Some(event) = queue.recv().await {
                let written = match event {
                    AuditEvent::Requested {
                        id,
                        agent_name,
                        kind,
                        operator_fingerprint,
                        at,
                    } => {
                        store
                            .record_session_requested(
                                &id,
                                &agent_name,
                                kind,
                                &operator_fingerprint,
                                at,
                            )
                            .await
                    }
                    AuditEvent::Accepted { id, at } => store.record_session_accepted(&id, at).await,
                    AuditEvent::Paired { id, at } => store.record_session_paired(&id, at).await,
                    AuditEvent::Ended { id, outcome, at } => {
                        store.record_session_ended(&id, &outcome, at).await
                    }
                    AuditEvent::Flush(written) => {
                        let _ = written.send(std::mem::take(&mut unwritten));
                        continue;
                    }
                };

                if let Err(error) = written {
                    unwritten += 1;
                    tracing::error!("session audit write failed: {error}");
                }
            }
        });

        Self { events }
    }

    fn requested(
        &self,
        id: &str,
        agent_name: &str,
        kind: &'static str,
        operator_fingerprint: &str,
    ) {
        self.record(|at| AuditEvent::Requested {
            id: id.to_owned(),
            agent_name: agent_name.to_owned(),
            kind,
            operator_fingerprint: operator_fingerprint.to_owned(),
            at,
        });
    }

    fn accepted(&self, id: &str) {
        self.record(|at| AuditEvent::Accepted {
            id: id.to_owned(),
            at,
        });
    }

    fn paired(&self, id: &str) {
        self.record(|at| AuditEvent::Paired {
            id: id.to_owned(),
            at,
        });
    }

    fn ended(&self, id: &str, outcome: &str) {
        self.record(|at| AuditEvent::Ended {
            id: id.to_owned(),
            outcome: outcome.to_owned(),
            at,
        });
    }

    /// Returns once every record queued so far is handled: an error if one of those queued
    /// since the previous flush could not be written.
    async fn flush(&self) -> Result<(), RevttyError> {
        let stopped = || RevttyError::message("the session audit writer has stopped");
        let (written, flushed) = oneshot::channel();
        self.events
            .send(AuditEvent::Flush(written))
            .await
            .map_err(|_| stopped())?;
        match flushed.await.map_err(|_| stopped())? {
            0 => Ok(()),
            unwritten => Err(RevttyError::message(format!(
                "{unwritten} session audit records could not be written"
            ))),
        }
    }

    /// Stamps the event now, when it happens, and queues it.
    fn record(&self, event: impl FnOnce(i64) -> AuditEvent) {
        let at = match crate::storage::unix_now() {
            Ok(at) => at,
            Err(error) => {
                tracing::error!("session audit record dropped: {error}");
                return;
            }
        };

        if self.events.try_send(event(at)).is_err() {
            tracing::error!("session audit queue is full; an audit record was dropped");
        }
    }
}

/// The relay's WebSocket tasks, which axum's graceful shutdown stops tracking once it has
/// handed their connection over: shutdown ends them and waits for them through this.
struct Lifecycle {
    /// Cloned by every task that enters and taken when shutdown begins, so that no task
    /// enters after that and `ended` closes once the last one is over.
    entry: std::sync::Mutex<Option<mpsc::Sender<()>>>,
    ended: Mutex<mpsc::Receiver<()>>,
    stopping: watch::Sender<bool>,
}

/// Held by a running WebSocket task.
struct LiveTask {
    _entry: mpsc::Sender<()>,
    stopping: watch::Receiver<bool>,
}

impl Lifecycle {
    fn new() -> Self {
        let (entry, ended) = mpsc::channel(1);
        Self {
            entry: std::sync::Mutex::new(Some(entry)),
            ended: Mutex::new(ended),
            stopping: watch::channel(false).0,
        }
    }

    /// `None` once shutdown has begun: the task must not start.
    fn enter(&self) -> Option<LiveTask> {
        let entry = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
        entry.as_ref().map(|entry| LiveTask {
            _entry: entry.clone(),
            stopping: self.stopping.subscribe(),
        })
    }

    fn begin_shutdown(&self) {
        self.entry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.stopping.send_replace(true);
    }

    /// Resolves once shutdown has begun.
    fn stopping(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut stopping = self.stopping.subscribe();
        async move {
            let _ = stopping.wait_for(|stopping| *stopping).await;
        }
    }

    /// After `begin_shutdown`: resolves once every task that entered is over.
    async fn tasks_ended(&self) {
        while self.ended.lock().await.recv().await.is_some() {}
    }
}

impl LiveTask {
    /// Resolves once shutdown has begun, also when it began before this call.
    async fn stopping(&mut self) {
        let _ = self.stopping.wait_for(|stopping| *stopping).await;
    }
}

#[derive(Clone)]
struct RelayState {
    store: Store,
    audit: AuditLog,
    timeouts: RelayTimeouts,
    lifecycle: Arc<Lifecycle>,
    agents: Arc<Mutex<HashMap<String, AgentHandle>>>,
    pending: Arc<Mutex<HashMap<String, PendingSession>>>,
    challenges: Arc<ChallengeSigner>,
    /// Challenges already spent by an enrolled operator, until they expire.
    spent_challenges: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    operator_sessions: Arc<Mutex<HashMap<[u8; 32], OperatorSession>>>,
    /// Operator sessions from their request until they end, pending or paired.
    live_sessions: Arc<Mutex<HashMap<String, LiveSession>>>,
}

impl RelayState {
    fn new(store: Store) -> Result<Self, RevttyError> {
        Ok(Self {
            audit: AuditLog::start(store.clone()),
            store,
            timeouts: RELAY_TIMEOUTS,
            lifecycle: Arc::new(Lifecycle::new()),
            agents: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            challenges: Arc::new(ChallengeSigner::new()?),
            spent_challenges: Arc::new(Mutex::new(HashMap::new())),
            operator_sessions: Arc::new(Mutex::new(HashMap::new())),
            live_sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    #[cfg(test)]
    fn with_timeouts(mut self, timeouts: RelayTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }
}

struct AgentHandle {
    /// The enrolled agent instance this connection authenticated as.
    agent_id: String,
    connection_id: Uuid,
    control: mpsc::Sender<ControlMessage>,
    active_sessions: usize,
    max_sessions: usize,
    /// Dropped when this registration is removed or replaced, which ends the connection's
    /// control loop even while operator sessions still hold `control`.
    _registration: oneshot::Sender<()>,
}

/// An operator session, from its request until it ends, and how to end it early when its
/// agent instance is removed or re-enrolled.
struct LiveSession {
    agent_id: String,
    cancel: oneshot::Sender<()>,
}

struct PendingSession {
    agent_name: String,
    agent_token_hash: [u8; 32],
    sender: Option<oneshot::Sender<WebSocket>>,
    decision_sender: Option<oneshot::Sender<AgentDecision>>,
}

#[derive(Clone, Copy)]
enum AgentDecision {
    Accepted,
    Rejected(SessionRejectReason),
}

#[derive(Clone, Copy)]
enum SessionKind {
    Probe,
    Shell,
    Exec,
}

impl SessionKind {
    fn offer(self, session_id: String, tunnel_token: String) -> ControlMessage {
        match self {
            Self::Probe => ControlMessage::ProbeOffer {
                version: CONTROL_PROTOCOL_VERSION,
                session_id,
                tunnel_token,
            },
            Self::Shell => ControlMessage::ShellOffer {
                version: CONTROL_PROTOCOL_VERSION,
                session_id,
                tunnel_token,
            },
            Self::Exec => ControlMessage::ExecOffer {
                version: CONTROL_PROTOCOL_VERSION,
                session_id,
                tunnel_token,
            },
        }
    }

    /// The session's kind in the audit; the command an exec runs travels only inside SSH.
    fn label(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Shell => "shell",
            Self::Exec => "exec",
        }
    }
}

/// What an operator challenge authorizes.
enum ChallengeScope<'a> {
    Agent(&'a str),
    /// Bound to the enrollment epoch: a list request signed before an enrollment is void
    /// after it, even when it was not spent because it listed nothing.
    List {
        epoch: u64,
    },
}

const CHALLENGE_PREFIX: &str = "rvc_";
const CHALLENGE_NONCE_LEN: usize = 16;
const CHALLENGE_EXPIRY_LEN: usize = 8;
const CHALLENGE_TAG_LEN: usize = 32;

/// Operator challenges carry their own authenticity: an HMAC binds scope, expiry and nonce
/// under a key that lives only in this relay process. Issuing one keeps no state, so an
/// unauthenticated flood cannot lock operators out.
struct ChallengeSigner {
    key: [u8; 64],
    started: Instant,
}

impl ChallengeSigner {
    fn new() -> Result<Self, RevttyError> {
        let mut key = [0_u8; 64];
        getrandom::fill(&mut key)
            .map_err(|error| RevttyError::runtime("generate challenge key", error))?;

        Ok(Self {
            key,
            started: Instant::now(),
        })
    }

    fn issue(&self, scope: &ChallengeScope<'_>) -> Result<String, RevttyError> {
        let mut nonce = [0_u8; CHALLENGE_NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|error| RevttyError::runtime("generate challenge nonce", error))?;
        let expires_at = u64::try_from(
            (Instant::now() + OPERATOR_CHALLENGE_TTL)
                .duration_since(self.started)
                .as_millis(),
        )
        .map_err(|_| RevttyError::message("relay uptime is outside the supported range"))?;

        let mut raw =
            Vec::with_capacity(CHALLENGE_NONCE_LEN + CHALLENGE_EXPIRY_LEN + CHALLENGE_TAG_LEN);
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&expires_at.to_be_bytes());
        raw.extend_from_slice(&self.mac(scope, expires_at, &nonce).finalize().into_bytes());

        Ok(format!("{CHALLENGE_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw)))
    }

    /// When `challenge` was issued by this process for `scope` and is still valid, returns
    /// its expiry.
    fn verify(&self, challenge: &str, scope: &ChallengeScope<'_>) -> Option<Instant> {
        let raw = URL_SAFE_NO_PAD
            .decode(challenge.strip_prefix(CHALLENGE_PREFIX)?)
            .ok()?;
        if raw.len() != CHALLENGE_NONCE_LEN + CHALLENGE_EXPIRY_LEN + CHALLENGE_TAG_LEN {
            return None;
        }

        let (nonce, rest) = raw.split_at(CHALLENGE_NONCE_LEN);
        let (expiry, tag) = rest.split_at(CHALLENGE_EXPIRY_LEN);
        let expires_at = u64::from_be_bytes(expiry.try_into().ok()?);

        // Constant-time tag comparison.
        self.mac(scope, expires_at, nonce).verify_slice(tag).ok()?;

        let expires_at = self
            .started
            .checked_add(Duration::from_millis(expires_at))?;
        (expires_at > Instant::now()).then_some(expires_at)
    }

    fn mac(&self, scope: &ChallengeScope<'_>, expires_at: u64, nonce: &[u8]) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new(&self.key.into());
        mac.update(b"revtty-operator-challenge-v1");
        match scope {
            // Agent names never contain NUL, so the separators keep scopes unambiguous.
            ChallengeScope::Agent(name) => {
                mac.update(b"\0agent\0");
                mac.update(name.as_bytes());
            }
            ChallengeScope::List { epoch } => {
                mac.update(b"\0list\0");
                mac.update(&epoch.to_be_bytes());
            }
        }
        mac.update(&expires_at.to_be_bytes());
        mac.update(nonce);
        mac
    }
}

struct OperatorSession {
    agent_name: String,
    /// The enrolled agent instance it was issued for; a re-enrolled agent of the same name
    /// is another instance.
    agent_id: String,
    /// SHA-256 fingerprint of the operator key whose signature opened this session.
    operator_fingerprint: String,
    expires_at: Instant,
}

pub async fn init(db: &FsPath) -> Result<(), RevttyError> {
    let _store = Store::open(db).await?;
    println!("relay database {}", db.display());
    println!("schema   ready");
    Ok(())
}

pub async fn create_enrollment(
    db: &FsPath,
    name: &str,
    operator_key_path: &FsPath,
    ttl_secs: u64,
    replace: bool,
) -> Result<(), RevttyError> {
    if !valid_name(name) {
        return Err(RevttyError::message(
            "agent names may contain only letters, digits, '.', '_' and '-'",
        ));
    }

    let encoded = fs::read_to_string(operator_key_path)
        .map_err(|error| RevttyError::runtime("read operator public key", error))?;
    let operator_key = PublicKey::from_openssh(&encoded)
        .map_err(|error| RevttyError::runtime("parse operator public key", error))?;

    if operator_key.algorithm() != Algorithm::Ed25519 {
        return Err(RevttyError::message(
            "v1 enrollment requires an Ed25519 operator key",
        ));
    }

    let operator_key = operator_key
        .to_openssh()
        .map_err(|error| RevttyError::runtime("encode operator public key", error))?;
    let store = Store::open(db).await?;
    let ttl = Duration::from_secs(ttl_secs);
    let enrollment = if replace {
        store
            .create_replacement_enrollment(name, &operator_key, ttl)
            .await?
    } else {
        store.create_enrollment(name, &operator_key, ttl).await?
    };

    println!("enrollment {}", enrollment.id);
    println!("target     {name}");
    if let Some(replaced) = &enrollment.replaces_agent_id {
        println!("replaces   {replaced}");
    }
    println!("expires    {}", enrollment.expires_at);
    println!("token      {}", enrollment.token.expose());
    Ok(())
}

pub async fn remove_agent(db: &FsPath, name: &str) -> Result<(), RevttyError> {
    let store = Store::open(db).await?;
    let Some(removed) = store.remove_agent(name).await? else {
        return Err(RevttyError::message(format!(
            "agent {name} is not enrolled"
        )));
    };

    println!("removed    {name}");
    println!("id         {}", removed.id);
    println!("enrollments cancelled {}", removed.cancelled_enrollments);
    println!(
        "A running relay closes its connections within {}s.",
        RELAY_TIMEOUTS.removal_sweep.as_secs()
    );
    Ok(())
}

pub async fn list_agents(db: &FsPath) -> Result<(), RevttyError> {
    let store = Store::open(db).await?;
    let agents = store.list_agents().await?;

    if agents.is_empty() {
        println!("No enrolled agents.");
        return Ok(());
    }

    for agent in agents {
        let host_fingerprint = public_key_fingerprint(&agent.host_key)?;
        println!(
            "{}\tid={}\tcreated={}\tlast_seen={}\tversion={}\thost={}\toperators={}",
            agent.name,
            agent.id,
            agent.created_at,
            agent
                .last_seen
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            agent.version.as_deref().unwrap_or("-"),
            host_fingerprint,
            agent.operators.join(",")
        );
    }

    Ok(())
}

pub async fn list_sessions(db: &FsPath, limit: u32) -> Result<(), RevttyError> {
    let store = Store::open(db).await?;
    let sessions = store.list_sessions(limit).await?;

    if sessions.is_empty() {
        println!("No sessions recorded.");
        return Ok(());
    }

    let time = |value: Option<i64>| value.map_or_else(|| "-".to_owned(), |value| value.to_string());
    for session in sessions {
        println!(
            "{}\t{}\t{}\toperator={}\trequested={}\taccepted={}\tpaired={}\tended={}\toutcome={}",
            session.id,
            session.agent_name,
            session.kind,
            session.operator_fingerprint,
            session.requested_at,
            time(session.accepted_at),
            time(session.paired_at),
            time(session.ended_at),
            session.outcome.as_deref().unwrap_or("-")
        );
    }

    Ok(())
}

pub async fn serve(bind: &str, db: &FsPath) -> Result<(), RevttyError> {
    // Before the relay says it listens: a signal right after that must not kill it.
    let mut interrupt = signal(SignalKind::interrupt())
        .map_err(|error| RevttyError::runtime("listen for SIGINT", error))?;
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|error| RevttyError::runtime("listen for SIGTERM", error))?;
    let shutdown = async move {
        tokio::select! {
            _ = interrupt.recv() => "SIGINT",
            _ = terminate.recv() => "SIGTERM",
        }
    };

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| RevttyError::runtime("bind relay", error))?;

    // The bound address, not the requested one: `--bind 127.0.0.1:0` picks a free port.
    let address = listener
        .local_addr()
        .map_err(|error| RevttyError::runtime("read relay listen address", error))?;

    let store = Store::open(db).await?;
    let interrupted = store.close_interrupted_sessions().await?;
    if interrupted > 0 {
        tracing::info!("marked {interrupted} sessions of a previous relay process as interrupted");
    }
    let state = RelayState::new(store)?;
    spawn_removal_sweep(state.clone());

    tracing::info!("revtty relay listening on {address}");
    serve_until(listener, state, shutdown).await
}

/// Serves until `shutdown` resolves, then stops accepting connections, finishes the requests
/// in flight, ends every control connection and operator session (audited `interrupted`) and
/// writes the queued audit records, all within `timeouts.shutdown`.
async fn serve_until(
    listener: tokio::net::TcpListener,
    state: RelayState,
    shutdown: impl Future<Output = &'static str>,
) -> Result<(), RevttyError> {
    let lifecycle = Arc::clone(&state.lifecycle);
    let audit = state.audit.clone();
    let grace = state.timeouts.shutdown;
    let server = axum::serve(listener, router(state))
        .with_graceful_shutdown(lifecycle.stopping())
        .into_future();
    tokio::pin!(server);

    let signal = tokio::select! {
        served = &mut server => {
            return served.map_err(|error| RevttyError::runtime("serve relay", error));
        }
        signal = shutdown => signal,
    };
    tracing::info!("{signal}: relay stopping");
    lifecycle.begin_shutdown();

    let stopped = tokio::time::timeout(grace, async {
        let served = server
            .await
            .map_err(|error| RevttyError::runtime("serve relay", error));
        lifecycle.tasks_ended().await;
        // Every session has queued its end by now.
        let audited = audit.flush().await.map_err(|error| {
            RevttyError::message(format!(
                "{error}; the relay's next start marks the sessions still open as interrupted"
            ))
        });
        served.and(audited)
    })
    .await;
    match stopped {
        Ok(Ok(())) => {
            tracing::info!("relay stopped");
            Ok(())
        }
        Ok(Err(error)) => Err(error),
        Err(_) => Err(RevttyError::message(format!(
            "relay did not stop within {}s; its next start marks the sessions still open as \
             interrupted",
            grace.as_secs()
        ))),
    }
}

fn router(state: RelayState) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/enroll", post(enroll_agent))
        .route("/v1/operator/list/challenge", post(operator_list_challenge))
        .route("/v1/operator/list", post(operator_list))
        .route("/v1/operator/challenge/{name}", post(operator_challenge))
        .route("/v1/operator/auth/{name}", post(operator_auth))
        .route("/v1/agent/{name}", get(persistent_agent_upgrade))
        .route("/v1/agent/{name}/check", post(agent_credential_check))
        .route("/v1/agent/{name}/rotate", post(agent_rotate))
        .route(
            "/v1/agent/{name}/rotate/confirm",
            post(agent_rotate_confirm),
        )
        .route("/v1/status/{name}", get(operator_status))
        .route("/v1/probe/{name}", get(persistent_probe_upgrade))
        .route("/v1/connect/{name}", get(persistent_connect_upgrade))
        .route("/v1/exec/{name}", get(persistent_exec_upgrade))
        .route("/v1/session/{session_id}", get(persistent_session_upgrade))
        .with_state(state)
}

async fn enroll_agent(
    State(state): State<RelayState>,
    Json(request): Json<EnrollRequest>,
) -> Response {
    let mut host_key = match PublicKey::from_openssh(&request.host_key) {
        Ok(key) if key.algorithm() == Algorithm::Ed25519 => key,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "v1 enrollment requires an Ed25519 host key",
            )
                .into_response();
        }
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid SSH host key").into_response(),
    };

    // Key material only: the comment is text from whoever enrolled, handed to every
    // operator, and a client before 4f30334 would write one with a line break into
    // `known_hosts` as a pin of its own.
    host_key.set_comment("");
    let host_key = match host_key.to_openssh() {
        Ok(key) => key,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    // The relay cannot verify a proof, only bound what it stores and hands to operators.
    if request
        .host_key_proof
        .as_deref()
        .is_some_and(|proof| !crate::pairing::is_mac(proof))
    {
        return (StatusCode::BAD_REQUEST, "invalid host key proof").into_response();
    }

    match state
        .store
        .consume_enrollment(
            &request.token,
            &host_key,
            request.host_key_proof.as_deref(),
            Some(&request.version),
        )
        .await
    {
        Ok(credential) => (
            StatusCode::CREATED,
            Json(EnrollResponse {
                agent_id: credential.id,
                name: credential.name,
                control_token: credential.control_token.expose().to_owned(),
                operator_key: credential.operator_key,
            }),
        )
            .into_response(),
        Err(error) => {
            tracing::warn!("enrollment rejected: {error}");
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

async fn operator_challenge(State(state): State<RelayState>, Path(name): Path<String>) -> Response {
    if !valid_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid agent name").into_response();
    }

    // No lookup: whether the agent exists is not revealed before authentication.
    issue_operator_challenge(&state, &ChallengeScope::Agent(&name))
}

async fn operator_list_challenge(State(state): State<RelayState>) -> Response {
    let epoch = match state.store.enrollment_epoch().await {
        Ok(epoch) => epoch,
        Err(error) => {
            tracing::error!("operator list challenge lookup failed: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    issue_operator_challenge(&state, &ChallengeScope::List { epoch })
}

fn issue_operator_challenge(state: &RelayState, scope: &ChallengeScope<'_>) -> Response {
    match state.challenges.issue(scope) {
        Ok(challenge) => Json(OperatorChallengeResponse {
            challenge,
            expires_in_secs: OPERATOR_CHALLENGE_TTL.as_secs(),
        })
        .into_response(),
        Err(error) => {
            tracing::error!("operator challenge generation failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Makes a verified challenge single-use. Only challenges signed by an enrolled operator are
/// recorded, so outsiders cannot fill the set; a full set refuses instead of evicting a
/// challenge that is still valid, which would allow its replay.
async fn spend_challenge(
    state: &RelayState,
    challenge: &str,
    expires_at: Instant,
) -> Result<(), StatusCode> {
    let mut spent = state.spent_challenges.lock().await;
    let now = Instant::now();
    // A challenge verified before its expiry may only get here after it, when its spent
    // record (which expires with it) can already be purged: past the expiry it is void.
    if expires_at <= now {
        return Err(StatusCode::UNAUTHORIZED);
    }
    spent.retain(|_, expiry| *expiry > now);

    let key = hash_token(challenge);
    if spent.contains_key(&key) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if spent.len() >= MAX_PENDING_OPERATOR_AUTH {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    spent.insert(key, expires_at);
    Ok(())
}

async fn operator_auth(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    Json(request): Json<OperatorAuthRequest>,
) -> Response {
    if !valid_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid agent name").into_response();
    }

    let Some(expires_at) = state
        .challenges
        .verify(&request.challenge, &ChallengeScope::Agent(&name))
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let signature = match SshSig::from_pem(request.signature.as_bytes()) {
        Ok(signature) => signature,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    // The signature names its key; it counts only if that key is one of the agent's
    // operators, and only once it verifies.
    let operator_key = PublicKey::from(signature.public_key().clone());
    if operator_key.algorithm() != Algorithm::Ed25519 {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let operator_fingerprint = operator_key.fingerprint(HashAlg::Sha256).to_string();

    let agent = match state.store.get_agent(&name).await {
        Ok(Some(agent)) => agent,
        // Same answer as a bad signature: agent names stay private.
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::error!("operator auth lookup failed: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if !agent.operators.contains(&operator_fingerprint) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let message = operator_auth_message(&name, &request.challenge);

    if operator_key
        .verify(OPERATOR_AUTH_NAMESPACE, message.as_bytes(), &signature)
        .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if let Err(status) = spend_challenge(&state, &request.challenge, expires_at).await {
        return status.into_response();
    }

    let session_token = match SecretToken::generate("rvo") {
        Ok(token) => token,
        Err(error) => {
            tracing::error!("operator session token generation failed: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let now = Instant::now();
    let mut sessions = state.operator_sessions.lock().await;
    sessions.retain(|_, value| value.expires_at > now);
    if sessions.len() >= MAX_PENDING_OPERATOR_AUTH {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    sessions.insert(
        session_token.hash(),
        OperatorSession {
            agent_name: name,
            agent_id: agent.id,
            operator_fingerprint,
            expires_at: now + OPERATOR_SESSION_TTL,
        },
    );

    (
        StatusCode::CREATED,
        Json(OperatorAuthResponse {
            session_token: session_token.expose().to_owned(),
            expires_in_secs: OPERATOR_SESSION_TTL.as_secs(),
            host_key: agent.host_key,
            host_key_proof: agent.host_key_proof,
        }),
    )
        .into_response()
}

async fn operator_list(
    State(state): State<RelayState>,
    Json(request): Json<OperatorListRequest>,
) -> Response {
    // The epoch and the agents come from one snapshot, so an enrollment either voids the
    // challenge or is not part of the answer.
    let (epoch, agents) = match state.store.list_agents_with_epoch().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::error!("operator list lookup failed: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let Some(expires_at) = state
        .challenges
        .verify(&request.challenge, &ChallengeScope::List { epoch })
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let operator_key = match PublicKey::from_openssh(&request.operator_key) {
        Ok(key) if key.algorithm() == Algorithm::Ed25519 => key,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let signature = match SshSig::from_pem(request.signature.as_bytes()) {
        Ok(signature) => signature,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let message = operator_list_auth_message(&request.challenge);

    if operator_key
        .verify(OPERATOR_AUTH_NAMESPACE, message.as_bytes(), &signature)
        .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let operator_fingerprint = operator_key.fingerprint(HashAlg::Sha256).to_string();

    let runtime = {
        let connected = state.agents.lock().await;
        connected
            .values()
            .map(|agent| {
                (
                    agent.agent_id.clone(),
                    (agent.active_sessions, agent.max_sessions),
                )
            })
            .collect::<HashMap<_, _>>()
    };

    let mut visible = Vec::new();
    for agent in agents {
        if !agent.operators.contains(&operator_fingerprint) {
            continue;
        }

        let live = runtime.get(&agent.id).copied();

        visible.push(AgentStatusResponse {
            id: agent.id,
            name: agent.name.clone(),
            online: live.is_some(),
            active_sessions: live.map_or(0, |value| value.0),
            max_sessions: live.and_then(|value| (value.1 > 0).then_some(value.1)),
            created_at: agent.created_at,
            last_seen: agent.last_seen,
            version: agent.version,
        });
    }

    // Replaying a request that listed nothing reveals nothing, and the epoch voids it once
    // an enrollment could change that; only an enrolled operator's request is recorded.
    if !visible.is_empty()
        && let Err(status) = spend_challenge(&state, &request.challenge, expires_at).await
    {
        return status.into_response();
    }

    Json(AgentListResponse { agents: visible }).into_response()
}

async fn operator_status(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid agent name").into_response();
    }

    let Some(session) = consume_operator_session(&state, &name, &headers).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let agent = match state.store.get_agent(&name).await {
        // Re-enrolled since the credential was checked: another instance, which this
        // operator may not be authorized for.
        Ok(Some(agent)) if agent.id != session.agent_id => {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        Ok(Some(agent)) => agent,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!("operator status lookup failed: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let runtime = {
        let agents = state.agents.lock().await;
        agents
            .get(&name)
            .filter(|connected| connected.agent_id == agent.id)
            .map(|connected| (connected.active_sessions, connected.max_sessions))
    };

    Json(AgentStatusResponse {
        id: agent.id,
        name: agent.name,
        online: runtime.is_some(),
        active_sessions: runtime.map_or(0, |value| value.0),
        max_sessions: runtime.and_then(|value| (value.1 > 0).then_some(value.1)),
        created_at: agent.created_at,
        last_seen: agent.last_seen,
        version: agent.version,
    })
    .into_response()
}

async fn persistent_probe_upgrade(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    persistent_operator_upgrade(state, name, headers, ws, SessionKind::Probe).await
}

async fn persistent_connect_upgrade(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    persistent_operator_upgrade(state, name, headers, ws, SessionKind::Shell).await
}

async fn persistent_exec_upgrade(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    persistent_operator_upgrade(state, name, headers, ws, SessionKind::Exec).await
}

async fn persistent_operator_upgrade(
    state: RelayState,
    name: String,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
    kind: SessionKind,
) -> Response {
    if !valid_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid agent name").into_response();
    }

    let Some(session) = consume_operator_session(&state, &name, &headers).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let control = {
        let agents = state.agents.lock().await;
        agents
            .get(&name)
            .filter(|agent| agent.agent_id == session.agent_id)
            .map(|agent| agent.control.clone())
    };

    let Some(control) = control else {
        return (StatusCode::NOT_FOUND, "agent is offline").into_response();
    };

    ws.max_message_size(MAX_MESSAGE_SIZE)
        .max_frame_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| {
            handle_operator_session(
                socket,
                state,
                name,
                session.agent_id,
                session.operator_fingerprint,
                control,
                kind,
            )
        })
        .into_response()
}

/// Spends the operator credential in `headers`, which is valid once and only for `agent_name`,
/// and only while the operator is still one of that agent instance's operators.
async fn consume_operator_session(
    state: &RelayState,
    agent_name: &str,
    headers: &HeaderMap,
) -> Option<OperatorSession> {
    let token = bearer_token(headers)?;

    let session = {
        let mut sessions = state.operator_sessions.lock().await;
        sessions.remove(&hash_token(token))
    }?;

    if session.agent_name != agent_name || session.expires_at <= Instant::now() {
        return None;
    }

    match state
        .store
        .operator_authorized(&session.agent_id, &session.operator_fingerprint)
        .await
    {
        Ok(true) => Some(session),
        Ok(false) => None,
        Err(error) => {
            tracing::error!("operator session check failed: {error}");
            None
        }
    }
}

async fn persistent_agent_upgrade(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !valid_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid agent name").into_response();
    }

    let Some(token) = bearer_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let agent_id = match state.store.authenticate_agent(&name, token).await {
        Ok(Some(agent_id)) => agent_id,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::error!("agent authentication failed: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if let Err(error) = state.store.mark_seen(&agent_id, None).await {
        tracing::error!("failed to update agent presence: {error}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    ws.max_message_size(MAX_MESSAGE_SIZE)
        .max_frame_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| async move {
            let Some(mut task) = state.lifecycle.enter() else {
                return;
            };
            // From the Hello on: a stopping relay must not wait for it.
            tokio::select! {
                () = handle_agent(socket, state, name, agent_id) => {}
                () = task.stopping() => {}
            }
        })
        .into_response()
}

/// Lets `agent doctor` validate its control credential without opening a control channel,
/// which would replace the running agent's registration.
async fn agent_credential_check(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid agent name").into_response();
    }

    let Some(token) = bearer_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    match state.store.authenticate_agent(&name, token).await {
        Ok(Some(_)) => StatusCode::NO_CONTENT.into_response(),
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::error!("agent credential check failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Starts a control credential rotation, authenticated with the current credential.
async fn agent_rotate(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AgentRotateRequest>,
) -> Response {
    if !valid_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid agent name").into_response();
    }
    let Some(token) = bearer_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let next_hash = match URL_SAFE_NO_PAD
        .decode(&request.next_hash)
        .ok()
        .and_then(|hash| <[u8; 32]>::try_from(hash).ok())
    {
        Some(hash) => hash,
        None => return (StatusCode::BAD_REQUEST, "invalid credential hash").into_response(),
    };

    match state.store.begin_rotation(&name, token, next_hash).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::error!("agent {name} credential rotation failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Completes a rotation, authenticated with the new credential; repeating it is harmless.
async fn agent_rotate_confirm(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid agent name").into_response();
    }
    let Some(token) = bearer_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    match state.store.confirm_rotation(&name, token).await {
        Ok(RotationConfirmation::Promoted) => {
            tracing::info!("agent {name} rotated its control credential");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(RotationConfirmation::AlreadyCurrent) => StatusCode::NO_CONTENT.into_response(),
        Ok(RotationConfirmation::Rejected) => StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::error!("agent {name} credential rotation failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn persistent_session_upgrade(
    State(state): State<RelayState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let token_hash = hash_token(token);

    let sender = {
        let mut pending = state.pending.lock().await;
        let Some(session) = pending.get_mut(&session_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };

        if session.agent_token_hash != token_hash {
            return StatusCode::UNAUTHORIZED.into_response();
        }

        let Some(sender) = session.sender.take() else {
            return StatusCode::NOT_FOUND.into_response();
        };

        sender
    };

    ws.max_message_size(MAX_MESSAGE_SIZE)
        .max_frame_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| attach_reserved_agent_session(socket, sender))
        .into_response()
}

async fn handle_agent(socket: WebSocket, state: RelayState, name: String, agent_id: String) {
    let timeouts = state.timeouts;
    let (mut sender, mut receiver) = socket.split();

    // Registered only after a valid `Hello`: an agent speaking another protocol version must
    // not be reported online or offered sessions.
    let Some((agent_version, active_sessions, max_sessions)) =
        receive_agent_hello(&mut sender, &mut receiver, &name, timeouts).await
    else {
        return;
    };

    let connection_id = Uuid::new_v4();
    let (control_tx, mut control_rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);
    let (registration, deregistered) = oneshot::channel::<()>();

    {
        // Claimed in the database and registered in memory under one lock: two connections
        // of the same agent cannot end up current in one place and replaced in the other.
        // From the claim on, the reports of any connection this one replaces are refused.
        let mut agents = state.agents.lock().await;
        match state
            .store
            .claim_control_connection(&agent_id, &connection_id.to_string())
            .await
        {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                tracing::error!("failed to register agent {name}: {error}");
                return;
            }
        }
        agents.insert(
            name.clone(),
            AgentHandle {
                agent_id: agent_id.clone(),
                connection_id,
                control: control_tx,
                active_sessions,
                max_sessions,
                _registration: registration,
            },
        );
    }

    if let Err(error) = state.store.mark_seen(&agent_id, Some(&agent_version)).await {
        tracing::error!("failed to persist agent hello: {error}");
    }

    tracing::info!("agent online: {name}");

    let idle = tokio::time::sleep(timeouts.agent_idle);
    tokio::pin!(idle);

    // Everything the connection does stops once its registration goes, a write or a store
    // call in progress included: removed, replaced by a newer connection, or swept as no
    // longer enrolled.
    let serve = async {
        loop {
            tokio::select! {
                control = control_rx.recv() => {
                    let Some(control) = control else {
                        break;
                    };

                    let Ok(text) = serde_json::to_string(&control) else {
                        break;
                    };

                    let sent =
                        tokio::time::timeout(timeouts.control_send, sender.send(Message::Text(text.into())))
                            .await;
                    if !matches!(sent, Ok(Ok(()))) {
                        break;
                    }
                }
                () = &mut idle => {
                    tracing::warn!(
                        "agent {name} silent for {}s; dropping its control connection",
                        timeouts.agent_idle.as_secs()
                    );
                    break;
                }
                message = receiver.next() => {
                    idle.as_mut()
                        .reset(tokio::time::Instant::now() + timeouts.agent_idle);

                    match message {
                        Some(Ok(Message::Text(text))) => {
                            if let Ok(control) = serde_json::from_str::<ControlMessage>(&text) {
                                match control {
                                    ControlMessage::Hello {
                                        version,
                                        name: hello_name,
                                        agent_version,
                                        active_sessions,
                                        max_sessions,
                                    } if version == CONTROL_PROTOCOL_VERSION && hello_name == name => {
                                        {
                                            let mut agents = state.agents.lock().await;
                                            if let Some(agent) = agents
                                                .get_mut(&name)
                                                .filter(|agent| agent.connection_id == connection_id)
                                            {
                                                agent.active_sessions = active_sessions;
                                                agent.max_sessions = max_sessions;
                                            }
                                        }

                                        if let Err(error) =
                                            state.store.mark_seen(&agent_id, Some(&agent_version)).await
                                        {
                                            tracing::error!("failed to persist agent hello: {error}");
                                        }
                                    }
                                    ControlMessage::Heartbeat {
                                        version,
                                        active_sessions,
                                    } if version == CONTROL_PROTOCOL_VERSION => {
                                        {
                                            let mut agents = state.agents.lock().await;
                                            if let Some(agent) = agents
                                                .get_mut(&name)
                                                .filter(|agent| agent.connection_id == connection_id)
                                            {
                                                agent.active_sessions = active_sessions;
                                            }
                                        }

                                        if let Err(error) = state.store.mark_seen(&agent_id, None).await {
                                            tracing::error!("failed to persist agent heartbeat: {error}");
                                        }
                                    }
                                    ControlMessage::SessionAccept {
                                        version,
                                        session_id,
                                    } if version == CONTROL_PROTOCOL_VERSION => {
                                        record_agent_decision(
                                            &state,
                                            &name,
                                            &session_id,
                                            AgentDecision::Accepted,
                                        )
                                        .await;
                                    }
                                    ControlMessage::SessionReject {
                                        version,
                                        session_id,
                                        reason,
                                    } if version == CONTROL_PROTOCOL_VERSION => {
                                        record_agent_decision(
                                            &state,
                                            &name,
                                            &session_id,
                                            AgentDecision::Rejected(reason),
                                        )
                                        .await;
                                    }
                                    ControlMessage::OperatorsReport {
                                        version,
                                        revision,
                                        operators,
                                    } if version == CONTROL_PROTOCOL_VERSION => {
                                        let keep = record_operators_report(
                                            &state,
                                            &name,
                                            &agent_id,
                                            connection_id,
                                            revision,
                                            &operators,
                                        )
                                        .await;
                                        if !keep {
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        Some(Ok(_)) => {}
                    }
                }
            }
        }
    };

    tokio::select! {
        () = serve => {}
        _ = deregistered => {}
    }
    // The connection is over: close it now, not after the cleanup below, which can wait for
    // the registry while another connection's registration holds it.
    drop(sender);
    drop(receiver);

    let mut agents = state.agents.lock().await;
    if agents
        .get(&name)
        .is_some_and(|agent| agent.connection_id == connection_id)
    {
        agents.remove(&name);
        tracing::info!("agent offline: {name}");
    }
}

/// Waits for the agent's `Hello` and validates it, returning its version and capacity.
/// An incompatible or missing `Hello` closes the connection, with an explicit error when
/// the agent spoke a different protocol version.
async fn receive_agent_hello(
    sender: &mut SplitSink<WebSocket, Message>,
    receiver: &mut SplitStream<WebSocket>,
    name: &str,
    timeouts: RelayTimeouts,
) -> Option<(String, usize, usize)> {
    let first = match tokio::time::timeout(timeouts.agent_hello, receiver.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        Ok(_) => return None,
        Err(_) => {
            tracing::warn!("agent {name} sent no hello; closing its control connection");
            return None;
        }
    };

    let rejection = match serde_json::from_str::<ControlMessage>(&first) {
        Ok(ControlMessage::Hello {
            version,
            name: hello_name,
            agent_version,
            active_sessions,
            max_sessions,
        }) if version == CONTROL_PROTOCOL_VERSION && hello_name == name => {
            return Some((agent_version, active_sessions, max_sessions));
        }
        Ok(ControlMessage::Hello { version, .. }) if version != CONTROL_PROTOCOL_VERSION => {
            format!(
                "incompatible control protocol version {version}; this relay speaks version {CONTROL_PROTOCOL_VERSION}"
            )
        }
        Ok(ControlMessage::Hello { .. }) => "hello names a different agent".to_owned(),
        _ => "expected hello as the first control message".to_owned(),
    };

    tracing::warn!("agent {name} rejected: {rejection}");
    let _ = tokio::time::timeout(
        timeouts.control_send,
        sender.send(Message::Text(
            format!("{SESSION_ERROR_PREFIX}{rejection}").into(),
        )),
    )
    .await;
    let _ = tokio::time::timeout(timeouts.control_send, sender.close()).await;
    None
}

/// Stores an agent's operator list when it comes from the agent's current control connection,
/// returning whether that connection may stay open. A list that is empty or holds an unusable
/// key is ignored whole: the relay never narrows or widens what the agent reported. A list
/// that cannot be stored closes the connection: the agent sends its list again after it
/// reconnects, and never otherwise.
async fn record_operators_report(
    state: &RelayState,
    name: &str,
    agent_id: &str,
    connection_id: Uuid,
    revision: u64,
    operators: &[String],
) -> bool {
    if i64::try_from(revision).is_err() {
        tracing::warn!(
            "agent {name} reported an out-of-range operator list revision; report ignored"
        );
        return true;
    }

    let mut reported = Vec::with_capacity(operators.len());
    for encoded in operators {
        match PublicKey::from_openssh(encoded) {
            Ok(key) if key.algorithm() == Algorithm::Ed25519 => reported.push(ReportedOperator {
                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                public_key: encoded.clone(),
            }),
            _ => {
                tracing::warn!("agent {name} reported an unusable operator key; report ignored");
                return true;
            }
        }
    }
    if reported.is_empty() {
        tracing::warn!("agent {name} reported no operators; report ignored");
        return true;
    }

    match state
        .store
        .apply_operators_report(agent_id, &connection_id.to_string(), revision, reported)
        .await
    {
        Ok(OperatorsReportOutcome::Applied { changed: true }) => {
            tracing::info!(
                "agent {name} operators updated to revision {revision} ({} operators)",
                operators.len()
            );
            true
        }
        Ok(OperatorsReportOutcome::Applied { changed: false }) => true,
        Ok(OperatorsReportOutcome::NotCurrent) => {
            tracing::warn!("agent {name} reported operators on a replaced connection; closing it");
            false
        }
        Err(error) => {
            tracing::error!(
                "failed to store operators of agent {name}: {error}; closing its control \
                 connection so that it reports them again"
            );
            false
        }
    }
}

async fn record_agent_decision(
    state: &RelayState,
    agent_name: &str,
    session_id: &str,
    decision: AgentDecision,
) {
    let sender = {
        let mut pending = state.pending.lock().await;
        if pending
            .get(session_id)
            .is_none_or(|session| session.agent_name.as_str() != agent_name)
        {
            return;
        }

        if matches!(decision, AgentDecision::Rejected(_)) {
            pending
                .remove(session_id)
                .and_then(|mut session| session.decision_sender.take())
        } else {
            pending
                .get_mut(session_id)
                .and_then(|session| session.decision_sender.take())
        }
    };

    if let Some(sender) = sender {
        let _ = sender.send(decision);
    }
}

/// Runs one operator session, registered as live until it ends so that the removal sweep can
/// end it when its agent instance is removed or re-enrolled, whatever stage it is in.
async fn handle_operator_session(
    operator_socket: WebSocket,
    state: RelayState,
    agent_name: String,
    agent_id: String,
    operator_fingerprint: String,
    control: mpsc::Sender<ControlMessage>,
    kind: SessionKind,
) {
    let Some(mut task) = state.lifecycle.enter() else {
        return;
    };
    let session_id = Uuid::new_v4().simple().to_string();
    // Audited before the sweep can see the session, so that even a session cancelled at once
    // has its request on record.
    state.audit.requested(
        &session_id,
        &agent_name,
        kind.label(),
        &operator_fingerprint,
    );
    let (cancel, cancelled) = oneshot::channel();
    state
        .live_sessions
        .lock()
        .await
        .insert(session_id.clone(), LiveSession { agent_id, cancel });

    tokio::select! {
        () = run_operator_session(
            operator_socket,
            state.clone(),
            session_id.clone(),
            agent_name.clone(),
            control,
            kind,
        ) => {}
        // Dropping the session closes both of its WebSockets.
        Ok(()) = cancelled => {
            state.pending.lock().await.remove(&session_id);
            state.audit.ended(&session_id, "agent_removed");
            tracing::info!(
                "{} {session_id} for {agent_name} closed: the agent was removed or re-enrolled",
                kind.label()
            );
        }
        () = task.stopping() => {
            state.pending.lock().await.remove(&session_id);
            state.audit.ended(&session_id, "interrupted");
            tracing::info!(
                "{} {session_id} for {agent_name} closed: the relay is stopping",
                kind.label()
            );
        }
    }

    state.live_sessions.lock().await.remove(&session_id);
}

async fn run_operator_session(
    mut operator_socket: WebSocket,
    state: RelayState,
    session_id: String,
    agent_name: String,
    control: mpsc::Sender<ControlMessage>,
    kind: SessionKind,
) {
    let agent_token = match SecretToken::generate("rvs") {
        Ok(token) => token,
        Err(error) => {
            tracing::error!("session token generation failed: {error}");
            state.audit.ended(&session_id, "internal_error");
            return;
        }
    };
    let (session_tx, session_rx) = oneshot::channel();
    let (decision_tx, decision_rx) = oneshot::channel();

    {
        let mut pending = state.pending.lock().await;
        pending.insert(
            session_id.clone(),
            PendingSession {
                agent_name: agent_name.clone(),
                agent_token_hash: agent_token.hash(),
                sender: Some(session_tx),
                decision_sender: Some(decision_tx),
            },
        );
    }

    // One deadline covers queueing the offer and the agent's decision: an agent whose
    // control channel is not draining must not hold the operator past it.
    let accept_deadline = tokio::time::Instant::now() + state.timeouts.agent_accept;
    let offer = kind.offer(session_id.clone(), agent_token.expose().to_owned());

    match tokio::time::timeout_at(accept_deadline, control.send(offer)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            state.pending.lock().await.remove(&session_id);
            state.audit.ended(&session_id, "agent_offline");
            return;
        }
        Err(_) => {
            state.pending.lock().await.remove(&session_id);
            state.audit.ended(&session_id, "agent_unresponsive");
            send_operator_session_error(&mut operator_socket, SESSION_NOT_ACCEPTED).await;
            tracing::warn!(
                "{} offer could not be queued for {agent_name}: {session_id}",
                kind.label()
            );
            return;
        }
    }

    tracing::info!("{} requested for {agent_name}: {session_id}", kind.label());

    match tokio::time::timeout_at(accept_deadline, decision_rx).await {
        Ok(Ok(AgentDecision::Accepted)) => {
            state.audit.accepted(&session_id);
            tracing::info!("{} accepted by {agent_name}: {session_id}", kind.label());
        }
        Ok(Ok(AgentDecision::Rejected(reason))) => {
            state.pending.lock().await.remove(&session_id);
            state.audit.ended(
                &session_id,
                &format!("rejected:{}", reject_reason_name(reason)),
            );
            let detail = match reason {
                SessionRejectReason::Busy => "agent is busy",
                SessionRejectReason::IncompatibleVersion => {
                    "agent rejected an incompatible protocol version"
                }
                SessionRejectReason::InternalError => "agent could not start the session",
            };
            send_operator_session_error(&mut operator_socket, detail).await;
            tracing::info!(
                "{} rejected by {agent_name}: {session_id} ({reason:?})",
                kind.label()
            );
            return;
        }
        _ => {
            state.pending.lock().await.remove(&session_id);
            state.audit.ended(&session_id, "accept_timeout");
            send_session_cancel(&control, &session_id).await;
            send_operator_session_error(&mut operator_socket, SESSION_NOT_ACCEPTED).await;
            tracing::warn!(
                "{} acceptance timed out for {agent_name}: {session_id}",
                kind.label()
            );
            return;
        }
    }

    match tokio::time::timeout(state.timeouts.data_tunnel, session_rx).await {
        Ok(Ok(agent_socket)) => {
            state.pending.lock().await.remove(&session_id);
            state.audit.paired(&session_id);
            tracing::info!("{} paired for {agent_name}: {session_id}", kind.label());
            let end = bridge_websockets(operator_socket, agent_socket).await;
            state.audit.ended(&session_id, end.outcome());
        }
        _ => {
            state.pending.lock().await.remove(&session_id);
            state.audit.ended(&session_id, "tunnel_timeout");
            send_session_cancel(&control, &session_id).await;
            send_operator_session_error(
                &mut operator_socket,
                "agent accepted the session but its data tunnel timed out",
            )
            .await;
            tracing::warn!(
                "{} data tunnel timed out for {agent_name}: {session_id}",
                kind.label()
            );
        }
    }
}

fn reject_reason_name(reason: SessionRejectReason) -> &'static str {
    match reason {
        SessionRejectReason::Busy => "busy",
        SessionRejectReason::IncompatibleVersion => "incompatible_version",
        SessionRejectReason::InternalError => "internal_error",
    }
}

async fn send_operator_session_error(socket: &mut WebSocket, detail: &str) {
    let text = format!("{SESSION_ERROR_PREFIX}{detail}");
    let _ = socket.send(Message::Text(text.into())).await;
}

/// Best effort: a control channel that is full belongs to an agent that is not draining it,
/// and the session is already abandoned on the relay side.
async fn send_session_cancel(control: &mpsc::Sender<ControlMessage>, session_id: &str) {
    let _ = control.try_send(ControlMessage::SessionCancel {
        version: CONTROL_PROTOCOL_VERSION,
        session_id: session_id.to_owned(),
    });
}

/// Checks every `timeouts.removal_sweep` that the agents the relay serves are still
/// enrolled, independently of their control connections: a removed or re-enrolled agent
/// instance loses its control connection and every session it is part of, also when only a
/// data tunnel is left.
fn spawn_removal_sweep(state: RelayState) {
    tokio::spawn(async move {
        let mut sweep = tokio::time::interval(state.timeouts.removal_sweep);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            sweep.tick().await;
            sweep_removed_agents(&state).await;
        }
    });
}

async fn sweep_removed_agents(state: &RelayState) {
    let mut served = state
        .agents
        .lock()
        .await
        .values()
        .map(|agent| agent.agent_id.clone())
        .collect::<HashSet<_>>();
    served.extend(
        state
            .live_sessions
            .lock()
            .await
            .values()
            .map(|session| session.agent_id.clone()),
    );
    if served.is_empty() {
        return;
    }

    let enrolled = match state
        .store
        .existing_agent_ids(served.iter().cloned().collect())
        .await
    {
        Ok(enrolled) => enrolled,
        // Without an answer nothing is closed, rather than every connection; the next sweep
        // asks again.
        Err(error) => {
            tracing::error!("removal sweep failed: {error}");
            return;
        }
    };
    let removed = served
        .difference(&enrolled)
        .cloned()
        .collect::<HashSet<_>>();
    if removed.is_empty() {
        return;
    }

    state.agents.lock().await.retain(|name, agent| {
        let keep = !removed.contains(&agent.agent_id);
        if !keep {
            tracing::info!(
                "agent {name} was removed or re-enrolled; closing its control connection"
            );
        }
        keep
    });

    let cancelled = {
        let mut sessions = state.live_sessions.lock().await;
        let ids = sessions
            .iter()
            .filter(|(_, session)| removed.contains(&session.agent_id))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| sessions.remove(&id))
            .collect::<Vec<_>>()
    };
    for session in cancelled {
        let _ = session.cancel.send(());
    }
}

async fn attach_reserved_agent_session(socket: WebSocket, sender: oneshot::Sender<WebSocket>) {
    let _ = sender.send(socket);
}

/// How a paired tunnel ended, as far as the relay can tell without reading SSH content.
enum TunnelEnd {
    /// One side closed the WebSocket with a close frame.
    Closed,
    OperatorLost,
    AgentLost,
}

impl TunnelEnd {
    fn outcome(&self) -> &'static str {
        match self {
            Self::Closed => "completed",
            Self::OperatorLost => "operator_disconnected",
            Self::AgentLost => "agent_disconnected",
        }
    }
}

async fn bridge_websockets(operator: WebSocket, agent: WebSocket) -> TunnelEnd {
    let (mut operator_tx, mut operator_rx) = operator.split();
    let (mut agent_tx, mut agent_rx) = agent.split();

    let operator_to_agent = async {
        loop {
            match operator_rx.next().await {
                Some(Ok(Message::Close(frame))) => {
                    let _ = agent_tx.send(Message::Close(frame)).await;
                    return TunnelEnd::Closed;
                }
                Some(Ok(message)) => {
                    if agent_tx.send(message).await.is_err() {
                        return TunnelEnd::AgentLost;
                    }
                }
                Some(Err(_)) | None => return TunnelEnd::OperatorLost,
            }
        }
    };

    let agent_to_operator = async {
        loop {
            match agent_rx.next().await {
                Some(Ok(Message::Close(frame))) => {
                    let _ = operator_tx.send(Message::Close(frame)).await;
                    return TunnelEnd::Closed;
                }
                Some(Ok(message)) => {
                    if operator_tx.send(message).await.is_err() {
                        return TunnelEnd::OperatorLost;
                    }
                }
                Some(Err(_)) | None => return TunnelEnd::AgentLost,
            }
        }
    };

    tokio::select! {
        end = operator_to_agent => end,
        end = agent_to_operator => end,
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn public_key_fingerprint(encoded: &str) -> Result<String, RevttyError> {
    let key = PublicKey::from_openssh(encoded)
        .map_err(|error| RevttyError::runtime("parse persisted SSH public key", error))?;
    Ok(key.fingerprint(HashAlg::Sha256).to_string())
}

pub async fn doctor(db: &FsPath) -> Result<(), RevttyError> {
    let store = Store::open(db).await?;
    let agents = store.list_agents().await?;
    let schema = store.schema_version().await?;
    // Whoever can write the database, or replace it through its directory, can enroll
    // agents and swap their keys.
    crate::config::check_not_writable_by_others(db)?;
    let directory = db
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| FsPath::new("."));
    let directory_warning = crate::config::check_shared_directory(directory)?;

    println!("relay      ready");
    println!("protocol   v{}", crate::protocol::CONTROL_PROTOCOL_VERSION);
    println!("database   {}", db.display());
    println!("schema     v{schema}");
    println!("agents     {}", agents.len());
    if let Some(warning) = directory_warning {
        println!("warning    {warning}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::Arc;
    use std::time::Duration;

    use futures_util::{SinkExt, StreamExt};
    use reqwest_websocket::Message as ClientMessage;
    use russh::Preferred;
    use russh::client;
    use russh::keys::key::{PrivateKeyWithHashAlg, safe_rng};
    use russh::keys::{
        Algorithm, HashAlg as RusshHashAlg, PrivateKey, PublicKey, PublicKeyOrCertificate,
    };
    use russh::server;
    use tokio::sync::{mpsc, oneshot};
    use uuid::Uuid;

    use super::{
        AgentDecision, AgentHandle, Lifecycle, OperatorSession, PendingSession, RelayState,
        RelayTimeouts, record_agent_decision, record_operators_report, router, serve_until,
        spend_challenge,
    };
    use crate::error::RevttyError;
    use crate::protocol::{
        AgentListResponse, AgentStatusResponse, CONTROL_PROTOCOL_VERSION, ControlMessage,
        EnrollRequest, EnrollResponse, OPERATOR_AUTH_NAMESPACE, OperatorAuthRequest,
        OperatorAuthResponse, OperatorChallengeResponse, OperatorListRequest, ProbeResult,
        SESSION_ERROR_PREFIX, SessionRejectReason, operator_auth_message,
        operator_list_auth_message,
    };
    use crate::storage::Store;
    use crate::token::SecretToken;
    use crate::transport::{connect_websocket, websocket_byte_stream};

    struct TestServer {
        authorized_client: PublicKey,
    }

    impl server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            public_key: &PublicKey,
        ) -> Result<server::Auth, Self::Error> {
            if public_key == &self.authorized_client {
                Ok(server::Auth::Accept)
            } else {
                Ok(server::Auth::reject())
            }
        }
    }

    struct TestClient {
        expected_server_key: PublicKey,
    }

    impl client::Handler for TestClient {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            server_public_key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(matches!(
                server_public_key,
                PublicKeyOrCertificate::PublicKey { key, .. }
                    if key == &self.expected_server_key
            ))
        }
    }

    fn ed25519_key() -> PrivateKey {
        let mut rng = safe_rng();
        PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("generate Ed25519 key")
    }

    fn ed25519_only() -> Preferred {
        Preferred {
            key: Cow::Owned(vec![Algorithm::Ed25519]),
            ..Preferred::default()
        }
    }

    /// The first control message every agent sends.
    fn test_hello(name: &str) -> ClientMessage {
        ClientMessage::Text(
            serde_json::to_string(&ControlMessage::Hello {
                version: CONTROL_PROTOCOL_VERSION,
                name: name.to_owned(),
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                active_sessions: 0,
                max_sessions: 4,
            })
            .expect("encode agent hello"),
        )
    }

    #[tokio::test]
    async fn agent_decisions_are_scoped_and_rejection_cleans_pending() {
        let store = Store::open_in_memory().await.expect("open store");
        let state = RelayState::new(store).expect("create relay state");
        let (socket_tx, _socket_rx) = oneshot::channel();
        let (decision_tx, mut decision_rx) = oneshot::channel();

        state.pending.lock().await.insert(
            "session".to_owned(),
            PendingSession {
                agent_name: "demo".to_owned(),
                agent_token_hash: [7; 32],
                sender: Some(socket_tx),
                decision_sender: Some(decision_tx),
            },
        );

        record_agent_decision(&state, "other-agent", "session", AgentDecision::Accepted).await;
        assert!(decision_rx.try_recv().is_err());

        record_agent_decision(
            &state,
            "demo",
            "session",
            AgentDecision::Rejected(SessionRejectReason::Busy),
        )
        .await;

        assert!(matches!(
            decision_rx.await.expect("receive decision"),
            AgentDecision::Rejected(SessionRejectReason::Busy)
        ));
        assert!(!state.pending.lock().await.contains_key("session"));
    }

    #[tokio::test]
    async fn persistent_enrollment_and_agent_auth_round_trip() {
        let store = Store::open_in_memory()
            .await
            .expect("open in-memory relay store");
        let state = RelayState::new(store.clone()).expect("create relay state");
        let app = router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let address = listener.local_addr().expect("test relay address");

        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test relay");
        });

        let operator_key = ed25519_key()
            .public_key()
            .to_openssh()
            .expect("operator key");
        let host_key = ed25519_key().public_key().to_openssh().expect("host key");

        let enrollment = store
            .create_enrollment("persistent-demo", &operator_key, Duration::from_secs(60))
            .await
            .expect("create enrollment");

        let http = reqwest::Client::new();
        let response = http
            .post(format!("http://{address}/v1/enroll"))
            .json(&EnrollRequest {
                token: enrollment.token.expose().to_owned(),
                host_key,
                version: "0.1.0".to_owned(),
                host_key_proof: None,
            })
            .send()
            .await
            .expect("send enrollment request");

        assert_eq!(response.status(), reqwest::StatusCode::CREATED);

        let enrolled: EnrollResponse = response.json().await.expect("decode enrollment response");
        assert_eq!(enrolled.name, "persistent-demo");
        assert_eq!(enrolled.operator_key, operator_key);

        let websocket = connect_websocket(
            &http,
            &format!("ws://{address}"),
            "/v1/agent/persistent-demo",
            &enrolled.control_token,
        )
        .await
        .expect("connect persistent agent");

        drop(websocket);

        let reuse = http
            .post(format!("http://{address}/v1/enroll"))
            .json(&EnrollRequest {
                token: enrollment.token.expose().to_owned(),
                host_key: ed25519_key()
                    .public_key()
                    .to_openssh()
                    .expect("second host key"),
                version: "0.1.0".to_owned(),
                host_key_proof: None,
            })
            .send()
            .await
            .expect("send reused enrollment");

        assert_eq!(reuse.status(), reqwest::StatusCode::UNAUTHORIZED);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn host_key_proofs_are_bounded_stored_and_handed_to_operators() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let store = Store::open_in_memory().await.expect("open relay store");
        let operator = ed25519_key();
        let enrollment = store
            .create_enrollment(
                "proven",
                &operator.public_key().to_openssh().expect("operator key"),
                Duration::from_secs(60),
            )
            .await
            .expect("create enrollment");
        let (_state, base, server) = http_relay(store).await;
        let http = reqwest::Client::new();
        let host_key = ed25519_key().public_key().to_openssh().expect("host key");
        let enroll = |host_key_proof: String| {
            http.post(format!("{base}/v1/enroll"))
                .json(&EnrollRequest {
                    token: enrollment.token.expose().to_owned(),
                    host_key: host_key.clone(),
                    version: "0.1.0".to_owned(),
                    host_key_proof: Some(host_key_proof),
                })
                .send()
        };

        // The relay cannot check a proof, only that it is shaped like one; a refused request
        // leaves the enrollment unused.
        for malformed in [
            "not base64!".to_owned(),
            "A".repeat(4096),
            URL_SAFE_NO_PAD.encode([0_u8; 31]),
        ] {
            let response = enroll(malformed).await.expect("send enrollment");
            assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        }
        let proof = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let response = enroll(proof.clone()).await.expect("send enrollment");
        assert_eq!(response.status(), reqwest::StatusCode::CREATED);

        let challenge =
            fetch_challenge(&http, format!("{base}/v1/operator/challenge/proven")).await;
        let response = post_auth(&http, &base, "proven", &operator, &challenge).await;
        assert_eq!(response.status(), reqwest::StatusCode::CREATED);
        let auth: OperatorAuthResponse = response.json().await.expect("decode operator auth");
        assert_eq!(auth.host_key_proof.as_deref(), Some(proof.as_str()));

        server.abort();
    }

    #[tokio::test]
    async fn host_keys_are_stored_without_their_comment() {
        let store = Store::open_in_memory().await.expect("open relay store");
        let operator = ed25519_key();
        let enrollment = store
            .create_enrollment(
                "commented",
                &operator.public_key().to_openssh().expect("operator key"),
                Duration::from_secs(60),
            )
            .await
            .expect("create enrollment");
        let (_state, base, server) = http_relay(store.clone()).await;
        let http = reqwest::Client::new();
        let mut host_key = ed25519_key().public_key().clone();
        host_key.set_comment("admin@secret-host");

        let response = http
            .post(format!("{base}/v1/enroll"))
            .json(&EnrollRequest {
                token: enrollment.token.expose().to_owned(),
                host_key: host_key.to_openssh().expect("host key"),
                version: "0.1.0".to_owned(),
                host_key_proof: None,
            })
            .send()
            .await
            .expect("send enrollment");
        assert_eq!(response.status(), reqwest::StatusCode::CREATED);

        let agents = store.list_agents().await.expect("list agents");
        assert!(
            !agents[0].host_key.contains("secret-host"),
            "{}",
            agents[0].host_key
        );
        let challenge =
            fetch_challenge(&http, format!("{base}/v1/operator/challenge/commented")).await;
        let response = post_auth(&http, &base, "commented", &operator, &challenge).await;
        let auth: OperatorAuthResponse = response.json().await.expect("decode operator auth");
        let handed = PublicKey::from_openssh(&auth.host_key).expect("parse handed host key");
        assert_eq!(
            auth.host_key.split_whitespace().count(),
            2,
            "{}",
            auth.host_key
        );
        assert_eq!(handed.key_data(), host_key.key_data());

        server.abort();
    }

    #[tokio::test]
    async fn signed_operator_list_is_scoped_and_single_use() {
        let store = Store::open_in_memory()
            .await
            .expect("open in-memory relay store");
        let state = RelayState::new(store.clone()).expect("create relay state");
        let app = router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let address = listener.local_addr().expect("test relay address");

        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test relay");
        });

        let operator_private = ed25519_key();
        let operator_key = operator_private
            .public_key()
            .to_openssh()
            .expect("operator key");
        let other_operator_key = ed25519_key()
            .public_key()
            .to_openssh()
            .expect("other operator key");

        for (name, key) in [
            ("visible-agent", operator_key.as_str()),
            ("hidden-agent", other_operator_key.as_str()),
        ] {
            let enrollment = store
                .create_enrollment(name, key, Duration::from_secs(60))
                .await
                .expect("create enrollment");
            let host_key = ed25519_key().public_key().to_openssh().expect("host key");
            store
                .consume_enrollment(enrollment.token.expose(), &host_key, None, Some("0.1.0"))
                .await
                .expect("consume enrollment");
        }

        let http = reqwest::Client::new();
        let challenge_response = http
            .post(format!("http://{address}/v1/operator/list/challenge"))
            .send()
            .await
            .expect("request operator list challenge");
        assert_eq!(challenge_response.status(), reqwest::StatusCode::OK);

        let challenge: OperatorChallengeResponse = challenge_response
            .json()
            .await
            .expect("decode operator list challenge");
        let message = operator_list_auth_message(&challenge.challenge);
        let signature = operator_private
            .sign(
                OPERATOR_AUTH_NAMESPACE,
                RusshHashAlg::Sha256,
                message.as_bytes(),
            )
            .expect("sign operator list challenge")
            .to_pem(ssh_key::LineEnding::LF)
            .expect("encode operator list signature");

        let request = OperatorListRequest {
            operator_key,
            challenge: challenge.challenge,
            signature,
        };

        let list_response = http
            .post(format!("http://{address}/v1/operator/list"))
            .json(&request)
            .send()
            .await
            .expect("request authenticated agent list");
        assert_eq!(list_response.status(), reqwest::StatusCode::OK);

        let list: AgentListResponse = list_response.json().await.expect("decode agent list");
        assert_eq!(list.agents.len(), 1);
        assert_eq!(list.agents[0].name, "visible-agent");
        assert!(!list.agents[0].online);

        let replay = http
            .post(format!("http://{address}/v1/operator/list"))
            .json(&request)
            .send()
            .await
            .expect("replay operator list request");
        assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn signed_operator_probe_is_single_use() {
        let store = Store::open_in_memory()
            .await
            .expect("open in-memory relay store");
        let state = RelayState::new(store.clone()).expect("create relay state");
        let app = router(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let address = listener.local_addr().expect("test relay address");

        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test relay");
        });

        let operator_private = ed25519_key();
        let operator_key = operator_private
            .public_key()
            .to_openssh()
            .expect("operator key");
        let host_key = ed25519_key().public_key().to_openssh().expect("host key");

        let enrollment = store
            .create_enrollment("signed-demo", &operator_key, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let credential = store
            .consume_enrollment(enrollment.token.expose(), &host_key, None, Some("0.1.0"))
            .await
            .expect("consume enrollment");

        let relay = format!("ws://{address}");
        let http = reqwest::Client::new();
        let mut agent = connect_websocket(
            &http,
            &relay,
            "/v1/agent/signed-demo",
            credential.control_token.expose(),
        )
        .await
        .expect("connect persistent agent");
        agent
            .send(test_hello("signed-demo"))
            .await
            .expect("send agent hello");

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.agents.lock().await.contains_key("signed-demo") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("agent becomes visible");

        let (mut agent_sender, mut agent_receiver) = agent.split();
        let agent_http = http.clone();
        let agent_relay = relay.clone();
        let control_token = credential.control_token.expose().to_owned();

        let agent_task = tokio::spawn(async move {
            while let Some(message) = agent_receiver.next().await {
                if let ClientMessage::Text(text) = message.expect("agent control message") {
                    let control: ControlMessage =
                        serde_json::from_str(&text).expect("decode probe offer");

                    if let ControlMessage::ProbeOffer {
                        session_id,
                        tunnel_token,
                        ..
                    } = control
                    {
                        agent_sender
                            .send(ClientMessage::Text(
                                serde_json::to_string(&ControlMessage::SessionAccept {
                                    version: CONTROL_PROTOCOL_VERSION,
                                    session_id: session_id.clone(),
                                })
                                .expect("encode session accept"),
                            ))
                            .await
                            .expect("send session accept");

                        let path = format!("/v1/session/{session_id}");
                        let rejected =
                            connect_websocket(&agent_http, &agent_relay, &path, &control_token)
                                .await;
                        assert!(
                            rejected.is_err(),
                            "long-lived control credential must not open a data tunnel"
                        );

                        let mut session =
                            connect_websocket(&agent_http, &agent_relay, &path, &tunnel_token)
                                .await
                                .expect("connect authenticated agent session");

                        let replay =
                            connect_websocket(&agent_http, &agent_relay, &path, &tunnel_token)
                                .await;
                        assert!(
                            replay.is_err(),
                            "agent tunnel credential must be single-use"
                        );

                        let result = ProbeResult {
                            name: "signed-demo".to_owned(),
                            os: "test-os".to_owned(),
                            arch: "test-arch".to_owned(),
                            version: "test-version".to_owned(),
                        };

                        session
                            .send(ClientMessage::Text(
                                serde_json::to_string(&result).expect("encode probe result"),
                            ))
                            .await
                            .expect("send probe result");
                        return;
                    }
                }
            }

            panic!("agent control connection ended before signed probe offer");
        });

        let challenge_response = http
            .post(format!(
                "http://{address}/v1/operator/challenge/signed-demo"
            ))
            .send()
            .await
            .expect("request operator challenge");
        assert_eq!(challenge_response.status(), reqwest::StatusCode::OK);

        let challenge: OperatorChallengeResponse = challenge_response
            .json()
            .await
            .expect("decode operator challenge");

        let message = operator_auth_message("signed-demo", &challenge.challenge);
        let signature = operator_private
            .sign(
                OPERATOR_AUTH_NAMESPACE,
                RusshHashAlg::Sha256,
                message.as_bytes(),
            )
            .expect("sign operator challenge")
            .to_pem(ssh_key::LineEnding::LF)
            .expect("encode operator signature");

        let auth_response = http
            .post(format!("http://{address}/v1/operator/auth/signed-demo"))
            .json(&OperatorAuthRequest {
                challenge: challenge.challenge.clone(),
                signature,
            })
            .send()
            .await
            .expect("authenticate operator");
        assert_eq!(auth_response.status(), reqwest::StatusCode::CREATED);

        let auth: OperatorAuthResponse = auth_response
            .json()
            .await
            .expect("decode operator auth response");

        let replay = http
            .post(format!("http://{address}/v1/operator/auth/signed-demo"))
            .json(&OperatorAuthRequest {
                challenge: challenge.challenge,
                signature: "invalid".to_owned(),
            })
            .send()
            .await
            .expect("replay operator challenge");
        assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);

        let mut operator =
            connect_websocket(&http, &relay, "/v1/probe/signed-demo", &auth.session_token)
                .await
                .expect("connect signed operator probe");

        let response = tokio::time::timeout(Duration::from_secs(2), operator.next())
            .await
            .expect("signed probe result timeout")
            .expect("operator websocket closed")
            .expect("operator websocket error");

        let ClientMessage::Text(text) = response else {
            panic!("expected signed probe text result");
        };
        let result: ProbeResult = serde_json::from_str(&text).expect("decode signed probe result");
        assert_eq!(result.name, "signed-demo");

        let reused_session =
            connect_websocket(&http, &relay, "/v1/probe/signed-demo", &auth.session_token).await;
        assert!(reused_session.is_err());

        let status_challenge_response = http
            .post(format!(
                "http://{address}/v1/operator/challenge/signed-demo"
            ))
            .send()
            .await
            .expect("request status operator challenge");
        assert_eq!(status_challenge_response.status(), reqwest::StatusCode::OK);

        let status_challenge: OperatorChallengeResponse = status_challenge_response
            .json()
            .await
            .expect("decode status operator challenge");
        let status_message = operator_auth_message("signed-demo", &status_challenge.challenge);
        let status_signature = operator_private
            .sign(
                OPERATOR_AUTH_NAMESPACE,
                RusshHashAlg::Sha256,
                status_message.as_bytes(),
            )
            .expect("sign status operator challenge")
            .to_pem(ssh_key::LineEnding::LF)
            .expect("encode status operator signature");

        let status_auth_response = http
            .post(format!("http://{address}/v1/operator/auth/signed-demo"))
            .json(&OperatorAuthRequest {
                challenge: status_challenge.challenge,
                signature: status_signature,
            })
            .send()
            .await
            .expect("authenticate status operator");
        assert_eq!(status_auth_response.status(), reqwest::StatusCode::CREATED);

        let status_auth: OperatorAuthResponse = status_auth_response
            .json()
            .await
            .expect("decode status operator auth");

        let status_response = http
            .get(format!("http://{address}/v1/status/signed-demo"))
            .bearer_auth(&status_auth.session_token)
            .send()
            .await
            .expect("request authenticated status");
        assert_eq!(status_response.status(), reqwest::StatusCode::OK);

        let status: AgentStatusResponse =
            status_response.json().await.expect("decode agent status");
        assert_eq!(status.id, credential.id);
        assert_eq!(status.name, "signed-demo");
        assert!(!status.online);
        assert_eq!(status.active_sessions, 0);
        assert_eq!(status.max_sessions, None);
        assert_eq!(status.version.as_deref(), Some("0.1.0"));

        let reused_status = http
            .get(format!("http://{address}/v1/status/signed-demo"))
            .bearer_auth(&status_auth.session_token)
            .send()
            .await
            .expect("retry authenticated status");
        assert_eq!(reused_status.status(), reqwest::StatusCode::UNAUTHORIZED);

        agent_task.await.expect("agent test task");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn signed_operator_ssh_uses_enrolled_keys() {
        let store = Store::open_in_memory()
            .await
            .expect("open in-memory relay store");
        let state = RelayState::new(store.clone()).expect("create relay state");
        let app = router(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let address = listener.local_addr().expect("test relay address");

        let relay_server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test relay");
        });

        let operator_private = ed25519_key();
        let operator_public = operator_private.public_key().clone();
        let operator_key = operator_public.to_openssh().expect("operator key");

        let agent_private = ed25519_key();
        let expected_server_key = agent_private.public_key().clone();
        let host_key = expected_server_key.to_openssh().expect("agent host key");

        let enrollment = store
            .create_enrollment("signed-ssh", &operator_key, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let credential = store
            .consume_enrollment(enrollment.token.expose(), &host_key, None, Some("0.1.0"))
            .await
            .expect("consume enrollment");

        let relay = format!("ws://{address}");
        let http = reqwest::Client::new();
        let mut agent = connect_websocket(
            &http,
            &relay,
            "/v1/agent/signed-ssh",
            credential.control_token.expose(),
        )
        .await
        .expect("connect persistent agent");
        agent
            .send(test_hello("signed-ssh"))
            .await
            .expect("send agent hello");

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.agents.lock().await.contains_key("signed-ssh") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("agent becomes visible");

        let (mut agent_sender, mut agent_receiver) = agent.split();
        let agent_http = http.clone();
        let agent_relay = relay.clone();

        let agent_task = tokio::spawn(async move {
            while let Some(message) = agent_receiver.next().await {
                if let ClientMessage::Text(text) = message.expect("agent control message") {
                    let control: ControlMessage =
                        serde_json::from_str(&text).expect("decode SSH session offer");

                    if let ControlMessage::ProbeOffer {
                        session_id,
                        tunnel_token,
                        ..
                    } = control
                    {
                        agent_sender
                            .send(ClientMessage::Text(
                                serde_json::to_string(&ControlMessage::SessionAccept {
                                    version: CONTROL_PROTOCOL_VERSION,
                                    session_id: session_id.clone(),
                                })
                                .expect("encode session accept"),
                            ))
                            .await
                            .expect("send session accept");

                        let path = format!("/v1/session/{session_id}");
                        let websocket =
                            connect_websocket(&agent_http, &agent_relay, &path, &tunnel_token)
                                .await
                                .expect("connect authenticated agent SSH session");
                        let (server_stream, bridge_task) = websocket_byte_stream(websocket);

                        let server_config = server::Config {
                            keys: vec![agent_private],
                            preferred: ed25519_only(),
                            ..Default::default()
                        };

                        let running = server::run_stream(
                            Arc::new(server_config),
                            server_stream,
                            TestServer {
                                authorized_client: operator_public,
                            },
                        )
                        .await
                        .expect("start enrolled SSH server through relay");

                        let _ = running.await;
                        bridge_task.abort();
                        let _ = bridge_task.await;
                        return;
                    }
                }
            }

            panic!("agent control connection ended before signed SSH offer");
        });

        let challenge_response = http
            .post(format!("http://{address}/v1/operator/challenge/signed-ssh"))
            .send()
            .await
            .expect("request operator challenge");
        assert_eq!(challenge_response.status(), reqwest::StatusCode::OK);

        let challenge: OperatorChallengeResponse = challenge_response
            .json()
            .await
            .expect("decode operator challenge");
        let message = operator_auth_message("signed-ssh", &challenge.challenge);
        let signature = operator_private
            .sign(
                OPERATOR_AUTH_NAMESPACE,
                RusshHashAlg::Sha256,
                message.as_bytes(),
            )
            .expect("sign operator challenge")
            .to_pem(ssh_key::LineEnding::LF)
            .expect("encode operator signature");

        let auth_response = http
            .post(format!("http://{address}/v1/operator/auth/signed-ssh"))
            .json(&OperatorAuthRequest {
                challenge: challenge.challenge,
                signature,
            })
            .send()
            .await
            .expect("authenticate operator");
        assert_eq!(auth_response.status(), reqwest::StatusCode::CREATED);

        let auth: OperatorAuthResponse = auth_response
            .json()
            .await
            .expect("decode operator auth response");

        let operator_websocket =
            connect_websocket(&http, &relay, "/v1/probe/signed-ssh", &auth.session_token)
                .await
                .expect("connect signed SSH operator path");
        let (client_stream, client_bridge) = websocket_byte_stream(operator_websocket);

        let client_config = client::Config {
            preferred: ed25519_only(),
            ..Default::default()
        };

        let mut session = client::connect_stream(
            Arc::new(client_config),
            client_stream,
            TestClient {
                expected_server_key,
            },
        )
        .await
        .expect("connect SSH client through signed v1 path");

        let auth = session
            .authenticate_publickey(
                "revtty",
                PrivateKeyWithHashAlg::new(Arc::new(operator_private), None),
            )
            .await
            .expect("authenticate enrolled operator SSH key");

        assert!(
            auth.success(),
            "enrolled operator key should authenticate to enrolled host key"
        );

        drop(session);
        client_bridge.abort();
        let _ = client_bridge.await;
        agent_task.abort();
        let _ = agent_task.await;
        relay_server.abort();
        let _ = relay_server.await;
    }

    const FAST_RELAY_TIMEOUTS: RelayTimeouts = RelayTimeouts {
        agent_idle: Duration::from_millis(300),
        agent_hello: Duration::from_millis(300),
        control_send: Duration::from_millis(300),
        agent_accept: Duration::from_millis(300),
        data_tunnel: Duration::from_millis(300),
        removal_sweep: Duration::from_millis(100),
        shutdown: Duration::from_secs(3),
    };

    /// A relay with short timeouts on a free local port and one enrolled agent.
    struct FastRelay {
        state: RelayState,
        url: String,
        control_token: String,
        agent_id: String,
        operator_fingerprint: String,
        /// Stops the relay as SIGINT or SIGTERM would.
        stop: oneshot::Sender<()>,
        server: tokio::task::JoinHandle<Result<(), RevttyError>>,
    }

    async fn fast_relay(agent: &str) -> FastRelay {
        fast_relay_with(agent, FAST_RELAY_TIMEOUTS).await
    }

    /// Production timeouts, except for a removal sweep that runs ten times a second.
    const SWEEP_TIMEOUTS: RelayTimeouts = RelayTimeouts {
        removal_sweep: Duration::from_millis(100),
        ..super::RELAY_TIMEOUTS
    };

    async fn fast_relay_with(agent: &str, timeouts: RelayTimeouts) -> FastRelay {
        let store = Store::open_in_memory().await.expect("open relay store");
        let state = RelayState::new(store.clone())
            .expect("create relay state")
            .with_timeouts(timeouts);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let address = listener.local_addr().expect("test relay address");
        let (stop, stopped) = oneshot::channel::<()>();
        let server = tokio::spawn(serve_until(listener, state.clone(), async move {
            // Only an explicit stop: a test that drops it keeps its relay running.
            if stopped.await.is_err() {
                std::future::pending::<()>().await;
            }
            "stop"
        }));

        let operator_key = ed25519_key()
            .public_key()
            .to_openssh()
            .expect("operator key");
        let host_key = ed25519_key().public_key().to_openssh().expect("host key");
        let enrollment = store
            .create_enrollment(agent, &operator_key, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let credential = store
            .consume_enrollment(enrollment.token.expose(), &host_key, None, Some("0.1.0"))
            .await
            .expect("consume enrollment");

        FastRelay {
            state,
            url: format!("ws://{address}"),
            control_token: credential.control_token.expose().to_owned(),
            agent_id: credential.id,
            operator_fingerprint: crate::storage::operator_fingerprint(&operator_key)
                .expect("operator fingerprint"),
            stop,
            server,
        }
    }

    /// Production timeouts, so that a session waits for its agent through the whole test.
    const STOPPING_TIMEOUTS: RelayTimeouts = RelayTimeouts {
        shutdown: Duration::from_secs(3),
        ..super::RELAY_TIMEOUTS
    };

    #[tokio::test]
    async fn no_task_starts_once_the_relay_is_stopping() {
        let lifecycle = Lifecycle::new();
        let mut running = lifecycle.enter().expect("a task enters a running relay");
        lifecycle.begin_shutdown();
        assert!(
            lifecycle.enter().is_none(),
            "a task entered a stopping relay"
        );

        // A task that entered before learns of the shutdown, however late it looks.
        tokio::time::timeout(Duration::from_secs(1), running.stopping())
            .await
            .expect("running task told to stop");
        let ended = lifecycle.tasks_ended();
        tokio::pin!(ended);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut ended)
                .await
                .is_err(),
            "the relay did not wait for a running task"
        );
        drop(running);
        tokio::time::timeout(Duration::from_secs(1), ended)
            .await
            .expect("the relay saw the last task end");
    }

    #[tokio::test]
    async fn a_stopping_relay_ends_its_sessions_and_writes_their_audit_first() {
        const NAME: &str = "stopping-agent";
        let mut relay = fast_relay_with(NAME, STOPPING_TIMEOUTS).await;
        let (mut agent, _operator) = connect_agent_and_operator(&relay, NAME, "connect").await;
        audited_outcome_stage(&relay.state, |_| true).await;

        // With the database busy, the session's end can only be queued.
        let (held, holding) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let store = relay.state.store.clone();
        let hold = tokio::spawn(async move { store.hold(held, released).await });
        holding.await.expect("database held");

        relay.stop.send(()).expect("stop relay");
        let closed = tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(Ok(_)) = agent.next().await {}
        })
        .await;
        assert!(closed.is_ok(), "the agent's control connection stayed open");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !relay.server.is_finished(),
            "the relay stopped before writing its audit records"
        );

        release.send(()).expect("release database");
        tokio::time::timeout(Duration::from_secs(3), &mut relay.server)
            .await
            .expect("relay stopped")
            .expect("relay task")
            .expect("relay stopped cleanly");
        hold.await.expect("database hold");
        let sessions = relay
            .state
            .store
            .list_sessions(10)
            .await
            .expect("list sessions");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].outcome.as_deref(), Some("interrupted"));
        assert!(sessions[0].ended_at.is_some());
    }

    #[tokio::test]
    async fn a_relay_whose_audit_writes_fail_does_not_stop_cleanly() {
        const NAME: &str = "unaudited-agent";
        let relay = fast_relay_with(NAME, STOPPING_TIMEOUTS).await;
        let (_agent, _operator) = connect_agent_and_operator(&relay, NAME, "connect").await;
        audited_outcome_stage(&relay.state, |_| true).await;
        relay.state.store.refuse_writes().await;

        relay.stop.send(()).expect("stop relay");
        let stopped = tokio::time::timeout(Duration::from_secs(3), relay.server)
            .await
            .expect("relay stopped")
            .expect("relay task");
        let error = stopped.expect_err("a relay that lost its audit records stopped cleanly");
        assert!(
            error.to_string().contains("could not be written"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_relay_that_cannot_write_its_audit_stops_after_its_grace_period() {
        const NAME: &str = "stuck-agent";
        let relay = fast_relay_with(
            NAME,
            RelayTimeouts {
                shutdown: Duration::from_millis(300),
                ..super::RELAY_TIMEOUTS
            },
        )
        .await;
        let (_agent, _operator) = connect_agent_and_operator(&relay, NAME, "connect").await;
        audited_outcome_stage(&relay.state, |_| true).await;
        let (held, holding) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let store = relay.state.store.clone();
        let hold = tokio::spawn(async move { store.hold(held, released).await });
        holding.await.expect("database held");

        relay.stop.send(()).expect("stop relay");
        let stopped = tokio::time::timeout(Duration::from_secs(2), relay.server)
            .await
            .expect("relay gave up within its grace period")
            .expect("relay task");
        let error = stopped.expect_err("a relay that could not write its audit stopped cleanly");
        assert!(error.to_string().contains("did not stop within"), "{error}");

        release.send(()).expect("release database");
        hold.await.expect("database hold");
    }

    #[tokio::test]
    async fn a_stopping_relay_does_not_wait_for_a_hello() {
        const NAME: &str = "silent-agent";
        let relay = fast_relay_with(NAME, STOPPING_TIMEOUTS).await;
        let _agent = connect_websocket(
            &reqwest::Client::new(),
            &relay.url,
            &format!("/v1/agent/{NAME}"),
            &relay.control_token,
        )
        .await
        .expect("connect agent");
        // The connection's task waits for a Hello, for 10 s.
        tokio::time::sleep(Duration::from_millis(100)).await;

        relay.stop.send(()).expect("stop relay");
        tokio::time::timeout(Duration::from_secs(1), relay.server)
            .await
            .expect("the relay waited for the agent's Hello")
            .expect("relay task")
            .expect("relay stopped cleanly");
    }

    async fn wait_registered(state: &RelayState, name: &str, registered: bool) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            if state.agents.lock().await.contains_key(name) == registered {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        state.agents.lock().await.contains_key(name) == registered
    }

    #[tokio::test]
    async fn silent_agent_is_dropped_after_idle_timeout() {
        let relay = fast_relay("quiet-agent").await;
        let mut agent = connect_websocket(
            &reqwest::Client::new(),
            &relay.url,
            "/v1/agent/quiet-agent",
            &relay.control_token,
        )
        .await
        .expect("connect agent");
        agent
            .send(test_hello("quiet-agent"))
            .await
            .expect("send agent hello");
        assert!(wait_registered(&relay.state, "quiet-agent", true).await);

        // Still connected but sending nothing, like a host whose network vanished.
        assert!(
            wait_registered(&relay.state, "quiet-agent", false).await,
            "relay kept a silent agent online"
        );

        drop(agent);
        relay.server.abort();
    }

    #[tokio::test]
    async fn incompatible_hello_is_rejected_explicitly() {
        let relay = fast_relay("future-agent").await;
        let mut agent = connect_websocket(
            &reqwest::Client::new(),
            &relay.url,
            "/v1/agent/future-agent",
            &relay.control_token,
        )
        .await
        .expect("connect agent");
        agent
            .send(ClientMessage::Text(
                serde_json::to_string(&ControlMessage::Hello {
                    version: CONTROL_PROTOCOL_VERSION + 1,
                    name: "future-agent".to_owned(),
                    agent_version: "9.0.0".to_owned(),
                    active_sessions: 0,
                    max_sessions: 4,
                })
                .expect("encode hello"),
            ))
            .await
            .expect("send agent hello");

        let reply = tokio::time::timeout(Duration::from_secs(2), agent.next())
            .await
            .expect("relay answers an incompatible hello");
        let Some(Ok(ClientMessage::Text(text))) = reply else {
            panic!("expected an error message, got {reply:?}");
        };
        assert!(
            text.starts_with(SESSION_ERROR_PREFIX) && text.contains("incompatible"),
            "unexpected rejection: {text}"
        );
        assert!(!relay.state.agents.lock().await.contains_key("future-agent"));

        relay.server.abort();
    }

    #[tokio::test]
    async fn agent_without_hello_is_never_registered() {
        let relay = fast_relay("mute-agent").await;
        let mut agent = connect_websocket(
            &reqwest::Client::new(),
            &relay.url,
            "/v1/agent/mute-agent",
            &relay.control_token,
        )
        .await
        .expect("connect agent");

        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                assert!(
                    !relay.state.agents.lock().await.contains_key("mute-agent"),
                    "agent registered before identifying itself"
                );
                match agent.next().await {
                    None | Some(Err(_)) | Some(Ok(ClientMessage::Close { .. })) => break,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "relay kept an unidentified agent connected");

        relay.server.abort();
    }

    #[tokio::test]
    async fn offer_to_stuck_agent_times_out_within_accept_deadline() {
        let relay = fast_relay("stuck-agent").await;

        // Registered, but its control queue is full and nothing drains it.
        let (control, _undrained) = mpsc::channel(1);
        control
            .try_send(ControlMessage::Heartbeat {
                version: CONTROL_PROTOCOL_VERSION,
                active_sessions: 0,
            })
            .expect("fill control queue");
        relay.state.agents.lock().await.insert(
            "stuck-agent".to_owned(),
            AgentHandle {
                agent_id: relay.agent_id.clone(),
                connection_id: Uuid::new_v4(),
                control,
                active_sessions: 0,
                max_sessions: 4,
                _registration: oneshot::channel().0,
            },
        );

        // An operator credential as `operator_auth` issues it.
        let session_token = SecretToken::generate("rvo").expect("operator session token");
        relay.state.operator_sessions.lock().await.insert(
            session_token.hash(),
            OperatorSession {
                agent_name: "stuck-agent".to_owned(),
                agent_id: relay.agent_id.clone(),
                operator_fingerprint: relay.operator_fingerprint.clone(),
                expires_at: std::time::Instant::now() + Duration::from_secs(30),
            },
        );

        let started = tokio::time::Instant::now();
        let mut operator = connect_websocket(
            &reqwest::Client::new(),
            &relay.url,
            "/v1/connect/stuck-agent",
            session_token.expose(),
        )
        .await
        .expect("connect operator");

        let reply = tokio::time::timeout(Duration::from_secs(3), operator.next())
            .await
            .expect("operator was held past the acceptance deadline");
        let Some(Ok(ClientMessage::Text(text))) = reply else {
            panic!("expected a session error, got {reply:?}");
        };
        assert!(
            text.starts_with(SESSION_ERROR_PREFIX) && text.contains("did not accept"),
            "unexpected session error: {text}"
        );
        assert!(started.elapsed() < FAST_RELAY_TIMEOUTS.agent_accept + Duration::from_secs(1));
        assert!(relay.state.pending.lock().await.is_empty());

        let session = audited_outcome(&relay.state, "agent_unresponsive").await;
        assert_eq!(session.kind, "shell");
        assert_eq!(session.operator_fingerprint, relay.operator_fingerprint);

        relay.server.abort();
    }

    #[tokio::test]
    async fn an_exec_request_is_offered_and_audited_as_exec() {
        const NAME: &str = "exec-agent";
        let relay = fast_relay(NAME).await;
        let (mut agent, _operator) = connect_agent_and_operator(&relay, NAME, "exec").await;

        let offered_as_exec = loop {
            let message = tokio::time::timeout(Duration::from_secs(3), agent.next())
                .await
                .expect("session offer")
                .expect("control connection open")
                .expect("control message");
            if let ClientMessage::Text(text) = message {
                match serde_json::from_str::<ControlMessage>(&text) {
                    Ok(ControlMessage::ExecOffer { .. }) => break true,
                    Ok(ControlMessage::ProbeOffer { .. } | ControlMessage::ShellOffer { .. }) => {
                        break false;
                    }
                    _ => {}
                }
            }
        };
        assert!(
            offered_as_exec,
            "an exec request was offered as another kind"
        );
        let session = audited_outcome_stage(&relay.state, |_| true).await;
        assert_eq!(session.kind, "exec");

        relay.server.abort();
    }

    #[tokio::test]
    async fn legacy_v0_endpoints_are_gone() {
        let store = Store::open_in_memory().await.expect("open relay store");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let address = listener.local_addr().expect("test relay address");
        let app = router(RelayState::new(store).expect("create relay state"));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test relay");
        });

        // The shared development token no longer opens anything.
        for path in ["/v0/agent/demo", "/v0/probe/demo", "/v0/session/session"] {
            let response = reqwest::Client::new()
                .get(format!("http://{address}{path}"))
                .bearer_auth("development-token")
                .send()
                .await
                .expect("request legacy endpoint");
            assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND, "{path}");
        }

        server.abort();
    }

    /// A relay with production timeouts on a free local port, reachable over HTTP.
    async fn http_relay(store: Store) -> (RelayState, String, tokio::task::JoinHandle<()>) {
        let state = RelayState::new(store).expect("create relay state");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let address = listener.local_addr().expect("test relay address");
        let app = router(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test relay");
        });
        (state, format!("http://{address}"), server)
    }

    async fn enroll(store: &Store, name: &str, operator_key: &str) {
        let enrollment = store
            .create_enrollment(name, operator_key, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let host_key = ed25519_key().public_key().to_openssh().expect("host key");
        store
            .consume_enrollment(enrollment.token.expose(), &host_key, None, Some("0.1.0"))
            .await
            .expect("consume enrollment");
    }

    async fn fetch_challenge(http: &reqwest::Client, url: String) -> String {
        let response = http.post(url).send().await.expect("request challenge");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response
            .json::<OperatorChallengeResponse>()
            .await
            .expect("decode challenge")
            .challenge
    }

    fn sign(key: &PrivateKey, message: &str) -> String {
        key.sign(
            OPERATOR_AUTH_NAMESPACE,
            RusshHashAlg::Sha256,
            message.as_bytes(),
        )
        .expect("sign challenge")
        .to_pem(ssh_key::LineEnding::LF)
        .expect("encode signature")
    }

    async fn post_list(
        http: &reqwest::Client,
        base: &str,
        key: &PrivateKey,
        challenge: &str,
    ) -> reqwest::Response {
        http.post(format!("{base}/v1/operator/list"))
            .json(&OperatorListRequest {
                operator_key: key.public_key().to_openssh().expect("operator key"),
                challenge: challenge.to_owned(),
                signature: sign(key, &operator_list_auth_message(challenge)),
            })
            .send()
            .await
            .expect("request agent list")
    }

    async fn post_auth(
        http: &reqwest::Client,
        base: &str,
        name: &str,
        key: &PrivateKey,
        challenge: &str,
    ) -> reqwest::Response {
        http.post(format!("{base}/v1/operator/auth/{name}"))
            .json(&OperatorAuthRequest {
                challenge: challenge.to_owned(),
                signature: sign(key, &operator_auth_message(name, challenge)),
            })
            .send()
            .await
            .expect("authenticate operator")
    }

    #[tokio::test]
    async fn challenge_flood_does_not_lock_out_operators() {
        let store = Store::open_in_memory().await.expect("open relay store");
        let operator = ed25519_key();
        enroll(
            &store,
            "flooded",
            &operator.public_key().to_openssh().expect("operator key"),
        )
        .await;
        let (_state, base, server) = http_relay(store).await;
        let http = reqwest::Client::new();

        // More unauthenticated challenge requests than the relay ever kept in memory.
        for round in 0..5_000 {
            let path = if round % 2 == 0 {
                "/v1/operator/list/challenge"
            } else {
                "/v1/operator/challenge/flooded"
            };
            let response = http
                .post(format!("{base}{path}"))
                .send()
                .await
                .expect("flood challenge");
            assert_eq!(response.status(), reqwest::StatusCode::OK, "round {round}");
        }

        let challenge =
            fetch_challenge(&http, format!("{base}/v1/operator/challenge/flooded")).await;
        let auth = post_auth(&http, &base, "flooded", &operator, &challenge).await;
        assert_eq!(auth.status(), reqwest::StatusCode::CREATED);

        server.abort();
    }

    #[tokio::test]
    async fn unenrolled_list_signatures_spend_nothing() {
        let store = Store::open_in_memory().await.expect("open relay store");
        let (state, base, server) = http_relay(store).await;
        let http = reqwest::Client::new();

        for _ in 0..20 {
            let stranger = ed25519_key();
            let challenge =
                fetch_challenge(&http, format!("{base}/v1/operator/list/challenge")).await;
            let response = post_list(&http, &base, &stranger, &challenge).await;
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let listed: AgentListResponse = response.json().await.expect("decode agent list");
            assert!(listed.agents.is_empty());
        }

        assert!(
            state.spent_challenges.lock().await.is_empty(),
            "signatures by unenrolled keys used up single-use capacity"
        );
        server.abort();
    }

    #[tokio::test]
    async fn list_signed_before_an_enrollment_is_void_after_it() {
        let store = Store::open_in_memory().await.expect("open relay store");
        let (_state, base, server) = http_relay(store.clone()).await;
        let http = reqwest::Client::new();
        let operator = ed25519_key();

        let challenge = fetch_challenge(&http, format!("{base}/v1/operator/list/challenge")).await;
        let empty = post_list(&http, &base, &operator, &challenge).await;
        assert_eq!(empty.status(), reqwest::StatusCode::OK);

        enroll(
            &store,
            "late-agent",
            &operator.public_key().to_openssh().expect("operator key"),
        )
        .await;

        // The same signed request, replayed after the enrollment.
        let replay = post_list(&http, &base, &operator, &challenge).await;
        assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);

        let fresh = fetch_challenge(&http, format!("{base}/v1/operator/list/challenge")).await;
        let listed: AgentListResponse = post_list(&http, &base, &operator, &fresh)
            .await
            .json()
            .await
            .expect("decode agent list");
        assert_eq!(listed.agents.len(), 1);
        assert_eq!(listed.agents[0].name, "late-agent");

        server.abort();
    }

    #[tokio::test]
    async fn challenge_and_auth_do_not_reveal_agent_names() {
        let store = Store::open_in_memory().await.expect("open relay store");
        let operator = ed25519_key();
        enroll(
            &store,
            "real-agent",
            &operator.public_key().to_openssh().expect("operator key"),
        )
        .await;
        let (_state, base, server) = http_relay(store).await;
        let http = reqwest::Client::new();
        let stranger = ed25519_key();

        for name in ["real-agent", "no-such-agent"] {
            let challenge =
                fetch_challenge(&http, format!("{base}/v1/operator/challenge/{name}")).await;
            let auth = post_auth(&http, &base, name, &stranger, &challenge).await;
            assert_eq!(auth.status(), reqwest::StatusCode::UNAUTHORIZED, "{name}");
        }

        server.abort();
    }

    #[tokio::test]
    async fn tampered_or_misused_challenges_are_rejected() {
        let store = Store::open_in_memory().await.expect("open relay store");
        let operator = ed25519_key();
        let operator_key = operator.public_key().to_openssh().expect("operator key");
        enroll(&store, "agent-a", &operator_key).await;
        enroll(&store, "agent-b", &operator_key).await;
        let (_state, base, server) = http_relay(store).await;
        let http = reqwest::Client::new();

        let for_a = fetch_challenge(&http, format!("{base}/v1/operator/challenge/agent-a")).await;
        let for_b = post_auth(&http, &base, "agent-b", &operator, &for_a).await;
        assert_eq!(for_b.status(), reqwest::StatusCode::UNAUTHORIZED);
        let as_list = post_list(&http, &base, &operator, &for_a).await;
        assert_eq!(as_list.status(), reqwest::StatusCode::UNAUTHORIZED);

        let mut tampered =
            fetch_challenge(&http, format!("{base}/v1/operator/challenge/agent-a")).await;
        let last = tampered.pop().expect("non-empty challenge");
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let forged = post_auth(&http, &base, "agent-a", &operator, &tampered).await;
        assert_eq!(forged.status(), reqwest::StatusCode::UNAUTHORIZED);

        // The genuine challenge still works once, then never again.
        let first = post_auth(&http, &base, "agent-a", &operator, &for_a).await;
        assert_eq!(first.status(), reqwest::StatusCode::CREATED);
        let replay = post_auth(&http, &base, "agent-a", &operator, &for_a).await;
        assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);

        server.abort();
    }

    #[tokio::test]
    async fn spent_challenge_cannot_be_reused_after_its_record_expires() {
        let store = Store::open_in_memory().await.expect("open relay store");
        let state = RelayState::new(store).expect("create relay state");
        let expires_at = std::time::Instant::now() + Duration::from_millis(50);

        spend_challenge(&state, "rvc_challenge", expires_at)
            .await
            .expect("first use");

        // A replay verified before the expiry that reaches this point only after it.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            spend_challenge(&state, "rvc_challenge", expires_at).await,
            Err(axum::http::StatusCode::UNAUTHORIZED),
            "an expired challenge was spent a second time"
        );
    }

    #[tokio::test]
    async fn rejected_session_is_audited_with_its_reason() {
        let relay = fast_relay("busy-agent").await;
        let mut agent = connect_websocket(
            &reqwest::Client::new(),
            &relay.url,
            "/v1/agent/busy-agent",
            &relay.control_token,
        )
        .await
        .expect("connect agent");
        agent
            .send(test_hello("busy-agent"))
            .await
            .expect("send agent hello");
        assert!(wait_registered(&relay.state, "busy-agent", true).await);

        // An agent at capacity turns every offer down.
        let agent_task = tokio::spawn(async move {
            while let Some(Ok(message)) = agent.next().await {
                let ClientMessage::Text(text) = message else {
                    continue;
                };
                if let Ok(ControlMessage::ProbeOffer { session_id, .. }) =
                    serde_json::from_str::<ControlMessage>(&text)
                {
                    let reject = ControlMessage::SessionReject {
                        version: CONTROL_PROTOCOL_VERSION,
                        session_id,
                        reason: SessionRejectReason::Busy,
                    };
                    let encoded = serde_json::to_string(&reject).expect("encode reject");
                    let _ = agent.send(ClientMessage::Text(encoded)).await;
                }
            }
        });

        let session_token = SecretToken::generate("rvo").expect("operator session token");
        relay.state.operator_sessions.lock().await.insert(
            session_token.hash(),
            OperatorSession {
                agent_name: "busy-agent".to_owned(),
                agent_id: relay.agent_id.clone(),
                operator_fingerprint: relay.operator_fingerprint.clone(),
                expires_at: std::time::Instant::now() + Duration::from_secs(30),
            },
        );

        let mut operator = connect_websocket(
            &reqwest::Client::new(),
            &relay.url,
            "/v1/probe/busy-agent",
            session_token.expose(),
        )
        .await
        .expect("connect operator");
        let reply = tokio::time::timeout(Duration::from_secs(3), operator.next())
            .await
            .expect("operator gets the rejection");
        assert!(
            matches!(&reply, Some(Ok(ClientMessage::Text(text))) if text.contains("agent is busy")),
            "unexpected reply: {reply:?}"
        );

        let session = audited_outcome(&relay.state, "rejected:busy").await;
        assert_eq!(session.agent_name, "busy-agent");
        assert_eq!(session.kind, "probe");
        assert_eq!(session.operator_fingerprint, relay.operator_fingerprint);
        assert!(session.ended_at.is_some());

        agent_task.abort();
        relay.server.abort();
    }

    #[tokio::test]
    async fn rotation_routes_switch_the_control_credential() {
        use base64::Engine as _;

        let relay = fast_relay("rotating-agent").await;
        let http = reqwest::Client::new();
        let base = relay.url.replacen("ws://", "http://", 1);
        let next = SecretToken::generate("rva").expect("next credential");
        let next_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(next.hash());
        let post = |path: &str, token: &str, body: Option<&str>| {
            let mut request = http
                .post(format!("{base}/v1/agent/rotating-agent{path}"))
                .bearer_auth(token);
            if let Some(hash) = body {
                request = request.json(&crate::protocol::AgentRotateRequest {
                    next_hash: hash.to_owned(),
                });
            }
            async move { request.send().await.expect("relay request").status() }
        };

        assert_eq!(
            post("/rotate", &relay.control_token, Some("not-a-hash")).await,
            reqwest::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post("/rotate", next.expose(), Some(&next_hash)).await,
            reqwest::StatusCode::UNAUTHORIZED,
            "a rotation started without the current credential"
        );
        assert_eq!(
            post("/rotate", &relay.control_token, Some(&next_hash)).await,
            reqwest::StatusCode::NO_CONTENT
        );
        assert_eq!(
            post("/check", &relay.control_token, None).await,
            reqwest::StatusCode::NO_CONTENT,
            "the current credential stopped working before the confirmation"
        );

        assert_eq!(
            post("/rotate/confirm", next.expose(), None).await,
            reqwest::StatusCode::NO_CONTENT
        );
        assert_eq!(
            post("/check", &relay.control_token, None).await,
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post("/check", next.expose(), None).await,
            reqwest::StatusCode::NO_CONTENT
        );
        // Confirming again, after a lost answer, is harmless; the old credential cannot.
        assert_eq!(
            post("/rotate/confirm", next.expose(), None).await,
            reqwest::StatusCode::NO_CONTENT
        );
        assert_eq!(
            post("/rotate/confirm", &relay.control_token, None).await,
            reqwest::StatusCode::UNAUTHORIZED
        );
        relay.server.abort();
    }

    #[tokio::test]
    async fn agent_credential_check_validates_without_registering() {
        let relay = fast_relay("checked-agent").await;
        let http = reqwest::Client::new();
        let url = format!(
            "{}/v1/agent/checked-agent/check",
            relay.url.replacen("ws://", "http://", 1)
        );

        let valid = http
            .post(&url)
            .bearer_auth(&relay.control_token)
            .send()
            .await
            .expect("check valid credential");
        assert_eq!(valid.status(), reqwest::StatusCode::NO_CONTENT);

        let invalid = http
            .post(&url)
            .bearer_auth("rva_not-the-token")
            .send()
            .await
            .expect("check invalid credential");
        assert_eq!(invalid.status(), reqwest::StatusCode::UNAUTHORIZED);

        assert!(
            relay.state.agents.lock().await.is_empty(),
            "a credential check registered the agent"
        );
        relay.server.abort();
    }

    fn operators_report(revision: u64, operators: &[&str]) -> ClientMessage {
        ClientMessage::Text(
            serde_json::to_string(&ControlMessage::OperatorsReport {
                version: CONTROL_PROTOCOL_VERSION,
                revision,
                operators: operators.iter().map(|key| (*key).to_owned()).collect(),
            })
            .expect("encode operators report"),
        )
    }

    /// Waits until the stored authorization of `fingerprint` on `agent_id` is `expected`.
    async fn wait_authorized(store: &Store, agent_id: &str, fingerprint: &str, expected: bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while store
            .operator_authorized(agent_id, fingerprint)
            .await
            .expect("check operator")
            != expected
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "operator {fingerprint} authorized != {expected}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn auth_status(
        http: &reqwest::Client,
        base: &str,
        name: &str,
        key: &PrivateKey,
    ) -> reqwest::Response {
        let challenge = fetch_challenge(http, format!("{base}/v1/operator/challenge/{name}")).await;
        post_auth(http, base, name, key, &challenge).await
    }

    async fn listed_names(http: &reqwest::Client, base: &str, key: &PrivateKey) -> Vec<String> {
        let challenge = fetch_challenge(http, format!("{base}/v1/operator/list/challenge")).await;
        let response = post_list(http, base, key, &challenge).await;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response
            .json::<AgentListResponse>()
            .await
            .expect("decode agent list")
            .agents
            .into_iter()
            .map(|agent| agent.name)
            .collect()
    }

    #[tokio::test]
    async fn operators_report_decides_who_gets_session_credentials() {
        const NAME: &str = "lifecycle-agent";
        let store = Store::open_in_memory().await.expect("open relay store");
        let first = ed25519_key();
        let second = ed25519_key();
        let first_key = first.public_key().to_openssh().expect("first key");
        let second_key = second.public_key().to_openssh().expect("second key");
        let second_fingerprint =
            crate::storage::operator_fingerprint(&second_key).expect("second fingerprint");
        let enrollment = store
            .create_enrollment(NAME, &first_key, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let host_key = ed25519_key().public_key().to_openssh().expect("host key");
        let credential = store
            .consume_enrollment(enrollment.token.expose(), &host_key, None, Some("0.1.0"))
            .await
            .expect("consume enrollment");
        let (state, base, server) = http_relay(store.clone()).await;
        let http = reqwest::Client::new();

        // Until the agent says otherwise, only the enrolled operator is accepted.
        assert_eq!(
            auth_status(&http, &base, NAME, &second).await.status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert!(listed_names(&http, &base, &second).await.is_empty());

        let mut agent = connect_websocket(
            &http,
            &base,
            &format!("/v1/agent/{NAME}"),
            credential.control_token.expose(),
        )
        .await
        .expect("connect agent");
        agent.send(test_hello(NAME)).await.expect("send hello");
        assert!(wait_registered(&state, NAME, true).await);

        agent
            .send(operators_report(2, &[&first_key, &second_key]))
            .await
            .expect("report added operator");
        wait_authorized(&store, &credential.id, &second_fingerprint, true).await;
        assert_eq!(listed_names(&http, &base, &second).await, vec![NAME]);
        let issued = auth_status(&http, &base, NAME, &second).await;
        assert_eq!(issued.status(), reqwest::StatusCode::CREATED);
        let issued: OperatorAuthResponse = issued.json().await.expect("decode auth response");

        // Revoked before it was used: the credential no longer opens anything.
        agent
            .send(operators_report(3, &[&first_key]))
            .await
            .expect("report revoked operator");
        wait_authorized(&store, &credential.id, &second_fingerprint, false).await;
        let status = http
            .get(format!("{base}/v1/status/{NAME}"))
            .bearer_auth(&issued.session_token)
            .send()
            .await
            .expect("use revoked operator credential");
        assert_eq!(status.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(
            auth_status(&http, &base, NAME, &second).await.status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert!(listed_names(&http, &base, &second).await.is_empty());

        // Once another control connection is the agent's current one, the earlier one is
        // closed and cannot change the operators any more.
        let mut current = connect_websocket(
            &http,
            &base,
            &format!("/v1/agent/{NAME}"),
            credential.control_token.expose(),
        )
        .await
        .expect("connect agent again");
        current.send(test_hello(NAME)).await.expect("send hello");
        current
            .send(operators_report(3, &[&first_key]))
            .await
            .expect("report from the current connection");
        tokio::time::sleep(Duration::from_millis(200)).await;
        agent
            .send(operators_report(4, &[&first_key, &second_key]))
            .await
            .expect("report from the replaced connection");
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while tokio::time::Instant::now() < deadline {
            assert!(
                !store
                    .operator_authorized(&credential.id, &second_fingerprint)
                    .await
                    .expect("check operator"),
                "a replaced control connection changed the operators"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        server.abort();
    }

    /// Waits until the relay closes `agent`'s control connection.
    async fn wait_closed_by_relay(
        agent: &mut reqwest_websocket::WebSocket,
        within: Duration,
    ) -> bool {
        tokio::time::timeout(within, async {
            loop {
                match agent.next().await {
                    Some(Ok(ClientMessage::Close { .. })) | Some(Err(_)) | None => return,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await
        .is_ok()
    }

    #[tokio::test]
    async fn operators_report_on_a_replaced_connection_closes_it() {
        const NAME: &str = "superseded-agent";
        let store = Store::open_in_memory().await.expect("open relay store");
        let operator = ed25519_key()
            .public_key()
            .to_openssh()
            .expect("operator key");
        let enrollment = store
            .create_enrollment(NAME, &operator, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let host_key = ed25519_key().public_key().to_openssh().expect("host key");
        let credential = store
            .consume_enrollment(enrollment.token.expose(), &host_key, None, Some("0.1.0"))
            .await
            .expect("consume enrollment");
        // Production timeouts: the agent is not dropped for idling during the test.
        let (state, base, server) = http_relay(store.clone()).await;
        let mut agent = connect_websocket(
            &reqwest::Client::new(),
            &base,
            &format!("/v1/agent/{NAME}"),
            credential.control_token.expose(),
        )
        .await
        .expect("connect agent");
        agent.send(test_hello(NAME)).await.expect("send hello");
        assert!(wait_registered(&state, NAME, true).await);

        // Another connection of the agent has claimed its place.
        assert!(
            store
                .claim_control_connection(&credential.id, "another-connection")
                .await
                .expect("claim control connection")
        );
        agent
            .send(operators_report(2, &[&operator]))
            .await
            .expect("send report");

        assert!(
            wait_closed_by_relay(&mut agent, Duration::from_secs(3)).await,
            "relay kept a replaced control connection open"
        );
        server.abort();
    }

    #[tokio::test]
    async fn operators_report_that_cannot_be_stored_closes_the_control_connection() {
        const NAME: &str = "blocked-agent";
        let path =
            std::env::temp_dir().join(format!("revtty-blocked-{}.db", Uuid::new_v4().simple()));
        let store = Store::open(&path).await.expect("open relay store");
        let operator = ed25519_key()
            .public_key()
            .to_openssh()
            .expect("operator key");
        let enrollment = store
            .create_enrollment(NAME, &operator, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let host_key = ed25519_key().public_key().to_openssh().expect("host key");
        let credential = store
            .consume_enrollment(enrollment.token.expose(), &host_key, None, Some("0.1.0"))
            .await
            .expect("consume enrollment");
        let (state, base, server) = http_relay(store).await;

        let mut agent = connect_websocket(
            &reqwest::Client::new(),
            &base,
            &format!("/v1/agent/{NAME}"),
            credential.control_token.expose(),
        )
        .await
        .expect("connect agent");
        agent.send(test_hello(NAME)).await.expect("send hello");
        assert!(wait_registered(&state, NAME, true).await);

        // Another writer holds the database longer than the relay's busy timeout.
        let blocker = tokio_rusqlite::rusqlite::Connection::open(&path).expect("open database");
        blocker
            .execute_batch("BEGIN IMMEDIATE;")
            .expect("lock database");
        let added = ed25519_key().public_key().to_openssh().expect("added key");
        agent
            .send(operators_report(2, &[&operator, &added]))
            .await
            .expect("send report");

        // Closed, the agent reconnects and reports its list again; left open, the list would
        // never be sent again.
        let closed = wait_closed_by_relay(&mut agent, Duration::from_secs(10)).await;
        blocker.execute_batch("ROLLBACK;").expect("unlock database");
        assert!(
            closed,
            "relay dropped an operators report and kept the connection"
        );

        server.abort();
        drop(state);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::test]
    async fn operators_report_in_flight_from_a_replaced_connection_is_ignored() {
        let relay = fast_relay("moving-agent").await;
        let added = ed25519_key().public_key().to_openssh().expect("added key");
        let added_fingerprint = crate::storage::operator_fingerprint(&added).expect("fingerprint");

        // The replaced connection registered first, the current one after it.
        let replaced = Uuid::new_v4();
        let current = Uuid::new_v4();
        for connection in [replaced, current] {
            assert!(
                relay
                    .state
                    .store
                    .claim_control_connection(&relay.agent_id, &connection.to_string())
                    .await
                    .expect("claim control connection")
            );
        }

        // A report the replaced connection had already received when the new one registered.
        record_operators_report(
            &relay.state,
            "moving-agent",
            &relay.agent_id,
            replaced,
            5,
            std::slice::from_ref(&added),
        )
        .await;
        assert!(
            !relay
                .state
                .store
                .operator_authorized(&relay.agent_id, &added_fingerprint)
                .await
                .expect("check operator"),
            "a replaced connection's report was stored"
        );

        record_operators_report(
            &relay.state,
            "moving-agent",
            &relay.agent_id,
            current,
            5,
            &[added],
        )
        .await;
        assert!(
            relay
                .state
                .store
                .operator_authorized(&relay.agent_id, &added_fingerprint)
                .await
                .expect("check operator"),
            "the current connection's report was not stored"
        );

        relay.server.abort();
    }

    /// The single audited session once it reaches `outcome`; audit writes are asynchronous.
    async fn audited_outcome(state: &RelayState, outcome: &str) -> crate::storage::SessionRecord {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let mut sessions = state.store.list_sessions(10).await.expect("list sessions");
            if sessions.len() == 1 && sessions[0].outcome.as_deref() == Some(outcome) {
                return sessions.remove(0);
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "expected one session with outcome {outcome:?}, got {:?}",
                sessions
                    .iter()
                    .map(|session| session.outcome.clone())
                    .collect::<Vec<_>>()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// An agent control connection that said hello, and an operator probe or shell request
    /// for it made with an operator credential as `operator_auth` issues it.
    async fn connect_agent_and_operator(
        relay: &FastRelay,
        name: &str,
        route: &str,
    ) -> (reqwest_websocket::WebSocket, reqwest_websocket::WebSocket) {
        let http = reqwest::Client::new();
        let mut agent = connect_websocket(
            &http,
            &relay.url,
            &format!("/v1/agent/{name}"),
            &relay.control_token,
        )
        .await
        .expect("connect agent");
        agent
            .send(test_hello(name))
            .await
            .expect("send agent hello");
        assert!(wait_registered(&relay.state, name, true).await);

        let session_token = SecretToken::generate("rvo").expect("operator session token");
        relay.state.operator_sessions.lock().await.insert(
            session_token.hash(),
            OperatorSession {
                agent_name: name.to_owned(),
                agent_id: relay.agent_id.clone(),
                operator_fingerprint: relay.operator_fingerprint.clone(),
                expires_at: std::time::Instant::now() + Duration::from_secs(30),
            },
        );
        let operator = connect_websocket(
            &http,
            &relay.url,
            &format!("/v1/{route}/{name}"),
            session_token.expose(),
        )
        .await
        .expect("connect operator");
        (agent, operator)
    }

    #[tokio::test]
    async fn removed_agent_loses_a_tunnel_that_outlived_its_control_connection() {
        const NAME: &str = "removed-agent";
        let relay = fast_relay_with(NAME, SWEEP_TIMEOUTS).await;
        super::spawn_removal_sweep(relay.state.clone());
        let (mut agent, mut operator) = connect_agent_and_operator(&relay, NAME, "probe").await;

        // The agent accepts and attaches its data tunnel, which then stays open.
        let offer = loop {
            let message = tokio::time::timeout(Duration::from_secs(3), agent.next())
                .await
                .expect("probe offer")
                .expect("control connection open")
                .expect("control message");
            if let ClientMessage::Text(text) = message
                && let Ok(ControlMessage::ProbeOffer {
                    session_id,
                    tunnel_token,
                    ..
                }) = serde_json::from_str::<ControlMessage>(&text)
            {
                break (session_id, tunnel_token);
            }
        };
        let accept = ControlMessage::SessionAccept {
            version: CONTROL_PROTOCOL_VERSION,
            session_id: offer.0.clone(),
        };
        agent
            .send(ClientMessage::Text(
                serde_json::to_string(&accept).expect("encode accept"),
            ))
            .await
            .expect("accept offer");
        let mut tunnel = connect_websocket(
            &reqwest::Client::new(),
            &relay.url,
            &format!("/v1/session/{}", offer.0),
            &offer.1,
        )
        .await
        .expect("open agent tunnel");
        let _ = audited_outcome_stage(&relay.state, |session| session.paired_at.is_some()).await;

        // The control connection goes; the tunnel does not.
        drop(agent);
        assert!(wait_registered(&relay.state, NAME, false).await);
        assert!(!relay.state.live_sessions.lock().await.is_empty());

        relay
            .state
            .store
            .remove_agent(NAME)
            .await
            .expect("remove agent")
            .expect("agent was enrolled");

        assert!(
            wait_closed_by_relay(&mut operator, Duration::from_secs(2)).await,
            "operator side of a removed agent's tunnel stayed open"
        );
        assert!(
            wait_closed_by_relay(&mut tunnel, Duration::from_secs(2)).await,
            "agent side of a removed agent's tunnel stayed open"
        );
        let session = audited_outcome(&relay.state, "agent_removed").await;
        assert!(session.paired_at.is_some());
        relay.server.abort();
    }

    #[tokio::test]
    async fn deregistered_control_connection_closes_while_the_registry_is_busy() {
        const NAME: &str = "busy-registry";
        let relay = fast_relay_with(NAME, SWEEP_TIMEOUTS).await;
        let mut agent = connect_websocket(
            &reqwest::Client::new(),
            &relay.url,
            &format!("/v1/agent/{NAME}"),
            &relay.control_token,
        )
        .await
        .expect("connect agent");
        agent
            .send(test_hello(NAME))
            .await
            .expect("send agent hello");
        assert!(wait_registered(&relay.state, NAME, true).await);

        // The sweep takes the registration, and the registry stays busy, as while another
        // connection's registration waits for the database.
        let mut agents = relay.state.agents.lock().await;
        agents.remove(NAME);
        let closed = wait_closed_by_relay(&mut agent, Duration::from_secs(2)).await;
        drop(agents);

        assert!(
            closed,
            "a deregistered control connection waited for the registry"
        );
        relay.server.abort();
    }

    #[tokio::test]
    async fn reenrolled_agent_loses_its_control_connection_and_pending_sessions() {
        const NAME: &str = "replaced-agent";
        let relay = fast_relay_with(NAME, SWEEP_TIMEOUTS).await;
        super::spawn_removal_sweep(relay.state.clone());
        let (mut agent, mut operator) = connect_agent_and_operator(&relay, NAME, "connect").await;

        // The agent never answers the offer: the session is pending.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while relay.state.pending.lock().await.is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "no pending session");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // The machine is reinstalled and re-enrolled under the same name.
        let operator_key = ed25519_key()
            .public_key()
            .to_openssh()
            .expect("operator key");
        let host_key = ed25519_key().public_key().to_openssh().expect("host key");
        let replacement = relay
            .state
            .store
            .create_replacement_enrollment(NAME, &operator_key, Duration::from_secs(60))
            .await
            .expect("create replacement");
        relay
            .state
            .store
            .consume_enrollment(replacement.token.expose(), &host_key, None, Some("0.1.0"))
            .await
            .expect("consume replacement");

        assert!(
            wait_closed_by_relay(&mut agent, Duration::from_secs(2)).await,
            "control connection of a replaced agent stayed open"
        );
        assert!(
            wait_closed_by_relay(&mut operator, Duration::from_secs(2)).await,
            "pending session of a replaced agent stayed open"
        );
        assert!(!relay.state.agents.lock().await.contains_key(NAME));
        assert!(relay.state.pending.lock().await.is_empty());
        let session = audited_outcome(&relay.state, "agent_removed").await;
        assert!(session.paired_at.is_none());
        relay.server.abort();
    }

    /// The single audited session once `reached` holds for it; audit writes are asynchronous.
    async fn audited_outcome_stage(
        state: &RelayState,
        reached: impl Fn(&crate::storage::SessionRecord) -> bool,
    ) -> crate::storage::SessionRecord {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let mut sessions = state.store.list_sessions(10).await.expect("list sessions");
            if sessions.len() == 1 && reached(&sessions[0]) {
                return sessions.remove(0);
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "audited session never reached the expected stage"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Pairs an operator probe with a fake agent tunnel, then ends the tunnel from the agent
    /// side either cleanly or by dropping the connection.
    async fn pair_and_end_tunnel(clean: bool) -> crate::storage::SessionRecord {
        let relay = fast_relay("tunnel-agent").await;
        let http = reqwest::Client::new();
        let mut agent = connect_websocket(
            &http,
            &relay.url,
            "/v1/agent/tunnel-agent",
            &relay.control_token,
        )
        .await
        .expect("connect agent");
        agent
            .send(test_hello("tunnel-agent"))
            .await
            .expect("send agent hello");
        assert!(wait_registered(&relay.state, "tunnel-agent", true).await);

        let tunnel_relay = relay.url.clone();
        let agent_task = tokio::spawn(async move {
            while let Some(Ok(message)) = agent.next().await {
                let ClientMessage::Text(text) = message else {
                    continue;
                };
                let Ok(ControlMessage::ProbeOffer {
                    session_id,
                    tunnel_token,
                    ..
                }) = serde_json::from_str::<ControlMessage>(&text)
                else {
                    continue;
                };
                let accept = ControlMessage::SessionAccept {
                    version: CONTROL_PROTOCOL_VERSION,
                    session_id: session_id.clone(),
                };
                let _ = agent
                    .send(ClientMessage::Text(
                        serde_json::to_string(&accept).expect("encode accept"),
                    ))
                    .await;

                let tunnel = connect_websocket(
                    &reqwest::Client::new(),
                    &tunnel_relay,
                    &format!("/v1/session/{session_id}"),
                    &tunnel_token,
                )
                .await
                .expect("open agent tunnel");
                tokio::time::sleep(Duration::from_millis(200)).await;
                if clean {
                    let _ = tunnel
                        .close(reqwest_websocket::CloseCode::Normal, None)
                        .await;
                } else {
                    drop(tunnel);
                }
            }
        });

        let session_token = SecretToken::generate("rvo").expect("operator session token");
        relay.state.operator_sessions.lock().await.insert(
            session_token.hash(),
            OperatorSession {
                agent_name: "tunnel-agent".to_owned(),
                agent_id: relay.agent_id.clone(),
                operator_fingerprint: relay.operator_fingerprint.clone(),
                expires_at: std::time::Instant::now() + Duration::from_secs(30),
            },
        );
        let mut operator = connect_websocket(
            &http,
            &relay.url,
            "/v1/probe/tunnel-agent",
            session_token.expose(),
        )
        .await
        .expect("connect operator");
        let _ = tokio::time::timeout(Duration::from_secs(3), operator.next()).await;

        let outcome = if clean {
            "completed"
        } else {
            "agent_disconnected"
        };
        let session = audited_outcome(&relay.state, outcome).await;
        agent_task.abort();
        relay.server.abort();
        session
    }

    #[tokio::test]
    async fn abruptly_cut_tunnel_is_not_audited_as_completed() {
        let session = pair_and_end_tunnel(false).await;
        assert!(session.paired_at.is_some());
    }

    #[tokio::test]
    async fn cleanly_closed_tunnel_is_audited_as_completed() {
        let session = pair_and_end_tunnel(true).await;
        assert!(session.paired_at.is_some());
    }
}
