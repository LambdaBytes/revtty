use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex, mpsc, oneshot};
use uuid::Uuid;

use crate::error::RevttyError;
use crate::protocol::{CONTROL_PROTOCOL_VERSION, ControlMessage};
use crate::transport::valid_name;

const CONTROL_QUEUE_DEPTH: usize = 16;
const SESSION_WAIT: Duration = Duration::from_secs(10);
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

#[derive(Clone)]
struct RelayState {
    token: Arc<str>,
    agents: Arc<Mutex<HashMap<String, AgentHandle>>>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<WebSocket>>>>,
}

impl RelayState {
    fn new(token: String) -> Self {
        Self {
            token: Arc::from(token),
            agents: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[derive(Clone)]
struct AgentHandle {
    connection_id: Uuid,
    control: mpsc::Sender<ControlMessage>,
}

pub fn init() -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("relay initialization"))
}

pub async fn serve(bind: &str, token: String) -> Result<(), RevttyError> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| RevttyError::runtime("bind relay", error))?;

    let app = router(RelayState::new(token));

    eprintln!("revtty relay transport proof listening on {bind}");

    axum::serve(listener, app)
        .await
        .map_err(|error| RevttyError::runtime("serve relay", error))
}

fn router(state: RelayState) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v0/agent/{name}", get(agent_upgrade))
        .route("/v0/probe/{name}", get(probe_upgrade))
        .route("/v0/session/{session_id}", get(session_upgrade))
        .with_state(state)
}

async fn agent_upgrade(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !authorized(&headers, &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !valid_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid agent name").into_response();
    }

    ws.max_message_size(MAX_MESSAGE_SIZE)
        .max_frame_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| handle_agent(socket, state, name))
        .into_response()
}

async fn probe_upgrade(
    State(state): State<RelayState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !authorized(&headers, &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !valid_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid agent name").into_response();
    }

    let control = {
        let agents = state.agents.lock().await;
        agents.get(&name).map(|agent| agent.control.clone())
    };

    let Some(control) = control else {
        return (StatusCode::NOT_FOUND, "agent is offline").into_response();
    };

    ws.max_message_size(MAX_MESSAGE_SIZE)
        .max_frame_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| handle_probe(socket, state, control))
        .into_response()
}

async fn session_upgrade(
    State(state): State<RelayState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !authorized(&headers, &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    ws.max_message_size(MAX_MESSAGE_SIZE)
        .max_frame_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| attach_agent_session(socket, state, session_id))
        .into_response()
}

async fn handle_agent(socket: WebSocket, state: RelayState, name: String) {
    let connection_id = Uuid::new_v4();
    let (control_tx, mut control_rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);

    {
        let mut agents = state.agents.lock().await;
        agents.insert(
            name.clone(),
            AgentHandle {
                connection_id,
                control: control_tx,
            },
        );
    }

    eprintln!("agent online: {name}");

    let (mut sender, mut receiver) = socket.split();

    loop {
        tokio::select! {
            control = control_rx.recv() => {
                let Some(control) = control else {
                    break;
                };

                let Ok(text) = serde_json::to_string(&control) else {
                    break;
                };

                if sender.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            message = receiver.next() => {
                match message {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
        }
    }

    let mut agents = state.agents.lock().await;
    if agents
        .get(&name)
        .is_some_and(|agent| agent.connection_id == connection_id)
    {
        agents.remove(&name);
        eprintln!("agent offline: {name}");
    }
}

async fn handle_probe(
    operator_socket: WebSocket,
    state: RelayState,
    control: mpsc::Sender<ControlMessage>,
) {
    let session_id = Uuid::new_v4().simple().to_string();
    let (session_tx, session_rx) = oneshot::channel();

    {
        let mut pending = state.pending.lock().await;
        pending.insert(session_id.clone(), session_tx);
    }

    let offer = ControlMessage::ProbeOffer {
        version: CONTROL_PROTOCOL_VERSION,
        session_id: session_id.clone(),
    };

    if control.send(offer).await.is_err() {
        state.pending.lock().await.remove(&session_id);
        return;
    }

    eprintln!("probe requested: {session_id}");

    match tokio::time::timeout(SESSION_WAIT, session_rx).await {
        Ok(Ok(agent_socket)) => {
            eprintln!("probe paired: {session_id}");
            bridge_websockets(operator_socket, agent_socket).await;
        }
        _ => {
            state.pending.lock().await.remove(&session_id);
            eprintln!("probe timed out: {session_id}");
        }
    }
}

async fn attach_agent_session(socket: WebSocket, state: RelayState, session_id: String) {
    let pending = {
        let mut pending = state.pending.lock().await;
        pending.remove(&session_id)
    };

    if let Some(pending) = pending {
        let _ = pending.send(socket);
    }
}

async fn bridge_websockets(left: WebSocket, right: WebSocket) {
    let (mut left_tx, mut left_rx) = left.split();
    let (mut right_tx, mut right_rx) = right.split();

    let left_to_right = async {
        while let Some(Ok(message)) = left_rx.next().await {
            if right_tx.send(message).await.is_err() {
                break;
            }
        }
    };

    let right_to_left = async {
        while let Some(Ok(message)) = right_rx.next().await {
            if left_tx.send(message).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = left_to_right => {}
        _ = right_to_left => {}
    }
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|candidate| candidate == token)
}

pub fn doctor() -> Result<(), RevttyError> {
    println!("relay transport proof: available");
    println!(
        "control protocol v{}",
        crate::protocol::CONTROL_PROTOCOL_VERSION
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use futures_util::{SinkExt, StreamExt};
    use reqwest_websocket::Message as ClientMessage;
    use russh::Preferred;
    use russh::client;
    use russh::keys::key::{PrivateKeyWithHashAlg, safe_rng};
    use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate};
    use russh::server;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::{RelayState, authorized, router};
    use crate::protocol::{ControlMessage, ProbeResult};
    use crate::transport::connect_websocket;

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

    async fn websocket_byte_stream(
        websocket: reqwest_websocket::WebSocket,
    ) -> (DuplexStream, tokio::task::JoinHandle<()>) {
        let (application, bridge) = tokio::io::duplex(64 * 1024);
        let (mut websocket_tx, mut websocket_rx) = websocket.split();
        let (mut bridge_rx, mut bridge_tx) = tokio::io::split(bridge);

        let task = tokio::spawn(async move {
            let websocket_to_stream = async {
                while let Some(message) = websocket_rx.next().await {
                    match message {
                        Ok(ClientMessage::Binary(data)) => {
                            bridge_tx.write_all(&data).await?;
                        }
                        Ok(ClientMessage::Close { .. }) | Err(_) => break,
                        Ok(_) => {}
                    }
                }

                Ok::<(), std::io::Error>(())
            };

            let stream_to_websocket = async {
                let mut buffer = [0_u8; 8192];

                loop {
                    let read = bridge_rx.read(&mut buffer).await?;
                    if read == 0 {
                        break;
                    }

                    websocket_tx
                        .send(ClientMessage::Binary(buffer[..read].to_vec().into()))
                        .await
                        .map_err(std::io::Error::other)?;
                }

                Ok::<(), std::io::Error>(())
            };

            tokio::select! {
                _ = websocket_to_stream => {}
                _ = stream_to_websocket => {}
            }
        });

        (application, task)
    }

    #[test]
    fn bearer_auth_requires_exact_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));

        assert!(authorized(&headers, "secret"));
        assert!(!authorized(&headers, "other"));
    }

    #[tokio::test]
    async fn reverse_probe_round_trip() {
        let state = RelayState::new("secret".to_owned());
        let app = router(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let address = listener.local_addr().expect("test relay address");

        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test relay");
        });

        let relay = format!("ws://{address}");
        let client = reqwest::Client::new();
        let agent = connect_websocket(&client, &relay, "/v0/agent/demo", "secret")
            .await
            .expect("connect test agent");

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.agents.lock().await.contains_key("demo") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("agent becomes visible");

        let (mut agent_sender, mut agent_receiver) = agent.split();
        let agent_client = client.clone();
        let agent_relay = relay.clone();

        let agent_task = tokio::spawn(async move {
            while let Some(message) = agent_receiver.next().await {
                match message.expect("agent control message") {
                    ClientMessage::Text(text) => {
                        let control: ControlMessage =
                            serde_json::from_str(&text).expect("decode probe offer");

                        if let ControlMessage::ProbeOffer { session_id, .. } = control {
                            let path = format!("/v0/session/{session_id}");
                            let mut session =
                                connect_websocket(&agent_client, &agent_relay, &path, "secret")
                                    .await
                                    .expect("connect agent session");

                            let result = ProbeResult {
                                name: "demo".to_owned(),
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

                            session
                                .close(reqwest_websocket::CloseCode::Normal, None)
                                .await
                                .expect("close agent session");
                            return;
                        }
                    }
                    ClientMessage::Ping(data) => {
                        agent_sender
                            .send(ClientMessage::Pong(data))
                            .await
                            .expect("send pong");
                    }
                    _ => {}
                }
            }

            panic!("agent control connection ended before probe offer");
        });

        let mut operator = connect_websocket(&client, &relay, "/v0/probe/demo", "secret")
            .await
            .expect("connect operator probe");

        let message = tokio::time::timeout(Duration::from_secs(2), operator.next())
            .await
            .expect("probe result timeout")
            .expect("operator websocket closed")
            .expect("operator websocket error");

        let ClientMessage::Text(text) = message else {
            panic!("expected text probe result");
        };

        let result: ProbeResult = serde_json::from_str(&text).expect("decode probe result");
        assert_eq!(result.name, "demo");
        assert_eq!(result.os, "test-os");
        assert_eq!(result.arch, "test-arch");
        assert_eq!(result.version, "test-version");

        agent_task.await.expect("agent test task");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn ssh_authenticates_through_reverse_relay() {
        let state = RelayState::new("secret".to_owned());
        let app = router(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test relay");
        let address = listener.local_addr().expect("test relay address");

        let relay_server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test relay");
        });

        let relay = format!("ws://{address}");
        let http = reqwest::Client::new();

        let server_key = ed25519_key();
        let expected_server_key = server_key.public_key().clone();

        let client_key = ed25519_key();
        let authorized_client = client_key.public_key().clone();

        let agent = connect_websocket(&http, &relay, "/v0/agent/demo", "secret")
            .await
            .expect("connect test agent");

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.agents.lock().await.contains_key("demo") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("agent becomes visible");

        let (_agent_sender, mut agent_receiver) = agent.split();
        let agent_http = http.clone();
        let agent_relay = relay.clone();

        let agent_task = tokio::spawn(async move {
            while let Some(message) = agent_receiver.next().await {
                if let ClientMessage::Text(text) = message.expect("agent control message") {
                    let control: ControlMessage =
                        serde_json::from_str(&text).expect("decode session offer");

                    if let ControlMessage::ProbeOffer { session_id, .. } = control {
                        let path = format!("/v0/session/{session_id}");
                        let websocket =
                            connect_websocket(&agent_http, &agent_relay, &path, "secret")
                                .await
                                .expect("connect agent SSH session");

                        let (server_stream, bridge_task) = websocket_byte_stream(websocket).await;
                        let server_config = server::Config {
                            keys: vec![server_key],
                            preferred: ed25519_only(),
                            ..Default::default()
                        };

                        let running = server::run_stream(
                            Arc::new(server_config),
                            server_stream,
                            TestServer { authorized_client },
                        )
                        .await
                        .expect("start SSH server through relay");

                        let _ = running.await;
                        bridge_task.abort();
                        let _ = bridge_task.await;
                        return;
                    }
                }
            }

            panic!("agent control connection ended before session offer");
        });

        let operator = connect_websocket(&http, &relay, "/v0/probe/demo", "secret")
            .await
            .expect("connect operator SSH session");
        let (client_stream, client_bridge) = websocket_byte_stream(operator).await;

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
        .expect("connect SSH client through reverse relay");

        let auth = session
            .authenticate_publickey(
                "revtty",
                PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
            )
            .await
            .expect("authenticate operator key through relay");

        assert!(auth.success(), "Ed25519 SSH auth through relay should succeed");

        drop(session);
        client_bridge.abort();
        let _ = client_bridge.await;
        agent_task.abort();
        let _ = agent_task.await;
        relay_server.abort();
        let _ = relay_server.await;
    }
}
