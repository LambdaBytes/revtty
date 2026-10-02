use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex, mpsc, oneshot};
use uuid::Uuid;

use crate::error::RevttyError;
use crate::protocol::{ControlMessage, CONTROL_PROTOCOL_VERSION};
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

    let state = RelayState {
        token: Arc::from(token),
        agents: Arc::new(Mutex::new(HashMap::new())),
        pending: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v0/agent/{name}", get(agent_upgrade))
        .route("/v0/probe/{name}", get(probe_upgrade))
        .route("/v0/session/{session_id}", get(session_upgrade))
        .with_state(state);

    eprintln!("revtty relay transport proof listening on {bind}");

    axum::serve(listener, app)
        .await
        .map_err(|error| RevttyError::runtime("serve relay", error))
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
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};

    use super::authorized;

    #[test]
    fn bearer_auth_requires_exact_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));

        assert!(authorized(&headers, "secret"));
        assert!(!authorized(&headers, "other"));
    }
}
