use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use reqwest_websocket::{Message, Upgrade, WebSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

use crate::error::RevttyError;

pub const DEFAULT_TRANSPORT: &str = "wss";

const STREAM_BUFFER_SIZE: usize = 256 * 1024;
const STREAM_CHUNK_SIZE: usize = 16 * 1024;

pub fn websocket_byte_stream(
    websocket: WebSocket,
) -> (DuplexStream, JoinHandle<Result<(), RevttyError>>) {
    let (application, bridge) = tokio::io::duplex(STREAM_BUFFER_SIZE);

    let task = tokio::spawn(async move {
        let (mut websocket_sender, mut websocket_receiver) = websocket.split();
        let (mut stream_reader, mut stream_writer) = tokio::io::split(bridge);
        let mut buffer = [0_u8; STREAM_CHUNK_SIZE];

        loop {
            tokio::select! {
                message = websocket_receiver.next() => {
                    match message {
                        Some(Ok(Message::Binary(data))) => {
                            stream_writer
                                .write_all(&data)
                                .await
                                .map_err(|error| RevttyError::runtime("write websocket data to stream", error))?;
                        }
                        Some(Ok(Message::Ping(data))) => {
                            websocket_sender
                                .send(Message::Pong(data))
                                .await
                                .map_err(|error| RevttyError::runtime("send websocket pong", error))?;
                        }
                        Some(Ok(Message::Pong(_))) => {}
                        Some(Ok(Message::Close { .. })) | None => break,
                        Some(Ok(Message::Text(_))) => {
                            return Err(RevttyError::message(
                                "unexpected text frame on binary session transport",
                            ));
                        }
                        Some(Err(error)) => {
                            return Err(RevttyError::runtime("receive websocket session data", error));
                        }
                    }
                }
                read = stream_reader.read(&mut buffer) => {
                    let read = read
                        .map_err(|error| RevttyError::runtime("read session stream", error))?;

                    if read == 0 {
                        break;
                    }

                    websocket_sender
                        .send(Message::Binary(buffer[..read].to_vec().into()))
                        .await
                        .map_err(|error| RevttyError::runtime("send websocket session data", error))?;
                }
            }
        }

        Ok(())
    });

    (application, task)
}

pub async fn check_relay_health(client: &Client, relay: &str) -> Result<(), RevttyError> {
    let url = http_url(relay, "/health")?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| RevttyError::runtime("relay health check", error))?;
    let status = response.status();

    if !status.is_success() {
        return Err(RevttyError::message(format!(
            "relay health check failed ({status})"
        )));
    }

    Ok(())
}

pub async fn connect_websocket(
    client: &Client,
    relay: &str,
    path: &str,
    token: &str,
) -> Result<WebSocket, RevttyError> {
    let url = websocket_url(relay, path)?;

    let response = client
        .get(url)
        .bearer_auth(token)
        .upgrade()
        .send()
        .await
        .map_err(|error| RevttyError::runtime("websocket handshake", error))?;

    response
        .into_websocket()
        .await
        .map_err(|error| RevttyError::runtime("websocket upgrade", error))
}

pub fn http_url(relay: &str, path: &str) -> Result<String, RevttyError> {
    if !path.starts_with('/') {
        return Err(RevttyError::message("HTTP path must start with '/'"));
    }

    let base = relay.trim_end_matches('/');
    let base = if let Some(rest) = base.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = base.strip_prefix("ws://") {
        format!("http://{rest}")
    } else if base.starts_with("https://") || base.starts_with("http://") {
        base.to_owned()
    } else {
        return Err(RevttyError::message(
            "relay URL must start with http://, https://, ws://, or wss://",
        ));
    };

    Ok(format!("{base}{path}"))
}

pub fn websocket_url(relay: &str, path: &str) -> Result<String, RevttyError> {
    if !path.starts_with('/') {
        return Err(RevttyError::message("websocket path must start with '/'"));
    }

    let base = relay.trim_end_matches('/');
    let base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if base.starts_with("wss://") || base.starts_with("ws://") {
        base.to_owned()
    } else {
        return Err(RevttyError::message(
            "relay URL must start with http://, https://, ws://, or wss://",
        ));
    };

    Ok(format!("{base}{path}"))
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::{http_url, valid_name, websocket_url};

    #[test]
    fn converts_wss_to_https() {
        assert_eq!(
            http_url("wss://relay.example.com/", "/v1/enroll").unwrap(),
            "https://relay.example.com/v1/enroll"
        );
    }

    #[test]
    fn converts_https_to_wss() {
        assert_eq!(
            websocket_url("https://relay.example.com/", "/v0/agent/demo").unwrap(),
            "wss://relay.example.com/v0/agent/demo"
        );
    }

    #[test]
    fn converts_http_to_ws() {
        assert_eq!(
            websocket_url("http://127.0.0.1:8787", "/health").unwrap(),
            "ws://127.0.0.1:8787/health"
        );
    }

    #[test]
    fn validates_machine_names() {
        assert!(valid_name("store-042"));
        assert!(valid_name("gateway_a.example"));
        assert!(!valid_name(""));
        assert!(!valid_name("bad/name"));
        assert!(!valid_name("bad name"));
    }
}
