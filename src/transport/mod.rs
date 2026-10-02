use reqwest::Client;
use reqwest_websocket::{Upgrade, WebSocket};

use crate::error::RevttyError;

pub const DEFAULT_TRANSPORT: &str = "wss";

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
