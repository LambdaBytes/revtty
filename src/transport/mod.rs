use std::net::IpAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use reqwest_websocket::{CloseCode, Message, Upgrade, WebSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

use crate::error::{RevttyError, with_sources};
use crate::protocol::SESSION_ERROR_PREFIX;

pub const DEFAULT_TRANSPORT: &str = "wss";

const STREAM_BUFFER_SIZE: usize = 256 * 1024;
const STREAM_CHUNK_SIZE: usize = 16 * 1024;
/// Time the bridge gets to send its close frame once the SSH side is done with the stream.
const BRIDGE_CLOSE_WAIT: Duration = Duration::from_secs(2);
/// Opening a WebSocket to the relay: name resolution, TCP, TLS and the HTTP upgrade. reqwest's
/// TCP keepalive and user timeout notice a dead path, not a peer that accepts the connection
/// and never answers, such as a frozen relay or a middlebox. The relay answers the upgrade
/// once it has authenticated the request, and gives an agent's data tunnel 10 s to attach.
const WEBSOCKET_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// SSH liveness policy shared by the operator client and the agent server.
#[derive(Clone, Copy, Debug)]
pub struct SshTimeouts {
    /// Keepalive requests while the session is idle; a healthy peer's reply keeps it open.
    pub keepalive_interval: Duration,
    /// Unanswered keepalives tolerated before the peer is considered gone.
    pub keepalive_max: usize,
    /// No traffic at all for this long closes the session. In russh this is also the only
    /// bound on the banner exchange and on writes the transport no longer accepts.
    pub inactivity: Duration,
}

pub const SSH_TIMEOUTS: SshTimeouts = SshTimeouts {
    keepalive_interval: Duration::from_secs(30),
    keepalive_max: 3,
    inactivity: Duration::from_secs(120),
};

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
                                .map_err(|error| {
                                    RevttyError::runtime("send websocket pong", websocket_error(error))
                                })?;
                        }
                        Some(Ok(Message::Pong(_))) => {}
                        Some(Ok(Message::Close { .. })) | None => break,
                        Some(Ok(Message::Text(text))) => {
                            if let Some(detail) = session_error_detail(&text) {
                                return Err(RevttyError::message(detail.to_owned()));
                            }

                            return Err(RevttyError::message(
                                "unexpected text frame on binary session transport",
                            ));
                        }
                        Some(Err(error)) => {
                            return Err(RevttyError::runtime(
                                "receive websocket session data",
                                websocket_error(error),
                            ));
                        }
                    }
                }
                read = stream_reader.read(&mut buffer) => {
                    let read = read
                        .map_err(|error| RevttyError::runtime("read session stream", error))?;

                    if read == 0 {
                        // The SSH side is done with the stream: close the tunnel cleanly so the
                        // relay can tell a finished session from a lost connection.
                        let _ = websocket_sender
                            .send(Message::Close {
                                code: CloseCode::Normal,
                                reason: String::new(),
                            })
                            .await;
                        break;
                    }

                    websocket_sender
                        .send(Message::Binary(buffer[..read].to_vec().into()))
                        .await
                        .map_err(|error| {
                            RevttyError::runtime("send websocket session data", websocket_error(error))
                        })?;
                }
            }
        }

        Ok(())
    });

    (application, task)
}

/// Waits briefly for the bridge to close the tunnel after the SSH session released the
/// stream, then stops it.
pub async fn finish_byte_stream(mut bridge: JoinHandle<Result<(), RevttyError>>) {
    if tokio::time::timeout(BRIDGE_CLOSE_WAIT, &mut bridge)
        .await
        .is_err()
    {
        bridge.abort();
        let _ = bridge.await;
    }
}

fn session_error_detail(text: &str) -> Option<&str> {
    text.strip_prefix(SESSION_ERROR_PREFIX)
        .filter(|detail| !detail.is_empty())
}

/// The HTTP client for every request to the relay. Redirects are followed as reqwest does by
/// default, except to a URL `refuse_remote_plaintext` refuses: a 307 or 308 resends the
/// request body, which can hold a credential (the enrollment token, for one).
///
/// HTTP/1.1 only: reqwest-websocket upgrades over HTTP/1.1, so a TLS terminator in front of
/// the relay that picked h2 from the ALPN offer, as Caddy does by default, would fail every
/// WebSocket while plain requests still worked.
pub fn relay_client() -> Result<Client, RevttyError> {
    Client::builder()
        .http1_only()
        .redirect(reqwest::redirect::Policy::custom(
            |attempt| match refuse_remote_plaintext(attempt.url().as_str()) {
                Ok(()) => reqwest::redirect::Policy::default().redirect(attempt),
                Err(error) => attempt.error(error.to_string()),
            },
        ))
        .build()
        .map_err(|error| RevttyError::runtime("build HTTP client", error))
}

pub async fn check_relay_health(client: &Client, relay: &str) -> Result<(), RevttyError> {
    let url = http_url(relay, "/health")?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| RevttyError::runtime("relay health check", with_sources(&error)))?;
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
    connect_websocket_within(client, relay, path, token, WEBSOCKET_HANDSHAKE_TIMEOUT).await
}

async fn connect_websocket_within(
    client: &Client,
    relay: &str,
    path: &str,
    token: &str,
    limit: Duration,
) -> Result<WebSocket, RevttyError> {
    let url = websocket_url(relay, path)?;

    let handshake = async {
        let response = client
            .get(url)
            .bearer_auth(token)
            .upgrade()
            .send()
            .await
            .map_err(|error| RevttyError::runtime("websocket handshake", websocket_error(error)))?;

        response
            .into_websocket()
            .await
            .map_err(|error| RevttyError::runtime("websocket upgrade", websocket_error(error)))
    };

    tokio::time::timeout(limit, handshake)
        .await
        .unwrap_or_else(|_| {
            Err(RevttyError::message(format!(
                "websocket handshake with the relay timed out after {limit:?}"
            )))
        })
}

/// reqwest-websocket's own messages ("reqwest error", "websocket upgrade failed", "tungstenite
/// error") leave the cause, such as the status of a refused upgrade or a TLS failure, to the
/// source chain. The URL reqwest adds is left out: the caller's context names the relay.
pub fn websocket_error(error: reqwest_websocket::Error) -> String {
    match error {
        reqwest_websocket::Error::Reqwest(error) => with_sources(&error.without_url()),
        error => with_sources(&error),
    }
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

    let url = format!("{base}{path}");
    refuse_remote_plaintext(&url)?;
    Ok(url)
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

    let url = format!("{base}{path}");
    refuse_remote_plaintext(&url)?;
    Ok(url)
}

/// Every request to the relay carries a bearer credential (enrollment, control, tunnel or
/// operator session token) that only TLS protects; SSH covers the terminal alone. Plain
/// http:// and ws:// are therefore accepted only for a relay on this machine.
fn refuse_remote_plaintext(url: &str) -> Result<(), RevttyError> {
    if !(url.starts_with("http://") || url.starts_with("ws://")) {
        return Ok(());
    }

    // Parsed as the request will be, so that userinfo cannot pass for the host.
    let parsed =
        reqwest::Url::parse(url).map_err(|error| RevttyError::runtime("parse relay URL", error))?;
    let loopback = match parsed.host_str() {
        Some("localhost") => true,
        // An IPv6 host keeps its brackets.
        Some(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        None => false,
    };

    if loopback {
        return Ok(());
    }
    Err(RevttyError::message(format!(
        "refusing unencrypted relay URL {}://{}: use https:// or wss://; http:// and ws:// are \
         only accepted for localhost, 127.0.0.0/8 or [::1]",
        parsed.scheme(),
        parsed.host_str().unwrap_or_default()
    )))
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Byte streams for exercising transport stalls in tests.
#[cfg(test)]
pub mod test_support {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    const STALLED: u8 = 1;
    const DISCARDING: u8 = 2;

    /// Switches an in-memory stream between working normally, never making progress again
    /// (a dead path), or silently dropping everything written to it (a black hole).
    #[derive(Clone, Default)]
    pub struct StreamControl(Arc<AtomicU8>);

    impl StreamControl {
        pub fn stall(&self) {
            self.0.store(STALLED, Ordering::SeqCst);
        }

        pub fn discard(&self) {
            self.0.store(DISCARDING, Ordering::SeqCst);
        }

        fn mode(&self) -> u8 {
            self.0.load(Ordering::SeqCst)
        }
    }

    pub struct ControlledStream {
        inner: DuplexStream,
        control: StreamControl,
    }

    impl ControlledStream {
        pub fn new(inner: DuplexStream, control: StreamControl) -> Self {
            Self { inner, control }
        }
    }

    impl AsyncRead for ControlledStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.control.mode() {
                // Never woken again: nothing arrives any more.
                STALLED | DISCARDING => Poll::Pending,
                _ => Pin::new(&mut self.inner).poll_read(context, buffer),
            }
        }
    }

    impl AsyncWrite for ControlledStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            match self.control.mode() {
                STALLED => Poll::Pending,
                DISCARDING => Poll::Ready(Ok(data.len())),
                _ => Pin::new(&mut self.inner).poll_write(context, data),
            }
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.control.mode() {
                STALLED => Poll::Pending,
                DISCARDING => Poll::Ready(Ok(())),
                _ => Pin::new(&mut self.inner).poll_flush(context),
            }
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.control.mode() {
                STALLED => Poll::Pending,
                DISCARDING => Poll::Ready(Ok(())),
                _ => Pin::new(&mut self.inner).poll_shutdown(context),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{http_url, session_error_detail, valid_name, websocket_url};

    #[test]
    fn parses_session_error_marker() {
        assert_eq!(
            session_error_detail("revtty-error:agent is busy"),
            Some("agent is busy")
        );
        assert_eq!(session_error_detail("plain text"), None);
        assert_eq!(session_error_detail("revtty-error:"), None);
    }

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
    fn refuses_unencrypted_relays_off_loopback() {
        for relay in [
            "http://relay.example.com",
            "ws://203.0.113.10:8787",
            "http://10.0.0.5:8787/",
            // The host is what follows the userinfo.
            "http://127.0.0.1@relay.example.com",
            "http://localhost.example.com",
        ] {
            let error = http_url(relay, "/health").expect_err(relay).to_string();
            assert!(error.contains("https://"), "{relay}: {error}");
            assert!(websocket_url(relay, "/v1/agent/demo").is_err(), "{relay}");
        }
    }

    #[test]
    fn accepts_unencrypted_relays_on_loopback() {
        for relay in [
            "http://127.0.0.1:8787",
            "ws://127.0.0.2:8787",
            "http://localhost:8787",
            "ws://LOCALHOST",
            "http://[::1]:8787",
        ] {
            assert!(http_url(relay, "/health").is_ok(), "{relay}");
            assert!(websocket_url(relay, "/v1/agent/demo").is_ok(), "{relay}");
        }
    }

    #[tokio::test]
    async fn relay_client_follows_redirects_except_to_unencrypted_remote_relays() {
        use axum::http::StatusCode;
        use axum::http::header::LOCATION;
        use axum::routing::post;

        let app = axum::Router::new()
            .route(
                "/to-remote",
                post(|| async {
                    // `.invalid` never resolves: nothing leaves this machine either way.
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(LOCATION, "http://relay.invalid:8787/v1/enroll")],
                    )
                }),
            )
            .route(
                "/to-loopback",
                post(|| async { (StatusCode::PERMANENT_REDIRECT, [(LOCATION, "/landed")]) }),
            )
            .route("/landed", post(|| async { StatusCode::NO_CONTENT }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirecting relay");
        let address = listener.local_addr().expect("redirecting relay address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve redirecting relay");
        });
        let client = super::relay_client().expect("relay client");

        let refused = client
            .post(format!("http://{address}/to-remote"))
            .json(&"rve_secret")
            .send()
            .await
            .expect_err("followed a redirect to a remote plain-HTTP relay");
        assert!(refused.is_redirect(), "{refused:?}");

        let followed = client
            .post(format!("http://{address}/to-loopback"))
            .json(&"body")
            .send()
            .await
            .expect("follow a redirect on loopback");
        assert_eq!(followed.status(), reqwest::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn a_websocket_handshake_nobody_answers_is_bounded() {
        // Accepts connections and never answers, as a frozen relay does: TCP keepalive sees a
        // healthy peer.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind frozen relay");
        let address = listener.local_addr().expect("frozen relay address");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let client = super::relay_client().expect("relay client");
        let started = tokio::time::Instant::now();

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            super::connect_websocket_within(
                &client,
                &format!("http://{address}"),
                "/v1/agent/demo",
                "rva_test",
                Duration::from_millis(200),
            ),
        )
        .await;

        let Ok(Err(error)) = outcome else {
            panic!("the handshake was not bounded");
        };
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn relay_client_offers_only_http1_to_tls_relays() {
        use tokio::io::AsyncReadExt;

        // Records the ClientHello and hangs up: no certificate is needed to see the offer.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TLS listener");
        let port = listener.local_addr().expect("TLS listener address").port();
        let hello = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept TLS client");
            let mut hello = vec![0_u8; 5 + 16 * 1024];
            let mut read = 0;
            // One TLS record; its length follows the 5-byte record header.
            while read < 5 || read < 5 + usize::from(u16::from_be_bytes([hello[3], hello[4]])) {
                let more = stream
                    .read(&mut hello[read..])
                    .await
                    .expect("read ClientHello");
                if more == 0 {
                    break;
                }
                read += more;
            }
            hello.truncate(read);
            hello
        });
        let client = super::relay_client().expect("relay client");

        let _ = super::connect_websocket(
            &client,
            &format!("https://localhost:{port}"),
            "/v1/agent/demo",
            "rva_test",
        )
        .await
        .expect_err("the listener hangs up");

        // reqwest-websocket upgrades over HTTP/1.1 only: a TLS terminator that picks h2, as
        // Caddy does by default, would fail every WebSocket.
        let hello = hello.await.expect("ClientHello");
        assert_eq!(offered_protocols(&hello), Some(vec!["http/1.1".to_owned()]));
    }

    /// The protocols a TLS ClientHello record offers in its ALPN extension.
    fn offered_protocols(hello: &[u8]) -> Option<Vec<String>> {
        let number = |at: usize, width: usize| -> Option<usize> {
            hello.get(at..at + width).map(|bytes| {
                bytes
                    .iter()
                    .fold(0, |value, byte| value << 8 | usize::from(*byte))
            })
        };
        // Record header, handshake header, client version and random.
        let mut at = 5 + 4 + 2 + 32;
        at += 1 + number(at, 1)?; // session id
        at += 2 + number(at, 2)?; // cipher suites
        at += 1 + number(at, 1)?; // compression methods
        let end = at + 2 + number(at, 2)?;
        at += 2;
        while at + 4 <= end {
            let (kind, size) = (number(at, 2)?, number(at + 2, 2)?);
            at += 4;
            if kind == 0x0010 {
                let mut protocols = Vec::new();
                let mut entry = at + 2;
                while entry < at + size {
                    let length = number(entry, 1)?;
                    let name = hello.get(entry + 1..entry + 1 + length)?;
                    protocols.push(String::from_utf8_lossy(name).into_owned());
                    entry += 1 + length;
                }
                return Some(protocols);
            }
            at += size;
        }
        None
    }

    #[tokio::test]
    async fn a_refused_websocket_upgrade_reports_the_status() {
        let app = axum::Router::new().route(
            "/v1/agent/demo",
            axum::routing::get(|| async { axum::http::StatusCode::UNAUTHORIZED }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind refusing relay");
        let address = listener.local_addr().expect("refusing relay address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve refusing relay");
        });
        let client = super::relay_client().expect("relay client");

        let error = super::connect_websocket(
            &client,
            &format!("http://{address}"),
            "/v1/agent/demo",
            "rva_test",
        )
        .await
        .expect_err("the relay refused the upgrade")
        .to_string();

        assert!(error.contains("401"), "{error}");
    }

    #[tokio::test]
    async fn websocket_errors_show_their_cause_without_the_url() {
        // Nothing listens on the port once this listener is gone.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("pick a free port")
            .port();
        let client = super::relay_client().expect("relay client");

        // reqwest prints the URL it was sending to, here with a marker in its query.
        let error = super::connect_websocket(
            &client,
            &format!("http://127.0.0.1:{port}/?url-marker"),
            "/v1/agent/demo",
            "rva_test",
        )
        .await
        .expect_err("nothing listens")
        .to_string();

        assert!(error.contains("refused"), "{error}");
        assert!(!error.contains("url-marker"), "{error}");
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
