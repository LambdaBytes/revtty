use std::fmt::Display;
use std::io;

use thiserror::Error;

/// What kind of failure an error is, when revtty knows it: shown before the message, so that
/// a DNS failure, a refused key or an offline agent are told apart at a glance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Dns,
    Tls,
    /// Refused, reset or unreachable: nothing answered at the network level.
    Connection,
    Timeout,
    /// The relay or the agent did not accept the credential or signature presented.
    Authentication,
    /// The identity was proven, and it may not do what it asked.
    Authorization,
    HostKey,
    Offline,
    /// The other side does not speak what this one asked for.
    Protocol,
    Io,
    Other,
}

impl ErrorKind {
    /// The name shown with an error of this kind; none for `Other`.
    pub fn label(self) -> Option<&'static str> {
        match self {
            Self::Dns => Some("DNS"),
            Self::Tls => Some("TLS"),
            Self::Connection => Some("connection"),
            Self::Timeout => Some("timeout"),
            Self::Authentication => Some("authentication"),
            Self::Authorization => Some("authorization"),
            Self::HostKey => Some("host key"),
            Self::Offline => Some("offline"),
            Self::Protocol => Some("protocol"),
            Self::Io => Some("I/O"),
            Self::Other => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum RevttyError {
    #[error("{message}")]
    Runtime { kind: ErrorKind, message: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl RevttyError {
    pub fn runtime(context: &str, error: impl Display) -> Self {
        Self::new(ErrorKind::Other, format!("{context}: {error}"))
    }

    pub fn message(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Other, message)
    }

    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self::Runtime {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Runtime { kind, .. } => *kind,
            Self::Io(_) => ErrorKind::Io,
        }
    }

    /// `message` in place of this error's text, of the same kind: for a caller that tells
    /// more about the failure without changing what it was.
    pub fn reworded(&self, message: impl Into<String>) -> Self {
        Self::new(self.kind(), message)
    }

    /// A request to the relay that got no answer, with its cause: DNS, TLS, connection or
    /// timeout when the cause tells which.
    pub fn request(context: &str, error: &reqwest::Error) -> Self {
        Self::new(
            request_kind(error),
            format!("{context}: {}", with_sources(error)),
        )
    }
}

/// I/O failures that mean the network path to the relay broke, whenever they happen.
const CONNECTION_FAILURES: [io::ErrorKind; 7] = [
    io::ErrorKind::ConnectionRefused,
    io::ErrorKind::ConnectionReset,
    io::ErrorKind::ConnectionAborted,
    io::ErrorKind::BrokenPipe,
    io::ErrorKind::NotConnected,
    io::ErrorKind::HostUnreachable,
    io::ErrorKind::NetworkUnreachable,
];

fn request_kind(error: &reqwest::Error) -> ErrorKind {
    if error.is_timeout() {
        return ErrorKind::Timeout;
    }
    if error.is_dns() {
        return ErrorKind::Dns;
    }
    let io_kinds = io_error_kinds(error);
    // How tokio-rustls reports a failed TLS handshake or an invalid certificate.
    if error.is_connect() && io_kinds.contains(&io::ErrorKind::InvalidData) {
        ErrorKind::Tls
    } else if error.is_connect()
        || io_kinds
            .iter()
            .any(|kind| CONNECTION_FAILURES.contains(kind))
    {
        ErrorKind::Connection
    } else {
        ErrorKind::Other
    }
}

/// The kinds of the `io::Error`s in `error`'s chain. The error an `io::Error` wraps is
/// reached through `get_ref`: its `source` skips it, and hyper-rustls wraps tokio-rustls'
/// TLS errors that way.
fn io_error_kinds(error: &(dyn std::error::Error + 'static)) -> Vec<io::ErrorKind> {
    let mut kinds = Vec::new();
    let mut next = Some(error);
    while let Some(current) = next {
        next = match current.downcast_ref::<io::Error>() {
            Some(io_error) => {
                kinds.push(io_error.kind());
                match io_error.get_ref() {
                    Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
                    None => current.source(),
                }
            }
            None => current.source(),
        };
    }
    kinds
}

/// `error` followed by its sources: TLS, DNS and connection failures only show in the chain.
pub fn with_sources(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();

    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }

    text
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{ErrorKind, RevttyError, with_sources};

    /// What `relay_client` makes of a request to `url`.
    async fn request_failure(url: &str, timeout: Option<Duration>) -> RevttyError {
        let client = crate::transport::relay_client().expect("relay client");
        let mut request = client.get(url);
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let error = request.send().await.expect_err("the request fails");
        RevttyError::request("reach the relay", &error)
    }

    #[tokio::test]
    async fn a_name_that_does_not_resolve_is_a_dns_failure() {
        // `.invalid` never resolves (RFC 6761).
        let error = request_failure("https://revtty.invalid/health", None).await;

        assert_eq!(error.kind(), ErrorKind::Dns, "{error}");
    }

    #[tokio::test]
    async fn a_refused_connection_is_a_connection_failure() {
        // Nothing listens on the port once this listener is gone.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("pick a free port")
            .port();

        let error = request_failure(&format!("http://127.0.0.1:{port}/health"), None).await;

        assert_eq!(error.kind(), ErrorKind::Connection, "{error}");
    }

    #[tokio::test]
    async fn a_connection_reset_before_the_answer_is_a_connection_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind resetting listener");
        let address = listener.local_addr().expect("resetting listener address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request).await;
            // Closing with no linger sends a reset in place of the answer.
            stream.set_zero_linger().expect("set zero linger");
            drop(stream);
        });

        let error = request_failure(&format!("http://{address}/health"), None).await;

        assert_eq!(error.kind(), ErrorKind::Connection, "{error}");
    }

    #[tokio::test]
    async fn a_server_that_does_not_speak_tls_is_a_tls_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind plain listener");
        let address = listener.local_addr().expect("plain listener address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let mut hello = [0_u8; 512];
            let _ = stream.read(&mut hello).await;
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let error = request_failure(&format!("https://{address}/health"), None).await;

        assert_eq!(error.kind(), ErrorKind::Tls, "{error}");
    }

    #[tokio::test]
    async fn a_server_that_never_answers_is_a_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent listener");
        let address = listener.local_addr().expect("silent listener address");
        let silent = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            std::future::pending::<()>().await;
            drop(stream);
        });

        let error = request_failure(
            &format!("http://{address}/health"),
            Some(Duration::from_millis(300)),
        )
        .await;

        assert_eq!(error.kind(), ErrorKind::Timeout, "{error}");
        silent.abort();
    }

    #[test]
    fn rewording_an_error_keeps_its_kind() {
        let error = RevttyError::new(ErrorKind::Offline, "agent is offline");
        let reworded = error.reworded(format!("{error}; try again later"));

        assert_eq!(reworded.kind(), ErrorKind::Offline);
        assert_eq!(reworded.to_string(), "agent is offline; try again later");
    }

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);

    impl fmt::Display for Layer {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|layer| layer as _)
        }
    }

    #[test]
    fn error_chain_includes_every_cause() {
        let error = Layer(
            "error sending request",
            Some(Box::new(Layer(
                "client error (Connect)",
                Some(Box::new(Layer(
                    "invalid peer certificate: UnknownIssuer",
                    None,
                ))),
            ))),
        );

        assert_eq!(
            with_sources(&error),
            "error sending request: client error (Connect): invalid peer certificate: UnknownIssuer"
        );
    }
}
