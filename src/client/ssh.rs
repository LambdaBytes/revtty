use std::borrow::Cow;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use reqwest_websocket::WebSocket;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, Preferred, client};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::RevttyError;
use crate::transport::{SSH_TIMEOUTS, SshTimeouts, websocket_byte_stream};

const STDIN_CHUNK: usize = 4096;
const STDIN_QUEUE_DEPTH: usize = 16;
/// Bound on key exchange plus operator authentication; russh does not bound the wait for
/// the agent's banner on the client side.
const SSH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

struct ClientHandler {
    expected_server_key: PublicKey,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Compare key material only: the pinned key keeps its OpenSSH comment, while the key
        // presented in the SSH key exchange never carries one.
        Ok(matches!(
            server_public_key,
            PublicKeyOrCertificate::PublicKey { key, .. }
                if key.key_data() == self.expected_server_key.key_data()
        ))
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> Result<Self, RevttyError> {
        enable_raw_mode()
            .map_err(|error| RevttyError::runtime("enable local terminal raw mode", error))?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// Reads local terminal input on a dedicated thread. `tokio::io::stdin` uses the runtime's
/// blocking pool, whose pending read cannot be cancelled, so the runtime would not shut down
/// after the session ends until another key was pressed. A plain thread is not waited for at
/// process exit. The channel closes at EOF; a read error is delivered before it closes.
fn spawn_stdin_reader() -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel(STDIN_QUEUE_DEPTH);

    std::thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buffer = [0_u8; STDIN_CHUNK];

        loop {
            let read = match stdin.read(&mut buffer) {
                Ok(0) => return,
                Ok(read) => Ok(buffer[..read].to_vec()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => Err(error),
            };
            let failed = read.is_err();

            if sender.blocking_send(read).is_err() || failed {
                return;
            }
        }
    });

    receiver
}

fn ed25519_only() -> Preferred {
    Preferred {
        key: Cow::Owned(vec![Algorithm::Ed25519]),
        ..Preferred::default()
    }
}

/// Keepalives keep an idle session open and detect an agent that disappears without
/// closing the connection.
fn client_config(timeouts: SshTimeouts) -> client::Config {
    client::Config {
        preferred: ed25519_only(),
        keepalive_interval: Some(timeouts.keepalive_interval),
        keepalive_max: timeouts.keepalive_max,
        inactivity_timeout: Some(timeouts.inactivity),
        ..Default::default()
    }
}

async fn open_session<S>(
    stream: S,
    config: client::Config,
    expected_server_key: PublicKey,
    operator_key: PrivateKey,
    within: Duration,
) -> Result<client::Handle<ClientHandler>, RevttyError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = async {
        let mut session = client::connect_stream(
            Arc::new(config),
            stream,
            ClientHandler {
                expected_server_key,
            },
        )
        .await
        .map_err(|error| RevttyError::runtime("establish SSH transport", error))?;

        let auth = session
            .authenticate_publickey(
                "revtty",
                PrivateKeyWithHashAlg::new(Arc::new(operator_key), None),
            )
            .await
            .map_err(|error| RevttyError::runtime("authenticate SSH operator key", error))?;

        if !auth.success() {
            return Err(RevttyError::message("SSH public-key authentication failed"));
        }

        Ok(session)
    };

    tokio::time::timeout(within, handshake)
        .await
        .map_err(|_| RevttyError::message("SSH handshake with the agent timed out"))?
}

pub async fn connect_terminal(
    websocket: WebSocket,
    operator_key_path: &Path,
    encoded_host_key: &str,
) -> Result<u32, RevttyError> {
    let operator_key = PrivateKey::read_openssh_file(operator_key_path)
        .map_err(|error| RevttyError::runtime("read operator SSH private key", error))?;
    let expected_server_key = PublicKey::from_openssh(encoded_host_key)
        .map_err(|error| RevttyError::runtime("parse pinned agent host key", error))?;

    if expected_server_key.algorithm() != Algorithm::Ed25519 {
        return Err(RevttyError::message(
            "v1 requires an Ed25519 agent host key",
        ));
    }

    let (stream, bridge_task) = websocket_byte_stream(websocket);

    let result = async {
        let session = open_session(
            stream,
            client_config(SSH_TIMEOUTS),
            expected_server_key,
            operator_key,
            SSH_HANDSHAKE_TIMEOUT,
        )
        .await?;

        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|error| RevttyError::runtime("open SSH terminal channel", error))?;

        let (cols, rows) = size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());

        channel
            .request_pty(false, &term, u32::from(cols), u32::from(rows), 0, 0, &[])
            .await
            .map_err(|error| RevttyError::runtime("request remote PTY", error))?;
        channel
            .request_shell(false)
            .await
            .map_err(|error| RevttyError::runtime("request remote shell", error))?;

        let mut resize =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .map_err(|error| RevttyError::runtime("listen for terminal resize", error))?;

        let _raw_mode = RawModeGuard::enter()?;
        let mut stdin = spawn_stdin_reader();
        let mut stdout = tokio::io::stdout();
        let mut stdin_closed = false;
        let mut exit_status = None;

        loop {
            tokio::select! {
                read = stdin.recv(), if !stdin_closed => {
                    match read {
                        None => {
                            stdin_closed = true;
                            let _ = channel.eof().await;
                        }
                        Some(Ok(input)) => {
                            channel
                                .data_bytes(input)
                                .await
                                .map_err(|error| RevttyError::runtime("send terminal input", error))?;
                        }
                        Some(Err(error)) => {
                            return Err(RevttyError::runtime("read local terminal input", error));
                        }
                    }
                }
                Some(()) = resize.recv() => {
                    let (cols, rows) = size()
                        .map_err(|error| RevttyError::runtime("read local terminal size", error))?;
                    channel
                        .window_change(u32::from(cols), u32::from(rows), 0, 0)
                        .await
                        .map_err(|error| RevttyError::runtime("resize remote PTY", error))?;
                }
                message = channel.wait() => {
                    match message {
                        Some(ChannelMsg::Data { data }) => {
                            stdout
                                .write_all(&data)
                                .await
                                .map_err(|error| RevttyError::runtime("write terminal output", error))?;
                            stdout
                                .flush()
                                .await
                                .map_err(|error| RevttyError::runtime("flush terminal output", error))?;
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            stdout
                                .write_all(&data)
                                .await
                                .map_err(|error| RevttyError::runtime("write terminal output", error))?;
                            stdout
                                .flush()
                                .await
                                .map_err(|error| RevttyError::runtime("flush terminal output", error))?;
                        }
                        Some(ChannelMsg::ExitStatus { exit_status: status }) => {
                            exit_status = Some(status);
                        }
                        Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                        _ => {}
                    }
                }
            }
        }

        let _ = session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await;

        Ok(exit_status.unwrap_or(0))
    }
    .await;

    if result.is_err() && bridge_task.is_finished() {
        let bridge_result = bridge_task.await;
        return match bridge_result {
            Ok(Err(error)) => Err(error),
            _ => result,
        };
    }

    bridge_task.abort();
    let _ = bridge_task.await;
    result
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use russh::keys::key::safe_rng;
    use russh::keys::{Algorithm, PrivateKey, PublicKey};
    use russh::{client, server};

    use std::time::Duration;

    use super::{ClientHandler, client_config, ed25519_only, open_session};
    use crate::transport::SshTimeouts;
    use crate::transport::test_support::{ControlledStream, StreamControl};

    struct HandshakeOnlyServer;

    impl server::Handler for HandshakeOnlyServer {
        type Error = russh::Error;
    }

    /// Accepts any operator key; stands in for the agent where only liveness matters.
    struct AcceptingServer;

    impl server::Handler for AcceptingServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            _public_key: &PublicKey,
        ) -> Result<server::Auth, Self::Error> {
            Ok(server::Auth::Accept)
        }
    }

    const FAST_TIMEOUTS: SshTimeouts = SshTimeouts {
        keepalive_interval: Duration::from_millis(100),
        keepalive_max: 3,
        inactivity: Duration::from_millis(300),
    };

    fn ed25519_key() -> PrivateKey {
        PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).expect("generate Ed25519 key")
    }

    #[tokio::test]
    async fn accepts_pinned_host_key_with_comment() {
        let mut host_key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519)
            .expect("generate Ed25519 host key");
        host_key.set_comment("revtty-agent");

        // The relay hands out the host key as persisted OpenSSH text, which keeps the comment;
        // the key presented during the SSH key exchange never carries one.
        let expected_server_key =
            PublicKey::from_openssh(&host_key.public_key().to_openssh().expect("encode host key"))
                .expect("parse host key");

        let server_config = server::Config {
            keys: vec![host_key],
            preferred: ed25519_only(),
            ..Default::default()
        };
        let client_config = client::Config {
            preferred: ed25519_only(),
            ..Default::default()
        };

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            if let Ok(running) =
                server::run_stream(Arc::new(server_config), server_stream, HandshakeOnlyServer)
                    .await
            {
                let _ = running.await;
            }
        });

        let session = client::connect_stream(
            Arc::new(client_config),
            client_stream,
            ClientHandler {
                expected_server_key,
            },
        )
        .await;
        assert!(
            session.is_ok(),
            "pinned host key with a comment was rejected"
        );

        drop(session);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn operator_session_detects_stalled_agent() {
        let host_key = ed25519_key();
        let expected_server_key = host_key.public_key().clone();
        let server_config = server::Config {
            keys: vec![host_key],
            preferred: ed25519_only(),
            ..Default::default()
        };

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let control = StreamControl::default();
        let client_stream = ControlledStream::new(client_stream, control.clone());

        let server_task = tokio::spawn(async move {
            if let Ok(running) =
                server::run_stream(Arc::new(server_config), server_stream, AcceptingServer).await
            {
                let _ = running.await;
            }
        });

        let session = open_session(
            client_stream,
            client_config(FAST_TIMEOUTS),
            expected_server_key,
            ed25519_key(),
            Duration::from_secs(5),
        )
        .await
        .expect("open operator session");

        // The agent's side goes silent and stops accepting data.
        control.stall();

        let deadline = tokio::time::Instant::now() + FAST_TIMEOUTS.inactivity * 5;
        while !session.is_closed() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            session.is_closed(),
            "operator session stayed open on a stalled transport"
        );

        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn handshake_times_out_when_agent_never_answers() {
        let (client_stream, _silent_agent) = tokio::io::duplex(64 * 1024);

        let opened = tokio::time::timeout(
            Duration::from_secs(5),
            open_session(
                client_stream,
                client_config(FAST_TIMEOUTS),
                ed25519_key().public_key().clone(),
                ed25519_key(),
                Duration::from_millis(300),
            ),
        )
        .await;

        assert!(
            matches!(opened, Ok(Err(_))),
            "SSH handshake against a silent agent was not bounded"
        );
    }
}
