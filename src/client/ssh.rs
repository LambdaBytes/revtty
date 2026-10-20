use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use reqwest_websocket::WebSocket;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, Disconnect, Preferred, Sig, client};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::error::RevttyError;
use crate::protocol::{PROBE_COMMAND, ProbeResult};
use crate::transport::{SSH_TIMEOUTS, SshTimeouts, finish_byte_stream, websocket_byte_stream};

const STDIN_CHUNK: usize = 4096;
const STDIN_QUEUE_DEPTH: usize = 16;
/// Bound on key exchange plus operator authentication; russh does not bound the wait for
/// the agent's banner on the client side.
const SSH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// From the authenticated session to the agent's whole answer to `PROBE_COMMAND`.
const PROBE_ANSWER_TIMEOUT: Duration = Duration::from_secs(10);
/// A probe answer is a few short strings.
const PROBE_ANSWER_LIMIT: usize = 4096;

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

/// Opens the session channel and starts a PTY shell, waiting for the agent to confirm each
/// step so a refusal is reported instead of leaving a silent terminal.
async fn open_terminal_channel(
    session: &client::Handle<ClientHandler>,
    term: &str,
    cols: u32,
    rows: u32,
) -> Result<Channel<client::Msg>, RevttyError> {
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|error| RevttyError::runtime("open SSH terminal channel", error))?;

    channel
        .request_pty(true, term, cols, rows, 0, 0, &[])
        .await
        .map_err(|error| RevttyError::runtime("request remote PTY", error))?;
    expect_channel_success(&mut channel, "allocate a remote PTY").await?;

    channel
        .request_shell(true)
        .await
        .map_err(|error| RevttyError::runtime("request remote shell", error))?;
    expect_channel_success(&mut channel, "start a remote shell").await?;

    Ok(channel)
}

async fn expect_channel_success(
    channel: &mut Channel<client::Msg>,
    action: &str,
) -> Result<(), RevttyError> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => {
                return Err(RevttyError::message(format!("agent could not {action}")));
            }
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {
                return Err(RevttyError::message(format!(
                    "agent closed the terminal before it could {action}"
                )));
            }
            Some(_) => {}
        }
    }
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

/// The operator's private key and the pinned agent host key a session authenticates with.
fn session_keys(
    operator_key_path: &Path,
    encoded_host_key: &str,
) -> Result<(PrivateKey, PublicKey), RevttyError> {
    let operator_key = PrivateKey::read_openssh_file(operator_key_path)
        .map_err(|error| RevttyError::runtime("read operator SSH private key", error))?;
    let expected_server_key = PublicKey::from_openssh(encoded_host_key)
        .map_err(|error| RevttyError::runtime("parse pinned agent host key", error))?;

    if expected_server_key.algorithm() != Algorithm::Ed25519 {
        return Err(RevttyError::message(
            "v1 requires an Ed25519 agent host key",
        ));
    }

    Ok((operator_key, expected_server_key))
}

/// Ends the transport under a finished session. When the session failed because its
/// transport did, as when the relay explains a refused session, that is the error to report:
/// the session can fail on the closed stream before the transport task has returned it.
async fn finish_session<T>(
    result: Result<T, RevttyError>,
    bridge_task: JoinHandle<Result<(), RevttyError>>,
) -> Result<T, RevttyError> {
    let transport_error = finish_byte_stream(bridge_task).await;
    match (result, transport_error) {
        (Err(_), Some(error)) => Err(error),
        (result, _) => result,
    }
}

/// Runs `PROBE_COMMAND` on the agent over SSH and returns its answer: the session proves the
/// pinned host key, and the agent checks the operator's key against its own list.
pub async fn run_probe(
    websocket: WebSocket,
    operator_key_path: &Path,
    encoded_host_key: &str,
    target: &str,
) -> Result<ProbeResult, RevttyError> {
    let (operator_key, expected_server_key) = session_keys(operator_key_path, encoded_host_key)?;
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

        let answer = tokio::time::timeout(PROBE_ANSWER_TIMEOUT, probe_answer(&session, target))
            .await
            .unwrap_or_else(|_| {
                Err(RevttyError::message(format!(
                    "the agent did not answer the probe within {}s",
                    PROBE_ANSWER_TIMEOUT.as_secs()
                )))
            });
        // Hanging up ends the agent's session and gives its slot back.
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await;
        answer
    }
    .await;

    finish_session(result, bridge_task).await
}

/// The answer of the agent `session` reached, which must call itself `target`.
async fn probe_answer(
    session: &client::Handle<ClientHandler>,
    target: &str,
) -> Result<ProbeResult, RevttyError> {
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|error| RevttyError::runtime("open SSH probe channel", error))?;
    channel
        .exec(true, PROBE_COMMAND)
        .await
        .map_err(|error| RevttyError::runtime("request probe", error))?;

    let mut answer = Vec::new();
    let mut exit_status = None;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Failure) => {
                return Err(RevttyError::message("the agent refused the probe"));
            }
            Some(ChannelMsg::Data { data }) => {
                if answer.len() + data.len() > PROBE_ANSWER_LIMIT {
                    return Err(RevttyError::message(format!(
                        "the agent's probe answer exceeds {PROBE_ANSWER_LIMIT} bytes"
                    )));
                }
                answer.extend_from_slice(&data);
            }
            Some(ChannelMsg::ExitStatus {
                exit_status: status,
            }) => exit_status = Some(status),
            Some(ChannelMsg::Close) | None => break,
            Some(_) => {}
        }
    }

    if exit_status != Some(0) {
        return Err(RevttyError::message(
            "the agent's probe ended without succeeding",
        ));
    }
    let result: ProbeResult = serde_json::from_slice(&answer)
        .map_err(|error| RevttyError::runtime("decode probe result", error))?;
    if result.name != target {
        return Err(RevttyError::message(format!(
            "the agent answered the probe as {:?}, not as {target}",
            result.name
        )));
    }
    Ok(result)
}

/// Runs an interactive terminal session; returns the remote exit status, or `None` when the
/// session ended without one (for example because the agent went away).
pub async fn connect_terminal(
    websocket: WebSocket,
    operator_key_path: &Path,
    encoded_host_key: &str,
) -> Result<Option<u32>, RevttyError> {
    let (operator_key, expected_server_key) = session_keys(operator_key_path, encoded_host_key)?;
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

        let (cols, rows) = size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());
        let mut channel =
            open_terminal_channel(&session, &term, u32::from(cols), u32::from(rows)).await?;

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

        Ok(exit_status)
    }
    .await;

    finish_session(result, bridge_task).await
}

/// Why `revtty exec` stopped waiting for a command.
#[derive(Clone, Copy)]
pub enum Stop {
    /// `--timeout` was over.
    TimedOut,
    /// Ctrl-C.
    Interrupted,
}

/// How a command `run_command` ran ended, as far as this operator knows.
pub enum CommandEnd {
    /// It exited with this status.
    Exited(u32),
    /// The signal of this SSH name killed it.
    Killed(String),
    /// The session ended without saying.
    Unknown,
    /// This operator stopped waiting first; the agent ends a command whose session ends.
    Stopped(Stop),
}

/// Most of each output stream a `Capture` keeps: 16 MiB.
pub const CAPTURE_LIMIT: usize = 16 * 1024 * 1024;

/// One of a command's output streams, kept in memory up to `CAPTURE_LIMIT` bytes.
#[derive(Default)]
pub struct Captured {
    pub bytes: Vec<u8>,
    /// More than `CAPTURE_LIMIT` bytes arrived: the rest was read and dropped.
    pub truncated: bool,
}

impl Captured {
    fn keep(&mut self, chunk: &[u8]) {
        let room = CAPTURE_LIMIT - self.bytes.len();
        if chunk.len() > room {
            self.truncated = true;
        }
        self.bytes
            .extend_from_slice(&chunk[..chunk.len().min(room)]);
    }
}

/// A command's stdout and stderr, kept instead of written here.
#[derive(Default)]
pub struct Capture {
    pub stdout: Captured,
    pub stderr: Captured,
}

/// Runs `command` on the agent over SSH: its stdout and stderr go to the local ones, or to
/// `capture` if there is one, and the local stdin goes to it if `forward_stdin`. `stop` ends
/// the run at any point, writing the output here included: its transport is cut, the agent
/// sees the session end and ends the command, and output not yet written here is dropped;
/// what `capture` got by then stays there.
pub async fn run_command(
    websocket: WebSocket,
    operator_key_path: &Path,
    encoded_host_key: &str,
    command: &str,
    forward_stdin: bool,
    capture: Option<&mut Capture>,
    stop: impl Future<Output = Stop>,
) -> Result<CommandEnd, RevttyError> {
    let (operator_key, expected_server_key) = session_keys(operator_key_path, encoded_host_key)?;
    let (stream, bridge_task) = websocket_byte_stream(websocket);
    let transport = bridge_task.abort_handle();
    tokio::pin!(stop);

    let result = tokio::select! {
        result = command_session(
            stream,
            operator_key,
            expected_server_key,
            command,
            forward_stdin,
            capture,
        ) => result,
        stopped = &mut stop => {
            transport.abort();
            return Ok(CommandEnd::Stopped(stopped));
        }
    };

    // The wait for the transport to close counts towards the run that `stop` bounds too.
    tokio::select! {
        result = finish_session(result, bridge_task) => result,
        stopped = stop => {
            transport.abort();
            Ok(CommandEnd::Stopped(stopped))
        }
    }
}

async fn command_session<S>(
    stream: S,
    operator_key: PrivateKey,
    expected_server_key: PublicKey,
    command: &str,
    forward_stdin: bool,
    capture: Option<&mut Capture>,
) -> Result<CommandEnd, RevttyError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
        .map_err(|error| RevttyError::runtime("open SSH command channel", error))?;
    channel
        .exec(true, command)
        .await
        .map_err(|error| RevttyError::runtime("request remote command", error))?;
    expect_channel_success(&mut channel, "run the command").await?;

    // Without input to send, a receiver whose sender is gone: the command's stdin closes at
    // once.
    let mut stdin = if forward_stdin {
        spawn_stdin_reader()
    } else {
        mpsc::channel(1).1
    };
    let mut stdin_open = true;
    let (mut stdout, mut stderr) = match capture {
        Some(Capture { stdout, stderr }) => (Output::Captured(stdout), Output::Captured(stderr)),
        None => (
            Output::Local(OutputWriter::spawn("output", Box::new(io::stdout()))),
            Output::Local(OutputWriter::spawn("error output", Box::new(io::stderr()))),
        ),
    };
    let mut end = CommandEnd::Unknown;

    loop {
        tokio::select! {
            read = stdin.recv(), if stdin_open => match read {
                None => {
                    stdin_open = false;
                    let _ = channel.eof().await;
                }
                Some(Ok(input)) => {
                    channel
                        .data_bytes(input)
                        .await
                        .map_err(|error| RevttyError::runtime("send command input", error))?;
                }
                Some(Err(error)) => return Err(RevttyError::runtime("read local input", error)),
            },
            message = channel.wait() => match message {
                Some(ChannelMsg::Data { data }) => stdout.write(&data).await?,
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => stderr.write(&data).await?,
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    end = CommandEnd::Exited(exit_status);
                }
                Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                    end = CommandEnd::Killed(signal_name_text(&signal_name));
                }
                // The exit status may follow the agent's EOF; only the close ends the command.
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
        }
    }

    stdout.finish().await?;
    stderr.finish().await?;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    Ok(end)
}

/// Where `command_session` puts one of the command's output streams.
enum Output<'a> {
    Local(OutputWriter),
    Captured(&'a mut Captured),
}

impl Output<'_> {
    async fn write(&mut self, chunk: &[u8]) -> Result<(), RevttyError> {
        match self {
            Self::Local(writer) => writer.write(chunk.to_vec()).await,
            Self::Captured(captured) => {
                captured.keep(chunk);
                Ok(())
            }
        }
    }

    async fn finish(self) -> Result<(), RevttyError> {
        match self {
            Self::Local(writer) => writer.finish().await,
            Self::Captured(_) => Ok(()),
        }
    }
}

/// Chunks of a command's output queued for a local writer thread.
const OUTPUT_QUEUE_DEPTH: usize = 16;

/// Writes one of a command's output streams here on a thread of its own, so that a local
/// reader that stops reading holds up only that thread, never what stops the run; what is
/// still queued then goes with the process.
struct OutputWriter {
    queue: mpsc::Sender<Vec<u8>>,
    written: oneshot::Receiver<io::Result<()>>,
    name: &'static str,
}

impl OutputWriter {
    fn spawn(name: &'static str, mut output: Box<dyn Write + Send>) -> Self {
        let (queue, mut chunks) = mpsc::channel::<Vec<u8>>(OUTPUT_QUEUE_DEPTH);
        let (done, written) = oneshot::channel();

        std::thread::spawn(move || {
            let mut write_all = || -> io::Result<()> {
                while let Some(chunk) = chunks.blocking_recv() {
                    output.write_all(&chunk)?;
                    output.flush()?;
                }
                Ok(())
            };
            let _ = done.send(write_all());
        });

        Self {
            queue,
            written,
            name,
        }
    }

    async fn write(&mut self, chunk: Vec<u8>) -> Result<(), RevttyError> {
        if self.queue.send(chunk).await.is_ok() {
            return Ok(());
        }
        // The thread stops taking chunks only once a write failed.
        Err(write_failure(self.name, (&mut self.written).await))
    }

    /// Waits until everything queued is written.
    async fn finish(self) -> Result<(), RevttyError> {
        drop(self.queue);
        match self.written.await {
            Ok(Ok(())) => Ok(()),
            failed => Err(write_failure(self.name, failed)),
        }
    }
}

fn write_failure(
    name: &str,
    written: Result<io::Result<()>, oneshot::error::RecvError>,
) -> RevttyError {
    match written {
        Ok(Err(error)) => RevttyError::runtime(&format!("write command {name}"), error),
        _ => RevttyError::message(format!("the writer of command {name} stopped")),
    }
}

/// A signal's SSH name (RFC 4254, section 6.10).
fn signal_name_text(signal: &Sig) -> String {
    match signal {
        Sig::ABRT => "ABRT",
        Sig::ALRM => "ALRM",
        Sig::FPE => "FPE",
        Sig::HUP => "HUP",
        Sig::ILL => "ILL",
        Sig::INT => "INT",
        Sig::KILL => "KILL",
        Sig::PIPE => "PIPE",
        Sig::QUIT => "QUIT",
        Sig::SEGV => "SEGV",
        Sig::TERM => "TERM",
        Sig::USR1 => "USR1",
        Sig::Custom(name) => name,
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use russh::keys::key::safe_rng;
    use russh::keys::{Algorithm, PrivateKey, PublicKey};
    use russh::{client, server};

    use std::time::Duration;

    use super::{
        CAPTURE_LIMIT, Captured, ClientHandler, client_config, ed25519_only, open_session,
        open_terminal_channel, probe_answer,
    };
    use crate::error::RevttyError;
    use crate::protocol::ProbeResult;
    use crate::transport::test_support::{ControlledStream, StreamControl};
    use crate::transport::{SSH_TIMEOUTS, SshTimeouts};

    struct HandshakeOnlyServer;

    impl server::Handler for HandshakeOnlyServer {
        type Error = russh::Error;
    }

    /// Accepts the operator and a session channel but refuses to allocate a PTY.
    struct PtyRefusingServer;

    impl server::Handler for PtyRefusingServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            _public_key: &PublicKey,
        ) -> Result<server::Auth, Self::Error> {
            Ok(server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<server::Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        async fn pty_request(
            &mut self,
            channel: russh::ChannelId,
            _term: &str,
            _col_width: u32,
            _row_height: u32,
            _pix_width: u32,
            _pix_height: u32,
            _modes: &[(russh::Pty, u32)],
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            session.channel_failure(channel)?;
            Ok(())
        }
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

    #[tokio::test]
    async fn refused_pty_is_reported_instead_of_hanging() {
        let host_key = ed25519_key();
        let expected_server_key = host_key.public_key().clone();
        let server_config = server::Config {
            keys: vec![host_key],
            preferred: ed25519_only(),
            ..Default::default()
        };
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            if let Ok(running) =
                server::run_stream(Arc::new(server_config), server_stream, PtyRefusingServer).await
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

        let opened = tokio::time::timeout(
            Duration::from_secs(2),
            open_terminal_channel(&session, "xterm", 80, 24),
        )
        .await
        .expect("PTY refusal was not reported");
        let Err(error) = opened else {
            panic!("terminal opened although the PTY was refused");
        };
        assert!(
            error
                .to_string()
                .contains("could not allocate a remote PTY"),
            "unexpected error: {error}"
        );

        server_task.abort();
        let _ = server_task.await;
    }

    const FORGED_ANSWER: &str = r#"{"name":"demo","os":"forged","arch":"x86_64","version":"0"}"#;

    /// Answers the probe for any operator, as a relay posing as the agent would.
    struct ProbeAnsweringServer;

    impl server::Handler for ProbeAnsweringServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            _public_key: &PublicKey,
        ) -> Result<server::Auth, Self::Error> {
            Ok(server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<server::Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: russh::ChannelId,
            _data: &[u8],
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            session.data(channel, FORGED_ANSWER.as_bytes().to_vec())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    /// A probe of `target` as `run_probe` makes it, to a server holding `server_key`, pinned
    /// as `pinned`.
    async fn probe_through(
        server_key: PrivateKey,
        pinned: PublicKey,
        target: &str,
    ) -> Result<ProbeResult, RevttyError> {
        let server_config = server::Config {
            keys: vec![server_key],
            preferred: ed25519_only(),
            ..Default::default()
        };
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            if let Ok(running) =
                server::run_stream(Arc::new(server_config), server_stream, ProbeAnsweringServer)
                    .await
            {
                let _ = running.await;
            }
        });

        let session = open_session(
            client_stream,
            client_config(SSH_TIMEOUTS),
            pinned,
            ed25519_key(),
            Duration::from_secs(5),
        )
        .await?;
        probe_answer(&session, target).await
    }

    #[tokio::test]
    async fn only_the_pinned_host_key_can_answer_a_probe() {
        // The server answers whoever asks: with the pinned key, its answer comes through.
        let pinned = ed25519_key();
        let pinned_key = pinned.public_key().clone();
        let answer = probe_through(pinned.clone(), pinned_key.clone(), "demo")
            .await
            .expect("the pinned key answered");
        assert_eq!(answer.os, "forged");

        // With any other key, as a relay has, it is refused before it can say anything.
        let Err(refused) = probe_through(ed25519_key(), pinned_key.clone(), "demo").await else {
            panic!("a server without the pinned key answered the probe");
        };
        assert!(refused.to_string().contains("SSH transport"), "{refused}");

        // Nor does the pinned key's answer count for another target.
        let Err(misnamed) = probe_through(pinned, pinned_key, "other").await else {
            panic!("an answer for demo counted as a probe of other");
        };
        assert!(misnamed.to_string().contains("not as other"), "{misnamed}");
    }

    #[test]
    fn a_captured_stream_keeps_its_first_bytes_up_to_the_limit() {
        let mut captured = Captured::default();
        captured.keep(&vec![b'a'; CAPTURE_LIMIT - 1]);
        captured.keep(b"b");
        assert_eq!(captured.bytes.len(), CAPTURE_LIMIT);
        assert!(!captured.truncated, "exactly the limit is not over it");

        let mut captured = Captured::default();
        captured.keep(&vec![b'a'; CAPTURE_LIMIT - 1]);
        // A chunk across the limit keeps what fits, and what comes after it is dropped.
        captured.keep(b"bc");
        captured.keep(b"d");
        assert_eq!(captured.bytes.len(), CAPTURE_LIMIT);
        assert_eq!(captured.bytes.last(), Some(&b'b'));
        assert!(captured.truncated);
    }
}
