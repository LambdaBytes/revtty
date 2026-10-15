use std::borrow::Cow;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use portable_pty::{Child, CommandBuilder, MasterPty, PtyPair, PtySize, native_pty_system};
use reqwest::Client;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Msg, Session};
use russh::{Channel, ChannelId, Preferred, Pty};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::config::Paths;
use crate::error::RevttyError;
use crate::identity::ensure_agent;
use crate::transport::{SSH_TIMEOUTS, SshTimeouts, connect_websocket, websocket_byte_stream};

const PTY_IO_CHUNK: usize = 16 * 1024;

/// Operator input accepted but not yet written to the PTY. russh replenishes the SSH window
/// as soon as data arrives, so SSH flow control cannot hold the operator back while the
/// remote process is not reading; past this bound the session is closed instead.
const INPUT_PENDING_LIMIT: usize = 8 * 1024 * 1024;
const INPUT_LIMIT_MESSAGE: &[u8] =
    b"\r\nrevtty: remote input buffer limit exceeded; closing session\r\n";

const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Time a shell gets to exit after hangup before it is killed.
const HANGUP_GRACE: Duration = Duration::from_secs(5);
const KILL_REAP_WAIT: Duration = Duration::from_secs(5);
/// Output still forwarded after the shell exits; a background job may keep the PTY open.
const OUTPUT_DRAIN_WAIT: Duration = Duration::from_secs(1);

/// Lets the agent stop every shell and wait for the teardowns before its runtime shuts down.
#[derive(Clone)]
pub struct ShellShutdown {
    signal: watch::Receiver<bool>,
    // Only shell supervisors hold strong senders, so the agent can wait for the channel to
    // close; once the agent drops its own sender no new shell can start.
    guard: mpsc::WeakSender<()>,
}

impl ShellShutdown {
    pub fn new(signal: watch::Receiver<bool>, guard: &mpsc::Sender<()>) -> Self {
        Self {
            signal,
            guard: guard.downgrade(),
        }
    }
}

struct PendingPty {
    channel: ChannelId,
    term: String,
    pair: PtyPair,
}

enum PtyInput {
    Data(Vec<u8>),
    Eof,
}

/// Handler-side view of a running shell. Dropping it (channel close, session end or
/// handler drop) closes `close`, which tells the shell supervisor to tear the shell down.
struct ActiveShell {
    channel: ChannelId,
    master: Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>,
    input: Option<mpsc::UnboundedSender<PtyInput>>,
    pending_input: Arc<AtomicUsize>,
    _close: oneshot::Sender<()>,
}

struct AgentSshHandler {
    authorized_operator: PublicKey,
    shutdown: ShellShutdown,
    open_channel: Option<ChannelId>,
    pending_pty: Option<PendingPty>,
    active_shell: Option<ActiveShell>,
}

impl AgentSshHandler {
    fn new(authorized_operator: PublicKey, shutdown: ShellShutdown) -> Self {
        Self {
            authorized_operator,
            shutdown,
            open_channel: None,
            pending_pty: None,
            active_shell: None,
        }
    }

    fn close_input(&mut self, channel: ChannelId) {
        let Some(active) = self
            .active_shell
            .as_mut()
            .filter(|active| active.channel == channel)
        else {
            return;
        };

        if let Some(input) = active.input.take() {
            let _ = input.send(PtyInput::Eof);
        }
    }

    /// Refuses the terminal and closes its channel, so the operator gets an answer instead of
    /// a silent terminal.
    fn refuse_terminal(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        session.channel_failure(channel)?;
        session.close(channel)?;
        self.close_shell(channel);
        Ok(())
    }

    fn close_shell(&mut self, channel: ChannelId) {
        if self
            .pending_pty
            .as_ref()
            .is_some_and(|pending| pending.channel == channel)
        {
            self.pending_pty.take();
        }

        if self
            .active_shell
            .as_ref()
            .is_some_and(|active| active.channel == channel)
        {
            self.active_shell.take();
        }

        if self.open_channel == Some(channel) {
            self.open_channel = None;
        }
    }
}

impl server::Handler for AgentSshHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        // Compare key material only: the enrolled key keeps its OpenSSH comment, while the key
        // presented in SSH authentication never carries one.
        if user == "revtty" && public_key.key_data() == self.authorized_operator.key_data() {
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.open_channel.is_some() {
            return Ok(());
        }

        self.open_channel = Some(channel.id());
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.open_channel != Some(channel)
            || self.pending_pty.is_some()
            || self.active_shell.is_some()
        {
            session.channel_failure(channel)?;
            return Ok(());
        }

        let size = pty_size(col_width, row_height, pix_width, pix_height);
        match native_pty_system().openpty(size) {
            Ok(pair) => {
                self.pending_pty = Some(PendingPty {
                    channel,
                    term: term.to_owned(),
                    pair,
                });
                session.channel_success(channel)?;
            }
            Err(error) => {
                eprintln!("PTY allocation failed: {error}");
                self.refuse_terminal(channel, session)?;
            }
        }

        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(pending) = self
            .pending_pty
            .take()
            .filter(|pending| pending.channel == channel)
        else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        // No new shell once the agent has started shutting down.
        let guard = match self.shutdown.guard.upgrade() {
            Some(guard) if !*self.shutdown.signal.borrow() => guard,
            _ => {
                self.refuse_terminal(channel, session)?;
                return Ok(());
            }
        };

        let PendingPty {
            channel,
            term,
            pair,
        } = pending;
        let PtyPair { slave, master } = pair;

        let pty = match open_pty_io(master.as_ref()) {
            Ok(pty) => Arc::new(pty),
            Err(error) => {
                eprintln!("PTY I/O setup failed: {error}");
                self.refuse_terminal(channel, session)?;
                return Ok(());
            }
        };

        let mut command = CommandBuilder::new_default_prog();
        command.env("TERM", term);

        let child = match slave.spawn_command(command) {
            Ok(child) => child,
            Err(error) => {
                eprintln!("shell spawn failed: {error}");
                self.refuse_terminal(channel, session)?;
                return Ok(());
            }
        };
        drop(slave);

        let handle = session.handle();
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let pending_input = Arc::new(AtomicUsize::new(0));
        let (close_tx, close_rx) = oneshot::channel();
        let master = Arc::new(Mutex::new(Some(master)));

        let output_task = tokio::spawn(forward_pty_output(
            Arc::clone(&pty),
            handle.clone(),
            channel,
        ));
        let input_task = tokio::spawn(forward_pty_input(
            Arc::clone(&pty),
            input_rx,
            Arc::clone(&pending_input),
        ));

        tokio::spawn(supervise_shell(ShellSupervisor {
            child,
            pty,
            master: Arc::clone(&master),
            output_task,
            input_task,
            handle,
            channel,
            close: close_rx,
            shutdown: self.shutdown.signal.clone(),
            _guard: guard,
        }));

        self.active_shell = Some(ActiveShell {
            channel,
            master,
            input: Some(input_tx),
            pending_input,
            _close: close_tx,
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Never wait here: russh runs this callback inside the session loop, which must keep
        // processing disconnects, keepalives and channel closes while the PTY is not reading.
        let Some(active) = self
            .active_shell
            .as_ref()
            .filter(|active| active.channel == channel)
        else {
            return Ok(());
        };
        let Some(input) = active.input.as_ref() else {
            return Ok(());
        };

        let pending = active
            .pending_input
            .fetch_add(data.len(), Ordering::AcqRel)
            .saturating_add(data.len());
        if pending > INPUT_PENDING_LIMIT {
            session.extended_data(channel, 1, INPUT_LIMIT_MESSAGE.to_vec())?;
            session.close(channel)?;
            self.close_shell(channel);
            return Ok(());
        }

        let _ = input.send(PtyInput::Data(data.to_vec()));
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let size = pty_size(col_width, row_height, pix_width, pix_height);

        if let Some(pending) = self
            .pending_pty
            .as_ref()
            .filter(|pending| pending.channel == channel)
        {
            let _ = pending.pair.master.resize(size);
        }

        if let Some(active) = self
            .active_shell
            .as_ref()
            .filter(|active| active.channel == channel)
            && let Ok(master) = active.master.lock()
            && let Some(master) = master.as_ref()
        {
            let _ = master.resize(size);
        }

        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.close_input(channel);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.close_shell(channel);
        Ok(())
    }
}

/// Non-blocking duplicate of the PTY master for async I/O. It replaces portable-pty's
/// reader and writer, whose blocking reads cannot be cancelled and whose writer's `Drop`
/// blocks writing a newline and EOF into the terminal.
fn open_pty_io(master: &dyn MasterPty) -> io::Result<AsyncFd<File>> {
    let raw = master
        .as_raw_fd()
        .ok_or_else(|| io::Error::other("PTY master has no file descriptor"))?;
    // SAFETY: `master` owns `raw` and stays alive for the duration of this borrow.
    let duplicate: OwnedFd = unsafe { BorrowedFd::borrow_raw(raw) }.try_clone_to_owned()?;

    // O_NONBLOCK lives on the shared open file description, so the master becomes
    // non-blocking too; it is only used for resize and termios, which are unaffected.
    // SAFETY: `duplicate` is a valid, owned file descriptor.
    let flags = unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe {
        libc::fcntl(
            duplicate.as_raw_fd(),
            libc::F_SETFL,
            flags | libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the `File` owns the descriptor, which stays open and unchanged for as long as
    // the `AsyncFd` owns the `File`.
    unsafe { AsyncFd::register(File::from(duplicate)) }.map_err(|error| error.into_parts().1)
}

async fn read_pty(pty: &AsyncFd<File>, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut ready = pty.readable().await?;
        match ready.try_io(|inner| {
            let mut file: &File = inner.get_ref();
            file.read(buffer)
        }) {
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
            Ok(result) => return result,
            Err(_would_block) => {}
        }
    }
}

async fn write_pty(pty: &AsyncFd<File>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let mut ready = pty.writable().await?;
        match ready.try_io(|inner| {
            let mut file: &File = inner.get_ref();
            file.write(data)
        }) {
            Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(Ok(written)) => data = &data[written..],
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
            Ok(Err(error)) => return Err(error),
            Err(_would_block) => {}
        }
    }

    Ok(())
}

/// Ends at EOF; on Linux the master reads EIO once every slave descriptor is closed.
async fn forward_pty_output(pty: Arc<AsyncFd<File>>, handle: server::Handle, channel: ChannelId) {
    let mut buffer = vec![0_u8; PTY_IO_CHUNK];

    loop {
        let read = match read_pty(&pty, &mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };

        if handle.data(channel, buffer[..read].to_vec()).await.is_err() {
            return;
        }
    }
}

async fn forward_pty_input(
    pty: Arc<AsyncFd<File>>,
    mut input: mpsc::UnboundedReceiver<PtyInput>,
    pending: Arc<AtomicUsize>,
) {
    while let Some(message) = input.recv().await {
        match message {
            PtyInput::Data(data) => {
                if write_pty(&pty, &data).await.is_err() {
                    return;
                }
                pending.fetch_sub(data.len(), Ordering::AcqRel);
            }
            PtyInput::Eof => {
                // Operator EOF reaches the terminal as the line discipline's EOF character,
                // which is only honoured at the start of a line.
                if let Some(eof) = terminal_eof_char(&pty) {
                    let _ = write_pty(&pty, &[b'\n', eof]).await;
                }
                return;
            }
        }
    }
}

fn terminal_eof_char(pty: &AsyncFd<File>) -> Option<u8> {
    // SAFETY: zeroed termios is a valid out-parameter for tcgetattr.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is a valid PTY master owned by `pty`.
    if unsafe { libc::tcgetattr(pty.as_raw_fd(), &mut termios) } != 0 {
        return None;
    }

    Some(termios.c_cc[libc::VEOF]).filter(|eof| *eof != 0)
}

/// Single owner of a shell process: the only code that reaps it and the only code that
/// signals it, and only while it is still unreaped, so a signal can never reach a reused PID.
struct ShellSupervisor {
    child: Box<dyn Child + Send + Sync>,
    pty: Arc<AsyncFd<File>>,
    master: Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>,
    output_task: JoinHandle<()>,
    input_task: JoinHandle<()>,
    handle: server::Handle,
    channel: ChannelId,
    close: oneshot::Receiver<()>,
    shutdown: watch::Receiver<bool>,
    _guard: mpsc::Sender<()>,
}

enum ShellEnd {
    Exited(u32),
    SessionClosed,
    AgentShutdown,
}

async fn supervise_shell(mut supervisor: ShellSupervisor) {
    let mut poll = tokio::time::interval(CHILD_POLL_INTERVAL);

    let end = loop {
        tokio::select! {
            _ = poll.tick() => match supervisor.child.try_wait() {
                Ok(Some(status)) => break ShellEnd::Exited(status.exit_code()),
                Ok(None) => {}
                Err(error) => {
                    eprintln!("shell wait failed: {error}");
                    break ShellEnd::Exited(1);
                }
            },
            // Resolves when the handler drops its side: channel closed or session ended.
            _ = &mut supervisor.close => break ShellEnd::SessionClosed,
            () = shutdown_requested(&mut supervisor.shutdown) => break ShellEnd::AgentShutdown,
        }
    };

    let output_drained = matches!(end, ShellEnd::Exited(_))
        && tokio::time::timeout(OUTPUT_DRAIN_WAIT, &mut supervisor.output_task)
            .await
            .is_ok();

    let ShellSupervisor {
        mut child,
        pty,
        master,
        output_task,
        input_task,
        handle,
        channel,
        ..
    } = supervisor;

    // Release every descriptor of the PTY master: the kernel then hangs up the terminal,
    // signalling the foreground process group and the session leader.
    if !output_drained {
        output_task.abort();
        let _ = output_task.await;
    }
    input_task.abort();
    let _ = input_task.await;
    drop(pty);
    if let Ok(mut master) = master.lock() {
        master.take();
    }

    match end {
        ShellEnd::Exited(code) => {
            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        }
        ShellEnd::SessionClosed => terminate_child(child.as_mut()).await,
        ShellEnd::AgentShutdown => {
            terminate_child(child.as_mut()).await;
            let _ = handle.close(channel).await;
        }
    }
}

async fn shutdown_requested(signal: &mut watch::Receiver<bool>) {
    if signal.wait_for(|stop| *stop).await.is_err() {
        // The agent dropped its sender without shutting down: never fires.
        std::future::pending::<()>().await;
    }
}

async fn terminate_child(child: &mut (dyn Child + Send + Sync)) {
    if !signal_if_running(child, libc::SIGHUP) || wait_for_exit(child, HANGUP_GRACE).await {
        return;
    }

    if signal_if_running(child, libc::SIGKILL) && !wait_for_exit(child, KILL_REAP_WAIT).await {
        eprintln!(
            "shell {} did not exit after SIGKILL",
            child.process_id().unwrap_or_default()
        );
    }
}

/// Sends `signal` only while `child` is unreaped (a zombie keeps its PID), returning whether
/// it was sent; `try_wait` reaps the child once it has exited.
fn signal_if_running(child: &mut (dyn Child + Send + Sync), signal: libc::c_int) -> bool {
    if !matches!(child.try_wait(), Ok(None)) {
        return false;
    }

    let Some(pid) = child
        .process_id()
        .and_then(|pid| libc::pid_t::try_from(pid).ok())
    else {
        return false;
    };

    // SAFETY: `pid` names our own child, which has not been reaped yet.
    unsafe { libc::kill(pid, signal) == 0 }
}

async fn wait_for_exit(child: &mut (dyn Child + Send + Sync), within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;

    loop {
        if !matches!(child.try_wait(), Ok(None)) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(CHILD_POLL_INTERVAL).await;
    }
}

fn pty_size(col_width: u32, row_height: u32, pix_width: u32, pix_height: u32) -> PtySize {
    PtySize {
        rows: u16::try_from(row_height).unwrap_or(u16::MAX).max(1),
        cols: u16::try_from(col_width).unwrap_or(u16::MAX).max(1),
        pixel_width: u16::try_from(pix_width).unwrap_or(u16::MAX),
        pixel_height: u16::try_from(pix_height).unwrap_or(u16::MAX),
    }
}

fn ed25519_only() -> Preferred {
    Preferred {
        key: Cow::Owned(vec![Algorithm::Ed25519]),
        ..Preferred::default()
    }
}

/// Keepalives detect an operator that disappears without closing the connection, so its
/// session and capacity slot are released; the inactivity bound also limits the banner
/// exchange and writes the transport no longer accepts.
fn server_config(host_key: PrivateKey, timeouts: SshTimeouts) -> server::Config {
    server::Config {
        keys: vec![host_key],
        preferred: ed25519_only(),
        keepalive_interval: Some(timeouts.keepalive_interval),
        keepalive_max: timeouts.keepalive_max,
        inactivity_timeout: Some(timeouts.inactivity),
        ..Default::default()
    }
}

pub async fn serve(
    client: &Client,
    relay: &str,
    tunnel_token: &str,
    session_id: &str,
    encoded_operator_key: &str,
    shutdown: ShellShutdown,
) -> Result<(), RevttyError> {
    let path = format!("/v1/session/{session_id}");
    let websocket = connect_websocket(client, relay, &path, tunnel_token).await?;
    let (stream, bridge_task) = websocket_byte_stream(websocket);

    let result = async {
        let paths = Paths::discover()?;
        let identity = ensure_agent(&paths)?;
        let host_key = PrivateKey::read_openssh_file(&identity.private_key_path)
            .map_err(|error| RevttyError::runtime("read agent SSH host key", error))?;
        let authorized_operator = PublicKey::from_openssh(encoded_operator_key)
            .map_err(|error| RevttyError::runtime("parse authorized operator key", error))?;

        if authorized_operator.algorithm() != Algorithm::Ed25519 {
            return Err(RevttyError::message("v1 requires an Ed25519 operator key"));
        }

        let running = server::run_stream(
            Arc::new(server_config(host_key, SSH_TIMEOUTS)),
            stream,
            AgentSshHandler::new(authorized_operator, shutdown),
        )
        .await
        .map_err(|error| RevttyError::runtime("start SSH server", error))?;

        running
            .await
            .map_err(|error| RevttyError::runtime("run SSH session", error))
    }
    .await;

    bridge_task.abort();
    let _ = bridge_task.await;
    result
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use portable_pty::Child;
    use russh::ChannelMsg;
    use russh::keys::key::{PrivateKeyWithHashAlg, safe_rng};
    use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate};
    use russh::{client, server};
    use tokio::sync::{mpsc, watch};

    use super::{AgentSshHandler, ShellShutdown, ed25519_only, server_config, signal_if_running};
    use crate::transport::SshTimeouts;
    use crate::transport::test_support::{ControlledStream, StreamControl};

    /// The agent side of shell shutdown: strong guard sender and shutdown signal.
    struct TestShutdown {
        signal: watch::Sender<bool>,
        guard: mpsc::Sender<()>,
        guards: mpsc::Receiver<()>,
    }

    impl TestShutdown {
        fn new() -> Self {
            let (signal, _) = watch::channel(false);
            let (guard, guards) = mpsc::channel(1);
            Self {
                signal,
                guard,
                guards,
            }
        }

        fn handle(&self) -> ShellShutdown {
            ShellShutdown::new(self.signal.subscribe(), &self.guard)
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

    #[tokio::test]
    async fn interactive_shell_runs_and_resizes_real_pty() {
        let server_key = ed25519_key();
        let expected_server_key = server_key.public_key().clone();
        let client_key = ed25519_key();
        let authorized_client = client_key.public_key().clone();

        let server_config = server::Config {
            keys: vec![server_key],
            preferred: ed25519_only(),
            ..Default::default()
        };
        let client_config = client::Config {
            preferred: ed25519_only(),
            ..Default::default()
        };

        let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
        let shutdown = TestShutdown::new();
        let shell_shutdown = shutdown.handle();

        let server_task = tokio::spawn(async move {
            let running = server::run_stream(
                Arc::new(server_config),
                server_stream,
                AgentSshHandler::new(authorized_client, shell_shutdown),
            )
            .await
            .expect("start SSH PTY server");

            let _ = running.await;
        });

        let mut session = client::connect_stream(
            Arc::new(client_config),
            client_stream,
            TestClient {
                expected_server_key,
            },
        )
        .await
        .expect("connect PTY client");

        let auth = session
            .authenticate_publickey(
                "revtty",
                PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
            )
            .await
            .expect("authenticate PTY client");
        assert!(auth.success());

        let mut channel = session
            .channel_open_session()
            .await
            .expect("open terminal channel");
        channel
            .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
            .await
            .expect("request PTY");
        channel.request_shell(true).await.expect("request shell");
        channel
            .window_change(111, 37, 0, 0)
            .await
            .expect("resize remote PTY");

        let command = [
            br"stty size; printf '\162\145\166\164\164\171\055\163\150\145\154\154\055\157\153\012'; exit"
                .as_slice(),
            b"\n".as_slice(),
        ]
        .concat();
        channel
            .data_bytes(command)
            .await
            .expect("send shell command");

        let output = tokio::time::timeout(Duration::from_secs(8), async {
            let mut output = Vec::new();

            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => output.extend_from_slice(&data),
                    ChannelMsg::Eof | ChannelMsg::Close => break,
                    _ => {}
                }
            }

            output
        })
        .await
        .expect("PTY shell timed out");

        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains("37 111"),
            "shell output did not reflect the resized PTY: {output}"
        );
        assert!(
            output.contains("revtty-shell-ok"),
            "shell output did not contain validation marker: {output}"
        );

        drop(session);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn accepts_enrolled_operator_key_with_comment() {
        let server_key = ed25519_key();
        let expected_server_key = server_key.public_key().clone();
        let mut client_key = ed25519_key();
        client_key.set_comment("revtty");

        // The agent loads the operator key from its persisted OpenSSH text, which keeps the
        // comment; the key presented over SSH never carries one.
        let authorized_client = PublicKey::from_openssh(
            &client_key
                .public_key()
                .to_openssh()
                .expect("encode operator key"),
        )
        .expect("parse operator key");

        let server_config = server::Config {
            keys: vec![server_key],
            preferred: ed25519_only(),
            ..Default::default()
        };
        let client_config = client::Config {
            preferred: ed25519_only(),
            ..Default::default()
        };

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let shutdown = TestShutdown::new();
        let shell_shutdown = shutdown.handle();

        let server_task = tokio::spawn(async move {
            let running = server::run_stream(
                Arc::new(server_config),
                server_stream,
                AgentSshHandler::new(authorized_client, shell_shutdown),
            )
            .await
            .expect("start SSH server");

            let _ = running.await;
        });

        let mut session = client::connect_stream(
            Arc::new(client_config),
            client_stream,
            TestClient {
                expected_server_key,
            },
        )
        .await
        .expect("connect SSH client");

        let auth = session
            .authenticate_publickey(
                "revtty",
                PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
            )
            .await
            .expect("authenticate operator");
        assert!(auth.success(), "operator key with a comment was rejected");

        drop(session);
        server_task.abort();
        let _ = server_task.await;
    }

    #[derive(Default)]
    struct ShellOutput {
        data: Vec<u8>,
        closed: bool,
    }

    /// A real agent SSH server with a real PTY shell, driven by an in-process SSH client.
    struct ShellHarness {
        session: client::Handle<TestClient>,
        writer: Arc<russh::ChannelWriteHalf<client::Msg>>,
        output: Arc<std::sync::Mutex<ShellOutput>>,
        server: tokio::task::JoinHandle<()>,
        shutdown: TestShutdown,
    }

    impl ShellHarness {
        async fn start() -> Self {
            let server_key = ed25519_key();
            let expected_server_key = server_key.public_key().clone();
            let client_key = ed25519_key();
            let authorized_client = client_key.public_key().clone();

            let server_config = server::Config {
                keys: vec![server_key],
                preferred: ed25519_only(),
                ..Default::default()
            };
            let client_config = client::Config {
                preferred: ed25519_only(),
                ..Default::default()
            };

            let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
            let shutdown = TestShutdown::new();
            let shell_shutdown = shutdown.handle();

            let server = tokio::spawn(async move {
                let running = server::run_stream(
                    Arc::new(server_config),
                    server_stream,
                    AgentSshHandler::new(authorized_client, shell_shutdown),
                )
                .await
                .expect("start SSH PTY server");

                let _ = running.await;
            });

            let mut session = client::connect_stream(
                Arc::new(client_config),
                client_stream,
                TestClient {
                    expected_server_key,
                },
            )
            .await
            .expect("connect PTY client");

            let auth = session
                .authenticate_publickey(
                    "revtty",
                    PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
                )
                .await
                .expect("authenticate PTY client");
            assert!(auth.success());

            let channel = session
                .channel_open_session()
                .await
                .expect("open terminal channel");
            channel
                .request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .expect("request PTY");
            channel.request_shell(true).await.expect("request shell");

            let (mut reader, writer) = channel.split();
            let output = Arc::new(std::sync::Mutex::new(ShellOutput::default()));
            let reader_output = Arc::clone(&output);
            tokio::spawn(async move {
                while let Some(message) = reader.wait().await {
                    let mut output = reader_output.lock().expect("shell output lock");
                    match message {
                        ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                            output.data.extend_from_slice(&data);
                        }
                        ChannelMsg::Close => output.closed = true,
                        _ => {}
                    }
                }
                reader_output.lock().expect("shell output lock").closed = true;
            });

            let harness = Self {
                session,
                writer: Arc::new(writer),
                output,
                server,
                shutdown,
            };
            harness.send("echo READY_$((1+1))\n").await;
            harness.wait_for("READY_2", Duration::from_secs(10)).await;
            harness
        }

        async fn send(&self, input: &str) {
            self.writer
                .data_bytes(input.as_bytes().to_vec())
                .await
                .expect("send shell input");
        }

        fn text(&self) -> String {
            let output = self.output.lock().expect("shell output lock");
            String::from_utf8_lossy(&output.data).into_owned()
        }

        fn closed(&self) -> bool {
            self.output.lock().expect("shell output lock").closed
        }

        async fn wait_for(&self, pattern: &str, within: Duration) -> String {
            let deadline = tokio::time::Instant::now() + within;
            loop {
                let text = self.text();
                if text.contains(pattern) {
                    return text;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for {pattern:?}; shell output: {text}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        async fn wait_closed(&self, within: Duration) -> bool {
            let deadline = tokio::time::Instant::now() + within;
            while tokio::time::Instant::now() < deadline {
                if self.closed() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            self.closed()
        }

        /// Drops the operator side and returns the agent's SSH session task.
        async fn disconnect(self) -> tokio::task::JoinHandle<()> {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                self.session
                    .disconnect(russh::Disconnect::ByApplication, "", "English"),
            )
            .await;
            drop(self.writer);
            drop(self.session);
            drop(self.shutdown);
            self.server
        }
    }

    fn marker_value(text: &str, key: &str) -> String {
        let start = text
            .rfind(key)
            .unwrap_or_else(|| panic!("missing {key} in shell output: {text}"))
            + key.len();
        text[start..]
            .chars()
            .take_while(|character| !character.is_whitespace())
            .collect()
    }

    fn process_alive(pid: &str) -> bool {
        std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn kill_process(pid: &str) {
        let _ = std::process::Command::new("kill")
            .args(["-9", pid])
            .stderr(std::process::Stdio::null())
            .status();
    }

    async fn wait_process_gone(pid: &str, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::Instant::now() < deadline {
            if !process_alive(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        !process_alive(pid)
    }

    // Raw mode makes the line discipline stop accepting input once its buffers are full
    // instead of discarding over-long lines, so unread input really backs up.
    const BLOCK_INPUT: &str = "stty raw -echo; echo RAW_$((2*2)); sleep 30\n";

    #[tokio::test]
    async fn disconnect_with_unread_pty_input_ends_session() {
        let shell = ShellHarness::start().await;
        shell.send(BLOCK_INPUT).await;
        shell.wait_for("RAW_4", Duration::from_secs(10)).await;

        // 4 MiB is 128 SSH packets of 32 KiB: far more than the PTY and kernel buffers.
        let writer = Arc::clone(&shell.writer);
        let flood = tokio::spawn(async move {
            let _ = writer.data_bytes(vec![b'x'; 4 * 1024 * 1024]).await;
        });
        tokio::time::sleep(Duration::from_millis(500)).await;

        let server = shell.disconnect().await;
        flood.abort();

        let finished = tokio::time::timeout(Duration::from_secs(5), server).await;
        assert!(
            finished.is_ok(),
            "agent SSH session did not end after the operator disconnected"
        );
    }

    #[tokio::test]
    async fn unread_pty_input_over_limit_closes_channel() {
        let shell = ShellHarness::start().await;
        shell.send(BLOCK_INPUT).await;
        shell.wait_for("RAW_4", Duration::from_secs(10)).await;

        let writer = Arc::clone(&shell.writer);
        let flood = tokio::spawn(async move {
            let _ = writer.data_bytes(vec![b'x'; 9 * 1024 * 1024]).await;
        });

        shell
            .wait_for("input buffer limit", Duration::from_secs(15))
            .await;
        assert!(
            shell.wait_closed(Duration::from_secs(5)).await,
            "channel stayed open after the input limit was exceeded"
        );

        flood.abort();
        let server = shell.disconnect().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    }

    #[tokio::test]
    async fn disconnect_reaps_shell_that_ignores_hangup() {
        let shell = ShellHarness::start().await;
        shell
            .send("trap '' HUP; echo PID=$$ END_$((3+4)); exec sleep 30\n")
            .await;
        let text = shell.wait_for("END_7", Duration::from_secs(10)).await;
        let pid = marker_value(&text, "PID=");

        let server = shell.disconnect().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;

        let gone = wait_process_gone(&pid, Duration::from_secs(10)).await;
        if !gone {
            kill_process(&pid);
        }
        assert!(
            gone,
            "session leader {pid} ignoring SIGHUP survived the session"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn disconnect_releases_pty_held_by_silent_background_job() {
        let shell = ShellHarness::start().await;
        // A background job that ignores SIGHUP keeps the PTY slave open without producing output.
        shell
            .send("(trap '' HUP; exec sleep 20) & echo BG=$! TTY=$(tty) END_$((3+4))\n")
            .await;
        let text = shell.wait_for("END_7", Duration::from_secs(10)).await;
        let background = marker_value(&text, "BG=");
        let tty = marker_value(&text, "TTY=");

        let server = shell.disconnect().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        let held = holds_pty_master(&tty);
        kill_process(&background);
        assert!(
            !held,
            "agent still holds the PTY master for {tty} after the session ended"
        );
    }

    /// Whether this process still has a PTY master open whose slave is `tty` (`/dev/pts/N`).
    #[cfg(target_os = "linux")]
    fn holds_pty_master(tty: &str) -> bool {
        let Some(index) = tty.strip_prefix("/dev/pts/") else {
            panic!("unexpected tty name {tty}");
        };
        let wanted = format!("tty-index:\t{index}");
        std::fs::read_dir("/proc/self/fdinfo")
            .expect("read /proc/self/fdinfo")
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .any(|info| info.lines().any(|line| line == wanted))
    }

    #[tokio::test]
    async fn shell_exit_closes_session_despite_background_job() {
        let shell = ShellHarness::start().await;
        shell.send("sleep 20 & echo BG=$! END_$((3+4))\n").await;
        let text = shell.wait_for("END_7", Duration::from_secs(10)).await;
        let background = marker_value(&text, "BG=");

        shell.send("exit\n").await;
        let closed = shell.wait_closed(Duration::from_secs(3)).await;
        kill_process(&background);
        assert!(
            closed,
            "session stayed open while a background job held the PTY"
        );

        let server = shell.disconnect().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    }

    #[tokio::test]
    async fn disconnect_does_not_inject_input() {
        let target = std::env::temp_dir().join(format!(
            "revtty-no-inject-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let shell = ShellHarness::start().await;
        shell
            .send(&format!(
                "trap '' HUP; echo PID=$$ END_$((3+4)); cat > '{}'\n",
                target.display()
            ))
            .await;
        let text = shell.wait_for("END_7", Duration::from_secs(10)).await;
        let pid = marker_value(&text, "PID=");
        tokio::time::sleep(Duration::from_millis(300)).await;

        // A partial line that the operator never submitted.
        shell.send("abc").await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        let server = shell.disconnect().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
        tokio::time::sleep(Duration::from_secs(2)).await;

        let written = std::fs::read_to_string(&target).unwrap_or_default();
        let _ = std::fs::remove_file(&target);
        if process_alive(&pid) {
            kill_process(&pid);
        }
        assert!(
            !written.contains("abc"),
            "disconnect submitted unsent terminal input: {written:?}"
        );
    }

    #[tokio::test]
    async fn operator_eof_ends_shell() {
        let shell = ShellHarness::start().await;
        shell.send("echo EOF_MARK_$((2+3))\n").await;
        shell.wait_for("EOF_MARK_5", Duration::from_secs(10)).await;

        shell.writer.eof().await.expect("send EOF");
        assert!(
            shell.wait_closed(Duration::from_secs(5)).await,
            "shell did not end after operator EOF"
        );

        let server = shell.disconnect().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    }

    #[test]
    fn exited_child_is_reaped_without_signal() {
        let child = std::process::Command::new("true")
            .spawn()
            .expect("spawn short-lived child");
        // Let it exit without reaping it: a zombie still owns its PID.
        std::thread::sleep(Duration::from_millis(300));
        let mut child: Box<dyn Child + Send + Sync> = Box::new(child);

        assert!(
            !signal_if_running(child.as_mut(), libc::SIGKILL),
            "a signal was sent to a child that had already exited"
        );
        assert!(matches!(child.try_wait(), Ok(Some(_))));
    }

    #[tokio::test]
    async fn agent_shutdown_waits_for_shell_teardown() {
        let mut shell = ShellHarness::start().await;
        shell
            .send("trap '' HUP; echo PID=$$ END_$((3+4)); exec sleep 30\n")
            .await;
        let text = shell.wait_for("END_7", Duration::from_secs(10)).await;
        let pid = marker_value(&text, "PID=");

        // What `agent run` does on SIGINT: signal, drop its own guard, wait for the rest.
        shell.shutdown.signal.send_replace(true);
        let (closed, _) = mpsc::channel(1);
        drop(std::mem::replace(&mut shell.shutdown.guard, closed));
        let waited = tokio::time::timeout(Duration::from_secs(10), shell.shutdown.guards.recv())
            .await
            .is_ok();

        let alive = process_alive(&pid);
        if alive {
            kill_process(&pid);
        }
        assert!(
            waited,
            "shell teardown did not finish within the shutdown bound"
        );
        assert!(
            !alive,
            "shutdown finished while shell {pid} was still running"
        );

        let server = shell.disconnect().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    }

    const FAST_TIMEOUTS: SshTimeouts = SshTimeouts {
        keepalive_interval: Duration::from_millis(100),
        keepalive_max: 3,
        inactivity: Duration::from_millis(300),
    };

    /// An authenticated session against the production server configuration, whose
    /// transport can be stalled or turned into a black hole from the agent's side.
    struct LivenessPair {
        session: client::Handle<TestClient>,
        server: tokio::task::JoinHandle<()>,
        control: StreamControl,
        _shutdown: TestShutdown,
    }

    async fn connect_with_timeouts(timeouts: SshTimeouts) -> LivenessPair {
        let server_key = ed25519_key();
        let expected_server_key = server_key.public_key().clone();
        let client_key = ed25519_key();
        let authorized_client = client_key.public_key().clone();

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let control = StreamControl::default();
        let server_stream = ControlledStream::new(server_stream, control.clone());
        let shutdown = TestShutdown::new();
        let shell_shutdown = shutdown.handle();
        let config = server_config(server_key, timeouts);

        let server = tokio::spawn(async move {
            if let Ok(running) = server::run_stream(
                Arc::new(config),
                server_stream,
                AgentSshHandler::new(authorized_client, shell_shutdown),
            )
            .await
            {
                let _ = running.await;
            }
        });

        // Like the operator client before keepalives were configured: it only answers the
        // agent's keepalives and never sends its own.
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
        .expect("connect SSH client");
        let auth = session
            .authenticate_publickey(
                "revtty",
                PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
            )
            .await
            .expect("authenticate operator");
        assert!(auth.success());

        LivenessPair {
            session,
            server,
            control,
            _shutdown: shutdown,
        }
    }

    #[tokio::test]
    async fn idle_session_survives_inactivity_bound_through_keepalives() {
        let pair = connect_with_timeouts(FAST_TIMEOUTS).await;

        // Five inactivity bounds without any operator traffic.
        tokio::time::sleep(FAST_TIMEOUTS.inactivity * 5).await;

        assert!(
            !pair.server.is_finished(),
            "agent closed a healthy idle session"
        );
        pair.session
            .channel_open_session()
            .await
            .expect("idle session is still usable");
        pair.server.abort();
    }

    #[tokio::test]
    async fn stalled_transport_ends_session() {
        let pair = connect_with_timeouts(FAST_TIMEOUTS).await;

        // Nothing is read or written any more, as on a dead network path.
        pair.control.stall();

        let ended = tokio::time::timeout(FAST_TIMEOUTS.inactivity * 5, pair.server).await;
        assert!(ended.is_ok(), "agent kept a stalled session open");
    }

    #[tokio::test]
    async fn black_holed_transport_ends_session() {
        let pair = connect_with_timeouts(FAST_TIMEOUTS).await;

        // Writes vanish and nothing comes back: keepalives go unanswered.
        pair.control.discard();

        let ended = tokio::time::timeout(FAST_TIMEOUTS.inactivity * 5, pair.server).await;
        assert!(ended.is_ok(), "agent kept a black-holed session open");
    }

    #[tokio::test]
    async fn silent_peer_before_banner_is_dropped() {
        let (_client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let shutdown = TestShutdown::new();
        let config = server_config(ed25519_key(), FAST_TIMEOUTS);

        let started = tokio::time::timeout(
            FAST_TIMEOUTS.inactivity * 5,
            server::run_stream(
                Arc::new(config),
                server_stream,
                AgentSshHandler::new(ed25519_key().public_key().clone(), shutdown.handle()),
            ),
        )
        .await;

        assert!(
            matches!(started, Ok(Err(_))),
            "agent waited indefinitely for a peer that never sent its banner"
        );
    }
}
