use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use portable_pty::{Child, CommandBuilder, MasterPty, PtyPair, PtySize, native_pty_system};
use reqwest::Client;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use russh::server::{self, Msg, Session};
use russh::{Channel, ChannelId, Preferred, Pty, Sig};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{AbortHandle, JoinHandle};

use crate::config::Paths;
use crate::error::RevttyError;
use crate::identity::ensure_agent;
use crate::protocol::PROBE_COMMAND;
use crate::transport::{
    SSH_TIMEOUTS, SshTimeouts, connect_websocket, finish_byte_stream, websocket_byte_stream,
};

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
/// Once a command has exited, how long each of its output pipes may stay silent before it is
/// left: a process the command left behind may keep it open. Only silence counts, so an
/// operator that reads slowly still gets the whole output.
const COMMAND_OUTPUT_SILENCE: Duration = Duration::from_secs(1);
/// The extended data type of a command's stderr (RFC 4254, section 5.2).
const SSH_EXTENDED_DATA_STDERR: u32 = 1;
/// Time the SSH session of a revoked operator gets to end once its transport is cut.
const REVOKED_SESSION_WAIT: Duration = Duration::from_secs(5);
/// A probe session ends after this long whatever the operator does: longer than the
/// operator's own bounds on the handshake (30 s) and on the answer (10 s).
const PROBE_SESSION_LIMIT: Duration = Duration::from_secs(45);
/// A session whose operator has not authenticated this long after it started is closed, so
/// that only an operator the agent lists keeps one of its slots any longer: longer than the
/// operator's own bound on its SSH handshake (30 s). russh alone ends an unauthenticated
/// session only as an idle one, after up to 120 s. The slot comes back once russh's session
/// task is over, which may first finish delaying a rejected authentication (1 s), and
/// `REVOKED_SESSION_WAIT` later at most.
const AUTHENTICATION_LIMIT: Duration = Duration::from_secs(45);

/// What an operator's SSH session is for, as the relay's offer says.
#[derive(Clone)]
pub enum SessionKind {
    /// An interactive shell in a PTY.
    Shell,
    /// One command, which the operator's `exec` request names, without a PTY.
    Exec,
    /// Only `exec` of `PROBE_COMMAND`, answered with this encoded `ProbeResult`.
    Probe(String),
}

/// The operator keys this agent accepts, as last read from its configuration.
#[derive(Clone)]
pub struct OperatorAllowlist {
    pub revision: u64,
    /// OpenSSH encodings without comments, as reported to the relay.
    pub operators: Vec<String>,
    keys: Vec<PublicKey>,
}

impl OperatorAllowlist {
    pub fn parse(revision: u64, operators: &[String]) -> Result<Self, RevttyError> {
        let keys = operators
            .iter()
            .map(|encoded| {
                let key = PublicKey::from_openssh(encoded).map_err(|error| {
                    RevttyError::runtime("parse authorized operator key", error)
                })?;
                if key.algorithm() != Algorithm::Ed25519 {
                    return Err(RevttyError::message("v1 requires Ed25519 operator keys"));
                }
                Ok(key)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // A comment is free text that JSON may expand sixfold; the relay needs only the key.
        let operators = keys
            .iter()
            .map(|key| {
                PublicKey::new(key.key_data().clone(), "")
                    .to_openssh()
                    .map_err(|error| RevttyError::runtime("encode operator key", error))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            revision,
            operators,
            keys,
        })
    }

    /// Compares key material only: configured keys keep their OpenSSH comment, while the key
    /// presented in SSH authentication never carries one.
    fn permits(&self, key: &PublicKey) -> bool {
        self.keys
            .iter()
            .any(|allowed| allowed.key_data() == key.key_data())
    }
}

/// Checks `key` against the current allowlist and, when it is allowed, runs `record` before
/// the allowlist can change. The borrow holds the watch's read lock, which its sender needs
/// to publish, so a revocation lands either before the check, which then refuses the key, or
/// after `record`, where the session's own subscription sees it.
fn authorize(
    allowlist: &mut watch::Receiver<OperatorAllowlist>,
    key: &PublicKey,
    record: impl FnOnce(),
) -> bool {
    let current = allowlist.borrow_and_update();
    if !current.permits(key) {
        return false;
    }

    record();
    true
}

/// Resolves once the key that authenticated the session is no longer allowed.
async fn operator_revoked(
    allowlist: &mut watch::Receiver<OperatorAllowlist>,
    authenticated: &Mutex<Option<PublicKey>>,
) -> PublicKey {
    loop {
        if allowlist.changed().await.is_err() {
            // The agent stopped watching its configuration: the list can no longer change.
            std::future::pending::<()>().await;
        }

        let revoked = {
            let current = allowlist.borrow_and_update();
            authenticated
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .filter(|key| !current.permits(key))
                .cloned()
        };
        if let Some(key) = revoked {
            return key;
        }
    }
}

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

/// Operator input for a shell's PTY or a command's stdin.
enum PtyInput {
    Data(Vec<u8>),
    Eof,
}

/// Handler-side view of a running shell or command; a command has no PTY `master`. Dropping
/// it (channel close, session end or handler drop) closes `close`, which tells the supervisor
/// to tear the shell or the command down.
struct ActiveShell {
    channel: ChannelId,
    master: Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>,
    input: Option<mpsc::UnboundedSender<PtyInput>>,
    pending_input: Arc<AtomicUsize>,
    _close: oneshot::Sender<()>,
}

struct AgentSshHandler {
    allowlist: watch::Receiver<OperatorAllowlist>,
    /// The key this session authenticated with, watched for revocation by `serve_stream`.
    authenticated: Arc<Mutex<Option<PublicKey>>>,
    shutdown: ShellShutdown,
    kind: SessionKind,
    open_channel: Option<ChannelId>,
    pending_pty: Option<PendingPty>,
    active_shell: Option<ActiveShell>,
}

impl AgentSshHandler {
    fn new(
        allowlist: watch::Receiver<OperatorAllowlist>,
        authenticated: Arc<Mutex<Option<PublicKey>>>,
        shutdown: ShellShutdown,
        kind: SessionKind,
    ) -> Self {
        Self {
            allowlist,
            authenticated,
            shutdown,
            kind,
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

    /// Refuses the terminal or command and closes its channel, so the operator gets an answer
    /// instead of a silent terminal.
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

    /// Runs the command of an exec session's `exec` request: one per channel, and none once
    /// the agent has started shutting down. The command itself is never logged.
    fn start_command(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        if self.open_channel != Some(channel) || self.active_shell.is_some() {
            session.channel_failure(channel)?;
            return Ok(());
        }

        let guard = match self.shutdown.guard.upgrade() {
            Some(guard) if !*self.shutdown.signal.borrow() => guard,
            _ => {
                self.refuse_terminal(channel, session)?;
                return Ok(());
            }
        };

        let SpawnedCommand {
            child,
            stdin,
            stdout,
            stderr,
        } = match spawn_command(command) {
            Ok(spawned) => spawned,
            Err(error) => {
                eprintln!("command spawn failed: {error}");
                self.refuse_terminal(channel, session)?;
                return Ok(());
            }
        };

        let handle = session.handle();
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let pending_input = Arc::new(AtomicUsize::new(0));
        let (close_tx, close_rx) = oneshot::channel();
        let (exited_tx, exited_rx) = watch::channel(false);

        let stdout_task = tokio::spawn(forward_command_output(
            stdout,
            handle.clone(),
            channel,
            None,
            exited_rx.clone(),
        ));
        let stderr_task = tokio::spawn(forward_command_output(
            stderr,
            handle.clone(),
            channel,
            Some(SSH_EXTENDED_DATA_STDERR),
            exited_rx,
        ));
        let input_task = tokio::spawn(forward_command_input(
            stdin,
            input_rx,
            Arc::clone(&pending_input),
        ));

        tokio::spawn(supervise_command(CommandSupervisor {
            child,
            stdout_task,
            stderr_task,
            input_task,
            exited: exited_tx,
            handle,
            channel,
            close: close_rx,
            shutdown: self.shutdown.signal.clone(),
            _guard: guard,
        }));

        self.active_shell = Some(ActiveShell {
            channel,
            master: Arc::new(Mutex::new(None)),
            input: Some(input_tx),
            pending_input,
            _close: close_tx,
        });
        session.channel_success(channel)?;
        Ok(())
    }
}

impl server::Handler for AgentSshHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        let authenticated = &self.authenticated;
        if user == "revtty"
            && authorize(&mut self.allowlist, public_key, || {
                *authenticated.lock().unwrap_or_else(PoisonError::into_inner) =
                    Some(public_key.clone());
            })
        {
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
        // A probe or a command has no terminal, and without a PTY no shell starts either.
        if !matches!(self.kind, SessionKind::Shell)
            || self.open_channel != Some(channel)
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

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(self.kind, SessionKind::Exec) {
            return self.start_command(channel, data, session);
        }
        // A shell session runs no command.
        let SessionKind::Probe(answer) = &self.kind else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if self.open_channel != Some(channel) || data != PROBE_COMMAND.as_bytes() {
            session.channel_failure(channel)?;
            return Ok(());
        }

        session.channel_success(channel)?;
        session.data(channel, answer.clone().into_bytes())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    // russh's defaults for the requests below answer nothing, so a client waiting for the
    // reply would hang: the agent runs no subsystem, sets no variable and forwards no X11.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
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
    register_nonblocking(duplicate)
}

/// Makes `descriptor` non-blocking and registers it with the runtime for async I/O.
fn register_nonblocking(descriptor: OwnedFd) -> io::Result<AsyncFd<File>> {
    // SAFETY: `descriptor` is a valid, owned file descriptor.
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe {
        libc::fcntl(
            descriptor.as_raw_fd(),
            libc::F_SETFL,
            flags | libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the `File` owns the descriptor, which stays open and unchanged for as long as
    // the `AsyncFd` owns the `File`.
    unsafe { AsyncFd::register(File::from(descriptor)) }.map_err(|error| error.into_parts().1)
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

/// A command's process, the leader of a process group of its own, and its pipes, set up for
/// async I/O.
struct SpawnedCommand {
    child: std::process::Child,
    stdin: AsyncFd<File>,
    stdout: AsyncFd<File>,
    stderr: AsyncFd<File>,
}

/// Starts `command` as sshd does, with the account's shell and `-c`, in the home directory
/// the interactive shell starts in, and in a process group of its own, so that cancelling it
/// can end what it started.
fn spawn_command(command: &[u8]) -> io::Result<SpawnedCommand> {
    let shell = CommandBuilder::new_default_prog().get_shell();
    let mut process = std::process::Command::new(&shell);
    process
        .arg("-c")
        .arg(OsStr::from_bytes(command))
        .env("SHELL", &shell)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(dirs) = directories::BaseDirs::new() {
        process.current_dir(dirs.home_dir());
    }

    let mut child = process.spawn()?;
    match command_pipes(&mut child) {
        Ok((stdin, stdout, stderr)) => Ok(SpawnedCommand {
            child,
            stdin,
            stdout,
            stderr,
        }),
        Err(error) => {
            // Not left running unwatched; reaping it may take a moment, so off the runtime.
            signal_group(&child, libc::SIGKILL);
            tokio::task::spawn_blocking(move || child.wait());
            Err(error)
        }
    }
}

fn command_pipes(
    child: &mut std::process::Child,
) -> io::Result<(AsyncFd<File>, AsyncFd<File>, AsyncFd<File>)> {
    let missing = || io::Error::other("command pipe was not set up");
    let stdin = child.stdin.take().ok_or_else(missing)?;
    let stdout = child.stdout.take().ok_or_else(missing)?;
    let stderr = child.stderr.take().ok_or_else(missing)?;
    Ok((
        register_nonblocking(stdin.into())?,
        register_nonblocking(stdout.into())?,
        register_nonblocking(stderr.into())?,
    ))
}

/// Forwards one of a command's output pipes to the channel until the pipe's EOF: as data or,
/// with `ext`, as extended data of that type. Once the command has exited (`exited`), a pipe
/// silent for `COMMAND_OUTPUT_SILENCE` is left.
async fn forward_command_output(
    pipe: AsyncFd<File>,
    handle: server::Handle,
    channel: ChannelId,
    ext: Option<u32>,
    mut exited: watch::Receiver<bool>,
) {
    let mut buffer = vec![0_u8; PTY_IO_CHUNK];

    loop {
        let read = tokio::select! {
            read = read_pty(&pipe, &mut buffer) => read,
            () = silent_after_exit(&mut exited) => return,
        };
        let read = match read {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };

        let data = buffer[..read].to_vec();
        let sent = match ext {
            Some(ext) => handle.extended_data(channel, ext, data).await,
            None => handle.data(channel, data).await,
        };
        if sent.is_err() {
            return;
        }
    }
}

/// Resolves `COMMAND_OUTPUT_SILENCE` after it starts, once the command has exited; never
/// while it runs.
async fn silent_after_exit(exited: &mut watch::Receiver<bool>) {
    if exited.wait_for(|exited| *exited).await.is_err() {
        std::future::pending::<()>().await;
    }
    tokio::time::sleep(COMMAND_OUTPUT_SILENCE).await;
}

/// Writes the operator's input to a command's stdin, and closes it at the operator's EOF.
/// Once the command has closed its stdin, input is discarded, as sshd does, so that it does
/// not count towards `INPUT_PENDING_LIMIT`.
async fn forward_command_input(
    stdin: AsyncFd<File>,
    mut input: mpsc::UnboundedReceiver<PtyInput>,
    pending: Arc<AtomicUsize>,
) {
    let mut stdin = Some(stdin);

    while let Some(message) = input.recv().await {
        match message {
            PtyInput::Data(data) => {
                if let Some(pipe) = &stdin
                    && write_pty(pipe, &data).await.is_err()
                {
                    stdin = None;
                }
                pending.fetch_sub(data.len(), Ordering::AcqRel);
            }
            // Dropping the pipe closes the command's stdin.
            PtyInput::Eof => return,
        }
    }
}

/// Single owner of a command's process, as `ShellSupervisor` is of a shell: the only code
/// that reaps its leader and the only code that signals its process group, and only while
/// the leader is unreaped, so that the group's ID, the leader's PID, cannot have been reused.
struct CommandSupervisor {
    child: std::process::Child,
    stdout_task: JoinHandle<()>,
    stderr_task: JoinHandle<()>,
    input_task: JoinHandle<()>,
    /// Set once the leader has exited: from then on, the output pipes' silence counts.
    exited: watch::Sender<bool>,
    handle: server::Handle,
    channel: ChannelId,
    close: oneshot::Receiver<()>,
    shutdown: watch::Receiver<bool>,
    _guard: mpsc::Sender<()>,
}

enum CommandEnd {
    /// The leader exited and the command's output was forwarded.
    Exited,
    /// The channel or the session closed first.
    SessionClosed,
    /// The agent is shutting down, or can no longer watch the command.
    Stopped,
}

async fn supervise_command(supervisor: CommandSupervisor) {
    let CommandSupervisor {
        mut child,
        mut stdout_task,
        mut stderr_task,
        input_task,
        exited,
        handle,
        channel,
        mut close,
        mut shutdown,
        _guard,
    } = supervisor;
    let mut poll = tokio::time::interval(CHILD_POLL_INTERVAL);

    let mut end = loop {
        tokio::select! {
            _ = poll.tick() => match leader_exited(&child) {
                Ok(false) => {}
                Ok(true) => break CommandEnd::Exited,
                Err(error) => {
                    eprintln!("command wait failed: {error}");
                    break CommandEnd::Stopped;
                }
            },
            // Resolves when the handler drops its side: channel closed or session ended.
            _ = &mut close => break CommandEnd::SessionClosed,
            () = shutdown_requested(&mut shutdown) => break CommandEnd::Stopped,
        }
    };

    // The leader stays unreaped while its output is forwarded, so that its group can still
    // be ended if the session goes first.
    if matches!(end, CommandEnd::Exited) {
        exited.send_replace(true);
        let forwarded = async {
            let _ = (&mut stdout_task).await;
            let _ = (&mut stderr_task).await;
        };
        tokio::select! {
            () = forwarded => {}
            _ = &mut close => end = CommandEnd::SessionClosed,
            () = shutdown_requested(&mut shutdown) => end = CommandEnd::Stopped,
        }
    }

    input_task.abort();
    match end {
        CommandEnd::Exited => {
            // Reaps the leader. What it left running in its group stays, as with a shell.
            match child.try_wait() {
                Ok(Some(status)) => report_exit(&handle, channel, status).await,
                Ok(None) => eprintln!("command {} exited but cannot be reaped", child.id()),
                Err(error) => eprintln!("command wait failed: {error}"),
            }
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        }
        CommandEnd::SessionClosed => {
            end_process_group(&mut child, [&stdout_task, &stderr_task]).await;
        }
        CommandEnd::Stopped => {
            end_process_group(&mut child, [&stdout_task, &stderr_task]).await;
            let _ = handle.close(channel).await;
        }
    }
    stdout_task.abort();
    stderr_task.abort();
}

/// Whether the command's leader has exited, leaving it unreaped: until it is reaped, neither
/// its PID nor its process group's ID can be reused.
fn leader_exited(leader: &std::process::Child) -> io::Result<bool> {
    // SAFETY: zeroed siginfo_t is a valid out-parameter for waitid.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `leader` is our own child, and WNOWAIT leaves it unreaped.
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            leader.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if waited != 0 {
        return Err(io::Error::last_os_error());
    }

    // With WNOHANG, `si_pid` stays zero while the leader is still running.
    // SAFETY: waitid filled `info` in, or left it zeroed.
    Ok(unsafe { info.si_pid() } != 0)
}

/// Sends `signal` to the command's process group, whose ID is its leader's PID. Only while
/// the leader is unreaped: no other process or group can have that ID before then. When
/// `leader_exited` cannot tell, nothing is sent.
fn signal_group(leader: &std::process::Child, signal: libc::c_int) {
    if leader_exited(leader).is_err() {
        return;
    }
    let Ok(group) = libc::pid_t::try_from(leader.id()) else {
        return;
    };
    // SAFETY: `group` is the process group our own unreaped child leads.
    unsafe { libc::kill(-group, signal) };
}

/// Ends a command still running, or whose output was not all forwarded: SIGTERM to its
/// process group, then, once its leader has exited and its output pipes are closed or
/// `HANGUP_GRACE` is over, SIGKILL to the group, so that a process that ignores SIGTERM goes
/// too, even when the leader is gone. Processes that left the group, as daemons do, are not
/// reached. Then reaps the leader.
async fn end_process_group(leader: &mut std::process::Child, output: [&JoinHandle<()>; 2]) {
    signal_group(leader, libc::SIGTERM);

    let deadline = tokio::time::Instant::now() + HANGUP_GRACE;
    // A leader that cannot be watched gets no more time than one that exited.
    while tokio::time::Instant::now() < deadline
        && (matches!(leader_exited(leader), Ok(false))
            || !output.iter().all(|task| task.is_finished()))
    {
        tokio::time::sleep(CHILD_POLL_INTERVAL).await;
    }

    signal_group(leader, libc::SIGKILL);
    if !wait_for_exit(leader, KILL_REAP_WAIT).await {
        eprintln!("command {} did not exit after SIGKILL", leader.id());
    }
}

/// Reports how the command's leader ended: its exit status, or the signal that killed it.
async fn report_exit(handle: &server::Handle, channel: ChannelId, status: ExitStatus) {
    if let Some(code) = status.code().and_then(|code| u32::try_from(code).ok()) {
        let _ = handle.exit_status_request(channel, code).await;
    } else if let Some(signal) = status.signal() {
        let _ = handle
            .exit_signal_request(
                channel,
                ssh_signal(signal),
                status.core_dumped(),
                String::new(),
                String::new(),
            )
            .await;
    }
}

/// A signal by its SSH name (RFC 4254, section 6.10), or by its number when SSH names none.
fn ssh_signal(signal: libc::c_int) -> Sig {
    match signal {
        libc::SIGABRT => Sig::ABRT,
        libc::SIGALRM => Sig::ALRM,
        libc::SIGFPE => Sig::FPE,
        libc::SIGHUP => Sig::HUP,
        libc::SIGILL => Sig::ILL,
        libc::SIGINT => Sig::INT,
        libc::SIGKILL => Sig::KILL,
        libc::SIGPIPE => Sig::PIPE,
        libc::SIGQUIT => Sig::QUIT,
        libc::SIGSEGV => Sig::SEGV,
        libc::SIGTERM => Sig::TERM,
        libc::SIGUSR1 => Sig::USR1,
        // Named by RFC 4254, though not by russh.
        libc::SIGUSR2 => Sig::Custom("USR2".to_owned()),
        other => Sig::Custom(other.to_string()),
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

/// Resolves once the relay cancels the session through `cancel`; never when the agent only
/// stopped tracking it and dropped the sender.
async fn relay_cancelled(cancel: oneshot::Receiver<()>) {
    if cancel.await.is_err() {
        std::future::pending::<()>().await;
    }
}

fn cancelled_by_relay() -> RevttyError {
    RevttyError::message("session cancelled by the relay")
}

#[allow(clippy::too_many_arguments)]
pub async fn serve(
    client: &Client,
    relay: &str,
    tunnel_token: &str,
    session_id: &str,
    allowlist: watch::Receiver<OperatorAllowlist>,
    shutdown: ShellShutdown,
    kind: SessionKind,
    cancel: oneshot::Receiver<()>,
) -> Result<(), RevttyError> {
    let cancelled = relay_cancelled(cancel);
    tokio::pin!(cancelled);

    let path = format!("/v1/session/{session_id}");
    let websocket = tokio::select! {
        websocket = connect_websocket(client, relay, &path, tunnel_token) => websocket?,
        () = &mut cancelled => return Err(cancelled_by_relay()),
    };
    let (stream, bridge_task) = websocket_byte_stream(websocket);
    let transport = bridge_task.abort_handle();

    let result = async {
        let paths = Paths::discover()?;
        let identity = ensure_agent(&paths)?;
        let host_key = PrivateKey::read_openssh_file(&identity.private_key_path)
            .map_err(|error| RevttyError::runtime("read agent SSH host key", error))?;

        let limit = matches!(kind, SessionKind::Probe(_)).then_some(PROBE_SESSION_LIMIT);
        serve_stream(
            stream,
            transport,
            server_config(host_key, SSH_TIMEOUTS),
            allowlist,
            shutdown,
            kind,
            limit,
            AUTHENTICATION_LIMIT,
            cancelled,
        )
        .await
    }
    .await;

    finish_byte_stream(bridge_task).await;
    result
}

/// Runs one operator's SSH session over `stream` until it ends, the key it authenticated
/// with is revoked, the relay cancels it (`cancelled`), `limit` is over or
/// `authentication_limit` is over before the operator authenticated, both counted from the
/// start. `transport` is the task that carries `stream`.
#[allow(clippy::too_many_arguments)]
async fn serve_stream<S>(
    stream: S,
    transport: AbortHandle,
    config: server::Config,
    allowlist: watch::Receiver<OperatorAllowlist>,
    shutdown: ShellShutdown,
    kind: SessionKind,
    limit: Option<Duration>,
    authentication_limit: Duration,
    cancelled: impl Future<Output = ()>,
) -> Result<(), RevttyError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::pin!(cancelled);
    let authenticated = Arc::new(Mutex::new(None));
    // Subscribed before the handler can authenticate anyone, so every later change of the
    // allowlist is seen here.
    let mut changes = allowlist.clone();
    // From the start: russh waits for the operator's banner for as long as the inactivity
    // timeout (120 s) before it returns the session.
    let limit_reached = async {
        match limit {
            Some(limit) => tokio::time::sleep(limit).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(limit_reached);
    let over_limit = || {
        RevttyError::message(format!(
            "session still open after {}s",
            limit.unwrap_or_default().as_secs_f64()
        ))
    };
    let unauthenticated_at_limit = async {
        tokio::time::sleep(authentication_limit).await;
        let in_time = authenticated
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        if in_time {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(unauthenticated_at_limit);
    let unauthenticated = || {
        RevttyError::message(format!(
            "operator did not authenticate within {}s",
            authentication_limit.as_secs_f64()
        ))
    };

    let started = tokio::select! {
        started = server::run_stream(
            Arc::new(config),
            stream,
            AgentSshHandler::new(allowlist, Arc::clone(&authenticated), shutdown, kind),
        ) => started,
        () = &mut limit_reached => {
            transport.abort();
            return Err(over_limit());
        }
        () = &mut unauthenticated_at_limit => {
            transport.abort();
            return Err(unauthenticated());
        }
        () = &mut cancelled => {
            transport.abort();
            return Err(cancelled_by_relay());
        }
    };
    let mut running = started.map_err(|error| RevttyError::runtime("start SSH server", error))?;

    tokio::select! {
        result = &mut running => {
            result.map_err(|error| RevttyError::runtime("run SSH session", error))
        }
        revoked = operator_revoked(&mut changes, &authenticated) => {
            let fingerprint = revoked.fingerprint(HashAlg::Sha256);
            eprintln!("operator {fingerprint} was revoked; closing its session");
            // Dropping the session would leave russh running; ending its transport stops it,
            // and dropping its handler tears the shell down.
            transport.abort();
            if tokio::time::timeout(REVOKED_SESSION_WAIT, &mut running)
                .await
                .is_err()
            {
                eprintln!(
                    "session of revoked operator {fingerprint} did not end within {}s",
                    REVOKED_SESSION_WAIT.as_secs()
                );
            }
            Err(RevttyError::message(format!(
                "operator {fingerprint} was revoked"
            )))
        }
        () = &mut limit_reached => {
            // A probe whose operator never hangs up must not keep its session slot.
            transport.abort();
            let _ = tokio::time::timeout(REVOKED_SESSION_WAIT, &mut running).await;
            Err(over_limit())
        }
        () = &mut unauthenticated_at_limit => {
            // Waited for, as for a revoked operator: the session's stream still yields what
            // the transport had buffered, so a key accepted just past the limit could start a
            // shell after the slot was given back.
            transport.abort();
            let _ = tokio::time::timeout(REVOKED_SESSION_WAIT, &mut running).await;
            Err(unauthenticated())
        }
        () = &mut cancelled => {
            // Returning while russh still runs the session would give its slot back early:
            // its task outlives `running` if dropped. Ending the transport stops it, as for a
            // revoked operator.
            transport.abort();
            let _ = tokio::time::timeout(REVOKED_SESSION_WAIT, &mut running).await;
            Err(cancelled_by_relay())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use portable_pty::Child;
    use russh::ChannelMsg;
    use russh::keys::key::{PrivateKeyWithHashAlg, safe_rng};
    use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate};
    use russh::{client, server};
    use tokio::sync::{mpsc, oneshot, watch};

    use super::{
        AUTHENTICATION_LIMIT, AgentSshHandler, COMMAND_OUTPUT_SILENCE, HANGUP_GRACE,
        INPUT_PENDING_LIMIT, KILL_REAP_WAIT, OperatorAllowlist, SessionKind, ShellShutdown,
        authorize, ed25519_only, operator_revoked, relay_cancelled, serve_stream, server_config,
        signal_if_running,
    };
    use crate::error::RevttyError;
    use crate::protocol::PROBE_COMMAND;
    use crate::transport::test_support::{ControlledStream, StreamControl};
    use crate::transport::{SSH_TIMEOUTS, SshTimeouts};

    fn allowlist_of(keys: &[&PublicKey]) -> OperatorAllowlist {
        let operators = keys
            .iter()
            .map(|key| key.to_openssh().expect("encode operator key"))
            .collect::<Vec<_>>();
        OperatorAllowlist::parse(1, &operators).expect("operator allowlist")
    }

    /// An allowlist that never changes: its sender is gone.
    fn allow_only(key: &PublicKey) -> watch::Receiver<OperatorAllowlist> {
        watch::channel(allowlist_of(&[key])).1
    }

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
                AgentSshHandler::new(
                    allow_only(&authorized_client),
                    Arc::default(),
                    shell_shutdown,
                    SessionKind::Shell,
                ),
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
                AgentSshHandler::new(
                    allow_only(&authorized_client),
                    Arc::default(),
                    shell_shutdown,
                    SessionKind::Shell,
                ),
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
                    AgentSshHandler::new(
                        allow_only(&authorized_client),
                        Arc::default(),
                        shell_shutdown,
                        SessionKind::Shell,
                    ),
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
                AgentSshHandler::new(
                    allow_only(&authorized_client),
                    Arc::default(),
                    shell_shutdown,
                    SessionKind::Shell,
                ),
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
                AgentSshHandler::new(
                    allow_only(ed25519_key().public_key()),
                    Arc::default(),
                    shutdown.handle(),
                    SessionKind::Shell,
                ),
            ),
        )
        .await;

        assert!(
            matches!(started, Ok(Err(_))),
            "agent waited indefinitely for a peer that never sent its banner"
        );
    }

    /// The production session path (`serve_stream`) with a live allowlist, over a transport
    /// task like the agent's WebSocket bridge, authenticated as `operator`.
    struct RevocableSession {
        allowlist: watch::Sender<OperatorAllowlist>,
        /// What the agent's control loop fires on the relay's `SessionCancel`.
        cancel: oneshot::Sender<()>,
        session: client::Handle<TestClient>,
        server: tokio::task::JoinHandle<Result<(), RevttyError>>,
        _shutdown: TestShutdown,
    }

    async fn revocable_session(
        operator: &PrivateKey,
        allowed: &[&PublicKey],
        authentication_limit: Duration,
    ) -> RevocableSession {
        agent_session(operator, allowed, authentication_limit, SessionKind::Shell).await
    }

    /// A session of `kind` as the agent serves it, which `operator` authenticated to.
    async fn agent_session(
        operator: &PrivateKey,
        allowed: &[&PublicKey],
        authentication_limit: Duration,
        kind: SessionKind,
    ) -> RevocableSession {
        let server_key = ed25519_key();
        let expected_server_key = server_key.public_key().clone();
        let (allowlist, allowlist_rx) = watch::channel(allowlist_of(allowed));

        let (client_stream, relay_side) = tokio::io::duplex(256 * 1024);
        let (application, agent_side) = tokio::io::duplex(256 * 1024);
        // Stands in for the bridge task that carries the agent's stream over the relay.
        let bridge = tokio::spawn(async move {
            let (mut relay_side, mut agent_side) = (relay_side, agent_side);
            let _ = tokio::io::copy_bidirectional(&mut relay_side, &mut agent_side).await;
        });

        let shutdown = TestShutdown::new();
        let (cancel, cancelled) = oneshot::channel();
        let server = tokio::spawn(serve_stream(
            application,
            bridge.abort_handle(),
            server_config(server_key, SSH_TIMEOUTS),
            allowlist_rx,
            shutdown.handle(),
            kind,
            None,
            authentication_limit,
            relay_cancelled(cancelled),
        ));

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
                PrivateKeyWithHashAlg::new(Arc::new(operator.clone()), None),
            )
            .await
            .expect("authenticate operator");
        assert!(auth.success(), "allowed operator was rejected");

        RevocableSession {
            allowlist,
            cancel,
            session,
            server,
            _shutdown: shutdown,
        }
    }

    async fn read_until(
        channel: &mut russh::Channel<client::Msg>,
        pattern: &str,
        within: Duration,
    ) -> String {
        let mut output = Vec::new();
        let read = tokio::time::timeout(within, async {
            while let Some(message) = channel.wait().await {
                if let ChannelMsg::Data { data } = message {
                    output.extend_from_slice(&data);
                    if String::from_utf8_lossy(&output).contains(pattern) {
                        return;
                    }
                }
            }
        })
        .await;
        let text = String::from_utf8_lossy(&output).into_owned();
        assert!(read.is_ok(), "timed out waiting for {pattern:?}: {text}");
        text
    }

    #[tokio::test]
    async fn revoked_operator_session_is_closed_and_its_shell_reaped() {
        let operator = ed25519_key();
        let other = ed25519_key();
        let shell = revocable_session(
            &operator,
            &[operator.public_key(), other.public_key()],
            AUTHENTICATION_LIMIT,
        )
        .await;

        let mut channel = shell
            .session
            .channel_open_session()
            .await
            .expect("open terminal channel");
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .expect("request PTY");
        channel.request_shell(true).await.expect("request shell");
        channel
            .data_bytes(b"echo PID=$$ END_$((3+4))\n".to_vec())
            .await
            .expect("send shell input");
        let text = read_until(&mut channel, "END_7", Duration::from_secs(10)).await;
        let pid = marker_value(&text, "PID=");

        // What the operator watch publishes once `agent operator revoke` rewrote the list.
        shell
            .allowlist
            .send_replace(allowlist_of(&[other.public_key()]));

        let ended = tokio::time::timeout(Duration::from_secs(5), shell.server)
            .await
            .expect("session of a revoked operator stayed open")
            .expect("session task");
        let error = ended.expect_err("revoked session ended as if completed");
        assert!(error.to_string().contains("revoked"), "{error}");

        let gone = wait_process_gone(&pid, Duration::from_secs(10)).await;
        if !gone {
            kill_process(&pid);
        }
        assert!(
            gone,
            "shell {pid} of a revoked operator survived its session"
        );
    }

    #[tokio::test]
    async fn a_session_the_relay_cancels_is_closed_and_its_shell_reaped() {
        let operator = ed25519_key();
        let mut shell =
            revocable_session(&operator, &[operator.public_key()], AUTHENTICATION_LIMIT).await;

        let mut channel = shell
            .session
            .channel_open_session()
            .await
            .expect("open terminal channel");
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .expect("request PTY");
        channel.request_shell(true).await.expect("request shell");
        channel
            .data_bytes(b"echo PID=$$ END_$((3+4))\n".to_vec())
            .await
            .expect("send shell input");
        let text = read_until(&mut channel, "END_7", Duration::from_secs(10)).await;
        let pid = marker_value(&text, "PID=");

        shell.cancel.send(()).expect("session still listening");

        let ended = tokio::time::timeout(Duration::from_secs(5), &mut shell.server)
            .await
            .expect("a cancelled session stayed open")
            .expect("session task");
        let error = ended.expect_err("cancelled session ended as if completed");
        assert!(error.to_string().contains("cancelled"), "{error}");

        // The operator's side of the transport is gone too: the session did not carry on
        // in russh's own task.
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            while channel.wait().await.is_some() {}
        })
        .await;
        assert!(closed.is_ok(), "the cancelled session kept its channel");
        let gone = wait_process_gone(&pid, Duration::from_secs(10)).await;
        if !gone {
            kill_process(&pid);
        }
        assert!(gone, "shell {pid} of a cancelled session survived it");
    }

    #[tokio::test]
    async fn a_session_the_relay_cancels_before_authentication_ends_at_once() {
        let (_silent_operator, agent_stream) = tokio::io::duplex(64 * 1024);
        let transport = tokio::spawn(std::future::pending::<()>());
        let (cancel, cancelled) = oneshot::channel();
        let served = tokio::spawn(serve_stream(
            agent_stream,
            transport.abort_handle(),
            server_config(ed25519_key(), SSH_TIMEOUTS),
            allow_only(ed25519_key().public_key()),
            TestShutdown::new().handle(),
            SessionKind::Shell,
            None,
            AUTHENTICATION_LIMIT,
            relay_cancelled(cancelled),
        ));

        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.send(()).expect("session still listening");
        let served = tokio::time::timeout(Duration::from_secs(2), served)
            .await
            .expect("a session cancelled before authentication stayed open")
            .expect("session task");

        let error = served.expect_err("a cancelled session ended as a success");
        assert!(error.to_string().contains("cancelled"), "{error}");
        assert!(transport.await.is_err_and(|error| error.is_cancelled()));
    }

    #[tokio::test]
    async fn a_session_whose_cancel_sender_is_dropped_keeps_running() {
        let operator = ed25519_key();
        let shell =
            revocable_session(&operator, &[operator.public_key()], AUTHENTICATION_LIMIT).await;

        // The agent drops a sender when it stops tracking the session, not to cancel it.
        drop(shell.cancel);
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(
            !shell.server.is_finished(),
            "dropping the cancel sender ended the session"
        );
        shell
            .session
            .channel_open_session()
            .await
            .expect("session is still usable");
        shell.server.abort();
    }

    #[tokio::test]
    async fn allowlist_change_that_keeps_the_key_keeps_the_session() {
        let operator = ed25519_key();
        let added = ed25519_key();
        let shell =
            revocable_session(&operator, &[operator.public_key()], AUTHENTICATION_LIMIT).await;

        shell
            .allowlist
            .send_replace(allowlist_of(&[operator.public_key(), added.public_key()]));
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(
            !shell.server.is_finished(),
            "an unrelated change closed the session"
        );
        shell
            .session
            .channel_open_session()
            .await
            .expect("session is still usable");
        shell.server.abort();
    }

    #[tokio::test]
    async fn operator_added_after_start_authenticates_and_others_do_not() {
        let operator = ed25519_key();
        let added = ed25519_key();
        let (allowlist, mut receiver) = watch::channel(allowlist_of(&[operator.public_key()]));
        let authenticated = Mutex::new(None);
        let record = |key: &PublicKey| {
            let key = key.clone();
            let authenticated = &authenticated;
            move || *authenticated.lock().expect("authenticated key") = Some(key)
        };

        // Keys the agent does not list are refused, whatever the relay believes.
        assert!(!authorize(
            &mut receiver,
            added.public_key(),
            record(added.public_key())
        ));

        allowlist.send_replace(allowlist_of(&[operator.public_key(), added.public_key()]));
        assert!(authorize(
            &mut receiver,
            added.public_key(),
            record(added.public_key())
        ));
        assert!(
            authenticated
                .lock()
                .expect("authenticated key")
                .as_ref()
                .is_some_and(|key| key.key_data() == added.public_key().key_data())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revocation_racing_authentication_is_never_missed() {
        let operator = ed25519_key();
        let (publisher, mut handler_view) = watch::channel(allowlist_of(&[operator.public_key()]));
        let publisher = Arc::new(publisher);
        let authenticated = Arc::new(Mutex::new(None));

        // The session's own subscription, already waiting for changes, as in `serve_stream`.
        let mut changes = handler_view.clone();
        let watched = Arc::clone(&authenticated);
        let watcher = tokio::spawn(async move { operator_revoked(&mut changes, &watched).await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let accepted = authorize(&mut handler_view, operator.public_key(), || {
            // The revocation is published between the check and the record of the key...
            let racing = Arc::clone(&publisher);
            std::thread::spawn(move || racing.send_replace(allowlist_of(&[])));
            // ...with time for it, and for the watcher's reaction, to happen if they can.
            std::thread::sleep(Duration::from_millis(300));
            *authenticated.lock().expect("authenticated key") = Some(operator.public_key().clone());
        });
        assert!(accepted);

        let revoked = tokio::time::timeout(Duration::from_secs(2), watcher).await;
        assert!(
            revoked.is_ok(),
            "a revocation published during authentication was never applied"
        );
    }

    const PROBE_ANSWER: &str = r#"{"name":"probed","os":"linux","arch":"x86_64","version":"0"}"#;

    /// A probe session as the agent serves it, and an SSH client that tried to authenticate
    /// to it with `operator`, which the agent's list holds only if `listed`.
    async fn probe_session(
        operator: &PrivateKey,
        listed: bool,
    ) -> (client::Handle<TestClient>, bool) {
        let server_key = ed25519_key();
        let expected_server_key = server_key.public_key().clone();
        let allowed = if listed {
            operator.public_key().clone()
        } else {
            ed25519_key().public_key().clone()
        };
        let (client_stream, agent_stream) = tokio::io::duplex(64 * 1024);
        // Stands in for the bridge task that carries the agent's stream.
        let transport = tokio::spawn(std::future::pending::<()>());
        tokio::spawn(serve_stream(
            agent_stream,
            transport.abort_handle(),
            server_config(server_key, SSH_TIMEOUTS),
            allow_only(&allowed),
            TestShutdown::new().handle(),
            SessionKind::Probe(PROBE_ANSWER.to_owned()),
            Some(Duration::from_secs(30)),
            AUTHENTICATION_LIMIT,
            std::future::pending(),
        ));

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
                PrivateKeyWithHashAlg::new(Arc::new(operator.clone()), None),
            )
            .await
            .expect("authenticate operator");
        (session, auth.success())
    }

    /// What `channel` gets, up to its close or for at most 2 s.
    async fn channel_messages(channel: &mut russh::Channel<client::Msg>) -> Vec<ChannelMsg> {
        let mut messages = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(message) = channel.wait().await {
                let closed = matches!(message, ChannelMsg::Close);
                messages.push(message);
                if closed {
                    break;
                }
            }
        })
        .await;
        messages
    }

    /// The first `count` replies `channel` gets to its requests, waiting at most 5 s.
    async fn channel_replies(
        channel: &mut russh::Channel<client::Msg>,
        count: usize,
    ) -> Vec<ChannelMsg> {
        let mut replies = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while replies.len() < count {
                match channel.wait().await {
                    Some(reply @ (ChannelMsg::Success | ChannelMsg::Failure)) => {
                        replies.push(reply)
                    }
                    Some(_) => {}
                    None => break,
                }
            }
        })
        .await;
        replies
    }

    /// Asks `channel` for what no agent session runs.
    async fn request_unsupported(channel: &russh::Channel<client::Msg>) {
        channel
            .request_subsystem(true, "sftp")
            .await
            .expect("request subsystem");
        channel
            .set_env(true, "LANG", "C")
            .await
            .expect("request variable");
        channel
            .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "00", 0)
            .await
            .expect("request X11");
    }

    #[tokio::test]
    async fn a_shell_session_refuses_what_it_does_not_run() {
        let operator = ed25519_key();
        let shell =
            revocable_session(&operator, &[operator.public_key()], AUTHENTICATION_LIMIT).await;
        let mut channel = shell
            .session
            .channel_open_session()
            .await
            .expect("open channel");

        channel.exec(true, "id").await.expect("request command");
        request_unsupported(&channel).await;
        // The refusals leave the channel to its terminal.
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .expect("request PTY");
        let replies = channel_replies(&mut channel, 5).await;

        assert!(
            matches!(
                replies[..],
                [
                    ChannelMsg::Failure,
                    ChannelMsg::Failure,
                    ChannelMsg::Failure,
                    ChannelMsg::Failure,
                    ChannelMsg::Success
                ]
            ),
            "a shell session left a request unanswered: {replies:?}"
        );
        shell.server.abort();
    }

    #[tokio::test]
    async fn a_probe_session_answers_the_probe_command() {
        let operator = ed25519_key();
        let (session, authenticated) = probe_session(&operator, true).await;
        assert!(authenticated, "listed operator was rejected");

        let mut channel = session.channel_open_session().await.expect("open channel");
        channel
            .exec(true, PROBE_COMMAND)
            .await
            .expect("request probe");
        let messages = channel_messages(&mut channel).await;

        assert!(matches!(messages.first(), Some(ChannelMsg::Success)));
        let answer = messages
            .iter()
            .filter_map(|message| match message {
                ChannelMsg::Data { data } => Some(data.to_vec()),
                _ => None,
            })
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(answer, PROBE_ANSWER.as_bytes());
        assert!(
            messages
                .iter()
                .any(|message| matches!(message, ChannelMsg::ExitStatus { exit_status: 0 }))
        );
        assert!(matches!(messages.last(), Some(ChannelMsg::Close)));
    }

    #[tokio::test]
    async fn a_probe_session_runs_nothing_else() {
        let operator = ed25519_key();

        let (session, _) = probe_session(&operator, true).await;
        let mut channel = session.channel_open_session().await.expect("open channel");
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .expect("request PTY");
        channel.request_shell(true).await.expect("request shell");
        let messages = channel_messages(&mut channel).await;
        let replies = messages
            .iter()
            .filter(|message| matches!(message, ChannelMsg::Success | ChannelMsg::Failure))
            .collect::<Vec<_>>();
        assert!(
            matches!(replies[..], [ChannelMsg::Failure, ChannelMsg::Failure]),
            "a probe session gave a terminal: {messages:?}"
        );

        let (session, _) = probe_session(&operator, true).await;
        let mut channel = session.channel_open_session().await.expect("open channel");
        channel.exec(true, "id").await.expect("request command");
        let messages = channel_messages(&mut channel).await;
        assert!(
            matches!(messages.first(), Some(ChannelMsg::Failure))
                && !messages
                    .iter()
                    .any(|message| matches!(message, ChannelMsg::Data { .. })),
            "a probe session ran another command: {messages:?}"
        );

        let (session, _) = probe_session(&operator, true).await;
        let mut channel = session.channel_open_session().await.expect("open channel");
        request_unsupported(&channel).await;
        let replies = channel_replies(&mut channel, 3).await;
        assert!(
            matches!(
                replies[..],
                [
                    ChannelMsg::Failure,
                    ChannelMsg::Failure,
                    ChannelMsg::Failure
                ]
            ),
            "a probe session left a request unanswered: {replies:?}"
        );
    }

    #[tokio::test]
    async fn an_operator_the_agent_does_not_list_gets_no_probe_answer() {
        let (_session, authenticated) = probe_session(&ed25519_key(), false).await;
        assert!(!authenticated, "unlisted operator authenticated to a probe");
    }

    #[tokio::test]
    async fn a_probe_session_ends_at_its_limit_even_before_the_banner() {
        // An operator that never speaks: russh alone would wait 120 s for its banner.
        let (_silent_operator, agent_stream) = tokio::io::duplex(64 * 1024);
        let transport = tokio::spawn(std::future::pending::<()>());
        let served = tokio::time::timeout(
            Duration::from_secs(2),
            serve_stream(
                agent_stream,
                transport.abort_handle(),
                server_config(ed25519_key(), SSH_TIMEOUTS),
                allow_only(ed25519_key().public_key()),
                TestShutdown::new().handle(),
                SessionKind::Probe(PROBE_ANSWER.to_owned()),
                Some(Duration::from_millis(300)),
                AUTHENTICATION_LIMIT,
                std::future::pending(),
            ),
        )
        .await
        .expect("the probe session outlived its limit");
        assert!(served.is_err(), "a silent probe session ended as a success");
        assert!(transport.await.is_err_and(|error| error.is_cancelled()));
    }

    #[tokio::test]
    async fn a_probe_operator_that_never_hangs_up_loses_its_session_at_the_limit() {
        let operator = ed25519_key();
        let server_key = ed25519_key();
        let expected_server_key = server_key.public_key().clone();
        let (client_stream, relay_side) = tokio::io::duplex(64 * 1024);
        let (application, agent_side) = tokio::io::duplex(64 * 1024);
        // Stands in for the bridge task: ending it closes the agent's stream.
        let bridge = tokio::spawn(async move {
            let (mut relay_side, mut agent_side) = (relay_side, agent_side);
            let _ = tokio::io::copy_bidirectional(&mut relay_side, &mut agent_side).await;
        });
        let server = tokio::spawn(serve_stream(
            application,
            bridge.abort_handle(),
            server_config(server_key, SSH_TIMEOUTS),
            allow_only(operator.public_key()),
            TestShutdown::new().handle(),
            SessionKind::Probe(PROBE_ANSWER.to_owned()),
            Some(Duration::from_millis(500)),
            AUTHENTICATION_LIMIT,
            std::future::pending(),
        ));

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
                PrivateKeyWithHashAlg::new(Arc::new(operator.clone()), None),
            )
            .await
            .expect("authenticate operator");
        assert!(auth.success());

        // Authenticated, it then keeps the session without asking anything.
        let served = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("the probe session outlived its limit")
            .expect("probe session task");
        assert!(served.is_err(), "an idle probe session ended as a success");
    }

    #[tokio::test]
    async fn an_operator_that_never_authenticates_loses_its_session_at_the_limit() {
        // An operator that never speaks: russh alone would wait 120 s for its banner.
        let (_silent_operator, agent_stream) = tokio::io::duplex(64 * 1024);
        let transport = tokio::spawn(std::future::pending::<()>());
        let served = tokio::time::timeout(
            Duration::from_secs(2),
            serve_stream(
                agent_stream,
                transport.abort_handle(),
                server_config(ed25519_key(), SSH_TIMEOUTS),
                allow_only(ed25519_key().public_key()),
                TestShutdown::new().handle(),
                SessionKind::Shell,
                None,
                Duration::from_millis(300),
                std::future::pending(),
            ),
        )
        .await
        .expect("an unauthenticated session outlived its limit");

        let error = served.expect_err("an unauthenticated session ended as a success");
        assert!(
            error.to_string().contains("did not authenticate"),
            "{error}"
        );
        assert!(transport.await.is_err_and(|error| error.is_cancelled()));
    }

    #[tokio::test]
    async fn an_operator_that_stops_after_the_key_exchange_loses_its_session_at_the_limit() {
        let server_key = ed25519_key();
        let expected_server_key = server_key.public_key().clone();
        let (client_stream, relay_side) = tokio::io::duplex(64 * 1024);
        let (application, agent_side) = tokio::io::duplex(64 * 1024);
        // Stands in for the bridge task: ending it closes the agent's stream.
        let bridge = tokio::spawn(async move {
            let (mut relay_side, mut agent_side) = (relay_side, agent_side);
            let _ = tokio::io::copy_bidirectional(&mut relay_side, &mut agent_side).await;
        });
        let server = tokio::spawn(serve_stream(
            application,
            bridge.abort_handle(),
            server_config(server_key, SSH_TIMEOUTS),
            allow_only(ed25519_key().public_key()),
            TestShutdown::new().handle(),
            SessionKind::Shell,
            None,
            Duration::from_millis(300),
            std::future::pending(),
        ));

        let client_config = client::Config {
            preferred: ed25519_only(),
            ..Default::default()
        };
        let _session = client::connect_stream(
            Arc::new(client_config),
            client_stream,
            TestClient {
                expected_server_key,
            },
        )
        .await
        .expect("connect SSH client");

        // It never authenticates: russh alone would keep the session until its first
        // keepalive, 30 s in, which a russh client does not expect before authenticating.
        let served = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("an unauthenticated session outlived its limit")
            .expect("session task");
        let error = served.expect_err("an unauthenticated session ended as a success");
        assert!(
            error.to_string().contains("did not authenticate"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn an_authenticated_session_outlives_the_authentication_limit() {
        let operator = ed25519_key();
        let started = tokio::time::Instant::now();
        let shell =
            revocable_session(&operator, &[operator.public_key()], Duration::from_secs(2)).await;

        tokio::time::sleep_until(started + Duration::from_secs(3)).await;
        assert!(
            !shell.server.is_finished(),
            "the authentication limit closed an authenticated session"
        );
        shell
            .session
            .channel_open_session()
            .await
            .expect("session is still usable");
        shell.server.abort();
    }

    /// What a command's channel got, up to its close or for at most `within`.
    #[derive(Default)]
    struct CommandOutput {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        exit_status: Option<u32>,
        eof: bool,
        closed: bool,
    }

    async fn command_output(
        channel: &mut russh::Channel<client::Msg>,
        within: Duration,
    ) -> CommandOutput {
        let mut output = CommandOutput::default();
        let _ = tokio::time::timeout(within, async {
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => output.stdout.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, ext: 1 } => {
                        output.stderr.extend_from_slice(&data);
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        output.exit_status = Some(exit_status);
                    }
                    ChannelMsg::Eof => output.eof = true,
                    ChannelMsg::Close => {
                        output.closed = true;
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await;
        output
    }

    /// An exec session as the agent serves it, and the channel `command` started on.
    async fn exec_session(command: &str) -> (RevocableSession, russh::Channel<client::Msg>) {
        let operator = ed25519_key();
        let session = agent_session(
            &operator,
            &[operator.public_key()],
            AUTHENTICATION_LIMIT,
            SessionKind::Exec,
        )
        .await;
        let mut channel = session
            .session
            .channel_open_session()
            .await
            .expect("open command channel");
        channel.exec(true, command).await.expect("request command");
        let replies = channel_replies(&mut channel, 1).await;
        assert!(
            matches!(replies[..], [ChannelMsg::Success]),
            "the agent did not start the command: {replies:?}"
        );
        (session, channel)
    }

    #[tokio::test]
    async fn an_exec_session_runs_its_command_with_separate_streams_and_exit_status() {
        let (session, mut channel) = exec_session("echo out; echo err >&2; exit 7").await;

        let output = command_output(&mut channel, Duration::from_secs(10)).await;

        assert_eq!(String::from_utf8_lossy(&output.stdout), "out\n");
        assert_eq!(String::from_utf8_lossy(&output.stderr), "err\n");
        assert_eq!(output.exit_status, Some(7));
        assert!(output.eof, "the command's output had no EOF");
        assert!(output.closed, "the command's channel stayed open");
        session.server.abort();
    }

    #[tokio::test]
    async fn an_exec_session_gives_the_command_its_input_and_eof() {
        let (session, mut channel) = exec_session("cat").await;

        channel
            .data_bytes(b"line one\nline two\n".to_vec())
            .await
            .expect("send input");
        channel.eof().await.expect("send EOF");
        let output = command_output(&mut channel, Duration::from_secs(10)).await;

        // cat ends only once its stdin reaches EOF.
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "line one\nline two\n"
        );
        assert_eq!(output.exit_status, Some(0));
        session.server.abort();
    }

    #[tokio::test]
    async fn an_exec_session_runs_one_command_and_no_terminal() {
        let operator = ed25519_key();
        let session = agent_session(
            &operator,
            &[operator.public_key()],
            AUTHENTICATION_LIMIT,
            SessionKind::Exec,
        )
        .await;
        let mut channel = session
            .session
            .channel_open_session()
            .await
            .expect("open channel");

        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .expect("request PTY");
        channel.request_shell(true).await.expect("request shell");
        channel
            .exec(true, "sleep 2")
            .await
            .expect("request command");
        channel
            .exec(true, "echo second")
            .await
            .expect("request a second command");
        request_unsupported(&channel).await;
        let replies = channel_replies(&mut channel, 7).await;

        assert!(
            matches!(
                replies[..],
                [
                    ChannelMsg::Failure,
                    ChannelMsg::Failure,
                    ChannelMsg::Success,
                    ChannelMsg::Failure,
                    ChannelMsg::Failure,
                    ChannelMsg::Failure,
                    ChannelMsg::Failure
                ]
            ),
            "an exec session ran something besides its one command: {replies:?}"
        );
        session.server.abort();
    }

    #[tokio::test]
    async fn an_operator_that_reads_late_gets_all_of_the_command_output() {
        const SIZE: usize = 3_000_000;
        let (session, mut channel) =
            exec_session("dd if=/dev/zero bs=1000 count=3000 2>/dev/null").await;

        // Well past the command's exit and the silence that may follow it.
        tokio::time::sleep(COMMAND_OUTPUT_SILENCE * 3).await;
        let output = command_output(&mut channel, Duration::from_secs(20)).await;

        assert_eq!(output.stdout.len(), SIZE, "the command's output was cut");
        assert_eq!(output.exit_status, Some(0));
        session.server.abort();
    }

    #[tokio::test]
    async fn a_background_job_that_keeps_the_output_open_does_not_hold_the_channel() {
        // The job keeps the command's stdout open, and writes nothing to it, after the
        // command has exited; it ends on its own later.
        let (session, mut channel) = exec_session("sleep 4 & echo started").await;
        let started = tokio::time::Instant::now();

        let output = command_output(&mut channel, Duration::from_secs(10)).await;

        assert_eq!(String::from_utf8_lossy(&output.stdout), "started\n");
        assert_eq!(output.exit_status, Some(0));
        assert!(output.closed, "the command's channel stayed open");
        assert!(
            started.elapsed() < COMMAND_OUTPUT_SILENCE * 3,
            "the channel waited for the background job: {:?}",
            started.elapsed()
        );
        session.server.abort();
    }

    #[tokio::test]
    async fn unread_command_input_over_limit_closes_the_channel() {
        let (session, channel) = exec_session("sleep 5").await;
        let (mut reader, writer) = channel.split();
        let flood = tokio::spawn(async move {
            let _ = writer
                .data_bytes(vec![b'x'; INPUT_PENDING_LIMIT + 1024 * 1024])
                .await;
        });

        let mut stderr = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(message) = reader.wait().await {
                match message {
                    ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                    ChannelMsg::Close => return true,
                    _ => {}
                }
            }
            false
        })
        .await;

        flood.abort();
        assert!(
            matches!(closed, Ok(true)),
            "the channel stayed open past the input limit"
        );
        assert!(
            String::from_utf8_lossy(&stderr).contains("input buffer limit"),
            "the operator was not told why: {}",
            String::from_utf8_lossy(&stderr)
        );
        session.server.abort();
    }

    #[tokio::test]
    async fn input_after_the_command_closed_its_stdin_is_discarded() {
        let (session, channel) = exec_session("exec 0<&-; sleep 1; echo done").await;
        let (mut reader, writer) = channel.split();
        // More than the agent keeps for a command that does not read, after it closed stdin.
        tokio::time::sleep(Duration::from_millis(300)).await;
        writer
            .data_bytes(vec![b'x'; INPUT_PENDING_LIMIT + 1024 * 1024])
            .await
            .expect("send input");

        let mut stdout = Vec::new();
        let mut exit_status = None;
        let _ = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(message) = reader.wait().await {
                match message {
                    ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    ChannelMsg::ExitStatus {
                        exit_status: status,
                    } => exit_status = Some(status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        })
        .await;

        assert_eq!(String::from_utf8_lossy(&stdout), "done\n");
        assert_eq!(exit_status, Some(0), "the command did not end on its own");
        session.server.abort();
    }

    /// How long ending a command's group may take: SIGTERM, up to `HANGUP_GRACE` while
    /// something holds its output open, SIGKILL and the reap, plus a margin.
    const GROUP_TEARDOWN: Duration =
        Duration::from_secs(HANGUP_GRACE.as_secs() + KILL_REAP_WAIT.as_secs() + 2);

    /// A command that ignores SIGTERM, printing its PID.
    const TERM_IGNORING_COMMAND: &str = "trap '' TERM; echo PID=$$ END_$((3+4)); exec sleep 30";

    async fn assert_gone(pid: &str, what: &str) {
        let gone = wait_process_gone(pid, GROUP_TEARDOWN).await;
        if !gone {
            kill_process(pid);
        }
        assert!(gone, "{what} {pid} survived");
    }

    #[tokio::test]
    async fn a_cancelled_exec_ends_a_child_that_ignores_sigterm() {
        // The leader ends on SIGTERM; its child ignores it, and keeps the output open. The
        // child prints its PID only once it ignores SIGTERM: before, SIGTERM would end it.
        let (mut session, mut channel) = exec_session(
            "sh -c 'trap \"\" TERM; echo CHILD=$$ END_$((3+4)); exec sleep 30' & wait",
        )
        .await;
        let text = read_until(&mut channel, "END_7", Duration::from_secs(10)).await;
        let child = marker_value(&text, "CHILD=");

        session.cancel.send(()).expect("session still listening");
        let ended = tokio::time::timeout(Duration::from_secs(10), &mut session.server)
            .await
            .expect("a cancelled exec session stayed open")
            .expect("session task");
        let error = ended.expect_err("cancelled session ended as if completed");
        assert!(error.to_string().contains("cancelled"), "{error}");

        assert_gone(
            &child,
            "a child that ignores SIGTERM, of a cancelled command,",
        )
        .await;
    }

    #[tokio::test]
    async fn revoking_the_operator_of_a_running_exec_ends_its_command() {
        let (session, mut channel) = exec_session(TERM_IGNORING_COMMAND).await;
        let text = read_until(&mut channel, "END_7", Duration::from_secs(10)).await;
        let pid = marker_value(&text, "PID=");

        session
            .allowlist
            .send_replace(allowlist_of(&[ed25519_key().public_key()]));
        let ended = tokio::time::timeout(Duration::from_secs(10), session.server)
            .await
            .expect("the exec session of a revoked operator stayed open")
            .expect("session task");
        let error = ended.expect_err("revoked session ended as if completed");
        assert!(error.to_string().contains("revoked"), "{error}");

        assert_gone(&pid, "the command of a revoked operator").await;
    }

    #[tokio::test]
    async fn agent_shutdown_waits_for_an_exec_teardown() {
        let (mut session, mut channel) = exec_session(TERM_IGNORING_COMMAND).await;
        let text = read_until(&mut channel, "END_7", Duration::from_secs(10)).await;
        let pid = marker_value(&text, "PID=");

        // What `agent run` does on a stop signal: signal, drop its own guard, wait for the rest.
        session._shutdown.signal.send_replace(true);
        let (closed, _) = mpsc::channel(1);
        drop(std::mem::replace(&mut session._shutdown.guard, closed));
        let waited = tokio::time::timeout(Duration::from_secs(10), session._shutdown.guards.recv())
            .await
            .is_ok();

        let alive = process_alive(&pid);
        if alive {
            kill_process(&pid);
        }
        assert!(
            waited,
            "exec teardown did not finish within the shutdown bound"
        );
        assert!(
            !alive,
            "shutdown finished while command {pid} was still running"
        );
        session.server.abort();
    }

    /// A process that started a session of its own, as a daemon does, is not in the
    /// command's group, which is all that ending the command reaches (see the README).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_process_that_left_the_command_group_outlives_its_cancellation() {
        let (mut session, mut channel) = exec_session(
            "setsid sh -c 'exec sleep 30' </dev/null >/dev/null 2>&1 & \
             echo DAEMON=$! LEADER=$$ END_$((3+4)); exec sleep 30",
        )
        .await;
        let text = read_until(&mut channel, "END_7", Duration::from_secs(10)).await;
        let daemon = marker_value(&text, "DAEMON=");
        let leader = marker_value(&text, "LEADER=");
        // Once it runs sleep, it has left the group: setsid came before.
        let detached = tokio::time::timeout(Duration::from_secs(5), async {
            while !std::fs::read_to_string(format!("/proc/{daemon}/comm"))
                .is_ok_and(|comm| comm.trim() == "sleep")
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(detached.is_ok(), "{daemon} did not start its own session");

        session.cancel.send(()).expect("session still listening");
        let _ = tokio::time::timeout(Duration::from_secs(10), &mut session.server).await;
        let leader_gone = wait_process_gone(&leader, GROUP_TEARDOWN).await;
        let daemon_alive = process_alive(&daemon);
        kill_process(&daemon);
        if !leader_gone {
            kill_process(&leader);
        }

        assert!(leader_gone, "the cancelled command {leader} survived");
        assert!(
            daemon_alive,
            "{daemon}, which left the command's group, was ended with it"
        );
    }

    #[test]
    fn signals_are_reported_by_their_ssh_names() {
        assert!(matches!(super::ssh_signal(libc::SIGTERM), russh::Sig::TERM));
        assert!(matches!(super::ssh_signal(libc::SIGKILL), russh::Sig::KILL));
        assert!(matches!(
            super::ssh_signal(libc::SIGUSR2),
            russh::Sig::Custom(name) if name == "USR2"
        ));
        // SSH names no more than its list: the number stands in for the name.
        assert!(matches!(
            super::ssh_signal(libc::SIGWINCH),
            russh::Sig::Custom(name) if name == libc::SIGWINCH.to_string()
        ));
    }
}
