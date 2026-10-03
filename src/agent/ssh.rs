use std::borrow::Cow;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtyPair, PtySize, native_pty_system};
use reqwest::Client;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Msg, Session};
use russh::{Channel, ChannelId, Preferred, Pty};
use tokio::sync::mpsc;

use crate::config::Paths;
use crate::error::RevttyError;
use crate::identity::ensure_agent;
use crate::transport::{connect_websocket, websocket_byte_stream};

const PTY_QUEUE_DEPTH: usize = 32;
const PTY_IO_CHUNK: usize = 16 * 1024;

struct PendingPty {
    channel: ChannelId,
    term: String,
    pair: PtyPair,
}

struct ActiveShell {
    channel: ChannelId,
    master: Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>,
    input: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
    killer: Box<dyn ChildKiller + Send + Sync>,
}

struct AgentSshHandler {
    authorized_operator: PublicKey,
    open_channel: Option<ChannelId>,
    pending_pty: Option<PendingPty>,
    active_shell: Option<ActiveShell>,
}

impl AgentSshHandler {
    fn new(authorized_operator: PublicKey) -> Self {
        Self {
            authorized_operator,
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

        if let Ok(mut input) = active.input.lock() {
            input.take();
        }
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
            if let Some(mut active) = self.active_shell.take() {
                let _ = active.killer.kill();
                if let Ok(mut input) = active.input.lock() {
                    input.take();
                }
                if let Ok(mut master) = active.master.lock() {
                    master.take();
                }
            }
        }

        if self.open_channel == Some(channel) {
            self.open_channel = None;
        }
    }
}

impl Drop for AgentSshHandler {
    fn drop(&mut self) {
        if let Some(active) = self.active_shell.as_mut() {
            let _ = active.killer.kill();
            if let Ok(mut input) = active.input.lock() {
                input.take();
            }
            if let Ok(mut master) = active.master.lock() {
                master.take();
            }
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
        if user == "revtty" && public_key == &self.authorized_operator {
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
                session.channel_failure(channel)?;
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

        let PendingPty {
            channel,
            term,
            pair,
        } = pending;
        let PtyPair { slave, master } = pair;

        let mut command = CommandBuilder::new_default_prog();
        command.env("TERM", term);

        let mut child = match slave.spawn_command(command) {
            Ok(child) => child,
            Err(error) => {
                eprintln!("shell spawn failed: {error}");
                session.channel_failure(channel)?;
                return Ok(());
            }
        };
        drop(slave);

        let mut reader = match master.try_clone_reader() {
            Ok(reader) => reader,
            Err(error) => {
                eprintln!("PTY reader creation failed: {error}");
                let _ = child.kill();
                session.channel_failure(channel)?;
                return Ok(());
            }
        };
        let mut writer = match master.take_writer() {
            Ok(writer) => writer,
            Err(error) => {
                eprintln!("PTY writer creation failed: {error}");
                let _ = child.kill();
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        let killer = child.clone_killer();
        let master = Arc::new(Mutex::new(Some(master)));
        let input = Arc::new(Mutex::new(None));
        let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(PTY_QUEUE_DEPTH);
        let (output_tx, mut output_rx) = mpsc::channel::<Vec<u8>>(PTY_QUEUE_DEPTH);

        if let Ok(mut slot) = input.lock() {
            *slot = Some(input_tx);
        } else {
            let _ = child.kill();
            session.channel_failure(channel)?;
            return Ok(());
        }

        std::thread::spawn(move || {
            let mut buffer = [0_u8; PTY_IO_CHUNK];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        if output_tx.blocking_send(buffer[..read].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        std::thread::spawn(move || {
            while let Some(data) = input_rx.blocking_recv() {
                if writer.write_all(&data).is_err() || writer.flush().is_err() {
                    break;
                }
            }
        });

        let session_handle = session.handle();
        let master_for_wait = Arc::clone(&master);
        let input_for_wait = Arc::clone(&input);
        let mut child_wait = tokio::task::spawn_blocking(move || child.wait());

        tokio::spawn(async move {
            let mut exit_code = None;
            let mut output_closed = false;

            loop {
                tokio::select! {
                    output = output_rx.recv(), if !output_closed => {
                        match output {
                            Some(data) => {
                                if session_handle.data(channel, data).await.is_err() {
                                    return;
                                }
                            }
                            None => output_closed = true,
                        }
                    }
                    status = &mut child_wait, if exit_code.is_none() => {
                        exit_code = Some(match status {
                            Ok(Ok(status)) => status.exit_code(),
                            _ => 1,
                        });

                        if let Ok(mut input) = input_for_wait.lock() {
                            input.take();
                        }
                        if let Ok(mut master) = master_for_wait.lock() {
                            master.take();
                        }
                    }
                }

                if output_closed && exit_code.is_some() {
                    break;
                }
            }

            let _ = session_handle
                .exit_status_request(channel, exit_code.unwrap_or(1))
                .await;
            let _ = session_handle.eof(channel).await;
            let _ = session_handle.close(channel).await;
        });

        self.active_shell = Some(ActiveShell {
            channel,
            master,
            input,
            killer,
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let sender = self
            .active_shell
            .as_ref()
            .filter(|active| active.channel == channel)
            .and_then(|active| {
                active
                    .input
                    .lock()
                    .ok()
                    .and_then(|input| input.as_ref().cloned())
            });

        if let Some(sender) = sender {
            let _ = sender.send(data.to_vec()).await;
        }

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

pub async fn serve(
    client: &Client,
    relay: &str,
    token: &str,
    session_id: &str,
    encoded_operator_key: &str,
) -> Result<(), RevttyError> {
    let path = format!("/v1/session/{session_id}");
    let websocket = connect_websocket(client, relay, &path, token).await?;
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

        let config = server::Config {
            keys: vec![host_key],
            preferred: ed25519_only(),
            ..Default::default()
        };

        let running = server::run_stream(
            Arc::new(config),
            stream,
            AgentSshHandler::new(authorized_operator),
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

    use russh::ChannelMsg;
    use russh::keys::key::{PrivateKeyWithHashAlg, safe_rng};
    use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate};
    use russh::{client, server};

    use super::{AgentSshHandler, ed25519_only};

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
    async fn interactive_shell_runs_inside_real_pty() {
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

        let server_task = tokio::spawn(async move {
            let running = server::run_stream(
                Arc::new(server_config),
                server_stream,
                AgentSshHandler::new(authorized_client),
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

        let command = [
            br"printf '\162\145\166\164\164\171\055\163\150\145\154\154\055\157\153\012'; exit"
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

        assert!(
            String::from_utf8_lossy(&output).contains("revtty-shell-ok"),
            "shell output did not contain validation marker: {}",
            String::from_utf8_lossy(&output)
        );

        drop(session);
        server_task.abort();
        let _ = server_task.await;
    }
}
