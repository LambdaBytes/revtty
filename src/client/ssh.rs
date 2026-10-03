use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;

use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use reqwest_websocket::WebSocket;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, Preferred, client};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::RevttyError;
use crate::transport::websocket_byte_stream;

struct ClientHandler {
    expected_server_key: PublicKey,
}

impl client::Handler for ClientHandler {
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

fn ed25519_only() -> Preferred {
    Preferred {
        key: Cow::Owned(vec![Algorithm::Ed25519]),
        ..Preferred::default()
    }
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
        let config = client::Config {
            preferred: ed25519_only(),
            ..Default::default()
        };

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

        let _raw_mode = RawModeGuard::enter()?;
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut input = [0_u8; 4096];
        let mut stdin_closed = false;
        let mut exit_status = None;

        loop {
            tokio::select! {
                read = stdin.read(&mut input), if !stdin_closed => {
                    match read {
                        Ok(0) => {
                            stdin_closed = true;
                            let _ = channel.eof().await;
                        }
                        Ok(read) => {
                            channel
                                .data(&input[..read])
                                .await
                                .map_err(|error| RevttyError::runtime("send terminal input", error))?;
                        }
                        Err(error) => {
                            return Err(RevttyError::runtime("read local terminal input", error));
                        }
                    }
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

    bridge_task.abort();
    let _ = bridge_task.await;
    result
}
