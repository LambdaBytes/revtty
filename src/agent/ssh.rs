use std::borrow::Cow;
use std::sync::Arc;

use reqwest::Client;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::{Preferred, server};

use crate::config::Paths;
use crate::error::RevttyError;
use crate::identity::ensure_agent;
use crate::transport::{connect_websocket, websocket_byte_stream};

struct AgentSshHandler {
    authorized_operator: PublicKey,
}

impl server::Handler for AgentSshHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        if public_key == &self.authorized_operator {
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::reject())
        }
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
            AgentSshHandler {
                authorized_operator,
            },
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
