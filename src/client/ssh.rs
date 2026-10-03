use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;

use reqwest_websocket::WebSocket;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{Disconnect, Preferred, client};

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

fn ed25519_only() -> Preferred {
    Preferred {
        key: Cow::Owned(vec![Algorithm::Ed25519]),
        ..Preferred::default()
    }
}

pub async fn authenticate(
    websocket: WebSocket,
    operator_key_path: &Path,
    encoded_host_key: &str,
) -> Result<(), RevttyError> {
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

        session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
            .map_err(|error| RevttyError::runtime("close SSH transport", error))
    }
    .await;

    bridge_task.abort();
    let _ = bridge_task.await;
    result
}
