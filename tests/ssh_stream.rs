use std::borrow::Cow;
use std::sync::Arc;

use russh::client;
use russh::keys::key::{PrivateKeyWithHashAlg, safe_rng};
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::server;
use russh::Preferred;

struct TestServer {
    authorized_client: PublicKey,
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        if public_key == &self.authorized_client {
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::reject())
        }
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

fn ed25519_only() -> Preferred {
    Preferred {
        key: Cow::Owned(vec![Algorithm::Ed25519]),
        ..Preferred::default()
    }
}

#[tokio::test]
async fn ssh_authenticates_over_arbitrary_duplex_stream() {
    let server_key = ed25519_key();
    let expected_server_key = server_key.public_key().clone();

    let client_key = ed25519_key();
    let authorized_client = client_key.public_key().clone();

    let mut server_config = server::Config::default();
    server_config.keys = vec![server_key];
    server_config.preferred = ed25519_only();

    let mut client_config = client::Config::default();
    client_config.preferred = ed25519_only();

    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);

    let server_task = tokio::spawn(async move {
        let running = server::run_stream(
            Arc::new(server_config),
            server_stream,
            TestServer { authorized_client },
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
    .expect("connect SSH client over duplex stream");

    let auth = session
        .authenticate_publickey(
            "revtty",
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .expect("authenticate operator key");

    assert!(auth.success(), "Ed25519 public-key auth should succeed");

    drop(session);
    server_task.abort();
    let _ = server_task.await;
}
