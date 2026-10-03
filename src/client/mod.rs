use futures_util::StreamExt;
use reqwest_websocket::Message;
use ssh_key::{HashAlg, LineEnding, PrivateKey};

use crate::config::Paths;
use crate::error::RevttyError;
use crate::protocol::{
    OPERATOR_AUTH_NAMESPACE, OperatorAuthRequest, OperatorAuthResponse, OperatorChallengeResponse,
    ProbeResult, operator_auth_message,
};
use crate::transport::{connect_websocket, http_url, valid_name};

pub fn init() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let identity = crate::identity::ensure_operator(&paths)?;

    println!(
        "identity {}",
        if identity.created {
            "created"
        } else {
            "existing"
        }
    );
    println!("fingerprint {}", identity.fingerprint);
    println!("private {}", identity.private_key_path.display());
    println!("public  {}", identity.public_key_path.display());
    Ok(())
}

pub fn list() -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("agent listing"))
}

pub fn status(_target: &str) -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("agent status"))
}

pub async fn probe(target: &str, relay: &str) -> Result<(), RevttyError> {
    if !valid_name(target) {
        return Err(RevttyError::message(
            "target names may contain only letters, digits, '.', '_' and '-'",
        ));
    }

    let paths = Paths::discover()?;
    let identity = crate::identity::ensure_operator(&paths)?;
    let private_key = PrivateKey::read_openssh_file(&identity.private_key_path)
        .map_err(|error| RevttyError::runtime("read operator private key", error))?;

    let client = reqwest::Client::new();
    let challenge_url = http_url(relay, &format!("/v1/operator/challenge/{target}"))?;
    let challenge_response = client
        .post(challenge_url)
        .send()
        .await
        .map_err(|error| RevttyError::runtime("request operator challenge", error))?;

    let challenge_status = challenge_response.status();
    if !challenge_status.is_success() {
        return Err(RevttyError::message(format!(
            "operator challenge rejected ({challenge_status})"
        )));
    }

    let challenge: OperatorChallengeResponse = challenge_response
        .json()
        .await
        .map_err(|error| RevttyError::runtime("decode operator challenge", error))?;

    let message = operator_auth_message(target, &challenge.challenge);
    let signature = private_key
        .sign(OPERATOR_AUTH_NAMESPACE, HashAlg::Sha256, message.as_bytes())
        .map_err(|error| RevttyError::runtime("sign operator challenge", error))?
        .to_pem(LineEnding::LF)
        .map_err(|error| RevttyError::runtime("encode operator SSH signature", error))?;

    let auth_url = http_url(relay, &format!("/v1/operator/auth/{target}"))?;
    let auth_response = client
        .post(auth_url)
        .json(&OperatorAuthRequest {
            challenge: challenge.challenge,
            signature,
        })
        .send()
        .await
        .map_err(|error| RevttyError::runtime("authenticate operator", error))?;

    let auth_status = auth_response.status();
    if !auth_status.is_success() {
        return Err(RevttyError::message(format!(
            "operator authentication rejected ({auth_status})"
        )));
    }

    let auth: OperatorAuthResponse = auth_response
        .json()
        .await
        .map_err(|error| RevttyError::runtime("decode operator authentication", error))?;

    let host_pin = crate::identity::pin_agent_host_key(&paths, relay, target, &auth.host_key)?;
    if host_pin.created {
        eprintln!("pinned host key {}", host_pin.fingerprint);
    }

    let path = format!("/v1/probe/{target}");
    let mut websocket = connect_websocket(&client, relay, &path, &auth.session_token).await?;

    while let Some(message) = websocket.next().await {
        match message {
            Ok(Message::Text(text)) => {
                let result: ProbeResult = serde_json::from_str(&text)
                    .map_err(|error| RevttyError::runtime("decode probe result", error))?;

                println!("target   {}", result.name);
                println!("status   reachable");
                println!("os       {}", result.os);
                println!("arch     {}", result.arch);
                println!("revtty   {}", result.version);
                return Ok(());
            }
            Ok(Message::Close { .. }) => break,
            Ok(_) => {}
            Err(error) => return Err(RevttyError::runtime("receive probe result", error)),
        }
    }

    Err(RevttyError::message(
        "probe session closed before the agent returned a result",
    ))
}

pub async fn connect(_target: &str) -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("remote terminal connection"))
}

pub fn doctor() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    println!("revtty {}", env!("CARGO_PKG_VERSION"));
    println!(
        "control protocol v{}",
        crate::protocol::CONTROL_PROTOCOL_VERSION
    );
    println!("default transport: {}", crate::transport::DEFAULT_TRANSPORT);
    println!("config: {}", paths.config_dir.display());
    println!("state: {}", paths.state_dir.display());
    Ok(())
}
