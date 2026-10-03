mod ssh;

use std::path::PathBuf;

use futures_util::StreamExt;
use reqwest_websocket::Message;
use ssh_key::{HashAlg, LineEnding, PrivateKey};

use crate::config::Paths;
use crate::error::RevttyError;
use crate::protocol::{
    AgentListResponse, AgentStatusResponse, OPERATOR_AUTH_NAMESPACE, OperatorAuthRequest,
    OperatorAuthResponse, OperatorChallengeResponse, OperatorListRequest, ProbeResult,
    operator_auth_message, operator_list_auth_message,
};
use crate::transport::{check_relay_health, connect_websocket, http_url, valid_name};

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

pub async fn list(relay: &str) -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let identity = crate::identity::ensure_operator(&paths)?;
    let private_key = PrivateKey::read_openssh_file(&identity.private_key_path)
        .map_err(|error| RevttyError::runtime("read operator private key", error))?;
    let operator_key = private_key
        .public_key()
        .to_openssh()
        .map_err(|error| RevttyError::runtime("encode operator public key", error))?;

    let client = reqwest::Client::new();
    let challenge_url = http_url(relay, "/v1/operator/list/challenge")?;
    let challenge_response = client
        .post(challenge_url)
        .send()
        .await
        .map_err(|error| RevttyError::runtime("request operator list challenge", error))?;

    let challenge_status = challenge_response.status();
    if !challenge_status.is_success() {
        return Err(RevttyError::message(format!(
            "operator list challenge rejected ({challenge_status})"
        )));
    }

    let challenge: OperatorChallengeResponse = challenge_response
        .json()
        .await
        .map_err(|error| RevttyError::runtime("decode operator list challenge", error))?;

    let message = operator_list_auth_message(&challenge.challenge);
    let signature = private_key
        .sign(OPERATOR_AUTH_NAMESPACE, HashAlg::Sha256, message.as_bytes())
        .map_err(|error| RevttyError::runtime("sign operator list challenge", error))?
        .to_pem(LineEnding::LF)
        .map_err(|error| RevttyError::runtime("encode operator list SSH signature", error))?;

    let list_url = http_url(relay, "/v1/operator/list")?;
    let response = client
        .post(list_url)
        .json(&OperatorListRequest {
            operator_key,
            challenge: challenge.challenge,
            signature,
        })
        .send()
        .await
        .map_err(|error| RevttyError::runtime("request agent list", error))?;

    let status = response.status();
    if !status.is_success() {
        return Err(RevttyError::message(format!(
            "operator list rejected ({status})"
        )));
    }

    let response: AgentListResponse = response
        .json()
        .await
        .map_err(|error| RevttyError::runtime("decode agent list", error))?;

    if response.agents.is_empty() {
        println!("No enrolled agents.");
        return Ok(());
    }

    for agent in response.agents {
        println!(
            "{}\t{}\tlast_seen={}\tversion={}",
            agent.name,
            if agent.online { "online" } else { "offline" },
            agent
                .last_seen
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            agent.version.as_deref().unwrap_or("-")
        );
    }

    Ok(())
}

pub async fn status(target: &str, relay: &str) -> Result<(), RevttyError> {
    let operator = authenticate_operator(target, relay).await?;
    let url = http_url(relay, &format!("/v1/status/{target}"))?;
    let response = operator
        .client
        .get(url)
        .bearer_auth(&operator.auth.session_token)
        .send()
        .await
        .map_err(|error| RevttyError::runtime("request agent status", error))?;

    let response_status = response.status();
    if !response_status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        return Err(RevttyError::message(format!(
            "agent status rejected ({response_status}){}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }

    let status: AgentStatusResponse = response
        .json()
        .await
        .map_err(|error| RevttyError::runtime("decode agent status", error))?;

    println!("target    {}", status.name);
    println!(
        "status    {}",
        if status.online { "online" } else { "offline" }
    );
    println!("id        {}", status.id);
    println!("created   {}", status.created_at);
    println!(
        "last_seen {}",
        status
            .last_seen
            .map_or_else(|| "-".to_owned(), |value| value.to_string())
    );
    println!("revtty    {}", status.version.as_deref().unwrap_or("-"));
    Ok(())
}

struct AuthenticatedOperator {
    client: reqwest::Client,
    private_key_path: PathBuf,
    auth: OperatorAuthResponse,
}

async fn authenticate_operator(
    target: &str,
    relay: &str,
) -> Result<AuthenticatedOperator, RevttyError> {
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

    Ok(AuthenticatedOperator {
        client,
        private_key_path: identity.private_key_path,
        auth,
    })
}

pub async fn probe(target: &str, relay: &str) -> Result<(), RevttyError> {
    let operator = authenticate_operator(target, relay).await?;
    let path = format!("/v1/probe/{target}");
    let mut websocket =
        connect_websocket(&operator.client, relay, &path, &operator.auth.session_token).await?;

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

pub async fn connect(target: &str, relay: &str) -> Result<(), RevttyError> {
    let operator = authenticate_operator(target, relay).await?;
    let path = format!("/v1/connect/{target}");
    let websocket =
        connect_websocket(&operator.client, relay, &path, &operator.auth.session_token).await?;

    let status = ssh::connect_terminal(
        websocket,
        &operator.private_key_path,
        &operator.auth.host_key,
    )
    .await?;

    eprintln!("\r\nconnection closed (exit {status})");
    Ok(())
}

pub async fn doctor(relay: &str) -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let identity = crate::identity::ensure_operator(&paths)?;
    let client = reqwest::Client::new();

    check_relay_health(&client, relay).await?;

    println!("revtty     {}", env!("CARGO_PKG_VERSION"));
    println!("protocol   v{}", crate::protocol::CONTROL_PROTOCOL_VERSION);
    println!("transport  {}", crate::transport::DEFAULT_TRANSPORT);
    println!("identity   {}", identity.fingerprint);
    println!("relay      {relay} reachable");
    println!("config     {}", paths.config_dir.display());
    println!("state      {}", paths.state_dir.display());
    Ok(())
}
