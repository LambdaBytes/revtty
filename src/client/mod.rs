mod ssh;

use std::io::IsTerminal;
use std::path::PathBuf;

use futures_util::StreamExt;
use reqwest_websocket::Message;
use ssh_key::{HashAlg, LineEnding, PrivateKey};

use crate::config::Paths;
use crate::error::RevttyError;
use crate::protocol::{
    AgentListResponse, AgentStatusResponse, OPERATOR_AUTH_NAMESPACE, OperatorAuthRequest,
    OperatorAuthResponse, OperatorChallengeResponse, OperatorListRequest, ProbeResult,
    SESSION_ERROR_PREFIX, operator_auth_message, operator_list_auth_message,
};
use crate::transport::{check_relay_health, connect_websocket, http_url, relay_client, valid_name};

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

pub fn forget(target: &str, relay: &str) -> Result<(), RevttyError> {
    if !valid_name(target) {
        return Err(RevttyError::message("invalid machine name"));
    }

    let paths = Paths::discover()?;
    let forgotten = crate::identity::forget_agent_host_key(&paths, relay, target)?;
    if forgotten == 0 {
        println!("no host key pinned for {target} on {relay}");
    } else {
        println!("forgotten  host key of {target} on {relay}");
        println!("The next status, probe or connect asks to pin its new host key.");
    }
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

    let client = relay_client()?;
    let mut response = request_agent_list(&client, &private_key, &operator_key, relay).await?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        // A list challenge is void once any agent is enrolled after it was issued; one
        // fresh attempt tells that apart from a key the relay really rejects.
        response = request_agent_list(&client, &private_key, &operator_key, relay).await?;
    }

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
            "{}\t{}\tsessions={}\tlast_seen={}\tversion={}",
            agent.name,
            if agent.online { "online" } else { "offline" },
            session_capacity(&agent),
            agent
                .last_seen
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            agent.version.as_deref().unwrap_or("-")
        );
    }

    Ok(())
}

pub async fn status(target: &str, relay: &str, host_key: Option<&str>) -> Result<(), RevttyError> {
    let operator = authenticate_operator(target, relay, host_key).await?;
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
    println!("sessions  {}", session_capacity(&status));
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

async fn request_agent_list(
    client: &reqwest::Client,
    private_key: &PrivateKey,
    operator_key: &str,
    relay: &str,
) -> Result<reqwest::Response, RevttyError> {
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
    client
        .post(list_url)
        .json(&OperatorListRequest {
            operator_key: operator_key.to_owned(),
            challenge: challenge.challenge,
            signature,
        })
        .send()
        .await
        .map_err(|error| RevttyError::runtime("request agent list", error))
}

fn session_capacity(status: &AgentStatusResponse) -> String {
    status.max_sessions.map_or_else(
        || "-".to_owned(),
        |max| format!("{}/{}", status.active_sessions, max),
    )
}

struct AuthenticatedOperator {
    client: reqwest::Client,
    private_key_path: PathBuf,
    auth: OperatorAuthResponse,
}

/// How the operator approved a host key that was not pinned yet.
enum HostKeyApproval {
    /// `--host-key` named the fingerprint: no time passed.
    Flag,
    /// Answered at the terminal, which may outlast the operator credential.
    Interactive,
}

async fn authenticate_operator(
    target: &str,
    relay: &str,
    expected_host_key: Option<&str>,
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

    let client = relay_client()?;
    let mut auth = request_operator_session(&client, &private_key, target, relay).await?;

    let check = crate::identity::check_agent_host_key(&paths, relay, target, &auth.host_key)?;
    if !check.pinned {
        let approval = approve_host_key(target, relay, &check.fingerprint, expected_host_key)?;
        crate::identity::pin_agent_host_key(&paths, relay, target, &auth.host_key)?;
        eprintln!("pinned host key {}", check.fingerprint);

        if let HostKeyApproval::Interactive = approval {
            // The operator credential is short-lived and single-use; request a new one and
            // make sure the relay still presents the key that was just approved.
            auth = request_operator_session(&client, &private_key, target, relay).await?;
            crate::identity::check_agent_host_key(&paths, relay, target, &auth.host_key)?;
        }
    }

    Ok(AuthenticatedOperator {
        client,
        private_key_path: identity.private_key_path,
        auth,
    })
}

/// The relay only relays the agent's host key, so a first pin is approved by the operator,
/// who compares the fingerprint with the one the target prints (`revtty agent status`).
fn approve_host_key(
    target: &str,
    relay: &str,
    fingerprint: &str,
    expected: Option<&str>,
) -> Result<HostKeyApproval, RevttyError> {
    if let Some(expected) = expected {
        if expected == fingerprint {
            return Ok(HostKeyApproval::Flag);
        }

        return Err(RevttyError::message(format!(
            "host key of {target} is {fingerprint}, not the expected {expected}; nothing was pinned"
        )));
    }

    if !std::io::stdin().is_terminal() {
        return Err(RevttyError::message(format!(
            "host key of {target} is not pinned yet (fingerprint {fingerprint}); compare it with \
             `revtty agent status` on the target and pass --host-key {fingerprint}"
        )));
    }

    eprint!(
        "The host key of {target} via {relay} is not pinned yet.\n\
         Fingerprint: {fingerprint}\n\
         Compare it with `revtty agent status` on the target.\n\
         Type yes or the fingerprint to pin it: "
    );

    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| RevttyError::runtime("read host key confirmation", error))?;
    let answer = answer.trim();

    if answer == "yes" || answer == fingerprint {
        Ok(HostKeyApproval::Interactive)
    } else {
        Err(RevttyError::message(
            "host key not confirmed; nothing was pinned",
        ))
    }
}

async fn request_operator_session(
    client: &reqwest::Client,
    private_key: &PrivateKey,
    target: &str,
    relay: &str,
) -> Result<OperatorAuthResponse, RevttyError> {
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

    auth_response
        .json()
        .await
        .map_err(|error| RevttyError::runtime("decode operator authentication", error))
}

pub async fn probe(target: &str, relay: &str, host_key: Option<&str>) -> Result<(), RevttyError> {
    let operator = authenticate_operator(target, relay, host_key).await?;
    let path = format!("/v1/probe/{target}");
    let mut websocket =
        connect_websocket(&operator.client, relay, &path, &operator.auth.session_token).await?;

    while let Some(message) = websocket.next().await {
        match message {
            Ok(Message::Text(text)) => {
                // The relay explains a refused session (busy agent, timeout) before closing.
                if let Some(detail) = text.strip_prefix(SESSION_ERROR_PREFIX) {
                    return Err(RevttyError::message(detail.to_owned()));
                }

                let result: ProbeResult = serde_json::from_str(&text)
                    .map_err(|error| RevttyError::runtime("decode probe result", error))?;

                println!("target   {}", result.name);
                println!("status   reachable");
                println!("os       {}", result.os);
                println!("arch     {}", result.arch);
                println!("revtty   {}", result.version);
                // Close the tunnel cleanly: the relay audits how sessions end.
                let _ = websocket
                    .close(reqwest_websocket::CloseCode::Normal, None)
                    .await;
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

/// Exit code when the session ended without a remote exit status, as with ssh.
const UNKNOWN_EXIT_CODE: u8 = 255;

/// Returns the code `revtty connect` exits with: the remote shell's exit status.
pub async fn connect(target: &str, relay: &str, host_key: Option<&str>) -> Result<u8, RevttyError> {
    let operator = authenticate_operator(target, relay, host_key).await?;
    let path = format!("/v1/connect/{target}");
    let websocket =
        connect_websocket(&operator.client, relay, &path, &operator.auth.session_token).await?;

    let status = ssh::connect_terminal(
        websocket,
        &operator.private_key_path,
        &operator.auth.host_key,
    )
    .await?;

    match status {
        Some(status) => {
            eprintln!("\r\nconnection closed (exit {status})");
            Ok(u8::try_from(status).unwrap_or(u8::MAX))
        }
        None => {
            eprintln!("\r\nconnection closed (exit status unknown)");
            Ok(UNKNOWN_EXIT_CODE)
        }
    }
}

pub async fn doctor(relay: &str) -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let identity = crate::identity::ensure_operator(&paths)?;
    let client = relay_client()?;

    // Whoever can change these can swap the operator key or the pinned agent host keys.
    crate::config::check_not_writable_by_others(&paths.config_dir)?;
    let known_hosts = paths.config_dir.join("known_hosts");
    if known_hosts.exists() {
        crate::config::check_not_writable_by_others(&known_hosts)?;
    }

    check_relay_health(&client, relay).await?;

    // A signed list proves the relay accepts this operator key end to end.
    let private_key = PrivateKey::read_openssh_file(&identity.private_key_path)
        .map_err(|error| RevttyError::runtime("read operator private key", error))?;
    let operator_key = private_key
        .public_key()
        .to_openssh()
        .map_err(|error| RevttyError::runtime("encode operator public key", error))?;
    let response = request_agent_list(&client, &private_key, &operator_key, relay).await?;
    if !response.status().is_success() {
        return Err(RevttyError::message(format!(
            "relay rejected the signed operator list ({})",
            response.status()
        )));
    }
    let listed: AgentListResponse = response
        .json()
        .await
        .map_err(|error| RevttyError::runtime("decode agent list", error))?;

    println!("revtty     {}", env!("CARGO_PKG_VERSION"));
    println!("protocol   v{}", crate::protocol::CONTROL_PROTOCOL_VERSION);
    println!("transport  {}", crate::transport::DEFAULT_TRANSPORT);
    println!("identity   {}", identity.fingerprint);
    println!("relay      {relay} reachable");
    println!(
        "auth       ok ({} agents enrolled for this key)",
        listed.agents.len()
    );
    println!("config     {}", paths.config_dir.display());
    println!("state      {}", paths.state_dir.display());
    Ok(())
}
