mod ssh;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use ssh_key::{HashAlg, LineEnding, PrivateKey};
use tokio::signal::unix::{SignalKind, signal};

use crate::config::Paths;
use crate::error::{RevttyError, with_sources};
use crate::identity::HostKeyTrust;
use crate::pairing::{PairingCode, PairingSecret};
use crate::protocol::{
    AgentListResponse, AgentStatusResponse, OPERATOR_AUTH_NAMESPACE, OperatorAuthRequest,
    OperatorAuthResponse, OperatorChallengeResponse, OperatorListRequest, SESSION_NOT_ACCEPTED,
    operator_auth_message, operator_list_auth_message,
};
use crate::transport::{
    RefusedUpgrade, check_relay_health, connect_websocket, connect_websocket_or_refusal, http_url,
    relay_client, valid_name,
};

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

/// Makes the pairing code for enrolling `target` with `token`, and keeps its secret for the
/// first contact with the target. Nothing is sent anywhere.
pub fn pair(target: &str, token: &str, relay: &str) -> Result<(), RevttyError> {
    if !valid_name(target) {
        return Err(RevttyError::message("invalid machine name"));
    }
    // The URL the target enrolls with: refused now if it would be refused there.
    http_url(relay, "/v1/enroll")?;

    let paths = Paths::discover()?;
    let identity = crate::identity::ensure_operator(&paths)?;
    // The enrollment exists, so it was made for an existing key: a code for a key created now
    // would only make the target refuse its enrollment, once the relay has used it up.
    if identity.created {
        return Err(RevttyError::message(format!(
            "there was no operator identity here, so the enrollment cannot be for it; one was \
             created now ({}). Run `revtty pair` where the operator key the enrollment names is, \
             or have {target} enrolled again for this one",
            identity.public_key_path.display()
        )));
    }
    let code = PairingCode::new(
        token,
        PairingSecret::generate()?,
        target,
        &identity.fingerprint,
    )?;
    crate::identity::save_pairing(&paths, relay, target, code.secret())?;

    let code = code.encode();
    println!("target     {target}");
    println!("relay      {relay}");
    println!("code       {code}");
    println!(
        "On the target, enroll with the code, never as --token (an older revtty that does not \
         know --pairing-code would send its secret to the relay):"
    );
    println!("revtty agent enroll --relay {relay} --pairing-code {code}");
    Ok(())
}

pub fn forget(target: &str, relay: &str) -> Result<(), RevttyError> {
    if !valid_name(target) {
        return Err(RevttyError::message("invalid machine name"));
    }

    let paths = Paths::discover()?;
    let forgotten = crate::identity::forget_agent_host_key(&paths, relay, target)?;
    if forgotten.pairing {
        println!("discarded  pairing code for {target} on {relay}");
    }
    if forgotten.pins == 0 {
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
    let operator = authenticate_operator(target, relay, host_key, true).await?;
    let url = http_url(relay, &format!("/v1/status/{target}"))?;
    let response = operator
        .client
        .get(url)
        .bearer_auth(&operator.auth.session_token)
        .send()
        .await
        .map_err(|error| RevttyError::runtime("request agent status", with_sources(&error)))?;

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
    let challenge_response = client.post(challenge_url).send().await.map_err(|error| {
        RevttyError::runtime("request operator list challenge", with_sources(&error))
    })?;

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
        .map_err(|error| RevttyError::runtime("request agent list", with_sources(&error)))
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

/// With `prompt` false, a host key that is neither pinned nor proven by a pairing code needs
/// `expected_host_key`: nothing is asked at the terminal.
async fn authenticate_operator(
    target: &str,
    relay: &str,
    expected_host_key: Option<&str>,
    prompt: bool,
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

    if let Some(expected) = expected_host_key {
        let check = crate::identity::check_agent_host_key(&paths, relay, target, &auth.host_key)?;
        // Checked even against a pin: the operator obtained it independently, and it names
        // the key this connection must reach.
        if expected != check.fingerprint {
            return Err(RevttyError::message(format!(
                "the host key the relay presented for {target} does not match --host-key \
                 {expected}; nothing was pinned"
            )));
        }
        // No time passed since the credential was issued, so it is still for this key.
        crate::identity::pin_agent_host_key(&paths, relay, target, &auth.host_key)?;
        if !check.pinned {
            eprintln!("pinned host key {}", check.fingerprint);
        }
    } else {
        match crate::identity::trust_agent_host_key(
            &paths,
            relay,
            target,
            &auth.host_key,
            auth.host_key_proof.as_deref(),
        )? {
            HostKeyTrust::Pinned => {}
            HostKeyTrust::Paired { fingerprint } => {
                eprintln!("pinned host key {fingerprint}, verified by pairing code");
            }
            HostKeyTrust::Unknown { fingerprint } => {
                confirm_host_key(target, relay, &fingerprint, prompt)?;
                crate::identity::pin_agent_host_key(&paths, relay, target, &auth.host_key)?;
                eprintln!("pinned host key {fingerprint}");

                // The operator credential is short-lived and single-use, and answering may
                // outlast it; request a new one and make sure the relay still presents the key
                // that was just approved: compared with that key itself, not through the pin,
                // which another process may have removed.
                let approved = auth.host_key.clone();
                auth = request_operator_session(&client, &private_key, target, relay).await?;
                if !crate::identity::same_agent_host_key(&approved, &auth.host_key)? {
                    return Err(RevttyError::message(format!(
                        "the relay presented another host key for {target} after it was \
                         confirmed; the session was not opened"
                    )));
                }
            }
        }
    }

    Ok(AuthenticatedOperator {
        client,
        private_key_path: identity.private_key_path,
        auth,
    })
}

/// The relay only relays the agent's host key, so without a pairing code a first pin needs the
/// fingerprint from the target itself (`revtty agent status`): given with --host-key, or typed
/// at the terminal here when `prompt` allows it. The fingerprint the relay presented is never
/// shown, so that it cannot be copied back in place of the target's.
fn confirm_host_key(
    target: &str,
    relay: &str,
    fingerprint: &str,
    prompt: bool,
) -> Result<(), RevttyError> {
    if !prompt || !std::io::stdin().is_terminal() {
        return Err(RevttyError::message(format!(
            "host key of {target} is not pinned yet; pass --host-key with the fingerprint \
             `revtty agent status` shows on the target"
        )));
    }

    eprint!(
        "The host key of {target} via {relay} is not pinned yet.\n\
         Run `revtty agent status` on the target and enter the host key fingerprint it shows: "
    );

    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| RevttyError::runtime("read host key confirmation", error))?;

    if answer.trim() == fingerprint {
        Ok(())
    } else {
        Err(RevttyError::message(
            "the fingerprint entered does not match the host key the relay presented; nothing \
             was pinned",
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
    let challenge_response = client.post(challenge_url).send().await.map_err(|error| {
        RevttyError::runtime("request operator challenge", with_sources(&error))
    })?;

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
        .map_err(|error| RevttyError::runtime("authenticate operator", with_sources(&error)))?;

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
    let operator = authenticate_operator(target, relay, host_key, true).await?;
    let path = format!("/v1/probe/{target}");
    let websocket =
        connect_websocket(&operator.client, relay, &path, &operator.auth.session_token).await?;
    let result = ssh::run_probe(
        websocket,
        &operator.private_key_path,
        &operator.auth.host_key,
        target,
    )
    .await?;

    println!("target   {}", result.name);
    println!("status   reachable");
    println!("os       {}", result.os);
    println!("arch     {}", result.arch);
    println!("revtty   {}", result.version);
    Ok(())
}

/// Exit code when the session ended without a remote exit status, as with ssh.
const UNKNOWN_EXIT_CODE: u8 = 255;

/// Returns the code `revtty connect` exits with: the remote shell's exit status.
pub async fn connect(target: &str, relay: &str, host_key: Option<&str>) -> Result<u8, RevttyError> {
    let operator = authenticate_operator(target, relay, host_key, true).await?;
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

/// Exit code when `revtty exec` stopped waiting after `--timeout`, as timeout(1) has it.
const TIMED_OUT_EXIT_CODE: u8 = 124;
/// Exit code when `revtty exec` was interrupted with Ctrl-C, as shells report SIGINT.
const INTERRUPTED_EXIT_CODE: u8 = 130;
/// How long `revtty exec` waits for its own message about a stop to reach stderr: a local
/// stderr that nobody reads must not hold it past its timeout or Ctrl-C.
const STOP_MESSAGE_WAIT: Duration = Duration::from_millis(200);

/// Runs `command` on `target` and returns the code `revtty exec` exits with: the command's
/// exit status, as with ssh. Nothing is asked at the terminal, so a host key not pinned yet
/// needs `host_key`. `timeout` and Ctrl-C end the whole run, authentication included, and
/// the command with it.
pub async fn exec(
    target: &str,
    relay: &str,
    host_key: Option<&str>,
    timeout: Option<Duration>,
    forward_stdin: bool,
    command: &str,
) -> Result<u8, RevttyError> {
    // Listening from the start: a Ctrl-C at any point must end the command.
    let mut interrupts = signal(SignalKind::interrupt())
        .map_err(|error| RevttyError::runtime("listen for Ctrl-C", error))?;
    let stop = async {
        let timed_out = async {
            match timeout {
                Some(timeout) => tokio::time::sleep(timeout).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = timed_out => ssh::Stop::TimedOut,
            _ = interrupts.recv() => ssh::Stop::Interrupted,
        }
    };
    tokio::pin!(stop);

    let opened = async {
        let operator = authenticate_operator(target, relay, host_key, false).await?;
        let path = format!("/v1/exec/{target}");
        let websocket = connect_websocket_or_refusal(
            &operator.client,
            relay,
            &path,
            &operator.auth.session_token,
        )
        .await?
        .map_err(exec_refused)?;
        Ok::<_, RevttyError>((operator, websocket))
    };
    let (operator, websocket) = tokio::select! {
        opened = opened => opened?,
        stopped = &mut stop => return Ok(stopped_exit_code(stopped, timeout).await),
    };

    let end = ssh::run_command(
        websocket,
        &operator.private_key_path,
        &operator.auth.host_key,
        command,
        forward_stdin,
        &mut stop,
    )
    .await
    .map_err(|error| {
        if error.to_string() == SESSION_NOT_ACCEPTED {
            RevttyError::message(format!(
                "{SESSION_NOT_ACCEPTED}; the agent may predate exec (upgrade revtty on {target})"
            ))
        } else {
            error
        }
    })?;

    Ok(match end {
        ssh::CommandEnd::Exited(status) => u8::try_from(status).unwrap_or(u8::MAX),
        ssh::CommandEnd::Killed(signal) => {
            eprintln!("revtty: the remote command was killed by signal {signal}");
            UNKNOWN_EXIT_CODE
        }
        ssh::CommandEnd::Unknown => {
            eprintln!("revtty: the remote command ended without an exit status");
            UNKNOWN_EXIT_CODE
        }
        ssh::CommandEnd::Stopped(stopped) => stopped_exit_code(stopped, timeout).await,
    })
}

async fn stopped_exit_code(stopped: ssh::Stop, timeout: Option<Duration>) -> u8 {
    let (message, code) = match stopped {
        ssh::Stop::TimedOut => (
            format!(
                "revtty: timed out after {}s; ending the remote command",
                timeout.unwrap_or_default().as_secs()
            ),
            TIMED_OUT_EXIT_CODE,
        ),
        ssh::Stop::Interrupted => (
            "revtty: interrupted; ending the remote command".to_owned(),
            INTERRUPTED_EXIT_CODE,
        ),
    };
    report_without_waiting(message).await;
    code
}

/// Writes `message` to stderr on a thread of its own and waits `STOP_MESSAGE_WAIT` at most:
/// a message stderr has not taken by then goes with the process.
async fn report_without_waiting(message: String) {
    let (written, wrote) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        eprintln!("{message}");
        let _ = written.send(());
    });
    let _ = tokio::time::timeout(STOP_MESSAGE_WAIT, wrote).await;
}

/// A relay that predates exec does not know its route, and answers as for any unknown path.
fn exec_refused(refused: RefusedUpgrade) -> RevttyError {
    if refused.status == reqwest::StatusCode::NOT_FOUND && refused.body.is_empty() {
        return RevttyError::message(
            "the relay does not support exec; upgrade revtty on the relay",
        );
    }
    RevttyError::message(format!(
        "relay refused the command ({}){}",
        refused.status,
        if refused.body.is_empty() {
            String::new()
        } else {
            format!(": {}", refused.body)
        }
    ))
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
    // Whoever can read a pairing's secret can forge the proof that pins a host key with it.
    let pairings = paths.config_dir.join("pairings");
    if pairings.exists() {
        crate::config::check_private_file(&pairings)?;
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

#[cfg(test)]
mod tests {
    use super::exec_refused;
    use crate::transport::RefusedUpgrade;

    #[test]
    fn exec_refusals_tell_an_old_relay_from_an_offline_agent() {
        let old_relay = exec_refused(RefusedUpgrade {
            status: reqwest::StatusCode::NOT_FOUND,
            body: String::new(),
        })
        .to_string();
        assert!(old_relay.contains("does not support exec"), "{old_relay}");

        let offline = exec_refused(RefusedUpgrade {
            status: reqwest::StatusCode::NOT_FOUND,
            body: "agent is offline".to_owned(),
        })
        .to_string();
        assert!(offline.ends_with(": agent is offline"), "{offline}");
        assert!(!offline.contains("does not support"), "{offline}");
    }
}
