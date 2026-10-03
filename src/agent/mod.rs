mod config;
mod ssh;

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

use futures_util::{SinkExt, StreamExt};
use reqwest_websocket::Message;
use ssh_key::{Algorithm, PublicKey};

use self::config::AgentConfig;
use crate::config::Paths;
use crate::identity::ensure_agent;

use crate::error::RevttyError;
use crate::protocol::{
    CONTROL_PROTOCOL_VERSION, ControlMessage, EnrollRequest, EnrollResponse, ProbeResult,
};
use crate::transport::{connect_websocket, http_url, valid_name};

const RECONNECT_BASE_MILLIS: u64 = 1_000;
const RECONNECT_CAP_MILLIS: u64 = 30_000;
const RECONNECT_JITTER_PERCENT: u64 = 20;

#[derive(Debug, Default)]
struct ReconnectBackoff {
    failures: u32,
}

impl ReconnectBackoff {
    fn reset(&mut self) {
        self.failures = 0;
    }

    fn next_delay(&mut self) -> Duration {
        let failures = self.failures;
        self.failures = self.failures.saturating_add(1);

        Duration::from_millis(reconnect_delay_millis(failures, jitter_sample(failures)))
    }
}

fn reconnect_base_millis(failures: u32) -> u64 {
    let multiplier = 1_u64 << failures.min(31);
    RECONNECT_BASE_MILLIS
        .saturating_mul(multiplier)
        .min(RECONNECT_CAP_MILLIS)
}

fn reconnect_delay_millis(failures: u32, sample: u64) -> u64 {
    let base = reconnect_base_millis(failures);
    let spread = base.saturating_mul(RECONNECT_JITTER_PERCENT) / 100;
    let floor = base.saturating_sub(spread);

    floor + sample % (spread + 1)
}

fn jitter_sample(failures: u32) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut value = (now as u64)
        ^ ((now >> 64) as u64)
        ^ (u64::from(std::process::id()) << 32)
        ^ u64::from(failures);

    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value
}

pub async fn enroll(relay: &str, token: &str) -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let identity = ensure_agent(&paths)?;
    let url = http_url(relay, "/v1/enroll")?;
    let request = EnrollRequest {
        token: token.to_owned(),
        host_key: identity.public_key.clone(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };

    let response = reqwest::Client::new()
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|error| RevttyError::runtime("send enrollment request", error))?;

    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        return Err(RevttyError::message(format!(
            "enrollment rejected ({status}){}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }

    let enrolled: EnrollResponse = response
        .json()
        .await
        .map_err(|error| RevttyError::runtime("decode enrollment response", error))?;

    if !valid_name(&enrolled.name) {
        return Err(RevttyError::message(
            "relay returned an invalid enrolled agent name",
        ));
    }

    let operator_key = PublicKey::from_openssh(&enrolled.operator_key)
        .map_err(|error| RevttyError::runtime("parse enrolled operator key", error))?;
    if operator_key.algorithm() != Algorithm::Ed25519 {
        return Err(RevttyError::message("v1 requires an Ed25519 operator key"));
    }

    AgentConfig {
        relay: relay.trim_end_matches('/').to_owned(),
        agent_id: enrolled.agent_id,
        name: enrolled.name.clone(),
        control_token: enrolled.control_token,
        operator_key: enrolled.operator_key,
    }
    .save(&paths)?;

    println!("agent      {}", enrolled.name);
    println!("host       {}", identity.fingerprint);
    println!(
        "identity   {}",
        if identity.created {
            "created"
        } else {
            "existing"
        }
    );
    println!("config     {}", AgentConfig::path(&paths).display());
    Ok(())
}

pub async fn run() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let config = AgentConfig::load(&paths)?;

    if !valid_name(&config.name) {
        return Err(RevttyError::message(
            "stored agent name is invalid; re-enroll this agent",
        ));
    }

    let client = reqwest::Client::new();
    let mut backoff = ReconnectBackoff::default();

    loop {
        let control = run_control_once(
            &client,
            &config.relay,
            &config.name,
            &config.control_token,
            &config.operator_key,
            &mut backoff,
        );

        tokio::select! {
            result = control => {
                if let Err(error) = result {
                    eprintln!("control connection lost: {error}");
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| RevttyError::runtime("wait for Ctrl-C", error))?;
                return Ok(());
            }
        }

        let delay = backoff.next_delay();
        eprintln!("reconnecting in {:.1}s", delay.as_secs_f64());

        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| RevttyError::runtime("wait for Ctrl-C", error))?;
                return Ok(());
            }
        }
    }
}

async fn run_control_once(
    client: &reqwest::Client,
    relay: &str,
    name: &str,
    token: &str,
    operator_key: &str,
    backoff: &mut ReconnectBackoff,
) -> Result<(), RevttyError> {
    let path = format!("/v1/agent/{name}");
    let websocket = connect_websocket(client, relay, &path, token).await?;
    let (mut sender, mut receiver) = websocket.split();

    send_control(
        &mut sender,
        ControlMessage::Hello {
            version: CONTROL_PROTOCOL_VERSION,
            name: name.to_owned(),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        },
    )
    .await?;

    backoff.reset();
    eprintln!("agent {name} connected to {relay}");

    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    heartbeat.tick().await;

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                send_control(
                    &mut sender,
                    ControlMessage::Heartbeat {
                        version: CONTROL_PROTOCOL_VERSION,
                    },
                )
                .await?;
            }
            message = receiver.next() => {
                match message {
                    Some(Ok(Message::Text(text))) => {
                        let control: ControlMessage = serde_json::from_str(&text)
                            .map_err(|error| RevttyError::runtime("decode control message", error))?;

                        match control {
                            ControlMessage::ProbeOffer {
                                version,
                                session_id,
                                tunnel_token,
                            } if version == CONTROL_PROTOCOL_VERSION => {
                                let client = client.clone();
                                let relay = relay.to_owned();
                                let name = name.to_owned();

                                tokio::spawn(async move {
                                    if let Err(error) = send_probe(
                                        &client,
                                        &relay,
                                        &tunnel_token,
                                        &session_id,
                                        &name,
                                    )
                                    .await
                                    {
                                        eprintln!("probe {session_id} failed: {error}");
                                    }
                                });
                            }
                            ControlMessage::ShellOffer {
                                version,
                                session_id,
                                tunnel_token,
                            } if version == CONTROL_PROTOCOL_VERSION => {
                                let client = client.clone();
                                let relay = relay.to_owned();
                                let operator_key = operator_key.to_owned();

                                tokio::spawn(async move {
                                    if let Err(error) = ssh::serve(
                                        &client,
                                        &relay,
                                        &tunnel_token,
                                        &session_id,
                                        &operator_key,
                                    )
                                    .await
                                    {
                                        eprintln!("shell {session_id} failed: {error}");
                                    }
                                });
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        sender
                            .send(Message::Pong(data))
                            .await
                            .map_err(|error| RevttyError::runtime("send control pong", error))?;
                    }
                    Some(Ok(Message::Close { .. })) | None => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        return Err(RevttyError::runtime("receive control message", error));
                    }
                }
            }
        }
    }
}

async fn send_control(
    sender: &mut futures_util::stream::SplitSink<
        reqwest_websocket::WebSocket,
        reqwest_websocket::Message,
    >,
    message: ControlMessage,
) -> Result<(), RevttyError> {
    let text = serde_json::to_string(&message)
        .map_err(|error| RevttyError::runtime("encode control message", error))?;

    sender
        .send(Message::Text(text))
        .await
        .map_err(|error| RevttyError::runtime("send control message", error))
}

async fn send_probe(
    client: &reqwest::Client,
    relay: &str,
    tunnel_token: &str,
    session_id: &str,
    name: &str,
) -> Result<(), RevttyError> {
    let path = format!("/v1/session/{session_id}");
    let mut websocket = connect_websocket(client, relay, &path, tunnel_token).await?;

    let result = ProbeResult {
        name: name.to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };

    let text = serde_json::to_string(&result)
        .map_err(|error| RevttyError::runtime("encode probe result", error))?;

    websocket
        .send(Message::Text(text))
        .await
        .map_err(|error| RevttyError::runtime("send probe result", error))?;

    websocket
        .close(reqwest_websocket::CloseCode::Normal, None)
        .await
        .map_err(|error| RevttyError::runtime("close probe session", error))
}

pub fn pty_test() -> Result<(), RevttyError> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| RevttyError::runtime("open local PTY", error))?;

    let mut command = CommandBuilder::new("/bin/echo");
    command.arg("revtty-pty-ok");

    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| RevttyError::runtime("spawn PTY smoke command", error))?;
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| RevttyError::runtime("clone PTY reader", error))?;

    let reader_thread = std::thread::spawn(move || -> std::io::Result<String> {
        let mut output = String::new();
        reader.read_to_string(&mut output)?;
        Ok(output)
    });

    let writer = pair
        .master
        .take_writer()
        .map_err(|error| RevttyError::runtime("take PTY writer", error))?;

    if cfg!(target_os = "macos") {
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(writer);

    let status = child
        .wait()
        .map_err(|error| RevttyError::runtime("wait for PTY smoke command", error))?;
    drop(pair.master);

    let output = reader_thread
        .join()
        .map_err(|_| RevttyError::message("PTY reader thread panicked"))?
        .map_err(|error| RevttyError::runtime("read PTY output", error))?;

    if !status.success() || !output.contains("revtty-pty-ok") {
        return Err(RevttyError::message("local PTY smoke test failed"));
    }

    println!("pty      ok");
    println!("os       {}", std::env::consts::OS);
    println!("arch     {}", std::env::consts::ARCH);
    Ok(())
}

pub fn status() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let config = AgentConfig::load(&paths)?;
    let identity = ensure_agent(&paths)?;

    println!("agent      {}", config.name);
    println!("relay      {}", config.relay);
    println!("id         {}", config.agent_id);
    println!("host       {}", identity.fingerprint);
    println!("config     {}", AgentConfig::path(&paths).display());
    Ok(())
}

pub fn doctor() -> Result<(), RevttyError> {
    let paths = Paths::discover()?;
    let config = AgentConfig::load(&paths)?;
    let identity = ensure_agent(&paths)?;

    println!("agent      configured");
    println!("name       {}", config.name);
    println!("host key   {}", identity.fingerprint);
    println!("protocol   v{}", crate::protocol::CONTROL_PROTOCOL_VERSION);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        RECONNECT_JITTER_PERCENT, ReconnectBackoff, pty_test, reconnect_base_millis,
        reconnect_delay_millis,
    };

    #[test]
    fn reconnect_backoff_grows_and_caps() {
        let expected = [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000];

        for (failures, expected_millis) in expected.into_iter().enumerate() {
            assert_eq!(
                reconnect_base_millis(failures as u32),
                expected_millis,
                "unexpected delay at failure {failures}"
            );
        }
    }

    #[test]
    fn reconnect_jitter_stays_bounded() {
        for failures in 0..10 {
            let base = reconnect_base_millis(failures);
            let spread = base * RECONNECT_JITTER_PERCENT / 100;
            let floor = base - spread;

            assert_eq!(reconnect_delay_millis(failures, 0), floor);

            let high = reconnect_delay_millis(failures, u64::MAX);
            assert!(high >= floor);
            assert!(high <= base);
        }
    }

    #[test]
    fn reconnect_backoff_reset_restarts_sequence() {
        let mut backoff = ReconnectBackoff::default();
        let first = backoff.next_delay();
        let second = backoff.next_delay();

        assert!(first <= std::time::Duration::from_secs(1));
        assert!(second >= std::time::Duration::from_millis(1_600));

        backoff.reset();
        let reset = backoff.next_delay();
        assert!(reset <= std::time::Duration::from_secs(1));
    }

    #[test]
    fn portable_pty_smoke_test() {
        pty_test().expect("portable PTY smoke test");
    }
}
