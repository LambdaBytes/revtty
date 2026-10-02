use futures_util::StreamExt;
use reqwest_websocket::Message;

use crate::config::Paths;
use crate::error::RevttyError;
use crate::protocol::ProbeResult;
use crate::transport::{connect_websocket, valid_name};

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

pub async fn probe(target: &str, relay: &str, token: &str) -> Result<(), RevttyError> {
    if !valid_name(target) {
        return Err(RevttyError::message(
            "target names may contain only letters, digits, '.', '_' and '-'",
        ));
    }

    let client = reqwest::Client::new();
    let path = format!("/v0/probe/{target}");
    let mut websocket = connect_websocket(&client, relay, &path, token).await?;

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
