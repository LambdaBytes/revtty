use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest_websocket::Message;

use crate::error::RevttyError;
use crate::protocol::{CONTROL_PROTOCOL_VERSION, ControlMessage, ProbeResult};
use crate::transport::{connect_websocket, valid_name};

pub async fn enroll(_relay: &str, _token: &str) -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("agent enrollment"))
}

pub async fn run(relay: &str, name: &str, token: &str) -> Result<(), RevttyError> {
    if !valid_name(name) {
        return Err(RevttyError::message(
            "agent names may contain only letters, digits, '.', '_' and '-'",
        ));
    }

    let client = reqwest::Client::new();

    loop {
        let control = run_control_once(&client, relay, name, token);

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

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
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
) -> Result<(), RevttyError> {
    let path = format!("/v0/agent/{name}");
    let websocket = connect_websocket(client, relay, &path, token).await?;
    let (mut sender, mut receiver) = websocket.split();

    send_control(
        &mut sender,
        ControlMessage::Hello {
            version: CONTROL_PROTOCOL_VERSION,
            name: name.to_owned(),
        },
    )
    .await?;

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

                        if let ControlMessage::ProbeOffer {
                            version,
                            session_id,
                        } = control
                        {
                            if version != CONTROL_PROTOCOL_VERSION {
                                continue;
                            }

                            let client = client.clone();
                            let relay = relay.to_owned();
                            let token = token.to_owned();
                            let name = name.to_owned();

                            tokio::spawn(async move {
                                if let Err(error) =
                                    send_probe(&client, &relay, &token, &session_id, &name).await
                                {
                                    eprintln!("probe {session_id} failed: {error}");
                                }
                            });
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
    token: &str,
    session_id: &str,
    name: &str,
) -> Result<(), RevttyError> {
    let path = format!("/v0/session/{session_id}");
    let mut websocket = connect_websocket(client, relay, &path, token).await?;

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
        .close()
        .await
        .map_err(|error| RevttyError::runtime("close probe session", error))
}

pub fn status() -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("agent status"))
}

pub fn doctor() -> Result<(), RevttyError> {
    println!("agent transport proof: available");
    println!(
        "control protocol v{}",
        crate::protocol::CONTROL_PROTOCOL_VERSION
    );
    Ok(())
}
