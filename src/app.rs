use std::time::Duration;

use crate::cli::{AgentCommand, Args, Command, OperatorCommand, RelayCommand};
use crate::config::Paths;
use crate::error::RevttyError;
use crate::settings::Settings;

/// Runs one command and returns the process exit code.
pub async fn run(args: Args) -> Result<u8, RevttyError> {
    let completed = match args.command {
        // Exits with the remote shell's status, like ssh.
        Command::Connect {
            target,
            relay,
            host_key,
        } => {
            let relay = operator_relay(relay)?;
            return crate::client::connect(&target, &relay, host_key.as_deref()).await;
        }
        // Exits with the remote command's status, like ssh.
        Command::Exec {
            target,
            relay,
            host_key,
            timeout,
            no_stdin,
            json,
            command,
        } => {
            return crate::client::exec(
                &target,
                &operator_relay(relay)?,
                host_key.as_deref(),
                timeout.map(Duration::from_secs),
                !no_stdin,
                &command.join(" "),
                json,
            )
            .await;
        }
        Command::Init { key } => crate::client::init(key.as_deref()),
        Command::List { relay, json } => crate::client::list(&operator_relay(relay)?, json).await,
        Command::Status {
            target,
            relay,
            host_key,
            json,
        } => {
            crate::client::status(&target, &operator_relay(relay)?, host_key.as_deref(), json).await
        }
        Command::Probe {
            target,
            relay,
            host_key,
            json,
        } => {
            crate::client::probe(&target, &operator_relay(relay)?, host_key.as_deref(), json).await
        }
        Command::Doctor { relay } => crate::client::doctor(&operator_relay(relay)?).await,
        Command::Pair {
            target,
            token,
            relay,
        } => crate::client::pair(&target, &token, &operator_relay(relay)?),
        Command::Forget { target, relay } => {
            crate::client::forget(&target, &operator_relay(relay)?)
        }
        Command::Agent { command } => match command {
            AgentCommand::Enroll {
                relay,
                token,
                pairing_code,
                max_sessions,
            } => {
                crate::agent::enroll(
                    &relay,
                    token.as_deref(),
                    pairing_code.as_deref(),
                    max_sessions,
                )
                .await
            }
            AgentCommand::Run => {
                crate::logging::init_service_logging()?;
                crate::agent::run().await
            }
            AgentCommand::PtyTest => crate::agent::pty_test(),
            AgentCommand::Status => crate::agent::status(),
            AgentCommand::Doctor => crate::agent::doctor().await,
            AgentCommand::RotateCredential => crate::agent::rotate_credential().await,
            AgentCommand::Operator { command } => match command {
                OperatorCommand::List => crate::agent::operator_list(),
                OperatorCommand::Add { key } => crate::agent::operator_add(&key),
                OperatorCommand::Revoke { fingerprint } => {
                    crate::agent::operator_revoke(&fingerprint)
                }
            },
        },
        Command::Relay { command } => {
            // Nothing else of the config directory: a relay may run without a home directory.
            let settings = Settings::load(Paths::config_dir_only()?.as_deref())?;
            match command {
                RelayCommand::Init { db } => crate::relay::init(&settings.relay_db(db)).await,
                RelayCommand::Enroll {
                    name,
                    operator_key,
                    ttl,
                    replace,
                    db,
                } => {
                    crate::relay::create_enrollment(
                        &settings.relay_db(db),
                        &name,
                        &operator_key,
                        ttl,
                        replace,
                    )
                    .await
                }
                RelayCommand::Remove { name, db } => {
                    crate::relay::remove_agent(&settings.relay_db(db), &name).await
                }
                RelayCommand::Agents { db } => {
                    crate::relay::list_agents(&settings.relay_db(db)).await
                }
                RelayCommand::Sessions { limit, db } => {
                    crate::relay::list_sessions(&settings.relay_db(db), limit).await
                }
                RelayCommand::Serve { bind, db } => {
                    crate::logging::init_service_logging()?;
                    crate::relay::serve(&settings.relay_bind(bind), &settings.relay_db(db)).await
                }
                RelayCommand::Doctor { db } => crate::relay::doctor(&settings.relay_db(db)).await,
            }
        }
    };

    completed.map(|()| 0)
}

/// The relay an operator command uses, checked with the rest of `config.toml` before anything
/// is sent.
fn operator_relay(given: Option<String>) -> Result<String, RevttyError> {
    Settings::load(Some(&Paths::discover()?.config_dir))?.operator_relay(given)
}
