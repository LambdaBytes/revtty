use std::time::Duration;

use crate::cli::{AgentCommand, Args, Command, OperatorCommand, RelayCommand};
use crate::error::RevttyError;

/// Runs one command and returns the process exit code.
pub async fn run(args: Args) -> Result<u8, RevttyError> {
    let completed = match args.command {
        // Exits with the remote shell's status, like ssh.
        Command::Connect {
            target,
            relay,
            host_key,
        } => return crate::client::connect(&target, &relay, host_key.as_deref()).await,
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
                &relay,
                host_key.as_deref(),
                timeout.map(Duration::from_secs),
                !no_stdin,
                &command.join(" "),
                json,
            )
            .await;
        }
        Command::Init => crate::client::init(),
        Command::List { relay, json } => crate::client::list(&relay, json).await,
        Command::Status {
            target,
            relay,
            host_key,
            json,
        } => crate::client::status(&target, &relay, host_key.as_deref(), json).await,
        Command::Probe {
            target,
            relay,
            host_key,
            json,
        } => crate::client::probe(&target, &relay, host_key.as_deref(), json).await,
        Command::Doctor { relay } => crate::client::doctor(&relay).await,
        Command::Pair {
            target,
            token,
            relay,
        } => crate::client::pair(&target, &token, &relay),
        Command::Forget { target, relay } => crate::client::forget(&target, &relay),
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
            AgentCommand::Run => crate::agent::run().await,
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
        Command::Relay { command } => match command {
            RelayCommand::Init { db } => crate::relay::init(&db).await,
            RelayCommand::Enroll {
                name,
                operator_key,
                ttl,
                replace,
                db,
            } => crate::relay::create_enrollment(&db, &name, &operator_key, ttl, replace).await,
            RelayCommand::Remove { name, db } => crate::relay::remove_agent(&db, &name).await,
            RelayCommand::Agents { db } => crate::relay::list_agents(&db).await,
            RelayCommand::Sessions { limit, db } => crate::relay::list_sessions(&db, limit).await,
            RelayCommand::Serve { bind, db } => crate::relay::serve(&bind, &db).await,
            RelayCommand::Doctor { db } => crate::relay::doctor(&db).await,
        },
    };

    completed.map(|()| 0)
}
