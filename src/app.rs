use crate::cli::{AgentCommand, Args, Command, RelayCommand};
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
        Command::Init => crate::client::init(),
        Command::List { relay } => crate::client::list(&relay).await,
        Command::Status {
            target,
            relay,
            host_key,
        } => crate::client::status(&target, &relay, host_key.as_deref()).await,
        Command::Probe {
            target,
            relay,
            host_key,
        } => crate::client::probe(&target, &relay, host_key.as_deref()).await,
        Command::Doctor { relay } => crate::client::doctor(&relay).await,
        Command::Agent { command } => match command {
            AgentCommand::Enroll {
                relay,
                token,
                max_sessions,
            } => crate::agent::enroll(&relay, &token, max_sessions).await,
            AgentCommand::Run => crate::agent::run().await,
            AgentCommand::PtyTest => crate::agent::pty_test(),
            AgentCommand::Status => crate::agent::status(),
            AgentCommand::Doctor => crate::agent::doctor().await,
        },
        Command::Relay { command } => match command {
            RelayCommand::Init { db } => crate::relay::init(&db).await,
            RelayCommand::Enroll {
                name,
                operator_key,
                ttl,
                db,
            } => crate::relay::create_enrollment(&db, &name, &operator_key, ttl).await,
            RelayCommand::Agents { db } => crate::relay::list_agents(&db).await,
            RelayCommand::Sessions { limit, db } => crate::relay::list_sessions(&db, limit).await,
            RelayCommand::Serve { bind, db } => crate::relay::serve(&bind, &db).await,
            RelayCommand::Doctor { db } => crate::relay::doctor(&db).await,
        },
    };

    completed.map(|()| 0)
}
