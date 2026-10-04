use crate::cli::{AgentCommand, Args, Command, RelayCommand};
use crate::error::RevttyError;

pub async fn run(args: Args) -> Result<(), RevttyError> {
    match args.command {
        Command::Init => crate::client::init(),
        Command::List { relay } => crate::client::list(&relay).await,
        Command::Status { target, relay } => crate::client::status(&target, &relay).await,
        Command::Probe { target, relay } => crate::client::probe(&target, &relay).await,
        Command::Connect { target, relay } => crate::client::connect(&target, &relay).await,
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
            RelayCommand::Serve { bind, token, db } => crate::relay::serve(&bind, token, &db).await,
            RelayCommand::Doctor { db } => crate::relay::doctor(&db).await,
        },
    }
}
