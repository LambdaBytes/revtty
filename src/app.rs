use crate::cli::{AgentCommand, Args, Command, RelayCommand};
use crate::error::RevttyError;

pub async fn run(args: Args) -> Result<(), RevttyError> {
    match args.command {
        Command::Init => crate::client::init(),
        Command::List => crate::client::list(),
        Command::Status { target } => crate::client::status(&target),
        Command::Probe {
            target,
            relay,
            token,
        } => crate::client::probe(&target, &relay, &token).await,
        Command::Connect { target } => crate::client::connect(&target).await,
        Command::Doctor => crate::client::doctor(),
        Command::Agent { command } => match command {
            AgentCommand::Enroll { relay, token } => crate::agent::enroll(&relay, &token).await,
            AgentCommand::Run => crate::agent::run().await,
            AgentCommand::PtyTest => crate::agent::pty_test(),
            AgentCommand::Status => crate::agent::status(),
            AgentCommand::Doctor => crate::agent::doctor(),
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
            RelayCommand::Doctor => crate::relay::doctor(),
        },
    }
}
