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
            AgentCommand::Run { relay, name, token } => {
                crate::agent::run(&relay, &name, &token).await
            }
            AgentCommand::Status => crate::agent::status(),
            AgentCommand::Doctor => crate::agent::doctor(),
        },
        Command::Relay { command } => match command {
            RelayCommand::Init => crate::relay::init(),
            RelayCommand::Serve { bind, token } => crate::relay::serve(&bind, token).await,
            RelayCommand::Doctor => crate::relay::doctor(),
        },
    }
}
