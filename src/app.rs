use crate::cli::{AgentCommand, Args, Command, RelayCommand};
use crate::error::RevttyError;

pub async fn run(args: Args) -> Result<(), RevttyError> {
    match args.command {
        Command::Init => crate::client::init(),
        Command::List => crate::client::list(),
        Command::Status { target } => crate::client::status(&target),
        Command::Connect { target } => crate::client::connect(&target).await,
        Command::Doctor => crate::client::doctor(),
        Command::Agent { command } => match command {
            AgentCommand::Enroll { relay, token } => crate::agent::enroll(&relay, &token).await,
            AgentCommand::Run => crate::agent::run().await,
            AgentCommand::Status => crate::agent::status(),
            AgentCommand::Doctor => crate::agent::doctor(),
        },
        Command::Relay { command } => match command {
            RelayCommand::Init => crate::relay::init(),
            RelayCommand::Serve => crate::relay::serve().await,
            RelayCommand::Doctor => crate::relay::doctor(),
        },
    }
}
