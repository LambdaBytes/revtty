use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "revtty", version, about)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize local operator state.
    Init,

    /// List enrolled machines.
    List,

    /// Show one machine's status.
    Status {
        /// Machine name or stable identifier.
        target: String,
    },

    /// Open an interactive remote terminal.
    Connect {
        /// Machine name or stable identifier.
        target: String,
    },

    /// Run local connectivity and configuration checks.
    Doctor,

    /// Manage or run the persistent target agent.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },

    /// Manage or run the public rendezvous relay.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Enroll this machine with a relay.
    Enroll {
        /// Relay base URL.
        #[arg(long)]
        relay: String,

        /// Single-use enrollment token.
        #[arg(long)]
        token: String,
    },

    /// Run the long-lived agent process.
    Run,

    /// Show local agent status.
    Status,

    /// Run agent-specific diagnostics.
    Doctor,
}

#[derive(Debug, Subcommand)]
pub enum RelayCommand {
    /// Initialize relay state.
    Init,

    /// Serve the relay API and WebSocket endpoints.
    Serve,

    /// Run relay-specific diagnostics.
    Doctor,
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser;

    #[test]
    fn parses_connect_target() {
        let args = Args::try_parse_from(["revtty", "connect", "store-042"]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_agent_enroll() {
        let args = Args::try_parse_from([
            "revtty",
            "agent",
            "enroll",
            "--relay",
            "https://relay.example.com",
            "--token",
            "token",
        ]);
        assert!(args.is_ok());
    }
}
