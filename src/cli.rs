use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "revtty", version, about)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
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

    /// Validate reverse connectivity to an online agent.
    Probe {
        /// Machine name.
        target: String,

        /// Relay base URL. http(s) is converted to ws(s).
        #[arg(long, default_value = "ws://127.0.0.1:8787", env = "REVTTY_RELAY")]
        relay: String,

        /// Development-only shared token for the transport proof.
        #[arg(long, env = "REVTTY_DEV_TOKEN")]
        token: String,
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

#[derive(Subcommand)]
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

    /// Run the long-lived transport-proof agent.
    Run {
        /// Relay base URL. http(s) is converted to ws(s).
        #[arg(long, default_value = "ws://127.0.0.1:8787", env = "REVTTY_RELAY")]
        relay: String,

        /// Stable development machine name.
        #[arg(long)]
        name: String,

        /// Development-only shared token for the transport proof.
        #[arg(long, env = "REVTTY_DEV_TOKEN")]
        token: String,
    },

    /// Validate the local PTY backend without any remote connection.
    PtyTest,

    /// Show local agent status.
    Status,

    /// Run agent-specific diagnostics.
    Doctor,
}

#[derive(Subcommand)]
pub enum RelayCommand {
    /// Initialize relay state.
    Init,

    /// Serve the transport-proof relay.
    Serve {
        /// Bind address. Keep loopback when terminating TLS with Caddy.
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,

        /// Development-only shared token for the transport proof.
        #[arg(long, env = "REVTTY_DEV_TOKEN")]
        token: String,
    },

    /// Run relay-specific diagnostics.
    Doctor,
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser;

    #[test]
    fn parses_probe_target() {
        let args = Args::try_parse_from([
            "revtty",
            "probe",
            "store-042",
            "--token",
            "development-token",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_agent_run() {
        let args = Args::try_parse_from([
            "revtty",
            "agent",
            "run",
            "--name",
            "store-042",
            "--token",
            "development-token",
        ]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_relay_serve() {
        let args =
            Args::try_parse_from(["revtty", "relay", "serve", "--token", "development-token"]);
        assert!(args.is_ok());
    }
}
