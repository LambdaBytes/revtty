use std::path::PathBuf;

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

    /// List enrolled machines authorized for this operator.
    List {
        /// Relay base URL.
        #[arg(long, default_value = "ws://127.0.0.1:8787", env = "REVTTY_RELAY")]
        relay: String,
    },

    /// Show one machine's status.
    Status {
        /// Machine name or stable identifier.
        target: String,

        /// Relay base URL.
        #[arg(long, default_value = "ws://127.0.0.1:8787", env = "REVTTY_RELAY")]
        relay: String,
    },

    /// Validate reverse connectivity to an online agent.
    Probe {
        /// Machine name.
        target: String,

        /// Relay base URL. http(s) is converted to ws(s).
        #[arg(long, default_value = "ws://127.0.0.1:8787", env = "REVTTY_RELAY")]
        relay: String,
    },

    /// Open an interactive remote terminal.
    Connect {
        /// Machine name or stable identifier.
        target: String,

        /// Relay base URL. http(s) is converted to ws(s).
        #[arg(long, default_value = "ws://127.0.0.1:8787", env = "REVTTY_RELAY")]
        relay: String,
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

    /// Run the enrolled long-lived agent using its persisted configuration.
    Run,

    /// Validate the local PTY backend without any remote connection.
    PtyTest,

    /// Show local agent status.
    Status,

    /// Run agent-specific diagnostics.
    Doctor,
}

#[derive(Subcommand)]
pub enum RelayCommand {
    /// Initialize or migrate the relay SQLite database.
    Init {
        /// Relay SQLite database path.
        #[arg(long, default_value = "revtty.db", env = "REVTTY_DB")]
        db: PathBuf,
    },

    /// Create a single-use enrollment token from the relay host.
    Enroll {
        /// Stable agent name reserved by this enrollment.
        name: String,

        /// Operator Ed25519 public key file authorized on the new agent.
        #[arg(long)]
        operator_key: PathBuf,

        /// Enrollment lifetime in seconds.
        #[arg(long, default_value_t = 600)]
        ttl: u64,

        /// Relay SQLite database path.
        #[arg(long, default_value = "revtty.db", env = "REVTTY_DB")]
        db: PathBuf,
    },

    /// List agents persisted by the relay.
    Agents {
        /// Relay SQLite database path.
        #[arg(long, default_value = "revtty.db", env = "REVTTY_DB")]
        db: PathBuf,
    },

    /// Serve the relay.
    Serve {
        /// Bind address. Keep loopback when terminating TLS with Caddy.
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,

        /// Development-only shared token for the /v0 transport proof.
        #[arg(long, env = "REVTTY_DEV_TOKEN")]
        token: String,

        /// Relay SQLite database path used by /v1 endpoints.
        #[arg(long, default_value = "revtty.db", env = "REVTTY_DB")]
        db: PathBuf,
    },

    /// Run relay-specific diagnostics.
    Doctor,
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser;

    #[test]
    fn parses_list() {
        let args = Args::try_parse_from(["revtty", "list"]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_probe_target() {
        let args = Args::try_parse_from(["revtty", "probe", "store-042"]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_status_target() {
        let args = Args::try_parse_from(["revtty", "status", "store-042"]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_connect_target() {
        let args = Args::try_parse_from(["revtty", "connect", "store-042"]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_agent_run() {
        let args = Args::try_parse_from(["revtty", "agent", "run"]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_relay_enroll() {
        let args = Args::try_parse_from([
            "revtty",
            "relay",
            "enroll",
            "store-042",
            "--operator-key",
            "operator.pub",
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
