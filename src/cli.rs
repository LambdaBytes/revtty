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
        /// Else REVTTY_RELAY, else `relay` under [operator] in config.toml.
        #[arg(long, env = "REVTTY_RELAY")]
        relay: Option<String>,

        /// Print the result as one line of JSON (see the README).
        #[arg(long)]
        json: bool,
    },

    /// Show one machine's status.
    Status {
        /// Machine name or stable identifier.
        target: String,

        /// Relay base URL.
        /// Else REVTTY_RELAY, else `relay` under [operator] in config.toml.
        #[arg(long, env = "REVTTY_RELAY")]
        relay: Option<String>,

        /// Agent host key fingerprint (SHA256:...) to pin on first contact, as printed by
        /// `revtty agent status` on the target.
        #[arg(long)]
        host_key: Option<String>,

        /// Print the result as one line of JSON (see the README).
        #[arg(long)]
        json: bool,
    },

    /// Validate reverse connectivity to an online agent.
    Probe {
        /// Machine name.
        target: String,

        /// Relay base URL. http(s) is converted to ws(s).
        /// Else REVTTY_RELAY, else `relay` under [operator] in config.toml.
        #[arg(long, env = "REVTTY_RELAY")]
        relay: Option<String>,

        /// Agent host key fingerprint (SHA256:...) to pin on first contact, as printed by
        /// `revtty agent status` on the target.
        #[arg(long)]
        host_key: Option<String>,

        /// Print the result as one line of JSON (see the README).
        #[arg(long)]
        json: bool,
    },

    /// Open an interactive remote terminal.
    Connect {
        /// Machine name or stable identifier.
        target: String,

        /// Relay base URL. http(s) is converted to ws(s).
        /// Else REVTTY_RELAY, else `relay` under [operator] in config.toml.
        #[arg(long, env = "REVTTY_RELAY")]
        relay: Option<String>,

        /// Agent host key fingerprint (SHA256:...) to pin on first contact, as printed by
        /// `revtty agent status` on the target.
        #[arg(long)]
        host_key: Option<String>,
    },

    /// Run one command on a machine, without a terminal, and exit with its exit status.
    Exec {
        /// Machine name.
        target: String,

        /// Relay base URL. http(s) is converted to ws(s).
        /// Else REVTTY_RELAY, else `relay` under [operator] in config.toml.
        #[arg(long, env = "REVTTY_RELAY")]
        relay: Option<String>,

        /// Agent host key fingerprint (SHA256:...) to pin on first contact, as printed by
        /// `revtty agent status` on the target. exec never asks for it.
        #[arg(long)]
        host_key: Option<String>,

        /// Stop after this many seconds and end the command (exit status 124).
        #[arg(long, value_name = "SECS", value_parser = clap::value_parser!(u64).range(1..))]
        timeout: Option<u64>,

        /// Send no input: the command's stdin is closed at once.
        #[arg(short = 'n')]
        no_stdin: bool,

        /// Keep the command's output and print it, with how the command ended, as one line of
        /// JSON (see the README).
        #[arg(long)]
        json: bool,

        /// The command, after `--`. The target's shell runs its words joined with spaces, as
        /// ssh does.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Run local connectivity and configuration checks.
    Doctor {
        /// Relay base URL.
        /// Else REVTTY_RELAY, else `relay` under [operator] in config.toml.
        #[arg(long, env = "REVTTY_RELAY")]
        relay: Option<String>,
    },

    /// Wrap an enrollment token from `revtty relay enroll` in a pairing code for the target,
    /// so that its host key gets pinned on first contact and the relay cannot pick its
    /// operator. Nothing is sent: the code's secret stays here and on the target.
    Pair {
        /// Machine name the enrollment was created for.
        target: String,

        /// Single-use enrollment token printed by `revtty relay enroll`.
        #[arg(long)]
        token: String,

        /// Relay base URL the target enrolls with and this operator connects through.
        /// Else REVTTY_RELAY, else `relay` under [operator] in config.toml.
        #[arg(long, env = "REVTTY_RELAY")]
        relay: Option<String>,
    },

    /// Forget a machine's pinned host key, after it was reinstalled and re-enrolled; a
    /// pairing pending for it is discarded too.
    Forget {
        /// Machine name.
        target: String,

        /// Relay base URL the key was pinned for.
        /// Else REVTTY_RELAY, else `relay` under [operator] in config.toml.
        #[arg(long, env = "REVTTY_RELAY")]
        relay: Option<String>,
    },

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
        #[arg(
            long,
            required_unless_present = "pairing_code",
            conflicts_with = "pairing_code"
        )]
        token: Option<String>,

        /// Pairing code printed by `revtty pair`: the enrollment token with a secret the relay
        /// never sees, which proves this machine's host key to the operator.
        #[arg(long)]
        pairing_code: Option<String>,

        /// Maximum concurrent probe/shell sessions accepted by this agent.
        #[arg(long, default_value_t = 4)]
        max_sessions: usize,
    },

    /// Run the enrolled long-lived agent using its persisted configuration.
    Run,

    /// Validate the local PTY backend without any remote connection.
    PtyTest,

    /// Show local agent status.
    Status,

    /// Run agent-specific diagnostics.
    Doctor,

    /// Replace the agent's relay credential with a new one; the agent must be stopped.
    RotateCredential,

    /// Manage the operators allowed to open shells on this agent.
    Operator {
        #[command(subcommand)]
        command: OperatorCommand,
    },
}

#[derive(Subcommand)]
pub enum OperatorCommand {
    /// Show the authorized operator keys and the list revision.
    List,

    /// Authorize one more operator public key (OpenSSH Ed25519).
    Add {
        /// Operator public key file, e.g. the id_ed25519.pub printed by `revtty init`, or `-`
        /// to read the key from stdin, as through `revtty exec`.
        key: PathBuf,
    },

    /// Revoke an operator; its open sessions on this agent are closed.
    Revoke {
        /// Fingerprint of the key to revoke (SHA256:...), as `agent operator list` shows it.
        fingerprint: String,
    },
}

#[derive(Subcommand)]
pub enum RelayCommand {
    /// Initialize or migrate the relay SQLite database.
    Init {
        /// Relay SQLite database path.
        /// Else REVTTY_DB, else `db` under [relay] in config.toml, else revtty.db.
        #[arg(long, env = "REVTTY_DB")]
        db: Option<PathBuf>,
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

        /// Re-enroll an agent that is already enrolled, e.g. a reinstalled machine: once
        /// the token is used, the old agent's credential, host key and operators are gone.
        #[arg(long)]
        replace: bool,

        /// Relay SQLite database path.
        /// Else REVTTY_DB, else `db` under [relay] in config.toml, else revtty.db.
        #[arg(long, env = "REVTTY_DB")]
        db: Option<PathBuf>,
    },

    /// Remove an enrolled agent and its unused enrollments; the session audit is kept.
    Remove {
        /// Agent name.
        name: String,

        /// Relay SQLite database path.
        /// Else REVTTY_DB, else `db` under [relay] in config.toml, else revtty.db.
        #[arg(long, env = "REVTTY_DB")]
        db: Option<PathBuf>,
    },

    /// List agents persisted by the relay.
    Agents {
        /// Relay SQLite database path.
        /// Else REVTTY_DB, else `db` under [relay] in config.toml, else revtty.db.
        #[arg(long, env = "REVTTY_DB")]
        db: Option<PathBuf>,
    },

    /// Serve the relay.
    Serve {
        /// Bind address. Keep loopback when terminating TLS with Caddy.
        /// Else `bind` under [relay] in config.toml, else 127.0.0.1:8787.
        #[arg(long)]
        bind: Option<String>,

        /// Relay SQLite database path used by /v1 endpoints.
        /// Else REVTTY_DB, else `db` under [relay] in config.toml, else revtty.db.
        #[arg(long, env = "REVTTY_DB")]
        db: Option<PathBuf>,
    },

    /// Show recent session audit records.
    Sessions {
        /// Maximum number of sessions to show, most recent first.
        #[arg(long, default_value_t = 50)]
        limit: u32,

        /// Relay SQLite database path.
        /// Else REVTTY_DB, else `db` under [relay] in config.toml, else revtty.db.
        #[arg(long, env = "REVTTY_DB")]
        db: Option<PathBuf>,
    },

    /// Run relay-specific diagnostics.
    Doctor {
        /// Relay SQLite database path.
        /// Else REVTTY_DB, else `db` under [relay] in config.toml, else revtty.db.
        #[arg(long, env = "REVTTY_DB")]
        db: Option<PathBuf>,
    },
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
    fn parses_exec_with_its_command_after_the_separator() {
        let args = Args::try_parse_from([
            "revtty",
            "exec",
            "store-042",
            "--timeout",
            "5",
            "-n",
            "--",
            "ls",
            "-l",
            "--all",
        ])
        .expect("parse exec");
        let super::Command::Exec {
            target,
            timeout,
            no_stdin,
            command,
            ..
        } = args.command
        else {
            panic!("parsed as another command");
        };
        assert_eq!(target, "store-042");
        assert_eq!(timeout, Some(5));
        assert!(no_stdin);
        // What follows `--` is the command's, options included.
        assert_eq!(command, ["ls", "-l", "--all"]);

        assert!(Args::try_parse_from(["revtty", "exec", "store-042"]).is_err());
        assert!(Args::try_parse_from(["revtty", "exec", "store-042", "--"]).is_err());
        assert!(
            Args::try_parse_from(["revtty", "exec", "store-042", "--timeout", "0", "--", "ls"])
                .is_err()
        );
    }

    #[test]
    fn parses_doctor() {
        let args = Args::try_parse_from(["revtty", "doctor"]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_relay_doctor() {
        let args = Args::try_parse_from(["revtty", "relay", "doctor"]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_agent_run() {
        let args = Args::try_parse_from(["revtty", "agent", "run"]);
        assert!(args.is_ok());
    }

    #[test]
    fn parses_agent_operator_commands() {
        assert!(Args::try_parse_from(["revtty", "agent", "operator", "list"]).is_ok());
        assert!(Args::try_parse_from(["revtty", "agent", "operator", "add", "op.pub"]).is_ok());
        assert!(
            Args::try_parse_from(["revtty", "agent", "operator", "revoke", "SHA256:abc"]).is_ok()
        );
        assert!(Args::try_parse_from(["revtty", "agent", "operator", "revoke"]).is_err());
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
    fn parses_rotate_credential() {
        assert!(Args::try_parse_from(["revtty", "agent", "rotate-credential"]).is_ok());
    }

    #[test]
    fn parses_lifecycle_commands() {
        assert!(
            Args::try_parse_from([
                "revtty",
                "relay",
                "enroll",
                "store-042",
                "--operator-key",
                "operator.pub",
                "--replace",
            ])
            .is_ok()
        );
        assert!(Args::try_parse_from(["revtty", "relay", "remove", "store-042"]).is_ok());
        assert!(Args::try_parse_from(["revtty", "forget", "store-042"]).is_ok());
        assert!(Args::try_parse_from(["revtty", "forget"]).is_err());
    }

    #[test]
    fn parses_pairing_commands() {
        assert!(
            Args::try_parse_from(["revtty", "pair", "store-042", "--token", "rve_token"]).is_ok()
        );
        assert!(Args::try_parse_from(["revtty", "pair", "store-042"]).is_err());

        let enroll = [
            "revtty",
            "agent",
            "enroll",
            "--relay",
            "https://relay.example.com",
        ];
        let with = |extra: &[&'static str]| {
            Args::try_parse_from(enroll.iter().chain(extra).copied().collect::<Vec<_>>())
        };
        assert!(with(&["--token", "rve_token"]).is_ok());
        assert!(with(&["--pairing-code", "rvp1.code"]).is_ok());
        // Exactly one of them.
        assert!(with(&[]).is_err());
        assert!(with(&["--token", "rve_token", "--pairing-code", "rvp1.code"]).is_err());
    }

    #[test]
    fn parses_relay_sessions() {
        assert!(Args::try_parse_from(["revtty", "relay", "sessions", "--limit", "5"]).is_ok());
    }

    #[test]
    fn parses_relay_serve() {
        assert!(Args::try_parse_from(["revtty", "relay", "serve"]).is_ok());
        // The development-only /v0 token is gone.
        assert!(
            Args::try_parse_from(["revtty", "relay", "serve", "--token", "development-token"])
                .is_err()
        );
    }
}
