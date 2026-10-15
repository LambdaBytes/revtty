# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog principles and the project intends to use Semantic Versioning once public protocol compatibility is defined.

## [Unreleased]

### Added

- Initial Rust project scaffold and terminal-first client/agent/relay command surface.
- Reverse transport proof with an outbound agent control WebSocket, on-demand second connection, relay rendezvous and operator `probe`.
- Linux and macOS CI with format, Clippy, tests and release builds.
- Platform-native state/config paths.
- Persistent Ed25519 operator and agent identities.
- SQLite relay persistence, migrations and single-use enrollment.
- Persistent authenticated agent control sessions with heartbeat/presence updates and bounded exponential reconnect backoff with jitter.
- SSHSIG operator challenge/response authentication and short-lived operator sessions.
- Authenticated operator `list` filtered by the proven SSH-key fingerprint, with single-use inventory challenges.
- Authenticated operator `status` with online/offline, last-seen and version metadata.
- OpenSSH-compatible host-key pinning with hard failure on unexpected key changes.
- Authenticated SSH transport through the WebSocket rendezvous relay.
- Interactive SSH-backed PTY shell with bounded I/O queues and cleanup.
- Live terminal resize propagation to the remote PTY.
- Separate one-time agent data-tunnel credentials; the long-lived agent control credential is rejected on the data path.
- Explicit session accept/reject/cancel lifecycle with separate acceptance and data-tunnel deadlines.
- Configurable per-agent concurrent session limit (default 4, maximum 64), including backward-compatible agent config loading.
- Explicit rejection of incompatible session-offer protocol versions instead of silently ignoring them.
- Live active-session/capacity reporting in operator `list` and `status`.
- Operator-visible pre-SSH rejection/timeout errors without exposing terminal payload to the relay.
- Stronger operator, agent and relay doctor checks for relay reachability, persisted agent configuration and relay SQLite state.
- Linux systemd agent template with an explicit OS account, restart-on-failure, graceful SIGINT shutdown, journald logging and restrictive runtime umask.
- Absolute `REVTTY_CONFIG_DIR` and `REVTTY_STATE_DIR` overrides for service/container deployments.
- Product, security, stack, scope, protocol and roadmap documentation.

- Persistent session audit metadata (operator fingerprint, target, kind, timestamps, outcome) and `relay sessions`.
- Doctor checks: TLS causes for relay failures, signed operator authentication, agent credential validation through a read-only relay endpoint, file and directory permissions, relay schema version.
- `--host-key` for `status`, `probe` and `connect` to approve a first host-key pin non-interactively.
- End-to-end tests that drive the real binary through a PTY.
- Versioned `Cargo.lock`.

### Changed

- The persistent `/v1` path now uses enrolled identities and scoped credentials instead of the development shared token.
- Protocol and prototype documentation now describe the implemented M1 state rather than the original scaffold.
- A first agent host-key pin requires the operator's confirmation; the relay can no longer introduce host keys.
- Operator challenges are stateless HMAC tokens; `list` challenges are bound to an enrollment epoch (relay schema v2).
- The relay registers an agent only after a valid `Hello` and drops agents whose control channel goes silent.
- SSH sessions use explicit keepalives and inactivity bounds on both ends.
- `connect` exits with the remote shell's status, or 255 when the session ended without one.
- revtty creates its configuration and state directories private to the user.

### Removed

- The `/v0` transport-proof endpoints, `relay serve --token` and `REVTTY_DEV_TOKEN`.

### Fixed

- `connect` failed with "Unknown server key" for identities created by `init` and `agent enroll`: key comments were compared together with the key material.
- An agent shell session could hang, keep its capacity slot and ignore disconnects when the remote process stopped reading input.
- Disconnecting injected a newline and EOF into the foreground program; shells ignoring SIGHUP and silent background jobs kept PTYs, threads and processes alive.
- Idle SSH sessions were closed after 10 minutes.
- Agents that vanished without closing their connection stayed online.
- The operator client waited for a key press before exiting after a session.
- Unauthenticated challenge requests could lock every operator out and revealed which agents exist.
- Hashed revtty `known_hosts` entries were skipped, falling back to a first pin.
- Rewriting an existing world-readable `agent.toml` kept its permissions.
- PTY or shell failures left a silent terminal; unknown control messages dropped the agent's connection.
