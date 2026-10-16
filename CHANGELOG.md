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
- `agent rotate-credential` replaces the agent's relay credential with one the agent generates, in two steps (`/v1/agent/{name}/rotate` and `/rotate/confirm`, relay schema v6) that an interrupted rotation can finish later; `agent run` refuses to start twice on one configuration.
- `relay enroll --replace` re-enrolls a reinstalled machine in place of the old agent instance, `relay remove` retires an agent, and the relay closes the control connection and every session of an agent instance that is no longer enrolled within 5 seconds (relay schema v5). `forget` clears an operator's pin of the old host key.
- Pairing codes: `revtty pair NAME --token TOKEN` wraps an enrollment token with a secret the relay never receives, for `agent enroll --pairing-code`. The agent refuses an operator or name the code was not made for, and proves its host key, which the operator's first contact pins without confirmation (relay schema v7). A machine enrolled again with a new code replaces its pin.
- Operator lists on the agent: `agent operator list|add|revoke`. A running agent rereads its list every 2 seconds, closes the open sessions of a revoked operator and reports the list to the relay (`operators_report`), which issues session credentials only to those operators (relay schema v4).

### Changed

- The persistent `/v1` path now uses enrolled identities and scoped credentials instead of the development shared token.
- Protocol and prototype documentation now describe the implemented M1 state rather than the original scaffold.
- A first agent host-key pin requires the operator's confirmation; the relay can no longer introduce host keys.
- Operator challenges are stateless HMAC tokens; `list` challenges are bound to an enrollment epoch (relay schema v2).
- The relay registers an agent only after a valid `Hello` and drops agents whose control channel goes silent.
- SSH sessions use explicit keepalives and inactivity bounds on both ends.
- `connect` exits with the remote shell's status, or 255 when the session ended without one.
- revtty creates its configuration and state directories private to the user.
- `agent.toml` holds `operators` and `operators_revision` instead of `operator_key` (older files still load) and is replaced atomically under a lock.
- `relay agents` shows each agent's `operators=` fingerprints; operator session credentials are checked against the agent's current operators when used.
- `relay enroll` refuses a name that is already enrolled unless `--replace` is given.
- `agent enroll` prints the operator's fingerprint and whether a pairing code verified it, and refuses a pairing code given as `--token`. `forget` also discards a pairing pending for the machine.
- Operator and agent commands refuse a plain `http://` or `ws://` relay URL unless its host is `localhost`, `127.0.0.0/8` or `[::1]`, and do not follow a relay's redirect to one, since enrollment, control and session credentials would cross the network unencrypted. An agent enrolled with such a URL stops at `agent run`; change `relay` in its `agent.toml` to the `https://` URL.

### Removed

- The `/v0` transport-proof endpoints, `relay serve --token` and `REVTTY_DEV_TOKEN`.

### Fixed

- Pinning an agent host key wrote the key's comment, which comes from the relay: a comment with a line break added a pin for another machine to `known_hosts`. Only the key material is written now.
- First contact no longer accepts `yes` nor shows the relay-presented fingerprint, in the prompt or in errors, including HOST KEY MISMATCH: the operator gives the fingerprint the target shows. `--host-key` is checked against the presented key even when a pin exists, and the credential renewed after an interactive confirmation must be for the key confirmed.
- A `@revoked` line in `known_hosts` was ignored when a pin for the same machine came first.
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
- `known_hosts` was created with the default mode, so `doctor` failed after the first pin under umask 002; `relay doctor` now only warns about a group-writable database directory.
- `probe` showed a decode error instead of the relay's reason, for example a busy agent.
