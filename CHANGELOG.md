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
- `docs/FIELD_TEST.md`: runbook for a first self-hosted deployment across NAT, with recovery drills and their expected results.
- Operator lists on the agent: `agent operator list|add|revoke`. A running agent rereads its list every 2 seconds, closes the open sessions of a revoked operator and reports the list to the relay (`operators_report`), which issues session credentials only to those operators (relay schema v4).
- launchd daemon for macOS agents (`packaging/launchd`, `docs/LAUNCHD.md`): runs the agent as an explicit account, restarts it after a crash but not after a clean stop, and gives it 15 s to stop. CI checks it with launchd on its macOS runners.
- Intel macOS CI (`macos-26-intel`): format, Clippy, tests, release build and the launchd smoke test, as on Apple Silicon.
- Linux aarch64 CI (`ubuntu-24.04-arm`): format, Clippy, tests and release build, as on x86_64.
- `revtty exec NAME -- COMMAND`: runs one command without a terminal over a new `exec_offer` session (`/v1/exec/{name}`, audited as `exec`). Separate stdout and stderr, forwarded stdin (`-n` to close it), the command's exit status, `--timeout` and Ctrl-C; it never asks for a host key. The agent runs the command in its own process group and ends that group when the session ends first; the relay never sees the command.
- `--json` on `list`, `status`, `probe` and `exec`: one line of JSON on stdout, with every field always present. `exec --json` keeps up to 16 MiB of each output stream, as UTF-8 text or base64, and prints it with the exit status or signal, at `--timeout` and Ctrl-C too.
- `agent operator add -` reads the key from stdin, so that an operator can authorize and revoke keys on a target with `revtty exec`; the README describes rotating an operator key that way.
- `revtty init --key PRIVATE_KEY` makes an existing OpenSSH Ed25519 key the operator identity, as a copy written whole and linked into place. It refuses a key protected by a passphrase, another algorithm, a key file other users can read and anything but a regular file, and never replaces an identity already there: importing the same key again changes nothing, another one is refused with both fingerprints.

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
- `doctor` fails when other users can read `pairings`.
- `probe` runs over SSH, as a shell does: the agent checks the operator against its own list and proves its pinned host key, and answers only `revtty-probe`. A probe answered without SSH, as older agents answer it and as a relay could, is refused; an older operator client gets no answer from a newer agent, which ends the session after 45 seconds.
- Relay URLs with a user name or password are refused, without quoting them. reqwest sent them as Basic credentials ahead of revtty's bearer token, so they never authenticated anything, while `agent.toml` kept them. `agent run` stops at start on such a stored URL, and `agent status` shows any stored URL that `agent run` refuses as refused.
- The request errors of operator commands and `agent enroll` show their cause, such as a refused connection or why a redirect was not followed.
- WebSocket errors show their cause, such as the status of a refused upgrade or the TLS or connection failure, instead of only `websocket upgrade failed`, `reqwest error` or `tungstenite error`.
- Operator and agent commands refuse a plain `http://` or `ws://` relay URL unless its host is `localhost`, `127.0.0.0/8` or `[::1]`, and do not follow a relay's redirect to one, since enrollment, control and session credentials would cross the network unencrypted. An agent enrolled with such a URL stops at `agent run`; change `relay` in its `agent.toml` to the `https://` URL.
- `agent run` and `relay serve` log through `tracing`: each line starts with its UTC time, its level and the module, and keeps the message it had. `RUST_LOG` selects what is logged, `info` by default, as a list of levels and `module=level` pairs such as `warn,revtty=debug`; any other value stops the service at start. Requests the relay refuses are never logged, since their text can hold a credential.
- Errors name their kind when revtty knows it, as in `error (DNS): …`: DNS, TLS, connection, timeout, authentication, authorization, host key, offline, protocol or I/O. Exit statuses do not change. A refused WebSocket upgrade, such as that of a session to an offline agent, shows what the relay answered.
- The relay answers 403 instead of 401 to an operator whose signature verifies, for a target that is not enrolled and for one that does not list its key alike, and to a session credential whose operator was revoked, or whose agent was removed or re-enrolled, since it was issued. A database failure while such a credential is checked answers 500 instead of 401.
- The operator commands have no default relay any more: `--relay`, else `REVTTY_RELAY`, else `relay` under `[operator]` in `config.toml` in the config directory; without any of them they fail before sending anything, saying so. The relay commands take `db` and `relay serve` takes `bind` from `[relay]` in the same file, below `--db`, `REVTTY_DB` and `--bind`, with the same defaults as before. Commands that read the file check all of it first, refusing unknown keys, a relative `db` and a file or directory other users could modify, and never quote it in an error. The relay commands look for the file in `REVTTY_CONFIG_DIR`, else in the user's config directory; with neither, as for an account without a home directory, they read none.

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
- Behind a TLS terminator that negotiates HTTP/2, as Caddy does by default, every WebSocket failed while plain requests worked: revtty now speaks HTTP/1.1 to the relay.
- `relay serve` died on SIGINT and SIGTERM, losing queued audit records and leaving its open sessions to be closed at its next start, with that start's time. It now stops accepting connections, finishes the requests in flight, ends its connections, records their sessions as `interrupted` and writes the audit before it exits, within 5 seconds; it exits with an error when it cannot.
- The relay stored, and handed to operators, the comment that came with an agent's host key; it keeps the key material only.
- A refused remote `ws://` relay URL was shown as `http://`.
- `probe` and `connect` could report `establish SSH transport: Disconnected` instead of the relay's reason, such as a busy agent.
- Opening a WebSocket had no time limit: a relay or middlebox that accepted the connection and never answered kept an agent from reconnecting, and a data tunnel kept its session slot. Every handshake now gives up after 10 seconds.
- An agent whose relay accepted the connection and then closed it, for example over an incompatible `Hello` or an operator list it could not store, reconnected about every second: the reconnect wait now restarts only once the relay answers a heartbeat ping.
- An agent SSH session whose operator never authenticated, because it never sent its SSH banner or stopped after the key exchange, kept its capacity slot until it was dropped as idle, up to 2 minutes later. It is now closed 45 s after it started.
- `exec` on a shell session, and `subsystem`, `env` and `x11-req` on any agent session, got no answer, so a client waiting for one hung. The agent now refuses them.
- A session the relay cancelled gave its capacity slot back at once while its SSH session, and the shell in it, kept running. The agent now closes the session's data tunnel and waits up to 5 s for it to end before it frees the slot.
- `agent run` stopped cleanly only on SIGINT: SIGTERM, with which service managers such as launchd stop a service, killed it at once and left its shells running. It now stops on SIGTERM as on SIGINT.
