# revtty

**Outbound-only remote terminal for machines behind NAT.**

No inbound ports. No VPN. No exposed SSH daemon — just secure, on-demand shell access from anywhere.

> Status: early implementation — M1 “First Shell” is in progress.

## Goal

`revtty` is a small, terminal-first remote maintenance tool. A persistent agent on the target machine keeps an outbound control connection to a relay. When an authorized operator requests a session, the agent opens an ephemeral outbound data tunnel and serves a real SSH-backed PTY through it.

The first milestone is intentionally narrow: **reliable shell access to Linux and macOS machines behind NAT with zero inbound ports.**

## Design principles

- Outbound-only agent.
- SSH for session semantics and cryptography; do not invent a terminal protocol.
- Relay routes sessions; it should not interpret terminal contents.
- Linux and macOS in v1; Windows is planned for v2.
- One Rust binary with client, agent, relay, and optional web-console roles.
- Small control plane: identity, presence, enrollment, authorization, rendezvous, lifecycle.
- Boring transport first: HTTPS/WSS on TCP/443.
- SQLite for relay persistence.
- Native service lifecycle: systemd on Linux and launchd on macOS.
- Stable, versioned protocol contracts before feature growth.
- No speculative abstraction: extract interfaces only when a second implementation exists.

See [docs/BRIEF.md](docs/BRIEF.md) for the architecture, [docs/V1_SCOPE.md](docs/V1_SCOPE.md) for the approved v1 scope, [docs/STACK.md](docs/STACK.md) for the vetted build-vs-reuse technology choices, [docs/ROADMAP.md](docs/ROADMAP.md) for delivery order and v2, and [docs/SYSTEMD.md](docs/SYSTEMD.md) for Linux agent service setup.

## Current implementation

The repository has moved beyond the scaffold. The authenticated M1 path now includes:

- persistent Ed25519 operator identity via `revtty init`;
- persistent Ed25519 agent host identity;
- SQLite relay state and single-use enrollment tokens;
- an authenticated persistent outbound agent control WebSocket with heartbeat and bounded exponential reconnect backoff with jitter;
- SSHSIG operator challenge/response authentication;
- signed operator `list` scoped to machines authorized for that operator key;
- authenticated operator `status` with online/offline, last-seen and version metadata;
- short-lived, single-use operator session credentials;
- OpenSSH-style agent host-key pinning;
- a separate one-time credential for each agent data tunnel;
- SSH carried end-to-end through an opaque WebSocket relay;
- a real interactive PTY shell;
- terminal input/output, EOF/exit handling and remote exit status capture;
- live terminal resize propagation;
- explicit session accept/reject/cancel lifecycle with independent acceptance/data-tunnel timeouts;
- configurable per-agent concurrent session limits with live capacity shown by `list` / `status`;
- explicit rejection of incompatible session-offer protocol versions;
- operator-visible pre-SSH errors for busy agents and rendezvous timeouts;
- operator, agent and relay doctor checks for identity/configuration, relay reachability and relay storage;
- a systemd template that runs the agent as an explicit OS account with restart-on-failure and journald logging;
- Linux and macOS CI for format, Clippy, tests and release builds.

The relay still carries the legacy `/v0` transport-proof endpoints. `REVTTY_DEV_TOKEN` is currently required by `relay serve` for those endpoints; the persistent `/v1` path uses enrollment, agent, operator and per-session credentials instead.

## Authenticated local flow

Initialize the operator identity:

```bash
cargo run -- init
```

Initialize relay storage and create a single-use enrollment token. Use the public-key path printed by `revtty init`:

```bash
cargo run -- relay init --db revtty.db
cargo run -- relay enroll store-042 \
  --operator-key <operator-public-key> \
  --db revtty.db
```

Start the relay:

```bash
export REVTTY_DEV_TOKEN='replace-with-a-long-random-development-token'
cargo run -- relay serve --db revtty.db
```

On the target machine, consume the enrollment token and start the persistent agent:

```bash
cargo run -- agent enroll \
  --relay http://127.0.0.1:8787 \
  --token <single-use-enrollment-token>

cargo run -- agent run
```

From the operator machine:

```bash
cargo run -- list --relay http://127.0.0.1:8787
cargo run -- status store-042 --relay http://127.0.0.1:8787
cargo run -- probe store-042 --relay http://127.0.0.1:8787
cargo run -- connect store-042 --relay http://127.0.0.1:8787
```

`list` proves possession of the operator key and returns only machines enrolled for that key. `status` uses target-scoped SSHSIG authentication. `connect` authenticates the operator, verifies the pinned agent host key, opens a one-time rendezvous and starts an interactive SSH PTY.

See [docs/PROTOTYPE.md](docs/PROTOTYPE.md) for validation details and the remaining real-NAT gate.

## M1 still in progress

The first shell works, but M1 is not complete. Notable remaining work includes:

- deeper doctor coverage for TLS/authentication/filesystem-permission failures;
- persistent session audit metadata;
- real NAT/CGNAT validation of the full authenticated `connect` path;
- recovery/fault tests around relay restart and network loss.

Later v1 milestones add macOS service parity, multi-operator management, `exec`, SFTP/copy, local forwarding and the optional web console.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release
```

## License

MIT.
