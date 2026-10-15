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
- OpenSSH-style agent host-key pinning, with the operator confirming the fingerprint on first contact;
- a separate one-time credential for each agent data tunnel;
- SSH carried end-to-end through an opaque WebSocket relay;
- a real interactive PTY shell;
- terminal input/output, EOF/exit handling and remote exit status capture;
- live terminal resize propagation;
- explicit session accept/reject/cancel lifecycle with independent acceptance/data-tunnel timeouts;
- configurable per-agent concurrent session limits with live capacity shown by `list` / `status`;
- explicit rejection of incompatible session-offer protocol versions;
- operator-visible pre-SSH errors for busy agents and rendezvous timeouts;
- operator, agent and relay doctor checks for configuration, relay reachability (with TLS causes), signed authentication, agent credentials, file permissions and relay schema;
- SSH keepalives and inactivity bounds on both ends: idle sessions stay open, sessions on a dead path end and release their capacity slot;
- relay expiry of silent agent control channels, and agent reconnection when the relay goes silent;
- agent registration only after a valid `Hello`, with an explicit rejection of other protocol versions;
- stateless HMAC operator challenges bound to their scope and expiry; single use is recorded only for enrolled operators, and `list` challenges are bound to the enrollment epoch;
- non-blocking PTY I/O with one supervisor per shell: no input is injected on disconnect, shells are reaped (SIGHUP, then SIGKILL), every PTY descriptor is released, and the agent finishes these teardowns before it exits;
- persistent session audit metadata (`relay sessions`);
- `connect` exits with the remote shell's status, or 255 when none arrived;
- a systemd template that runs the agent as an explicit OS account with restart-on-failure and journald logging;
- Linux and macOS CI for format, Clippy, tests and release builds.

The relay accepts only enrolled identities and scoped credentials: enrollment, agent control, operator session and per-session tunnel credentials.

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
cargo run -- relay serve --db revtty.db
```

On the target machine, consume the enrollment token and start the persistent agent:

```bash
cargo run -- agent enroll \
  --relay http://127.0.0.1:8787 \
  --token <single-use-enrollment-token>

cargo run -- agent run
```

`agent enroll` prints the agent's host key fingerprint (`host`); `agent status` shows it again.

From the operator machine:

```bash
cargo run -- list --relay http://127.0.0.1:8787
cargo run -- status store-042 --relay http://127.0.0.1:8787 \
  --host-key <agent-host-fingerprint>
cargo run -- probe store-042 --relay http://127.0.0.1:8787
cargo run -- connect store-042 --relay http://127.0.0.1:8787
```

The first contact pins the agent's host key, so it needs the fingerprint printed on the target (`--host-key`) or a confirmation at the interactive prompt; the relay cannot introduce a host key on its own.

`list` proves possession of the operator key and returns only machines enrolled for that key. `status` uses target-scoped SSHSIG authentication. `connect` authenticates the operator, verifies the pinned agent host key, opens a one-time rendezvous, starts an interactive SSH PTY and exits with the remote shell's status.

On the relay host, `cargo run -- relay sessions --db revtty.db` lists the audited sessions, and `doctor`, `agent doctor` and `relay doctor` check each role.

See [docs/PROTOTYPE.md](docs/PROTOTYPE.md) for validation details and the remaining real-NAT gate.

## M1 still in progress

The first shell works, but M1 is not complete. Notable remaining work includes:

- real NAT/CGNAT validation of the full authenticated `connect` path;
- recovery validation under real network loss and NAT mapping changes (local tests cover relay restarts and silent peers);
- a macOS CI run on the current tree.

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
