# revtty

**Outbound-only remote terminal for machines behind NAT.**

No inbound ports. No VPN. No exposed SSH daemon — just secure, on-demand shell access from anywhere.

> Status: early design / scaffold.

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

## Planned shape

```text
revtty
├── client
├── agent
├── relay
└── web
```

The intended operator experience is:

```bash
revtty list
revtty connect store-042
```

See [docs/BRIEF.md](docs/BRIEF.md) for the architecture, [docs/V1_SCOPE.md](docs/V1_SCOPE.md) for the approved v1 scope, [docs/STACK.md](docs/STACK.md) for the vetted build-vs-reuse technology choices, and [docs/ROADMAP.md](docs/ROADMAP.md) for delivery order and v2.

## Current proof

The first implemented slice validates outbound reverse connectivity without exposing a remote shell yet:

```bash
export REVTTY_DEV_TOKEN='replace-with-a-long-random-value'

# public/local relay
revtty relay serve

# target machine
revtty agent run --name demo

# operator
revtty probe demo
```

CI now validates the reverse rendezvous, portable PTY support on Linux/macOS, and an Ed25519-authenticated SSH handshake carried through the WebSocket relay. The public `probe` command remains the deliberately harmless way to validate the same outbound architecture across a real NAT boundary.

See [docs/PROTOTYPE.md](docs/PROTOTYPE.md) for the exact local and real-NAT validation procedure. The development token is temporary and is **not** the v1 security model.

## Development

The repository currently contains a compileable scaffold only.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo run -- --help
```

## License

MIT.
