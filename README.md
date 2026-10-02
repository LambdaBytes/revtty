# revtty

**Outbound-only remote terminal for machines behind NAT.**

No inbound ports. No VPN. No exposed SSH daemon — just secure, on-demand shell access from anywhere.

> Status: early design / scaffold.

## Goal

`revtty` is a small, terminal-first remote maintenance tool. A persistent agent on the target machine keeps an outbound control connection to a relay. When an authorized operator requests a session, the agent opens an ephemeral outbound data tunnel and serves a real SSH-backed PTY through it.

The first milestone is intentionally narrow: **reliable shell access to a Linux machine behind NAT with zero inbound ports.**

## Design principles

- Outbound-only agent.
- SSH for session semantics and cryptography; do not invent a terminal protocol.
- Relay routes sessions; it should not interpret terminal contents.
- Linux-first.
- One Rust binary with client, agent, and relay roles.
- Small control plane: identity, presence, enrollment, authorization, rendezvous, lifecycle.
- Boring transport first: HTTPS/WSS on TCP/443.
- SQLite for relay persistence.
- systemd for long-running agent lifecycle.
- Stable, versioned protocol contracts before feature growth.
- No speculative abstraction: extract interfaces only when a second implementation exists.

## Planned shape

```text
revtty
├── client
├── agent
└── relay
```

The intended operator experience is:

```bash
revtty list
revtty connect store-042
```

See [docs/BRIEF.md](docs/BRIEF.md) for the product and architecture brief, and [docs/ROADMAP.md](docs/ROADMAP.md) for candidate v1/v2 scope.

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
