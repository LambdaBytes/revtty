# First Reverse Transport Proof

Status: **development proof only — not production security**

This slice validates the highest-risk networking assumption before the project adds SSH, enrollment, SQLite, PTYs, browser access, or file transfer:

> Can a target behind NAT keep only an outbound control connection, receive an on-demand request, open a second outbound connection, rendezvous through the relay, and return data to an operator?

The current proof answers only that question.

## What is implemented

- one Rust binary;
- relay WebSocket endpoints;
- persistent outbound agent control WebSocket;
- heartbeat traffic;
- automatic reconnect after control-channel loss;
- named agent registration in relay memory;
- operator `probe <name>`;
- relay rendezvous;
- temporary second outbound agent WebSocket;
- opaque WebSocket forwarding through the relay;
- bounded relay control queues;
- WebSocket frame/message limits;
- Linux and macOS CI;
- automated end-to-end reverse-rendezvous test;
- local `portable-pty` smoke test on both Linux and macOS;
- Russh handshake and Ed25519 authentication over an arbitrary Tokio duplex stream;
- Russh handshake, pinned host key and Ed25519 operator authentication through the actual WebSocket rendezvous relay.

The probe result contains only:

- agent name;
- OS;
- CPU architecture;
- revtty version.

It does not execute a command supplied by the operator.

## Deliberately not implemented yet

- remote shell;
- **remote** PTY transport;
- persistent on-disk SSH identities and enrollment;
- production Ed25519 identity lifecycle;
- enrollment;
- host-key pinning;
- SQLite;
- session-specific credentials;
- systemd/launchd installation;
- list/status API;
- browser;
- SFTP/exec/forwarding.

The temporary shared development token authenticates the proof endpoints.

**Do not treat this token model as production security.**

## Local validation

Terminal 1:

```bash
export REVTTY_DEV_TOKEN='replace-with-a-long-random-value'
cargo run -- relay serve
```

Terminal 2:

```bash
export REVTTY_DEV_TOKEN='replace-with-a-long-random-value'
cargo run -- agent run --name demo
```

Terminal 3:

```bash
export REVTTY_DEV_TOKEN='replace-with-a-long-random-value'
cargo run -- probe demo
```

Expected shape:

```text
target   demo
status   reachable
os       linux
arch     x86_64
revtty   0.1.0
```

## Local PTY validation

The PTY backend is validated independently from the network path:

```bash
cargo run -- agent pty-test
```

Expected shape:

```text
pty      ok
os       linux
arch     x86_64
```

The smoke test uses a fixed local `/bin/echo` command; it does not accept or execute remote input. The same test runs in Ubuntu and macOS CI.

## Real NAT validation

Run the relay on a public Linux host behind HTTPS/WSS termination.

Caddy concept:

```text
revtty.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

Relay:

```bash
export REVTTY_DEV_TOKEN='a-long-random-development-token'
revtty relay serve
```

Agent on a machine behind NAT/CGNAT:

```bash
export REVTTY_DEV_TOKEN='same-development-token'
revtty agent run \
  --relay https://revtty.example.com \
  --name store-042
```

Operator:

```bash
export REVTTY_DEV_TOKEN='same-development-token'
revtty probe store-042 \
  --relay https://revtty.example.com
```

A successful result proves:

1. outbound persistent agent connectivity;
2. server-side presence/rendezvous;
3. operator-triggered control signaling;
4. a second on-demand outbound connection from the target;
5. bidirectional relay pairing across NAT.

## Validation status

The core architecture is now independently proven in CI on Linux and macOS:

1. outbound agent control connection: validated;
2. operator-triggered second outbound connection: validated;
3. relay rendezvous and bidirectional forwarding: validated;
4. portable PTY backend: validated;
5. SSH over arbitrary non-TCP stream: validated;
6. SSH through the WebSocket relay itself: validated;
7. pinned SSH host key: validated;
8. Ed25519 public-key operator authentication: validated.

The relay test does not open a shell or execute remote commands; it stops after successful SSH authentication.

## Next validation gate

The next meaningful validation is **real NAT/CGNAT**, using the documented `probe` command against a public HTTPS/WSS relay.

After that succeeds, implementation should move from proof credentials to the intended product security/lifecycle:

1. persistent Ed25519 agent host identity;
2. persistent Ed25519 operator identity;
3. enrollment and revocation;
4. session-specific one-time credentials;
5. SQLite durable state;
6. then connect the already validated PTY to authenticated SSH session channels.

This ordering keeps networking, identity, SSH, and PTY failures independently observable.
