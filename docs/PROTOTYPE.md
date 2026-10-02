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
- Linux and macOS CI.

The probe result contains only:

- agent name;
- OS;
- CPU architecture;
- revtty version.

It does not execute a command supplied by the operator.

## Deliberately not implemented yet

- remote shell;
- PTY transport;
- SSH;
- Ed25519 identity;
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

## Next validation gate

After this proof works over a real NAT boundary:

1. validate `portable-pty` locally on Linux and macOS;
2. put Russh over the paired byte stream;
3. add Ed25519 agent and operator identities;
4. replace the shared development token with the intended enrollment/authentication model;
5. only then add durable state and convenience features.

This keeps transport, PTY, and SSH failures independently observable.
