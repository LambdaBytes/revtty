# Reverse Transport and First Shell Proof

Status: **M1 development implementation — pre-v1.0**

The project started by validating the highest-risk networking assumption:

> Can a target behind NAT keep only an outbound control connection, receive an on-demand request, open a second outbound connection, rendezvous through the relay, and return data to an operator?

That transport proof is now implemented together with the first authenticated SSH/PTTY path. The remaining high-value validation is the same flow across a real NAT/CGNAT boundary and under failure/recovery conditions.

## What is implemented

- one Rust binary with operator, agent and relay roles;
- SQLite relay state and migrations;
- persistent Ed25519 operator identity;
- persistent Ed25519 agent host identity;
- single-use enrollment tokens;
- persistent outbound agent control WebSocket;
- heartbeat/presence persistence;
- automatic reconnect after control-channel loss with bounded exponential backoff, jitter and a 30-second cap;
- SSHSIG operator challenge/response authentication;
- short-lived, single-use operator session credentials;
- agent host-key pinning;
- operator `list` scoped to the authenticated operator key;
- operator `status <name>` with persisted presence metadata;
- operator `probe <name>`;
- operator `connect <name>`;
- on-demand outbound agent data tunnel;
- separate one-time credential for each agent data tunnel;
- opaque WebSocket forwarding through the relay;
- Ed25519 SSH public-key authentication end to end;
- real PTY-backed interactive shell;
- local raw-terminal guard and restoration;
- terminal resize propagation;
- remote EOF/exit handling;
- explicit session accept/reject/cancel control lifecycle;
- persisted per-agent concurrency limit with `busy` rejection;
- live active-session/capacity reporting in operator discovery/status;
- explicit incompatible-offer-version rejection;
- operator/agent relay-reachability diagnostics and relay SQLite diagnostics;
- systemd template service with an explicit OS account, restart-on-failure and journald logging;
- bounded relay/control and PTY I/O queues;
- WebSocket frame/message limits;
- Linux and macOS CI.

The relay does not interpret interactive terminal bytes.

## Current security boundary

The persistent `/v1` path no longer authenticates shells with the shared development token.

The current flow is:

1. an operator owns a persistent Ed25519 key;
2. the relay creates a single-use enrollment token tied to an agent name and operator public key;
3. the agent enrolls its persistent Ed25519 host key and receives a separate long-lived control credential;
4. the operator authenticates to the target using an OpenSSH SSHSIG challenge;
5. the relay returns a short-lived operator session credential and the enrolled host key;
6. the client pins/verifies that host key;
7. each rendezvous creates a new one-time agent tunnel credential;
8. SSH authenticates the operator public key again at the agent and encrypts the terminal payload end to end.

Machine discovery uses a separate one-time SSHSIG challenge. The operator supplies the public key whose possession it proves, and the relay returns only agents whose enrolled operator key has the same SHA-256 SSH fingerprint. The challenge is consumed once, so the signed list request cannot be replayed.

The long-lived agent control credential is explicitly rejected on the `/v1/session` data path, and the per-session agent credential is consumed at most once.

This is still pre-v1 security. Rotation, multi-operator revocation, service hardening, rate limiting and the complete fault/threat-model validation remain release work.

The legacy `/v0` transport-proof endpoints still use `REVTTY_DEV_TOKEN`; `relay serve` currently requires that value while those endpoints remain compiled in.

## Local validation

### 1. Operator identity

```bash
cargo run -- init
```

Keep the printed public-key path for enrollment.

### 2. Relay

```bash
cargo run -- relay init --db revtty.db

cargo run -- relay enroll store-042 \
  --operator-key <operator-public-key> \
  --db revtty.db

export REVTTY_DEV_TOKEN='replace-with-a-long-random-development-token'
cargo run -- relay serve --db revtty.db
```

The enrollment command prints the single-use token that the target consumes.

### 3. Target

```bash
cargo run -- agent enroll \
  --relay http://127.0.0.1:8787 \
  --token <single-use-enrollment-token>

cargo run -- agent run
```

The agent now loads its persisted configuration and identity; `agent run` does not take a machine name on every launch.

### 4. Operator discovery and status

```bash
cargo run -- list --relay http://127.0.0.1:8787
cargo run -- status store-042 --relay http://127.0.0.1:8787
```

`list` returns only machines authorized for the current operator key. `status` reports the persisted identity, online/offline state, last-seen timestamp and agent version.

### 5. Operator probe

```bash
cargo run -- probe store-042 --relay http://127.0.0.1:8787
```

Expected shape:

```text
target   store-042
status   reachable
os       linux
arch     x86_64
revtty   0.1.0
```

### 6. Interactive shell

```bash
cargo run -- connect store-042 --relay http://127.0.0.1:8787
```

The client authenticates with its operator key, verifies the enrolled host key, requests a real PTY and forwards terminal input/output through SSH. Local terminal resizes are propagated to the remote PTY.

## Independent PTY validation

The PTY backend can still be tested without the network path:

```bash
cargo run -- agent pty-test
```

Expected shape:

```text
pty      ok
os       linux
arch     x86_64
```

CI additionally opens an authenticated SSH shell on the real PTY backend and verifies a live resize.

## Real NAT/CGNAT validation

Run the relay on a public Linux host behind HTTPS/WSS termination.

Caddy concept:

```text
revtty.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

Initialize the relay, create an enrollment for the target and start it:

```bash
cargo run -- relay init --db revtty.db

cargo run -- relay enroll store-042 \
  --operator-key <operator-public-key> \
  --db revtty.db

export REVTTY_DEV_TOKEN='a-long-random-development-token'
cargo run -- relay serve --bind 127.0.0.1:8787 --db revtty.db
```

On the target behind NAT/CGNAT:

```bash
cargo run -- agent enroll \
  --relay https://revtty.example.com \
  --token <single-use-enrollment-token>

cargo run -- agent run
```

On the operator machine:

```bash
cargo run -- probe store-042 --relay https://revtty.example.com
cargo run -- connect store-042 --relay https://revtty.example.com
```

A successful interactive `connect` proves the complete first-shell network path across the real boundary:

1. persistent outbound target connectivity;
2. enrolled agent and operator identities;
3. signed operator authorization;
4. operator-triggered control signaling;
5. a second outbound connection from the target;
6. one-time session credential consumption;
7. relay pairing across NAT;
8. host-key verification and SSH public-key authentication;
9. interactive PTY traffic and resize over the tunnel.

## CI validation status

The repository currently validates these pieces on Linux and macOS:

- reverse rendezvous and bidirectional WebSocket forwarding;
- persistent enrollment and agent authentication;
- enrollment replay rejection;
- SSHSIG operator authentication and challenge replay rejection;
- signed operator listing filtered by authorized SSH-key fingerprint with challenge replay rejection;
- authenticated target status and single-use operator session credentials;
- host-key pinning and mismatch rejection;
- rejection of the long-lived control credential on the agent data path;
- single-use agent data-tunnel credentials;
- SSH over an arbitrary byte stream and through the relay;
- Ed25519 SSH operator authentication;
- real PTY-backed interactive shell behavior;
- PTY resize behavior;
- format, Clippy and release compilation.

## Next validation gates

The next gates for M1 are:

1. run the authenticated `connect` path across a real NAT/CGNAT boundary;
2. validate relay restart and network-loss recovery;
3. deepen doctor checks for TLS/authentication/filesystem-permission failures;
4. improve operator-visible rejection/error propagation and session audit metadata.

This keeps transport, identity, SSH, PTY and lifecycle failures independently observable.
