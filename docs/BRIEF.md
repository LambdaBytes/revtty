# revtty — Product & Architecture Brief

## 1. Product statement

**revtty is an outbound-only remote terminal for machines behind NAT.**

The target machine runs a small persistent agent. The agent never needs a public IP, inbound firewall rule, port-forward, VPN, or exposed SSH daemon. An authorized operator selects the machine by a stable human-readable name and opens an interactive terminal on demand.

The intended experience is deliberately simple:

```bash
revtty list
revtty connect store-042
```

The networking, rendezvous, authentication, and session setup should disappear behind those commands.

A useful shorthand is:

> **SSH for machines you can't SSH into.**

## 2. The problem

Remote maintenance is easy when the operator controls both sides of the network. It becomes fragile when the target is an appliance, Raspberry Pi, gateway, home server, customer installation, or remote Linux host behind NAT/CGNAT or a restrictive firewall.

Common workarounds add operational state:

- public SSH ports;
- port forwarding;
- dynamic DNS;
- site-to-site or mesh VPN configuration;
- manually managed reverse tunnels;
- temporary shell-sharing services;
- copied opaque connection addresses;
- custom firewall exceptions.

revtty exists for the narrower case: **a known machine should remain reachable for maintenance through a terminal, even when its network is not under the operator's control.**

## 3. Product boundaries

revtty is a remote-terminal product, not a general remote-management platform.

### In scope

- stable machine identity;
- persistent outbound agent connectivity;
- online/offline presence;
- secure enrollment;
- operator authentication and revocation;
- session rendezvous;
- an interactive SSH-backed PTY;
- reliable reconnect behavior;
- machine listing and status;
- diagnostics;
- minimal session audit metadata;
- self-hosted relay.

### Deliberately out of scope for the first implementation

- VPN or virtual network creation;
- arbitrary asset inventory;
- monitoring dashboards;
- patch management;
- remote desktop;
- endpoint management;
- stealth or hidden persistence;
- custom cryptography;
- a custom terminal protocol;
- NAT traversal written from scratch;
- Kubernetes as a deployment requirement;
- Redis/PostgreSQL/message queues unless scale proves SQLite insufficient.

The project should reject scope that does not directly make a secure remote terminal simpler or more reliable.

## 4. Core principles

1. **Outbound-only target.** The agent never requires an inbound listener reachable from the Internet.
2. **Reuse standards.** SSH handles terminal semantics, authentication, host keys, channels, resize events, signals, and session encryption.
3. **Do not invent cryptography.** Use established SSH/TLS implementations.
4. **Control plane and data plane are separate.** Presence/rendezvous should not be coupled to terminal data.
5. **Relay is a router, not a shell server.** CLI-to-agent terminal traffic remains SSH encrypted end to end.
6. **Boring transport first.** WSS over TCP/443 is preferred initially because reliability through unknown networks matters more than bandwidth or minimum latency.
7. **Linux first.** Prove one platform properly before adding ConPTY/macOS variants.
8. **One Rust package, one binary.** Client, agent, and relay are roles of the same codebase until there is a real reason to split them.
9. **No speculative abstraction.** Add a transport trait only when a second transport exists; extract crates only when reuse actually appears.
10. **Stable contracts before feature growth.** Version control-plane messages explicitly.

## 5. System shape

```text
                         Internet

        operator                              target
     ┌─────────────┐                     ┌──────────────┐
     │ revtty CLI  │                     │ revtty-agent │
     └──────┬──────┘                     └──────┬───────┘
            │                                   │
            │ HTTPS/WSS                         │ outbound WSS
            │                                   │
            ▼                                   ▼
                   ┌──────────────────┐
                   │   revtty-relay   │
                   │                  │
                   │ identity         │
                   │ presence         │
                   │ enrollment       │
                   │ rendezvous       │
                   │ session routing  │
                   └──────────────────┘
```

The relay has two responsibilities:

- a small control plane;
- ephemeral byte forwarding for active sessions.

It should not parse the SSH session carried through the data tunnel.

## 6. Control plane

The agent maintains a long-lived outbound WSS connection to the relay.

Control messages are intentionally small and versioned. The initial vocabulary is:

- `hello`;
- `heartbeat`;
- `session_offer`;
- `session_accept`;
- `session_reject`;
- `session_cancel`.

The control channel carries no interactive terminal stream.

### Presence

The relay needs only enough state to answer:

- is this machine online?
- when was it last seen?
- which agent version is running?
- how many sessions are active?

It should not grow into a hardware/software inventory collector.

### Reconnect

The agent must tolerate:

- relay restart;
- DNS interruption;
- Wi-Fi/Ethernet interruption;
- DHCP renewal;
- NAT mapping expiry;
- target reboot.

Reconnect should use bounded exponential backoff with jitter. A successful connection resets the backoff.

## 7. Data plane

When an operator asks for a session:

1. the CLI asks the relay to create a session;
2. the relay sends a short-lived session offer to the target agent;
3. the agent accepts or rejects it;
4. the CLI and agent each open an authenticated WSS data connection to the relay;
5. the relay pairs the two streams;
6. SSH runs between CLI and agent through that opaque stream;
7. the agent opens a native PTY only after SSH authentication succeeds;
8. the tunnel is destroyed when the session closes.

The data connection exists only while needed.

### Why WSS first

A maintenance terminal uses little bandwidth. Reliability through firewalls and proxies is more valuable than optimizing for peer-to-peer latency. TCP/443 also keeps deployment and troubleshooting understandable.

Future direct transports may be evaluated, but the initial architecture must not depend on them.

## 8. SSH session layer

The terminal session should use an existing Rust SSH implementation such as `russh`.

SSH is responsible for:

- key exchange;
- encryption;
- operator public-key authentication;
- agent host identity;
- PTY requests;
- terminal resize;
- signals;
- exit status;
- channels;
- future forwarding/SFTP capabilities if selected.

revtty should not define a competing shell protocol.

The SSH connection is between the operator-side client and the agent. The relay only sees opaque SSH bytes inside its WSS tunnel.

## 9. Identity model

There are three distinct credentials and they should stay distinct.

### Agent host identity

On first enrollment, the target generates a persistent Ed25519 SSH host key. This identifies the machine cryptographically.

The operator records and pins the host key during trusted enrollment. Later host-key changes are a hard failure until explicitly reconciled.

### Operator identity

An operator uses an Ed25519 SSH key dedicated to revtty by default. Reusing an existing SSH identity may be supported explicitly, but should not be the silent default.

The agent accepts public-key authentication only. Password and keyboard-interactive authentication are not part of the baseline design.

### Agent control credential

Enrollment gives the agent a random high-entropy credential used only to authenticate its control-plane connection to the relay.

This credential does not grant a shell. SSH authorization remains a separate layer.

## 10. Enrollment

Enrollment must be explicit and auditable.

Proposed flow:

```bash
# operator
revtty enroll create store-042

# target
sudo revtty agent enroll \
  --relay https://relay.example.com \
  --token <single-use-token>
```

The enrollment token should be:

- generated from cryptographically secure randomness;
- high entropy;
- short lived;
- single use;
- tied to the intended machine name;
- tied to the initiating operator public key.

The target generates its SSH host key locally and never uploads the private key.

At successful enrollment the relay knows the machine identity, display name, control credential hash, and operator authorization needed to bootstrap the first connection.

## 11. Session credentials

Each requested terminal session gets two different short-lived tunnel credentials:

- one for the operator side;
- one for the agent side.

They should be:

- random;
- single use;
- role specific;
- short lived;
- invalid after pairing or timeout.

Secrets must be sent in authorization headers or equivalent protected fields, never query strings that are likely to be logged.

## 12. Relay storage

The first relay should use SQLite.

Persistent data should remain small and explicit:

### agents

- stable id;
- human-readable name;
- SSH host public key/fingerprint;
- control credential hash;
- creation time;
- last-seen timestamp;
- last reported agent version.

### enrollments

- enrollment token hash;
- intended agent name;
- initial operator public key;
- creation time;
- expiry;
- consumed time.

### sessions

- session id;
- agent id;
- operator id where available;
- requested/start/end times;
- result/status.

Interactive terminal contents, commands, keystrokes, and file contents should not be stored by default.

Live sockets and pending rendezvous belong in memory, not SQLite.

A relay restart may drop active sessions. Agents reconnect automatically. Attempting to persist and reconstruct live SSH sessions is explicitly not a v1 requirement.

## 13. Target runtime

The Linux agent should be installed as an ordinary, visible system service.

Expected files:

```text
/usr/bin/revtty
/etc/revtty/agent.toml
/etc/revtty/authorized_keys
/var/lib/revtty/
```

systemd is responsible for process lifetime:

- start on boot;
- restart on crash;
- watchdog restart if the event loop becomes unhealthy;
- normal logs through journald.

revtty should not implement hidden persistence mechanisms.

The account used for the remote shell is configuration, not magic. Running as root must be an explicit administrator choice.

## 14. Relay deployment

The smallest useful deployment is:

```text
Caddy
  │ HTTPS/WSS :443
  ▼
revtty relay serve
  │
  └── SQLite
```

Caddy handles public TLS certificate acquisition and renewal initially. revtty does not need to implement ACME in v1.

A container deployment may package Caddy + revtty relay, but Docker must not be required for the binary itself.

## 15. CLI surface

The scaffold reserves this small surface:

```text
revtty init
revtty list
revtty status <target>
revtty connect <target>
revtty doctor

revtty agent enroll --relay <url> --token <token>
revtty agent run
revtty agent status
revtty agent doctor

revtty relay init
revtty relay serve
revtty relay doctor
```

Commands should remain scriptable and predictable. A machine-readable output contract can be added where it has real operational value.

No TUI is needed for the first product.

## 16. Technology choices

These are intended implementation choices, not dependencies that must be added before use:

- **Rust / Tokio** — async runtime and one deployable native binary;
- **clap** — CLI;
- **axum** — relay HTTP/WebSocket API;
- **tokio-tungstenite / axum WebSocket support** — WSS session transport as appropriate;
- **russh** — SSH session semantics and cryptography;
- **pty-process or equivalent maintained PTY abstraction** — Linux PTY;
- **SQLite + rusqlite/tokio-rusqlite** — relay persistence;
- **crossterm** — local terminal raw mode/resize;
- **tracing** — structured diagnostics;
- **sd-notify** — systemd readiness/watchdog;
- **Caddy** — public TLS termination.

Every dependency should enter Cargo.toml only when the code actually uses it.

## 17. Clean-code constraints

- `main.rs` parses, configures, dispatches, and exits; no business logic.
- Functions should have one reason to change.
- Protocol DTOs are separate from database rows and runtime connection state.
- No `unwrap()` or `expect()` on production network paths.
- Never hold a lock across `.await`.
- Network queues are bounded.
- Secrets are redacted by construction and never emitted by `Debug`/logs.
- No terminal bytes in normal logs.
- Errors keep useful context at subsystem boundaries.
- Feature work must preserve protocol and security invariants.
- Avoid opportunistic refactors inside fixes.
- Prefer direct concrete code before introducing generic traits.
- Tests should target state transitions and failure modes, not getters.

## 18. Reliability requirements

The product is valuable only if it works during an incident.

Important behaviors:

- graceful shutdown;
- deterministic session cleanup;
- heartbeat timeout;
- stale-agent expiry;
- connection and handshake timeouts;
- bounded reconnect backoff;
- replay-resistant single-use enrollment/session credentials;
- bounded concurrent sessions;
- explicit host-key mismatch errors;
- agent reconnect after relay restart;
- safe terminal restoration on CLI panic/error/interrupt;
- PTY process cleanup on disconnect.

## 19. Testing strategy

### Unit

- control-message round trips;
- token expiry and single-use behavior;
- session state machine;
- host-key verification;
- authorization decisions;
- config parsing.

### Integration

- operator ↔ relay ↔ fake agent session rendezvous;
- agent reconnect after relay restart;
- rejected expired/reused credentials;
- two tunnel sides pair exactly once.

### SSH end-to-end

- valid operator key succeeds;
- invalid operator key fails;
- correct host key succeeds;
- changed host key fails.

### PTY end-to-end

- shell starts;
- stdin/stdout work;
- resize propagates;
- Ctrl-C behaves correctly;
- Ctrl-D/exit closes the session;
- child process is reaped.

## 20. Browser client — future layer

A browser client makes sense after CLI session semantics are stable.

The browser should be another operator surface, not another agent-side service:

```text
xterm.js
   ↕
WebSocket
   ↕
revtty-web
   ↕
normal revtty session
   ↕
relay
   ↕
agent
```

No GoTTY process or extra inbound web server should run on targets.

A web gateway will be a stronger trust boundary than the opaque relay because a conventional server-side SSH client can see terminal plaintext. That distinction must remain explicit.

## 21. Alternative control/data transports — future layer

### MQTT control

MQTT may be useful for appliance fleets that already have broker connectivity. It should replace only the control/wakeup channel, not the SSH terminal protocol.

### Direct/P2P data

If direct paths become valuable, reuse an existing Rust networking layer such as iroh rather than implementing STUN/hole-punching/NAT traversal internally.

WSS relay fallback should remain available for restrictive networks.

## 22. v1 success criterion

v1 is successful when this test is boring and repeatable:

1. install a Linux agent on a machine behind NAT;
2. expose no inbound ports;
3. reboot target and relay independently;
4. observe the agent return online automatically;
5. run `revtty connect <name>` from an authorized operator machine;
6. receive a real interactive PTY;
7. resize, interrupt, exit, and reconnect repeatedly without corruption;
8. reject unauthorized keys and host-key mismatches;
9. diagnose common failures with `revtty doctor`.

Everything else is secondary.
