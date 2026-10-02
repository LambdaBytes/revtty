# revtty Technology Stack

Status: **v1 technology baseline**

Reviewed: 2026-10-03.

This document records the preferred implementation stack and, equally importantly, what revtty should **not** reimplement.

Versions below are the versions reviewed when this document was written. Dependencies should only be added to `Cargo.toml` when the corresponding code is implemented, and final resolved versions belong in a committed `Cargo.lock`.

## Decision rule

Use mature existing implementations for protocols, cryptography, PTYs, storage, HTTP, terminal emulation, and OS integration.

revtty should primarily implement:

- product-specific control-plane state;
- enrollment and authorization policy;
- presence and session lifecycle;
- relay rendezvous;
- small adapters between mature components;
- CLI/web UX.

revtty should not implement its own SSH, TLS, SFTP, terminal emulator, SQLite layer, cryptographic primitives, NAT traversal, or PTY syscalls unless a proven library cannot satisfy a concrete requirement.

## Rust / runtime

### Rust 1.89+ — selected

The current `russh 0.63.3` release declares Rust 1.89 as its MSRV, so revtty's minimum Rust version is 1.89.

### Tokio 1.x — selected

Use Tokio as the async runtime for:

- relay HTTP/WebSocket handling;
- outbound control connections;
- timers/timeouts;
- sockets;
- task coordination;
- SSH integration.

Do not introduce a second async runtime.

## CLI

### clap 4 — selected

Use derive-based clap for the single `revtty` binary and its roles/subcommands.

Later packaging can use:

- `clap_complete` for shell completions;
- `clap_mangen` for the man page.

## SSH

### russh 0.63.x — selected

Use Russh for both client and server SSH roles.

Reasons:

- active Tokio-native implementation;
- client and server support;
- accepts arbitrary `AsyncRead + AsyncWrite` streams via `connect_stream` / `run_stream`;
- public-key authentication;
- PTY/shell/exec channels;
- `direct-tcpip` for local forwarding;
- SFTP ecosystem;
- modern SSH algorithms;
- no need to run or expose OpenSSH `sshd` on the target.

Russh supports broad SSH interoperability, but revtty controls both ends and does not need that full surface.

V1 policy:

- Ed25519 host/operator keys only;
- use the upstream-default `aws-lc-rs` crypto backend;
- do not enable DSA or 3DES;
- do not enable optional SSH compression unless a measured use case appears;
- do not enable RSA support unless a later compatibility requirement justifies it;
- retain Russh's safe default KEX/cipher/MAC ordering and explicitly constrain key algorithms to Ed25519.

When the dependency is introduced, start by validating a narrow feature set equivalent to:

```toml
russh = { version = "0.63", default-features = false, features = ["aws-lc-rs"] }
```

If Russh's feature/API requirements change, preserve the policy rather than blindly preserving that exact Cargo line.

### ssh-key 0.6.x — selected where direct key handling is required

Use the RustCrypto `ssh-key` crate for:

- OpenSSH-compatible private/public key files;
- fingerprints;
- authorized_keys / known_hosts formats;
- Ed25519 key generation;
- SSHSIG signatures.

Prefer the same key formats users already understand from OpenSSH.

### Operator control-plane authentication: SSHSIG — selected design

Do not invent a proprietary signature envelope for operator-to-relay API authentication.

Preferred flow:

1. relay issues a random challenge nonce;
2. operator signs the challenge with its revtty SSH key using the OpenSSH SSHSIG format;
3. use a revtty-specific namespace such as `revtty-control-v1`;
4. relay verifies the registered SSH public key;
5. relay issues a short-lived opaque API session token.

This reuses the same operator identity without storing a permanent API password and avoids custom signing code/protocols.

The agent remains the authority for shell public-key authorization; relay API authentication alone must not grant shell access.

## SFTP / file transfer

### russh-sftp 3.x — selected

Use `russh-sftp` for `revtty cp`.

Required v1 behavior:

- upload;
- download;
- progress;
- cancellation/cleanup.

Do not create a revtty-specific file-transfer protocol.

## SSH forwarding

### Russh direct-tcpip — selected

Use SSH `direct-tcpip` channels for:

```bash
revtty forward target 18080:127.0.0.1:8080
```

No tunnel protocol needs to be designed for this.

Remote forwarding is deferred unless a real requirement appears.

## PTY

### portable-pty 0.9.x — selected

Use `portable-pty` as the agent PTY abstraction.

Reasons:

- part of the WezTerm codebase;
- mature real-world terminal usage;
- one API for Unix PTYs and Windows;
- supports process spawn, PTY resize, reader/writer access;
- Linux and macOS are covered for v1;
- preserves a credible path to Windows/ConPTY in v2 without replacing the abstraction.

`portable-pty` is primarily a synchronous interface. Isolate its blocking reads/writes/process waits behind dedicated tasks/threads and bounded Tokio channels rather than putting blocking I/O on Tokio workers.

### Alternatives reviewed

#### pty-process

Good Tokio-native choice for Unix and supports Linux/macOS well. Rejected as the baseline because it is Unix-focused, which would force a new PTY abstraction for Windows v2.

#### rust-pty

Technically attractive: Tokio-native and already covers Unix + Windows ConPTY. It is being watched, but it is a young 2026 project with much less production adoption than portable-pty. Re-evaluate before Windows implementation; do not base v1 on it yet.

## Local operator terminal

### crossterm 0.29.x — selected

Use for:

- raw mode;
- terminal size;
- resize events;
- portable terminal input/event handling where needed.

Wrap raw mode in an RAII guard so terminal restoration happens on every normal error path; retain a panic safety hook as a final fallback.

## Relay HTTP / WebSocket server

### axum 0.8.x — selected

Use Axum for:

- REST API;
- control WebSocket endpoint;
- data-tunnel WebSocket endpoint;
- web-console backend;
- health endpoint.

Use Axum's WebSocket frame/message size limits explicitly.

### Tower ecosystem — selected

Use Tower-compatible middleware rather than custom HTTP plumbing.

Likely additions when needed:

- `tower-http` for normal HTTP middleware;
- `tower-governor` for rate limiting sensitive endpoints.

Do not add middleware crates before the endpoint requiring them exists.

## Outbound HTTP / WebSocket client

### reqwest 0.13.x — selected

Use one configured Reqwest client for operator/agent HTTP calls.

Reasons:

- mature;
- Rustls TLS by default in the reviewed release;
- platform certificate verification;
- system proxy support;
- timeouts and normal HTTP ergonomics.

System proxy behavior matters for agents deployed on corporate/customer networks.

### reqwest-websocket 0.6.x — selected for outbound WSS

Use its Reqwest upgrade extension for agent/operator WSS connections so WebSockets share the same proxy/TLS/request configuration as HTTP.

This avoids independently recreating HTTP CONNECT/system-proxy behavior.

### tokio-tungstenite 0.30.x — mature fallback, not baseline direct dependency

Tokio Tungstenite is mature and remains the fallback if `reqwest-websocket` exposes a real limitation.

Do not add both direct client stacks without need.

Axum may use Tungstenite internally; that is an implementation detail.

## WebSocket-to-SSH stream bridge

### Small local bounded bridge — selected

Russh operates on an `AsyncRead + AsyncWrite` byte stream while WebSocket is message-oriented.

Use:

```text
WebSocket binary frames
        ↕
bounded bridge tasks
        ↕
tokio::io::DuplexStream
        ↕
russh connect_stream / run_stream
```

This adapter is intentionally small product glue.

Do not introduce a second WebSocket ecosystem or an immature generic stream-wrapper crate only to avoid this bridge.

Rules:

- binary frames only for session bytes;
- bounded buffers;
- backpressure;
- explicit max frame/message sizes;
- deterministic close propagation;
- no text conversion of SSH data.

## Persistence

### SQLite — selected

SQLite is the right v1 datastore for the single-node self-hosted relay.

No PostgreSQL, Redis, or distributed database is required.

### tokio-rusqlite 0.8.x + rusqlite bundled — selected

Use `tokio-rusqlite` to keep SQLite work off Tokio async workers.

Enable the bundled SQLite feature for reproducible Linux/macOS deployments rather than relying on whichever system SQLite happens to be installed.

Recommended database settings:

- WAL journal mode;
- foreign keys enabled;
- a finite busy timeout;
- synchronous=NORMAL unless testing shows a stronger setting is justified.

### rusqlite_migration 2.6.x — selected

Use it for append-only schema migrations.

Do not build a home-grown migration framework.

## Paths and configuration

### directories 6.x — selected

Use `ProjectDirs` for OS-correct operator config/state locations.

Do not hard-code Linux-style `~/.config` paths on macOS or future Windows clients.

System-agent paths remain explicit platform policy:

- Linux: standard system paths under `/etc` and `/var/lib`;
- macOS: standard Application Support/service locations as defined by the installer.

### serde + toml — selected

Use plain Serde data structures + TOML files.

Do not introduce a large layered configuration framework until a real need appears.

Precedence:

```text
defaults < config file < environment (service-only cases) < CLI flags
```

## Random tokens / secret handling

### getrandom 0.4.x — selected for bearer-token entropy

Use the OS CSPRNG directly for fixed-size random tokens.

Example conceptual token material:

- 32 random bytes;
- URL-safe base64 without padding for transport.

Do not use UUIDs as secrets.

### secrecy 0.10.x — selected

Wrap bearer/enrollment/session credentials in secret types so accidental `Debug` and serialization are harder.

### sha2 0.11.x — selected for hashes of random bearer tokens

For 256-bit uniformly random bearer tokens, store SHA-256(token) rather than plaintext.

This rule is specific to high-entropy machine-generated tokens. Human passwords would require a password KDF; v1 should avoid introducing human password storage where possible.

### base64 0.23.x — selected

Use URL-safe no-padding encoding for random bearer tokens.

### UUID v4 — selected for non-secret identifiers

Use UUIDs only for public opaque identifiers such as session/enrollment IDs.

IDs and credentials are deliberately different concepts.

## Structured logging

### tracing + tracing-subscriber — selected

Use structured spans/events and `RUST_LOG`.

Let systemd/journald and macOS service logging collect stdout/stderr rather than implementing a custom log-file subsystem.

Never log:

- terminal payloads;
- private keys;
- bearer tokens;
- enrollment tokens;
- session tunnel tokens;
- Authorization headers;
- transferred file contents.

## Linux service integration

### systemd unit + sd-notify 0.5.x — selected

Use normal systemd units plus the small `sd-notify` crate for readiness/watchdog signaling.

No libsystemd dependency is required.

## macOS service integration

### launchd plist — selected; no Rust wrapper dependency

Use the native launchd service mechanism and ship a plist/template.

Do not add a crate just to wrap `launchctl`.

Keep lifecycle-specific code behind a tiny platform module so Windows Service support can be added in v2.

## TLS certificates

### Caddy — selected for public relay/web TLS in v1

Keep ACME/certificate issuance/renewal outside revtty.

Recommended self-hosted topology:

```text
Internet :443
    ↓
Caddy
    ↓
revtty relay/web on loopback
```

Do not add direct Rust ACME/certificate-management code in v1.

Outbound agent/operator HTTPS/WSS still validates TLS using the selected Reqwest/Rustls platform trust path.

## Browser terminal

### @xterm/xterm 6.x — selected

Use stable xterm.js, not GoTTY.

### @xterm/addon-fit — selected

Use the official fit addon for container/viewport resizing, then send resulting rows/cols to revtty's WebSocket session.

### TypeScript + Vite — selected minimal web stack

Start with a small TypeScript frontend.

Do not introduce React solely to render:

- machine list/search;
- session tabs;
- xterm.js.

A framework can be added later only if the actual web UI grows enough to justify it.

Do not use xterm.js beta/experimental APIs in v1 unless unavoidable.

## Browser authentication / sessions

### tower-sessions 0.15.x — selected

Use Tower/Axum session middleware instead of writing cookie/session machinery.

For v1, in-memory web sessions are acceptable: restarting the web service logs users out.

Permanent operator authorization remains in revtty's own persistence/security model.

### Native web access

Avoid creating a username/password database solely for v1.

A simple self-hosted mode can authenticate a high-entropy revtty web access credential and then establish an HttpOnly/Secure/SameSite server-side session.

OIDC is a future extension if needed.

Requirements:

- HTTPS for non-loopback use;
- HttpOnly Secure cookies;
- Origin checks for WebSocket upgrades;
- CSRF-safe state-changing HTTP endpoints;
- rate-limited login;
- no SSH private keys in browser storage.

## Rate limiting

### tower-governor 0.8.x — selected when endpoints exist

Use for:

- enrollment attempts;
- operator login/auth challenge abuse;
- web login;
- session creation abuse.

Use correct client-address extraction behind the configured reverse proxy; never blindly trust arbitrary forwarded-IP headers.

## SFTP, exec and forwarding reuse

Do not create separate protocols:

- shell → SSH PTY channel;
- `revtty exec` → SSH exec channel;
- `revtty cp` → SFTP subsystem;
- `revtty forward` → SSH direct-tcpip.

All ride the same authenticated revtty session/rendezvous model.

## Release / packaging

Reuse the working philosophy already used by LambdaBytes CLI projects:

- GitHub Actions;
- release-mode native binaries;
- SHA256SUMS;
- `cargo-deb` for Debian/Ubuntu;
- generated completions/man pages;
- macOS tarballs + launchd assets.

Evaluate `cargo-dist` later when the release matrix exists, but do not introduce it until it demonstrably simplifies rather than duplicates the release workflow.

## Dependency/security checks

Before v1 release, add:

- `cargo audit` for RustSec advisories;
- `cargo deny` for license/source/advisory/dependency policy.

Keep dependency features narrow. Do not enable `--all-features` in release artifacts merely for convenience if it activates legacy or unused protocol features.

## Future networking

### MQTT

If added, use a mature MQTT client such as `rumqttc` for control-plane signaling only.

SSH session bytes never travel over MQTT.

### Direct/P2P

If added, evaluate Iroh or another mature maintained NAT-traversal implementation.

Never implement STUN, hole punching, ICE, or a custom relay protocol from scratch.

WSS/TCP relay remains the reliability fallback.

## Packages intentionally not selected

### GoTTY / ttyd on targets

Not needed. The agent already owns the PTY/SSH endpoint. The browser is another operator surface.

### OpenSSH sshd as a dependency

Not required. Russh provides the application-embedded SSH protocol endpoint.

### SQLx / PostgreSQL

Too much machinery for the v1 single-node relay; SQLite is sufficient.

### Redis

No distributed live-state problem exists in v1.

### custom TLS / ACME stack

Caddy already solves it.

### custom terminal emulator

xterm.js already solves it in the browser; the local CLI uses the user's actual terminal.

### custom cryptography

Never.
