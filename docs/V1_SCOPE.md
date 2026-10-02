# revtty v1.0 Scope

Status: **approved scope**

This document is the source of truth for features required before revtty is called v1.0.

The implementation may be delivered through smaller pre-1.0 milestones, but features listed here belong to the v1 product unless explicitly moved in a later scope decision.

## Product promise

> Secure, on-demand terminal access to known Linux and macOS machines behind NAT, with no inbound ports required on the target.

The primary UX remains:

```bash
revtty list
revtty connect store-042
```

v1 extends that same connection model to non-interactive commands, file transfer, local forwarding, multiple operators, and an optional browser console.

## Platform matrix

### Operator CLI

Required:

- Linux x86_64.
- Linux aarch64.
- macOS Apple Silicon / aarch64.
- macOS Intel / x86_64.

### Agent

Required:

- Linux x86_64.
- Linux aarch64.
- macOS Apple Silicon / aarch64.
- macOS Intel / x86_64.

### Relay

Official v1 deployment target:

- Linux x86_64.
- Linux aarch64 where dependencies permit.

The relay may compile or run on macOS for development, but production support is not a v1 promise.

### Windows

Windows is explicitly reserved for v2.

The v1 architecture must avoid Unix-only protocol assumptions so that a Windows agent can later add ConPTY and Windows Service integration without changing the wire protocol.

## 1. Core CLI

Required operator commands:

```text
revtty init
revtty list
revtty status <target>
revtty connect <target>
revtty exec <target> -- <command...>
revtty cp <source> <destination>
revtty forward <target> <local>:<remote>
revtty doctor
```

Required management surfaces:

```text
revtty operator list <target>
revtty operator add <target> --key <public-key>
revtty operator revoke <target> <fingerprint>

revtty agent enroll --relay <url> --token <token>
revtty agent run
revtty agent status
revtty agent doctor

revtty relay init
revtty relay serve
revtty relay doctor

revtty web serve
```

The exact spelling may evolve before implementation is frozen, but each capability belongs in v1.

## 2. Agent connectivity

- Outbound-only target connectivity.
- No required target-side Internet-facing listener.
- Persistent WSS control channel over TCP/443.
- Heartbeat/presence.
- Online/offline state.
- Last-seen timestamp.
- Agent version reporting.
- Active-session count.
- Automatic reconnect.
- Bounded exponential reconnect backoff with jitter.
- DNS/network interruption recovery.
- Relay restart recovery.
- Graceful shutdown.
- Bounded internal queues and backpressure.

## 3. Platform service lifecycle

### Linux

- systemd service.
- Start on boot.
- Restart on crash.
- Readiness notification where useful.
- Watchdog support.
- journald-compatible logs.
- Secure filesystem permissions for state and credentials.

### macOS

- launchd service definition.
- Persistent start/restart behavior appropriate for a maintenance agent.
- Standard macOS filesystem paths.
- Secure state/key permissions.
- Logging that remains diagnosable with native macOS tooling.
- Install/uninstall documentation or a minimal service-install helper.

The agent runs as one explicit OS account. v1 does not implement a complex PAM/directory-service user mapping layer.

## 4. Enrollment and identities

- Dedicated Ed25519 operator identity by default.
- Ability to explicitly use/import an existing compatible operator key.
- Persistent Ed25519 SSH host identity per agent.
- Separate high-entropy agent-to-relay control credential.
- Single-use enrollment token.
- Enrollment expiry.
- Enrollment replay rejection.
- Agent host-key fingerprint shown clearly.
- Host-key pinning.
- Hard failure on unexpected host-key changes.
- Explicit identity replacement/re-enrollment flow.
- Public-key SSH authentication only.
- No password SSH authentication.
- No anonymous shell mode.
- No secrets in query strings.
- Secret files created with restrictive permissions.
- Secret-bearing types/logs must be redacted by construction.

## 5. Multi-operator access

v1 includes multiple SSH operator identities.

Requirements:

- Agent-side authorized operator allowlist.
- First operator bootstrapped during enrollment.
- List authorized operators.
- Add a public key.
- Revoke a public key.
- Display stable fingerprints.
- Key rotation path.
- Revocation takes effect without reinstalling the agent.

Security invariant:

> The relay alone must not be able to grant a new SSH shell identity.

Operator allowlist changes should therefore require authorization by an already trusted operator or another agent-local administrative action. The relay may transport the management request and store non-authoritative metadata, but it is not the root of SSH authorization.

No enterprise RBAC engine is required in v1.

## 6. Session rendezvous

- Session creation API.
- Versioned control protocol.
- `hello`.
- `heartbeat`.
- `session_offer`.
- `session_accept`.
- `session_reject`.
- `session_cancel`.
- Separate control and data planes.
- Ephemeral WSS data tunnel over TCP/443.
- Separate short-lived operator and agent tunnel credentials.
- Single-use tunnel credentials.
- Session credential expiry.
- Exact one-time pairing of tunnel sides.
- Connection timeout.
- Agent-acceptance timeout.
- SSH-handshake timeout.
- Deterministic cleanup.
- Configurable per-agent concurrency limit.
- Relay restart may terminate active sessions; agents reconnect automatically.

## 7. SSH and interactive terminal

- Real SSH between operator endpoint and agent.
- Mature Rust SSH implementation.
- End-to-end SSH encryption through the relay.
- Relay does not interpret CLI terminal contents.
- Real PTY on Linux.
- Real PTY on macOS.
- One common PTY abstraction at the agent boundary.
- PTY choice must keep a future Windows/ConPTY backend feasible.
- Interactive shell.
- stdin/stdout/stderr semantics appropriate to PTY mode.
- Terminal resize propagation.
- Signal handling.
- Ctrl-C.
- Ctrl-D/EOF.
- Remote exit status.
- Robust disconnect cleanup.
- Guaranteed local terminal restoration after normal exit, error, interrupt, and panic.
- No terminal recording by default.

## 8. Non-interactive command execution

v1 includes:

```bash
revtty exec store-042 -- systemctl status nginx
```

Requirements:

- Reuse SSH exec channels.
- No second command protocol.
- Remote exit status propagated.
- stdout/stderr handling.
- Execution timeout.
- Ctrl-C/cancellation.
- Optional structured JSON result for automation.
- Single-target semantics first; no fleet orchestration requirement.

## 9. File transfer

v1 includes SFTP-backed copy:

```bash
revtty cp ./config.toml store-042:/tmp/config.toml
revtty cp store-042:/var/log/app.log .
```

Requirements:

- Reuse SSH/SFTP.
- Upload.
- Download.
- Progress reporting.
- Safe cancellation/cleanup.
- Predictable overwrite behavior.
- Preserve the target agent's filesystem permissions model.
- No custom file-transfer protocol.

Recursive directory copy is desirable but may be cut if it threatens v1 stability; single-file transfer is mandatory.

## 10. Local port forwarding

v1 includes local SSH forwarding:

```bash
revtty forward store-042 18080:127.0.0.1:8080
```

Requirements:

- Reuse SSH `direct-tcpip`.
- Bind local listener to loopback by default.
- Explicit flag required for non-loopback bind.
- Clear connection lifecycle and Ctrl-C cleanup.
- Forwarding metadata may be audited.
- No VPN.
- No exit-node behavior.
- Remote forwarding is not required for v1.

## 11. Browser console

v1 includes an optional browser operator surface.

Architecture:

```text
browser
   |
 xterm.js
   |
 HTTPS/WSS
   |
revtty web
   |
 normal revtty SSH session
   |
relay
   |
agent
```

Requirements:

- `revtty web serve`.
- Browser machine list.
- Search/filter.
- Online/offline/last-seen display.
- Connect action.
- xterm.js terminal.
- Resize propagation.
- Session close/status.
- Multiple terminal tabs if implementation remains simple.
- Usable layout on desktop and tablet/mobile for emergency access.
- Target agent remains unchanged.
- No GoTTY/ttyd service installed on targets.
- No operator SSH private keys stored in browser localStorage or IndexedDB.

### Web authentication in v1

The web console must never be unauthenticated when exposed remotely.

Minimum supported self-hosted model:

- high-entropy operator/web access credentials;
- only hashed verifier material stored server-side where practical;
- HTTPS required for remote use;
- secure HttpOnly session cookies after login;
- SameSite protections;
- CSRF-safe state-changing endpoints;
- login/session rate limiting.

OIDC is desirable but remains v2 unless it can be added without delaying or complicating the core v1 security model.

### Web trust boundary

The simple v1 web architecture terminates the operator-side SSH session in `revtty web`.

Therefore the web component can see terminal plaintext and is a trusted endpoint, unlike the opaque relay.

This distinction must be documented prominently.

## 12. Relay persistence and runtime

SQLite is the v1 persistent store.

Required persistent domains:

- agents;
- enrollments;
- session metadata;
- web/operator metadata required by the selected authentication model.

Live sockets and pending rendezvous remain in memory.

No Redis/PostgreSQL/distributed coordination in v1.

Required relay properties:

- HTTP API.
- WSS agent-control endpoint.
- WSS session-tunnel endpoint.
- Health endpoint.
- Graceful shutdown.
- Bounded memory.
- Rate limiting on sensitive endpoints.
- Stale-agent handling.
- Schema migrations.
- Caddy-compatible deployment.
- No active-session reconstruction after restart.

## 13. Configuration

- Predictable per-platform config/state paths.
- TOML config.
- CLI flags override config.
- Environment overrides where useful for service/container deployment.
- Strict validation before network activity.
- Explicit relay URL.
- Explicit service/shell account behavior.
- Safe timeout bounds.
- No hidden magic config.

## 14. Diagnostics

### Operator

- local config.
- operator identity.
- DNS.
- relay HTTPS.
- authentication.
- protocol/API compatibility.

### Agent

- config.
- host identity.
- control credential.
- filesystem permissions.
- DNS.
- relay reachability.
- TLS.
- WSS/control authentication.
- service integration hints for current OS.

### Relay

- storage.
- migrations.
- state directory.
- bind config.
- public/base URL sanity.
- protocol version.

Errors should distinguish DNS, TLS, authentication, authorization, host-key mismatch, offline agent, timeout, and protocol mismatch.

## 15. Security

- Threat model documented.
- SSH public-key auth only.
- End-to-end SSH for CLI/exec/SFTP/forwarding sessions.
- OS CSPRNG for bearer credentials.
- Short-lived scoped session tokens.
- Replay protection.
- Rate limiting.
- Explicit concurrency limits.
- Secret redaction.
- No secret URLs.
- Dependency advisory checks in release process.
- No custom cryptographic primitives.
- No stealth/covert persistence.
- Private vulnerability reporting before public release.

## 16. Logging and audit metadata

Use structured tracing.

Never log:

- private keys;
- bearer/enrollment/session tokens;
- Authorization headers;
- terminal bytes;
- keystrokes;
- transferred file contents.

v1 session metadata may include:

- operator identity/fingerprint;
- target;
- requested/start/end times;
- session type: shell / exec / sftp / forward / web;
- outcome.

Command contents are not required to be recorded.

## 17. Packaging

### Linux

- x86_64 release binary.
- aarch64 release binary.
- tar.gz artifacts.
- Debian/Ubuntu package.
- systemd unit.
- SHA256SUMS.

### macOS

- Apple Silicon release binary.
- Intel release binary.
- tar.gz artifacts.
- launchd plist/service assets.
- installation and service setup documentation.

Homebrew is useful but not required to declare v1 complete.

### Common

- shell completions.
- man page.
- changelog.
- SemVer.
- upgrade/compatibility documentation.

## 18. CI and testing

CI must run:

- `cargo fmt --check`;
- `cargo clippy --all-targets --all-features -- -D warnings`;
- `cargo test`;
- release build.

Before v1.0, CI/release validation must include both Linux and macOS where platform-specific behavior exists.

Required tests include:

- protocol round trips;
- malformed/incompatible messages;
- enrollment expiry/replay;
- session token expiry/replay;
- authorization changes;
- host-key verification;
- agent presence;
- session rendezvous;
- SSH authentication;
- unauthorized operator rejection;
- Linux PTY E2E;
- macOS PTY E2E;
- resize;
- Ctrl-C;
- EOF/exit;
- `exec` exit/output behavior;
- SFTP upload/download;
- local forwarding;
- relay restart -> agent reconnect;
- agent restart -> reconnect;
- network loss/recovery;
- slow consumer/backpressure;
- long-idle control connection;
- repeated connect/disconnect soak test.

## 19. Explicitly deferred to v2

- Windows agent/client support.
- Windows Service integration.
- ConPTY backend.
- MQTT control backend.
- Direct/P2P transport.
- QUIC path optimization.
- Iroh or equivalent NAT-traversal integration.
- Remote SSH forwarding.
- OIDC if not completed cleanly in v1.
- Enterprise RBAC.
- SSH certificate authority model.
- Hardware-backed key integration.
- Relay clustering/multi-region.
- Redis/PostgreSQL/distributed presence.
- Session recording.
- Remote desktop.
- VPN/exit-node behavior.

## 20. V1 implementation milestones

The scope should be delivered incrementally.

### M0 — Scaffold

- repository structure;
- CI;
- docs;
- protocol version placeholder;
- command surface.

### M1 — First Shell / Linux

- relay;
- enrollment;
- WSS control channel;
- presence;
- rendezvous;
- SSH;
- Linux PTY;
- systemd;
- `list/status/connect`;
- reconnect;
- doctor basics.

### M2 — macOS parity

- macOS client;
- macOS agent;
- PTY parity;
- launchd;
- path/config parity;
- Apple Silicon + Intel artifacts;
- macOS E2E tests.

### M3 — Access management and automation

- multiple operators;
- add/revoke;
- credential rotation;
- `exec`;
- JSON automation output.

### M4 — SSH capabilities

- SFTP/`cp`;
- local port forwarding.

### M5 — Web console

- `revtty web serve`;
- web authentication;
- agent list/search;
- xterm.js terminal;
- browser session lifecycle;
- documented trust boundary.

### M6 — Release hardening

- fault/soak tests;
- packaging;
- protocol compatibility promise;
- security review;
- installation/deployment docs;
- v1.0 release criteria.

## 21. V1 exit criterion

v1.0 is ready when:

1. Linux and macOS targets can be installed as persistent outbound-only agents.
2. Agents recover after reboot, network loss, and relay restart.
3. Authorized Linux/macOS operators can list and connect to them by stable name.
4. Interactive PTY behavior is reliable on both target OSes.
5. Unauthorized keys and changed host keys are rejected.
6. Multiple operators can be added and revoked without reinstalling targets.
7. `exec`, single-file SFTP copy, and local forwarding use the same SSH security model.
8. The optional authenticated browser console can open a usable terminal without target-side web services.
9. Relay operation remains simple: one process, SQLite, and ordinary HTTPS/WSS termination.
10. Core security, E2E, recovery, and soak tests are green.
