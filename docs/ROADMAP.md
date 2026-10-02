# revtty — Candidate v1 / v2 Scope

This is a **decision document**, not a promise. Items are grouped so the v1 boundary can be chosen deliberately before implementation expands.

The product invariant is unchanged:

> Secure remote terminal access to known machines behind NAT, with no inbound ports on the target.

---

## v1 candidates

### Product core

- One Rust repository and one `revtty` binary.
- Linux-first target support.
- Linux x86_64 release artifact.
- Linux aarch64 release artifact.
- Human-readable stable machine names.
- `revtty init`.
- `revtty list`.
- `revtty status <target>`.
- `revtty connect <target>`.
- `revtty doctor`.
- `revtty agent enroll`.
- `revtty agent run`.
- `revtty agent status`.
- `revtty agent doctor`.
- `revtty relay init`.
- `revtty relay serve`.
- `revtty relay doctor`.

### Agent lifecycle

- Persistent outbound control connection only.
- WSS over TCP/443 as the initial control transport.
- No required inbound listener.
- Heartbeats.
- Online/offline state.
- Last-seen timestamp.
- Agent version reporting.
- Automatic reconnect.
- Bounded exponential reconnect backoff with jitter.
- Graceful shutdown.
- systemd service.
- Start on boot.
- Restart on crash.
- systemd readiness notification.
- systemd watchdog support.
- journald-compatible logging.
- Explicit configurable shell account.
- Clean child/PTY teardown after disconnect.

### Enrollment and identities

- Single-use enrollment tokens.
- Enrollment token expiration.
- Cryptographically random enrollment tokens.
- Persistent Ed25519 agent SSH host key.
- Dedicated Ed25519 operator identity by default.
- Option to import/use a chosen existing operator key if explicitly requested.
- SSH public-key authentication only.
- No password authentication.
- Agent host-key pinning.
- Hard failure on host-key mismatch.
- First operator authorization installed during enrollment.
- Agent control-plane credential distinct from SSH credentials.
- Store only hashes of high-entropy relay bearer credentials where practical.
- Secret files created with restrictive permissions.
- No credentials in URL query strings.
- No secrets in normal logs/debug representations.

### Session lifecycle

- Session creation API.
- Versioned control protocol.
- `hello`.
- `heartbeat`.
- `session_offer`.
- `session_accept`.
- `session_reject`.
- `session_cancel`.
- Separate ephemeral data tunnel from persistent control channel.
- WSS data tunnel over TCP/443.
- Different one-time credentials for operator and agent tunnel sides.
- Short session-token TTL.
- One-time session-token use.
- Pair each tunnel side exactly once.
- Connection timeout.
- Agent acceptance timeout.
- Idle/handshake timeout.
- Explicit session state machine.
- Deterministic cleanup on failure.
- Configurable maximum concurrent sessions per agent.
- Relay restart may terminate active sessions; agents reconnect automatically.

### Terminal / SSH

- Real SSH session between operator and agent.
- Existing Rust SSH implementation; no custom shell crypto/protocol.
- End-to-end SSH encryption through the relay.
- Relay does not interpret terminal content.
- Native Linux PTY.
- Interactive shell request.
- stdin.
- stdout/stderr.
- terminal resize propagation.
- signal handling needed for normal interactive use.
- exit status.
- Ctrl-C behavior.
- Ctrl-D/normal shell exit.
- Local terminal raw-mode lifecycle.
- Guaranteed local terminal restoration on normal exit, errors, Ctrl-C, and panic.

### Relay

- Small HTTP/WebSocket service.
- Agent registry.
- In-memory live connection registry.
- In-memory pending-session rendezvous.
- SQLite persistent state.
- Agents table.
- Enrollments table.
- Session metadata table.
- Store start/end/result metadata, not terminal contents.
- Health endpoint.
- Graceful shutdown.
- Basic rate limiting on enrollment/session creation/auth failures.
- Bounded memory/queue usage.
- Stale-agent expiry.
- Caddy-compatible reverse-proxy deployment.
- Caddy as recommended initial TLS/ACME termination.
- No Redis/Postgres requirement.
- No session reconstruction after relay restart.

### Operator / authorization management

- List authorized operator keys for an agent or fleet scope.
- Add an operator public key.
- Revoke an operator public key.
- Rotate the local operator identity.
- Rotate/reissue an agent control credential.
- Clear, explicit fingerprint display.
- No implicit trust of changed host keys.

### Configuration

- Predictable config paths.
- TOML configuration.
- Environment overrides only where useful for service deployment.
- CLI flags override config values.
- Secure defaults.
- Config validation before opening network connections.
- Explicit relay URL.
- Explicit run-as shell user.
- Timeouts configurable within safe bounds.

### Diagnostics

- Operator doctor: config, identity, DNS, relay reachability, API compatibility.
- Agent doctor: config, host key, credential presence, DNS, relay reachability, WSS auth.
- Relay doctor: storage, bind address, schema state, runtime config.
- Useful error messages for DNS/TLS/auth/host-key/session-timeout failures.
- Structured debug logging via `RUST_LOG`.
- Never log terminal content or bearer secrets.

### Protocol and compatibility

- Control protocol version starts at v1.
- Document message schemas and invariants.
- Unknown message handling is explicit.
- Reject incompatible major/control protocol versions cleanly.
- Stable machine/session identifiers.
- Contract tests for serialization.
- Migration strategy for SQLite schema from the first persistent release.

### Testing

- Unit tests for protocol round trips.
- Unit tests for token expiry/reuse.
- Unit tests for session state transitions.
- Unit tests for config validation.
- Unit tests for host-key checks.
- Integration test for agent registration/presence.
- Integration test for session rendezvous.
- Integration test for relay restart → agent reconnect.
- E2E SSH authentication tests.
- E2E Linux PTY test.
- Resize test.
- Ctrl-C test.
- Exit/cleanup test.
- Unauthorized operator test.
- Changed host-key rejection test.
- Expired enrollment token test.
- Reused enrollment token test.
- Reused session token test.
- Concurrency-limit test.

### Packaging / release

- `cargo fmt --check`.
- `cargo clippy --all-targets --all-features -- -D warnings`.
- `cargo test`.
- GitHub Actions CI.
- Release profile with LTO/strip.
- Linux tar.gz binaries.
- Debian/Ubuntu `.deb`.
- systemd unit packaged with `.deb`.
- SHA256SUMS.
- README quick start.
- `docs/BRIEF.md`.
- protocol documentation.
- security/threat-model documentation.
- CHANGELOG.
- MIT license.
- SemVer.
- Define a compatibility promise before calling the protocol 1.0 stable.

### Optional v1 candidates — choose deliberately

These fit the product but are not required to prove First Shell:

- `revtty exec <target> -- <command>` for non-interactive commands.
- `--json` output for `list`, `status`, and `doctor`.
- Agent rename.
- Tags/groups for machine selection.
- Multiple simultaneously authorized operators.
- Local machine alias support.
- Shell selection.
- Per-agent session concurrency policy.
- Operator/session audit query command.
- Docker image for relay.
- Minimal docker-compose example with Caddy + relay.
- IPv6-aware diagnostics.
- Shell completion and man page generation.

---

## v2 candidates

### Web console

- Optional `revtty web serve` role.
- Browser machine list.
- Search/filter machines.
- Online/offline/last-seen display.
- Browser connect action.
- xterm.js terminal.
- Terminal resize.
- Multiple browser terminal tabs.
- Mobile-friendly emergency terminal.
- Web session close/status UX.
- Web authentication.
- OIDC support for external identity providers.
- Optional TOTP/local-login mode for small self-hosted deployments.
- Explicitly document that the web gateway can see terminal plaintext unless a later browser-E2E design is implemented.
- Keep the target agent unchanged; no GoTTY/ttyd process on targets.

### Richer operator authorization

- Named operators rather than raw key-only management.
- Fleet/group-scoped authorization.
- Per-agent authorization.
- Read-only metadata roles separate from shell permission.
- Time-limited operator grants.
- Approval-required sessions as an optional policy.
- API tokens for automation.
- Operator activity/audit views.

### Remote command mode

- `revtty exec <target> -- <command>` if not selected for v1.
- Structured exit code.
- stdout/stderr separation.
- Non-interactive timeout.
- Machine-readable JSON result.
- Multi-target exec considered only after single-target semantics are stable.

### Files

- SFTP using the existing SSH session layer.
- `revtty cp`.
- Upload.
- Download.
- Directory transfer if underlying implementation supports it safely.
- Transfer cancellation.
- Transfer progress.
- Explicit path/permission handling.

### Port forwarding

- SSH local forwarding.
- Remote forwarding only if the threat model remains clear.
- `revtty forward <target> <local>:<remote>`.
- Strong defaults that bind local forwards to loopback.
- Clear audit metadata for forwards.
- No general VPN behavior.

### MQTT control backend

- MQTT as an alternative control/wakeup plane.
- TLS-authenticated MQTT.
- Per-agent topics.
- Signed/authenticated session requests.
- Replay protection.
- WSS data tunnel remains available.
- Do not carry interactive terminal bytes over MQTT.
- Useful for fleets already connected to an MQTT broker.

### Additional target platforms

- macOS agent.
- launchd service packaging.
- Windows agent.
- Windows Service packaging.
- ConPTY terminal backend.
- Cross-platform config/state path handling.
- Cross-platform E2E tests.

### Direct data paths

- Evaluate iroh or another maintained Rust NAT-traversal layer.
- Direct QUIC path when peers can establish it.
- Relay fallback when direct path fails.
- Never implement STUN/hole punching from scratch.
- Preserve the same session/auth model regardless of transport.
- WSS/TCP fallback for UDP-blocked networks.
- Transport diagnostics showing direct vs relayed path.

### Fleet usability

- Tags/groups if not selected for v1.
- Saved filters.
- Agent version visibility.
- Controlled agent credential rotation at fleet scale.
- Controlled agent upgrade mechanism only if it can remain simple and explicit.
- Bulk status queries.
- Fleet-level doctor/compatibility report.

### Session usability

- Reconnect/resume semantics evaluated carefully; do not pretend a dead SSH session survived.
- Optional tmux/screen integration for durable user workflows.
- Shared/view-only session considered separately from shell authorization.
- Session history metadata.
- Optional session recording only as an explicit, opt-in feature with a clear privacy/security model.

### API

- Documented external API.
- Stable JSON schemas.
- API authentication.
- Webhooks for agent online/offline/session events if real integrations require them.
- No plugin framework unless multiple real integrations prove the need.

### Packaging / distribution

- Homebrew package.
- RPM.
- Windows installer.
- macOS package.
- Container image hardening for relay/web.
- Upgrade documentation.
- Backward-compatibility test matrix across supported versions.

---

## Explicit non-goals unless the product thesis changes

- Full VPN/mesh networking.
- General-purpose TCP/UDP tunneling suite.
- Exit nodes.
- Remote desktop.
- Endpoint monitoring platform.
- Package/patch management platform.
- Hardware/software asset inventory platform.
- Stealth agent behavior.
- Persistence evasion.
- Custom cryptographic primitives.
- Home-grown NAT traversal.
- Kubernetes requirement.
- Mandatory cloud/SaaS account.
- AI features without a concrete remote-terminal use case.
