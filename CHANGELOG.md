# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog principles and the project intends to use Semantic Versioning once public protocol compatibility is defined.

## [Unreleased]

### Added

- Initial Rust project scaffold and terminal-first client/agent/relay command surface.
- Reverse transport proof with an outbound agent control WebSocket, on-demand second connection, relay rendezvous and operator `probe`.
- Linux and macOS CI with format, Clippy, tests and release builds.
- Platform-native state/config paths.
- Persistent Ed25519 operator and agent identities.
- SQLite relay persistence, migrations and single-use enrollment.
- Persistent authenticated agent control sessions with heartbeat/presence updates.
- SSHSIG operator challenge/response authentication and short-lived operator sessions.
- OpenSSH-compatible host-key pinning with hard failure on unexpected key changes.
- Authenticated SSH transport through the WebSocket rendezvous relay.
- Interactive SSH-backed PTY shell with bounded I/O queues and cleanup.
- Live terminal resize propagation to the remote PTY.
- Separate one-time agent data-tunnel credentials; the long-lived agent control credential is rejected on the data path.
- Product, security, stack, scope, protocol and roadmap documentation.

### Changed

- The persistent `/v1` path now uses enrolled identities and scoped credentials instead of the development shared token.
- Protocol and prototype documentation now describe the implemented M1 state rather than the original scaffold.
