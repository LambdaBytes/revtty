# revtty Roadmap

The v1 feature boundary is approved and frozen in [V1_SCOPE.md](V1_SCOPE.md).

The vetted implementation stack is documented in [STACK.md](STACK.md).

This file tracks delivery order and the v2+ backlog. It is not a second definition of v1 scope.

## v1 delivery plan

### M0 — Scaffold

- repository structure;
- strict CI;
- architecture/security/protocol docs;
- vetted dependency strategy;
- Linux + macOS build validation;
- command surface.

### M1 — First Shell / Linux

- relay HTTP/WSS skeleton;
- SQLite schema and migrations;
- enrollment;
- operator identity;
- agent identity;
- persistent WSS control channel;
- presence and heartbeats;
- session rendezvous;
- SSH over paired WSS tunnels;
- Linux PTY;
- systemd service;
- reconnect/backoff;
- `list`, `status`, `connect`;
- baseline doctor commands;
- core fault/E2E tests.

### M2 — macOS parity

- macOS operator CLI;
- macOS agent;
- shared portable PTY boundary;
- launchd service;
- platform-correct paths;
- Apple Silicon build;
- Intel build;
- PTY/session E2E tests on macOS.

### M3 — Access management and automation

- multiple authorized operators;
- operator list/add/revoke;
- SSHSIG-based operator control-plane authentication;
- operator key rotation;
- agent credential rotation;
- `revtty exec`;
- machine-readable status/exec output where useful;
- audit metadata.

### M4 — SSH capabilities

- SFTP integration;
- `revtty cp` upload/download;
- transfer progress/cancellation;
- local SSH forwarding;
- safe loopback bind defaults;
- E2E tests for both.

### M5 — Web console

- `revtty web serve`;
- authenticated web sessions;
- machine list/search;
- xterm.js 6 stable;
- fit/resize;
- browser session lifecycle;
- desktop/mobile emergency use;
- explicit web plaintext trust boundary;
- no target-side GoTTY/ttyd service.

### M6 — v1 release hardening

- protocol compatibility contract;
- bounded-frame/buffer review;
- security/threat-model review;
- dependency audit/deny policy;
- fault tests;
- soak tests;
- Linux packages;
- macOS release artifacts;
- systemd/launchd assets;
- completions/man page;
- install/upgrade/deployment docs;
- v1.0 release.

## v2 candidates

### Windows

Windows is the primary platform expansion planned for v2.

- Windows operator CLI.
- Windows agent.
- Windows Service lifecycle.
- ConPTY backend.
- Windows config/state paths.
- x86_64 Windows release.
- Windows ARM64 if demand/build support justifies it.
- Windows E2E terminal tests.
- Preserve v1 wire protocol and SSH semantics.

The v1 PTY/service boundaries must not make this harder than adding a new platform backend.

### MQTT control plane

For appliance/IoT environments already using MQTT:

- MQTT as alternative control/signaling transport;
- TLS-authenticated broker connection;
- per-agent routing;
- replay-safe session signaling;
- WSS remains available;
- terminal data never carried over MQTT.

Use a mature MQTT implementation such as `rumqttc`; do not create an MQTT client.

### Direct/P2P data path

Only if measurements or relay cost/latency justify it:

- evaluate Iroh or another mature Rust NAT-traversal stack;
- direct QUIC when available;
- relay fallback always remains;
- path diagnostics;
- no custom STUN;
- no custom ICE;
- no custom hole punching.

Reliability remains more important than forcing P2P.

### Remote forwarding

Local forwarding is v1.

Remote SSH forwarding can be added in v2 if a concrete maintenance use case justifies the additional exposure/security policy.

No exit-node or VPN behavior.

### Web identity expansion

- OIDC;
- external identity providers;
- optional MFA flows where appropriate;
- named web operators;
- tighter per-agent policies.

Do not turn this into an enterprise IAM platform unless users actually need it.

### Advanced key support

- SSH agent integration;
- hardware-backed/FIDO keys where the Rust/OpenSSH ecosystem supports the required signing path;
- optional short-lived SSH certificates if fleet scale justifies a CA.

### Fleet ergonomics

Only after simple named-machine workflows become insufficient:

- tags/groups;
- saved filters;
- bulk status;
- fleet compatibility report;
- controlled agent upgrades.

Avoid generic orchestration.

### Session ergonomics

- optional tmux integration for durable remote workflows;
- shared/view-only sessions if there is a real support use case;
- session metadata/history improvements;
- optional recording only with an explicit opt-in security/privacy model.

Do not claim transparent session resume for a dead SSH session.

### Relay scaling

Only when single-node measurements prove it necessary:

- multiple relay instances;
- shared persistence;
- distributed presence/rendezvous;
- rolling upgrades;
- multi-region;
- relay federation.

Do not introduce Redis/PostgreSQL/distributed coordination preemptively.

## Explicit non-goals

Unless the product thesis is deliberately changed, revtty is not:

- a full VPN/mesh network;
- a generic TCP/UDP tunneling suite;
- an exit node;
- remote desktop/screen sharing;
- endpoint monitoring;
- a metrics dashboard;
- patch/package management;
- asset inventory;
- ticketing;
- generic orchestration;
- a Kubernetes access platform;
- covert/stealth persistence;
- a custom cryptography project;
- a custom NAT-traversal implementation.

## Product guardrail

A feature should materially improve one of:

- obtaining a secure terminal;
- maintaining access reliability;
- operator authorization;
- safe shell-adjacent workflows such as exec/copy/forward;
- diagnosing revtty itself.

If it does not, it probably belongs elsewhere.
