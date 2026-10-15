# Project Memory: revtty

## Facts
- Single bin crate `revtty` 0.1.0, edition 2024, MSRV 1.95; client/agent/relay roles in one binary (src/app.rs)
- Modules: src/{agent,client,relay,identity,protocol,transport}; storage.rs = SQLite (tokio-rusqlite + migrations)
- Stack: tokio, axum ws (relay), reqwest+reqwest-websocket (client), russh aws-lc-rs, portable-pty, clap derive+env
- Tests: unit inline `#[cfg(test)]` in most modules; only integration test is tests/ssh_stream.rs
- Defaults: relay bind 127.0.0.1:8787, db revtty.db (REVTTY_DB); client relay ws://127.0.0.1:8787 (REVTTY_RELAY)
- `--relay` accepts ws/wss/http/https; schemes converted by http_url/websocket_url (src/transport/mod.rs:124)
- Host-key pins in <config_dir>/known_hosts, alias revtty-<16hex sha256(relay)>-<agent> (src/identity/mod.rs:193)
- Agent max_sessions default 4, range 1..=64 (src/agent/config.rs:14); relay enroll --ttl default 600 s
- Dirs: ProjectDirs(io, LambdaBytes, revtty); config_dir/state_dir overridable via env (src/config.rs:14)
- 2026-10-15 status: M1 'First Shell' in progress; pending gates in docs/PROTOTYPE.md 'Next validation gates'
- Docs: BRIEF=arch, V1_SCOPE, STACK=deps, ROADMAP, PROTOCOL=wire, PROTOTYPE=validation, SYSTEMD=agent service
- Remote GitHub LambdaBytes/revtty; CI .github/workflows/ci.yml, ubuntu+macos, toolchain pinned 1.95.0
- Commits: conventional prefixes (feat/fix/test/docs/style/refactor) plus [skip ci] / [full ci] subject tags

## Commands
- build(default): `cargo check`; release: `cargo build --release` (CI step)
- test(default): `cargo test`; CI: `cargo test --all-targets --all-features` (same here: no features/lib/examples)
- lint: `cargo fmt --check` + `cargo clippy --all-targets --all-features -- -D warnings` (same as CI)
- run(app): `cargo run -- <subcmd>`; full relay/agent/operator flow in README 'Authenticated local flow'

## Gotchas
- 2026-10-15: Cargo.lock never committed (git log --all); each CI run resolves latest semver deps -> drift risk
- 2026-10-15: `relay serve` requires --token/REVTTY_DEV_TOKEN (src/cli.rs:145) even for /v1-only use (legacy /v0)
- 2026-10-15: REVTTY_CONFIG_DIR / REVTTY_STATE_DIR must be absolute paths or the command errors (src/config.rs:34)
- 2026-10-15: pin alias hashes relay URL (ws=http, wss=https); a different host/port/scheme pins anew
- 2026-10-15: CI ignores docs/** and **/*.md; macOS job only on PR/dispatch or push whose message has [full ci]
