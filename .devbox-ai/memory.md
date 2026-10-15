# Project Memory: revtty

## Facts
- Single bin crate `revtty` 0.1.0, edition 2024, MSRV 1.95; client/agent/relay roles in one binary (src/app.rs)
- Modules: src/{agent,client,relay,identity,protocol,transport}; storage.rs = SQLite (tokio-rusqlite + migrations)
- Stack: tokio, axum ws (relay), reqwest+reqwest-websocket (client), russh aws-lc-rs, portable-pty, clap derive+env
- Tests: unit inline `#[cfg(test)]`; integration: tests/ssh_stream.rs and tests/e2e.rs (real binary driven via a PTY)
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
- e2e: `cargo test --test e2e` (~35 s, one test waits past the 30 s operator credential); needs loopback sockets
- build(default): `cargo check`; release: `cargo build --release` (CI step)
- test(default): `cargo test`; CI: `cargo test --all-targets --all-features` (same here: no features/lib/examples)
- lint: `cargo fmt --check` + `cargo clippy --all-targets --all-features -- -D warnings` (same as CI)
- run(app): `cargo run -- <subcmd>`; full relay/agent/operator flow in README 'Authenticated local flow'

## Gotchas
- 2026-10-15: relay schema v3 = sessions audit; queued best-effort writes stamped at the event (relay AuditLog)
- 2026-10-15: doctors fail on group/other-writable revtty dirs (like OpenSSH StrictModes); revtty creates them 0700
- 2026-10-15: first host-key pin needs --host-key <SHA256 fp from agent enroll/status> or a TTY yes; e2e passes the flag
- 2026-10-15: operator challenges are HMAC'd with a per-process key: a relay restart voids outstanding challenges
- 2026-10-15: portable-pty 0.9 writer Drop does a blocking write of newline+VEOF; agent PTY I/O uses its own AsyncFd
- 2026-10-15: tokio 1.53 deprecates AsyncFd::new (I/O safety); use unsafe AsyncFd::register with a SAFETY note
- 2026-10-15: agent shell is a login shell (-sh): /etc/profile resets PS1; tests wait on computed echo markers
- 2026-10-15: ssh-key PublicKey == compares comment; SSH wire keys have none -> always compare key_data()
- 2026-10-15: unit tests use comment-less random keys; real init/enroll keys carry comments (revtty, revtty-agent)
- 2026-10-15: russh defaults (600 s inactivity, no keepalive) overridden by transport::SSH_TIMEOUTS on both sides
- 2026-10-15: russh awaits server Handler callbacks inline in the session loop; a blocking await stalls the session
- 2026-10-15: portable-pty 0.9 ChildKiller::kill sends SIGHUP to the shell PID only, no process-group kill
- 2026-10-15: tokio::io::stdin read can't be cancelled; runtime shutdown waits for it (client hangs until Enter)
- 2026-10-15: Cargo.lock is versioned (binary crate); CI builds use the committed resolution
- 2026-10-15: REVTTY_CONFIG_DIR / REVTTY_STATE_DIR must be absolute paths or the command errors (src/config.rs:34)
- 2026-10-15: pin alias hashes relay URL (ws=http, wss=https); a different host/port/scheme pins anew
- 2026-10-15: CI ignores docs/** and **/*.md; macOS job only on PR/dispatch or push whose message has [full ci]
