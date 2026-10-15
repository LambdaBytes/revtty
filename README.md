# revtty

**Outbound-only remote terminal for machines behind NAT.**

No inbound ports. No VPN. No exposed SSH daemon — just secure, on-demand shell access from anywhere.

> Status: M1 “First Shell” works end to end on Linux. It is pre-v1.0 software: the protocol may still change, and real NAT/CGNAT and macOS validation are pending (see [Limitations](#limitations)).

## How it works

```text
operator                           relay                             target
revtty connect                     revtty relay serve                revtty agent run
     │                                  │                                  │
     │                                  │◀──── control channel (WSS out) ──│  always open
     │── 1. signed session request ────▶│                                  │
     │                                  │── 2. session offer ─────────────▶│
     │                                  │◀──── 3. data tunnel (WSS out) ───│
     │◀═══════════ 4. SSH end to end through the paired tunnels ══════════▶│
```

- A persistent **agent** on the target keeps one outbound WebSocket to the **relay**. It never listens on a port.
- An authorized **operator** asks the relay for a session; the agent opens a second outbound connection for it and the relay pairs the two.
- **SSH runs end to end** between the operator's client and the agent, over the paired WebSockets. The relay only routes bytes: it never sees the terminal in clear and never terminates SSH.
- One Rust binary carries all three roles. The relay keeps its state in SQLite.

Design principles, scope and roadmap: [docs/BRIEF.md](docs/BRIEF.md), [docs/V1_SCOPE.md](docs/V1_SCOPE.md), [docs/STACK.md](docs/STACK.md), [docs/ROADMAP.md](docs/ROADMAP.md). Protocol: [docs/PROTOCOL.md](docs/PROTOCOL.md). Validation notes: [docs/PROTOTYPE.md](docs/PROTOTYPE.md).

## What revtty does today

**Access**

- Interactive shell on a real PTY of an enrolled Linux or macOS machine: input, output, live resize, EOF, and the remote exit status as `revtty connect`'s exit code (255 when the session ended without one).
- `probe` checks a target end to end; `list` and `status` show presence: online/offline, last seen, version, sessions in use and allowed.
- Several concurrent sessions per agent (default 4, up to 64); extra requests get an explicit "agent is busy".

**Security**

- Persistent Ed25519 identities for the operator (`revtty init`) and every agent.
- Agents join with a single-use, expiring enrollment token bound to one agent name and one operator key.
- Operators authenticate with OpenSSH signatures (SSHSIG) over single-use challenges and receive a 30-second, single-use session credential. Each data tunnel gets its own one-time credential, and the agent's long-lived control credential is refused on the data path.
- `list` only shows agents enrolled for the signing key. Challenge requests do not reveal which agents exist, and they keep no relay state: unauthenticated requests cannot use up what operators need to authenticate.
- The agent's host key is pinned per relay and agent in revtty's own `known_hosts`. The first pin needs the operator's confirmation of the fingerprint printed on the target, so the relay cannot introduce a host key; a changed key is a hard failure.
- The agent authenticates the operator's key again inside SSH. Only Ed25519 keys are accepted.

**Reliability**

- The agent reconnects with bounded exponential backoff and jitter, including when the relay goes silent.
- The relay drops agents that stop sending heartbeats, so `status` does not report vanished machines as online.
- SSH keepalives on both ends: idle sessions stay open, sessions on a dead network path end and free their slot.
- Shell teardown never injects input, reaps the shell (SIGHUP, then SIGKILL after 5 s) and releases the PTY; on SIGINT the agent waits up to 10 s for these teardowns before it exits.

**Operations**

- Session audit on the relay (`relay sessions`): operator key fingerprint, target, kind, request/accept/pair/end times and outcome. Terminal bytes and credentials are never recorded.
- `doctor`, `agent doctor` and `relay doctor`: relay reachability with the underlying TLS or network cause, signed operator authentication, agent credential validation, file and directory permissions, relay schema version.
- A systemd template that runs the agent as an explicit OS account ([docs/SYSTEMD.md](docs/SYSTEMD.md)).

## Try it on one machine

Operator and agent can share one user account: their files do not overlap. Build once:

```bash
cargo build --release
export PATH="$PWD/target/release:$PATH"
```

Operator identity (note the public key path it prints), then the relay database and a single-use enrollment for the agent `store-042`:

```bash
revtty init
revtty relay init --db revtty.db
revtty relay enroll store-042 --operator-key <operator-public-key-path> --db revtty.db
```

Start the relay and leave it running:

```bash
revtty relay serve --db revtty.db
```

In another terminal, enroll the target with the printed token and start the agent:

```bash
revtty agent enroll --relay http://127.0.0.1:8787 --token <single-use-enrollment-token>
revtty agent run
```

`agent enroll` prints the agent's host key fingerprint on its `host` line; `revtty agent status` shows it again. As the operator:

```bash
revtty list --relay http://127.0.0.1:8787
revtty probe store-042 --relay http://127.0.0.1:8787 --host-key <agent-host-fingerprint>
revtty connect store-042 --relay http://127.0.0.1:8787
```

The first `status`, `probe` or `connect` to an agent pins its host key: pass the fingerprint with `--host-key`, or answer the interactive prompt with `yes` (or the fingerprint) after comparing it with the target's. Later commands verify against the pin.

On the relay host, `revtty relay sessions --db revtty.db` shows the audited sessions.

## Deploying across real networks

- **Relay**: run it on a host that operators and targets can reach, behind a TLS-terminating reverse proxy; `relay serve` speaks plain HTTP/WebSocket and binds to loopback by default. With Caddy:

  ```text
  revtty.example.com {
      reverse_proxy 127.0.0.1:8787
  }
  ```

  Then use `--relay https://revtty.example.com` everywhere. Keep the relay database and its directory writable only by the relay's account: `relay doctor` fails if other users can write them, and warns about a group-writable directory.
- **Agent**: enroll and run it as the account whose shell operators should get, ideally as a service ([docs/SYSTEMD.md](docs/SYSTEMD.md)). Give the operators the fingerprint that `agent enroll` prints.
- **Operator**: run `revtty init` once per operator machine; the relay administrator enrolls each agent for that operator's public key.

## Command reference

| Command | Role | What it does |
|---|---|---|
| `init` | operator | Create or show the operator identity. |
| `list --relay URL` | operator | Agents enrolled for this operator key, with presence and capacity. |
| `status NAME --relay URL [--host-key FP]` | operator | One agent's status. |
| `probe NAME --relay URL [--host-key FP]` | operator | Round trip through the agent: name, OS, architecture, version. |
| `connect NAME --relay URL [--host-key FP]` | operator | Interactive shell; exits with the remote status. |
| `doctor --relay URL` | operator | Local permissions, relay reachability and signed authentication. |
| `agent enroll --relay URL --token TOKEN [--max-sessions N]` | target | Consume an enrollment token and store the agent configuration. |
| `agent run` | target | Run the persistent agent. |
| `agent status`, `agent doctor`, `agent pty-test` | target | Local configuration, full diagnostics, local PTY check. |
| `relay init`, `relay serve [--bind ADDR]` | relay | Create or migrate the database; serve the relay. |
| `relay enroll NAME --operator-key FILE [--ttl SECS]` | relay | Single-use enrollment token (default lifetime 600 s). |
| `relay agents`, `relay sessions [--limit N]`, `relay doctor` | relay | Enrolled agents, session audit, diagnostics. |

`--relay` accepts `http(s)://` or `ws(s)://`. For the operator commands it defaults to `$REVTTY_RELAY`, else `ws://127.0.0.1:8787`; `agent enroll` requires it explicitly and the agent then keeps it in `agent.toml`. Relay commands take `--db`, defaulting to `$REVTTY_DB`, else `revtty.db`.

## Files

| Role | Files | Location |
|---|---|---|
| operator | `id_ed25519`, `id_ed25519.pub`, `known_hosts` | config directory |
| agent | `agent.toml` (holds the control credential) | config directory |
| agent | `agent_ed25519`, `agent_ed25519.pub` (host key) | state directory |
| relay | SQLite database | `--db` |

On Linux the defaults are `~/.config/revtty` and `~/.local/share/revtty`; `REVTTY_CONFIG_DIR` and `REVTTY_STATE_DIR` override them with absolute paths. revtty creates these directories private to the user and writes private keys, `known_hosts` and `agent.toml` with mode 0600. The doctors refuse files or directories that other users could modify; the one exception is the directory holding the relay database, which the administrator chooses: there a group-writable mode is a warning (with user private groups, the default on Debian and Ubuntu, the group is only the owner) and a world-writable one fails.

## Limitations

- **Pre-v1**: the protocol and database schema may still change between versions. Database migrations run automatically and only forward.
- **Not yet validated** across a real NAT/CGNAT boundary or under real network loss; local tests cover relay restarts and silent peers. macOS is covered by CI, but the latest lifecycle and end-to-end tests have only run on Linux so far.
- **One operator key per agent**, fixed at enrollment. There are no commands yet to add or revoke operators, rotate credentials, or re-enroll or remove an agent.
- **One relay process**: agent presence lives in its memory; there is no clustering or high availability.
- **Not yet**: rate limiting, packages or signed release artifacts, a launchd service for macOS agents, Windows support.
- **Audit is best effort**: records are written asynchronously and dropped with a warning if the queue fills up.
- **Interactive shell only**: no `exec`, file copy or port forwarding yet.

The remaining v1 milestones are in [docs/ROADMAP.md](docs/ROADMAP.md).

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release
```

The end-to-end tests (`cargo test --test e2e`) drive the real binary through a PTY over loopback sockets. One of them deliberately waits past the 30-second operator credential, so that suite takes about 35 seconds.

## License

MIT.
