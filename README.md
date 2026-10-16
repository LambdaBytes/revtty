# revtty

**Outbound-only remote terminal for machines behind NAT.**

No inbound ports. No VPN. No exposed SSH daemon — just secure, on-demand shell access from anywhere.

> Status: M1 “First Shell” works end to end; the full test suite, end-to-end tests included, passes on Linux and macOS in CI. It is pre-v1.0 software: the protocol may still change, and validation across a real NAT/CGNAT boundary is pending (see [Limitations](#limitations)).

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
- Agents join with a single-use, expiring enrollment token bound to one agent name and its first operator key.
- Optionally the operator wraps that token in a pairing code (`revtty pair`) whose secret never reaches the relay: the agent then checks that the relay enrolled it for that operator under that name, and proves its host key to the operator, so that a relay compromised at enrollment can neither authorize a key of its own on the agent nor have the operator pin another host key.
- Operators authenticate with OpenSSH signatures (SSHSIG) over single-use challenges and receive a 30-second, single-use session credential. Each data tunnel gets its own one-time credential, and the agent's long-lived control credential is refused on the data path.
- `list` only shows agents that authorize the signing key. Challenge requests do not reveal which agents exist, and they keep no relay state: unauthenticated requests cannot use up what operators need to authenticate.
- The agent's host key is pinned per relay and agent in revtty's own `known_hosts`. The first pin needs the operator's confirmation of the fingerprint printed on the target, or the agent's pairing proof, so the relay cannot introduce a host key; a changed key is a hard failure unless the machine was enrolled again with a new pairing code.
- The agent authenticates the operator's key again inside SSH, against its own operator list in `agent.toml`. Only Ed25519 keys are accepted.
- Operators are managed on the target with `revtty agent operator list|add|revoke`, locally or from an operator's `revtty connect` shell. The running agent applies a change within 2 seconds: a revoked operator's open sessions are closed and new ones refused. The last operator cannot be revoked.
- The relay learns the agent's operator list from the agent, and issues session credentials only to those operators; it cannot add one, because the agent's own list decides SSH access.

**Reliability**

- The agent reconnects with bounded exponential backoff and jitter, including when the relay goes silent.
- The relay drops agents that stop sending heartbeats, so `status` does not report vanished machines as online.
- SSH keepalives on both ends: idle sessions stay open, sessions on a dead network path end and free their slot.
- Shell teardown never injects input, reaps the shell (SIGHUP, then SIGKILL after 5 s) and releases the PTY; on SIGINT the agent waits up to 10 s for these teardowns before it exits.

**Operations**

- Session audit on the relay (`relay sessions`): operator key fingerprint, target, kind, request/accept/pair/end times and outcome. Terminal bytes and credentials are never recorded.
- The agent's relay credential is replaced with `agent rotate-credential` while the agent is stopped: the agent generates the new credential and saves it before the relay learns its hash, so an interrupted rotation is finished by the next `agent run`. Only one `agent run` runs per configuration.
- A reinstalled machine is re-enrolled under its name with `relay enroll NAME --replace`, and an agent is retired with `relay remove NAME`. Within 5 seconds the relay closes the old agent's control connection and every session it is part of, open data tunnels included; its credential no longer works. Operators then see a host key mismatch for the new machine and clear the old pin with `revtty forget NAME`, unless the machine was enrolled with a new pairing code: its proof replaces the pin.
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

The first `status`, `probe` or `connect` to an agent pins its host key once the operator gives the fingerprint that `revtty agent status` (or `agent enroll`) shows on the target: with `--host-key`, or typed at the interactive prompt. revtty never shows the fingerprint the relay presents before it is pinned, so that it cannot be copied in place of the target's. Later commands verify against the pin, and a `--host-key` given later is still checked against the key presented.

With a pairing code the fingerprint does not have to travel. Before handing the token to the target, the operator wraps it; nothing is sent, and the code's secret stays in the operator's `pairings` file and on the target's command line:

```bash
revtty pair store-042 --token <single-use-enrollment-token> --relay http://127.0.0.1:8787
revtty agent enroll --relay http://127.0.0.1:8787 --pairing-code <pairing-code>
```

The second command runs on the target, which prints the operator's fingerprint as `verified by pairing code` (with `--token`, `as reported by the relay, not verified`). The operator's first `status`, `probe` or `connect` then pins the host key the agent proved, without `--host-key`, and uses the pairing up. Give the code only to a revtty that knows `--pairing-code`, and never as `--token`: an older one would send it whole to the relay.

On the relay host, `revtty relay sessions --db revtty.db` shows the audited sessions.

## Deploying across real networks

- **Relay**: run it on a host that operators and targets can reach, behind a TLS-terminating reverse proxy; `relay serve` speaks plain HTTP/WebSocket and binds to loopback by default. With Caddy:

  ```text
  revtty.example.com {
      reverse_proxy 127.0.0.1:8787
  }
  ```

  Then use `--relay https://revtty.example.com` everywhere. Keep the relay database and its directory writable only by the relay's account: `relay doctor` fails if other users can write them, and warns about a group-writable directory.
- **Agent**: enroll and run it as the account whose shell operators should get, ideally as a service ([docs/SYSTEMD.md](docs/SYSTEMD.md)). Enroll it with a pairing code from its first operator, or give the operators the fingerprint that `agent enroll` prints.
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
| `pair NAME --token TOKEN --relay URL` | operator | Wrap an enrollment token in a pairing code for the target; nothing is sent. |
| `forget NAME --relay URL` | operator | Forget a machine's pinned host key, after it was reinstalled and re-enrolled, and discard a pairing pending for it. |
| `agent enroll --relay URL (--token TOKEN \| --pairing-code CODE) [--max-sessions N]` | target | Consume an enrollment and store the agent configuration. |
| `agent run` | target | Run the persistent agent. |
| `agent status`, `agent doctor`, `agent pty-test` | target | Local configuration, full diagnostics, local PTY check. |
| `agent operator list`, `agent operator add KEYFILE`, `agent operator revoke FINGERPRINT` | target | Show, authorize or revoke operator keys. |
| `agent rotate-credential` | target | Replace the agent's relay credential; the agent must be stopped. |
| `relay init`, `relay serve [--bind ADDR]` | relay | Create or migrate the database; serve the relay. |
| `relay enroll NAME --operator-key FILE [--ttl SECS] [--replace]` | relay | Single-use enrollment token (default lifetime 600 s); `--replace` re-enrolls an enrolled agent. |
| `relay remove NAME` | relay | Remove an agent and its unused enrollments; the audit is kept. |
| `relay agents`, `relay sessions [--limit N]`, `relay doctor` | relay | Enrolled agents, session audit, diagnostics. |

`--relay` accepts `https://` or `wss://`, and plain `http://` or `ws://` only for a relay on the same machine (`localhost`, `127.0.0.0/8` or `[::1]`), and a redirect to any other plain URL is not followed: every request carries a credential that only TLS protects. For the operator commands it defaults to `$REVTTY_RELAY`, else `ws://127.0.0.1:8787`; `agent enroll` requires it explicitly and the agent then keeps it in `agent.toml`. Relay commands take `--db`, defaulting to `$REVTTY_DB`, else `revtty.db`.

## Files

| Role | Files | Location |
|---|---|---|
| operator | `id_ed25519`, `id_ed25519.pub`, `known_hosts`, `pairings` (secrets of pairing codes not used yet) | config directory |
| agent | `agent.toml` (holds the control credential and the operator list), `agent.lock`, `agent.run.lock` | config directory |
| agent | `agent_ed25519`, `agent_ed25519.pub` (host key) | state directory |
| relay | SQLite database | `--db` |

On Linux the defaults are `~/.config/revtty` and `~/.local/share/revtty`; `REVTTY_CONFIG_DIR` and `REVTTY_STATE_DIR` override them with absolute paths. revtty creates these directories private to the user and writes private keys, `known_hosts`, `pairings` and `agent.toml` with mode 0600. The doctors refuse files or directories that other users could modify; the one exception is the directory holding the relay database, which the administrator chooses: there a group-writable mode is a warning (with user private groups, the default on Debian and Ubuntu, the group is only the owner) and a world-writable one fails.

## Limitations

- **Pre-v1**: the protocol and database schema may still change between versions. Database migrations run automatically and only forward.
- **Not yet validated** across a real NAT/CGNAT boundary or under real network loss; local tests cover relay restarts and silent peers.
- **No roles**: every authorized operator of an agent can manage its operators.
- **Pairing codes need both ends updated**: an operator client that predates them pins the first host key by confirmation, as before. A pairing code covers the agent's first operator only; operators added later confirm the host key themselves.
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
