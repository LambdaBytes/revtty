# Field test: a self-hosted relay across NAT

This runbook checks the two open M1 gates of [PROTOTYPE.md](PROTOTYPE.md#next-validation-gates) on real networks:

1. the authenticated `connect` path across a real NAT or CGNAT boundary;
2. recovery under real network loss and NAT mapping changes.

Run it only on machines you own and name for the test: a lab target, never a production gateway or sensor.

## Topology

| Role | Machine | Network |
|---|---|---|
| relay | a VPS with a public address and a DNS name, `relay.example.net` below | public |
| target | a lab machine running the agent as a service | behind NAT, ideally CGNAT (a 4G/5G router) |
| operator | a laptop | any other network |

Keep the three clocks synchronised (NTP): the drills compare timestamps across journals. Note whether the router's WAN address is private or in `100.64.0.0/10` (CGNAT).

## Timers behind the expected results

| What | Value |
|---|---|
| Agent heartbeat (control message plus WebSocket ping) | every 15 s |
| Agent gives up on a relay that sent nothing | 45 s |
| Agent gives up on a control write that makes no progress | 10 s |
| Opening any WebSocket to the relay (DNS, TCP, TLS, upgrade) | 10 s |
| Agent reconnect wait | 0.8–1 s, doubling, capped at 24–30 s; back to the first step once the relay answers a heartbeat ping on the new connection |
| Relay drops an agent that sent nothing | 45 s |
| Relay waits for an agent's `Hello`, its answer to an offer, its data tunnel | 10 s, 5 s, 10 s |
| SSH session keepalive | every 30 s; the session ends after more than 3 go unanswered, or after 120 s without traffic |
| TCP under reqwest's defaults (Linux) | keepalive after 15 s idle, 3 probes 15 s apart; unacknowledged data for 30 s ends the connection |

These are the settings; the drills measure what they add up to.

## 1. Relay

On the VPS, as an administrator (Debian or Ubuntu):

```bash
sudo install -m 0755 revtty /usr/bin/revtty
sudo useradd --system --home-dir /var/lib/revtty-relay --shell /usr/sbin/nologin revtty-relay
sudo install -d -m 0700 -o revtty-relay -g revtty-relay /var/lib/revtty-relay
sudo -u revtty-relay /usr/bin/revtty relay init --db /var/lib/revtty-relay/revtty.db
sudo systemd-run --unit revtty-relay -p User=revtty-relay -p UMask=0077 -p Restart=on-failure /usr/bin/revtty relay serve --db /var/lib/revtty-relay/revtty.db
sudo -u revtty-relay /usr/bin/revtty relay doctor --db /var/lib/revtty-relay/revtty.db
```

`systemd-run` starts a transient service: logs go to `journalctl -u revtty-relay`, and it does not survive a reboot of the VPS. `relay serve` binds `127.0.0.1:8787`; Caddy terminates TLS in front of it (`/etc/caddy/Caddyfile`, then `sudo systemctl reload caddy`):

```text
relay.example.net {
    reverse_proxy 127.0.0.1:8787
}
```

From the operator's laptop, `curl -fsS -o /dev/null -w '%{http_code}\n' https://relay.example.net/health` prints `204`.

## 2. Operator and enrollment

On the laptop:

```bash
revtty init
```

Copy the public key it prints to the VPS, then enroll the target for it there. The token expires after 10 minutes (`--ttl` changes that):

```bash
sudo install -m 0644 -o revtty-relay -g revtty-relay operator.pub /var/lib/revtty-relay/operator.pub
sudo -u revtty-relay /usr/bin/revtty relay enroll field-01 --operator-key /var/lib/revtty-relay/operator.pub --db /var/lib/revtty-relay/revtty.db
```

Back on the laptop, wrap the token in a pairing code; nothing is sent:

```bash
revtty pair field-01 --token <single-use-enrollment-token> --relay https://relay.example.net
```

## 3. Target

Install the agent as in [SYSTEMD.md](SYSTEMD.md), with `ACCOUNT` set to the account whose shell operators get, but enroll with the pairing code:

```bash
sudo -u "$ACCOUNT" env REVTTY_CONFIG_DIR="/var/lib/revtty/$ACCOUNT/config" REVTTY_STATE_DIR="/var/lib/revtty/$ACCOUNT/state" /usr/bin/revtty agent enroll --relay https://relay.example.net --pairing-code <pairing-code>
sudo systemctl enable --now "revtty-agent@$ACCOUNT.service"
sudo -u "$ACCOUNT" env REVTTY_CONFIG_DIR="/var/lib/revtty/$ACCOUNT/config" REVTTY_STATE_DIR="/var/lib/revtty/$ACCOUNT/state" /usr/bin/revtty agent doctor
```

`agent enroll` must print `operator   SHA256:… (verified by pairing code)`, and the journal `agent field-01 connected to https://relay.example.net`.

## 4. Gate 1: connect across NAT

On the laptop:

```bash
revtty doctor --relay https://relay.example.net
revtty list --relay https://relay.example.net
revtty probe field-01 --relay https://relay.example.net
revtty connect field-01 --relay https://relay.example.net
```

The first `probe` prints `pinned host key SHA256:…, verified by pairing code` without asking anything. In the shell, check `id` (the agent's account) and that a full-screen program (`top`, `vi`) redraws on a window resize. Gate 1 passes when this works with the target behind the NAT, and `revtty relay sessions --db …` on the VPS records the session.

## 5. Gate 2: drills

Before each drill, open a shell with `revtty connect` and run `while sleep 1; do date; done` in it, unless the drill says otherwise. Follow the logs with timestamps:

```bash
journalctl -f -o short-precise -u "revtty-agent@$ACCOUNT.service"
journalctl -f -o short-precise -u revtty-relay
```

| Drill | How | Expected |
|---|---|---|
| D1 Short link loss | Take the target's uplink away for 20 s (unplug the router's WAN, or turn off its mobile data). | The dates pause and resume in the same shell; the agent keeps its control connection. |
| D2 Link loss at the TCP limit | As D1, for 45 s. | Record whether the shell survives. On Linux, data left unacknowledged for 30 s ends a connection, so with output flowing the shell is expected to end well before SSH's own limit of about 2 minutes. The agent recovers as in D3. |
| D3 Long link loss | As D1, for 3 minutes. | The shell ends (`connect` exits 255). Within about 45 s the agent logs a lost control connection (`relay sent nothing for 45s`, or a connection error) and then attempts with growing waits; the relay logs `agent field-01 silent for 45s`. Within about a minute of the link coming back, the agent logs `connected` and `revtty list` shows it online. |
| D4 NAT mapping change | Reboot the router, or force a mobile reattach (airplane mode on the router), with the shell open. | Old connections die without a reset. The agent reconnects on its own as in D3; the shell survives only if the mapping did. |
| D5 Relay restart | `sudo systemctl stop revtty-relay`, wait 10 s, then the `systemd-run` line of step 1 again. | The shell ends at once (`connect` exits 255). The agent logs `control connection lost`, then attempts with growing waits that Caddy answers with `502 Bad Gateway`, and is back within the current wait after the relay is up. |
| D6 Relay frozen | `sudo systemctl kill -s SIGSTOP revtty-relay`, 60 s later `sudo systemctl kill -s SIGCONT revtty-relay`. | The shell survives. About 45 s after the last frame the agent drops its control connection; its attempts log `websocket handshake with the relay timed out after 10s`. Once the relay resumes, the agent is back within its current wait (at most 30 s) and a handshake; at once if an attempt was waiting on the relay. |
| D7 Relay frozen longer | As D6, for 3 minutes. | The shell ends 120 s in, on SSH inactivity (`connect` exits 255). The agent keeps trying with growing waits and is back as in D6. |
| D8 Target reboot | `sudo reboot` on the target, no shell open. | The agent starts once the network is online and `revtty list` shows it online. |
| D9 Power cut | Pull the target's power for 30 s, no shell open. | As D8, and `agent doctor` passes afterwards. |
| D10 Idle shell | Leave a shell idle for 15 minutes. | It stays open. |

Gate 2 passes when, after every drill, the agent comes back without anyone touching the target, within about a minute of the network and the relay being available again, and a new `connect` works.

For every drill, record the start and end times, the agent and relay journal lines between them, `connect`'s exit status and `sudo -u revtty-relay /usr/bin/revtty relay sessions --db /var/lib/revtty-relay/revtty.db`. Anything that does not match the table is a finding: keep the journals.

### Rehearsed on one machine

D5, D6 and D7, and a stopped agent, were rehearsed with this version on loopback, without root (plain HTTP to `127.0.0.1`, relay frozen with SIGSTOP, shell producing output):

| Drill | Observed |
|---|---|
| D5, relay down 5 s, no proxy | shell ended at once, exit 255; attempts refused (`Connection refused`); agent back 6.1–6.5 s after the relay stopped |
| D6, relay frozen 60 s | shell survived; control dropped 42 s in; one handshake timed out after 10 s; agent back 0.1 s after the relay resumed, an attempt being under way |
| D7, relay frozen 150 s | shell ended 120.0 s in (SSH inactivity), exit 255; four handshakes timed out with waits of 0.9 to 16 s; agent back 0.1 s after the relay resumed, an attempt being under way |
| agent stopped (SIGINT) and started again at once | shell ended within 0.1 s, exit 255; agent back 0.2 s after the stop |

A frozen relay is not a lost link: its kernel still acknowledges data, so the TCP timeouts never fire there. Link loss, NAT changes and power cuts need the field.

The TLS path was rehearsed with a local terminator that, like Caddy, prefers HTTP/2: enrollment, the agent's control connection and a paired `probe` all went through it over HTTP/1.1. Caddy itself was not.

## 6. Footprint on the target

```bash
ls -l /usr/bin/revtty
ps -o rss,nlwp,cmd -C revtty
```

Take `ps` with the agent idle and again with one shell open. The agent's runtime starts one worker thread per CPU core, so the thread count and part of the memory scale with the cores. For comparison, on an x86-64 Linux machine with 32 cores: a 12.9 MB binary (5.7 MB gzipped), the idle agent at about 9 MiB resident with 33 threads and no measurable CPU time over 25 s, and about 1.5 MiB more with one shell open, besides the login shell itself (about 6 MiB).

## 7. Cleanup

```bash
revtty forget field-01 --relay https://relay.example.net
sudo -u revtty-relay /usr/bin/revtty relay remove field-01 --db /var/lib/revtty-relay/revtty.db
sudo systemctl disable --now "revtty-agent@$ACCOUNT.service"
sudo systemctl stop revtty-relay
```

The first runs on the laptop, the second and fourth on the VPS, the third on the target. Then remove `/var/lib/revtty/$ACCOUNT` on the target, and the Caddy site, `/var/lib/revtty-relay` and the `revtty-relay` user on the VPS.
