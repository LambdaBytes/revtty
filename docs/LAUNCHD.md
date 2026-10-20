# macOS launchd agent

revtty ships a launchd daemon definition for the target agent at `packaging/launchd/io.lambdabytes.revtty-agent.plist`.

The plist runs the agent, and its SSH/PTY shells, as one **explicit OS account**, the `ACCOUNT` it names: launchd has no templates, so each account gets its own copy with `ACCOUNT` replaced. The daemon never runs as root implicitly.

## Install

Install the binary into `/usr/local/bin` (`/usr/bin` is protected by System Integrity Protection):

```bash
sudo install -m 0755 revtty /usr/local/bin/revtty
```

Choose an existing local account. The examples below use `maintenance`:

```bash
ACCOUNT=maintenance
GROUP="$(id -gn "$ACCOUNT")"
LABEL="io.lambdabytes.revtty-agent.$ACCOUNT"

sudo install -d -m 0755 "/Library/Application Support/revtty"
sudo install -d -m 0700 -o "$ACCOUNT" -g "$GROUP" \
  "/Library/Application Support/revtty/$ACCOUNT" \
  "/Library/Application Support/revtty/$ACCOUNT/config" \
  "/Library/Application Support/revtty/$ACCOUNT/state"
sudo install -d -m 0755 /Library/Logs/revtty
sudo install -m 0600 -o "$ACCOUNT" -g "$GROUP" /dev/null "/Library/Logs/revtty/agent-$ACCOUNT.log"
```

Enroll as that same account, with the same paths the plist uses, and the pairing code the operator made with `revtty pair` from the enrollment token:

```bash
sudo -u "$ACCOUNT" env \
  REVTTY_CONFIG_DIR="/Library/Application Support/revtty/$ACCOUNT/config" \
  REVTTY_STATE_DIR="/Library/Application Support/revtty/$ACCOUNT/state" \
  /usr/local/bin/revtty agent enroll \
    --relay https://revtty.example.com \
    --pairing-code <code-from-revtty-pair>
```

Give the code only as `--pairing-code`, never as `--token`: a revtty that predates pairing codes would send its secret to the relay. Without a code, `--token <single-use-enrollment-token>` enrolls the same way.

`agent enroll` prints the operator's fingerprint, `verified by pairing code` or, with `--token`, `as reported by the relay, not verified`, and the agent's host key fingerprint (`host`). With a pairing code, the operator's first `status`, `probe` or `connect` pins the host key the agent proved. With a token, give the operators the fingerprint: they pin it with `--host-key <fingerprint>` or by typing it at the prompt.

Then install the plist for the account and load it, which also starts the agent:

```bash
sed "s/ACCOUNT/$ACCOUNT/g" packaging/launchd/io.lambdabytes.revtty-agent.plist \
  | sudo tee "/Library/LaunchDaemons/$LABEL.plist" > /dev/null
sudo chown root:wheel "/Library/LaunchDaemons/$LABEL.plist"
sudo chmod 0644 "/Library/LaunchDaemons/$LABEL.plist"
plutil -lint "/Library/LaunchDaemons/$LABEL.plist"
sudo launchctl bootstrap system "/Library/LaunchDaemons/$LABEL.plist"
```

Inspect it with native tools:

```bash
sudo launchctl print "system/$LABEL"
sudo tail -f "/Library/Logs/revtty/agent-$ACCOUNT.log"
```

`launchctl print` shows the agent's `pid`, its `state` and the `last exit code`.

## Operators and credential rotation

Operator keys are managed as the same account, with the same paths: `revtty agent operator list`, `add` and `revoke`. The running agent applies a change within 2 seconds, without a restart.

Rotating the agent's relay credential needs the agent stopped. SIGTERM stops it cleanly, and launchd does not restart an agent that exited cleanly; the agent may take up to 10 s to end its shells, and launchd kills it 15 s after the signal at the latest, so wait until `launchctl print` shows no `pid` before rotating:

```bash
sudo launchctl kill SIGTERM "system/$LABEL"
while sudo launchctl print "system/$LABEL" | grep -q '^[[:space:]]*pid = '; do sleep 1; done
sudo -u "$ACCOUNT" env REVTTY_CONFIG_DIR="/Library/Application Support/revtty/$ACCOUNT/config" REVTTY_STATE_DIR="/Library/Application Support/revtty/$ACCOUNT/state" /usr/local/bin/revtty agent rotate-credential
sudo launchctl kickstart "system/$LABEL"
```

A rotation interrupted by a network failure or a power loss is finished by the agent's next start, or by running `rotate-credential` again.

## Uninstall

```bash
sudo launchctl bootout "system/$LABEL"
sudo rm "/Library/LaunchDaemons/$LABEL.plist"
```

The account's revtty state stays in `/Library/Application Support/revtty/$ACCOUNT` until you remove it; the relay keeps the agent enrolled until `revtty relay remove` runs there.

## Lifecycle and permissions

The plist:

- starts the agent when it is loaded and at every boot (`RunAtLoad`); the agent retries the relay with growing waits while the network comes up;
- restarts the agent after a crash, at most every 5 s (`KeepAlive` with `SuccessfulExit` false, `ThrottleInterval`), but not after a clean exit;
- stops it with SIGTERM, which takes the agent's graceful Ctrl-C path, and with SIGKILL 15 s later (`ExitTimeOut`), above the 10 s the agent waits for its shells;
- uses `Umask` 0077;
- keeps the account's state under `/Library/Application Support/revtty/<account>`;
- writes stdout and stderr to `/Library/Logs/revtty/agent-<account>.log`, created beforehand for the account;
- sets `PATH` to include `/usr/local/bin`, which launchd's default lacks, for the shells the agent starts.

launchd keeps the log file open: after rotating it, for example with `newsyslog`, restart the agent (`sudo launchctl kickstart -k "system/$LABEL"`) so that it writes to the new file.

When the agent stops, it ends its shells. A process that detached into a session of its own, such as a daemon started from a shell, is not tracked by the agent and keeps running; launchd does not end it either.

`REVTTY_CONFIG_DIR` and `REVTTY_STATE_DIR` must be absolute paths. They are general runtime overrides and are useful for system services and containers as well as this daemon.

The plist deliberately does not apply a sandbox that would silently change what the selected maintenance account can do inside the remote shell. Authorization remains the normal permission model of that explicit OS account.
