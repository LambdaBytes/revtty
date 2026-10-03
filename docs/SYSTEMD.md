# Linux systemd agent

revtty ships a template unit for the target agent at `packaging/systemd/revtty-agent@.service`.

The instance name is the **explicit OS account** used by the remote shell. For example, `revtty-agent@maintenance.service` runs both the agent and its SSH/PTTY shell as the local `maintenance` account. The unit never selects root implicitly.

## Install

Install the binary and unit:

```bash
sudo install -m 0755 revtty /usr/bin/revtty
sudo install -m 0644 packaging/systemd/revtty-agent@.service \
  /etc/systemd/system/revtty-agent@.service
sudo systemctl daemon-reload
```

Choose an existing local account. The examples below use `maintenance`:

```bash
ACCOUNT=maintenance
GROUP="$(id -gn "$ACCOUNT")"

sudo install -d -m 0700 -o "$ACCOUNT" -g "$GROUP" \
  "/var/lib/revtty/$ACCOUNT" \
  "/var/lib/revtty/$ACCOUNT/config" \
  "/var/lib/revtty/$ACCOUNT/state"
```

Enroll as that same account, with the same paths used by the unit:

```bash
sudo -u "$ACCOUNT" env \
  REVTTY_CONFIG_DIR="/var/lib/revtty/$ACCOUNT/config" \
  REVTTY_STATE_DIR="/var/lib/revtty/$ACCOUNT/state" \
  /usr/bin/revtty agent enroll \
    --relay https://revtty.example.com \
    --token <single-use-enrollment-token>
```

Then enable the service:

```bash
sudo systemctl enable --now "revtty-agent@$ACCOUNT.service"
```

Inspect it with native tools:

```bash
systemctl status "revtty-agent@$ACCOUNT.service"
journalctl -u "revtty-agent@$ACCOUNT.service"
```

## Lifecycle and permissions

The unit:

- waits for `network-online.target`;
- restarts the agent after process failure;
- sends SIGINT on stop so the existing graceful Ctrl-C path is used;
- uses `UMask=0077`;
- uses a per-account state root under `/var/lib/revtty/<account>`;
- leaves stdout/stderr attached to systemd, so logs are available through journald.

`REVTTY_CONFIG_DIR` and `REVTTY_STATE_DIR` must be absolute paths. They are general runtime overrides and are useful for system services and containers as well as this unit.

The unit deliberately does not apply filesystem or privilege sandboxes that would silently change what the selected maintenance account can do inside the remote shell. Authorization remains the normal permission model of that explicit OS account.
