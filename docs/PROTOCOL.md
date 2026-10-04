# revtty Control Protocol

Status: **draft / implemented pre-v1 subset**

The control protocol coordinates authenticated agent presence and session rendezvous. It does not carry terminal bytes. Interactive terminal data is SSH carried over an ephemeral WebSocket data tunnel.

The wire contract may still change before the first stable release.

## Envelope

Control messages are tagged JSON with an explicit numeric protocol version.

Current heartbeat example:

```json
{
  "type": "heartbeat",
  "version": 1
}
```

## Implemented control messages

### hello

Sent by the agent immediately after authenticating its persistent control connection.

Fields:

- `version`
- `name`
- `agent_version`

### heartbeat

Periodic liveness update.

Fields:

- `version`

### probe_offer

Relay asks the agent to open the data side of a probe rendezvous.

Fields:

- `version`
- `session_id`
- `tunnel_token`

### shell_offer

Relay asks the agent to open the data side of an SSH shell rendezvous.

Fields:

- `version`
- `session_id`
- `tunnel_token`

The `tunnel_token` is generated independently for each rendezvous, delivered only over the authenticated agent control channel, stored by the relay only as a hash while pending and consumed at most once. A pending rendezvous is also bounded by the relay's session wait timeout.

The long-lived agent control credential is not accepted by the persistent `/v1/session/{session_id}` data endpoint.

### session_accept

The agent confirms that it has reserved local capacity for the offered session. The relay waits for this explicit acceptance before considering the v1 rendezvous accepted.

Fields:

- `version`
- `session_id`

### session_reject

The agent rejects an offer before opening the data tunnel.

Fields:

- `version`
- `session_id`
- `reason`: `busy`, `incompatible_version`, or `internal_error`

A full per-agent session pool produces `busy`. An unsupported offer version produces `incompatible_version` rather than being silently ignored.

### session_cancel

The relay tells the agent to abort an accepted session when the acceptance/data-tunnel deadline expires.

Fields:

- `version`
- `session_id`

The agent tracks spawned session tasks by ID and aborts the matching task on cancellation.

## Operator authentication and rendezvous credentials

Operator control authentication currently uses HTTP JSON endpoints around an OpenSSH SSHSIG challenge rather than a control-channel message.

The flow is:

1. request a target-specific challenge;
2. sign the canonical `revtty-control-v1` message with the operator Ed25519 key;
3. submit the SSHSIG;
4. receive a short-lived opaque operator session credential plus the enrolled agent host key;
5. consume that credential once when opening `/v1/probe/{name}` or `/v1/connect/{name}`;
6. the relay generates a separate one-time agent `tunnel_token` and sends the corresponding offer over the agent control channel.

The operator and agent rendezvous credentials are therefore distinct.

`revtty status <name>` reuses this target-scoped authentication flow and consumes the resulting operator session credential once on `GET /v1/status/{name}`. It returns persisted identity/presence metadata plus the relay's current online/offline view without opening a data tunnel.

`revtty list` uses a separate one-time SSHSIG inventory challenge. The client signs the canonical `scope=list` message and sends its Ed25519 public key with the signature. The relay verifies possession of that key and returns only enrolled agents whose authorized operator key has the same SHA-256 SSH fingerprint. The inventory challenge is removed when used, including failed/replayed attempts.

## Data plane

After the operator and agent WebSockets are paired, the relay forwards frames without interpreting the SSH payload.

For an interactive shell:

```text
operator Russh client
        |
        | SSH
        v
operator WSS ===== opaque relay ===== agent WSS
                                      |
                                      | SSH
                                      v
                               agent Russh server
                                      |
                                      v
                                     PTY
```

SSH performs agent host authentication and operator public-key authentication independently of the relay control authorization.

## Implemented invariants

- Terminal bytes never appear in control messages.
- Session credentials are sent in authorization headers, not URL query strings.
- Operator session credentials are target-scoped, short lived and single use.
- Operator inventory challenges are short lived, single use and return only agents authorized for the proven key.
- Agent data-tunnel credentials are per-rendezvous and single use.
- A v1 rendezvous requires explicit agent acceptance before pairing.
- Concurrent probe/shell sessions are bounded by persisted per-agent configuration.
- Agent acceptance and data-tunnel waits have separate deadlines; timeout triggers `session_cancel`.
- A persistent agent control credential cannot open a `/v1/session` data tunnel.
- A pending agent side is paired at most once.
- Operator and agent rendezvous credentials are distinct.
- The relay can route terminal data without understanding the SSH payload.
- Secret-bearing control types do not derive debug formatting.

## Required before the stable v1 protocol

The approved v1 scope still requires the following protocol hardening:

- stronger operator-visible rejection/error propagation;
- persistence/audit metadata for completed sessions;
- a documented compatibility policy for stable releases.

These should extend the existing contract rather than create a second terminal protocol.
