# revtty Control Protocol

Status: **draft / pre-implementation**

The control protocol coordinates agent presence and session rendezvous. It does not carry terminal bytes. The terminal session uses SSH over an ephemeral data tunnel.

## Envelope

The current scaffold uses tagged JSON messages and an explicit numeric protocol version.

Example:

```json
{
  "type": "heartbeat",
  "version": 1,
  "active_sessions": 0
}
```

## v1 messages

### hello

Sent by the agent after authenticating its control connection.

Fields:

- `version`
- `agent_id`
- `agent_version`

### heartbeat

Periodic liveness update.

Fields:

- `version`
- `active_sessions`

### session_offer

Relay asks an agent to prepare an outbound data tunnel.

Fields:

- `version`
- `session_id`
- `expires_at_unix`
- `tunnel_token`

The tunnel token is secret, short lived, role specific, and single use. It must never be logged.

### session_accept

Agent accepted the offered session.

Fields:

- `version`
- `session_id`

### session_reject

Agent rejected the offered session.

Fields:

- `version`
- `session_id`
- `reason`

The reason must be safe for logs and must not contain secrets.

### session_cancel

The pending session should be abandoned.

Fields:

- `version`
- `session_id`

## Invariants

- Unknown incompatible protocol versions fail explicitly.
- Terminal data never appears in control messages.
- Session credentials are never placed in URL query strings.
- Session credentials expire and are consumed at most once.
- A tunnel side is paired at most once.
- Operator and agent tunnel credentials are distinct.
- The relay may route data without understanding the SSH payload.
- Secrets must be redacted from diagnostic formatting and logs.

This document will become normative as implementation lands. Message changes before the first stable release may still be breaking.
