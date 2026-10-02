# Security Policy and Threat Model

revtty is intended for legitimate remote administration of systems the operator is authorized to manage.

## Security model

The target agent makes outbound connections only. No public inbound port is required on the target.

The design separates trust:

- **SSH** protects the operator-to-agent terminal session and authenticates operator keys and the agent host key.
- **TLS/WSS** protects each connection to the relay in transit.
- **The relay** is trusted for availability, identity metadata, presence, and rendezvous, but the CLI data path is designed so the relay does not need plaintext terminal access.

## Baseline requirements

- Ed25519 agent host keys.
- Public-key SSH operator authentication.
- Host-key pinning.
- Single-use, expiring enrollment tokens.
- Single-use, expiring session tunnel tokens.
- Distinct control-plane and SSH credentials.
- No secrets in query strings.
- No terminal data in normal logs.
- No bearer credentials in diagnostic output.
- Restrictive filesystem permissions for local secret material.
- Explicit operator revocation.
- Bounded authentication/session attempts.
- Supported cryptographic algorithms come from maintained SSH/TLS libraries; revtty does not define its own primitives.

## Non-goals

revtty does not attempt to hide itself, evade endpoint controls, bypass authorization, or provide covert persistence. The agent should be installed as a normal visible service by an administrator.

## Web console

A future conventional web terminal changes the trust boundary: if a server-side web gateway terminates the browser session and acts as the SSH client, that gateway can see terminal plaintext. This must be documented explicitly and kept separate from the opaque relay role.

## Reporting a vulnerability

Until a dedicated disclosure channel is published, open a private security advisory in this repository rather than a public issue. Do not include live credentials, private keys, or customer infrastructure details in public reports.
