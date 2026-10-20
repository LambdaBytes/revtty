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

Relay asks the agent to open the data side of a probe rendezvous. The agent serves SSH on it, as for a shell, and answers only `exec revtty-probe`: a `ProbeResult` in JSON (`name`, `os`, `arch`, `version`) on the channel, exit status 0, then EOF and close. A PTY, a shell or any other command is refused, and the session ends after 45 s at most. The operator hangs up once it has the answer.

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

### exec_offer

Relay asks the agent to open the data side of an SSH rendezvous for one command (`revtty exec`). The agent serves SSH on it and runs the one `exec` request of its session channel with the agent account's shell and `-c`, in that account's home directory, without a PTY: the command's stdout goes as channel data, its stderr as extended data of type 1, and the operator's data to its stdin, which the operator's EOF closes. Once the command exits, the agent forwards the rest of its output, leaving a pipe that stays silent for 1 s (a background job may hold it open), then sends `exit-status` or `exit-signal`, EOF and close. A PTY, a shell, a second `exec` or anything else is refused. When the session ends first, the agent ends the command's process group (SIGTERM, then SIGKILL within 5 s). The command travels only inside SSH: the relay never sees it and audits the session as `exec`.

Fields:

- `version`
- `session_id`
- `tunnel_token`

An agent that predates this message cannot decode it and ignores it, so the relay ends the session at its acceptance deadline ("agent did not accept the session before timeout").

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

The agent tracks its session tasks by ID. On cancellation the matching task stops opening the session's data tunnel or, once it is open, closes it and waits up to 5 s for the SSH session to end, before it gives the session slot back.

### operators_report

The agent tells the relay which operator keys it accepts: right after `hello`, and whenever its operator list in `agent.toml` changes.

Fields:

- `version`
- `revision`: the list's revision in `agent.toml`
- `operators`: OpenSSH Ed25519 public keys, without their comments (at most 64)

The relay stores a report only when it comes from the agent's current control connection, which the relay records in its database when the connection registers; whatever its revision, that report is what the agent enforces (an `agent.toml` restored from a backup goes back in revisions). A report that arrives on a replaced connection, or that the relay cannot store, closes that control connection: the agent reconnects and reports its list again. A report with an empty list or an unusable key is ignored whole. Relays that predate this message ignore it, and agents that never send it keep the operator they were enrolled for.

The relay uses the list only to decide whom it issues operator session credentials to. SSH authentication on the agent enforces the agent's own list, so a relay that adds a key to its copy gains no shell.

## Operator authentication and rendezvous credentials

Operator control authentication currently uses HTTP JSON endpoints around an OpenSSH SSHSIG challenge rather than a control-channel message.

The flow is:

1. request a target-specific challenge;
2. sign the canonical `revtty-control-v1` message with the operator Ed25519 key;
3. submit the SSHSIG;
4. receive a short-lived opaque operator session credential plus the enrolled agent host key; the relay takes the key from the signature and accepts it only if it is one of the agent's reported operators;
5. consume that credential once when opening `/v1/probe/{name}`, `/v1/connect/{name}` or `/v1/exec/{name}`; it is refused if the operator was revoked, or the agent re-enrolled, in between (a relay that predates exec answers `/v1/exec/{name}` with a 404 and an empty body);
6. the relay generates a separate one-time agent `tunnel_token` and sends the corresponding offer over the agent control channel.

The operator and agent rendezvous credentials are therefore distinct.

`revtty status <name>` reuses this target-scoped authentication flow and consumes the resulting operator session credential once on `GET /v1/status/{name}`. It returns persisted identity/presence metadata plus the relay's current online/offline view without opening a data tunnel.

`revtty list` uses a separate one-time SSHSIG inventory challenge. The client signs the canonical `scope=list` message and sends its Ed25519 public key with the signature. The relay verifies possession of that key and returns only enrolled agents whose reported operators include its SHA-256 SSH fingerprint. The inventory challenge is removed when used, including failed/replayed attempts.

## Pairing codes

A pairing code lets the relay take part in enrollment without being able to choose the agent's first operator or the host key that operator pins.

1. The relay administrator creates the enrollment as usual (`relay enroll NAME --operator-key FILE`) and hands the token to that operator.
2. Without contacting anything, the operator runs `revtty pair NAME --token TOKEN --relay URL`: it generates a secret S, 32 random bytes written `rvk_` plus their base64url, keeps it in its `pairings` file under the key of `(relay, NAME)`, and prints the code `rvp1.TOKEN.S.TAG`, where `TAG = HMAC-SHA256(S, "revtty pairing operator v1\0" ‖ NAME ‖ "\0" ‖ operator fingerprint)`.
3. On the target, `agent enroll --pairing-code CODE` sends `POST /v1/enroll` with only TOKEN and `host_key_proof = HMAC-SHA256(S, "revtty pairing host-key v1\0" ‖ host key fingerprint)`. Before saving anything it checks TAG against the `name` and the fingerprint of `operator_key` in the answer.
4. The relay checks only that the proof is base64url of 32 bytes, stores it with the agent instance (`agents.host_key_proof`, schema v7) and returns it in the operator authentication answer as `host_key_proof`.
5. At the first `status`, `probe` or `connect`, when the presented key is not the pinned one and a pairing is pending for `(relay, NAME)`, the client pins the key only if the proof verifies under S, replacing a previous pin, and removes the pairing first. Otherwise, and when no proof comes, it pins nothing and changes no file.

Fingerprints are OpenSSH SHA-256 fingerprints as printed (`SHA256:` and unpadded base64); MACs are unpadded base64url. S is used once: pinning with it, a new `pair` for the same agent, an explicit approval (`--host-key` or the prompt, even of the key already pinned) and `forget` all remove it, so a proof the relay held back cannot override a decision the operator made later.

Both fields are optional and left out when absent. A relay that predates them ignores the request field and sends no proof, which the client reports and answers by asking for `--host-key`; a client that predates them ignores the answer field and asks for the fingerprint as before. A revtty that predates `--pairing-code` refuses the flag, but one given the code as `--token` would send S to the relay.

## Agent credential rotation

The agent replaces its control credential in two HTTP steps, while it is stopped:

1. it generates the new credential and saves it as pending in `agent.toml`;
2. `POST /v1/agent/{name}/rotate` with the current credential as bearer and `{"next_hash": ...}`, the base64url SHA-256 of the new credential: the relay records it, and keeps accepting the current one;
3. `POST /v1/agent/{name}/rotate/confirm` with the new credential as bearer: the relay makes it the control credential, after which the old one is refused. Confirming with the credential that is already current answers 204 again, so a lost answer can be retried;
4. the agent makes the new credential its own.

An agent that finds a pending credential, at its next start or rotation, confirms it: 204 finishes the rotation, 401 abandons it once the current credential is still accepted (`/check`), and 404 or 405, from a relay without rotation, abandons it.

## Operator-visible rendezvous failures

Before SSH starts, the relay may send one control text frame on the operator data WebSocket using the reserved `revtty-error:` prefix. The byte-stream adapter converts that frame into a local error instead of feeding it into SSH.

Current errors cover:

- agent concurrency limit reached;
- incompatible offer version;
- agent-side startup failure;
- agent acceptance timeout;
- accepted session whose data tunnel never arrives.

Once SSH traffic begins, session payload remains binary and opaque to the relay.

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

A probe takes the same path; the agent's SSH server answers `revtty-probe` instead of starting a PTY.

In either kind of session the agent refuses, with a channel failure, `exec` of any other command, `subsystem`, `env` and `x11-req`, and closes the session if the operator has not authenticated within 45 s of its start.

SSH performs agent host authentication and operator public-key authentication independently of the relay control authorization.

## Implemented invariants

- Terminal bytes never appear in control messages.
- Session credentials are sent in authorization headers, not URL query strings.
- Operator session credentials are target-scoped, short lived and single use.
- Operator inventory challenges are short lived, single use and return only agents authorized for the proven key.
- Agent data-tunnel credentials are per-rendezvous and single use.
- A v1 rendezvous requires explicit agent acceptance before pairing.
- Concurrent probe/shell sessions are bounded by persisted per-agent configuration; a session whose operator has not authenticated over SSH is closed 45 s after its start and gives its slot back within 5 s more.
- Agent acceptance and data-tunnel waits have separate deadlines; timeout triggers `session_cancel`.
- A persistent agent control credential cannot open a `/v1/session` data tunnel.
- A pending agent side is paired at most once.
- Operator and agent rendezvous credentials are distinct.
- The relay keeps an agent's operator list only as the agent reported it on its current control connection; SSH access is decided by the agent's own list.
- A pairing secret never reaches the relay; with a pairing code the agent keeps no operator the code was not made for, and the operator pins no host key the agent did not prove.
- Operator session credentials, control connections and sessions belong to one enrolled agent instance; when it is removed or re-enrolled, the relay closes them within its removal sweep (5 s), data tunnels included.
- The relay can route terminal data without understanding the SSH payload.
- A probe answer counts only over SSH, from the pinned host key, to an operator on the agent's own list; an answer in a text frame is refused.
- A relay stopping on SIGINT or SIGTERM admits no new connection, ends every session as `interrupted` and writes its audit records before it exits, within 5 s.
- Secret-bearing control types do not derive debug formatting.

## Required before the stable v1 protocol

The approved v1 scope still requires the following protocol hardening:

- persistence/audit metadata for completed sessions;
- a documented compatibility policy for stable releases.

These should extend the existing contract rather than create a second terminal protocol.
