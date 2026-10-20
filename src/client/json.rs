//! What `--json` prints: the CLI's contract with scripts, kept apart from the relay's
//! responses so that a change there does not change it. Every field is always there, `null`
//! when it does not apply; times are Unix seconds.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;

use super::ssh::{Captured, CommandEnd, Stop};
use crate::error::RevttyError;
use crate::protocol::{AgentStatusResponse, ProbeResult};

#[derive(Serialize)]
struct ListedAgent<'a> {
    name: &'a str,
    online: bool,
    active_sessions: usize,
    max_sessions: Option<usize>,
    last_seen: Option<i64>,
    version: Option<&'a str>,
}

#[derive(Serialize)]
struct AgentStatus<'a> {
    id: &'a str,
    name: &'a str,
    online: bool,
    active_sessions: usize,
    max_sessions: Option<usize>,
    created_at: i64,
    last_seen: Option<i64>,
    version: Option<&'a str>,
}

#[derive(Serialize)]
struct Probe<'a> {
    name: &'a str,
    /// Always true: a probe that does not get through is an error, with no JSON.
    reachable: bool,
    os: &'a str,
    arch: &'a str,
    version: &'a str,
}

#[derive(Serialize)]
struct ExecResult<'a> {
    target: &'a str,
    exit_status: Option<u32>,
    /// The SSH name of the signal that killed the command, such as `TERM`.
    exit_signal: Option<&'a str>,
    timed_out: bool,
    interrupted: bool,
    stdout: Option<&'a str>,
    stdout_base64: Option<String>,
    stdout_truncated: bool,
    stderr: Option<&'a str>,
    stderr_base64: Option<String>,
    stderr_truncated: bool,
}

pub fn agents(agents: &[AgentStatusResponse]) -> Result<String, RevttyError> {
    let agents: Vec<_> = agents
        .iter()
        .map(|agent| ListedAgent {
            name: &agent.name,
            online: agent.online,
            active_sessions: agent.active_sessions,
            max_sessions: agent.max_sessions,
            last_seen: agent.last_seen,
            version: agent.version.as_deref(),
        })
        .collect();
    encode(&agents)
}

pub fn status(status: &AgentStatusResponse) -> Result<String, RevttyError> {
    encode(&AgentStatus {
        id: &status.id,
        name: &status.name,
        online: status.online,
        active_sessions: status.active_sessions,
        max_sessions: status.max_sessions,
        created_at: status.created_at,
        last_seen: status.last_seen,
        version: status.version.as_deref(),
    })
}

pub fn probe(result: &ProbeResult) -> Result<String, RevttyError> {
    encode(&Probe {
        name: &result.name,
        reachable: true,
        os: &result.os,
        arch: &result.arch,
        version: &result.version,
    })
}

pub fn exec(
    target: &str,
    end: &CommandEnd,
    stdout: &Captured,
    stderr: &Captured,
) -> Result<String, RevttyError> {
    let (exit_status, exit_signal) = match end {
        CommandEnd::Exited(status) => (Some(*status), None),
        CommandEnd::Killed(signal) => (None, Some(signal.as_str())),
        CommandEnd::Unknown | CommandEnd::Stopped(_) => (None, None),
    };
    let (stdout_text, stdout_base64) = stream(stdout);
    let (stderr_text, stderr_base64) = stream(stderr);

    encode(&ExecResult {
        target,
        exit_status,
        exit_signal,
        timed_out: matches!(end, CommandEnd::Stopped(Stop::TimedOut)),
        interrupted: matches!(end, CommandEnd::Stopped(Stop::Interrupted)),
        stdout: stdout_text,
        stdout_base64,
        stdout_truncated: stdout.truncated,
        stderr: stderr_text,
        stderr_base64,
        stderr_truncated: stderr.truncated,
    })
}

/// A stream as UTF-8 text, or else as standard base64; the other one is `None`. A stream that
/// the capture limit cut within a character comes in base64 too: the bytes that would say
/// whether it was one were dropped.
fn stream(captured: &Captured) -> (Option<&str>, Option<String>) {
    match std::str::from_utf8(&captured.bytes) {
        Ok(text) => (Some(text), None),
        Err(_) => (None, Some(STANDARD.encode(&captured.bytes))),
    }
}

fn encode(value: &impl Serialize) -> Result<String, RevttyError> {
    serde_json::to_string(value).map_err(|error| RevttyError::runtime("encode JSON output", error))
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::{Value, json};

    use super::exec;
    use crate::client::ssh::{CAPTURE_LIMIT, Captured, CommandEnd, Stop};

    fn captured(bytes: &[u8], truncated: bool) -> Captured {
        Captured {
            bytes: bytes.to_vec(),
            truncated,
        }
    }

    fn exec_value(end: &CommandEnd, stdout: &Captured, stderr: &Captured) -> Value {
        let encoded = exec("demo", end, stdout, stderr).expect("encode exec result");
        serde_json::from_str(&encoded).expect("exec result is JSON")
    }

    #[test]
    fn an_exec_result_has_every_field_with_null_where_it_does_not_apply() {
        let value = exec_value(
            &CommandEnd::Exited(7),
            &captured(b"out\n", false),
            &captured(b"", false),
        );
        assert_eq!(
            value,
            json!({
                "target": "demo",
                "exit_status": 7,
                "exit_signal": null,
                "timed_out": false,
                "interrupted": false,
                "stdout": "out\n",
                "stdout_base64": null,
                "stdout_truncated": false,
                "stderr": "",
                "stderr_base64": null,
                "stderr_truncated": false,
            })
        );

        let killed = exec_value(
            &CommandEnd::Killed("TERM".to_owned()),
            &captured(b"", false),
            &captured(b"", false),
        );
        assert_eq!(killed["exit_status"], Value::Null);
        assert_eq!(killed["exit_signal"], "TERM");

        let timed_out = exec_value(
            &CommandEnd::Stopped(Stop::TimedOut),
            &captured(b"partial", false),
            &captured(b"", false),
        );
        assert_eq!(timed_out["exit_status"], Value::Null);
        assert_eq!(timed_out["timed_out"], true);
        assert_eq!(timed_out["interrupted"], false);
        assert_eq!(timed_out["stdout"], "partial");

        let interrupted = exec_value(
            &CommandEnd::Stopped(Stop::Interrupted),
            &captured(b"", false),
            &captured(b"", false),
        );
        assert_eq!(interrupted["timed_out"], false);
        assert_eq!(interrupted["interrupted"], true);
    }

    #[test]
    fn output_that_is_not_utf8_comes_in_base64_and_decodes_exactly() {
        let bytes = [b'o', b'k', 0xff, 0xfe, 0x00, b'\n'];
        let value = exec_value(
            &CommandEnd::Exited(0),
            &captured(&bytes, false),
            &captured("ñ\n".as_bytes(), false),
        );
        assert_eq!(value["stdout"], Value::Null);
        let decoded = STANDARD
            .decode(value["stdout_base64"].as_str().expect("stdout in base64"))
            .expect("standard base64");
        assert_eq!(decoded, bytes);
        assert_eq!(value["stderr"], "ñ\n");
        assert_eq!(value["stderr_base64"], Value::Null);

        // A stream that ends within a character is not text either.
        let cut = &"añ".as_bytes()[..2];
        let ended = exec_value(
            &CommandEnd::Exited(0),
            &captured(cut, false),
            &captured(b"", false),
        );
        assert_eq!(ended["stdout"], Value::Null);
        assert!(ended["stdout_base64"].is_string());
    }

    #[test]
    fn a_capture_cut_within_a_character_comes_whole_in_base64() {
        // Kept the same from text that goes on with "ñ" and from bytes that go on with
        // C3 FF, which is not UTF-8: the byte after the cut, which tells them apart, was
        // dropped.
        let mut bytes = vec![b'a'; CAPTURE_LIMIT - 1];
        bytes.push(0xc3);
        let value = exec_value(
            &CommandEnd::Exited(0),
            &captured(&bytes, true),
            &captured(b"", false),
        );
        assert_eq!(value["stdout"], Value::Null);
        assert_eq!(value["stdout_truncated"], true);
        let decoded = STANDARD
            .decode(value["stdout_base64"].as_str().expect("stdout in base64"))
            .expect("standard base64");
        assert_eq!(decoded, bytes);
    }
}
