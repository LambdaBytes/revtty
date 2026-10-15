//! End-to-end flow with the real binary: operator identity, relay, enrolled agent, probe and
//! an interactive `connect` driven through a local PTY.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

const REVTTY: &str = env!("CARGO_BIN_EXE_revtty");
const AGENT_NAME: &str = "e2e-agent";

/// Temporary state for one test; removed on drop.
struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("revtty-e2e-{}", uuid::Uuid::new_v4().simple()));
        // Private like a real deployment: the doctors reject state other users could modify.
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&path).expect("create e2e root");
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A background revtty process, killed on drop, whose stderr is captured.
struct Running {
    child: Child,
    log: Arc<Mutex<String>>,
}

impl Running {
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn revtty process");
        let stderr = child.stderr.take().expect("capture stderr");
        let log = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&log);

        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                let mut log = sink.lock().expect("log lock");
                log.push_str(&line);
                log.push('\n');
            }
        });

        Self { child, log }
    }

    fn log(&self) -> String {
        self.log.lock().expect("log lock").clone()
    }

    fn wait_for_log(&self, pattern: &str, within: Duration) -> String {
        self.wait_for_log_count(pattern, 1, within)
    }

    fn wait_for_log_count(&self, pattern: &str, count: usize, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            let log = self.log();
            if log.matches(pattern).count() >= count {
                return log;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {pattern:?} in log:\n{log}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Environment of one revtty role (operator, agent): its own config and state directories.
struct Role {
    config: PathBuf,
    state: PathBuf,
}

impl Role {
    fn new(root: &TempRoot, name: &str) -> Self {
        Self {
            config: root.path(&format!("{name}/config")),
            state: root.path(&format!("{name}/state")),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(REVTTY);
        command
            .env("REVTTY_CONFIG_DIR", &self.config)
            .env("REVTTY_STATE_DIR", &self.state)
            .env_remove("REVTTY_RELAY")
            .env_remove("REVTTY_DB");
        command
    }

    fn run(&self, args: &[&str]) -> String {
        let output = self
            .command()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run revtty");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "revtty {args:?} failed ({}):\n{stdout}{stderr}",
            output.status
        );
        stdout + &stderr
    }
}

impl Role {
    fn run_failing(&self, args: &[&str]) -> String {
        let output = self
            .command()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run revtty");
        let text = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "revtty {args:?} unexpectedly succeeded:\n{text}"
        );
        text
    }
}

fn field<'a>(output: &'a str, name: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .map(str::trim)
        .unwrap_or_else(|| panic!("missing {name:?} in output:\n{output}"))
}

fn start_relay(root: &TempRoot, relay_role: &Role) -> (Running, String) {
    start_relay_on(root, relay_role, "127.0.0.1:0")
}

fn start_relay_on(root: &TempRoot, relay_role: &Role, bind: &str) -> (Running, String) {
    let db = root.path("relay.db");
    let mut command = relay_role.command();
    command
        .args(["relay", "serve", "--bind", bind, "--db"])
        .arg(&db);
    let relay = Running::spawn(command);

    let log = relay.wait_for_log("listening on ", Duration::from_secs(15));
    let address = log
        .lines()
        .find_map(|line| line.split("listening on ").nth(1))
        .map(str::trim)
        .expect("relay listen address")
        .to_owned();

    (relay, format!("http://{address}"))
}

/// Enrolls the agent and returns its host key fingerprint, as the target prints it.
fn enroll_agent(
    root: &TempRoot,
    relay_role: &Role,
    operator: &Role,
    agent: &Role,
    url: &str,
) -> String {
    enroll_agent_with(root, relay_role, operator, agent, url, &[])
}

fn enroll_agent_with(
    root: &TempRoot,
    relay_role: &Role,
    operator: &Role,
    agent: &Role,
    url: &str,
    extra: &[&str],
) -> String {
    let db = root.path("relay.db");
    let db = db.to_str().expect("utf-8 path");
    let operator_key = operator.config.join("id_ed25519.pub");

    let enrollment = relay_role.run(&[
        "relay",
        "enroll",
        AGENT_NAME,
        "--operator-key",
        operator_key.to_str().expect("utf-8 path"),
        "--db",
        db,
    ]);
    let token = field(&enrollment, "token");

    let mut args = vec!["agent", "enroll", "--relay", url, "--token", token];
    args.extend_from_slice(extra);
    let enrolled = agent.run(&args);
    field(&enrolled, "host").to_owned()
}

fn start_agent(root: &TempRoot, agent: &Role) -> Running {
    let home = root.path("agent/home");
    std::fs::create_dir_all(&home).expect("create agent home");

    let mut command = agent.command();
    command
        .args(["agent", "run"])
        // A predictable login shell that does not read the developer's own profile.
        .env("SHELL", "/bin/sh")
        .env("HOME", &home)
        .env_remove("ENV");
    let running = Running::spawn(command);
    running.wait_for_log("connected to", Duration::from_secs(15));
    running
}

/// Runs `revtty connect` inside a PTY, like an operator's terminal.
struct Terminal {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    writer: Box<dyn Write + Send>,
    output: Arc<Mutex<Vec<u8>>>,
}

impl Terminal {
    fn connect(operator: &Role, url: &str, host_key: Option<&str>) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open operator PTY");

        let mut command = CommandBuilder::new(REVTTY);
        command.args(["connect", AGENT_NAME, "--relay", url]);
        if let Some(host_key) = host_key {
            command.args(["--host-key", host_key]);
        }
        command.env("REVTTY_CONFIG_DIR", &operator.config);
        command.env("REVTTY_STATE_DIR", &operator.state);
        command.env("TERM", "xterm");
        command.env_remove("REVTTY_RELAY");

        let child = pair
            .slave
            .spawn_command(command)
            .expect("spawn revtty connect");
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().expect("PTY reader");
        let writer = pair.master.take_writer().expect("PTY writer");
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&output);

        std::thread::spawn(move || {
            let _master = pair.master;
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                sink.lock()
                    .expect("terminal output lock")
                    .extend_from_slice(&buffer[..read]);
            }
        });

        Self {
            child,
            writer,
            output,
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().expect("terminal output lock")).into_owned()
    }

    fn wait_for(&self, pattern: &str, within: Duration, logs: &[&Running]) {
        let deadline = Instant::now() + within;
        loop {
            let text = self.text();
            if text.contains(pattern) {
                return;
            }
            if Instant::now() >= deadline {
                let logs = logs
                    .iter()
                    .map(|running| running.log())
                    .collect::<Vec<_>>()
                    .join("\n---\n");
                panic!("timed out waiting for {pattern:?}\nterminal:\n{text}\nlogs:\n{logs}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Types a computed marker until the remote shell answers, which also proves the local
    /// terminal is in raw mode and the SSH session is up.
    fn wait_ready(&mut self, within: Duration, logs: &[&Running]) {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            self.send("echo REVTTY_READY_$((2+3))\r");
            let retry = Instant::now() + Duration::from_secs(1);
            while Instant::now() < retry {
                if self.text().contains("REVTTY_READY_5") {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        self.wait_for("REVTTY_READY_5", Duration::ZERO, logs);
    }

    fn send(&mut self, input: &str) {
        self.writer
            .write_all(input.as_bytes())
            .and_then(|()| self.writer.flush())
            .expect("type into operator terminal");
    }

    fn wait_exit(&mut self, within: Duration) -> Option<portable_pty::ExitStatus> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn prepare(root: &TempRoot) -> (Role, Role, Role) {
    let operator = Role::new(root, "operator");
    let agent = Role::new(root, "agent");
    let relay = Role::new(root, "relay");

    operator.run(&["init"]);
    relay.run(&[
        "relay",
        "init",
        "--db",
        root.path("relay.db").to_str().expect("utf-8 path"),
    ]);

    (operator, agent, relay)
}

#[test]
fn operator_connects_to_enrolled_agent_shell() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let agent_process = start_agent(&root, &agent);

    let probe = operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    assert!(
        probe.contains("status   reachable"),
        "unexpected probe output:\n{probe}"
    );

    let mut terminal = Terminal::connect(&operator, &url, None);
    let logs = [&relay, &agent_process];
    terminal.wait_ready(Duration::from_secs(20), &logs);

    // The marker is computed remotely, so the echoed input cannot match it.
    terminal.send("echo REVTTY_E2E_$((6*7)); exit 7\r");
    terminal.wait_for("REVTTY_E2E_42", Duration::from_secs(20), &logs);
    terminal.wait_for("connection closed (exit 7)", Duration::from_secs(20), &logs);

    let status = terminal
        .wait_exit(Duration::from_secs(5))
        .unwrap_or_else(|| {
            panic!(
                "revtty connect kept running after the session closed:\n{}",
                terminal.text()
            )
        });
    assert_eq!(status.exit_code(), 7, "remote exit status not propagated");

    // The relay audited who opened the shell and how it ended.
    let operator_fingerprint = field(&operator.run(&["init"]), "fingerprint").to_owned();
    let db = root.path("relay.db");
    let db = db.to_str().expect("utf-8 path");
    let deadline = Instant::now() + Duration::from_secs(5);
    let audited = loop {
        let sessions = relay_role.run(&["relay", "sessions", "--db", db]);
        let shell = sessions
            .lines()
            .find(|line| line.contains("\tshell\t"))
            .map(str::to_owned);
        if let Some(line) = shell.filter(|line| line.contains("outcome=completed")) {
            break line;
        }
        assert!(
            Instant::now() < deadline,
            "shell session not audited as completed:\n{sessions}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        audited.contains(&format!("operator={operator_fingerprint}")),
        "audit record lacks the operator fingerprint: {audited}"
    );
}

fn process_alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn agent_sigint_reaps_active_shell() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let mut agent_process = start_agent(&root, &agent);

    let mut terminal = Terminal::connect(&operator, &url, Some(&host_key));
    let logs = [&relay, &agent_process];
    terminal.wait_ready(Duration::from_secs(20), &logs);

    // A session leader that ignores SIGHUP and never reads the terminal: only the agent's
    // SIGKILL escalation can end it.
    terminal.send("trap '' HUP; echo PID=$$ END_$((3+4)); exec sleep 60\r");
    terminal.wait_for("END_7", Duration::from_secs(20), &logs);
    let text = terminal.text();
    let start = text.rfind("PID=").expect("shell pid") + "PID=".len();
    let pid: String = text[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    assert!(process_alive(&pid), "remote shell {pid} is not running");

    let agent_pid = agent_process.child.id().to_string();
    let signalled = Command::new("kill")
        .args(["-INT", &agent_pid])
        .status()
        .expect("send SIGINT to agent");
    assert!(signalled.success());

    let deadline = Instant::now() + Duration::from_secs(12);
    let exited = loop {
        if let Ok(Some(status)) = agent_process.child.try_wait() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let shell_alive = process_alive(&pid);
    if shell_alive {
        let _ = Command::new("kill").args(["-9", &pid]).status();
    }
    assert!(
        exited.is_some(),
        "agent did not exit after SIGINT:\n{}",
        agent_process.log()
    );
    assert!(
        !shell_alive,
        "agent exited while its shell {pid} was still running"
    );
}

#[test]
fn agent_recovers_after_relay_restart() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let agent_process = start_agent(&root, &agent);
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);

    // Restart the relay on the same address with the same database.
    let address = url.trim_start_matches("http://").to_owned();
    drop(relay);
    let (relay, restarted_url) = start_relay_on(&root, &relay_role, &address);
    assert_eq!(restarted_url, url);

    agent_process.wait_for_log_count("connected to", 2, Duration::from_secs(30));
    relay.wait_for_log("agent online", Duration::from_secs(10));

    let status = operator.run(&["status", AGENT_NAME, "--relay", &url]);
    assert!(
        status.contains("status    online"),
        "agent not online after relay restart:\n{status}"
    );

    let mut terminal = Terminal::connect(&operator, &url, None);
    let logs = [&relay, &agent_process];
    terminal.wait_ready(Duration::from_secs(20), &logs);
    terminal.send("echo REVTTY_E2E_$((6*7)); exit 7\r");
    terminal.wait_for("REVTTY_E2E_42", Duration::from_secs(20), &logs);
    terminal.wait_for("connection closed (exit 7)", Duration::from_secs(20), &logs);
}

#[test]
fn first_contact_requires_host_key_confirmation() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);
    let known_hosts = operator.config.join("known_hosts");

    // Without a terminal and without --host-key, nothing the relay says gets pinned.
    let refused = operator.run_failing(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(
        refused.contains("not pinned yet") && refused.contains(&host_key),
        "unexpected refusal:\n{refused}"
    );
    assert!(
        !known_hosts.exists(),
        "a host key was pinned without approval"
    );

    let mismatched = operator.run_failing(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        "SHA256:not-the-agent",
    ]);
    assert!(
        mismatched.contains("nothing was pinned"),
        "unexpected mismatch report:\n{mismatched}"
    );
    assert!(!known_hosts.exists(), "a mismatched host key was pinned");

    let probe = operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    assert!(
        probe.contains("status   reachable"),
        "unexpected probe output:\n{probe}"
    );
    assert!(known_hosts.exists());

    // Once pinned, no confirmation is needed.
    operator.run(&["probe", AGENT_NAME, "--relay", &url]);
}

#[test]
fn slow_interactive_host_key_confirmation_still_connects() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let agent_process = start_agent(&root, &agent);

    let mut terminal = Terminal::connect(&operator, &url, None);
    let logs = [&relay, &agent_process];
    terminal.wait_for(
        "Type yes or the fingerprint",
        Duration::from_secs(20),
        &logs,
    );
    assert!(
        terminal.text().contains(&host_key),
        "prompt did not show the agent fingerprint:\n{}",
        terminal.text()
    );

    // Longer than the 30 s operator credential obtained before the prompt.
    std::thread::sleep(Duration::from_secs(32));
    terminal.send("yes\r");

    terminal.wait_ready(Duration::from_secs(20), &logs);
    terminal.send("echo REVTTY_E2E_$((6*7)); exit 7\r");
    terminal.wait_for("REVTTY_E2E_42", Duration::from_secs(20), &logs);
    terminal.wait_for("connection closed (exit 7)", Duration::from_secs(20), &logs);
}

#[test]
fn lost_agent_ends_session_with_unknown_exit_status() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let mut agent_process = start_agent(&root, &agent);

    let mut terminal = Terminal::connect(&operator, &url, Some(&host_key));
    terminal.wait_ready(Duration::from_secs(20), &[&relay, &agent_process]);

    // The agent disappears mid-session: no exit status will ever arrive.
    agent_process.child.kill().expect("kill agent");
    let _ = agent_process.child.wait();

    terminal.wait_for(
        "connection closed (exit status unknown)",
        Duration::from_secs(20),
        &[&relay],
    );
    let status = terminal
        .wait_exit(Duration::from_secs(5))
        .expect("revtty connect exits after losing the agent");
    assert_eq!(status.exit_code(), 255, "a lost session reported success");
}

#[test]
fn doctors_check_authentication_permissions_and_tls() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);

    // After a first pin, as on any real operator machine.
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    let operator_doctor = operator.run(&["doctor", "--relay", &url]);
    assert!(
        operator_doctor.contains("auth       ok (1 agents enrolled for this key)"),
        "operator doctor did not prove authentication:\n{operator_doctor}"
    );

    let agent_doctor = agent.run(&["agent", "doctor"]);
    assert!(
        agent_doctor.contains("credential accepted by the relay"),
        "agent doctor did not check its credential:\n{agent_doctor}"
    );

    let db = root.path("relay.db");
    let relay_doctor =
        relay_role.run(&["relay", "doctor", "--db", db.to_str().expect("utf-8 path")]);
    assert!(
        relay_doctor.contains("schema     v6"),
        "unexpected relay doctor output:\n{relay_doctor}"
    );

    // A control credential readable by other users, or a relay database others could
    // replace through its directory, is reported.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o777))
            .expect("open up the relay directory");
        let replaceable =
            relay_role.run_failing(&["relay", "doctor", "--db", db.to_str().expect("utf-8 path")]);
        assert!(
            replaceable.contains("writable by other users"),
            "writable relay directory not reported:\n{replaceable}"
        );

        // A group-writable directory, as left by the usual umask 002 with user private
        // groups, is reported but does not fail.
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o775))
            .expect("make the relay directory group-writable");
        let shared = relay_role.run(&["relay", "doctor", "--db", db.to_str().expect("utf-8 path")]);
        assert!(
            shared.contains("warning") && shared.contains("writable by its group"),
            "group-writable relay directory not reported:\n{shared}"
        );
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))
            .expect("restore the relay directory");

        let config = agent.config.join("agent.toml");
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644))
            .expect("make agent config readable");
        let exposed = agent.run_failing(&["agent", "doctor"]);
        assert!(
            exposed.contains("accessible by other users"),
            "readable agent config not reported:\n{exposed}"
        );
    }

    // Speaking TLS to a plain-HTTP relay fails with the TLS cause, not just "request failed".
    let tls = operator.run_failing(&["doctor", "--relay", &url.replacen("http://", "https://", 1)]);
    assert!(
        tls.contains("corrupt message") || tls.contains("InvalidContentType"),
        "TLS failure cause not shown:\n{tls}"
    );
}

#[test]
fn busy_agent_is_reported_to_probe() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent_with(
        &root,
        &relay_role,
        &operator,
        &agent,
        &url,
        &["--max-sessions", "1"],
    );
    let agent_process = start_agent(&root, &agent);

    // The only session slot is taken by an open shell.
    let mut terminal = Terminal::connect(&operator, &url, Some(&host_key));
    terminal.wait_ready(Duration::from_secs(20), &[&relay, &agent_process]);

    let refused = operator.run_failing(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(
        refused.contains("agent is busy"),
        "busy agent not reported to probe:\n{refused}"
    );
}

#[test]
fn operators_are_managed_from_a_session_and_revocation_closes_it() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let second = Role::new(&root, "second");
    let second_fingerprint = field(&second.run(&["init"]), "fingerprint").to_owned();
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let agent_process = start_agent(&root, &agent);
    let logs = [&relay, &agent_process];

    // The target's administrator authorizes a second operator; the running agent picks it up
    // and tells the relay.
    let second_key = second.config.join("id_ed25519.pub");
    let added = agent.run(&[
        "agent",
        "operator",
        "add",
        second_key.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(field(&added, "added"), second_fingerprint);
    agent_process.wait_for_log("operator list revision 2", Duration::from_secs(10));
    relay.wait_for_log("operators updated to revision 2", Duration::from_secs(10));

    let mut terminal = Terminal::connect(&second, &url, Some(&host_key));
    terminal.wait_ready(Duration::from_secs(20), &logs);

    // Inside the agent's own shell, revtty manages the agent it runs under.
    terminal.send(&format!("{REVTTY} agent operator list\r"));
    terminal.wait_for(
        &format!("operator   {second_fingerprint}"),
        Duration::from_secs(10),
        &logs,
    );

    // An operator revoking itself: the change is written, then its session is closed.
    terminal.send(&format!(
        "{REVTTY} agent operator revoke {second_fingerprint}\r"
    ));
    terminal.wait_for(
        &format!("revoked    {second_fingerprint}"),
        Duration::from_secs(10),
        &logs,
    );
    let started = Instant::now();
    let status = terminal
        .wait_exit(Duration::from_secs(10))
        .unwrap_or_else(|| {
            panic!(
                "session of a revoked operator stayed open:\n{}",
                terminal.text()
            )
        });
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "revocation took {:?}",
        started.elapsed()
    );
    assert_ne!(
        status.exit_code(),
        0,
        "a revoked session ended as a success"
    );
    agent_process.wait_for_log("was revoked; closing its session", Duration::from_secs(5));

    // The relay no longer issues it credentials, and the agent would refuse it anyway.
    relay.wait_for_log("operators updated to revision 3", Duration::from_secs(10));
    let refused = second.run_failing(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(
        refused.contains("401"),
        "revoked operator still authenticated:\n{refused}"
    );

    // The enrolled operator still connects, and cannot leave the agent without operators.
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    let first_fingerprint = field(&operator.run(&["init"]), "fingerprint").to_owned();
    let last = agent.run_failing(&["agent", "operator", "revoke", &first_fingerprint]);
    assert!(
        last.contains("last operator"),
        "last operator revoked:\n{last}"
    );
}

#[test]
fn reinstalled_agent_is_reenrolled_in_place_and_then_removed() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let old_agent = start_agent(&root, &agent);
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);

    let db = root.path("relay.db");
    let db = db.to_str().expect("utf-8 path");
    let operator_key = operator.config.join("id_ed25519.pub");
    let operator_key = operator_key.to_str().expect("utf-8 path");

    // An enrolled name is not taken over by accident.
    let refused = relay_role.run_failing(&[
        "relay",
        "enroll",
        AGENT_NAME,
        "--operator-key",
        operator_key,
        "--db",
        db,
    ]);
    assert!(refused.contains("--replace"), "{refused}");

    // The machine is reinstalled: a new agent identity takes the old one's place.
    let reinstalled = Role::new(&root, "reinstalled");
    let enrollment = relay_role.run(&[
        "relay",
        "enroll",
        AGENT_NAME,
        "--operator-key",
        operator_key,
        "--replace",
        "--db",
        db,
    ]);
    let token = field(&enrollment, "token");
    let enrolled = reinstalled.run(&["agent", "enroll", "--relay", &url, "--token", token]);
    let new_host_key = field(&enrolled, "host").to_owned();
    assert_ne!(new_host_key, host_key);

    // The relay closes the old agent's connection, and its credential is gone: the
    // reconnection after that is refused.
    relay.wait_for_log(
        "was removed or re-enrolled; closing its control connection",
        Duration::from_secs(10),
    );
    let log = old_agent.wait_for_log_count("control connection lost", 2, Duration::from_secs(20));
    assert!(
        log.contains("websocket upgrade failed"),
        "old agent reconnected:\n{log}"
    );
    drop(old_agent);
    let doctor = agent.run_failing(&["agent", "doctor"]);
    assert!(
        doctor.contains("rejected this agent's credential"),
        "old agent's credential still accepted:\n{doctor}"
    );
    let new_agent = start_agent(&root, &reinstalled);

    // The pin is the old machine's: a hard failure that says how to recover.
    let mismatch = operator.run_failing(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(
        mismatch.contains("HOST KEY MISMATCH") && mismatch.contains("revtty forget"),
        "{mismatch}"
    );
    let forgotten = operator.run(&["forget", AGENT_NAME, "--relay", &url]);
    assert!(forgotten.contains("forgotten"), "{forgotten}");
    let probe = operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &new_host_key,
    ]);
    assert!(probe.contains("status   reachable"), "{probe}");

    // Removed, the agent loses its connection and is gone for its operators.
    let removed = relay_role.run(&["relay", "remove", AGENT_NAME, "--db", db]);
    assert!(removed.contains("removed"), "{removed}");
    relay.wait_for_log_count(
        "was removed or re-enrolled; closing its control connection",
        2,
        Duration::from_secs(10),
    );
    let gone = operator.run_failing(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(gone.contains("401"), "{gone}");
    drop(new_agent);
}

#[test]
fn control_credential_rotates_while_the_agent_is_stopped() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let agent_process = start_agent(&root, &agent);
    let token_before = std::fs::read_to_string(agent.config.join("agent.toml"))
        .expect("read agent config")
        .lines()
        .find(|line| line.starts_with("control_token"))
        .expect("control token line")
        .to_owned();

    // A running agent keeps its credential, and only one agent runs per configuration.
    let refused = agent.run_failing(&["agent", "rotate-credential"]);
    assert!(refused.contains("the agent is running"), "{refused}");
    let second = agent.run_failing(&["agent", "run"]);
    assert!(second.contains("another `revtty agent run`"), "{second}");

    drop(agent_process);
    let rotated = agent.run(&["agent", "rotate-credential"]);
    assert!(rotated.contains("credential rotated"), "{rotated}");
    relay.wait_for_log("rotated its control credential", Duration::from_secs(5));
    let token_after = std::fs::read_to_string(agent.config.join("agent.toml"))
        .expect("read agent config")
        .lines()
        .find(|line| line.starts_with("control_token"))
        .expect("control token line")
        .to_owned();
    assert_ne!(token_after, token_before);

    // The agent comes back with the new credential.
    let _agent_process = start_agent(&root, &agent);
    let doctor = agent.run(&["agent", "doctor"]);
    assert!(
        doctor.contains("credential accepted by the relay"),
        "{doctor}"
    );
    let probe = operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    assert!(probe.contains("status   reachable"), "{probe}");
}

#[test]
fn agent_run_finishes_an_interrupted_rotation_before_connecting() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);

    // A rotation interrupted before the relay heard of its credential.
    let config_path = agent.config.join("agent.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("read agent config");
    config.push_str("pending_control_token = \"rva_never_sent\"\n");
    std::fs::write(&config_path, config).expect("leave a pending rotation");
    let doctor = agent.run_failing(&["agent", "doctor"]);
    assert!(doctor.contains("rotation was interrupted"), "{doctor}");

    let agent_process = start_agent(&root, &agent);
    let config = std::fs::read_to_string(&config_path).expect("read agent config");
    assert!(
        !config.contains("pending_control_token"),
        "pending rotation left in place:\n{config}"
    );
    let probe = operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    assert!(probe.contains("status   reachable"), "{probe}");
    drop(agent_process);
    drop(relay);
}
