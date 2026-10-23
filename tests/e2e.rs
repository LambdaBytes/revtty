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
    reader: Option<std::thread::JoinHandle<()>>,
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

        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                let mut log = sink.lock().expect("log lock");
                log.push_str(&line);
                log.push('\n');
            }
        });

        Self {
            child,
            log,
            reader: Some(reader),
        }
    }

    /// Stops the process with SIGTERM and returns all it logged, up to its end of stderr.
    fn terminate(mut self, within: Duration) -> String {
        let signalled = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("send SIGTERM");
        assert!(signalled.success());
        let deadline = Instant::now() + within;
        while self.child.try_wait().expect("poll process").is_none() {
            assert!(
                Instant::now() < deadline,
                "process did not stop within {within:?} of SIGTERM:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        if let Some(reader) = self.reader.take() {
            reader.join().expect("log reader");
        }
        self.log()
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
    /// `RUST_LOG` for what this role runs; without one, the developer's own does not apply.
    log_filter: Option<&'static str>,
}

impl Role {
    fn new(root: &TempRoot, name: &str) -> Self {
        Self {
            config: root.path(&format!("{name}/config")),
            state: root.path(&format!("{name}/state")),
            log_filter: None,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(REVTTY);
        command
            .env("REVTTY_CONFIG_DIR", &self.config)
            .env("REVTTY_STATE_DIR", &self.state)
            .env_remove("REVTTY_RELAY")
            .env_remove("REVTTY_DB");
        match self.log_filter {
            Some(filter) => command.env("RUST_LOG", filter),
            None => command.env_remove("RUST_LOG"),
        };
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

/// A plain-HTTP server on loopback that answers every request with a 307 to `location`,
/// after reading it whole so that the client sees the answer rather than a reset.
fn redirecting_server(location: &str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind redirecting server");
    let address = listener.local_addr().expect("redirecting server address");
    let location = location.to_owned();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().expect("clone redirect stream"));
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; length];
            let _ = reader.read_exact(&mut body);
            let _ = write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });

    format!("http://{address}")
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
        let mut args = vec!["connect", AGENT_NAME, "--relay", url];
        if let Some(host_key) = host_key {
            args.extend(["--host-key", host_key]);
        }
        Self::spawn(operator, &args)
    }

    /// Runs `revtty` with `args` in the PTY.
    fn spawn(operator: &Role, args: &[&str]) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open operator PTY");

        let mut command = CommandBuilder::new(REVTTY);
        command.args(args);
        command.env("REVTTY_CONFIG_DIR", &operator.config);
        command.env("REVTTY_STATE_DIR", &operator.state);
        command.env("TERM", "xterm");
        command.env_remove("REVTTY_RELAY");

        let child = pair
            .slave
            .spawn_command(command)
            .expect("spawn revtty in a PTY");
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
    stopping_the_agent_reaps_its_active_shell("INT");
}

/// launchd stops a service with SIGTERM, and so does systemd without `KillSignal=SIGINT`.
#[test]
fn agent_sigterm_reaps_active_shell() {
    stopping_the_agent_reaps_its_active_shell("TERM");
}

#[test]
fn agent_sigterm_during_a_reconnect_wait_stops_it_at_once() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let mut agent_process = start_agent(&root, &agent);
    agent_process.wait_for_log("connected to", Duration::from_secs(20));

    // With the relay gone the waits double: the third is 3.2 to 4 s long.
    drop(relay);
    agent_process.wait_for_log_count("reconnecting in", 3, Duration::from_secs(20));
    let agent_pid = agent_process.child.id().to_string();
    let signalled = Command::new("kill")
        .args(["-TERM", &agent_pid])
        .status()
        .expect("signal the agent");
    assert!(signalled.success());

    let deadline = Instant::now() + Duration::from_millis(1500);
    let exited = loop {
        if let Ok(Some(status)) = agent_process.child.try_wait() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let Some(status) = exited else {
        panic!(
            "agent finished its reconnect wait before it stopped:\n{}",
            agent_process.log()
        );
    };
    assert!(
        status.success(),
        "agent exited with {status} after SIGTERM:\n{}",
        agent_process.log()
    );
}

fn stopping_the_agent_reaps_its_active_shell(signal: &str) {
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
        .args([&format!("-{signal}"), &agent_pid])
        .status()
        .expect("signal the agent");
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
    let Some(status) = exited else {
        panic!(
            "agent did not exit after SIG{signal}:\n{}",
            agent_process.log()
        );
    };
    assert!(
        status.success(),
        "agent exited with {status} after SIG{signal}:\n{}",
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
fn relay_stops_on_sigterm_and_audits_the_sessions_it_ends() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (mut relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let agent_process = start_agent(&root, &agent);

    let mut terminal = Terminal::connect(&operator, &url, Some(&host_key));
    terminal.wait_ready(Duration::from_secs(20), &[&relay, &agent_process]);

    // `systemctl stop` sends SIGTERM.
    let relay_pid = relay.child.id().to_string();
    let signalled = Command::new("kill")
        .args(["-TERM", &relay_pid])
        .status()
        .expect("send SIGTERM to relay");
    assert!(signalled.success());

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Ok(Some(status)) = relay.child.try_wait() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "relay did not stop within 5 s of SIGTERM:\n{}",
            relay.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        status.success(),
        "relay exited with {status} after SIGTERM:\n{}",
        relay.log()
    );

    let ended = terminal
        .wait_exit(Duration::from_secs(10))
        .expect("revtty connect kept running after the relay stopped");
    assert_eq!(ended.exit_code(), 255);

    // Recorded by the relay that ended the session, not left open for its next start.
    let db = root.path("relay.db");
    let sessions = relay_role.run(&[
        "relay",
        "sessions",
        "--db",
        db.to_str().expect("utf-8 path"),
    ]);
    let shell = sessions
        .lines()
        .find(|line| line.contains("\tshell\t"))
        .unwrap_or_else(|| panic!("no shell session audited:\n{sessions}"));
    assert!(
        shell.contains("outcome=interrupted") && !shell.contains("ended=-"),
        "shell session not closed by the stopping relay: {shell}"
    );
}

#[test]
fn first_contact_requires_host_key_confirmation() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);
    let known_hosts = operator.config.join("known_hosts");

    // Without a terminal and without --host-key, nothing the relay says gets pinned, nor is
    // its fingerprint offered for copying: it must come from the target.
    let refused = operator.run_failing(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(
        refused.contains("not pinned yet") && !refused.contains(&host_key),
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
        mismatched.contains("nothing was pinned") && !mismatched.contains(&host_key),
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

    // Once pinned, no confirmation is needed; a --host-key is still checked against the key
    // presented, since the operator obtained it independently.
    operator.run(&["probe", AGENT_NAME, "--relay", &url]);
    let contradicted = operator.run_failing(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        "SHA256:not-the-agent",
    ]);
    assert!(
        contradicted.contains("does not match --host-key"),
        "a contradicting --host-key was ignored:\n{contradicted}"
    );
}

#[test]
fn interactive_confirmation_needs_the_fingerprint_from_the_target() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let agent_process = start_agent(&root, &agent);
    let logs = [&relay, &agent_process];
    let known_hosts = operator.config.join("known_hosts");

    for answer in ["yes", "SHA256:not-the-agent"] {
        let mut terminal = Terminal::connect(&operator, &url, None);
        terminal.wait_for(
            "enter the host key fingerprint",
            Duration::from_secs(20),
            &logs,
        );
        assert!(
            !terminal.text().contains(&host_key),
            "prompt offered the relay's fingerprint:\n{}",
            terminal.text()
        );
        terminal.send(&format!("{answer}\r"));
        terminal.wait_for("nothing was pinned", Duration::from_secs(20), &logs);
        let status = terminal
            .wait_exit(Duration::from_secs(5))
            .expect("revtty connect exits after a refused confirmation");
        assert_ne!(status.exit_code(), 0, "{answer:?} was accepted");
        assert!(!known_hosts.exists(), "{answer:?} pinned the host key");
    }
}

#[test]
fn a_host_key_swapped_during_interactive_confirmation_is_refused() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let agent_process = start_agent(&root, &agent);
    let logs = [&relay, &agent_process];

    let mut terminal = Terminal::connect(&operator, &url, None);
    terminal.wait_for(
        "enter the host key fingerprint",
        Duration::from_secs(20),
        &logs,
    );

    // While the operator compares fingerprints, the relay starts presenting another key: the
    // credential renewed after the confirmation must be for the key confirmed, whatever the
    // pin file says by then.
    let other_key =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("other host key")
            .public_key()
            .to_openssh()
            .expect("encode other host key");
    let db = tokio_rusqlite::rusqlite::Connection::open(root.path("relay.db"))
        .expect("open relay database");
    db.busy_timeout(Duration::from_secs(5))
        .expect("wait for the relay's writes");
    db.execute(
        "UPDATE agents SET host_key = ?1 WHERE name = ?2",
        tokio_rusqlite::rusqlite::params![other_key, AGENT_NAME],
    )
    .expect("swap the presented host key");

    terminal.send(&format!("{host_key}\r"));
    terminal.wait_for("after it was confirmed", Duration::from_secs(20), &logs);
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
        "enter the host key fingerprint",
        Duration::from_secs(20),
        &logs,
    );

    // Longer than the 30 s operator credential obtained before the prompt.
    std::thread::sleep(Duration::from_secs(32));
    terminal.send(&format!("{host_key}\r"));

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

    // After a first pin, as on any real operator machine, and with a pairing not used yet.
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    operator.run(&[
        "pair",
        "other-machine",
        "--token",
        "rve_unused",
        "--relay",
        &url,
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
        relay_doctor.contains("schema     v7"),
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

        // Whoever reads a pairing's secret can forge the proof that pins a host key with it.
        let pairings = operator.config.join("pairings");
        std::fs::set_permissions(&pairings, std::fs::Permissions::from_mode(0o644))
            .expect("make pairings readable");
        let readable = operator.run_failing(&["doctor", "--relay", &url]);
        assert!(
            readable.contains("accessible by other users"),
            "readable pairings not reported:\n{readable}"
        );
        std::fs::set_permissions(&pairings, std::fs::Permissions::from_mode(0o600))
            .expect("restore pairings");
    }

    // Speaking TLS to a plain-HTTP relay fails with the TLS cause, not just "request failed".
    let tls = operator.run_failing(&["doctor", "--relay", &url.replacen("http://", "https://", 1)]);
    assert!(
        tls.contains("corrupt message") || tls.contains("InvalidContentType"),
        "TLS failure cause not shown:\n{tls}"
    );
}

#[test]
fn unencrypted_relays_are_refused_off_loopback() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    // A `.invalid` name never resolves, so nothing reaches the network even without the check.
    let remote = "http://relay.invalid:8787";

    let doctor = operator.run_failing(&["doctor", "--relay", remote]);
    assert!(doctor.contains("unencrypted"), "{doctor}");
    let enrolled = agent.run_failing(&[
        "agent",
        "enroll",
        "--relay",
        remote,
        "--token",
        "rve_unused",
    ]);
    assert!(enrolled.contains("unencrypted"), "{enrolled}");
    assert!(!agent.config.join("agent.toml").exists());

    // Nor is it reached through a redirect, which would resend the enrollment token with it.
    let redirecting = redirecting_server(&format!("{remote}/v1/enroll"));
    let redirected = agent.run_failing(&[
        "agent",
        "enroll",
        "--relay",
        &redirecting,
        "--token",
        "rve_unused",
    ]);
    assert!(
        redirected.contains("refusing unencrypted relay URL") && !redirected.contains("dns error"),
        "{redirected}"
    );
    assert!(!agent.config.join("agent.toml").exists());

    // An agent whose stored relay is refused, as an older version could enroll it, stops at
    // start instead of retrying it forever.
    let (_relay, url) = start_relay(&root, &relay_role);
    enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let config_path = agent.config.join("agent.toml");
    let config = std::fs::read_to_string(&config_path).expect("read agent config");
    assert!(config.contains(&url), "{config}");
    std::fs::write(&config_path, config.replace(&url, remote)).expect("store a remote relay");

    let mut run = agent
        .command()
        .args(["agent", "run"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent run");
    let deadline = Instant::now() + Duration::from_secs(15);
    while run.try_wait().expect("poll agent run").is_none() {
        if Instant::now() >= deadline {
            let _ = run.kill();
            let _ = run.wait();
            panic!("agent run kept retrying a refused relay URL");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = run.wait_with_output().expect("agent run output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("unencrypted"), "{stderr}");
}

/// Runs `args` until it exits, at most `within`; panics if it keeps running.
fn run_until_exit(role: &Role, args: &[&str], within: Duration) -> std::process::Output {
    let mut run = role
        .command()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn revtty");
    let deadline = Instant::now() + within;
    while run.try_wait().expect("poll revtty").is_none() {
        if Instant::now() >= deadline {
            let _ = run.kill();
            let _ = run.wait();
            panic!("revtty {args:?} kept running");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    run.wait_with_output().expect("revtty output")
}

/// Runs `revtty exec` against the e2e agent with `args`, `input` on its stdin, and waits at
/// most `within` for it to exit.
fn exec_until_exit(
    operator: &Role,
    url: &str,
    args: &[&str],
    input: &[u8],
    within: Duration,
) -> std::process::Output {
    let mut run = operator
        .command()
        .args(["exec", AGENT_NAME, "--relay", url])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn revtty exec");
    let mut stdin = run.stdin.take().expect("exec stdin");
    // A command that does not read its input may let it go unwritten.
    let _ = stdin.write_all(input);
    drop(stdin);

    let deadline = Instant::now() + within;
    while run.try_wait().expect("poll revtty exec").is_none() {
        if Instant::now() >= deadline {
            let _ = run.kill();
            let _ = run.wait();
            panic!("revtty exec {args:?} kept running");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    run.wait_with_output().expect("revtty exec output")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn exec_runs_a_command_with_its_streams_input_and_exit_status() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let agent_process = start_agent(&root, &agent);
    // Pinned first, so that exec has nothing of its own to say.
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);

    let ran = exec_until_exit(
        &operator,
        &url,
        &["--", "echo out; echo err >&2; : REVTTY_EXEC_MARKER; exit 7"],
        b"",
        Duration::from_secs(20),
    );
    assert_eq!(ran.status.code(), Some(7), "{}", text(&ran.stderr));
    assert_eq!(text(&ran.stdout), "out\n");
    assert_eq!(text(&ran.stderr), "err\n");

    // Its words are joined, as ssh does, and its input reaches it.
    let piped = exec_until_exit(
        &operator,
        &url,
        &["--", "tr", "a-z", "A-Z"],
        b"from the operator\n",
        Duration::from_secs(20),
    );
    assert_eq!(piped.status.code(), Some(0), "{}", text(&piped.stderr));
    assert_eq!(text(&piped.stdout), "FROM THE OPERATOR\n");

    // With -n, none does.
    let without_input = exec_until_exit(
        &operator,
        &url,
        &["-n", "--", "cat"],
        b"not for the command\n",
        Duration::from_secs(20),
    );
    assert_eq!(
        without_input.status.code(),
        Some(0),
        "{}",
        text(&without_input.stderr)
    );
    assert_eq!(text(&without_input.stdout), "");

    // The relay audits each as an exec, and neither it nor the agent logs what ran.
    let db = root.path("relay.db");
    let db = db.to_str().expect("utf-8 path");
    let deadline = Instant::now() + Duration::from_secs(5);
    let sessions = loop {
        let sessions = relay_role.run(&["relay", "sessions", "--db", db]);
        let completed = sessions
            .lines()
            .filter(|line| line.contains("\texec\t") && line.contains("outcome=completed"))
            .count();
        if completed == 3 {
            break sessions;
        }
        assert!(
            Instant::now() < deadline,
            "exec sessions not audited as completed:\n{sessions}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    for (what, said) in [
        ("relay sessions", sessions),
        ("relay log", relay.log()),
        ("agent log", agent_process.log()),
    ] {
        assert!(
            !said.contains("REVTTY_EXEC_MARKER"),
            "the {what} shows the command:\n{said}"
        );
    }
}

#[test]
fn exec_gives_up_at_its_timeout() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);

    let started = Instant::now();
    let ran = exec_until_exit(
        &operator,
        &url,
        &["--timeout", "1", "-n", "--", "sleep 5"],
        b"",
        Duration::from_secs(20),
    );

    assert_eq!(ran.status.code(), Some(124), "{}", text(&ran.stderr));
    assert!(
        text(&ran.stderr).contains("timed out after 1s"),
        "{}",
        text(&ran.stderr)
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "exec waited for the command: {:?}",
        started.elapsed()
    );
}

#[test]
fn exec_stops_on_time_while_its_local_output_is_not_read() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);

    // More than a pipe holds, to an output this test reads only once exec has exited.
    const TO_STDOUT: &str = "dd if=/dev/zero bs=1000 count=1000 2>/dev/null; sleep 10";
    const TO_STDERR: &str = "dd if=/dev/zero bs=1000 count=1000 >&2 2>/dev/null; sleep 10";
    for (stream, command) in [("stdout", TO_STDOUT), ("stderr", TO_STDERR)] {
        let started = Instant::now();
        let ran = exec_until_exit(
            &operator,
            &url,
            &["--timeout", "2", "-n", "--", command],
            b"",
            Duration::from_secs(15),
        );
        assert_eq!(ran.status.code(), Some(124), "with {stream} not read");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "exec outlived its timeout with {stream} not read: {:?}",
            started.elapsed()
        );
    }

    // Ctrl-C, with stdout not read.
    let mut run = operator
        .command()
        .args(["exec", AGENT_NAME, "--relay", &url, "-n", "--", TO_STDOUT])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn revtty exec");
    std::thread::sleep(Duration::from_secs(2));
    let interrupted = Instant::now();
    let pid = run.id().to_string();
    let sent = Command::new("kill")
        .args(["-INT", &pid])
        .status()
        .expect("run kill");
    assert!(sent.success(), "SIGINT not delivered");
    let deadline = interrupted + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = run.try_wait().expect("poll revtty exec") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = run.kill();
            let _ = run.wait();
            panic!("exec kept running after Ctrl-C with stdout not read");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(130));
}

#[test]
fn exec_never_asks_for_a_host_key() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);

    // At a terminal, where connect would ask for the fingerprint, exec fails at once.
    let mut terminal = Terminal::spawn(
        &operator,
        &["exec", AGENT_NAME, "--relay", &url, "--", "true"],
    );
    let status = terminal.wait_exit(Duration::from_secs(15));
    let output = terminal.text();
    let Some(status) = status else {
        panic!("revtty exec waited at the terminal:\n{output}");
    };
    assert!(!status.success(), "exec ran without a pinned host key");
    assert!(output.contains("pass --host-key"), "{output}");
    assert!(
        !operator.config.join("known_hosts").exists(),
        "a host key was pinned without approval"
    );
}

/// The JSON that `revtty args` printed on stdout; it must succeed.
fn json_output(role: &Role, args: &[&str]) -> serde_json::Value {
    let output = role
        .command()
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run revtty");
    assert!(
        output.status.success(),
        "revtty {args:?} failed ({}):\n{}",
        output.status,
        text(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "revtty {args:?} printed no JSON ({error}):\n{}",
            text(&output.stdout)
        )
    })
}

fn json_keys(value: &serde_json::Value) -> Vec<&str> {
    let mut keys: Vec<_> = value
        .as_object()
        .expect("a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

/// Reads `run`'s stdout and stderr as they come until it exits, at most `within`.
fn read_until_exit(mut run: Child, within: Duration) -> std::process::Output {
    fn read_all(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).expect("read revtty output");
            bytes
        })
    }
    let stdout = read_all(run.stdout.take().expect("revtty stdout"));
    let stderr = read_all(run.stderr.take().expect("revtty stderr"));

    let deadline = Instant::now() + within;
    let status = loop {
        if let Some(status) = run.try_wait().expect("poll revtty") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = run.kill();
            let _ = run.wait();
            panic!("revtty kept running");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    std::process::Output {
        status,
        stdout: stdout.join().expect("stdout reader"),
        stderr: stderr.join().expect("stderr reader"),
    }
}

fn spawn_exec(operator: &Role, url: &str, args: &[&str]) -> Child {
    operator
        .command()
        .args(["exec", AGENT_NAME, "--relay", url])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn revtty exec")
}

fn exec_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "revtty exec printed no JSON ({error}):\n{}",
            text(&output.stderr)
        )
    })
}

#[test]
fn list_status_and_probe_print_json() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    const AGENT_FIELDS: [&str; 6] = [
        "active_sessions",
        "last_seen",
        "max_sessions",
        "name",
        "online",
        "version",
    ];

    assert_eq!(
        json_output(&operator, &["list", "--relay", &url, "--json"]),
        serde_json::json!([])
    );

    // Enrolled, not running: offline, with no capacity to report.
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let listed = json_output(&operator, &["list", "--relay", &url, "--json"]);
    let agents = listed.as_array().expect("a JSON array");
    assert_eq!(agents.len(), 1, "{listed}");
    assert_eq!(json_keys(&agents[0]), AGENT_FIELDS);
    assert_eq!(agents[0]["name"], AGENT_NAME);
    assert_eq!(agents[0]["online"], false);
    assert_eq!(agents[0]["max_sessions"], serde_json::Value::Null);
    assert!(agents[0]["last_seen"].is_i64(), "{listed}");

    let _agent_process = start_agent(&root, &agent);
    let probe = json_output(
        &operator,
        &[
            "probe",
            AGENT_NAME,
            "--relay",
            &url,
            "--host-key",
            &host_key,
            "--json",
        ],
    );
    assert_eq!(
        probe,
        serde_json::json!({
            "name": AGENT_NAME,
            "reachable": true,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "version": env!("CARGO_PKG_VERSION"),
        })
    );

    let status = json_output(
        &operator,
        &["status", AGENT_NAME, "--relay", &url, "--json"],
    );
    assert_eq!(
        json_keys(&status),
        [
            "active_sessions",
            "created_at",
            "id",
            "last_seen",
            "max_sessions",
            "name",
            "online",
            "version"
        ]
    );
    assert_eq!(status["name"], AGENT_NAME);
    assert_eq!(status["online"], true);
    assert_eq!(status["max_sessions"], 4);
    assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
    assert!(status["last_seen"].is_i64(), "{status}");
    // The same agent as the text says.
    let said = operator.run(&["status", AGENT_NAME, "--relay", &url]);
    assert_eq!(status["id"], field(&said, "id"), "{said}");
    assert_eq!(status["created_at"].to_string(), field(&said, "created"));

    let listed = json_output(&operator, &["list", "--relay", &url, "--json"]);
    assert_eq!(listed[0]["online"], true, "{listed}");
    assert_eq!(listed[0]["max_sessions"], 4, "{listed}");
}

#[test]
fn exec_prints_its_result_as_json() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);

    let ran = read_until_exit(
        spawn_exec(
            &operator,
            &url,
            &["--json", "--", "printf out; printf err >&2; exit 3"],
        ),
        Duration::from_secs(20),
    );
    assert_eq!(ran.status.code(), Some(3), "{}", text(&ran.stderr));
    assert_eq!(text(&ran.stderr), "");
    assert_eq!(
        text(&ran.stdout).lines().count(),
        1,
        "{}",
        text(&ran.stdout)
    );
    assert_eq!(
        exec_json(&ran),
        serde_json::json!({
            "target": AGENT_NAME,
            "exit_status": 3,
            "exit_signal": null,
            "timed_out": false,
            "interrupted": false,
            "stdout": "out",
            "stdout_base64": null,
            "stdout_truncated": false,
            "stderr": "err",
            "stderr_base64": null,
            "stderr_truncated": false,
        })
    );

    // Output that is not UTF-8, from a command that a signal killed.
    let killed = read_until_exit(
        spawn_exec(
            &operator,
            &url,
            &["--json", "--", "printf '\\377\\376'; kill -TERM $$"],
        ),
        Duration::from_secs(20),
    );
    assert_eq!(killed.status.code(), Some(255), "{}", text(&killed.stderr));
    let result = exec_json(&killed);
    assert_eq!(result["stdout"], serde_json::Value::Null);
    assert_eq!(result["stdout_base64"], "//4=");
    assert_eq!(result["exit_status"], serde_json::Value::Null);
    assert_eq!(result["exit_signal"], "TERM");

    // Past the capture limit, the output is still read, to the command's end.
    let long = read_until_exit(
        spawn_exec(
            &operator,
            &url,
            &[
                "--json",
                "--",
                "head -c 17000000 /dev/zero | tr '\\0' a; echo done >&2",
            ],
        ),
        Duration::from_secs(60),
    );
    assert_eq!(long.status.code(), Some(0), "{}", text(&long.stderr));
    let result = exec_json(&long);
    assert_eq!(result["stdout_truncated"], true);
    assert_eq!(
        result["stdout"].as_str().map(str::len),
        Some(16 * 1024 * 1024)
    );
    assert_eq!(result["stderr"], "done\n");
    assert_eq!(result["stderr_truncated"], false);
}

#[test]
fn exec_json_at_its_timeout_waits_for_a_late_reader() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);

    // Its JSON holds more than a pipe does, so it waits for this test to read it.
    let run = spawn_exec(
        &operator,
        &url,
        &[
            "--json",
            "--timeout",
            "5",
            "-n",
            "--",
            "printf partial; head -c 1000000 /dev/zero | tr '\\0' x; sleep 20",
        ],
    );
    // Past the timeout, which also covers authentication and the connection.
    std::thread::sleep(Duration::from_secs(7));
    let reading = Instant::now();
    let ran = read_until_exit(run, Duration::from_secs(15));
    // Stopped at its timeout, before this test read anything: not when the command ended.
    assert!(
        reading.elapsed() < Duration::from_secs(3),
        "exec ran past its timeout: {:?}",
        reading.elapsed()
    );
    assert_eq!(ran.status.code(), Some(124), "{}", text(&ran.stderr));
    let result = exec_json(&ran);
    assert_eq!(result["timed_out"], true);
    assert_eq!(result["interrupted"], false);
    assert_eq!(result["exit_status"], serde_json::Value::Null);
    assert!(
        result["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.starts_with("partial")),
        "{}",
        result["stdout"]
    );
}

#[test]
fn ctrl_c_ends_exec_while_its_json_waits_for_a_reader() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);

    let mut run = spawn_exec(
        &operator,
        &url,
        &[
            "--json",
            "-n",
            "--",
            "head -c 1000000 /dev/zero | tr '\\0' x",
        ],
    );
    // The JSON comes once the command has ended: its first byte says exec is writing it.
    // The rest, more than a pipe holds, waits for a read that this test never makes.
    let mut stdout = run.stdout.take().expect("exec stdout");
    let (first, read) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut byte = [0_u8; 1];
        let got = stdout.read_exact(&mut byte).map(|()| byte[0]);
        let _ = first.send((got, stdout));
    });
    let Ok((got, _unread)) = read.recv_timeout(Duration::from_secs(20)) else {
        let _ = run.kill();
        let _ = run.wait();
        panic!("revtty exec wrote no JSON");
    };
    assert_eq!(got.expect("read the JSON"), b'{');

    let pid = run.id().to_string();
    let sent = Command::new("kill")
        .args(["-INT", &pid])
        .status()
        .expect("run kill");
    assert!(sent.success(), "SIGINT not delivered");
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = run.try_wait().expect("poll revtty exec") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = run.kill();
            let _ = run.wait();
            panic!("exec kept writing its JSON after Ctrl-C");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(130));
    let mut stderr = String::new();
    run.stderr
        .take()
        .expect("exec stderr")
        .read_to_string(&mut stderr)
        .expect("read exec stderr");
    assert!(stderr.contains("cut short"), "{stderr}");
}

/// The PID the remote command wrote to `pid_file`, at most `within` after it started.
fn remote_pid(pid_file: &std::path::Path, within: Duration) -> String {
    let deadline = Instant::now() + within;
    loop {
        if let Ok(written) = std::fs::read_to_string(pid_file)
            && let Some(pid) = written.strip_suffix('\n')
        {
            assert!(pid.bytes().all(|byte| byte.is_ascii_digit()), "{written:?}");
            return pid.to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "the remote command did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_process_gone(pid: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while process_alive(pid) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

#[test]
fn exec_ends_its_remote_command_at_its_timeout_and_on_ctrl_c() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);

    for json in [false, true] {
        for interrupt in [false, true] {
            let case = format!("json={json} interrupt={interrupt}");
            let pid_file = root.path(&format!("command-{json}-{interrupt}.pid"));
            let command = format!(
                "echo started; echo $$ > '{}'; exec sleep 600",
                pid_file.display()
            );
            let mut args = vec!["-n"];
            if json {
                args.push("--json");
            }
            if !interrupt {
                args.extend(["--timeout", "3"]);
            }
            args.extend(["--", &command]);

            let run = spawn_exec(&operator, &url, &args);
            let pid = remote_pid(&pid_file, Duration::from_secs(20));
            if interrupt {
                // Long enough for `started` to reach exec, which then has output to report.
                std::thread::sleep(Duration::from_secs(1));
                let sent = Command::new("kill")
                    .args(["-INT", &run.id().to_string()])
                    .status()
                    .expect("run kill");
                assert!(sent.success(), "SIGINT not delivered ({case})");
            }
            let ran = read_until_exit(run, Duration::from_secs(15));
            // Before any assertion, so that a failing one leaves no remote command behind.
            let gone = wait_process_gone(&pid, Duration::from_secs(15));
            if !gone {
                let _ = Command::new("kill").args(["-9", &pid]).status();
            }

            let expected = if interrupt { 130 } else { 124 };
            assert_eq!(
                ran.status.code(),
                Some(expected),
                "{case}: {}",
                text(&ran.stderr)
            );
            if json {
                let result = exec_json(&ran);
                assert_eq!(result["interrupted"], interrupt, "{case}: {result}");
                assert_eq!(result["timed_out"], !interrupt, "{case}: {result}");
                assert_eq!(result["exit_status"], serde_json::Value::Null, "{case}");
                assert_eq!(result["stdout"], "started\n", "{case}: {result}");
            } else {
                assert_eq!(text(&ran.stdout), "started\n", "{case}");
            }
            assert!(
                gone,
                "{case}: the remote command {pid} outlived revtty exec"
            );
        }
    }
}

/// Stands in for an agent that predates exec on its control connection: it says hello and
/// then lets every offer go unanswered, as an older agent does with an `exec_offer` it cannot
/// decode.
fn ignore_session_offers(url: &str, control_token: &str) {
    use futures_util::{SinkExt, StreamExt};
    use reqwest_websocket::{Message, Upgrade};

    let relay = url.replace("http://", "ws://");
    let token = control_token.to_owned();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fake agent runtime");
        runtime.block_on(async move {
            let mut control = reqwest::Client::new()
                .get(format!("{relay}/v1/agent/{AGENT_NAME}"))
                .bearer_auth(&token)
                .upgrade()
                .send()
                .await
                .expect("fake agent control upgrade")
                .into_websocket()
                .await
                .expect("fake agent control connection");
            let hello = serde_json::json!({
                "type": "hello",
                "version": 1,
                "name": AGENT_NAME,
                "agent_version": "0.1.0",
                "active_sessions": 0,
                "max_sessions": 4,
            });
            control
                .send(Message::Text(hello.to_string()))
                .await
                .expect("send fake hello");
            while let Some(Ok(_)) = control.next().await {}
        });
    });
}

/// Sends `body` as JSON to `path` of the plain-HTTP relay at `url`; returns its status line.
fn post_json(url: &str, path: &str, body: &str) -> String {
    let address = url.strip_prefix("http://").expect("plain-HTTP relay URL");
    let mut stream = std::net::TcpStream::connect(address).expect("connect to relay");
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("send request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response.lines().next().unwrap_or_default().to_owned()
}

/// The first token-shaped string in `log`: a revtty credential prefix and the 43 base64url
/// characters of a generated token.
fn token_in(log: &str) -> Option<&str> {
    ["rve_", "rva_", "rvo_", "rvs_", "rvk_"]
        .iter()
        .find_map(|prefix| {
            log.match_indices(prefix).find_map(|(at, _)| {
                let candidate = log.get(at..at + prefix.len() + 43)?;
                candidate[prefix.len()..]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                    .then_some(candidate)
            })
        })
}

#[test]
fn service_logs_keep_credentials_and_session_data_out_even_at_trace_level() {
    let root = TempRoot::new();
    let (operator, mut agent, mut relay_role) = prepare(&root);
    agent.log_filter = Some("trace");
    relay_role.log_filter = Some("trace");
    let (relay, url) = start_relay(&root, &relay_role);
    let token = enrollment_token(&root, &relay_role, &operator, false);
    let enrolled = agent.run(&["agent", "enroll", "--relay", &url, "--token", &token]);
    let host_key = field(&enrolled, "host").to_owned();
    let config = std::fs::read_to_string(agent.config.join("agent.toml")).expect("read agent.toml");
    let config: toml::Table = toml::from_str(&config).expect("parse agent.toml");
    let control_token = config["control_token"].as_str().expect("control token");
    let agent_process = start_agent(&root, &agent);
    // At trace level the agent's "connected to" can be a dependency's, written before the
    // relay registered it.
    relay.wait_for_log("agent online", Duration::from_secs(10));

    // A probe, a command with input and a shell. The marker is computed remotely, and
    // every byte that carries it travels inside SSH.
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    let ran = exec_until_exit(
        &operator,
        &url,
        &["--", "read line; echo REVTTY_LOG_$((6*7)) $line"],
        b"REVTTY_LOG_INPUT\n",
        Duration::from_secs(20),
    );
    assert_eq!(
        text(&ran.stdout),
        "REVTTY_LOG_42 REVTTY_LOG_INPUT\n",
        "{}",
        text(&ran.stderr)
    );
    let mut terminal = Terminal::connect(&operator, &url, None);
    let logs = [&relay, &agent_process];
    terminal.wait_ready(Duration::from_secs(20), &logs);
    terminal.send("echo REVTTY_LOG_$((6*7)); exit\r");
    terminal.wait_for("REVTTY_LOG_42", Duration::from_secs(20), &logs);
    terminal
        .wait_exit(Duration::from_secs(10))
        .expect("revtty connect kept running after its shell exited");

    // A request the relay refuses, made of a credential: the refusal does not quote it.
    let body = serde_json::to_string(&token).expect("encode token");
    let refused = post_json(&url, "/v1/enroll", &body);
    assert!(refused.starts_with("HTTP/1.1 422 "), "{refused}");

    // Stopped, so that their logs hold everything they wrote.
    let relay_log = relay.terminate(Duration::from_secs(10));
    let agent_log = agent_process.terminate(Duration::from_secs(15));
    for (service, log) in [("relay", relay_log), ("agent", agent_log)] {
        // Lines from tracing, with dependencies' trace events among them.
        assert!(log.contains(" INFO "), "{service} log:\n{log}");
        assert!(log.contains("TRACE "), "{service} log:\n{log}");
        for secret in [token.as_str(), control_token, "REVTTY_LOG_"] {
            assert!(
                !log.contains(secret),
                "{secret} in the {service} log:\n{log}"
            );
        }
        for header in ["authorization", "bearer"] {
            assert!(
                !log.to_ascii_lowercase().contains(header),
                "{header} in the {service} log:\n{log}"
            );
        }
        assert_eq!(token_in(&log), None, "token in the {service} log:\n{log}");
    }
}

/// Runs `revtty` as `role` and returns its exit status and the last line it wrote to stderr.
fn failure(role: &Role, args: &[&str]) -> (Option<i32>, String) {
    let output = role
        .command()
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run revtty");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let last = stderr.lines().last().unwrap_or_default().to_owned();
    (output.status.code(), last)
}

#[test]
fn errors_name_their_kind_and_keep_their_exit_status() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    enroll_agent(&root, &relay_role, &operator, &agent, &url);

    // A key of its own, which the agent does not list: its signature is good.
    let stranger = Role::new(&root, "stranger");
    stranger.run(&["init"]);
    let (status, line) = failure(&stranger, &["status", AGENT_NAME, "--relay", &url]);
    assert_eq!(status, Some(1), "{line}");
    assert!(
        line.starts_with(&format!(
            "error (authorization): this operator key is not authorized for {AGENT_NAME}"
        )),
        "{line}"
    );
    // The same for a name nobody enrolled.
    let (status, unknown) = failure(&stranger, &["status", "nobody", "--relay", &url]);
    assert_eq!(status, Some(1), "{unknown}");
    assert_eq!(
        unknown,
        line.replace(AGENT_NAME, "nobody"),
        "an unknown name is answered as a forbidden one"
    );

    let (status, line) = failure(
        &operator,
        &[
            "status",
            AGENT_NAME,
            "--relay",
            &url,
            "--host-key",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ],
    );
    assert_eq!(status, Some(1), "{line}");
    assert!(line.starts_with("error (host key): "), "{line}");

    let (status, line) = failure(
        &operator,
        &["status", AGENT_NAME, "--relay", "https://revtty.invalid"],
    );
    assert_eq!(status, Some(1), "{line}");
    assert!(line.starts_with("error (DNS): "), "{line}");
}

/// Writes `config.toml` for `role`, in a config directory private to the user as revtty
/// creates it, and with the mode an editor gives it under umask 022.
fn write_settings(role: &Role, content: &str) {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&role.config)
        .expect("create config directory");
    let path = role.config.join("config.toml");
    std::fs::write(&path, content).expect("write config.toml");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("set config.toml mode");
}

#[test]
fn an_imported_key_is_the_operator_identity() {
    let root = TempRoot::new();
    let (_, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);

    // A key the operator already has, private as ssh-keygen writes it.
    let mut key =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("generate key");
    key.set_comment("me@laptop");
    let source = root.path("ssh/id_ed25519");
    std::fs::create_dir_all(source.parent().expect("key directory")).expect("create key dir");
    std::fs::write(
        &source,
        key.to_openssh(ssh_key::LineEnding::LF).expect("encode key"),
    )
    .expect("write key");
    std::fs::set_permissions(&source, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("set key mode");
    let fingerprint = key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();

    let operator = Role::new(&root, "importer");
    let source = source.to_str().expect("utf-8 path");
    let imported = operator.run(&["init", "--key", source]);
    assert!(imported.contains("identity imported"), "{imported}");
    assert!(imported.contains(&fingerprint), "{imported}");
    let again = operator.run(&["init", "--key", source]);
    assert!(again.contains("identity existing"), "{again}");

    // Agents enrolled for the imported key accept this operator.
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let _agent_process = start_agent(&root, &agent);
    let listed = operator.run(&["list", "--relay", &url]);
    assert!(listed.contains(AGENT_NAME), "{listed}");
    let probe = operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    assert!(probe.contains("status   reachable"), "{probe}");

    // Another key never replaces it.
    let other = Role::new(&root, "other");
    other.run(&["init"]);
    let (status, line) = failure(&other, &["init", "--key", source]);
    assert_eq!(status, Some(1), "{line}");
    assert!(line.contains("another key"), "{line}");
}

#[test]
fn operator_and_relay_commands_take_their_settings_from_config_toml() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    enroll_agent(&root, &relay_role, &operator, &agent, &url);

    // No relay anywhere: there is no default to fall back on.
    let (status, line) = failure(&operator, &["list"]);
    assert_eq!(status, Some(1), "{line}");
    assert!(line.starts_with("error: no relay configured"), "{line}");
    for way in ["--relay", "REVTTY_RELAY", "[operator]", "config.toml"] {
        assert!(line.contains(way), "{line}");
    }

    write_settings(&operator, &format!("[operator]\nrelay = \"{url}\"\n"));
    let listed = operator.run(&["list"]);
    assert!(listed.contains(AGENT_NAME), "{listed}");
    // REVTTY_RELAY wins over the file.
    let mut overridden = operator.command();
    let output = overridden
        .args(["list"])
        .env("REVTTY_RELAY", "https://revtty.invalid")
        .stdin(Stdio::null())
        .output()
        .expect("run revtty");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error (DNS): "), "{stderr}");

    // A broken file fails a command even when its flags give every value.
    write_settings(
        &operator,
        "[operator]\nrelay_url = \"https://relay.example.com\"\n",
    );
    let (status, line) = failure(&operator, &["list", "--relay", &url]);
    assert_eq!(status, Some(1), "{line}");
    assert!(line.contains("config.toml is invalid at line 2"), "{line}");

    // The relay's database from the file, unless --db names another.
    let db = root.path("relay.db");
    write_settings(
        &relay_role,
        &format!("[relay]\ndb = \"{}\"\n", db.to_str().expect("utf-8 path")),
    );
    let agents = relay_role.run(&["relay", "agents"]);
    assert!(agents.contains(AGENT_NAME), "{agents}");
    let other = root.path("other.db");
    let other = other.to_str().expect("utf-8 path");
    relay_role.run(&["relay", "init", "--db", other]);
    let none = relay_role.run(&["relay", "agents", "--db", other]);
    assert!(!none.contains(AGENT_NAME), "{none}");
    let output = relay_role
        .command()
        .args(["relay", "agents"])
        .env("REVTTY_DB", other)
        .output()
        .expect("run revtty");
    assert!(output.status.success());
    let from_env = String::from_utf8_lossy(&output.stdout);
    assert!(
        !from_env.contains(AGENT_NAME),
        "REVTTY_DB lost to the file: {from_env}"
    );

    // Relay commands look up the config directory alone: a state directory they never use
    // cannot fail them.
    let output = relay_role
        .command()
        .args(["relay", "agents"])
        .env("REVTTY_STATE_DIR", "relative/state")
        .output()
        .expect("run revtty");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");

    // `relay serve` listens where the file says.
    write_settings(
        &relay_role,
        &format!(
            "[relay]\nbind = \"127.0.0.1:0\"\ndb = \"{}\"\n",
            db.to_str().expect("utf-8 path")
        ),
    );
    let mut serve = relay_role.command();
    serve.args(["relay", "serve"]);
    let served = Running::spawn(serve);
    let log = served.wait_for_log("listening on ", Duration::from_secs(15));
    assert!(log.contains("listening on 127.0.0.1:"), "{log}");
    assert!(!log.contains("listening on 127.0.0.1:8787"), "{log}");
}

#[test]
fn exec_on_an_agent_that_predates_it_says_so() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);

    let config = std::fs::read_to_string(agent.config.join("agent.toml")).expect("read agent.toml");
    let config: toml::Table = toml::from_str(&config).expect("parse agent.toml");
    let control_token = config["control_token"].as_str().expect("control token");
    ignore_session_offers(&url, control_token);
    relay.wait_for_log("agent online", Duration::from_secs(10));

    let ran = exec_until_exit(
        &operator,
        &url,
        &["--host-key", &host_key, "-n", "--", "true"],
        b"",
        Duration::from_secs(20),
    );
    assert_eq!(ran.status.code(), Some(1), "{}", text(&ran.stderr));
    let stderr = text(&ran.stderr);
    assert!(stderr.contains("did not accept the session"), "{stderr}");
    assert!(
        stderr.contains("the agent may predate exec"),
        "no hint to upgrade the agent: {stderr}"
    );
}

#[test]
fn relay_urls_with_credentials_are_refused() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    // reqwest sends them as Basic credentials, which authenticate nothing at the relay.
    let with_credentials = url.replacen("http://", "http://alice:SECRETPW@", 1);
    let token = enrollment_token(&root, &relay_role, &operator, false);

    let refused = agent.run_failing(&[
        "agent",
        "enroll",
        "--relay",
        &with_credentials,
        "--token",
        &token,
    ]);
    assert!(refused.contains("user name or password"), "{refused}");
    assert!(!refused.contains("SECRETPW"), "{refused}");
    assert!(!agent.config.join("agent.toml").exists());

    // An agent an older version enrolled with them keeps them out of its output and stops.
    agent.run(&["agent", "enroll", "--relay", &url, "--token", &token]);
    let config_path = agent.config.join("agent.toml");
    let config = std::fs::read_to_string(&config_path).expect("read agent config");
    std::fs::write(&config_path, config.replace(&url, &with_credentials))
        .expect("store a relay with credentials");

    let status = agent.run(&["agent", "status"]);
    assert!(
        status.contains("relay      refused: relay URL must not contain a user name or password"),
        "{status}"
    );
    assert!(!status.contains("SECRETPW"), "{status}");

    let run = run_until_exit(&agent, &["agent", "run"], Duration::from_secs(15));
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success(), "{stderr}");
    assert!(stderr.contains("user name or password"), "{stderr}");
    assert!(!stderr.contains("SECRETPW"), "{stderr}");
}

#[test]
fn operator_request_errors_show_their_cause() {
    let root = TempRoot::new();
    let (operator, _agent, _relay_role) = prepare(&root);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
    let url = format!("http://{}", closed.local_addr().expect("reserved port"));
    drop(closed);

    for args in [
        vec!["list", "--relay", &url],
        vec!["status", AGENT_NAME, "--relay", &url],
    ] {
        let failed = operator.run_failing(&args);
        assert!(failed.contains("refused"), "{args:?}: {failed}");
    }
}

/// Stands in for the enrolled agent on its control connection and answers the first probe
/// offer as agents did before probes went over SSH, and as a relay could on its own: a
/// `ProbeResult` in a text frame, with no SSH session to prove the pinned host key.
fn answer_probe_without_ssh(url: &str, control_token: &str) {
    use futures_util::{SinkExt, StreamExt};
    use reqwest_websocket::{CloseCode, Message, Upgrade};

    let relay = url.replace("http://", "ws://");
    let token = control_token.to_owned();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fake agent runtime");
        runtime.block_on(async move {
            let client = reqwest::Client::new();
            let mut control = client
                .get(format!("{relay}/v1/agent/{AGENT_NAME}"))
                .bearer_auth(&token)
                .upgrade()
                .send()
                .await
                .expect("fake agent control upgrade")
                .into_websocket()
                .await
                .expect("fake agent control connection");
            let hello = serde_json::json!({
                "type": "hello",
                "version": 1,
                "name": AGENT_NAME,
                "agent_version": "0.1.0",
                "active_sessions": 0,
                "max_sessions": 4,
            });
            control
                .send(Message::Text(hello.to_string()))
                .await
                .expect("send fake hello");

            while let Some(Ok(message)) = control.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let offer: serde_json::Value =
                    serde_json::from_str(&text).expect("decode control message");
                if offer["type"] != "probe_offer" {
                    continue;
                }
                let session_id = offer["session_id"].as_str().expect("session id");
                let tunnel_token = offer["tunnel_token"].as_str().expect("tunnel token");
                let accept = serde_json::json!({
                    "type": "session_accept",
                    "version": 1,
                    "session_id": session_id,
                });
                control
                    .send(Message::Text(accept.to_string()))
                    .await
                    .expect("accept probe");

                let mut tunnel = client
                    .get(format!("{relay}/v1/session/{session_id}"))
                    .bearer_auth(tunnel_token)
                    .upgrade()
                    .send()
                    .await
                    .expect("fake tunnel upgrade")
                    .into_websocket()
                    .await
                    .expect("fake tunnel");
                let answer = serde_json::json!({
                    "name": AGENT_NAME,
                    "os": "linux",
                    "arch": "x86_64",
                    "version": "0.1.0",
                });
                tunnel
                    .send(Message::Text(answer.to_string()))
                    .await
                    .expect("send probe answer");
                let _ = tunnel.close(CloseCode::Normal, None).await;
                return;
            }
        });
    });
}

#[test]
fn a_probe_answered_without_ssh_is_refused() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let host_key = enroll_agent(&root, &relay_role, &operator, &agent, &url);

    // The enrolled agent's control credential, used by a process that is not revtty.
    let config = std::fs::read_to_string(agent.config.join("agent.toml")).expect("read agent.toml");
    let config: toml::Table = toml::from_str(&config).expect("parse agent.toml");
    let control_token = config["control_token"].as_str().expect("control token");
    answer_probe_without_ssh(&url, control_token);
    relay.wait_for_log("agent online", Duration::from_secs(10));

    let refused = operator.run_failing(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    assert!(!refused.contains("reachable"), "{refused}");
    assert!(refused.contains("answered without SSH"), "{refused}");
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

    // A probe ends its SSH session cleanly and gives the only slot back for the next one.
    let db = root.path("relay.db");
    let db = db.to_str().expect("utf-8 path");
    for probes in 1..=2 {
        let probed = operator.run(&[
            "probe",
            AGENT_NAME,
            "--relay",
            &url,
            "--host-key",
            &host_key,
        ]);
        assert!(probed.contains("status   reachable"), "{probed}");

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let sessions = relay_role.run(&["relay", "sessions", "--db", db]);
            let completed = sessions
                .lines()
                .filter(|line| line.contains("\tprobe\t") && line.contains("outcome=completed"))
                .count();
            if completed == probes {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "probe {probes} not audited as completed:\n{sessions}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

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

    // An operator revoking itself: the change is written, then its session is closed. The
    // agent cuts a revoked operator off at once, which can be before the command's own output
    // reaches the terminal: the change is checked on the target instead.
    let started = Instant::now();
    terminal.send(&format!(
        "{REVTTY} agent operator revoke {second_fingerprint}\r"
    ));
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
    let listed = agent.run(&["agent", "operator", "list"]);
    assert!(
        listed.contains("revision   3") && !listed.contains(&second_fingerprint),
        "the revocation was not written:\n{listed}"
    );

    // The relay no longer issues it credentials, and the agent would refuse it anyway.
    relay.wait_for_log("operators updated to revision 3", Duration::from_secs(10));
    let refused = second.run_failing(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(
        refused.contains("error (authorization)") && refused.contains("403"),
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
    // Revoked on the target, outside any session, `revoke` confirms what it changed.
    agent.run(&[
        "agent",
        "operator",
        "add",
        second_key.to_str().expect("utf-8 path"),
    ]);
    let revoked = agent.run(&["agent", "operator", "revoke", &second_fingerprint]);
    assert_eq!(field(&revoked, "revoked"), second_fingerprint);
    assert_eq!(field(&revoked, "revision"), "5");

    let first_fingerprint = field(&operator.run(&["init"]), "fingerprint").to_owned();
    let last = agent.run_failing(&["agent", "operator", "revoke", &first_fingerprint]);
    assert!(
        last.contains("last operator"),
        "last operator revoked:\n{last}"
    );
}

#[test]
fn an_operator_key_is_rotated_with_exec() {
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
    let old_fingerprint = field(&operator.run(&["init"]), "fingerprint").to_owned();

    // As the README rotates it: a new identity, with the pins of the current one.
    let new = Role::new(&root, "new");
    let new_fingerprint = field(&new.run(&["init"]), "fingerprint").to_owned();
    std::fs::copy(
        operator.config.join("known_hosts"),
        new.config.join("known_hosts"),
    )
    .expect("copy the pins");
    let new_key = std::fs::read(new.config.join("id_ed25519.pub")).expect("read the new key");

    // The current key authorizes it on the target, with the new key on stdin.
    let added = exec_until_exit(
        &operator,
        &url,
        &["--", &format!("{REVTTY} agent operator add -")],
        &new_key,
        Duration::from_secs(20),
    );
    assert_eq!(added.status.code(), Some(0), "{}", text(&added.stderr));
    assert_eq!(field(&text(&added.stdout), "added"), new_fingerprint);
    agent_process.wait_for_log("operator list revision 2", Duration::from_secs(10));
    relay.wait_for_log("operators updated to revision 2", Duration::from_secs(10));
    new.run(&["probe", AGENT_NAME, "--relay", &url]);

    // The new key revokes the old one, which then gets nothing from the relay.
    let revoked = exec_until_exit(
        &new,
        &url,
        &[
            "-n",
            "--",
            &format!("{REVTTY} agent operator revoke {old_fingerprint}"),
        ],
        b"",
        Duration::from_secs(20),
    );
    assert_eq!(revoked.status.code(), Some(0), "{}", text(&revoked.stderr));
    assert_eq!(field(&text(&revoked.stdout), "revoked"), old_fingerprint);
    relay.wait_for_log("operators updated to revision 3", Duration::from_secs(10));
    let refused = exec_until_exit(
        &operator,
        &url,
        &["-n", "--", "true"],
        b"",
        Duration::from_secs(20),
    );
    assert!(
        !refused.status.success() && text(&refused.stderr).contains("error (authorization)"),
        "the revoked key still runs commands:\n{}",
        text(&refused.stderr)
    );

    // Nor can the last operator revoke itself through exec.
    let last = exec_until_exit(
        &new,
        &url,
        &[
            "-n",
            "--",
            &format!("{REVTTY} agent operator revoke {new_fingerprint}"),
        ],
        b"",
        Duration::from_secs(20),
    );
    assert_eq!(last.status.code(), Some(1), "{}", text(&last.stderr));
    assert!(
        text(&last.stderr).contains("last operator"),
        "{}",
        text(&last.stderr)
    );
    new.run(&["probe", AGENT_NAME, "--relay", &url]);
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
        log.contains("the relay refused the WebSocket upgrade (401 Unauthorized)"),
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
        mismatch.contains("HOST KEY MISMATCH")
            && mismatch.contains("revtty forget")
            && !mismatch.contains(&new_host_key),
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
    assert!(
        gone.contains("error (authorization)") && gone.contains("403"),
        "{gone}"
    );
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

/// A new enrollment for the agent, `--replace` when it replaces an enrolled one; its token.
fn enrollment_token(root: &TempRoot, relay_role: &Role, operator: &Role, replace: bool) -> String {
    let db = root.path("relay.db");
    let operator_key = operator.config.join("id_ed25519.pub");
    let mut args = vec![
        "relay",
        "enroll",
        AGENT_NAME,
        "--operator-key",
        operator_key.to_str().expect("utf-8 path"),
        "--db",
        db.to_str().expect("utf-8 path"),
    ];
    if replace {
        args.push("--replace");
    }
    field(&relay_role.run(&args), "token").to_owned()
}

/// Enrolls `agent` with a pairing code the operator made; returns the agent's host key
/// fingerprint and the code.
fn paired_enrollment(
    root: &TempRoot,
    relay_role: &Role,
    operator: &Role,
    agent: &Role,
    url: &str,
    replace: bool,
) -> (String, String) {
    let token = enrollment_token(root, relay_role, operator, replace);
    let paired = operator.run(&["pair", AGENT_NAME, "--token", &token, "--relay", url]);
    let code = field(&paired, "code").to_owned();
    assert!(
        paired.contains(&format!(
            "revtty agent enroll --relay {url} --pairing-code {code}"
        )),
        "{paired}"
    );

    let enrolled = agent.run(&["agent", "enroll", "--relay", url, "--pairing-code", &code]);
    let operator_fingerprint = field(&operator.run(&["init"]), "fingerprint").to_owned();
    assert_eq!(
        field(&enrolled, "operator"),
        format!("{operator_fingerprint} (verified by pairing code)")
    );
    (field(&enrolled, "host").to_owned(), code)
}

/// The base64 of the pairing secret inside `code`, which must never reach the relay.
fn pairing_secret(code: &str) -> String {
    let secret = code.split('.').nth(2).expect("pairing secret");
    secret
        .strip_prefix("rvk_")
        .expect("secret prefix")
        .to_owned()
}

fn pending_pairings(operator: &Role) -> String {
    std::fs::read_to_string(operator.config.join("pairings")).unwrap_or_default()
}

#[test]
fn paired_enrollment_pins_the_host_key_on_first_contact() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (relay, url) = start_relay(&root, &relay_role);
    let token = enrollment_token(&root, &relay_role, &operator, false);

    // Paired where there was no operator identity, the code would be for a new key the
    // enrollment cannot name.
    let stranger = Role::new(&root, "stranger");
    let refused = stranger.run_failing(&["pair", AGENT_NAME, "--token", &token, "--relay", &url]);
    assert!(refused.contains("no operator identity"), "{refused}");
    assert!(!stranger.config.join("pairings").exists());

    let paired = operator.run(&["pair", AGENT_NAME, "--token", &token, "--relay", &url]);
    let code = field(&paired, "code").to_owned();
    let secret = pairing_secret(&code);

    // Misused, the code is refused before anything is sent, and never quoted.
    for args in [
        vec!["--token", code.as_str()],
        vec!["--token", token.as_str(), "--pairing-code", code.as_str()],
        vec!["--pairing-code", &code[..code.len() - 3]],
    ] {
        let mut command = vec!["agent", "enroll", "--relay", url.as_str()];
        command.extend(args);
        let refused = agent.run_failing(&command);
        assert!(!refused.contains(&secret), "{refused}");
    }

    // The enrollment was not used by those attempts.
    let enrolled = agent.run(&["agent", "enroll", "--relay", &url, "--pairing-code", &code]);
    assert!(
        enrolled.contains("(verified by pairing code)"),
        "{enrolled}"
    );
    let host_key = field(&enrolled, "host").to_owned();
    let _agent_process = start_agent(&root, &agent);

    let probe = operator.run(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(
        probe.contains("status   reachable")
            && probe.contains(&format!(
                "pinned host key {host_key}, verified by pairing code"
            )),
        "{probe}"
    );
    assert!(
        pending_pairings(&operator).is_empty(),
        "pairing not used up"
    );
    let again = operator.run(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(!again.contains("pinned host key"), "{again}");

    // The relay never had the secret.
    for file in ["relay.db", "relay.db-wal"] {
        let stored = std::fs::read(root.path(file)).unwrap_or_default();
        assert!(
            !stored
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "{file} holds the pairing secret"
        );
    }
    assert!(
        !relay.log().contains(&secret),
        "the relay logged the secret"
    );
}

#[test]
fn a_relay_cannot_have_another_host_key_pinned_despite_pairing() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    let (host_key, _code) = paired_enrollment(&root, &relay_role, &operator, &agent, &url, false);
    let _agent_process = start_agent(&root, &agent);
    let known_hosts = operator.config.join("known_hosts");

    // --host-key is the operator's own word: it is checked first, even against a valid proof.
    let contradicted = operator.run_failing(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        "SHA256:not-the-agent",
    ]);
    assert!(
        contradicted.contains("does not match --host-key"),
        "{contradicted}"
    );
    assert!(!known_hosts.exists());
    assert!(!pending_pairings(&operator).is_empty());

    let db = tokio_rusqlite::rusqlite::Connection::open(root.path("relay.db"))
        .expect("open relay database");
    db.busy_timeout(Duration::from_secs(5))
        .expect("wait for the relay's writes");
    let (agent_key, agent_proof): (String, String) = db
        .query_row(
            "SELECT host_key, host_key_proof FROM agents WHERE name = ?1",
            [AGENT_NAME],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read the enrolled host key and proof");
    let other_key =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("other host key")
            .public_key()
            .to_openssh()
            .expect("encode other host key");
    let present = |key: &str, proof: Option<&str>| {
        db.execute(
            "UPDATE agents SET host_key = ?1, host_key_proof = ?2 WHERE name = ?3",
            tokio_rusqlite::rusqlite::params![key, proof, AGENT_NAME],
        )
        .expect("change what the relay presents");
    };

    // Another key with the agent's proof, or a proof the relay made up.
    let made_up = "A".repeat(43);
    for (key, proof) in [
        (other_key.as_str(), agent_proof.as_str()),
        (agent_key.as_str(), made_up.as_str()),
    ] {
        present(key, Some(proof));
        let refused = operator.run_failing(&["probe", AGENT_NAME, "--relay", &url]);
        assert!(
            refused.contains("nothing was pinned") && !refused.contains("SHA256:"),
            "{refused}"
        );
        assert!(
            !known_hosts.exists(),
            "a host key was pinned without its proof"
        );
    }

    // A relay that predates pairing codes sends no proof: the operator is asked for
    // --host-key, which pins the key and discards the pairing.
    present(&agent_key, None);
    let refused = operator.run_failing(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(refused.contains("--host-key"), "{refused}");
    let probe = operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    assert!(probe.contains("status   reachable"), "{probe}");
    assert!(pending_pairings(&operator).is_empty());

    // A pairing made later, for a reinstall that does not happen, is void once the pinned key
    // is reaffirmed: a proof the relay holds back cannot replace it afterwards.
    let token = enrollment_token(&root, &relay_role, &operator, true);
    operator.run(&["pair", AGENT_NAME, "--token", &token, "--relay", &url]);
    assert!(!pending_pairings(&operator).is_empty());
    operator.run(&[
        "probe",
        AGENT_NAME,
        "--relay",
        &url,
        "--host-key",
        &host_key,
    ]);
    assert!(pending_pairings(&operator).is_empty());
}

#[test]
fn a_machine_paired_again_replaces_its_pin() {
    let root = TempRoot::new();
    let (operator, agent, relay_role) = prepare(&root);
    let (_relay, url) = start_relay(&root, &relay_role);
    paired_enrollment(&root, &relay_role, &operator, &agent, &url, false);
    let old_agent = start_agent(&root, &agent);
    operator.run(&["probe", AGENT_NAME, "--relay", &url]);
    drop(old_agent);

    // Reinstalled and paired again: its new key replaces the pin, with no `forget`.
    let reinstalled = Role::new(&root, "reinstalled");
    let (new_host_key, _code) =
        paired_enrollment(&root, &relay_role, &operator, &reinstalled, &url, true);
    let new_agent = start_agent(&root, &reinstalled);
    let probe = operator.run(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(
        probe.contains("status   reachable")
            && probe.contains(&format!(
                "pinned host key {new_host_key}, verified by pairing code"
            )),
        "{probe}"
    );
    let pins = std::fs::read_to_string(operator.config.join("known_hosts")).expect("read pins");
    assert_eq!(pins.lines().count(), 1, "{pins}");
    drop(new_agent);

    // Reinstalled with a plain token, the operator key is the relay's word and a changed
    // host key is a mismatch, as without pairing codes.
    let third = Role::new(&root, "third");
    let token = enrollment_token(&root, &relay_role, &operator, true);
    let enrolled = third.run(&["agent", "enroll", "--relay", &url, "--token", &token]);
    assert!(
        enrolled.contains("(as reported by the relay, not verified)"),
        "{enrolled}"
    );
    let _third_agent = start_agent(&root, &third);
    let mismatch = operator.run_failing(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(mismatch.contains("HOST KEY MISMATCH"), "{mismatch}");
}
