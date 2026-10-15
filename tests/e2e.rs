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
        std::fs::create_dir_all(&path).expect("create e2e root");
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
        let deadline = Instant::now() + within;
        loop {
            let log = self.log();
            if log.contains(pattern) {
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

fn field<'a>(output: &'a str, name: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .map(str::trim)
        .unwrap_or_else(|| panic!("missing {name:?} in output:\n{output}"))
}

fn start_relay(root: &TempRoot, relay_role: &Role) -> (Running, String) {
    let db = root.path("relay.db");
    let mut command = relay_role.command();
    command
        .args(["relay", "serve", "--bind", "127.0.0.1:0", "--db"])
        .arg(&db)
        .env("REVTTY_DEV_TOKEN", "e2e-dev-token");
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

fn enroll_agent(root: &TempRoot, relay_role: &Role, operator: &Role, agent: &Role, url: &str) {
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

    agent.run(&["agent", "enroll", "--relay", url, "--token", token]);
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
    fn connect(operator: &Role, url: &str) -> Self {
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
    enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let agent_process = start_agent(&root, &agent);

    let probe = operator.run(&["probe", AGENT_NAME, "--relay", &url]);
    assert!(
        probe.contains("status   reachable"),
        "unexpected probe output:\n{probe}"
    );

    let mut terminal = Terminal::connect(&operator, &url);
    let logs = [&relay, &agent_process];
    terminal.wait_ready(Duration::from_secs(20), &logs);

    // The marker is computed remotely, so the echoed input cannot match it.
    terminal.send("echo REVTTY_E2E_$((6*7)); exit 7\r");
    terminal.wait_for("REVTTY_E2E_42", Duration::from_secs(20), &logs);
    terminal.wait_for("connection closed (exit 7)", Duration::from_secs(20), &logs);

    assert!(
        terminal.wait_exit(Duration::from_secs(5)).is_some(),
        "revtty connect kept running after the session closed:\n{}",
        terminal.text()
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
    enroll_agent(&root, &relay_role, &operator, &agent, &url);
    let mut agent_process = start_agent(&root, &agent);

    let mut terminal = Terminal::connect(&operator, &url);
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
