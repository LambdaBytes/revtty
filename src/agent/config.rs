use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, HashAlg, PublicKey};

use crate::config::{ExclusiveLock, Paths};
use crate::error::RevttyError;
use crate::protocol::MAX_OPERATORS;

const AGENT_CONFIG_FILE: &str = "agent.toml";
/// Written in full and then renamed over `agent.toml`, so a reader sees either the previous
/// configuration or the new one, never a partial file.
const AGENT_CONFIG_TEMP_FILE: &str = ".agent.toml.tmp";
/// Held while `agent.toml` is read, changed and written back. It is never renamed or
/// removed, so every writer locks the same file.
const AGENT_CONFIG_LOCK_FILE: &str = "agent.lock";
/// Held by `agent run` for as long as it runs.
const AGENT_RUN_LOCK_FILE: &str = "agent.run.lock";
pub const DEFAULT_MAX_SESSIONS: usize = 4;
pub const MAX_SESSIONS_LIMIT: usize = 64;

fn default_max_sessions() -> usize {
    DEFAULT_MAX_SESSIONS
}

pub fn validate_max_sessions(value: usize) -> Result<(), RevttyError> {
    if !(1..=MAX_SESSIONS_LIMIT).contains(&value) {
        return Err(RevttyError::message(format!(
            "max_sessions must be between 1 and {MAX_SESSIONS_LIMIT}"
        )));
    }

    Ok(())
}

/// SHA-256 fingerprint of an operator key, which must be an OpenSSH Ed25519 public key.
pub fn operator_fingerprint(encoded: &str) -> Result<String, RevttyError> {
    Ok(parse_operator_key(encoded)?
        .fingerprint(HashAlg::Sha256)
        .to_string())
}

fn parse_operator_key(encoded: &str) -> Result<PublicKey, RevttyError> {
    let key = PublicKey::from_openssh(encoded)
        .map_err(|error| RevttyError::runtime("parse operator key", error))?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(RevttyError::message("v1 requires Ed25519 operator keys"));
    }

    Ok(key)
}

/// A usable operator list: not empty, within bounds, valid Ed25519 keys, no key twice.
pub fn validate_operators(operators: &[String]) -> Result<(), RevttyError> {
    if operators.is_empty() {
        return Err(RevttyError::message(
            "the agent configuration authorizes no operator",
        ));
    }
    if operators.len() > MAX_OPERATORS {
        return Err(RevttyError::message(format!(
            "an agent authorizes at most {MAX_OPERATORS} operators"
        )));
    }

    let mut seen = HashSet::new();
    for encoded in operators {
        let fingerprint = operator_fingerprint(encoded)?;
        if !seen.insert(fingerprint.clone()) {
            return Err(RevttyError::message(format!(
                "operator {fingerprint} is listed twice"
            )));
        }
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct AgentConfig {
    pub relay: String,
    pub agent_id: String,
    pub name: String,
    pub control_token: String,
    /// OpenSSH public keys of the operators allowed to open shells; never empty. This list,
    /// not the relay, is what the agent's SSH authentication enforces.
    #[serde(default)]
    pub operators: Vec<String>,
    /// Grows with every change to `operators`.
    #[serde(default)]
    pub operators_revision: u64,
    /// The single operator key of configurations written before operator lists.
    #[serde(default, rename = "operator_key", skip_serializing)]
    legacy_operator_key: Option<String>,
    /// The control credential a rotation in progress replaces `control_token` with, saved
    /// before the relay hears of it so that an interrupted rotation can be finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_control_token: Option<String>,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
}

impl AgentConfig {
    /// A newly enrolled agent, authorizing the operator it was enrolled for.
    pub fn new(
        relay: String,
        agent_id: String,
        name: String,
        control_token: String,
        operator_key: String,
        max_sessions: usize,
    ) -> Self {
        Self {
            relay,
            agent_id,
            name,
            control_token,
            operators: vec![operator_key],
            operators_revision: 1,
            legacy_operator_key: None,
            pending_control_token: None,
            max_sessions,
        }
    }

    pub fn path(paths: &Paths) -> PathBuf {
        paths.config_dir.join(AGENT_CONFIG_FILE)
    }

    pub fn load(paths: &Paths) -> Result<Self, RevttyError> {
        let path = Self::path(paths);
        let encoded = fs::read_to_string(&path)
            .map_err(|error| RevttyError::runtime("read agent configuration", error))?;
        // Only where, never what: toml quotes the offending line and serde the offending value,
        // either of which may be the control credential, and agents log these errors.
        let mut config: Self = toml::from_str(&encoded).map_err(|error| {
            let line = error
                .span()
                .and_then(|span| encoded.get(..span.start))
                .map(|before| before.matches('\n').count() + 1);
            RevttyError::message(match line {
                Some(line) => format!(
                    "agent configuration {} is invalid at line {line} (content not shown: \
                     the file holds the control credential)",
                    path.display()
                ),
                None => format!(
                    "agent configuration {} is invalid (content not shown: the file holds the \
                     control credential)",
                    path.display()
                ),
            })
        })?;

        if let Some(legacy) = config.legacy_operator_key.take()
            && config.operators.is_empty()
        {
            config.operators.push(legacy);
            config.operators_revision = config.operators_revision.max(1);
        }

        config.validate()?;
        Ok(config)
    }

    /// Replaces the stored configuration with this one.
    pub fn save(&self, paths: &Paths) -> Result<(), RevttyError> {
        let lock = ConfigLock::acquire(paths)?;
        self.write(paths, &lock)
    }

    /// Reads the stored configuration, applies `change` and writes the result, holding the
    /// configuration lock throughout so that concurrent changes are never lost. Nothing is
    /// written when `change` fails.
    pub fn update<T>(
        paths: &Paths,
        change: impl FnOnce(&mut Self) -> Result<T, RevttyError>,
    ) -> Result<T, RevttyError> {
        let lock = ConfigLock::acquire(paths)?;
        let mut config = Self::load(paths)?;
        let outcome = change(&mut config)?;
        config.write(paths, &lock)?;
        Ok(outcome)
    }

    /// Authorizes one more operator key, returning its fingerprint.
    pub fn add_operator(&mut self, encoded: &str) -> Result<String, RevttyError> {
        let key = parse_operator_key(encoded.trim())?;
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        // Comments do not identify keys: the same key material is the same operator.
        if self
            .operators
            .iter()
            .any(|existing| operator_fingerprint(existing).is_ok_and(|known| known == fingerprint))
        {
            return Err(RevttyError::message(format!(
                "operator {fingerprint} is already authorized"
            )));
        }
        if self.operators.len() >= MAX_OPERATORS {
            return Err(RevttyError::message(format!(
                "an agent authorizes at most {MAX_OPERATORS} operators"
            )));
        }

        let encoded = key
            .to_openssh()
            .map_err(|error| RevttyError::runtime("encode operator key", error))?;
        self.operators.push(encoded);
        self.bump_operators_revision()?;
        Ok(fingerprint)
    }

    /// Removes the operator whose key has `fingerprint`; the last operator cannot be removed.
    pub fn revoke_operator(&mut self, fingerprint: &str) -> Result<(), RevttyError> {
        let Some(index) = self.operators.iter().position(|encoded| {
            operator_fingerprint(encoded).is_ok_and(|known| known == fingerprint)
        }) else {
            return Err(RevttyError::message(format!(
                "no authorized operator has fingerprint {fingerprint}"
            )));
        };
        if self.operators.len() == 1 {
            return Err(RevttyError::message(
                "cannot revoke the last operator; authorize another one first",
            ));
        }

        self.operators.remove(index);
        self.bump_operators_revision()
    }

    fn bump_operators_revision(&mut self) -> Result<(), RevttyError> {
        self.operators_revision = self
            .operators_revision
            .checked_add(1)
            .ok_or_else(|| RevttyError::message("operator list revision overflow"))?;
        Ok(())
    }

    fn validate(&self) -> Result<(), RevttyError> {
        validate_max_sessions(self.max_sessions)?;
        // The relay stores it as a signed 64-bit integer.
        if i64::try_from(self.operators_revision).is_err() {
            return Err(RevttyError::message("operators_revision is out of range"));
        }
        validate_operators(&self.operators)
    }

    fn write(&self, paths: &Paths, _lock: &ConfigLock) -> Result<(), RevttyError> {
        self.validate()?;
        let encoded = toml::to_string_pretty(self)
            .map_err(|error| RevttyError::runtime("encode agent configuration", error))?;

        let temp = paths.config_dir.join(AGENT_CONFIG_TEMP_FILE);
        write_private_file(&temp, encoded.as_bytes())?;
        fs::rename(&temp, Self::path(paths))
            .map_err(|error| RevttyError::runtime("replace agent configuration", error))?;
        // The rename survives a power loss only once the directory entry is on disk; callers
        // act on the new configuration (and tell the relay about it) right after this.
        File::open(&paths.config_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                RevttyError::runtime(
                    "agent configuration replaced, but syncing its directory failed",
                    error,
                )
            })
    }
}

/// Exclusive hold on the agent configuration, released when dropped.
struct ConfigLock {
    _lock: ExclusiveLock,
}

impl ConfigLock {
    fn acquire(paths: &Paths) -> Result<Self, RevttyError> {
        crate::config::create_private_dir(&paths.config_dir)
            .map_err(|error| RevttyError::runtime("create agent config directory", error))?;

        ExclusiveLock::acquire(&paths.config_dir.join(AGENT_CONFIG_LOCK_FILE))
            .map(|lock| Self { _lock: lock })
            .map_err(|error| RevttyError::runtime("lock agent configuration", error))
    }
}

/// Held by a running agent. `rotate-credential` needs the agent stopped, and a second agent on
/// one configuration would fight the first over its relay connection.
pub struct RunLock {
    _lock: ExclusiveLock,
}

impl RunLock {
    /// The lock, or `None` while an agent is running with this configuration.
    pub fn try_acquire(paths: &Paths) -> Result<Option<Self>, RevttyError> {
        crate::config::create_private_dir(&paths.config_dir)
            .map_err(|error| RevttyError::runtime("create agent config directory", error))?;

        ExclusiveLock::try_acquire(&paths.config_dir.join(AGENT_RUN_LOCK_FILE))
            .map(|lock| lock.map(|lock| Self { _lock: lock }))
            .map_err(|error| RevttyError::runtime("lock the agent's run state", error))
    }
}

fn write_private_file(path: &Path, content: &[u8]) -> Result<(), RevttyError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(path)
        .map_err(|error| RevttyError::runtime("open agent configuration", error))?;

    // The creation mode does not apply to an existing file; make it private before the
    // control token is written into it.
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| RevttyError::runtime("secure agent configuration permissions", error))?;

    file.write_all(content)
        .map_err(|error| RevttyError::runtime("write agent configuration", error))?;
    file.sync_all()
        .map_err(|error| RevttyError::runtime("sync agent configuration", error))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use ssh_key::{Algorithm, PrivateKey};
    use uuid::Uuid;

    use super::{AgentConfig, operator_fingerprint};
    use crate::config::Paths;

    fn operator_key(comment: &str) -> String {
        let mut key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
            .expect("generate operator key");
        key.set_comment(comment);
        key.public_key().to_openssh().expect("encode operator key")
    }

    fn test_paths(label: &str) -> (std::path::PathBuf, Paths) {
        let root = std::env::temp_dir().join(format!("revtty-{label}-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        (root, paths)
    }

    fn enrolled(operator: &str, max_sessions: usize) -> AgentConfig {
        AgentConfig::new(
            "https://relay.example.com".to_owned(),
            "agent-id".to_owned(),
            "store-042".to_owned(),
            "rva_secret".to_owned(),
            operator.to_owned(),
            max_sessions,
        )
    }

    #[test]
    fn agent_config_round_trips_privately() {
        let (root, paths) = test_paths("agent-config");
        let operator = operator_key("operator");
        let config = enrolled(&operator, 7);

        config.save(&paths).expect("save agent config");
        let loaded = AgentConfig::load(&paths).expect("load agent config");

        assert_eq!(loaded.relay, config.relay);
        assert_eq!(loaded.agent_id, config.agent_id);
        assert_eq!(loaded.name, config.name);
        assert_eq!(loaded.control_token, config.control_token);
        assert_eq!(loaded.operators, vec![operator]);
        assert_eq!(loaded.operators_revision, 1);
        assert_eq!(loaded.max_sessions, 7);

        #[cfg(unix)]
        {
            let mode = fs::metadata(AgentConfig::path(&paths))
                .expect("agent config metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        fs::remove_dir_all(root).expect("clean agent config test directory");
    }

    #[cfg(unix)]
    #[test]
    fn saving_over_a_readable_config_makes_it_private() {
        let (root, paths) = test_paths("agent-perms");
        fs::create_dir_all(&paths.config_dir).expect("create config directory");

        // A config left world-readable, e.g. created by hand or restored from a backup.
        let path = AgentConfig::path(&paths);
        fs::write(&path, "stale").expect("write stale config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("make stale config readable");

        enrolled(&operator_key("operator"), 4)
            .save(&paths)
            .expect("save agent config");

        let mode = fs::metadata(&path)
            .expect("agent config metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "control token written to a readable file");

        fs::remove_dir_all(root).expect("clean agent config test directory");
    }

    #[test]
    fn legacy_agent_config_defaults_session_limit() {
        let config: AgentConfig = toml::from_str(
            r#"
relay = "https://relay.example.com"
agent_id = "agent-id"
name = "store-042"
control_token = "rva_secret"
operator_key = "ssh-ed25519 AAAA"
"#,
        )
        .expect("parse legacy agent config");

        assert_eq!(config.max_sessions, super::DEFAULT_MAX_SESSIONS);
    }

    #[test]
    fn legacy_operator_key_loads_as_the_only_operator() {
        let (root, paths) = test_paths("agent-legacy");
        fs::create_dir_all(&paths.config_dir).expect("create config directory");
        let operator = operator_key("legacy");
        fs::write(
            AgentConfig::path(&paths),
            format!(
                "relay = \"https://relay.example.com\"\nagent_id = \"agent-id\"\n\
                 name = \"store-042\"\ncontrol_token = \"rva_secret\"\n\
                 operator_key = \"{operator}\"\n"
            ),
        )
        .expect("write legacy config");

        let loaded = AgentConfig::load(&paths).expect("load legacy config");
        assert_eq!(loaded.operators, vec![operator.clone()]);
        assert_eq!(loaded.operators_revision, 1);

        // Rewritten in the current format only.
        AgentConfig::update(&paths, |_| Ok(())).expect("rewrite legacy config");
        let stored = fs::read_to_string(AgentConfig::path(&paths)).expect("read config");
        assert!(stored.contains("operators = ["), "{stored}");
        assert!(!stored.contains("operator_key"), "{stored}");
        assert_eq!(
            AgentConfig::load(&paths).expect("reload").operators,
            vec![operator]
        );

        fs::remove_dir_all(root).expect("clean agent config test directory");
    }

    #[test]
    fn legacy_operator_key_with_a_long_comment_still_loads() {
        let (root, paths) = test_paths("agent-legacy-long");
        fs::create_dir_all(&paths.config_dir).expect("create config directory");
        let operator = operator_key(&"c".repeat(2048));
        fs::write(
            AgentConfig::path(&paths),
            format!(
                "relay = \"https://relay.example.com\"\nagent_id = \"agent-id\"\n\
                 name = \"store-042\"\ncontrol_token = \"rva_secret\"\n\
                 operator_key = \"{operator}\"\n"
            ),
        )
        .expect("write legacy config");

        let loaded = AgentConfig::load(&paths).expect("load legacy config with a long comment");
        assert_eq!(loaded.operators, vec![operator]);

        fs::remove_dir_all(root).expect("clean agent config test directory");
    }

    #[test]
    fn revisions_beyond_the_relay_range_are_refused() {
        let mut config = enrolled(&operator_key("operator"), 4);
        config.operators_revision = i64::MAX as u64;
        assert!(config.validate().is_ok());
        config.operators_revision += 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn operators_are_added_and_revoked_by_fingerprint() {
        let first = operator_key("first");
        let second = operator_key("second");
        let mut config = enrolled(&first, 4);

        let fingerprint = config.add_operator(&second).expect("add operator");
        assert_eq!(
            fingerprint,
            operator_fingerprint(&second).expect("fingerprint")
        );
        assert_eq!(config.operators.len(), 2);
        assert_eq!(config.operators_revision, 2);

        // The same key under another comment is the same operator.
        let renamed = second.replace(" second", " renamed");
        assert!(config.add_operator(&renamed).is_err());
        assert!(config.add_operator("ssh-rsa AAAA not-ed25519").is_err());

        config
            .revoke_operator(&fingerprint)
            .expect("revoke operator");
        assert_eq!(config.operators, vec![first.clone()]);
        assert_eq!(config.operators_revision, 3);

        let only = operator_fingerprint(&first).expect("fingerprint");
        let refused = config
            .revoke_operator(&only)
            .expect_err("last operator revoked");
        assert!(refused.to_string().contains("last operator"), "{refused}");
        assert!(config.revoke_operator("SHA256:unknown").is_err());
        assert_eq!(config.operators_revision, 3, "a refused change counted");
    }

    #[test]
    fn concurrent_updates_are_never_lost() {
        let (root, paths) = test_paths("agent-concurrent");
        enrolled(&operator_key("initial"), 4)
            .save(&paths)
            .expect("save agent config");

        let writers = 6;
        let barrier = Arc::new(Barrier::new(writers));
        let handles = (0..writers)
            .map(|index| {
                let paths = paths.clone();
                let barrier = Arc::clone(&barrier);
                let key = operator_key(&format!("writer-{index}"));
                std::thread::spawn(move || {
                    barrier.wait();
                    AgentConfig::update(&paths, |config| {
                        // Every writer reads before any of them writes, unless they are
                        // serialized.
                        std::thread::sleep(Duration::from_millis(50));
                        config.add_operator(&key)
                    })
                    .expect("add operator concurrently");
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().expect("writer thread");
        }

        let loaded = AgentConfig::load(&paths).expect("load agent config");
        assert_eq!(loaded.operators.len(), writers + 1, "an update was lost");
        assert_eq!(loaded.operators_revision, writers as u64 + 1);

        fs::remove_dir_all(root).expect("clean agent config test directory");
    }

    #[test]
    fn parse_errors_do_not_quote_the_configuration() {
        let (root, paths) = test_paths("agent-parse-error");
        fs::create_dir_all(&paths.config_dir).expect("create config directory");

        for (broken, line) in [
            // A syntax error, which toml reports with the line it is on.
            (
                "relay = \"https://relay.example.com\"\ncontrol_token = \"rva_SECRET_MARKER\n",
                "line 2",
            ),
            // A value of the wrong type, which serde reports with the value.
            (
                "relay = \"https://relay.example.com\"\nagent_id = \"agent-id\"\n\
                 name = \"store-042\"\ncontrol_token = \"rva_other\"\n\
                 max_sessions = \"rva_SECRET_MARKER\"\n",
                "line 5",
            ),
        ] {
            fs::write(AgentConfig::path(&paths), broken).expect("write broken config");
            let error = AgentConfig::load(&paths)
                .err()
                .expect("broken configuration loaded");
            let error = error.to_string();
            assert!(!error.contains("SECRET_MARKER"), "{error}");
            assert!(error.contains(line), "{error}");
        }

        fs::remove_dir_all(root).expect("clean agent config test directory");
    }

    #[test]
    fn rejects_invalid_session_limits() {
        assert!(super::validate_max_sessions(0).is_err());
        assert!(super::validate_max_sessions(super::MAX_SESSIONS_LIMIT + 1).is_err());
    }

    #[test]
    fn rejects_unusable_operator_lists() {
        let key = operator_key("operator");
        assert!(super::validate_operators(&[]).is_err());
        assert!(super::validate_operators(&[key.clone(), key.clone()]).is_err());
        assert!(super::validate_operators(&["ssh-ed25519 AAAA".to_owned()]).is_err());
        assert!(super::validate_operators(&[key]).is_ok());
    }
}
