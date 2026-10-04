use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use serde::{Deserialize, Serialize};

use crate::config::Paths;
use crate::error::RevttyError;

const AGENT_CONFIG_FILE: &str = "agent.toml";
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

#[derive(Serialize, Deserialize)]
pub struct AgentConfig {
    pub relay: String,
    pub agent_id: String,
    pub name: String,
    pub control_token: String,
    pub operator_key: String,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
}

impl AgentConfig {
    pub fn path(paths: &Paths) -> PathBuf {
        paths.config_dir.join(AGENT_CONFIG_FILE)
    }

    pub fn load(paths: &Paths) -> Result<Self, RevttyError> {
        let path = Self::path(paths);
        let encoded = fs::read_to_string(&path)
            .map_err(|error| RevttyError::runtime("read agent configuration", error))?;
        let config: Self = toml::from_str(&encoded)
            .map_err(|error| RevttyError::runtime("parse agent configuration", error))?;
        validate_max_sessions(config.max_sessions)?;
        Ok(config)
    }

    pub fn save(&self, paths: &Paths) -> Result<(), RevttyError> {
        validate_max_sessions(self.max_sessions)?;
        fs::create_dir_all(&paths.config_dir)
            .map_err(|error| RevttyError::runtime("create agent config directory", error))?;

        let path = Self::path(paths);
        let encoded = toml::to_string_pretty(self)
            .map_err(|error| RevttyError::runtime("encode agent configuration", error))?;

        write_private_file(&path, encoded.as_bytes())
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
    file.write_all(content)
        .map_err(|error| RevttyError::runtime("write agent configuration", error))?;
    file.sync_all()
        .map_err(|error| RevttyError::runtime("sync agent configuration", error))
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use uuid::Uuid;

    use super::AgentConfig;
    use crate::config::Paths;

    #[test]
    fn agent_config_round_trips_privately() {
        let root = std::env::temp_dir().join(format!("revtty-agent-config-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        let config = AgentConfig {
            relay: "https://relay.example.com".to_owned(),
            agent_id: "agent-id".to_owned(),
            name: "store-042".to_owned(),
            control_token: "rva_secret".to_owned(),
            operator_key: "ssh-ed25519 AAAA".to_owned(),
            max_sessions: 7,
        };

        config.save(&paths).expect("save agent config");
        let loaded = AgentConfig::load(&paths).expect("load agent config");

        assert_eq!(loaded.relay, config.relay);
        assert_eq!(loaded.agent_id, config.agent_id);
        assert_eq!(loaded.name, config.name);
        assert_eq!(loaded.control_token, config.control_token);
        assert_eq!(loaded.operator_key, config.operator_key);
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
    fn rejects_invalid_session_limits() {
        assert!(super::validate_max_sessions(0).is_err());
        assert!(super::validate_max_sessions(super::MAX_SESSIONS_LIMIT + 1).is_err());
    }
}
