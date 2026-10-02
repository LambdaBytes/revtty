use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use serde::{Deserialize, Serialize};

use crate::config::Paths;
use crate::error::RevttyError;

const AGENT_CONFIG_FILE: &str = "agent.toml";

#[derive(Serialize, Deserialize)]
pub struct AgentConfig {
    pub relay: String,
    pub agent_id: String,
    pub name: String,
    pub control_token: String,
    pub operator_key: String,
}

impl AgentConfig {
    pub fn path(paths: &Paths) -> PathBuf {
        paths.config_dir.join(AGENT_CONFIG_FILE)
    }

    pub fn load(paths: &Paths) -> Result<Self, RevttyError> {
        let path = Self::path(paths);
        let encoded = fs::read_to_string(&path)
            .map_err(|error| RevttyError::runtime("read agent configuration", error))?;
        toml::from_str(&encoded)
            .map_err(|error| RevttyError::runtime("parse agent configuration", error))
    }

    pub fn save(&self, paths: &Paths) -> Result<(), RevttyError> {
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
        };

        config.save(&paths).expect("save agent config");
        let loaded = AgentConfig::load(&paths).expect("load agent config");

        assert_eq!(loaded.relay, config.relay);
        assert_eq!(loaded.agent_id, config.agent_id);
        assert_eq!(loaded.name, config.name);
        assert_eq!(loaded.control_token, config.control_token);
        assert_eq!(loaded.operator_key, config.operator_key);

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
}
