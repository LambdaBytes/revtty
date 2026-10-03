use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use sha2::{Digest, Sha256};
use ssh_key::known_hosts::{Entry as KnownHostEntry, HostPatterns};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, KnownHosts, LineEnding, PrivateKey, PublicKey};

use crate::config::Paths;
use crate::error::RevttyError;

const OPERATOR_KEY_FILE: &str = "id_ed25519";
const OPERATOR_PUBLIC_KEY_FILE: &str = "id_ed25519.pub";
const AGENT_KEY_FILE: &str = "agent_ed25519";
const AGENT_PUBLIC_KEY_FILE: &str = "agent_ed25519.pub";
const KNOWN_HOSTS_FILE: &str = "known_hosts";

pub struct AgentIdentity {
    pub public_key: String,
    pub fingerprint: String,
    pub created: bool,
}

pub struct OperatorIdentity {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub fingerprint: String,
    pub created: bool,
}

pub struct HostKeyPin {
    pub fingerprint: String,
    pub created: bool,
}

pub fn ensure_agent(paths: &Paths) -> Result<AgentIdentity, RevttyError> {
    fs::create_dir_all(&paths.state_dir)
        .map_err(|error| RevttyError::runtime("create agent state directory", error))?;

    let private_key_path = paths.state_dir.join(AGENT_KEY_FILE);
    let public_key_path = paths.state_dir.join(AGENT_PUBLIC_KEY_FILE);

    let (private_key, created) = if private_key_path.exists() {
        let key = PrivateKey::read_openssh_file(&private_key_path)
            .map_err(|error| RevttyError::runtime("read agent private key", error))?;
        (key, false)
    } else {
        let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|error| RevttyError::runtime("generate agent Ed25519 key", error))?;
        key.set_comment("revtty-agent");
        write_private_key(&private_key_path, &key)?;
        (key, true)
    };

    secure_private_key_permissions(&private_key_path)?;

    let public_key = private_key.public_key();
    let public_text = public_key
        .to_openssh()
        .map_err(|error| RevttyError::runtime("encode agent public key", error))?;

    fs::write(&public_key_path, format!("{public_text}\n"))
        .map_err(|error| RevttyError::runtime("write agent public key", error))?;

    Ok(AgentIdentity {
        public_key: public_text,
        fingerprint: public_key.fingerprint(HashAlg::Sha256).to_string(),
        created,
    })
}

pub fn ensure_operator(paths: &Paths) -> Result<OperatorIdentity, RevttyError> {
    fs::create_dir_all(&paths.config_dir)
        .map_err(|error| RevttyError::runtime("create operator config directory", error))?;

    let private_key_path = paths.config_dir.join(OPERATOR_KEY_FILE);
    let public_key_path = paths.config_dir.join(OPERATOR_PUBLIC_KEY_FILE);

    let (private_key, created) = if private_key_path.exists() {
        let key = PrivateKey::read_openssh_file(&private_key_path)
            .map_err(|error| RevttyError::runtime("read operator private key", error))?;
        (key, false)
    } else {
        let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|error| RevttyError::runtime("generate operator Ed25519 key", error))?;
        key.set_comment("revtty");
        write_private_key(&private_key_path, &key)?;
        (key, true)
    };

    secure_private_key_permissions(&private_key_path)?;

    let public_key = private_key.public_key();
    let public_text = public_key
        .to_openssh()
        .map_err(|error| RevttyError::runtime("encode operator public key", error))?;

    fs::write(&public_key_path, format!("{public_text}\n"))
        .map_err(|error| RevttyError::runtime("write operator public key", error))?;

    Ok(OperatorIdentity {
        private_key_path,
        public_key_path,
        fingerprint: public_key.fingerprint(HashAlg::Sha256).to_string(),
        created,
    })
}

pub fn pin_agent_host_key(
    paths: &Paths,
    relay: &str,
    agent_name: &str,
    encoded_key: &str,
) -> Result<HostKeyPin, RevttyError> {
    let public_key = PublicKey::from_openssh(encoded_key)
        .map_err(|error| RevttyError::runtime("parse enrolled agent host key", error))?;

    if public_key.algorithm() != Algorithm::Ed25519 {
        return Err(RevttyError::message(
            "v1 requires an Ed25519 agent host key",
        ));
    }

    fs::create_dir_all(&paths.config_dir)
        .map_err(|error| RevttyError::runtime("create operator config directory", error))?;

    let path = paths.config_dir.join(KNOWN_HOSTS_FILE);
    let alias = known_host_alias(relay, agent_name);
    let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();

    if path.exists() {
        let entries = KnownHosts::read_file(&path)
            .map_err(|error| RevttyError::runtime("read revtty known_hosts", error))?;

        for entry in entries {
            if !entry_matches_alias(&entry, &alias) {
                continue;
            }

            if entry.marker().is_some() {
                return Err(RevttyError::message(format!(
                    "host key for {agent_name} is marked revoked"
                )));
            }

            if entry.public_key() == &public_key {
                return Ok(HostKeyPin {
                    fingerprint,
                    created: false,
                });
            }

            return Err(RevttyError::message(format!(
                "HOST KEY MISMATCH for {agent_name}: pinned {}, received {}",
                entry.public_key().fingerprint(HashAlg::Sha256),
                fingerprint
            )));
        }
    }

    let public_text = public_key
        .to_openssh()
        .map_err(|error| RevttyError::runtime("encode enrolled agent host key", error))?;
    let line = format!("{alias} {public_text}");
    let entry = KnownHostEntry::from_str(&line)
        .map_err(|error| RevttyError::runtime("validate known_hosts entry", error))?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| RevttyError::runtime("open revtty known_hosts", error))?;

    writeln!(file, "{entry}")
        .map_err(|error| RevttyError::runtime("write revtty known_hosts", error))?;
    file.sync_all()
        .map_err(|error| RevttyError::runtime("sync revtty known_hosts", error))?;

    Ok(HostKeyPin {
        fingerprint,
        created: true,
    })
}

fn known_host_alias(relay: &str, agent_name: &str) -> String {
    let relay = canonical_relay_identity(relay);
    let digest = Sha256::digest(relay.as_bytes());
    let mut relay_id = String::with_capacity(16);

    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(relay_id, "{byte:02x}");
    }

    format!("revtty-{relay_id}-{agent_name}")
}

fn canonical_relay_identity(relay: &str) -> String {
    let relay = relay.trim().trim_end_matches('/').to_ascii_lowercase();

    if let Some(rest) = relay.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = relay.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        relay
    }
}

fn entry_matches_alias(entry: &KnownHostEntry, alias: &str) -> bool {
    match entry.host_patterns() {
        HostPatterns::Patterns(patterns) => patterns.iter().any(|pattern| pattern == alias),
        HostPatterns::HashedName { .. } => false,
    }
}

fn write_private_key(path: &Path, key: &PrivateKey) -> Result<(), RevttyError> {
    let encoded = key
        .to_openssh(LineEnding::LF)
        .map_err(|error| RevttyError::runtime("encode operator private key", error))?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(path)
        .map_err(|error| RevttyError::runtime("create operator private key", error))?;

    file.write_all(encoded.as_bytes())
        .map_err(|error| RevttyError::runtime("write operator private key", error))?;
    file.sync_all()
        .map_err(|error| RevttyError::runtime("sync operator private key", error))
}

fn secure_private_key_permissions(path: &Path) -> Result<(), RevttyError> {
    #[cfg(unix)]
    {
        let metadata = fs::metadata(path)
            .map_err(|error| RevttyError::runtime("inspect operator private key", error))?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions).map_err(|error| {
            RevttyError::runtime("secure operator private key permissions", error)
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};
    use uuid::Uuid;

    use super::{ensure_operator, pin_agent_host_key};
    use crate::config::Paths;

    #[test]
    fn host_key_pinning_is_stable_and_rejects_changes() {
        let root = std::env::temp_dir().join(format!("revtty-known-hosts-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));

        let first_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("first agent key")
            .public_key()
            .to_openssh()
            .expect("first agent public key");
        let second_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("second agent key")
            .public_key()
            .to_openssh()
            .expect("second agent public key");

        let first = pin_agent_host_key(
            &paths,
            "https://relay.example.com/",
            "store-042",
            &first_key,
        )
        .expect("pin first host key");
        assert!(first.created);

        let same = pin_agent_host_key(&paths, "wss://relay.example.com", "store-042", &first_key)
            .expect("reuse same host key");
        assert!(!same.created);
        assert_eq!(same.fingerprint, first.fingerprint);

        let mismatch = pin_agent_host_key(
            &paths,
            "https://relay.example.com",
            "store-042",
            &second_key,
        );
        assert!(mismatch.is_err());

        let other_relay = pin_agent_host_key(
            &paths,
            "https://other-relay.example.com",
            "store-042",
            &second_key,
        )
        .expect("pin same name on another relay");
        assert!(other_relay.created);

        let known_hosts =
            fs::read_to_string(paths.config_dir.join("known_hosts")).expect("read known_hosts");
        assert_eq!(known_hosts.lines().count(), 2);

        fs::remove_dir_all(root).expect("clean known_hosts test directory");
    }

    #[test]
    fn operator_identity_is_stable_and_private() {
        let root = std::env::temp_dir().join(format!("revtty-identity-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));

        let first = ensure_operator(&paths).expect("create operator identity");
        let second = ensure_operator(&paths).expect("load operator identity");

        assert!(first.created);
        assert!(!second.created);
        assert_eq!(first.fingerprint, second.fingerprint);
        assert!(first.fingerprint.starts_with("SHA256:"));
        assert!(first.private_key_path.exists());
        assert!(first.public_key_path.exists());

        #[cfg(unix)]
        {
            let mode = fs::metadata(&first.private_key_path)
                .expect("private key metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        fs::remove_dir_all(root).expect("clean identity test directory");
    }
}
