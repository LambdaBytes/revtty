use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey};

use crate::config::Paths;
use crate::error::RevttyError;

pub struct IdentityInfo {
    pub private_key: PathBuf,
    pub public_key: PathBuf,
    pub fingerprint: String,
}

pub fn ensure_operator_identity(paths: &Paths) -> Result<IdentityInfo, RevttyError> {
    fs::create_dir_all(&paths.config_dir)
        .map_err(|error| RevttyError::runtime("create revtty config directory", error))?;

    let private_path = paths.config_dir.join("id_ed25519");
    let public_path = paths.config_dir.join("id_ed25519.pub");

    let private_key = if private_path.exists() {
        load_private_key(&private_path)?
    } else {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|error| RevttyError::runtime("generate Ed25519 operator identity", error))?;

        let encoded = key
            .to_openssh(LineEnding::LF)
            .map_err(|error| RevttyError::runtime("encode operator private key", error))?;

        write_secret_new(&private_path, encoded.as_bytes())?;
        key
    };

    if private_key.algorithm() != Algorithm::Ed25519 {
        return Err(RevttyError::message(
            "revtty operator identity must be an Ed25519 key",
        ));
    }

    let public_key = private_key.public_key().clone();
    ensure_public_key(&public_path, &public_key)?;

    Ok(IdentityInfo {
        private_key: private_path,
        public_key: public_path,
        fingerprint: public_key.fingerprint(HashAlg::Sha256).to_string(),
    })
}

pub fn load_operator_private_key(paths: &Paths) -> Result<PrivateKey, RevttyError> {
    load_private_key(&paths.config_dir.join("id_ed25519"))
}

pub fn load_operator_public_key(paths: &Paths) -> Result<PublicKey, RevttyError> {
    let path = paths.config_dir.join("id_ed25519.pub");
    let encoded = fs::read_to_string(&path)
        .map_err(|error| RevttyError::runtime("read operator public key", error))?;

    PublicKey::from_openssh(&encoded)
        .map_err(|error| RevttyError::runtime("parse operator public key", error))
}

fn load_private_key(path: &Path) -> Result<PrivateKey, RevttyError> {
    let encoded = fs::read(path)
        .map_err(|error| RevttyError::runtime("read operator private key", error))?;

    PrivateKey::from_openssh(&encoded)
        .map_err(|error| RevttyError::runtime("parse operator private key", error))
}

fn ensure_public_key(path: &Path, expected: &PublicKey) -> Result<(), RevttyError> {
    if path.exists() {
        let encoded = fs::read_to_string(path)
            .map_err(|error| RevttyError::runtime("read operator public key", error))?;
        let existing = PublicKey::from_openssh(&encoded)
            .map_err(|error| RevttyError::runtime("parse operator public key", error))?;

        if existing != *expected {
            return Err(RevttyError::message(
                "operator public key does not match the private identity",
            ));
        }

        return Ok(());
    }

    let encoded = expected
        .to_openssh()
        .map_err(|error| RevttyError::runtime("encode operator public key", error))?;
    fs::write(path, format!("{encoded}\n"))
        .map_err(|error| RevttyError::runtime("write operator public key", error))
}

#[cfg(unix)]
fn write_secret_new(path: &Path, bytes: &[u8]) -> Result<(), RevttyError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| RevttyError::runtime("create operator private key", error))?;

    file.write_all(bytes)
        .map_err(|error| RevttyError::runtime("write operator private key", error))?;
    file.sync_all()
        .map_err(|error| RevttyError::runtime("sync operator private key", error))
}

#[cfg(not(unix))]
fn write_secret_new(path: &Path, bytes: &[u8]) -> Result<(), RevttyError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| RevttyError::runtime("create operator private key", error))?;

    file.write_all(bytes)
        .map_err(|error| RevttyError::runtime("write operator private key", error))?;
    file.sync_all()
        .map_err(|error| RevttyError::runtime("sync operator private key", error))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{ensure_operator_identity, load_operator_private_key, load_operator_public_key};
    use crate::config::Paths;

    #[test]
    fn operator_identity_is_idempotent_and_consistent() {
        let root = std::env::temp_dir().join(format!("revtty-identity-{}", uuid::Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));

        let first = ensure_operator_identity(&paths).expect("create operator identity");
        let second = ensure_operator_identity(&paths).expect("load operator identity");

        assert_eq!(first.fingerprint, second.fingerprint);

        let private_key = load_operator_private_key(&paths).expect("load private key");
        let public_key = load_operator_public_key(&paths).expect("load public key");
        assert_eq!(private_key.public_key(), &public_key);

        fs::remove_dir_all(root).expect("remove identity test directory");
    }

    #[cfg(unix)]
    #[test]
    fn private_key_uses_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("revtty-permissions-{}", uuid::Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));

        let identity = ensure_operator_identity(&paths).expect("create operator identity");
        let mode = fs::metadata(&identity.private_key)
            .expect("private key metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600);

        fs::remove_dir_all(root).expect("remove permissions test directory");
    }
}
