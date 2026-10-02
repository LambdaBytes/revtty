use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

use crate::config::Paths;
use crate::error::RevttyError;

const OPERATOR_KEY_FILE: &str = "id_ed25519";
const OPERATOR_PUBLIC_KEY_FILE: &str = "id_ed25519.pub";

pub struct OperatorIdentity {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub fingerprint: String,
    pub created: bool,
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

    use uuid::Uuid;

    use super::ensure_operator;
    use crate::config::Paths;

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
