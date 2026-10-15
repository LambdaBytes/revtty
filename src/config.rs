use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;

use crate::error::RevttyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Paths {
    pub fn discover() -> Result<Self, RevttyError> {
        let dirs = ProjectDirs::from("io", "LambdaBytes", "revtty")
            .ok_or_else(|| RevttyError::message("unable to determine revtty user directories"))?;

        Ok(Self {
            config_dir: path_override("REVTTY_CONFIG_DIR", dirs.config_dir().to_path_buf())?,
            state_dir: path_override("REVTTY_STATE_DIR", dirs.data_local_dir().to_path_buf())?,
        })
    }

    #[cfg(test)]
    pub fn new(config_dir: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
            state_dir: state_dir.into(),
        }
    }
}

/// Creates a revtty config or state directory, and any missing parent, private to this user:
/// with a group-writable umask the defaults would let others replace keys or pins. Existing
/// directories keep their mode; `doctor` reports unsafe ones.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }

    builder.create(path)
}

/// An exclusive `flock` on `path`, held until dropped; the kernel also drops it when the
/// process dies. Lock files are never renamed or removed, so every writer locks the same file.
pub struct ExclusiveLock {
    _file: File,
}

impl ExclusiveLock {
    /// Waits until the lock is free.
    pub fn acquire(path: &Path) -> io::Result<Self> {
        Self::lock(path, libc::LOCK_EX)?
            .ok_or_else(|| io::Error::other("a blocking lock returned without the lock"))
    }

    /// Takes the lock only if nobody holds it.
    pub fn try_acquire(path: &Path) -> io::Result<Option<Self>> {
        Self::lock(path, libc::LOCK_EX | libc::LOCK_NB)
    }

    fn lock(path: &Path, operation: libc::c_int) -> io::Result<Option<Self>> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;

        loop {
            // SAFETY: `file` owns a valid descriptor for the duration of the call.
            if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
                return Ok(Some(Self { _file: file }));
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(None),
                _ => return Err(error),
            }
        }
    }
}

/// Fails when another user could modify `path`: replacing keys, credentials or pinned host
/// keys would bypass revtty's checks.
pub fn check_not_writable_by_others(path: &Path) -> Result<(), RevttyError> {
    #[cfg(unix)]
    {
        let mode = file_mode(path)?;
        if mode & 0o022 != 0 {
            return Err(RevttyError::message(format!(
                "{} is writable by other users (mode {mode:o}); run chmod go-w {}",
                path.display(),
                path.display()
            )));
        }
    }

    Ok(())
}

/// For a directory revtty does not create, such as the one holding the relay database:
/// world-writable fails; group-writable is returned as a warning, because with user private
/// groups (the default on Debian and Ubuntu, with umask 002) the group is only the owner.
pub fn check_shared_directory(path: &Path) -> Result<Option<String>, RevttyError> {
    #[cfg(unix)]
    {
        let mode = file_mode(path)?;
        if mode & 0o002 != 0 {
            return Err(RevttyError::message(format!(
                "{} is writable by other users (mode {mode:o}); run chmod o-w {}",
                path.display(),
                path.display()
            )));
        }
        if mode & 0o020 != 0 {
            return Ok(Some(format!(
                "{} is writable by its group (mode {mode:o}); make sure only trusted accounts are in it",
                path.display()
            )));
        }
    }

    Ok(None)
}

/// Fails when another user could read `path`, which holds a credential.
pub fn check_private_file(path: &Path) -> Result<(), RevttyError> {
    #[cfg(unix)]
    {
        let mode = file_mode(path)?;
        if mode & 0o077 != 0 {
            return Err(RevttyError::message(format!(
                "{} is accessible by other users (mode {mode:o}); run chmod 600 {}",
                path.display(),
                path.display()
            )));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Result<u32, RevttyError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777)
        .map_err(|error| RevttyError::runtime(&format!("inspect {}", path.display()), error))
}

fn path_override(name: &str, fallback: PathBuf) -> Result<PathBuf, RevttyError> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(fallback);
    };

    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(RevttyError::message(format!(
            "{name} must be an absolute path"
        )));
    }

    Ok(path)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use uuid::Uuid;

    use super::{
        check_not_writable_by_others, check_private_file, check_shared_directory,
        create_private_dir,
    };

    #[test]
    fn permission_checks_flag_other_users() {
        let root = std::env::temp_dir().join(format!("revtty-perms-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create test directory");
        let file = root.join("credential");
        fs::write(&file, "secret").expect("write test file");

        let set = |path: &std::path::Path, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
        };

        set(&file, 0o600);
        assert!(check_private_file(&file).is_ok());
        assert!(check_not_writable_by_others(&file).is_ok());

        set(&file, 0o644);
        assert!(check_private_file(&file).is_err());
        assert!(check_not_writable_by_others(&file).is_ok());

        set(&file, 0o664);
        assert!(check_not_writable_by_others(&file).is_err());

        set(&root, 0o777);
        assert!(check_not_writable_by_others(&root).is_err());
        assert!(check_shared_directory(&root).is_err());
        set(&root, 0o775);
        assert!(check_not_writable_by_others(&root).is_err());
        assert!(matches!(check_shared_directory(&root), Ok(Some(_))));
        set(&root, 0o700);
        assert!(check_not_writable_by_others(&root).is_ok());
        assert!(matches!(check_shared_directory(&root), Ok(None)));

        fs::remove_dir_all(root).expect("clean test directory");
    }

    #[test]
    fn revtty_directories_are_created_private() {
        let root = std::env::temp_dir().join(format!("revtty-private-dir-{}", Uuid::new_v4()));
        let nested = root.join("config").join("revtty");

        create_private_dir(&nested).expect("create private directory");

        for path in [&root, &root.join("config"), &nested] {
            let mode = fs::metadata(path)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "{} created with mode {mode:o}", path.display());
        }
        assert!(check_not_writable_by_others(&nested).is_ok());

        fs::remove_dir_all(root).expect("clean test directory");
    }
}
