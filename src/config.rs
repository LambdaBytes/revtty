use std::path::PathBuf;

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
