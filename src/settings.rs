use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::RevttyError;

const SETTINGS_FILE: &str = "config.toml";
pub const DEFAULT_BIND: &str = "127.0.0.1:8787";
pub const DEFAULT_DB: &str = "revtty.db";

/// `config.toml` in the config directory: optional settings of the operator and relay
/// commands. A flag wins over its environment variable, which wins over this file, which wins
/// over the built-in default; the operator's relay has no default.
pub struct Settings {
    /// `None` without a config directory: then there is no file either.
    path: Option<PathBuf>,
    file: SettingsFile,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsFile {
    #[serde(default)]
    operator: OperatorSettings,
    #[serde(default)]
    relay: RelaySettings,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorSettings {
    relay: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelaySettings {
    bind: Option<String>,
    db: Option<PathBuf>,
}

impl Settings {
    /// Reads and checks the whole file, whichever values the command takes from it: a broken
    /// file fails at once instead of when a later command first needs it. No file is no
    /// settings.
    pub fn load(config_dir: Option<&Path>) -> Result<Self, RevttyError> {
        let Some(config_dir) = config_dir else {
            return Ok(Self {
                path: None,
                file: SettingsFile::default(),
            });
        };
        let path = config_dir.join(SETTINGS_FILE);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: Some(path),
                    file: SettingsFile::default(),
                });
            }
            Err(error) => {
                return Err(RevttyError::runtime(
                    &format!("inspect {}", path.display()),
                    error,
                ));
            }
        };

        // Whoever can replace it can send this operator to another relay. Checked before it is
        // opened: in a directory others can write, a FIFO in its place would block the read.
        crate::config::check_not_writable_by_others(config_dir)?;
        crate::config::check_not_writable_by_others(&path)?;
        if !metadata.is_file() {
            return Err(RevttyError::message(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        let encoded = fs::read_to_string(&path)
            .map_err(|error| RevttyError::runtime(&format!("read {}", path.display()), error))?;

        // Only where, never what: toml quotes the offending line and serde the offending value,
        // and a mistyped relay URL may carry a password.
        let file: SettingsFile = toml::from_str(&encoded).map_err(|error| {
            let line = error
                .span()
                .and_then(|span| encoded.get(..span.start))
                .map(|before| before.matches('\n').count() + 1);
            let at = line
                .map(|line| format!(" at line {line}"))
                .unwrap_or_default();
            RevttyError::message(format!(
                "{} is invalid{at} (content not shown); it may set relay under [operator], and \
                 bind and db under [relay]",
                path.display()
            ))
        })?;

        validate(&file, &path)?;
        Ok(Self {
            path: Some(path),
            file,
        })
    }
    /// The relay an operator command uses: `given` (--relay or REVTTY_RELAY), else the file's.
    pub fn operator_relay(&self, given: Option<String>) -> Result<String, RevttyError> {
        given
            .or_else(|| self.file.operator.relay.clone())
            .ok_or_else(|| {
                let file = self.path.as_deref().unwrap_or(Path::new(SETTINGS_FILE));
                RevttyError::message(format!(
                    "no relay configured: pass --relay, set REVTTY_RELAY, or set relay under \
                     [operator] in {}",
                    file.display()
                ))
            })
    }

    /// The address `relay serve` listens on: `given` (--bind), else the file's, else
    /// `DEFAULT_BIND`.
    pub fn relay_bind(&self, given: Option<String>) -> String {
        given
            .or_else(|| self.file.relay.bind.clone())
            .unwrap_or_else(|| DEFAULT_BIND.to_owned())
    }

    /// The relay database: `given` (--db or REVTTY_DB), else the file's, else `DEFAULT_DB`.
    pub fn relay_db(&self, given: Option<PathBuf>) -> PathBuf {
        given
            .or_else(|| self.file.relay.db.clone())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DB))
    }
}

/// The values the parser cannot check. Like parse errors, these never quote the file: the
/// transport's own errors name the host of a refused URL.
fn validate(file: &SettingsFile, path: &Path) -> Result<(), RevttyError> {
    let path = path.display();
    if let Some(relay) = &file.operator.relay
        && crate::transport::http_url(relay, "/").is_err()
    {
        return Err(RevttyError::message(format!(
            "relay under [operator] in {path} is not a relay URL revtty uses: https:// or wss://, \
             or http:// or ws:// for localhost, 127.0.0.0/8 or [::1] only, with no user name or \
             password"
        )));
    }
    if let Some(bind) = &file.relay.bind
        && bind.parse::<SocketAddr>().is_err()
    {
        return Err(RevttyError::message(format!(
            "bind under [relay] in {path} must be an IP address and a port, such as \
             {DEFAULT_BIND}"
        )));
    }
    // Relative to what would depend on where the command runs.
    if let Some(db) = &file.relay.db
        && !db.is_absolute()
    {
        return Err(RevttyError::message(format!(
            "db under [relay] in {path} must be an absolute path"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::Settings;
    use crate::config::Paths;

    struct TestDir {
        root: PathBuf,
        paths: Paths,
    }

    impl TestDir {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("revtty-settings-{}", Uuid::new_v4()));
            let paths = Paths::new(root.join("config"), root.join("state"));
            crate::config::create_private_dir(&paths.config_dir).expect("create config directory");
            Self { root, paths }
        }

        /// Written as an editor would with umask 022, whatever the umask of the tests.
        fn write(&self, content: &str) {
            let path = self.paths.config_dir.join("config.toml");
            fs::write(&path, content).expect("write settings");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("set mode");
            }
        }

        fn load(&self) -> Result<Settings, String> {
            Settings::load(Some(&self.paths.config_dir)).map_err(|error| error.to_string())
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn without_a_file_there_are_only_defaults_and_no_operator_relay() {
        let dir = TestDir::new();
        let settings = dir.load().expect("load without a file");

        assert_eq!(settings.relay_bind(None), super::DEFAULT_BIND);
        assert_eq!(settings.relay_db(None), PathBuf::from(super::DEFAULT_DB));
        let missing = settings
            .operator_relay(None)
            .expect_err("a relay without any setting")
            .to_string();
        for way in ["--relay", "REVTTY_RELAY", "[operator]", "config.toml"] {
            assert!(missing.contains(way), "{missing}");
        }
    }

    #[test]
    fn without_a_config_directory_there_is_no_file() {
        let settings = Settings::load(None).expect("load without a config directory");

        assert_eq!(settings.relay_db(None), PathBuf::from(super::DEFAULT_DB));
        let missing = settings
            .operator_relay(None)
            .expect_err("a relay without any setting")
            .to_string();
        assert!(missing.contains("config.toml"), "{missing}");
    }

    #[cfg(unix)]
    #[test]
    fn something_other_than_a_file_is_refused_without_reading_it() {
        let dir = TestDir::new();
        let path = dir.paths.config_dir.join("config.toml");
        let encoded = std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("path");
        // SAFETY: `encoded` is a valid NUL-terminated path for the duration of the call.
        assert_eq!(
            unsafe { libc::mkfifo(encoded.as_ptr(), 0o644) },
            0,
            "mkfifo"
        );

        // Reading a FIFO nobody writes blocks: on a thread, so that the test fails instead.
        let (loaded, outcome) = std::sync::mpsc::channel();
        let config_dir = dir.paths.config_dir.clone();
        std::thread::spawn(move || {
            let _ = loaded.send(
                Settings::load(Some(&config_dir))
                    .err()
                    .map(|e| e.to_string()),
            );
        });
        let error = outcome
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("loading blocked on the FIFO")
            .expect("FIFO loaded");
        assert!(error.contains("is not a regular file"), "{error}");
    }

    #[test]
    fn a_given_value_wins_over_the_file_which_wins_over_the_default() {
        let dir = TestDir::new();
        dir.write(
            "[operator]\nrelay = \"https://relay.example.com\"\n\n\
             [relay]\nbind = \"127.0.0.1:9000\"\ndb = \"/var/lib/revtty-relay/revtty.db\"\n",
        );
        let settings = dir.load().expect("load settings");

        assert_eq!(
            settings.operator_relay(None).expect("relay from the file"),
            "https://relay.example.com"
        );
        assert_eq!(
            settings
                .operator_relay(Some("wss://other.example.com".to_owned()))
                .expect("relay given"),
            "wss://other.example.com"
        );
        assert_eq!(settings.relay_bind(None), "127.0.0.1:9000");
        assert_eq!(
            settings.relay_bind(Some("[::1]:8787".to_owned())),
            "[::1]:8787"
        );
        assert_eq!(
            settings.relay_db(None),
            PathBuf::from("/var/lib/revtty-relay/revtty.db")
        );
        assert_eq!(
            settings.relay_db(Some(PathBuf::from("other.db"))),
            PathBuf::from("other.db")
        );
    }

    #[test]
    fn unknown_keys_and_invalid_values_are_refused() {
        let dir = TestDir::new();
        for (content, expected) in [
            (
                "relay = \"https://relay.example.com\"\n",
                "is invalid at line 1",
            ),
            (
                "[operator]\nrelay_url = \"https://relay.example.com\"\n",
                "is invalid at line 2",
            ),
            (
                "[relay]\nbind = \"127.0.0.1:8787\"\nport = 8787\n",
                "is invalid at line 3",
            ),
            (
                "[agent]\nrelay = \"https://relay.example.com\"\n",
                "is invalid",
            ),
            ("[relay]\ndb = \"revtty.db\"\n", "must be an absolute path"),
            (
                "[relay]\nbind = \"localhost:8787\"\n",
                "must be an IP address and a port",
            ),
            (
                "[operator]\nrelay = \"http://relay.example.com\"\n",
                "is not a relay URL revtty uses",
            ),
        ] {
            dir.write(content);
            let error = match dir.load() {
                Ok(_) => panic!("loaded {content:?}"),
                Err(error) => error,
            };
            assert!(error.contains(expected), "{content:?}: {error}");
        }
    }

    #[test]
    fn errors_never_show_the_content_of_the_file() {
        let dir = TestDir::new();
        for content in [
            // A syntax error, which toml reports with the line it is on.
            "[operator]\nrelay = \"https://user:SECRET_MARKER@relay.example.com\n",
            // A value of the wrong type, which serde reports with the value.
            "[relay]\nbind = \"127.0.0.1:8787\"\ndb = [\"SECRET_MARKER\"]\n",
            // A URL carrying credentials, refused when it is checked.
            "[operator]\nrelay = \"https://user:SECRET_MARKER@relay.example.com\"\n",
            // A refused URL, whose host the transport's error would name.
            "[operator]\nrelay = \"http://SECRET_MARKER.example.com\"\n",
        ] {
            dir.write(content);
            let error = match dir.load() {
                Ok(_) => panic!("loaded {content:?}"),
                Err(error) => error,
            };
            // Any case: a parsed URL comes back with its host in lower case.
            assert!(
                !error.to_ascii_lowercase().contains("secret_marker"),
                "{error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_file_or_directory_others_could_replace_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let set = |path: &std::path::Path, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
        };
        let dir = TestDir::new();
        dir.write("[operator]\nrelay = \"https://relay.example.com\"\n");
        let file = dir.paths.config_dir.join("config.toml");

        set(&file, 0o664);
        assert!(dir.load().is_err(), "group-writable file accepted");
        set(&file, 0o644);
        assert!(dir.load().is_ok());

        set(&dir.paths.config_dir, 0o777);
        assert!(dir.load().is_err(), "world-writable directory accepted");
        set(&dir.paths.config_dir, 0o700);
        assert!(dir.load().is_ok());
    }
}
