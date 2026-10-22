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
use crate::error::{ErrorKind, RevttyError};
use crate::pairing::PairingSecret;

const OPERATOR_KEY_FILE: &str = "id_ed25519";
const OPERATOR_PUBLIC_KEY_FILE: &str = "id_ed25519.pub";
const AGENT_KEY_FILE: &str = "agent_ed25519";
const AGENT_PUBLIC_KEY_FILE: &str = "agent_ed25519.pub";
const KNOWN_HOSTS_FILE: &str = "known_hosts";
/// Held by every writer of `known_hosts`: `forget` rewrites the file and would otherwise drop
/// a pin appended meanwhile.
const KNOWN_HOSTS_LOCK_FILE: &str = "known_hosts.lock";
const KNOWN_HOSTS_TEMP_FILE: &str = ".known_hosts.tmp";
/// Secrets of the pairings made with `revtty pair` and not used yet, one per agent; written
/// under the known_hosts lock, since each decides a pin.
const PAIRINGS_FILE: &str = "pairings";
const PAIRINGS_TEMP_FILE: &str = ".pairings.tmp";

pub struct AgentIdentity {
    pub private_key_path: PathBuf,
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

pub struct HostKeyCheck {
    pub fingerprint: String,
    /// Whether this key is already pinned for the agent on this relay.
    pub pinned: bool,
}

/// How a host key the relay presented is trusted (`trust_agent_host_key`).
pub enum HostKeyTrust {
    /// It is the pinned key.
    Pinned,
    /// Pinned now: the agent proved it with the pairing code made for it.
    Paired { fingerprint: String },
    /// Neither pinned nor proven: pinning it needs the operator's confirmation.
    Unknown { fingerprint: String },
}

/// What `forget_agent_host_key` removed.
pub struct Forgotten {
    /// Pins of the agent's host key.
    pub pins: usize,
    /// Whether a pairing was pending for the agent.
    pub pairing: bool,
}

/// What the pins say about a host key.
enum PinState {
    Pinned,
    Unpinned,
    /// Another key is pinned for the agent: its fingerprint.
    Mismatch(String),
}

pub fn ensure_agent(paths: &Paths) -> Result<AgentIdentity, RevttyError> {
    crate::config::create_private_dir(&paths.state_dir)
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
        private_key_path,
        public_key: public_text,
        fingerprint: public_key.fingerprint(HashAlg::Sha256).to_string(),
        created,
    })
}

pub fn ensure_operator(paths: &Paths) -> Result<OperatorIdentity, RevttyError> {
    crate::config::create_private_dir(&paths.config_dir)
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

/// Checks the relay-supplied host key of an agent against the operator's pin without ever
/// creating one: the relay is not trusted to introduce host keys, so a first pin needs the
/// operator's confirmation (`pin_agent_host_key`) or the agent's pairing proof
/// (`trust_agent_host_key`).
pub fn check_agent_host_key(
    paths: &Paths,
    relay: &str,
    agent_name: &str,
    encoded_key: &str,
) -> Result<HostKeyCheck, RevttyError> {
    let public_key = parse_agent_host_key(encoded_key)?;
    let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
    let alias = known_host_alias(relay, agent_name);

    let pinned = match pin_state(paths, &alias, agent_name, &public_key)? {
        PinState::Pinned => true,
        PinState::Unpinned => false,
        PinState::Mismatch(pinned) => {
            return Err(host_key_mismatch(relay, agent_name, &pinned, false));
        }
    };
    Ok(HostKeyCheck {
        fingerprint,
        pinned,
    })
}

/// Trusts the host key the relay presented when it is the pinned one, or when the agent
/// proved it with the pairing pending for it: then the key is pinned, in place of an earlier
/// pin (a machine reinstalled and paired again), and the pairing is used up. Without a
/// pairing, a key other than the pinned one is a hard failure; with one, so is a missing or
/// wrong proof, and then no file is touched.
pub fn trust_agent_host_key(
    paths: &Paths,
    relay: &str,
    agent_name: &str,
    encoded_key: &str,
    proof: Option<&str>,
) -> Result<HostKeyTrust, RevttyError> {
    let public_key = parse_agent_host_key(encoded_key)?;
    let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
    let alias = known_host_alias(relay, agent_name);
    crate::config::create_private_dir(&paths.config_dir)
        .map_err(|error| RevttyError::runtime("create operator config directory", error))?;
    // The pairing is read, used and removed under the lock its writers hold.
    let _lock = lock_known_hosts(paths)?;

    let state = pin_state(paths, &alias, agent_name, &public_key)?;
    if let PinState::Pinned = state {
        return Ok(HostKeyTrust::Pinned);
    }
    let Some(secret) = pairings_without(paths, &alias)?.1 else {
        return match state {
            PinState::Mismatch(pinned) => Err(host_key_mismatch(relay, agent_name, &pinned, false)),
            _ => Ok(HostKeyTrust::Unknown { fingerprint }),
        };
    };

    let proven = match proof {
        Some(proof) => secret.host_key_proof_matches(&fingerprint, proof)?,
        None => false,
    };
    if !proven {
        return Err(match state {
            PinState::Mismatch(pinned) => host_key_mismatch(relay, agent_name, &pinned, true),
            _ => RevttyError::new(
                ErrorKind::HostKey,
                format!(
                    "the relay did not prove the host key of {agent_name} with the pairing code made \
                 for it; nothing was pinned. If the relay predates pairing codes, pass --host-key \
                 with the fingerprint `revtty agent status` shows on the target"
                ),
            ),
        });
    }

    let (mut pins, _) = pins_without(paths, &alias, agent_name)?;
    pins.push_str(&pin_line(&alias, public_key)?);
    pins.push('\n');
    // Used up before the pin is written: an interruption in between leaves neither, never a
    // secret that could still prove a key.
    remove_pairing(paths, &alias)?;
    replace_private_file(
        paths,
        KNOWN_HOSTS_TEMP_FILE,
        KNOWN_HOSTS_FILE,
        pins.as_bytes(),
        "revtty known_hosts",
    )?;
    Ok(HostKeyTrust::Paired { fingerprint })
}

/// Pins a host key the operator confirmed, with --host-key or at the prompt, and voids any
/// pairing pending for the agent even when the key was pinned already: a proof the relay held
/// back cannot override an explicit approval later.
pub fn pin_agent_host_key(
    paths: &Paths,
    relay: &str,
    agent_name: &str,
    encoded_key: &str,
) -> Result<(), RevttyError> {
    crate::config::create_private_dir(&paths.config_dir)
        .map_err(|error| RevttyError::runtime("create operator config directory", error))?;
    let _lock = lock_known_hosts(paths)?;

    let public_key = parse_agent_host_key(encoded_key)?;
    let alias = known_host_alias(relay, agent_name);
    let pinned = match pin_state(paths, &alias, agent_name, &public_key)? {
        PinState::Pinned => true,
        PinState::Unpinned => false,
        PinState::Mismatch(pinned) => {
            return Err(host_key_mismatch(relay, agent_name, &pinned, false));
        }
    };
    remove_pairing(paths, &alias)?;
    if pinned {
        return Ok(());
    }

    let line = pin_line(&alias, public_key)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    // Whoever can write the pins can redirect `connect` to another host key.
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(paths.config_dir.join(KNOWN_HOSTS_FILE))
        .map_err(|error| RevttyError::runtime("open revtty known_hosts", error))?;

    writeln!(file, "{line}")
        .map_err(|error| RevttyError::runtime("write revtty known_hosts", error))?;
    file.sync_all()
        .map_err(|error| RevttyError::runtime("sync revtty known_hosts", error))
}

/// Removes the host key pinned for `agent_name` on `relay` and the pairing pending for it;
/// every other line of both files is kept as it was.
pub fn forget_agent_host_key(
    paths: &Paths,
    relay: &str,
    agent_name: &str,
) -> Result<Forgotten, RevttyError> {
    if !paths.config_dir.exists() {
        return Ok(Forgotten {
            pins: 0,
            pairing: false,
        });
    }
    let _lock = lock_known_hosts(paths)?;

    let alias = known_host_alias(relay, agent_name);
    let (kept, pins) = pins_without(paths, &alias, agent_name)?;
    let pairing = remove_pairing(paths, &alias)?;
    if pins > 0 {
        replace_private_file(
            paths,
            KNOWN_HOSTS_TEMP_FILE,
            KNOWN_HOSTS_FILE,
            kept.as_bytes(),
            "revtty known_hosts",
        )?;
    }
    Ok(Forgotten { pins, pairing })
}

/// Keeps the secret of the pairing made for `agent_name` on `relay` (`revtty pair`), in place
/// of any earlier one for that agent, whose proofs then no longer verify.
pub fn save_pairing(
    paths: &Paths,
    relay: &str,
    agent_name: &str,
    secret: &PairingSecret,
) -> Result<(), RevttyError> {
    crate::config::create_private_dir(&paths.config_dir)
        .map_err(|error| RevttyError::runtime("create operator config directory", error))?;
    let _lock = lock_known_hosts(paths)?;

    let alias = known_host_alias(relay, agent_name);
    let (mut pairings, _) = pairings_without(paths, &alias)?;
    pairings.push_str(&format!("{alias} {}\n", secret.expose()));
    replace_private_file(
        paths,
        PAIRINGS_TEMP_FILE,
        PAIRINGS_FILE,
        pairings.as_bytes(),
        "revtty pairings",
    )
}

/// What the pins say about a host key. Hashed names and markers fail closed.
fn pin_state(
    paths: &Paths,
    alias: &str,
    agent_name: &str,
    public_key: &PublicKey,
) -> Result<PinState, RevttyError> {
    let path = paths.config_dir.join(KNOWN_HOSTS_FILE);
    if !path.exists() {
        return Ok(PinState::Unpinned);
    }
    let entries = KnownHosts::read_file(&path)
        .map_err(|error| RevttyError::runtime("read revtty known_hosts", error))?;

    // A hashed name could be this agent, anywhere in the file; skipping it could accept a
    // key the hashed entry contradicts or fall back to a first pin, so fail closed.
    if entries
        .iter()
        .any(|entry| matches!(entry.host_patterns(), HostPatterns::HashedName { .. }))
    {
        return Err(RevttyError::message(format!(
            "{} contains hashed host names, which revtty cannot match; restore the unhashed file",
            path.display()
        )));
    }

    // A marker decides wherever it is in the file: a pin on an earlier line must not
    // outrank a later @revoked, and any other marker cannot be judged, so fail closed.
    if entries
        .iter()
        .any(|entry| entry_matches_alias(entry, alias) && entry.marker().is_some())
    {
        return Err(RevttyError::new(
            ErrorKind::HostKey,
            format!("host key for {agent_name} is marked revoked"),
        ));
    }

    for entry in entries {
        if !entry_matches_alias(&entry, alias) {
            continue;
        }
        if entry.public_key().key_data() == public_key.key_data() {
            return Ok(PinState::Pinned);
        }
        return Ok(PinState::Mismatch(
            entry.public_key().fingerprint(HashAlg::Sha256).to_string(),
        ));
    }
    Ok(PinState::Unpinned)
}

/// The key received is not shown: its fingerprint is the relay's word, and an operator
/// recovering from a reinstall must take the new one from the machine.
fn host_key_mismatch(relay: &str, agent_name: &str, pinned: &str, paired: bool) -> RevttyError {
    RevttyError::new(
        ErrorKind::HostKey,
        format!(
            "HOST KEY MISMATCH for {agent_name}: the relay presented a key other than the pinned \
         {pinned}{}. If the machine was reinstalled and re-enrolled, run `revtty forget \
         {agent_name} --relay {relay}` and connect with the --host-key that `revtty agent \
         status` shows on it",
            if paired {
                ", and did not prove it with the pairing code pending for it"
            } else {
                ""
            }
        ),
    )
}

/// The `known_hosts` line pinning `public_key` for `alias`. Only the key material: the
/// comment is the relay's text, and one that breaks the line would add a pin of its own, for
/// any other machine.
fn pin_line(alias: &str, mut public_key: PublicKey) -> Result<String, RevttyError> {
    public_key.set_comment("");
    let public_text = public_key
        .to_openssh()
        .map_err(|error| RevttyError::runtime("encode enrolled agent host key", error))?;
    let line = format!("{alias} {public_text}");
    let _: KnownHostEntry = KnownHostEntry::from_str(&line)
        .map_err(|error| RevttyError::runtime("validate known_hosts entry", error))?;
    Ok(line)
}

/// The pins without those of `alias`, and how many those were. Lines revtty did not write
/// for it are refused: removing them would undo more than its pin.
fn pins_without(
    paths: &Paths,
    alias: &str,
    agent_name: &str,
) -> Result<(String, usize), RevttyError> {
    let path = paths.config_dir.join(KNOWN_HOSTS_FILE);
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(RevttyError::runtime("read revtty known_hosts", error)),
    };

    let mut removed = 0;
    let mut kept = String::with_capacity(content.len());
    for line in content.lines() {
        let Some(entry) = KnownHostEntry::from_str(line)
            .ok()
            .filter(|entry| entry_matches_alias(entry, alias))
        else {
            kept.push_str(line);
            kept.push('\n');
            continue;
        };

        if entry.marker().is_some() {
            return Err(RevttyError::message(format!(
                "the host key pinned for {agent_name} is marked in {}; edit that line by hand",
                path.display()
            )));
        }
        if matches!(entry.host_patterns(), HostPatterns::Patterns(patterns) if patterns.len() > 1) {
            return Err(RevttyError::message(format!(
                "a line of {} pins {agent_name} together with other hosts; edit it by hand",
                path.display()
            )));
        }
        removed += 1;
    }
    Ok((kept, removed))
}

/// The pairings other than that of `alias`, and its secret. Lines are `<alias> <secret>`;
/// they are never quoted in errors.
fn pairings_without(
    paths: &Paths,
    alias: &str,
) -> Result<(String, Option<PairingSecret>), RevttyError> {
    let path = paths.config_dir.join(PAIRINGS_FILE);
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((String::new(), None));
        }
        Err(error) => return Err(RevttyError::runtime("read revtty pairings", error)),
    };

    let mut kept = String::with_capacity(content.len());
    let mut secret = None;
    for line in content.lines() {
        let Some(parsed) = line.split_once(' ').and_then(|(line_alias, encoded)| {
            Some((line_alias, PairingSecret::parse(encoded).ok()?))
        }) else {
            return Err(RevttyError::message(format!(
                "{} is damaged; remove it and run `revtty pair` again for the pending enrollments",
                path.display()
            )));
        };
        if parsed.0 == alias {
            secret = Some(parsed.1);
        } else {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    Ok((kept, secret))
}

/// Removes the pairing pending for `alias`; returns whether there was one.
fn remove_pairing(paths: &Paths, alias: &str) -> Result<bool, RevttyError> {
    let (kept, secret) = pairings_without(paths, alias)?;
    if secret.is_none() {
        return Ok(false);
    }
    replace_private_file(
        paths,
        PAIRINGS_TEMP_FILE,
        PAIRINGS_FILE,
        kept.as_bytes(),
        "revtty pairings",
    )?;
    Ok(true)
}

/// Replaces `name` in the operator config directory whole and private to the user, so that a
/// crash leaves the old content or the new one; the replacement is on disk once this returns.
fn replace_private_file(
    paths: &Paths,
    temp_name: &str,
    name: &str,
    content: &[u8],
    what: &str,
) -> Result<(), RevttyError> {
    let temp = paths.config_dir.join(temp_name);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temp)
        .map_err(|error| RevttyError::runtime(&format!("open {what}"), error))?;
    // The creation mode does not apply to a temporary file left behind.
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| RevttyError::runtime(&format!("secure {what}"), error))?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(|error| RevttyError::runtime(&format!("write {what}"), error))?;
    fs::rename(&temp, paths.config_dir.join(name))
        .map_err(|error| RevttyError::runtime(&format!("replace {what}"), error))?;
    fs::File::open(&paths.config_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| RevttyError::runtime(&format!("sync {what} directory"), error))
}

fn lock_known_hosts(paths: &Paths) -> Result<crate::config::ExclusiveLock, RevttyError> {
    crate::config::ExclusiveLock::acquire(&paths.config_dir.join(KNOWN_HOSTS_LOCK_FILE))
        .map_err(|error| RevttyError::runtime("lock revtty known_hosts", error))
}

fn parse_agent_host_key(encoded_key: &str) -> Result<PublicKey, RevttyError> {
    let public_key = PublicKey::from_openssh(encoded_key)
        .map_err(|error| RevttyError::runtime("parse enrolled agent host key", error))?;

    if public_key.algorithm() != Algorithm::Ed25519 {
        return Err(RevttyError::new(
            ErrorKind::HostKey,
            "v1 requires an Ed25519 agent host key",
        ));
    }

    Ok(public_key)
}

/// Whether two encodings of an agent host key carry the same key material.
pub fn same_agent_host_key(first: &str, second: &str) -> Result<bool, RevttyError> {
    Ok(parse_agent_host_key(first)?.key_data() == parse_agent_host_key(second)?.key_data())
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

    use std::io::Write;

    use super::{
        HostKeyTrust, check_agent_host_key, ensure_operator, forget_agent_host_key,
        known_host_alias, pairings_without, pin_agent_host_key, save_pairing, trust_agent_host_key,
    };
    use crate::config::Paths;
    use crate::pairing::PairingSecret;

    fn host_key() -> String {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("agent key")
            .public_key()
            .to_openssh()
            .expect("agent public key")
    }

    #[test]
    fn a_key_comment_cannot_pin_another_machine() {
        let root = std::env::temp_dir().join(format!("revtty-pin-comment-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        let relay = "https://relay.example.com";
        let attacker_key = host_key();
        // A genuine key, whose fingerprint the operator confirms, carrying a comment that
        // continues on a line of its own with a pin for another machine.
        let presented = format!(
            "{} innocuous\n{} {attacker_key}",
            host_key(),
            known_host_alias(relay, "store-043")
        );

        pin_agent_host_key(&paths, relay, "store-042", &presented).expect("pin presented key");

        let pins = std::fs::read_to_string(paths.config_dir.join("known_hosts"))
            .expect("read known_hosts");
        assert_eq!(pins.lines().count(), 1, "{pins}");
        assert!(
            check_agent_host_key(&paths, relay, "store-042", &presented)
                .expect("check pinned key")
                .pinned
        );
        assert!(
            !check_agent_host_key(&paths, relay, "store-043", &attacker_key)
                .expect("check the other machine")
                .pinned,
            "{pins}"
        );

        fs::remove_dir_all(root).expect("clean pin comment test directory");
    }

    #[test]
    fn a_revoked_key_stays_revoked_whatever_the_line_order() {
        let root = std::env::temp_dir().join(format!("revtty-revoked-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        let relay = "https://relay.example.com";
        let key = host_key();
        pin_agent_host_key(&paths, relay, "store-042", &key).expect("pin host key");
        let path = paths.config_dir.join("known_hosts");
        let pin = fs::read_to_string(&path).expect("read known_hosts");
        let pin = pin.trim_end();

        for content in [
            format!("{pin}\n@revoked {pin}\n"),
            format!("@revoked {pin}\n{pin}\n"),
        ] {
            fs::write(&path, &content).expect("write known_hosts");
            let checked = check_agent_host_key(&paths, relay, "store-042", &key);
            assert!(
                checked
                    .as_ref()
                    .is_err_and(|error| error.to_string().contains("revoked")),
                "{content}"
            );
        }

        fs::remove_dir_all(root).expect("clean revoked test directory");
    }

    #[test]
    fn forgetting_a_pin_keeps_every_other_pin() {
        let root = std::env::temp_dir().join(format!("revtty-forget-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        let relay = "https://relay.example.com";
        let other_relay = "https://other-relay.example.com";
        let (old_key, new_key, neighbour_key, elsewhere_key) =
            (host_key(), host_key(), host_key(), host_key());
        pin_agent_host_key(&paths, relay, "store-042", &old_key).expect("pin");
        pin_agent_host_key(&paths, relay, "store-043", &neighbour_key).expect("pin");
        pin_agent_host_key(&paths, other_relay, "store-042", &elsewhere_key).expect("pin");

        let mismatch = check_agent_host_key(&paths, relay, "store-042", &new_key)
            .err()
            .expect("changed host key accepted");
        assert!(
            mismatch.to_string().contains("revtty forget store-042"),
            "{mismatch}"
        );

        assert_eq!(
            forget_agent_host_key(&paths, "wss://relay.example.com/", "store-042")
                .expect("forget pin")
                .pins,
            1
        );
        // The reinstalled machine's new key can now be confirmed and pinned.
        assert!(
            !check_agent_host_key(&paths, relay, "store-042", &new_key)
                .expect("check new key")
                .pinned
        );
        assert!(
            check_agent_host_key(&paths, relay, "store-043", &neighbour_key)
                .expect("check neighbour")
                .pinned
        );
        assert!(
            check_agent_host_key(&paths, other_relay, "store-042", &elsewhere_key)
                .expect("check other relay")
                .pinned
        );
        assert_eq!(
            forget_agent_host_key(&paths, relay, "store-042")
                .expect("forget again")
                .pins,
            0
        );

        #[cfg(unix)]
        {
            let mode = fs::metadata(paths.config_dir.join("known_hosts"))
                .expect("known_hosts metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        fs::remove_dir_all(root).expect("clean forget test directory");
    }

    #[test]
    fn forget_refuses_lines_revtty_did_not_write() {
        let root = std::env::temp_dir().join(format!("revtty-forget-manual-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        let relay = "https://relay.example.com";
        pin_agent_host_key(&paths, relay, "store-042", &host_key()).expect("pin");
        pin_agent_host_key(&paths, relay, "store-043", &host_key()).expect("pin");
        let path = paths.config_dir.join("known_hosts");
        let pins = fs::read_to_string(&path).expect("read known_hosts");
        let mut lines = pins.lines().map(str::to_owned).collect::<Vec<_>>();
        let first_alias = lines[0].split(' ').next().expect("alias").to_owned();
        let second_alias = lines[1].split(' ').next().expect("alias").to_owned();

        // Both names on one line, as an operator could have merged them.
        let merged = lines[0].replacen(&first_alias, &format!("{first_alias},{second_alias}"), 1);
        fs::write(&path, format!("{merged}\n")).expect("write merged line");
        assert!(forget_agent_host_key(&paths, relay, "store-042").is_err());
        assert_eq!(
            fs::read_to_string(&path).expect("read"),
            format!("{merged}\n")
        );

        // A key marked revoked stays revoked.
        lines[0] = format!("@revoked {}", lines[0]);
        fs::write(&path, format!("{}\n", lines[0])).expect("write revoked line");
        assert!(forget_agent_host_key(&paths, relay, "store-042").is_err());
        assert!(
            fs::read_to_string(&path)
                .expect("read")
                .starts_with("@revoked")
        );

        fs::remove_dir_all(root).expect("clean forget test directory");
    }

    #[test]
    fn forgetting_while_pinning_loses_no_pin() {
        // Every write is synced to disk: enough rounds to interleave, few enough to stay fast.
        const PINS: usize = 25;
        let root = std::env::temp_dir().join(format!("revtty-forget-race-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        let relay = "https://relay.example.com";
        let churned = host_key();
        pin_agent_host_key(&paths, relay, "churned", &churned).expect("pin");

        let pinner_paths = paths.clone();
        let pinner = std::thread::spawn(move || {
            for index in 0..PINS {
                pin_agent_host_key(&pinner_paths, relay, &format!("agent-{index}"), &host_key())
                    .expect("pin");
            }
        });
        for _ in 0..PINS {
            forget_agent_host_key(&paths, relay, "churned").expect("forget");
            pin_agent_host_key(&paths, relay, "churned", &churned).expect("pin again");
        }
        pinner.join().expect("pinner thread");

        let pins = fs::read_to_string(paths.config_dir.join("known_hosts")).expect("read");
        assert_eq!(
            pins.lines().count(),
            PINS + 1,
            "a pin written meanwhile was lost"
        );

        fs::remove_dir_all(root).expect("clean forget test directory");
    }

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

        let unknown = check_agent_host_key(
            &paths,
            "https://relay.example.com/",
            "store-042",
            &first_key,
        )
        .expect("check unpinned host key");
        assert!(!unknown.pinned);
        assert!(
            !paths.config_dir.join("known_hosts").exists(),
            "checking a host key must not pin it"
        );

        pin_agent_host_key(
            &paths,
            "https://relay.example.com/",
            "store-042",
            &first_key,
        )
        .expect("pin first host key");

        let same = check_agent_host_key(&paths, "wss://relay.example.com", "store-042", &first_key)
            .expect("reuse same host key");
        assert!(same.pinned);
        assert_eq!(same.fingerprint, unknown.fingerprint);

        let mismatch = check_agent_host_key(
            &paths,
            "https://relay.example.com",
            "store-042",
            &second_key,
        );
        assert!(mismatch.is_err());
        assert!(
            pin_agent_host_key(
                &paths,
                "https://relay.example.com",
                "store-042",
                &second_key
            )
            .is_err()
        );

        let other_relay = check_agent_host_key(
            &paths,
            "https://other-relay.example.com",
            "store-042",
            &second_key,
        )
        .expect("check same name on another relay");
        assert!(!other_relay.pinned);
        pin_agent_host_key(
            &paths,
            "https://other-relay.example.com",
            "store-042",
            &second_key,
        )
        .expect("pin same name on another relay");

        let known_hosts =
            fs::read_to_string(paths.config_dir.join("known_hosts")).expect("read known_hosts");
        assert_eq!(known_hosts.lines().count(), 2);

        fs::remove_dir_all(root).expect("clean known_hosts test directory");
    }

    #[cfg(unix)]
    #[test]
    fn known_hosts_is_created_private() {
        let root = std::env::temp_dir().join(format!("revtty-known-hosts-mode-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("agent key")
            .public_key()
            .to_openssh()
            .expect("agent public key");

        pin_agent_host_key(&paths, "https://relay.example.com", "store-042", &key)
            .expect("pin host key");

        let mode = fs::metadata(paths.config_dir.join("known_hosts"))
            .expect("known_hosts metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "known_hosts created with mode {mode:o}");

        fs::remove_dir_all(root).expect("clean known_hosts test directory");
    }

    #[test]
    fn hashed_known_hosts_entries_fail_closed() {
        let root = std::env::temp_dir().join(format!("revtty-hashed-hosts-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        fs::create_dir_all(&paths.config_dir).expect("create config directory");

        let pinned_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("pinned agent key")
            .public_key()
            .to_openssh()
            .expect("pinned agent public key");
        let other_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("other agent key")
            .public_key()
            .to_openssh()
            .expect("other agent public key");

        // What `ssh-keygen -H` leaves behind: the alias replaced by a salted hash.
        let salt = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        fs::write(
            paths.config_dir.join("known_hosts"),
            format!("|1|{salt}|{salt} {pinned_key}\n"),
        )
        .expect("write hashed known_hosts");

        let checked =
            check_agent_host_key(&paths, "https://relay.example.com", "store-042", &other_key);
        assert!(
            checked.is_err(),
            "a hashed entry was skipped and another host key accepted"
        );

        // A matching pin earlier in the file must not hide a later hashed entry.
        fs::remove_file(paths.config_dir.join("known_hosts")).expect("reset known_hosts");
        pin_agent_host_key(
            &paths,
            "https://relay.example.com",
            "store-042",
            &pinned_key,
        )
        .expect("pin agent host key");
        let mut known_hosts = fs::OpenOptions::new()
            .append(true)
            .open(paths.config_dir.join("known_hosts"))
            .expect("open known_hosts");
        writeln!(known_hosts, "|1|{salt}|{salt} {other_key}").expect("append hashed entry");

        assert!(
            check_agent_host_key(
                &paths,
                "https://relay.example.com",
                "store-042",
                &pinned_key,
            )
            .is_err(),
            "a hashed entry after a matching pin was not reported"
        );

        fs::remove_dir_all(root).expect("clean hashed known_hosts test directory");
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

    const RELAY: &str = "https://relay.example.com";

    fn temp_paths(label: &str) -> (std::path::PathBuf, Paths) {
        let root = std::env::temp_dir().join(format!("revtty-{label}-{}", Uuid::new_v4()));
        let paths = Paths::new(root.join("config"), root.join("state"));
        (root, paths)
    }

    fn fingerprint(key: &str) -> String {
        ssh_key::PublicKey::from_openssh(key)
            .expect("parse host key")
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
    }

    fn pair(paths: &Paths, name: &str) -> PairingSecret {
        let secret = PairingSecret::generate().expect("pairing secret");
        save_pairing(paths, RELAY, name, &secret).expect("save pairing");
        // A copy, as the agent gets it through the code.
        PairingSecret::parse(secret.expose()).expect("copy secret")
    }

    fn proof(secret: &PairingSecret, key: &str) -> String {
        secret
            .host_key_proof(&fingerprint(key))
            .expect("host key proof")
    }

    fn pending(paths: &Paths, name: &str) -> Option<String> {
        pairings_without(paths, &known_host_alias(RELAY, name))
            .expect("read pairings")
            .1
            .map(|secret| secret.expose().to_owned())
    }

    fn read(path: std::path::PathBuf) -> Option<Vec<u8>> {
        fs::read(path).ok()
    }

    #[test]
    fn a_pairing_proof_pins_the_paired_key_once() {
        let (root, paths) = temp_paths("paired");
        let (key, other_key) = (host_key(), host_key());
        let secret = pair(&paths, "store-042");
        let other_secret = pair(&paths, "store-043");

        // Each pairing proves only its own agent's key: the secret is looked up by name.
        let crossed = trust_agent_host_key(
            &paths,
            RELAY,
            "store-043",
            &key,
            Some(&proof(&secret, &key)),
        );
        assert!(
            crossed.is_err(),
            "store-043 trusted a proof made for store-042"
        );
        assert_eq!(
            pending(&paths, "store-043").as_deref(),
            Some(other_secret.expose())
        );

        let trusted = trust_agent_host_key(
            &paths,
            RELAY,
            "store-042",
            &key,
            Some(&proof(&secret, &key)),
        )
        .expect("trust proven key");
        assert!(
            matches!(&trusted, HostKeyTrust::Paired { fingerprint: shown } if *shown == fingerprint(&key))
        );
        assert!(
            check_agent_host_key(&paths, RELAY, "store-042", &key)
                .expect("check pin")
                .pinned
        );
        assert!(
            pending(&paths, "store-042").is_none(),
            "pairing not used up"
        );
        assert!(
            pending(&paths, "store-043").is_some(),
            "another agent's pairing went"
        );

        // Used up: the same proof is now only the pinned key's, and proves no other key.
        assert!(matches!(
            trust_agent_host_key(
                &paths,
                RELAY,
                "store-042",
                &key,
                Some(&proof(&secret, &key))
            )
            .expect("trust pinned key"),
            HostKeyTrust::Pinned
        ));
        assert!(
            trust_agent_host_key(
                &paths,
                RELAY,
                "store-042",
                &other_key,
                Some(&proof(&secret, &other_key))
            )
            .is_err_and(|error| error.to_string().contains("HOST KEY MISMATCH"))
        );

        fs::remove_dir_all(root).expect("clean pairing test directory");
    }

    #[test]
    fn a_missing_or_wrong_proof_changes_no_file() {
        let (root, paths) = temp_paths("unproven");
        let (pinned_key, presented_key) = (host_key(), host_key());
        let stranger = PairingSecret::generate().expect("unrelated secret");
        let known_hosts = || read(paths.config_dir.join("known_hosts"));
        let pairings = || read(paths.config_dir.join("pairings"));

        // Not pinned yet: a relay that sends no proof, or a wrong one, pins nothing.
        pair(&paths, "store-042");
        let before = (known_hosts(), pairings());
        for proof in [None, Some(proof(&stranger, &presented_key))] {
            let refused =
                trust_agent_host_key(&paths, RELAY, "store-042", &presented_key, proof.as_deref());
            assert!(
                refused.is_err_and(|error| error.to_string().contains("--host-key")),
                "{proof:?}"
            );
            assert_eq!((known_hosts(), pairings()), before, "{proof:?}");
        }

        // Pinned: another key without a valid proof is a mismatch, and the pin stays.
        pin_agent_host_key(&paths, RELAY, "store-042", &pinned_key).expect("pin");
        pair(&paths, "store-042");
        let before = (known_hosts(), pairings());
        for proof in [None, Some(proof(&stranger, &presented_key))] {
            let refused =
                trust_agent_host_key(&paths, RELAY, "store-042", &presented_key, proof.as_deref());
            assert!(
                refused.as_ref().is_err_and(|error| {
                    let text = error.to_string();
                    text.contains("HOST KEY MISMATCH")
                        && !text.contains(&fingerprint(&presented_key))
                }),
                "{proof:?}: {:?}",
                refused.err().map(|error| error.to_string())
            );
            assert_eq!((known_hosts(), pairings()), before, "{proof:?}");

            // The pinned key itself is still trusted, and the pending pairing kept for a
            // reinstall to come.
            assert!(matches!(
                trust_agent_host_key(&paths, RELAY, "store-042", &pinned_key, proof.as_deref())
                    .expect("trust pinned key"),
                HostKeyTrust::Pinned
            ));
            assert_eq!((known_hosts(), pairings()), before, "{proof:?}");
        }

        fs::remove_dir_all(root).expect("clean pairing test directory");
    }

    #[test]
    fn a_machine_paired_again_replaces_its_pin() {
        let (root, paths) = temp_paths("repaired");
        let (old_key, new_key, neighbour_key) = (host_key(), host_key(), host_key());
        pin_agent_host_key(&paths, RELAY, "store-042", &old_key).expect("pin");
        pin_agent_host_key(&paths, RELAY, "store-043", &neighbour_key).expect("pin");
        let secret = pair(&paths, "store-042");

        let trusted = trust_agent_host_key(
            &paths,
            RELAY,
            "store-042",
            &new_key,
            Some(&proof(&secret, &new_key)),
        )
        .expect("trust the reinstalled machine's key");

        assert!(matches!(trusted, HostKeyTrust::Paired { .. }));
        let pins = fs::read_to_string(paths.config_dir.join("known_hosts")).expect("read pins");
        assert_eq!(pins.lines().count(), 2, "{pins}");
        assert!(
            check_agent_host_key(&paths, RELAY, "store-042", &new_key)
                .expect("check new key")
                .pinned
        );
        assert!(
            check_agent_host_key(&paths, RELAY, "store-043", &neighbour_key)
                .expect("check neighbour")
                .pinned
        );
        assert!(pending(&paths, "store-042").is_none());

        fs::remove_dir_all(root).expect("clean pairing test directory");
    }

    #[test]
    fn a_new_pairing_voids_the_previous_one() {
        let (root, paths) = temp_paths("repaired-twice");
        let key = host_key();
        let first = pair(&paths, "store-042");
        let second = pair(&paths, "store-042");

        let stale =
            trust_agent_host_key(&paths, RELAY, "store-042", &key, Some(&proof(&first, &key)));
        assert!(
            stale.is_err(),
            "a proof under the replaced secret pinned the key"
        );
        assert_eq!(
            pending(&paths, "store-042").as_deref(),
            Some(second.expose())
        );

        assert!(matches!(
            trust_agent_host_key(
                &paths,
                RELAY,
                "store-042",
                &key,
                Some(&proof(&second, &key))
            )
            .expect("trust under the current secret"),
            HostKeyTrust::Paired { .. }
        ));

        fs::remove_dir_all(root).expect("clean pairing test directory");
    }

    #[test]
    fn explicit_approvals_and_forget_void_a_pending_pairing() {
        let (root, paths) = temp_paths("voided");
        let (approved_key, replayed_key) = (host_key(), host_key());

        // A first pin approved by hand: a proof the relay held back cannot replace it.
        let secret = pair(&paths, "store-042");
        let held_back = proof(&secret, &replayed_key);
        pin_agent_host_key(&paths, RELAY, "store-042", &approved_key).expect("approve");
        assert!(pending(&paths, "store-042").is_none());
        assert!(
            trust_agent_host_key(&paths, RELAY, "store-042", &replayed_key, Some(&held_back))
                .is_err_and(|error| error.to_string().contains("HOST KEY MISMATCH"))
        );

        // The pinned key reaffirmed (--host-key matching the pin) voids a pairing made since.
        let secret = pair(&paths, "store-042");
        let held_back = proof(&secret, &replayed_key);
        pin_agent_host_key(&paths, RELAY, "store-042", &approved_key).expect("reaffirm");
        assert!(pending(&paths, "store-042").is_none());
        assert!(
            trust_agent_host_key(&paths, RELAY, "store-042", &replayed_key, Some(&held_back))
                .is_err_and(|error| error.to_string().contains("HOST KEY MISMATCH"))
        );
        assert!(
            check_agent_host_key(&paths, RELAY, "store-042", &approved_key)
                .expect("check approved key")
                .pinned
        );

        // `forget` takes a pending pairing with the pin.
        let secret = pair(&paths, "store-042");
        let forgotten = forget_agent_host_key(&paths, RELAY, "store-042").expect("forget");
        assert_eq!((forgotten.pins, forgotten.pairing), (1, true));
        assert!(matches!(
            trust_agent_host_key(
                &paths,
                RELAY,
                "store-042",
                &replayed_key,
                Some(&proof(&secret, &replayed_key))
            )
            .expect("trust after forget"),
            HostKeyTrust::Unknown { .. }
        ));

        fs::remove_dir_all(root).expect("clean pairing test directory");
    }

    #[test]
    fn an_interrupted_pairing_leaves_neither_secret_nor_new_pin() {
        let (root, paths) = temp_paths("interrupted");
        let (old_key, new_key, first_key) = (host_key(), host_key(), host_key());
        pin_agent_host_key(&paths, RELAY, "store-042", &old_key).expect("pin");
        let replacing = pair(&paths, "store-042");
        let first = pair(&paths, "store-043");
        // The pins cannot be rewritten: the write fails once the pairing is used up.
        let blocker = paths.config_dir.join(".known_hosts.tmp");
        fs::create_dir(&blocker).expect("block the pins rewrite");

        for (name, key, secret) in [
            ("store-042", &new_key, &replacing),
            ("store-043", &first_key, &first),
        ] {
            let interrupted =
                trust_agent_host_key(&paths, RELAY, name, key, Some(&proof(secret, key)));
            assert!(interrupted.is_err(), "{name}");
            assert!(
                pending(&paths, name).is_none(),
                "{name}: the secret survived"
            );
        }
        fs::remove_dir(&blocker).expect("unblock");

        // As if the pairings never existed: the old pin holds, the other agent is unknown.
        assert!(
            trust_agent_host_key(
                &paths,
                RELAY,
                "store-042",
                &new_key,
                Some(&proof(&replacing, &new_key))
            )
            .is_err_and(|error| error.to_string().contains("HOST KEY MISMATCH"))
        );
        assert!(
            check_agent_host_key(&paths, RELAY, "store-042", &old_key)
                .expect("check old pin")
                .pinned
        );
        assert!(matches!(
            trust_agent_host_key(
                &paths,
                RELAY,
                "store-043",
                &first_key,
                Some(&proof(&first, &first_key))
            )
            .expect("trust after the interruption"),
            HostKeyTrust::Unknown { .. }
        ));

        fs::remove_dir_all(root).expect("clean pairing test directory");
    }

    #[cfg(unix)]
    #[test]
    fn pairings_stay_private() {
        let (root, paths) = temp_paths("pairings-mode");
        fs::create_dir_all(&paths.config_dir).expect("create config directory");
        // A temporary file another process left readable is made private before use.
        let temp = paths.config_dir.join(".pairings.tmp");
        fs::write(&temp, "").expect("leave a temporary file");
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o644)).expect("make it readable");
        let mode = || {
            fs::metadata(paths.config_dir.join("pairings"))
                .expect("pairings metadata")
                .permissions()
                .mode()
                & 0o777
        };

        let secret = pair(&paths, "store-042");
        pair(&paths, "store-043");
        assert_eq!(mode(), 0o600);
        let key = host_key();
        trust_agent_host_key(
            &paths,
            RELAY,
            "store-042",
            &key,
            Some(&proof(&secret, &key)),
        )
        .expect("use a pairing");
        assert_eq!(mode(), 0o600);

        fs::remove_dir_all(root).expect("clean pairing test directory");
    }

    #[test]
    fn pairing_while_pinning_loses_nothing() {
        // Every write is synced to disk: enough rounds to interleave, few enough to stay fast.
        const ROUNDS: usize = 20;
        let (root, paths) = temp_paths("pairing-race");
        let paired = (0..ROUNDS)
            .map(|index| {
                let name = format!("paired-{index}");
                let secret = pair(&paths, &name);
                (name, secret)
            })
            .collect::<Vec<_>>();
        let start = std::sync::Arc::new(std::sync::Barrier::new(2));

        let pairer_paths = paths.clone();
        let pairer_start = std::sync::Arc::clone(&start);
        let pairer = std::thread::spawn(move || {
            pairer_start.wait();
            (0..ROUNDS)
                .map(|index| {
                    let name = format!("new-{index}");
                    let secret = PairingSecret::generate().expect("pairing secret");
                    save_pairing(&pairer_paths, RELAY, &name, &secret).expect("save pairing");
                    (name, secret.expose().to_owned())
                })
                .collect::<Vec<_>>()
        });
        start.wait();
        for (name, secret) in &paired {
            let key = host_key();
            trust_agent_host_key(&paths, RELAY, name, &key, Some(&proof(secret, &key)))
                .expect("use a pairing");
        }
        let created = pairer.join().expect("pairer thread");

        for (name, secret) in created {
            assert_eq!(
                pending(&paths, &name).as_deref(),
                Some(secret.as_str()),
                "{name}"
            );
        }
        let pins = fs::read_to_string(paths.config_dir.join("known_hosts")).expect("read pins");
        assert_eq!(
            pins.lines().count(),
            ROUNDS,
            "a pin written meanwhile was lost"
        );
        for (name, _) in &paired {
            assert!(pending(&paths, name).is_none(), "{name}");
        }

        fs::remove_dir_all(root).expect("clean pairing test directory");
    }
}
