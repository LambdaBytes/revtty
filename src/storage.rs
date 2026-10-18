use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite_migration::{HookError, HookResult, M, Migrations};
use ssh_key::{HashAlg, PublicKey};
use thiserror::Error;
use tokio_rusqlite::Connection;
use tokio_rusqlite::rusqlite::{OptionalExtension, Transaction, params};
use uuid::Uuid;

use crate::error::RevttyError;
use crate::token::{SecretToken, hash_token};

const SCHEMA_V1: &str = r#"
CREATE TABLE enrollments (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash BLOB NOT NULL UNIQUE,
    agent_name TEXT NOT NULL,
    operator_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);

CREATE INDEX enrollments_expires_at_idx
    ON enrollments(expires_at);

CREATE TABLE agents (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    control_hash BLOB NOT NULL UNIQUE,
    host_key TEXT NOT NULL,
    operator_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER,
    version TEXT
);

CREATE INDEX agents_last_seen_idx
    ON agents(last_seen);
"#;

/// Enrollment epoch: advances with every consumed enrollment, so a signed operator `list`
/// request issued before an enrollment cannot be replayed to see the newly enrolled agent.
const SCHEMA_V2: &str = r#"
CREATE TABLE relay_meta (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    enrollment_epoch INTEGER NOT NULL
);

INSERT INTO relay_meta (id, enrollment_epoch) VALUES (1, 0);
"#;

/// Session audit metadata: who asked for which session and how it ended. Never terminal
/// bytes or credentials.
const SCHEMA_V3: &str = r#"
CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,
    agent_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    operator_fingerprint TEXT NOT NULL,
    requested_at INTEGER NOT NULL,
    accepted_at INTEGER,
    paired_at INTEGER,
    ended_at INTEGER,
    outcome TEXT
);

CREATE INDEX sessions_requested_at_idx
    ON sessions(requested_at);
"#;

/// The operators each agent reports it accepts. `agents.operator_key` remains the key the
/// agent was enrolled for; this table is the current set, seeded from it, that decides whom
/// the relay issues session credentials to. The agent's own list is what SSH enforces.
/// `control_connection` names the agent's current control connection: only its reports are
/// stored, so a late report from a replaced connection cannot overwrite a newer one.
const SCHEMA_V4: &str = r#"
CREATE TABLE agent_operators (
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    public_key TEXT NOT NULL,
    PRIMARY KEY (agent_id, fingerprint)
);

CREATE INDEX agent_operators_fingerprint_idx
    ON agent_operators(fingerprint);

ALTER TABLE agents ADD COLUMN operators_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN control_connection TEXT;
"#;

/// An enrollment that re-enrolls an existing agent (`relay enroll --replace`) names the agent
/// instance it replaces; it can be consumed only while that instance is still the agent.
const SCHEMA_V5: &str = r#"
ALTER TABLE enrollments ADD COLUMN replaces_agent_id TEXT;
"#;

/// A control credential rotation in progress: the hash of the credential the agent will use
/// once it confirms the rotation with it.
const SCHEMA_V6: &str = r#"
ALTER TABLE agents ADD COLUMN next_control_hash BLOB;
"#;

/// The proof of its host key an agent enrolled with a pairing code sent: the relay hands it
/// to operators, who verify it with the pairing secret the relay never sees.
const SCHEMA_V7: &str = r#"
ALTER TABLE agents ADD COLUMN host_key_proof TEXT;
"#;

/// Seeds `agent_operators` with each agent's enrolled key; fingerprints are computed here,
/// which SQL cannot do.
fn seed_agent_operators(transaction: &Transaction) -> HookResult {
    let agents = {
        let mut statement = transaction.prepare("SELECT id, operator_key FROM agents")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    for (agent_id, operator_key) in agents {
        let fingerprint = operator_fingerprint(&operator_key).ok_or_else(|| {
            HookError::Hook(format!("agent {agent_id} has an invalid operator key"))
        })?;
        transaction.execute(
            "INSERT INTO agent_operators (agent_id, fingerprint, public_key) VALUES (?1, ?2, ?3)",
            params![agent_id, fingerprint, operator_key],
        )?;
    }

    Ok(())
}

pub fn operator_fingerprint(encoded: &str) -> Option<String> {
    PublicKey::from_openssh(encoded)
        .ok()
        .map(|key| key.fingerprint(HashAlg::Sha256).to_string())
}

#[derive(Debug, Error)]
enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] tokio_rusqlite::rusqlite::Error),

    #[error("enrollment token is invalid, expired, or already used")]
    InvalidEnrollment,

    #[error("enrollment token could not be consumed atomically")]
    EnrollmentRace,

    #[error("relay metadata is missing or invalid")]
    InvalidRelayMeta,

    #[error("enrollment operator key is invalid")]
    InvalidOperatorKey,

    #[error("operator list revision is outside the supported range")]
    InvalidRevision,

    #[error("agent {0} is already enrolled; use --replace to re-enroll it")]
    AlreadyEnrolled(String),

    #[error("agent {0} is not enrolled, so there is nothing to replace")]
    NotEnrolled(String),

    #[error("the agent this enrollment replaces was re-enrolled or removed after it was created")]
    ReplacedAgentChanged,
}

#[derive(Clone)]
pub struct Store {
    conn: Connection,
}

pub struct Enrollment {
    pub id: String,
    pub token: SecretToken,
    pub expires_at: i64,
    /// The agent instance a `--replace` enrollment replaces once consumed.
    pub replaces_agent_id: Option<String>,
}

/// How the relay answered a rotation confirmation.
#[derive(Debug, PartialEq, Eq)]
pub enum RotationConfirmation {
    /// The confirmed credential replaced the agent's control credential.
    Promoted,
    /// It already is the control credential: a repeated confirmation.
    AlreadyCurrent,
    /// It is neither the agent's pending nor its current credential.
    Rejected,
}

/// What `remove_agent` deleted.
pub struct RemovedAgent {
    pub id: String,
    /// Unused enrollments for the name, which could otherwise bring the agent back.
    pub cancelled_enrollments: usize,
}

pub struct AgentCredential {
    pub id: String,
    pub name: String,
    pub operator_key: String,
    pub control_token: SecretToken,
}

pub struct SessionRecord {
    pub id: String,
    pub agent_name: String,
    pub kind: String,
    pub operator_fingerprint: String,
    pub requested_at: i64,
    pub accepted_at: Option<i64>,
    pub paired_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub outcome: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AgentRecord {
    pub id: String,
    pub name: String,
    pub host_key: String,
    /// The agent's pairing proof of `host_key`, when it was enrolled with a pairing code.
    pub host_key_proof: Option<String>,
    /// Fingerprints of the operators the agent last reported, sorted.
    pub operators: Vec<String>,
    pub created_at: i64,
    pub last_seen: Option<i64>,
    pub version: Option<String>,
}

/// One operator key of an agent's report, already validated.
pub struct ReportedOperator {
    pub fingerprint: String,
    pub public_key: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OperatorsReportOutcome {
    /// Stored; `changed` tells whether the set of operators differs from the previous one.
    Applied { changed: bool },
    /// The agent is gone, or the report came from a connection that is no longer its
    /// current one.
    NotCurrent,
}

const AGENT_COLUMNS: &str = "SELECT a.id, a.name, a.host_key, a.created_at, a.last_seen, a.version,
            COALESCE(group_concat(o.fingerprint, ','), ''), a.host_key_proof
     FROM agents a
     LEFT JOIN agent_operators o ON o.agent_id = a.id";

fn agent_record(
    row: &tokio_rusqlite::rusqlite::Row<'_>,
) -> tokio_rusqlite::rusqlite::Result<AgentRecord> {
    let operators: String = row.get(6)?;
    // Fingerprints are `SHA256:` plus base64, which never contains a comma.
    let mut operators = operators
        .split(',')
        .filter(|fingerprint| !fingerprint.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    operators.sort();

    Ok(AgentRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        host_key: row.get(2)?,
        host_key_proof: row.get(7)?,
        operators,
        created_at: row.get(3)?,
        last_seen: row.get(4)?,
        version: row.get(5)?,
    })
}

impl Store {
    pub async fn open(path: &Path) -> Result<Self, RevttyError> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            crate::config::create_private_dir(parent)
                .map_err(|error| RevttyError::runtime("create relay state directory", error))?;
        }

        let conn = Connection::open(path)
            .await
            .map_err(|error| RevttyError::runtime("open relay SQLite database", error))?;

        initialize(&conn).await?;
        Ok(Self { conn })
    }

    #[cfg(test)]
    pub(crate) async fn open_in_memory() -> Result<Self, RevttyError> {
        let conn = Connection::open_in_memory()
            .await
            .map_err(|error| RevttyError::runtime("open in-memory relay database", error))?;

        initialize(&conn).await?;
        Ok(Self { conn })
    }

    /// Occupies the database until `release` is signalled, so that other calls queue behind
    /// it; `held` is signalled once it does.
    #[cfg(test)]
    pub(crate) async fn hold(
        &self,
        held: tokio::sync::oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        let _ = self
            .conn
            .call(move |_| {
                let _ = held.send(());
                let _ = release.recv();
                Ok::<_, StoreError>(())
            })
            .await;
    }

    /// Every write fails from now on, as on a database that has gone read-only.
    #[cfg(test)]
    pub(crate) async fn refuse_writes(&self) {
        self.conn
            .call(|conn| {
                conn.execute_batch("PRAGMA query_only = ON")?;
                Ok::<_, StoreError>(())
            })
            .await
            .expect("make the database read-only");
    }

    /// A single-use enrollment for a new agent; the name must not be enrolled yet.
    pub async fn create_enrollment(
        &self,
        agent_name: &str,
        operator_key: &str,
        ttl: Duration,
    ) -> Result<Enrollment, RevttyError> {
        self.insert_enrollment(agent_name, operator_key, ttl, false)
            .await
    }

    /// A single-use enrollment that re-enrolls the existing agent `agent_name`: consuming it
    /// replaces that agent instance (identity, credential and operators) by a new one.
    pub async fn create_replacement_enrollment(
        &self,
        agent_name: &str,
        operator_key: &str,
        ttl: Duration,
    ) -> Result<Enrollment, RevttyError> {
        self.insert_enrollment(agent_name, operator_key, ttl, true)
            .await
    }

    async fn insert_enrollment(
        &self,
        agent_name: &str,
        operator_key: &str,
        ttl: Duration,
        replace: bool,
    ) -> Result<Enrollment, RevttyError> {
        let id = Uuid::new_v4().simple().to_string();
        let token = SecretToken::generate("rve")?;
        let token_hash = token.hash().to_vec();
        let created_at = unix_now()?;
        let ttl_secs = i64::try_from(ttl.as_secs())
            .map_err(|_| RevttyError::message("enrollment TTL is too large"))?;
        let expires_at = created_at
            .checked_add(ttl_secs)
            .ok_or_else(|| RevttyError::message("enrollment expiry overflow"))?;

        let insert_id = id.clone();
        let name = agent_name.to_owned();
        let operator_key = operator_key.to_owned();

        let replaces_agent_id = self
            .conn
            .call(move |conn| {
                let transaction = conn.transaction()?;
                let enrolled = transaction
                    .query_row(
                        "SELECT id FROM agents WHERE name = ?1",
                        params![name],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                let replaces_agent_id = match (enrolled, replace) {
                    (None, false) => None,
                    (Some(_), false) => return Err(StoreError::AlreadyEnrolled(name)),
                    (None, true) => return Err(StoreError::NotEnrolled(name)),
                    (Some(id), true) => Some(id),
                };

                transaction.execute(
                    "INSERT INTO enrollments
                     (id, token_hash, agent_name, operator_key, created_at, expires_at,
                      replaces_agent_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        insert_id,
                        token_hash,
                        name,
                        operator_key,
                        created_at,
                        expires_at,
                        replaces_agent_id
                    ],
                )?;
                transaction.commit()?;
                Ok::<_, StoreError>(replaces_agent_id)
            })
            .await
            .map_err(|error| RevttyError::runtime("create enrollment", error))?;

        Ok(Enrollment {
            id,
            token,
            expires_at,
            replaces_agent_id,
        })
    }

    pub async fn consume_enrollment(
        &self,
        enrollment_token: &str,
        host_key: &str,
        host_key_proof: Option<&str>,
        version: Option<&str>,
    ) -> Result<AgentCredential, RevttyError> {
        let enrollment_hash = hash_token(enrollment_token).to_vec();
        let agent_id = Uuid::new_v4().simple().to_string();
        let control_token = SecretToken::generate("rva")?;
        let control_hash = control_token.hash().to_vec();
        let now = unix_now()?;
        let host_key = host_key.to_owned();
        let host_key_proof = host_key_proof.map(str::to_owned);
        let version = version.map(str::to_owned);
        let inserted_id = agent_id.clone();

        let (name, operator_key) = self
            .conn
            .call(move |conn| {
                let transaction = conn.transaction()?;

                let (agent_name, operator_key, replaces_agent_id) = transaction
                    .query_row(
                        "SELECT agent_name, operator_key, replaces_agent_id
                         FROM enrollments
                         WHERE token_hash = ?1
                           AND used_at IS NULL
                           AND expires_at >= ?2",
                        params![enrollment_hash, now],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                            ))
                        },
                    )
                    .optional()?
                    .ok_or(StoreError::InvalidEnrollment)?;

                let updated = transaction.execute(
                    "UPDATE enrollments
                     SET used_at = ?1
                     WHERE token_hash = ?2
                       AND used_at IS NULL",
                    params![now, enrollment_hash],
                )?;

                if updated != 1 {
                    return Err(StoreError::EnrollmentRace);
                }

                let operator_fingerprint =
                    operator_fingerprint(&operator_key).ok_or(StoreError::InvalidOperatorKey)?;

                // The instance it replaces goes, with its credential and operators, only while
                // it is still the agent of that name: of two replacements, the second fails.
                if let Some(replaced) = &replaces_agent_id {
                    let deleted = transaction.execute(
                        "DELETE FROM agents WHERE id = ?1 AND name = ?2",
                        params![replaced, agent_name],
                    )?;
                    if deleted != 1 {
                        return Err(StoreError::ReplacedAgentChanged);
                    }
                }

                transaction.execute(
                    "INSERT INTO agents
                     (id, name, control_hash, host_key, operator_key, created_at, last_seen, version,
                      host_key_proof)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8)",
                    params![
                        inserted_id,
                        agent_name,
                        control_hash,
                        host_key,
                        operator_key,
                        now,
                        version,
                        host_key_proof
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO agent_operators (agent_id, fingerprint, public_key)
                     VALUES (?1, ?2, ?3)",
                    params![inserted_id, operator_fingerprint, operator_key],
                )?;

                let advanced = transaction.execute(
                    "UPDATE relay_meta SET enrollment_epoch = enrollment_epoch + 1 WHERE id = 1",
                    [],
                )?;
                if advanced != 1 {
                    return Err(StoreError::InvalidRelayMeta);
                }

                transaction.commit()?;
                Ok::<_, StoreError>((agent_name, operator_key))
            })
            .await
            .map_err(|error| RevttyError::runtime("consume enrollment", error))?;

        Ok(AgentCredential {
            id: agent_id,
            name,
            operator_key,
            control_token,
        })
    }

    /// The id of the agent `agent_name` when `control_token` is its current credential.
    pub async fn authenticate_agent(
        &self,
        agent_name: &str,
        control_token: &str,
    ) -> Result<Option<String>, RevttyError> {
        let name = agent_name.to_owned();
        let hash = hash_token(control_token).to_vec();

        self.conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT id FROM agents WHERE name = ?1 AND control_hash = ?2",
                    params![name, hash],
                    |row| row.get(0),
                )
                .optional()
                .map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("authenticate agent", error))
    }

    /// Makes `connection_id` the current control connection of agent `agent_id`, returning
    /// whether the agent still exists. From then on only that connection's reports are stored.
    pub async fn claim_control_connection(
        &self,
        agent_id: &str,
        connection_id: &str,
    ) -> Result<bool, RevttyError> {
        let agent_id = agent_id.to_owned();
        let connection_id = connection_id.to_owned();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE agents SET control_connection = ?1 WHERE id = ?2",
                    params![connection_id, agent_id],
                )
                .map(|updated| updated == 1)
                .map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("register agent control connection", error))
    }

    /// Replaces the operators of agent `agent_id` with the list its current control
    /// connection `connection_id` reported. Whatever that list's revision, it is what the
    /// agent enforces now (an `agent.toml` restored from a backup goes back in revisions).
    /// The enrollment epoch advances only when the set of operators changes, which voids list
    /// requests signed before the change.
    pub async fn apply_operators_report(
        &self,
        agent_id: &str,
        connection_id: &str,
        revision: u64,
        operators: Vec<ReportedOperator>,
    ) -> Result<OperatorsReportOutcome, RevttyError> {
        let agent_id = agent_id.to_owned();
        let connection_id = connection_id.to_owned();

        self.conn
            .call(move |conn| {
                let revision = i64::try_from(revision).map_err(|_| StoreError::InvalidRevision)?;
                let transaction = conn.transaction()?;

                let current_connection = transaction
                    .query_row(
                        "SELECT 1 FROM agents WHERE id = ?1 AND control_connection = ?2",
                        params![agent_id, connection_id],
                        |_| Ok(()),
                    )
                    .optional()?;
                if current_connection.is_none() {
                    return Ok(OperatorsReportOutcome::NotCurrent);
                }

                let current = {
                    let mut statement = transaction.prepare(
                        "SELECT fingerprint FROM agent_operators WHERE agent_id = ?1",
                    )?;
                    let rows = statement.query_map(params![agent_id], |row| row.get::<_, String>(0))?;
                    rows.collect::<Result<std::collections::BTreeSet<_>, _>>()?
                };
                let reported = operators
                    .iter()
                    .map(|operator| operator.fingerprint.clone())
                    .collect::<std::collections::BTreeSet<_>>();
                let changed = current != reported;

                transaction.execute(
                    "UPDATE agents SET operators_revision = ?1 WHERE id = ?2",
                    params![revision, agent_id],
                )?;
                if changed {
                    transaction.execute(
                        "DELETE FROM agent_operators WHERE agent_id = ?1",
                        params![agent_id],
                    )?;
                    for operator in &operators {
                        transaction.execute(
                            "INSERT OR IGNORE INTO agent_operators (agent_id, fingerprint, public_key)
                             VALUES (?1, ?2, ?3)",
                            params![agent_id, operator.fingerprint, operator.public_key],
                        )?;
                    }
                    let advanced = transaction.execute(
                        "UPDATE relay_meta SET enrollment_epoch = enrollment_epoch + 1 WHERE id = 1",
                        [],
                    )?;
                    if advanced != 1 {
                        return Err(StoreError::InvalidRelayMeta);
                    }
                }

                transaction.commit()?;
                Ok(OperatorsReportOutcome::Applied { changed })
            })
            .await
            .map_err(|error| RevttyError::runtime("store operators report", error))
    }

    /// Removes the agent `agent_name` with its operators, and the unused enrollments for that
    /// name. The session audit is kept.
    pub async fn remove_agent(
        &self,
        agent_name: &str,
    ) -> Result<Option<RemovedAgent>, RevttyError> {
        let name = agent_name.to_owned();

        self.conn
            .call(move |conn| {
                let transaction = conn.transaction()?;
                let Some(id) = transaction
                    .query_row(
                        "SELECT id FROM agents WHERE name = ?1",
                        params![name],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                else {
                    return Ok(None);
                };

                transaction.execute("DELETE FROM agents WHERE id = ?1", params![id])?;
                let cancelled_enrollments = transaction.execute(
                    "DELETE FROM enrollments WHERE agent_name = ?1 AND used_at IS NULL",
                    params![name],
                )?;
                transaction.commit()?;
                Ok::<_, StoreError>(Some(RemovedAgent {
                    id,
                    cancelled_enrollments,
                }))
            })
            .await
            .map_err(|error| RevttyError::runtime("remove agent", error))
    }

    /// Which of `agent_ids` still name an enrolled agent instance.
    pub async fn existing_agent_ids(
        &self,
        agent_ids: Vec<String>,
    ) -> Result<std::collections::HashSet<String>, RevttyError> {
        self.conn
            .call(move |conn| {
                let mut statement = conn.prepare("SELECT 1 FROM agents WHERE id = ?1")?;
                let mut existing = std::collections::HashSet::new();
                for id in agent_ids {
                    if statement.exists(params![id])? {
                        existing.insert(id);
                    }
                }
                Ok::<_, StoreError>(existing)
            })
            .await
            .map_err(|error| RevttyError::runtime("look up enrolled agents", error))
    }

    /// Whether agent `agent_id` still exists and lists the operator `fingerprint`.
    pub async fn operator_authorized(
        &self,
        agent_id: &str,
        fingerprint: &str,
    ) -> Result<bool, RevttyError> {
        let agent_id = agent_id.to_owned();
        let fingerprint = fingerprint.to_owned();

        self.conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT 1 FROM agent_operators WHERE agent_id = ?1 AND fingerprint = ?2",
                    params![agent_id, fingerprint],
                    |_| Ok(()),
                )
                .optional()
                .map(|value| value.is_some())
                .map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("check operator authorization", error))
    }

    /// Records `next_hash` as the control credential agent `agent_name` is rotating to,
    /// replacing any earlier unconfirmed one, when `control_token` is its current credential;
    /// returns whether it was. Checked in the same statement: a request authenticated before
    /// another rotation took effect cannot start one with a credential that is no longer valid.
    pub async fn begin_rotation(
        &self,
        agent_name: &str,
        control_token: &str,
        next_hash: [u8; 32],
    ) -> Result<bool, RevttyError> {
        let name = agent_name.to_owned();
        let current_hash = hash_token(control_token).to_vec();
        let next_hash = next_hash.to_vec();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE agents SET next_control_hash = ?1 WHERE name = ?2 AND control_hash = ?3",
                    params![next_hash, name, current_hash],
                )
                .map(|updated| updated == 1)
                .map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("begin credential rotation", error))
    }

    /// Makes `token` the control credential of agent `agent_name` when it is the credential
    /// the agent is rotating to. Confirming the current credential again changes nothing, so
    /// an agent that lost the answer can repeat it.
    pub async fn confirm_rotation(
        &self,
        agent_name: &str,
        token: &str,
    ) -> Result<RotationConfirmation, RevttyError> {
        let name = agent_name.to_owned();
        let hash = hash_token(token).to_vec();

        self.conn
            .call(move |conn| {
                let transaction = conn.transaction()?;
                let promoted = transaction.execute(
                    "UPDATE agents SET control_hash = next_control_hash, next_control_hash = NULL
                     WHERE name = ?1 AND next_control_hash = ?2",
                    params![name, hash],
                )?;
                let confirmation = if promoted == 1 {
                    RotationConfirmation::Promoted
                } else if transaction
                    .prepare("SELECT 1 FROM agents WHERE name = ?1 AND control_hash = ?2")?
                    .exists(params![name, hash])?
                {
                    RotationConfirmation::AlreadyCurrent
                } else {
                    RotationConfirmation::Rejected
                };
                transaction.commit()?;
                Ok::<_, StoreError>(confirmation)
            })
            .await
            .map_err(|error| RevttyError::runtime("confirm credential rotation", error))
    }

    /// Records that agent instance `agent_id` was just seen; a replaced or removed instance
    /// updates nothing.
    pub async fn mark_seen(
        &self,
        agent_id: &str,
        version: Option<&str>,
    ) -> Result<(), RevttyError> {
        let agent_id = agent_id.to_owned();
        let version = version.map(str::to_owned);
        let now = unix_now()?;

        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE agents SET last_seen = ?1, version = COALESCE(?2, version)
                     WHERE id = ?3",
                    params![now, version, agent_id],
                )?;
                Ok::<_, StoreError>(())
            })
            .await
            .map_err(|error| RevttyError::runtime("update agent presence", error))
    }

    pub async fn get_agent(&self, agent_name: &str) -> Result<Option<AgentRecord>, RevttyError> {
        let name = agent_name.to_owned();

        self.conn
            .call(move |conn| {
                conn.query_row(
                    &format!("{AGENT_COLUMNS} WHERE a.name = ?1 GROUP BY a.id"),
                    params![name],
                    agent_record,
                )
                .optional()
                .map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("get enrolled agent", error))
    }

    /// `at` is when the event happened (Unix seconds); writes may run later.
    pub async fn record_session_requested(
        &self,
        id: &str,
        agent_name: &str,
        kind: &str,
        operator_fingerprint: &str,
        at: i64,
    ) -> Result<(), RevttyError> {
        let values = (
            id.to_owned(),
            agent_name.to_owned(),
            kind.to_owned(),
            operator_fingerprint.to_owned(),
        );

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO sessions (id, agent_name, kind, operator_fingerprint, requested_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![values.0, values.1, values.2, values.3, at],
                )?;
                Ok::<_, StoreError>(())
            })
            .await
            .map_err(|error| RevttyError::runtime("record session request", error))
    }

    pub async fn record_session_accepted(&self, id: &str, at: i64) -> Result<(), RevttyError> {
        self.stamp_session(id, "accepted_at", at).await
    }

    pub async fn record_session_paired(&self, id: &str, at: i64) -> Result<(), RevttyError> {
        self.stamp_session(id, "paired_at", at).await
    }

    /// Records how a session ended; only the first outcome is kept.
    pub async fn record_session_ended(
        &self,
        id: &str,
        outcome: &str,
        at: i64,
    ) -> Result<(), RevttyError> {
        let id = id.to_owned();
        let outcome = outcome.to_owned();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE sessions SET ended_at = ?1, outcome = ?2
                     WHERE id = ?3 AND ended_at IS NULL",
                    params![at, outcome, id],
                )?;
                Ok::<_, StoreError>(())
            })
            .await
            .map_err(|error| RevttyError::runtime("record session end", error))
    }

    /// Sessions still open belonged to a previous relay process, which took them down with
    /// it; returns how many were closed.
    pub async fn close_interrupted_sessions(&self) -> Result<usize, RevttyError> {
        let now = unix_now()?;

        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE sessions SET ended_at = ?1, outcome = 'interrupted'
                     WHERE ended_at IS NULL",
                    params![now],
                )
                .map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("close interrupted sessions", error))
    }

    /// Most recent sessions first.
    pub async fn list_sessions(&self, limit: u32) -> Result<Vec<SessionRecord>, RevttyError> {
        self.conn
            .call(move |conn| {
                let mut statement = conn.prepare(
                    "SELECT id, agent_name, kind, operator_fingerprint, requested_at,
                            accepted_at, paired_at, ended_at, outcome
                     FROM sessions
                     ORDER BY requested_at DESC, rowid DESC
                     LIMIT ?1",
                )?;

                let rows = statement.query_map(params![limit], |row| {
                    Ok(SessionRecord {
                        id: row.get(0)?,
                        agent_name: row.get(1)?,
                        kind: row.get(2)?,
                        operator_fingerprint: row.get(3)?,
                        requested_at: row.get(4)?,
                        accepted_at: row.get(5)?,
                        paired_at: row.get(6)?,
                        ended_at: row.get(7)?,
                        outcome: row.get(8)?,
                    })
                })?;

                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("list sessions", error))
    }

    /// `column` is one of the fixed lifecycle columns, never caller input.
    async fn stamp_session(
        &self,
        id: &str,
        column: &'static str,
        at: i64,
    ) -> Result<(), RevttyError> {
        let id = id.to_owned();

        self.conn
            .call(move |conn| {
                conn.execute(
                    &format!("UPDATE sessions SET {column} = ?1 WHERE id = ?2"),
                    params![at, id],
                )?;
                Ok::<_, StoreError>(())
            })
            .await
            .map_err(|error| RevttyError::runtime("record session progress", error))
    }

    pub async fn schema_version(&self) -> Result<i64, RevttyError> {
        self.conn
            .call(|conn| {
                conn.query_row("PRAGMA user_version", [], |row| row.get(0))
                    .map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("read schema version", error))
    }

    pub async fn enrollment_epoch(&self) -> Result<u64, RevttyError> {
        self.conn
            .call(|conn| read_enrollment_epoch(conn))
            .await
            .map_err(|error| RevttyError::runtime("read enrollment epoch", error))
    }

    /// The enrollment epoch and the enrolled agents, read from one snapshot.
    pub async fn list_agents_with_epoch(&self) -> Result<(u64, Vec<AgentRecord>), RevttyError> {
        self.conn
            .call(|conn| {
                let transaction = conn.transaction()?;
                let epoch = read_enrollment_epoch(&transaction)?;
                let agents = read_agents(&transaction)?;
                transaction.commit()?;
                Ok::<_, StoreError>((epoch, agents))
            })
            .await
            .map_err(|error| RevttyError::runtime("list enrolled agents", error))
    }

    pub async fn list_agents(&self) -> Result<Vec<AgentRecord>, RevttyError> {
        self.conn
            .call(|conn| read_agents(conn))
            .await
            .map_err(|error| RevttyError::runtime("list enrolled agents", error))
    }
}

fn read_enrollment_epoch(conn: &tokio_rusqlite::rusqlite::Connection) -> Result<u64, StoreError> {
    let epoch: i64 = conn
        .query_row(
            "SELECT enrollment_epoch FROM relay_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(StoreError::InvalidRelayMeta)?;

    u64::try_from(epoch).map_err(|_| StoreError::InvalidRelayMeta)
}

fn read_agents(
    conn: &tokio_rusqlite::rusqlite::Connection,
) -> Result<Vec<AgentRecord>, StoreError> {
    let mut statement = conn.prepare(&format!("{AGENT_COLUMNS} GROUP BY a.id ORDER BY a.name"))?;
    let rows = statement.query_map([], agent_record)?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

async fn initialize(conn: &Connection) -> Result<(), RevttyError> {
    conn.call(|conn| {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             PRAGMA synchronous = NORMAL;",
        )
    })
    .await
    .map_err(|error| RevttyError::runtime("configure relay SQLite database", error))?;

    conn.call(|conn| migrations().to_latest(conn))
        .await
        .map_err(|error| RevttyError::runtime("migrate relay SQLite database", error))
}

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(SCHEMA_V1),
        M::up(SCHEMA_V2),
        M::up(SCHEMA_V3),
        M::up_with_hook(SCHEMA_V4, seed_agent_operators),
        M::up(SCHEMA_V5),
        M::up(SCHEMA_V6),
        M::up(SCHEMA_V7),
    ])
}

pub fn unix_now() -> Result<i64, RevttyError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| RevttyError::runtime("read system clock", error))?;

    i64::try_from(duration.as_secs())
        .map_err(|_| RevttyError::message("system clock is outside supported range"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio_rusqlite::rusqlite::{Connection as SqliteConnection, params};

    use super::{
        OperatorsReportOutcome, ReportedOperator, RotationConfirmation, SCHEMA_V1, SCHEMA_V2,
        SCHEMA_V3, Store, migrations, operator_fingerprint,
    };
    use crate::token::SecretToken;

    const OPERATOR_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB operator";
    const HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC host";

    #[test]
    fn migrations_validate() {
        migrations().validate().expect("valid migrations");
    }

    #[tokio::test]
    async fn enrollment_is_single_use_and_creates_agent_credential() {
        let store = Store::open_in_memory().await.expect("open store");
        let enrollment = store
            .create_enrollment("store-042", OPERATOR_KEY, Duration::from_secs(60))
            .await
            .expect("create enrollment");

        let credential = store
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, None, Some("0.1.0"))
            .await
            .expect("consume enrollment");

        assert_eq!(credential.name, "store-042");
        assert_eq!(credential.operator_key, OPERATOR_KEY);
        assert_eq!(
            store
                .authenticate_agent("store-042", credential.control_token.expose())
                .await
                .expect("authenticate agent"),
            Some(credential.id.clone())
        );
        assert!(
            store
                .authenticate_agent("store-042", "wrong-token")
                .await
                .expect("reject wrong token")
                .is_none()
        );

        let second = store
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, None, Some("0.1.0"))
            .await;
        assert!(second.is_err());

        let agents = store.list_agents().await.expect("list agents");
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "store-042");
        assert_eq!(agents[0].host_key, HOST_KEY);
        assert_eq!(agents[0].version.as_deref(), Some("0.1.0"));
        // The enrolled operator is the agent's first operator.
        assert_eq!(
            agents[0].operators,
            vec![operator_fingerprint(OPERATOR_KEY).expect("fingerprint")]
        );
    }

    #[tokio::test]
    async fn presence_updates_are_persisted() {
        let store = Store::open_in_memory().await.expect("open store");
        let enrollment = store
            .create_enrollment("demo", OPERATOR_KEY, Duration::from_secs(60))
            .await
            .expect("create enrollment");

        let credential = store
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, None, None)
            .await
            .expect("consume enrollment");

        store
            .mark_seen(&credential.id, Some("0.2.0"))
            .await
            .expect("mark seen");

        let agents = store.list_agents().await.expect("list agents");
        let agent = agents.first().expect("agent exists");

        assert!(agent.last_seen.is_some());
        assert_eq!(agent.version.as_deref(), Some("0.2.0"));
    }

    #[tokio::test]
    async fn enrollment_epoch_advances_with_each_enrollment() {
        let store = Store::open_in_memory().await.expect("open store");
        assert_eq!(store.enrollment_epoch().await.expect("read epoch"), 0);

        for (round, name) in ["first", "second"].into_iter().enumerate() {
            let enrollment = store
                .create_enrollment(name, OPERATOR_KEY, Duration::from_secs(60))
                .await
                .expect("create enrollment");
            store
                .consume_enrollment(enrollment.token.expose(), HOST_KEY, None, None)
                .await
                .expect("consume enrollment");

            let (epoch, agents) = store
                .list_agents_with_epoch()
                .await
                .expect("list agents with epoch");
            assert_eq!(epoch, round as u64 + 1);
            assert_eq!(agents.len(), round + 1);
        }

        // An unconsumed or rejected enrollment does not advance it.
        let unused = store
            .create_enrollment("third", OPERATOR_KEY, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        assert!(
            store
                .consume_enrollment("rve_not-a-token", HOST_KEY, None, None)
                .await
                .is_err()
        );
        drop(unused);
        assert_eq!(store.enrollment_epoch().await.expect("read epoch"), 2);
    }

    #[tokio::test]
    async fn v1_database_migrates_with_agents_intact() {
        let path = std::env::temp_dir().join(format!(
            "revtty-migrate-{}.db",
            uuid::Uuid::new_v4().simple()
        ));

        {
            let conn = SqliteConnection::open(&path).expect("create v1 database");
            conn.execute_batch(SCHEMA_V1).expect("apply schema v1");
            conn.pragma_update(None, "user_version", 1)
                .expect("mark schema v1");
            conn.execute(
                "INSERT INTO agents
                 (id, name, control_hash, host_key, operator_key, created_at, last_seen, version)
                 VALUES ('agent-id', 'legacy', x'00', ?1, ?2, 1, 1, '0.1.0')",
                params![HOST_KEY, OPERATOR_KEY],
            )
            .expect("insert v1 agent");
        }

        let store = Store::open(&path)
            .await
            .expect("open and migrate v1 database");
        let (epoch, agents) = store
            .list_agents_with_epoch()
            .await
            .expect("list migrated agents");
        assert_eq!(epoch, 0);
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "legacy");

        drop(store);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::test]
    async fn v3_database_migrates_seeding_each_agents_operator() {
        let path = std::env::temp_dir().join(format!(
            "revtty-migrate-v3-{}.db",
            uuid::Uuid::new_v4().simple()
        ));

        {
            let conn = SqliteConnection::open(&path).expect("create v3 database");
            conn.execute_batch(SCHEMA_V1).expect("apply schema v1");
            conn.execute_batch(SCHEMA_V2).expect("apply schema v2");
            conn.execute_batch(SCHEMA_V3).expect("apply schema v3");
            conn.pragma_update(None, "user_version", 3)
                .expect("mark schema v3");
            conn.execute(
                "INSERT INTO agents
                 (id, name, control_hash, host_key, operator_key, created_at, last_seen, version)
                 VALUES ('agent-id', 'legacy', x'00', ?1, ?2, 1, 1, '0.1.0')",
                params![HOST_KEY, OPERATOR_KEY],
            )
            .expect("insert v3 agent");
        }

        let store = Store::open(&path)
            .await
            .expect("open and migrate v3 database");
        assert_eq!(store.schema_version().await.expect("schema version"), 7);
        let fingerprint = operator_fingerprint(OPERATOR_KEY).expect("fingerprint");
        let agent = store
            .get_agent("legacy")
            .await
            .expect("get migrated agent")
            .expect("migrated agent exists");
        assert_eq!(agent.operators, vec![fingerprint.clone()]);
        assert!(
            store
                .operator_authorized("agent-id", &fingerprint)
                .await
                .expect("check operator")
        );

        drop(store);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::test]
    async fn v6_database_migrates_with_agents_intact() {
        let path = std::env::temp_dir().join(format!(
            "revtty-migrate-v6-{}.db",
            uuid::Uuid::new_v4().simple()
        ));

        {
            let mut conn = SqliteConnection::open(&path).expect("create v6 database");
            migrations()
                .to_version(&mut conn, 6)
                .expect("migrate to schema v6");
            conn.execute(
                "INSERT INTO agents
                 (id, name, control_hash, host_key, operator_key, created_at, last_seen, version)
                 VALUES ('agent-id', 'legacy', x'00', ?1, ?2, 1, 1, '0.1.0')",
                params![HOST_KEY, OPERATOR_KEY],
            )
            .expect("insert v6 agent");
            conn.execute(
                "INSERT INTO agent_operators (agent_id, fingerprint, public_key)
                 VALUES ('agent-id', ?1, ?2)",
                params![
                    operator_fingerprint(OPERATOR_KEY).expect("fingerprint"),
                    OPERATOR_KEY
                ],
            )
            .expect("insert v6 operator");
        }

        let store = Store::open(&path)
            .await
            .expect("open and migrate v6 database");
        assert_eq!(store.schema_version().await.expect("schema version"), 7);
        let agent = store
            .get_agent("legacy")
            .await
            .expect("get migrated agent")
            .expect("migrated agent exists");
        assert_eq!(agent.host_key, HOST_KEY);
        assert_eq!(agent.host_key_proof, None);
        assert_eq!(
            agent.operators,
            vec![operator_fingerprint(OPERATOR_KEY).expect("fingerprint")]
        );

        drop(store);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::test]
    async fn a_host_key_proof_belongs_to_the_instance_enrolled_with_it() {
        let store = Store::open_in_memory().await.expect("open store");
        let enrollment = store
            .create_enrollment("store-042", OPERATOR_KEY, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        store
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, Some("proof-one"), None)
            .await
            .expect("consume enrollment");
        let proof = || async {
            store
                .get_agent("store-042")
                .await
                .expect("get agent")
                .expect("agent exists")
                .host_key_proof
        };
        assert_eq!(proof().await.as_deref(), Some("proof-one"));

        // A replacement brings its own proof, or none: never the old instance's.
        for next in [None, Some("proof-two")] {
            let replacement = store
                .create_replacement_enrollment("store-042", OPERATOR_KEY, Duration::from_secs(60))
                .await
                .expect("create replacement enrollment");
            store
                .consume_enrollment(replacement.token.expose(), HOST_KEY, next, None)
                .await
                .expect("consume replacement enrollment");
            assert_eq!(proof().await.as_deref(), next);
        }
    }

    fn reported(keys: &[&str]) -> Vec<ReportedOperator> {
        keys.iter()
            .map(|key| ReportedOperator {
                fingerprint: operator_fingerprint(key).expect("fingerprint"),
                public_key: (*key).to_owned(),
            })
            .collect()
    }

    #[tokio::test]
    async fn operators_reports_apply_from_the_current_connection_only() {
        let second_key = OPERATOR_KEY.replace('B', "D");
        let second_key = second_key.as_str();
        let store = Store::open_in_memory().await.expect("open store");
        let enrollment = store
            .create_enrollment("store-042", OPERATOR_KEY, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let credential = store
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, None, None)
            .await
            .expect("consume enrollment");
        let id = credential.id.as_str();
        let epoch = store.enrollment_epoch().await.expect("epoch");
        let first = operator_fingerprint(OPERATOR_KEY).expect("fingerprint");
        let second = operator_fingerprint(second_key).expect("fingerprint");

        assert!(
            store
                .claim_control_connection(id, "connection-1")
                .await
                .expect("claim connection")
        );
        // The enrolled agent's first report repeats what the relay already has.
        assert_eq!(
            store
                .apply_operators_report(id, "connection-1", 1, reported(&[OPERATOR_KEY]))
                .await
                .expect("first report"),
            OperatorsReportOutcome::Applied { changed: false }
        );
        assert_eq!(store.enrollment_epoch().await.expect("epoch"), epoch);

        assert_eq!(
            store
                .apply_operators_report(
                    id,
                    "connection-1",
                    2,
                    reported(&[OPERATOR_KEY, second_key])
                )
                .await
                .expect("added operator"),
            OperatorsReportOutcome::Applied { changed: true }
        );
        assert_eq!(store.enrollment_epoch().await.expect("epoch"), epoch + 1);
        assert!(store.operator_authorized(id, &second).await.expect("check"));

        // The agent reconnects; a report the old connection sent late changes nothing.
        assert!(
            store
                .claim_control_connection(id, "connection-2")
                .await
                .expect("claim connection")
        );
        assert_eq!(
            store
                .apply_operators_report(id, "connection-1", 3, reported(&[second_key]))
                .await
                .expect("late report"),
            OperatorsReportOutcome::NotCurrent
        );
        assert!(store.operator_authorized(id, &first).await.expect("check"));

        // Whatever its revision, the current connection's list is what the agent enforces,
        // as after restoring `agent.toml` from a backup.
        assert_eq!(
            store
                .apply_operators_report(id, "connection-2", 1, reported(&[second_key]))
                .await
                .expect("restored list"),
            OperatorsReportOutcome::Applied { changed: true }
        );
        assert!(!store.operator_authorized(id, &first).await.expect("check"));
        assert_eq!(
            store
                .get_agent("store-042")
                .await
                .expect("get agent")
                .expect("agent exists")
                .operators,
            vec![second.clone()]
        );
        assert_eq!(store.enrollment_epoch().await.expect("epoch"), epoch + 2);

        assert!(
            !store
                .claim_control_connection("gone", "connection-3")
                .await
                .expect("claim for a removed agent")
        );
        assert_eq!(
            store
                .apply_operators_report("gone", "connection-3", 9, reported(&[second_key]))
                .await
                .expect("unknown agent"),
            OperatorsReportOutcome::NotCurrent
        );
    }

    #[tokio::test]
    async fn replacement_enrollment_replaces_the_instance_it_was_created_for() {
        let replacement_key = OPERATOR_KEY.replace('B', "E");
        let store = Store::open_in_memory().await.expect("open store");
        let enrollment = store
            .create_enrollment("store-042", OPERATOR_KEY, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let original = store
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, None, None)
            .await
            .expect("consume enrollment");

        // A plain enrollment cannot take over an enrolled name, and nothing can be replaced
        // that is not enrolled.
        assert!(
            store
                .create_enrollment("store-042", OPERATOR_KEY, Duration::from_secs(60))
                .await
                .is_err()
        );
        assert!(
            store
                .create_replacement_enrollment("unknown", OPERATOR_KEY, Duration::from_secs(60))
                .await
                .is_err()
        );

        let first = store
            .create_replacement_enrollment("store-042", &replacement_key, Duration::from_secs(60))
            .await
            .expect("create replacement");
        assert_eq!(
            first.replaces_agent_id.as_deref(),
            Some(original.id.as_str())
        );
        let second = store
            .create_replacement_enrollment("store-042", &replacement_key, Duration::from_secs(60))
            .await
            .expect("create a second replacement");

        let epoch = store.enrollment_epoch().await.expect("epoch");
        let replaced = store
            .consume_enrollment(first.token.expose(), HOST_KEY, None, None)
            .await
            .expect("consume replacement");
        assert_ne!(replaced.id, original.id);
        assert_eq!(store.enrollment_epoch().await.expect("epoch"), epoch + 1);
        // The old instance is gone, with its credential and operators.
        assert!(
            store
                .authenticate_agent("store-042", original.control_token.expose())
                .await
                .expect("authenticate old credential")
                .is_none()
        );
        let old_operator = operator_fingerprint(OPERATOR_KEY).expect("fingerprint");
        assert!(
            !store
                .operator_authorized(&original.id, &old_operator)
                .await
                .expect("check old operator")
        );
        let agent = store
            .get_agent("store-042")
            .await
            .expect("get agent")
            .expect("agent exists");
        assert_eq!(agent.id, replaced.id);
        assert_eq!(
            agent.operators,
            vec![operator_fingerprint(&replacement_key).expect("fingerprint")]
        );

        // The second replacement was created for the instance that is gone.
        assert!(
            store
                .consume_enrollment(second.token.expose(), HOST_KEY, None, None)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .get_agent("store-042")
                .await
                .expect("get agent")
                .expect("agent exists")
                .id,
            replaced.id
        );
    }

    #[tokio::test]
    async fn removed_agent_takes_its_operators_and_pending_enrollments() {
        let store = Store::open_in_memory().await.expect("open store");
        let enrollment = store
            .create_enrollment("store-042", OPERATOR_KEY, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let credential = store
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, None, None)
            .await
            .expect("consume enrollment");
        let pending = store
            .create_replacement_enrollment("store-042", OPERATOR_KEY, Duration::from_secs(60))
            .await
            .expect("create replacement");
        store
            .record_session_requested("s1", "store-042", "shell", "SHA256:operator", 100)
            .await
            .expect("record session");

        let removed = store
            .remove_agent("store-042")
            .await
            .expect("remove agent")
            .expect("agent was enrolled");
        assert_eq!(removed.id, credential.id);
        assert_eq!(removed.cancelled_enrollments, 1);
        assert!(
            store
                .get_agent("store-042")
                .await
                .expect("get agent")
                .is_none()
        );
        assert!(
            store
                .existing_agent_ids(vec![credential.id.clone()])
                .await
                .expect("look up agents")
                .is_empty()
        );
        assert!(
            !store
                .operator_authorized(
                    &credential.id,
                    &operator_fingerprint(OPERATOR_KEY).expect("fingerprint")
                )
                .await
                .expect("check operator")
        );
        assert!(
            store
                .consume_enrollment(pending.token.expose(), HOST_KEY, None, None)
                .await
                .is_err(),
            "an enrollment issued before the removal brought the agent back"
        );
        assert_eq!(store.list_sessions(10).await.expect("audit kept").len(), 1);
        assert!(
            store
                .remove_agent("store-042")
                .await
                .expect("remove again")
                .is_none()
        );
    }

    #[tokio::test]
    async fn rotation_switches_credentials_only_once_confirmed() {
        let store = Store::open_in_memory().await.expect("open store");
        let enrollment = store
            .create_enrollment("store-042", OPERATOR_KEY, Duration::from_secs(60))
            .await
            .expect("create enrollment");
        let credential = store
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, None, None)
            .await
            .expect("consume enrollment");
        let current = credential.control_token.expose();
        let next = SecretToken::generate("rva").expect("next credential");
        let authenticated = |token: String| {
            let store = store.clone();
            async move {
                store
                    .authenticate_agent("store-042", &token)
                    .await
                    .expect("authenticate")
                    .is_some()
            }
        };

        let stranger = SecretToken::generate("rva").expect("unrelated credential");
        assert!(
            !store
                .begin_rotation("store-042", stranger.expose(), next.hash())
                .await
                .expect("begin with a wrong credential")
        );
        assert!(
            store
                .begin_rotation("store-042", current, next.hash())
                .await
                .expect("begin rotation")
        );
        // Until confirmed, the current credential works and the next one does not.
        assert!(authenticated(current.to_owned()).await);
        assert!(!authenticated(next.expose().to_owned()).await);

        assert_eq!(
            store
                .confirm_rotation("store-042", stranger.expose())
                .await
                .expect("confirm unrelated"),
            RotationConfirmation::Rejected
        );
        assert_eq!(
            store
                .confirm_rotation("store-042", next.expose())
                .await
                .expect("confirm"),
            RotationConfirmation::Promoted
        );
        assert!(!authenticated(current.to_owned()).await);
        assert!(authenticated(next.expose().to_owned()).await);

        // An agent that lost the answer confirms again.
        assert_eq!(
            store
                .confirm_rotation("store-042", next.expose())
                .await
                .expect("confirm again"),
            RotationConfirmation::AlreadyCurrent
        );
        assert_eq!(
            store
                .confirm_rotation("store-042", current)
                .await
                .expect("confirm the old credential"),
            RotationConfirmation::Rejected
        );
        // A request authenticated with the old credential before the promotion, and stalled
        // since, cannot start another rotation.
        let late = SecretToken::generate("rva").expect("late credential");
        assert!(
            !store
                .begin_rotation("store-042", current, late.hash())
                .await
                .expect("begin with the replaced credential")
        );
        assert_eq!(
            store
                .confirm_rotation("store-042", late.expose())
                .await
                .expect("confirm the late credential"),
            RotationConfirmation::Rejected
        );
        assert!(authenticated(next.expose().to_owned()).await);
    }

    #[tokio::test]
    async fn session_audit_records_event_times_once() {
        let store = Store::open_in_memory().await.expect("open store");

        store
            .record_session_requested("s1", "store-042", "shell", "SHA256:operator", 100)
            .await
            .expect("record request");
        store
            .record_session_accepted("s1", 101)
            .await
            .expect("record acceptance");
        store
            .record_session_paired("s1", 102)
            .await
            .expect("record pairing");
        store
            .record_session_ended("s1", "completed", 160)
            .await
            .expect("record end");
        // A later outcome does not overwrite the first.
        store
            .record_session_ended("s1", "tunnel_timeout", 999)
            .await
            .expect("ignore second end");

        store
            .record_session_requested("s2", "store-042", "probe", "SHA256:operator", 200)
            .await
            .expect("record second request");
        assert_eq!(
            store
                .close_interrupted_sessions()
                .await
                .expect("close interrupted"),
            1
        );

        let sessions = store.list_sessions(10).await.expect("list sessions");
        assert_eq!(sessions.len(), 2);
        let first = sessions
            .iter()
            .find(|session| session.id == "s1")
            .expect("first session");
        assert_eq!(first.agent_name, "store-042");
        assert_eq!(first.kind, "shell");
        assert_eq!(first.operator_fingerprint, "SHA256:operator");
        // The times the events happened, whenever the writes ran.
        assert_eq!(
            (
                first.requested_at,
                first.accepted_at,
                first.paired_at,
                first.ended_at
            ),
            (100, Some(101), Some(102), Some(160))
        );
        assert_eq!(first.outcome.as_deref(), Some("completed"));
        let second = sessions
            .iter()
            .find(|session| session.id == "s2")
            .expect("second session");
        assert_eq!(second.outcome.as_deref(), Some("interrupted"));
        assert!(second.accepted_at.is_none());

        assert_eq!(store.list_sessions(1).await.expect("limited list").len(), 1);
    }
}
