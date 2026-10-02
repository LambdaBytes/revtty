use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite_migration::{M, Migrations};
use thiserror::Error;
use tokio_rusqlite::Connection;
use tokio_rusqlite::rusqlite::{OptionalExtension, params};
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

#[derive(Debug, Error)]
enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] tokio_rusqlite::rusqlite::Error),

    #[error("enrollment token is invalid, expired, or already used")]
    InvalidEnrollment,

    #[error("enrollment token could not be consumed atomically")]
    EnrollmentRace,
}

#[derive(Clone)]
pub struct Store {
    conn: Connection,
}

pub struct Enrollment {
    pub id: String,
    pub token: SecretToken,
    pub expires_at: i64,
}

pub struct AgentCredential {
    pub id: String,
    pub name: String,
    pub operator_key: String,
    pub control_token: SecretToken,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AgentRecord {
    pub id: String,
    pub name: String,
    pub host_key: String,
    pub operator_key: String,
    pub created_at: i64,
    pub last_seen: Option<i64>,
    pub version: Option<String>,
}

impl Store {
    pub async fn open(path: &Path) -> Result<Self, RevttyError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| RevttyError::runtime("create relay state directory", error))?;
        }

        let conn = Connection::open(path)
            .await
            .map_err(|error| RevttyError::runtime("open relay SQLite database", error))?;

        initialize(&conn).await?;
        Ok(Self { conn })
    }

    #[cfg(test)]
    async fn open_in_memory() -> Result<Self, RevttyError> {
        let conn = Connection::open_in_memory()
            .await
            .map_err(|error| RevttyError::runtime("open in-memory relay database", error))?;

        initialize(&conn).await?;
        Ok(Self { conn })
    }

    pub async fn create_enrollment(
        &self,
        agent_name: &str,
        operator_key: &str,
        ttl: Duration,
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

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO enrollments
                     (id, token_hash, agent_name, operator_key, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        insert_id,
                        token_hash,
                        name,
                        operator_key,
                        created_at,
                        expires_at
                    ],
                )?;
                Ok::<_, StoreError>(())
            })
            .await
            .map_err(|error| RevttyError::runtime("create enrollment", error))?;

        Ok(Enrollment {
            id,
            token,
            expires_at,
        })
    }

    pub async fn consume_enrollment(
        &self,
        enrollment_token: &str,
        host_key: &str,
        version: Option<&str>,
    ) -> Result<AgentCredential, RevttyError> {
        let enrollment_hash = hash_token(enrollment_token).to_vec();
        let agent_id = Uuid::new_v4().simple().to_string();
        let control_token = SecretToken::generate("rva")?;
        let control_hash = control_token.hash().to_vec();
        let now = unix_now()?;
        let host_key = host_key.to_owned();
        let version = version.map(str::to_owned);
        let inserted_id = agent_id.clone();

        let (name, operator_key) = self
            .conn
            .call(move |conn| {
                let transaction = conn.transaction()?;

                let enrollment = transaction
                    .query_row(
                        "SELECT agent_name, operator_key
                         FROM enrollments
                         WHERE token_hash = ?1
                           AND used_at IS NULL
                           AND expires_at >= ?2",
                        params![enrollment_hash, now],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
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

                transaction.execute(
                    "INSERT INTO agents
                     (id, name, control_hash, host_key, operator_key, created_at, last_seen, version)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
                    params![
                        inserted_id,
                        enrollment.0,
                        control_hash,
                        host_key,
                        enrollment.1,
                        now,
                        version
                    ],
                )?;

                transaction.commit()?;
                Ok::<_, StoreError>(enrollment)
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

    pub async fn authenticate_agent(
        &self,
        agent_name: &str,
        control_token: &str,
    ) -> Result<bool, RevttyError> {
        let name = agent_name.to_owned();
        let hash = hash_token(control_token).to_vec();

        self.conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT 1 FROM agents WHERE name = ?1 AND control_hash = ?2",
                    params![name, hash],
                    |_| Ok(()),
                )
                .optional()
                .map(|value| value.is_some())
                .map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("authenticate agent", error))
    }

    pub async fn mark_seen(
        &self,
        agent_name: &str,
        version: Option<&str>,
    ) -> Result<(), RevttyError> {
        let name = agent_name.to_owned();
        let version = version.map(str::to_owned);
        let now = unix_now()?;

        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE agents SET last_seen = ?1, version = COALESCE(?2, version)
                     WHERE name = ?3",
                    params![now, version, name],
                )?;
                Ok::<_, StoreError>(())
            })
            .await
            .map_err(|error| RevttyError::runtime("update agent presence", error))
    }

    pub async fn list_agents(&self) -> Result<Vec<AgentRecord>, RevttyError> {
        self.conn
            .call(|conn| {
                let mut statement = conn.prepare(
                    "SELECT id, name, host_key, operator_key, created_at, last_seen, version
                     FROM agents
                     ORDER BY name",
                )?;

                let rows = statement.query_map([], |row| {
                    Ok(AgentRecord {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        host_key: row.get(2)?,
                        operator_key: row.get(3)?,
                        created_at: row.get(4)?,
                        last_seen: row.get(5)?,
                        version: row.get(6)?,
                    })
                })?;

                rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("list enrolled agents", error))
    }

    pub async fn get_agent(&self, agent_name: &str) -> Result<Option<AgentRecord>, RevttyError> {
        let name = agent_name.to_owned();

        self.conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT id, name, host_key, operator_key, created_at, last_seen, version
                     FROM agents
                     WHERE name = ?1",
                    params![name],
                    |row| {
                        Ok(AgentRecord {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            host_key: row.get(2)?,
                            operator_key: row.get(3)?,
                            created_at: row.get(4)?,
                            last_seen: row.get(5)?,
                            version: row.get(6)?,
                        })
                    },
                )
                .optional()
                .map_err(StoreError::from)
            })
            .await
            .map_err(|error| RevttyError::runtime("read enrolled agent", error))
    }
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
    Migrations::new(vec![M::up(SCHEMA_V1)])
}

fn unix_now() -> Result<i64, RevttyError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| RevttyError::runtime("read system clock", error))?;

    i64::try_from(duration.as_secs())
        .map_err(|_| RevttyError::message("system clock is outside supported range"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Store, migrations};

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
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, Some("0.1.0"))
            .await
            .expect("consume enrollment");

        assert_eq!(credential.name, "store-042");
        assert_eq!(credential.operator_key, OPERATOR_KEY);
        assert!(
            store
                .authenticate_agent("store-042", credential.control_token.expose())
                .await
                .expect("authenticate agent")
        );
        assert!(
            !store
                .authenticate_agent("store-042", "wrong-token")
                .await
                .expect("reject wrong token")
        );

        let second = store
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, Some("0.1.0"))
            .await;
        assert!(second.is_err());

        let agents = store.list_agents().await.expect("list agents");
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "store-042");
        assert_eq!(agents[0].host_key, HOST_KEY);
        assert_eq!(agents[0].version.as_deref(), Some("0.1.0"));
    }

    #[tokio::test]
    async fn presence_updates_are_persisted() {
        let store = Store::open_in_memory().await.expect("open store");
        let enrollment = store
            .create_enrollment("demo", OPERATOR_KEY, Duration::from_secs(60))
            .await
            .expect("create enrollment");

        store
            .consume_enrollment(enrollment.token.expose(), HOST_KEY, None)
            .await
            .expect("consume enrollment");

        store
            .mark_seen("demo", Some("0.2.0"))
            .await
            .expect("mark seen");

        let agent = store
            .get_agent("demo")
            .await
            .expect("get agent")
            .expect("agent exists");

        assert!(agent.last_seen.is_some());
        assert_eq!(agent.version.as_deref(), Some("0.2.0"));
    }
}
