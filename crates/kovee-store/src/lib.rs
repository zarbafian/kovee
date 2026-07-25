//! SQLite storage for the kovee personal profile (design §8, §12): plain
//! WAL SQLite (no envelope encryption — same-UID data), numbered
//! `user_version` migrations, the K1 core tables, and the §12.2 command
//! transaction: state, event(s) with dense sequences, the idempotency
//! record, and outbox rows commit atomically in ONE SQL transaction — or
//! none of them exist.
//!
//! What you write (the daemon's side of one mutation):
//! ```
//! use kovee_store::{Store, CommandScope, CrashHooks, Applied};
//! let mut store = Store::open_in_memory().unwrap();
//! store.bootstrap(0).unwrap();
//! let scope = CommandScope {
//!     actor_scope: "external_client/prin-owner/realm-personal".into(),
//!     operation: "project_create".into(),
//!     idempotency_key: "idem-1".into(),
//!     request_digest: "d".repeat(64),
//! };
//! let outcome = store.command_transaction(&scope, 0, CrashHooks::NONE, |txn| {
//!     txn.audit("doc.test", "detail");
//!     Ok(Applied { result: serde_json::json!({"ok": true}),
//!                  revision: Some(1), event_cursor: None })
//! }).unwrap();
//! // A replay of the same scoped key returns byte-identical bytes.
//! let replay = store.command_transaction(&scope, 0, CrashHooks::NONE,
//!     |_| unreachable!("a replay never re-executes")).unwrap();
//! assert_eq!(outcome.bytes(), replay.bytes());
//! ```

pub mod audit;
pub mod schema;

use std::io::Read as _;
use std::path::Path;

use kovee_core::canonical;
use kovee_core::event::EventEnvelope;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::Realm;
use kovee_core::time::rfc3339_utc;
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const META_INSTALLATION_ID: &str = "installation_id";
const META_REALM_ID: &str = "realm_id";
const META_CURSOR_SECRET: &str = "cursor_secret";

/// The deterministic personal-profile realm id: the personal profile has
/// exactly one realm and no `realm_create` operation exists before K3
/// (`installation_admin_v1`), so clients can address it without discovery.
pub const PERSONAL_REALM_ID: &str = "realm-personal";
/// The one authenticated principal of the personal profile (same-UID
/// channel binding, §9.1: local mode binds one principal to Unix peer
/// credentials). Channel-derived; never accepted from a request body.
pub const OWNER_ACTOR_REF: &str = "prin-owner";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Audit(#[from] audit::AuditError),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("canonicalization: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error("entropy: {0}")]
    Entropy(std::io::Error),
    #[error("corrupt store state: {0}")]
    Corrupt(String),
}

/// A command either fails with a §11.7 problem (nothing committed) or a
/// store fault.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("problem: {0:?}")]
    Problem(Problem),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<rusqlite::Error> for CommandError {
    fn from(e: rusqlite::Error) -> CommandError {
        CommandError::Store(StoreError::Db(e))
    }
}

/// The §11.2 idempotency scope: keys are scoped by authenticated actor,
/// operation, and realm — `actor_scope` carries surface, actor, and realm.
#[derive(Debug, Clone)]
pub struct CommandScope {
    pub actor_scope: String,
    pub operation: String,
    pub idempotency_key: String,
    /// The §11.2 canonical request digest (`kcp-command-idempotency`).
    pub request_digest: String,
}

/// What one applied mutation hands back to the transaction wrapper.
pub struct Applied {
    /// The operation-specific `result` payload (§11.2 ok arm).
    pub result: Value,
    pub revision: Option<u64>,
    pub event_cursor: Option<String>,
}

/// The §12.2 outcome: the exact serialized `CommandResult` bytes — stored
/// on first execution, returned verbatim on replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    Fresh(Vec<u8>),
    Replayed(Vec<u8>),
}

impl CommandOutcome {
    pub fn bytes(&self) -> &[u8] {
        match self {
            CommandOutcome::Fresh(b) | CommandOutcome::Replayed(b) => b,
        }
    }
}

/// Crash-honesty test hooks (the K1 kill-and-restart matrix): abort the
/// process at a named §12.2 commit point. `NONE` in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashHooks {
    pub abort_before_commit: bool,
    pub abort_after_commit: bool,
}

impl CrashHooks {
    pub const NONE: CrashHooks = CrashHooks {
        abort_before_commit: false,
        abort_after_commit: false,
    };
}

/// A new event to append inside a command transaction. Sequences are
/// allocated by the store (dense, §11.3); ids/digests are derived here.
pub struct NewEvent {
    pub stream_id: String,
    /// Present for project-scoped events: allocates one dense
    /// `project_sequence` under the project head row.
    pub project_id: Option<String>,
    pub event_type: &'static str,
    pub schema_ref: String,
    pub resource_ref: String,
    pub resource_revision: Option<u64>,
    pub causation_ref: Option<String>,
    pub correlation_ref: String,
    pub classification_ref: String,
    pub payload: Value,
}

/// The open command transaction handed to an operation's apply closure —
/// §12.2 steps 5–8 run through this.
pub struct CommandTxn<'a> {
    tx: &'a rusqlite::Transaction<'a>,
    installation_id: String,
    realm_id: String,
    now: i64,
    audit_records: Vec<(String, String)>,
}

impl CommandTxn<'_> {
    pub fn conn(&self) -> &Connection {
        self.tx
    }

    pub fn now_ts(&self) -> String {
        rfc3339_utc(self.now)
    }

    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    pub fn realm_id(&self) -> &str {
        &self.realm_id
    }

    /// Queues a body-free audit record; written inside this transaction.
    pub fn audit(&mut self, event: &str, detail: &str) {
        self.audit_records
            .push((event.to_owned(), detail.to_owned()));
    }

    /// §12.2 steps 7 + 8: appends one typed event with dense sequence
    /// allocation (per-stream and per-project) and enqueues its outbox
    /// notification. Aborted transactions consume no sequence (§11.3).
    pub fn append_event(&mut self, new: NewEvent) -> Result<EventEnvelope, StoreError> {
        let stream_sequence = self.next_stream_sequence(&new.stream_id)?;
        let project_sequence = match &new.project_id {
            Some(project_id) => Some(self.next_project_sequence(project_id)?),
            None => None,
        };
        let event_id = new_id("evt")?;
        // The §11.8 payload-digest projection is a recorded K0 gap
        // (shape-only): pinned here as the canonical-object digest of the
        // inline payload under the event schema ref.
        let (_, payload_digest) =
            canonical::canonical_object_digest("kcp-event-payload", &new.schema_ref, &new.payload)?;
        let event = EventEnvelope {
            event_id,
            installation_id: self.installation_id.clone(),
            realm_id: self.realm_id.clone(),
            project_id: new.project_id,
            stream_id: new.stream_id,
            stream_sequence,
            project_sequence,
            event_type: new.event_type.to_owned(),
            schema_ref: new.schema_ref,
            resource_ref: new.resource_ref,
            resource_revision: new.resource_revision,
            actor_ref: OWNER_ACTOR_REF.to_owned(),
            causation_ref: new.causation_ref,
            correlation_ref: new.correlation_ref,
            occurred_at: rfc3339_utc(self.now),
            classification_ref: new.classification_ref,
            payload_digest,
            payload: Some(new.payload),
            payload_ref: None,
            ext: None,
        };
        self.tx.execute(
            "INSERT INTO events (event_id, installation_id, realm_id, project_id,
                 stream_id, stream_sequence, project_sequence, type, schema_ref,
                 resource_ref, resource_revision, actor_ref, causation_ref,
                 correlation_ref, occurred_at, classification_ref, payload_digest,
                 payload)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                event.event_id,
                event.installation_id,
                event.realm_id,
                event.project_id,
                event.stream_id,
                event.stream_sequence as i64,
                event.project_sequence.map(|s| s as i64),
                event.event_type,
                event.schema_ref,
                event.resource_ref,
                event.resource_revision.map(|r| r as i64),
                event.actor_ref,
                event.causation_ref,
                event.correlation_ref,
                event.occurred_at,
                event.classification_ref,
                event.payload_digest,
                serde_json::to_string(&event.payload)?,
            ],
        )?;
        // §12.4: the outbox notification is a minimal envelope with a
        // stable delivery id derived from the logical event id.
        let outbox_payload = serde_json::json!({
            "event_id": event.event_id,
            "stream_id": event.stream_id,
            "stream_sequence": event.stream_sequence,
            "project_id": event.project_id,
            "project_sequence": event.project_sequence,
            "type": event.event_type,
        });
        self.enqueue_outbox(&event.event_id, "event", &outbox_payload)?;
        Ok(event)
    }

    /// §12.2 step 8: inserts one outbox row (dedup key `delivery_id`).
    pub fn enqueue_outbox(
        &mut self,
        delivery_id: &str,
        kind: &str,
        payload: &Value,
    ) -> Result<(), StoreError> {
        self.tx.execute(
            "INSERT INTO outbox (delivery_id, kind, payload, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![delivery_id, kind, serde_json::to_string(payload)?, self.now],
        )?;
        Ok(())
    }

    /// Mints the §11.3 opaque authenticated cursor from inside the open
    /// transaction (the `event_cursor` of a mutation's result).
    pub fn mint_project_cursor(&self, project_id: &str, seq: u64) -> Result<String, StoreError> {
        let secret = schema::meta_get(self.tx, META_CURSOR_SECRET)?
            .ok_or_else(|| StoreError::Corrupt("store is not bootstrapped".to_owned()))?;
        mint_cursor(&secret, project_id, seq)
    }

    fn next_stream_sequence(&mut self, stream_id: &str) -> Result<u64, StoreError> {
        self.tx.execute(
            "INSERT INTO stream_heads (stream_id, next_sequence) VALUES (?1, 2)
             ON CONFLICT(stream_id) DO UPDATE SET next_sequence = next_sequence + 1",
            [stream_id],
        )?;
        let next: i64 = self.tx.query_row(
            "SELECT next_sequence FROM stream_heads WHERE stream_id = ?1",
            [stream_id],
            |r| r.get(0),
        )?;
        Ok((next - 1) as u64)
    }

    fn next_project_sequence(&mut self, project_id: &str) -> Result<u64, StoreError> {
        let allocated: Option<i64> = self
            .tx
            .query_row(
                "UPDATE projects SET next_project_sequence = next_project_sequence + 1
                 WHERE project_id = ?1
                 RETURNING next_project_sequence - 1",
                [project_id],
                |r| r.get(0),
            )
            .optional()?;
        match allocated {
            Some(seq) => Ok(seq as u64),
            None => Err(StoreError::Corrupt(format!(
                "no project head row for {project_id}"
            ))),
        }
    }
}

/// One personal-profile authoritative database.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens (creating if absent) the database at `path`.
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        Store::from_conn(Connection::open(path)?)
    }

    /// Opens an in-memory database — tests and doc examples.
    pub fn open_in_memory() -> Result<Store, StoreError> {
        Store::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(mut conn: Connection) -> Result<Store, StoreError> {
        // The command transaction reads (idempotency, heads) then writes;
        // IMMEDIATE takes the write lock at BEGIN so check-and-act is a
        // genuine CAS under a second connection.
        conn.set_transaction_behavior(rusqlite::TransactionBehavior::Immediate);
        let journal_mode = schema::open_and_migrate(&conn)?;
        // WAL must actually be in effect on disk (in-memory reports
        // "memory"); a rollback-journal mode means WAL silently failed.
        if journal_mode != "wal" && journal_mode != "memory" {
            return Err(StoreError::Corrupt(format!(
                "journal_mode is {journal_mode:?}, expected wal"
            )));
        }
        Ok(Store { conn })
    }

    /// First-run bootstrap: mints the installation id, the cursor secret,
    /// and the personal realm row (§8 personal profile — one realm; no
    /// realm_create operation exists before K3). Idempotent.
    pub fn bootstrap(&mut self, now: i64) -> Result<(), StoreError> {
        if schema::meta_get(&self.conn, META_INSTALLATION_ID)?.is_some() {
            return Ok(());
        }
        let installation_id = new_id("inst")?;
        let mut secret = [0u8; 32];
        fill_random(&mut secret)?;
        let tx = self.conn.unchecked_transaction()?;
        schema::meta_set(&tx, META_INSTALLATION_ID, installation_id.as_bytes())?;
        schema::meta_set(&tx, META_REALM_ID, PERSONAL_REALM_ID.as_bytes())?;
        schema::meta_set(&tx, META_CURSOR_SECRET, &secret)?;
        tx.execute(
            "INSERT INTO realms (realm_id, installation_id, revision, name, status,
                 home_region, auth_policy_ref, retention_policy_ref,
                 encryption_key_ref, created_at)
             VALUES (?1, ?2, 1, 'personal', 'active', 'local',
                 'auth-local-uds', 'ret-default', 'enc-none-plain', ?3)",
            params![PERSONAL_REALM_ID, installation_id, rfc3339_utc(now)],
        )?;
        audit::append(&tx, now, "realm.bootstrapped", PERSONAL_REALM_ID)?;
        tx.commit()?;
        Ok(())
    }

    pub fn installation_id(&self) -> Result<String, StoreError> {
        schema::meta_get_text(&self.conn, META_INSTALLATION_ID)?
            .ok_or_else(|| StoreError::Corrupt("store is not bootstrapped".to_owned()))
    }

    /// Read-only access for queries outside a command transaction.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Verifies the audit chain; returns the number of records.
    pub fn verify_audit(&self) -> Result<u64, StoreError> {
        Ok(audit::verify_chain(&self.conn)?)
    }

    /// The §12.2 command transaction. In ONE SQL transaction:
    /// 3. canonicalize + check the idempotency record — an exact replay
    ///    returns the stored byte-identical result without re-executing; a
    ///    changed covered value is `idempotency-mismatch`;
    /// 4–6. the apply closure locks/compares aggregate heads, validates
    ///    the transition, and updates normalized state;
    /// 7. the closure appends typed events (dense sequences) and audit;
    /// 8. the closure enqueues outbox rows;
    /// 9. the canonical result bytes are persisted in the idempotency
    ///    record;
    /// 10. commit — or, on any failure, none of it exists.
    ///
    /// (Steps 1–2, channel authentication and authorization, precede this
    /// call in the daemon.)
    pub fn command_transaction(
        &mut self,
        scope: &CommandScope,
        now: i64,
        hooks: CrashHooks,
        apply: impl FnOnce(&mut CommandTxn) -> Result<Applied, Problem>,
    ) -> Result<CommandOutcome, CommandError> {
        let installation_id = self.installation_id()?;
        let realm_id = schema::meta_get_text(&self.conn, META_REALM_ID)?
            .ok_or_else(|| StoreError::Corrupt("store is not bootstrapped".to_owned()))?;
        let tx = self.conn.transaction()?;

        // Step 3: the idempotency record decides replay vs mismatch.
        let prior: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT request_digest, result FROM idempotency_records
                 WHERE actor_scope = ?1 AND operation = ?2 AND idempotency_key = ?3",
                params![scope.actor_scope, scope.operation, scope.idempotency_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((stored_digest, stored_result)) = prior {
            if stored_digest == scope.request_digest {
                // §11.2: replay reauthorization against the current
                // dependency set — trivially satisfied in the personal
                // profile (the same-UID owner is the only principal).
                return Ok(CommandOutcome::Replayed(stored_result));
            }
            return Err(CommandError::Problem(
                Problem::new(
                    ProblemKind::IdempotencyMismatch,
                    "same scoped idempotency key, different canonical request",
                )
                .with_detail("reusing an idempotency key with changed arguments is refused"),
            ));
        }

        // Steps 4–8 run in the closure against this open transaction.
        let mut txn = CommandTxn {
            tx: &tx,
            installation_id,
            realm_id,
            now,
            audit_records: Vec::new(),
        };
        let applied = match apply(&mut txn) {
            Ok(applied) => applied,
            Err(problem) => {
                drop(txn);
                tx.rollback()?;
                return Err(CommandError::Problem(problem));
            }
        };
        let audit_records = std::mem::take(&mut txn.audit_records);
        drop(txn);
        for (event, detail) in &audit_records {
            audit::append(&tx, now, event, detail)?;
        }

        // Step 9: persist the canonical result for idempotent replay.
        let result = kovee_core::envelope::CommandResult::Ok {
            result: applied.result,
            revision: applied.revision,
            event_cursor: applied.event_cursor.clone(),
        };
        let bytes = serde_json::to_vec(&result).map_err(StoreError::from)?;
        tx.execute(
            "INSERT INTO idempotency_records
                 (actor_scope, operation, idempotency_key, request_digest,
                  result, revision, event_cursor, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                scope.actor_scope,
                scope.operation,
                scope.idempotency_key,
                scope.request_digest,
                bytes,
                applied.revision.map(|r| r as i64),
                applied.event_cursor,
                now,
            ],
        )?;

        // Crash-honesty hook: die BEFORE commit — nothing may survive.
        if hooks.abort_before_commit {
            std::process::abort();
        }
        // Step 10: commit before replying.
        tx.commit()?;
        // Crash-honesty hook: die AFTER commit and before the reply — the
        // retry must find the stored byte-identical result.
        if hooks.abort_after_commit {
            std::process::abort();
        }
        Ok(CommandOutcome::Fresh(bytes))
    }

    // ------------------------------------------------------ read side ----

    pub fn get_realm(&self, realm_id: &str) -> Result<Option<Realm>, StoreError> {
        self.conn
            .query_row(
                "SELECT realm_id, installation_id, revision, name, status, home_region,
                        auth_policy_ref, retention_policy_ref, encryption_key_ref,
                        created_at
                 FROM realms WHERE realm_id = ?1",
                [realm_id],
                |r| {
                    Ok(Realm {
                        realm_id: r.get(0)?,
                        installation_id: r.get(1)?,
                        revision: r.get::<_, i64>(2)? as u64,
                        name: r.get(3)?,
                        status: r.get(4)?,
                        home_region: r.get(5)?,
                        auth_policy_ref: r.get(6)?,
                        retention_policy_ref: r.get(7)?,
                        encryption_key_ref: r.get(8)?,
                        created_at: r.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Ordered project-stream events strictly after `after_project_seq`,
    /// optionally narrowed by type prefixes, at most `limit` rows.
    pub fn list_project_events(
        &self,
        project_id: &str,
        after_project_seq: u64,
        type_prefixes: Option<&[String]>,
        limit: u64,
    ) -> Result<Vec<EventEnvelope>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, installation_id, realm_id, project_id, stream_id,
                    stream_sequence, project_sequence, type, schema_ref, resource_ref,
                    resource_revision, actor_ref, causation_ref, correlation_ref,
                    occurred_at, classification_ref, payload_digest, payload
             FROM events
             WHERE project_id = ?1 AND project_sequence > ?2
             ORDER BY project_sequence ASC",
        )?;
        let rows = stmt.query_map(params![project_id, after_project_seq as i64], |r| {
            let payload_text: String = r.get(17)?;
            Ok((
                EventEnvelope {
                    event_id: r.get(0)?,
                    installation_id: r.get(1)?,
                    realm_id: r.get(2)?,
                    project_id: r.get(3)?,
                    stream_id: r.get(4)?,
                    stream_sequence: r.get::<_, i64>(5)? as u64,
                    project_sequence: r.get::<_, Option<i64>>(6)?.map(|s| s as u64),
                    event_type: r.get(7)?,
                    schema_ref: r.get(8)?,
                    resource_ref: r.get(9)?,
                    resource_revision: r.get::<_, Option<i64>>(10)?.map(|v| v as u64),
                    actor_ref: r.get(11)?,
                    causation_ref: r.get(12)?,
                    correlation_ref: r.get(13)?,
                    occurred_at: r.get(14)?,
                    classification_ref: r.get(15)?,
                    payload_digest: r.get(16)?,
                    payload: None,
                    payload_ref: None,
                    ext: None,
                },
                payload_text,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (mut event, payload_text) = row?;
            let keep = match type_prefixes {
                None => true,
                Some(prefixes) => {
                    prefixes.is_empty()
                        || prefixes.iter().any(|p| {
                            event.event_type == *p || event.event_type.starts_with(&format!("{p}."))
                        })
                }
            };
            if !keep {
                continue;
            }
            event.payload = Some(serde_json::from_str(&payload_text)?);
            events.push(event);
            if events.len() as u64 >= limit {
                break;
            }
        }
        Ok(events)
    }

    // ------------------------------------------------- opaque cursors ----

    /// Mints the §11.3 opaque authenticated cursor for a project-stream
    /// position: an HMAC-tagged encoding of source stream, sequence, and
    /// snapshot epoch. Never a raw sequence on the wire.
    pub fn mint_project_cursor(&self, project_id: &str, seq: u64) -> Result<String, StoreError> {
        mint_cursor(&self.cursor_secret()?, project_id, seq)
    }

    /// Verifies and decodes a cursor minted by [`Store::mint_project_cursor`]
    /// for the same project. Possession of a cursor grants nothing —
    /// authorization is rechecked at read time (§11.4).
    pub fn parse_project_cursor(&self, cursor: &str, project_id: &str) -> Result<u64, Problem> {
        let fail = || {
            Problem::new(ProblemKind::Invalid, "invalid cursor")
                .with_detail("after_cursor is not a cursor this installation minted")
        };
        let mut parts = cursor.split('.');
        let (Some("kc1"), Some(body), Some(tag), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(fail());
        };
        let bytes = unhex(body).ok_or_else(fail)?;
        let tag = unhex(tag).ok_or_else(fail)?;
        let secret = self.cursor_secret().map_err(|_| fail())?;
        if hmac_sha256(&secret, &bytes).as_slice() != tag.as_slice() {
            return Err(fail());
        }
        let payload: Value = serde_json::from_slice(&bytes).map_err(|_| fail())?;
        if payload["source"].as_str() != Some(project_id) {
            return Err(fail());
        }
        payload["seq"].as_u64().ok_or_else(fail)
    }

    fn cursor_secret(&self) -> Result<Vec<u8>, StoreError> {
        schema::meta_get(&self.conn, META_CURSOR_SECRET)?
            .ok_or_else(|| StoreError::Corrupt("store is not bootstrapped".to_owned()))
    }
}

fn mint_cursor(secret: &[u8], project_id: &str, seq: u64) -> Result<String, StoreError> {
    let payload = serde_json::json!({
        "v": 1, "source": project_id, "seq": seq, "epoch": 1,
    });
    let bytes = serde_json::to_vec(&payload)?;
    let tag = hmac_sha256(secret, &bytes);
    Ok(format!("kc1.{}.{}", hex(&bytes), hex(&tag)))
}

/// A fresh prefixed id: 16 bytes of OS entropy as hex.
pub fn new_id(prefix: &str) -> Result<String, StoreError> {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes)?;
    Ok(format!("{prefix}-{}", hex(&bytes)))
}

fn fill_random(out: &mut [u8]) -> Result<(), StoreError> {
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(out))
        .map_err(StoreError::Entropy)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// HMAC-SHA256 (RFC 2104) over the store's cursor secret.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        key_block[..32].copy_from_slice(&h.finalize());
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(key_block.map(|b| b ^ 0x36));
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(key_block.map(|b| b ^ 0x5c));
    outer.update(inner_hash);
    outer.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_case_two() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn cursor_round_trips_and_rejects_tampering() {
        let mut store = Store::open_in_memory().unwrap();
        store.bootstrap(0).unwrap();
        let cursor = store.mint_project_cursor("proj-1", 7).unwrap();
        assert_eq!(store.parse_project_cursor(&cursor, "proj-1").unwrap(), 7);
        // Wrong project: refused.
        assert!(store.parse_project_cursor(&cursor, "proj-2").is_err());
        // Flipped payload byte: refused.
        let mut tampered = cursor.clone().into_bytes();
        tampered[6] = if tampered[6] == b'a' { b'b' } else { b'a' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert!(store.parse_project_cursor(&tampered, "proj-1").is_err());
    }

    #[test]
    fn idempotency_mismatch_is_refused_and_never_reexecutes() {
        let mut store = Store::open_in_memory().unwrap();
        store.bootstrap(0).unwrap();
        let mut scope = CommandScope {
            actor_scope: "s".into(),
            operation: "project_create".into(),
            idempotency_key: "k".into(),
            request_digest: "a".repeat(64),
        };
        store
            .command_transaction(&scope, 0, CrashHooks::NONE, |_| {
                Ok(Applied {
                    result: serde_json::json!({"n": 1}),
                    revision: Some(1),
                    event_cursor: None,
                })
            })
            .unwrap();
        scope.request_digest = "b".repeat(64);
        let err = store
            .command_transaction(&scope, 0, CrashHooks::NONE, |_| {
                panic!("a mismatch must never re-execute")
            })
            .unwrap_err();
        match err {
            CommandError::Problem(p) => {
                assert_eq!(p.kind, ProblemKind::IdempotencyMismatch)
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn failed_apply_commits_nothing() {
        let mut store = Store::open_in_memory().unwrap();
        store.bootstrap(0).unwrap();
        let scope = CommandScope {
            actor_scope: "s".into(),
            operation: "project_create".into(),
            idempotency_key: "k".into(),
            request_digest: "a".repeat(64),
        };
        let err = store
            .command_transaction(&scope, 0, CrashHooks::NONE, |txn| {
                txn.enqueue_outbox("d-1", "event", &serde_json::json!({}))
                    .map_err(|_| Problem::new(ProblemKind::Internal, "outbox"))?;
                Err(Problem::new(ProblemKind::StaleRevision, "stale"))
            })
            .unwrap_err();
        assert!(matches!(err, CommandError::Problem(_)));
        let outbox: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        let idem: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM idempotency_records", [], |r| r.get(0))
            .unwrap();
        assert_eq!((outbox, idem), (0, 0), "a failed command leaves nothing");
    }
}
