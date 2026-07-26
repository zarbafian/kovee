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
//!
//! Two R1 corrections live in that one function:
//! - [`Store::command_transaction_guarded`] runs an operation-specific
//!   **replay authorizer** before any stored byte is released (KV-R1), so
//!   a dead worker attempt gets a typed problem, not its old receipt;
//! - the §11.8 **result bounds are judged inside the transaction**
//!   (KV-C2), so an over-cap result rolls the command back instead of
//!   committing a receipt every reply — original and replay — would have
//!   to answer with `internal`.

pub mod audit;
pub mod objkey;
pub mod privacy;
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

const META_INSTALLATION_ID: &str = "installation_id";
const META_REALM_ID: &str = "realm_id";
const META_CURSOR_SECRET: &str = "cursor_secret";
/// The privacy-access chain key (family PROFILE §7): ONE key for the
/// whole chain — a scope key, class `scope_erasure_safe` (D-R0-1).
/// Destroying it erases verifiability of the entire chain, never one
/// record.
const META_PRIVACY_CHAIN_KEY: &str = "privacy_chain_key";
/// The governed-work digest scope key (K2 slice 1): ONE key per
/// installation's governance scope, class `scope_erasure_safe`.
/// Destroying it erases verifiability of the whole governance scope,
/// never of one binding row.
const META_GOVERNANCE_SCOPE_KEY: &str = "governance_scope_key";
/// The realm (Society) key that WRAPS every per-object erasure secret
/// (D-R1-2). It is a key-encryption key only: no object digest is
/// derived from it, so it is never the thing an object's verifiability
/// rests on. Erasing one object destroys that object's wrapped secret
/// and nothing else.
const META_REALM_OBJECT_KEY: &str = "realm_object_key";
/// Set inside an erasure transaction, cleared once the file-level
/// compaction that removes freed plaintext pages has run. A crash
/// between the two leaves the flag set and the next open compacts.
const META_ERASURE_COMPACTION_PENDING: &str = "erasure_compaction_pending";

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
    /// The attributed actor; `None` means the owner principal. Worker
    /// surface commands attribute their deployment (§10.2).
    pub actor_ref: Option<String>,
    /// A `dev.kovee.*` constant for Kovee's own events; a caller-supplied
    /// registered type for `application_event_emit` (never `dev.kovee.*`).
    pub event_type: String,
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
            event_type: new.event_type,
            schema_ref: new.schema_ref,
            resource_ref: new.resource_ref,
            resource_revision: new.resource_revision,
            actor_ref: new.actor_ref.unwrap_or_else(|| OWNER_ACTOR_REF.to_owned()),
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
        mint_token(
            &secret,
            &Token {
                source: project_id.to_owned(),
                seq,
                boundary: None,
                key: None,
            },
        )
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
        let store = Store { conn };
        // A database bootstrapped before V2/V4/V5 has no privacy chain
        // key, governance scope key, or realm object key — mint them
        // once (secrets need entropy, so migrations cannot).
        if schema::meta_get(&store.conn, META_INSTALLATION_ID)?.is_some() {
            for name in [
                META_PRIVACY_CHAIN_KEY,
                META_GOVERNANCE_SCOPE_KEY,
                META_REALM_OBJECT_KEY,
            ] {
                if schema::meta_get(&store.conn, name)?.is_none() {
                    let mut key = [0u8; 32];
                    fill_random(&mut key)?;
                    schema::meta_set(&store.conn, name, &key)?;
                }
            }
            // A crash between an erasure commit and its compaction left
            // freed plaintext pages in the file: finish the job now.
            if schema::meta_get(&store.conn, META_ERASURE_COMPACTION_PENDING)?.is_some() {
                store.compact_after_erasure()?;
            }
        }
        Ok(store)
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
        let mut chain_key = [0u8; 32];
        fill_random(&mut chain_key)?;
        let mut governance_key = [0u8; 32];
        fill_random(&mut governance_key)?;
        let mut realm_object_key = [0u8; 32];
        fill_random(&mut realm_object_key)?;
        let tx = self.conn.unchecked_transaction()?;
        schema::meta_set(&tx, META_INSTALLATION_ID, installation_id.as_bytes())?;
        schema::meta_set(&tx, META_REALM_ID, PERSONAL_REALM_ID.as_bytes())?;
        schema::meta_set(&tx, META_CURSOR_SECRET, &secret)?;
        schema::meta_set(&tx, META_PRIVACY_CHAIN_KEY, &chain_key)?;
        schema::meta_set(&tx, META_GOVERNANCE_SCOPE_KEY, &governance_key)?;
        schema::meta_set(&tx, META_REALM_OBJECT_KEY, &realm_object_key)?;
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
        self.command_transaction_guarded(scope, now, hooks, |_| Ok(()), apply)
    }

    /// The §12.2 command transaction with an **operation-specific replay
    /// authorizer** (§11.2 replay reauthorization, KV-R1).
    ///
    /// Stored result bytes are released ONLY after `replay_authorizer`
    /// re-checks this operation's current resources and dependency set
    /// inside the same transaction. A stale worker attempt, a completed
    /// attempt, or an advanced fence therefore receives its typed
    /// problem — never its old receipt, and never a re-execution.
    ///
    /// ```
    /// # use kovee_store::*;
    /// # use kovee_core::problem::{Problem, ProblemKind};
    /// let mut store = Store::open_in_memory().unwrap();
    /// store.bootstrap(0).unwrap();
    /// let scope = CommandScope {
    ///     actor_scope: "worker/inv-1/realm-personal".into(),
    ///     operation: "contribution_append".into(),
    ///     idempotency_key: "k".into(),
    ///     request_digest: "d".repeat(64),
    /// };
    /// store.command_transaction(&scope, 0, CrashHooks::NONE, |_| Ok(Applied {
    ///     result: serde_json::json!({"ok": true}), revision: Some(1), event_cursor: None,
    /// })).unwrap();
    /// // The lease is gone: the replay is refused, not served.
    /// let err = store.command_transaction_guarded(&scope, 0, CrashHooks::NONE,
    ///     |_| Err(Problem::new(ProblemKind::StaleLease, "attempt binding is not current")),
    ///     |_| unreachable!("a refused replay never re-executes")).unwrap_err();
    /// assert!(matches!(err, CommandError::Problem(p) if p.kind == ProblemKind::StaleLease));
    /// ```
    pub fn command_transaction_guarded(
        &mut self,
        scope: &CommandScope,
        now: i64,
        hooks: CrashHooks,
        replay_authorizer: impl FnOnce(&Connection) -> Result<(), Problem>,
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
                // §11.2 replay reauthorization (KV-R1): the
                // operation-specific authorizer re-checks the current
                // resource and dependency set BEFORE any stored byte is
                // released. Channel authentication (§12.2 step 1) has
                // already happened; this is the per-operation half.
                if let Err(problem) = replay_authorizer(&tx) {
                    tx.rollback()?;
                    return Err(CommandError::Problem(problem));
                }
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
        // KV-C2: the §11.8 result bounds are judged INSIDE the
        // transaction. An over-cap result rolls the whole command back,
        // so a committed receipt can never be permanently unobtainable
        // (previously state/events/outbox/idempotency committed and every
        // reply — original and replay — was `internal`).
        let bounds = check_result_bounds(&applied.result);
        let result = kovee_core::envelope::CommandResult::Ok {
            result: applied.result,
            revision: applied.revision,
            event_cursor: applied.event_cursor.clone(),
        };
        let bytes = serde_json::to_vec(&result).map_err(StoreError::from)?;
        let bounds = bounds.and_then(|()| {
            if bytes.len() > kovee_core::limits::REPLY_MAX_BYTES {
                Err(over_cap(format!(
                    "the serialized result is {} bytes; the §11.8 reply cap is {}",
                    bytes.len(),
                    kovee_core::limits::REPLY_MAX_BYTES
                )))
            } else {
                Ok(())
            }
        });
        if let Err(problem) = bounds {
            tx.rollback()?;
            return Err(CommandError::Problem(problem));
        }
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
        self.mint_token(&Token {
            source: project_id.to_owned(),
            seq,
            boundary: None,
            key: None,
        })
    }

    /// Verifies and decodes a cursor minted by [`Store::mint_project_cursor`]
    /// for the same project. Possession of a cursor grants nothing —
    /// authorization is rechecked at read time (§11.4).
    pub fn parse_project_cursor(&self, cursor: &str, project_id: &str) -> Result<u64, Problem> {
        Ok(self.parse_token(cursor, project_id)?.seq)
    }

    /// Mints an opaque authenticated token (§11.3/§11.5): pagination
    /// cursors and snapshot tokens share this construction. The token
    /// binds its source (owner + query identity), boundary, and last key;
    /// it grants nothing — authorization is rechecked on every page.
    pub fn mint_token(&self, token: &Token) -> Result<String, StoreError> {
        mint_token(&self.cursor_secret()?, token)
    }

    /// Verifies and decodes a token for the exact expected source. A
    /// token minted for another source, query, or installation is
    /// indistinguishably `invalid`.
    pub fn parse_token(&self, raw: &str, expected_source: &str) -> Result<Token, Problem> {
        let fail = || {
            Problem::new(ProblemKind::Invalid, "invalid cursor")
                .with_detail("not a cursor this installation minted for this source")
        };
        let mut parts = raw.split('.');
        let (Some("kc1"), Some(body), Some(tag), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(fail());
        };
        let bytes = unhex(body).ok_or_else(fail)?;
        let tag = unhex(tag).ok_or_else(fail)?;
        let secret = self.cursor_secret().map_err(|_| fail())?;
        if kovee_core::family::hmac_sha256(&secret, &bytes).as_slice() != tag.as_slice() {
            return Err(fail());
        }
        let payload: Value = serde_json::from_slice(&bytes).map_err(|_| fail())?;
        if payload["source"].as_str() != Some(expected_source) {
            return Err(fail());
        }
        Ok(Token {
            source: expected_source.to_owned(),
            seq: payload["seq"].as_u64().ok_or_else(fail)?,
            boundary: payload["b"].as_u64(),
            key: payload["k"].as_str().map(str::to_owned),
        })
    }

    fn cursor_secret(&self) -> Result<Vec<u8>, StoreError> {
        schema::meta_get(&self.conn, META_CURSOR_SECRET)?
            .ok_or_else(|| StoreError::Corrupt("store is not bootstrapped".to_owned()))
    }

    /// The privacy-access chain key (PROFILE §7 scope key).
    pub fn privacy_chain_key(&self) -> Result<Vec<u8>, StoreError> {
        schema::meta_get(&self.conn, META_PRIVACY_CHAIN_KEY)?
            .ok_or_else(|| StoreError::Corrupt("store is not bootstrapped".to_owned()))
    }

    /// The governed-work digest scope key (PROFILE §6 scope key): every
    /// `KoveeRealmByomBinding` / `KoveeSocietyMapping` /
    /// `KoveeGovernanceOwnerBinding` / `DelegatedPrincipalCredential`
    /// digest is an HMAC under this one key.
    pub fn governance_scope_key(&self) -> Result<Vec<u8>, StoreError> {
        schema::meta_get(&self.conn, META_GOVERNANCE_SCOPE_KEY)?
            .ok_or_else(|| StoreError::Corrupt("store is not bootstrapped".to_owned()))
    }

    /// The realm (Society) key that wraps per-object erasure secrets
    /// (D-R1-2). Never a digest key: destroying it would only make
    /// wrapped secrets unopenable, and no object's digest derives from
    /// it.
    pub fn realm_object_key(&self) -> Result<Vec<u8>, StoreError> {
        realm_object_key_of(&self.conn)
    }

    /// Rewrites the file so pages freed by an erasure carry no residue:
    /// checkpoint the WAL away, VACUUM the main file, checkpoint again.
    /// `secure_delete` already zeroes freed cells; this closes the
    /// file-level residue (old page images in the WAL, free pages) that
    /// a byte-level grep would otherwise still find.
    pub fn compact_after_erasure(&self) -> Result<(), StoreError> {
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .optional()?;
        self.conn.execute_batch("VACUUM")?;
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .optional()?;
        self.conn.execute(
            "DELETE FROM meta WHERE key = ?1",
            [META_ERASURE_COMPACTION_PENDING],
        )?;
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .optional()?;
        Ok(())
    }

    /// Looks up a stored idempotency record outside a command transaction
    /// (§10.10 artifact finalization pre-checks its key before its
    /// non-atomic seal pipeline). Returns `(request_digest, result)`.
    pub fn lookup_idempotency(
        &self,
        scope: &CommandScope,
    ) -> Result<Option<(String, Vec<u8>)>, StoreError> {
        self.conn
            .query_row(
                "SELECT request_digest, result FROM idempotency_records
                 WHERE actor_scope = ?1 AND operation = ?2 AND idempotency_key = ?3",
                params![scope.actor_scope, scope.operation, scope.idempotency_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(StoreError::from)
    }
}

/// The governed-work digest scope key read from an OPEN transaction (the
/// saga derives its digests inside the command transaction, so it cannot
/// go through `&Store`).
pub fn governance_scope_key_of(conn: &Connection) -> Result<Vec<u8>, StoreError> {
    schema::meta_get(conn, META_GOVERNANCE_SCOPE_KEY)?
        .ok_or_else(|| StoreError::Corrupt("store is not bootstrapped".to_owned()))
}

/// The realm object-wrapping key read from an OPEN transaction (objects
/// are minted and erased inside command transactions).
pub fn realm_object_key_of(conn: &Connection) -> Result<Vec<u8>, StoreError> {
    schema::meta_get(conn, META_REALM_OBJECT_KEY)?
        .ok_or_else(|| StoreError::Corrupt("store is not bootstrapped".to_owned()))
}

/// Marks, inside an open erasure transaction, that the file still holds
/// freed plaintext pages. [`Store::compact_after_erasure`] clears it.
pub fn mark_erasure_compaction_pending(conn: &Connection) -> Result<(), StoreError> {
    schema::meta_set(conn, META_ERASURE_COMPACTION_PENDING, b"1")?;
    Ok(())
}

/// The §11.7 problem an over-cap result raises inside the transaction.
fn over_cap(detail: String) -> Problem {
    Problem::new(
        ProblemKind::Invalid,
        "the result exceeds the §11.8 reply bounds",
    )
    .with_detail(detail)
}

/// §11.8 result bounds checked before the idempotency record is written:
/// no array in the result may exceed [`kovee_core::limits::LIST_MAX_ITEMS`].
/// An unbounded accumulation (policy-change preparation's frontier list,
/// repeated frontier pins) fails the command instead of committing a
/// receipt nobody can ever read back.
fn check_result_bounds(result: &Value) -> Result<(), Problem> {
    fn walk(value: &Value, path: &str) -> Result<(), Problem> {
        match value {
            Value::Array(items) => {
                if items.len() > kovee_core::limits::LIST_MAX_ITEMS {
                    return Err(over_cap(format!(
                        "result member {path} carries {} items; the §11.8 list cap is {}",
                        items.len(),
                        kovee_core::limits::LIST_MAX_ITEMS
                    )));
                }
                for (i, item) in items.iter().enumerate() {
                    walk(item, &format!("{path}[{i}]"))?;
                }
                Ok(())
            }
            Value::Object(map) => {
                for (key, item) in map {
                    walk(item, &format!("{path}.{key}"))?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    walk(result, "result")
}

/// The decoded payload of an opaque authenticated cursor/snapshot token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Source binding: owner id plus (for list tokens) the query
    /// identity, e.g. `snap:space_list:proj-1`.
    pub source: String,
    /// The position or as-of boundary in the source's own sequence.
    pub seq: u64,
    /// The project-event boundary observed when the snapshot was created.
    pub boundary: Option<u64>,
    /// The exclusive last key already returned (keyed pagination).
    pub key: Option<String>,
}

fn mint_token(secret: &[u8], token: &Token) -> Result<String, StoreError> {
    let mut payload = serde_json::Map::new();
    payload.insert("v".into(), Value::from(1));
    payload.insert("source".into(), Value::String(token.source.clone()));
    payload.insert("seq".into(), Value::from(token.seq));
    payload.insert("epoch".into(), Value::from(1));
    if let Some(b) = token.boundary {
        payload.insert("b".into(), Value::from(b));
    }
    if let Some(k) = &token.key {
        payload.insert("k".into(), Value::String(k.clone()));
    }
    let bytes = serde_json::to_vec(&Value::Object(payload))?;
    let tag = kovee_core::family::hmac_sha256(secret, &bytes);
    Ok(format!("kc1.{}.{}", hex(&bytes), hex(&tag)))
}

/// A fresh prefixed id: 16 bytes of OS entropy as hex.
pub fn new_id(prefix: &str) -> Result<String, StoreError> {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes)?;
    Ok(format!("{prefix}-{}", hex(&bytes)))
}

pub(crate) fn fill_random(out: &mut [u8]) -> Result<(), StoreError> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_case_two() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        let mac = kovee_core::family::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
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
    fn an_over_cap_result_commits_nothing_at_all() {
        // KV-C2: the bound is judged inside the transaction, so the
        // over-cap command leaves no event, no outbox row, and — the
        // point — no idempotency record whose stored bytes every replay
        // would have to answer with `internal`.
        let mut store = Store::open_in_memory().unwrap();
        store.bootstrap(0).unwrap();
        let scope = CommandScope {
            actor_scope: "s".into(),
            operation: "project_access_policy_change_prepare".into(),
            idempotency_key: "k".into(),
            request_digest: "a".repeat(64),
        };
        let oversized: Vec<Value> = (0..kovee_core::limits::LIST_MAX_ITEMS + 1)
            .map(|i| Value::from(format!("front-{i}")))
            .collect();
        let err = store
            .command_transaction(&scope, 0, CrashHooks::NONE, |txn| {
                txn.enqueue_outbox("d-1", "event", &serde_json::json!({}))
                    .map_err(|_| Problem::new(ProblemKind::Internal, "outbox"))?;
                Ok(Applied {
                    result: serde_json::json!({"affected": oversized}),
                    revision: Some(1),
                    event_cursor: None,
                })
            })
            .unwrap_err();
        match err {
            CommandError::Problem(p) => {
                assert_eq!(p.kind, ProblemKind::Invalid);
                assert!(p.detail.unwrap_or_default().contains("affected"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let (outbox, idem): (i64, i64) = (
            store
                .conn()
                .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))
                .unwrap(),
            store
                .conn()
                .query_row("SELECT COUNT(*) FROM idempotency_records", [], |r| r.get(0))
                .unwrap(),
        );
        assert_eq!((outbox, idem), (0, 0), "no receipt may be left behind");
        // And the same key is still free: the caller can narrow and retry.
        store
            .command_transaction(&scope, 0, CrashHooks::NONE, |_| {
                Ok(Applied {
                    result: serde_json::json!({"affected": ["front-0"]}),
                    revision: Some(1),
                    event_cursor: None,
                })
            })
            .unwrap();
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
