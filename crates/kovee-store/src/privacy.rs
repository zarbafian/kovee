//! The internal, developer-labeled PrivacyAccessRecord chain (family
//! PROFILE §7, D-R0-1): allowed AND denied sensitive reads both append a
//! chained record before any sensitive bytes are released. Records carry
//! actor, operation, purpose, canonical query digest, result cardinality
//! and bytes, and outcome — never result plaintext.
//!
//! Honesty labels: this is integrity evidence inside one same-UID
//! security domain (developer assurance profile), not protection against
//! the owner; the chain key is a per-chain scope key, so its digests are
//! class `scope_erasure_safe` — destroying the key erases verifiability
//! of the entire chain, never one record.
//!
//! What you write (the daemon's side of one sensitive read):
//! ```
//! use kovee_store::{privacy, Store};
//! let mut store = Store::open_in_memory().unwrap();
//! store.bootstrap(0).unwrap();
//! let seq = privacy::append_record(&mut store, &privacy::Access {
//!     operation: "contribution_show".into(),
//!     purpose_ref: "purpose-owner-read".into(),
//!     actor_scope: "external_client/prin-owner/realm-personal".into(),
//!     query: serde_json::json!({"contribution_id": "contrib-1"}),
//!     result_object_count: 1,
//!     result_bytes: 42,
//!     outcome: privacy::Outcome::Allowed,
//! }, 0).unwrap();
//! assert_eq!(seq, 1);
//! assert_eq!(privacy::verify_chain(&store).unwrap(), 1);
//! ```

use kovee_core::canonical::canonical_object_digest;
use kovee_core::family::{privacy_chain_link, privacy_record_digest, DigestRef};
use kovee_core::time::rfc3339_utc;
use rusqlite::{params, OptionalExtension as _};
use serde_json::Value;

use crate::{Store, StoreError, PERSONAL_REALM_ID};

/// The classification ref that marks an object as sensitive for the K1
/// developer profile: reads of such objects chain a privacy record.
pub const SENSITIVE_CLASSIFICATION: &str = "class-sensitive";

/// The chain `key_ref` recorded in every DigestRef of this installation's
/// chain.
pub fn chain_key_ref() -> String {
    format!("kovee-privacy-chain:{PERSONAL_REALM_ID}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allowed,
    Denied,
    Error,
}

impl Outcome {
    fn token(self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Denied => "denied",
            Outcome::Error => "error",
        }
    }
}

/// One sensitive access to record.
pub struct Access {
    pub operation: String,
    pub purpose_ref: String,
    /// The authenticated actor scope; only its digest enters the record.
    pub actor_scope: String,
    /// The exact query arguments; only their canonical digest enters the
    /// record (never payload bytes).
    pub query: Value,
    pub result_object_count: u64,
    pub result_bytes: u64,
    pub outcome: Outcome,
}

/// Appends one chained record in its own committed transaction and
/// returns its dense `internal_access_sequence`. The caller must commit
/// this BEFORE releasing sensitive bytes (PROFILE §7 release rule:
/// unlogged bytes are never served).
pub fn append_record(store: &mut Store, access: &Access, now: i64) -> Result<u64, StoreError> {
    let chain_key = store.privacy_chain_key()?;
    let installation_id = store.installation_id()?;
    let key_ref = chain_key_ref();
    let tx = store.conn.transaction()?;

    let previous: Option<(i64, String)> = tx
        .query_row(
            "SELECT internal_access_sequence, record FROM privacy_access_records
             ORDER BY internal_access_sequence DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (sequence, previous_digest) = match &previous {
        None => (1i64, None),
        Some((seq, record_text)) => {
            let record: Value = serde_json::from_str(record_text)?;
            let digest: DigestRef = serde_json::from_value(record["record_digest"].clone())
                .map_err(|_| StoreError::Corrupt("privacy record without digest".to_owned()))?;
            (seq + 1, Some(digest))
        }
    };

    let (_, actor_binding_digest) = canonical_object_digest(
        "kovee-actor-binding",
        "schema:kovee-actor-binding-v1",
        &Value::String(access.actor_scope.clone()),
    )?;
    let (_, query_digest) = canonical_object_digest(
        "kovee-privacy-query",
        "schema:kovee-privacy-query-v1",
        &access.query,
    )?;
    let (_, dependency_digest) = canonical_object_digest(
        "kovee-authz-dependency-set",
        "schema:kovee-authz-dependency-set-v1",
        &serde_json::json!({
            "surface_actor": access.actor_scope,
            "realm": PERSONAL_REALM_ID,
            "assurance": "developer",
        }),
    )?;

    // The exact PROFILE §7 preimage member set; `previous_access_digest`
    // is wholly absent at genesis (never a null-valued pseudo-ref).
    let mut record = serde_json::Map::new();
    record.insert("society_id".into(), Value::String(PERSONAL_REALM_ID.into()));
    record.insert("internal_access_sequence".into(), Value::from(sequence));
    let access_event_id = crate::new_id("acc")?;
    record.insert("access_event_id".into(), Value::String(access_event_id));
    record.insert(
        "endpoint_incarnation".into(),
        Value::String(installation_id),
    );
    record.insert("recovery_epoch".into(), Value::from(0));
    record.insert(
        "actor_binding_digest".into(),
        Value::String(actor_binding_digest),
    );
    record.insert("operation".into(), Value::String(access.operation.clone()));
    record.insert(
        "purpose_ref".into(),
        Value::String(access.purpose_ref.clone()),
    );
    record.insert("query_or_scope_digest".into(), Value::String(query_digest));
    record.insert(
        "result_object_count".into(),
        Value::from(access.result_object_count),
    );
    record.insert("result_bytes".into(), Value::from(access.result_bytes));
    record.insert(
        "outcome".into(),
        Value::String(access.outcome.token().to_owned()),
    );
    record.insert("dependency_digest".into(), Value::String(dependency_digest));
    record.insert("occurred_at".into(), Value::String(rfc3339_utc(now)));
    if let Some(prev) = &previous_digest {
        record.insert(
            "previous_access_digest".into(),
            serde_json::to_value(privacy_chain_link(prev))?,
        );
    }

    let preimage_record = Value::Object(record.clone());
    let digest = privacy_record_digest(&chain_key, &key_ref, &preimage_record)
        .map_err(|e| StoreError::Corrupt(format!("privacy record digest: {e}")))?;
    let value_hex = digest.value_hex.clone();
    record.insert("record_digest".into(), serde_json::to_value(digest)?);

    tx.execute(
        "INSERT INTO privacy_access_records
             (internal_access_sequence, record, record_digest_hex, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            sequence,
            serde_json::to_string(&Value::Object(record))?,
            value_hex,
            now
        ],
    )?;
    tx.commit()?;
    Ok(sequence as u64)
}

/// Re-derives every record digest and chain link from genesis; returns
/// the number of records verified.
pub fn verify_chain(store: &Store) -> Result<u64, StoreError> {
    let chain_key = store.privacy_chain_key()?;
    let key_ref = chain_key_ref();
    let mut stmt = store.conn.prepare(
        "SELECT internal_access_sequence, record, record_digest_hex
         FROM privacy_access_records ORDER BY internal_access_sequence ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut count = 0u64;
    let mut previous: Option<DigestRef> = None;
    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let record_text: String = row.get(1)?;
        let stored_hex: String = row.get(2)?;
        let mut record: Value = serde_json::from_str(&record_text)?;
        let broken = |detail: &str| StoreError::Corrupt(format!("privacy chain @{seq}: {detail}"));
        let stored: DigestRef = serde_json::from_value(
            record
                .as_object_mut()
                .ok_or_else(|| broken("not an object"))?
                .remove("record_digest")
                .ok_or_else(|| broken("record_digest missing"))?,
        )
        .map_err(|_| broken("record_digest malformed"))?;
        if stored.value_hex != stored_hex {
            return Err(broken("digest column mismatch"));
        }
        match (&previous, record.get("previous_access_digest")) {
            (None, None) => {}
            (Some(prev), Some(link_value)) => {
                let link: DigestRef = serde_json::from_value(link_value.clone())
                    .map_err(|_| broken("chain link malformed"))?;
                if link != privacy_chain_link(prev) {
                    return Err(broken("chain link mismatch"));
                }
            }
            _ => return Err(broken("chain link presence mismatch")),
        }
        let rederived = privacy_record_digest(&chain_key, &key_ref, &record)
            .map_err(|e| broken(&format!("preimage: {e}")))?;
        if rederived != stored {
            return Err(broken("record digest mismatch"));
        }
        previous = Some(stored);
        count += 1;
    }
    Ok(count)
}
