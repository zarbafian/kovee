//! Append-only, hash-linked, body-free audit log (akson §15.3 style).
//!
//! Each record hash-links to its predecessor, so accidental or
//! out-of-domain modification is locally tamper-evident — integrity
//! evidence within one security domain, not protection against a same-UID
//! attacker. `event` is a low-cardinality type and `detail` carries
//! digests and identifiers, never bodies, prompts, paths, or secrets.
//! Audit insertion shares the command transaction (§12.2 step 7), so
//! there is no unrecorded committed command.
//!
//! `hash = SHA-256(prev_hash ‖ seq ‖ ts ‖ len(event) ‖ event ‖
//! len(detail) ‖ detail)`, lengths big-endian u64; genesis `prev_hash` is
//! 32 zero bytes.

use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// The genesis predecessor hash (before the first record).
pub const GENESIS: [u8; 32] = [0u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error("audit chain broken at seq {seq}")]
    Broken { seq: i64 },
}

fn record_hash(prev: &[u8], seq: i64, ts: i64, event: &str, detail: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(seq.to_be_bytes());
    h.update(ts.to_be_bytes());
    h.update((event.len() as u64).to_be_bytes());
    h.update(event.as_bytes());
    h.update((detail.len() as u64).to_be_bytes());
    h.update(detail.as_bytes());
    h.finalize().into()
}

fn head(conn: &Connection) -> rusqlite::Result<[u8; 32]> {
    use rusqlite::OptionalExtension as _;
    let row: Option<Vec<u8>> = conn
        .query_row(
            "SELECT hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(row.and_then(|b| b.try_into().ok()).unwrap_or(GENESIS))
}

/// Appends one record, linking it to the current head. Returns its `seq`.
/// Call inside the same transaction as the effect being recorded.
pub fn append(conn: &Connection, ts: i64, event: &str, detail: &str) -> rusqlite::Result<i64> {
    let prev = head(conn)?;
    let next_seq: i64 = conn.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM audit", [], |r| {
        r.get(0)
    })?;
    let hash = record_hash(&prev, next_seq, ts, event, detail);
    conn.execute(
        "INSERT INTO audit (seq, ts, event, detail, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            next_seq,
            ts,
            event,
            detail,
            prev.as_slice(),
            hash.as_slice()
        ],
    )?;
    Ok(next_seq)
}

/// Walks the chain from genesis and confirms every link and hash.
/// Returns the number of records verified.
pub fn verify_chain(conn: &Connection) -> Result<u64, AuditError> {
    let mut stmt =
        conn.prepare("SELECT seq, ts, event, detail, prev_hash, hash FROM audit ORDER BY seq ASC")?;
    let mut rows = stmt.query([])?;
    let mut prev = GENESIS;
    let mut count = 0u64;
    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let ts: i64 = row.get(1)?;
        let event: String = row.get(2)?;
        let detail: String = row.get(3)?;
        let stored_prev: Vec<u8> = row.get(4)?;
        let stored_hash: Vec<u8> = row.get(5)?;
        let expected = record_hash(&prev, seq, ts, &event, &detail);
        if stored_prev != prev || stored_hash != expected {
            return Err(AuditError::Broken { seq });
        }
        prev = expected;
        count += 1;
    }
    Ok(count)
}
