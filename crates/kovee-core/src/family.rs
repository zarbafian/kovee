//! The C1 family digest constructions kovee consumes (byom-hosted
//! PROFILE, pinned by the lock manifest): typed [`DigestRef`]s, the
//! `$domain` type-tag canonicalization, HMAC-SHA-256, and the
//! PrivacyAccessRecord chain of PROFILE §7 (D-R0-1).
//!
//! What you write (one chained privacy record):
//! ```
//! use kovee_core::family::{privacy_record_digest, DigestRef};
//! let record = serde_json::json!({
//!     "society_id": "realm-personal", "internal_access_sequence": 1,
//!     "access_event_id": "acc-1", "endpoint_incarnation": "inst-1",
//!     "recovery_epoch": 0, "actor_binding_digest": "a".repeat(64),
//!     "operation": "contribution_show", "purpose_ref": "purpose-read",
//!     "query_or_scope_digest": "b".repeat(64),
//!     "result_object_count": 1, "result_bytes": 42,
//!     "outcome": "allowed", "dependency_digest": "c".repeat(64),
//!     "occurred_at": "2026-07-26T00:00:00Z",
//! });
//! let key = [7u8; 32];
//! let digest: DigestRef =
//!     privacy_record_digest(&key, "kovee-privacy-chain:realm-personal", &record).unwrap();
//! assert_eq!(digest.class, "scope_erasure_safe");
//! assert_eq!(digest.value_hex.len(), 64);
//! ```
//!
//! Class semantics (PROFILE §6, D-R0-1): `scope_erasure_safe` is an HMAC
//! under a protected per-scope key — destroying the chain key erases
//! verifiability of the entire chain, never one record.
//! `local_erasure_safe` is an HMAC under a random per-object secret —
//! destroying that secret erases exactly that object's verifiability
//! (amendment A5: artifact content addressing for erasable plaintext).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::canonical::{jcs, CanonicalError};

/// The byom type tag of the privacy-record preimage (PROFILE §7).
pub const PRIVACY_RECORD_TAG: &str = "bpp-privacy-access-record-v1";

/// A typed family digest, never an unlabelled hash (PROFILE §6.1). The
/// wire shape is closed: exactly `class`, `algorithm`, `value_hex`, plus
/// `key_ref` for the keyed erasure classes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestRef {
    pub class: String,
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_ref: Option<String>,
    pub value_hex: String,
}

impl DigestRef {
    /// A `scope_erasure_safe` ref (per-scope HMAC key; PROFILE §6.1).
    pub fn scope_erasure_safe(key_ref: &str, value_hex: String) -> DigestRef {
        DigestRef {
            class: "scope_erasure_safe".to_owned(),
            algorithm: "hmac-sha-256".to_owned(),
            key_ref: Some(key_ref.to_owned()),
            value_hex,
        }
    }

    /// A `local_erasure_safe` ref (random per-object secret; PROFILE
    /// §6.1, amendment A5 content addressing for erasable plaintext).
    pub fn local_erasure_safe(key_ref: &str, value_hex: String) -> DigestRef {
        DigestRef {
            class: "local_erasure_safe".to_owned(),
            algorithm: "hmac-sha-256".to_owned(),
            key_ref: Some(key_ref.to_owned()),
            value_hex,
        }
    }
}

/// Byom type-tagged canonical bytes (PROFILE §2): inject the reserved
/// `$domain` member at the top level, then JCS. An object already
/// carrying `$domain` fails closed.
pub fn tagged_canonical(tag: &str, object: &Value) -> Result<Vec<u8>, CanonicalError> {
    let Value::Object(map) = object else {
        // Only objects are type-tagged (PROFILE §2).
        return Err(CanonicalError::NonFinite);
    };
    if map.contains_key("$domain") {
        return Err(CanonicalError::NonFinite);
    }
    let mut tagged = map.clone();
    tagged.insert("$domain".to_owned(), Value::String(tag.to_owned()));
    jcs(&Value::Object(tagged))
}

/// HMAC-SHA-256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
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

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The exact PROFILE §7 preimage member list, all required. The record's
/// own `record_digest` is EXCLUDED from the preimage; the chain link
/// `previous_access_digest` is a member when present and wholly absent at
/// genesis.
pub const PRIVACY_PREIMAGE_MEMBERS: [&str; 14] = [
    "society_id",
    "internal_access_sequence",
    "access_event_id",
    "endpoint_incarnation",
    "recovery_epoch",
    "actor_binding_digest",
    "operation",
    "purpose_ref",
    "query_or_scope_digest",
    "result_object_count",
    "result_bytes",
    "outcome",
    "dependency_digest",
    "occurred_at",
];

#[derive(Debug, thiserror::Error)]
pub enum PrivacyRecordError {
    #[error("privacy_record_missing_{0}")]
    MissingMember(&'static str),
    #[error("privacy_record_preimage_carries_record_digest")]
    CarriesRecordDigest,
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

/// `record_digest` for a privacy access record (PROFILE §7): the
/// `scope_erasure_safe` HMAC over
/// `tagged("bpp-privacy-access-record-v1", record − record_digest)`.
/// `record` must carry every preimage member (plus
/// `previous_access_digest` after genesis) and must NOT carry its own
/// `record_digest`.
pub fn privacy_record_digest(
    chain_key: &[u8],
    key_ref: &str,
    record: &Value,
) -> Result<DigestRef, PrivacyRecordError> {
    let Value::Object(map) = record else {
        return Err(PrivacyRecordError::MissingMember("society_id"));
    };
    if map.contains_key("record_digest") {
        return Err(PrivacyRecordError::CarriesRecordDigest);
    }
    for member in PRIVACY_PREIMAGE_MEMBERS {
        if !map.contains_key(member) {
            return Err(PrivacyRecordError::MissingMember(member));
        }
    }
    let preimage = tagged_canonical(PRIVACY_RECORD_TAG, record)?;
    let mac = hmac_sha256(chain_key, &preimage);
    Ok(DigestRef::scope_erasure_safe(key_ref, hex(&mac)))
}

/// The chain link derived from the previous record's digest (PROFILE §7):
/// same class and key ref, the previous `value_hex` carried forward.
pub fn privacy_chain_link(previous: &DigestRef) -> DigestRef {
    DigestRef::scope_erasure_safe(
        previous.key_ref.as_deref().unwrap_or_default(),
        previous.value_hex.clone(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn record() -> Value {
        serde_json::json!({
            "society_id": "realm-personal", "internal_access_sequence": 1,
            "access_event_id": "acc-1", "endpoint_incarnation": "inst-1",
            "recovery_epoch": 0, "actor_binding_digest": "a".repeat(64),
            "operation": "contribution_show", "purpose_ref": "purpose-read",
            "query_or_scope_digest": "b".repeat(64),
            "result_object_count": 1, "result_bytes": 42,
            "outcome": "allowed", "dependency_digest": "c".repeat(64),
            "occurred_at": "2026-07-26T00:00:00Z",
        })
    }

    #[test]
    fn tagged_canonical_leads_with_the_domain_tag() {
        let bytes = tagged_canonical("bpp-privacy-access-record-v1", &record()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("{\"$domain\":\"bpp-privacy-access-record-v1\""));
    }

    #[test]
    fn an_existing_domain_member_fails_closed() {
        let mut r = record();
        r["$domain"] = serde_json::json!("evil");
        assert!(tagged_canonical("t", &r).is_err());
    }

    #[test]
    fn a_missing_preimage_member_fails_closed() {
        let mut r = record();
        r.as_object_mut().unwrap().remove("dependency_digest");
        let err = privacy_record_digest(&[0u8; 32], "k", &r).unwrap_err();
        assert!(err.to_string().contains("privacy_record_missing_"));
    }

    #[test]
    fn a_preimage_carrying_record_digest_fails_closed() {
        let mut r = record();
        r["record_digest"] = serde_json::json!({});
        let err = privacy_record_digest(&[0u8; 32], "k", &r).unwrap_err();
        assert_eq!(
            err.to_string(),
            "privacy_record_preimage_carries_record_digest"
        );
    }

    #[test]
    fn record_digest_is_a_typed_scope_erasure_safe_ref() {
        let d = privacy_record_digest(&[1u8; 32], "kovee-privacy-chain:realm-personal", &record())
            .unwrap();
        assert_eq!(d.class, "scope_erasure_safe");
        assert_eq!(d.algorithm, "hmac-sha-256");
        assert_eq!(
            d.key_ref.as_deref(),
            Some("kovee-privacy-chain:realm-personal")
        );
        // Re-derive by hand: HMAC over the tagged canonical preimage.
        let preimage = tagged_canonical(PRIVACY_RECORD_TAG, &record()).unwrap();
        assert_eq!(d.value_hex, hex(&hmac_sha256(&[1u8; 32], &preimage)));
    }
}
