//! How a broker record's digest is keyed — and why the choice is not
//! cosmetic.
//!
//! The family profile fixes two classes for the digests the model broker
//! produces, and byom's runtime schemas demand a specific one per field:
//!
//! - [`RecordDigestKey::Portable`] → `portable_public`, an UNKEYED SHA-256.
//!   The CROSS-BOUNDARY class: byom must be able to recompute it, which is
//!   what turns "the request field can only match the server value" into a
//!   machine check. Used for the byom source fragment.
//! - [`RecordDigestKey::Object`] → `local_erasure_safe`, an HMAC under a
//!   RANDOM per-object secret (D-R1-2). Used for records that are **Kovee's
//!   own objects** — the disclosure manifest, the provider-context chain,
//!   the local effect. byom holds only their refs and digests, so it could
//!   not recompute them anyway; and destroying one object's secret erases
//!   exactly that object's verifiability and nothing else.
//!
//! Using the wrong one is a conformance failure, not a preference: byomd
//! answers `digest_class_mismatch`.
//!
//! What you write:
//! ```
//! use kovee_effects::{record_digest, RecordDigestKey};
//! let projection = serde_json::json!({"a": 1});
//! let portable = record_digest("kovee-doc-v1", &projection,
//!                              RecordDigestKey::Portable).unwrap();
//! assert_eq!(portable.class, "portable_public");
//! let secret = [7u8; 32];
//! let keyed = record_digest("kovee-doc-v1", &projection,
//!     RecordDigestKey::Object { key_ref: "kovee-effect-object:meff-1", secret: &secret }).unwrap();
//! assert_eq!(keyed.class, "local_erasure_safe");
//! assert_ne!(portable.value_hex, keyed.value_hex);
//! ```

use serde_json::Value;

use kovee_core::family::{hex, hmac_sha256, sha256_hex, tagged_canonical, DigestRef};

/// Which family class a record's digest takes, and the key material when it
/// is a keyed one. Copy-cheap and borrowed: the secret is never owned here.
#[derive(Debug, Clone, Copy)]
pub enum RecordDigestKey<'a> {
    /// Unkeyed SHA-256, `portable_public`.
    Portable,
    /// HMAC-SHA-256 under a random per-object secret, `local_erasure_safe`.
    Object {
        key_ref: &'a str,
        secret: &'a [u8; 32],
    },
}

impl RecordDigestKey<'_> {
    pub fn class(&self) -> &'static str {
        match self {
            RecordDigestKey::Portable => "portable_public",
            RecordDigestKey::Object { .. } => "local_erasure_safe",
        }
    }
}

/// The digest over `tagged_canonical(tag, projection)` in the requested
/// class. `None` when the projection is not canonicalizable (a non-object,
/// or one already carrying the reserved `$domain` member) — fail-closed.
pub fn record_digest(tag: &str, projection: &Value, key: RecordDigestKey<'_>) -> Option<DigestRef> {
    let preimage = tagged_canonical(tag, projection).ok()?;
    Some(match key {
        RecordDigestKey::Portable => DigestRef::portable_public(sha256_hex(&preimage)),
        RecordDigestKey::Object { key_ref, secret } => {
            DigestRef::local_erasure_safe(key_ref, hex(&hmac_sha256(secret, &preimage)))
        }
    })
}

/// The `key_ref` convention for one Kovee broker object: the object kind and
/// its exact id, so an operator reading a digest can tell which secret's
/// destruction would erase it.
pub fn object_key_ref(kind: &str, object_id: &str) -> String {
    format!("kovee-{kind}-object:{object_id}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_two_classes_are_distinct_and_correctly_labelled() {
        let projection = json!({"disclosure_id": "disc-1", "total_bytes": 42});
        let portable = record_digest("kovee-t-v1", &projection, RecordDigestKey::Portable).unwrap();
        assert_eq!(portable.class, "portable_public");
        assert_eq!(portable.algorithm, "sha-256");
        assert!(portable.key_ref.is_none());

        let secret = [9u8; 32];
        let keyed = record_digest(
            "kovee-t-v1",
            &projection,
            RecordDigestKey::Object {
                key_ref: "kovee-disclosure-object:disc-1",
                secret: &secret,
            },
        )
        .unwrap();
        assert_eq!(keyed.class, "local_erasure_safe");
        assert_eq!(keyed.algorithm, "hmac-sha-256");
        assert_eq!(
            keyed.key_ref.as_deref(),
            Some("kovee-disclosure-object:disc-1")
        );
        assert_ne!(portable.value_hex, keyed.value_hex);
    }

    #[test]
    fn a_different_secret_is_a_different_digest_and_erasure_is_per_object() {
        let projection = json!({"a": 1});
        let one = record_digest(
            "kovee-t-v1",
            &projection,
            RecordDigestKey::Object {
                key_ref: "k",
                secret: &[1u8; 32],
            },
        )
        .unwrap();
        let two = record_digest(
            "kovee-t-v1",
            &projection,
            RecordDigestKey::Object {
                key_ref: "k",
                secret: &[2u8; 32],
            },
        )
        .unwrap();
        assert_ne!(one.value_hex, two.value_hex);
    }

    #[test]
    fn a_non_object_projection_fails_closed() {
        assert!(record_digest("kovee-t-v1", &json!([1, 2]), RecordDigestKey::Portable).is_none());
        // And one already carrying the reserved member.
        assert!(record_digest(
            "kovee-t-v1",
            &json!({"$domain": "sneaky"}),
            RecordDigestKey::Portable
        )
        .is_none());
    }

    #[test]
    fn the_key_ref_names_the_object_whose_secret_keys_it() {
        assert_eq!(
            object_key_ref("model-effect", "meff-1"),
            "kovee-model-effect-object:meff-1"
        );
    }
}
