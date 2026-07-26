//! The §16.2 `DisclosureManifest` — what exactly leaves, to whom, under
//! which recorded provider claims.
//!
//! `provider_claims` is `{region, retention, training_use}` and is
//! **mandatory** for a model disclosure: the whole point of the record is
//! that a human authorizing egress saw those three answers. They are
//! recorded assertions the provider makes, not independently proven facts,
//! and [`ProviderClaims::is_complete`] refuses a blank.
//!
//! What you write:
//! ```
//! use kovee_effects::{DisclosureItem, DisclosureManifest, ProviderClaims, RecordDigestKey};
//! use kovee_core::family::DigestRef;
//! let secret = [7u8; 32];
//! let manifest = DisclosureManifest::model_egress(
//!     "disc-1", "realm-personal", Some("proj-1"), Some("space-1"),
//!     "model-profile:mp-anthropic-1", "purpose-review",
//!     &["collaboration_item"],
//!     vec![DisclosureItem {
//!         ref_: "contrib-1".into(), revision: Some(1),
//!         digest: DigestRef::portable_public("a".repeat(64)), size: 42,
//!     }],
//!     Vec::new(),
//!     ProviderClaims {
//!         region: "us".into(), retention: "zero-retention".into(),
//!         training_use: "prohibited".into(),
//!     },
//!     "2026-07-26T00:00:00Z",
//!     RecordDigestKey::Object { key_ref: "kovee-disclosure-object:disc-1", secret: &secret },
//! ).unwrap();
//! assert_eq!(manifest.total_bytes, 42);
//! assert!(manifest.provider_claims.is_complete());
//! // Kovee's own object: keyed, so destroying that one secret erases
//! // exactly this disclosure's verifiability (D-R1-2).
//! assert_eq!(manifest.digest.class, "local_erasure_safe");
//! ```

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use kovee_core::family::DigestRef;

use crate::keying::{record_digest, RecordDigestKey};

/// The byom type tag of a Kovee disclosure-manifest preimage.
pub const DISCLOSURE_TAG: &str = "kovee-disclosure-manifest-v1";

/// The recipient kind of a model disclosure (§16.2 `recipient_kind`).
pub const RECIPIENT_MODEL_PROVIDER: &str = "model_provider";

/// The recorded provider claims every model disclosure carries (§16.2).
/// Three answers, all required: where the bytes are processed, how long
/// the provider keeps them, and whether they may train on them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderClaims {
    /// The processing region the provider asserts (e.g. `us`, `eu`).
    pub region: String,
    /// The retention the provider asserts (e.g. `zero-retention`,
    /// `30-days`).
    pub retention: String,
    /// Whether the provider may train on the disclosed bytes (e.g.
    /// `prohibited`, `permitted`). Never defaulted: an absent answer is a
    /// refusal, not "probably fine".
    pub training_use: String,
}

impl ProviderClaims {
    /// Whether all three claims are present and non-blank. A manifest with
    /// an incomplete claim set cannot be built.
    pub fn is_complete(&self) -> bool {
        !self.region.trim().is_empty()
            && !self.retention.trim().is_empty()
            && !self.training_use.trim().is_empty()
    }
}

/// One exact item that leaves (§16.2 `exact_items[]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureItem {
    #[serde(rename = "ref")]
    pub ref_: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revision: Option<u64>,
    pub digest: DigestRef,
    pub size: u64,
}

/// One explicit transformation (§16.2 `transformations[]`). Calling
/// something "redacted" without a result digest is insufficient, so both
/// digests are required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transformation {
    pub kind: String,
    pub source_digest: DigestRef,
    pub result_digest: DigestRef,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DisclosureError {
    #[error("provider_claims is incomplete: region, retention and training_use are all required")]
    IncompleteClaims,
    #[error("a model disclosure names at least one exact item")]
    NoItems,
    #[error("purpose is required: authorization binds the final bytes for a stated purpose")]
    NoPurpose,
    #[error("data_classes is required: the classification of what leaves is not optional")]
    NoDataClasses,
    #[error("the disclosure manifest could not be canonicalized")]
    Uncanonical,
}

/// The §16.2 disclosure manifest, as the model broker records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureManifest {
    pub disclosure_id: String,
    pub sender_realm: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sender_project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sender_space: Option<String>,
    pub recipient_kind: String,
    /// The exact model profile the bytes leave through — never a broad
    /// vendor name (§16.2: "the authorization binds the final
    /// bytes/references that leave, not merely a broad topic name").
    pub recipient_binding: String,
    pub purpose: String,
    pub data_classes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context_assembly_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context_assembly_digest: Option<DigestRef>,
    pub exact_items: Vec<DisclosureItem>,
    pub transformations: Vec<Transformation>,
    pub provider_claims: ProviderClaims,
    pub total_bytes: u64,
    pub created_at: String,
    pub digest: DigestRef,
}

impl DisclosureManifest {
    /// Builds one model-egress disclosure manifest and its digest.
    ///
    /// The digest is over the canonical record WITHOUT the digest member, so
    /// a holder of the record and the key can re-derive it — which is what
    /// makes the byom permit's `disclosure_digest` a machine check rather
    /// than trust. The class comes from `key`: a model disclosure is
    /// **Kovee's own object**, so it is keyed `local_erasure_safe` under a
    /// random per-object secret (D-R1-2, and what byom's runtime schemas
    /// require), which also means destroying that one secret erases exactly
    /// this disclosure's verifiability.
    #[allow(clippy::too_many_arguments)]
    pub fn model_egress(
        disclosure_id: &str,
        sender_realm: &str,
        sender_project: Option<&str>,
        sender_space: Option<&str>,
        recipient_binding: &str,
        purpose: &str,
        data_classes: &[&str],
        exact_items: Vec<DisclosureItem>,
        transformations: Vec<Transformation>,
        provider_claims: ProviderClaims,
        created_at: &str,
        key: RecordDigestKey<'_>,
    ) -> Result<DisclosureManifest, DisclosureError> {
        if !provider_claims.is_complete() {
            return Err(DisclosureError::IncompleteClaims);
        }
        if exact_items.is_empty() {
            return Err(DisclosureError::NoItems);
        }
        if purpose.trim().is_empty() {
            return Err(DisclosureError::NoPurpose);
        }
        if data_classes.is_empty() {
            return Err(DisclosureError::NoDataClasses);
        }
        let total_bytes = exact_items.iter().map(|i| i.size).sum();
        let mut manifest = DisclosureManifest {
            disclosure_id: disclosure_id.to_owned(),
            sender_realm: sender_realm.to_owned(),
            sender_project: sender_project.map(str::to_owned),
            sender_space: sender_space.map(str::to_owned),
            recipient_kind: RECIPIENT_MODEL_PROVIDER.to_owned(),
            recipient_binding: recipient_binding.to_owned(),
            purpose: purpose.to_owned(),
            data_classes: data_classes.iter().map(|c| (*c).to_owned()).collect(),
            context_assembly_ref: None,
            context_assembly_digest: None,
            exact_items,
            transformations,
            provider_claims,
            total_bytes,
            created_at: created_at.to_owned(),
            digest: DigestRef::portable_public("0".repeat(64)),
        };
        manifest.digest = manifest.recompute_digest(key)?;
        Ok(manifest)
    }

    /// Binds the ContextAssembly the items were re-authorized from, then
    /// re-derives the digest.
    pub fn with_context_assembly(
        mut self,
        assembly_ref: &str,
        assembly_digest: DigestRef,
        key: RecordDigestKey<'_>,
    ) -> Result<DisclosureManifest, DisclosureError> {
        self.context_assembly_ref = Some(assembly_ref.to_owned());
        self.context_assembly_digest = Some(assembly_digest);
        self.digest = self.recompute_digest(key)?;
        Ok(self)
    }

    /// The canonical projection the digest is taken over (digest member
    /// excluded — a self-referential digest cannot be recomputed).
    pub fn projection(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        if let Some(map) = value.as_object_mut() {
            map.remove("digest");
        }
        value
    }

    fn recompute_digest(&self, key: RecordDigestKey<'_>) -> Result<DigestRef, DisclosureError> {
        record_digest(DISCLOSURE_TAG, &self.projection(), key).ok_or(DisclosureError::Uncanonical)
    }

    /// Re-derives the digest under `key` and compares: a tampered manifest,
    /// or one whose items changed after authorization, fails here.
    pub fn verify(&self, key: RecordDigestKey<'_>) -> Result<(), DisclosureError> {
        if self.recompute_digest(key)? == self.digest {
            Ok(())
        } else {
            Err(DisclosureError::Uncanonical)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn item(name: &str, size: u64) -> DisclosureItem {
        DisclosureItem {
            ref_: name.to_owned(),
            revision: Some(1),
            digest: DigestRef::portable_public("b".repeat(64)),
            size,
        }
    }

    fn claims() -> ProviderClaims {
        ProviderClaims {
            region: "us".to_owned(),
            retention: "zero-retention".to_owned(),
            training_use: "prohibited".to_owned(),
        }
    }

    const SECRET: [u8; 32] = [7u8; 32];

    fn key() -> RecordDigestKey<'static> {
        RecordDigestKey::Object {
            key_ref: "kovee-disclosure-object:disc-1",
            secret: &SECRET,
        }
    }

    fn build(
        items: Vec<DisclosureItem>,
        claims: ProviderClaims,
    ) -> Result<DisclosureManifest, DisclosureError> {
        DisclosureManifest::model_egress(
            "disc-1",
            "realm-personal",
            Some("proj-1"),
            Some("space-1"),
            "model-profile:mp-1",
            "purpose-review",
            &["collaboration_item"],
            items,
            Vec::new(),
            claims,
            "2026-07-26T00:00:00Z",
            key(),
        )
    }

    #[test]
    fn a_complete_manifest_sums_its_bytes_and_digests_itself() {
        let manifest = build(vec![item("c-1", 10), item("c-2", 32)], claims()).unwrap();
        assert_eq!(manifest.total_bytes, 42);
        assert_eq!(manifest.recipient_kind, RECIPIENT_MODEL_PROVIDER);
        // Kovee's own object: keyed under a random per-object secret, which
        // is also the class byom's runtime schemas require.
        assert_eq!(manifest.digest.class, "local_erasure_safe");
        assert_eq!(manifest.digest.algorithm, "hmac-sha-256");
        assert_eq!(
            manifest.digest.key_ref.as_deref(),
            Some("kovee-disclosure-object:disc-1")
        );
        manifest.verify(key()).unwrap();
        // The digest member is excluded from its own preimage.
        assert!(manifest.projection().get("digest").is_none());
        // A destroyed (here: different) secret cannot re-derive it — which is
        // exactly what per-object erasure means.
        let other = [8u8; 32];
        assert!(manifest
            .verify(RecordDigestKey::Object {
                key_ref: "kovee-disclosure-object:disc-1",
                secret: &other
            })
            .is_err());
    }

    #[test]
    fn every_one_of_the_three_provider_claims_is_mandatory() {
        for (region, retention, training_use) in [
            ("", "zero-retention", "prohibited"),
            ("us", "", "prohibited"),
            // The one this exists for: a blank training_use is a refusal.
            ("us", "zero-retention", ""),
            ("us", "zero-retention", "   "),
        ] {
            let c = ProviderClaims {
                region: region.to_owned(),
                retention: retention.to_owned(),
                training_use: training_use.to_owned(),
            };
            assert!(!c.is_complete());
            assert_eq!(
                build(vec![item("c-1", 1)], c).unwrap_err(),
                DisclosureError::IncompleteClaims
            );
        }
        assert!(claims().is_complete());
    }

    #[test]
    fn an_empty_disclosure_is_refused() {
        assert_eq!(
            build(Vec::new(), claims()).unwrap_err(),
            DisclosureError::NoItems
        );
    }

    #[test]
    fn a_changed_item_changes_the_digest() {
        let a = build(vec![item("c-1", 10)], claims()).unwrap();
        let b = build(vec![item("c-1", 11)], claims()).unwrap();
        assert_ne!(
            a.digest, b.digest,
            "one more disclosed byte is a new digest"
        );
        // And a changed training_use claim is a different authorization.
        let mut relaxed = claims();
        relaxed.training_use = "permitted".to_owned();
        let c = build(vec![item("c-1", 10)], relaxed).unwrap();
        assert_ne!(a.digest, c.digest);
    }

    #[test]
    fn tampering_after_the_fact_is_detected() {
        let mut manifest = build(vec![item("c-1", 10)], claims()).unwrap();
        manifest.provider_claims.training_use = "permitted".to_owned();
        assert!(
            manifest.verify(key()).is_err(),
            "the digest no longer matches"
        );
    }

    #[test]
    fn binding_the_context_assembly_rebinds_the_digest() {
        let manifest = build(vec![item("c-1", 10)], claims()).unwrap();
        let before = manifest.digest.clone();
        let bound = manifest
            .with_context_assembly(
                "ctxasm-1",
                DigestRef::portable_public("c".repeat(64)),
                key(),
            )
            .unwrap();
        assert_ne!(before, bound.digest);
        bound.verify(key()).unwrap();
    }
}
