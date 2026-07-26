//! The §16.3 `ProviderContextManifest` — the complete ordered chain from
//! the source context to the exact bytes that leave, plus the byom source
//! fragment the C2 contract fixes
//! (`byom/spec/governed-work/provider-context-manifest-byom-fields.schema.json`).
//!
//! Two halves, and the split is the contract:
//!
//! - [`ByomSourceFields`] is byom's — read from `episode_claim` /
//!   `context_manifest_show`, echoed and never invented. It is a source
//!   RELATION fragment, not a record: byom owns none of the final ordering.
//! - the rest is Kovee's — system/assistant instructions, tool schemas,
//!   adapter wrappers, deterministic transformations, the provider binding
//!   and profile revisions, the disclosure manifest ref/digest, and the
//!   final `provider-request-bytes` typed byte digest.
//!
//! An absent segment, a changed order, or a digest mismatch blocks egress.
//! The manifest is audit data, not a bearer grant.
//!
//! What you write:
//! ```
//! use kovee_effects::{ByomSourceFields, ProviderContextManifest, RecordDigestKey, Segment, SegmentKind};
//! use kovee_core::family::DigestRef;
//! # fn d(b: u8) -> DigestRef { DigestRef::portable_public(format!("{b:02x}").repeat(32)) }
//! let secret = [7u8; 32];
//! let key = RecordDigestKey::Object { key_ref: "kovee-pcm-object:pcm-1", secret: &secret };
//! let manifest = ProviderContextManifest::build(
//!     "pcm-1", "inv-1", "att-1", 1,
//!     Some(ByomSourceFields::example()),
//!     vec![
//!         Segment::new(SegmentKind::SystemInstruction, "sys-1", 1, d(1), "class-public"),
//!         Segment::new(SegmentKind::CollaborationItem, "contrib-1", 1, d(2), "class-public"),
//!     ],
//!     ("mpb-1", 1, d(3)), ("mp-1", 1, d(4)), "anthropic-messages-2023-06-01",
//!     "disc-1", d(5), "authdep-1", d(6),
//!     "2026-07-26T00:00:00Z", key,
//! ).unwrap();
//! // The final provider bytes are bound LAST, once they exist.
//! let sealed = manifest.seal(br#"{"model":"claude-haiku-4-5-20251001"}"#, key).unwrap();
//! assert!(sealed.final_provider_request_typed_byte_digest.len() == 64);
//! ```

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use kovee_core::canonical::typed_byte_digest;
use kovee_core::family::DigestRef;

use crate::keying::{record_digest, RecordDigestKey};

/// The byom type tag of a Kovee provider-context-manifest preimage.
pub const MANIFEST_TAG: &str = "kovee-provider-context-manifest-v1";
/// The byom type tag of the byom source fragment (the fragment
/// `ByomEpisodeBinding.context_source_digest` is taken over).
pub const SOURCE_FRAGMENT_TAG: &str = "kovee-provider-context-byom-source-v1";
/// The §11.8 typed-bytes domain of the final provider request.
pub const PROVIDER_REQUEST_DOMAIN: &str = "dev.kovee.provider-request-bytes.v1";

/// The closed §16.3 segment kinds. `adapter_wrapper` and `transformation`
/// are the driver's own deterministic work; nothing else may be appended
/// ("no convenience context is appended").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentKind {
    CollaborationItem,
    SystemInstruction,
    AssistantInstruction,
    ToolSchema,
    AdapterWrapper,
    Transformation,
}

impl SegmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SegmentKind::CollaborationItem => "collaboration_item",
            SegmentKind::SystemInstruction => "system_instruction",
            SegmentKind::AssistantInstruction => "assistant_instruction",
            SegmentKind::ToolSchema => "tool_schema",
            SegmentKind::AdapterWrapper => "adapter_wrapper",
            SegmentKind::Transformation => "transformation",
        }
    }
}

/// One ordered chain segment (§16.3 `ordered_segments[]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Segment {
    pub kind: SegmentKind,
    #[serde(rename = "ref")]
    pub ref_: String,
    pub revision: u64,
    pub digest: DigestRef,
    pub classification_ref: String,
    pub order: u64,
}

impl Segment {
    /// A segment whose `order` is assigned by
    /// [`ProviderContextManifest::build`] from its position.
    pub fn new(
        kind: SegmentKind,
        ref_: &str,
        revision: u64,
        digest: DigestRef,
        classification_ref: &str,
    ) -> Segment {
        Segment {
            kind,
            ref_: ref_.to_owned(),
            revision,
            digest,
            classification_ref: classification_ref.to_owned(),
            order: 0,
        }
    }
}

/// One ordered byom source item (`ordered_source_items[]` of the C2
/// fragment schema).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceItem {
    #[serde(rename = "ref")]
    pub ref_: String,
    pub digest: DigestRef,
}

/// The byom source fields §16.6 item 5 adds to Kovee's
/// ProviderContextManifest, member for member as the C2 schema fixes them.
/// Every value here is READ from byom (`episode_claim`'s committed
/// binding, `context_manifest_show`) and echoed — Kovee invents none of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByomSourceFields {
    pub byom_endpoint_ref: String,
    pub society_ref: String,
    pub participant_ref: String,
    pub participant_binding_epoch: u64,
    pub activity_stream_ref: String,
    pub episode_ref: String,
    pub byom_attempt_ref: String,
    pub byom_fence_epoch: u64,
    pub context_manifest_ref: String,
    pub context_manifest_digest: DigestRef,
    pub ordered_source_items: Vec<SourceItem>,
    pub classification_overlay_digest: DigestRef,
    pub purpose_ref: String,
    pub mandate_use_refs: Vec<String>,
    pub disclosure_ceiling_ref: String,
    /// Explicitly omitted inputs under current policy: an erased or
    /// revoked input fails materialization; a new manifest may omit it
    /// explicitly, never silently.
    pub explicit_omissions: Vec<String>,
    pub authorization_dependency_digest: DigestRef,
}

impl ByomSourceFields {
    /// The `portable_public` digest over exactly this canonical fragment —
    /// the same construction `ByomEpisodeBinding.context_source_digest`
    /// uses. Unkeyed on purpose: this is the CROSS-BOUNDARY class, so byom
    /// recomputes it independently and agreement is a machine check.
    pub fn digest(&self) -> Result<DigestRef, ManifestError> {
        let value = serde_json::to_value(self).map_err(|_| ManifestError::Uncanonical)?;
        record_digest(SOURCE_FRAGMENT_TAG, &value, RecordDigestKey::Portable)
            .ok_or(ManifestError::Uncanonical)
    }

    /// A doc/test fragment with every required member present.
    pub fn example() -> ByomSourceFields {
        let d = |b: u8| DigestRef::portable_public(format!("{b:02x}").repeat(32));
        ByomSourceFields {
            byom_endpoint_ref: "byom-endpoint-local".to_owned(),
            society_ref: "soc-1".to_owned(),
            participant_ref: "part-agent-1".to_owned(),
            participant_binding_epoch: 1,
            activity_stream_ref: "acts-1".to_owned(),
            episode_ref: "ep-1".to_owned(),
            byom_attempt_ref: "att-1".to_owned(),
            byom_fence_epoch: 1,
            context_manifest_ref: "ctxman-1".to_owned(),
            context_manifest_digest: d(0xa1),
            ordered_source_items: vec![SourceItem {
                ref_: "contrib-1".to_owned(),
                digest: d(0xa2),
            }],
            classification_overlay_digest: d(0xa3),
            purpose_ref: "purpose-review".to_owned(),
            mandate_use_refs: vec!["muse-1".to_owned()],
            disclosure_ceiling_ref: "ceiling-1".to_owned(),
            explicit_omissions: Vec::new(),
            authorization_dependency_digest: d(0xa4),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("the provider-context chain is empty: an absent segment blocks egress")]
    EmptyChain,
    #[error("segment order is not 1..n contiguous ascending (a changed order blocks egress)")]
    BrokenOrder,
    #[error("the provider-context manifest could not be canonicalized")]
    Uncanonical,
    #[error("the final provider-request digest is not bound yet")]
    Unsealed,
    #[error("the sealed provider-request digest does not match the bytes about to leave")]
    ByteMismatch,
}

/// A revisioned record reference: ref, revision, digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRef {
    #[serde(rename = "ref")]
    pub ref_: String,
    pub revision: u64,
    pub digest: DigestRef,
}

/// The §16.3 provider-context manifest the egress broker owns and
/// persists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderContextManifest {
    pub provider_context_id: String,
    pub revision: u64,
    pub invocation_id: String,
    pub attempt_id: String,
    pub kovee_fence_epoch: u64,
    /// byom's source fragment, when this call runs inside a governed
    /// Episode. Absent for an ungoverned local call.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub byom_source: Option<ByomSourceFields>,
    pub ordered_segments: Vec<Segment>,
    pub provider_binding: RecordRef,
    pub model_profile: RecordRef,
    pub adapter_version: String,
    pub disclosure_manifest_ref: String,
    pub disclosure_manifest_digest: DigestRef,
    pub authorization_dependency_set_ref: String,
    pub authority_digest: DigestRef,
    /// The §11.8 typed byte digest of the exact provider request bytes.
    /// Empty until [`ProviderContextManifest::seal`] binds it.
    pub final_provider_request_typed_byte_digest: String,
    pub created_at: String,
    pub digest: DigestRef,
}

impl ProviderContextManifest {
    /// Builds the chain, assigning contiguous `order` from position. The
    /// final byte digest is bound later by [`seal`](Self::seal), because it
    /// cannot exist before the driver has produced the request.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        provider_context_id: &str,
        invocation_id: &str,
        attempt_id: &str,
        kovee_fence_epoch: u64,
        byom_source: Option<ByomSourceFields>,
        segments: Vec<Segment>,
        provider_binding: (&str, u64, DigestRef),
        model_profile: (&str, u64, DigestRef),
        adapter_version: &str,
        disclosure_manifest_ref: &str,
        disclosure_manifest_digest: DigestRef,
        authorization_dependency_set_ref: &str,
        authority_digest: DigestRef,
        created_at: &str,
        key: RecordDigestKey<'_>,
    ) -> Result<ProviderContextManifest, ManifestError> {
        if segments.is_empty() {
            return Err(ManifestError::EmptyChain);
        }
        let ordered_segments = segments
            .into_iter()
            .enumerate()
            .map(|(i, mut s)| {
                s.order = i as u64 + 1;
                s
            })
            .collect();
        let mut manifest = ProviderContextManifest {
            provider_context_id: provider_context_id.to_owned(),
            revision: 1,
            invocation_id: invocation_id.to_owned(),
            attempt_id: attempt_id.to_owned(),
            kovee_fence_epoch,
            byom_source,
            ordered_segments,
            provider_binding: RecordRef {
                ref_: provider_binding.0.to_owned(),
                revision: provider_binding.1,
                digest: provider_binding.2,
            },
            model_profile: RecordRef {
                ref_: model_profile.0.to_owned(),
                revision: model_profile.1,
                digest: model_profile.2,
            },
            adapter_version: adapter_version.to_owned(),
            disclosure_manifest_ref: disclosure_manifest_ref.to_owned(),
            disclosure_manifest_digest,
            authorization_dependency_set_ref: authorization_dependency_set_ref.to_owned(),
            authority_digest,
            final_provider_request_typed_byte_digest: String::new(),
            created_at: created_at.to_owned(),
            digest: DigestRef::portable_public("0".repeat(64)),
        };
        manifest.digest = manifest.recompute_digest(key)?;
        Ok(manifest)
    }

    /// Binds the exact provider-request bytes as the last link of the
    /// chain and re-derives the manifest digest. Called once, on the bytes
    /// that are about to leave — not on a draft.
    pub fn seal(
        mut self,
        request_bytes: &[u8],
        key: RecordDigestKey<'_>,
    ) -> Result<ProviderContextManifest, ManifestError> {
        self.final_provider_request_typed_byte_digest =
            typed_byte_digest(PROVIDER_REQUEST_DOMAIN, "application/json", request_bytes);
        self.digest = self.recompute_digest(key)?;
        Ok(self)
    }

    /// Refuses egress unless the bytes about to leave are byte-for-byte the
    /// ones the sealed chain (and therefore the consumed permit) bound.
    pub fn check_bytes(&self, request_bytes: &[u8]) -> Result<(), ManifestError> {
        if self.final_provider_request_typed_byte_digest.is_empty() {
            return Err(ManifestError::Unsealed);
        }
        let actual = typed_byte_digest(PROVIDER_REQUEST_DOMAIN, "application/json", request_bytes);
        if actual == self.final_provider_request_typed_byte_digest {
            Ok(())
        } else {
            Err(ManifestError::ByteMismatch)
        }
    }

    /// Verifies the chain: contiguous ascending order and a digest that
    /// re-derives. A dropped or reordered segment fails here.
    pub fn verify(&self, key: RecordDigestKey<'_>) -> Result<(), ManifestError> {
        for (i, segment) in self.ordered_segments.iter().enumerate() {
            if segment.order != i as u64 + 1 {
                return Err(ManifestError::BrokenOrder);
            }
        }
        if self.ordered_segments.is_empty() {
            return Err(ManifestError::EmptyChain);
        }
        if self.recompute_digest(key)? != self.digest {
            return Err(ManifestError::Uncanonical);
        }
        Ok(())
    }

    pub fn projection(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        if let Some(map) = value.as_object_mut() {
            map.remove("digest");
        }
        value
    }

    fn recompute_digest(&self, key: RecordDigestKey<'_>) -> Result<DigestRef, ManifestError> {
        record_digest(MANIFEST_TAG, &self.projection(), key).ok_or(ManifestError::Uncanonical)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn d(b: u8) -> DigestRef {
        DigestRef::portable_public(format!("{b:02x}").repeat(32))
    }

    const SECRET: [u8; 32] = [7u8; 32];

    fn key() -> RecordDigestKey<'static> {
        RecordDigestKey::Object {
            key_ref: "kovee-provider-context-object:pcm-1",
            secret: &SECRET,
        }
    }

    fn manifest(segments: Vec<Segment>) -> Result<ProviderContextManifest, ManifestError> {
        ProviderContextManifest::build(
            "pcm-1",
            "inv-1",
            "att-1",
            1,
            Some(ByomSourceFields::example()),
            segments,
            ("mpb-1", 1, d(0x11)),
            ("mp-1", 1, d(0x22)),
            "anthropic-messages-2023-06-01",
            "disc-1",
            d(0x33),
            "authdep-1",
            d(0x44),
            "2026-07-26T00:00:00Z",
            key(),
        )
    }

    fn two() -> Vec<Segment> {
        vec![
            Segment::new(
                SegmentKind::SystemInstruction,
                "sys-1",
                1,
                d(1),
                "class-pub",
            ),
            Segment::new(
                SegmentKind::CollaborationItem,
                "contrib-1",
                1,
                d(2),
                "class-pub",
            ),
        ]
    }

    #[test]
    fn order_is_assigned_from_position_and_verified() {
        let m = manifest(two()).unwrap();
        assert_eq!(m.ordered_segments[0].order, 1);
        assert_eq!(m.ordered_segments[1].order, 2);
        m.verify(key()).unwrap();
        assert_eq!(m.digest.class, "local_erasure_safe");
    }

    #[test]
    fn an_empty_chain_blocks_egress() {
        assert_eq!(manifest(Vec::new()).unwrap_err(), ManifestError::EmptyChain);
    }

    #[test]
    fn a_reordered_or_dropped_segment_fails_verification() {
        let mut m = manifest(two()).unwrap();
        m.ordered_segments.swap(0, 1);
        assert_eq!(m.verify(key()).unwrap_err(), ManifestError::BrokenOrder);
        let mut m = manifest(two()).unwrap();
        m.ordered_segments.pop();
        // Order stays 1..n, so the digest is what catches the omission.
        assert_eq!(m.verify(key()).unwrap_err(), ManifestError::Uncanonical);
    }

    #[test]
    fn the_final_bytes_are_bound_last_and_checked_before_egress() {
        let m = manifest(two()).unwrap();
        // Unsealed: nothing may leave.
        assert_eq!(m.check_bytes(b"{}").unwrap_err(), ManifestError::Unsealed);
        let sealed = m.seal(br#"{"model":"m","messages":[]}"#, key()).unwrap();
        assert_eq!(sealed.final_provider_request_typed_byte_digest.len(), 64);
        sealed.verify(key()).unwrap();
        sealed
            .check_bytes(br#"{"model":"m","messages":[]}"#)
            .unwrap();
        // One byte different is a different request.
        assert_eq!(
            sealed
                .check_bytes(br#"{"model":"n","messages":[]}"#)
                .unwrap_err(),
            ManifestError::ByteMismatch
        );
    }

    #[test]
    fn the_byom_source_fragment_digests_independently() {
        let fragment = ByomSourceFields::example();
        let a = fragment.digest().unwrap();
        assert_eq!(a.class, "portable_public");
        // A CROSS-BOUNDARY digest: unkeyed exactly so byom can recompute it.
        assert_eq!(a.algorithm, "sha-256");
        let mut other = fragment.clone();
        other.byom_fence_epoch = 2;
        assert_ne!(
            a,
            other.digest().unwrap(),
            "the fence is part of the source"
        );
    }

    #[test]
    fn the_byom_source_fragment_carries_every_c2_member() {
        // The C2 schema's `required` list, member for member.
        let value = serde_json::to_value(ByomSourceFields::example()).unwrap();
        for member in [
            "byom_endpoint_ref",
            "society_ref",
            "participant_ref",
            "participant_binding_epoch",
            "activity_stream_ref",
            "episode_ref",
            "byom_attempt_ref",
            "byom_fence_epoch",
            "context_manifest_ref",
            "context_manifest_digest",
            "ordered_source_items",
            "classification_overlay_digest",
            "purpose_ref",
            "mandate_use_refs",
            "disclosure_ceiling_ref",
            "explicit_omissions",
            "authorization_dependency_digest",
        ] {
            assert!(value.get(member).is_some(), "{member} is required by C2");
        }
        assert_eq!(value.as_object().unwrap().len(), 17);
    }
}
