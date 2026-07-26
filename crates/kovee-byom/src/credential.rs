//! `DelegatedPrincipalCredential` — the short-lived, sender-constrained
//! credential the Kovee gateway presents on byom's governance surface for
//! `kovee_endeavor_form` and `external_command_terminalize`
//! (C2 profile; byom §14.4/§16.3, family contract L5–L6).
//!
//! What you write:
//! ```
//! use kovee_byom::credential::{Delegation, DpcMint, MintContext, SenderConstraint};
//! use kovee_byom::records::GovernanceDigests;
//! use kovee_core::family::DigestRef;
//! # let binding = kovee_byom::records::sample_active_binding();
//! let digests = GovernanceDigests::new(&[9u8; 32], "realm-personal");
//! let mint = DpcMint {
//!     issuer_ref: "kovee-gateway:realm-personal",
//!     nonce: "nonce-0001",
//!     sender_constraint: SenderConstraint::channel_exporter(
//!         DigestRef::scope_erasure_safe("kovee-governance:realm-personal", "a".repeat(64))),
//!     delegation: Delegation {
//!         source_principal_ref: "prin-owner",
//!         bound_participant_ref: "part-1",
//!         participant_binding_epoch: 1,
//!         allowed_operations: &["kovee_endeavor_form"],
//!         authentication_observation_ref: "authobs-1",
//!         assurance_level: "personal-uds-owner",
//!     },
//!     subject_projection: serde_json::json!({"endeavor_proposal_digest": "…"}),
//!     issued_at: 1_800_000_000,
//!     lifetime_seconds: 120,
//! };
//! let context = MintContext {
//!     binding: &binding,
//!     society_ref: "soc-1".to_owned(),
//!     society_recovery_epoch: 0,
//! };
//! let dpc = mint.issue(&context, &digests).unwrap();
//! assert_eq!(dpc.surface, "governance");
//! assert_eq!(dpc.audience, binding.delegated_principal_audience);
//! ```
//!
//! Plumbing: the credential binds — per §14.4's two normative sentences —
//! a proof key, the Participant and its binding epoch, the endpoint
//! incarnation, the Society recovery epoch, the audience, the surface,
//! the operation family, the exact prepared subject, a nonce, an issue
//! time, and a short expiry. The `(issuer_ref, nonce)` pair is atomic: the
//! consume record lives in the host store, a replay under the same pair
//! returns the stored result, and a generic Kovee service credential can
//! never become a principal.

use kovee_core::family::DigestRef;
use kovee_core::time::rfc3339_utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::records::{GovernanceDigests, KoveeRealmByomBinding, RecordError};

/// Byom type tags for the credential preimages.
pub const TAG_CREDENTIAL: &str = "kovee-delegated-principal-credential-v1";
pub const TAG_SUBJECT: &str = "kovee-delegated-principal-subject-v1";
pub const TAG_ACTOR_BINDING: &str = "kovee-source-actor-binding-v1";
pub const TAG_AUTH_OBSERVATION: &str = "kovee-authentication-observation-v1";

/// The credential's only surface (R39/R40 are governance-surface rows).
pub const CREDENTIAL_SURFACE: &str = "governance";

/// The closed operation family a delegated principal may drive.
pub const DELEGATED_OPERATIONS: [&str; 2] = ["kovee_endeavor_form", "external_command_terminalize"];

/// Closed §14.4 sender-constraint methods.
pub const SENDER_CONSTRAINT_METHODS: [&str; 3] = ["mtls", "dpop", "channel_exporter"];

/// The longest short expiry this profile mints (§14.4 "short expiry").
pub const MAX_LIFETIME_SECONDS: u64 = 300;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CredentialError {
    #[error("audience must equal the binding's delegated_principal_audience")]
    Audience,
    #[error("allowed_operations must name 1-2 operations from the closed delegated family")]
    Operations,
    #[error("sender_constraint.method is not in the closed §14.4 list")]
    SenderConstraint,
    #[error("expiry must be short: 1..={MAX_LIFETIME_SECONDS} seconds")]
    Lifetime,
    #[error("the binding is not active under the byom_governed_work_v1 bundle")]
    Binding,
    #[error("digest: {0}")]
    Digest(String),
}

impl From<RecordError> for CredentialError {
    fn from(e: RecordError) -> CredentialError {
        CredentialError::Digest(e.to_string())
    }
}

/// §14.4: sender-constrained, not merely bearer and audience-bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderConstraint {
    pub method: String,
    pub key_binding_digest: DigestRef,
}

impl SenderConstraint {
    /// The local channel-exporter binding: the personal profile's
    /// UID-checked Unix socket is the proof channel.
    pub fn channel_exporter(key_binding_digest: DigestRef) -> SenderConstraint {
        SenderConstraint {
            method: "channel_exporter".to_owned(),
            key_binding_digest,
        }
    }
}

/// The Kovee-gateway delegation half of §14.4.
#[derive(Debug, Clone, Copy)]
pub struct Delegation<'a> {
    pub source_principal_ref: &'a str,
    pub bound_participant_ref: &'a str,
    pub participant_binding_epoch: u64,
    pub allowed_operations: &'a [&'a str],
    pub authentication_observation_ref: &'a str,
    pub assurance_level: &'a str,
}

/// Everything one minting needs. The Society, endpoint, and binding
/// facts are read from the `KoveeRealmByomBinding` — never from the
/// caller — so a credential cannot outrun its binding.
pub struct DpcMint<'a> {
    pub issuer_ref: &'a str,
    pub nonce: &'a str,
    pub sender_constraint: SenderConstraint,
    pub delegation: Delegation<'a>,
    /// The exact prepared subject or preparation scope (§14.4); the
    /// formation intent pins the same digest.
    pub subject_projection: Value,
    pub issued_at: i64,
    pub lifetime_seconds: u64,
}

impl DpcMint<'_> {
    /// Mints the credential against an ACTIVE binding and one Society
    /// mapping's recovery epoch.
    pub fn issue(
        &self,
        context: &MintContext,
        digests: &GovernanceDigests,
    ) -> Result<DelegatedPrincipalCredential, CredentialError> {
        if context.binding.compatibility_bundle != crate::records::COMPATIBILITY_BUNDLE
            || context.binding.status != "active"
        {
            return Err(CredentialError::Binding);
        }
        if !SENDER_CONSTRAINT_METHODS.contains(&self.sender_constraint.method.as_str()) {
            return Err(CredentialError::SenderConstraint);
        }
        let ops = self.delegation.allowed_operations;
        if ops.is_empty()
            || ops.len() > 2
            || ops.iter().any(|op| !DELEGATED_OPERATIONS.contains(op))
            || (ops.len() == 2 && ops[0] == ops[1])
        {
            return Err(CredentialError::Operations);
        }
        if self.lifetime_seconds == 0 || self.lifetime_seconds > MAX_LIFETIME_SECONDS {
            return Err(CredentialError::Lifetime);
        }

        let subject_digest = digests.digest(TAG_SUBJECT, &self.subject_projection)?;
        let source_actor_binding_digest = digests.digest(
            TAG_ACTOR_BINDING,
            &serde_json::json!({
                "realm_ref": context.binding.realm_ref,
                "source_principal_ref": self.delegation.source_principal_ref,
                "bound_participant_ref": self.delegation.bound_participant_ref,
                "participant_binding_epoch": self.delegation.participant_binding_epoch,
            }),
        )?;
        let authentication_observation_digest = digests.digest(
            TAG_AUTH_OBSERVATION,
            &serde_json::json!({
                "authentication_observation_ref": self.delegation.authentication_observation_ref,
                "assurance_level": self.delegation.assurance_level,
                "observed_at": rfc3339_utc(self.issued_at),
            }),
        )?;

        let mut credential = DelegatedPrincipalCredential {
            credential_id: format!("dpc-{}-{}", self.issuer_ref_tag(), self.nonce),
            issuer_ref: self.issuer_ref.to_owned(),
            nonce: self.nonce.to_owned(),
            sender_constraint: self.sender_constraint.clone(),
            source_principal_ref: self.delegation.source_principal_ref.to_owned(),
            source_actor_binding_digest,
            bound_participant_ref: self.delegation.bound_participant_ref.to_owned(),
            participant_binding_epoch: self.delegation.participant_binding_epoch,
            society_ref: context.society_ref.clone(),
            society_recovery_epoch: context.society_recovery_epoch,
            endpoint_incarnation: context.binding.endpoint_incarnation.clone(),
            realm_byom_binding_ref: context.binding.binding_ref.clone(),
            realm_byom_binding_revision: context.binding.binding_revision,
            realm_byom_binding_epoch: context.binding.binding_epoch,
            realm_byom_binding_digest: context.binding.digest.clone(),
            audience: context.binding.delegated_principal_audience.clone(),
            surface: CREDENTIAL_SURFACE.to_owned(),
            allowed_operations: ops.iter().map(|o| (*o).to_owned()).collect(),
            delegated_principal_subject_digest: subject_digest,
            authentication_observation_ref: self
                .delegation
                .authentication_observation_ref
                .to_owned(),
            authentication_observation_digest,
            assurance_level: self.delegation.assurance_level.to_owned(),
            issued_at: rfc3339_utc(self.issued_at),
            expires_at: rfc3339_utc(self.issued_at + self.lifetime_seconds as i64),
            digest: DigestRef::scope_erasure_safe(digests.key_ref(), "0".repeat(64)),
        };
        credential.digest = credential.compute_digest(digests)?;
        Ok(credential)
    }

    fn issuer_ref_tag(&self) -> String {
        self.issuer_ref
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect()
    }
}

/// The binding-derived facts a minting reads (never caller-supplied).
pub struct MintContext<'a> {
    pub binding: &'a KoveeRealmByomBinding,
    pub society_ref: String,
    pub society_recovery_epoch: u64,
}

/// The C2 `DelegatedPrincipalCredential` profile, field list verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedPrincipalCredential {
    pub credential_id: String,
    pub issuer_ref: String,
    pub nonce: String,
    pub sender_constraint: SenderConstraint,
    pub source_principal_ref: String,
    pub source_actor_binding_digest: DigestRef,
    pub bound_participant_ref: String,
    pub participant_binding_epoch: u64,
    pub society_ref: String,
    pub society_recovery_epoch: u64,
    pub endpoint_incarnation: String,
    pub realm_byom_binding_ref: String,
    pub realm_byom_binding_revision: u64,
    pub realm_byom_binding_epoch: u64,
    pub realm_byom_binding_digest: DigestRef,
    pub audience: String,
    pub surface: String,
    pub allowed_operations: Vec<String>,
    pub delegated_principal_subject_digest: DigestRef,
    pub authentication_observation_ref: String,
    pub authentication_observation_digest: DigestRef,
    pub assurance_level: String,
    pub issued_at: String,
    pub expires_at: String,
    pub digest: DigestRef,
}

impl DelegatedPrincipalCredential {
    pub fn compute_digest(&self, digests: &GovernanceDigests) -> Result<DigestRef, RecordError> {
        let mut projection = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(map) = projection.as_object_mut() {
            map.remove("digest");
        }
        digests.digest(TAG_CREDENTIAL, &projection)
    }

    /// Every binding-bound invariant the schema pins but JSON Schema
    /// cannot check across records (§14.4, family contract L5–L6).
    pub fn check_against(&self, binding: &KoveeRealmByomBinding) -> Result<(), CredentialError> {
        if self.audience != binding.delegated_principal_audience {
            return Err(CredentialError::Audience);
        }
        if self.realm_byom_binding_ref != binding.binding_ref
            || self.realm_byom_binding_epoch != binding.binding_epoch
            || self.endpoint_incarnation != binding.endpoint_incarnation
        {
            return Err(CredentialError::Binding);
        }
        if self.surface != CREDENTIAL_SURFACE {
            return Err(CredentialError::Operations);
        }
        Ok(())
    }

    /// The atomic consume key (family contract L5–L6): the host store
    /// enforces `UNIQUE(issuer_ref, nonce)` and a replay under the same
    /// pair returns the stored result.
    pub fn consume_key(&self) -> (&str, &str) {
        (&self.issuer_ref, &self.nonce)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::records::sample_active_binding;

    fn digests() -> GovernanceDigests {
        GovernanceDigests::new(&[9u8; 32], "realm-personal")
    }

    fn context(binding: &KoveeRealmByomBinding) -> MintContext<'_> {
        MintContext {
            binding,
            society_ref: "soc-1".to_owned(),
            society_recovery_epoch: 0,
        }
    }

    fn mint<'a>(ops: &'a [&'a str], lifetime: u64) -> DpcMint<'a> {
        DpcMint {
            issuer_ref: "kovee-gateway:realm-personal",
            nonce: "nonce-0001",
            sender_constraint: SenderConstraint::channel_exporter(DigestRef::scope_erasure_safe(
                "kovee-governance:realm-personal",
                "a".repeat(64),
            )),
            delegation: Delegation {
                source_principal_ref: "prin-owner",
                bound_participant_ref: "part-1",
                participant_binding_epoch: 1,
                allowed_operations: ops,
                authentication_observation_ref: "authobs-1",
                assurance_level: "personal-uds-owner",
            },
            subject_projection: serde_json::json!({"endeavor_proposal_digest": "abc"}),
            issued_at: 1_800_000_000,
            lifetime_seconds: lifetime,
        }
    }

    #[test]
    fn a_minted_credential_is_audience_workload_realm_command_and_authorization_bound() {
        let binding = sample_active_binding();
        let context = context(&binding);
        let dpc = mint(&["kovee_endeavor_form"], 120)
            .issue(&context, &digests())
            .unwrap();
        // Audience: exactly the binding's.
        assert_eq!(dpc.audience, "byom:local:governance");
        // Workload/realm: the binding ref, revision, epoch, incarnation.
        assert_eq!(dpc.realm_byom_binding_ref, "krbb-1");
        assert_eq!(dpc.realm_byom_binding_epoch, 1);
        assert_eq!(dpc.endpoint_incarnation, "inc-1");
        assert_eq!(dpc.society_ref, "soc-1");
        // Command: the closed operation family, governance surface only.
        assert_eq!(dpc.allowed_operations, vec!["kovee_endeavor_form"]);
        assert_eq!(dpc.surface, "governance");
        // Authorization: sender-constrained plus the observation.
        assert_eq!(dpc.sender_constraint.method, "channel_exporter");
        assert_eq!(dpc.authentication_observation_ref, "authobs-1");
        // Short expiry.
        assert_eq!(dpc.issued_at, "2027-01-15T08:00:00Z");
        assert_eq!(dpc.expires_at, "2027-01-15T08:02:00Z");
        dpc.check_against(context.binding).unwrap();
    }

    #[test]
    fn a_credential_outside_the_closed_operation_family_is_refused() {
        let binding = sample_active_binding();
        let context = context(&binding);
        for ops in [
            &[][..],
            &["society_bootstrap"][..],
            &["kovee_endeavor_form", "kovee_endeavor_form"][..],
        ] {
            assert_eq!(
                mint(ops, 120).issue(&context, &digests()).unwrap_err(),
                CredentialError::Operations
            );
        }
    }

    #[test]
    fn a_long_lived_credential_is_refused() {
        let binding = sample_active_binding();
        let context = context(&binding);
        assert_eq!(
            mint(&["kovee_endeavor_form"], 0)
                .issue(&context, &digests())
                .unwrap_err(),
            CredentialError::Lifetime
        );
        assert_eq!(
            mint(&["kovee_endeavor_form"], MAX_LIFETIME_SECONDS + 1)
                .issue(&context, &digests())
                .unwrap_err(),
            CredentialError::Lifetime
        );
    }

    #[test]
    fn a_pending_binding_mints_nothing() {
        // Step 1's bindings are durable but NOT authoritative: no derived
        // channel, credential, or permit may be issued from them.
        let mut pending = sample_active_binding();
        pending.status = "pending".to_owned();
        let context = context(&pending);
        assert_eq!(
            mint(&["kovee_endeavor_form"], 120)
                .issue(&context, &digests())
                .unwrap_err(),
            CredentialError::Binding
        );
    }

    #[test]
    fn an_audience_or_binding_mismatch_is_caught_on_use() {
        let binding = sample_active_binding();
        let context = context(&binding);
        let dpc = mint(&["external_command_terminalize"], 60)
            .issue(&context, &digests())
            .unwrap();
        let mut other = sample_active_binding();
        other.delegated_principal_audience = "byom:other:governance".to_owned();
        assert_eq!(
            dpc.check_against(&other).unwrap_err(),
            CredentialError::Audience
        );
        let mut rotated = sample_active_binding();
        rotated.endpoint_incarnation = "inc-2".to_owned();
        assert_eq!(
            dpc.check_against(&rotated).unwrap_err(),
            CredentialError::Binding
        );
    }

    #[test]
    fn the_consume_key_is_the_atomic_issuer_nonce_pair() {
        let binding = sample_active_binding();
        let context = context(&binding);
        let dpc = mint(&["kovee_endeavor_form"], 120)
            .issue(&context, &digests())
            .unwrap();
        assert_eq!(
            dpc.consume_key(),
            ("kovee-gateway:realm-personal", "nonce-0001")
        );
    }

    #[test]
    fn the_credential_round_trips_through_its_closed_shape() {
        let binding = sample_active_binding();
        let context = context(&binding);
        let dpc = mint(&["kovee_endeavor_form"], 120)
            .issue(&context, &digests())
            .unwrap();
        let json = serde_json::to_value(&dpc).unwrap();
        assert_eq!(
            serde_json::from_value::<DelegatedPrincipalCredential>(json.clone()).unwrap(),
            dpc
        );
        let mut widened = json;
        widened["scope"] = Value::String("*".to_owned());
        assert!(serde_json::from_value::<DelegatedPrincipalCredential>(widened).is_err());
    }
}
