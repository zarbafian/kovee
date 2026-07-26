//! The three C2 host records of the greenfield binding half, in the exact
//! shapes `byom/spec/governed-work/*.schema.json` freezes, plus the typed
//! digests they carry.
//!
//! What you write (one inert binding, then its exact-scope digest):
//! ```
//! use kovee_byom::records::{GovernanceDigests, KoveeRealmByomBinding};
//! use kovee_byom::scope::Selector;
//! let digests = GovernanceDigests::new(&[7u8; 32], "realm-personal");
//! let scope = Selector::parse("project:proj-1").unwrap();
//! let scope_digest = digests.exact_scope(&scope).unwrap();
//! assert_eq!(scope_digest.class, "scope_erasure_safe");
//! assert_eq!(scope_digest.key_ref.as_deref(),
//!            Some("kovee-governance:realm-personal"));
//! ```
//!
//! Plumbing: every digest is a typed family `DigestRef` (PROFILE §6.1),
//! never a bare hash. The class is `scope_erasure_safe` — an HMAC under
//! ONE protected per-realm governance key, so destroying that key erases
//! verifiability of the whole governance scope, never of a single row
//! (D-R0-1). The preimage is `tagged_canonical(tag, projection)`: RFC
//! 8785 JCS with byom's reserved `$domain` member injected at the top.

use kovee_core::family::{hex, hmac_sha256, tagged_canonical, DigestRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::scope::Selector;

/// The one compatibility bundle these shapes exist under (§16.6): a new
/// bundle is a new schema version, never a widened field.
pub const COMPATIBILITY_BUNDLE: &str = "byom_governed_work_v1";

/// Byom type tags for the Kovee-owned governed-work preimages.
pub const TAG_REALM_BINDING: &str = "kovee-realm-byom-binding-v1";
pub const TAG_SOCIETY_MAPPING: &str = "kovee-society-mapping-v1";
pub const TAG_OWNER_BINDING: &str = "kovee-governance-owner-binding-v1";
pub const TAG_GOVERNED_SCOPE: &str = "kovee-governed-scope-v1";
pub const TAG_DEPENDENCY_SET: &str = "kovee-governance-dependency-set-v1";
pub const TAG_ENABLE_SUBJECT: &str = "kovee-governance-enable-subject-v1";

/// Closed `KoveeRealmByomBinding.historical_recovery_mode` enum (§16.6).
pub const HISTORICAL_RECOVERY_MODES: [&str; 2] = ["disabled", "exact_formation_intent_only"];

/// Kovee-owned `status` value set for `KoveeRealmByomBinding` and
/// `KoveeSocietyMapping`. §16.6 leaves the value set untyped (a recorded
/// C2 gap); byom pins only the saga semantics, so this closes it:
/// `pending` before the owner CAS, `active` atomically with it, `void`
/// after a rollback.
pub const BINDING_STATUSES: [&str; 3] = ["pending", "active", "void"];

/// Closed `KoveeGovernanceOwnerBinding.governance_owner` enum, verbatim
/// §16.6. The `sage` arm exists for spec fidelity and is never exercised
/// in this stack (amendment A1).
pub const GOVERNANCE_OWNERS: [&str; 3] = ["sage", "byom", "none"];

/// Closed `KoveeGovernanceOwnerBinding.status` enum, verbatim §16.6.
pub const OWNER_STATUSES: [&str; 2] = ["active", "frozen"];

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("canonicalization: {0}")]
    Canonical(#[from] kovee_core::canonical::CanonicalError),
}

/// The realm's governance digest scope: one protected key, one key ref.
#[derive(Debug, Clone)]
pub struct GovernanceDigests {
    key: Vec<u8>,
    key_ref: String,
}

impl GovernanceDigests {
    pub fn new(scope_key: &[u8], realm_ref: &str) -> GovernanceDigests {
        GovernanceDigests {
            key: scope_key.to_vec(),
            key_ref: format!("kovee-governance:{realm_ref}"),
        }
    }

    pub fn key_ref(&self) -> &str {
        &self.key_ref
    }

    /// The typed digest of one tagged canonical projection.
    pub fn digest(&self, tag: &str, projection: &Value) -> Result<DigestRef, RecordError> {
        let preimage = tagged_canonical(tag, projection)?;
        Ok(DigestRef::scope_erasure_safe(
            &self.key_ref,
            hex(&hmac_sha256(&self.key, &preimage)),
        ))
    }

    /// The canonical digest of an exact governed scope — the
    /// `exact_scope_digest` whose `(realm_ref, …)` pair is unique.
    pub fn exact_scope(&self, selector: &Selector) -> Result<DigestRef, RecordError> {
        self.digest(TAG_GOVERNED_SCOPE, &selector.projection())
    }

    /// The digest over the frozen `governance_enable` authorization
    /// dependency set (family contract §2.A): realm revision, target
    /// `society_ref` + Society recovery epoch, byomd endpoint identity and
    /// incarnation, expected `KoveeRealmByomBinding`, mapping revision.
    #[allow(clippy::too_many_arguments)]
    pub fn dependency_set(&self, deps: &DependencySet) -> Result<DigestRef, RecordError> {
        self.digest(
            TAG_DEPENDENCY_SET,
            &serde_json::to_value(deps).unwrap_or(Value::Null),
        )
    }

    /// The subject digest the confirming human sees (family contract
    /// §2.A "Subject digest" cell): the (realm, society_ref, recovery
    /// epoch, byom endpoint, mapping revision, owner transition) tuple.
    pub fn enable_subject(&self, subject: &EnableSubject) -> Result<DigestRef, RecordError> {
        self.digest(
            TAG_ENABLE_SUBJECT,
            &serde_json::to_value(subject).unwrap_or(Value::Null),
        )
    }
}

/// The frozen authorization dependency set of `governance_enable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencySet {
    pub realm_ref: String,
    pub realm_revision: u64,
    pub society_ref: String,
    pub society_recovery_epoch: u64,
    pub byom_endpoint_ref: String,
    pub endpoint_incarnation: String,
    /// The expected absent-or-identical `KoveeRealmByomBinding`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expected_binding_ref: Option<String>,
    pub society_mapping_revision: u64,
}

/// The exact subject the confirming human is shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnableSubject {
    pub realm_ref: String,
    pub society_ref: String,
    pub society_recovery_epoch: u64,
    pub byom_endpoint_ref: String,
    pub endpoint_incarnation: String,
    pub exact_scope_selector: String,
    pub society_mapping_revision: u64,
    /// Always `none->byom` for the greenfield saga; the `sage->none->byom`
    /// cutover is a different machine (amendment A2).
    pub owner_binding_transition: String,
}

/// §16.6 `KoveeRealmByomBinding`, field list verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KoveeRealmByomBinding {
    pub binding_ref: String,
    pub realm_ref: String,
    pub binding_revision: u64,
    pub binding_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub predecessor_binding_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub predecessor_binding_digest: Option<DigestRef>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub binding_lineage_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub binding_lineage_digest: Option<DigestRef>,
    pub byom_endpoint_ref: String,
    pub endpoint_incarnation: String,
    pub compatibility_bundle: String,
    pub delegated_principal_audience: String,
    pub external_authorization_audience: String,
    pub historical_recovery_mode: String,
    pub recovery_authorization_policy_ref: String,
    pub recovery_authorization_policy_digest: DigestRef,
    pub status: String,
    pub dependency_digest: DigestRef,
    pub digest: DigestRef,
}

impl KoveeRealmByomBinding {
    /// The record's own digest: every member except `digest` itself.
    pub fn compute_digest(&self, digests: &GovernanceDigests) -> Result<DigestRef, RecordError> {
        let mut projection = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(map) = projection.as_object_mut() {
            map.remove("digest");
        }
        digests.digest(TAG_REALM_BINDING, &projection)
    }
}

/// §16.6 `KoveeSocietyMapping`, field list verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KoveeSocietyMapping {
    pub realm_ref: String,
    pub society_ref: String,
    pub society_recovery_epoch: u64,
    pub allowed_project_and_space_selectors: Vec<String>,
    pub classification_binding_ref: String,
    pub governance_owner_binding_ref: String,
    pub governance_owner_binding_digest: DigestRef,
    pub status: String,
    pub revision: u64,
    pub digest: DigestRef,
}

impl KoveeSocietyMapping {
    pub fn compute_digest(&self, digests: &GovernanceDigests) -> Result<DigestRef, RecordError> {
        let mut projection = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(map) = projection.as_object_mut() {
            map.remove("digest");
        }
        digests.digest(TAG_SOCIETY_MAPPING, &projection)
    }
}

/// §16.6 `KoveeGovernanceOwnerBinding`, field list verbatim with the full
/// `sage | byom | none` enum (amendment A1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KoveeGovernanceOwnerBinding {
    pub realm_ref: String,
    pub exact_scope_selector: String,
    pub exact_scope_digest: DigestRef,
    pub revision: u64,
    pub binding_epoch: u64,
    pub governance_owner: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub owner_endpoint_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub owner_binding_ref: Option<String>,
    /// Set only by a byom §25 `GovernanceCutover`; the greenfield saga
    /// never sets it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cutover_ref: Option<String>,
    pub status: String,
    pub digest: DigestRef,
}

impl KoveeGovernanceOwnerBinding {
    pub fn compute_digest(&self, digests: &GovernanceDigests) -> Result<DigestRef, RecordError> {
        let mut projection = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(map) = projection.as_object_mut() {
            map.remove("digest");
        }
        digests.digest(TAG_OWNER_BINDING, &projection)
    }

    /// The schema's `oneOf`: `none` carries no owner refs; an owning arm
    /// names both. Enforced here because JSON Schema cannot check it
    /// against the stored row.
    pub fn owner_arm_is_coherent(&self) -> bool {
        match self.governance_owner.as_str() {
            "none" => self.owner_endpoint_ref.is_none() && self.owner_binding_ref.is_none(),
            "byom" | "sage" => {
                self.owner_endpoint_ref.is_some() && self.owner_binding_ref.is_some()
            }
            _ => false,
        }
    }
}

/// A fixed, fully populated ACTIVE binding — the fixture the doc
/// examples and the credential tests mint against. Not a constructor:
/// real bindings are minted by the greenfield saga.
pub fn sample_active_binding() -> KoveeRealmByomBinding {
    let d = GovernanceDigests::new(&[9u8; 32], "realm-personal");
    let fixed = |n: &str| {
        d.digest("kovee-fixture-v1", &serde_json::json!({"n": n}))
            .unwrap_or_else(|_| DigestRef::scope_erasure_safe(d.key_ref(), "0".repeat(64)))
    };
    KoveeRealmByomBinding {
        binding_ref: "krbb-1".to_owned(),
        realm_ref: "realm-personal".to_owned(),
        binding_revision: 2,
        binding_epoch: 1,
        predecessor_binding_ref: None,
        predecessor_binding_digest: None,
        binding_lineage_ref: None,
        binding_lineage_digest: None,
        byom_endpoint_ref: "local".to_owned(),
        endpoint_incarnation: "inc-1".to_owned(),
        compatibility_bundle: COMPATIBILITY_BUNDLE.to_owned(),
        delegated_principal_audience: "byom:local:governance".to_owned(),
        external_authorization_audience: "byom:local:external-authorization".to_owned(),
        historical_recovery_mode: "disabled".to_owned(),
        recovery_authorization_policy_ref: "recovery-policy-default".to_owned(),
        recovery_authorization_policy_digest: fixed("recovery-policy"),
        status: "active".to_owned(),
        dependency_digest: fixed("dependency-set"),
        digest: fixed("binding"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn digests() -> GovernanceDigests {
        GovernanceDigests::new(&[3u8; 32], "realm-personal")
    }

    fn owner_binding(owner: &str) -> KoveeGovernanceOwnerBinding {
        let d = digests();
        let scope = Selector::parse("project:proj-1").unwrap();
        KoveeGovernanceOwnerBinding {
            realm_ref: "realm-personal".to_owned(),
            exact_scope_selector: scope.as_str().to_owned(),
            exact_scope_digest: d.exact_scope(&scope).unwrap(),
            revision: 1,
            binding_epoch: 1,
            governance_owner: owner.to_owned(),
            owner_endpoint_ref: (owner != "none").then(|| "local".to_owned()),
            owner_binding_ref: (owner != "none").then(|| "krbb-1".to_owned()),
            cutover_ref: None,
            status: "active".to_owned(),
            digest: DigestRef::scope_erasure_safe("k", "0".repeat(64)),
        }
    }

    #[test]
    fn every_governed_work_digest_is_typed_and_scope_keyed() {
        let d = digests();
        let scope = Selector::parse("project:proj-1").unwrap();
        let digest = d.exact_scope(&scope).unwrap();
        assert_eq!(digest.class, "scope_erasure_safe");
        assert_eq!(digest.algorithm, "hmac-sha-256");
        assert_eq!(
            digest.key_ref.as_deref(),
            Some("kovee-governance:realm-personal")
        );
        assert_eq!(digest.value_hex.len(), 64);
        // Re-derive by hand: HMAC over the tagged canonical preimage.
        let preimage = tagged_canonical(TAG_GOVERNED_SCOPE, &scope.projection()).unwrap();
        assert_eq!(digest.value_hex, hex(&hmac_sha256(&[3u8; 32], &preimage)));
    }

    #[test]
    fn a_different_scope_digests_differently() {
        let d = digests();
        let a = d
            .exact_scope(&Selector::parse("project:proj-1").unwrap())
            .unwrap();
        let b = d
            .exact_scope(&Selector::parse("project:proj-2").unwrap())
            .unwrap();
        assert_ne!(a.value_hex, b.value_hex);
    }

    #[test]
    fn the_record_digest_excludes_the_digest_member_itself() {
        let d = digests();
        let mut row = owner_binding("none");
        let first = row.compute_digest(&d).unwrap();
        // Changing only the (excluded) digest member leaves it stable.
        row.digest = DigestRef::scope_erasure_safe("k", "f".repeat(64));
        assert_eq!(row.compute_digest(&d).unwrap(), first);
        // Changing a covered member does not.
        row.revision = 2;
        assert_ne!(row.compute_digest(&d).unwrap(), first);
    }

    #[test]
    fn the_owner_arm_oneof_is_enforced_in_code() {
        assert!(owner_binding("none").owner_arm_is_coherent());
        assert!(owner_binding("byom").owner_arm_is_coherent());
        let mut broken = owner_binding("none");
        broken.owner_binding_ref = Some("krbb-1".to_owned());
        assert!(!broken.owner_arm_is_coherent());
        let mut half = owner_binding("byom");
        half.owner_endpoint_ref = None;
        assert!(!half.owner_arm_is_coherent());
    }

    #[test]
    fn the_records_round_trip_through_their_closed_shapes() {
        let row = owner_binding("byom");
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(
            serde_json::from_value::<KoveeGovernanceOwnerBinding>(json.clone()).unwrap(),
            row
        );
        // Closed: an unknown member fails.
        let mut widened = json;
        widened["grants_authority"] = Value::Bool(true);
        assert!(serde_json::from_value::<KoveeGovernanceOwnerBinding>(widened).is_err());
        // `none` omits the owner refs entirely (schema oneOf arm 1).
        let none = serde_json::to_value(owner_binding("none")).unwrap();
        assert!(none.get("owner_endpoint_ref").is_none());
        assert!(none.get("cutover_ref").is_none());
    }
}
