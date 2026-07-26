//! The CROSS-BOUNDARY derivations of the governed-work seam: the
//! `portable_public` SHA-256 tags byom and Kovee compute independently
//! from the same bytes, so §16.3's "the server recomputes it; the
//! request can only match" is a machine check rather than trust.
//!
//! What you write:
//! ```
//! use kovee_byom::hostint;
//! let command = serde_json::json!({"society_ref": "soc-1"});
//! let d = hostint::command_digest(&command).unwrap();
//! assert_eq!(d.class, "portable_public");
//! // A retry re-derives the identical digest from the identical bytes.
//! assert_eq!(d, hostint::command_digest(&command).unwrap());
//! ```
//!
//! Plumbing, and the one thing worth knowing: the governed-work records
//! Kovee keeps in its OWN store carry `scope_erasure_safe` digests (an
//! HMAC under the per-realm governance key — D-R0-1, so destroying that
//! key erases the whole governance scope's verifiability). Those digests
//! are unrecomputable by anyone without the key, which is exactly wrong
//! for a value the counterparty must check. So every field that crosses
//! the seam — the command digest, the credential and its subject, the
//! binding quadruple byomd pins, the proposal/position/slot-snapshot
//! digests — is derived HERE, unkeyed, under byom's own `$domain` tags.
//! One record, two digests, each honest about who can verify it.

use kovee_core::family::{sha256_hex, tagged_canonical, DigestRef};
use serde_json::{json, Value};

use crate::records::{KoveeRealmByomBinding, KoveeSocietyMapping};

/// `$domain` tag of the stable `KoveeEndeavorFormCommand` bytes — the
/// `canonical_command_digest` preimage, covering ONLY the command (never
/// attempt id/nonce, authentication observation/proof, transport request
/// id, or send time; §16.3).
pub const COMMAND_TAG: &str = "bpp-kovee-endeavor-form-command-v0";
/// `$domain` tag of the embedded EndeavorProposal body.
pub const PROPOSAL_TAG: &str = "bpp-kovee-endeavor-proposal-v0";
/// `$domain` tag of the embedded source-principal Position body.
pub const POSITION_TAG: &str = "bpp-kovee-source-principal-position-v0";
/// `$domain` tag of the computed formation slot snapshot.
pub const SLOT_SNAPSHOT_TAG: &str = "bpp-kovee-formation-slot-snapshot-v0";
/// `$domain` tag of the `KoveeEndeavorFormResult` envelope.
pub const RESULT_TAG: &str = "bpp-kovee-endeavor-form-result-v0";
/// `$domain` tag of the `DelegatedPrincipalCredential` (minus `digest`).
pub const CREDENTIAL_TAG: &str = "bpp-delegated-principal-credential-v0";
/// `$domain` tag of the five-fact / three-way result envelopes.
pub const QUERY_RESULT_TAG: &str = "bpp-external-command-result-query-result-v0";
pub const TERMINALIZE_RESULT_TAG: &str = "bpp-external-command-terminalize-result-v0";
/// `$domain` tag of the per-attempt authentication binding (§16.3:
/// `canonical_command_digest || idempotency_domain_digest ||
/// attempt_nonce || attempt_recovery_binding_digest` and the
/// server-derived current actor binding).
pub const ATTEMPT_PROOF_TAG: &str = "bpp-kovee-attempt-authentication-v0";
/// `$domain` tag of the wire projections of the two host binding records.
pub const WIRE_BINDING_TAG: &str = "bpp-kovee-realm-byom-binding-v0";
pub const WIRE_MAPPING_TAG: &str = "bpp-kovee-society-mapping-v0";
/// `$domain` tag of the recovery-policy projection the wire binding pins.
pub const WIRE_POLICY_TAG: &str = "bpp-kovee-recovery-policy-v0";
/// `$domain` tag of the source-actor binding a delegated principal is
/// bound to (`source_actor_binding_digest`).
pub const ACTOR_BINDING_TAG: &str = "bpp-kovee-source-actor-binding-v0";
/// `$domain` tag of one authentication observation.
pub const OBSERVATION_TAG: &str = "bpp-kovee-authentication-observation-v0";

/// The transport-preamble prefix carrying a `DelegatedPrincipalCredential`
/// on byomd's governance socket. The credential is CHANNEL material: the
/// closed per-operation request schemas carry no credential member.
pub const DPC_PREAMBLE_PREFIX: &str = "dpc1.";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("cross-boundary digest: {0}")]
pub struct HostIntError(String);

/// A `portable_public` SHA-256 digest over one object's `$domain`-tagged
/// JCS bytes.
pub fn portable_digest(tag: &str, object: &Value) -> Result<DigestRef, HostIntError> {
    let preimage = tagged_canonical(tag, object).map_err(|e| HostIntError(e.to_string()))?;
    Ok(DigestRef::portable_public(sha256_hex(&preimage)))
}

/// The digest a self-describing record carries over itself: the record
/// minus its own `digest` member, `$domain`-tagged.
pub fn self_digest(tag: &str, record: &Value) -> Result<DigestRef, HostIntError> {
    let mut projected = record.clone();
    if let Some(map) = projected.as_object_mut() {
        map.remove("digest");
    }
    portable_digest(tag, &projected)
}

/// `canonical_command_digest` over the stable command bytes (§16.3).
pub fn command_digest(command: &Value) -> Result<DigestRef, HostIntError> {
    portable_digest(COMMAND_TAG, command)
}

/// The `$domain`-tagged attempt-authentication binding (§16.3). The
/// developer profile presents it as `ap1.<64 hex>`; the endpoint
/// recomputes it exactly, so a replaced command, nonce, recovery binding,
/// or actor binding cannot ride an old proof.
pub fn attempt_proof(
    canonical_command_digest: &DigestRef,
    idempotency_domain_digest: &DigestRef,
    attempt_nonce: &str,
    attempt_recovery_binding_digest: &DigestRef,
    source_actor_binding_digest: &DigestRef,
) -> Result<String, HostIntError> {
    let bound = json!({
        "canonical_command_digest": canonical_command_digest.value_hex,
        "idempotency_domain_digest": idempotency_domain_digest.value_hex,
        "attempt_nonce": attempt_nonce,
        "attempt_recovery_binding_digest": attempt_recovery_binding_digest.value_hex,
        "source_actor_binding_digest": source_actor_binding_digest.value_hex,
    });
    let preimage =
        tagged_canonical(ATTEMPT_PROOF_TAG, &bound).map_err(|e| HostIntError(e.to_string()))?;
    Ok(format!("ap1.{}", sha256_hex(&preimage)))
}

/// The computed formation slot snapshot (§16.3: the server recomputes it,
/// the request can only match). It names no server-minted id, so Kovee
/// derives the identical bytes from the proposal it authored.
pub fn slot_snapshot(
    society_ref: &str,
    society_recovery_epoch: u64,
    governance_rule_set_ref: &str,
    endeavor_proposal_digest: &DigestRef,
    sponsor_participant_refs: &[String],
) -> Value {
    let mut seats: Vec<Value> = sponsor_participant_refs
        .iter()
        .map(|p| json!({"kind": "sponsor", "participant_ref": p, "surface": "participant"}))
        .collect();
    seats.sort_by_key(|s| s["participant_ref"].as_str().unwrap_or_default().to_owned());
    json!({
        "society_ref": society_ref,
        "society_recovery_epoch": society_recovery_epoch,
        "governance_rule_set_ref": governance_rule_set_ref,
        "endeavor_proposal_digest": endeavor_proposal_digest,
        "required_seats": seats,
    })
}

/// The `source_actor_binding_digest`: the durable (realm, principal,
/// Participant, binding epoch) tuple both sides pin.
pub fn actor_binding_digest(
    realm_ref: &str,
    source_principal_ref: &str,
    bound_participant_ref: &str,
    participant_binding_epoch: u64,
) -> Result<DigestRef, HostIntError> {
    portable_digest(
        ACTOR_BINDING_TAG,
        &json!({
            "realm_ref": realm_ref,
            "source_principal_ref": source_principal_ref,
            "bound_participant_ref": bound_participant_ref,
            "participant_binding_epoch": participant_binding_epoch,
        }),
    )
}

/// One authentication observation's digest.
pub fn observation_digest(
    observation_ref: &str,
    assurance_level: &str,
    observed_at: &str,
) -> Result<DigestRef, HostIntError> {
    portable_digest(
        OBSERVATION_TAG,
        &json!({
            "authentication_observation_ref": observation_ref,
            "assurance_level": assurance_level,
            "observed_at": observed_at,
        }),
    )
}

// ------------------------------------------------ the wire projections ----

/// The byom-wire projection of a `KoveeRealmByomBinding`: the same
/// identity and members, with every digest re-derived in the
/// `portable_public` class the counterparty can recompute. Kovee's stored
/// row keeps its `scope_erasure_safe` digests untouched.
pub fn wire_binding(binding: &KoveeRealmByomBinding) -> Result<Value, HostIntError> {
    let policy = portable_digest(
        WIRE_POLICY_TAG,
        &json!({
            "policy_ref": binding.recovery_authorization_policy_ref,
            "mode": binding.historical_recovery_mode,
        }),
    )?;
    let mut row = json!({
        "binding_ref": binding.binding_ref,
        "realm_ref": binding.realm_ref,
        "binding_revision": binding.binding_revision,
        "binding_epoch": binding.binding_epoch,
        "byom_endpoint_ref": binding.byom_endpoint_ref,
        "endpoint_incarnation": binding.endpoint_incarnation,
        "compatibility_bundle": binding.compatibility_bundle,
        "delegated_principal_audience": binding.delegated_principal_audience,
        "external_authorization_audience": binding.external_authorization_audience,
        "historical_recovery_mode": binding.historical_recovery_mode,
        "recovery_authorization_policy_ref": binding.recovery_authorization_policy_ref,
        "recovery_authorization_policy_digest": policy,
        "status": binding.status,
        "dependency_digest": portable_digest(
            WIRE_BINDING_TAG,
            &json!({"dependency_of": binding.binding_ref, "epoch": binding.binding_epoch}),
        )?,
    });
    let digest = self_digest(WIRE_BINDING_TAG, &row)?;
    row["digest"] = serde_json::to_value(&digest).unwrap_or(Value::Null);
    Ok(row)
}

/// The four-member binding pin byomd checks on every use (§16.6 item 1;
/// family contract L8): ref, revision, epoch, digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingPin {
    pub binding_ref: String,
    pub binding_revision: u64,
    pub binding_epoch: u64,
    pub digest: DigestRef,
}

impl BindingPin {
    /// Reads the pin off a wire projection.
    pub fn of(wire: &Value) -> Result<BindingPin, HostIntError> {
        let text = |k: &str| {
            wire.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| HostIntError(format!("wire binding has no {k}")))
        };
        let number = |k: &str| {
            wire.get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| HostIntError(format!("wire binding has no {k}")))
        };
        Ok(BindingPin {
            binding_ref: text("binding_ref")?,
            binding_revision: number("binding_revision")?,
            binding_epoch: number("binding_epoch")?,
            digest: serde_json::from_value(wire.get("digest").cloned().unwrap_or(Value::Null))
                .map_err(|e| HostIntError(e.to_string()))?,
        })
    }

    pub fn as_json(&self) -> Value {
        json!({
            "binding_ref": self.binding_ref,
            "binding_revision": self.binding_revision,
            "binding_epoch": self.binding_epoch,
            "digest": self.digest,
        })
    }
}

/// The byom-wire projection of a `KoveeSocietyMapping`.
pub fn wire_mapping(mapping: &KoveeSocietyMapping) -> Result<Value, HostIntError> {
    let owner = portable_digest(
        WIRE_MAPPING_TAG,
        &json!({
            "owner_binding_ref": mapping.governance_owner_binding_ref,
            "revision": mapping.revision,
        }),
    )?;
    let mut row = json!({
        "realm_ref": mapping.realm_ref,
        "society_ref": mapping.society_ref,
        "society_recovery_epoch": mapping.society_recovery_epoch,
        "allowed_project_and_space_selectors": mapping.allowed_project_and_space_selectors,
        "classification_binding_ref": mapping.classification_binding_ref,
        "governance_owner_binding_ref": mapping.governance_owner_binding_ref,
        "governance_owner_binding_digest": owner,
        "status": mapping.status,
        "revision": mapping.revision,
    });
    let digest = self_digest(WIRE_MAPPING_TAG, &row)?;
    row["digest"] = serde_json::to_value(&digest).unwrap_or(Value::Null);
    Ok(row)
}

/// The whole `<byom-data-dir>/kovee/host-binding.json` document: the
/// inert context amendment A2 lets Kovee supply. It is CONFIGURATION —
/// byomd re-validates every field on every use, and no Kovee operation
/// can author Society state through it.
pub fn host_binding_document(
    binding: &KoveeRealmByomBinding,
    mapping: &KoveeSocietyMapping,
    issuer_refs: &[String],
    endpoint_root_id: &str,
) -> Result<Value, HostIntError> {
    let wire = wire_binding(binding)?;
    let pin = BindingPin::of(&wire)?;
    Ok(json!({
        "realm_byom_binding": wire,
        "society_mapping": wire_mapping(mapping)?,
        "delegated_principal_issuers": issuer_refs,
        "recovery_binding": pin.as_json(),
        "endpoint_root_id": endpoint_root_id,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::records::sample_active_binding;

    #[test]
    fn the_command_digest_covers_only_the_command_bytes() {
        let a = command_digest(&json!({"society_ref": "soc-1", "n": 1})).unwrap();
        let b = command_digest(&json!({"n": 1, "society_ref": "soc-1"})).unwrap();
        assert_eq!(a, b, "member order is canonicalized away");
        assert_eq!(a.class, "portable_public");
        assert_eq!(a.algorithm, "sha-256");
        assert!(a.key_ref.is_none(), "a cross-boundary digest is unkeyed");
        assert_ne!(a, command_digest(&json!({"n": 2})).unwrap());
    }

    #[test]
    fn a_fresh_nonce_changes_the_attempt_proof_but_not_the_command() {
        let d = DigestRef::portable_public("a".repeat(64));
        let domain = DigestRef::scope_erasure_safe("k", "b".repeat(64));
        let one = attempt_proof(&d, &domain, "nonce-1", &d, &d).unwrap();
        let two = attempt_proof(&d, &domain, "nonce-2", &d, &d).unwrap();
        assert_ne!(one, two);
        assert!(one.starts_with("ap1."));
        assert_eq!(one.len(), 4 + 64);
    }

    #[test]
    fn the_wire_binding_is_portable_where_the_stored_row_is_scope_keyed() {
        let stored = sample_active_binding();
        // The stored row's digests are keyed: nobody without the realm
        // governance key can recompute them.
        assert_eq!(stored.digest.class, "scope_erasure_safe");
        let wire = wire_binding(&stored).unwrap();
        for key in [
            "digest",
            "dependency_digest",
            "recovery_authorization_policy_digest",
        ] {
            assert_eq!(wire[key]["class"], json!("portable_public"), "{key}");
            assert_eq!(wire[key]["algorithm"], json!("sha-256"), "{key}");
            assert!(wire[key].get("key_ref").is_none(), "{key}");
        }
        // And the wire digest genuinely covers the wire bytes.
        assert_eq!(
            self_digest(WIRE_BINDING_TAG, &wire).unwrap(),
            serde_json::from_value::<DigestRef>(wire["digest"].clone()).unwrap()
        );
        let pin = BindingPin::of(&wire).unwrap();
        assert_eq!(pin.binding_ref, stored.binding_ref);
        assert_eq!(pin.binding_epoch, stored.binding_epoch);
    }

    #[test]
    fn the_slot_snapshot_sorts_its_seats() {
        let proposal = DigestRef::portable_public("c".repeat(64));
        let one = slot_snapshot(
            "soc-1",
            0,
            "rules-1",
            &proposal,
            &["part-b".to_owned(), "part-a".to_owned()],
        );
        let two = slot_snapshot(
            "soc-1",
            0,
            "rules-1",
            &proposal,
            &["part-a".to_owned(), "part-b".to_owned()],
        );
        assert_eq!(one, two);
        assert_eq!(one["required_seats"][0]["participant_ref"], json!("part-a"));
    }
}
