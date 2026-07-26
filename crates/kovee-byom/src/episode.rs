//! `ByomEpisodeBinding` and the DUAL fences — the Kovee-side record of
//! one hosted Episode attempt (byom §16.6 item 3, family contract
//! L19–L22/L31/L34–L37, Δ5), and the machine
//! `byom/spec/descriptors/byom-episode-binding.json` commits.
//!
//! What you write (the whole fence rule):
//! ```
//! use kovee_byom::episode::{Fences, FenceError};
//! let bound = Fences { byom: 7, kovee: 3 };
//! bound.check(&Fences { byom: 7, kovee: 3 }).unwrap();     // both current
//! // Either one advancing invalidates the binding for EVERY further
//! // mutation — a successor attempt gets a new binding row.
//! assert_eq!(bound.check(&Fences { byom: 8, kovee: 3 }), Err(FenceError::Byom));
//! assert_eq!(bound.check(&Fences { byom: 7, kovee: 4 }), Err(FenceError::Kovee));
//! ```
//!
//! Plumbing: the four-stage activation (byom §11.1) has four records and
//! four owners, and Kovee owns exactly one of them —
//! [`PlacementBinding`]. A `WakeIntent` is the Participant's; the kernel
//! computes admission and allocates resources; Kovee then places among
//! already-eligible Manifestations and byom's narrow runtime adapter
//! records only the admission. Nothing skips a stage: this module refuses
//! to bind an Episode whose placement was not admitted.
//!
//! The Episode/EpisodeLease lifecycle itself is byom's
//! (`spec/descriptors/episode.json`) — referenced here, never re-owned.
//! This module owns only the Kovee-side binding record.

use kovee_core::family::DigestRef;
use serde::{Deserialize, Serialize};

// -------------------------------------------------------- the two fences ----

/// The DUAL fences (family contract L21/R30): a runtime mutation carrying
/// only ONE of them is invalid, and either one advancing invalidates the
/// binding for every further mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fences {
    /// Byom-side: advanced by a new attempt claim, an activity hold, a
    /// recovery-epoch change, or an endpoint re-incarnation.
    pub byom: u64,
    /// Kovee host-side: the invocation fence.
    pub kovee: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FenceError {
    #[error("the byom fence advanced: this binding is fenced for every further mutation")]
    Byom,
    #[error(
        "the kovee invocation fence advanced: this binding is fenced for every further mutation"
    )]
    Kovee,
}

impl Fences {
    /// Checks a presented pair against the bound pair. Both must match:
    /// presenting one current fence and one stale one is not "mostly
    /// current", it is fenced.
    pub fn check(&self, presented: &Fences) -> Result<(), FenceError> {
        if presented.byom != self.byom {
            return Err(FenceError::Byom);
        }
        if presented.kovee != self.kovee {
            return Err(FenceError::Kovee);
        }
        Ok(())
    }
}

// ------------------------------------------------------ placement stage ----

/// `PlacementBinding` (byom §11.1 stage 4) — the ONE activation record
/// Kovee authors. Byom's runtime adapter records only the matching
/// `PlacementAdmission` after source verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementBinding {
    /// Always `kovee`: the record exists to say who placed.
    pub owner_protocol: String,
    pub placement_id: String,
    pub revision: u64,
    pub resource_allocation_ref: String,
    pub resource_allocation_digest: DigestRef,
    pub selected_manifestation_ref: String,
    pub selected_manifestation_digest: DigestRef,
    pub host_runtime_binding: String,
    pub kovee_invocation_ref: String,
    pub placement_constraint_digest: DigestRef,
    pub kovee_fence_epoch: u64,
    pub state: String,
    pub created_at: String,
    pub digest: DigestRef,
}

/// `PlacementBinding.state`, §11.1 verbatim.
pub const PLACEMENT_STATES: [&str; 4] = ["placed", "started", "released", "failed"];

/// The owner every `PlacementBinding` carries.
pub const PLACEMENT_OWNER: &str = "kovee";

// ------------------------------------------------------ the binding row ----

/// `ByomEpisodeBinding.state` — the Kovee-owned machine
/// (`spec/descriptors/byom-episode-binding.json`). `fenced` and
/// `released` are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingState {
    #[serde(rename = "bound")]
    Bound,
    #[serde(rename = "fenced")]
    Fenced,
    #[serde(rename = "released")]
    Released,
}

impl BindingState {
    pub fn as_str(self) -> &'static str {
        match self {
            BindingState::Bound => "bound",
            BindingState::Fenced => "fenced",
            BindingState::Released => "released",
        }
    }

    pub fn parse(text: &str) -> Option<BindingState> {
        match text {
            "bound" => Some(BindingState::Bound),
            "fenced" => Some(BindingState::Fenced),
            "released" => Some(BindingState::Released),
            _ => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, BindingState::Bound)
    }
}

/// `ByomEpisodeBinding` — the §16.6 item 3 field list verbatim, plus the
/// four family-contract groups the §16.6 block omits (recorded gaps): the
/// L22 idempotency key, the L34–L37 `allowed_local_commitments` set, and
/// the Δ5 context refs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByomEpisodeBinding {
    pub byom_endpoint_ref: String,
    pub endpoint_incarnation: String,
    pub society_ref: String,
    pub recovery_epoch: u64,
    pub participant_ref: String,
    pub participant_binding_epoch: u64,
    pub manifestation_ref: String,
    pub activity_stream_ref: String,
    pub episode_ref: String,
    pub generation: u64,
    pub byom_attempt_ref: String,
    pub byom_fence_epoch: u64,
    pub kovee_invocation_ref: String,
    pub kovee_invocation_fence: u64,
    pub mandate_use_refs: Vec<String>,
    pub context_source_digest: DigestRef,
    pub byom_budget_reservation_ref: String,
    pub byom_budget_reservation_digest: DigestRef,
    pub external_budget_bridge_ref: String,
    pub kovee_subordinate_reservation_ref: String,
    pub kovee_subordinate_reservation_digest: DigestRef,
    pub dependency_digest: DigestRef,
    pub digest: DigestRef,
    /// L22 idempotent-create key: `UNIQUE(episode_ref, byom_attempt_ref,
    /// kovee_invocation_ref)` in code, and an exact retry returns the
    /// identical row.
    pub stable_binding_key: String,
    /// L34–L37: the closed set of local commitment classes the hosted
    /// child may make intra-turn. Anything else goes through
    /// `call_open`/`pledge_propose`/`act_intent_*`.
    pub allowed_local_commitments: Vec<String>,
    pub context_manifest_ref: String,
    pub context_manifest_digest: DigestRef,
    /// The Δ5 optional pairs are all-or-none.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kovee_context_assembly_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kovee_context_assembly_digest: Option<DigestRef>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider_context_manifest_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider_context_manifest_digest: Option<DigestRef>,
}

impl ByomEpisodeBinding {
    pub fn fences(&self) -> Fences {
        Fences {
            byom: self.byom_fence_epoch,
            kovee: self.kovee_invocation_fence,
        }
    }

    /// The all-or-none rule the schema's `oneOf` arms express: a ref
    /// without its digest (or the reverse) is not a half-known context,
    /// it is a malformed row.
    pub fn context_pairs_are_coherent(&self) -> bool {
        self.kovee_context_assembly_ref.is_some() == self.kovee_context_assembly_digest.is_some()
            && self.provider_context_manifest_ref.is_some()
                == self.provider_context_manifest_digest.is_some()
    }
}

/// The closed set of Kovee local-commitment classes a hosted child may
/// make intra-turn (family contract L34–L37).
pub const LOCAL_COMMITMENT_CLASSES: [&str; 3] = [
    "contribution_append",
    "attention_mark",
    "context_assembly_pin",
];

/// Whether every named class is inside the closed set.
pub fn local_commitments_are_closed(classes: &[String]) -> bool {
    classes
        .iter()
        .all(|c| LOCAL_COMMITMENT_CLASSES.contains(&c.as_str()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn digest(seed: &str) -> DigestRef {
        DigestRef::portable_public(format!("{seed:0>64}"))
    }

    fn binding() -> ByomEpisodeBinding {
        ByomEpisodeBinding {
            byom_endpoint_ref: "local".to_owned(),
            endpoint_incarnation: "inc-1".to_owned(),
            society_ref: "soc-1".to_owned(),
            recovery_epoch: 0,
            participant_ref: "part-1".to_owned(),
            participant_binding_epoch: 1,
            manifestation_ref: "man-1".to_owned(),
            activity_stream_ref: "as-1".to_owned(),
            episode_ref: "epi-1".to_owned(),
            generation: 2,
            byom_attempt_ref: "att-1".to_owned(),
            byom_fence_epoch: 7,
            kovee_invocation_ref: "inv-1".to_owned(),
            kovee_invocation_fence: 3,
            mandate_use_refs: vec!["mu-1".to_owned()],
            context_source_digest: digest("a"),
            byom_budget_reservation_ref: "brs-1".to_owned(),
            byom_budget_reservation_digest: digest("b"),
            external_budget_bridge_ref: "ebb-1".to_owned(),
            kovee_subordinate_reservation_ref: "ksr-1".to_owned(),
            kovee_subordinate_reservation_digest: digest("c"),
            dependency_digest: digest("d"),
            digest: digest("e"),
            stable_binding_key: "epi-1|att-1|inv-1".to_owned(),
            allowed_local_commitments: vec!["contribution_append".to_owned()],
            context_manifest_ref: "cm-1".to_owned(),
            context_manifest_digest: digest("f"),
            kovee_context_assembly_ref: None,
            kovee_context_assembly_digest: None,
            provider_context_manifest_ref: None,
            provider_context_manifest_digest: None,
        }
    }

    #[test]
    fn a_mutation_must_present_both_fences_current() {
        let bound = binding().fences();
        bound.check(&Fences { byom: 7, kovee: 3 }).unwrap();
        assert_eq!(
            bound.check(&Fences { byom: 8, kovee: 3 }),
            Err(FenceError::Byom)
        );
        assert_eq!(
            bound.check(&Fences { byom: 7, kovee: 4 }),
            Err(FenceError::Kovee)
        );
        // A stale byom fence is caught even when the Kovee one is stale
        // too — one refusal is enough, and it names the byom side first.
        assert_eq!(
            bound.check(&Fences { byom: 6, kovee: 2 }),
            Err(FenceError::Byom)
        );
    }

    #[test]
    fn the_context_pairs_are_all_or_none() {
        let mut row = binding();
        assert!(row.context_pairs_are_coherent());
        row.kovee_context_assembly_ref = Some("ca-1".to_owned());
        assert!(!row.context_pairs_are_coherent());
        row.kovee_context_assembly_digest = Some(digest("9"));
        assert!(row.context_pairs_are_coherent());
    }

    #[test]
    fn the_binding_round_trips_through_its_closed_shape() {
        let row = binding();
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(
            serde_json::from_value::<ByomEpisodeBinding>(json.clone()).unwrap(),
            row
        );
        // Closed: an unknown member fails rather than being ignored.
        let mut widened = json;
        widened["skips_a_fence"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ByomEpisodeBinding>(widened).is_err());
    }

    #[test]
    fn local_commitments_stay_inside_the_closed_set() {
        assert!(local_commitments_are_closed(&[
            "contribution_append".to_owned()
        ]));
        assert!(!local_commitments_are_closed(
            &["pledge_propose".to_owned()]
        ));
    }

    #[test]
    fn terminal_binding_states_are_terminal() {
        assert!(!BindingState::Bound.is_terminal());
        assert!(BindingState::Fenced.is_terminal());
        assert!(BindingState::Released.is_terminal());
        assert_eq!(BindingState::parse("fenced"), Some(BindingState::Fenced));
        assert_eq!(BindingState::parse("running"), None);
    }
}
