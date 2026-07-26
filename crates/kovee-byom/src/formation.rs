//! The `EndeavorFormationIntent` / `Slot` / `Attempt` machine — the
//! Kovee-owned half of §16.3, exactly as
//! `byom/spec/descriptors/endeavor-formation.json` commits it.
//!
//! What you write (the whole recovery decision, in one call):
//! ```
//! use kovee_byom::formation::{Fact, IntentState, Move, resolve};
//! // A verified `absent` says only "nothing there NOW" — it can never
//! // release the slot, because a delayed command may still commit.
//! let step = resolve(IntentState::Submitting, &Fact::Absent).unwrap();
//! assert_eq!(step.intent, IntentState::AwaitingPrincipal);
//! assert!(!step.releases_slot);
//! // A verified tombstone is Byom's terminal claim over the exact
//! // IdempotencyDomain: only THAT releases it.
//! let step = resolve(IntentState::Ambiguous, &Fact::Tombstone).unwrap();
//! assert_eq!(step.intent, IntentState::Canceled);
//! assert!(step.releases_slot);
//! assert_eq!(step.via, Move::TombstoneVerified);
//! ```
//!
//! Plumbing worth knowing:
//!
//! - the intent and slot states are ONE machine — every row CASes both
//!   under the slot generation, and [`Step::slot`] is the paired slot
//!   state, never an independent decision;
//! - exactly four things release a slot: a pre-send cancel, a verified
//!   tombstone, a verified `historically_fenced_absent`, and a committed
//!   ExternalLink. Timeout, absence, authentication expiry, binding
//!   rotation, an unverified historical lookup, and `ambiguous` never do;
//! - the attempt machine is separate and append-only: resolving an intent
//!   never rewrites an earlier attempt's send/authentication evidence.

use kovee_core::family::DigestRef;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hostint::{self, HostIntError};

// ------------------------------------------------------------- states ----

macro_rules! wire_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            $(#[serde(rename = $text)] $variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }

            pub fn parse(text: &str) -> Option<$name> {
                match text { $($text => Some($name::$variant),)+ _ => None }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

wire_enum! {
    /// `EndeavorFormationIntent.state`, §16.3 verbatim. `linked` and
    /// `canceled` are terminal.
    IntentState {
        Prepared => "prepared",
        Submitting => "submitting",
        RemoteUnknown => "remote_unknown",
        AwaitingPrincipal => "awaiting_principal",
        ByomCommitted => "byom_committed",
        Linking => "linking",
        Linked => "linked",
        Ambiguous => "ambiguous",
        Canceled => "canceled",
    }
}

wire_enum! {
    /// `EndeavorFormationSlot.state`, §16.3 verbatim. It pairs with the
    /// intent through the closed recovery machine (held↔prepared,
    /// released↔canceled/linked, others 1:1).
    SlotState {
        Held => "held",
        Submitting => "submitting",
        RemoteUnknown => "remote_unknown",
        AwaitingPrincipal => "awaiting_principal",
        ByomCommitted => "byom_committed",
        Linking => "linking",
        Ambiguous => "ambiguous",
        Released => "released",
    }
}

wire_enum! {
    /// `EndeavorFormationAttempt.state`, §16.3 verbatim.
    AttemptState {
        Prepared => "prepared",
        Sent => "sent",
        ReplyReceived => "reply_received",
        TransportUnknown => "transport_unknown",
        Reconciled => "reconciled",
        Canceled => "canceled",
    }
}

wire_enum! {
    /// The descriptor's `via` labels — the transition names, so a Kovee
    /// event carries the machine's own word for what happened.
    Move {
        FormationPrepare => "formation_prepare",
        FormationCancel => "formation_cancel",
        KoveeEndeavorForm => "kovee_endeavor_form",
        TransportOutcomeUnknown => "transport_outcome_unknown",
        CommittedResultVerified => "committed_result_verified",
        AbsenceVerified => "absence_verified",
        UnknownResult => "unknown_result",
        TombstoneVerified => "tombstone_verified",
        HistoricallyFencedAbsentVerified => "historically_fenced_absent_verified",
        TerminalizeNotTerminalizable => "terminalize_not_terminalizable",
        ExternalLinkBegin => "external_link_begin",
        ExternalLinkRetry => "external_link_retry",
        ExternalLinkCommit => "external_link_commit",
    }
}

impl IntentState {
    /// The paired slot state (the closed 1:1 mapping of the descriptor).
    pub fn slot(self) -> SlotState {
        match self {
            IntentState::Prepared => SlotState::Held,
            IntentState::Submitting => SlotState::Submitting,
            IntentState::RemoteUnknown => SlotState::RemoteUnknown,
            IntentState::AwaitingPrincipal => SlotState::AwaitingPrincipal,
            IntentState::ByomCommitted => SlotState::ByomCommitted,
            IntentState::Linking => SlotState::Linking,
            IntentState::Ambiguous => SlotState::Ambiguous,
            IntentState::Linked | IntentState::Canceled => SlotState::Released,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, IntentState::Linked | IntentState::Canceled)
    }
}

// -------------------------------------------------------- the five facts ----

/// One `ExternalCommandResultQuery` answer — §16.3's five-fact union,
/// plus the two non-`committed` terminalization outcomes that drive the
/// same machine rows.
#[derive(Debug, Clone, PartialEq)]
pub enum Fact {
    /// A valid signed `KoveeEndeavorFormResult` envelope.
    Committed(Box<CommittedResult>),
    /// A complete query of the LIVE target domain found neither result
    /// nor tombstone. It proves nothing about later arrival.
    Absent,
    /// A complete externally witnessed `RestoreLineageProof` found no row
    /// and every predecessor execution domain is permanently fenced.
    HistoricallyFencedAbsent { receipt_ref: String },
    /// Byom's durable terminal claim over the exact IdempotencyDomain.
    Tombstone,
    /// In-flight, incomplete retention, unavailable, or unverifiable.
    Unknown,
    /// `external_command_terminalize` answered `not_terminalizable` with
    /// one closed blocking state — a Byom no-op.
    NotTerminalizable { blocking_state: String },
}

/// The verified `committed` fact: the retained signed envelope, its
/// digest, and the endpoint signature, carried UNMODIFIED.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommittedResult {
    pub envelope: Value,
    pub digest: DigestRef,
    pub signature: String,
}

impl CommittedResult {
    pub fn endeavor_ref(&self) -> Option<&str> {
        self.envelope.get("endeavor_ref").and_then(Value::as_str)
    }

    /// Re-derives the envelope's own digest from its exact bytes: the
    /// `committed` fact is verified, not trusted (§16.3 table row 4).
    pub fn verify(&self) -> Result<(), FactError> {
        if self.signature.is_empty() {
            return Err(FactError(
                "committed fact carries no server signature".into(),
            ));
        }
        let recomputed = hostint::self_digest(hostint::RESULT_TAG, &self.envelope)
            .map_err(|e| FactError(e.to_string()))?;
        let carried: DigestRef =
            serde_json::from_value(self.envelope.get("digest").cloned().unwrap_or(Value::Null))
                .map_err(|_| FactError("committed envelope carries no typed digest".into()))?;
        if recomputed != carried || carried != self.digest {
            return Err(FactError(
                "the committed envelope digest does not cover these exact bytes".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("external command fact: {0}")]
pub struct FactError(String);

impl From<HostIntError> for FactError {
    fn from(e: HostIntError) -> FactError {
        FactError(e.to_string())
    }
}

impl Fact {
    /// Reads one five-fact union off byomd's reply. The status-specific
    /// members are closed, so a `committed` arm carrying a tombstone (or
    /// the reverse) is refused rather than partly believed.
    pub fn from_query_result(result: &Value) -> Result<Fact, FactError> {
        let status = result
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| FactError("the query result carries no status".into()))?;
        let forbid = |keys: &[&str]| -> Result<(), FactError> {
            for key in keys {
                if result.get(*key).is_some_and(|v| !v.is_null()) {
                    return Err(FactError(format!("status {status:?} forbids {key}")));
                }
            }
            Ok(())
        };
        match status {
            "committed" => {
                forbid(&["tombstone_ref", "historical_fence_receipt_ref"])?;
                let committed = CommittedResult {
                    envelope: result
                        .get("committed_result_envelope")
                        .cloned()
                        .ok_or_else(|| FactError("committed carries no result envelope".into()))?,
                    digest: serde_json::from_value(
                        result
                            .get("committed_result_digest")
                            .cloned()
                            .unwrap_or(Value::Null),
                    )
                    .map_err(|_| FactError("committed carries no typed result digest".into()))?,
                    signature: result
                        .get("committed_result_signature")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                };
                committed.verify()?;
                Ok(Fact::Committed(Box::new(committed)))
            }
            "absent" => {
                forbid(&[
                    "committed_result_envelope",
                    "tombstone_ref",
                    "historical_fence_receipt_ref",
                    "restore_lineage_evidence_ref",
                ])?;
                Ok(Fact::Absent)
            }
            "historically_fenced_absent" => {
                forbid(&["committed_result_envelope", "tombstone_ref"])?;
                let receipt_ref = result
                    .get("historical_fence_receipt_ref")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        FactError("historically_fenced_absent carries no fence receipt".into())
                    })?;
                if result.get("restore_lineage_evidence_ref").is_none() {
                    return Err(FactError(
                        "historically_fenced_absent carries no RestoreLineage evidence".into(),
                    ));
                }
                Ok(Fact::HistoricallyFencedAbsent {
                    receipt_ref: receipt_ref.to_owned(),
                })
            }
            "non_reexecuting_tombstone" => {
                forbid(&["committed_result_envelope", "historical_fence_receipt_ref"])?;
                if result.get("tombstone_ref").is_none() {
                    return Err(FactError("the tombstone fact carries no ref".into()));
                }
                Ok(Fact::Tombstone)
            }
            "unknown" => {
                forbid(&[
                    "committed_result_envelope",
                    "tombstone_ref",
                    "historical_fence_receipt_ref",
                ])?;
                Ok(Fact::Unknown)
            }
            other => Err(FactError(format!("{other:?} is not one of the five facts"))),
        }
    }

    /// The same reading for `external_command_terminalize`'s closed
    /// three-way union: `committed` and `not_terminalizable` are Byom
    /// no-ops, only `terminalized` supplies the tombstone.
    pub fn from_terminalize_result(result: &Value) -> Result<Fact, FactError> {
        match result.get("status").and_then(Value::as_str) {
            Some("committed") => {
                let committed = CommittedResult {
                    envelope: result
                        .get("committed_result_envelope")
                        .cloned()
                        .ok_or_else(|| FactError("committed carries no result envelope".into()))?,
                    digest: serde_json::from_value(
                        result
                            .get("committed_result_digest")
                            .cloned()
                            .unwrap_or(Value::Null),
                    )
                    .map_err(|_| FactError("committed carries no typed result digest".into()))?,
                    signature: result
                        .get("committed_result_signature")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                };
                committed.verify()?;
                Ok(Fact::Committed(Box::new(committed)))
            }
            Some("terminalized") => {
                if result.get("authority_journal_receipt_ref").is_none() {
                    return Err(FactError(
                        "terminalized carries no synchronous AuthorityJournalReceipt".into(),
                    ));
                }
                Ok(Fact::Tombstone)
            }
            Some("not_terminalizable") => {
                let blocking_state = result
                    .get("blocking_state")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        FactError("not_terminalizable names no blocking state".into())
                    })?;
                if !BLOCKING_STATES.contains(&blocking_state) {
                    return Err(FactError(format!(
                        "{blocking_state:?} is not a closed blocking state"
                    )));
                }
                Ok(Fact::NotTerminalizable {
                    blocking_state: blocking_state.to_owned(),
                })
            }
            other => Err(FactError(format!(
                "{other:?} is not a terminalization outcome"
            ))),
        }
    }
}

/// §16.3's closed `not_terminalizable` blocking states.
pub const BLOCKING_STATES: [&str; 4] = [
    "prepared_or_in_flight",
    "lineage_incomplete",
    "witness_unavailable",
    "domain_conflict",
];

// ---------------------------------------------------------- the machine ----

/// One committed row of the machine: the new paired states, the
/// descriptor's own `via` label, and whether the slot releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    pub intent: IntentState,
    pub slot: SlotState,
    pub via: Move,
    pub releases_slot: bool,
}

impl Step {
    fn to(intent: IntentState, via: Move) -> Step {
        Step {
            intent,
            slot: intent.slot(),
            via,
            releases_slot: intent.is_terminal(),
        }
    }
}

/// Applying one verified fact to the current intent state. `None` is the
/// honest answer for a fact this state has no row for — rejection is the
/// absence of a transition, never an invented one.
pub fn resolve(state: IntentState, fact: &Fact) -> Option<Step> {
    use IntentState as S;
    match fact {
        // Table row 4 — a valid signed result envelope, from anywhere.
        Fact::Committed(_) => match state {
            S::Prepared
            | S::Submitting
            | S::RemoteUnknown
            | S::AwaitingPrincipal
            | S::Ambiguous
            | S::ByomCommitted => Some(Step::to(S::ByomCommitted, Move::CommittedResultVerified)),
            // Row 10: repeated committed facts leave a linking pair alone.
            S::Linking => Some(Step::to(S::Linking, Move::CommittedResultVerified)),
            S::Linked | S::Canceled => None,
        },
        // Table row 5 — live absence. NO release, ever.
        Fact::Absent => match state {
            S::Submitting | S::RemoteUnknown | S::AwaitingPrincipal | S::Ambiguous => {
                Some(Step::to(S::AwaitingPrincipal, Move::AbsenceVerified))
            }
            _ => None,
        },
        // Table row 6 — unknown, invalid, or incomplete lineage.
        Fact::Unknown => match state {
            S::Submitting | S::RemoteUnknown | S::AwaitingPrincipal | S::Ambiguous => {
                Some(Step::to(S::Ambiguous, Move::UnknownResult))
            }
            _ => None,
        },
        // Table row 7 — the verified non-reexecuting tombstone releases.
        Fact::Tombstone => match state {
            S::Prepared
            | S::Submitting
            | S::RemoteUnknown
            | S::AwaitingPrincipal
            | S::Ambiguous => Some(Step::to(S::Canceled, Move::TombstoneVerified)),
            _ => None,
        },
        // Table row 8 — a complete witnessed fence receipt releases.
        Fact::HistoricallyFencedAbsent { .. } => match state {
            S::Prepared
            | S::Submitting
            | S::RemoteUnknown
            | S::AwaitingPrincipal
            | S::Ambiguous => Some(Step::to(
                S::Canceled,
                Move::HistoricallyFencedAbsentVerified,
            )),
            _ => None,
        },
        // Table row 9 — a Byom no-op: the pair is unchanged.
        Fact::NotTerminalizable { .. } => match state {
            S::Submitting | S::RemoteUnknown | S::AwaitingPrincipal | S::Ambiguous => {
                Some(Step::to(state, Move::TerminalizeNotTerminalizable))
            }
            _ => None,
        },
    }
}

/// Whether a resubmission is admissible from this state (descriptor rows
/// `prepared → submitting` and `awaiting_principal → submitting`). Every
/// other state either has nothing to send or has already committed.
pub fn may_submit(state: IntentState) -> bool {
    matches!(
        state,
        IntentState::Prepared | IntentState::AwaitingPrincipal
    )
}

/// Whether a local cancel is still admissible: ONLY from `prepared`, and
/// only while no slot has been acquired for a send (table row 1).
pub fn may_cancel(state: IntentState) -> bool {
    state == IntentState::Prepared
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    fn committed_envelope() -> Value {
        let mut envelope = json!({
            "kovee_formation_intent_ref": "efi-1",
            "endeavor_ref": "end-1",
            "endeavor_revision": 1,
        });
        let digest = hostint::self_digest(hostint::RESULT_TAG, &envelope).unwrap();
        envelope["digest"] = serde_json::to_value(&digest).unwrap();
        envelope
    }

    fn committed_fact() -> Value {
        let envelope = committed_envelope();
        json!({
            "status": "committed",
            "committed_result_envelope": envelope.clone(),
            "committed_result_digest": envelope["digest"],
            "committed_result_signature": "sig1.aa",
        })
    }

    #[test]
    fn only_four_things_release_the_slot() {
        // Cancel-before-send is the pre-send release; the other three are
        // facts. Every other row holds the slot.
        let released: Vec<(IntentState, &Fact)> = vec![
            (IntentState::Ambiguous, &Fact::Tombstone),
            (IntentState::Submitting, &Fact::Tombstone),
        ];
        for (state, fact) in released {
            assert!(resolve(state, fact).unwrap().releases_slot);
        }
        let fenced = Fact::HistoricallyFencedAbsent {
            receipt_ref: "hfr-1".to_owned(),
        };
        assert!(
            resolve(IntentState::RemoteUnknown, &fenced)
                .unwrap()
                .releases_slot
        );
        for (state, fact) in [
            (IntentState::Submitting, Fact::Absent),
            (IntentState::RemoteUnknown, Fact::Unknown),
            (IntentState::Ambiguous, Fact::Unknown),
            (
                IntentState::AwaitingPrincipal,
                Fact::NotTerminalizable {
                    blocking_state: "prepared_or_in_flight".to_owned(),
                },
            ),
        ] {
            let step = resolve(state, &fact).unwrap();
            assert!(!step.releases_slot, "{state} + {fact:?} must not release");
            assert_ne!(step.slot, SlotState::Released);
        }
    }

    #[test]
    fn a_not_terminalizable_answer_changes_nothing() {
        for state in [
            IntentState::Submitting,
            IntentState::RemoteUnknown,
            IntentState::AwaitingPrincipal,
            IntentState::Ambiguous,
        ] {
            let step = resolve(
                state,
                &Fact::NotTerminalizable {
                    blocking_state: "domain_conflict".to_owned(),
                },
            )
            .unwrap();
            assert_eq!(step.intent, state);
            assert_eq!(step.via, Move::TerminalizeNotTerminalizable);
        }
    }

    #[test]
    fn the_committed_fact_is_verified_not_trusted() {
        let fact = Fact::from_query_result(&committed_fact()).unwrap();
        let Fact::Committed(result) = &fact else {
            panic!("expected committed, got {fact:?}")
        };
        assert_eq!(result.endeavor_ref(), Some("end-1"));

        // One edited byte and the digest no longer covers the envelope.
        let mut tampered = committed_fact();
        tampered["committed_result_envelope"]["endeavor_ref"] = json!("end-999");
        assert!(Fact::from_query_result(&tampered).is_err());
        // A missing signature is refused too.
        let mut unsigned = committed_fact();
        unsigned["committed_result_signature"] = json!("");
        assert!(Fact::from_query_result(&unsigned).is_err());
    }

    #[test]
    fn the_status_specific_fields_are_closed() {
        // `absent` is exactly "nothing here now" — it may not smuggle a
        // fence receipt that would release the slot.
        let smuggled = json!({
            "status": "absent",
            "historical_fence_receipt_ref": "hfr-1",
        });
        assert!(Fact::from_query_result(&smuggled).is_err());
        // And `historically_fenced_absent` without its evidence is not a
        // fenced absence at all.
        let bare = json!({"status": "historically_fenced_absent"});
        assert!(Fact::from_query_result(&bare).is_err());
        let complete = json!({
            "status": "historically_fenced_absent",
            "restore_lineage_evidence_ref": "rlp-1",
            "historical_fence_receipt_ref": "hfr-1",
        });
        assert_eq!(
            Fact::from_query_result(&complete).unwrap(),
            Fact::HistoricallyFencedAbsent {
                receipt_ref: "hfr-1".to_owned()
            }
        );
    }

    #[test]
    fn a_terminalization_reads_its_own_closed_union() {
        let terminalized = json!({
            "status": "terminalized",
            "tombstone_ref": "tomb-1",
            "authority_journal_receipt_ref": "ajr-1",
        });
        assert_eq!(
            Fact::from_terminalize_result(&terminalized).unwrap(),
            Fact::Tombstone
        );
        // A tombstone without the synchronous journal receipt is refused.
        let no_receipt = json!({"status": "terminalized", "tombstone_ref": "tomb-1"});
        assert!(Fact::from_terminalize_result(&no_receipt).is_err());
        // An unlisted blocking state is not a closed blocking state.
        let odd = json!({"status": "not_terminalizable", "blocking_state": "because"});
        assert!(Fact::from_terminalize_result(&odd).is_err());
    }

    #[test]
    fn terminal_pairs_never_leave_terminal() {
        for state in [IntentState::Linked, IntentState::Canceled] {
            for fact in [Fact::Absent, Fact::Unknown, Fact::Tombstone] {
                assert!(resolve(state, &fact).is_none(), "{state} moved on {fact:?}");
            }
            assert!(!may_submit(state));
            assert!(!may_cancel(state));
        }
    }

    #[test]
    fn resubmission_and_cancel_have_exactly_their_descriptor_rows() {
        assert!(may_submit(IntentState::Prepared));
        assert!(may_submit(IntentState::AwaitingPrincipal));
        for state in [
            IntentState::Submitting,
            IntentState::RemoteUnknown,
            IntentState::ByomCommitted,
            IntentState::Ambiguous,
        ] {
            assert!(!may_submit(state), "{state} may not resubmit");
        }
        assert!(may_cancel(IntentState::Prepared));
        // After bytes may have left, cancel is not a row of this machine.
        assert!(!may_cancel(IntentState::Submitting));
        assert!(!may_cancel(IntentState::Ambiguous));
    }

    #[test]
    fn the_slot_pairing_is_the_closed_mapping() {
        assert_eq!(IntentState::Prepared.slot(), SlotState::Held);
        assert_eq!(IntentState::Linked.slot(), SlotState::Released);
        assert_eq!(IntentState::Canceled.slot(), SlotState::Released);
        for state in [
            IntentState::Submitting,
            IntentState::RemoteUnknown,
            IntentState::AwaitingPrincipal,
            IntentState::ByomCommitted,
            IntentState::Ambiguous,
            IntentState::Linking,
        ] {
            assert_eq!(state.slot().as_str(), state.as_str(), "1:1 for {state}");
        }
    }
}
