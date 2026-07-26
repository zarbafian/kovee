//! The permit gate: **no byte leaves without a valid byom
//! `ExecutionConsumptionReceipt` for this exact execution key.**
//!
//! The act chain is byom's — `act_intent_prepare` → `act_intent_position`
//! → `act_intent_finalize` produce ONE `GovernanceDecision`, and Kovee
//! neither authors nor widens it. Kovee's broker does exactly one thing on
//! that surface: it calls `execution_permit_consume` with the stable
//! execution key of an already-committed local Effect, and stores the one
//! immutable receipt byom returns (§16.1 steps 1-4, byom R34).
//!
//! [`authorize`] is the fail-closed gate over that receipt. It is a pure
//! function so the refusals are unit-provable and identical wherever the
//! broker runs:
//!
//! | refusal | cause |
//! |---|---|
//! | [`PermitError::NoPermit`] | no receipt at all — nothing was consumed |
//! | [`PermitError::SpentPermit`] | `max_uses: 1` already spent by a dispatched attempt |
//! | [`PermitError::NotOneShot`] | a receipt claiming more than one use |
//! | [`PermitError::WrongExecutionKey`] | a receipt for another effect's key |
//! | [`PermitError::WrongAudience`] | a receipt minted for another driver |
//! | [`PermitError::SubjectMismatch`] | the authorized subject is not this effect's |
//! | [`PermitError::DisclosureMismatch`] | a different disclosure than the one authorized |
//! | [`PermitError::StaleFence`] | either fence advanced since consumption |
//! | [`PermitError::EpisodeMismatch`] | another Episode, or an unbound episode-scoped call |
//! | [`PermitError::Expired`] | the receipt's own deadline passed |
//! | [`PermitError::WrongEndpoint`] | another byomd incarnation or recovery epoch |
//!
//! What you write:
//! ```
//! use kovee_effects::{authorize, Expectation, PermitError};
//! # use kovee_core::family::DigestRef;
//! # let subject = DigestRef::portable_public("11".repeat(32));
//! # let disclosure = DigestRef::portable_public("22".repeat(32));
//! let expect = Expectation {
//!     execution_key: "exec-abc", subject_digest: &subject,
//!     disclosure_digest: &disclosure,
//!     driver_audience: kovee_effects::BROKER_DRIVER_AUDIENCE,
//!     episode: None, endpoint_incarnation: "inst-1", recovery_epoch: 0,
//!     now: 1_800_000_000, already_spent: false,
//! };
//! // No receipt, no call. This is the whole point of the broker.
//! assert_eq!(authorize(None, &expect).unwrap_err(), PermitError::NoPermit);
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

use kovee_core::family::DigestRef;
use kovee_core::time::unix_from_rfc3339_utc;

/// The driver audience byom's Δ4 `model_egress` class subject pins for
/// this broker. A receipt minted for any other audience is unusable here,
/// and byomd refuses to mint one for an audience the act did not name.
pub const BROKER_DRIVER_AUDIENCE: &str = "kovee-model-broker";

/// byom's protocol name in Kovee's `ExternalAuthorizationConsumption`
/// record (§16.1). Governance is byom's; there is no Sage lineage.
pub const OWNER_PROTOCOL_BYOM: &str = "byom";
/// The §16.1 phase of a model-egress consumption: consumed BEFORE egress,
/// never fabricated alongside it.
pub const PHASE_PRE_EGRESS: &str = "pre_egress";

/// The one immutable receipt `execution_permit_consume` returns, as Kovee
/// records it. Every member is byom's; Kovee echoes and checks, never
/// invents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConsumptionReceipt {
    pub receipt_id: String,
    pub byom_endpoint_ref: String,
    pub endpoint_incarnation: String,
    pub recovery_epoch: u64,
    pub intent_ref: String,
    /// The digest members are `Option` because byom's `receipt_result`
    /// currently renders them `null` (byom f232b04; its own B3 suite asserts
    /// only the non-digest members, so the gap is unobserved there). Kovee
    /// checks every digest byom DOES report and records the ones it does not
    /// in [`ExecutionPermit::owner_unverified_digests`] — an absent digest is
    /// never treated as a match. It is not a hole in the authorization:
    /// `execution_permit_consume` re-derives the intent, subject and
    /// disclosure digests against its own committed act INSIDE the consuming
    /// transaction and refuses a mismatch, so the receipt echoing them is a
    /// second check, not the only one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub intent_digest: Option<DigestRef>,
    /// The MandateUse byom inserted exactly once for this consumption.
    pub mandate_use_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mandate_use_digest: Option<DigestRef>,
    pub stable_execution_key: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subject_digest: Option<DigestRef>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub disclosure_digest: Option<DigestRef>,
    pub driver_audience: String,
    pub participant_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub episode_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub episode_fence_digest: Option<DigestRef>,
    pub budget_reservation_set_ref: String,
    pub issued_at: String,
    pub expires_at: String,
    pub max_uses: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub digest: Option<DigestRef>,
    /// byom sets this when the identical canonical request recovered the
    /// retained receipt (the host crashed after consumption). A replay is
    /// still exactly one authorized use.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub replayed: Option<bool>,
}

impl ExecutionConsumptionReceipt {
    /// Parses byom's `result` object. Unknown members are refused: a
    /// receipt shape Kovee does not fully understand cannot be reasoned
    /// about, so it fails closed rather than being partly honored.
    pub fn from_result(result: &Value) -> Result<ExecutionConsumptionReceipt, PermitError> {
        serde_json::from_value(result.clone()).map_err(|e| PermitError::Malformed(e.to_string()))
    }

    /// Whether this receipt recovered a retained one (byom's `replayed`).
    pub fn is_replay(&self) -> bool {
        self.replayed.unwrap_or(false)
    }
}

/// The Episode and fence pair a governed model call must be bound to
/// (family contract L21: one current fence is not enough).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpisodeFence<'a> {
    pub episode_ref: &'a str,
    pub fence_digest: &'a DigestRef,
    pub byom_fence_epoch: u64,
    pub kovee_invocation_fence: u64,
}

/// What the broker requires of a receipt before it will dial a provider.
#[derive(Debug, Clone, Copy)]
pub struct Expectation<'a> {
    /// The stable execution key of the already-committed local Effect.
    pub execution_key: &'a str,
    /// The exact subject digest byom authorized.
    pub subject_digest: &'a DigestRef,
    /// The exact disclosure manifest digest that was authorized.
    pub disclosure_digest: &'a DigestRef,
    /// This broker's audience ([`BROKER_DRIVER_AUDIENCE`]).
    pub driver_audience: &'a str,
    /// The Episode and both current fence epochs, for a governed call.
    pub episode: Option<EpisodeFence<'a>>,
    pub endpoint_incarnation: &'a str,
    pub recovery_epoch: u64,
    pub now: i64,
    /// Whether this effect already has a dispatched attempt under this
    /// receipt. A `max_uses: 1` receipt authorizes exactly one dispatch.
    pub already_spent: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PermitError {
    #[error(
        "no byom execution-consumption receipt: the broker will not call a provider without one"
    )]
    NoPermit,
    #[error("this one-shot permit is already spent by a dispatched attempt; a new attempt needs a new byom act")]
    SpentPermit,
    #[error("the receipt claims max_uses {0}; a model-egress permit is one-shot by construction")]
    NotOneShot(u64),
    #[error("the receipt's stable_execution_key {got:?} is not this effect's {want:?}")]
    WrongExecutionKey { want: String, got: String },
    #[error("the receipt was minted for driver audience {got:?}, not {want:?}")]
    WrongAudience { want: String, got: String },
    #[error("the receipt authorizes another subject digest")]
    SubjectMismatch,
    #[error("the receipt authorizes another disclosure than the one about to leave")]
    DisclosureMismatch,
    #[error("a governed model call binds the exact Episode and BOTH fences")]
    Unbound,
    #[error("the receipt binds Episode {got:?}, not {want:?}")]
    EpisodeMismatch { want: String, got: String },
    #[error("the receipt pins another ByomEpisodeBinding digest: the fence advanced")]
    StaleFence,
    #[error("the receipt expired at {0}")]
    Expired(String),
    #[error("the receipt has no usable expiry ({0:?}): an unreadable deadline is not 'never'")]
    UnreadableExpiry(String),
    #[error("the receipt is from another byomd incarnation or recovery epoch")]
    WrongEndpoint,
    #[error("the byom receipt is malformed: {0}")]
    Malformed(String),
}

/// The local intersection `ExecutionPermit` (§16.1): the owner's exact
/// receipt narrowed by Kovee's current restrictions, recording every
/// contributing digest. Holding one is what makes egress lawful; it is
/// minted only by [`authorize`] and carries no credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPermit {
    pub owner_protocol: String,
    pub phase: String,
    pub owner_endpoint_ref: String,
    pub owner_intent_ref: String,
    pub owner_receipt_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub owner_receipt_digest: Option<DigestRef>,
    pub mandate_use_ref: String,
    pub execution_key: String,
    /// Kovee's own values, which the consumption request bound and byomd
    /// re-derived. They are what the plan is checked against at dispatch.
    pub subject_digest: DigestRef,
    pub disclosure_digest: DigestRef,
    /// Which receipt digests byom did not report, so could not be
    /// independently re-checked here. Empty is the healthy case, and this
    /// list is part of the audit record rather than a silent omission.
    pub owner_unverified_digests: Vec<String>,
    pub driver_audience: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub episode_ref: Option<String>,
    pub byom_fence_epoch: u64,
    pub kovee_invocation_fence: u64,
    pub budget_reservation_set_ref: String,
    pub expires_at: String,
    pub max_uses: u64,
}

/// The gate. Every check is a refusal, and the order is deliberate: the
/// absent permit first (the commonest and most serious mistake), the spent
/// permit next (a duplicate disclosure and a duplicate charge), then the
/// bindings, then the clock.
pub fn authorize(
    receipt: Option<&ExecutionConsumptionReceipt>,
    expect: &Expectation<'_>,
) -> Result<ExecutionPermit, PermitError> {
    let receipt = receipt.ok_or(PermitError::NoPermit)?;
    if expect.already_spent {
        return Err(PermitError::SpentPermit);
    }
    if receipt.max_uses != 1 {
        return Err(PermitError::NotOneShot(receipt.max_uses));
    }
    if receipt.stable_execution_key != expect.execution_key {
        return Err(PermitError::WrongExecutionKey {
            want: expect.execution_key.to_owned(),
            got: receipt.stable_execution_key.clone(),
        });
    }
    if receipt.driver_audience != expect.driver_audience {
        return Err(PermitError::WrongAudience {
            want: expect.driver_audience.to_owned(),
            got: receipt.driver_audience.clone(),
        });
    }
    // Every digest byom REPORTS must match; each one it does not report is
    // recorded, never assumed. `execution_permit_consume` already re-derived
    // all three against its own committed act before minting this receipt.
    let mut unverified = Vec::new();
    match &receipt.subject_digest {
        Some(digest) if digest == expect.subject_digest => {}
        Some(_) => return Err(PermitError::SubjectMismatch),
        None => unverified.push("subject_digest".to_owned()),
    }
    match &receipt.disclosure_digest {
        Some(digest) if digest == expect.disclosure_digest => {}
        Some(_) => return Err(PermitError::DisclosureMismatch),
        None => unverified.push("disclosure_digest".to_owned()),
    }
    if receipt.intent_digest.is_none() {
        unverified.push("intent_digest".to_owned());
    }
    if receipt.digest.is_none() {
        unverified.push("receipt_digest".to_owned());
    }
    if receipt.endpoint_incarnation != expect.endpoint_incarnation
        || receipt.recovery_epoch != expect.recovery_epoch
    {
        return Err(PermitError::WrongEndpoint);
    }
    let (byom_fence, kovee_fence) = match expect.episode {
        Some(episode) => {
            let bound = receipt.episode_ref.as_deref().ok_or(PermitError::Unbound)?;
            if bound != episode.episode_ref {
                return Err(PermitError::EpisodeMismatch {
                    want: episode.episode_ref.to_owned(),
                    got: bound.to_owned(),
                });
            }
            match &receipt.episode_fence_digest {
                Some(digest) if digest == episode.fence_digest => {}
                Some(_) => return Err(PermitError::StaleFence),
                // byomd compared the fence digest against its own committed
                // ByomEpisodeBinding inside the consuming transaction; an
                // unreported echo is recorded, not assumed.
                None => unverified.push("episode_fence_digest".to_owned()),
            }
            (episode.byom_fence_epoch, episode.kovee_invocation_fence)
        }
        None => {
            // An episode-bound receipt cannot authorize an unbound call.
            if receipt.episode_ref.is_some() {
                return Err(PermitError::Unbound);
            }
            (0, 0)
        }
    };
    let expires_at = unix_from_rfc3339_utc(&receipt.expires_at)
        .ok_or_else(|| PermitError::UnreadableExpiry(receipt.expires_at.clone()))?;
    if expires_at <= expect.now {
        return Err(PermitError::Expired(receipt.expires_at.clone()));
    }
    Ok(ExecutionPermit {
        owner_protocol: OWNER_PROTOCOL_BYOM.to_owned(),
        phase: PHASE_PRE_EGRESS.to_owned(),
        owner_endpoint_ref: receipt.byom_endpoint_ref.clone(),
        owner_intent_ref: receipt.intent_ref.clone(),
        owner_receipt_ref: receipt.receipt_id.clone(),
        owner_receipt_digest: receipt.digest.clone(),
        mandate_use_ref: receipt.mandate_use_ref.clone(),
        execution_key: receipt.stable_execution_key.clone(),
        subject_digest: expect.subject_digest.clone(),
        disclosure_digest: expect.disclosure_digest.clone(),
        owner_unverified_digests: unverified,
        driver_audience: receipt.driver_audience.clone(),
        episode_ref: receipt.episode_ref.clone(),
        byom_fence_epoch: byom_fence,
        kovee_invocation_fence: kovee_fence,
        budget_reservation_set_ref: receipt.budget_reservation_set_ref.clone(),
        expires_at: receipt.expires_at.clone(),
        max_uses: 1,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn d(b: u8) -> DigestRef {
        DigestRef::portable_public(format!("{b:02x}").repeat(32))
    }

    const NOW: i64 = 1_800_000_000; // 2027-01-15T08:00:00Z
    const LATER: &str = "2027-01-15T09:00:00Z";
    const EARLIER: &str = "2027-01-15T07:00:00Z";

    fn receipt() -> ExecutionConsumptionReceipt {
        ExecutionConsumptionReceipt {
            receipt_id: "ecr-1".into(),
            byom_endpoint_ref: "byom-endpoint-local".into(),
            endpoint_incarnation: "inst-1".into(),
            recovery_epoch: 0,
            intent_ref: "actint-1".into(),
            intent_digest: Some(d(0x01)),
            mandate_use_ref: "muse-1".into(),
            mandate_use_digest: Some(d(0x02)),
            stable_execution_key: "exec-abc".into(),
            subject_digest: Some(d(0x03)),
            disclosure_digest: Some(d(0x04)),
            driver_audience: BROKER_DRIVER_AUDIENCE.into(),
            participant_ref: "part-agent-1".into(),
            episode_ref: Some("ep-1".into()),
            episode_fence_digest: Some(d(0x05)),
            budget_reservation_set_ref: "rset-1".into(),
            issued_at: "2027-01-15T08:00:00Z".into(),
            expires_at: LATER.into(),
            max_uses: 1,
            digest: Some(d(0x06)),
            replayed: None,
        }
    }

    fn expectation<'a>(
        subject: &'a DigestRef,
        disclosure: &'a DigestRef,
        fence: &'a DigestRef,
    ) -> Expectation<'a> {
        Expectation {
            execution_key: "exec-abc",
            subject_digest: subject,
            disclosure_digest: disclosure,
            driver_audience: BROKER_DRIVER_AUDIENCE,
            episode: Some(EpisodeFence {
                episode_ref: "ep-1",
                fence_digest: fence,
                byom_fence_epoch: 7,
                kovee_invocation_fence: 1,
            }),
            endpoint_incarnation: "inst-1",
            recovery_epoch: 0,
            now: NOW,
            already_spent: false,
        }
    }

    #[test]
    fn a_valid_receipt_mints_the_intersection_permit() {
        let (s, di, f) = (d(0x03), d(0x04), d(0x05));
        let permit = authorize(Some(&receipt()), &expectation(&s, &di, &f)).unwrap();
        assert_eq!(permit.max_uses, 1);
        assert_eq!(permit.owner_protocol, "byom");
        assert_eq!(permit.phase, "pre_egress");
        assert_eq!(permit.owner_receipt_ref, "ecr-1");
        assert_eq!(permit.mandate_use_ref, "muse-1");
        assert_eq!(permit.byom_fence_epoch, 7);
        assert_eq!(permit.kovee_invocation_fence, 1);
        // Every contributing digest is recorded (§16.1).
        assert_eq!(permit.subject_digest, s);
        assert_eq!(permit.disclosure_digest, di);
        // And no credential rides along.
        let json = serde_json::to_string(&permit).unwrap();
        assert!(!json.contains("api-key") && !json.contains("sk-"));
    }

    #[test]
    fn no_receipt_is_the_refusal_that_matters_most() {
        let (s, di, f) = (d(0x03), d(0x04), d(0x05));
        assert_eq!(
            authorize(None, &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::NoPermit
        );
    }

    #[test]
    fn a_spent_one_shot_permit_cannot_authorize_a_second_dispatch() {
        let (s, di, f) = (d(0x03), d(0x04), d(0x05));
        let mut expect = expectation(&s, &di, &f);
        expect.already_spent = true;
        assert_eq!(
            authorize(Some(&receipt()), &expect).unwrap_err(),
            PermitError::SpentPermit
        );
        // A receipt CLAIMING more than one use is refused outright.
        let mut multi = receipt();
        multi.max_uses = 2;
        assert_eq!(
            authorize(Some(&multi), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::NotOneShot(2)
        );
    }

    #[test]
    fn a_receipt_for_another_key_audience_or_subject_is_refused() {
        let (s, di, f) = (d(0x03), d(0x04), d(0x05));
        let mut other_key = receipt();
        other_key.stable_execution_key = "exec-other".into();
        assert!(matches!(
            authorize(Some(&other_key), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::WrongExecutionKey { .. }
        ));
        let mut other_audience = receipt();
        other_audience.driver_audience = "kovee-other-broker".into();
        assert!(matches!(
            authorize(Some(&other_audience), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::WrongAudience { .. }
        ));
        let mut other_subject = receipt();
        other_subject.subject_digest = Some(d(0xee));
        assert_eq!(
            authorize(Some(&other_subject), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::SubjectMismatch
        );
    }

    #[test]
    fn a_different_disclosure_is_refused_and_an_unreported_one_is_recorded() {
        let (s, di, f) = (d(0x03), d(0x04), d(0x05));
        let mut changed = receipt();
        changed.disclosure_digest = Some(d(0xdd));
        assert_eq!(
            authorize(Some(&changed), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::DisclosureMismatch
        );
        // A digest byom did not report is NAMED in the permit, never assumed
        // to match. byomd re-derived it against its own committed act inside
        // the consuming transaction, so the authorization still binds it.
        let mut absent = receipt();
        absent.disclosure_digest = None;
        let permit = authorize(Some(&absent), &expectation(&s, &di, &f)).unwrap();
        assert_eq!(
            permit.owner_unverified_digests,
            vec!["disclosure_digest".to_owned()]
        );
        // And a healthy receipt names nothing as unverified.
        let permit = authorize(Some(&receipt()), &expectation(&s, &di, &f)).unwrap();
        assert!(permit.owner_unverified_digests.is_empty());
    }

    #[test]
    fn a_stale_fence_or_another_episode_is_refused() {
        let (s, di) = (d(0x03), d(0x04));
        // The binding digest advanced: the fence moved under the receipt.
        let advanced = d(0x55);
        assert_eq!(
            authorize(Some(&receipt()), &expectation(&s, &di, &advanced)).unwrap_err(),
            PermitError::StaleFence
        );
        let f = d(0x05);
        let mut other_episode = receipt();
        other_episode.episode_ref = Some("ep-2".into());
        assert!(matches!(
            authorize(Some(&other_episode), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::EpisodeMismatch { .. }
        ));
        // A governed call whose receipt binds no Episode at all.
        let mut unbound = receipt();
        unbound.episode_ref = None;
        unbound.episode_fence_digest = None;
        assert_eq!(
            authorize(Some(&unbound), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::Unbound
        );
        // And the converse: an episode-bound receipt for an unbound call.
        let mut expect = expectation(&s, &di, &f);
        expect.episode = None;
        assert_eq!(
            authorize(Some(&receipt()), &expect).unwrap_err(),
            PermitError::Unbound
        );
    }

    #[test]
    fn an_expired_or_unreadable_deadline_fails_closed() {
        let (s, di, f) = (d(0x03), d(0x04), d(0x05));
        let mut expired = receipt();
        expired.expires_at = EARLIER.into();
        assert!(matches!(
            authorize(Some(&expired), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::Expired(_)
        ));
        let mut unreadable = receipt();
        unreadable.expires_at = "whenever".into();
        assert!(matches!(
            authorize(Some(&unreadable), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::UnreadableExpiry(_)
        ));
    }

    #[test]
    fn another_byomd_incarnation_or_recovery_epoch_is_refused() {
        let (s, di, f) = (d(0x03), d(0x04), d(0x05));
        let mut reincarnated = receipt();
        reincarnated.endpoint_incarnation = "inst-2".into();
        assert_eq!(
            authorize(Some(&reincarnated), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::WrongEndpoint
        );
        let mut recovered = receipt();
        recovered.recovery_epoch = 1;
        assert_eq!(
            authorize(Some(&recovered), &expectation(&s, &di, &f)).unwrap_err(),
            PermitError::WrongEndpoint
        );
    }

    #[test]
    fn byoms_reply_parses_and_an_unknown_member_fails_closed() {
        let wire = serde_json::to_value(receipt()).unwrap();
        let parsed = ExecutionConsumptionReceipt::from_result(&wire).unwrap();
        assert_eq!(parsed, receipt());
        assert!(!parsed.is_replay());
        // byom's replay marker.
        let mut replayed = wire.clone();
        replayed["replayed"] = serde_json::json!(true);
        assert!(ExecutionConsumptionReceipt::from_result(&replayed)
            .unwrap()
            .is_replay());
        // A member Kovee does not understand is not silently ignored.
        let mut extended = wire;
        extended["some_new_grant"] = serde_json::json!("trust me");
        assert!(matches!(
            ExecutionConsumptionReceipt::from_result(&extended).unwrap_err(),
            PermitError::Malformed(_)
        ));
    }
}
