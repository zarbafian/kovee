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
//! | [`PermitError::UnkeyedProvenance`] | a receipt attested under a key anyone could recompute |
//!
//! What you write:
//! ```
//! use kovee_effects::{authorize, Expectation, PermitError};
//! # use kovee_core::family::DigestRef;
//! # use kovee_effects::Origin;
//! # let subject = DigestRef::portable_public("11".repeat(32));
//! # let disclosure = DigestRef::portable_public("22".repeat(32));
//! # let origin = Origin::https("api.anthropic.com", 443);
//! let expect = Expectation {
//!     execution_key: "exec-abc", subject_digest: &subject,
//!     disclosure_digest: &disclosure,
//!     driver_audience: kovee_effects::BROKER_DRIVER_AUDIENCE,
//!     episode: None, endpoint_incarnation: "inst-1", recovery_epoch: 0,
//!     now: 1_800_000_000, already_spent: false, bound_origin: &origin,
//! };
//! // No receipt, no call. This is the whole point of the broker.
//! assert_eq!(authorize(None, &expect).unwrap_err(), PermitError::NoPermit);
//! ```
//!
//! # Why these two types are opaque (D-R3-1)
//!
//! Both are authority-bearing values that cross a trust boundary *inside*
//! one process, so neither is a plain record:
//!
//! - every field is private, and neither type has a public constructor;
//! - a receipt exists only by [`ExecutionConsumptionReceipt::from_result`]
//!   parsing byom's reply — the type itself is not `Deserialize`, so no
//!   caller can conjure one from JSON of its own;
//! - turning a receipt into a permit needs a [`ConsumedReceipt`], which
//!   requires the daemon's own keyed per-object secret: an authenticated
//!   constructor, not a public one;
//! - [`ExecutionPermit`] is neither `Clone` nor `Deserialize`, and
//!   [`crate::dispatch`] takes it **by value**, so a permit cannot be used
//!   twice by the same code path; and
//! - the one authorized use lives in a **durable** [`SpentLedger`], so a
//!   second permit *value* for the same consumption is worthless in fact.
//!
//! Each of those is a compile error rather than a convention, and the
//! `compile_fail` doctests on the types below are how that is proven.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use kovee_core::family::DigestRef;
use kovee_core::time::unix_from_rfc3339_utc;

use crate::egress::{EgressPolicy, Origin};
use crate::keying::{record_digest, RecordDigestKey};

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

/// byom's reply members, as the wire carries them. **Private on purpose**:
/// it is the only `Deserialize` in this module, so the only way to get a
/// receipt is to parse a reply through
/// [`ExecutionConsumptionReceipt::from_result`].
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptWire {
    receipt_id: String,
    byom_endpoint_ref: String,
    endpoint_incarnation: String,
    recovery_epoch: u64,
    intent_ref: String,
    /// The digest members are `Option` because byom's `receipt_result`
    /// currently renders them `null` (byom f232b04; its own B3 suite asserts
    /// only the non-digest members, so the gap is unobserved there). Kovee
    /// checks every digest byom DOES report and records the ones it does not
    /// in the permit's `owner_unverified_digests` — an absent digest is
    /// never treated as a match. It is not a hole in the authorization:
    /// `execution_permit_consume` re-derives the intent, subject and
    /// disclosure digests against its own committed act INSIDE the consuming
    /// transaction and refuses a mismatch, so the receipt echoing them is a
    /// second check, not the only one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    intent_digest: Option<DigestRef>,
    /// The MandateUse byom inserted exactly once for this consumption.
    mandate_use_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    mandate_use_digest: Option<DigestRef>,
    stable_execution_key: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    subject_digest: Option<DigestRef>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    disclosure_digest: Option<DigestRef>,
    driver_audience: String,
    participant_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    episode_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    episode_fence_digest: Option<DigestRef>,
    budget_reservation_set_ref: String,
    issued_at: String,
    expires_at: String,
    max_uses: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    digest: Option<DigestRef>,
    /// byom sets this when the identical canonical request recovered the
    /// retained receipt (the host crashed after consumption). A replay is
    /// still exactly one authorized use.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    replayed: Option<bool>,
}

/// The one immutable receipt `execution_permit_consume` returns, as Kovee
/// records it. Every member is byom's; Kovee echoes and checks, never
/// invents.
///
/// Opaque by construction (D-R3-1): no public field, no public constructor,
/// and no `Deserialize` — so a receipt in Kovee's hands always came through
/// [`ExecutionConsumptionReceipt::from_result`] over byom's reply. It stays
/// `Serialize`, because Kovee must record byom's reply verbatim.
///
/// A literal will not compile:
/// ```compile_fail,E0422
/// # use kovee_effects::ExecutionConsumptionReceipt;
/// let receipt = ExecutionConsumptionReceipt { max_uses: 1 };
/// ```
/// Nor will deserializing one out of thin air:
/// ```compile_fail,E0277
/// # use kovee_effects::ExecutionConsumptionReceipt;
/// let receipt: ExecutionConsumptionReceipt =
///     serde_json::from_str(r#"{"max_uses":1}"#).unwrap();
/// ```
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ExecutionConsumptionReceipt(ReceiptWire);

impl ExecutionConsumptionReceipt {
    /// Parses byom's `result` object — the only way one of these exists.
    /// Unknown members are refused: a receipt shape Kovee does not fully
    /// understand cannot be reasoned about, so it fails closed rather than
    /// being partly honored.
    pub fn from_result(result: &Value) -> Result<ExecutionConsumptionReceipt, PermitError> {
        let wire: ReceiptWire = serde_json::from_value(result.clone())
            .map_err(|e| PermitError::Malformed(e.to_string()))?;
        Ok(ExecutionConsumptionReceipt(wire))
    }

    /// Whether this receipt recovered a retained one (byom's `replayed`).
    pub fn is_replay(&self) -> bool {
        self.0.replayed.unwrap_or(false)
    }

    pub fn receipt_id(&self) -> &str {
        &self.0.receipt_id
    }
    pub fn byom_endpoint_ref(&self) -> &str {
        &self.0.byom_endpoint_ref
    }
    pub fn intent_ref(&self) -> &str {
        &self.0.intent_ref
    }
    pub fn stable_execution_key(&self) -> &str {
        &self.0.stable_execution_key
    }
    pub fn mandate_use_ref(&self) -> &str {
        &self.0.mandate_use_ref
    }
    /// byom's own digest over the receipt, when byom reported one.
    pub fn digest(&self) -> Option<&DigestRef> {
        self.0.digest.as_ref()
    }
}

/// A receipt Kovee has **attested**: the authenticated constructor between a
/// parsed reply and an [`ExecutionPermit`].
///
/// [`authorize`] will not look at a bare [`ExecutionConsumptionReceipt`]. It
/// takes one of these, and minting one requires a *keyed* per-object secret
/// — the daemon's realm-wrapped consumption key, which no worker-reachable
/// path holds. The keyed digest it computes over the exact receipt bytes and
/// the durable consumption id is recorded in the permit, so an auditor can
/// later re-derive it and see that the permit was minted from the committed
/// receipt and not from something else.
#[derive(Debug)]
pub struct ConsumedReceipt<'a> {
    receipt: &'a ExecutionConsumptionReceipt,
    consumption_ref: &'a str,
    provenance: DigestRef,
}

/// The type tag of the receipt-provenance preimage.
pub const RECEIPT_PROVENANCE_TAG: &str = "kovee-consumption-provenance-v1";

impl<'a> ConsumedReceipt<'a> {
    /// Attests one committed consumption. `key` must be a keyed
    /// ([`RecordDigestKey::Object`]) key: an unkeyed one is refused, because
    /// anyone could recompute it and the attestation would prove nothing.
    pub fn attest(
        receipt: &'a ExecutionConsumptionReceipt,
        consumption_ref: &'a str,
        key: RecordDigestKey<'_>,
    ) -> Result<ConsumedReceipt<'a>, PermitError> {
        if !matches!(key, RecordDigestKey::Object { .. }) {
            return Err(PermitError::UnkeyedProvenance);
        }
        let projection = json!({
            "consumption_ref": consumption_ref,
            "receipt": serde_json::to_value(receipt)
                .map_err(|e| PermitError::Malformed(e.to_string()))?,
        });
        let provenance = record_digest(RECEIPT_PROVENANCE_TAG, &projection, key)
            .ok_or(PermitError::Unattestable)?;
        Ok(ConsumedReceipt {
            receipt,
            consumption_ref,
            provenance,
        })
    }

    pub fn consumption_ref(&self) -> &str {
        self.consumption_ref
    }

    /// The keyed digest that binds this receipt to its consumption record.
    pub fn provenance(&self) -> &DigestRef {
        &self.provenance
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
    /// The destination the **provider binding** records. This is the origin
    /// the permit authorizes; it is copied into the permit and is what
    /// [`crate::dispatch`] rechecks the outgoing call against — never a
    /// field of the plan, which is the value R3 changed after authorization
    /// (R3-B02).
    pub bound_origin: &'a Origin,
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
    #[error(
        "a receipt attested under an unkeyed digest proves nothing: provenance needs the \
         daemon's own per-object secret"
    )]
    UnkeyedProvenance,
    #[error("the receipt could not be canonicalized for attestation")]
    Unattestable,
}

/// The local intersection `ExecutionPermit` (§16.1): the owner's exact
/// receipt narrowed by Kovee's current restrictions, recording every
/// contributing digest. Holding one is what makes egress lawful; it is
/// minted only by [`authorize`] and carries no credential.
///
/// It is `Serialize` because §16.1 requires the intersection to be recorded.
/// It is deliberately **not** `Clone`, **not** `Deserialize`, and has no
/// public field or constructor, and [`crate::dispatch`] takes it **by
/// value** — so the value cannot be duplicated, forged, or reused:
///
/// ```compile_fail,E0599
/// # fn f(permit: kovee_effects::ExecutionPermit) {
/// let second = permit.clone();
/// # }
/// ```
/// ```compile_fail,E0277
/// # use kovee_effects::ExecutionPermit;
/// let permit: ExecutionPermit = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail,E0616
/// # fn f(mut permit: kovee_effects::ExecutionPermit) {
/// permit.execution_key = "exec-someone-elses".to_owned();
/// # }
/// ```
#[derive(Debug, Serialize)]
pub struct ExecutionPermit {
    owner_protocol: String,
    phase: String,
    owner_endpoint_ref: String,
    owner_intent_ref: String,
    owner_receipt_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    owner_receipt_digest: Option<DigestRef>,
    /// The keyed digest binding this permit to the exact committed receipt
    /// and consumption record it was minted from ([`ConsumedReceipt`]).
    owner_receipt_provenance: DigestRef,
    /// The durable `ExternalAuthorizationConsumption` this permit's one use
    /// is claimed against — the row a [`SpentLedger`] moves to `spent`.
    consumption_ref: String,
    mandate_use_ref: String,
    execution_key: String,
    /// Kovee's own values, which the consumption request bound and byomd
    /// re-derived. They are what the plan is checked against at dispatch.
    subject_digest: DigestRef,
    disclosure_digest: DigestRef,
    /// Which receipt digests byom did not report, so could not be
    /// independently re-checked here. Empty is the healthy case, and this
    /// list is part of the audit record rather than a silent omission.
    owner_unverified_digests: Vec<String>,
    driver_audience: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    episode_ref: Option<String>,
    byom_fence_epoch: u64,
    kovee_invocation_fence: u64,
    budget_reservation_set_ref: String,
    expires_at: String,
    max_uses: u64,
    /// The destination this permit authorizes, copied from the provider
    /// binding at authorization, and the one-origin egress policy derived
    /// from it. Dispatch rechecks against these (R3-B02).
    bound_origin: Origin,
    bound_egress_policy: EgressPolicy,
}

impl ExecutionPermit {
    pub fn owner_protocol(&self) -> &str {
        &self.owner_protocol
    }
    pub fn phase(&self) -> &str {
        &self.phase
    }
    pub fn owner_endpoint_ref(&self) -> &str {
        &self.owner_endpoint_ref
    }
    pub fn owner_intent_ref(&self) -> &str {
        &self.owner_intent_ref
    }
    pub fn owner_receipt_ref(&self) -> &str {
        &self.owner_receipt_ref
    }
    pub fn owner_receipt_provenance(&self) -> &DigestRef {
        &self.owner_receipt_provenance
    }
    pub fn consumption_ref(&self) -> &str {
        &self.consumption_ref
    }
    pub fn mandate_use_ref(&self) -> &str {
        &self.mandate_use_ref
    }
    pub fn execution_key(&self) -> &str {
        &self.execution_key
    }
    pub fn subject_digest(&self) -> &DigestRef {
        &self.subject_digest
    }
    pub fn disclosure_digest(&self) -> &DigestRef {
        &self.disclosure_digest
    }
    pub fn owner_unverified_digests(&self) -> &[String] {
        &self.owner_unverified_digests
    }
    pub fn driver_audience(&self) -> &str {
        &self.driver_audience
    }
    pub fn episode_ref(&self) -> Option<&str> {
        self.episode_ref.as_deref()
    }
    pub fn byom_fence_epoch(&self) -> u64 {
        self.byom_fence_epoch
    }
    pub fn kovee_invocation_fence(&self) -> u64 {
        self.kovee_invocation_fence
    }
    pub fn budget_reservation_set_ref(&self) -> &str {
        &self.budget_reservation_set_ref
    }
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }
    pub fn max_uses(&self) -> u64 {
        self.max_uses
    }
    /// The one origin this permit authorizes.
    pub fn bound_origin(&self) -> &Origin {
        &self.bound_origin
    }
    /// The egress policy derived from that origin at authorization.
    pub fn bound_egress_policy(&self) -> &EgressPolicy {
        &self.bound_egress_policy
    }
}

// ------------------------------------------------------- the spent ledger ----

/// Whether this dispatch won the permit's single use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// This call claimed the one use. Exactly one caller ever sees this.
    Claimed,
    /// The use was already claimed — by an earlier dispatch, or by a
    /// process that died mid-dispatch. Nothing may leave.
    AlreadySpent,
}

/// The **durable** one-shot state a permit is coupled to.
///
/// A permit value is necessary but not sufficient: [`crate::dispatch`] claims
/// the single use through this ledger before it opens a socket, so a second
/// permit value for the same consumption — however a caller came to hold one
/// — sends nothing. The implementation must be atomic and survive a crash;
/// koveed's is a conditional `UPDATE` on the consumption row.
pub trait SpentLedger {
    /// Moves this permit's consumption from unspent to spent, atomically.
    /// `Err` is a ledger failure and is treated as a refusal: a use that
    /// cannot be recorded is a use that does not happen.
    fn claim_single_use(&self, permit: &ExecutionPermit) -> Result<Claim, String>;
}

/// An in-memory ledger for tests: the durable one lives in koveed.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct MemorySpentLedger {
    spent: std::sync::Mutex<Vec<String>>,
}

#[cfg(any(test, feature = "testing"))]
impl SpentLedger for MemorySpentLedger {
    fn claim_single_use(&self, permit: &ExecutionPermit) -> Result<Claim, String> {
        let mut spent = self.spent.lock().map_err(|e| e.to_string())?;
        let key = permit.consumption_ref().to_owned();
        if spent.contains(&key) {
            return Ok(Claim::AlreadySpent);
        }
        spent.push(key);
        Ok(Claim::Claimed)
    }
}

/// The gate. Every check is a refusal, and the order is deliberate: the
/// absent permit first (the commonest and most serious mistake), the spent
/// permit next (a duplicate disclosure and a duplicate charge), then the
/// bindings, then the clock.
///
/// It takes a [`ConsumedReceipt`], not a receipt: the authenticated
/// constructor is part of the gate (D-R3-1).
pub fn authorize(
    consumed: Option<ConsumedReceipt<'_>>,
    expect: &Expectation<'_>,
) -> Result<ExecutionPermit, PermitError> {
    let consumed = consumed.ok_or(PermitError::NoPermit)?;
    let receipt = &consumed.receipt.0;
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
        owner_receipt_provenance: consumed.provenance.clone(),
        consumption_ref: consumed.consumption_ref.to_owned(),
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
        bound_origin: expect.bound_origin.clone(),
        bound_egress_policy: EgressPolicy::allowing([expect.bound_origin.clone()]),
    })
}

/// Fixtures shared with the broker's tests. A test receipt is built from
/// byom's reply JSON and parsed by [`ExecutionConsumptionReceipt::from_result`]
/// — the same door production uses, because there is no other.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod fixture {
    use super::*;
    use serde_json::json;

    /// The daemon's per-object consumption secret, in a test.
    pub(crate) const SECRET: [u8; 32] = [11u8; 32];
    pub(crate) const CONSUMPTION: &str = "eac-1";
    pub(crate) const EXPIRES: &str = "2027-01-15T09:00:00Z";

    pub(crate) fn digest(b: u8) -> DigestRef {
        DigestRef::portable_public(format!("{b:02x}").repeat(32))
    }

    /// byom's `result` object for one consumption.
    pub(crate) fn reply(
        execution_key: &str,
        subject: &DigestRef,
        disclosure: &DigestRef,
        fence: &DigestRef,
    ) -> Value {
        json!({
            "receipt_id": "ecr-1",
            "byom_endpoint_ref": "byom-endpoint-local",
            "endpoint_incarnation": "inst-1",
            "recovery_epoch": 0,
            "intent_ref": "actint-1",
            "intent_digest": digest(0x01),
            "mandate_use_ref": "muse-1",
            "mandate_use_digest": digest(0x02),
            "stable_execution_key": execution_key,
            "subject_digest": subject,
            "disclosure_digest": disclosure,
            "driver_audience": BROKER_DRIVER_AUDIENCE,
            "participant_ref": "part-agent-1",
            "episode_ref": "ep-1",
            "episode_fence_digest": fence,
            "budget_reservation_set_ref": "rset-1",
            "issued_at": "2027-01-15T08:00:00Z",
            "expires_at": EXPIRES,
            "max_uses": 1,
            "digest": digest(0x06),
        })
    }

    pub(crate) fn receipt_from(reply: &Value) -> ExecutionConsumptionReceipt {
        ExecutionConsumptionReceipt::from_result(reply).unwrap()
    }

    /// The keyed per-object attestation the daemon performs on the committed
    /// consumption row.
    pub(crate) fn attest(receipt: &ExecutionConsumptionReceipt) -> ConsumedReceipt<'_> {
        ConsumedReceipt::attest(receipt, CONSUMPTION, key()).unwrap()
    }

    pub(crate) fn key() -> RecordDigestKey<'static> {
        RecordDigestKey::Object {
            key_ref: "kovee-consumption-object:eac-1",
            secret: &SECRET,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::fixture::*;
    use super::*;

    const NOW: i64 = 1_800_000_000; // 2027-01-15T08:00:00Z
    const EARLIER: &str = "2027-01-15T07:00:00Z";

    fn d(b: u8) -> DigestRef {
        digest(b)
    }

    /// byom's reply for the healthy case.
    fn reply_ok() -> Value {
        reply("exec-abc", &d(0x03), &d(0x04), &d(0x05))
    }

    fn origin() -> Origin {
        Origin::https("api.anthropic.com", 443)
    }

    fn expectation<'a>(
        subject: &'a DigestRef,
        disclosure: &'a DigestRef,
        fence: &'a DigestRef,
        origin: &'a Origin,
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
            bound_origin: origin,
        }
    }

    #[test]
    fn a_valid_receipt_mints_the_intersection_permit() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let receipt = receipt_from(&reply_ok());
        let permit = authorize(Some(attest(&receipt)), &expectation(&s, &di, &f, &o)).unwrap();
        assert_eq!(permit.max_uses(), 1);
        assert_eq!(permit.owner_protocol(), "byom");
        assert_eq!(permit.phase(), "pre_egress");
        assert_eq!(permit.owner_receipt_ref(), "ecr-1");
        assert_eq!(permit.mandate_use_ref(), "muse-1");
        assert_eq!(permit.byom_fence_epoch(), 7);
        assert_eq!(permit.kovee_invocation_fence(), 1);
        // Every contributing digest is recorded (§16.1).
        assert_eq!(permit.subject_digest(), &s);
        assert_eq!(permit.disclosure_digest(), &di);
        // The durable row this permit's one use is claimed against, and the
        // keyed provenance over the exact committed receipt.
        assert_eq!(permit.consumption_ref(), CONSUMPTION);
        assert_eq!(
            permit.owner_receipt_provenance().class,
            "local_erasure_safe"
        );
        // The destination is bound HERE, from the provider binding.
        assert_eq!(permit.bound_origin(), &o);
        assert_eq!(
            permit.bound_egress_policy(),
            &EgressPolicy::allowing([o.clone()])
        );
        // And no credential rides along.
        let json = serde_json::to_string(&permit).unwrap();
        assert!(!json.contains("api-key") && !json.contains("sk-"));
    }

    #[test]
    fn no_receipt_is_the_refusal_that_matters_most() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        assert_eq!(
            authorize(None, &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::NoPermit
        );
    }

    #[test]
    fn an_unkeyed_attestation_proves_nothing_and_is_refused() {
        let receipt = receipt_from(&reply_ok());
        assert_eq!(
            ConsumedReceipt::attest(&receipt, CONSUMPTION, RecordDigestKey::Portable).unwrap_err(),
            PermitError::UnkeyedProvenance
        );
    }

    #[test]
    fn the_provenance_binds_the_exact_receipt_bytes_and_its_consumption() {
        let receipt = receipt_from(&reply_ok());
        let one = attest(&receipt);
        // The same receipt under the same consumption re-derives identically:
        // an auditor holding the daemon's secret can re-check the permit.
        assert_eq!(attest(&receipt).provenance(), one.provenance());
        // Another consumption record, or another receipt, does not.
        let other_row = ConsumedReceipt::attest(&receipt, "eac-2", key()).unwrap();
        assert_ne!(other_row.provenance(), one.provenance());
        let mut altered = reply_ok();
        altered["mandate_use_ref"] = serde_json::json!("muse-someone-elses");
        let altered = receipt_from(&altered);
        assert_ne!(attest(&altered).provenance(), one.provenance());
        // And a different daemon secret does not either.
        let other_secret = [12u8; 32];
        let elsewhere = ConsumedReceipt::attest(
            &receipt,
            CONSUMPTION,
            RecordDigestKey::Object {
                key_ref: "kovee-consumption-object:eac-1",
                secret: &other_secret,
            },
        )
        .unwrap();
        assert_ne!(elsewhere.provenance(), one.provenance());
    }

    #[test]
    fn a_spent_one_shot_permit_cannot_authorize_a_second_dispatch() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let receipt = receipt_from(&reply_ok());
        let mut expect = expectation(&s, &di, &f, &o);
        expect.already_spent = true;
        assert_eq!(
            authorize(Some(attest(&receipt)), &expect).unwrap_err(),
            PermitError::SpentPermit
        );
        // A receipt CLAIMING more than one use is refused outright.
        let mut multi = reply_ok();
        multi["max_uses"] = serde_json::json!(2);
        let multi = receipt_from(&multi);
        assert_eq!(
            authorize(Some(attest(&multi)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::NotOneShot(2)
        );
    }

    #[test]
    fn the_durable_ledger_grants_the_single_use_exactly_once() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let receipt = receipt_from(&reply_ok());
        // TWO permits from the ONE receipt: a caller that never consulted the
        // spent flag. The value is not what limits the use — the ledger is.
        let first = authorize(Some(attest(&receipt)), &expectation(&s, &di, &f, &o)).unwrap();
        let second = authorize(Some(attest(&receipt)), &expectation(&s, &di, &f, &o)).unwrap();
        let ledger = MemorySpentLedger::default();
        assert_eq!(ledger.claim_single_use(&first).unwrap(), Claim::Claimed);
        assert_eq!(
            ledger.claim_single_use(&second).unwrap(),
            Claim::AlreadySpent
        );
        // And the first permit itself cannot be re-claimed either.
        assert_eq!(
            ledger.claim_single_use(&first).unwrap(),
            Claim::AlreadySpent
        );
    }

    #[test]
    fn a_receipt_for_another_key_audience_or_subject_is_refused() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let mut other_key = reply_ok();
        other_key["stable_execution_key"] = serde_json::json!("exec-other");
        let other_key = receipt_from(&other_key);
        assert!(matches!(
            authorize(Some(attest(&other_key)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::WrongExecutionKey { .. }
        ));
        let mut other_audience = reply_ok();
        other_audience["driver_audience"] = serde_json::json!("kovee-other-broker");
        let other_audience = receipt_from(&other_audience);
        assert!(matches!(
            authorize(Some(attest(&other_audience)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::WrongAudience { .. }
        ));
        let mut other_subject = reply_ok();
        other_subject["subject_digest"] = serde_json::to_value(d(0xee)).unwrap();
        let other_subject = receipt_from(&other_subject);
        assert_eq!(
            authorize(Some(attest(&other_subject)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::SubjectMismatch
        );
    }

    #[test]
    fn a_different_disclosure_is_refused_and_an_unreported_one_is_recorded() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let mut changed = reply_ok();
        changed["disclosure_digest"] = serde_json::to_value(d(0xdd)).unwrap();
        let changed = receipt_from(&changed);
        assert_eq!(
            authorize(Some(attest(&changed)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::DisclosureMismatch
        );
        // A digest byom did not report is NAMED in the permit, never assumed
        // to match. byomd re-derived it against its own committed act inside
        // the consuming transaction, so the authorization still binds it.
        let mut absent = reply_ok();
        absent["disclosure_digest"] = Value::Null;
        let absent = receipt_from(&absent);
        let permit = authorize(Some(attest(&absent)), &expectation(&s, &di, &f, &o)).unwrap();
        assert_eq!(
            permit.owner_unverified_digests(),
            ["disclosure_digest".to_owned()]
        );
        // And a healthy receipt names nothing as unverified.
        let receipt = receipt_from(&reply_ok());
        let permit = authorize(Some(attest(&receipt)), &expectation(&s, &di, &f, &o)).unwrap();
        assert!(permit.owner_unverified_digests().is_empty());
    }

    #[test]
    fn a_stale_fence_or_another_episode_is_refused() {
        let (s, di, o) = (d(0x03), d(0x04), origin());
        // The binding digest advanced: the fence moved under the receipt.
        let advanced = d(0x55);
        let receipt = receipt_from(&reply_ok());
        assert_eq!(
            authorize(Some(attest(&receipt)), &expectation(&s, &di, &advanced, &o)).unwrap_err(),
            PermitError::StaleFence
        );
        let f = d(0x05);
        let mut other_episode = reply_ok();
        other_episode["episode_ref"] = serde_json::json!("ep-2");
        let other_episode = receipt_from(&other_episode);
        assert!(matches!(
            authorize(Some(attest(&other_episode)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::EpisodeMismatch { .. }
        ));
        // A governed call whose receipt binds no Episode at all.
        let mut unbound = reply_ok();
        unbound["episode_ref"] = Value::Null;
        unbound["episode_fence_digest"] = Value::Null;
        let unbound = receipt_from(&unbound);
        assert_eq!(
            authorize(Some(attest(&unbound)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::Unbound
        );
        // And the converse: an episode-bound receipt for an unbound call.
        let mut expect = expectation(&s, &di, &f, &o);
        expect.episode = None;
        assert_eq!(
            authorize(Some(attest(&receipt)), &expect).unwrap_err(),
            PermitError::Unbound
        );
    }

    #[test]
    fn an_expired_or_unreadable_deadline_fails_closed() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let mut expired = reply_ok();
        expired["expires_at"] = serde_json::json!(EARLIER);
        let expired = receipt_from(&expired);
        assert!(matches!(
            authorize(Some(attest(&expired)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::Expired(_)
        ));
        let mut unreadable = reply_ok();
        unreadable["expires_at"] = serde_json::json!("whenever");
        let unreadable = receipt_from(&unreadable);
        assert!(matches!(
            authorize(Some(attest(&unreadable)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::UnreadableExpiry(_)
        ));
    }

    #[test]
    fn another_byomd_incarnation_or_recovery_epoch_is_refused() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let mut reincarnated = reply_ok();
        reincarnated["endpoint_incarnation"] = serde_json::json!("inst-2");
        let reincarnated = receipt_from(&reincarnated);
        assert_eq!(
            authorize(Some(attest(&reincarnated)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::WrongEndpoint
        );
        let mut recovered = reply_ok();
        recovered["recovery_epoch"] = serde_json::json!(1);
        let recovered = receipt_from(&recovered);
        assert_eq!(
            authorize(Some(attest(&recovered)), &expectation(&s, &di, &f, &o)).unwrap_err(),
            PermitError::WrongEndpoint
        );
    }

    #[test]
    fn byoms_reply_parses_and_an_unknown_member_fails_closed() {
        let wire = reply_ok();
        let parsed = ExecutionConsumptionReceipt::from_result(&wire).unwrap();
        assert_eq!(parsed.receipt_id(), "ecr-1");
        assert_eq!(parsed.stable_execution_key(), "exec-abc");
        assert_eq!(parsed.mandate_use_ref(), "muse-1");
        assert_eq!(parsed.intent_ref(), "actint-1");
        assert_eq!(parsed.byom_endpoint_ref(), "byom-endpoint-local");
        assert_eq!(parsed.digest(), Some(&d(0x06)));
        assert!(!parsed.is_replay());
        // It round-trips through Kovee's own durable record: the stored reply
        // re-parses to the identical receipt, which is what makes the
        // crash-recovery path use the SAME door as the live one.
        let stored = serde_json::to_value(&parsed).unwrap();
        assert_eq!(
            ExecutionConsumptionReceipt::from_result(&stored).unwrap(),
            parsed
        );
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
