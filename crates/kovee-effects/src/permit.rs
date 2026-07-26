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
//! # One door, and it is keyed
//!
//! Everything on this page hangs off a single value: the
//! [`ConsumptionAuthority`]. The daemon builds exactly one, from key material
//! no worker-reachable path holds and the **durable** spent ledger, and it is
//! then the only way to
//!
//! 1. turn byom's reply into a receipt ([`ConsumptionAuthority::admit`]),
//! 2. attest that receipt against its committed consumption row
//!    ([`ConsumptionAuthority::attest`]),
//! 3. mint a permit ([`ConsumptionAuthority::authorize`]), and
//! 4. spend one — [`crate::dispatch`] takes the authority, **not** a ledger
//!    chosen at the call site, and refuses a permit this authority did not
//!    seal.
//!
//! Each step verifies the previous one's keyed tag rather than assuming it,
//! so the chain reply → receipt → attestation → permit → egress is
//! authenticated end to end under one secret (R3-B01, D-R3-1).
//!
//! What you write:
//! ```
//! use kovee_effects::{Claim, ConsumptionAuthority, Expectation, ExecutionPermit,
//!                     PermitError, SpentLedger};
//! # use kovee_core::family::DigestRef;
//! # use kovee_effects::Origin;
//! # let subject = DigestRef::portable_public("11".repeat(32));
//! # let disclosure = DigestRef::portable_public("22".repeat(32));
//! # let origin = Origin::https("api.anthropic.com", 443);
//! struct Rows;                       // the daemon's durable consumption table
//! impl SpentLedger for Rows {
//!     fn claim_single_use(&self, _p: &ExecutionPermit) -> Result<Claim, String> {
//!         Ok(Claim::Claimed)
//!     }
//! }
//! // The daemon's one authority: its realm-derived secret and its own ledger.
//! let authority = ConsumptionAuthority::new(
//!     "kovee-consumption-object:realm-personal", [7u8; 32], &Rows);
//!
//! let expect = Expectation {
//!     execution_key: "exec-abc", subject_digest: &subject,
//!     disclosure_digest: &disclosure,
//!     driver_audience: kovee_effects::BROKER_DRIVER_AUDIENCE,
//!     episode: None, endpoint_incarnation: "inst-1", recovery_epoch: 0,
//!     now: 1_800_000_000, already_spent: false, bound_origin: &origin,
//! };
//! // No receipt, no call. This is the whole point of the broker.
//! assert_eq!(authority.authorize(None, &expect).unwrap_err(), PermitError::NoPermit);
//! ```
//!
//! # Why these types are opaque, and why that is not the whole fix (D-R3-1)
//!
//! Opacity came first and is still here: every field is private, no type has
//! a public constructor or a `Deserialize`, [`ExecutionPermit`] is not
//! `Clone`, and [`crate::dispatch`] takes it **by value**.
//!
//! R3's confirmation showed opacity alone is not a gate. A caller could
//! author the receipt JSON, hand it to a public parser, attest it under a key
//! **of its own choosing**, and dispatch it against a ledger **of its own
//! writing** — every value opaque, every value forged. So the parser, the
//! attestation and the ledger all moved behind the authority:
//!
//! - a receipt exists only as [`ConsumptionAuthority::admit`] returns it, and
//!   it carries a keyed admission tag over its exact members;
//! - [`ConsumptionAuthority::attest`] **verifies** that tag before it will
//!   attest anything, so a receipt admitted elsewhere is refused here;
//! - the attestation takes **no key argument** — the secret is the
//!   authority's, never the call site's;
//! - the minted permit carries a keyed **seal** over its whole authorized
//!   projection, and `dispatch` re-verifies it under the same authority;
//! - the single use is claimed in the ledger the authority **owns**, so no
//!   call site can substitute a permissive one.
//!
//! What that leaves, stated plainly: code that can construct a
//! `ConsumptionAuthority` *is* the daemon, because it supplies the daemon's
//! secret and the daemon's ledger. A library cannot distinguish it from the
//! daemon; only byom signing its own receipts could, and byom does not sign
//! them today. What is closed is everything short of that — no receipt, no
//! attestation, no permit and no spent use can be produced by any code that
//! does not already hold both.
//!
//! Each opacity claim is a compile error rather than a convention, and
//! `tests/compile_gate.rs` is how that is proven against rustc's own
//! diagnostics.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use kovee_core::family::{hmac_sha256, tagged_canonical, DigestRef};
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

/// The type tag of the receipt-admission preimage: what the authority MACs
/// when byom's reply first becomes a receipt.
pub const RECEIPT_ADMISSION_TAG: &str = "kovee-consumption-admission-v1";
/// The type tag of the receipt-provenance preimage.
pub const RECEIPT_PROVENANCE_TAG: &str = "kovee-consumption-provenance-v1";
/// The type tag of the permit seal: what `dispatch` re-verifies.
pub const PERMIT_SEAL_TAG: &str = "kovee-execution-permit-seal-v1";

/// A comparison whose duration does not depend on where the first difference
/// is. Every check on this page compares a secret-keyed tag, so none of them
/// uses `==`.
fn ct_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for i in 0..32 {
        difference |= left[i] ^ right[i];
    }
    difference == 0
}

/// The same, for the hex of a keyed digest.
fn ct_eq_str(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (l, r) in left.bytes().zip(right.bytes()) {
        difference |= l ^ r;
    }
    difference == 0
}

/// byom's reply members, as the wire carries them. **Private on purpose**:
/// it is the only `Deserialize` in this module, and the only code that can
/// reach it is [`ConsumptionAuthority::admit`].
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
/// Opaque *and* admitted (D-R3-1): no public field, no public constructor, no
/// `Deserialize`, and a private keyed **admission tag** that only a
/// [`ConsumptionAuthority`] can compute. So a receipt in Kovee's hands did
/// not merely parse — it came through
/// [`ConsumptionAuthority::admit`] under the daemon's own secret, and
/// [`ConsumptionAuthority::attest`] re-checks that before it will do anything
/// with it. It stays `Serialize`, because Kovee must record byom's reply
/// verbatim; the admission tag is not part of that record, it is re-derived
/// whenever the stored reply is admitted again.
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
/// Nor will parsing JSON of one's own, which is what R3's confirmation did:
/// ```compile_fail,E0624
/// # use kovee_effects::ExecutionConsumptionReceipt;
/// # fn f(mine: &serde_json::Value) {
/// let receipt = ExecutionConsumptionReceipt::from_result(mine);
/// # }
/// ```
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ExecutionConsumptionReceipt {
    wire: ReceiptWire,
    /// The keyed tag of the authority that admitted this reply. Not part of
    /// the recorded receipt: it is a fact about *this process's* handling of
    /// byom's bytes, not a member of byom's record.
    #[serde(skip)]
    admission: [u8; 32],
}

impl ExecutionConsumptionReceipt {
    /// Parses byom's `result` object. **Private**: the public door is
    /// [`ConsumptionAuthority::admit`], which is this plus the keyed
    /// admission tag. Unknown members are refused — a receipt shape Kovee
    /// does not fully understand cannot be reasoned about, so it fails closed
    /// rather than being partly honored.
    fn from_result(result: &Value) -> Result<ReceiptWire, PermitError> {
        serde_json::from_value(result.clone()).map_err(|e| PermitError::Malformed(e.to_string()))
    }

    /// Whether this receipt recovered a retained one (byom's `replayed`).
    pub fn is_replay(&self) -> bool {
        self.wire.replayed.unwrap_or(false)
    }

    pub fn receipt_id(&self) -> &str {
        &self.wire.receipt_id
    }
    pub fn byom_endpoint_ref(&self) -> &str {
        &self.wire.byom_endpoint_ref
    }
    pub fn intent_ref(&self) -> &str {
        &self.wire.intent_ref
    }
    pub fn stable_execution_key(&self) -> &str {
        &self.wire.stable_execution_key
    }
    pub fn mandate_use_ref(&self) -> &str {
        &self.wire.mandate_use_ref
    }
    /// byom's own digest over the receipt, when byom reported one.
    pub fn digest(&self) -> Option<&DigestRef> {
        self.wire.digest.as_ref()
    }
}

/// A receipt Kovee has **attested**: the authenticated step between an
/// admitted reply and an [`ExecutionPermit`].
///
/// It exists only as [`ConsumptionAuthority::attest`] returns it, and only
/// after that authority has verified the receipt's admission tag. The keyed
/// digest it carries is over the exact receipt bytes and the durable
/// consumption id, so an auditor holding the daemon's secret can re-derive it
/// and see that the permit was minted from the committed receipt and not from
/// something else.
#[derive(Debug)]
pub struct ConsumedReceipt<'a> {
    receipt: &'a ExecutionConsumptionReceipt,
    consumption_ref: &'a str,
    provenance: DigestRef,
}

impl ConsumedReceipt<'_> {
    pub fn consumption_ref(&self) -> &str {
        self.consumption_ref
    }

    /// The keyed digest that binds this receipt to its consumption record.
    pub fn provenance(&self) -> &DigestRef {
        &self.provenance
    }
}

// -------------------------------------------------------- the authority ----

/// The daemon's one consumption authority: the secret that authenticates
/// every step from byom's reply to an outbound byte, and the **durable**
/// ledger the single use is claimed in.
///
/// Both are chosen **here**, once, by the code that owns the daemon's key
/// material and its database — never at a dispatch call site. That is the
/// difference R3's confirmation demanded: a caller can no longer pick the
/// attestation secret, and can no longer pair a permit with a ledger that
/// forgets.
///
/// The secret must be per-realm key material the daemon derives (koveed
/// derives it from the realm object key), not a constant and not anything a
/// worker can read.
pub struct ConsumptionAuthority<'a> {
    key_ref: String,
    secret: [u8; 32],
    ledger: &'a dyn SpentLedger,
}

impl std::fmt::Debug for ConsumptionAuthority<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsumptionAuthority")
            .field("key_ref", &self.key_ref)
            .field("secret", &"redacted")
            .finish()
    }
}

impl<'a> ConsumptionAuthority<'a> {
    /// The daemon's authority. `key_ref` names the secret in the audit record
    /// — it is what a later reader of a permit's `owner_receipt_provenance`
    /// uses to tell which key would have to be destroyed to erase it.
    pub fn new(
        key_ref: &str,
        secret: [u8; 32],
        ledger: &'a dyn SpentLedger,
    ) -> ConsumptionAuthority<'a> {
        ConsumptionAuthority {
            key_ref: key_ref.to_owned(),
            secret,
            ledger,
        }
    }

    /// The `key_ref` this authority's digests are keyed under.
    pub fn key_ref(&self) -> &str {
        &self.key_ref
    }

    /// The **only** way an [`ExecutionConsumptionReceipt`] comes into
    /// existence: byom's `result` object, parsed and tagged under this
    /// authority's secret.
    ///
    /// The tag is over the parsed members rather than the raw bytes, so the
    /// crash-recovery path — re-admitting the reply Kovee durably stored —
    /// reproduces the identical receipt and uses the same door as the live
    /// one.
    pub fn admit(&self, reply: &Value) -> Result<ExecutionConsumptionReceipt, PermitError> {
        let wire = ExecutionConsumptionReceipt::from_result(reply)?;
        let admission = self.tag(RECEIPT_ADMISSION_TAG, &wire)?;
        Ok(ExecutionConsumptionReceipt { wire, admission })
    }

    /// Attests one committed consumption. There is no key argument: the
    /// secret is this authority's. A receipt this authority did not admit is
    /// refused before anything is computed over it.
    pub fn attest<'r>(
        &self,
        receipt: &'r ExecutionConsumptionReceipt,
        consumption_ref: &'r str,
    ) -> Result<ConsumedReceipt<'r>, PermitError> {
        self.check_admission(receipt)?;
        Ok(ConsumedReceipt {
            provenance: self.provenance_of(receipt, consumption_ref)?,
            receipt,
            consumption_ref,
        })
    }

    /// The keyed digest this authority — and only this authority — derives
    /// for one receipt under one consumption row. `attest` produces it and
    /// `authorize` re-derives it, so an attestation made anywhere else is a
    /// value this authority would never have written.
    fn provenance_of(
        &self,
        receipt: &ExecutionConsumptionReceipt,
        consumption_ref: &str,
    ) -> Result<DigestRef, PermitError> {
        let projection = json!({
            "consumption_ref": consumption_ref,
            "receipt": serde_json::to_value(receipt)
                .map_err(|e| PermitError::Malformed(e.to_string()))?,
        });
        record_digest(
            RECEIPT_PROVENANCE_TAG,
            &projection,
            RecordDigestKey::Object {
                key_ref: &self.key_ref,
                secret: &self.secret,
            },
        )
        .ok_or(PermitError::Unattestable)
    }

    /// The gate. Every check is a refusal, and the order is deliberate: the
    /// absent permit first (the commonest and most serious mistake), the
    /// provenance next (an attestation this authority did not make is not an
    /// attestation), the spent permit, then the bindings, then the clock.
    ///
    /// It takes a [`ConsumedReceipt`], not a receipt: the authenticated
    /// constructor is part of the gate (D-R3-1).
    pub fn authorize(
        &self,
        consumed: Option<ConsumedReceipt<'_>>,
        expect: &Expectation<'_>,
    ) -> Result<ExecutionPermit, PermitError> {
        let consumed = consumed.ok_or(PermitError::NoPermit)?;
        // Both keyed tags, re-verified rather than trusted: the receipt was
        // admitted here, and the attestation was made here.
        self.check_admission(consumed.receipt)?;
        let mine = self.provenance_of(consumed.receipt, consumed.consumption_ref)?;
        if mine.class != consumed.provenance.class
            || mine.algorithm != consumed.provenance.algorithm
            || mine.key_ref != consumed.provenance.key_ref
            || !ct_eq_str(&mine.value_hex, &consumed.provenance.value_hex)
        {
            return Err(PermitError::ForeignAttestation);
        }
        let receipt = &consumed.receipt.wire;
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
        let mut permit = ExecutionPermit {
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
            seal: [0u8; 32],
        };
        // The seal covers the permit's whole recorded projection — the seal
        // itself is `skip`ped, so this is exactly what a later reader sees.
        permit.seal = self.tag(PERMIT_SEAL_TAG, &permit)?;
        Ok(permit)
    }

    /// Whether this authority sealed that permit. Crate-private: it is
    /// [`crate::dispatch`]'s first refusal, not a question a caller asks.
    pub(crate) fn sealed(&self, permit: &ExecutionPermit) -> bool {
        match self.tag(PERMIT_SEAL_TAG, permit) {
            Ok(expected) => ct_eq(&permit.seal, &expected),
            Err(_) => false,
        }
    }

    /// The one use, claimed in the ledger this authority owns. Crate-private
    /// for the same reason: no call site chooses the ledger.
    pub(crate) fn claim_single_use(&self, permit: &ExecutionPermit) -> Result<Claim, String> {
        self.ledger.claim_single_use(permit)
    }

    fn check_admission(&self, receipt: &ExecutionConsumptionReceipt) -> Result<(), PermitError> {
        let expected = self.tag(RECEIPT_ADMISSION_TAG, &receipt.wire)?;
        if ct_eq(&receipt.admission, &expected) {
            Ok(())
        } else {
            Err(PermitError::UnadmittedReceipt)
        }
    }

    /// The keyed tag over any canonicalizable projection.
    fn tag<T: Serialize>(&self, domain: &str, value: &T) -> Result<[u8; 32], PermitError> {
        let projection =
            serde_json::to_value(value).map_err(|e| PermitError::Malformed(e.to_string()))?;
        let preimage =
            tagged_canonical(domain, &projection).map_err(|_| PermitError::Unattestable)?;
        Ok(hmac_sha256(&self.secret, &preimage))
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
        "this receipt was not admitted by this consumption authority: a receipt is byom's reply \
         through `admit`, never JSON someone had to hand"
    )]
    UnadmittedReceipt,
    #[error(
        "this attestation was made under another consumption authority's secret, so it proves \
         nothing here"
    )]
    ForeignAttestation,
    #[error("the receipt could not be canonicalized for attestation")]
    Unattestable,
}

/// The local intersection `ExecutionPermit` (§16.1): the owner's exact
/// receipt narrowed by Kovee's current restrictions, recording every
/// contributing digest. Holding one is what makes egress lawful; it is
/// minted only by [`ConsumptionAuthority::authorize`] and carries no
/// credential.
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
///
/// And it is *sealed*: the private `seal` is a keyed tag over everything
/// below, so a permit minted under another authority is refused at dispatch
/// even though the value itself is perfectly well formed.
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
    /// The authority's keyed tag over every member above. Not recorded: it
    /// authenticates the value inside this process, and the audit record is
    /// byom's members plus Kovee's own, not Kovee's internal key material.
    #[serde(skip)]
    seal: [u8; 32],
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
///
/// A ledger is chosen **once**, when the [`ConsumptionAuthority`] is built,
/// and `dispatch` takes the authority rather than a ledger: R3's confirmation
/// dispatched a forged permit against a ledger of its own writing, and that
/// argument no longer exists.
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

/// Fixtures shared with the broker's tests. A test receipt is built from
/// byom's reply JSON and admitted by a test authority — the same door
/// production uses, because there is no other.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod fixture {
    use super::*;
    use serde_json::json;

    /// The daemon's per-realm consumption secret, in a test.
    pub(crate) const SECRET: [u8; 32] = [11u8; 32];
    pub(crate) const KEY_REF: &str = "kovee-consumption-object:realm-personal";
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

    /// The daemon's authority over a ledger the caller supplies.
    pub(crate) fn authority(ledger: &dyn SpentLedger) -> ConsumptionAuthority<'_> {
        ConsumptionAuthority::new(KEY_REF, SECRET, ledger)
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
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let receipt = authority.admit(&reply_ok()).unwrap();
        let consumed = authority.attest(&receipt, CONSUMPTION).unwrap();
        let permit = authority
            .authorize(Some(consumed), &expectation(&s, &di, &f, &o))
            .unwrap();
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
        assert_eq!(
            permit.owner_receipt_provenance().key_ref.as_deref(),
            Some(KEY_REF)
        );
        // The destination is bound HERE, from the provider binding.
        assert_eq!(permit.bound_origin(), &o);
        assert_eq!(
            permit.bound_egress_policy(),
            &EgressPolicy::allowing([o.clone()])
        );
        // The seal is this authority's, and it is not part of the record.
        assert!(authority.sealed(&permit));
        let json = serde_json::to_string(&permit).unwrap();
        assert!(!json.contains("seal"));
        // And no credential rides along.
        assert!(!json.contains("api-key") && !json.contains("sk-"));
    }

    #[test]
    fn no_receipt_is_the_refusal_that_matters_most() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let ledger = MemorySpentLedger::default();
        assert_eq!(
            authority(&ledger)
                .authorize(None, &expectation(&s, &di, &f, &o))
                .unwrap_err(),
            PermitError::NoPermit
        );
    }

    /// R3's confirmation minted a permit from JSON of its own under a secret
    /// of its own. Both halves are now refused at runtime as well as at
    /// compile time: a receipt admitted by one authority cannot be attested,
    /// nor an attestation honored, by another.
    #[test]
    fn a_receipt_or_attestation_from_another_authority_is_refused() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let ledger = MemorySpentLedger::default();
        let daemon = authority(&ledger);
        let forger =
            ConsumptionAuthority::new("kovee-consumption-object:mine", [0xffu8; 32], &ledger);

        // The forger admits its own reply — and the daemon will not attest it.
        let theirs = forger.admit(&reply_ok()).unwrap();
        assert_eq!(
            daemon.attest(&theirs, CONSUMPTION).unwrap_err(),
            PermitError::UnadmittedReceipt
        );
        // Nor will the daemon authorize the forger's own attestation, even of
        // a receipt the daemon itself admitted.
        let ours = daemon.admit(&reply_ok()).unwrap();
        let attested_elsewhere = forger.attest(&theirs, CONSUMPTION).unwrap();
        assert_eq!(
            daemon
                .authorize(Some(attested_elsewhere), &expectation(&s, &di, &f, &o))
                .unwrap_err(),
            PermitError::UnadmittedReceipt
        );
        // The daemon's own chain still works, and the forger cannot seal it.
        let consumed = daemon.attest(&ours, CONSUMPTION).unwrap();
        let permit = daemon
            .authorize(Some(consumed), &expectation(&s, &di, &f, &o))
            .unwrap();
        assert!(daemon.sealed(&permit));
        assert!(
            !forger.sealed(&permit),
            "a permit is sealed to one authority"
        );
    }

    /// An attestation whose receipt IS admitted here but whose keyed
    /// provenance came from elsewhere: the separate `ForeignAttestation`
    /// refusal, reached by handing one authority's `ConsumedReceipt` to
    /// another that shares the admission secret but not the key_ref.
    #[test]
    fn an_attestation_keyed_under_another_key_ref_is_refused() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let ledger = MemorySpentLedger::default();
        let daemon = authority(&ledger);
        // Same secret (so `admit` agrees), different key_ref (so the
        // provenance digest, and therefore its tag, differs).
        let sibling = ConsumptionAuthority::new("kovee-consumption-object:other", SECRET, &ledger);
        let receipt = daemon.admit(&reply_ok()).unwrap();
        let elsewhere = sibling.attest(&receipt, CONSUMPTION).unwrap();
        assert_eq!(
            daemon
                .authorize(Some(elsewhere), &expectation(&s, &di, &f, &o))
                .unwrap_err(),
            PermitError::ForeignAttestation
        );
    }

    #[test]
    fn the_provenance_binds_the_exact_receipt_bytes_and_its_consumption() {
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let receipt = authority.admit(&reply_ok()).unwrap();
        let one = authority.attest(&receipt, CONSUMPTION).unwrap();
        // The same receipt under the same consumption re-derives identically:
        // an auditor holding the daemon's secret can re-check the permit.
        assert_eq!(
            authority
                .attest(&receipt, CONSUMPTION)
                .unwrap()
                .provenance(),
            one.provenance()
        );
        // Another consumption record, or another receipt, does not.
        let other_row = authority.attest(&receipt, "eac-2").unwrap();
        assert_ne!(other_row.provenance(), one.provenance());
        let mut altered = reply_ok();
        altered["mandate_use_ref"] = serde_json::json!("muse-someone-elses");
        let altered = authority.admit(&altered).unwrap();
        assert_ne!(
            authority
                .attest(&altered, CONSUMPTION)
                .unwrap()
                .provenance(),
            one.provenance()
        );
        // And a different daemon secret does not either.
        let elsewhere = ConsumptionAuthority::new(KEY_REF, [12u8; 32], &ledger);
        let theirs = elsewhere.admit(&reply_ok()).unwrap();
        assert_ne!(
            elsewhere.attest(&theirs, CONSUMPTION).unwrap().provenance(),
            one.provenance()
        );
    }

    #[test]
    fn a_spent_one_shot_permit_cannot_authorize_a_second_dispatch() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let receipt = authority.admit(&reply_ok()).unwrap();
        let mut expect = expectation(&s, &di, &f, &o);
        expect.already_spent = true;
        assert_eq!(
            authority
                .authorize(
                    Some(authority.attest(&receipt, CONSUMPTION).unwrap()),
                    &expect
                )
                .unwrap_err(),
            PermitError::SpentPermit
        );
        // A receipt CLAIMING more than one use is refused outright.
        let mut multi = reply_ok();
        multi["max_uses"] = serde_json::json!(2);
        let multi = authority.admit(&multi).unwrap();
        assert_eq!(
            authority
                .authorize(
                    Some(authority.attest(&multi, CONSUMPTION).unwrap()),
                    &expectation(&s, &di, &f, &o)
                )
                .unwrap_err(),
            PermitError::NotOneShot(2)
        );
    }

    #[test]
    fn the_durable_ledger_grants_the_single_use_exactly_once() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let receipt = authority.admit(&reply_ok()).unwrap();
        // TWO permits from the ONE receipt: a caller that never consulted the
        // spent flag. The value is not what limits the use — the ledger is.
        let first = authority
            .authorize(
                Some(authority.attest(&receipt, CONSUMPTION).unwrap()),
                &expectation(&s, &di, &f, &o),
            )
            .unwrap();
        let second = authority
            .authorize(
                Some(authority.attest(&receipt, CONSUMPTION).unwrap()),
                &expectation(&s, &di, &f, &o),
            )
            .unwrap();
        assert_eq!(authority.claim_single_use(&first).unwrap(), Claim::Claimed);
        assert_eq!(
            authority.claim_single_use(&second).unwrap(),
            Claim::AlreadySpent
        );
        // And the first permit itself cannot be re-claimed either.
        assert_eq!(
            authority.claim_single_use(&first).unwrap(),
            Claim::AlreadySpent
        );
    }

    /// Every refusal below shares the same shape, so they share a helper: the
    /// daemon's authority admits `reply`, attests it, and reports what the
    /// gate said.
    fn refusal(reply: &Value, expect: &Expectation<'_>) -> PermitError {
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let receipt = authority.admit(reply).unwrap();
        let consumed = authority.attest(&receipt, CONSUMPTION).unwrap();
        authority
            .authorize(Some(consumed), expect)
            .expect_err("the gate must refuse")
    }

    #[test]
    fn a_receipt_for_another_key_audience_or_subject_is_refused() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let expect = expectation(&s, &di, &f, &o);
        let mut other_key = reply_ok();
        other_key["stable_execution_key"] = serde_json::json!("exec-other");
        assert!(matches!(
            refusal(&other_key, &expect),
            PermitError::WrongExecutionKey { .. }
        ));
        let mut other_audience = reply_ok();
        other_audience["driver_audience"] = serde_json::json!("kovee-other-broker");
        assert!(matches!(
            refusal(&other_audience, &expect),
            PermitError::WrongAudience { .. }
        ));
        let mut other_subject = reply_ok();
        other_subject["subject_digest"] = serde_json::to_value(d(0xee)).unwrap();
        assert_eq!(
            refusal(&other_subject, &expect),
            PermitError::SubjectMismatch
        );
    }

    #[test]
    fn a_different_disclosure_is_refused_and_an_unreported_one_is_recorded() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let expect = expectation(&s, &di, &f, &o);
        let mut changed = reply_ok();
        changed["disclosure_digest"] = serde_json::to_value(d(0xdd)).unwrap();
        assert_eq!(refusal(&changed, &expect), PermitError::DisclosureMismatch);
        // A digest byom did not report is NAMED in the permit, never assumed
        // to match. byomd re-derived it against its own committed act inside
        // the consuming transaction, so the authorization still binds it.
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let mut absent = reply_ok();
        absent["disclosure_digest"] = Value::Null;
        let absent = authority.admit(&absent).unwrap();
        let permit = authority
            .authorize(
                Some(authority.attest(&absent, CONSUMPTION).unwrap()),
                &expect,
            )
            .unwrap();
        assert_eq!(
            permit.owner_unverified_digests(),
            ["disclosure_digest".to_owned()]
        );
        // And a healthy receipt names nothing as unverified.
        let receipt = authority.admit(&reply_ok()).unwrap();
        let permit = authority
            .authorize(
                Some(authority.attest(&receipt, CONSUMPTION).unwrap()),
                &expect,
            )
            .unwrap();
        assert!(permit.owner_unverified_digests().is_empty());
    }

    #[test]
    fn a_stale_fence_or_another_episode_is_refused() {
        let (s, di, o) = (d(0x03), d(0x04), origin());
        // The binding digest advanced: the fence moved under the receipt.
        let advanced = d(0x55);
        assert_eq!(
            refusal(&reply_ok(), &expectation(&s, &di, &advanced, &o)),
            PermitError::StaleFence
        );
        let f = d(0x05);
        let expect = expectation(&s, &di, &f, &o);
        let mut other_episode = reply_ok();
        other_episode["episode_ref"] = serde_json::json!("ep-2");
        assert!(matches!(
            refusal(&other_episode, &expect),
            PermitError::EpisodeMismatch { .. }
        ));
        // A governed call whose receipt binds no Episode at all.
        let mut unbound = reply_ok();
        unbound["episode_ref"] = Value::Null;
        unbound["episode_fence_digest"] = Value::Null;
        assert_eq!(refusal(&unbound, &expect), PermitError::Unbound);
        // And the converse: an episode-bound receipt for an unbound call.
        let mut no_episode = expectation(&s, &di, &f, &o);
        no_episode.episode = None;
        assert_eq!(refusal(&reply_ok(), &no_episode), PermitError::Unbound);
    }

    #[test]
    fn an_expired_or_unreadable_deadline_fails_closed() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let expect = expectation(&s, &di, &f, &o);
        let mut expired = reply_ok();
        expired["expires_at"] = serde_json::json!(EARLIER);
        assert!(matches!(
            refusal(&expired, &expect),
            PermitError::Expired(_)
        ));
        let mut unreadable = reply_ok();
        unreadable["expires_at"] = serde_json::json!("whenever");
        assert!(matches!(
            refusal(&unreadable, &expect),
            PermitError::UnreadableExpiry(_)
        ));
    }

    #[test]
    fn another_byomd_incarnation_or_recovery_epoch_is_refused() {
        let (s, di, f, o) = (d(0x03), d(0x04), d(0x05), origin());
        let expect = expectation(&s, &di, &f, &o);
        let mut reincarnated = reply_ok();
        reincarnated["endpoint_incarnation"] = serde_json::json!("inst-2");
        assert_eq!(refusal(&reincarnated, &expect), PermitError::WrongEndpoint);
        let mut recovered = reply_ok();
        recovered["recovery_epoch"] = serde_json::json!(1);
        assert_eq!(refusal(&recovered, &expect), PermitError::WrongEndpoint);
    }

    #[test]
    fn byoms_reply_parses_and_an_unknown_member_fails_closed() {
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let wire = reply_ok();
        let parsed = authority.admit(&wire).unwrap();
        assert_eq!(parsed.receipt_id(), "ecr-1");
        assert_eq!(parsed.stable_execution_key(), "exec-abc");
        assert_eq!(parsed.mandate_use_ref(), "muse-1");
        assert_eq!(parsed.intent_ref(), "actint-1");
        assert_eq!(parsed.byom_endpoint_ref(), "byom-endpoint-local");
        assert_eq!(parsed.digest(), Some(&d(0x06)));
        assert!(!parsed.is_replay());
        // It round-trips through Kovee's own durable record: the stored reply
        // RE-ADMITS to the identical receipt, admission tag included, which is
        // what makes the crash-recovery path use the SAME door as the live one.
        let stored = serde_json::to_value(&parsed).unwrap();
        assert_eq!(authority.admit(&stored).unwrap(), parsed);
        // byom's replay marker.
        let mut replayed = wire.clone();
        replayed["replayed"] = serde_json::json!(true);
        assert!(authority.admit(&replayed).unwrap().is_replay());
        // A member Kovee does not understand is not silently ignored.
        let mut extended = wire;
        extended["some_new_grant"] = serde_json::json!("trust me");
        assert!(matches!(
            authority.admit(&extended).unwrap_err(),
            PermitError::Malformed(_)
        ));
    }

    #[test]
    fn the_keyed_tag_is_compared_in_constant_time() {
        // Not a timing measurement — a proof that the comparison used is the
        // folding one and reports what `==` would.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        assert!(ct_eq(&a, &b));
        b[31] = 1;
        assert!(!ct_eq(&a, &b));
        a[0] = 9;
        assert!(!ct_eq(&a, &b));
    }
}
