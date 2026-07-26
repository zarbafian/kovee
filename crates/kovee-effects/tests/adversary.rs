//! R3's own probes, kept as tests, from an OUTSIDE crate using only the
//! public production API — which is where the forgery lived.
//!
//! The probes themselves no longer compile: `ExecutionConsumptionReceipt::
//! from_result`, `ConsumedReceipt::attest`, the free `authorize`, the ledger
//! argument to `dispatch`, `HttpsTransport` and the `Transport` trait are all
//! gone from the public surface, and `tests/compile_gate.rs` proves each
//! refusal against rustc's own diagnostic.
//!
//! What is left to check at *runtime* is the part a compiler cannot state:
//! that an authority which is not this daemon's buys nothing. So the
//! adversary here does the strongest thing still available to an outside
//! crate — it builds a [`ConsumptionAuthority`] of its own, with its own
//! secret and a ledger that forgets, and mints a perfectly well-formed permit
//! — and that permit is refused, claims nothing, and sends nothing.
//!
//! The honest boundary, stated where it is easiest to check: code that can
//! construct a `ConsumptionAuthority` supplies the daemon's secret and the
//! daemon's ledger, so a library cannot tell it apart from the daemon. Only
//! byom signing its own receipts could, and byom does not sign them today.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kovee_core::family::DigestRef;
use kovee_effects::*;
use serde_json::json;

const CONTEXT_SECRET: [u8; 32] = [7u8; 32];
/// The daemon's per-realm consumption secret. A worker never sees it.
const DAEMON_SECRET: [u8; 32] = [11u8; 32];
const DAEMON_KEY_REF: &str = "kovee-consumption-object:realm-personal";

/// A destination that certainly does not resolve, so a probe that reaches the
/// socket makes no real network request — and reaching it at all is visible.
fn origin() -> Origin {
    Origin::https("forged.invalid", 443)
}

fn d(b: u8) -> DigestRef {
    DigestRef::portable_public(format!("{b:02x}").repeat(32))
}

fn claims() -> ProviderClaims {
    ProviderClaims {
        region: "us".into(),
        retention: "30-days".into(),
        training_use: "prohibited".into(),
    }
}

fn keys() -> PlanKeys<'static> {
    PlanKeys {
        context: RecordDigestKey::Object {
            key_ref: "kovee-provider-context-object:pcm-1",
            secret: &CONTEXT_SECRET,
        },
    }
}

fn planned() -> CallPlan {
    let binding = ModelProviderBinding::new(
        "mpb-1",
        "realm-personal",
        ProviderKind::Anthropic,
        origin(),
        claims(),
        "env:KOVEE_ADVERSARY_KEY",
        "terms-1",
    )
    .unwrap();
    let profile = ModelProfile::new(
        "mp-1",
        &binding,
        ANTHROPIC_MODEL,
        RequestLimits {
            input_tokens: 40_000,
            output_tokens: 1_024,
            calls: 1,
        },
    )
    .unwrap();
    let disclosure = DisclosureManifest::model_egress(
        "disc-1",
        "realm-personal",
        Some("proj-1"),
        Some("space-1"),
        "model-profile:mp-1",
        "purpose-review",
        &["collaboration_item"],
        vec![DisclosureItem {
            ref_: "contrib-1".into(),
            revision: Some(1),
            digest: d(0xb1),
            size: 12,
        }],
        Vec::new(),
        claims(),
        "2027-01-15T08:00:00Z",
    )
    .unwrap();
    let chain = ProviderContextManifest::build(
        "pcm-1",
        "inv-1",
        "att-1",
        1,
        Some(ByomSourceFields::example()),
        vec![Segment::new(
            SegmentKind::CollaborationItem,
            "contrib-1",
            1,
            d(2),
            "class-public",
        )],
        (
            &binding.model_provider_binding_id,
            binding.revision,
            binding.digest.clone(),
        ),
        (
            &profile.model_profile_id,
            profile.revision,
            profile.digest.clone(),
        ),
        &profile.adapter_version,
        &disclosure.disclosure_id,
        disclosure.digest.clone(),
        "authdep-1",
        d(0x44),
        "2027-01-15T08:00:00Z",
        keys().context,
    )
    .unwrap();
    let subject = d(0x03);
    plan(
        &PlanInput {
            effect_id: "meff-1",
            execution_key: "exec-forged",
            subject_digest: &subject,
            system: None,
            prompt: "Say OK.",
            max_output_tokens: 16,
            classification_ref: "class-public",
        },
        &binding,
        &profile,
        disclosure,
        chain,
        keys(),
    )
    .unwrap()
}

/// A credential the adversary resolved from the daemon's own environment.
fn credential() -> Credential {
    std::env::set_var("KOVEE_ADVERSARY_KEY", "sk-ant-stolen");
    resolve(&CredentialRef::Env("KOVEE_ADVERSARY_KEY".into()), |_| None).unwrap()
}

/// byom's reply for one consumption of this plan — or, in the adversary's
/// hands, the JSON it wishes byom had sent.
fn reply(plan: &CallPlan, fence: &DigestRef) -> serde_json::Value {
    json!({
        "receipt_id": "ecr-forged",
        "byom_endpoint_ref": "byom-endpoint-local",
        "endpoint_incarnation": "inst-1",
        "recovery_epoch": 0,
        "intent_ref": "actint-forged",
        "intent_digest": d(0x01),
        "mandate_use_ref": "muse-forged",
        "mandate_use_digest": d(0x02),
        "stable_execution_key": plan.execution_key(),
        "subject_digest": plan.subject_digest(),
        "disclosure_digest": plan.disclosure().digest,
        "driver_audience": BROKER_DRIVER_AUDIENCE,
        "participant_ref": "part-agent-1",
        "episode_ref": "ep-1",
        "episode_fence_digest": fence,
        "budget_reservation_set_ref": "rset-forged",
        "issued_at": "2027-01-15T08:00:00Z",
        "expires_at": "2099-01-15T09:00:00Z",
        "max_uses": 1,
        "digest": d(0x06),
    })
}

fn expectation<'a>(plan: &'a CallPlan, fence: &'a DigestRef, bound: &'a Origin) -> Expectation<'a> {
    Expectation {
        execution_key: plan.execution_key(),
        subject_digest: plan.subject_digest(),
        disclosure_digest: &plan.disclosure().digest,
        driver_audience: BROKER_DRIVER_AUDIENCE,
        episode: Some(EpisodeFence {
            episode_ref: "ep-1",
            fence_digest: fence,
            byom_fence_epoch: 7,
            kovee_invocation_fence: 1,
        }),
        endpoint_incarnation: "inst-1",
        recovery_epoch: 0,
        now: 1_800_000_000,
        already_spent: false,
        bound_origin: bound,
    }
}

/// A ledger that counts. As the daemon's, "claims == 0" proves a refusal
/// happened before the socket could open; as the adversary's, it is the
/// permissive ledger R3's confirmation supplied at the call site.
#[derive(Default)]
struct CountingLedger {
    claims: AtomicUsize,
}

impl CountingLedger {
    fn claims(&self) -> usize {
        self.claims.load(Ordering::SeqCst)
    }
}

impl SpentLedger for CountingLedger {
    fn claim_single_use(&self, _permit: &ExecutionPermit) -> Result<Claim, String> {
        self.claims.fetch_add(1, Ordering::SeqCst);
        Ok(Claim::Claimed)
    }
}

/// R3-B01. The adversary authors the receipt, chooses the secret and writes
/// the ledger — all of it, exactly as the confirmation did, except that the
/// three separate public entry points are now one authority it has to build
/// itself. The permit it gets is well formed and worthless: the daemon's
/// dispatch refuses it before the first check that could have let it through,
/// and the daemon's ledger never records a use.
#[test]
fn a_permit_from_an_authority_of_ones_own_sends_nothing() {
    let plan = planned();
    let fence = d(0x05);
    let bound = origin();

    // The adversary's authority: its own secret, and a ledger that forgets.
    let forgetful = CountingLedger::default();
    let forger =
        ConsumptionAuthority::new("kovee-consumption-object:mine", [0xffu8; 32], &forgetful);
    let receipt = forger.admit(&reply(&plan, &fence)).unwrap();
    let consumed = forger.attest(&receipt, "eac-forged").unwrap();
    let forged = forger
        .authorize(Some(consumed), &expectation(&plan, &fence, &bound))
        .expect("a well-formed permit, minted by a well-formed authority");
    assert_eq!(forged.execution_key(), "exec-forged");

    // The daemon's authority: its own secret, its own ledger.
    let rows = CountingLedger::default();
    let daemon = ConsumptionAuthority::new(DAEMON_KEY_REF, DAEMON_SECRET, &rows);
    let outcome = dispatch(
        &plan,
        forged,
        &Egress::live(),
        &credential(),
        &daemon,
        Duration::from_millis(200),
    );
    assert_eq!(outcome.state, EffectState::Failed);
    let observation = outcome.observation.unwrap_or_default();
    assert!(
        observation.contains("was not sealed by the consumption authority"),
        "the seal must be what refused it, not something downstream: {observation}"
    );
    assert!(
        !observation.contains("resolve"),
        "nothing may reach the transport: {observation}"
    );
    assert_eq!(rows.claims(), 0, "the daemon's ledger recorded no use");
    assert_eq!(
        forgetful.claims(),
        0,
        "and the adversary's own ledger was never consulted either — \
         `dispatch` takes the authority, not a ledger"
    );
}

/// A receipt or an attestation that came from somewhere else is refused
/// before it can become a permit at all — the two halves of R3's "any caller
/// can supply both the receipt and the supposed attestation secret".
#[test]
fn a_receipt_or_attestation_from_elsewhere_never_becomes_a_permit() {
    let plan = planned();
    let fence = d(0x05);
    let bound = origin();
    let rows = CountingLedger::default();
    let daemon = ConsumptionAuthority::new(DAEMON_KEY_REF, DAEMON_SECRET, &rows);
    let forgetful = CountingLedger::default();
    let forger =
        ConsumptionAuthority::new("kovee-consumption-object:mine", [0xffu8; 32], &forgetful);

    // A receipt the daemon did not admit.
    let theirs = forger.admit(&reply(&plan, &fence)).unwrap();
    assert_eq!(
        daemon.attest(&theirs, "eac-1").unwrap_err(),
        PermitError::UnadmittedReceipt
    );
    // An attestation the daemon did not make.
    let elsewhere = forger.attest(&theirs, "eac-1").unwrap();
    assert_eq!(
        daemon
            .authorize(Some(elsewhere), &expectation(&plan, &fence, &bound))
            .unwrap_err(),
        PermitError::UnadmittedReceipt
    );
}

/// The control that makes the two refusals above mean something: the same
/// chain, with the daemon's own authority throughout, does reach the wire.
/// The destination is `forged.invalid`, so "reached the wire" is a name
/// lookup and not a provider call.
#[test]
fn the_daemons_own_permit_does_reach_the_wire() {
    let plan = planned();
    let fence = d(0x05);
    let bound = origin();
    let rows = CountingLedger::default();
    let daemon = ConsumptionAuthority::new(DAEMON_KEY_REF, DAEMON_SECRET, &rows);
    let receipt = daemon.admit(&reply(&plan, &fence)).unwrap();
    let consumed = daemon.attest(&receipt, "eac-1").unwrap();
    let permit = daemon
        .authorize(Some(consumed), &expectation(&plan, &fence, &bound))
        .unwrap();
    let outcome = dispatch(
        &plan,
        permit,
        &Egress::live(),
        &credential(),
        &daemon,
        Duration::from_millis(200),
    );
    assert_eq!(
        rows.claims(),
        1,
        "the one use was claimed before the socket"
    );
    let observation = outcome.observation.unwrap_or_default();
    assert!(
        observation.contains("resolve"),
        "a lawful permit reaches the transport: {observation}"
    );
}

/// R3-B02's residue: what a caller holding a real provider credential can
/// still do. It can resolve the credential and hold an `Egress` — and there
/// is no method on either that moves a byte. The compile gate proves the
/// absence; this pins the two values that remain reachable.
#[test]
fn a_credential_and_an_egress_are_inert_without_a_permit() {
    let credential = credential();
    assert!(!credential.is_empty());
    // A credential cannot be read, serialized, or printed.
    assert_eq!(format!("{credential:?}"), "Credential(redacted, 13 bytes)");
    // An egress names its profile and does nothing else.
    let egress = Egress::live();
    assert_eq!(egress.profile(), PROFILE_HTTPS);
    // A request can still be BUILT — a driver is a pure mapping — but there
    // is nothing public to hand it to.
    let request = ANTHROPIC
        .build(&ModelRequest {
            model: ANTHROPIC_MODEL,
            system: None,
            prompt: "exfiltrate",
            max_output_tokens: 16,
        })
        .unwrap();
    assert_eq!(request.path, "/v1/messages");
}
