//! R3's own probes, kept as tests, from an OUTSIDE crate using only the
//! public production API — which is where the forgery lived.
//!
//! What is left here is small, and that is the result rather than a gap.
//! R3's third confirmation stopped forging the *pieces* and built the
//! **authority**: its own secret, its own ledger that forgets, its own
//! receipt JSON, and that same authority handed to `dispatch` — two permits,
//! two claims, two sends. So the authority itself left the public surface.
//! From out here there is now no way to
//!
//! - construct a [`ConsumptionAuthority`] (`new` is crate-private and
//!   test-only),
//! - be a [`SpentLedger`] (the trait is sealed by an unnameable supertrait),
//! - take the daemon's grant (`take_daemon_authority` is compiled only into a
//!   `daemon` build), or
//! - therefore admit a receipt, attest one, mint a permit, or call `dispatch`
//!   at all.
//!
//! Every one of those is a compile error with a diagnostic asserted in
//! `tests/compile_gate.rs` — including R3's probe reproduced **verbatim** as
//! one program — because a refusal that is a compile error cannot be a
//! runtime test. The runtime half of the old file (a forged permit refused by
//! the daemon's authority, and the lawful control that reaches the wire) moved
//! into the crate's own tests, where it could be made stronger than it was:
//! `broker::tests::a_permit_from_an_authority_of_ones_own_sends_nothing` now
//! gives the forger the daemon's **own key material**, so the refusal is the
//! daemon's durable ledger and not a key mismatch, and
//! `a_permit_altered_after_it_was_sealed_sends_nothing` sweeps every sealed
//! member.
//!
//! What remains testable from out here is what an outside crate can still
//! reach — and it is inert.
//!
//! The honest boundary, stated where it is easiest to check: this closes the
//! external-crate path. It does not distinguish the daemon from other code
//! compiled into a `daemon` build; only byom signing its own receipts could,
//! and byom does not sign them today.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use kovee_core::family::DigestRef;
use kovee_effects::*;
use serde_json::json;

const CONTEXT_SECRET: [u8; 32] = [7u8; 32];

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
            act_intent_ref: "actint-forged",
            subject_digest: &subject,
            context_manifest_ref: "ctxman-forged",
            context_manifest_digest: &subject,
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

/// R3-B01. Everything the adversary still holds after building the whole
/// chain by hand: the plan, the receipt JSON it authored, and the
/// `Expectation` it would have passed — every input to the gate except the
/// one that matters.
///
/// It cannot turn any of it into a receipt, an attestation or a permit,
/// because all three exist only as a `ConsumptionAuthority` returns them and
/// there is no way out here to have one. That step is a compile error, so
/// what this test pins is the runtime fact underneath it: these values are
/// data, and no public function turns data into authority.
#[test]
fn everything_an_outside_crate_can_still_author_is_only_data() {
    let plan = planned();
    let fence = d(0x05);
    let bound = origin();

    // The receipt JSON R3's confirmation authored — still perfectly writable,
    // and still just JSON. `admit` is the only thing that makes a receipt of
    // it, and `admit` is a method on a value this crate cannot obtain.
    let forged = reply(&plan, &fence);
    assert_eq!(forged["max_uses"], 1);
    assert_eq!(forged["stable_execution_key"], "exec-forged");
    assert_eq!(forged["driver_audience"], BROKER_DRIVER_AUDIENCE);

    // The Expectation is public — it is what the DAEMON passes in, and it
    // carries no authority of its own.
    let expect = expectation(&plan, &fence, &bound);
    assert_eq!(expect.execution_key, "exec-forged");
    assert!(!expect.already_spent);

    // And the plan is sealed over the exact bytes, so even the one input the
    // adversary fully controls cannot be edited after the fact.
    plan.context_manifest()
        .check_bytes(&plan.request().body)
        .unwrap();
    assert_eq!(plan.origin(), &bound);
    assert!(plan.host_effect_digest().key_ref.is_none());
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

/// The one wire an outside crate can name is `Egress`, and naming it is all
/// it can do: no transport to construct, no `send` to call, and no second
/// egress-shaped thing in the crate. (`tests/compile_gate.rs` proves the
/// absences, by the root path and by the module path both.)
#[test]
fn the_only_reachable_wire_is_the_sealed_one() {
    let live = Egress::live();
    assert_eq!(live.profile(), PROFILE_HTTPS);
    assert_eq!(Egress::live().profile(), live.profile());
    // The profile is what an audit reads to tell a real provider call from a
    // test one, and a production build has only this one to report.
    assert_ne!(PROFILE_HTTPS, PROFILE_RECORDING);
    // The egress carries no destination and no credential of its own: both
    // arrive at `dispatch`, from the permit and the daemon's secret table.
    assert!(!format!("{live:?}").contains("sk-"));
}
