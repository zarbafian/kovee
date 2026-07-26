//! K2 — ONE real model call per provider, through the whole enforcement
//! chain: byom's act chain, the one-shot permit, the fail-closed egress
//! checks, a live TLS 1.3 request to the provider, and the metering report on
//! byom's meter channel.
//!
//! Nothing is substituted. `k2_broker` proves the refusals with a recording
//! transport; this suite proves the happy path is not a fiction — that the
//! bytes the chain sealed are the bytes a real provider accepts, that the
//! credential the broker injects is the one the provider authenticates, and
//! that the usage the provider reports is what reaches byom.
//!
//! Doubly gated, and it skips CLEANLY rather than failing:
//!
//! - `#[ignore]` — it needs outbound TCP 443 and spends real money, so it
//!   never runs in the default suite. Run it with:
//!   ```text
//!   ANTHROPIC_API_KEY=sk-ant-… cargo test -p koveed --test k2_broker_live -- --ignored
//!   ```
//! - the provider's key must be in the environment, and the byom repository
//!   must be present (`$KOVEE_BYOM_REPO`, else the sibling `../byom`).
//!
//! The model is `$KOVEE_LIVE_ANTHROPIC_MODEL` / `$KOVEE_LIVE_OPENAI_MODEL`
//! when set, else the constants the broker ships with.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::byomd::*;
use common::tmp;
use kovee_byom::bpp::Endpoint;
use kovee_core::family::DigestRef;
use kovee_effects::{EffectState, Egress, ProviderClaims, ProviderKind, RequestLimits};
use kovee_store::Store;
use koveed::episode::{self, Notice, Runtime};
use koveed::model_broker::{self, ActAuthorization, CompleteRequest, Fault};
use serde_json::{json, Value};

const REALM: &str = "realm-personal";
const PROJECT: &str = "proj-broker-live";
const BROKER: &str = "kovee-model-broker";
/// The HOST-owned ContextManifest every act in this suite is prepared under.
/// byom compares the ref AND the digest at consumption (R3-A01).
const CONTEXT_MANIFEST: &str = "kovee-ctxman-live";
/// A prompt whose correct answer is one token, so the call is cheap and the
/// assertion is unambiguous.
const PROMPT: &str = "Reply with exactly the two characters: OK";
const SYSTEM: &str = "You reply with exactly what you are asked for and nothing else.";

/// The env var that must hold the provider key, and the profile the broker
/// seeded for it.
fn provider_env(kind: ProviderKind) -> (&'static str, &'static str, &'static str) {
    match kind {
        ProviderKind::Anthropic => (
            "ANTHROPIC_API_KEY",
            "mp-anthropic-realm-personal",
            "KOVEE_LIVE_ANTHROPIC_MODEL",
        ),
        ProviderKind::Openai => (
            "OPENAI_API_KEY",
            "mp-openai-realm-personal",
            "KOVEE_LIVE_OPENAI_MODEL",
        ),
    }
}

// -------------------------------------------------------------- the tests ----

#[test]
#[ignore = "needs ANTHROPIC_API_KEY and outbound TCP 443; spends real money"]
fn one_real_anthropic_call_through_the_whole_chain() {
    live_call(ProviderKind::Anthropic, "k2-broker-live-anthropic");
}

#[test]
#[ignore = "needs OPENAI_API_KEY and outbound TCP 443; spends real money"]
fn one_real_openai_call_through_the_whole_chain() {
    live_call(ProviderKind::Openai, "k2-broker-live-openai");
}

// R3-B02 removed the test that used to live here, and it could not survive
// the fix: it built an `HttpsTransport` and called `Transport::send`
// directly, with a `PreparedRequest` of its own and no permit — the exact
// bypass the seal closes. `Transport`, `HttpsTransport` and `RawResponse`
// are crate-private now, and the only public way a byte leaves is
// `kovee_effects::dispatch`, against a permit this daemon's own
// `ConsumptionAuthority` sealed.
//
// What that test proved — that the live wire reaches both providers and
// that an invalid key comes back as a mapped 401 — is proved by
// `live_call` below, over the whole governed chain, whenever a key is in
// the environment. It is no longer separately cheap to check, and that is
// the cost of the seal rather than an oversight.

/// The whole path for one provider: byom's act chain, the permit, the real
/// TLS request, the outcome, and the metering report.
fn live_call(kind: ProviderKind, tag: &str) {
    let (env_name, profile_ref, model_env) = provider_env(kind);
    let Some(key) = std::env::var(env_name).ok().filter(|k| !k.is_empty()) else {
        return println!("{tag}: skipped — ${env_name} is not set");
    };
    let Some(mut live) = boot(tag) else {
        return println!(
            "{tag}: skipped — no byom repository (set KOVEE_BYOM_REPO or check out ../byom)"
        );
    };
    // The credential is in the DAEMON's environment; the broker is the only
    // reader, and the seeding below records only a REFERENCE to it.
    std::env::set_var(env_name, &key);
    let model = std::env::var(model_env).ok().filter(|m| !m.is_empty());
    let claims = ProviderClaims {
        region: "us".to_owned(),
        retention: "30-days".to_owned(),
        training_use: "prohibited".to_owned(),
    };
    let selector = model.unwrap_or_else(|| {
        match kind {
            ProviderKind::Anthropic => kovee_effects::ANTHROPIC_MODEL,
            ProviderKind::Openai => kovee_effects::OPENAI_MODEL,
        }
        .to_owned()
    });
    let (binding, profile) = model_broker::register(
        &mut live.store,
        REALM,
        kind,
        claims,
        &format!("env:{env_name}"),
        &selector,
        RequestLimits {
            input_tokens: 10_000,
            output_tokens: 32,
            calls: 1,
        },
        0,
    )
    .expect("register the provider binding");
    assert_eq!(profile.model_profile_id, profile_ref);
    assert!(binding.is_active());
    println!("{tag}: calling {} as {selector}", binding.endpoint);

    let call = Call {
        attempt_id: live.attempt_id.clone(),
        fence: live.fence,
        binding_key: live.bound.stable_binding_key.clone(),
        profile_ref: profile_ref.to_owned(),
    };
    let authorization = authorize(&mut live, "lv", &call);
    // THE live transport: rustls, TLS 1.3 only, Mozilla roots compiled in, no
    // redirects, and the connection-time address-class check. It is a
    // process singleton inside kovee-effects that no caller can name; this
    // is the whole of the public surface onto it.
    let egress = Egress::live();
    assert_eq!(egress.profile(), kovee_effects::PROFILE_HTTPS);
    let runtime = live.runtime();
    let completion = model_broker::complete(
        &mut live.store,
        &runtime,
        egress,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    )
    .unwrap_or_else(|e| panic!("{tag}: the live call failed: {e:?}"));

    // -- the model answered -------------------------------------------------
    assert_eq!(
        completion.state,
        EffectState::Completed,
        "{tag}: {completion:?}"
    );
    let text = completion.text.as_deref().unwrap_or_default();
    println!("{tag}: model said {text:?} ({:?})", completion.usage);
    assert!(
        text.to_ascii_uppercase().contains("OK"),
        "{tag}: unexpected answer {text:?}"
    );
    assert_eq!(
        completion.transport_profile,
        kovee_effects::PROFILE_HTTPS,
        "a REAL provider call, recorded as such"
    );

    // -- the usage the PROVIDER reported, metered to byom -------------------
    assert!(
        completion.usage.input_tokens > 0 && completion.usage.output_tokens > 0,
        "{tag}: the provider reported no usage: {:?}",
        completion.usage
    );
    assert!(completion.usage_reported, "{tag}: usage reached the meter");
    let (input, output): (i64, i64) = live
        .store
        .conn()
        .query_row(
            "SELECT input_tokens, output_tokens FROM model_usage_reports
             WHERE effect_attempt_id = ?1",
            [&completion.effect_attempt_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (input as u64, output as u64),
        (
            completion.usage.input_tokens,
            completion.usage.output_tokens
        )
    );
    assert!(
        live.byomd.count("SELECT COUNT(*) FROM usage_reports") >= 1,
        "byom holds the usage report"
    );
    let ledger = live.byomd.ledger(PARENT_ACCOUNT);
    assert!(ledger.conserves(), "{ledger:?}");

    // -- the authority that let it happen ----------------------------------
    assert_eq!(
        live.byomd
            .count("SELECT COUNT(*) FROM execution_consumption_receipts"),
        1,
        "exactly one consumed permit for one call"
    );
    assert_eq!(live.byomd.count("SELECT COUNT(*) FROM mandate_uses"), 1);
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM act_intents WHERE intent_id = ?1",
            &authorization.act_intent_ref
        ),
        Some("consumed".to_owned())
    );

    // -- and the credential is still nowhere a worker can see it ------------
    let view = completion.worker_view().to_string();
    for forbidden in [key.as_str(), "https://", &binding.endpoint.host] {
        assert!(
            !view.contains(forbidden),
            "{tag}: the worker's reply leaked {forbidden}"
        );
    }
    let disclosure =
        model_broker::read_disclosure(live.store.conn(), &completion.disclosure_manifest_ref)
            .unwrap()
            .expect("the disclosure manifest");
    assert_eq!(disclosure.provider_claims.training_use, "prohibited");
    assert_eq!(disclosure.total_bytes, (SYSTEM.len() + PROMPT.len()) as u64);
    let chain = model_broker::read_provider_context(
        live.store.conn(),
        &completion.provider_context_manifest_ref,
    )
    .unwrap()
    .expect("the provider-context manifest");
    assert_eq!(chain.final_provider_request_typed_byte_digest.len(), 64);
    assert_eq!(chain.model_profile.ref_, profile_ref);
}

// ------------------------------------------------------------ the harness ----

struct Live {
    byomd: Byomd,
    agent: AgentSociety,
    store: Store,
    endpoint: Endpoint,
    channels: PathBuf,
    bound: episode::Bound,
    attempt_id: String,
    fence: u64,
}

impl Live {
    fn runtime(&self) -> Runtime {
        Runtime::new(&self.endpoint, &self.channels)
    }
}

struct Call {
    attempt_id: String,
    fence: u64,
    binding_key: String,
    profile_ref: String,
}

impl Call {
    fn request(&self) -> CompleteRequest<'_> {
        CompleteRequest {
            realm: REALM,
            project: Some(PROJECT),
            attempt_id: &self.attempt_id,
            fence_epoch: self.fence,
            model_profile_ref: &self.profile_ref,
            purpose_ref: "purpose-explore-live",
            classification_ref: "class-public",
            system: Some(SYSTEM),
            prompt: PROMPT,
            max_output_tokens: 16,
            stable_binding_key: Some(&self.binding_key),
        }
    }
}

/// byomd plus one running Episode plus one running worker attempt.
fn boot(tag: &str) -> Option<Live> {
    let repo = byom_repo()?;
    let binary = byomd_binary(&repo);
    let base = tmp(tag);
    let byomd = Byomd::start(&binary, &base.join("byom-data"), &base.join("byom-run"));
    let agent = bootstrap_agent_society(&byomd, tag);
    let mut store = Store::open(&base.join("kovee.sqlite3")).unwrap();
    store.bootstrap(0).unwrap();
    koveed::budget::seam_fixture(&mut store, &agent.society_id, 0, &agent.incarnation);
    // The realm's CAPACITY CEILING: a subordinate reservation is debited
    // against a granted account, never against a fabricated name (R3-U03).
    koveed::budget::provision_realm_capacity(&mut store, "realm-personal", 0).unwrap();
    let endpoint = Endpoint::at("local", &byomd.run_dir);
    let channels = byomd.channels_dir();
    let runtime = Runtime::new(&endpoint, &channels);
    let wake = wake_intent(&byomd, &agent, "lv");
    let mut notice = notice(&agent, &wake);
    let channel = runtime
        .participant_channel(&agent.participant_ref)
        .expect("claim the participant channel");
    let requested =
        episode::request(&mut store, &runtime, &channel, &notice, 0).expect("episode_request");
    notice.resource_allocation_ref = requested.resource_allocation_ref.clone().unwrap();
    notice.resource_allocation_digest = requested.resource_allocation_digest.clone().unwrap();
    let episode_ref = requested.episode_ref.clone();
    let placed = episode::place(&mut store, REALM, &notice, "kovee-inv-live", 0).unwrap();
    episode::admit(&mut store, &runtime, &placed.placement_id, &notice, 0)
        .expect("placement_admit");
    let bound = episode::start(
        &mut store,
        &runtime,
        &placed.placement_id,
        &notice,
        &episode_ref,
        900,
        0,
    )
    .expect("episode_claim + episode_start");
    let (_, attempt_id, fence) =
        koveed::invoke::attempt_fixture(&mut store, PROJECT, None, None).unwrap();
    Some(Live {
        byomd,
        agent,
        store,
        endpoint,
        channels,
        bound,
        attempt_id,
        fence,
    })
}

fn notice(agent: &AgentSociety, wake: &str) -> Notice {
    let allocation = format!("alloc-{wake}-r1");
    Notice {
        society_ref: agent.society_id.clone(),
        recovery_epoch: 0,
        participant_ref: agent.participant_ref.clone(),
        participant_binding_epoch: agent.participant_binding_epoch,
        manifestation_ref: agent.manifestation_ref.clone(),
        activity_stream_ref: agent.activity_stream_ref.clone(),
        generation: 1,
        wake_intent_ref: wake.to_owned(),
        activation_admission_ref: format!("adm-{wake}-r1"),
        resource_allocation_ref: allocation.clone(),
        resource_allocation_digest: DigestRef::portable_public("0".repeat(64)),
        mandate_use_refs: vec![],
        // Replaced by byom's own PUBLISHED fragment once `episode_request`
        // answers (R3-L02).
        parent_budget: serde_json::Value::Null,
        context_manifest_ref: CONTEXT_MANIFEST.to_owned(),
    }
}

/// Stage the disclosure, then run byom's own act chain over it.
fn authorize(live: &mut Live, key: &str, call: &Call) -> ActAuthorization {
    let (profile, binding) =
        model_broker::read_profile(live.store.conn(), REALM, &call.profile_ref).unwrap();
    let staged = model_broker::stage(&mut live.store, &call.request(), &profile, &binding, 0)
        .expect("stage the disclosure manifest");
    let disclosure_ref = staged.disclosure_manifest_ref().to_owned();
    let disclosure_digest = staged.disclosure_digest().clone();
    let prepared = participant_call(
        &live.byomd,
        &live.agent.channel,
        &json!({
            "version": BPP_VERSION, "op": "act_intent_prepare",
            "meta": live.agent.meta(&format!("actprep-{key}"), None),
            "kind": "model_egress",
            "execution_kind": "external_effect",
            "subject_ref": format!("subject-{key}"),
            "subject_revision": 1,
            "mandate_ref": live.agent.mandate_id,
            "mandate_revision": mandate_revision(&live.byomd, &live.agent.mandate_id),
            "mandate_digest": mandate_subject_digest(&live.byomd, &live.agent.mandate_id),
            "context_manifest_ref": CONTEXT_MANIFEST,
            "context_manifest_digest": keyed_digest(0xe1),
            "disclosure_manifest_ref": disclosure_ref,
            "disclosure_manifest_digest": serde_json::to_value(&disclosure_digest).unwrap(),
            "driver_audience": BROKER,
        }),
    );
    assert_eq!(
        prepared["outcome"],
        json!("ok"),
        "act_intent_prepare: {prepared}"
    );
    let result = &prepared["result"];
    let intent_id = result["intent_id"].as_str().unwrap().to_owned();
    let subject_digest = result["subject_digest"].clone();
    let seat = result["required_seat_refs"][0].as_str().unwrap().to_owned();
    live.byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION, "op": "act_intent_position",
            "meta": live.agent.meta(&format!("actpos-{key}"), None),
            "proposal_ref": intent_id,
            "proposal_revision": 1,
            "subject_digest": subject_digest,
            "seat_ref": seat,
            "value": "assent",
        }),
    );
    let finalized = live.byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION, "op": "act_intent_finalize",
            "meta": live.agent.meta(&format!("actfin-{key}"), Some(1)),
            "intent_id": intent_id,
            "subject_digest": subject_digest,
        }),
    );
    ActAuthorization {
        act_intent_digest: serde_json::from_value(intent_digest(&live.byomd, &intent_id)).unwrap(),
        act_revision: finalized["result"]["revision"].as_u64().unwrap(),
        subject_digest: serde_json::from_value(subject_digest).unwrap(),
        // The HOST-owned ContextManifest pair the act's seats assented to.
        // byom compares BOTH at consumption now (R3-A01), so the values a
        // consumption presents are the ones prepared above — not an empty
        // pair, which is exactly what byom refuses.
        context_manifest_ref: CONTEXT_MANIFEST.to_owned(),
        context_manifest_digest: serde_json::from_value(keyed_digest(0xe1)).unwrap(),
        stable_execution_key: result["stable_execution_key"].as_str().unwrap().to_owned(),
        budget_reservation_set_ref: result["budget_reservation_set_ref"]
            .as_str()
            .unwrap()
            .to_owned(),
        act_intent_ref: intent_id,
    }
}

fn intent_digest(byomd: &Byomd, intent_id: &str) -> Value {
    let text = byomd
        .row(
            "SELECT intent_digest FROM act_intents WHERE intent_id = ?1",
            intent_id,
        )
        .unwrap_or_else(|| panic!("intent digest {intent_id}"));
    serde_json::from_str(&text).unwrap()
}

fn mandate_revision(byomd: &Byomd, mandate_id: &str) -> u64 {
    byomd
        .number(
            "SELECT revision FROM mandates WHERE mandate_id = ?1",
            mandate_id,
        )
        .unwrap_or(1)
        .max(0) as u64
}

fn mandate_subject_digest(byomd: &Byomd, mandate_id: &str) -> Value {
    let text = byomd
        .row(
            "SELECT subject_digest FROM mandates WHERE mandate_id = ?1",
            mandate_id,
        )
        .unwrap_or_else(|| panic!("mandate subject digest {mandate_id}"));
    serde_json::from_str(&text).unwrap()
}

fn keyed_digest(seed: u8) -> Value {
    json!({
        "class": "local_erasure_safe",
        "algorithm": "hmac-sha-256",
        "key_ref": format!("kovee-broker-live-object:{seed:02x}"),
        "value_hex": format!("{seed:02x}").repeat(32),
    })
}
