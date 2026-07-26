//! K2 — the model broker against the REAL `byomd` (byom f232b04, the
//! `model_egress` act chain of DESIGN.md §13.1-§13.3).
//!
//! No stub anywhere on the authority side: it builds and spawns byom's
//! daemon, activates a real Episode, drives byom's own act chain
//! (`act_intent_prepare` → `act_intent_position` → `act_intent_finalize`),
//! and then makes Kovee's broker consume the permit and dispatch. The only
//! substituted piece is the wire itself — a
//! [`RecordingTransport`](kovee_effects::RecordingTransport) stands in for
//! the provider so "zero requests left" is a machine-checkable fact. Every
//! effect dispatched through it records `transport_profile:
//! recording-test-double`, so no receipt can claim a real provider call.
//!
//! | property | proof | asserted from |
//! |---|---|---|
//! | no permit → no egress | `no_permit_means_no_provider_call` | BOTH |
//! | a spent one-shot permit refuses a second dispatch | `a_spent_permit_refuses_a_second_dispatch` | BOTH |
//! | a stale fence refuses | `a_stale_fence_refuses_before_any_byte_leaves` | BOTH |
//! | prepared-before-egress, proven by a real crash | `a_crash_between_prepare_and_dispatch_leaves_a_prepared_undispatched_effect` | BOTH |
//! | an uncertain send is ambiguous, frozen, reconcilable | `an_uncertain_send_is_ambiguous_and_frozen_until_reconciled` | Kovee |
//! | the disclosure manifest is complete, incl. `training_use` | `the_disclosure_manifest_is_complete_and_names_training_use` | Kovee |
//! | the credential is nowhere a worker or an event can see it | `the_credential_never_reaches_worker_visible_state` | Kovee |
//!
//! Gated on the byom repository being present — `$KOVEE_BYOM_REPO`, else the
//! sibling `../byom`. When present it always runs; it never silently passes
//! on a byomd failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};

use common::byomd::*;
use common::tmp;
use kovee_byom::bpp::Endpoint;
use kovee_core::family::DigestRef;
use kovee_core::problem::ProblemKind;
use kovee_effects::{EffectState, RecordingTransport, Transport};
use kovee_store::Store;
use koveed::episode::{self, Notice, ParentItem, Runtime};
use koveed::model_broker::{self, ActAuthorization, CompleteRequest, Fault};
use serde_json::{json, Value};

const REALM: &str = "realm-personal";
const PROJECT: &str = "proj-broker";
const PROFILE: &str = "mp-anthropic-realm-personal";
/// byom's Δ4 class subject pins this exact audience for the model broker.
const BROKER: &str = "kovee-model-broker";
/// The provider reply the recording transport answers with.
const REPLY: &[u8] = br#"{"id":"msg_01broker","model":"claude-haiku-4-5-20251001",
    "stop_reason":"end_turn","content":[{"type":"text","text":"OK"}],
    "usage":{"input_tokens":41,"output_tokens":2}}"#;
/// The credential the broker must inject — and which must appear nowhere
/// else. Distinctive so a substring scan is decisive.
const KEY: &str = "sk-ant-k2-broker-canary-000";

// ------------------------------------------------------------ the harness ----

struct Live {
    byomd: Byomd,
    agent: AgentSociety,
    store: Store,
    endpoint: Endpoint,
    channels: PathBuf,
    base: PathBuf,
    /// The running Episode's binding, and the attempt bound to it.
    bound: episode::Bound,
    attempt_id: String,
    fence: u64,
}

/// One worker call's OWNED inputs. Owned so a test can hold it across a
/// `&mut store` borrow — everything the broker needs, and nothing it does
/// not (no provider, host, header, or credential is expressible here).
struct Call {
    attempt_id: String,
    fence: u64,
    binding_key: String,
    prompt: String,
}

impl Call {
    fn request(&self) -> CompleteRequest<'_> {
        CompleteRequest {
            realm: REALM,
            project: Some(PROJECT),
            attempt_id: &self.attempt_id,
            fence_epoch: self.fence,
            model_profile_ref: PROFILE,
            purpose_ref: "purpose-explore-live",
            classification_ref: "class-public",
            system: Some(SYSTEM),
            prompt: &self.prompt,
            max_output_tokens: 64,
            stable_binding_key: Some(&self.binding_key),
        }
    }
}

/// The assistant instruction every call in this suite sends.
const SYSTEM: &str = "Answer with OK.";

impl Live {
    fn runtime(&self) -> Runtime {
        Runtime::new(&self.endpoint, &self.channels)
    }

    fn call(&self, prompt: &str) -> Call {
        Call {
            attempt_id: self.attempt_id.clone(),
            fence: self.fence,
            binding_key: self.bound.stable_binding_key.clone(),
            prompt: prompt.to_owned(),
        }
    }

    fn events(&self) -> Vec<Value> {
        let mut stmt = self
            .store
            .conn()
            .prepare("SELECT payload, type FROM events ORDER BY stream_sequence ASC")
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok(json!({
                    "type": r.get::<_, String>(1)?,
                    "payload": r.get::<_, Option<String>>(0)?,
                }))
            })
            .unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    fn effect(&self, effect_id: &str) -> Value {
        let row = model_broker::read_effect(self.store.conn(), effect_id)
            .unwrap()
            .expect("the effect row");
        json!({
            "state": row.state,
            "execution_key": row.execution_key,
            "act_intent_ref": row.act_intent_ref,
            "episode_ref": row.episode_ref,
            "disclosure_manifest_ref": row.disclosure_manifest_ref,
        })
    }

    fn count(&self, sql: &str) -> i64 {
        self.store.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }
}

/// Boots byomd, activates a real Episode, and prepares the worker attempt
/// and provider binding the broker needs. `None` when this checkout is
/// standalone.
fn live(tag: &str) -> Option<Live> {
    let repo = byom_repo()?;
    let binary = byomd_binary(&repo);
    let base = tmp(tag);
    let byomd = Byomd::start(&binary, &base.join("byom-data"), &base.join("byom-run"));
    let agent = bootstrap_agent_society(&byomd, tag);
    let mut store = Store::open(&base.join("kovee.sqlite3")).unwrap();
    store.bootstrap(0).unwrap();
    koveed::budget::seam_fixture(&mut store, &agent.society_id, 0, &agent.incarnation);
    let endpoint = Endpoint::at("local", &byomd.run_dir);
    let channels = byomd.channels_dir();

    // A real Episode, activated across both daemons (the k2_episode_live
    // path): the model call runs INSIDE it and presents both its fences.
    let runtime = Runtime::new(&endpoint, &channels);
    let wake = wake_intent(&byomd, &agent, "b1");
    let mut notice = notice(&agent, &wake);
    let channel = runtime
        .participant_channel(&agent.participant_ref)
        .expect("claim the participant channel");
    let requested =
        episode::request(&mut store, &runtime, &channel, &notice, 0).expect("episode_request");
    notice.resource_allocation_ref = requested.resource_allocation_ref.clone().unwrap();
    notice.resource_allocation_digest = requested.resource_allocation_digest.clone().unwrap();
    let episode_ref = requested.episode_ref.clone();
    let placed = episode::place(&mut store, REALM, &notice, "kovee-inv-broker", 0).unwrap();
    episode::admit(&mut store, &runtime, &placed.placement_id, &notice, 0)
        .expect("placement_admit");
    let bound = episode::start(
        &mut store,
        &runtime,
        &placed.placement_id,
        &notice,
        &episode_ref,
        600,
        0,
    )
    .expect("episode_claim + episode_start");

    // The worker attempt the model call is bound to, and the provider
    // binding it leaves through. The credential lives in the DAEMON's
    // environment, never in a worker request.
    let (_, attempt_id, fence) =
        koveed::invoke::attempt_fixture(&mut store, PROJECT, None, None).unwrap();
    std::env::set_var("ANTHROPIC_API_KEY", KEY);
    model_broker::seed_default_bindings(&mut store, REALM, 0).unwrap();

    Some(Live {
        byomd,
        agent,
        store,
        endpoint,
        channels,
        base,
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
        byom_budget_reservation_ref: format!("rset-{allocation}"),
        byom_reservation_set_revision: 1,
        external_budget_bridge_ref: format!("bridge-{allocation}"),
        stable_external_reservation_key: format!("sub-{allocation}"),
        parent_reservation_items: vec![ParentItem {
            account_ref: PARENT_ACCOUNT.to_owned(),
            account_revision: 1,
            dimension: "unit".to_owned(),
            unit: "unit".to_owned(),
            worst_case_amount: EPISODE_WORST_CASE,
        }],
        context_manifest_ref: "kovee-ctxman-broker".to_owned(),
    }
}

/// Stages the disclosure manifest, then runs byom's OWN act chain over it
/// and returns the authorization notice byom produced. Kovee invents none of
/// it, and byomd re-derives every member inside `execution_permit_consume`.
fn authorize(live: &mut Live, key: &str, call: &Call, audience: &str) -> ActAuthorization {
    let (profile, binding) = model_broker::read_profile(live.store.conn(), REALM, PROFILE).unwrap();
    let staged = model_broker::stage(&mut live.store, &call.request(), &profile, &binding, 0)
        .expect("stage the disclosure manifest");
    let disclosure_ref = staged.disclosure_manifest_ref().to_owned();
    let disclosure_digest = staged.disclosure_digest().clone();
    prepare_position_finalize(
        &live.byomd,
        &live.agent,
        key,
        audience,
        &disclosure_ref,
        &disclosure_digest,
    )
}

/// byom's own act chain for one `model_egress` act, over Kovee's committed
/// disclosure manifest. Returns the notice `execution_permit_consume` will
/// re-derive every member of.
fn prepare_position_finalize(
    byomd: &Byomd,
    agent: &AgentSociety,
    key: &str,
    audience: &str,
    disclosure_ref: &str,
    disclosure_digest: &DigestRef,
) -> ActAuthorization {
    let prepared = participant_call(
        byomd,
        &agent.channel,
        &json!({
            "version": BPP_VERSION, "op": "act_intent_prepare",
            "meta": agent.meta(&format!("actprep-{key}"), None),
            "kind": "model_egress",
            "execution_kind": "external_effect",
            "subject_ref": format!("subject-{key}"),
            "subject_revision": 1,
            "mandate_ref": agent.mandate_id,
            // byom's own current revision and subject digest, read from its
            // store: a caller that guesses either is refused.
            "mandate_revision": mandate_revision(byomd, &agent.mandate_id),
            "mandate_digest": mandate_subject_digest(byomd, &agent.mandate_id),
            "context_manifest_ref": "kovee-ctxman-broker",
            // byom's act_intent_prepare requires the KEYED class here: the
            // ContextManifest is a local object whose verifiability byom
            // erases with the act, not one it recomputes.
            "context_manifest_digest": keyed_digest(0xe1),
            "disclosure_manifest_ref": disclosure_ref,
            "disclosure_manifest_digest": serde_json::to_value(disclosure_digest).unwrap(),
            "driver_audience": audience,
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
    // The human GATE seat assents, then ONE GovernanceDecision is derived.
    byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION, "op": "act_intent_position",
            "meta": agent.meta(&format!("actpos-{key}"), None),
            "proposal_ref": intent_id,
            "proposal_revision": 1,
            "subject_digest": subject_digest,
            "seat_ref": seat,
            "value": "assent",
        }),
    );
    let finalized = byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION, "op": "act_intent_finalize",
            "meta": agent.meta(&format!("actfin-{key}"), Some(1)),
            "intent_id": intent_id,
            "subject_digest": subject_digest,
        }),
    );
    assert_eq!(finalized["result"]["state"], json!("authorized"));
    ActAuthorization {
        act_intent_digest: serde_json::from_value(intent_digest(byomd, &intent_id)).unwrap(),
        act_revision: finalized["result"]["revision"].as_u64().unwrap(),
        subject_digest: serde_json::from_value(subject_digest).unwrap(),
        stable_execution_key: result["stable_execution_key"].as_str().unwrap().to_owned(),
        budget_reservation_set_ref: result["budget_reservation_set_ref"]
            .as_str()
            .unwrap()
            .to_owned(),
        act_intent_ref: intent_id,
    }
}

/// Prepares an act and STOPS: no seat has assented, so nothing authorizes it.
fn prepare_only(
    byomd: &Byomd,
    agent: &AgentSociety,
    key: &str,
    disclosure_ref: &str,
    disclosure_digest: &DigestRef,
) -> ActAuthorization {
    let prepared = participant_call(
        byomd,
        &agent.channel,
        &json!({
            "version": BPP_VERSION, "op": "act_intent_prepare",
            "meta": agent.meta(&format!("actprep-{key}"), None),
            "kind": "model_egress",
            "execution_kind": "external_effect",
            "subject_ref": format!("subject-{key}"),
            "subject_revision": 1,
            "mandate_ref": agent.mandate_id,
            // byom's own current revision and subject digest, read from its
            // store: a caller that guesses either is refused.
            "mandate_revision": mandate_revision(byomd, &agent.mandate_id),
            "mandate_digest": mandate_subject_digest(byomd, &agent.mandate_id),
            "context_manifest_ref": "kovee-ctxman-broker",
            // byom's act_intent_prepare requires the KEYED class here: the
            // ContextManifest is a local object whose verifiability byom
            // erases with the act, not one it recomputes.
            "context_manifest_digest": keyed_digest(0xe1),
            "disclosure_manifest_ref": disclosure_ref,
            "disclosure_manifest_digest": serde_json::to_value(disclosure_digest).unwrap(),
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
    ActAuthorization {
        act_intent_digest: serde_json::from_value(intent_digest(byomd, &intent_id)).unwrap(),
        act_revision: 1,
        subject_digest: serde_json::from_value(result["subject_digest"].clone()).unwrap(),
        stable_execution_key: result["stable_execution_key"].as_str().unwrap().to_owned(),
        budget_reservation_set_ref: result["budget_reservation_set_ref"]
            .as_str()
            .unwrap()
            .to_owned(),
        act_intent_ref: intent_id,
    }
}

/// byom's own committed digests, read out of byomd's store the way byom's
/// fixtures do (byom exposes them on no wire surface).
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
        "key_ref": format!("kovee-broker-test-object:{seed:02x}"),
        "value_hex": format!("{seed:02x}").repeat(32),
    })
}

/// Advances the byom fence epoch in the COMMITTED binding record — the value
/// Kovee actually presents — so the next consumption carries a superseded
/// pair and byomd itself refuses it.
fn advance_byom_fence(live: &Live, key: &str) {
    let text: String = live
        .store
        .conn()
        .query_row(
            "SELECT record FROM byom_episode_bindings WHERE stable_binding_key = ?1",
            [key],
            |r| r.get(0),
        )
        .unwrap();
    let mut record: Value = serde_json::from_str(&text).unwrap();
    let next = record["byom_fence_epoch"].as_u64().unwrap() + 1;
    record["byom_fence_epoch"] = json!(next);
    live.store
        .conn()
        .execute(
            "UPDATE byom_episode_bindings SET record = ?2, byom_fence_epoch = ?3
             WHERE stable_binding_key = ?1",
            rusqlite::params![key, record.to_string(), next as i64],
        )
        .unwrap();
}

fn skipped(tag: &str) {
    println!("{tag}: skipped — no byom repository (set KOVEE_BYOM_REPO or check out ../byom)");
}

// ------------------------------------------------------------ the refusals ----

#[test]
fn no_permit_means_no_provider_call() {
    let Some(mut live) = live("k2-broker-no-permit") else {
        return skipped("k2_broker");
    };
    let runtime = live.runtime();
    let call = live.call("Say OK.");
    let (profile, binding) = model_broker::read_profile(live.store.conn(), REALM, PROFILE).unwrap();
    let staged =
        model_broker::stage(&mut live.store, &call.request(), &profile, &binding, 0).unwrap();
    // The act is PREPARED but nothing has authorized it: no seat assented, so
    // there is no GovernanceDecision and nothing to consume.
    let authorization = prepare_only(
        &live.byomd,
        &live.agent,
        "np",
        staged.disclosure_manifest_ref(),
        staged.disclosure_digest(),
    );
    let transport = RecordingTransport::answering(REPLY);
    let refused = model_broker::complete(
        &mut live.store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    )
    .expect_err("no permit, no call");

    // byom's own answer, passed through: the act is `prepared`, so there is
    // no decision to consume.
    assert!(
        refused
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("prepared"),
        "{refused:?}"
    );
    assert_eq!(transport.send_count(), 0, "NOT ONE BYTE left");
    // The prepared effect exists — it is committed before authority is asked
    // for — but no attempt and no consumption do.
    assert_eq!(live.count("SELECT COUNT(*) FROM model_effects"), 1);
    assert_eq!(live.count("SELECT COUNT(*) FROM model_effect_attempts"), 0);
    assert_eq!(
        live.count("SELECT COUNT(*) FROM external_authorization_consumptions"),
        0
    );
    // And byom minted no receipt and inserted no MandateUse.
    assert_eq!(
        live.byomd
            .count("SELECT COUNT(*) FROM execution_consumption_receipts"),
        0
    );
    assert_eq!(live.byomd.count("SELECT COUNT(*) FROM mandate_uses"), 0);
}

#[test]
fn a_spent_permit_refuses_a_second_dispatch() {
    let Some(mut live) = live("k2-broker-spent") else {
        return skipped("k2_broker");
    };
    let runtime = live.runtime();
    let call = live.call("Say OK.");
    let authorization = authorize(&mut live, "sp", &call, BROKER);
    let transport = RecordingTransport::answering(REPLY);
    let first = model_broker::complete(
        &mut live.store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    )
    .expect("the first, authorized call");
    assert_eq!(first.state, EffectState::Completed);
    assert_eq!(transport.send_count(), 1);
    assert_eq!(
        live.byomd
            .count("SELECT COUNT(*) FROM execution_consumption_receipts"),
        1
    );
    assert_eq!(
        live.byomd.count("SELECT COUNT(*) FROM mandate_uses"),
        1,
        "exactly one MandateUse for one consumption"
    );

    // A second dispatch under the SAME one-shot permit. The effect already
    // has a dispatched attempt, so the gate answers SPENT — and it does so
    // before the transport is touched.
    let (profile, binding) = model_broker::read_profile(live.store.conn(), REALM, PROFILE).unwrap();
    let staged =
        model_broker::stage(&mut live.store, &call.request(), &profile, &binding, 0).unwrap();
    let prepared = model_broker::prepare(
        &mut live.store,
        &call.request(),
        &authorization,
        &profile,
        &binding,
        &staged,
        0,
    )
    .expect("the same effect, found by its execution key");
    assert!(prepared.already_existed, "one effect per one-shot key");
    let spent = model_broker::consume_permit(
        &mut live.store,
        &runtime,
        &call.request(),
        &authorization,
        &prepared,
        0,
    )
    .expect_err("a spent one-shot permit authorizes nothing further");
    assert_eq!(spent.kind, ProblemKind::Forbidden, "{spent:?}");
    assert!(
        spent
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("already spent"),
        "{spent:?}"
    );
    assert_eq!(transport.send_count(), 1, "still exactly one request left");
    assert_eq!(live.byomd.count("SELECT COUNT(*) FROM mandate_uses"), 1);

    // And the whole call again under the same act is refused too: byom will
    // not consume a spent one-shot decision twice.
    let again = model_broker::complete(
        &mut live.store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    );
    assert!(again.is_err(), "a consumed act authorizes nothing further");
    assert_eq!(transport.send_count(), 1);
}

#[test]
fn a_stale_fence_refuses_before_any_byte_leaves() {
    let Some(mut live) = live("k2-broker-fence") else {
        return skipped("k2_broker");
    };
    let runtime = live.runtime();
    let call = live.call("Say OK.");
    let authorization = authorize(&mut live, "sf", &call, BROKER);

    // (a) KOVEE's fence: the worker's attempt fence advances, so the fence it
    // presents is superseded and §15.2 refuses before anything else happens.
    let advanced =
        koveed::invoke::advance_attempt_fence(&mut live.store, &live.attempt_id).unwrap();
    assert_eq!(advanced, live.fence + 1);
    let transport = RecordingTransport::answering(REPLY);
    let refused = model_broker::complete(
        &mut live.store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    )
    .expect_err("a stale attempt fence authorizes nothing");
    assert_eq!(refused.kind, ProblemKind::StaleLease, "{refused:?}");
    assert_eq!(transport.send_count(), 0, "NOT ONE BYTE left");
    assert_eq!(live.count("SELECT COUNT(*) FROM model_effect_attempts"), 0);

    // (b) BYOM's fence: the Episode binding's byom fence advances, so the
    // consumption presents a superseded pair and byomd itself refuses.
    live.fence = advanced;
    advance_byom_fence(&live, &live.bound.stable_binding_key);
    let call = live.call("Say OK.");
    let refused = model_broker::complete(
        &mut live.store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    )
    .expect_err("a superseded byom fence authorizes nothing");
    assert!(
        matches!(
            refused.kind,
            ProblemKind::StaleRevision | ProblemKind::StaleLease
        ),
        "{refused:?}"
    );
    assert_eq!(transport.send_count(), 0, "NOT ONE BYTE left");
    assert_eq!(
        live.byomd
            .count("SELECT COUNT(*) FROM execution_consumption_receipts"),
        0,
        "no receipt is minted behind a stale fence"
    );
    assert_eq!(live.byomd.count("SELECT COUNT(*) FROM mandate_uses"), 0);
}

// --------------------------------------- prepared-before-egress (a crash) ----

/// The child half of the crash proof: prepare the effect, then die.
///
/// Not a test in its own right — it is `#[ignore]`d because the parent
/// re-execs this binary to run exactly it, under `$KOVEE_BROKER_CRASH_SPEC`.
#[test]
#[ignore = "driven by a_crash_between_prepare_and_dispatch_leaves_a_prepared_undispatched_effect"]
fn crash_child_prepares_then_dies() {
    let spec =
        std::env::var("KOVEE_BROKER_CRASH_SPEC").expect("this helper is driven by its parent test");
    let spec: Value = serde_json::from_str(&spec).unwrap();
    let store_path = spec["store"].as_str().unwrap().to_owned();
    let mut store = Store::open(Path::new(&store_path)).unwrap();
    let authorization = ActAuthorization {
        act_intent_ref: spec["act_intent_ref"].as_str().unwrap().to_owned(),
        act_intent_digest: serde_json::from_value(spec["act_intent_digest"].clone()).unwrap(),
        act_revision: spec["act_revision"].as_u64().unwrap(),
        subject_digest: serde_json::from_value(spec["subject_digest"].clone()).unwrap(),
        stable_execution_key: spec["stable_execution_key"].as_str().unwrap().to_owned(),
        budget_reservation_set_ref: spec["budget_reservation_set_ref"]
            .as_str()
            .unwrap()
            .to_owned(),
    };
    let call = Call {
        attempt_id: spec["attempt_id"].as_str().unwrap().to_owned(),
        fence: spec["fence_epoch"].as_u64().unwrap(),
        binding_key: spec["stable_binding_key"].as_str().unwrap().to_owned(),
        prompt: "Say OK.".to_owned(),
    };
    let runtime_dir = PathBuf::from(spec["runtime_dir"].as_str().unwrap());
    let channels = PathBuf::from(spec["channels"].as_str().unwrap());
    let endpoint = Endpoint::at("local", &runtime_dir);
    let runtime = Runtime::new(&endpoint, &channels);
    let transport = RecordingTransport::answering(REPLY);
    // Dies by `abort()` the instant the prepared effect is committed.
    let _ = model_broker::complete(
        &mut store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::AbortAfterPrepare,
    );
    panic!("the child was supposed to abort after preparing");
}

#[test]
fn a_crash_between_prepare_and_dispatch_leaves_a_prepared_undispatched_effect() {
    let Some(mut live) = live("k2-broker-crash") else {
        return skipped("k2_broker");
    };
    let runtime = live.runtime();
    let call = live.call("Say OK.");
    let authorization = authorize(&mut live, "cr", &call, BROKER);
    let store_path = live.base.join("kovee.sqlite3");
    let spec = json!({
        "store": store_path.to_string_lossy(),
        "runtime_dir": live.endpoint.runtime_dir().to_string_lossy(),
        "channels": live.channels.to_string_lossy(),
        "attempt_id": call.attempt_id,
        "fence_epoch": call.fence,
        "stable_binding_key": call.binding_key,
        "act_intent_ref": authorization.act_intent_ref,
        "act_intent_digest": serde_json::to_value(&authorization.act_intent_digest).unwrap(),
        "act_revision": authorization.act_revision,
        "subject_digest": serde_json::to_value(&authorization.subject_digest).unwrap(),
        "stable_execution_key": authorization.stable_execution_key,
        "budget_reservation_set_ref": authorization.budget_reservation_set_ref,
    });
    // Hand the database file to the child.
    live.store = Store::open_in_memory().unwrap();

    // A REAL crash: a child process runs the chain and `abort()`s the instant
    // the prepared effect is committed.
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crash_child_prepares_then_dies",
            "--ignored",
            "--test-threads",
            "1",
        ])
        .env("KOVEE_BROKER_CRASH_SPEC", spec.to_string())
        .env("ANTHROPIC_API_KEY", KEY)
        .env("KOVEE_BYOM_CHANNELS_DIR", &live.channels)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawn the crash child");
    assert!(!status.success(), "the child must have aborted: {status:?}");

    // Reopen the database the dead process left behind.
    live.store = Store::open(&store_path).unwrap();
    let effect = model_broker::effect_by_execution_key(
        live.store.conn(),
        &authorization.stable_execution_key,
    )
    .unwrap()
    .expect("the prepared effect survived the crash");
    assert_eq!(
        effect.state, "prepared",
        "committed BEFORE authority was asked for and before any egress"
    );
    // Nothing dispatched, nothing consumed, and — decisively — byom minted no
    // receipt, so the one-shot authority is intact and no provider call could
    // have happened.
    assert_eq!(live.count("SELECT COUNT(*) FROM model_effect_attempts"), 0);
    assert_eq!(
        live.count("SELECT COUNT(*) FROM external_authorization_consumptions"),
        0
    );
    assert_eq!(
        live.byomd
            .count("SELECT COUNT(*) FROM execution_consumption_receipts"),
        0
    );
    assert_eq!(live.byomd.count("SELECT COUNT(*) FROM mandate_uses"), 0);
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM act_intents WHERE intent_id = ?1",
            &authorization.act_intent_ref
        ),
        Some("authorized".to_owned()),
        "the act is still authorized and unconsumed"
    );
    // The `prepared` event is on the stream, the `dispatching` one is not.
    let types: Vec<String> = live
        .events()
        .iter()
        .map(|e| e["type"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(types
        .iter()
        .any(|t| t == "dev.kovee.model-effect.prepared.v1"));
    assert!(
        !types
            .iter()
            .any(|t| t == "dev.kovee.model-effect.dispatching.v1"),
        "{types:?}"
    );

    // The startup sweep does NOT make it ambiguous: nothing was sent.
    let recovered = model_broker::recover_dispatching(&mut live.store, 0).unwrap();
    assert_eq!(recovered, 0);
    assert_eq!(live.effect(&effect.effect_id)["state"], json!("prepared"));

    // And the retry is a REPLAY of the same effect, not a second one.
    let transport = RecordingTransport::answering(REPLY);
    let completed = model_broker::complete(
        &mut live.store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    )
    .expect("the retry completes once");
    assert_eq!(completed.effect_id, effect.effect_id);
    assert_eq!(completed.state, EffectState::Completed);
    assert_eq!(live.count("SELECT COUNT(*) FROM model_effects"), 1);
    assert_eq!(transport.send_count(), 1, "exactly one provider call ever");
}

// ------------------------------------------------------- ambiguity, frozen ----

#[test]
fn an_uncertain_send_is_ambiguous_and_frozen_until_reconciled() {
    let Some(mut live) = live("k2-broker-ambiguous") else {
        return skipped("k2_broker");
    };
    let runtime = live.runtime();
    let call = live.call("Say OK.");
    let authorization = authorize(&mut live, "am", &call, BROKER);
    // The request left, and then the connection died: the outcome is UNKNOWN.
    // "No receipt observed" is not proof of failure (§16.1).
    let transport = RecordingTransport::uncertain("connection reset after write");
    let outcome = model_broker::complete(
        &mut live.store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    )
    .expect("an ambiguous outcome is recorded, not raised");
    assert_eq!(outcome.state, EffectState::Ambiguous);
    assert!(outcome.retry_frozen, "retry is frozen, never auto-retried");
    assert!(outcome
        .observation
        .as_deref()
        .unwrap()
        .contains("may have been transmitted"));
    assert_eq!(transport.send_count(), 1);
    assert_eq!(live.effect(&outcome.effect_id)["state"], json!("ambiguous"));
    assert_eq!(frozen_flag(&live, &outcome.effect_attempt_id), 1);
    let types: Vec<String> = live
        .events()
        .iter()
        .map(|e| e["type"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(
        types
            .iter()
            .any(|t| t == "dev.kovee.model-effect.ambiguous.v1"),
        "{types:?}"
    );

    // Reconciliation is an operator act. It records what was observed and
    // clears the freeze; it cannot unconsume the byom permit.
    model_broker::reconcile(
        &mut live.store,
        &outcome.effect_attempt_id,
        EffectState::Failed,
        "the provider's dashboard shows no request for this idempotency key",
        0,
    )
    .expect("reconcile");
    assert_eq!(live.effect(&outcome.effect_id)["state"], json!("failed"));
    assert_eq!(frozen_flag(&live, &outcome.effect_attempt_id), 0);
    // The consumed MandateUse stays consumed: another attempt needs a NEW act.
    assert_eq!(live.byomd.count("SELECT COUNT(*) FROM mandate_uses"), 1);
    // And a second reconciliation of an already-resolved attempt is refused.
    assert!(model_broker::reconcile(
        &mut live.store,
        &outcome.effect_attempt_id,
        EffectState::Completed,
        "changed my mind",
        0,
    )
    .is_err());
}

/// byom's receipt and the local intersection permit for one execution key.
fn consumption(live: &Live, execution_key: &str) -> (Value, Value) {
    let (receipt, permit): (String, String) = live
        .store
        .conn()
        .query_row(
            "SELECT receipt, permit FROM external_authorization_consumptions
             WHERE execution_key = ?1",
            [execution_key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    (
        serde_json::from_str(&receipt).unwrap(),
        serde_json::from_str(&permit).unwrap(),
    )
}

fn frozen_flag(live: &Live, attempt_id: &str) -> i64 {
    live.store
        .conn()
        .query_row(
            "SELECT retry_frozen FROM model_effect_attempts WHERE effect_attempt_id = ?1",
            [attempt_id],
            |r| r.get(0),
        )
        .unwrap()
}

// ------------------------------------------- disclosure and the credential ----

#[test]
fn the_disclosure_manifest_is_complete_and_names_training_use() {
    let Some(mut live) = live("k2-broker-disclosure") else {
        return skipped("k2_broker");
    };
    let runtime = live.runtime();
    let prompt = "Summarize the pinned note.";
    let call = live.call(prompt);
    let authorization = authorize(&mut live, "dm", &call, BROKER);
    let transport = RecordingTransport::answering(REPLY);
    let completed = model_broker::complete(
        &mut live.store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    )
    .expect("the call");

    let disclosure =
        model_broker::read_disclosure(live.store.conn(), &completed.disclosure_manifest_ref)
            .unwrap()
            .expect("the disclosure manifest is persisted");
    // All three provider claims, and `training_use` is one of them.
    assert!(disclosure.provider_claims.is_complete());
    assert_eq!(disclosure.provider_claims.training_use, "prohibited");
    assert!(!disclosure.provider_claims.region.is_empty());
    assert!(!disclosure.provider_claims.retention.is_empty());
    // The exact items that left, with their sizes — not a topic name.
    assert_eq!(
        disclosure.exact_items.len(),
        2,
        "the assistant instruction and the prompt"
    );
    assert_eq!(disclosure.total_bytes, (SYSTEM.len() + prompt.len()) as u64);
    assert_eq!(disclosure.recipient_kind, "model_provider");
    assert_eq!(
        disclosure.recipient_binding,
        format!("model-profile:{PROFILE}")
    );
    assert_eq!(disclosure.purpose, "purpose-explore-live");
    assert_eq!(disclosure.data_classes, vec!["class-public".to_owned()]);
    // The digest is keyed under this disclosure's own object secret:
    // destroying it erases exactly this disclosure's verifiability.
    assert_eq!(disclosure.digest.class, "local_erasure_safe");

    // And byom's one-shot permit bound exactly this disclosure. The
    // consumption row carries both byom's receipt and the local intersection
    // permit the gate minted from it.
    let (receipt, permit) = consumption(&live, &authorization.stable_execution_key);
    assert_eq!(receipt["max_uses"], json!(1));
    assert_eq!(receipt["driver_audience"], json!(BROKER));
    assert!(!receipt["mandate_use_ref"].is_null());
    assert_eq!(
        permit["disclosure_digest"],
        serde_json::to_value(&disclosure.digest).unwrap(),
        "the permit authorized THIS disclosure"
    );
    assert_eq!(permit["phase"], json!("pre_egress"));
    assert_eq!(permit["owner_protocol"], json!("byom"));
    assert_eq!(permit["max_uses"], json!(1));
    // byom 12c8fd2 renders every receipt digest member (it previously
    // rendered them null, which is why this once asserted the opposite).
    // Nothing is left unverified: the permit re-checked every echo against
    // what Kovee sent, and byomd re-derived them against its own committed
    // act inside the consuming transaction.
    let unverified: Vec<String> = permit["owner_unverified_digests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert!(
        unverified.is_empty(),
        "byom publishes every receipt digest now: {unverified:?}"
    );
    // The receipt's own binding digest is the one that authenticates the
    // permit before egress, so re-derive it rather than trusting it: it is
    // portable_public per A8, over the frozen fragment both sides hold.
    let receipt_digest = &receipt["digest"];
    assert_eq!(receipt_digest["class"], json!("portable_public"));
    assert_eq!(receipt_digest["algorithm"], json!("sha-256"));
    assert!(
        receipt_digest["key_ref"].is_null(),
        "a portable_public digest carries no key_ref: {receipt_digest}"
    );
    assert_eq!(
        receipt["mandate_use_digest"]["class"],
        json!("portable_public"),
        "the MandateUse pin must be consumer-derivable (A8)"
    );

    // The §16.3 chain is persisted, ordered, and ends at the exact bytes.
    let chain = model_broker::read_provider_context(
        live.store.conn(),
        &completed.provider_context_manifest_ref,
    )
    .unwrap()
    .expect("the provider-context manifest is persisted");
    let orders: Vec<u64> = chain.ordered_segments.iter().map(|s| s.order).collect();
    assert_eq!(orders, vec![1, 2, 3]);
    assert_eq!(chain.final_provider_request_typed_byte_digest.len(), 64);
    assert_eq!(chain.disclosure_manifest_ref, disclosure.disclosure_id);
    // byom's §12.1 source fragment is carried, and it is byom's own.
    let source = chain.byom_source.expect("the byom source fragment");
    assert_eq!(source.episode_ref, live.bound.episode_ref);
    assert_eq!(source.byom_fence_epoch, live.bound.fences.byom);
    assert_eq!(source.society_ref, live.agent.society_id);
}

#[test]
fn the_credential_never_reaches_worker_visible_state() {
    let Some(mut live) = live("k2-broker-credential") else {
        return skipped("k2_broker");
    };
    let runtime = live.runtime();
    let call = live.call("Say OK.");
    let authorization = authorize(&mut live, "cd", &call, BROKER);
    let transport = RecordingTransport::answering(REPLY);
    let completed = model_broker::complete(
        &mut live.store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    )
    .expect("the call");

    // 1. It DID reach the wire — the broker really injected it.
    let sent = transport.sent().pop().expect("one request");
    assert_eq!(sent.header("x-api-key"), Some(KEY));
    assert_eq!(sent.origin.host, "api.anthropic.com");
    assert_eq!(sent.origin.scheme, "https");
    assert_eq!(sent.path, "/v1/messages");

    // 2. The worker's view carries no key, no host, no URL, no header.
    let view = completed.worker_view().to_string();
    for forbidden in [KEY, "sk-ant", "x-api-key", "api.anthropic.com", "https://"] {
        assert!(
            !view.contains(forbidden),
            "the worker's reply leaked {forbidden}: {view}"
        );
    }
    assert!(view.contains("\"text\":\"OK\""), "{view}");

    // 3. No event payload carries it either.
    for event in live.events() {
        let text = event.to_string();
        for forbidden in [KEY, "sk-ant", "x-api-key", "api.anthropic.com"] {
            assert!(
                !text.contains(forbidden),
                "event {} leaked {forbidden}",
                event["type"]
            );
        }
    }

    // 4. Nor does any stored broker record.
    for sql in [
        "SELECT record FROM disclosure_manifests",
        "SELECT record FROM provider_context_manifests",
        "SELECT receipt FROM external_authorization_consumptions",
        "SELECT record FROM model_profiles",
    ] {
        let mut stmt = live.store.conn().prepare(sql).unwrap();
        let rows: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        for text in rows {
            assert!(!text.contains(KEY), "{sql} leaked the credential");
            assert!(!text.contains("sk-ant"), "{sql} leaked a key-shaped string");
        }
    }

    // 5. The provider binding records a REFERENCE, never the secret.
    let binding_record: String = live
        .store
        .conn()
        .query_row(
            "SELECT record FROM model_provider_bindings WHERE provider_kind = 'anthropic'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(binding_record.contains("env:ANTHROPIC_API_KEY"));
    assert!(!binding_record.contains(KEY));

    // 6. And the effect records WHICH wire carried it, so no receipt can
    //    claim a real provider call that did not happen.
    let profile: String = live
        .store
        .conn()
        .query_row(
            "SELECT transport_profile FROM model_effect_attempts WHERE effect_attempt_id = ?1",
            [&completed.effect_attempt_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(profile, kovee_effects::PROFILE_RECORDING);
    assert_eq!(completed.transport_profile, transport.profile());
}

// ----------------------------------------------------------- the metering ----

#[test]
fn usage_is_metered_to_byoms_meter_channel() {
    let Some(mut live) = live("k2-broker-metering") else {
        return skipped("k2_broker");
    };
    let runtime = live.runtime();
    let call = live.call("Say OK.");
    let authorization = authorize(&mut live, "mt", &call, BROKER);
    let transport = RecordingTransport::answering(REPLY);
    let completed = model_broker::complete(
        &mut live.store,
        &runtime,
        &transport,
        &call.request(),
        &authorization,
        0,
        Fault::None,
    )
    .expect("the call");
    // The provider's own numbers, extracted by the driver.
    assert_eq!(completed.usage.input_tokens, 41);
    assert_eq!(completed.usage.output_tokens, 2);
    assert!(completed.usage_reported, "the meter channel was used");

    // Kovee's row is EVIDENCE; the settlement is byom's.
    let (input, output): (i64, i64) = live
        .store
        .conn()
        .query_row(
            "SELECT input_tokens, output_tokens FROM model_usage_reports
             WHERE effect_attempt_id = ?1",
            [&completed.effect_attempt_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((input, output), (41, 2));
    // byom holds the report on its own side, and its conservation ledger
    // still balances after the settlement it decided on.
    assert!(
        live.byomd.count("SELECT COUNT(*) FROM usage_reports") >= 1,
        "byom holds the usage report"
    );
    let ledger = live.byomd.ledger(PARENT_ACCOUNT);
    assert!(ledger.conserves(), "{ledger:?}");
    let types: Vec<String> = live
        .events()
        .iter()
        .map(|e| e["type"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(
        types
            .iter()
            .any(|t| t == "dev.kovee.model-effect.usage-reported.v1"),
        "{types:?}"
    );
}
