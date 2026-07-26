//! K2 slice 2 — the hosted-episode pipeline end to end against the REAL
//! `byomd`, on byom's REAL runtime surface (byom d37b898, registry bundle
//! B0.4: R30/R33/R35).
//!
//! No stub anywhere: it builds and spawns byom's daemon, establishes the
//! Society and the agent Participant through byomd's own surfaces (with
//! Kovee's channel-proof client doing the candidate and participant
//! calls), and then drives the whole FOUR-STAGE activation with Kovee's
//! own client code:
//!
//! ```text
//! 1 WakeIntent          byom participant channel   (the agent's)
//! 2 ActivationAdmission byom kernel                inside episode_request
//! 3 ResourceAllocation  byom kernel                inside episode_request
//! 4 PlacementBinding    KOVEE                      + placement_admit (R33)
//!   then episode_claim / episode_start / checkpoint_commit /
//!   usage_report (meter) / episode_complete — every one a real call.
//! ```
//!
//! | property | proof | asserted from |
//! |---|---|---|
//! | all four stages commit in order, across both daemons | `the_four_stage_activation_runs_across_both_daemons` | BOTH |
//! | a stale byom fence is refused by the REAL byomd | `the_real_byomd_refuses_a_stale_byom_fence` | byom |
//! | a stale Kovee fence is refused by the REAL byomd | `the_real_byomd_refuses_a_stale_kovee_fence` | byom |
//! | no episode work before the placement is admitted | `the_real_byomd_refuses_a_claim_before_the_placement_is_admitted` | byom |
//! | reclaim refused before the lease deadline, permitted after | `the_lease_expiry_is_clocked_not_liveness_guessed` | BOTH |
//!
//! Gated on the byom repository being present — `$KOVEE_BYOM_REPO`, else
//! the sibling `../byom` — mirroring the plan's env-gated real-harness
//! discipline (§8). When present it always runs; it never silently passes
//! on a byomd failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::byomd::*;
use common::tmp;
use kovee_byom::bpp::{BppError, Endpoint};
use kovee_byom::episode::Fences;
use kovee_byom::runtime::{self, Workload};
use kovee_core::family::DigestRef;
use kovee_core::problem::ProblemKind;
use kovee_store::Store;
use koveed::episode::{self, Notice, ParentItem, Runtime};
use serde_json::{json, Value};

const REALM: &str = "realm-personal";

/// One live pair of daemons: byomd on its five sockets, and a Kovee store
/// whose governed-work seam pins byomd's real Society and incarnation.
struct Live {
    byomd: Byomd,
    agent: AgentSociety,
    store: Store,
    endpoint: Endpoint,
    channels: PathBuf,
}

impl Live {
    fn runtime(&self) -> Runtime {
        Runtime::new(&self.endpoint, &self.channels)
    }

    /// Stages 1-3, then the notice byom would hand Kovee. Every byom-owned
    /// reference is DERIVED the way byom derives it (so Kovee can only
    /// match), and the allocation digest is byom's own committed one.
    fn activate(&mut self, key: &str) -> (Notice, String) {
        let wake = wake_intent(&self.byomd, &self.agent, key);
        let mut notice = self.notice(&wake);
        // Stage 1 committed, nothing else yet.
        assert_eq!(
            self.byomd.row(
                "SELECT state FROM wake_intents WHERE wake_intent_id = ?1",
                &wake
            ),
            Some("submitted".to_owned())
        );
        assert!(
            self.byomd
                .row(
                    "SELECT state FROM activation_admissions WHERE admission_id = ?1",
                    &notice.activation_admission_ref
                )
                .is_none(),
            "no admission exists before the kernel evaluates the committed WakeIntent"
        );

        // Stages 2 and 3 run inside byom's `episode_request` — Kovee calls
        // it on the participant channel and names the stage ids byom
        // DERIVED, so it can only match them.
        let runtime = Runtime::new(&self.endpoint, &self.channels);
        // Kovee claims the participant channel itself, from its own
        // configured endpoint and channel directory.
        let channel = runtime
            .participant_channel(&self.agent.participant_ref)
            .expect("claim the participant channel byomd published");
        assert_eq!(
            channel.channel_id(),
            self.agent.channel.channel_id(),
            "the same channel byomd published for the admitted agent"
        );
        let requested = episode::request(&mut self.store, &runtime, &channel, &notice, 0)
            .expect("episode_request against the live byomd");
        assert_eq!(
            requested.state, "eligible",
            "the Episode is eligible but NOT queued: queueing needs both exact reservation sets"
        );
        notice.resource_allocation_digest = serde_json::from_value(
            self.byomd
                .allocation_digest(&notice.resource_allocation_ref),
        )
        .unwrap();
        (notice, requested.episode_ref)
    }

    fn notice(&self, wake: &str) -> Notice {
        let allocation = format!("alloc-{wake}-r1");
        Notice {
            society_ref: self.agent.society_id.clone(),
            recovery_epoch: 0,
            participant_ref: self.agent.participant_ref.clone(),
            participant_binding_epoch: self.agent.participant_binding_epoch,
            manifestation_ref: self.agent.manifestation_ref.clone(),
            activity_stream_ref: self.agent.activity_stream_ref.clone(),
            generation: 1,
            wake_intent_ref: wake.to_owned(),
            activation_admission_ref: format!("adm-{wake}-r1"),
            resource_allocation_ref: allocation.clone(),
            // Filled from byom's committed row once stage 3 exists.
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
            context_manifest_ref: "kovee-ctxman-live".to_owned(),
        }
    }

    /// Kovee's own record of one binding, straight out of Kovee's store.
    fn kovee_binding(&self, key: &str) -> Value {
        let args: kovee_core::ops::EpisodeBindingShowArgs =
            serde_json::from_value(json!({"stable_binding_key": key})).unwrap();
        let bytes = episode::byom_episode_binding_show(&self.store, REALM, &args).unwrap();
        let reply: Value = serde_json::from_slice(&bytes).unwrap();
        reply["result"]["bindings"][0].clone()
    }
}

/// Boots both daemons, or `None` when this checkout is standalone.
fn live(tag: &str) -> Option<Live> {
    let repo = byom_repo()?;
    let binary = byomd_binary(&repo);
    let base = tmp(tag);
    let byomd = Byomd::start(&binary, &base.join("byom-data"), &base.join("byom-run"));
    let agent = bootstrap_agent_society(&byomd, tag);

    let mut store = Store::open(&base.join("kovee.sqlite3")).unwrap();
    store.bootstrap(0).unwrap();
    // The seam pins byomd's REAL Society and incarnation: every runtime
    // `meta` carries both, and byomd refuses a mismatch.
    koveed::budget::seam_fixture(&mut store, &agent.society_id, 0, &agent.incarnation);

    let endpoint = Endpoint::at("local", &byomd.run_dir);
    let channels = byomd.channels_dir();
    Some(Live {
        byomd,
        agent,
        store,
        endpoint,
        channels,
    })
}

fn skipped(tag: &str) {
    println!("{tag}: skipped — no byom repository (set KOVEE_BYOM_REPO or check out ../byom)");
}

// ------------------------------------------------- the four-stage path ----

#[test]
fn the_four_stage_activation_runs_across_both_daemons() {
    let Some(mut live) = live("k2-episode-live-four-stage") else {
        return skipped("k2_episode_live");
    };
    let (notice, episode_ref) = live.activate("e1");
    let allocation = notice.resource_allocation_ref.clone();

    // -- BYOM's records: stages 2 and 3 are committed, in order ----------
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM activation_admissions WHERE admission_id = ?1",
            &notice.activation_admission_ref
        ),
        Some("admitted".to_owned()),
        "stage 2 (byom's record)"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT wake_intent_ref FROM activation_admissions WHERE admission_id = ?1",
            &notice.activation_admission_ref
        ),
        Some(notice.wake_intent_ref.clone()),
        "the admission cites the exact committed WakeIntent (byom's record)"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM resource_allocations WHERE allocation_id = ?1",
            &allocation
        ),
        Some("reserved".to_owned()),
        "stage 3 stops at reserved until Kovee's subordinate confirms (byom's record)"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM external_budget_bridges WHERE bridge_id = ?1",
            &notice.external_budget_bridge_ref
        ),
        Some("requested".to_owned()),
        "the §11.4 bridge is persisted under its stable key BEFORE queueing (byom's record)"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM episodes WHERE episode_id = ?1",
            &episode_ref
        ),
        Some("eligible".to_owned()),
        "the Episode exists but does NOT queue (byom's record)"
    );
    let before = live.byomd.ledger(PARENT_ACCOUNT);
    assert!(before.conserves(), "byom ledger conservation: {before:?}");
    // The Episode's OWN §11.4 reservation row, on top of the Mandate's
    // standing hold on the same ceiling set.
    assert_eq!(
        live.byomd.number(
            "SELECT amount FROM budget_reservations WHERE holder_kind = 'episode_allocation'
             AND holder_ref = ?1",
            &allocation
        ),
        Some(EPISODE_WORST_CASE as i64),
        "byom holds the per-Episode worst case (byom's record)"
    );
    // What the Mandate itself holds, so the close can be checked against it.
    let mandate_held = before.reserved - EPISODE_WORST_CASE as i64;

    // -- stage 4: KOVEE authors the PlacementBinding --------------------
    let placed = episode::place(&mut live.store, REALM, &notice, "kovee-inv-live-1", 0).unwrap();
    assert_eq!(placed.record.owner_protocol, "kovee");
    assert_eq!(
        placed.record.resource_allocation_digest, notice.resource_allocation_digest,
        "Kovee pins byom's OWN committed allocation digest — it cannot derive one"
    );

    // A claim BEFORE the admission: the real byomd refuses it, because
    // nothing queues without both reservation sets.
    let refused_early = raw_claim(&live, &notice, &episode_ref, &placed.placement_id, 300);
    let problem = definite(refused_early);
    assert_eq!(problem["kind"], "admission_required", "{problem}");

    // -- placement_admit (R33), carrying Kovee's subordinate confirm ----
    let runtime = live.runtime();
    let admitted = episode::admit(&mut live.store, &runtime, &placed.placement_id, &notice, 0)
        .expect("placement_admit against the live byomd");
    assert_eq!(admitted.bridge_state, "confirmed");
    assert!(admitted.episode_queued);

    // BYOM's records: stage 4, the bridge, and the queued Episode.
    assert_eq!(
        live.byomd.row(
            "SELECT verification_status FROM placement_admissions
             WHERE resource_allocation_ref = ?1",
            &allocation
        ),
        Some("verified".to_owned()),
        "byom verified the source binding and recorded ONLY the admission"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT kovee_placement_ref FROM placement_admissions
             WHERE resource_allocation_ref = ?1",
            &allocation
        ),
        Some(placed.placement_id.clone()),
        "byom's admission cites Kovee's exact placement (byom's record)"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM resource_allocations WHERE allocation_id = ?1",
            &allocation
        ),
        Some("bridged".to_owned()),
        "stage 3 completes only now: reserved -> bridged (byom's record)"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM episodes WHERE episode_id = ?1",
            &episode_ref
        ),
        Some("queued".to_owned()),
        "the Episode queues behind BOTH exact reservation sets (byom's record)"
    );
    // The subordinate reservation byom stored is the one KOVEE committed —
    // narrowed to half the parent worst case, never above it.
    let sub_amount: i64 = live
        .byomd
        .number(
            "SELECT json_extract(record, '$.items[0].amount') FROM subordinate_reservations
             WHERE subordinate_reservation_ref = ?1",
            &admitted.subordinate_reservation_ref,
        )
        .expect("byom stored Kovee's subordinate reservation");
    assert_eq!(sub_amount, (EPISODE_WORST_CASE / 2) as i64);
    // KOVEE's own record of the same saga row.
    let kovee_sub =
        koveed::budget::read(live.store.conn(), &notice.stable_external_reservation_key)
            .unwrap()
            .expect("Kovee's subordinate reservation");
    assert_eq!(
        kovee_sub.subordinate_reservation_ref,
        admitted.subordinate_reservation_ref
    );
    assert_eq!(kovee_sub.reserved("unit"), EPISODE_WORST_CASE / 2);
    assert_eq!(kovee_sub.parent_ceiling("unit"), EPISODE_WORST_CASE);

    // -- episode_claim + episode_start ----------------------------------
    let bound = episode::start(
        &mut live.store,
        &runtime,
        &placed.placement_id,
        &notice,
        &episode_ref,
        300,
        0,
    )
    .expect("episode_claim + episode_start against the live byomd");
    assert_eq!(bound.fences.kovee, placed.kovee_fence_epoch);
    assert!(bound.fences.byom >= 1);

    // BYOM's records: the lease head, the attempt, and byom's OWN
    // ByomEpisodeBinding under the key Kovee chose.
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM episode_lease_heads WHERE episode_id = ?1",
            &episode_ref
        ),
        Some("lease_running".to_owned()),
        "byom's lease head is running (byom's record)"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT current_attempt_ref FROM episode_lease_heads WHERE episode_id = ?1",
            &episode_ref
        ),
        Some(bound.byom_attempt_ref.clone()),
        "the head's current attempt is the one Kovee bound (byom's record)"
    );
    assert_eq!(
        live.byomd.number(
            "SELECT byom_fence_epoch FROM episode_lease_heads WHERE episode_id = ?1",
            &episode_ref
        ),
        Some(bound.fences.byom as i64),
        "the byom fence Kovee stored is the one byom minted"
    );
    assert_eq!(
        live.byomd.number(
            "SELECT kovee_invocation_fence FROM byom_episode_bindings
             WHERE stable_binding_key = ?1",
            &bound.stable_binding_key
        ),
        Some(bound.fences.kovee as i64),
        "byom's own binding row carries the KOVEE fence (family contract L21)"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM episodes WHERE episode_id = ?1",
            &episode_ref
        ),
        Some("running".to_owned())
    );
    // KOVEE's record of the same CAS.
    let kovee_row = live.kovee_binding(&bound.stable_binding_key);
    assert_eq!(kovee_row["state"], json!("bound"));
    assert_eq!(kovee_row["byom_attempt_ref"], json!(bound.byom_attempt_ref));
    assert_eq!(kovee_row["byom_fence_epoch"], json!(bound.fences.byom));
    assert_eq!(
        kovee_row["byom_lease_revision"],
        json!(bound.lease_revision),
        "Kovee carries byom's lease revision, never one of its own"
    );

    // -- a checkpoint under BOTH fences ---------------------------------
    let lease_after_checkpoint = episode::checkpoint(
        &mut live.store,
        &runtime,
        &bound.stable_binding_key,
        bound.fences,
        "kovee-ckpt-live-1",
        0,
    )
    .expect("checkpoint_commit against the live byomd");
    assert!(lease_after_checkpoint > bound.lease_revision);
    // BYOM's record: one immutable EpisodeAttemptEvent of kind
    // `checkpoint`, under the same attempt.
    assert_eq!(
        live.byomd
            .count("SELECT COUNT(*) FROM episode_attempt_events WHERE kind = 'checkpoint'"),
        1,
        "byom recorded exactly one checkpoint attempt event (byom's record)"
    );
    assert_eq!(
        live.byomd.number(
            "SELECT revision FROM episode_lease_heads WHERE episode_id = ?1",
            &episode_ref
        ),
        Some(lease_after_checkpoint as i64)
    );
    // KOVEE's record moved to byom's new lease revision.
    assert_eq!(
        live.kovee_binding(&bound.stable_binding_key)["byom_lease_revision"],
        json!(lease_after_checkpoint)
    );

    // -- the measured settlement, on byom's METER channel ---------------
    let charge = 40;
    let settled = episode::settle(
        &mut live.store,
        &runtime,
        &bound.stable_binding_key,
        bound.fences,
        charge,
        0,
    )
    .expect("usage_report (trusted_meter) against the live byomd");
    assert_eq!(settled["settlement"]["settled"], json!(true), "{settled}");
    assert_eq!(
        live.byomd.row(
            "SELECT status FROM usage_settlements WHERE reservation_set_ref = ?1",
            &notice.byom_budget_reservation_ref
        ),
        Some("measured".to_owned()),
        "byom recorded a MEASURED settlement, not a conservative maximum"
    );
    let after_settle = live.byomd.ledger(PARENT_ACCOUNT);
    assert!(after_settle.conserves(), "{after_settle:?}");
    assert_eq!(
        after_settle.committed, charge as i64,
        "byom committed exactly the measured charge (byom's record)"
    );
    // KOVEE's own settled row: monotonic, capped, stable-keyed.
    let kovee_sub =
        koveed::budget::read(live.store.conn(), &notice.stable_external_reservation_key)
            .unwrap()
            .unwrap();
    assert_eq!(
        kovee_sub.state,
        kovee_byom::budget::ReservationState::Settled
    );
    assert!(kovee_sub.usage_settlement_ref.is_some());

    // -- the orderly close ----------------------------------------------
    let completed = episode::complete(
        &mut live.store,
        &runtime,
        &bound.stable_binding_key,
        bound.fences,
        0,
    )
    .expect("episode_complete against the live byomd");
    assert_eq!(completed["state"], json!("completed"));
    assert_eq!(completed["lease_state"], json!("lease_terminal"));
    assert_eq!(completed["byom_episode_binding_state"], json!("released"));
    // BYOM's records: terminal everywhere, and the reserved remainder
    // released (`released_lifetime` is an audit counter, not a bucket).
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM episodes WHERE episode_id = ?1",
            &episode_ref
        ),
        Some("completed".to_owned())
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM byom_episode_bindings WHERE stable_binding_key = ?1",
            &bound.stable_binding_key
        ),
        Some("released".to_owned()),
        "byom released its own binding row (byom's record)"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM external_budget_bridges WHERE bridge_id = ?1",
            &notice.external_budget_bridge_ref
        ),
        Some("released".to_owned())
    );
    let closed = live.byomd.ledger(PARENT_ACCOUNT);
    assert!(closed.conserves(), "{closed:?}");
    assert_eq!(
        closed.reserved, mandate_held,
        "the Episode's hold is gone and only the Mandate's stays (byom's record)"
    );
    assert_eq!(closed.committed, charge as i64);
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM budget_reservations WHERE holder_kind = 'episode_allocation'
             AND holder_ref = ?1",
            &allocation
        ),
        Some("released".to_owned()),
        "only the demonstrably unspent remainder was released (byom's record)"
    );
    // KOVEE's record: released, terminal, and it advances nothing further.
    let kovee_row = live.kovee_binding(&bound.stable_binding_key);
    assert_eq!(kovee_row["state"], json!("released"));
    assert_eq!(kovee_row["episode_state"], json!("completed"));
    assert_eq!(
        episode::checkpoint(
            &mut live.store,
            &runtime,
            &bound.stable_binding_key,
            bound.fences,
            "kovee-ckpt-live-2",
            0,
        )
        .unwrap_err()
        .kind,
        ProblemKind::Forbidden
    );
    // byomd removed the Episode's worker and meter token files with the
    // terminal state: a missing token is a STATE answer.
    assert!(
        runtime::token(&live.channels, Workload::Worker, &episode_ref).is_err(),
        "a terminal Episode keeps no worker token"
    );
}

// ------------------------------------------------------- dual fences ----

#[test]
fn the_real_byomd_refuses_a_stale_byom_fence() {
    let Some(mut live) = live("k2-episode-live-byom-fence") else {
        return skipped("k2_episode_live");
    };
    let (notice, episode_ref) = live.activate("f1");
    let bound = activate_attempt(&mut live, &notice, &episode_ref, 300);

    // The exact same call with the byom fence bumped by one. Kovee's own
    // fence check is bypassed on purpose: this asserts the REAL daemon's
    // refusal, not Kovee's.
    let refused = protected_call(
        &live,
        &notice,
        &episode_ref,
        "checkpoint_commit",
        Fences {
            byom: bound.fences.byom + 1,
            kovee: bound.fences.kovee,
        },
        &bound,
    );
    let problem = definite(refused);
    assert_eq!(problem["kind"], "stale_lease", "{problem}");
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("stale byom_fence_epoch"),
        "{problem}"
    );
    // Nothing advanced on byom's side.
    assert_eq!(
        live.byomd.number(
            "SELECT revision FROM episode_lease_heads WHERE episode_id = ?1",
            &episode_ref
        ),
        Some(bound.lease_revision as i64)
    );
    assert_eq!(
        live.byomd
            .count("SELECT COUNT(*) FROM episode_attempt_events WHERE kind = 'checkpoint'"),
        0
    );
}

#[test]
fn the_real_byomd_refuses_a_stale_kovee_fence() {
    let Some(mut live) = live("k2-episode-live-kovee-fence") else {
        return skipped("k2_episode_live");
    };
    let (notice, episode_ref) = live.activate("g1");
    let bound = activate_attempt(&mut live, &notice, &episode_ref, 300);

    // One CURRENT fence and one stale one is not "mostly current": byom
    // refuses it for the exact reason (family contract L21).
    let refused = protected_call(
        &live,
        &notice,
        &episode_ref,
        "checkpoint_commit",
        Fences {
            byom: bound.fences.byom,
            kovee: bound.fences.kovee + 1,
        },
        &bound,
    );
    let problem = definite(refused);
    assert_eq!(problem["kind"], "stale_lease", "{problem}");
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("stale kovee_invocation_fence"),
        "{problem}"
    );
    assert_eq!(
        live.byomd
            .count("SELECT COUNT(*) FROM episode_attempt_events WHERE kind = 'checkpoint'"),
        0
    );
}

#[test]
fn the_real_byomd_refuses_a_claim_before_the_placement_is_admitted() {
    let Some(mut live) = live("k2-episode-live-order") else {
        return skipped("k2_episode_live");
    };
    let (notice, episode_ref) = live.activate("h1");
    let placed = episode::place(&mut live.store, REALM, &notice, "kovee-inv-live-h1", 0).unwrap();

    // Kovee refuses locally first (no admission recorded).
    let runtime = live.runtime();
    let local = episode::start(
        &mut live.store,
        &runtime,
        &placed.placement_id,
        &notice,
        &episode_ref,
        300,
        0,
    )
    .unwrap_err();
    assert_eq!(local.kind, ProblemKind::Forbidden);
    assert!(local
        .detail
        .as_ref()
        .unwrap()
        .contains("nothing skips a stage"));

    // And the REAL byomd refuses the same claim on its own account: an
    // Episode that is not `queued` cannot be claimed, and only an admitted
    // placement with both reservation sets queues one.
    let problem = definite(raw_claim(
        &live,
        &notice,
        &episode_ref,
        &placed.placement_id,
        300,
    ));
    assert_eq!(problem["kind"], "admission_required", "{problem}");
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("never from arrival"),
        "{problem}"
    );
    // No lease head, no attempt, no binding — on either side.
    assert_eq!(
        live.byomd.count("SELECT COUNT(*) FROM episode_lease_heads"),
        0
    );
    assert_eq!(
        live.byomd
            .count("SELECT COUNT(*) FROM byom_episode_bindings"),
        0
    );
}

// ----------------------------------------------------- clocked expiry ----

#[test]
fn the_lease_expiry_is_clocked_not_liveness_guessed() {
    let Some(mut live) = live("k2-episode-live-expiry") else {
        return skipped("k2_episode_live");
    };
    let (notice, episode_ref) = live.activate("i1");
    // A one-second lease, CLAIMED and not started: byomd mints
    // `expires_at_unix = now + ttl` at the claim, and only the
    // AUTHORITATIVE clock strictly passing it makes the head re-claimable
    // (`lease_leased -> lease_expired`). A started head that outlives its
    // deadline is a different transition — `running -> ambiguous`, never
    // blindly repeated — which is why the probe claims without starting.
    let placed = episode::place(&mut live.store, REALM, &notice, "kovee-inv-live-i1", 0).unwrap();
    let runtime = live.runtime();
    episode::admit(&mut live.store, &runtime, &placed.placement_id, &notice, 0)
        .expect("placement_admit");
    let first = episode::claim(
        &mut live.store,
        &runtime,
        &placed.placement_id,
        &notice,
        &episode_ref,
        1,
        0,
    )
    .expect("episode_claim");
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM episode_lease_heads WHERE episode_id = ?1",
            &episode_ref
        ),
        Some("lease_leased".to_owned()),
        "the head is claimed but not running (byom's record)"
    );
    let deadline = live
        .byomd
        .number(
            "SELECT expires_at_unix FROM episode_lease_heads WHERE episode_id = ?1",
            &episode_ref,
        )
        .expect("byom minted a clocked deadline");
    assert!(deadline > 0, "the deadline is minted at claim, not guessed");

    // BEFORE the deadline: the live head is not stealable. A crash or
    // silence enables nothing — there is no liveness probe anywhere.
    let placement = placed.placement_id.clone();
    let advanced = episode::advance_invocation(&mut live.store, &placement).unwrap();
    assert_eq!(advanced.kovee_fence_epoch, 2);
    let early = episode::claim(
        &mut live.store,
        &runtime,
        &placement,
        &notice,
        &episode_ref,
        300,
        0,
    )
    .unwrap_err();
    assert_eq!(early.kind, ProblemKind::StaleLease, "{early:?}");
    assert!(
        early
            .detail
            .as_ref()
            .unwrap()
            .contains("a live lease head is not stealable"),
        "{early:?}"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM episode_lease_heads WHERE episode_id = ?1",
            &episode_ref
        ),
        Some("lease_leased".to_owned()),
        "the head is untouched by the refused reclaim (byom's record)"
    );

    // AFTER the deadline: the server-time sweep expires the head on the
    // authoritative clock, and the reclaim is permitted under a NEW byom
    // fence and a NEW binding row.
    wait_past(deadline);
    let second = episode::claim(
        &mut live.store,
        &runtime,
        &placement,
        &notice,
        &episode_ref,
        300,
        0,
    )
    .expect("the reclaim after the clocked deadline");
    assert_ne!(second.stable_binding_key, first.stable_binding_key);
    assert!(
        second.fences.byom > first.fences.byom,
        "a reclaim mints a NEW byom fence: {:?} then {:?}",
        first.fences,
        second.fences
    );
    assert_eq!(second.fences.kovee, 2);

    // BYOM's records: the expiry is retained (the head is never deleted
    // and no fence is reused), and the predecessor binding is FENCED.
    assert_eq!(
        live.byomd.number(
            "SELECT expiry_count FROM episode_lease_heads WHERE episode_id = ?1",
            &episode_ref
        ),
        Some(1),
        "the expiry is counted, not erased (byom's record)"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM byom_episode_bindings WHERE stable_binding_key = ?1",
            &first.stable_binding_key
        ),
        Some("fenced".to_owned()),
        "byom fenced the predecessor binding at the successor's claim"
    );
    assert_eq!(
        live.byomd.row(
            "SELECT state FROM byom_episode_bindings WHERE stable_binding_key = ?1",
            &second.stable_binding_key
        ),
        Some("bound".to_owned())
    );
    // KOVEE's records: two rows, the predecessor retained for audit.
    let predecessor = live.kovee_binding(&first.stable_binding_key);
    assert_eq!(predecessor["byom_fence_epoch"], json!(first.fences.byom));
    let successor = live.kovee_binding(&second.stable_binding_key);
    assert_eq!(successor["state"], json!("bound"));
    // And the predecessor's pair advances nothing now.
    assert_eq!(
        episode::checkpoint(
            &mut live.store,
            &runtime,
            &first.stable_binding_key,
            first.fences,
            "kovee-ckpt-stale",
            0,
        )
        .unwrap_err()
        .kind,
        ProblemKind::StaleLease
    );
}

// ------------------------------------------------------------ helpers ----

/// Admits the placement and claims/starts one attempt.
fn activate_attempt(
    live: &mut Live,
    notice: &Notice,
    episode_ref: &str,
    ttl: u64,
) -> episode::Bound {
    let placed = episode::place(
        &mut live.store,
        REALM,
        notice,
        &format!("kovee-inv-live-{episode_ref}"),
        0,
    )
    .unwrap();
    let runtime = Runtime::new(&live.endpoint, &live.channels);
    episode::admit(&mut live.store, &runtime, &placed.placement_id, notice, 0)
        .expect("placement_admit");
    episode::start(
        &mut live.store,
        &runtime,
        &placed.placement_id,
        notice,
        episode_ref,
        ttl,
        0,
    )
    .expect("episode_claim + episode_start")
}

/// One hand-built protected runtime call, sent through Kovee's own runtime
/// client under the real worker token: this is how a fence pair reaches
/// byomd without Kovee's local check filtering it first.
fn protected_call(
    live: &Live,
    notice: &Notice,
    episode_ref: &str,
    op: &str,
    fences: Fences,
    bound: &episode::Bound,
) -> Result<Value, BppError> {
    let token = runtime::token(&live.channels, Workload::Worker, episode_ref).unwrap();
    let request = json!({
        "version": kovee_byom::bpp::BPP_VERSION,
        "op": op,
        "meta": {
            "request_id": format!("kovee-probe-{op}-{}", fences.byom),
            "idempotency_key": format!("kovee-probe-{op}-{}-{}", fences.byom, fences.kovee),
            "expected_endpoint_incarnation": live.agent.incarnation,
            "expected_recovery_epoch": 0,
        },
        "episode_ref": episode_ref,
        "generation": notice.generation,
        "byom_attempt_ref": bound.byom_attempt_ref,
        "byom_fence_epoch": fences.byom,
        "kovee_invocation_fence": fences.kovee,
        "expected_lease_revision": bound.lease_revision,
        "checkpoint_ref": format!("kovee-probe-ckpt-{}", fences.byom),
        "checkpoint_digest": {
            "class": "local_erasure_safe",
            "algorithm": "hmac-sha-256",
            "key_ref": "kovee-probe-object:1",
            "value_hex": "1c".repeat(32),
        },
    });
    runtime::call(live.endpoint(), &token, &request).map(|reply| reply.result)
}

/// One hand-built `episode_claim`, for the pre-admission probe.
fn raw_claim(
    live: &Live,
    notice: &Notice,
    episode_ref: &str,
    placement_id: &str,
    ttl: u64,
) -> Result<Value, BppError> {
    let token = runtime::token(&live.channels, Workload::Worker, episode_ref).unwrap();
    let request = json!({
        "version": kovee_byom::bpp::BPP_VERSION,
        "op": "episode_claim",
        "meta": {
            "request_id": format!("kovee-probe-claim-{placement_id}"),
            "idempotency_key": format!("kovee-probe-claim-{placement_id}"),
            "expected_endpoint_incarnation": live.agent.incarnation,
            "expected_recovery_epoch": 0,
        },
        "episode_ref": episode_ref,
        "generation": notice.generation,
        "holder_runtime_binding": "kovee-runtime-probe",
        "claim_subject_digest": {
            "class": "local_erasure_safe",
            "algorithm": "hmac-sha-256",
            "key_ref": "kovee-probe-object:1",
            "value_hex": "2d".repeat(32),
        },
        "lease_ttl_seconds": ttl,
        "kovee_invocation_ref": "kovee-inv-probe",
        "kovee_invocation_fence": 1,
        "stable_binding_key": format!("ebk-probe-{placement_id}"),
        "context_manifest_ref": notice.context_manifest_ref,
        "context_manifest_digest": {
            "class": "local_erasure_safe",
            "algorithm": "hmac-sha-256",
            "key_ref": "kovee-probe-object:1",
            "value_hex": "3e".repeat(32),
        },
        "context_source_digest": {
            "class": "portable_public",
            "algorithm": "sha-256",
            "value_hex": "4f".repeat(32),
        },
        "mandate_use_refs": [],
        "allowed_local_commitments": ["contribution_append"],
    });
    runtime::call(live.endpoint(), &token, &request).map(|reply| reply.result)
}

impl Live {
    fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

/// byom's typed problem body — a DEFINITE refusal, never a transport
/// guess.
fn definite(outcome: Result<Value, BppError>) -> Value {
    match outcome {
        Ok(result) => panic!("expected a refusal, byomd answered ok: {result}"),
        Err(error) => {
            assert!(
                error.is_definite(),
                "expected a typed byom problem, got {error}"
            );
            match error {
                BppError::Problem(problem) => json!({
                    "kind": problem.kind,
                    "detail": problem.detail.clone().unwrap_or_default(),
                }),
                other => panic!("expected a byom problem, got {other}"),
            }
        }
    }
}

/// Waits until the wall clock is STRICTLY past byomd's minted deadline —
/// the only thing that makes an unyielded head re-claimable.
fn wait_past(deadline: i64) {
    let limit = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while kovee_core::time::unix_now() <= deadline {
        assert!(
            std::time::Instant::now() < limit,
            "the clock never passed the lease deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
