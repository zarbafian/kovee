//! K2 slice 2 — the KOVEE-OWNED half of the hosted-episode pipeline: the
//! records Kovee authors and the refusals it makes on its own, before a
//! byte reaches byomd (byom §16.6 item 3, family contract L19–L22; the
//! machine of `byom/spec/descriptors/byom-episode-binding.json`).
//!
//! | property | proof |
//! |---|---|
//! | placement admitted before ANY episode work — refused with no endpoint reachable | `no_episode_work_happens_before_byom_admits_the_placement` |
//! | a stale byom fence refuses locally, before any call | `a_stale_byom_fence_refuses_before_byom_is_ever_called` |
//! | a stale kovee fence refuses locally, before any call | `a_stale_kovee_fence_refuses_before_byom_is_ever_called` |
//! | idempotent create over the stable key | `the_binding_is_idempotent_over_its_stable_key` |
//! | a successor attempt gets a NEW row under a NEW key | `a_successor_invocation_binds_afresh` |
//! | the read surface reports both fences and byom's lease revision | `the_read_surface_reports_both_fences_and_the_byom_lease_revision` |
//! | the per-object secret is random and wrapped, and the episode digests byom recomputes are cross-boundary | `the_placement_secret_is_a_random_wrapped_blob_and_the_episode_digests_are_cross_boundary` |
//!
//! There is NO scripted byom endpoint here: the whole four-stage path
//! against a live `byomd` — `episode_request`, `placement_admit`,
//! `episode_claim`/`episode_start`, `checkpoint_commit`, `usage_report`,
//! `episode_complete`, the dual-fence refusals byomd itself makes, and the
//! clocked lease expiry — is `k2_episode_live`. What this suite covers is
//! exactly what Kovee decides without asking: the endpoint it is handed
//! points at a directory with no sockets in it, so any test here that
//! passed by reaching byom would fail instead.
//!
//! # Recorded deviations
//!
//! Slice 2's deviation 5 — "byomd serves no runtime surface, so
//! `k2_episode` scripts that half" — is **withdrawn**. byom d37b898 serves
//! `runtime.sock`, and every operation of the Kovee-side pipeline is now a
//! real call against it under a byomd-minted workload token
//! (`k2_episode_live`).
//!
//! What remains out-of-band is exactly one thing, and it is byom's own
//! recorded gap, not a Kovee stub: **the notification itself**. byom has no
//! outbound Kovee client and exposes no read that returns the committed
//! `ResourceAllocation` head, yet `placement_admit` requires Kovee to pin
//! that record's exact `local_erasure_safe` digest. So the `Notice` Kovee
//! is handed carries byom-owned facts that Kovee can only echo — the
//! allocation ref (kernel-derived, so Kovee can compute it and byom checks
//! the match), the allocation DIGEST (not derivable, not readable over any
//! surface), the bridge ref, the kernel-derived stable reservation key, and
//! the parent §11.4 items. In `k2_episode_live` the harness reads that
//! digest out of byomd's own database — the same inspection channel byom's
//! own runtime fixture uses for it. Nothing else about the pipeline is
//! scripted: the tokens, the channel proofs, the fences, the lease
//! revisions, and every refusal come from the running daemon.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::tmp;
use kovee_byom::bpp::Endpoint;
use kovee_byom::episode::Fences;
use kovee_core::family::DigestRef;
use kovee_core::problem::ProblemKind;
use kovee_store::Store;
use koveed::episode::{self, Notice, ParentItem, Runtime};
use serde_json::{json, Value};

const REALM: &str = "realm-personal";

fn notice() -> Notice {
    Notice {
        society_ref: "soc-1".to_owned(),
        recovery_epoch: 0,
        participant_ref: "part-1".to_owned(),
        participant_binding_epoch: 1,
        manifestation_ref: "man-1".to_owned(),
        activity_stream_ref: "as-1".to_owned(),
        generation: 2,
        wake_intent_ref: "wi-1".to_owned(),
        activation_admission_ref: "adm-wi-1-r1".to_owned(),
        resource_allocation_ref: "alloc-wi-1-r1".to_owned(),
        // ECHOED from byom: the class byom commits its own record digests
        // in, which is why Kovee stores it rather than deriving it.
        resource_allocation_digest: DigestRef::local_erasure_safe(
            "society-key:soc-1/object:alloc-wi-1-r1",
            "a".repeat(64),
        ),
        mandate_use_refs: vec!["mu-1".to_owned()],
        byom_budget_reservation_ref: "brs-alloc-wi-1-r1".to_owned(),
        byom_reservation_set_revision: 1,
        external_budget_bridge_ref: "bridge-alloc-wi-1-r1".to_owned(),
        stable_external_reservation_key: "sub-alloc-wi-1-r1".to_owned(),
        parent_reservation_items: vec![ParentItem {
            account_ref: "budget-mandate-1".to_owned(),
            account_revision: 1,
            dimension: "unit".to_owned(),
            unit: "unit".to_owned(),
            worst_case_amount: 256,
        }],
        context_manifest_ref: "cm-1".to_owned(),
    }
}

/// A store with an ACTIVE governed-work seam, and an endpoint pointed at a
/// directory that holds NO byomd sockets and NO workload tokens: every
/// refusal this suite asserts is therefore Kovee's own.
fn fixture(tag: &str) -> (Store, Endpoint, std::path::PathBuf) {
    let base = tmp(tag);
    let mut store = Store::open(&base.join("kovee.sqlite3")).unwrap();
    store.bootstrap(0).unwrap();
    koveed::budget::doc_seam(&mut store);
    let empty = base.join("no-byom-here");
    std::fs::create_dir_all(&empty).unwrap();
    (store, Endpoint::at("local", &empty), empty)
}

fn unreachable_runtime(endpoint: &Endpoint, channels: &std::path::Path) -> Runtime {
    Runtime::new(endpoint, channels)
}

/// One bound attempt, committed exactly as the claim/start CAS would have,
/// without any byom call: the fence pair and the lease revision are the
/// ones byomd would have returned.
fn bind_attempt(store: &mut Store, byom_fence: u64, lease_revision: u64) -> episode::Bound {
    let notice = notice();
    let placed = episode::place(store, REALM, &notice, "kovee-inv-1", 0).unwrap();
    // The admission byom would have recorded, so `bind` sees a placement
    // whose stage 4 is complete.
    admitted(store, &placed.placement_id);
    let placement = episode::read_placement(store.conn(), &placed.placement_id)
        .unwrap()
        .unwrap();
    let key = format!("ebk-test-{byom_fence}");
    episode::bind(
        store,
        REALM,
        &placement,
        &notice,
        "ep-1",
        &format!("att-{byom_fence}"),
        Fences {
            byom: byom_fence,
            kovee: placed.kovee_fence_epoch,
        },
        lease_revision,
        &key,
        // byom's own binding identity, as `episode_claim` would have
        // reported it: the fence digest the model broker later presents to
        // `execution_permit_consume` and the §12.1 source fragment.
        &episode::ByomBindingSide {
            binding_ref: Some(format!("beb-byom-{byom_fence}")),
            binding_digest: Some(kovee_core::family::DigestRef::portable_public(
                format!("{byom_fence:02x}").repeat(32),
            )),
            source_fields: Some(serde_json::to_value(byom_source_fields(byom_fence)).unwrap()),
        },
        0,
    )
    .unwrap()
}

/// byom's §12.1 provider-context source fragment, C2 member for member.
fn byom_source_fields(byom_fence: u64) -> kovee_effects::ByomSourceFields {
    let mut fields = kovee_effects::ByomSourceFields::example();
    fields.byom_fence_epoch = byom_fence;
    fields.episode_ref = "ep-1".to_owned();
    fields.byom_attempt_ref = format!("att-{byom_fence}");
    fields
}

fn admitted(store: &mut Store, placement_id: &str) {
    store
        .conn()
        .execute(
            "UPDATE byom_placement_bindings
             SET admission_ref = 'plc-admitted', admitted_at = '1970-01-01T00:00:00Z'
             WHERE placement_id = ?1",
            [placement_id],
        )
        .unwrap();
}

// ------------------------------------------------------------ stage order ----

#[test]
fn no_episode_work_happens_before_byom_admits_the_placement() {
    let (mut store, endpoint, channels) = fixture("k2-episode-order");
    let runtime = unreachable_runtime(&endpoint, &channels);
    let notice = notice();

    // Kovee authors the one activation record it owns, over the allocation
    // digest BYOM committed — echoed, never derived.
    let placed = episode::place(&mut store, REALM, &notice, "kovee-inv-1", 0).unwrap();
    assert_eq!(placed.record.owner_protocol, "kovee");
    assert_eq!(placed.record.state, "placed");
    assert_eq!(placed.kovee_fence_epoch, 1);
    assert_eq!(
        placed.record.resource_allocation_digest, notice.resource_allocation_digest,
        "the allocation digest is byom's own record digest, carried verbatim"
    );
    // And the digest byom pins as the CROSS-BOUNDARY class is that class.
    assert_eq!(placed.record.digest.class, "portable_public");
    assert_eq!(placed.record.digest.algorithm, "sha-256");
    assert_eq!(placed.record.digest.key_ref, None);

    // The claim refuses OUTRIGHT: with no admission there is nothing to
    // ask byom about, and the endpoint here could not answer anyway.
    let refused = episode::start(
        &mut store,
        &runtime,
        &placed.placement_id,
        &notice,
        "ep-1",
        300,
        0,
    )
    .unwrap_err();
    assert_eq!(refused.kind, ProblemKind::Forbidden);
    assert!(
        refused
            .detail
            .as_ref()
            .unwrap()
            .contains("nothing skips a stage"),
        "{refused:?}"
    );
    // And no binding exists to fence, honor, or settle.
    assert!(bindings(&store).is_empty());

    // Placing the same allocation twice is the identical placement.
    let again = episode::place(&mut store, REALM, &notice, "kovee-inv-1", 0).unwrap();
    assert_eq!(again.placement_id, placed.placement_id);
}

// ------------------------------------------------------------ dual fences ----

#[test]
fn a_stale_byom_fence_refuses_before_byom_is_ever_called() {
    let (mut store, endpoint, channels) = fixture("k2-episode-byom-fence");
    let runtime = unreachable_runtime(&endpoint, &channels);
    let bound = bind_attempt(&mut store, 7, 2);

    // A successor attempt claimed the Episode: the BYOM fence advanced.
    let presented = Fences {
        byom: bound.fences.byom + 1,
        kovee: bound.fences.kovee,
    };
    let refused = episode::checkpoint(
        &mut store,
        &runtime,
        &bound.stable_binding_key,
        presented,
        "ckpt-1",
        1,
    )
    .unwrap_err();
    assert_eq!(refused.kind, ProblemKind::StaleLease);
    assert!(
        refused.detail.as_ref().unwrap().contains("byom fence"),
        "{refused:?}"
    );

    // The row is FENCED and retained for audit — a stale worker keeps its
    // bytes as local evidence but advances no head.
    let row = &bindings(&store)[0];
    assert_eq!(row["state"], json!("fenced"));
    assert!(row["fenced_reason"].is_string(), "{row}");
    assert_eq!(row["byom_fence_epoch"], json!(bound.fences.byom));
    // Terminal: even the ORIGINAL pair advances nothing now.
    let after = episode::checkpoint(
        &mut store,
        &runtime,
        &bound.stable_binding_key,
        bound.fences,
        "ckpt-2",
        2,
    )
    .unwrap_err();
    assert_eq!(after.kind, ProblemKind::Forbidden);
    assert!(
        after.detail.as_ref().unwrap().contains("advances nothing"),
        "{after:?}"
    );
}

#[test]
fn a_stale_kovee_fence_refuses_before_byom_is_ever_called() {
    let (mut store, endpoint, channels) = fixture("k2-episode-kovee-fence");
    let runtime = unreachable_runtime(&endpoint, &channels);
    let bound = bind_attempt(&mut store, 7, 2);

    // The HOST-side fence advanced: a mutation presenting a current byom
    // fence and a stale Kovee one is not "mostly current", it is fenced.
    let presented = Fences {
        byom: bound.fences.byom,
        kovee: bound.fences.kovee + 1,
    };
    let refused = episode::yield_episode(
        &mut store,
        &runtime,
        &bound.stable_binding_key,
        presented,
        "cont-1",
        1,
    )
    .unwrap_err();
    assert_eq!(refused.kind, ProblemKind::StaleLease);
    assert!(
        refused
            .detail
            .as_ref()
            .unwrap()
            .contains("kovee invocation fence"),
        "{refused:?}"
    );
    let row = &bindings(&store)[0];
    assert_eq!(row["state"], json!("fenced"));
    assert_eq!(row["kovee_invocation_fence"], json!(bound.fences.kovee));

    // A mutation carrying only ONE fence is invalid — presenting the bound
    // byom fence with a zeroed Kovee one is refused too.
    let (mut store, endpoint, channels) = fixture("k2-episode-kovee-fence-2");
    let runtime = unreachable_runtime(&endpoint, &channels);
    let bound = bind_attempt(&mut store, 7, 2);
    let half = Fences {
        byom: bound.fences.byom,
        kovee: 0,
    };
    assert_eq!(
        episode::complete(&mut store, &runtime, &bound.stable_binding_key, half, 1)
            .unwrap_err()
            .kind,
        ProblemKind::StaleLease
    );
}

// -------------------------------------------------------- idempotent create ----

#[test]
fn the_binding_is_idempotent_over_its_stable_key() {
    let (mut store, _endpoint, _channels) = fixture("k2-episode-idempotent");
    let first = bind_attempt(&mut store, 7, 2);
    let again = bind_attempt(&mut store, 7, 2);
    assert_eq!(again.stable_binding_key, first.stable_binding_key);
    assert_eq!(again.record, first.record);
    assert_eq!(again.lease_revision, first.lease_revision);
    assert_eq!(
        bindings(&store).len(),
        1,
        "a second binding row was created"
    );

    // The record is the §16.6 shape, with BOTH fences, the closed
    // local-commitment set, and the digest CLASSES byom's runtime schemas
    // pin: erasure-safe for what Kovee authors, portable for what both
    // sides recompute.
    let record = &bindings(&store)[0]["record"];
    assert_eq!(record["byom_fence_epoch"], json!(7));
    assert_eq!(record["kovee_invocation_fence"], json!(1));
    assert_eq!(
        record["allowed_local_commitments"],
        json!(["contribution_append", "attention_mark"])
    );
    assert_eq!(record["context_manifest_ref"], json!("cm-1"));
    assert_eq!(
        record["external_budget_bridge_ref"],
        json!("bridge-alloc-wi-1-r1")
    );
    assert_eq!(record["mandate_use_refs"], json!(["mu-1"]));
    // CROSS-BOUNDARY (byom amendment A8): byom holds only the ContextManifest
    // ref, so the digest must be one byom can recompute — unkeyed.
    assert_eq!(
        record["context_manifest_digest"]["class"],
        "portable_public"
    );
    assert_eq!(record["context_manifest_digest"]["algorithm"], "sha-256");
    assert!(record["context_manifest_digest"]["key_ref"].is_null());
    assert_eq!(record["context_source_digest"]["class"], "portable_public");
}

// -------------------------------------------------------- successor attempt ----

#[test]
fn a_successor_invocation_binds_afresh() {
    let (mut store, _endpoint, _channels) = fixture("k2-episode-successor");
    let notice = notice();
    let placed = episode::place(&mut store, REALM, &notice, "kovee-inv-1", 0).unwrap();
    admitted(&mut store, &placed.placement_id);

    // The Kovee-side fence advance a successor needs: a NEW invocation ref
    // and a NEW fence, so the stable key is new and the predecessor's
    // binding is fenced for every further mutation.
    let advanced = episode::advance_invocation(&mut store, &placed.placement_id).unwrap();
    assert_eq!(advanced.kovee_fence_epoch, placed.kovee_fence_epoch + 1);
    assert_ne!(
        advanced.record.kovee_invocation_ref,
        placed.record.kovee_invocation_ref
    );
}

// ------------------------------------------------------------ read surface ----

#[test]
fn the_read_surface_reports_both_fences_and_the_byom_lease_revision() {
    let (mut store, _endpoint, _channels) = fixture("k2-episode-show");
    let bound = bind_attempt(&mut store, 7, 4);
    let shown = show(&store, json!({"episode_ref": "ep-1"}));
    let rows = shown["bindings"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["byom_fence_epoch"], json!(7));
    assert_eq!(rows[0]["kovee_invocation_fence"], json!(1));
    // byom's number, carried — never incremented locally.
    assert_eq!(rows[0]["byom_lease_revision"], json!(4));
    assert_eq!(
        rows[0]["stable_binding_key"],
        json!(bound.stable_binding_key)
    );
}

// ------------------------------------------------ per-object secrets, A8 ----

#[test]
fn the_placement_secret_is_a_random_wrapped_blob_and_the_episode_digests_are_cross_boundary() {
    // byom's amendment A8 (family lock c1-r3) settled which class each
    // episode-claim digest takes, and it moved the ones Kovee AUTHORS to the
    // CROSS-BOUNDARY `portable_public` class: byom holds only their refs, so
    // it must be able to recompute the digest itself, and a keyed value
    // inside a class both sides derive is exactly what D-R1-2 forbids.
    //
    // Two consequences this proves:
    //   1. the per-object secret is still a RANDOM wrapped blob, minted at
    //      placement time and destroyed with the row (D-R1-2);
    //   2. destroying it no longer breaks a checkpoint, because no episode
    //      digest is keyed under it any more. Per-object erasure now applies
    //      where `local_erasure_safe` actually lives: the model broker's own
    //      disclosure / provider-context / effect records (`k2_broker`).
    let (mut store, endpoint, channels) = fixture("k2-episode-erasure");
    let runtime = unreachable_runtime(&endpoint, &channels);
    let bound = bind_attempt(&mut store, 7, 2);
    let placement: String = store
        .conn()
        .query_row(
            "SELECT placement_id FROM byom_episode_bindings WHERE stable_binding_key = ?1",
            [&bound.stable_binding_key],
            |r| r.get(0),
        )
        .unwrap();
    let wrapped: Vec<u8> = store
        .conn()
        .query_row(
            "SELECT object_secret FROM byom_placement_bindings WHERE placement_id = ?1",
            [&placement],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(wrapped.len(), kovee_store::objkey::WRAPPED_LEN);

    // Every digest Kovee authors for byom is unkeyed and therefore
    // recomputable by byom.
    let record = bindings(&store)[0]["record"].clone();
    for field in ["context_manifest_digest", "context_source_digest"] {
        assert_eq!(
            record[field]["class"], "portable_public",
            "{field} is cross-boundary (A8)"
        );
        assert!(record[field]["key_ref"].is_null(), "{field} carries no key");
    }

    // Destroying the secret leaves the episode path working: the refusal it
    // used to cause was a keyed-digest derivation that no longer happens.
    store
        .conn()
        .execute(
            "UPDATE byom_placement_bindings SET object_secret = NULL WHERE placement_id = ?1",
            [&placement],
        )
        .unwrap();
    let outcome = episode::checkpoint(
        &mut store,
        &runtime,
        &bound.stable_binding_key,
        bound.fences,
        "ckpt-1",
        1,
    );
    // It still fails — but at the UNREACHABLE endpoint, not at a destroyed
    // secret, which is the whole point.
    let refused = outcome.unwrap_err();
    assert_ne!(refused.kind, ProblemKind::Forbidden, "{refused:?}");
    assert!(
        !refused
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("can no longer be re-derived"),
        "{refused:?}"
    );
}

// ------------------------------------------------------------------ helpers ----

fn show(store: &Store, args: Value) -> Value {
    let args: kovee_core::ops::EpisodeBindingShowArgs = serde_json::from_value(args).unwrap();
    let bytes = episode::byom_episode_binding_show(store, REALM, &args).unwrap();
    let reply: Value = serde_json::from_slice(&bytes).unwrap();
    reply["result"].clone()
}

fn bindings(store: &Store) -> Vec<Value> {
    show(store, json!({}))["bindings"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}
