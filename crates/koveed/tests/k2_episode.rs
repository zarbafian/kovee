//! K2 slice 2 — the hosted-episode pipeline: stage order and the DUAL
//! fences (byom §16.6 item 3, family contract L19–L22; the machine of
//! `byom/spec/descriptors/byom-episode-binding.json`).
//!
//! | property | proof |
//! |---|---|
//! | placement admitted before ANY episode work | `no_episode_work_happens_before_byom_admits_the_placement` |
//! | a stale byom fence refuses | `a_stale_byom_fence_refuses_and_fences_the_binding` |
//! | a stale kovee fence refuses | `a_stale_kovee_fence_refuses_and_fences_the_binding` |
//! | idempotent create over the stable key | `the_binding_is_idempotent_over_its_stable_key` |
//! | Continuation hand-off; a successor gets a NEW row | `a_yield_hands_off_a_continuation_and_a_successor_binds_afresh` |
//! | orderly close hands the reservations to settlement | `a_complete_releases_the_binding_and_hands_off_the_reservations` |
//!
//! Recorded deviation: byomd does not serve the R30/R33 **runtime**
//! surface yet (its four sockets are governance, candidate, participant,
//! and projection; `placement_admit` and the Episode lease operations are
//! byom's own B0.3/B3 slice). So the byom half of stage 3 and stage 4 is a
//! scripted runtime endpoint here, while everything Kovee owns — the
//! PlacementBinding, the admission check, the binding row, and every
//! dual-fence refusal — is the real implementation. The formation suite
//! (`k2_formation`) is the one that runs against the real daemon.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::tmp;
use kovee_byom::bpp::Endpoint;
use kovee_byom::episode::Fences;
use kovee_core::problem::ProblemKind;
use kovee_store::Store;
use koveed::episode::{self, Notice};
use serde_json::{json, Value};

/// A scripted byom RUNTIME surface: the one surface byomd does not serve
/// yet. It answers the four operations stage 3 and stage 4 need, and its
/// fence numbers are the ones a real claim would mint.
struct RuntimeStub {
    dir: PathBuf,
    fence: Arc<Mutex<u64>>,
    stop: Arc<Mutex<bool>>,
}

impl RuntimeStub {
    fn start(dir: &Path, byom_fence: u64) -> RuntimeStub {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join("runtime.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let fence = Arc::new(Mutex::new(byom_fence));
        let stop = Arc::new(Mutex::new(false));
        let served = Arc::clone(&fence);
        let stopped = Arc::clone(&stop);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *stopped.lock().unwrap() {
                    return;
                }
                let Ok(stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let request: Value = match serde_json::from_str(line.trim_end()) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let fence = *served.lock().unwrap();
                let result = match request["op"].as_str().unwrap_or_default() {
                    "placement_admit" => json!({
                        "admission_id": "padm-1",
                        "kovee_placement_ref": request["kovee_placement_ref"],
                        "kovee_placement_revision": request["kovee_placement_revision"],
                        "verification_status": "verified",
                        "digest": {"class": "portable_public", "algorithm": "sha-256",
                                   "value_hex": "a".repeat(64)},
                    }),
                    "episode_request" => json!({"episode_ref": "epi-1", "state": "eligible"}),
                    "episode_claim" => json!({
                        "byom_attempt_ref": format!("att-{fence}"),
                        "byom_fence_epoch": fence,
                        "state": "lease_leased",
                    }),
                    "episode_start" => json!({"state": "lease_running"}),
                    _ => json!({}),
                };
                let mut stream = stream;
                let _ = stream.write_all(
                    format!("{}\n", json!({"outcome": "ok", "result": result})).as_bytes(),
                );
            }
        });
        RuntimeStub {
            dir: dir.to_path_buf(),
            fence,
            stop,
        }
        .also_wait()
    }

    fn also_wait(self) -> RuntimeStub {
        // The listener is bound before the thread starts serving, so one
        // connect attempt is enough to know the path is live.
        for _ in 0..100 {
            if std::os::unix::net::UnixStream::connect(self.dir.join("runtime.sock")).is_ok() {
                return self;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("runtime stub never came up");
    }

    fn endpoint(&self) -> Endpoint {
        Endpoint::at("local", &self.dir)
    }

    /// A new attempt claim advances the byom fence — which is exactly what
    /// invalidates every binding of the previous attempt.
    fn advance_byom_fence(&self) -> u64 {
        let mut fence = self.fence.lock().unwrap();
        *fence += 1;
        *fence
    }
}

impl Drop for RuntimeStub {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
        let _ = std::os::unix::net::UnixStream::connect(self.dir.join("runtime.sock"));
    }
}

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
        resource_allocation_ref: "alloc-1".to_owned(),
        mandate_use_refs: vec!["mu-1".to_owned()],
        byom_budget_reservation_ref: "brs-1".to_owned(),
        external_budget_bridge_ref: "ebb-1".to_owned(),
        context_manifest_ref: "cm-1".to_owned(),
    }
}

fn fixture(tag: &str) -> (Store, RuntimeStub) {
    let base = tmp(tag);
    let mut store = Store::open(&base.join("kovee.sqlite3")).unwrap();
    store.bootstrap(0).unwrap();
    // An ACTIVE governed-work seam: an Episode is hosted only under one.
    koveed::budget::doc_seam(&mut store);
    let stub = RuntimeStub::start(&base.join("byom-run"), 7);
    (store, stub)
}

/// Places, admits, and starts one Episode attempt.
fn activate(store: &mut Store, stub: &RuntimeStub) -> episode::Bound {
    let notice = notice();
    let placed = episode::place(store, REALM, &notice, "inv-1", 0).unwrap();
    episode::admit(store, &stub.endpoint(), &placed.placement_id, 0).unwrap();
    episode::start(store, &stub.endpoint(), &placed.placement_id, &notice, 0).unwrap()
}

// ------------------------------------------------------------ stage order ----

#[test]
fn no_episode_work_happens_before_byom_admits_the_placement() {
    let (mut store, stub) = fixture("k2-episode-order");
    let notice = notice();

    // Stage 2: Kovee authors the one activation record it owns.
    let placed = episode::place(&mut store, REALM, &notice, "inv-1", 0).unwrap();
    assert_eq!(placed.record.owner_protocol, "kovee");
    assert_eq!(placed.record.state, "placed");
    assert_eq!(placed.kovee_fence_epoch, 1);

    // Stage 4 refuses outright: nothing skips a stage.
    let refused = episode::start(
        &mut store,
        &stub.endpoint(),
        &placed.placement_id,
        &notice,
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

    // Stage 3, then stage 4.
    episode::admit(&mut store, &stub.endpoint(), &placed.placement_id, 0).unwrap();
    let bound = episode::start(
        &mut store,
        &stub.endpoint(),
        &placed.placement_id,
        &notice,
        0,
    )
    .unwrap();
    assert_eq!(bound.fences, Fences { byom: 7, kovee: 1 });
    assert_eq!(bindings(&store).len(), 1);

    // Placing the same allocation twice is the identical placement.
    let again = episode::place(&mut store, REALM, &notice, "inv-1", 0).unwrap();
    assert_eq!(again.placement_id, placed.placement_id);
}

// ------------------------------------------------------------ dual fences ----

#[test]
fn a_stale_byom_fence_refuses_and_fences_the_binding() {
    let (mut store, stub) = fixture("k2-episode-byom-fence");
    let bound = activate(&mut store, &stub);

    // A successor attempt claimed the Episode: the BYOM fence advanced.
    let advanced = stub.advance_byom_fence();
    let stale = Fences {
        byom: bound.fences.byom,
        kovee: bound.fences.kovee,
    };
    let presented = Fences {
        byom: advanced,
        kovee: bound.fences.kovee,
    };
    let refused =
        episode::checkpoint(&mut store, &bound.stable_binding_key, presented, 1).unwrap_err();
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
    assert_eq!(row["byom_fence_epoch"], json!(stale.byom));
    // Terminal: even the ORIGINAL pair advances nothing now.
    let after = episode::checkpoint(&mut store, &bound.stable_binding_key, stale, 2).unwrap_err();
    assert_eq!(after.kind, ProblemKind::Forbidden);
    assert!(
        after.detail.as_ref().unwrap().contains("advances nothing"),
        "{after:?}"
    );
}

#[test]
fn a_stale_kovee_fence_refuses_and_fences_the_binding() {
    let (mut store, stub) = fixture("k2-episode-kovee-fence");
    let bound = activate(&mut store, &stub);

    // The HOST-side fence advanced: a mutation presenting a current byom
    // fence and a stale Kovee one is not "mostly current", it is fenced.
    let presented = Fences {
        byom: bound.fences.byom,
        kovee: bound.fences.kovee + 1,
    };
    let refused = episode::yield_episode(
        &mut store,
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

    // A mutation carrying only ONE fence is invalid — presenting the
    // bound byom fence with a zeroed Kovee one is refused too.
    let (mut store, stub) = fixture("k2-episode-kovee-fence-2");
    let bound = activate(&mut store, &stub);
    let half = Fences {
        byom: bound.fences.byom,
        kovee: 0,
    };
    assert_eq!(
        episode::complete(&mut store, &bound.stable_binding_key, half, 1)
            .unwrap_err()
            .kind,
        ProblemKind::StaleLease
    );
}

// -------------------------------------------------------- idempotent create ----

#[test]
fn the_binding_is_idempotent_over_its_stable_key() {
    let (mut store, stub) = fixture("k2-episode-idempotent");
    let first = activate(&mut store, &stub);
    // An exact retry at the same claim CAS returns the IDENTICAL row.
    let notice = notice();
    let placed = episode::place(&mut store, REALM, &notice, "inv-1", 0).unwrap();
    let again = episode::start(
        &mut store,
        &stub.endpoint(),
        &placed.placement_id,
        &notice,
        0,
    )
    .unwrap();
    assert_eq!(again.stable_binding_key, first.stable_binding_key);
    assert_eq!(again.record, first.record);
    assert_eq!(
        bindings(&store).len(),
        1,
        "a second binding row was created"
    );

    // The record is the §16.6 shape, with BOTH fences and the closed
    // local-commitment set.
    let record = &bindings(&store)[0]["record"];
    assert_eq!(record["byom_fence_epoch"], json!(7));
    assert_eq!(record["kovee_invocation_fence"], json!(1));
    assert_eq!(
        record["allowed_local_commitments"],
        json!(["contribution_append", "attention_mark"])
    );
    assert_eq!(record["context_manifest_ref"], json!("cm-1"));
    assert_eq!(record["external_budget_bridge_ref"], json!("ebb-1"));
    assert_eq!(record["mandate_use_refs"], json!(["mu-1"]));

    // And the read surface reports it with both fences.
    let shown = show(&store, json!({"episode_ref": "epi-1"}));
    assert_eq!(shown["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(shown["bindings"][0]["byom_fence_epoch"], json!(7));
    assert_eq!(shown["bindings"][0]["kovee_invocation_fence"], json!(1));
}

// -------------------------------------------------------- yield and rebind ----

#[test]
fn a_yield_hands_off_a_continuation_and_a_successor_binds_afresh() {
    let (mut store, stub) = fixture("k2-episode-yield");
    let bound = activate(&mut store, &stub);
    let handoff = episode::yield_episode(
        &mut store,
        &bound.stable_binding_key,
        bound.fences,
        "cont-1",
        1,
    )
    .unwrap();
    assert_eq!(handoff["continuation_ref"], json!("cont-1"));
    assert_eq!(handoff["byom_fence_epoch"], json!(bound.fences.byom));
    assert_eq!(handoff["successor_requires_new_binding"], json!(true));
    assert_eq!(bindings(&store)[0]["episode_state"], json!("yielded"));

    // The successor attempt claims under a NEW byom fence, so it gets a
    // NEW binding row under a new stable key — re-binding is never a
    // transition of the old row.
    let successor = Fences {
        byom: stub.advance_byom_fence(),
        kovee: bound.fences.kovee,
    };
    let placed = episode::place(&mut store, REALM, &notice(), "inv-1", 0).unwrap();
    let rebound = episode::rebind(
        &mut store,
        REALM,
        &placed.placement_id,
        &notice(),
        "epi-1",
        "att-successor",
        successor,
        2,
    )
    .unwrap();
    assert_ne!(rebound.stable_binding_key, bound.stable_binding_key);
    assert_eq!(rebound.fences, successor);
    // Both rows exist: the predecessor stays in the audit closure.
    let rows = bindings(&store);
    assert_eq!(rows.len(), 2);
    // And the predecessor cannot advance anything under the new fence.
    assert_eq!(
        episode::checkpoint(&mut store, &bound.stable_binding_key, successor, 3)
            .unwrap_err()
            .kind,
        ProblemKind::StaleLease
    );
}

// ------------------------------------------------------------ orderly close ----

#[test]
fn a_complete_releases_the_binding_and_hands_off_the_reservations() {
    let (mut store, stub) = fixture("k2-episode-complete");
    let bound = activate(&mut store, &stub);
    // Intra-episode mutations honor both fences.
    episode::checkpoint(&mut store, &bound.stable_binding_key, bound.fences, 1).unwrap();
    episode::complete(&mut store, &bound.stable_binding_key, bound.fences, 2).unwrap();
    let row = &bindings(&store)[0];
    assert_eq!(row["state"], json!("released"));
    assert_eq!(row["episode_state"], json!("completed"));
    // Terminal: the released row stays in the audit closure and advances
    // nothing further.
    assert_eq!(
        episode::checkpoint(&mut store, &bound.stable_binding_key, bound.fences, 3)
            .unwrap_err()
            .kind,
        ProblemKind::Forbidden
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
