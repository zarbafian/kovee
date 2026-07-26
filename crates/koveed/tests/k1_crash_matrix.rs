//! K1 crash matrix: kill-and-restart at each §12.2 command-transaction
//! commit point (the slice-1 crash hooks, extended to every slice-2
//! mutation, including the artifact-finalize pipeline points). For every
//! armed operation:
//!
//! - `before_commit`: after restart nothing of the transaction exists;
//!   the retry with the SAME key executes fresh, exactly once;
//! - `after_commit`: the transaction is durable exactly once; the retry
//!   replays the stored byte-identical result;
//! - and in both cases a second retry is byte-identical to the first.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{json, Value};

/// Counts committed effects of the armed op: events of `event_type` in
/// the project stream.
fn count_events(daemon: &DaemonProc, project: &str, event_type: &str) -> usize {
    let events = daemon.expect_ok(&events_read(project));
    events["result"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"].as_str() == Some(event_type))
        .count()
}

/// Project sequences must stay dense and monotonic (§11.3) after every
/// crash/retry cycle.
fn assert_dense(daemon: &DaemonProc, project: &str) {
    let events = daemon.expect_ok(&events_read(project));
    for (i, event) in events["result"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(
            event["project_sequence"].as_u64(),
            Some(i as u64 + 1),
            "project sequence not dense at {i}: {event}"
        );
    }
}

/// One matrix cell: arm `phase:op`, fire `target`, restart, verify the
/// §12.2 exactly-once contract via `probe` (committed-effect count).
fn run_cell(name: &str, op: &str, phase: &str, setup: impl FnOnce(&DaemonProc) -> (String, Value)) {
    let base = tmp(&format!("k1-matrix-{name}-{phase}"));
    let data = base.join("data");
    let run = base.join("run");

    let healthy = DaemonProc::start(&data, &run, None);
    let (project, target) = setup(&healthy);
    let event_type = event_type_of(op);
    let committed_before = count_events(&healthy, &project, event_type);
    drop(healthy);

    let armed = DaemonProc::start(&data, &run, Some(&format!("{phase}:{op}")));
    assert!(
        armed.request_raw(&target).is_none(),
        "{name}/{phase}: the armed daemon must die before replying"
    );
    armed.wait_dead();

    let recovered = DaemonProc::start(&data, &run, None);
    let committed_after_crash = count_events(&recovered, &project, event_type);
    match phase {
        "before_commit" => assert_eq!(
            committed_after_crash, committed_before,
            "{name}/{phase}: nothing may survive a pre-commit abort"
        ),
        "after_commit" => assert_eq!(
            committed_after_crash,
            committed_before + 1,
            "{name}/{phase}: the committed transaction survives exactly once"
        ),
        other => panic!("unknown phase {other}"),
    }
    assert_dense(&recovered, &project);

    // The idempotent retry: exactly one effect, byte-identical replays.
    let raw_first = recovered.request_raw(&target).unwrap();
    let first: Value = serde_json::from_str(&raw_first).unwrap();
    assert_eq!(first["outcome"].as_str(), Some("ok"), "{name}: {first}");
    assert_eq!(
        count_events(&recovered, &project, event_type),
        committed_before + 1,
        "{name}/{phase}: exactly one committed effect after the retry"
    );
    let raw_second = recovered.request_raw(&target).unwrap();
    assert_eq!(
        raw_first, raw_second,
        "{name}/{phase}: replays are byte-identical"
    );
    assert_eq!(
        count_events(&recovered, &project, event_type),
        committed_before + 1,
        "{name}/{phase}: a replay commits nothing new"
    );
    assert_dense(&recovered, &project);
}

fn event_type_of(op: &str) -> &'static str {
    match op {
        "project_create" => "dev.kovee.project.created.v1",
        "space_create" => "dev.kovee.space.created.v1",
        "contribution_append" => "dev.kovee.space.contribution-appended.v1",
        "relation_assert" => "dev.kovee.space.relation-asserted.v1",
        "frontier_pin" => "dev.kovee.space.frontier-pinned.v1",
        "context_assembly_create" => "dev.kovee.space.context-assembly-created.v1",
        "invocation_create" => "dev.kovee.invocation.created.v1",
        // -------------------------------------------------- slice 3 ----
        "project_update_metadata" => "dev.kovee.project.updated.v1",
        "project_access_policy_change_prepare" => "dev.kovee.project.policy-change-prepared.v1",
        "project_access_policy_change_confirm" => "dev.kovee.project.policy-change-confirmed.v1",
        "project_access_policy_change_cancel" => "dev.kovee.project.policy-change-canceled.v1",
        "space_update_metadata" => "dev.kovee.space.updated.v1",
        "space_freeze" => "dev.kovee.space.frozen.v1",
        "space_reopen" => "dev.kovee.space.reopened.v1",
        "space_archive" => "dev.kovee.space.archived.v1",
        "space_restrict" => "dev.kovee.space.restricted.v1",
        "space_policy_narrow" => "dev.kovee.space.policy-narrowed.v1",
        "space_access_widen_prepare" => "dev.kovee.space.access-widening-prepared.v1",
        "space_access_widen_confirm" => "dev.kovee.space.access-widening-confirmed.v1",
        "space_access_widen_cancel" => "dev.kovee.space.access-widening-canceled.v1",
        "space_participant_add" => "dev.kovee.space.participant-added.v1",
        "space_participant_activate" => "dev.kovee.space.participant-activated.v1",
        "space_participant_update" => "dev.kovee.space.participant-updated.v1",
        "space_participant_remove" => "dev.kovee.space.participant-removed.v1",
        "space_access_grant_create" => "dev.kovee.space.access-grant-created.v1",
        "space_access_grant_revoke" => "dev.kovee.space.access-grant-revoked.v1",
        "contribution_withdraw" => "dev.kovee.space.contribution-withdrawn.v1",
        "contribution_supersede" => "dev.kovee.space.contribution-superseded.v1",
        "contribution_redact" => "dev.kovee.space.contribution-redacted.v1",
        "relation_retract" => "dev.kovee.space.relation-retracted.v1",
        "lens_create" => "dev.kovee.space.lens-created.v1",
        "lens_update" => "dev.kovee.space.lens-updated.v1",
        "lens_revoke" => "dev.kovee.space.lens-revoked.v1",
        "reaction_set" => "dev.kovee.space.reaction-set.v1",
        "assistant_alias_bind" => "dev.kovee.assistant.alias-bound.v1",
        "assistant_alias_update" => "dev.kovee.assistant.alias-updated.v1",
        "assistant_alias_revoke" => "dev.kovee.assistant.alias-revoked.v1",
        "invocation_cancel" => "dev.kovee.invocation.canceled.v1",
        other => panic!("no event probe for {other}"),
    }
}

fn both_phases(name: &str, op: &'static str, setup: impl Fn(&DaemonProc) -> (String, Value)) {
    for phase in ["before_commit", "after_commit"] {
        run_cell(name, op, phase, &setup);
    }
}

#[test]
fn project_create_matrix() {
    // The armed op creates the project itself, so its event stream is
    // only knowable from the retry result: the exactly-once proof is the
    // byte-identical replay plus exactly one dense `project.created`
    // event in the stream the retry names.
    for phase in ["before_commit", "after_commit"] {
        let base = tmp(&format!("k1-matrix-project-{phase}"));
        let data = base.join("data");
        let run = base.join("run");
        // Bootstrap the store, then arm.
        drop(DaemonProc::start(&data, &run, None));
        let target = mutation(
            "project_create",
            None,
            "idem-matrix-project",
            json!({
                "name": "matrix",
            }),
        );
        let armed = DaemonProc::start(&data, &run, Some(&format!("{phase}:project_create")));
        assert!(armed.request_raw(&target).is_none(), "{phase}: must die");
        armed.wait_dead();
        let recovered = DaemonProc::start(&data, &run, None);
        let raw_first = recovered.request_raw(&target).unwrap();
        let first: Value = serde_json::from_str(&raw_first).unwrap();
        assert_eq!(first["outcome"].as_str(), Some("ok"), "{phase}: {first}");
        let raw_second = recovered.request_raw(&target).unwrap();
        assert_eq!(raw_first, raw_second, "{phase}: replay is byte-identical");
        let project = first["result"]["project_id"].as_str().unwrap();
        assert_eq!(
            count_events(&recovered, project, "dev.kovee.project.created.v1"),
            1,
            "{phase}: exactly one committed create"
        );
        assert_dense(&recovered, project);
    }
}

#[test]
fn space_create_matrix() {
    both_phases("space-create", "space_create", |daemon| {
        let (project, _, _, _) = setup_space(daemon);
        let target = mutation(
            "space_create",
            Some(&project),
            "idem-matrix-space2",
            json!({"title": "matrix2", "visibility": "project"}),
        );
        (project, target)
    });
}

#[test]
fn contribution_append_matrix() {
    both_phases("append", "contribution_append", |daemon| {
        let (project, space, branch, head) = setup_space(daemon);
        let target = mutation(
            "contribution_append",
            Some(&project),
            "idem-matrix-append",
            json!({
                "space_id": space, "branch_id": branch,
                "expected_head_digest": head,
                "kind": "utterance",
                "body_parts": [{"media_type": "text/plain", "text": "crash me"}],
            }),
        );
        (project, target)
    });
}

#[test]
fn relation_assert_matrix() {
    both_phases("relation", "relation_assert", |daemon| {
        let (project, space, branch, head) = setup_space(daemon);
        let (a_id, a_digest, head) = append(
            daemon,
            &project,
            &space,
            &branch,
            &head,
            "idem-a",
            "claim",
            "claim A",
            json!({}),
        );
        let (b_id, b_digest, head) = append(
            daemon,
            &project,
            &space,
            &branch,
            &head,
            "idem-b",
            "critique",
            "critique B",
            json!({}),
        );
        let target = mutation(
            "relation_assert",
            Some(&project),
            "idem-matrix-relation",
            json!({
                "space_id": space, "branch_id": branch,
                "expected_head_digest": head,
                "kind": "challenges",
                "from_ref": {"object_ref": b_id, "revision": 1, "digest": b_digest},
                "to_ref": {"object_ref": a_id, "revision": 1, "digest": a_digest},
            }),
        );
        (project, target)
    });
}

#[test]
fn frontier_pin_matrix() {
    both_phases("frontier", "frontier_pin", |daemon| {
        let (project, space, branch, head) = setup_space(daemon);
        let _ = append(
            daemon,
            &project,
            &space,
            &branch,
            &head,
            "idem-c",
            "question",
            "q?",
            json!({}),
        );
        let target = mutation(
            "frontier_pin",
            Some(&project),
            "idem-matrix-frontier",
            json!({"space_id": space, "branch_id": branch}),
        );
        (project, target)
    });
}

#[test]
fn context_assembly_create_matrix() {
    both_phases("assembly", "context_assembly_create", |daemon| {
        let (project, space, branch, head) = setup_space(daemon);
        let (q_id, _, _) = append(
            daemon,
            &project,
            &space,
            &branch,
            &head,
            "idem-q",
            "question",
            "q?",
            json!({}),
        );
        let target = mutation(
            "context_assembly_create",
            Some(&project),
            "idem-matrix-assembly",
            json!({
                "space_id": space, "branch_id": branch,
                "audience_ref": "asstdep-dep-local-dev",
                "purpose": "crash matrix",
                "selection_policy_ref": "explicit_refs_v1",
                "required_refs": [q_id],
                "trigger_refs": [q_id],
            }),
        );
        (project, target)
    });
}

#[test]
fn invocation_create_matrix() {
    both_phases("invoke", "invocation_create", |daemon| {
        let (project, space, branch, head) = setup_space(daemon);
        let (q_id, _, _) = append(
            daemon,
            &project,
            &space,
            &branch,
            &head,
            "idem-q",
            "question",
            "q?",
            json!({}),
        );
        let assembly = daemon.expect_ok(&mutation(
            "context_assembly_create",
            Some(&project),
            "idem-asm",
            json!({
                "space_id": space, "branch_id": branch,
                "audience_ref": "asstdep-dep-local-dev",
                "purpose": "crash matrix",
                "selection_policy_ref": "explicit_refs_v1",
                "required_refs": [q_id],
                "trigger_refs": [q_id],
            }),
        ));
        let target = mutation(
            "invocation_create",
            Some(&project),
            "idem-matrix-invoke",
            json!({
                "assistant_deployment_id": "dep-local-dev",
                "assistant_deployment_revision": 1,
                "space_id": space,
                "branch_id": branch,
                "context_assembly_ref": assembly["result"]["assembly_id"],
                "context_assembly_digest": assembly["result"]["digest"],
                "deadline": "2027-01-01T00:00:00Z",
            }),
        );
        (project, target)
    });
}

// ---------------------------------------------------- artifact finalize ----

fn artifact_setup(daemon: &DaemonProc, bytes: &[u8]) -> (String, String, Value) {
    let raw_hex = {
        use std::fmt::Write as _;
        let digest = <sha2::Sha256 as sha2::Digest>::digest(bytes);
        digest.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    };
    let begin = daemon.expect_ok(&mutation(
        "artifact_upload_begin",
        None,
        "idem-artifact-begin",
        json!({
            "declared_raw_sha256": raw_hex,
            "declared_size": bytes.len(),
            "declared_media_type": "text/plain",
        }),
    ));
    let upload_id = begin["result"]["upload_id"].as_str().unwrap().to_owned();
    let artifact_id = begin["result"]["artifact_id"].as_str().unwrap().to_owned();
    // Write the bytes through the credential's staging path.
    let credential = daemon.expect_ok(&read_cmd(
        "artifact_upload_credential",
        None,
        json!({"upload_id": upload_id}),
    ));
    let staging = credential["result"]["credential"]["path"].as_str().unwrap();
    std::fs::write(staging, bytes).unwrap();
    let finalize = mutation(
        "artifact_upload_finalize",
        None,
        "idem-artifact-finalize",
        json!({"upload_id": upload_id}),
    );
    (upload_id, artifact_id, finalize)
}

fn artifact_state(daemon: &DaemonProc, artifact_id: &str) -> String {
    let shown = daemon.expect_ok(&read_cmd(
        "artifact_show",
        None,
        json!({"artifact_id": artifact_id}),
    ));
    shown["result"]["state"].as_str().unwrap().to_owned()
}

#[test]
fn artifact_finalize_matrix_unverified_bytes_never_become_available() {
    // Every pre-final-commit crash point: seal-state txn committed, bytes
    // sealed, final txn armed — in NO case may the artifact read
    // `available` after the crash; the retry completes it exactly once.
    for phase in ["after_seal_txn", "after_seal", "before_commit"] {
        let base = tmp(&format!("k1-matrix-artifact-{phase}"));
        let data = base.join("data");
        let run = base.join("run");
        let healthy = DaemonProc::start(&data, &run, None);
        let (upload_id, artifact_id, finalize) = artifact_setup(&healthy, b"artifact bytes");
        drop(healthy);

        let armed = DaemonProc::start(
            &data,
            &run,
            Some(&format!("{phase}:artifact_upload_finalize")),
        );
        assert!(
            armed.request_raw(&finalize).is_none(),
            "{phase}: the armed daemon must die before replying"
        );
        armed.wait_dead();

        let recovered = DaemonProc::start(&data, &run, None);
        let state = artifact_state(&recovered, &artifact_id);
        assert_ne!(
            state, "available",
            "{phase}: unverified bytes never become available"
        );
        // The retry reconciles from the same upload id and completes
        // exactly once.
        let raw_first = recovered.request_raw(&finalize).unwrap();
        let first: Value = serde_json::from_str(&raw_first).unwrap();
        assert_eq!(first["outcome"].as_str(), Some("ok"), "{phase}: {first}");
        assert_eq!(first["result"]["state"].as_str(), Some("completed"));
        assert_eq!(artifact_state(&recovered, &artifact_id), "available");
        let raw_second = recovered.request_raw(&finalize).unwrap();
        assert_eq!(raw_first, raw_second, "{phase}: replay is byte-identical");
        let upload = recovered.expect_ok(&read_cmd(
            "artifact_upload_show",
            None,
            json!({"upload_id": upload_id}),
        ));
        assert_eq!(upload["result"]["state"].as_str(), Some("completed"));
    }

    // after_commit: the availability is durable; the retry replays.
    let base = tmp("k1-matrix-artifact-after-commit");
    let data = base.join("data");
    let run = base.join("run");
    let healthy = DaemonProc::start(&data, &run, None);
    let (_upload_id, artifact_id, finalize) = artifact_setup(&healthy, b"artifact bytes");
    drop(healthy);
    let armed = DaemonProc::start(&data, &run, Some("after_commit:artifact_upload_finalize"));
    assert!(armed.request_raw(&finalize).is_none());
    armed.wait_dead();
    let recovered = DaemonProc::start(&data, &run, None);
    assert_eq!(artifact_state(&recovered, &artifact_id), "available");
    let raw_first = recovered.request_raw(&finalize).unwrap();
    let raw_second = recovered.request_raw(&finalize).unwrap();
    assert_eq!(raw_first, raw_second);
}

#[test]
fn artifact_upload_begin_matrix() {
    for phase in ["before_commit", "after_commit"] {
        let base = tmp(&format!("k1-matrix-artifact-begin-{phase}"));
        let data = base.join("data");
        let run = base.join("run");
        let healthy = DaemonProc::start(&data, &run, None);
        // Bootstrap only.
        let _ = setup_space(&healthy);
        drop(healthy);
        let target = mutation(
            "artifact_upload_begin",
            None,
            "idem-matrix-begin",
            json!({
                "declared_raw_sha256": "a".repeat(64),
                "declared_size": 4,
                "declared_media_type": "text/plain",
            }),
        );
        let armed = DaemonProc::start(&data, &run, Some(&format!("{phase}:artifact_upload_begin")));
        assert!(armed.request_raw(&target).is_none());
        armed.wait_dead();
        let recovered = DaemonProc::start(&data, &run, None);
        let raw_first = recovered.request_raw(&target).unwrap();
        let first: Value = serde_json::from_str(&raw_first).unwrap();
        assert_eq!(first["outcome"].as_str(), Some("ok"), "{phase}: {first}");
        let raw_second = recovered.request_raw(&target).unwrap();
        assert_eq!(raw_first, raw_second, "{phase}: replay is byte-identical");
        // Exactly one upload row answers this key: the shown state is
        // `prepared` and both replies name the same upload id.
        let upload_id = first["result"]["upload_id"].as_str().unwrap();
        let upload = recovered.expect_ok(&read_cmd(
            "artifact_upload_show",
            None,
            json!({"upload_id": upload_id}),
        ));
        assert_eq!(upload["result"]["state"].as_str(), Some("prepared"));
    }
}

// ================================================= slice-3 mutations ----

/// Appends one contribution and returns its id (fresh setup helper for
/// the disposition cells).
fn seeded_contribution(daemon: &DaemonProc, key: &str) -> (String, String, String, String, String) {
    let (project, space, branch, head) = setup_space(daemon);
    let (id, digest, head) = append(
        daemon,
        &project,
        &space,
        &branch,
        &head,
        key,
        "claim",
        "seed",
        json!({}),
    );
    (project, space, id, digest, head)
}

#[test]
fn project_lifecycle_matrix() {
    both_phases("project-update", "project_update_metadata", |daemon| {
        let (project, _, _, _) = setup_space(daemon);
        let target = mutation(
            "project_update_metadata",
            Some(&project),
            "idem-matrix-pupd",
            json!({"name": "renamed"}),
        );
        (project, target)
    });
    both_phases(
        "papc-prepare",
        "project_access_policy_change_prepare",
        |daemon| {
            let (project, _, _, _) = setup_space(daemon);
            let target = mutation(
                "project_access_policy_change_prepare",
                Some(&project),
                "idem-matrix-papc-prep",
                json!({"proposed_policy_set_ref": "policy-tighter"}),
            );
            (project, target)
        },
    );
    both_phases(
        "papc-confirm",
        "project_access_policy_change_confirm",
        |daemon| {
            let (project, _, _, _) = setup_space(daemon);
            let prepared = daemon.expect_ok(&mutation(
                "project_access_policy_change_prepare",
                Some(&project),
                "idem-papc-prep",
                json!({"proposed_policy_set_ref": "policy-tighter"}),
            ));
            let target = mutation(
                "project_access_policy_change_confirm",
                Some(&project),
                "idem-matrix-papc-conf",
                json!({
                    "change_id": prepared["result"]["change_id"],
                    "decision_receipt_ref": "receipt-owner-1",
                }),
            );
            (project, target)
        },
    );
    both_phases(
        "papc-cancel",
        "project_access_policy_change_cancel",
        |daemon| {
            let (project, _, _, _) = setup_space(daemon);
            let prepared = daemon.expect_ok(&mutation(
                "project_access_policy_change_prepare",
                Some(&project),
                "idem-papc-prep2",
                json!({}),
            ));
            let target = mutation(
                "project_access_policy_change_cancel",
                Some(&project),
                "idem-matrix-papc-cancel",
                json!({"change_id": prepared["result"]["change_id"]}),
            );
            (project, target)
        },
    );
}

#[test]
fn space_lifecycle_matrix() {
    both_phases("space-update", "space_update_metadata", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "space_update_metadata",
            Some(&project),
            "idem-matrix-supd",
            json!({"space_id": space, "title": "Renamed"}),
        );
        (project, target)
    });
    both_phases("space-freeze", "space_freeze", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "space_freeze",
            Some(&project),
            "idem-matrix-freeze",
            json!({"space_id": space}),
        );
        (project, target)
    });
    both_phases("space-reopen", "space_reopen", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        daemon.expect_ok(&mutation(
            "space_freeze",
            Some(&project),
            "idem-freeze-setup",
            json!({"space_id": space}),
        ));
        let target = mutation(
            "space_reopen",
            Some(&project),
            "idem-matrix-reopen",
            json!({"space_id": space}),
        );
        (project, target)
    });
    both_phases("space-archive", "space_archive", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "space_archive",
            Some(&project),
            "idem-matrix-archive",
            json!({"space_id": space}),
        );
        (project, target)
    });
    both_phases("space-restrict", "space_restrict", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "space_restrict",
            Some(&project),
            "idem-matrix-restrict",
            json!({"space_id": space}),
        );
        (project, target)
    });
    both_phases("space-narrow", "space_policy_narrow", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "space_policy_narrow",
            Some(&project),
            "idem-matrix-narrow",
            json!({"space_id": space, "policy_set_ref": "policy-tighter"}),
        );
        (project, target)
    });
}

#[test]
fn widening_matrix() {
    both_phases("widen-prepare", "space_access_widen_prepare", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "space_access_widen_prepare",
            Some(&project),
            "idem-matrix-widen-prep",
            json!({"space_id": space, "proposed_visibility": "project"}),
        );
        (project, target)
    });
    both_phases("widen-confirm", "space_access_widen_confirm", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let prepared = daemon.expect_ok(&mutation(
            "space_access_widen_prepare",
            Some(&project),
            "idem-widen-prep",
            json!({"space_id": space, "proposed_visibility": "project"}),
        ));
        let target = mutation(
            "space_access_widen_confirm",
            Some(&project),
            "idem-matrix-widen-conf",
            json!({
                "widening_id": prepared["result"]["widening_id"],
                "decision_receipt_ref": "receipt-owner-1",
            }),
        );
        (project, target)
    });
    both_phases("widen-cancel", "space_access_widen_cancel", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let prepared = daemon.expect_ok(&mutation(
            "space_access_widen_prepare",
            Some(&project),
            "idem-widen-prep2",
            json!({"space_id": space}),
        ));
        let target = mutation(
            "space_access_widen_cancel",
            Some(&project),
            "idem-matrix-widen-cancel",
            json!({"widening_id": prepared["result"]["widening_id"]}),
        );
        (project, target)
    });
}

fn subject_digest_of(participant: &Value) -> String {
    let projection = json!({
        "participant_id": participant["participant_id"],
        "space_id": participant["space_id"],
        "subject_ref": participant["subject_ref"],
        "kind": participant["kind"],
        "role": participant["role"],
    });
    kovee_core::canonical::canonical_object_digest(
        "kovee-participant-subject",
        "schema:space-participant-v1",
        &projection,
    )
    .unwrap()
    .1
}

#[test]
fn participant_matrix() {
    both_phases("part-add", "space_participant_add", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "space_participant_add",
            Some(&project),
            "idem-matrix-part-add",
            json!({
                "space_id": space, "subject_ref": "prin-guest",
                "kind": "principal", "role": "observer",
            }),
        );
        (project, target)
    });
    both_phases("part-activate", "space_participant_activate", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let added = daemon.expect_ok(&mutation(
            "space_participant_add",
            Some(&project),
            "idem-part-add",
            json!({
                "space_id": space, "subject_ref": "prin-guest",
                "kind": "principal", "role": "observer",
            }),
        ));
        let target = mutation(
            "space_participant_activate",
            Some(&project),
            "idem-matrix-part-act",
            json!({
                "participant_id": added["result"]["participant_id"],
                "subject_digest": subject_digest_of(&added["result"]),
            }),
        );
        (project, target)
    });
    both_phases("part-update", "space_participant_update", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let added = daemon.expect_ok(&mutation(
            "space_participant_add",
            Some(&project),
            "idem-part-add2",
            json!({
                "space_id": space, "subject_ref": "prin-guest",
                "kind": "principal", "role": "observer",
            }),
        ));
        daemon.expect_ok(&mutation(
            "space_participant_activate",
            Some(&project),
            "idem-part-act2",
            json!({
                "participant_id": added["result"]["participant_id"],
                "subject_digest": subject_digest_of(&added["result"]),
            }),
        ));
        let target = mutation(
            "space_participant_update",
            Some(&project),
            "idem-matrix-part-upd",
            json!({
                "participant_id": added["result"]["participant_id"],
                "role": "contributor",
            }),
        );
        (project, target)
    });
    both_phases("part-remove", "space_participant_remove", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let added = daemon.expect_ok(&mutation(
            "space_participant_add",
            Some(&project),
            "idem-part-add3",
            json!({
                "space_id": space, "subject_ref": "prin-guest",
                "kind": "principal", "role": "observer",
            }),
        ));
        let target = mutation(
            "space_participant_remove",
            Some(&project),
            "idem-matrix-part-rm",
            json!({"participant_id": added["result"]["participant_id"]}),
        );
        (project, target)
    });
}

#[test]
fn grant_matrix() {
    both_phases("grant-create", "space_access_grant_create", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "space_access_grant_create",
            Some(&project),
            "idem-matrix-grant",
            json!({
                "space_id": space, "subject_ref": "prin-guest",
                "allowed_actions": ["contribution_read"],
            }),
        );
        (project, target)
    });
    both_phases("grant-revoke", "space_access_grant_revoke", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let created = daemon.expect_ok(&mutation(
            "space_access_grant_create",
            Some(&project),
            "idem-grant-setup",
            json!({
                "space_id": space, "subject_ref": "prin-guest",
                "allowed_actions": ["contribution_read"],
            }),
        ));
        let target = mutation(
            "space_access_grant_revoke",
            Some(&project),
            "idem-matrix-grant-rev",
            json!({"space_access_id": created["result"]["space_access_id"]}),
        );
        (project, target)
    });
}

#[test]
fn disposition_matrix() {
    both_phases("withdraw", "contribution_withdraw", |daemon| {
        let (project, _, id, _, _) = seeded_contribution(daemon, "idem-seed-w");
        let target = mutation(
            "contribution_withdraw",
            Some(&project),
            "idem-matrix-withdraw",
            json!({"contribution_ref": id, "reason_class": "obsolete"}),
        );
        (project, target)
    });
    both_phases("supersede", "contribution_supersede", |daemon| {
        let (project, space, branch, head) = setup_space(daemon);
        let (old_id, _, head) = append(
            daemon,
            &project,
            &space,
            &branch,
            &head,
            "idem-a",
            "claim",
            "v1",
            json!({}),
        );
        let (new_id, _, _) = append(
            daemon,
            &project,
            &space,
            &branch,
            &head,
            "idem-b",
            "claim",
            "v2",
            json!({}),
        );
        let target = mutation(
            "contribution_supersede",
            Some(&project),
            "idem-matrix-supersede",
            json!({
                "contribution_ref": old_id, "replacement_ref": new_id,
                "reason_class": "revised",
            }),
        );
        (project, target)
    });
    both_phases("redact", "contribution_redact", |daemon| {
        let (project, _, id, _, _) = seeded_contribution(daemon, "idem-seed-r");
        let target = mutation(
            "contribution_redact",
            Some(&project),
            "idem-matrix-redact",
            json!({"contribution_ref": id, "reason_class": "policy_erasure"}),
        );
        (project, target)
    });
    both_phases("retract", "relation_retract", |daemon| {
        let (project, space, branch, head) = setup_space(daemon);
        let (a_id, a_digest, head) = append(
            daemon,
            &project,
            &space,
            &branch,
            &head,
            "idem-a",
            "claim",
            "a",
            json!({}),
        );
        let (b_id, b_digest, head) = append(
            daemon,
            &project,
            &space,
            &branch,
            &head,
            "idem-b",
            "critique",
            "b",
            json!({}),
        );
        let relation = daemon.expect_ok(&mutation(
            "relation_assert",
            Some(&project),
            "idem-rel-setup",
            json!({
                "space_id": space, "branch_id": branch,
                "expected_head_digest": head,
                "kind": "challenges",
                "from_ref": {"object_ref": b_id, "revision": 1, "digest": b_digest},
                "to_ref": {"object_ref": a_id, "revision": 1, "digest": a_digest},
            }),
        ));
        let target = mutation(
            "relation_retract",
            Some(&project),
            "idem-matrix-retract",
            json!({
                "relation_ref": relation["result"]["relation_id"],
                "reason_class": "withdrawn_claim",
            }),
        );
        (project, target)
    });
}

#[test]
fn lens_and_reaction_matrix() {
    both_phases("lens-create", "lens_create", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "lens_create",
            Some(&project),
            "idem-matrix-lens",
            json!({
                "space_id": space, "kind": "custom",
                "query_ast": {"select": "contributions"},
                "sort_spec": {"order_by": "branch_sequence"},
                "presentation_options": {"render": "chronological"},
                "visibility": "project",
            }),
        );
        (project, target)
    });
    both_phases("lens-update", "lens_update", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "lens_update",
            Some(&project),
            "idem-matrix-lens-upd",
            json!({
                "lens_id": format!("lens-stream-{space}"),
                "presentation_options": {"render": "compact"},
            }),
        );
        (project, target)
    });
    both_phases("lens-revoke", "lens_revoke", |daemon| {
        let (project, space, _, _) = setup_space(daemon);
        let target = mutation(
            "lens_revoke",
            Some(&project),
            "idem-matrix-lens-rev",
            json!({"lens_id": format!("lens-workbench-{space}")}),
        );
        (project, target)
    });
    both_phases("reaction", "reaction_set", |daemon| {
        let (project, _, id, digest, _) = seeded_contribution(daemon, "idem-seed-react");
        let target = mutation(
            "reaction_set",
            Some(&project),
            "idem-matrix-react",
            json!({
                "space_id": daemon.expect_ok(&read_cmd(
                    "contribution_show", Some(&project),
                    json!({"contribution_id": id}),
                ))["result"]["space_id"],
                "target_ref": id, "target_revision": 1, "target_digest": digest,
                "key": "insightful", "state": "present",
            }),
        );
        (project, target)
    });
}

#[test]
fn alias_and_cancel_matrix() {
    both_phases("alias-bind", "assistant_alias_bind", |daemon| {
        let (project, _, _, _) = setup_space(daemon);
        let target = mutation(
            "assistant_alias_bind",
            Some(&project),
            "idem-matrix-alias",
            json!({
                "display_alias": "Dev Helper",
                "assistant_deployment_id": "dep-local-dev",
                "deployment_revision": 1,
            }),
        );
        (project, target)
    });
    both_phases("alias-update", "assistant_alias_update", |daemon| {
        let (project, _, _, _) = setup_space(daemon);
        let bound = daemon.expect_ok(&mutation(
            "assistant_alias_bind",
            Some(&project),
            "idem-alias-setup",
            json!({
                "display_alias": "Dev Helper",
                "assistant_deployment_id": "dep-local-dev",
                "deployment_revision": 1,
            }),
        ));
        let target = mutation(
            "assistant_alias_update",
            Some(&project),
            "idem-matrix-alias-upd",
            json!({
                "alias_binding_id": bound["result"]["alias_binding_id"],
                "assistant_deployment_id": "dep-local-dev",
                "deployment_revision": 1,
            }),
        );
        (project, target)
    });
    both_phases("alias-revoke", "assistant_alias_revoke", |daemon| {
        let (project, _, _, _) = setup_space(daemon);
        let bound = daemon.expect_ok(&mutation(
            "assistant_alias_bind",
            Some(&project),
            "idem-alias-setup2",
            json!({
                "display_alias": "Dev Helper",
                "assistant_deployment_id": "dep-local-dev",
                "deployment_revision": 1,
            }),
        ));
        let target = mutation(
            "assistant_alias_revoke",
            Some(&project),
            "idem-matrix-alias-rev",
            json!({"alias_binding_id": bound["result"]["alias_binding_id"]}),
        );
        (project, target)
    });
    both_phases("inv-cancel", "invocation_cancel", |daemon| {
        let (project, _, _, _) = setup_space(daemon);
        let invocation = daemon.expect_ok(&mutation(
            "invocation_create",
            Some(&project),
            "idem-inv-setup",
            json!({
                "assistant_deployment_id": "dep-local-dev",
                "assistant_deployment_revision": 1,
                "deadline": "2027-01-01T00:00:00Z",
            }),
        ));
        let target = mutation(
            "invocation_cancel",
            Some(&project),
            "idem-matrix-inv-cancel",
            json!({"invocation_id": invocation["result"]["invocation_id"]}),
        );
        (project, target)
    });
}

// -------------------------------------------- realm-level mutations ----

/// A realm-level matrix cell: the probe is a read-derived count instead
/// of a project-stream event count.
fn realm_cell(
    name: &str,
    op: &str,
    phase: &str,
    setup: impl FnOnce(&DaemonProc) -> Value,
    probe: impl Fn(&DaemonProc) -> usize,
) {
    let base = tmp(&format!("k1-matrix-{name}-{phase}"));
    let data = base.join("data");
    let run = base.join("run");
    let healthy = DaemonProc::start(&data, &run, None);
    let target = setup(&healthy);
    let committed_before = probe(&healthy);
    drop(healthy);

    let armed = DaemonProc::start(&data, &run, Some(&format!("{phase}:{op}")));
    assert!(
        armed.request_raw(&target).is_none(),
        "{name}/{phase}: the armed daemon must die before replying"
    );
    armed.wait_dead();

    let recovered = DaemonProc::start(&data, &run, None);
    let committed_after_crash = probe(&recovered);
    match phase {
        "before_commit" => assert_eq!(committed_after_crash, committed_before),
        "after_commit" => assert_eq!(committed_after_crash, committed_before + 1),
        other => panic!("unknown phase {other}"),
    }
    let raw_first = recovered.request_raw(&target).unwrap();
    let first: Value = serde_json::from_str(&raw_first).unwrap();
    assert_eq!(first["outcome"].as_str(), Some("ok"), "{name}: {first}");
    assert_eq!(probe(&recovered), committed_before + 1);
    let raw_second = recovered.request_raw(&target).unwrap();
    assert_eq!(raw_first, raw_second, "{name}/{phase}: byte-identical");
    assert_eq!(probe(&recovered), committed_before + 1);
}

fn list_count(daemon: &DaemonProc, op: &str, args: Value) -> usize {
    let page = daemon.expect_ok(&read_cmd(op, None, args));
    page["result"]["items"].as_array().unwrap().len()
}

#[test]
fn assistant_registry_matrix() {
    for phase in ["before_commit", "after_commit"] {
        realm_cell(
            "assistant-create",
            "assistant_create",
            phase,
            |_| {
                mutation(
                    "assistant_create",
                    None,
                    "idem-matrix-asst",
                    json!({"name": "Summarizer", "description": "Summarizes spaces."}),
                )
            },
            |daemon| list_count(daemon, "assistant_list", json!({"limit": 512})),
        );
        realm_cell(
            "revision-register",
            "assistant_revision_register",
            phase,
            |daemon| {
                let created = daemon.expect_ok(&mutation(
                    "assistant_create",
                    None,
                    "idem-asst-setup",
                    json!({"name": "Summarizer", "description": "Summarizes spaces."}),
                ));
                let definition_id = created["result"]["definition_id"].as_str().unwrap();
                mutation(
                    "assistant_revision_register",
                    None,
                    "idem-matrix-asstrev",
                    revision_register_args(definition_id, "v1"),
                )
            },
            |daemon| list_count(daemon, "assistant_revision_list", json!({"limit": 512})),
        );
        realm_cell(
            "deployment-create",
            "deployment_create",
            phase,
            |_| {
                mutation(
                    "deployment_create",
                    None,
                    "idem-matrix-dep",
                    deployment_create_args("asstrev-local-dev"),
                )
            },
            |daemon| list_count(daemon, "deployment_list", json!({"limit": 512})),
        );
        realm_cell(
            "deployment-activate",
            "deployment_activate",
            phase,
            |daemon| {
                let dep = daemon.expect_ok(&mutation(
                    "deployment_create",
                    None,
                    "idem-dep-setup",
                    deployment_create_args("asstrev-local-dev"),
                ));
                mutation(
                    "deployment_activate",
                    None,
                    "idem-matrix-dep-act",
                    json!({"assistant_deployment_id": dep["result"]["assistant_deployment_id"]}),
                )
            },
            // The bootstrap deployment is already active: count actives.
            |daemon| {
                let page =
                    daemon.expect_ok(&read_cmd("deployment_list", None, json!({"limit": 512})));
                page["result"]["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|d| d["status"].as_str() == Some("active"))
                    .count()
            },
        );
        realm_cell(
            "deployment-drain",
            "deployment_drain",
            phase,
            |daemon| {
                let dep = daemon.expect_ok(&mutation(
                    "deployment_create",
                    None,
                    "idem-dep-setup-drain",
                    deployment_create_args("asstrev-local-dev"),
                ));
                let id = dep["result"]["assistant_deployment_id"].clone();
                daemon.expect_ok(&mutation(
                    "deployment_activate",
                    None,
                    "idem-dep-act-drain",
                    json!({"assistant_deployment_id": id}),
                ));
                mutation(
                    "deployment_drain",
                    None,
                    "idem-matrix-dep-drain",
                    json!({"assistant_deployment_id": id}),
                )
            },
            |daemon| {
                let page =
                    daemon.expect_ok(&read_cmd("deployment_list", None, json!({"limit": 512})));
                page["result"]["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|d| d["status"].as_str() == Some("drained"))
                    .count()
            },
        );
    }
}

fn revision_register_args(definition_id: &str, version: &str) -> Value {
    json!({
        "definition_id": definition_id,
        "version": version,
        "manifest": {
            "schema_version": "kovee-manifest-v1",
            "definition_id": definition_id,
            "version": version,
            "entrypoint": "main.py",
            "package_digest": "1c".repeat(32),
            "runtime": {"python": "3.12"},
            "supported_worker_protocols": ["kcp-worker-0.1"],
            "input_schema_ref": "schema:any-v1",
            "output_schema_ref": "schema:any-v1",
            "skills": ["summarize"],
            "attention_proposals": [],
            "requested_capabilities": [],
            "model_profiles": [],
            "tool_profiles": [],
            "network_policy": {},
            "resource_limits": {"cpu": 1, "memory": 256, "disk": 64, "output_bytes": 65536},
            "default_timeout": 60,
            "max_concurrency": 1,
            "causal_concurrency_policy": "serial-branch",
            "checkpoint_support": false,
            "cancellation_support": true,
            "security_profiles": ["developer"],
        },
        "package_artifact_ref": "artifact-pkg-1",
        "package_digest": "1c".repeat(32),
        "config_schema_digest": "2d".repeat(32),
        "sdk_protocol_range": "kcp-worker-0.1",
    })
}

fn deployment_create_args(revision_id: &str) -> Value {
    json!({
        "assistant_revision_id": revision_id,
        "config_ref": "cfg-1",
        "config_digest": "3e".repeat(32),
        "secret_binding_set_ref": "secrets-none",
        "secret_binding_set_digest": "4f".repeat(32),
        "policy_ref": "policy-default",
        "pool_ref": "pool-local",
        "security_profile": "developer",
        "concurrency_policy": "serial-branch",
        "rollout_policy": {},
    })
}

#[test]
fn application_event_emit_matrix() {
    // Worker-surface cell: claim the attempt, then arm the emit.
    for phase in ["before_commit", "after_commit"] {
        let base = tmp(&format!("k1-matrix-app-emit-{phase}"));
        let data = base.join("data");
        let run = base.join("run");
        let healthy = DaemonProc::start(&data, &run, None);
        let (project, space, _, _) = setup_space(&healthy);
        let invocation = healthy.expect_ok(&mutation(
            "invocation_create",
            Some(&project),
            "idem-inv-emit",
            json!({
                "assistant_deployment_id": "dep-local-dev",
                "assistant_deployment_revision": 1,
                "space_id": space,
                "deadline": "2027-01-01T00:00:00Z",
            }),
        ));
        let claimed = healthy.worker_expect_ok(&mutation(
            "invocation_claim",
            None,
            "idem-claim-emit",
            json!({"invocation_id": invocation["result"]["invocation_id"]}),
        ));
        let target = mutation(
            "application_event_emit",
            Some(&project),
            "idem-matrix-emit",
            json!({
                "attempt_id": claimed["result"]["attempt_id"],
                "fence_epoch": claimed["result"]["fence_epoch"],
                "type": "com.example.summary.ready.v1",
                "payload": {"note": "crash me"},
            }),
        );
        let committed_before = count_events(&healthy, &project, "com.example.summary.ready.v1");
        drop(healthy);

        let armed = DaemonProc::start(
            &data,
            &run,
            Some(&format!("{phase}:application_event_emit")),
        );
        assert!(
            armed
                .request_raw_at(&armed.worker_socket(), &target)
                .is_none(),
            "{phase}: the armed daemon must die before replying"
        );
        armed.wait_dead();

        let recovered = DaemonProc::start(&data, &run, None);
        let committed_after = count_events(&recovered, &project, "com.example.summary.ready.v1");
        match phase {
            "before_commit" => assert_eq!(committed_after, committed_before),
            "after_commit" => assert_eq!(committed_after, committed_before + 1),
            other => panic!("unknown phase {other}"),
        }
        assert_dense(&recovered, &project);
        let raw_first = recovered
            .request_raw_at(&recovered.worker_socket(), &target)
            .unwrap();
        let first: Value = serde_json::from_str(&raw_first).unwrap();
        assert_eq!(first["outcome"].as_str(), Some("ok"), "{phase}: {first}");
        assert_eq!(
            count_events(&recovered, &project, "com.example.summary.ready.v1"),
            committed_before + 1
        );
        let raw_second = recovered
            .request_raw_at(&recovered.worker_socket(), &target)
            .unwrap();
        assert_eq!(raw_first, raw_second, "{phase}: replay is byte-identical");
        assert_dense(&recovered, &project);
    }
}

// ------------------------------------------------- staging cleanup (KV-C1) ----

/// KV-C1: a crash between the artifact-finalize commit and its staging
/// tidy-up used to leave the plaintext in BOTH the sealed store and
/// staging, forever — exact replay returned before the cleanup and no
/// sweeper existed. The startup mark-and-sweep and the replay-path
/// cleanup both have to remove it.
#[test]
fn a_crash_before_staging_cleanup_leaves_no_plaintext_staging_copy() {
    let base = tmp("k1-matrix-staging-sweep");
    let data = base.join("data");
    let run = base.join("run");
    let plaintext = b"staging plaintext: the second copy that must not survive";

    let healthy = DaemonProc::start(&data, &run, None);
    let (upload_id, artifact_id, finalize) = artifact_setup(&healthy, plaintext);
    let staging = data
        .join("artifacts")
        .join("staging")
        .join(upload_id.clone());
    assert!(staging.exists(), "the staging copy exists before finalize");
    drop(healthy);

    // Die after the finalize commit, before the tidy-up.
    let armed = DaemonProc::start(&data, &run, Some("after_commit:artifact_upload_finalize"));
    assert!(armed.request_raw(&finalize).is_none());
    armed.wait_dead();
    assert!(
        staging.exists(),
        "the crash must genuinely leave the staging copy behind"
    );
    assert!(
        std::fs::read(&staging).unwrap() == plaintext,
        "…and it is the plaintext"
    );

    // Restart: the startup mark-and-sweep removes it against a fresh
    // database reference check (the upload is `completed`).
    let recovered = DaemonProc::start(&data, &run, None);
    assert_eq!(artifact_state(&recovered, &artifact_id), "available");
    assert!(
        !staging.exists(),
        "the startup sweep must remove the orphaned staging blob"
    );

    // The replay still answers, and cleanup is part of the replay too: a
    // staging copy that reappears after the commit (a slow provider
    // write, a partially-run retry) is removed by the next replay rather
    // than waiting for the next restart.
    std::fs::write(&staging, plaintext).unwrap();
    let raw_first = recovered.request_raw(&finalize).unwrap();
    assert!(
        !staging.exists(),
        "the finalize replay must clean staging idempotently"
    );
    let raw_second = recovered.request_raw(&finalize).unwrap();
    assert_eq!(raw_first, raw_second, "replay stays byte-identical");

    // A staging blob whose upload row never existed is swept as well.
    let orphan = data.join("artifacts").join("staging").join("upl-ghost");
    std::fs::write(&orphan, plaintext).unwrap();
    drop(recovered);
    let restarted = DaemonProc::start(&data, &run, None);
    assert!(
        !orphan.exists(),
        "an unreferenced staging blob is swept at startup"
    );
    drop(restarted);
}
