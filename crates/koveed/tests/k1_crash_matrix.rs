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
