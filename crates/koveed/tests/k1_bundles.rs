//! K1 bundle completeness (§11.6: bundles are atomic). Three proofs:
//!
//! 1. `hello`/`protocol_info` advertise exactly the three K1 bundles —
//!    and may do so only because
//! 2. EVERY `spec/registry.json` entry has a live dispatch arm on its
//!    surface (external_client + operator → the client socket, owner
//!    principal per registry-README resolutions 5/6; worker → the worker
//!    socket): probed per entry, the daemon never answers `unknown-op`.
//! 3. The slice-3 operations behave: lifecycle transitions, prepared
//!    widening, participants, grants, lenses, reactions, dispositions
//!    with A5 erasure-safe redaction, the assistant registry pipeline,
//!    and the worker `application_event_emit` / `invocation_cancel`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{json, Value};

const BUNDLES: [&str; 3] = ["core_v1", "shared_space_v1", "developer_assistant_v1"];

fn hello_cmd() -> Value {
    json!({
        "version": "0.1",
        "op": "hello",
        "args": {
            "supported_versions": ["0.1"],
            "implementation": "k1-bundles-test",
            "implementation_version": "0.0.1",
            "requested_features": [],
        },
    })
}

#[test]
fn hello_and_protocol_info_advertise_the_three_complete_bundles() {
    let base = tmp("k1-bundles-hello");
    let daemon = DaemonProc::start(&base.join("data"), &base.join("run"), None);
    let hello = daemon.expect_ok(&hello_cmd());
    assert_eq!(hello["result"]["features"], json!(BUNDLES));
    let info = daemon.expect_ok(&json!({
        "version": "0.1", "op": "protocol_info", "args": {},
    }));
    assert_eq!(info["result"]["features"], json!(BUNDLES));
    assert_eq!(info["result"]["supported_versions"], json!(["0.1"]));
    assert!(info["result"].get("selected_version").is_none());
}

#[test]
fn the_incomplete_k2_bundle_is_not_advertised_but_its_operations_dispatch() {
    // §11.6: bundles are atomic — every operation of a LISTED bundle
    // dispatches, or the bundle is not listed. After K2 slice 2 the
    // `governed_work_binding_v1` binding AND formation halves are live
    // (nine operations), but `collaboration_context_bundle_*` and
    // `workspace_*` are still unbuilt, so the bundle must not appear in
    // `hello`/`protocol_info`.
    let base = tmp("k1-bundles-k2-honesty");
    let daemon = DaemonProc::start(&base.join("data"), &base.join("run"), None);
    let hello = daemon.expect_ok(&hello_cmd());
    let features = hello["result"]["features"].as_array().unwrap();
    assert!(
        !features.iter().any(|f| f == "governed_work_binding_v1"),
        "an incomplete bundle must not be advertised: {features:?}"
    );
    // Live all the same: a shape-valid read reaches its handler.
    let show = daemon.expect_ok(&read_cmd("governance_show", None, json!({})));
    assert_eq!(show["result"]["governance_owner"], json!("none"));
    assert_eq!(
        show["result"]["compatibility_bundle"],
        json!("byom_governed_work_v1")
    );
    // The slice-2 names ARE callable now — a shape-valid read reaches its
    // handler and answers the recorded (empty) state.
    let promotions = daemon.expect_ok(&read_cmd("endeavor_promotion_show", None, json!({})));
    assert_eq!(promotions["result"]["promotions"], json!([]));
    let bindings = daemon.expect_ok(&read_cmd("byom_episode_binding_show", None, json!({})));
    assert_eq!(bindings["result"]["bindings"], json!([]));
    // And the names still reserved for the bundle's unbuilt half are not.
    for op in [
        "collaboration_context_bundle_prepare",
        "workspace_allocation_binding_show",
    ] {
        daemon.expect_problem(&read_cmd(op, None, json!({})), "unknown-op");
    }
}

#[test]
fn every_registry_entry_has_a_dispatch_arm_on_its_surface() {
    // The ops.rs↔registry parity of names is proven in kovee-core
    // (`ops_table_matches_the_frozen_registry_exactly`); this test closes
    // the loop per (operation, surface) ENTRY: a syntactically minimal
    // command for each entry must reach past dispatch — any answer but
    // `unknown-op`/`unsupported-version` proves the arm exists.
    let registry_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("spec")
        .join("registry.json");
    let registry: Value =
        serde_json::from_str(&std::fs::read_to_string(registry_path).unwrap()).unwrap();
    let entries = registry["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        100,
        "the frozen registry holds 90 K1 entries, the 3 K2 slice-1 binding ones, the 6 slice-2 \
         formation/episode-binding ones, and the model broker's `model_complete` worker row"
    );

    let base = tmp("k1-bundles-parity");
    let daemon = DaemonProc::start(&base.join("data"), &base.join("run"), None);
    for (i, entry) in entries.iter().enumerate() {
        let op = entry["operation"].as_str().unwrap();
        let surface = entry["surface"].as_str().unwrap();
        let spec = kovee_core::ops::op_spec(op)
            .unwrap_or_else(|| panic!("registry op {op} missing from the ops table"));

        // Build the minimal envelope the op's schema shape requires.
        let mut cmd = serde_json::Map::new();
        cmd.insert("version".into(), json!("0.1"));
        cmd.insert("op".into(), json!(op));
        use kovee_core::ops::FieldRule;
        if spec.realm_id != FieldRule::Forbidden {
            cmd.insert("realm_id".into(), json!("realm-personal"));
        }
        if spec.project_id == FieldRule::Required {
            cmd.insert("project_id".into(), json!("proj-absent"));
        }
        if spec.kind == kovee_core::ops::OpKind::Mutation {
            cmd.insert(
                "meta".into(),
                json!({
                    "request_id": format!("req-parity-{i}"),
                    "idempotency_key": format!("idem-parity-{i}"),
                }),
            );
        }
        cmd.insert("args".into(), json!({}));
        let cmd = Value::Object(cmd);

        let reply = match surface {
            "worker" => daemon.worker_request(&cmd),
            // Operator entries bind to the owner principal on the client
            // socket in the personal profile (README resolutions 5/6).
            _ => daemon.request(&cmd),
        };
        if reply["outcome"].as_str() == Some("problem") {
            let kind = reply["problem"]["type"].as_str().unwrap();
            assert!(
                kind != "urn:kovee:error:unknown-op"
                    && kind != "urn:kovee:error:unsupported-version",
                "({op}, {surface}) has no dispatch arm: {reply}"
            );
        }
    }

    // And the converse stays closed: the worker-only operation is not
    // callable on the external surface, nor an unregistered name anywhere.
    let emit = mutation(
        "application_event_emit",
        Some("proj-x"),
        "idem-conv-1",
        json!({}),
    );
    daemon.expect_problem(&emit, "unknown-op");
    let bogus = read_cmd("space_dissolve", None, json!({}));
    daemon.expect_problem(&bogus, "unknown-op");
    let worker_bogus = read_cmd("space_list", Some("proj-x"), json!({"limit": 1}));
    let reply = daemon.worker_request(&worker_bogus);
    assert_eq!(
        reply["problem"]["type"].as_str(),
        Some("urn:kovee:error:unknown-op"),
        "a worker never enumerates the client surface"
    );
}

#[test]
fn lifecycle_participants_grants_lenses_and_reactions_flow() {
    let base = tmp("k1-bundles-lifecycle");
    let daemon = DaemonProc::start(&base.join("data"), &base.join("run"), None);
    let (project, space, branch, head) = setup_space(&daemon);

    // Project metadata + policy-change prepare/confirm.
    let renamed = daemon.expect_ok(&mutation(
        "project_update_metadata",
        Some(&project),
        "idem-pupd",
        json!({"name": "renamed"}),
    ));
    assert_eq!(renamed["result"]["name"].as_str(), Some("renamed"));
    let papc = daemon.expect_ok(&mutation(
        "project_access_policy_change_prepare",
        Some(&project),
        "idem-papc",
        json!({"proposed_policy_set_ref": "policy-tighter"}),
    ));
    assert_eq!(papc["result"]["state"].as_str(), Some("prepared"));
    assert_eq!(
        papc["result"]["effective_change"].as_str(),
        Some("incomparable")
    );
    let change_id = papc["result"]["change_id"].as_str().unwrap().to_owned();
    let confirmed = daemon.expect_ok(&mutation(
        "project_access_policy_change_confirm",
        Some(&project),
        "idem-papc-conf",
        json!({"change_id": change_id, "decision_receipt_ref": "receipt-1"}),
    ));
    assert_eq!(confirmed["result"]["state"].as_str(), Some("confirmed"));
    let shown = daemon.expect_ok(&read_cmd("project_show", Some(&project), json!({})));
    assert_eq!(
        shown["result"]["policy_set_ref"].as_str(),
        Some("policy-tighter")
    );
    let listed = daemon.expect_ok(&read_cmd(
        "project_access_policy_change_list",
        Some(&project),
        json!({"limit": 10}),
    ));
    assert_eq!(listed["result"]["items"].as_array().unwrap().len(), 1);

    // Space lifecycle: freeze blocks appends; reopen unblocks.
    daemon.expect_ok(&mutation(
        "space_freeze",
        Some(&project),
        "idem-freeze",
        json!({"space_id": space}),
    ));
    let blocked = mutation(
        "contribution_append",
        Some(&project),
        "idem-blocked",
        json!({
            "space_id": space, "branch_id": branch,
            "expected_head_digest": head, "kind": "utterance",
            "body_parts": [{"media_type": "text/plain", "text": "nope"}],
        }),
    );
    daemon.expect_problem(&blocked, "stale-revision");
    daemon.expect_ok(&mutation(
        "space_reopen",
        Some(&project),
        "idem-reopen",
        json!({"space_id": space}),
    ));
    let (c_id, c_digest, _) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-c1",
        "claim",
        "hello",
        json!({}),
    );

    // Prepared widening round-trip (restricted → project).
    daemon.expect_ok(&mutation(
        "space_restrict",
        Some(&project),
        "idem-restrict",
        json!({"space_id": space}),
    ));
    let widening = daemon.expect_ok(&mutation(
        "space_access_widen_prepare",
        Some(&project),
        "idem-widen",
        json!({"space_id": space, "proposed_visibility": "project"}),
    ));
    let widening_id = widening["result"]["widening_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let confirmed = daemon.expect_ok(&mutation(
        "space_access_widen_confirm",
        Some(&project),
        "idem-widen-conf",
        json!({"widening_id": widening_id, "decision_receipt_ref": "receipt-2"}),
    ));
    assert_eq!(confirmed["result"]["state"].as_str(), Some("confirmed"));
    let space_now = daemon.expect_ok(&read_cmd(
        "space_show",
        Some(&project),
        json!({"space_id": space}),
    ));
    assert_eq!(space_now["result"]["visibility"].as_str(), Some("project"));
    // A second confirm of the same intent: no longer prepared.
    daemon.expect_problem(
        &mutation(
            "space_access_widen_confirm",
            Some(&project),
            "idem-widen-conf2",
            json!({"widening_id": confirmed["result"]["widening_id"], "decision_receipt_ref": "receipt-3"}),
        ),
        "stale-revision",
    );

    // Participants: add → activate (exact subject digest) → update → remove.
    let added = daemon.expect_ok(&mutation(
        "space_participant_add",
        Some(&project),
        "idem-part",
        json!({
            "space_id": space, "subject_ref": "prin-guest",
            "kind": "principal", "role": "observer",
        }),
    ));
    assert_eq!(added["result"]["status"].as_str(), Some("proposed"));
    let participant_id = added["result"]["participant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // A wrong digest fails the exact-subject match.
    daemon.expect_problem(
        &mutation(
            "space_participant_activate",
            Some(&project),
            "idem-part-act-bad",
            json!({"participant_id": participant_id, "subject_digest": "0".repeat(64)}),
        ),
        "stale-revision",
    );
    let digest = kovee_core::canonical::canonical_object_digest(
        "kovee-participant-subject",
        "schema:space-participant-v1",
        &json!({
            "participant_id": added["result"]["participant_id"],
            "space_id": added["result"]["space_id"],
            "subject_ref": added["result"]["subject_ref"],
            "kind": added["result"]["kind"],
            "role": added["result"]["role"],
        }),
    )
    .unwrap()
    .1;
    let active = daemon.expect_ok(&mutation(
        "space_participant_activate",
        Some(&project),
        "idem-part-act",
        json!({"participant_id": participant_id, "subject_digest": digest}),
    ));
    assert_eq!(active["result"]["status"].as_str(), Some("active"));
    let updated = daemon.expect_ok(&mutation(
        "space_participant_update",
        Some(&project),
        "idem-part-upd",
        json!({"participant_id": participant_id, "role": "contributor", "status": "muted"}),
    ));
    assert_eq!(updated["result"]["role"].as_str(), Some("contributor"));
    assert_eq!(updated["result"]["status"].as_str(), Some("muted"));
    let participants = daemon.expect_ok(&read_cmd(
        "space_participant_list",
        Some(&project),
        json!({"space_id": space, "limit": 10}),
    ));
    // Owner steward + guest.
    assert_eq!(participants["result"]["items"].as_array().unwrap().len(), 2);
    let removed = daemon.expect_ok(&mutation(
        "space_participant_remove",
        Some(&project),
        "idem-part-rm",
        json!({"participant_id": participant_id}),
    ));
    assert_eq!(removed["result"]["status"].as_str(), Some("revoked"));

    // Grants (owner-bound operator family).
    let grant = daemon.expect_ok(&mutation(
        "space_access_grant_create",
        Some(&project),
        "idem-grant",
        json!({
            "space_id": space, "subject_ref": "prin-guest",
            "allowed_actions": ["contribution_read", "reaction_set"],
        }),
    ));
    assert_eq!(grant["result"]["status"].as_str(), Some("active"));
    let grants = daemon.expect_ok(&read_cmd(
        "space_access_grant_list",
        Some(&project),
        json!({"space_id": space, "limit": 10}),
    ));
    assert_eq!(grants["result"]["items"].as_array().unwrap().len(), 1);
    let revoked = daemon.expect_ok(&mutation(
        "space_access_grant_revoke",
        Some(&project),
        "idem-grant-rev",
        json!({"space_access_id": grant["result"]["space_access_id"]}),
    ));
    assert_eq!(revoked["result"]["status"].as_str(), Some("revoked"));

    // Lens CRUD + read of a custom lens.
    let lens = daemon.expect_ok(&mutation(
        "lens_create",
        Some(&project),
        "idem-lens",
        json!({
            "space_id": space, "kind": "custom",
            "query_ast": {"select": "contributions"},
            "sort_spec": {"order_by": "branch_sequence"},
            "presentation_options": {"render": "compact"},
            "visibility": "project",
        }),
    ));
    let lens_id = lens["result"]["lens_id"].as_str().unwrap().to_owned();
    let shown = daemon.expect_ok(&read_cmd(
        "lens_show",
        Some(&project),
        json!({"lens_id": lens_id}),
    ));
    assert_eq!(shown["result"]["kind"].as_str(), Some("custom"));
    let lens_page = daemon.expect_ok(&read_cmd(
        "lens_read",
        Some(&project),
        json!({"lens_id": lens_id, "limit": 10}),
    ));
    assert!(!lens_page["result"]["items"].as_array().unwrap().is_empty());
    daemon.expect_ok(&mutation(
        "lens_update",
        Some(&project),
        "idem-lens-upd",
        json!({"lens_id": lens_id, "visibility": "private"}),
    ));
    daemon.expect_ok(&mutation(
        "lens_revoke",
        Some(&project),
        "idem-lens-rev",
        json!({"lens_id": lens_id}),
    ));
    daemon.expect_problem(
        &read_cmd("lens_show", Some(&project), json!({"lens_id": lens_id})),
        "not-found",
    );
    let lenses = daemon.expect_ok(&read_cmd(
        "lens_list",
        Some(&project),
        json!({"space_id": space, "limit": 10}),
    ));
    // The two built-ins remain.
    assert_eq!(lenses["result"]["items"].as_array().unwrap().len(), 2);

    // Reactions: exact target pin, upsert semantics.
    daemon.expect_problem(
        &mutation(
            "reaction_set",
            Some(&project),
            "idem-react-stale",
            json!({
                "space_id": space, "target_ref": c_id, "target_revision": 1,
                "target_digest": "0".repeat(64), "key": "insightful",
                "state": "present",
            }),
        ),
        "stale-revision",
    );
    let reaction = daemon.expect_ok(&mutation(
        "reaction_set",
        Some(&project),
        "idem-react",
        json!({
            "space_id": space, "target_ref": c_id, "target_revision": 1,
            "target_digest": c_digest, "key": "insightful", "state": "present",
        }),
    ));
    assert_eq!(reaction["result"]["state"].as_str(), Some("present"));
    let toggled = daemon.expect_ok(&mutation(
        "reaction_set",
        Some(&project),
        "idem-react-2",
        json!({
            "space_id": space, "target_ref": c_id, "target_revision": 1,
            "target_digest": c_digest, "key": "insightful", "state": "removed",
        }),
    ));
    assert_eq!(toggled["result"]["state"].as_str(), Some("removed"));
    assert_eq!(
        toggled["result"]["reaction_id"], reaction["result"]["reaction_id"],
        "the upsert keeps one row per (target, actor, key)"
    );

    // snapshot_read over the project's space collection + event_payload.
    let snapshot = daemon.expect_ok(&read_cmd(
        "snapshot_read",
        None,
        json!({"source": project, "limit": 10}),
    ));
    assert_eq!(snapshot["result"]["items"].as_array().unwrap().len(), 1);
    assert!(snapshot["result"]["snapshot"].is_string());
    let events = daemon.expect_ok(&events_read(&project));
    let event_id = events["result"]["events"][0]["event_id"].as_str().unwrap();
    let payload = daemon.expect_ok(&read_cmd(
        "event_payload",
        None,
        json!({"event_id": event_id}),
    ));
    assert_eq!(payload["result"]["event_id"].as_str(), Some(event_id));
    assert!(payload["result"]["payload"].is_object());

    // disclosure_manifest_show: dispatched, empty collection in K1.
    daemon.expect_problem(
        &read_cmd(
            "disclosure_manifest_show",
            None,
            json!({"disclosure_id": "disc-absent"}),
        ),
        "not-found",
    );

    // diagnose (owner-bound operator read).
    let diagnosis = daemon.expect_ok(&read_cmd("diagnose", None, json!({})));
    assert_eq!(diagnosis["result"]["status"].as_str(), Some("pass"));
    daemon.expect_problem(
        &read_cmd("diagnose", None, json!({"checks": ["exfiltrate"]})),
        "invalid",
    );

    // Archive is terminal for admin mutations.
    daemon.expect_ok(&mutation(
        "space_archive",
        Some(&project),
        "idem-archive",
        json!({"space_id": space}),
    ));
    daemon.expect_problem(
        &mutation(
            "space_update_metadata",
            Some(&project),
            "idem-post-archive",
            json!({"space_id": space, "title": "late"}),
        ),
        "stale-revision",
    );
}

#[test]
fn dispositions_and_erasure_safe_redaction() {
    let base = tmp("k1-bundles-dispositions");
    let daemon = DaemonProc::start(&base.join("data"), &base.join("run"), None);
    let (project, space, branch, head) = setup_space(&daemon);
    let secret_text = "the launch code is 0000";
    let (old_id, old_digest, head) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-old",
        "claim",
        secret_text,
        json!({}),
    );
    let (new_id, _, head) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-new",
        "claim",
        "revised claim",
        json!({}),
    );

    // withdraw + supersede: append-only dispositions, content retained.
    let withdrawn = daemon.expect_ok(&mutation(
        "contribution_withdraw",
        Some(&project),
        "idem-withdraw",
        json!({"contribution_ref": old_id, "reason_class": "obsolete"}),
    ));
    assert_eq!(withdrawn["result"]["kind"].as_str(), Some("withdraw"));
    assert!(withdrawn["result"].get("payload_removed_at").is_none());
    daemon.expect_problem(
        &mutation(
            "contribution_withdraw",
            Some(&project),
            "idem-withdraw-2",
            json!({"contribution_ref": old_id, "reason_class": "obsolete"}),
        ),
        "invalid",
    );
    let superseded = daemon.expect_ok(&mutation(
        "contribution_supersede",
        Some(&project),
        "idem-supersede",
        json!({
            "contribution_ref": old_id, "replacement_ref": new_id,
            "reason_class": "revised",
        }),
    ));
    assert_eq!(
        superseded["result"]["replacement_ref"].as_str(),
        Some(new_id.as_str())
    );
    let still_there = daemon.expect_ok(&read_cmd(
        "contribution_show",
        Some(&project),
        json!({"contribution_id": old_id}),
    ));
    assert_eq!(
        still_there["result"]["body_parts"][0]["text"].as_str(),
        Some(secret_text),
        "withdraw/supersede never remove content"
    );

    // A5 redaction: content removed, typed local_erasure_safe digest
    // retained, disposition + event recorded.
    let redacted = daemon.expect_ok(&mutation(
        "contribution_redact",
        Some(&project),
        "idem-redact",
        json!({"contribution_ref": old_id, "reason_class": "policy_erasure"}),
    ));
    assert_eq!(redacted["result"]["kind"].as_str(), Some("redact"));
    assert!(redacted["result"]["payload_removed_at"].is_string());

    let after = daemon.expect_ok(&read_cmd(
        "contribution_show",
        Some(&project),
        json!({"contribution_id": old_id}),
    ));
    let body = &after["result"]["body_parts"];
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(
        body[0]["media_type"].as_str(),
        Some("application/x.kovee.redacted")
    );
    assert_eq!(body[0]["text"].as_str(), Some(""));
    let new_digest = after["result"]["content_digest"].as_str().unwrap();
    // KV-A5-1 / D-R1-2: the digest was `local_erasure_safe` from the
    // FIRST append, so redaction does not have to move it — there was
    // never a plaintext-derived value for a retained copy to hold.
    assert_eq!(
        new_digest, old_digest,
        "a keyed content digest survives redaction unchanged"
    );
    assert_eq!(new_digest.len(), 64, "the keyed digest value is 64 hex");

    // The retained ledger no longer carries the plaintext anywhere: the
    // appended event's payload was re-projected under the keyed digest.
    let events = daemon.expect_ok(&events_read(&project));
    let text = serde_json::to_string(&events).unwrap();
    assert!(
        !text.contains(secret_text),
        "no event payload may retain redacted plaintext"
    );
    // The keyed digest is still there (it is not plaintext-derived) and
    // still names the same object.
    assert!(
        text.contains(&old_digest),
        "the keyed digest stays: it is the object's stable content address"
    );
    // Dense sequences preserved through the disposition flow.
    for (i, event) in events["result"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(event["project_sequence"].as_u64(), Some(i as u64 + 1));
    }

    // A second redaction fails; the disposition trail records history.
    daemon.expect_problem(
        &mutation(
            "contribution_redact",
            Some(&project),
            "idem-redact-2",
            json!({"contribution_ref": old_id, "reason_class": "policy_erasure"}),
        ),
        "invalid",
    );

    // Relation retraction (assert on fresh contributions, then retract).
    // Note the branch head is untouched by redaction: the fold already
    // happened, so appends continue from the last returned head.
    let (a_id, a_digest, head) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-ra",
        "claim",
        "a",
        json!({}),
    );
    let (b_id, b_digest, head) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-rb",
        "critique",
        "b",
        json!({}),
    );
    let relation = daemon.expect_ok(&mutation(
        "relation_assert",
        Some(&project),
        "idem-rel",
        json!({
            "space_id": space, "branch_id": branch,
            "expected_head_digest": head,
            "kind": "challenges",
            "from_ref": {"object_ref": b_id, "revision": 1, "digest": b_digest},
            "to_ref": {"object_ref": a_id, "revision": 1, "digest": a_digest},
        }),
    ));
    let retracted = daemon.expect_ok(&mutation(
        "relation_retract",
        Some(&project),
        "idem-retract",
        json!({
            "relation_ref": relation["result"]["relation_id"],
            "reason_class": "withdrawn_claim",
        }),
    ));
    assert_eq!(retracted["result"]["kind"].as_str(), Some("retract"));
    daemon.expect_problem(
        &mutation(
            "relation_retract",
            Some(&project),
            "idem-retract-2",
            json!({
                "relation_ref": relation["result"]["relation_id"],
                "reason_class": "withdrawn_claim",
            }),
        ),
        "invalid",
    );
}

#[test]
fn assistant_registry_pipeline_and_worker_surface() {
    let base = tmp("k1-bundles-assistants");
    let daemon = DaemonProc::start(&base.join("data"), &base.join("run"), None);
    let (project, space, branch, head) = setup_space(&daemon);

    // Definition → revision (deterministic manifest checks) → deployment.
    let definition = daemon.expect_ok(&mutation(
        "assistant_create",
        None,
        "idem-asst",
        json!({"name": "Summarizer", "description": "Summarizes a space."}),
    ));
    let definition_id = definition["result"]["definition_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let manifest = |version: &str| {
        json!({
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
        })
    };
    // A manifest binding a different version fails deterministically.
    daemon.expect_problem(
        &mutation(
            "assistant_revision_register",
            None,
            "idem-rev-bad",
            json!({
                "definition_id": definition_id, "version": "v2",
                "manifest": manifest("v1"),
                "package_artifact_ref": "artifact-pkg",
                "package_digest": "1c".repeat(32),
                "config_schema_digest": "2d".repeat(32),
                "sdk_protocol_range": "kcp-worker-0.1",
            }),
        ),
        "invalid",
    );
    let revision = daemon.expect_ok(&mutation(
        "assistant_revision_register",
        None,
        "idem-rev",
        json!({
            "definition_id": definition_id, "version": "v1",
            "manifest": manifest("v1"),
            "package_artifact_ref": "artifact-pkg",
            "package_digest": "1c".repeat(32),
            "config_schema_digest": "2d".repeat(32),
            "sdk_protocol_range": "kcp-worker-0.1",
        }),
    ));
    let revision_id = revision["result"]["assistant_revision_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Confinement honesty: a non-developer profile is refused.
    daemon.expect_problem(
        &mutation(
            "deployment_create",
            None,
            "idem-dep-confined",
            json!({
                "assistant_revision_id": revision_id,
                "config_ref": "cfg-1", "config_digest": "3e".repeat(32),
                "secret_binding_set_ref": "secrets-none",
                "secret_binding_set_digest": "4f".repeat(32),
                "policy_ref": "policy-default", "pool_ref": "pool-local",
                "security_profile": "confined",
                "concurrency_policy": "serial-branch",
                "rollout_policy": {},
            }),
        ),
        "forbidden",
    );
    let deployment = daemon.expect_ok(&mutation(
        "deployment_create",
        None,
        "idem-dep",
        json!({
            "assistant_revision_id": revision_id,
            "config_ref": "cfg-1", "config_digest": "3e".repeat(32),
            "secret_binding_set_ref": "secrets-none",
            "secret_binding_set_digest": "4f".repeat(32),
            "policy_ref": "policy-default", "pool_ref": "pool-local",
            "security_profile": "developer",
            "concurrency_policy": "serial-branch",
            "rollout_policy": {},
        }),
    ));
    let deployment_id = deployment["result"]["assistant_deployment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(deployment["result"]["status"].as_str(), Some("created"));
    // Invoking a non-active deployment fails; activate, then invoke.
    daemon.expect_problem(
        &mutation(
            "invocation_create",
            Some(&project),
            "idem-inv-early",
            json!({
                "assistant_deployment_id": deployment_id,
                "assistant_deployment_revision": 1,
                "deadline": "2027-01-01T00:00:00Z",
            }),
        ),
        "not-found",
    );
    let activated = daemon.expect_ok(&mutation(
        "deployment_activate",
        None,
        "idem-dep-act",
        json!({"assistant_deployment_id": deployment_id}),
    ));
    assert_eq!(activated["result"]["status"].as_str(), Some("active"));

    // Alias binding + mention resolution in a contribution.
    let alias = daemon.expect_ok(&mutation(
        "assistant_alias_bind",
        Some(&project),
        "idem-alias",
        json!({
            "display_alias": "  Summarizer   Bot ",
            "assistant_deployment_id": deployment_id,
            "deployment_revision": 2,
        }),
    ));
    assert_eq!(
        alias["result"]["normalized_alias"].as_str(),
        Some("summarizer bot"),
        "normalization is deterministic and server-side"
    );
    let alias_id = alias["result"]["alias_binding_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Duplicate normalized alias in the project is refused.
    daemon.expect_problem(
        &mutation(
            "assistant_alias_bind",
            Some(&project),
            "idem-alias-dup",
            json!({
                "display_alias": "SUMMARIZER BOT",
                "assistant_deployment_id": deployment_id,
                "deployment_revision": 2,
            }),
        ),
        "invalid",
    );
    // A mention resolves the exact alias revision — a stale pin fails.
    let mention_part = |revision: u64| {
        json!([{
            "target_kind": "assistant_alias", "target_ref": alias_id,
            "target_revision": revision, "display_text": "@Summarizer Bot",
        }])
    };
    daemon.expect_problem(
        &mutation(
            "contribution_append",
            Some(&project),
            "idem-mention-stale",
            json!({
                "space_id": space, "branch_id": branch,
                "expected_head_digest": head, "kind": "utterance",
                "body_parts": mention_part(7),
            }),
        ),
        "stale-revision",
    );
    daemon.expect_ok(&mutation(
        "contribution_append",
        Some(&project),
        "idem-mention",
        json!({
            "space_id": space, "branch_id": branch,
            "expected_head_digest": head, "kind": "utterance",
            "body_parts": mention_part(1),
        }),
    ));

    // Reads over the registry.
    let assistants = daemon.expect_ok(&read_cmd("assistant_list", None, json!({"limit": 10})));
    // asst-local-dev (bootstrap) + Summarizer.
    assert_eq!(assistants["result"]["items"].as_array().unwrap().len(), 2);
    let revisions = daemon.expect_ok(&read_cmd(
        "assistant_revision_list",
        None,
        json!({"limit": 10, "definition_id": definition_id}),
    ));
    assert_eq!(revisions["result"]["items"].as_array().unwrap().len(), 1);
    let deployments = daemon.expect_ok(&read_cmd(
        "deployment_list",
        None,
        json!({"limit": 10, "assistant_revision_id": revision_id}),
    ));
    assert_eq!(deployments["result"]["items"].as_array().unwrap().len(), 1);
    let aliases = daemon.expect_ok(&read_cmd(
        "assistant_alias_list",
        Some(&project),
        json!({"limit": 10}),
    ));
    assert_eq!(aliases["result"]["items"].as_array().unwrap().len(), 1);

    // Invocation list + cancel; canceled attempts fence worker writes.
    let invocation = daemon.expect_ok(&mutation(
        "invocation_create",
        Some(&project),
        "idem-inv",
        json!({
            "assistant_deployment_id": "dep-local-dev",
            "assistant_deployment_revision": 1,
            "space_id": space,
            "deadline": "2027-01-01T00:00:00Z",
        }),
    ));
    let invocation_id = invocation["result"]["invocation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let queued = daemon.expect_ok(&read_cmd(
        "invocation_list",
        Some(&project),
        json!({"limit": 10, "state": "queued"}),
    ));
    assert_eq!(queued["result"]["items"].as_array().unwrap().len(), 1);
    let claimed = daemon.worker_expect_ok(&mutation(
        "invocation_claim",
        None,
        "idem-claim",
        json!({"invocation_id": invocation_id}),
    ));
    let attempt_id = claimed["result"]["attempt_id"].as_str().unwrap().to_owned();
    let fence = claimed["result"]["fence_epoch"].as_u64().unwrap();

    // Worker application_event_emit: reserved namespace refused, a
    // registered type lands in the project ledger.
    daemon.worker_expect_problem(
        &mutation(
            "application_event_emit",
            Some(&project),
            "idem-emit-reserved",
            json!({
                "attempt_id": attempt_id, "fence_epoch": fence,
                "type": "dev.kovee.space.created.v1", "payload": {"forged": true},
            }),
        ),
        "forbidden",
    );
    let emitted = daemon.worker_expect_ok(&mutation(
        "application_event_emit",
        Some(&project),
        "idem-emit",
        json!({
            "attempt_id": attempt_id, "fence_epoch": fence,
            "type": "com.example.summary.ready.v1", "payload": {"note": "done"},
        }),
    ));
    assert!(emitted["result"]["event_id"].is_string());
    let events = daemon.expect_ok(&events_read(&project));
    assert!(events["result"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["type"].as_str() == Some("com.example.summary.ready.v1")));

    // Worker cancel: only an exact child invocation — none exists in K1.
    daemon.worker_expect_problem(
        &mutation(
            "invocation_cancel",
            Some(&project),
            "idem-worker-cancel",
            json!({
                "invocation_id": invocation_id,
                "attempt_id": attempt_id, "fence_epoch": fence,
            }),
        ),
        "not-found",
    );

    // External cancel wins the terminal race; the fenced attempt is out.
    let canceled = daemon.expect_ok(&mutation(
        "invocation_cancel",
        Some(&project),
        "idem-cancel",
        json!({"invocation_id": invocation_id, "reason": "operator stop"}),
    ));
    assert_eq!(canceled["result"]["state"].as_str(), Some("canceled"));
    daemon.expect_problem(
        &mutation(
            "invocation_cancel",
            Some(&project),
            "idem-cancel-2",
            json!({"invocation_id": invocation_id}),
        ),
        "stale-revision",
    );
    daemon.worker_expect_problem(
        &mutation(
            "application_event_emit",
            Some(&project),
            "idem-emit-late",
            json!({
                "attempt_id": attempt_id, "fence_epoch": fence,
                "type": "com.example.summary.late.v1", "payload": {},
            }),
        ),
        "stale-lease",
    );

    // Drain the deployment; a drained deployment cannot be re-drained.
    daemon.expect_ok(&mutation(
        "deployment_drain",
        None,
        "idem-drain",
        json!({"assistant_deployment_id": deployment_id}),
    ));
    daemon.expect_problem(
        &mutation(
            "deployment_drain",
            None,
            "idem-drain-2",
            json!({"assistant_deployment_id": deployment_id}),
        ),
        "invalid",
    );
}
