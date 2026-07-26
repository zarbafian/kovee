//! KV-R1: the §11.2 replay reauthorizer.
//!
//! Exact replay used to return the stored bytes BEFORE any
//! operation-specific check ran, so a worker whose attempt had completed
//! — or whose fence had moved on — still collected its old receipt. Both
//! cases are proved here: the replay must fail with a typed problem, and
//! it must fail *without re-executing* (nothing new lands in the ledger).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{json, Value};

/// Sets up an invocation, claims it on the worker surface, and returns
/// `(project, invocation_id, attempt_id, fence, worker append command)`.
fn claimed_worker(
    daemon: &DaemonProc,
    project: &str,
    space: &str,
    branch: &str,
    head: &str,
) -> (String, String, u64, Value) {
    let invocation = daemon.expect_ok(&mutation(
        "invocation_create",
        Some(project),
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
    let claimed = daemon.worker_expect_ok(&mutation(
        "invocation_claim",
        None,
        "idem-claim",
        json!({"invocation_id": invocation_id}),
    ));
    let attempt_id = claimed["result"]["attempt_id"].as_str().unwrap().to_owned();
    let fence = claimed["result"]["fence_epoch"].as_u64().unwrap();
    let append = mutation(
        "contribution_append",
        Some(project),
        "idem-worker-append",
        json!({
            "space_id": space,
            "branch_id": branch,
            "expected_head_digest": head,
            "kind": "synthesis",
            "body_parts": [{"media_type": "text/plain", "text": "worker output"}],
            "attempt_id": attempt_id,
            "fence_epoch": fence,
        }),
    );
    (invocation_id, attempt_id, fence, append)
}

fn event_count(daemon: &DaemonProc, project: &str) -> usize {
    let events = daemon.expect_ok(&events_read(project));
    events["result"]["events"].as_array().unwrap().len()
}

/// One `application_event_emit` request for this attempt binding.
fn emit(project: &str, attempt_id: &str, fence: u64) -> Value {
    mutation(
        "application_event_emit",
        Some(project),
        "idem-worker-emit",
        json!({
            "attempt_id": attempt_id,
            "fence_epoch": fence,
            "type": "com.example.worker-note.v1",
            "payload": {"note": "progress"},
        }),
    )
}

/// KV-R1, re-probed exactly as the R1 confirmation probed it.
///
/// `application_event_emit` was the operation still on the unguarded
/// `command_transaction`, so an exact replay returned the stored bytes
/// before the attempt/fence check ever ran. Emit on a live attempt (ok,
/// and a live replay is still byte-identical), complete the attempt, then
/// present the identical request: it must come back as the stale problem,
/// not as the old receipt — and must re-execute nothing.
#[test]
fn an_application_event_replay_is_refused_after_the_attempt_completes() {
    let base = tmp("k1-replay-auth-app-event");
    let daemon = DaemonProc::start(&base.join("data"), &base.join("run"), None);
    let (project, space, branch, head) = setup_space(&daemon);
    let (invocation_id, attempt_id, fence, _append) =
        claimed_worker(&daemon, &project, &space, &branch, &head);

    let emit = emit(&project, &attempt_id, fence);
    let first = daemon.worker_expect_ok(&emit);
    let event_id = first["result"]["event_id"].as_str().unwrap().to_owned();
    // While the attempt is live the exact replay still returns the exact
    // stored bytes — the property the authorizer must not break.
    let replay = daemon.worker_expect_ok(&emit);
    assert_eq!(
        first, replay,
        "a live attempt still replays byte-identically"
    );
    let after_replay = event_count(&daemon, &project);

    // The attempt completes.
    daemon.worker_expect_ok(&mutation(
        "invocation_complete",
        Some(&project),
        "idem-complete",
        json!({
            "invocation_id": invocation_id,
            "attempt_id": attempt_id,
            "fence_epoch": fence,
        }),
    ));

    // The identical emit request now: a typed problem, no receipt.
    let refused = daemon.worker_expect_problem(&emit, "stale-lease");
    assert!(
        refused.get("result").is_none(),
        "a refused replay must carry no receipt: {refused}"
    );
    assert!(
        !serde_json::to_string(&refused).unwrap().contains(&event_id),
        "the refused replay leaked the old receipt: {refused}"
    );
    assert_eq!(
        event_count(&daemon, &project),
        after_replay + 1,
        "only the completion event was added; the refused replay executed nothing"
    );
}

/// The same probe against an advanced fence rather than a completed
/// attempt: the attempt is still `running`, so the fence is unambiguously
/// what refuses the replay.
#[test]
fn an_application_event_replay_is_refused_by_an_advanced_fence() {
    let base = tmp("k1-replay-auth-app-event-fence");
    let data = base.join("data");
    let run = base.join("run");
    let daemon = DaemonProc::start(&data, &run, None);
    let (project, space, branch, head) = setup_space(&daemon);
    let (_invocation_id, attempt_id, fence, _append) =
        claimed_worker(&daemon, &project, &space, &branch, &head);

    let emit = emit(&project, &attempt_id, fence);
    daemon.worker_expect_ok(&emit);
    let before = event_count(&daemon, &project);
    drop(daemon);

    // The supervisor fences the attempt out (K1 has no operation that
    // advances a fence, so the epoch moves directly on the durable row).
    {
        let conn = rusqlite::Connection::open(data.join("kovee.db")).unwrap();
        let changed = conn
            .execute(
                "UPDATE invocation_attempts SET fence_epoch = fence_epoch + 1
                 WHERE attempt_id = ?1 AND state = 'running'",
                [&attempt_id],
            )
            .unwrap();
        assert_eq!(changed, 1, "the attempt must still be running");
    }

    let daemon = DaemonProc::start(&data, &run, None);
    daemon.worker_expect_problem(&emit, "stale-lease");
    assert_eq!(
        event_count(&daemon, &project),
        before,
        "the refused replay executed nothing"
    );
}

#[test]
fn a_completed_attempt_is_refused_its_old_receipt() {
    let base = tmp("k1-replay-auth-completed");
    let daemon = DaemonProc::start(&base.join("data"), &base.join("run"), None);
    let (project, space, branch, head) = setup_space(&daemon);
    let (invocation_id, attempt_id, fence, append) =
        claimed_worker(&daemon, &project, &space, &branch, &head);

    // The live attempt writes, and — while it is still live — an exact
    // replay is served from the stored bytes. That is the property the
    // authorizer must NOT break.
    let first = daemon.worker_expect_ok(&append);
    let replay = daemon.worker_expect_ok(&append);
    assert_eq!(
        first, replay,
        "a live attempt still replays byte-identically"
    );
    let after_replay = event_count(&daemon, &project);

    // The attempt completes.
    daemon.worker_expect_ok(&mutation(
        "invocation_complete",
        Some(&project),
        "idem-complete",
        json!({
            "invocation_id": invocation_id,
            "attempt_id": attempt_id,
            "fence_epoch": fence,
        }),
    ));

    // Now the same exact replay is refused — a typed problem, not the old
    // receipt — and nothing was re-executed.
    daemon.worker_expect_problem(&append, "stale-lease");
    assert_eq!(
        event_count(&daemon, &project),
        after_replay + 1,
        "only the completion event was added; the refused replay executed nothing"
    );

    // The completion's own replay is refused for the same reason: its
    // attempt is no longer running either.
    daemon.worker_expect_problem(
        &mutation(
            "invocation_complete",
            Some(&project),
            "idem-complete",
            json!({
                "invocation_id": invocation_id,
                "attempt_id": attempt_id,
                "fence_epoch": fence,
            }),
        ),
        "stale-lease",
    );
}

#[test]
fn an_advanced_fence_is_refused_its_old_receipt() {
    let base = tmp("k1-replay-auth-fence");
    let data = base.join("data");
    let run = base.join("run");
    let daemon = DaemonProc::start(&data, &run, None);
    let (project, space, branch, head) = setup_space(&daemon);
    let (_invocation_id, attempt_id, _fence, append) =
        claimed_worker(&daemon, &project, &space, &branch, &head);
    daemon.worker_expect_ok(&append);
    let before = event_count(&daemon, &project);
    drop(daemon);

    // The supervisor fences the attempt out (K1 has no operation that
    // advances a fence, so the epoch is moved directly on the durable
    // row — exactly the state a re-lease would leave behind). The attempt
    // stays `running`, so the fence is unambiguously what refuses.
    {
        let conn = rusqlite::Connection::open(data.join("kovee.db")).unwrap();
        let changed = conn
            .execute(
                "UPDATE invocation_attempts SET fence_epoch = fence_epoch + 1
                 WHERE attempt_id = ?1 AND state = 'running'",
                [&attempt_id],
            )
            .unwrap();
        assert_eq!(changed, 1, "the attempt must still be running");
    }

    let daemon = DaemonProc::start(&data, &run, None);
    // The old fence presents the same exact request: refused, not served.
    daemon.worker_expect_problem(&append, "stale-lease");
    assert_eq!(
        event_count(&daemon, &project),
        before,
        "the refused replay executed nothing"
    );
}
