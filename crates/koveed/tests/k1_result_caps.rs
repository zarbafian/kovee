//! KV-C2: §11.8 result bounds are enforced INSIDE the command
//! transaction.
//!
//! The defect: the 1 MiB reply cap was checked only after
//! `command_transaction` had committed. `project_access_policy_change_prepare`
//! accumulates one entry per pinned frontier and repeated frontier pins
//! are unbounded, so once the serialized result crossed the cap the
//! state, events, outbox row and idempotency record were all durable
//! while the client got `internal` — and every replay returned the same
//! `internal`, leaving a committed receipt permanently unobtainable.
//!
//! The fix has to hold two things at once: the over-cap command commits
//! NOTHING, and the bounded operations that feed it keep working.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{json, Value};

/// The §11.8 list cap the result bound enforces.
const LIST_MAX_ITEMS: usize = 256;

fn papc_prepare(project: &str, key: &str) -> Value {
    mutation(
        "project_access_policy_change_prepare",
        Some(project),
        key,
        json!({"proposed_policy_set_ref": "policy-tighter"}),
    )
}

fn prepared_events(daemon: &DaemonProc, project: &str) -> usize {
    let events = daemon.expect_ok(&events_read(project));
    events["result"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["type"].as_str() == Some("dev.kovee.project.access-policy-change-prepared.v1")
        })
        .count()
}

#[test]
fn an_unbounded_accumulated_result_rolls_back_instead_of_committing() {
    let base = tmp("k1-result-caps");
    let daemon = DaemonProc::start(&base.join("data"), &base.join("run"), None);
    let (project, space, branch, _head) = setup_space(&daemon);

    // Under the cap the preparation works and its frontier list is
    // exactly what was pinned.
    for i in 0..3 {
        daemon.expect_ok(&mutation(
            "frontier_pin",
            Some(&project),
            &format!("idem-pin-warmup-{i}"),
            json!({"space_id": space, "branch_id": branch}),
        ));
    }
    let ok = daemon.expect_ok(&papc_prepare(&project, "idem-papc-small"));
    assert_eq!(
        ok["result"]["affected_space_frontier_refs"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let baseline_prepared = prepared_events(&daemon, &project);

    // The repeated-frontier-pin case: pinning is unbounded, and every
    // individual pin stays a bounded, committed, replayable command.
    for i in 3..=LIST_MAX_ITEMS {
        let pinned = daemon.expect_ok(&mutation(
            "frontier_pin",
            Some(&project),
            &format!("idem-pin-{i}"),
            json!({"space_id": space, "branch_id": branch}),
        ));
        assert!(pinned["result"]["frontier_id"].is_string());
    }

    // The accumulating consumer now exceeds the §11.8 list cap. It must
    // fail with a TYPED problem — not `internal` — and commit nothing.
    let refused = daemon.expect_problem(&papc_prepare(&project, "idem-papc-over"), "invalid");
    let detail = refused["problem"]["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("affected_space_frontier_refs"),
        "the problem must name the offending member: {refused}"
    );
    assert_eq!(
        prepared_events(&daemon, &project),
        baseline_prepared,
        "an over-cap preparation must commit no event"
    );

    // The receipt is not committed-but-unobtainable: the SAME key
    // presented again gets the same typed refusal, and a fresh key gets
    // it too — there is no stored `internal` masking a durable change.
    let again = daemon.expect_problem(&papc_prepare(&project, "idem-papc-over"), "invalid");
    assert_eq!(
        again["problem"]["detail"], refused["problem"]["detail"],
        "the refusal is stable, not a stored error hiding a commit"
    );
    daemon.expect_problem(&papc_prepare(&project, "idem-papc-over-2"), "invalid");
    assert_eq!(prepared_events(&daemon, &project), baseline_prepared);

    // Nothing else broke: the space still accepts work after the rollback.
    let shown = daemon.expect_ok(&read_cmd(
        "space_show",
        Some(&project),
        json!({"space_id": space}),
    ));
    assert_eq!(shown["result"]["status"].as_str(), Some("open"));
}
