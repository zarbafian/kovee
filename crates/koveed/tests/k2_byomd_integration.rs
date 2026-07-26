//! K2 slice 1 — the greenfield saga end to end against the REAL `byomd`.
//!
//! No stub: it builds and spawns byom's daemon (`common::byomd`),
//! bootstraps a Society through its own governance socket
//! (`society_prepare` → `society_bootstrap`, the native genesis path
//! Kovee is never allowed to take), then runs `kovee governance_enable`
//! against that live endpoint and checks that the binding Kovee committed
//! pins exactly what byomd reports.
//!
//! It is gated on the byom repository being present — `$KOVEE_BYOM_REPO`,
//! else the sibling `../byom` — mirroring the plan's env-gated
//! real-harness discipline (§8). When present it always runs; it never
//! silently passes on a byomd failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::byomd::*;
use common::*;
use serde_json::{json, Value};

const SCOPE: &str = "project:proj-1";

fn enable(key: &str, society_ref: &str, expected_owner_revision: u64) -> Value {
    mutation(
        "governance_enable",
        None,
        key,
        json!({
            "byom_endpoint_ref": "local",
            "society_ref": society_ref,
            "exact_scope_selector": SCOPE,
            "allowed_project_and_space_selectors": [SCOPE],
            "classification_binding_ref": "class-bind-k2",
            "expected_owner_revision": expected_owner_revision,
        }),
    )
}

#[test]
fn greenfield_enablement_runs_end_to_end_against_a_real_byomd() {
    let Some(repo) = byom_repo() else {
        println!(
            "k2_byomd_integration: skipped — no byom repository \
             (set KOVEE_BYOM_REPO or check out ../byom)"
        );
        return;
    };
    let binary = byomd_binary(&repo);
    let base = tmp("k2-byomd-integration");

    // 1. The real byomd, on its own four sockets.
    let byomd = Byomd::start(&binary, &base.join("byom-data"), &base.join("byom-run"));
    let hello = byomd.call_ok(
        "governance",
        &json!({"version": BPP_VERSION, "op": "hello"}),
    );
    let incarnation = hello["result"]["endpoint_incarnation"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(hello["result"]["versions"], json!([BPP_VERSION]));
    assert_eq!(hello["result"]["surface"], json!("governance"));

    // 2. A Society, established natively — never by Kovee.
    let society_id = bootstrap_society(&byomd, &incarnation);
    let seen = byomd.call_ok(
        "projection",
        &json!({"version": BPP_VERSION, "op": "society_show", "society_id": society_id}),
    );
    assert_eq!(seen["result"]["state"], json!("active"));

    // 3. koveed, pointed at that live endpoint.
    let byom_run = base.join("byom-run").to_string_lossy().into_owned();
    let daemon = DaemonProc::start_with_env(
        &base.join("kovee-data"),
        &base.join("kovee-run"),
        None,
        &[("KOVEE_BYOM_RUNTIME_DIR", byom_run.as_str())],
    );

    // Kovee is never the genesis actor: an unknown Society is refused by
    // the REAL byomd's `not_found`, not by a stub.
    let refused = daemon.expect_problem(
        &enable("idem-genesis", "soc-does-not-exist", 0),
        "forbidden",
    );
    assert!(
        refused["problem"]["detail"]
            .as_str()
            .unwrap()
            .contains("never the genesis governance actor"),
        "{refused}"
    );

    // 4. The saga, end to end.
    let enabled = daemon.expect_ok(&enable("idem-enable-1", &society_id, 0));
    let result = &enabled["result"];
    assert_eq!(result["state"], json!("active"));
    assert_eq!(result["society"]["society_ref"], json!(society_id));
    assert_eq!(result["society"]["state"], json!("active"));
    // The binding pins exactly what byomd reported — server-recomputed,
    // never taken from the wire.
    assert_eq!(
        result["binding"]["endpoint_incarnation"],
        json!(incarnation)
    );
    assert_eq!(
        result["mapping"]["society_recovery_epoch"],
        seen["result"]["recovery_epoch"]
    );
    assert_eq!(result["owner_binding"]["governance_owner"], json!("byom"));
    assert_eq!(
        result["owner_binding"]["owner_endpoint_ref"],
        json!("local")
    );

    // 5. Retry against the live endpoint stays byte-identical.
    let a = daemon
        .request_raw(&enable("idem-enable-1", &society_id, 0))
        .unwrap();
    let b = daemon
        .request_raw(&enable("idem-enable-1", &society_id, 0))
        .unwrap();
    assert_eq!(a, b);

    // 6. And the read surface reports the live binding.
    let shown = daemon.expect_ok(&read_cmd("governance_show", None, json!({})));
    assert_eq!(shown["result"]["governance_owner"], json!("byom"));
    let slot = &shown["result"]["enablements"].as_array().unwrap()[0];
    assert_eq!(slot["state"], json!("active"));
    assert_eq!(slot["society_ref"], json!(society_id));
    assert_eq!(slot["endpoint_incarnation"], json!(incarnation));
}
