//! K2 slice 1 — the D10 greenfield enablement saga, every branch of the
//! machine committed in `byom/spec/descriptors/greenfield-enablement.json`:
//!
//! | branch | proof |
//! |---|---|
//! | `absent → bindings_created → active` | `happy_path_creates_inert_bindings_then_cases_the_owner` |
//! | `active → active` (retry) | `an_exact_retry_returns_the_identical_binding_byte_for_byte` |
//! | overlap rejected (active owner) | `an_overlapping_scope_is_rejected_before_anything_is_created` |
//! | overlap rejected (pending past step 1) | `an_overlapping_scope_is_rejected_while_a_pending_enablement_holds_it` |
//! | `bindings_created → rolled_back` | `a_definite_pre_cas_failure_rolls_back_and_spends_the_epoch` |
//! | `rolled_back → bindings_created` (new epoch) | same test's second half |
//! | unknown outcome is NOT a transition | `an_unknown_endpoint_answer_moves_nothing` |
//! | `active → disabled` | `a_governed_disable_freezes_the_owner_row_and_keeps_its_arm` |
//! | refusal: Society not active | `an_inactive_society_refuses_the_enable` |
//! | refusal: Kovee tries to genesis | `kovee_can_never_be_the_genesis_governance_actor` |
//! | exact-CAS | `a_wrong_expected_owner_revision_commits_nothing` |
//! | confirmed subject digest | `a_wrong_confirmed_subject_digest_commits_nothing` |
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::byomstub::{Answer, ByomStub};
use common::*;
use serde_json::{json, Value};

const SCOPE: &str = "project:proj-1";
const WIDER: &str = "project:*";
const OTHER: &str = "project:proj-2";

fn enable_args(scope: &str, expected_owner_revision: u64) -> Value {
    json!({
        "byom_endpoint_ref": "local",
        "society_ref": "soc-stub",
        "exact_scope_selector": scope,
        "allowed_project_and_space_selectors": [scope],
        "classification_binding_ref": "class-bind-1",
        "expected_owner_revision": expected_owner_revision,
    })
}

fn enable(key: &str, scope: &str, expected_owner_revision: u64) -> Value {
    mutation(
        "governance_enable",
        None,
        key,
        enable_args(scope, expected_owner_revision),
    )
}

/// A daemon plus a stub byomd wired to it.
struct Fixture {
    daemon: DaemonProc,
    stub: ByomStub,
    base: std::path::PathBuf,
}

fn fixture(name: &str, hello: Vec<Answer>, society: Vec<Answer>) -> Fixture {
    let base = tmp(name);
    let stub = ByomStub::start(&base.join("byom"), hello, society);
    let daemon = DaemonProc::start_with_env(
        &base.join("data"),
        &base.join("run"),
        None,
        &[("KOVEE_BYOM_RUNTIME_DIR", &stub.dir().to_string_lossy())],
    );
    Fixture { daemon, stub, base }
}

fn active_fixture(name: &str) -> Fixture {
    fixture(
        name,
        vec![Answer::hello("inc-stub-1")],
        vec![Answer::society("active", 0)],
    )
}

fn show(daemon: &DaemonProc) -> Value {
    daemon.expect_ok(&read_cmd("governance_show", None, json!({})))["result"].clone()
}

fn slot_state(state: &Value, enablement_id: &str) -> String {
    state["enablements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["enablement_id"] == enablement_id)
        .unwrap_or_else(|| panic!("no slot {enablement_id} in {state}"))["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

// ------------------------------------------------------------ happy path ----

#[test]
fn happy_path_creates_inert_bindings_then_cases_the_owner() {
    let f = active_fixture("k2-greenfield-happy");

    // Before: no owner anywhere.
    let before = show(&f.daemon);
    assert_eq!(before["governance_owner"], json!("none"));
    assert!(before["enablements"].as_array().unwrap().is_empty());

    let reply = f.daemon.expect_ok(&enable("idem-enable-1", SCOPE, 0));
    let result = &reply["result"];
    assert_eq!(result["state"], json!("active"));

    // Step 1's records, now authoritative.
    let binding = &result["binding"];
    assert_eq!(
        binding["compatibility_bundle"],
        json!("byom_governed_work_v1")
    );
    assert_eq!(binding["status"], json!("active"));
    assert_eq!(binding["binding_epoch"], json!(1));
    assert_eq!(binding["endpoint_incarnation"], json!("inc-stub-1"));
    assert_eq!(result["mapping"]["status"], json!("active"));
    assert_eq!(result["mapping"]["society_recovery_epoch"], json!(0));

    // Step 2's CAS: none → byom at the expected revision, with both
    // owner refs set atomically.
    let owner = &result["owner_binding"];
    assert_eq!(owner["governance_owner"], json!("byom"));
    assert_eq!(owner["status"], json!("active"));
    assert_eq!(owner["owner_endpoint_ref"], json!("local"));
    assert_eq!(owner["owner_binding_ref"], binding["binding_ref"]);
    assert_eq!(owner["exact_scope_selector"], json!(SCOPE));
    assert_eq!(owner["binding_epoch"], json!(1));
    // The owner row started at revision 1 (`none`) and the CAS advanced it.
    assert_eq!(owner["revision"], json!(2));
    assert_eq!(reply["revision"], json!(2));

    // Every digest is a typed, scope-keyed family DigestRef.
    for digest in [
        &owner["exact_scope_digest"],
        &owner["digest"],
        &binding["digest"],
    ] {
        assert_eq!(digest["class"], json!("scope_erasure_safe"));
        assert_eq!(digest["algorithm"], json!("hmac-sha-256"));
        assert_eq!(
            digest["key_ref"],
            json!("kovee-governance:realm-personal"),
            "one protected per-realm governance key"
        );
        assert_eq!(digest["value_hex"].as_str().unwrap().len(), 64);
    }

    // And the read surface agrees.
    let after = show(&f.daemon);
    assert_eq!(after["governance_owner"], json!("byom"));
    assert_eq!(
        slot_state(&after, result["enablement_id"].as_str().unwrap()),
        "active"
    );
}

// ------------------------------------------------------- retry identical ----

#[test]
fn an_exact_retry_returns_the_identical_binding_byte_for_byte() {
    let f = active_fixture("k2-greenfield-retry");
    let first = f
        .daemon
        .request_raw(&enable("idem-enable-1", SCOPE, 0))
        .unwrap();
    let second = f
        .daemon
        .request_raw(&enable("idem-enable-1", SCOPE, 0))
        .unwrap();
    assert_eq!(
        first, second,
        "retry after activation must be byte-identical"
    );

    // A different idempotency key over the same (realm, exact scope,
    // epoch) still returns THE SAME binding — never a second creation,
    // CAS, or epoch advance (RetryIdempotent).
    let third: Value = serde_json::from_str(
        &f.daemon
            .request_raw(&enable("idem-enable-2", SCOPE, 0))
            .unwrap(),
    )
    .unwrap();
    let first_value: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(third["result"], first_value["result"]);
    assert_eq!(third["revision"], first_value["revision"]);

    let state = show(&f.daemon);
    assert_eq!(
        state["enablements"].as_array().unwrap().len(),
        1,
        "exactly one saga row survives every retry"
    );
    assert_eq!(state["owner_bindings"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------- overlap rejection ----

#[test]
fn an_overlapping_scope_is_rejected_before_anything_is_created() {
    let f = active_fixture("k2-greenfield-overlap-active");
    f.daemon.expect_ok(&enable("idem-enable-1", SCOPE, 0));

    // `project:*` covers `project:proj-1`: rejected (§16.6 item 1).
    let reply = f
        .daemon
        .expect_problem(&enable("idem-enable-2", WIDER, 0), "forbidden");
    assert!(
        reply["problem"]["detail"]
            .as_str()
            .unwrap()
            .contains("overlap"),
        "{reply}"
    );

    // Rejection is the ABSENCE of a transition: nothing was created.
    let state = show(&f.daemon);
    assert_eq!(state["enablements"].as_array().unwrap().len(), 1);
    assert_eq!(state["owner_bindings"].as_array().unwrap().len(), 1);

    // A disjoint scope is fine — overlap, not exclusivity, is the rule.
    f.daemon.expect_ok(&enable("idem-enable-3", OTHER, 0));
    assert_eq!(show(&f.daemon)["enablements"].as_array().unwrap().len(), 2);
}

#[test]
fn an_overlapping_scope_is_rejected_while_a_pending_enablement_holds_it() {
    // A pending enablement PAST STEP 1 blocks an overlapping enable just
    // as an active owner does. Reaching that state needs a crash between
    // the two commits, which is exactly what the abort hook gives us.
    let base = tmp("k2-greenfield-overlap-pending");
    let stub = ByomStub::active(&base.join("byom"));
    let byom_dir = stub.dir().to_string_lossy().into_owned();
    let env = [("KOVEE_BYOM_RUNTIME_DIR", byom_dir.as_str())];

    {
        let daemon = DaemonProc::start_with_env(
            &base.join("data"),
            &base.join("run"),
            Some("after_commit:governance_enable#create"),
            &env,
        );
        assert!(
            daemon
                .request_raw(&enable("idem-enable-1", SCOPE, 0))
                .is_none(),
            "the daemon dies after step 1 commits"
        );
        daemon.wait_dead();
    }

    let daemon = DaemonProc::start_with_env(&base.join("data"), &base.join("run"), None, &env);
    let state = show(&daemon);
    let pending = &state["enablements"].as_array().unwrap()[0];
    assert_eq!(pending["state"], json!("bindings_created"));
    // Not yet authoritative: the owner is still `none`.
    assert_eq!(state["governance_owner"], json!("none"));

    let reply = daemon.expect_problem(&enable("idem-enable-2", WIDER, 0), "forbidden");
    assert!(
        reply["problem"]["detail"]
            .as_str()
            .unwrap()
            .contains("bindings_created"),
        "the pending enablement is named as the blocker: {reply}"
    );
}

// ----------------------------------------- rollback then new-epoch enable ----

#[test]
fn a_definite_pre_cas_failure_rolls_back_and_spends_the_epoch() {
    // The endpoint re-incarnates between step 1's read and the pre-CAS
    // re-verification: a DEFINITE mismatch, so the saga's own failure
    // handling rolls back (greenfield-saga §4).
    let f = fixture(
        "k2-greenfield-rollback",
        vec![Answer::hello("inc-stub-1"), Answer::hello("inc-stub-2")],
        vec![Answer::society("active", 0)],
    );
    let reply = f
        .daemon
        .expect_problem(&enable("idem-enable-1", SCOPE, 0), "forbidden");
    let detail = reply["problem"]["detail"].as_str().unwrap();
    assert!(detail.contains("re-incarnated"), "{reply}");
    assert!(detail.contains("spent"), "{reply}");

    let state = show(&f.daemon);
    let slot = &state["enablements"].as_array().unwrap()[0];
    assert_eq!(slot["state"], json!("rolled_back"));
    assert_eq!(slot["binding_epoch"], json!(1));
    // The owner binding stayed `none` — a rolled-back epoch never owns.
    assert_eq!(state["governance_owner"], json!("none"));
    assert_eq!(
        state["owner_bindings"].as_array().unwrap()[0]["governance_owner"],
        json!("none")
    );

    // The rolled-back epoch can never activate, even on an exact retry.
    let refused = f
        .daemon
        .expect_problem(&enable("idem-enable-1", SCOPE, 0), "forbidden");
    assert!(
        refused["problem"]["detail"]
            .as_str()
            .unwrap()
            .contains("spent"),
        "{refused}"
    );

    // Re-enablement is a FRESH governance_enable under a NEW epoch.
    f.stub.rescript(
        vec![Answer::hello("inc-stub-2")],
        vec![Answer::society("active", 0)],
    );
    let reenabled = f.daemon.expect_ok(&enable("idem-enable-2", SCOPE, 1));
    assert_eq!(reenabled["result"]["state"], json!("active"));
    assert_eq!(
        reenabled["result"]["binding"]["binding_epoch"],
        json!(2),
        "a new epoch, never a resurrection of the rolled-back one"
    );
    assert_eq!(
        reenabled["result"]["binding"]["endpoint_incarnation"],
        json!("inc-stub-2")
    );

    // Both epochs survive: one spent, one active.
    let state = show(&f.daemon);
    let slots = state["enablements"].as_array().unwrap();
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0]["state"], json!("rolled_back"));
    assert_eq!(slots[1]["state"], json!("active"));
    assert_eq!(state["governance_owner"], json!("byom"));
}

#[test]
fn a_society_leaving_active_before_the_cas_also_rolls_back() {
    let f = fixture(
        "k2-greenfield-rollback-society",
        vec![Answer::hello("inc-stub-1")],
        vec![Answer::society("active", 0), Answer::society("held", 0)],
    );
    let reply = f
        .daemon
        .expect_problem(&enable("idem-enable-1", SCOPE, 0), "forbidden");
    assert!(
        reply["problem"]["detail"]
            .as_str()
            .unwrap()
            .contains("left the active state"),
        "{reply}"
    );
    assert_eq!(show(&f.daemon)["governance_owner"], json!("none"));
}

// ---------------------------------------------- unknown is not an answer ----

#[test]
fn an_unknown_endpoint_answer_moves_nothing() {
    // byomd closes without replying during the pre-CAS re-verification.
    // That is UNKNOWN, not a refusal: nothing rolls back and nothing
    // activates — guessing is not a transition (greenfield-saga §5).
    let f = fixture(
        "k2-greenfield-unknown",
        vec![Answer::hello("inc-stub-1"), Answer::Close],
        vec![Answer::society("active", 0)],
    );
    f.daemon
        .expect_problem(&enable("idem-enable-1", SCOPE, 0), "unavailable");

    let state = show(&f.daemon);
    let slot = &state["enablements"].as_array().unwrap()[0];
    assert_eq!(
        slot["state"],
        json!("bindings_created"),
        "the slot stays where it was; the operator resolves query-first"
    );
    assert_eq!(state["governance_owner"], json!("none"));

    // A verified answer then drives the retry to completion.
    f.stub.rescript(
        vec![Answer::hello("inc-stub-1")],
        vec![Answer::society("active", 0)],
    );
    let done = f.daemon.expect_ok(&enable("idem-enable-1", SCOPE, 0));
    assert_eq!(done["result"]["state"], json!("active"));
    assert_eq!(
        done["result"]["binding"]["binding_epoch"],
        json!(1),
        "the SAME epoch completes — no second creation"
    );
}

// ------------------------------------------------------ genesis refusals ----

#[test]
fn kovee_can_never_be_the_genesis_governance_actor() {
    // The Society does not exist: byomd answers not_found. Kovee refuses
    // rather than establishing one (amendment A2).
    let f = fixture(
        "k2-greenfield-genesis",
        vec![Answer::hello("inc-stub-1")],
        vec![Answer::Problem("not_found", 404)],
    );
    let reply = f
        .daemon
        .expect_problem(&enable("idem-enable-1", SCOPE, 0), "forbidden");
    assert!(
        reply["problem"]["detail"]
            .as_str()
            .unwrap()
            .contains("never the genesis governance actor"),
        "{reply}"
    );
    // Nothing at all was created.
    let state = show(&f.daemon);
    assert!(state["enablements"].as_array().unwrap().is_empty());
    assert!(state["owner_bindings"].as_array().unwrap().is_empty());

    // And no Kovee operation can establish a Society: the native
    // genesis verbs are not on any Kovee surface.
    for op in ["society_prepare", "society_bootstrap"] {
        f.daemon
            .expect_problem(&mutation(op, None, "idem-genesis", json!({})), "unknown-op");
    }
}

#[test]
fn an_inactive_society_refuses_the_enable() {
    let f = fixture(
        "k2-greenfield-forming",
        vec![Answer::hello("inc-stub-1")],
        vec![Answer::society("forming", 0)],
    );
    let reply = f
        .daemon
        .expect_problem(&enable("idem-enable-1", SCOPE, 0), "forbidden");
    assert!(
        reply["problem"]["detail"]
            .as_str()
            .unwrap()
            .contains("\"forming\""),
        "{reply}"
    );
    assert!(show(&f.daemon)["enablements"]
        .as_array()
        .unwrap()
        .is_empty());
}

// ------------------------------------------------------------- exact CAS ----

#[test]
fn a_wrong_expected_owner_revision_commits_nothing() {
    let f = active_fixture("k2-greenfield-cas");
    // The owner row is absent, so only 0 can match.
    f.daemon
        .expect_problem(&enable("idem-enable-1", SCOPE, 7), "stale-revision");
    assert!(show(&f.daemon)["enablements"]
        .as_array()
        .unwrap()
        .is_empty());

    f.daemon.expect_ok(&enable("idem-enable-2", SCOPE, 0));
    // Now a fresh, non-retry enable of a DIFFERENT target on the same
    // scope hits the owned row.
    let other_target = mutation(
        "governance_enable",
        None,
        "idem-enable-3",
        json!({
            "byom_endpoint_ref": "local",
            "society_ref": "soc-other",
            "exact_scope_selector": SCOPE,
            "allowed_project_and_space_selectors": [SCOPE],
            "classification_binding_ref": "class-bind-1",
            "expected_owner_revision": 0,
        }),
    );
    f.daemon.expect_problem(&other_target, "forbidden");
}

#[test]
fn a_wrong_confirmed_subject_digest_commits_nothing() {
    let f = active_fixture("k2-greenfield-subject");
    let mut args = enable_args(SCOPE, 0);
    args["confirmed_subject_digest"] = json!("9".repeat(64));
    let cmd = mutation("governance_enable", None, "idem-enable-1", args);
    f.daemon.expect_problem(&cmd, "forbidden");
    assert!(show(&f.daemon)["enablements"]
        .as_array()
        .unwrap()
        .is_empty());

    // The digest the enablement actually commits is accepted.
    let ok = f.daemon.expect_ok(&enable("idem-enable-2", SCOPE, 0));
    let subject = ok["result"]["subject_digest"].as_str().unwrap().to_owned();
    assert_eq!(subject.len(), 64);
    assert_eq!(
        show(&f.daemon)["enablements"].as_array().unwrap()[0]["subject_digest"],
        json!(subject)
    );
}

// -------------------------------------------------------------- disable ----

#[test]
fn a_governed_disable_freezes_the_owner_row_and_keeps_its_arm() {
    let f = active_fixture("k2-greenfield-disable");
    let enabled = f.daemon.expect_ok(&enable("idem-enable-1", SCOPE, 0));
    let binding_ref = enabled["result"]["binding"]["binding_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    let subject = enabled["result"]["subject_digest"]
        .as_str()
        .unwrap()
        .to_owned();

    // Always step-up: a wrong (or missing) confirmation refuses.
    let wrong = mutation(
        "governance_disable",
        None,
        "idem-disable-0",
        json!({
            "binding_ref": binding_ref,
            "expected_owner_revision": 2,
            "confirmed_subject_digest": "0".repeat(64),
        }),
    );
    f.daemon.expect_problem(&wrong, "forbidden");

    let disabled = f.daemon.expect_ok(&mutation(
        "governance_disable",
        None,
        "idem-disable-1",
        json!({
            "binding_ref": binding_ref,
            "expected_owner_revision": 2,
            "confirmed_subject_digest": subject,
        }),
    ));
    let owner = &disabled["result"]["owner_binding"];
    assert_eq!(owner["status"], json!("frozen"));
    // The owner ARM is retained for audit; only the status changes.
    assert_eq!(owner["governance_owner"], json!("byom"));
    assert_eq!(owner["owner_binding_ref"], json!(binding_ref));
    assert_eq!(owner["revision"], json!(3));
    // Derived channels invalidate with the binding.
    assert_eq!(disabled["result"]["binding"]["status"], json!("void"));

    // After the CAS there is no rollback: only this disable, and only
    // once.
    f.daemon.expect_problem(
        &mutation(
            "governance_disable",
            None,
            "idem-disable-2",
            json!({
                "binding_ref": binding_ref,
                "expected_owner_revision": 3,
                "confirmed_subject_digest": subject,
            }),
        ),
        "forbidden",
    );

    // Re-enablement after a governed disable is a fresh saga row under a
    // new binding epoch, not a transition of this machine.
    let reenabled = f.daemon.expect_ok(&enable("idem-enable-2", SCOPE, 3));
    assert_eq!(reenabled["result"]["binding"]["binding_epoch"], json!(2));
    let state = show(&f.daemon);
    let slots = state["enablements"].as_array().unwrap();
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0]["state"], json!("disabled"));
    assert_eq!(slots[1]["state"], json!("active"));
}

// ------------------------------------------------------------ read shape ----

#[test]
fn governance_show_narrows_by_binding_and_never_mutates() {
    let f = active_fixture("k2-greenfield-show");
    let enabled = f.daemon.expect_ok(&enable("idem-enable-1", SCOPE, 0));
    let binding_ref = enabled["result"]["binding"]["binding_ref"]
        .as_str()
        .unwrap()
        .to_owned();

    let narrowed = f.daemon.expect_ok(&read_cmd(
        "governance_show",
        None,
        json!({"binding_ref": binding_ref}),
    ));
    assert_eq!(
        narrowed["result"]["enablements"].as_array().unwrap().len(),
        1
    );
    // An unknown binding is the uniform not-found — reads enumerate
    // nothing.
    f.daemon.expect_problem(
        &read_cmd("governance_show", None, json!({"binding_ref": "krbb-nope"})),
        "not-found",
    );
    // A read carrying meta is refused outright (§11.2, R0 KENV-01).
    f.daemon.expect_problem(
        &mutation("governance_show", None, "idem-read", json!({})),
        "invalid",
    );
    // Nothing moved.
    assert_eq!(show(&f.daemon)["governance_owner"], json!("byom"));
    let _ = &f.base;
}
