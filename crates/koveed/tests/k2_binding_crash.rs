//! K2 slice 1 — kill-and-restart at EVERY greenfield-saga commit point.
//!
//! The saga has three commits (`#create`, `#activate`, `#rollback`) plus
//! `governance_disable`'s single one, and the K1 `KOVEED_ABORT` hook
//! arms `before_commit` / `after_commit` at each. Two invariants hold at
//! every point, whatever the daemon did before it died:
//!
//! - **no partial binding** — a `KoveeRealmByomBinding`, its
//!   `KoveeSocietyMapping`, and its saga slot exist together or not at
//!   all, and a binding is `active` only when its owner row says `byom`;
//! - **no double activation** — the owner CAS wins at most once per
//!   scope and epoch, and the retry returns the stored identical result
//!   rather than advancing anything.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};

use common::byomstub::{Answer, ByomStub};
use common::*;
use serde_json::{json, Value};

const SCOPE: &str = "project:proj-1";

fn enable(key: &str, expected_owner_revision: u64) -> Value {
    mutation(
        "governance_enable",
        None,
        key,
        json!({
            "byom_endpoint_ref": "local",
            "society_ref": "soc-stub",
            "exact_scope_selector": SCOPE,
            "allowed_project_and_space_selectors": [SCOPE],
            "classification_binding_ref": "class-bind-1",
            "expected_owner_revision": expected_owner_revision,
        }),
    )
}

struct Bench {
    base: PathBuf,
    #[allow(dead_code)]
    stub: ByomStub,
    byom_dir: String,
}

impl Bench {
    fn new(name: &str, hello: Vec<Answer>, society: Vec<Answer>) -> Bench {
        let base = tmp(name);
        let stub = ByomStub::start(&base.join("byom"), hello, society);
        let byom_dir = stub.dir().to_string_lossy().into_owned();
        Bench {
            base,
            stub,
            byom_dir,
        }
    }

    fn happy(name: &str) -> Bench {
        Bench::new(
            name,
            vec![Answer::hello("inc-stub-1")],
            vec![Answer::society("active", 0)],
        )
    }

    fn daemon(&self, abort: Option<&str>) -> DaemonProc {
        DaemonProc::start_with_env(
            &self.base.join("data"),
            &self.base.join("run"),
            abort,
            &[("KOVEE_BYOM_RUNTIME_DIR", self.byom_dir.as_str())],
        )
    }

    fn db(&self) -> PathBuf {
        self.base.join("data").join("kovee.db")
    }
}

/// The two structural invariants, read straight from the store.
fn assert_store_is_coherent(db: &Path) -> (i64, i64, i64) {
    let store = kovee_store::Store::open(db).unwrap();
    let conn = store.conn();
    let count = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap();

    let bindings = count("SELECT COUNT(*) FROM kovee_realm_byom_bindings");
    let mappings = count("SELECT COUNT(*) FROM kovee_society_mappings");
    let slots = count("SELECT COUNT(*) FROM greenfield_enablements");
    assert_eq!(
        (bindings, mappings),
        (slots, slots),
        "no partial binding: binding, mapping, and saga slot commit together"
    );
    // Every slot's binding and mapping exist.
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM greenfield_enablements e
             WHERE NOT EXISTS (SELECT 1 FROM kovee_realm_byom_bindings b
                               WHERE b.binding_ref = e.binding_ref)
                OR NOT EXISTS (SELECT 1 FROM kovee_society_mappings m
                               WHERE m.mapping_id = e.mapping_id)"
        ),
        0,
        "no saga slot without its records"
    );
    // A binding is authoritative only under an owning owner row.
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM kovee_realm_byom_bindings b
             WHERE b.status = 'active'
               AND NOT EXISTS (SELECT 1 FROM kovee_governance_owner_bindings o
                               WHERE o.owner_binding_ref = b.binding_ref
                                 AND o.governance_owner = 'byom')"
        ),
        0,
        "no active binding without an owning owner row"
    );
    // No double activation: at most one active slot per (scope, epoch),
    // and the owner row is single per exact scope by primary key.
    let active_slots = count("SELECT COUNT(*) FROM greenfield_enablements WHERE state = 'active'");
    let owning = count(
        "SELECT COUNT(*) FROM kovee_governance_owner_bindings
         WHERE governance_owner = 'byom' AND status = 'active'",
    );
    assert_eq!(
        active_slots, owning,
        "exactly one owning row per active enablement"
    );
    // The audit chain survives every crash.
    store.verify_audit().unwrap();
    (bindings, active_slots, owning)
}

fn show(daemon: &DaemonProc) -> Value {
    daemon.expect_ok(&read_cmd("governance_show", None, json!({})))["result"].clone()
}

fn crash_then_restart(bench: &Bench, abort: &str, command: &Value) {
    let daemon = bench.daemon(Some(abort));
    let reply = daemon.request_raw(command);
    assert!(
        reply.is_none(),
        "{abort}: the daemon must die before replying, got {reply:?}"
    );
    daemon.wait_dead();
    assert_store_is_coherent(&bench.db());
}

// -------------------------------------------------------- step 1 commit ----

#[test]
fn a_crash_before_step_one_commits_leaves_nothing() {
    let bench = Bench::happy("k2-crash-before-create");
    crash_then_restart(
        &bench,
        "before_commit:governance_enable#create",
        &enable("idem-enable-1", 0),
    );

    let daemon = bench.daemon(None);
    let state = show(&daemon);
    assert!(state["enablements"].as_array().unwrap().is_empty());
    assert!(state["owner_bindings"].as_array().unwrap().is_empty());
    assert_eq!(state["governance_owner"], json!("none"));

    // The retry starts from absent and completes.
    let done = daemon.expect_ok(&enable("idem-enable-1", 0));
    assert_eq!(done["result"]["state"], json!("active"));
    assert_eq!(done["result"]["binding"]["binding_epoch"], json!(1));
    assert_eq!(assert_store_is_coherent(&bench.db()), (1, 1, 1));
}

#[test]
fn a_crash_after_step_one_commits_leaves_inert_bindings_and_no_owner() {
    let bench = Bench::happy("k2-crash-after-create");
    crash_then_restart(
        &bench,
        "after_commit:governance_enable#create",
        &enable("idem-enable-1", 0),
    );

    let daemon = bench.daemon(None);
    let state = show(&daemon);
    let slot = &state["enablements"].as_array().unwrap()[0];
    assert_eq!(slot["state"], json!("bindings_created"));
    // Durable but NOT authoritative.
    assert_eq!(state["governance_owner"], json!("none"));
    assert_eq!(
        state["owner_bindings"].as_array().unwrap()[0]["governance_owner"],
        json!("none")
    );
    assert_eq!(slot["record"]["binding"]["status"], json!("pending"));
    assert_eq!(slot["record"]["mapping"]["status"], json!("pending"));

    // The retry re-enters at the recorded state and completes the SAME
    // epoch — never a second creation.
    let done = daemon.expect_ok(&enable("idem-enable-1", 0));
    assert_eq!(done["result"]["state"], json!("active"));
    assert_eq!(done["result"]["binding"]["binding_epoch"], json!(1));
    assert_eq!(
        done["result"]["enablement_id"], slot["enablement_id"],
        "the same saga row"
    );
    assert_eq!(assert_store_is_coherent(&bench.db()), (1, 1, 1));
}

// -------------------------------------------------------- step 2 commit ----

#[test]
fn a_crash_before_the_cas_commits_activates_nothing() {
    let bench = Bench::happy("k2-crash-before-activate");
    crash_then_restart(
        &bench,
        "before_commit:governance_enable#activate",
        &enable("idem-enable-1", 0),
    );

    let daemon = bench.daemon(None);
    let state = show(&daemon);
    assert_eq!(
        state["enablements"].as_array().unwrap()[0]["state"],
        json!("bindings_created")
    );
    assert_eq!(state["governance_owner"], json!("none"));

    let done = daemon.expect_ok(&enable("idem-enable-1", 0));
    assert_eq!(
        done["result"]["owner_binding"]["governance_owner"],
        json!("byom")
    );
    assert_eq!(done["result"]["owner_binding"]["revision"], json!(2));
    assert_eq!(assert_store_is_coherent(&bench.db()), (1, 1, 1));
}

#[test]
fn a_crash_after_the_cas_commits_never_activates_twice() {
    let bench = Bench::happy("k2-crash-after-activate");
    crash_then_restart(
        &bench,
        "after_commit:governance_enable#activate",
        &enable("idem-enable-1", 0),
    );

    let daemon = bench.daemon(None);
    let state = show(&daemon);
    assert_eq!(
        state["enablements"].as_array().unwrap()[0]["state"],
        json!("active")
    );
    assert_eq!(state["governance_owner"], json!("byom"));
    // The CAS won exactly once: revision 2, not 3.
    assert_eq!(
        state["owner_bindings"].as_array().unwrap()[0]["revision"],
        json!(2)
    );

    // The retry returns the stored identical result, byte for byte.
    let first = daemon.request_raw(&enable("idem-enable-1", 0)).unwrap();
    let second = daemon.request_raw(&enable("idem-enable-1", 0)).unwrap();
    assert_eq!(first, second);
    let parsed: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(parsed["result"]["state"], json!("active"));
    assert_eq!(parsed["revision"], json!(2), "no epoch or revision advance");
    assert_eq!(assert_store_is_coherent(&bench.db()), (1, 1, 1));
}

// ------------------------------------------------------ rollback commit ----

#[test]
fn a_crash_around_the_rollback_commit_keeps_the_epoch_honest() {
    // The endpoint re-incarnates between step 1 and the pre-CAS check, so
    // the saga rolls back — and dies at that commit.
    let bench = Bench::new(
        "k2-crash-rollback",
        vec![Answer::hello("inc-stub-1"), Answer::hello("inc-stub-2")],
        vec![Answer::society("active", 0)],
    );
    crash_then_restart(
        &bench,
        "before_commit:governance_enable#rollback",
        &enable("idem-enable-1", 0),
    );

    // Nothing committed: the slot is still pending, the owner still none.
    {
        let daemon = bench.daemon(None);
        let state = show(&daemon);
        assert_eq!(
            state["enablements"].as_array().unwrap()[0]["state"],
            json!("bindings_created")
        );
        assert_eq!(state["governance_owner"], json!("none"));
    }

    // Now let the rollback commit and die immediately after.
    crash_then_restart(
        &bench,
        "after_commit:governance_enable#rollback",
        &enable("idem-enable-1", 0),
    );

    let daemon = bench.daemon(None);
    let state = show(&daemon);
    let slot = &state["enablements"].as_array().unwrap()[0];
    assert_eq!(slot["state"], json!("rolled_back"));
    assert_eq!(slot["binding_epoch"], json!(1));
    assert_eq!(state["governance_owner"], json!("none"));

    // A rolled-back epoch can NEVER activate, across restarts.
    let refused = daemon.expect_problem(&enable("idem-enable-1", 0), "forbidden");
    assert!(
        refused["problem"]["detail"]
            .as_str()
            .unwrap()
            .contains("spent"),
        "{refused}"
    );
    let (bindings, active, owning) = assert_store_is_coherent(&bench.db());
    assert_eq!((bindings, active, owning), (1, 0, 0));
}

// ------------------------------------------------------- disable commit ----

#[test]
fn a_crash_around_the_disable_commit_freezes_at_most_once() {
    let bench = Bench::happy("k2-crash-disable");
    let (binding_ref, subject) = {
        let daemon = bench.daemon(None);
        let enabled = daemon.expect_ok(&enable("idem-enable-1", 0));
        (
            enabled["result"]["binding"]["binding_ref"]
                .as_str()
                .unwrap()
                .to_owned(),
            enabled["result"]["subject_digest"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
    };
    let disable = mutation(
        "governance_disable",
        None,
        "idem-disable-1",
        json!({
            "binding_ref": binding_ref,
            "expected_owner_revision": 2,
            "confirmed_subject_digest": subject,
        }),
    );

    crash_then_restart(&bench, "before_commit:governance_disable", &disable);
    {
        let daemon = bench.daemon(None);
        let state = show(&daemon);
        assert_eq!(state["governance_owner"], json!("byom"));
        assert_eq!(
            state["owner_bindings"].as_array().unwrap()[0]["status"],
            json!("active"),
            "a crash before the disable commit freezes nothing"
        );
    }

    crash_then_restart(&bench, "after_commit:governance_disable", &disable);
    let daemon = bench.daemon(None);
    let state = show(&daemon);
    let owner = &state["owner_bindings"].as_array().unwrap()[0];
    assert_eq!(owner["status"], json!("frozen"));
    // The owner arm is retained for audit; the freeze happened once.
    assert_eq!(owner["governance_owner"], json!("byom"));
    assert_eq!(owner["revision"], json!(3));
    assert_eq!(
        state["enablements"].as_array().unwrap()[0]["state"],
        json!("disabled")
    );

    // The retry returns the stored identical result.
    let first = daemon.request_raw(&disable).unwrap();
    let second = daemon.request_raw(&disable).unwrap();
    assert_eq!(first, second);
    let parsed: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(parsed["revision"], json!(3), "no second freeze");
    let (bindings, active, owning) = assert_store_is_coherent(&bench.db());
    assert_eq!((bindings, active, owning), (1, 0, 0));
}
