//! K2 slice 2 — the `byom_subordinate` budget bridge (byom §11.4, §16.6
//! item 4; family contract L31–L33; the machine of
//! `byom/spec/descriptors/subordinate-reservation.json`).
//!
//! | property | proof |
//! |---|---|
//! | never above parent (`NeverAboveParent`) | `a_subordinate_reservation_is_never_above_its_byom_parent` |
//! | idempotent create (`CreateOnce`) | `the_reservation_is_created_once_per_stable_key` |
//! | conservation and `SettleOnce` | `settlement_is_metered_conserved_and_applied_once` |
//! | `uncertain` never releases on a timeout | `an_uncertain_reservation_releases_only_through_the_r38_seat` |
//! | a denial charges nothing | `a_definite_denial_releases_only_unspent_capacity` |
//!
//! Recorded deviation: the byom kernel initiates this saga at
//! `resource_allocate`, which byomd does not serve yet — and §16.6 item 4
//! gives it no BPP or KCP operation at all, deliberately (Kovee platform
//! capacity lives under another owner and is never part of the byom
//! transaction). So the parent reservation set is supplied here as byom
//! would supply it, and everything Kovee owns — the reservation record, the
//! cross-member checks, and the settlement arithmetic — is real.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::tmp;
use kovee_byom::budget::{Item, Meter, ReservationState};
use kovee_core::problem::ProblemKind;
use kovee_store::Store;
use koveed::budget::{self, Parent};

const REALM: &str = "realm-personal";

fn store(tag: &str) -> Store {
    let base = tmp(tag);
    let mut store = Store::open(&base.join("kovee.sqlite3")).unwrap();
    store.bootstrap(0).unwrap();
    budget::doc_seam(&mut store);
    store
}

fn parent(stable_key: &str) -> Parent {
    Parent {
        byom_reservation_set_ref: "brs-1".to_owned(),
        byom_reservation_set_revision: 2,
        external_budget_bridge_ref: "ebb-1".to_owned(),
        stable_external_reservation_key: stable_key.to_owned(),
        society_ref: "soc-1".to_owned(),
        society_recovery_epoch: 0,
    }
}

/// One subordinate item pinned to its exact parent §11.4 reservation item.
fn item(amount: u64, parent_worst_case: u64) -> Item {
    Item {
        kovee_account_ref: "kovee-acct-1".to_owned(),
        dimension: "unit".to_owned(),
        unit: "call".to_owned(),
        amount,
        parent_account_ref: "byom-acct-1".to_owned(),
        parent_account_revision: 3,
        parent_dimension: "unit".to_owned(),
        parent_unit: "call".to_owned(),
        parent_worst_case_amount: parent_worst_case,
        parent_delegation_ref: None,
    }
}

// -------------------------------------------------------- never above parent ----

#[test]
fn a_subordinate_reservation_is_never_above_its_byom_parent() {
    let mut store = store("k2-budget-parent");

    // Narrowing is the whole point: the subordinate side may reserve LESS.
    let narrowed = budget::reserve(
        &mut store,
        REALM,
        &parent("stable-narrow"),
        vec![item(40, 100)],
        0,
    )
    .unwrap();
    assert_eq!(narrowed.state, ReservationState::Confirmed);
    assert_eq!(narrowed.reserved("unit"), 40);
    assert_eq!(narrowed.parent_ceiling("unit"), 100);
    assert_eq!(narrowed.reservation_class, "byom_subordinate");
    // Exactly at parent is admissible; above it never is.
    budget::reserve(
        &mut store,
        REALM,
        &parent("stable-exact"),
        vec![item(100, 100)],
        0,
    )
    .unwrap();
    let over = budget::reserve(
        &mut store,
        REALM,
        &parent("stable-over"),
        vec![item(101, 100)],
        0,
    )
    .unwrap_err();
    assert_eq!(over.kind, ProblemKind::BudgetExceeded);
    assert!(
        over.detail
            .as_ref()
            .unwrap()
            .contains("never reserve above parent_worst_case_amount"),
        "{over:?}"
    );
    // Nothing was committed for the refused key: the check precedes the row.
    assert!(budget::read(store.conn(), "stable-over").unwrap().is_none());

    // And it may not RESHAPE the dimension either — narrowing or denying
    // are the only two moves, never a parallel charge under another axis.
    let mut reshaped = item(10, 100);
    reshaped.dimension = "tokens".to_owned();
    let refused = budget::reserve(
        &mut store,
        REALM,
        &parent("stable-reshape"),
        vec![reshaped],
        0,
    )
    .unwrap_err();
    assert_eq!(refused.kind, ProblemKind::BudgetExceeded);
    assert!(
        refused.detail.as_ref().unwrap().contains("reshape"),
        "{refused:?}"
    );
}

// ------------------------------------------------------------ CreateOnce ----

#[test]
fn the_reservation_is_created_once_per_stable_key() {
    let mut store = store("k2-budget-once");
    let parent = parent("stable-1");
    let first = budget::reserve(&mut store, REALM, &parent, vec![item(40, 100)], 0).unwrap();
    // An exact retry returns the IDENTICAL reservation, never a second row.
    let again = budget::reserve(&mut store, REALM, &parent, vec![item(40, 100)], 1).unwrap();
    assert_eq!(
        first.subordinate_reservation_ref,
        again.subordinate_reservation_ref
    );
    assert_eq!(first.digest, again.digest);
    assert_eq!(first, again);
    // Even a DIFFERENT ask under the same stable key returns the stored
    // one: the key is the identity of the request, not a hint.
    let narrower = budget::reserve(&mut store, REALM, &parent, vec![item(5, 100)], 2).unwrap();
    assert_eq!(narrower.reserved("unit"), 40);

    // The bridge back-reference is what the episode binding pins.
    let (reference, digest) = budget::reservation_of_bridge(store.conn(), "ebb-1")
        .unwrap()
        .expect("the bridge names its subordinate reservation");
    assert_eq!(reference, first.subordinate_reservation_ref);
    assert_eq!(digest, first.digest);
}

// ------------------------------------------------------- settle and conserve ----

#[test]
fn settlement_is_metered_conserved_and_applied_once() {
    let mut store = store("k2-budget-settle");
    let reservation = budget::reserve(
        &mut store,
        REALM,
        &parent("stable-1"),
        vec![item(40, 100)],
        0,
    )
    .unwrap();
    let reference = reservation.subordinate_reservation_ref.clone();

    // A worker report is EVIDENCE, never a meter.
    let refused =
        budget::settle(&mut store, &reference, "unit", 10, Meter::Report, "us-1", 1).unwrap_err();
    assert_eq!(refused.kind, ProblemKind::BudgetExceeded);
    assert!(
        refused
            .detail
            .as_ref()
            .unwrap()
            .contains("evidence, not meters"),
        "{refused:?}"
    );

    // A charge above the reserved amount is refused before anything moves.
    assert_eq!(
        budget::settle(
            &mut store,
            &reference,
            "unit",
            41,
            Meter::TrustedBroker,
            "us-1",
            1
        )
        .unwrap_err()
        .kind,
        ProblemKind::BudgetExceeded
    );

    // A measured settlement from a trusted meter: conservation holds —
    // charged plus the remainder returning to the parent bucket is exactly
    // what was reserved.
    let settled = budget::settle(
        &mut store,
        &reference,
        "unit",
        10,
        Meter::TrustedBroker,
        "us-1",
        2,
    )
    .unwrap();
    assert_eq!(settled.charged, 10);
    assert_eq!(settled.remainder, 30);
    assert_eq!(settled.charged + settled.remainder, 40);

    // SettleOnce: a repeat under the same key re-serves the numbers rather
    // than charging again.
    let repeat = budget::settle(
        &mut store,
        &reference,
        "unit",
        25,
        Meter::VerifiedProviderReceipt,
        "us-1",
        3,
    )
    .unwrap();
    assert_eq!(repeat.charged, 10, "a settled reservation never re-charges");
    let stored = budget::read(store.conn(), "stable-1").unwrap().unwrap();
    assert_eq!(stored.state, ReservationState::Settled);
    assert_eq!(stored.usage_settlement_ref.as_deref(), Some("us-1"));
    stored.check().unwrap();

    // Release hands back exactly the demonstrably unspent remainder.
    let released = budget::release(&mut store, &reference, 4).unwrap();
    assert_eq!(released, 30);
    let stored = budget::read(store.conn(), "stable-1").unwrap().unwrap();
    assert_eq!(stored.state, ReservationState::Released);
}

// --------------------------------------------------------------- uncertain ----

#[test]
fn an_uncertain_reservation_releases_only_through_the_r38_seat() {
    let mut store = store("k2-budget-uncertain");
    let reservation = budget::reserve(
        &mut store,
        REALM,
        &parent("stable-1"),
        vec![item(40, 100)],
        0,
    )
    .unwrap();
    let reference = reservation.subordinate_reservation_ref.clone();
    budget::mark_uncertain(&mut store, REALM, "stable-1", "the reply was lost", 1).unwrap();
    let stored = budget::read(store.conn(), "stable-1").unwrap().unwrap();
    assert_eq!(stored.state, ReservationState::Uncertain);

    // No settlement from uncertain: only a CONFIRMED reservation settles.
    assert_eq!(
        budget::settle(
            &mut store,
            &reference,
            "unit",
            10,
            Meter::TrustedBroker,
            "us-1",
            2
        )
        .unwrap_err()
        .kind,
        ProblemKind::Forbidden
    );

    // And no ordinary release either: the byom parent stays reserved and
    // spend stays blocked. Guessing is not a transition.
    let refused = budget::release(&mut store, &reference, 3).unwrap_err();
    assert_eq!(refused.kind, ProblemKind::Ambiguous);
    assert!(
        refused.detail.as_ref().unwrap().contains("never a timeout"),
        "{refused:?}"
    );
    assert_eq!(
        budget::read(store.conn(), "stable-1")
            .unwrap()
            .unwrap()
            .state,
        ReservationState::Uncertain,
        "an uncertain reservation must not drift out of uncertain"
    );

    // The R38 seat needs a FRESH challenge for an ambiguous release.
    let stale = budget::reconcile_uncertain(&mut store, &reference, "dec-1", false, 4).unwrap_err();
    assert_eq!(stale.kind, ProblemKind::AuthorizationStale);
    // With one, the governance decision releases the unspent quantity.
    let released = budget::reconcile_uncertain(&mut store, &reference, "dec-1", true, 5).unwrap();
    assert_eq!(released, 40);
    assert_eq!(
        budget::read(store.conn(), "stable-1")
            .unwrap()
            .unwrap()
            .state,
        ReservationState::Released
    );
}

// ------------------------------------------------------------------- denial ----

#[test]
fn a_definite_denial_releases_only_unspent_capacity() {
    let mut store = store("k2-budget-deny");
    let parent = parent("stable-1");
    let reservation = budget::reserve(&mut store, REALM, &parent, vec![item(40, 100)], 0).unwrap();
    budget::deny(&mut store, REALM, &parent, "no local capacity", 1).unwrap();
    let stored = budget::read(store.conn(), "stable-1").unwrap().unwrap();
    assert_eq!(stored.state, ReservationState::Denied);
    // Nothing was ever charged, so the whole reservation returns.
    let released =
        budget::release(&mut store, &reservation.subordinate_reservation_ref, 2).unwrap();
    assert_eq!(released, 40);
    assert_eq!(
        budget::read(store.conn(), "stable-1")
            .unwrap()
            .unwrap()
            .state,
        ReservationState::Released
    );
}
