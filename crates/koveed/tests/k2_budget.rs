//! K2 slice 2 — the `byom_subordinate` budget bridge (byom §11.4, §16.6
//! item 4; family contract L31–L33; the machine of
//! `byom/spec/descriptors/subordinate-reservation.json`) and Kovee's own
//! **capacity ledger**.
//!
//! | property | proof |
//! |---|---|
//! | never above parent (`NeverAboveParent`) | `a_subordinate_reservation_is_never_above_its_byom_parent` |
//! | idempotent create (`CreateOnce`) | `the_reservation_is_created_once_per_stable_key` |
//! | conservation and `SettleOnce` | `settlement_is_metered_conserved_and_applied_once` |
//! | `uncertain` never releases on a timeout | `an_uncertain_reservation_releases_only_through_the_r38_seat` |
//! | a denial charges nothing | `a_definite_denial_releases_only_unspent_capacity` |
//! | the ACCOUNT ledger, not row arithmetic (R3-U03) | `the_capacity_ledger_conserves_across_every_transition` |
//! | child rollup (R3-U03) | `capacity_delegated_to_a_child_rolls_back_up_unspent` |
//! | the two-sided saga (R3-U01/U02) | `settlement_is_a_two_sided_saga_capped_locally_first` |
//! | the saga record's own mechanics | `the_durable_saga_record_applies_only_what_the_peer_answers` |
//! | duplicate parent-item pins (R3-U04) | `duplicate_parent_item_pins_cannot_amplify_the_parent` |
//! | the verified parent fragment (R3-L02) | `the_parent_comes_only_from_byoms_verified_fragment` |
//!
//! The crash BETWEEN the two sides (R3-U02) is not provable here: a stub peer
//! cannot show that production reconciliation exists. It is locked in
//! `k2_episode_live`, against the real `byomd` and the real `koveed` binary.
//!
//! Recorded deviation: the byom kernel initiates this saga at
//! `resource_allocate`, and §16.6 item 4 gives it no BPP or KCP operation at
//! all, deliberately (Kovee platform capacity lives under another owner and
//! is never part of the byom transaction). So the parent-budget FRAGMENT is
//! composed here the way byom composes it — with byom's own `$domain` tags,
//! so a mismatch would be a real disagreement — and everything Kovee owns
//! (the reservation record, the cross-member checks, the ledger, and the
//! settlement saga) is real.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::tmp;
use kovee_byom::budget::{Item, Meter, ReservationState};
use kovee_core::problem::ProblemKind;
use kovee_store::Store;
use koveed::budget::{self, Parent, RemoteSettlement, SagaPhase};
use serde_json::{json, Value};

const REALM: &str = "realm-personal";
const ACCOUNT: &str = "kovee-capacity-realm-personal";
const CEILING: u64 = 1_000;

fn store(tag: &str) -> Store {
    let base = tmp(tag);
    let mut store = Store::open(&base.join("kovee.sqlite3")).unwrap();
    store.bootstrap(0).unwrap();
    budget::doc_seam(&mut store);
    budget::grant_capacity(&mut store, REALM, "unit", "call", CEILING, 0).unwrap();
    store
}

/// One parent item, exactly as byom publishes them in the fragment.
fn parent_item(worst_case: u64, revision: u64) -> Value {
    json!({
        "account_ref": "byom-acct-1",
        "account_revision": revision,
        "dimension": "unit",
        "unit": "call",
        "worst_case_amount": worst_case,
    })
}

/// byom's frozen `portable_public` parent-budget fragment, verified.
fn parent_with(stable_key: &str, items: Value) -> Parent {
    budget::verify_parent_fragment(
        &budget::doc_fragment(
            "brs-1",
            2,
            &format!("ebb-{stable_key}"),
            1,
            stable_key,
            items,
        ),
        "soc-1",
        0,
    )
    .unwrap()
}

fn parent(stable_key: &str) -> Parent {
    parent_with(stable_key, json!([parent_item(100, 3)]))
}

/// One subordinate item pinned to the fragment's parent item.
fn item(amount: u64, parent_worst_case: u64) -> Item {
    Item {
        kovee_account_ref: ACCOUNT.to_owned(),
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

fn account(store: &Store) -> koveed::budget::Account {
    budget::account(store.conn(), ACCOUNT, "unit")
        .unwrap()
        .expect("the realm capacity account")
}

/// Runs the whole saga against a peer that agrees — the shape every
/// production call site uses.
fn settle_with_peer(
    store: &mut Store,
    reservation_ref: &str,
    charge: u64,
    key: &str,
    now: i64,
) -> Result<kovee_byom::budget::Settlement, kovee_core::problem::Problem> {
    let pending = budget::settle_begin(
        store,
        reservation_ref,
        "unit",
        charge,
        Meter::TrustedBroker,
        key,
        now,
    )?;
    budget::settle_commit(store, &pending, Some("byom-us-1"), charge, now)
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
    // The LEDGER moved, which is what "reserved" now means.
    assert_eq!(
        (account(&store).remaining, account(&store).reserved),
        (960, 40)
    );

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
    // Nothing was committed for the refused key, and nothing was debited:
    // the check precedes the row AND the ledger move.
    assert!(budget::read(store.conn(), "stable-over").unwrap().is_none());
    assert_eq!(account(&store).reserved, 140);
    assert!(account(&store).conserves());

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
    // And the retry debited the ledger exactly ONCE.
    assert_eq!(account(&store).reserved, 40);
    assert!(account(&store).conserves());

    // The bridge back-reference is what the episode binding pins.
    let (reference, digest) = budget::reservation_of_bridge(store.conn(), "ebb-stable-1")
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

    // A worker report is EVIDENCE, never a meter — and the refusal happens
    // in step 1 of the saga, before any remote call.
    let refused = budget::settle_begin(
        &mut store,
        &reference,
        "unit",
        10,
        Meter::Report,
        "us-report",
        1,
    )
    .unwrap_err();
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
        budget::settle_begin(
            &mut store,
            &reference,
            "unit",
            41,
            Meter::TrustedBroker,
            "us-over",
            1
        )
        .unwrap_err()
        .kind,
        ProblemKind::BudgetExceeded
    );
    assert!(
        budget::saga_of(store.conn(), "us-over").unwrap().is_none(),
        "a locally refused settlement leaves no saga record at all"
    );

    // A measured settlement from a trusted meter: conservation holds —
    // charged plus the remainder returning to the parent bucket is exactly
    // what was reserved.
    let settled = settle_with_peer(&mut store, &reference, 10, "us-1", 2).unwrap();
    assert_eq!(settled.charged, 10);
    assert_eq!(settled.remainder, 30);
    assert_eq!(settled.charged + settled.remainder, 40);
    // And on the ACCOUNT, which is where conservation actually lives.
    let a = account(&store);
    assert_eq!((a.remaining, a.reserved, a.committed), (960, 30, 10));
    assert!(a.conserves());

    // SettleOnce: a second settlement of the same reservation is refused
    // rather than charging again.
    let repeat = budget::settle_begin(
        &mut store,
        &reference,
        "unit",
        25,
        Meter::VerifiedProviderReceipt,
        "us-2",
        3,
    )
    .unwrap_err();
    assert_eq!(repeat.kind, ProblemKind::Forbidden);
    assert!(repeat.detail.as_ref().unwrap().contains("SettleOnce"));
    // The exact retry under the SAME stable key re-serves the stored numbers.
    let replay = settle_with_peer(&mut store, &reference, 10, "us-1", 3).unwrap();
    assert_eq!(replay.charged, 10, "a settled reservation never re-charges");
    assert_eq!(account(&store).committed, 10);

    let stored = budget::read(store.conn(), "stable-1").unwrap().unwrap();
    assert_eq!(stored.state, ReservationState::Settled);
    assert_eq!(stored.usage_settlement_ref.as_deref(), Some("us-1"));
    stored.check().unwrap();

    // Release hands back exactly the demonstrably unspent remainder — into
    // the ledger's `remaining`, in the same accounting step.
    let released = budget::release(&mut store, &reference, 4).unwrap();
    assert_eq!(released, 30);
    let a = account(&store);
    assert_eq!((a.remaining, a.reserved, a.committed), (990, 0, 10));
    assert_eq!(a.ceiling, CEILING, "a settlement never moves the ceiling");
    assert!(a.conserves());
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
    // The quantity is PARKED, not returned: conservation still holds and
    // `remaining` did not grow.
    let a = account(&store);
    assert_eq!((a.remaining, a.reserved, a.uncertain), (960, 0, 40));
    assert!(a.conserves());

    // No settlement from uncertain: only a CONFIRMED reservation settles.
    assert_eq!(
        budget::settle_begin(
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
    assert_eq!(account(&store).uncertain, 40, "nor may the quantity drift");

    // The R38 seat needs a FRESH challenge for an ambiguous release.
    let stale = budget::reconcile_uncertain(&mut store, &reference, "dec-1", false, 4).unwrap_err();
    assert_eq!(stale.kind, ProblemKind::AuthorizationStale);
    assert_eq!(account(&store).uncertain, 40);
    // With one, the governance decision releases the unspent quantity — and
    // ONLY here does it return to `remaining`.
    let released = budget::reconcile_uncertain(&mut store, &reference, "dec-1", true, 5).unwrap();
    assert_eq!(released, 40);
    let a = account(&store);
    assert_eq!((a.remaining, a.uncertain), (CEILING, 0));
    assert!(a.conserves());
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
    // HeldIffOpen: a denial does not by itself unblock spend — the release
    // does, in one step.
    assert_eq!(account(&store).reserved, 40);
    let released =
        budget::release(&mut store, &reservation.subordinate_reservation_ref, 2).unwrap();
    assert_eq!(released, 40);
    let a = account(&store);
    assert_eq!((a.remaining, a.reserved, a.committed), (CEILING, 0, 0));
    assert!(a.conserves());
    assert_eq!(
        budget::read(store.conn(), "stable-1")
            .unwrap()
            .unwrap()
            .state,
        ReservationState::Released
    );
}

// ================================================== R3 probes: the ledger ==

/// **R3-U03, reproduced.** `kovee_account_ref` used to be a fabricated
/// string: nothing loaded it, nothing debited it, and the only durable
/// numbers were the reservation row's own `charged` / `released_lifetime`
/// audit scalars — so a "conservation" assertion could only compare a row
/// against itself.
///
/// The probe: assert the ACCOUNT counters and the ceiling at every step, and
/// require the ledger to REFUSE what it cannot back.
#[test]
fn the_capacity_ledger_conserves_across_every_transition() {
    let mut store = store("k2-budget-ledger");
    let base = account(&store);
    assert_eq!(
        (base.ceiling, base.remaining, base.reserved, base.committed),
        (CEILING, CEILING, 0, 0)
    );
    assert!(base.conserves());

    // A reservation the ledger cannot cover is REFUSED — narrowing is a
    // constraint, not a comment. The fragment's parent is 4_000, but the
    // account has 1_000.
    let big = parent_with("stable-big", json!([parent_item(4_000, 3)]));
    let items = budget::subordinate_items(store.conn(), REALM, &big).unwrap();
    assert_eq!(
        items[0].amount, CEILING,
        "the narrowing is capped by what the LEDGER really has, not by half \
         the parent (which would be 2_000)"
    );
    let over = budget::reserve(
        &mut store,
        REALM,
        &big,
        vec![Item {
            amount: CEILING + 1,
            ..items[0].clone()
        }],
        0,
    )
    .unwrap_err();
    assert_eq!(over.kind, ProblemKind::BudgetExceeded);
    assert_eq!(account(&store), base, "a refused reserve moves nothing");

    // reserve -> settle -> release, asserting the account each time.
    let r = budget::reserve(&mut store, REALM, &parent("s1"), vec![item(100, 100)], 0).unwrap();
    let reference = r.subordinate_reservation_ref.clone();
    let a = account(&store);
    assert_eq!((a.remaining, a.reserved), (900, 100));
    assert!(a.conserves());

    settle_with_peer(&mut store, &reference, 60, "us-1", 1).unwrap();
    let a = account(&store);
    assert_eq!((a.remaining, a.reserved, a.committed), (900, 40, 60));
    assert!(a.conserves());

    budget::release(&mut store, &reference, 2).unwrap();
    let a = account(&store);
    assert_eq!((a.remaining, a.reserved, a.committed), (940, 0, 60));
    assert_eq!(a.ceiling, CEILING);
    assert!(a.conserves());

    // A grant RAISES the ceiling and lands in `remaining`; it never
    // rewrites what was already spent.
    let raised = budget::grant_capacity(&mut store, REALM, "unit", "call", 2_000, 3).unwrap();
    assert_eq!(
        (raised.ceiling, raised.remaining, raised.committed),
        (2_000, 1_940, 60)
    );
    assert!(raised.conserves());
    // And it is monotonic: a lower grant is a no-op, not a silent shrink.
    let lower = budget::grant_capacity(&mut store, REALM, "unit", "call", 10, 4).unwrap();
    assert_eq!(lower.ceiling, 2_000);
    // A grant may not requantify the account either.
    assert_eq!(
        budget::grant_capacity(&mut store, REALM, "unit", "token", 3_000, 5)
            .unwrap_err()
            .kind,
        ProblemKind::BudgetExceeded
    );
}

/// **R3-U03, the child-rollup transition.** Delegated capacity leaves the
/// parent's `remaining` for `delegated_to_children`, so conservation holds on
/// both rows and the parent cannot spend what it delegated; the unspent part
/// rolls back up, and an UNRESOLVED child does not roll up at all.
#[test]
fn capacity_delegated_to_a_child_rolls_back_up_unspent() {
    let mut store = store("k2-budget-rollup");
    let child = "kovee-capacity-child-1";

    let (parent_row, child_row) =
        budget::delegate_to_child(&mut store, REALM, "unit", child, 400, 0).unwrap();
    assert_eq!(
        (parent_row.remaining, parent_row.delegated_to_children),
        (600, 400)
    );
    assert_eq!((child_row.ceiling, child_row.remaining), (400, 400));
    assert!(parent_row.conserves() && child_row.conserves());

    // The child spends some of it through a reservation of its own.
    let child_parent = parent_with("stable-child", json!([parent_item(300, 3)]));
    let mut child_item = item(150, 300);
    child_item.kovee_account_ref = child.to_owned();
    let r = budget::reserve(&mut store, REALM, &child_parent, vec![child_item], 0).unwrap();
    let reference = r.subordinate_reservation_ref.clone();
    // An unresolved child cannot roll up: an unknown quantity never returns.
    assert_eq!(
        budget::rollup_child(&mut store, REALM, "unit", child, 1)
            .unwrap_err()
            .kind,
        ProblemKind::Ambiguous
    );

    settle_with_peer(&mut store, &reference, 100, "us-child", 1).unwrap();
    budget::release(&mut store, &reference, 2).unwrap();
    let (parent_row, child_row) =
        budget::rollup_child(&mut store, REALM, "unit", child, 3).unwrap();
    // The unspent 300 came back; the 100 the child really spent stays
    // delegated, and both rows still conserve.
    assert_eq!(
        (parent_row.remaining, parent_row.delegated_to_children),
        (900, 100)
    );
    assert_eq!(
        (child_row.ceiling, child_row.remaining, child_row.committed),
        (100, 0, 100)
    );
    assert!(parent_row.conserves() && child_row.conserves());
    assert_eq!(parent_row.ceiling, CEILING);
}

// ============================================== R3 probes: the saga (U01/U02) ==

/// **R3-U01, reproduced.** The probe: byom's parent is 256, Kovee narrows to
/// 128, and a charge of 200 is settled. The old order sent the charge to byom
/// FIRST and checked Kovee's own cap afterwards, so byom committed 200 while
/// Kovee answered `budget_exceeded` and stayed `confirmed` with `charged = 0`.
///
/// The local cap now precedes every remote call, and `subordinate + 1` — still
/// far below the parent — is refused with no saga record and no ledger move.
#[test]
fn settlement_is_a_two_sided_saga_capped_locally_first() {
    let mut store = store("k2-budget-saga");
    // The exact probe shape: parent 256, subordinate narrowed to 128.
    let parent = parent_with("stable-probe", json!([parent_item(256, 3)]));
    let items = budget::subordinate_items(store.conn(), REALM, &parent).unwrap();
    assert_eq!(items[0].amount, 128, "narrowed to half the 256 parent");
    let r = budget::reserve(&mut store, REALM, &parent, items, 0).unwrap();
    let reference = r.subordinate_reservation_ref.clone();
    let held = account(&store);
    assert_eq!((held.remaining, held.reserved), (CEILING - 128, 128));

    // THE PROBE: 200 units. Below the 256 parent, above the 128 confirmed
    // subordinate. It is refused HERE, in step 1, before a byte leaves.
    let over = budget::settle_begin(
        &mut store,
        &reference,
        "unit",
        200,
        Meter::TrustedBroker,
        "us-probe",
        1,
    )
    .unwrap_err();
    assert_eq!(over.kind, ProblemKind::BudgetExceeded);
    assert!(
        budget::saga_of(store.conn(), "us-probe").unwrap().is_none(),
        "nothing was recorded, so nothing was ever sent"
    );
    // `subordinate + 1 <= parent` — the exact boundary the finding named.
    assert_eq!(
        budget::settle_begin(
            &mut store,
            &reference,
            "unit",
            129,
            Meter::TrustedBroker,
            "us-boundary",
            1
        )
        .unwrap_err()
        .kind,
        ProblemKind::BudgetExceeded
    );
    assert_eq!(account(&store), held, "a refused settlement moves nothing");
    assert_eq!(
        budget::read(store.conn(), "stable-probe")
            .unwrap()
            .unwrap()
            .state,
        ReservationState::Confirmed
    );

    // The saga in order: step 1 records DURABLY before the remote half.
    let pending = budget::settle_begin(
        &mut store,
        &reference,
        "unit",
        128,
        Meter::TrustedBroker,
        "us-ok",
        2,
    )
    .unwrap();
    assert_eq!(pending.phase, SagaPhase::RemotePending);
    assert_eq!(
        budget::saga_of(store.conn(), "us-ok")
            .unwrap()
            .unwrap()
            .phase,
        SagaPhase::RemotePending,
        "the local record exists BEFORE the peer is called: that is what a \
         crash between the two sides leaves behind"
    );
    assert_eq!(account(&store), held, "step 1 charges nothing by itself");

    // A peer that claims MORE than this side capped is refused loudly rather
    // than adopted — the split-ledger condition itself.
    let split = budget::settle_commit(&mut store, &pending, Some("byom-us"), 200, 3).unwrap_err();
    assert_eq!(split.kind, ProblemKind::BudgetExceeded);
    assert_eq!(
        budget::saga_of(store.conn(), "us-ok")
            .unwrap()
            .unwrap()
            .phase,
        SagaPhase::Unknown
    );
    assert_eq!(account(&store), held, "and it applies nothing");

    // The agreeing peer: byom's own number, within the local cap.
    let settled = budget::settle_commit(&mut store, &pending, Some("byom-us"), 128, 4).unwrap();
    assert_eq!((settled.charged, settled.remainder), (128, 0));
    let a = account(&store);
    assert_eq!(
        (a.remaining, a.reserved, a.committed),
        (CEILING - 128, 0, 128)
    );
    assert!(a.conserves());
    assert_eq!(
        budget::saga_of(store.conn(), "us-ok")
            .unwrap()
            .unwrap()
            .phase,
        SagaPhase::Settled
    );

    // A CHANGED ask under the same stable settlement key is a mismatch, not
    // a second settlement.
    assert_eq!(
        budget::settle_begin(
            &mut store,
            &reference,
            "unit",
            10,
            Meter::TrustedBroker,
            "us-ok",
            5
        )
        .unwrap_err()
        .kind,
        ProblemKind::IdempotencyMismatch
    );
}

/// The saga RECORD's own mechanics, with a stub peer: a durable row survives a
/// reopen, an answered query applies exactly the peer's number, and an
/// unanswered one stays unresolved.
///
/// This is deliberately **not** the R3-U02 lock. Its "peer" is a closure, so it
/// cannot show that the production start-up sweep exists at all — the
/// confirmer deleted that entire invocation from `Daemon::new` and this test
/// stayed green. The lock is
/// `k2_episode_live::a_crash_between_the_two_sides_reconciles_to_byoms_truth`,
/// where the peer is the real `byomd` and the reconciler is the real `koveed`
/// binary.
#[test]
fn the_durable_saga_record_applies_only_what_the_peer_answers() {
    let base = tmp("k2-budget-crash");
    let path = base.join("kovee.sqlite3");
    let reference;
    {
        let mut store = Store::open(&path).unwrap();
        store.bootstrap(0).unwrap();
        budget::doc_seam(&mut store);
        budget::grant_capacity(&mut store, REALM, "unit", "call", CEILING, 0).unwrap();
        let r = budget::reserve(
            &mut store,
            REALM,
            &parent("stable-crash"),
            vec![item(44, 100)],
            0,
        )
        .unwrap();
        reference = r.subordinate_reservation_ref.clone();
        // Step 1 commits the durable local record...
        budget::settle_begin(
            &mut store,
            &reference,
            "unit",
            44,
            Meter::TrustedBroker,
            "kovee-model-settle-1",
            1,
        )
        .unwrap();
        // ...and the process dies HERE, after byom committed 44 and before
        // Kovee applied anything. This is exactly the R3 state.
        let a = budget::account(store.conn(), ACCOUNT, "unit")
            .unwrap()
            .unwrap();
        assert_eq!((a.reserved, a.committed), (44, 0));
    }

    // A fresh process over the same durable store.
    let mut store = Store::open(&path).unwrap();
    let unresolved = budget::unresolved_sagas(store.conn()).unwrap();
    assert_eq!(unresolved.len(), 1, "the crash left evidence, not silence");
    assert_eq!(unresolved[0].charge, 44);
    assert_eq!(unresolved[0].phase, SagaPhase::RemotePending);

    // The peer's recovery query surfaces byom's TRUTH: it really committed 44
    // under this stable settlement key.
    let mut asked = 0;
    let mut resolve = |_: &mut Store,
                       pending: &budget::Pending|
     -> Result<RemoteSettlement, kovee_core::problem::Problem> {
        asked += 1;
        assert_eq!(pending.stable_settlement_key, "kovee-model-settle-1");
        Ok(RemoteSettlement::Settled {
            settlement_ref: Some("byom-settle-1".to_owned()),
            charged: 44,
        })
    };
    let done = budget::reconcile_settlements(&mut store, 2, &mut resolve).unwrap();
    assert_eq!(asked, 1);
    assert_eq!((done.examined, done.settled, done.still_unknown), (1, 1, 0));

    // The two sides now agree, on the ACCOUNT and on the row.
    let a = account(&store);
    assert_eq!(
        (a.remaining, a.reserved, a.committed),
        (CEILING - 44, 0, 44)
    );
    assert!(a.conserves());
    let stored = budget::read(store.conn(), "stable-crash").unwrap().unwrap();
    assert_eq!(stored.state, ReservationState::Settled);
    assert_eq!(
        store
            .conn()
            .query_row(
                "SELECT charged FROM byom_subordinate_reservations
                 WHERE subordinate_reservation_ref = ?1",
                [&reference],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        44,
        "the exact defect: byom charged 44 while this counter stayed 0"
    );
    assert!(budget::unresolved_sagas(store.conn()).unwrap().is_empty());

    // A peer that cannot be asked leaves the record UNKNOWN — never settled,
    // never released. Guessing is not a transition.
    let r2 = budget::reserve(
        &mut store,
        REALM,
        &parent("stable-crash-2"),
        vec![item(10, 100)],
        3,
    )
    .unwrap();
    budget::settle_begin(
        &mut store,
        &r2.subordinate_reservation_ref,
        "unit",
        10,
        Meter::TrustedBroker,
        "kovee-model-settle-2",
        3,
    )
    .unwrap();
    let mut silent = |_: &mut Store,
                      _: &budget::Pending|
     -> Result<RemoteSettlement, kovee_core::problem::Problem> {
        Ok(RemoteSettlement::Unknown {
            detail: "the meter channel did not answer".to_owned(),
        })
    };
    let done = budget::reconcile_settlements(&mut store, 4, &mut silent).unwrap();
    assert_eq!((done.examined, done.settled, done.still_unknown), (1, 0, 1));
    assert_eq!(
        budget::read(store.conn(), "stable-crash-2")
            .unwrap()
            .unwrap()
            .state,
        ReservationState::Confirmed,
        "an unresolved settlement never advances the reservation"
    );
    assert_eq!(account(&store).reserved, 10);
    assert!(account(&store).conserves());
}

// ================================================ R3 probes: U04 and L02 ==

/// **R3-U04, reproduced.** The probe reported two 100-unit children against
/// ONE 100-unit parent item and both sides accepted it; Kovee summed the
/// duplicate parents and reported 200 of parent capacity.
#[test]
fn duplicate_parent_item_pins_cannot_amplify_the_parent() {
    let mut store = store("k2-budget-duplicate");
    let parent = parent("stable-dup");
    assert_eq!(parent.items.len(), 1, "one published parent item");
    assert_eq!(parent.ceiling("unit"), 100);

    // THE PROBE.
    let doubled = budget::reserve(
        &mut store,
        REALM,
        &parent,
        vec![item(100, 100), item(100, 100)],
        0,
    )
    .unwrap_err();
    assert_eq!(doubled.kind, ProblemKind::BudgetExceeded);
    assert!(
        doubled
            .detail
            .as_ref()
            .unwrap()
            .contains("pin the same parent"),
        "{doubled:?}"
    );
    assert!(budget::read(store.conn(), "stable-dup").unwrap().is_none());
    assert_eq!(account(&store).reserved, 0, "and nothing was debited");

    // A subordinate item claiming a parent item the fragment does not
    // publish is refused too — identity, not membership.
    let mut invented = item(10, 100);
    invented.parent_account_revision = 7;
    let refused = budget::reserve(&mut store, REALM, &parent, vec![invented], 0).unwrap_err();
    assert_eq!(refused.kind, ProblemKind::StaleRevision);
    assert!(
        refused.detail.as_ref().unwrap().contains("DISTINCT"),
        "{refused:?}"
    );

    // Two DISTINCT published parent items are a real 200 of parent capacity.
    let two = parent_with(
        "stable-two",
        json!([parent_item(100, 3), parent_item(100, 4)]),
    );
    let mut second = item(100, 100);
    second.parent_account_revision = 4;
    let ok = budget::reserve(&mut store, REALM, &two, vec![item(100, 100), second], 0).unwrap();
    assert_eq!(ok.reserved("unit"), 200);
    assert_eq!(ok.parent_ceiling("unit"), 200);
    assert_eq!(account(&store).reserved, 200);
    assert!(account(&store).conserves());
}

/// **R3-L02, reproduced against BYOM's OWN recorded fragment.**
///
/// The parent used to arrive as caller arguments and naming conventions, and
/// Kovee MINTED byom's reservation digest with its own governance key. The
/// fragment is now the only door, and — the part that was missing — the
/// fragment this test verifies is **byom's**, not one Kovee composed for
/// itself. The previous version called `budget::doc_fragment`, so Kovee
/// constructed and verified both sides: changing only Kovee's
/// `PARENT_BUDGET_TAG` left it green, because both halves moved together.
///
/// `crates/koveed/tests/vectors/byom-parent-budget-fragment.json` is a recording of
/// byom's own producer (`byomd::episode_ops::parent_budget_fragment`), pinned
/// by the same digest constant byom's
/// `the_published_fragment_reproduces_the_pinned_family_vector` names. Kovee
/// only consumes it. A domain tag, member set or canonicalization that no
/// longer agrees with byom's is now a machine-visible disagreement on
/// whichever side moved.
#[test]
fn the_parent_comes_only_from_byoms_verified_fragment() {
    const VECTOR: &str = include_str!("vectors/byom-parent-budget-fragment.json");
    /// The one constant both repositories name literally.
    const PINNED_DIGEST: &str = "9ecda50f25f5a1f4da5e264f175c2bfcfade42fc3e9ca3ebdacfc52bcf819398";

    let mut store = store("k2-budget-fragment");
    let vector: Value = serde_json::from_str(VECTOR).expect("the pinned byom vector parses");
    assert_eq!(
        vector["owner"], "byom",
        "this vector is byom's, not Kovee's"
    );
    let fragment = vector["fragment"].clone();
    assert_eq!(fragment["digest"]["value_hex"], PINNED_DIGEST);

    // BYOM's recorded fragment verifies on this side, with no help from any
    // Kovee-side producer. This is the assertion the confirmer's independent
    // test made and the shipped one did not.
    let byoms = budget::verify_parent_fragment(&fragment, "soc-1", 0)
        .expect("byom's own recorded fragment verifies against Kovee's verifier");
    let inputs = &vector["inputs"];
    assert_eq!(
        byoms.byom_reservation_set_ref,
        inputs["byom_budget_reservation_set_ref"].as_str().unwrap()
    );
    assert_eq!(
        byoms.byom_reservation_set_revision,
        inputs["byom_budget_reservation_set_revision"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        byoms.external_budget_bridge_ref,
        inputs["external_budget_bridge_ref"].as_str().unwrap()
    );
    assert_eq!(
        byoms.stable_external_reservation_key,
        inputs["stable_external_reservation_key"].as_str().unwrap()
    );
    assert_eq!(
        byoms.ceiling("unit"),
        inputs["items"][0]["worst_case_amount"].as_u64().unwrap()
    );
    assert_eq!(byoms.fragment_digest.value_hex, PINNED_DIGEST);
    // Tampering with byom's recorded bytes is refused for the same reason.
    let mut tampered_vector = fragment.clone();
    tampered_vector["items"][0]["worst_case_amount"] = json!(4_096);
    assert_eq!(
        budget::verify_parent_fragment(&tampered_vector, "soc-1", 0)
            .unwrap_err()
            .kind,
        ProblemKind::StaleRevision
    );

    // The rest of the negatives run over a locally composed fragment, because
    // they need members byom would never emit (an extra one, a missing one).
    let items = json!([parent_item(256, 3)]);
    let fragment = budget::doc_fragment("brs-9", 4, "ebb-9", 2, "stable-frag", items.clone());

    // The frozen member set, exactly.
    let mut members: Vec<&str> = fragment
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|k| *k != "digest")
        .collect();
    members.sort_unstable();
    let mut frozen = budget::PARENT_BUDGET_FIELDS.to_vec();
    frozen.sort_unstable();
    assert_eq!(members, frozen);

    let parent = budget::verify_parent_fragment(&fragment, "soc-1", 0).unwrap();
    assert_eq!(parent.byom_reservation_set_ref, "brs-9");
    assert_eq!(parent.byom_reservation_set_revision, 4);
    assert_eq!(parent.external_budget_bridge_ref, "ebb-9");
    assert_eq!(parent.external_budget_bridge_revision, 2);
    assert_eq!(parent.stable_external_reservation_key, "stable-frag");
    assert_eq!(parent.ceiling("unit"), 256);
    assert_eq!(parent.byom_reservation_set_digest.class, "portable_public");

    // A TAMPERED fragment does not verify: raising the published parent worst
    // case while keeping the digest of the original bytes is exactly the
    // caller-supplied parent fact this fix removes.
    let mut tampered = fragment.clone();
    tampered["items"][0]["worst_case_amount"] = json!(4_096);
    let refused = budget::verify_parent_fragment(&tampered, "soc-1", 0).unwrap_err();
    assert_eq!(refused.kind, ProblemKind::StaleRevision);
    assert!(
        refused.detail.as_ref().unwrap().contains("re-derive"),
        "{refused:?}"
    );
    // So does a fragment with an extra member, and one with a missing one.
    let mut widened = fragment.clone();
    widened["parent_amount"] = json!(4_096);
    assert_eq!(
        budget::verify_parent_fragment(&widened, "soc-1", 0)
            .unwrap_err()
            .kind,
        ProblemKind::StaleRevision
    );
    let mut narrowed = fragment.clone();
    narrowed.as_object_mut().unwrap().remove("items");
    assert!(budget::verify_parent_fragment(&narrowed, "soc-1", 0).is_err());
    // And a tampered nested SET digest, which is the value Kovee used to mint
    // for itself under its own key.
    let mut faked = fragment.clone();
    faked["byom_budget_reservation_set_digest"]["value_hex"] = json!("f".repeat(64));
    assert!(budget::verify_parent_fragment(&faked, "soc-1", 0).is_err());

    // The reservation stores BYOM's verified digest, never a minted one, and
    // keeps the exact bytes it verified.
    let sub = budget::subordinate_items(store.conn(), REALM, &parent).unwrap();
    let r = budget::reserve(&mut store, REALM, &parent, sub, 0).unwrap();
    assert_eq!(
        r.byom_reservation_set_digest, parent.byom_reservation_set_digest,
        "the stored byom digest is byom's own, verified — not one Kovee HMAC'd \
         under its own governance scope key"
    );
    let (stored, digest) =
        budget::stored_parent_fragment(store.conn(), &r.subordinate_reservation_ref)
            .unwrap()
            .expect("the verified fragment is kept for audit");
    assert_eq!(digest, parent.fragment_digest);
    assert_eq!(stored["items"], items);
    // The account on the item is the LEDGER's row, not a fabricated name.
    assert_eq!(r.items[0].kovee_account_ref, ACCOUNT);
    assert!(budget::account(store.conn(), ACCOUNT, "unit")
        .unwrap()
        .is_some());
}
