//! The `byom_subordinate` reservation bridge (byom §11.4, §16.6 item 4):
//! the saga Kovee runs against byom's PARENT reservation, never above it,
//! created once per stable key, and settled only from a trusted meter.
//!
//! What you write:
//! ```
//! # use koveed::budget::*;
//! # use kovee_byom::budget::{Item, Meter};
//! # let mut store = kovee_store::Store::open_in_memory().unwrap();
//! # store.bootstrap(0).unwrap();
//! # let parent = Parent {
//! #     byom_reservation_set_ref: "brs-1".into(), byom_reservation_set_revision: 2,
//! #     external_budget_bridge_ref: "ebb-1".into(),
//! #     stable_external_reservation_key: "stable-1".into(),
//! #     society_ref: "soc-1".into(), society_recovery_epoch: 0,
//! # };
//! # let items = vec![Item {
//! #     kovee_account_ref: "acct-1".into(), dimension: "unit".into(), unit: "call".into(),
//! #     amount: 40, parent_account_ref: "byom-acct-1".into(), parent_account_revision: 3,
//! #     parent_dimension: "unit".into(), parent_unit: "call".into(),
//! #     parent_worst_case_amount: 100, parent_delegation_ref: None,
//! # }];
//! # koveed::budget::doc_seam(&mut store);
//! // Reserve (idempotent over the stable key), then settle from a meter.
//! let first = reserve(&mut store, "realm-personal", &parent, items.clone(), 0).unwrap();
//! let again = reserve(&mut store, "realm-personal", &parent, items, 0).unwrap();
//! assert_eq!(first.subordinate_reservation_ref, again.subordinate_reservation_ref);
//! let settled = settle(&mut store, &first.subordinate_reservation_ref, "unit", 10,
//!                      Meter::TrustedBroker, "us-1", 0).unwrap();
//! // Conservation: the charge plus what returns to the parent bucket is
//! // exactly what was reserved.
//! assert_eq!(settled.charged + settled.remainder, 40);
//! ```
//!
//! Plumbing worth knowing: the states with NO release are the point.
//! `uncertain` never releases on a timeout — the byom parent stays
//! reserved, spend stays blocked, and only the R38 reconciliation seat
//! (with a fresh challenge) can let go. Guessing is not a transition.

use kovee_byom::budget::{
    settle as settle_amount, ByomSubordinateReservation, Item, Meter, ReservationState, Settlement,
    RESERVATION_CLASS,
};
use kovee_byom::records::GovernanceDigests;
use kovee_core::event::{
    EVENT_SUBORDINATE_CONFIRMED, EVENT_SUBORDINATE_DENIED, EVENT_SUBORDINATE_RELEASED,
    EVENT_SUBORDINATE_REQUESTED, EVENT_SUBORDINATE_SETTLED, EVENT_SUBORDINATE_UNCERTAIN,
};
use kovee_core::family::DigestRef;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::time::rfc3339_utc;
use kovee_store::{new_id, Applied, CommandScope, CrashHooks, NewEvent, Store, OWNER_ACTOR_REF};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::{json, Value};

use crate::governance::active_seam;
use crate::state::{internal, not_found, store_problem, DEFAULT_CLASSIFICATION};

const TAG_RESERVATION: &str = "kovee-byom-subordinate-reservation-v1";
const TAG_SETTLEMENT: &str = "kovee-usage-settlement-v1";

/// The byom-owned parent this bridge hangs off. Kovee never invents any of
/// it: the kernel initiates at `resource_allocate` and persists the
/// `ExternalBudgetBridge` with its stable key BEFORE queueing.
#[derive(Debug, Clone)]
pub struct Parent {
    pub byom_reservation_set_ref: String,
    pub byom_reservation_set_revision: u64,
    pub external_budget_bridge_ref: String,
    pub stable_external_reservation_key: String,
    pub society_ref: String,
    pub society_recovery_epoch: u64,
}

fn digests_of(conn: &Connection, realm: &str) -> Result<GovernanceDigests, Problem> {
    let key = kovee_store::governance_scope_key_of(conn).map_err(store_problem)?;
    Ok(GovernanceDigests::new(&key, realm))
}

fn refused(title: &str, detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::BudgetExceeded, title).with_detail(detail)
}

/// `subordinate_reserve_request` → `subordinate_reserved`: Kovee durably
/// commits the exact subordinate reservation (possibly NARROWED) and
/// returns its ref, revision, and digest for the bridge to persist.
///
/// CreateOnce: an exact retry under the same
/// `stable_external_reservation_key` returns the identical pending
/// reservation, never a second row.
pub fn reserve(
    store: &mut Store,
    realm: &str,
    parent: &Parent,
    items: Vec<Item>,
    now: i64,
) -> Result<ByomSubordinateReservation, Problem> {
    if let Some(existing) = read(store.conn(), &parent.stable_external_reservation_key)? {
        return Ok(existing);
    }
    // NeverAboveParent, checked before anything is committed: a
    // subordinate item may narrow or deny, never reshape or exceed.
    for (index, item) in items.iter().enumerate() {
        item.check().map_err(|e| {
            refused(
                "the subordinate reservation would exceed its byom parent",
                format!("item {index}: {e} (§11.4, family contract L32)"),
            )
        })?;
    }
    let digests = digests_of(store.conn(), realm)?;
    let (binding, mapping) = active_seam(store.conn(), realm)?.ok_or_else(|| {
        Problem::new(
            ProblemKind::Forbidden,
            "this realm has no active governed-work binding",
        )
        .with_detail("a budget bridge is pinned to the realm binding epoch (L2)")
    })?;
    if mapping.society_ref != parent.society_ref
        || mapping.society_recovery_epoch != parent.society_recovery_epoch
    {
        return Err(Problem::new(
            ProblemKind::StaleRevision,
            "the bridge names another Society or recovery epoch",
        ));
    }

    let mut record = ByomSubordinateReservation {
        subordinate_reservation_ref: new_id("ksr").map_err(store_problem)?,
        revision: 1,
        reservation_class: RESERVATION_CLASS.to_owned(),
        realm_ref: realm.to_owned(),
        realm_byom_binding_ref: binding.binding_ref.clone(),
        realm_byom_binding_epoch: binding.binding_epoch,
        society_ref: mapping.society_ref.clone(),
        society_recovery_epoch: mapping.society_recovery_epoch,
        byom_reservation_set_ref: parent.byom_reservation_set_ref.clone(),
        byom_reservation_set_revision: parent.byom_reservation_set_revision,
        byom_reservation_set_digest: digests
            .digest(
                TAG_RESERVATION,
                &json!({
                    "byom_reservation_set_ref": parent.byom_reservation_set_ref,
                    "revision": parent.byom_reservation_set_revision,
                }),
            )
            .map_err(|_| internal())?,
        external_budget_bridge_ref: parent.external_budget_bridge_ref.clone(),
        stable_external_reservation_key: parent.stable_external_reservation_key.clone(),
        items,
        state: ReservationState::Confirmed,
        usage_settlement_ref: None,
        usage_settlement_digest: None,
        created_at: rfc3339_utc(now),
        digest: DigestRef::portable_public("0".repeat(64)),
    };
    record.digest = self_digest(&digests, &record)?;
    record.check().map_err(|e| {
        refused(
            "the subordinate reservation is not admissible",
            e.to_string(),
        )
    })?;

    // `requested` is written first and confirmed in the same commit: the
    // saga row exists before the capacity is claimed, so a crash leaves a
    // reservation Kovee can query, never an unrecorded charge.
    insert(store, realm, &record, ReservationState::Requested, now)?;
    event(
        store,
        realm,
        &record,
        EVENT_SUBORDINATE_REQUESTED,
        json!({"state": "requested"}),
        now,
    )?;
    set_state(store.conn(), &record, ReservationState::Confirmed, now)?;
    event(
        store,
        realm,
        &record,
        EVENT_SUBORDINATE_CONFIRMED,
        json!({
            "state": "confirmed",
            "subordinate_reservation_ref": record.subordinate_reservation_ref,
            "revision": record.revision,
            "digest": record.digest,
        }),
        now,
    )?;
    Ok(record)
}

/// `subordinate_denied`: Kovee's DEFINITE denial. It releases only
/// demonstrably unspent byom reservations — nothing was ever charged.
pub fn deny(
    store: &mut Store,
    realm: &str,
    parent: &Parent,
    reason: &str,
    now: i64,
) -> Result<(), Problem> {
    let record =
        read(store.conn(), &parent.stable_external_reservation_key)?.ok_or_else(not_found)?;
    set_state(store.conn(), &record, ReservationState::Denied, now)?;
    event(
        store,
        realm,
        &record,
        EVENT_SUBORDINATE_DENIED,
        json!({"state": "denied", "reason": reason, "charged": 0}),
        now,
    )
}

/// `subordinate_outcome_unknown`: a recorded FACT, not a decision. The
/// byom reservation is NOT released and spend stays blocked until the
/// stable query or the R38 seat resolves it (family contract L33).
pub fn mark_uncertain(
    store: &mut Store,
    realm: &str,
    stable_key: &str,
    detail: &str,
    now: i64,
) -> Result<(), Problem> {
    let record = read(store.conn(), stable_key)?.ok_or_else(not_found)?;
    set_state(store.conn(), &record, ReservationState::Uncertain, now)?;
    event(
        store,
        realm,
        &record,
        EVENT_SUBORDINATE_UNCERTAIN,
        json!({
            "state": "uncertain",
            "detail": detail,
            "byom_reservation_released": false,
            "spend_blocked": true,
            "only_release": "R38 budget_reconcile with a fresh challenge",
        }),
        now,
    )
}

/// `subordinate_settle`: measured settlement from a trusted broker meter
/// or an independently verified provider receipt. Monotonic, stable-keyed,
/// applied once on both sides, and never above the reserved amount.
pub fn settle(
    store: &mut Store,
    reservation_ref: &str,
    dimension: &str,
    charge: u64,
    meter: Meter,
    usage_settlement_ref: &str,
    now: i64,
) -> Result<Settlement, Problem> {
    let (realm, mut record, previously_charged) = read_by_ref(store.conn(), reservation_ref)?;
    if record.state == ReservationState::Settled {
        // Applied once: a repeat under the same key re-serves the numbers
        // rather than charging again.
        return Ok(Settlement {
            charged: previously_charged,
            remainder: record
                .reserved(dimension)
                .saturating_sub(previously_charged),
        });
    }
    if record.state != ReservationState::Confirmed {
        return Err(Problem::new(
            ProblemKind::Forbidden,
            "only a confirmed reservation settles",
        )
        .with_detail(format!(
            "the reservation is {:?}; an uncertain one is released only by the R38 seat",
            record.state.as_str()
        )));
    }
    let settlement =
        settle_amount(&record, dimension, previously_charged, charge, meter).map_err(|e| {
            refused(
                "the settlement is not admissible",
                format!("{e} (§11.4: participant and worker reports are evidence, not meters)"),
            )
        })?;

    let digests = digests_of(store.conn(), &realm)?;
    record.revision += 1;
    record.state = ReservationState::Settled;
    record.usage_settlement_ref = Some(usage_settlement_ref.to_owned());
    record.usage_settlement_digest = Some(
        digests
            .digest(
                TAG_SETTLEMENT,
                &json!({
                    "usage_settlement_ref": usage_settlement_ref,
                    "stable_external_reservation_key": record.stable_external_reservation_key,
                    "dimension": dimension,
                    "charged": settlement.charged,
                }),
            )
            .map_err(|_| internal())?,
    );
    record.digest = self_digest(&digests, &record)?;
    record
        .check()
        .map_err(|e| refused("the settled reservation is not admissible", e.to_string()))?;
    store
        .conn()
        .execute(
            "UPDATE byom_subordinate_reservations
             SET state = ?2, revision = ?3, charged = ?4, released_lifetime = released_lifetime + ?5,
                 record = ?6, updated_at = ?7
             WHERE subordinate_reservation_ref = ?1",
            params![
                reservation_ref,
                ReservationState::Settled.as_str(),
                record.revision as i64,
                settlement.charged as i64,
                settlement.remainder as i64,
                serde_json::to_string(&record).map_err(|_| internal())?,
                rfc3339_utc(now),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    event(
        store,
        &realm,
        &record,
        EVENT_SUBORDINATE_SETTLED,
        json!({
            "state": "settled",
            "dimension": dimension,
            "charged": settlement.charged,
            "remainder": settlement.remainder,
            "reserved": record.reserved(dimension),
            "usage_settlement_ref": usage_settlement_ref,
        }),
        now,
    )?;
    Ok(settlement)
}

/// `subordinate_release`: saga completion. Releases only the demonstrably
/// unspent remainder; `released_lifetime` is a monotonic AUDIT counter,
/// never an available bucket.
pub fn release(store: &mut Store, reservation_ref: &str, now: i64) -> Result<u64, Problem> {
    let (realm, record, charged) = read_by_ref(store.conn(), reservation_ref)?;
    if record.state == ReservationState::Uncertain {
        return Err(Problem::new(
            ProblemKind::Ambiguous,
            "an uncertain reservation is released only by the R38 seat",
        )
        .with_detail(
            "family contract L33: the only release from `uncertain` is the exact budget_reconcile \
             governance seat with a fresh challenge — never a timeout",
        ));
    }
    let remainder = record
        .items
        .iter()
        .map(|i| i.amount)
        .sum::<u64>()
        .saturating_sub(charged);
    set_state(store.conn(), &record, ReservationState::Released, now)?;
    event(
        store,
        &realm,
        &record,
        EVENT_SUBORDINATE_RELEASED,
        json!({
            "state": "released",
            "charged": charged,
            "released_remainder": remainder,
            "released_lifetime_is_audit_counter": true,
        }),
        now,
    )?;
    Ok(remainder)
}

/// `budget_reconcile` (R38): the ONE release from `uncertain`, and it is a
/// governance decision with a fresh challenge — never a timeout.
pub fn reconcile_uncertain(
    store: &mut Store,
    reservation_ref: &str,
    decision_ref: &str,
    fresh_challenge: bool,
    now: i64,
) -> Result<u64, Problem> {
    let (realm, record, charged) = read_by_ref(store.conn(), reservation_ref)?;
    if record.state != ReservationState::Uncertain {
        return Err(Problem::new(
            ProblemKind::Forbidden,
            "budget_reconcile releases only an uncertain reservation",
        ));
    }
    if !fresh_challenge {
        return Err(Problem::new(
            ProblemKind::AuthorizationStale,
            "ambiguous release requires a fresh challenge",
        )
        .with_detail("R38: the exact reconciliation seat, freshly challenged"));
    }
    let remainder = record
        .items
        .iter()
        .map(|i| i.amount)
        .sum::<u64>()
        .saturating_sub(charged);
    set_state(store.conn(), &record, ReservationState::Released, now)?;
    event(
        store,
        &realm,
        &record,
        EVENT_SUBORDINATE_RELEASED,
        json!({
            "state": "released",
            "via": "budget_reconcile",
            "decision_ref": decision_ref,
            "released_remainder": remainder,
        }),
        now,
    )?;
    Ok(remainder)
}

// ------------------------------------------------------------ row access ----

fn self_digest(
    digests: &GovernanceDigests,
    record: &ByomSubordinateReservation,
) -> Result<DigestRef, Problem> {
    let mut projection = serde_json::to_value(record).unwrap_or(Value::Null);
    if let Some(map) = projection.as_object_mut() {
        map.remove("digest");
    }
    digests
        .digest(TAG_RESERVATION, &projection)
        .map_err(|_| internal())
}

fn insert(
    store: &mut Store,
    realm: &str,
    record: &ByomSubordinateReservation,
    state: ReservationState,
    now: i64,
) -> Result<(), Problem> {
    let at = rfc3339_utc(now);
    store
        .conn()
        .execute(
            "INSERT INTO byom_subordinate_reservations (subordinate_reservation_ref, realm_ref,
                 stable_external_reservation_key, external_budget_bridge_ref,
                 byom_reservation_set_ref, realm_byom_binding_ref, realm_byom_binding_epoch,
                 revision, state, charged, released_lifetime, record, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,0,?10,?11,?11)",
            params![
                record.subordinate_reservation_ref,
                realm,
                record.stable_external_reservation_key,
                record.external_budget_bridge_ref,
                record.byom_reservation_set_ref,
                record.realm_byom_binding_ref,
                record.realm_byom_binding_epoch as i64,
                record.revision as i64,
                state.as_str(),
                serde_json::to_string(record).map_err(|_| internal())?,
                at,
            ],
        )
        .map_err(|e| {
            if matches!(
                e,
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code: rusqlite::ErrorCode::ConstraintViolation,
                        ..
                    },
                    _
                )
            ) {
                Problem::new(
                    ProblemKind::IdempotencyMismatch,
                    "this stable external reservation key already holds a reservation",
                )
            } else {
                store_problem(e.into())
            }
        })?;
    Ok(())
}

fn set_state(
    conn: &Connection,
    record: &ByomSubordinateReservation,
    state: ReservationState,
    now: i64,
) -> Result<(), Problem> {
    let mut stored = record.clone();
    stored.state = state;
    conn.execute(
        "UPDATE byom_subordinate_reservations SET state = ?2, record = ?3, updated_at = ?4
         WHERE subordinate_reservation_ref = ?1",
        params![
            record.subordinate_reservation_ref,
            state.as_str(),
            serde_json::to_string(&stored).map_err(|_| internal())?,
            rfc3339_utc(now),
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

/// The reservation of one stable key, if any.
pub fn read(
    conn: &Connection,
    stable_key: &str,
) -> Result<Option<ByomSubordinateReservation>, Problem> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT record, state FROM byom_subordinate_reservations
             WHERE stable_external_reservation_key = ?1",
            [stable_key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    let Some((text, state)) = row else {
        return Ok(None);
    };
    let mut record: ByomSubordinateReservation =
        serde_json::from_str(&text).map_err(|_| internal())?;
    record.state = ReservationState::parse(&state).ok_or_else(internal)?;
    Ok(Some(record))
}

fn read_by_ref(
    conn: &Connection,
    reservation_ref: &str,
) -> Result<(String, ByomSubordinateReservation, u64), Problem> {
    let (realm, text, state, charged): (String, String, String, i64) = conn
        .query_row(
            "SELECT realm_ref, record, state, charged FROM byom_subordinate_reservations
             WHERE subordinate_reservation_ref = ?1",
            [reservation_ref],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?
        .ok_or_else(not_found)?;
    let mut record: ByomSubordinateReservation =
        serde_json::from_str(&text).map_err(|_| internal())?;
    record.state = ReservationState::parse(&state).ok_or_else(internal)?;
    Ok((realm, record, charged as u64))
}

/// The `(ref, digest)` pair an `ExternalBudgetBridge` persists for one
/// bridge row — what the episode binding pins (§11.4).
pub fn reservation_of_bridge(
    conn: &Connection,
    bridge_ref: &str,
) -> Result<Option<(String, DigestRef)>, Problem> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT subordinate_reservation_ref, record FROM byom_subordinate_reservations
             WHERE external_budget_bridge_ref = ?1",
            [bridge_ref],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    let Some((reference, text)) = row else {
        return Ok(None);
    };
    let record: ByomSubordinateReservation = serde_json::from_str(&text).map_err(|_| internal())?;
    Ok(Some((reference, record.digest)))
}

fn event(
    store: &mut Store,
    realm: &str,
    record: &ByomSubordinateReservation,
    event_type: &str,
    payload: Value,
    now: i64,
) -> Result<(), Problem> {
    let scope = CommandScope {
        actor_scope: format!("owner/{OWNER_ACTOR_REF}/{realm}"),
        operation: format!("subordinate_reservation_event:{event_type}"),
        idempotency_key: format!("{}:{event_type}", record.stable_external_reservation_key),
        request_digest: "0".repeat(64),
    };
    let reference = record.subordinate_reservation_ref.clone();
    let bridge = record.external_budget_bridge_ref.clone();
    let event_type = event_type.to_owned();
    let outcome = store.command_transaction(&scope, now, CrashHooks::NONE, move |txn| {
        txn.audit(
            "subordinate-reservation.transition",
            &format!("reservation={reference} event={event_type}"),
        );
        txn.append_event(NewEvent {
            stream_id: reference.clone(),
            project_id: None,
            actor_ref: Some(OWNER_ACTOR_REF.to_owned()),
            event_type: event_type.clone(),
            schema_ref: "schema:kovee-byom-subordinate-reservation-v1".to_owned(),
            resource_ref: reference.clone(),
            resource_revision: None,
            causation_ref: None,
            correlation_ref: bridge.clone(),
            classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
            payload: payload.clone(),
        })
        .map_err(store_problem)?;
        Ok(Applied {
            result: json!({"subordinate_reservation_ref": reference}),
            revision: None,
            event_cursor: None,
        })
    });
    crate::handlers::command_outcome_bytes(outcome)?;
    Ok(())
}

/// An ACTIVE governed-work seam inserted into `store`, for the doc example
/// and the budget tests — real seams come from the greenfield saga.
#[doc(hidden)]
#[allow(clippy::expect_used)]
pub fn doc_seam(store: &mut Store) {
    let binding = crate::credentials::doc_binding(store);
    store
        .conn()
        .execute(
            "INSERT INTO kovee_society_mappings (mapping_id, realm_ref, society_ref,
                 society_recovery_epoch, allowed_project_and_space_selectors,
                 classification_binding_ref, governance_owner_binding_ref,
                 governance_owner_binding_digest, status, revision, digest, binding_ref,
                 created_at)
             VALUES ('ksm-doc','realm-personal','soc-1',0,'[\"project:*\"]','class-1',?1,?2,
                 'active',1,?2,?1,'1970-01-01T00:00:00Z')",
            rusqlite::params![
                binding.binding_ref,
                serde_json::to_string(&binding.digest).unwrap_or_default(),
            ],
        )
        .expect("insert mapping fixture");
    store
        .conn()
        .execute(
            "INSERT INTO greenfield_enablements (enablement_id, realm_ref,
                 exact_scope_digest_hex, exact_scope_selector, binding_epoch, state,
                 society_ref, society_recovery_epoch, byom_endpoint_ref, endpoint_incarnation,
                 binding_ref, mapping_id, expected_owner_revision, subject_digest_hex,
                 dependency_digest_hex, result, created_at, updated_at)
             VALUES ('gfe-doc','realm-personal','00','project:*',1,'active','soc-1',0,'local',
                 'inc-1',?1,'ksm-doc',1,'00','00','{}','1970-01-01T00:00:00Z',
                 '1970-01-01T00:00:00Z')",
            [&binding.binding_ref],
        )
        .expect("insert enablement fixture");
}
