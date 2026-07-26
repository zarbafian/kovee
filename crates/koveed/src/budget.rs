//! The `byom_subordinate` reservation bridge (byom §11.4, §16.6 item 4) and
//! Kovee's own **capacity ledger**: the saga Kovee runs against byom's PARENT
//! reservation, never above it, created once per stable key, debited against
//! a real account, and settled only from a trusted meter — as a two-sided
//! saga with a durable local record on each side (disposition D-R3-2).
//!
//! What you write:
//! ```
//! # use koveed::budget::*;
//! # use kovee_byom::budget::Meter;
//! # let mut store = kovee_store::Store::open_in_memory().unwrap();
//! # store.bootstrap(0).unwrap();
//! # koveed::budget::doc_seam(&mut store);
//! # let parent = doc_parent();
//! // 0. Capacity is GRANTED, never assumed: this is the ceiling everything
//! //    below is debited against.
//! grant_capacity(&mut store, "realm-personal", "unit", "call", 1_000, 0).unwrap();
//! // 1. Reserve (idempotent over byom's stable key). The items are narrowed
//! //    to what the ledger really has, and `remaining` moves to `reserved`.
//! let items = subordinate_items(store.conn(), "realm-personal", &parent).unwrap();
//! let first = reserve(&mut store, "realm-personal", &parent, items.clone(), 0).unwrap();
//! let again = reserve(&mut store, "realm-personal", &parent, items, 0).unwrap();
//! assert_eq!(first.subordinate_reservation_ref, again.subordinate_reservation_ref);
//! let ledger = |s: &kovee_store::Store| {
//!     koveed::budget::account(s.conn(), "kovee-capacity-realm-personal", "unit")
//!         .unwrap().unwrap()
//! };
//! assert_eq!((ledger(&store).remaining, ledger(&store).reserved), (1_000 - 50, 50));
//! // 2. Settle as a SAGA: local record first, then the peer, then commit.
//! let pending = settle_begin(&mut store, &first.subordinate_reservation_ref,
//!                            "unit", 10, Meter::TrustedBroker, "us-1", 0).unwrap();
//! let settled = settle_commit(&mut store, &pending, Some("byom-us-1"), 10, 0).unwrap();
//! // Conservation, on the ACCOUNT: the charge left `reserved` for
//! // `committed`, and the ceiling never moved.
//! assert_eq!((ledger(&store).reserved, ledger(&store).committed), (40, 10));
//! assert!(ledger(&store).conserves());
//! // 3. Release returns exactly the demonstrably unspent remainder.
//! assert_eq!(release(&mut store, &first.subordinate_reservation_ref, 0).unwrap(), 40);
//! let a = ledger(&store);
//! assert_eq!((a.remaining, a.reserved, a.committed), (1_000 - 10, 0, 10));
//! assert_eq!(settled.charged + settled.remainder, 50);
//! ```
//!
//! Plumbing worth knowing:
//!
//! - **The account is the ledger, not the row.** `ceiling = remaining +
//!   reserved + committed + uncertain + delegated_to_children` holds after
//!   every transition, and every transition moves quantities between buckets
//!   of one row inside one SQLite transaction. A reservation whose
//!   `remaining` cannot cover it is refused, so narrowing is a real
//!   constraint rather than a comment.
//! - **Settlement is a two-sided saga.** [`settle_begin`] caps locally and
//!   commits a durable saga row BEFORE the peer is called; the caller then
//!   performs the remote half and finishes with [`settle_commit`] or
//!   [`settle_abandon`]. A process that dies in between restarts with a row
//!   in `remote_pending`, and [`reconcile_settlements`] QUERIES the peer
//!   under the same stable key and applies what the peer really committed.
//! - **The states with NO release are the point.** `uncertain` never releases
//!   on a timeout — the byom parent stays reserved, spend stays blocked, and
//!   only the R38 reconciliation seat (with a fresh challenge) can let go.
//!   Guessing is not a transition.

use kovee_byom::budget::{
    check_items, settle as settle_amount, ByomSubordinateReservation, Item, Meter,
    ReservationState, Settlement, RESERVATION_CLASS,
};
use kovee_byom::records::GovernanceDigests;
use kovee_core::event::{
    EVENT_SUBORDINATE_CONFIRMED, EVENT_SUBORDINATE_DENIED, EVENT_SUBORDINATE_RELEASED,
    EVENT_SUBORDINATE_REQUESTED, EVENT_SUBORDINATE_SETTLED, EVENT_SUBORDINATE_UNCERTAIN,
};
use kovee_core::family::{tagged_canonical, DigestRef};
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::time::rfc3339_utc;
use kovee_store::{new_id, Applied, CommandScope, CrashHooks, NewEvent, Store, OWNER_ACTOR_REF};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::{json, Value};

use crate::governance::active_seam;
use crate::state::{internal, not_found, store_problem, DEFAULT_CLASSIFICATION};

const TAG_RESERVATION: &str = "kovee-byom-subordinate-reservation-v1";
const TAG_SETTLEMENT: &str = "kovee-usage-settlement-v1";

/// The canonicalization domain of byom's published parent-budget fragment.
/// It is byom's domain: Kovee re-derives the digest to VERIFY the fragment it
/// was handed and never mints one of its own (amendment A8, D-R3-3).
pub const PARENT_BUDGET_TAG: &str = "bpp-parent-budget-fragment-v0";
/// The canonicalization domain of the nested reservation-set binding digest.
pub const RESERVATION_SET_BINDING_TAG: &str = "bpp-budget-reservation-set-binding-v0";
/// The frozen member set of the fragment, in byom's published order.
pub const PARENT_BUDGET_FIELDS: [&str; 7] = [
    "byom_budget_reservation_set_ref",
    "byom_budget_reservation_set_revision",
    "byom_budget_reservation_set_digest",
    "external_budget_bridge_ref",
    "external_budget_bridge_revision",
    "stable_external_reservation_key",
    "items",
];

/// One byom-owned §11.4 parent reservation item, exactly as byom published
/// it in the fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentItem {
    pub account_ref: String,
    pub account_revision: u64,
    pub dimension: String,
    pub unit: String,
    pub worst_case_amount: u64,
}

impl ParentItem {
    /// The identity a subordinate item claims. Claimed once, by exactly one
    /// item (R3-U04).
    pub fn identity(&self) -> kovee_byom::budget::ParentIdentity {
        (
            self.account_ref.clone(),
            self.account_revision,
            self.dimension.clone(),
            self.unit.clone(),
            self.worst_case_amount,
        )
    }
}

/// The byom-owned parent this bridge hangs off, as [`verify_parent_fragment`]
/// established it.
///
/// Every budget member here came out of the FROZEN `portable_public` fragment
/// byom published and Kovee re-derived. None of it is named by convention,
/// supplied by a caller, or minted locally — which is the whole of R3-L02.
/// `society_ref` / `society_recovery_epoch` are Society identity rather than
/// budget facts, and are compared against the realm's active mapping.
#[derive(Debug, Clone)]
pub struct Parent {
    pub byom_reservation_set_ref: String,
    pub byom_reservation_set_revision: u64,
    /// **byom's** portable set digest, verified — never minted here. Kovee
    /// used to HMAC a value of its own under its own governance key and store
    /// it as though it were byom's.
    pub byom_reservation_set_digest: DigestRef,
    pub external_budget_bridge_ref: String,
    pub external_budget_bridge_revision: u64,
    pub stable_external_reservation_key: String,
    pub items: Vec<ParentItem>,
    /// The fragment's own digest, and the exact bytes it covers.
    pub fragment_digest: DigestRef,
    pub fragment: Value,
    pub society_ref: String,
    pub society_recovery_epoch: u64,
}

impl Parent {
    /// The parent's worst case for one dimension, over the published items.
    pub fn ceiling(&self, dimension: &str) -> u64 {
        self.items
            .iter()
            .filter(|i| i.dimension == dimension)
            .map(|i| i.worst_case_amount)
            .sum()
    }
}

fn stale(title: &str, detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::StaleRevision, title).with_detail(detail)
}

/// Consumes byom's published parent-budget fragment: re-derives BOTH
/// `portable_public` digests and refuses anything that does not agree
/// (R3-L02, disposition D-R3-3).
///
/// This is the only door the parent facts come through. Before it existed the
/// driver fabricated `rset-…` / `bridge-…` / `sub-…` references from the wake
/// intent's name and took the parent account and worst case from its own
/// caller's arguments, and Kovee minted byom's reservation digest with its own
/// key — so a wrong parent was undetectable on this side.
pub fn verify_parent_fragment(
    fragment: &Value,
    society_ref: &str,
    society_recovery_epoch: u64,
) -> Result<Parent, Problem> {
    let object = fragment.as_object().ok_or_else(|| {
        stale(
            "byom published no parent-budget fragment",
            "the four-stage activation reads the parent from the frozen \
             portable_public fragment episode_request publishes (D-R3-3)",
        )
    })?;
    // The FROZEN member set, exactly: an unexpected member would change bytes
    // a consumer already verified, and a missing one would mean a parent fact
    // has to come from somewhere else — which is the defect.
    let mut emitted: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|k| *k != "digest")
        .collect();
    let mut frozen = PARENT_BUDGET_FIELDS.to_vec();
    emitted.sort_unstable();
    frozen.sort_unstable();
    if emitted != frozen {
        return Err(stale(
            "the parent-budget fragment is not byom's frozen member set",
            format!("expected exactly {frozen:?} plus digest, got {emitted:?}"),
        ));
    }
    let mut covered = fragment.clone();
    if let Some(map) = covered.as_object_mut() {
        map.remove("digest");
    }
    let declared: DigestRef = serde_json::from_value(
        object.get("digest").cloned().unwrap_or(Value::Null),
    )
    .map_err(|_| {
        stale(
            "the parent-budget fragment carries no usable digest",
            "a fragment without a re-derivable digest is an out-of-band budget step",
        )
    })?;
    let recomputed = portable_of(PARENT_BUDGET_TAG, &covered)?;
    if declared.value_hex != recomputed.value_hex || declared.class != recomputed.class {
        return Err(stale(
            "the parent-budget fragment does not verify",
            "the portable_public bpp-parent-budget-fragment-v0 digest must re-derive \
             from exactly the published members",
        ));
    }
    let items = parent_items_of(object)?;
    let set_ref = text_of(object, "byom_budget_reservation_set_ref")?;
    let set_revision = number_of(object, "byom_budget_reservation_set_revision")?;
    let set_digest: DigestRef = serde_json::from_value(
        object
            .get("byom_budget_reservation_set_digest")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|_| {
        stale(
            "the parent-budget fragment carries no usable reservation-set digest",
            "byom's keyed record commitment is never asked for; this member is the \
             portable one (amendment A8)",
        )
    })?;
    let set_recomputed = portable_of(
        RESERVATION_SET_BINDING_TAG,
        &json!({
            "reservation_set_id": set_ref,
            "revision": set_revision,
            "items": object.get("items").cloned().unwrap_or(Value::Null),
        }),
    )?;
    if set_digest.value_hex != set_recomputed.value_hex || set_digest.class != set_recomputed.class
    {
        return Err(stale(
            "the published reservation-set digest does not verify",
            "the set digest is portable_public over {reservation_set_id, revision, items}",
        ));
    }
    Ok(Parent {
        byom_reservation_set_ref: set_ref,
        byom_reservation_set_revision: set_revision,
        byom_reservation_set_digest: set_digest,
        external_budget_bridge_ref: text_of(object, "external_budget_bridge_ref")?,
        external_budget_bridge_revision: number_of(object, "external_budget_bridge_revision")?,
        stable_external_reservation_key: text_of(object, "stable_external_reservation_key")?,
        items,
        fragment_digest: declared,
        fragment: covered,
        society_ref: society_ref.to_owned(),
        society_recovery_epoch,
    })
}

fn portable_of(tag: &str, projection: &Value) -> Result<DigestRef, Problem> {
    let preimage = tagged_canonical(tag, projection).map_err(|_| internal())?;
    Ok(DigestRef::portable_public(kovee_core::family::sha256_hex(
        &preimage,
    )))
}

fn text_of(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, Problem> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            stale(
                "the parent-budget fragment is unusable",
                format!("no {key}"),
            )
        })
}

fn number_of(object: &serde_json::Map<String, Value>, key: &str) -> Result<u64, Problem> {
    object.get(key).and_then(Value::as_u64).ok_or_else(|| {
        stale(
            "the parent-budget fragment is unusable",
            format!("no {key}"),
        )
    })
}

fn parent_items_of(object: &serde_json::Map<String, Value>) -> Result<Vec<ParentItem>, Problem> {
    let list = object
        .get("items")
        .and_then(Value::as_array)
        .filter(|l| !l.is_empty())
        .ok_or_else(|| {
            stale(
                "the parent-budget fragment publishes no parent items",
                "a subordinate reservation pins exact parent items or it pins nothing",
            )
        })?;
    let mut items = Vec::with_capacity(list.len());
    for entry in list {
        let object = entry.as_object().ok_or_else(|| {
            stale(
                "the parent-budget fragment is unusable",
                "a parent item is not an object",
            )
        })?;
        items.push(ParentItem {
            account_ref: text_of(object, "account_ref")?,
            account_revision: number_of(object, "account_revision")?,
            dimension: text_of(object, "dimension")?,
            unit: text_of(object, "unit")?,
            worst_case_amount: number_of(object, "worst_case_amount")?,
        });
    }
    Ok(items)
}

fn digests_of(conn: &Connection, realm: &str) -> Result<GovernanceDigests, Problem> {
    let key = kovee_store::governance_scope_key_of(conn).map_err(store_problem)?;
    Ok(GovernanceDigests::new(&key, realm))
}

fn refused(title: &str, detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::BudgetExceeded, title).with_detail(detail)
}

// ==================================================== the capacity ledger ==

/// The five buckets of a capacity account, in conservation order. Bucket
/// names reach SQL, so the set is closed here and nowhere else.
const BUCKETS: [&str; 5] = [
    "remaining",
    "reserved",
    "committed",
    "uncertain",
    "delegated_to_children",
];

fn bucket(name: &str) -> Result<&'static str, Problem> {
    BUCKETS
        .iter()
        .find(|b| **b == name)
        .copied()
        .ok_or_else(internal)
}

/// One normative capacity-account row (R3-U03).
///
/// This is the ledger `kovee_account_ref` used to only *name*: nothing loaded
/// it and nothing debited it, so the reservations' `charged` /
/// `released_lifetime` scalars were the only durable numbers and
/// "conservation" was a row compared against itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub account_ref: String,
    pub dimension: String,
    pub unit: String,
    pub ceiling: u64,
    pub remaining: u64,
    pub reserved: u64,
    pub committed: u64,
    pub uncertain: u64,
    pub delegated_to_children: u64,
    pub parent_account_ref: Option<String>,
    pub revision: u64,
}

impl Account {
    /// The §11.4 identity, which must hold at EVERY observation:
    /// `ceiling = remaining + reserved + committed + uncertain + delegated`.
    pub fn conserves(&self) -> bool {
        self.ceiling
            == self.remaining
                + self.reserved
                + self.committed
                + self.uncertain
                + self.delegated_to_children
    }
}

/// The capacity account of one realm and dimension. It is a real row with a
/// real ceiling; a realm without one cannot reserve at all.
pub fn realm_account_ref(realm: &str) -> String {
    format!("kovee-capacity-{realm}")
}

/// Reads one `(account, dimension)` ledger row.
pub fn account(
    conn: &Connection,
    account_ref: &str,
    dimension: &str,
) -> Result<Option<Account>, Problem> {
    conn.query_row(
        "SELECT account_ref, dimension, unit, ceiling, remaining, reserved, committed,
                uncertain, delegated_to_children, parent_account_ref, revision
         FROM kovee_capacity_accounts WHERE account_ref = ?1 AND dimension = ?2",
        params![account_ref, dimension],
        |r| {
            Ok(Account {
                account_ref: r.get(0)?,
                dimension: r.get(1)?,
                unit: r.get(2)?,
                ceiling: r.get::<_, i64>(3)?.max(0) as u64,
                remaining: r.get::<_, i64>(4)?.max(0) as u64,
                reserved: r.get::<_, i64>(5)?.max(0) as u64,
                committed: r.get::<_, i64>(6)?.max(0) as u64,
                uncertain: r.get::<_, i64>(7)?.max(0) as u64,
                delegated_to_children: r.get::<_, i64>(8)?.max(0) as u64,
                parent_account_ref: r.get(9)?,
                revision: r.get::<_, i64>(10)?.max(0) as u64,
            })
        },
    )
    .optional()
    .map_err(|e| store_problem(e.into()))
}

/// The realm's default capacity ceiling in `unit` units, overridable with
/// `$KOVEE_REALM_CAPACITY_UNITS`. It is the daemon's own configuration: no
/// worker request reaches it, and it is the number every subordinate
/// reservation is really debited against.
pub const DEFAULT_REALM_CAPACITY_UNITS: u64 = 1_000_000;

/// Provisions the realm's `unit` capacity account at daemon start.
/// Idempotent, and monotonic in the ceiling.
pub fn provision_realm_capacity(
    store: &mut Store,
    realm: &str,
    now: i64,
) -> Result<Account, Problem> {
    let ceiling = std::env::var("KOVEE_REALM_CAPACITY_UNITS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_REALM_CAPACITY_UNITS);
    grant_capacity(store, realm, "unit", "unit", ceiling, now)
}

/// Grants (or raises) the realm's capacity ceiling for one dimension. A
/// ceiling only ever rises, and the delta lands in `remaining` — so capacity
/// enters the ledger exactly once, through an explicit act, and never because
/// something needed it.
pub fn grant_capacity(
    store: &mut Store,
    realm: &str,
    dimension: &str,
    unit: &str,
    ceiling: u64,
    now: i64,
) -> Result<Account, Problem> {
    let account_ref = realm_account_ref(realm);
    let at = rfc3339_utc(now);
    let txn = store
        .conn()
        .unchecked_transaction()
        .map_err(|e| store_problem(e.into()))?;
    match account(&txn, &account_ref, dimension)? {
        None => {
            txn.execute(
                "INSERT INTO kovee_capacity_accounts (account_ref, dimension, realm_ref, unit,
                     ceiling, remaining, reserved, committed, uncertain,
                     delegated_to_children, parent_account_ref, revision, created_at, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?5,0,0,0,0,NULL,1,?6,?6)",
                params![account_ref, dimension, realm, unit, ceiling as i64, at],
            )
            .map_err(|e| store_problem(e.into()))?;
        }
        Some(existing) => {
            if existing.unit != unit {
                return Err(refused(
                    "this capacity account measures another unit",
                    format!(
                        "the account is denominated in {:?}; a grant may raise a ceiling, never \
                         requantify it",
                        existing.unit
                    ),
                ));
            }
            if ceiling > existing.ceiling {
                let delta = ceiling - existing.ceiling;
                txn.execute(
                    "UPDATE kovee_capacity_accounts
                     SET ceiling = ceiling + ?3, remaining = remaining + ?3,
                         revision = revision + 1, updated_at = ?4
                     WHERE account_ref = ?1 AND dimension = ?2",
                    params![account_ref, dimension, delta as i64, at],
                )
                .map_err(|e| store_problem(e.into()))?;
            }
        }
    }
    txn.commit().map_err(|e| store_problem(e.into()))?;
    account(store.conn(), &account_ref, dimension)?.ok_or_else(internal)
}

/// Moves `amount` between two buckets of ONE account row. The underflow
/// guard and the write are the same statement, so no transition can observe a
/// half-applied move — and the caller supplies an open transaction, so
/// several moves compose into one atomic ledger transition.
fn move_between(
    txn: &Connection,
    account_ref: &str,
    dimension: &str,
    from: &str,
    to: &str,
    amount: u64,
    now: i64,
) -> Result<(), Problem> {
    if amount == 0 {
        return Ok(());
    }
    let (from, to) = (bucket(from)?, bucket(to)?);
    let changed = txn
        .execute(
            &format!(
                "UPDATE kovee_capacity_accounts
                 SET {from} = {from} - ?3, {to} = {to} + ?3, revision = revision + 1,
                     updated_at = ?4
                 WHERE account_ref = ?1 AND dimension = ?2 AND {from} >= ?3"
            ),
            params![account_ref, dimension, amount as i64, rfc3339_utc(now)],
        )
        .map_err(|e| store_problem(e.into()))?;
    if changed == 1 {
        return Ok(());
    }
    let have = account(txn, account_ref, dimension)?;
    Err(match have {
        None => refused(
            "this realm has no capacity account for that dimension",
            format!(
                "{account_ref}/{dimension} does not exist: capacity is GRANTED, never \
                 conjured by the code that wants to spend it (R3-U03)"
            ),
        ),
        Some(a) => refused(
            "the capacity ledger cannot cover this move",
            format!(
                "{account_ref}/{dimension}: {from} holds {}, {amount} requested",
                match from {
                    "remaining" => a.remaining,
                    "reserved" => a.reserved,
                    "committed" => a.committed,
                    "uncertain" => a.uncertain,
                    _ => a.delegated_to_children,
                }
            ),
        ),
    })
}

/// One open capacity hold: which account and dimension a subordinate
/// reservation's quantity sits in, and how much of it has been charged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
    pub account_ref: String,
    pub dimension: String,
    pub amount: u64,
    pub charged: u64,
    pub state: String,
}

/// The open holds of one subordinate reservation.
pub fn holds(conn: &Connection, reservation_ref: &str) -> Result<Vec<Hold>, Problem> {
    let mut stmt = conn
        .prepare(
            "SELECT account_ref, dimension, amount, charged, state
             FROM kovee_capacity_reservations
             WHERE holder_kind = 'byom_subordinate' AND holder_ref = ?1
             ORDER BY account_ref, dimension",
        )
        .map_err(|e| store_problem(e.into()))?;
    let rows = stmt
        .query_map([reservation_ref], |r| {
            Ok(Hold {
                account_ref: r.get(0)?,
                dimension: r.get(1)?,
                amount: r.get::<_, i64>(2)?.max(0) as u64,
                charged: r.get::<_, i64>(3)?.max(0) as u64,
                state: r.get(4)?,
            })
        })
        .map_err(|e| store_problem(e.into()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| store_problem(e.into()))?);
    }
    Ok(out)
}

fn set_hold_state(
    txn: &Connection,
    reservation_ref: &str,
    state: &str,
    now: i64,
) -> Result<(), Problem> {
    txn.execute(
        "UPDATE kovee_capacity_reservations SET state = ?2, updated_at = ?3
         WHERE holder_kind = 'byom_subordinate' AND holder_ref = ?1",
        params![reservation_ref, state, rfc3339_utc(now)],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

/// The **child-rollup** pair. A hosted child gets its own account whose
/// ceiling is carved out of the parent's `remaining` into
/// `delegated_to_children`, so conservation holds on BOTH rows and the parent
/// can no longer spend what it delegated.
pub fn delegate_to_child(
    store: &mut Store,
    realm: &str,
    dimension: &str,
    child_account_ref: &str,
    amount: u64,
    now: i64,
) -> Result<(Account, Account), Problem> {
    let parent_ref = realm_account_ref(realm);
    let parent = account(store.conn(), &parent_ref, dimension)?.ok_or_else(|| {
        refused(
            "this realm has no capacity account to delegate from",
            "capacity is granted before it is delegated (R3-U03)",
        )
    })?;
    let at = rfc3339_utc(now);
    let txn = store
        .conn()
        .unchecked_transaction()
        .map_err(|e| store_problem(e.into()))?;
    move_between(
        &txn,
        &parent_ref,
        dimension,
        "remaining",
        "delegated_to_children",
        amount,
        now,
    )?;
    if account(&txn, child_account_ref, dimension)?.is_some() {
        txn.execute(
            "UPDATE kovee_capacity_accounts
             SET ceiling = ceiling + ?3, remaining = remaining + ?3, revision = revision + 1,
                 updated_at = ?4
             WHERE account_ref = ?1 AND dimension = ?2",
            params![child_account_ref, dimension, amount as i64, at],
        )
        .map_err(|e| store_problem(e.into()))?;
    } else {
        txn.execute(
            "INSERT INTO kovee_capacity_accounts (account_ref, dimension, realm_ref, unit,
                 ceiling, remaining, reserved, committed, uncertain, delegated_to_children,
                 parent_account_ref, revision, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?5,0,0,0,0,?6,1,?7,?7)",
            params![
                child_account_ref,
                dimension,
                realm,
                parent.unit,
                amount as i64,
                parent_ref,
                at
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    }
    txn.commit().map_err(|e| store_problem(e.into()))?;
    Ok((
        account(store.conn(), &parent_ref, dimension)?.ok_or_else(internal)?,
        account(store.conn(), child_account_ref, dimension)?.ok_or_else(internal)?,
    ))
}

/// The rollup half: a child's UNSPENT ceiling returns to the parent's
/// `remaining`. What the child committed stays delegated — it was really
/// spent — and an unresolved child (anything still `reserved` or `uncertain`)
/// cannot roll up at all.
pub fn rollup_child(
    store: &mut Store,
    realm: &str,
    dimension: &str,
    child_account_ref: &str,
    now: i64,
) -> Result<(Account, Account), Problem> {
    let parent_ref = realm_account_ref(realm);
    let child = account(store.conn(), child_account_ref, dimension)?.ok_or_else(not_found)?;
    if child.parent_account_ref.as_deref() != Some(parent_ref.as_str()) {
        return Err(Problem::new(
            ProblemKind::Forbidden,
            "this account is not a child of the realm's capacity account",
        ));
    }
    if child.reserved != 0 || child.uncertain != 0 {
        return Err(Problem::new(
            ProblemKind::Ambiguous,
            "an unresolved child account does not roll up",
        )
        .with_detail(format!(
            "{child_account_ref}/{dimension} still holds {} reserved and {} uncertain: an \
             unknown quantity never returns to remaining",
            child.reserved, child.uncertain
        )));
    }
    let at = rfc3339_utc(now);
    let txn = store
        .conn()
        .unchecked_transaction()
        .map_err(|e| store_problem(e.into()))?;
    if child.remaining > 0 {
        txn.execute(
            "UPDATE kovee_capacity_accounts
             SET ceiling = ceiling - ?3, remaining = remaining - ?3, revision = revision + 1,
                 updated_at = ?4
             WHERE account_ref = ?1 AND dimension = ?2 AND remaining >= ?3",
            params![child_account_ref, dimension, child.remaining as i64, at],
        )
        .map_err(|e| store_problem(e.into()))?;
        move_between(
            &txn,
            &parent_ref,
            dimension,
            "delegated_to_children",
            "remaining",
            child.remaining,
            now,
        )?;
    }
    txn.commit().map_err(|e| store_problem(e.into()))?;
    Ok((
        account(store.conn(), &parent_ref, dimension)?.ok_or_else(internal)?,
        account(store.conn(), child_account_ref, dimension)?.ok_or_else(internal)?,
    ))
}

/// Kovee's subordinate items for one VERIFIED parent: one per published
/// parent item, narrowed to what Kovee's own ledger actually grants and never
/// reshaped.
///
/// The account here is the row the ledger holds, read from the ledger — not
/// the `format!("kovee-capacity-{realm}")` string a caller used to place in
/// the record for nobody to check.
pub fn subordinate_items(
    conn: &Connection,
    realm: &str,
    parent: &Parent,
) -> Result<Vec<Item>, Problem> {
    let mut items = Vec::with_capacity(parent.items.len());
    for entry in &parent.items {
        let account_ref = realm_account_ref(realm);
        let ledger = account(conn, &account_ref, &entry.dimension)?.ok_or_else(|| {
            refused(
                "this realm has no capacity account for a parent dimension",
                format!(
                    "{account_ref}/{} does not exist: a subordinate reservation is debited \
                     against a granted ceiling, never against a fabricated account name \
                     (R3-U03)",
                    entry.dimension
                ),
            )
        })?;
        if ledger.unit != entry.unit {
            return Err(refused(
                "the local capacity account measures another unit than the parent item",
                format!(
                    "the account is denominated in {:?} and the parent item in {:?}; a \
                     subordinate item may narrow or deny, never requantify",
                    ledger.unit, entry.unit
                ),
            ));
        }
        // The narrowing this profile applies — half the parent worst case —
        // capped by what the ledger really has left. Narrowing is now a
        // constraint: an empty account narrows to nothing and denies.
        let amount = (entry.worst_case_amount / 2).min(ledger.remaining);
        if amount == 0 {
            return Err(refused(
                "the realm's capacity account has nothing left to reserve",
                format!(
                    "{account_ref}/{}: remaining {}, parent worst case {} — the saga denies \
                     rather than confirming a reservation the ledger cannot back",
                    entry.dimension, ledger.remaining, entry.worst_case_amount
                ),
            ));
        }
        items.push(Item {
            kovee_account_ref: ledger.account_ref,
            dimension: entry.dimension.clone(),
            unit: entry.unit.clone(),
            amount,
            parent_account_ref: entry.account_ref.clone(),
            parent_account_revision: entry.account_revision,
            parent_dimension: entry.dimension.clone(),
            parent_unit: entry.unit.clone(),
            parent_worst_case_amount: entry.worst_case_amount,
            parent_delegation_ref: None,
        });
    }
    Ok(items)
}

/// Kovee's own independent cap against the EXACT verified parent items — the
/// mirror of byom's check, because neither side may cap on the strength of
/// the other's arithmetic (D-R3-2). Each reported item claims one distinct
/// published parent item, on all five coordinates.
fn check_against_parent(items: &[Item], parent: &Parent) -> Result<(), Problem> {
    check_items(items).map_err(|e| {
        refused(
            "the subordinate reservation would exceed its byom parent",
            format!("{e} (§11.4, family contract L32)"),
        )
    })?;
    let mut claimed = vec![false; parent.items.len()];
    for item in items {
        let pinned = item.parent_identity();
        let hit = parent
            .items
            .iter()
            .enumerate()
            .position(|(index, entry)| !claimed[index] && entry.identity() == pinned);
        let Some(index) = hit else {
            return Err(stale(
                "the subordinate item does not pin an exact unclaimed parent item",
                "every reported item claims one DISTINCT item of the verified parent-budget \
                 fragment (account, revision, dimension, unit, worst case), so a duplicate \
                 pin can never amplify one parent (R3-U04)",
            ));
        };
        claimed[index] = true;
    }
    Ok(())
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
    // NeverAboveParent, checked before anything is committed — per item, over
    // the whole set, and against the EXACT verified parent items.
    check_against_parent(&items, parent)?;
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
        // BYOM's digest, verified from byom's published fragment. Kovee used
        // to MINT this value here, HMAC-ing a projection of its own under its
        // own governance scope key and storing it as though it were byom's
        // (R3-L02) — a digest byom could never have produced and nobody could
        // check.
        byom_reservation_set_digest: parent.byom_reservation_set_digest.clone(),
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

    // `requested` is written first and the LEDGER IS DEBITED in the same
    // transaction: the saga row exists before the capacity is claimed, and
    // the capacity is claimed before anything downstream may spend it. A
    // crash anywhere here leaves a reservation Kovee can query with the
    // quantity conservatively held — never an unrecorded charge, and never a
    // confirmed reservation the ledger does not back.
    let txn = store
        .conn()
        .unchecked_transaction()
        .map_err(|e| store_problem(e.into()))?;
    insert(
        &txn,
        realm,
        &record,
        ReservationState::Requested,
        now,
        parent,
    )?;
    for item in &record.items {
        move_between(
            &txn,
            &item.kovee_account_ref,
            &item.dimension,
            "remaining",
            "reserved",
            item.amount,
            now,
        )?;
        // One hold row per `(holder, account, dimension)`: several items
        // against the same account aggregate into it, so the ledger's view of
        // what this reservation holds is a single number per account.
        txn.execute(
            "INSERT INTO kovee_capacity_reservations (capacity_reservation_id, realm_ref,
                 account_ref, dimension, holder_kind, holder_ref, amount, charged, state,
                 created_at, updated_at)
             VALUES (?1,?2,?3,?4,'byom_subordinate',?5,?6,0,'reserved',?7,?7)
             ON CONFLICT(holder_kind, holder_ref, account_ref, dimension)
             DO UPDATE SET amount = amount + excluded.amount, updated_at = excluded.updated_at",
            params![
                new_id("kcr").map_err(store_problem)?,
                realm,
                item.kovee_account_ref,
                item.dimension,
                record.subordinate_reservation_ref,
                item.amount as i64,
                rfc3339_utc(now),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    }
    txn.commit().map_err(|e| store_problem(e.into()))?;
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
            "parent_budget_digest": parent.fragment_digest,
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
    // The quantity moves into the ledger's `uncertain` bucket, so
    // conservation still holds and nothing can return to `remaining` without
    // the R38 decision.
    let txn = store
        .conn()
        .unchecked_transaction()
        .map_err(|e| store_problem(e.into()))?;
    for hold in holds(&txn, &record.subordinate_reservation_ref)? {
        if hold.state != "reserved" {
            continue;
        }
        move_between(
            &txn,
            &hold.account_ref,
            &hold.dimension,
            "reserved",
            "uncertain",
            hold.amount - hold.charged,
            now,
        )?;
    }
    set_hold_state(&txn, &record.subordinate_reservation_ref, "uncertain", now)?;
    set_state(&txn, &record, ReservationState::Uncertain, now)?;
    txn.commit().map_err(|e| store_problem(e.into()))?;
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

// =========================================== the two-sided settlement saga ==

/// The durable local half of one in-flight settlement (disposition D-R3-2).
///
/// The row this describes is committed BEFORE the remote half is attempted,
/// which is the whole point: a process that dies between the two sides
/// restarts knowing that a settlement exists under a known stable key, and
/// [`reconcile_settlements`] can then ask the peer what it committed instead
/// of guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub stable_settlement_key: String,
    pub realm: String,
    pub subordinate_reservation_ref: String,
    pub dimension: String,
    /// The charge Kovee capped LOCALLY, before any byte left.
    pub charge: u64,
    pub meter: Meter,
    pub phase: SagaPhase,
}

/// The phases of the local saga record. `RemotePending` is the only one a
/// crash can leave behind, and it is exactly the one reconciliation resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SagaPhase {
    /// Capped locally, recorded durably, remote half not yet resolved.
    RemotePending,
    /// The peer committed and Kovee applied the same number.
    Settled,
    /// The peer definitely refused; nothing was charged on either side.
    Denied,
    /// The remote outcome is unknown. Nothing is charged and nothing is
    /// released — the reconciliation query, not a timeout, resolves it.
    Unknown,
}

impl SagaPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            SagaPhase::RemotePending => "remote_pending",
            SagaPhase::Settled => "settled",
            SagaPhase::Denied => "denied",
            SagaPhase::Unknown => "unknown",
        }
    }

    fn parse(text: &str) -> Option<SagaPhase> {
        match text {
            "remote_pending" => Some(SagaPhase::RemotePending),
            "settled" => Some(SagaPhase::Settled),
            "denied" => Some(SagaPhase::Denied),
            "unknown" => Some(SagaPhase::Unknown),
            _ => None,
        }
    }
}

fn meter_name(meter: Meter) -> &'static str {
    match meter {
        Meter::TrustedBroker => "trusted_broker",
        Meter::VerifiedProviderReceipt => "verified_provider_receipt",
        Meter::Report => "report",
    }
}

fn meter_of(text: &str) -> Meter {
    match text {
        "verified_provider_receipt" => Meter::VerifiedProviderReceipt,
        "trusted_broker" => Meter::TrustedBroker,
        _ => Meter::Report,
    }
}

/// What the peer's side of the saga really did, as its reply or its recovery
/// query reported it. There is no arm that means "assume".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSettlement {
    Settled {
        settlement_ref: Option<String>,
        charged: u64,
    },
    NotSettled {
        reason: String,
    },
    Unknown {
        detail: String,
    },
}

/// **Step 1 of the saga.** Caps the charge LOCALLY against Kovee's own
/// confirmed items and its own ledger, then commits the durable local record.
///
/// This ordering is the R3-U01 fix. The old path sent an arbitrary charge to
/// byom FIRST and checked its own ceiling afterwards, so a charge byom
/// accepted and Kovee refused left byom committed and Kovee `confirmed` with
/// charge 0 — two ledgers, one truth each. Nothing leaves this side now until
/// this side has agreed to it.
pub fn settle_begin(
    store: &mut Store,
    reservation_ref: &str,
    dimension: &str,
    charge: u64,
    meter: Meter,
    stable_settlement_key: &str,
    now: i64,
) -> Result<Pending, Problem> {
    let (realm, record, previously_charged) = read_by_ref(store.conn(), reservation_ref)?;
    if let Some(existing) = saga_of(store.conn(), stable_settlement_key)? {
        // The stable key is the identity of the settlement, so an exact retry
        // returns the recorded one and a CHANGED ask under the same key is a
        // mismatch rather than a second settlement.
        if existing.subordinate_reservation_ref != reservation_ref
            || existing.dimension != dimension
            || existing.charge != charge
        {
            return Err(Problem::new(
                ProblemKind::IdempotencyMismatch,
                "this stable settlement key already names another settlement",
            )
            .with_detail(format!(
                "recorded {} of {:?} on {}; asked {charge} of {dimension:?} on {reservation_ref}",
                existing.charge, existing.dimension, existing.subordinate_reservation_ref
            )));
        }
        return Ok(existing);
    }
    if record.state == ReservationState::Settled {
        return Err(Problem::new(
            ProblemKind::Forbidden,
            "this subordinate reservation is already settled",
        )
        .with_detail(
            "SettleOnce: one measured settlement per stable external reservation key; a further \
             metered report is evidence, not a second charge",
        ));
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
    // The LOCAL cap, before a byte leaves: the meter must be one that may
    // settle, the charge must be monotonic, and it must be within the exact
    // confirmed subordinate items.
    settle_amount(&record, dimension, previously_charged, charge, meter).map_err(|e| {
        refused(
            "the settlement is not admissible",
            format!("{e} (§11.4: participant and worker reports are evidence, not meters)"),
        )
    })?;
    // ...and within what the ledger actually holds for this reservation.
    let held: u64 = holds(store.conn(), reservation_ref)?
        .iter()
        .filter(|h| h.dimension == dimension && h.state == "reserved")
        .map(|h| h.amount - h.charged)
        .sum();
    if charge > held {
        return Err(refused(
            "the capacity ledger does not hold this charge",
            format!(
                "{reservation_ref} holds {held} of {dimension:?} in `reserved`; {charge} \
                 requested (R3-U03: the account, not the row, is the ledger)"
            ),
        ));
    }
    let at = rfc3339_utc(now);
    store
        .conn()
        .execute(
            "INSERT INTO kovee_settlement_saga (stable_settlement_key, realm_ref,
                 subordinate_reservation_ref, dimension, charge, meter, phase,
                 remote_settlement_ref, remote_charged, detail, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,'remote_pending',NULL,NULL,NULL,?7,?7)",
            params![
                stable_settlement_key,
                realm,
                reservation_ref,
                dimension,
                charge as i64,
                meter_name(meter),
                at,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok(Pending {
        stable_settlement_key: stable_settlement_key.to_owned(),
        realm,
        subordinate_reservation_ref: reservation_ref.to_owned(),
        dimension: dimension.to_owned(),
        charge,
        meter,
        phase: SagaPhase::RemotePending,
    })
}

/// **Step 2 of the saga.** Applies exactly what the peer committed: the
/// reservation becomes `settled`, the ledger moves `reserved → committed`, and
/// the saga row resolves — all in one transaction.
///
/// `remote_charged` is the peer's OWN number, and it must be within the cap
/// this side already agreed to. A peer number above the local cap is the
/// split-ledger condition itself: it is refused loudly and the saga is left
/// `unknown` rather than papered over.
pub fn settle_commit(
    store: &mut Store,
    pending: &Pending,
    remote_settlement_ref: Option<&str>,
    remote_charged: u64,
    now: i64,
) -> Result<Settlement, Problem> {
    let (realm, mut record, previously_charged) =
        read_by_ref(store.conn(), &pending.subordinate_reservation_ref)?;
    if record.state == ReservationState::Settled {
        return Ok(Settlement {
            charged: previously_charged,
            remainder: record
                .reserved(&pending.dimension)
                .saturating_sub(previously_charged),
        });
    }
    if remote_charged > pending.charge {
        set_saga_phase(
            store.conn(),
            &pending.stable_settlement_key,
            SagaPhase::Unknown,
            None,
            Some(remote_charged),
            &format!(
                "the peer committed {remote_charged} where this side capped {}: the two \
                 ledgers would disagree, so nothing is applied here",
                pending.charge
            ),
            now,
        )?;
        return Err(refused(
            "the peer settled above this side's own cap",
            "neither side may charge on the strength of the other's arithmetic (D-R3-2); the \
             saga is recorded `unknown` and resolved by reconciliation, never by adopting the \
             larger number",
        ));
    }
    let settlement = settle_amount(
        &record,
        &pending.dimension,
        previously_charged,
        remote_charged,
        pending.meter,
    )
    .map_err(|e| {
        refused(
            "the settlement is not admissible",
            format!("{e} (§11.4: participant and worker reports are evidence, not meters)"),
        )
    })?;

    let digests = digests_of(store.conn(), &realm)?;
    record.revision += 1;
    record.state = ReservationState::Settled;
    record.usage_settlement_ref = Some(pending.stable_settlement_key.clone());
    record.usage_settlement_digest = Some(
        digests
            .digest(
                TAG_SETTLEMENT,
                &json!({
                    "usage_settlement_ref": pending.stable_settlement_key,
                    "stable_external_reservation_key": record.stable_external_reservation_key,
                    "dimension": pending.dimension,
                    "charged": settlement.charged,
                    "peer_settlement_ref": remote_settlement_ref,
                }),
            )
            .map_err(|_| internal())?,
    );
    record.digest = self_digest(&digests, &record)?;
    record
        .check()
        .map_err(|e| refused("the settled reservation is not admissible", e.to_string()))?;
    let txn = store
        .conn()
        .unchecked_transaction()
        .map_err(|e| store_problem(e.into()))?;
    txn.execute(
        "UPDATE byom_subordinate_reservations
         SET state = ?2, revision = ?3, charged = ?4, released_lifetime = released_lifetime + ?5,
             record = ?6, updated_at = ?7
         WHERE subordinate_reservation_ref = ?1",
        params![
            pending.subordinate_reservation_ref,
            ReservationState::Settled.as_str(),
            record.revision as i64,
            settlement.charged as i64,
            settlement.remainder as i64,
            serde_json::to_string(&record).map_err(|_| internal())?,
            rfc3339_utc(now),
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    // The LEDGER move: the charge leaves `reserved` for `committed`, and the
    // remainder stays held until the release. Kovee used to record only the
    // audit scalars above and move nothing at all (R3-U03).
    let mut left = settlement.charged;
    for hold in holds(&txn, &pending.subordinate_reservation_ref)? {
        if left == 0 || hold.dimension != pending.dimension || hold.state != "reserved" {
            continue;
        }
        let take = left.min(hold.amount - hold.charged);
        move_between(
            &txn,
            &hold.account_ref,
            &hold.dimension,
            "reserved",
            "committed",
            take,
            now,
        )?;
        txn.execute(
            "UPDATE kovee_capacity_reservations SET charged = charged + ?3, updated_at = ?4
             WHERE holder_kind = 'byom_subordinate' AND holder_ref = ?1 AND account_ref = ?2",
            params![
                pending.subordinate_reservation_ref,
                hold.account_ref,
                take as i64,
                rfc3339_utc(now),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
        left -= take;
    }
    txn.execute(
        "UPDATE kovee_settlement_saga
         SET phase = 'settled', remote_settlement_ref = ?2, remote_charged = ?3, updated_at = ?4
         WHERE stable_settlement_key = ?1",
        params![
            pending.stable_settlement_key,
            remote_settlement_ref,
            remote_charged as i64,
            rfc3339_utc(now),
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    txn.commit().map_err(|e| store_problem(e.into()))?;
    event(
        store,
        &realm,
        &record,
        EVENT_SUBORDINATE_SETTLED,
        json!({
            "state": "settled",
            "dimension": pending.dimension,
            "charged": settlement.charged,
            "remainder": settlement.remainder,
            "reserved": record.reserved(&pending.dimension),
            "usage_settlement_ref": pending.stable_settlement_key,
            "peer_settlement_ref": remote_settlement_ref,
            "applied_once_on_both_sides": true,
        }),
        now,
    )?;
    Ok(settlement)
}

/// **Step 2, the refusal arm.** The peer definitely did not settle: nothing is
/// charged on either side, and the reservation stays `confirmed` and
/// releasable.
pub fn settle_denied(
    store: &mut Store,
    pending: &Pending,
    reason: &str,
    now: i64,
) -> Result<(), Problem> {
    set_saga_phase(
        store.conn(),
        &pending.stable_settlement_key,
        SagaPhase::Denied,
        None,
        None,
        reason,
        now,
    )
}

/// **Step 2, the unknown arm.** The remote outcome could not be established.
/// Nothing is charged and nothing is released; the saga row survives for
/// [`reconcile_settlements`] to resolve against the peer.
pub fn settle_unknown(
    store: &mut Store,
    pending: &Pending,
    detail: &str,
    now: i64,
) -> Result<(), Problem> {
    set_saga_phase(
        store.conn(),
        &pending.stable_settlement_key,
        SagaPhase::Unknown,
        None,
        None,
        detail,
        now,
    )
}

/// What one reconciliation sweep resolved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reconciled {
    pub examined: usize,
    pub settled: usize,
    pub denied: usize,
    pub still_unknown: usize,
}

/// **Crash recovery for the saga.** Every unresolved local record is resolved
/// by ASKING the peer under the same stable settlement key, and by applying
/// exactly what the peer answers.
///
/// This is what makes the two sides converge after a crash between them. The
/// resolver re-issues the peer's own idempotent settlement call, so the reply
/// is either the settlement the peer really committed (replayed, with its
/// charge), a definite refusal, or still unknown — and an unknown stays
/// unknown. Guessing is not a transition.
pub fn reconcile_settlements(
    store: &mut Store,
    now: i64,
    resolve: &mut dyn FnMut(&mut Store, &Pending) -> Result<RemoteSettlement, Problem>,
) -> Result<Reconciled, Problem> {
    let mut out = Reconciled::default();
    for pending in unresolved_sagas(store.conn())? {
        out.examined += 1;
        match resolve(store, &pending) {
            Ok(RemoteSettlement::Settled {
                settlement_ref,
                charged,
            }) => {
                settle_commit(store, &pending, settlement_ref.as_deref(), charged, now)?;
                out.settled += 1;
            }
            Ok(RemoteSettlement::NotSettled { reason }) => {
                settle_denied(store, &pending, &reason, now)?;
                out.denied += 1;
            }
            Ok(RemoteSettlement::Unknown { detail }) => {
                settle_unknown(store, &pending, &detail, now)?;
                out.still_unknown += 1;
            }
            Err(problem) => {
                // A failed query is not evidence of anything: the record stays
                // unresolved and the next sweep asks again.
                settle_unknown(
                    store,
                    &pending,
                    &format!("the reconciliation query failed: {}", problem.title),
                    now,
                )?;
                out.still_unknown += 1;
            }
        }
    }
    Ok(out)
}

/// The unresolved local settlement records — what a restart must reconcile.
pub fn unresolved_sagas(conn: &Connection) -> Result<Vec<Pending>, Problem> {
    let mut stmt = conn
        .prepare(
            "SELECT stable_settlement_key, realm_ref, subordinate_reservation_ref, dimension,
                    charge, meter, phase
             FROM kovee_settlement_saga WHERE phase IN ('remote_pending', 'unknown')
             ORDER BY created_at ASC, stable_settlement_key ASC",
        )
        .map_err(|e| store_problem(e.into()))?;
    let rows = stmt
        .query_map([], saga_from_row)
        .map_err(|e| store_problem(e.into()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| store_problem(e.into()))?);
    }
    Ok(out)
}

/// One local settlement record by its stable key.
pub fn saga_of(conn: &Connection, stable_key: &str) -> Result<Option<Pending>, Problem> {
    conn.query_row(
        "SELECT stable_settlement_key, realm_ref, subordinate_reservation_ref, dimension,
                charge, meter, phase
         FROM kovee_settlement_saga WHERE stable_settlement_key = ?1",
        [stable_key],
        saga_from_row,
    )
    .optional()
    .map_err(|e| store_problem(e.into()))
}

fn saga_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Pending> {
    Ok(Pending {
        stable_settlement_key: r.get(0)?,
        realm: r.get(1)?,
        subordinate_reservation_ref: r.get(2)?,
        dimension: r.get(3)?,
        charge: r.get::<_, i64>(4)?.max(0) as u64,
        meter: meter_of(&r.get::<_, String>(5)?),
        phase: SagaPhase::parse(&r.get::<_, String>(6)?).unwrap_or(SagaPhase::Unknown),
    })
}

#[allow(clippy::too_many_arguments)]
fn set_saga_phase(
    conn: &Connection,
    stable_key: &str,
    phase: SagaPhase,
    remote_settlement_ref: Option<&str>,
    remote_charged: Option<u64>,
    detail: &str,
    now: i64,
) -> Result<(), Problem> {
    conn.execute(
        "UPDATE kovee_settlement_saga
         SET phase = ?2, remote_settlement_ref = COALESCE(?3, remote_settlement_ref),
             remote_charged = COALESCE(?4, remote_charged), detail = ?5, updated_at = ?6
         WHERE stable_settlement_key = ?1",
        params![
            stable_key,
            phase.as_str(),
            remote_settlement_ref,
            remote_charged.map(|c| c as i64),
            detail,
            rfc3339_utc(now),
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

/// `subordinate_release`: saga completion. Releases only the demonstrably
/// unspent remainder — back into the ledger's `remaining` bucket, in the same
/// accounting step. `released_lifetime` is a monotonic AUDIT counter, never an
/// available bucket.
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
    if record.state == ReservationState::Released {
        return Ok(0);
    }
    let remainder = record
        .items
        .iter()
        .map(|i| i.amount)
        .sum::<u64>()
        .saturating_sub(charged);
    let txn = store
        .conn()
        .unchecked_transaction()
        .map_err(|e| store_problem(e.into()))?;
    for hold in holds(&txn, reservation_ref)? {
        if hold.state != "reserved" {
            continue;
        }
        move_between(
            &txn,
            &hold.account_ref,
            &hold.dimension,
            "reserved",
            "remaining",
            hold.amount - hold.charged,
            now,
        )?;
    }
    set_hold_state(&txn, reservation_ref, "released", now)?;
    set_state(&txn, &record, ReservationState::Released, now)?;
    txn.commit().map_err(|e| store_problem(e.into()))?;
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
    // The unknown quantity returns to `remaining` ONLY here.
    let txn = store
        .conn()
        .unchecked_transaction()
        .map_err(|e| store_problem(e.into()))?;
    for hold in holds(&txn, reservation_ref)? {
        if hold.state != "uncertain" {
            continue;
        }
        move_between(
            &txn,
            &hold.account_ref,
            &hold.dimension,
            "uncertain",
            "remaining",
            hold.amount - hold.charged,
            now,
        )?;
    }
    set_hold_state(&txn, reservation_ref, "released", now)?;
    set_state(&txn, &record, ReservationState::Released, now)?;
    txn.commit().map_err(|e| store_problem(e.into()))?;
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
    txn: &Connection,
    realm: &str,
    record: &ByomSubordinateReservation,
    state: ReservationState,
    now: i64,
    parent: &Parent,
) -> Result<(), Problem> {
    let at = rfc3339_utc(now);
    txn.execute(
        "INSERT INTO byom_subordinate_reservations (subordinate_reservation_ref, realm_ref,
                 stable_external_reservation_key, external_budget_bridge_ref,
                 byom_reservation_set_ref, realm_byom_binding_ref, realm_byom_binding_epoch,
                 revision, state, charged, released_lifetime, record, created_at, updated_at,
                 parent_budget_fragment, parent_budget_digest)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,0,?10,?11,?11,?12,?13)",
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
            // The EXACT fragment bytes Kovee verified, kept so the parent
            // facts stay auditable and re-derivable after the fact.
            parent.fragment.to_string(),
            serde_json::to_string(&parent.fragment_digest).map_err(|_| internal())?,
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

/// The saga state of one subordinate reservation, if the row exists.
pub fn state_of(
    conn: &Connection,
    reservation_ref: &str,
) -> Result<Option<ReservationState>, Problem> {
    let text: Option<String> = conn
        .query_row(
            "SELECT state FROM byom_subordinate_reservations
             WHERE subordinate_reservation_ref = ?1",
            [reservation_ref],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    Ok(match text {
        None => None,
        Some(text) => Some(ReservationState::parse(&text).ok_or_else(internal)?),
    })
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

/// The verified parent-budget fragment stored with one reservation — the
/// exact bytes Kovee checked, kept for audit.
pub fn stored_parent_fragment(
    conn: &Connection,
    reservation_ref: &str,
) -> Result<Option<(Value, DigestRef)>, Problem> {
    let row: Option<(Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT parent_budget_fragment, parent_budget_digest
             FROM byom_subordinate_reservations WHERE subordinate_reservation_ref = ?1",
            [reservation_ref],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    let Some((Some(fragment), Some(digest))) = row else {
        return Ok(None);
    };
    Ok(Some((
        serde_json::from_str(&fragment).map_err(|_| internal())?,
        serde_json::from_str(&digest).map_err(|_| internal())?,
    )))
}

/// A parent-budget fragment composed exactly as byom publishes it, for the
/// doc example and the budget tests. Real fragments arrive over the wire from
/// `episode_request`; this one is derived with byom's own domains, so a
/// mismatch here would be a real disagreement.
#[doc(hidden)]
#[allow(clippy::expect_used)]
pub fn doc_fragment(
    set_ref: &str,
    set_revision: u64,
    bridge_ref: &str,
    bridge_revision: u64,
    stable_key: &str,
    items: Value,
) -> Value {
    let set_digest = portable_of(
        RESERVATION_SET_BINDING_TAG,
        &json!({
            "reservation_set_id": set_ref,
            "revision": set_revision,
            "items": items,
        }),
    )
    .expect("the reservation-set binding digest");
    let covered = json!({
        "byom_budget_reservation_set_ref": set_ref,
        "byom_budget_reservation_set_revision": set_revision,
        "byom_budget_reservation_set_digest": set_digest,
        "external_budget_bridge_ref": bridge_ref,
        "external_budget_bridge_revision": bridge_revision,
        "stable_external_reservation_key": stable_key,
        "items": items,
    });
    let digest = portable_of(PARENT_BUDGET_TAG, &covered).expect("the parent-budget digest");
    let mut published = covered;
    if let Some(map) = published.as_object_mut() {
        map.insert(
            "digest".to_owned(),
            serde_json::to_value(&digest).unwrap_or(Value::Null),
        );
    }
    published
}

/// The verified parent of the doc example.
#[doc(hidden)]
#[allow(clippy::expect_used)]
pub fn doc_parent() -> Parent {
    verify_parent_fragment(
        &doc_fragment(
            "brs-1",
            2,
            "ebb-1",
            1,
            "stable-1",
            json!([{
                "account_ref": "byom-acct-1", "account_revision": 3,
                "dimension": "unit", "unit": "call", "worst_case_amount": 100,
            }]),
        ),
        "soc-1",
        0,
    )
    .expect("the doc fragment verifies")
}

/// An ACTIVE governed-work seam inserted into `store`, for the doc example
/// and the budget tests — real seams come from the greenfield saga.
#[doc(hidden)]
pub fn doc_seam(store: &mut Store) {
    seam_fixture(store, "soc-1", 0, "inc-1");
}

/// The same seam pinned to a LIVE byomd: the Society it actually
/// bootstrapped and the endpoint incarnation it actually reports. Every
/// runtime `meta` pins both, so a cross-daemon suite cannot use the
/// fixture values.
#[doc(hidden)]
#[allow(clippy::expect_used)]
pub fn seam_fixture(
    store: &mut Store,
    society_ref: &str,
    society_recovery_epoch: u64,
    endpoint_incarnation: &str,
) {
    let binding = crate::credentials::doc_binding(store);
    store
        .conn()
        .execute(
            "UPDATE kovee_realm_byom_bindings SET endpoint_incarnation = ?2
             WHERE binding_ref = ?1",
            rusqlite::params![binding.binding_ref, endpoint_incarnation],
        )
        .expect("pin the live endpoint incarnation");
    store
        .conn()
        .execute(
            "INSERT INTO kovee_society_mappings (mapping_id, realm_ref, society_ref,
                 society_recovery_epoch, allowed_project_and_space_selectors,
                 classification_binding_ref, governance_owner_binding_ref,
                 governance_owner_binding_digest, status, revision, digest, binding_ref,
                 created_at)
             VALUES ('ksm-doc','realm-personal',?3,?4,'[\"project:*\"]','class-1',?1,?2,
                 'active',1,?2,?1,'1970-01-01T00:00:00Z')",
            rusqlite::params![
                binding.binding_ref,
                serde_json::to_string(&binding.digest).unwrap_or_default(),
                society_ref,
                society_recovery_epoch as i64,
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
             VALUES ('gfe-doc','realm-personal','00','project:*',1,'active',?2,?3,'local',
                 ?4,?1,'ksm-doc',1,'00','00','{}','1970-01-01T00:00:00Z',
                 '1970-01-01T00:00:00Z')",
            rusqlite::params![
                binding.binding_ref,
                society_ref,
                society_recovery_epoch as i64,
                endpoint_incarnation,
            ],
        )
        .expect("insert enablement fixture");
}
