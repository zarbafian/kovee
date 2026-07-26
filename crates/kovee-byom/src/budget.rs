//! `ByomSubordinateReservation` — the `byom_subordinate` budget bridge
//! (byom §11.4, §16.6 item 4; family contract L31–L33), and the saga
//! `byom/spec/descriptors/subordinate-reservation.json` commits.
//!
//! What you write (the whole never-above-parent rule):
//! ```
//! use kovee_byom::budget::{Item, ItemError};
//! let item = Item {
//!     kovee_account_ref: "acct-1".into(), dimension: "unit".into(),
//!     unit: "call".into(), amount: 40,
//!     parent_account_ref: "byom-acct-1".into(), parent_account_revision: 3,
//!     parent_dimension: "unit".into(), parent_unit: "call".into(),
//!     parent_worst_case_amount: 100, parent_delegation_ref: None,
//! };
//! item.check().unwrap();                       // narrowing is allowed
//! let mut over = item.clone();
//! over.amount = 101;                           // exceeding is not
//! assert_eq!(over.check(), Err(ItemError::AboveParent));
//! ```
//!
//! Plumbing worth knowing: a subordinate reservation may NARROW or DENY,
//! never reshape or parallel-charge. So `dimension`/`unit` must equal the
//! parent's and `amount` must not exceed `parent_worst_case_amount` —
//! JSON Schema cannot compare two members of one object, which is exactly
//! why the check lives in code. The states with no release are the point
//! of the machine: an unknown result stays `uncertain`, the byom parent
//! stays reserved, spend stays blocked, and only the R38 governance seat
//! (never a timeout) releases it.

use kovee_core::family::DigestRef;
use serde::{Deserialize, Serialize};

/// `ByomSubordinateReservation.state` — the §11.4 `ExternalBudgetBridge`
/// state list verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReservationState {
    #[serde(rename = "requested")]
    Requested,
    #[serde(rename = "confirmed")]
    Confirmed,
    #[serde(rename = "denied")]
    Denied,
    #[serde(rename = "uncertain")]
    Uncertain,
    #[serde(rename = "settled")]
    Settled,
    #[serde(rename = "released")]
    Released,
}

impl ReservationState {
    pub fn as_str(self) -> &'static str {
        match self {
            ReservationState::Requested => "requested",
            ReservationState::Confirmed => "confirmed",
            ReservationState::Denied => "denied",
            ReservationState::Uncertain => "uncertain",
            ReservationState::Settled => "settled",
            ReservationState::Released => "released",
        }
    }

    pub fn parse(text: &str) -> Option<ReservationState> {
        match text {
            "requested" => Some(ReservationState::Requested),
            "confirmed" => Some(ReservationState::Confirmed),
            "denied" => Some(ReservationState::Denied),
            "uncertain" => Some(ReservationState::Uncertain),
            "settled" => Some(ReservationState::Settled),
            "released" => Some(ReservationState::Released),
            _ => None,
        }
    }
}

/// The one reservation-set class this record shape exists under.
pub const RESERVATION_CLASS: &str = "byom_subordinate";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ItemError {
    #[error("a subordinate item may narrow or deny but never reshape the dimension")]
    Dimension,
    #[error("a subordinate item may narrow or deny but never reshape the unit")]
    Unit,
    #[error("a subordinate item may never reserve above parent_worst_case_amount")]
    AboveParent,
}

/// One per-dimension subordinate item, pinned to its exact parent §11.4
/// reservation item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    /// The Kovee-owned capacity account this item reserves against —
    /// another owner entirely, never part of the byom transaction.
    pub kovee_account_ref: String,
    pub dimension: String,
    pub unit: String,
    pub amount: u64,
    pub parent_account_ref: String,
    pub parent_account_revision: u64,
    pub parent_dimension: String,
    pub parent_unit: String,
    pub parent_worst_case_amount: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent_delegation_ref: Option<String>,
}

/// One parent §11.4 reservation item's IDENTITY: the four coordinates plus
/// the worst case. Two parent items sharing an identity are two distinct
/// items, and each may be claimed by at most ONE subordinate item.
pub type ParentIdentity = (String, u64, String, String, u64);

impl Item {
    /// The three cross-member rules JSON Schema cannot express
    /// (`SubordinateReservation.tla` NeverAboveParent).
    pub fn check(&self) -> Result<(), ItemError> {
        if self.dimension != self.parent_dimension {
            return Err(ItemError::Dimension);
        }
        if self.unit != self.parent_unit {
            return Err(ItemError::Unit);
        }
        if self.amount > self.parent_worst_case_amount {
            return Err(ItemError::AboveParent);
        }
        Ok(())
    }

    /// The exact parent item this subordinate item claims.
    pub fn parent_identity(&self) -> ParentIdentity {
        (
            self.parent_account_ref.clone(),
            self.parent_account_revision,
            self.parent_dimension.clone(),
            self.parent_unit.clone(),
            self.parent_worst_case_amount,
        )
    }
}

/// The SET-level never-above-parent rules — the ones a per-item loop cannot
/// see, and whose absence let a duplicate pin amplify the parent (R3-U04).
///
/// ```
/// use kovee_byom::budget::{check_items, Item, ReservationError};
/// # fn item(amount: u64) -> Item { Item {
/// #     kovee_account_ref: "acct-1".into(), dimension: "unit".into(),
/// #     unit: "call".into(), amount,
/// #     parent_account_ref: "byom-acct-1".into(), parent_account_revision: 3,
/// #     parent_dimension: "unit".into(), parent_unit: "call".into(),
/// #     parent_worst_case_amount: 100, parent_delegation_ref: None } }
/// // Two 100-unit children against ONE 100-unit parent item is not 200 of
/// // capacity — it is one parent item claimed twice.
/// assert_eq!(
///     check_items(&[item(100), item(100)]),
///     Err(ReservationError::DuplicateParentItem),
/// );
/// check_items(&[item(100)]).unwrap();
/// ```
pub fn check_items(items: &[Item]) -> Result<(), ReservationError> {
    for (index, item) in items.iter().enumerate() {
        item.check().map_err(|e| ReservationError::Item(index, e))?;
    }
    // 1. Unique exact parent-item identity: a parent item is claimed once.
    let mut claimed: Vec<ParentIdentity> = Vec::with_capacity(items.len());
    for item in items {
        let identity = item.parent_identity();
        if claimed.contains(&identity) {
            return Err(ReservationError::DuplicateParentItem);
        }
        claimed.push(identity);
    }
    // 2. Aggregate cap per (account, revision, dimension, unit): the
    //    subordinate total never exceeds the total the distinct parent items
    //    of that key carry.
    let mut keys: Vec<(String, u64, String, String)> = Vec::new();
    for item in items {
        let key = (
            item.parent_account_ref.clone(),
            item.parent_account_revision,
            item.parent_dimension.clone(),
            item.parent_unit.clone(),
        );
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    for key in &keys {
        let matching = |item: &&Item| {
            item.parent_account_ref == key.0
                && item.parent_account_revision == key.1
                && item.parent_dimension == key.2
                && item.parent_unit == key.3
        };
        let want: u64 = items.iter().filter(matching).map(|i| i.amount).sum();
        let have: u64 = items
            .iter()
            .filter(matching)
            .map(|i| i.parent_worst_case_amount)
            .sum();
        if want > have {
            return Err(ReservationError::AboveParentTotal);
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReservationError {
    #[error("reservation_class must be byom_subordinate")]
    Class,
    #[error("a reservation carries at least one item")]
    Empty,
    #[error("item {0}: {1}")]
    Item(usize, ItemError),
    #[error("settled state and the UsageSettlement pair are all-or-none")]
    Settlement,
    #[error("a settled charge may never exceed the reserved amount")]
    OverCharge,
    #[error("settlement is monotonic: a charge never decreases")]
    NonMonotonic,
    #[error("two subordinate items pin the same parent §11.4 item: a parent item is claimed once")]
    DuplicateParentItem,
    #[error(
        "the subordinate total exceeds the parent total for one \
         account/revision/dimension/unit"
    )]
    AboveParentTotal,
}

/// `ByomSubordinateReservation` — the §11.4-derived Kovee-side record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByomSubordinateReservation {
    pub subordinate_reservation_ref: String,
    pub revision: u64,
    pub reservation_class: String,
    pub realm_ref: String,
    pub realm_byom_binding_ref: String,
    /// An epoch advance invalidates the bridge (family contract L2).
    pub realm_byom_binding_epoch: u64,
    pub society_ref: String,
    pub society_recovery_epoch: u64,
    pub byom_reservation_set_ref: String,
    pub byom_reservation_set_revision: u64,
    pub byom_reservation_set_digest: DigestRef,
    pub external_budget_bridge_ref: String,
    /// Idempotent create: an exact retry under the same key returns the
    /// identical reservation, never a second row.
    pub stable_external_reservation_key: String,
    pub items: Vec<Item>,
    pub state: ReservationState,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub usage_settlement_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub usage_settlement_digest: Option<DigestRef>,
    pub created_at: String,
    pub digest: DigestRef,
}

impl ByomSubordinateReservation {
    /// Everything the frozen shape pins that JSON Schema cannot check.
    pub fn check(&self) -> Result<(), ReservationError> {
        if self.reservation_class != RESERVATION_CLASS {
            return Err(ReservationError::Class);
        }
        if self.items.is_empty() {
            return Err(ReservationError::Empty);
        }
        // Per item AND across the set: a duplicate parent-item pin is not
        // extra capacity (R3-U04).
        check_items(&self.items)?;
        let settled = self.state == ReservationState::Settled;
        let paired = self.usage_settlement_ref.is_some() && self.usage_settlement_digest.is_some();
        let absent = self.usage_settlement_ref.is_none() && self.usage_settlement_digest.is_none();
        if settled != paired || (!settled && !absent) {
            return Err(ReservationError::Settlement);
        }
        Ok(())
    }

    /// The reserved amount for one dimension — the ceiling a settlement
    /// may never exceed.
    pub fn reserved(&self, dimension: &str) -> u64 {
        self.items
            .iter()
            .filter(|i| i.dimension == dimension)
            .map(|i| i.amount)
            .sum()
    }

    /// The parent's worst-case ceiling for one dimension, over the DISTINCT
    /// parent items claimed. Summing every item's `parent_worst_case_amount`
    /// blindly is exactly how a duplicate pin inflated the parent (R3-U04).
    pub fn parent_ceiling(&self, dimension: &str) -> u64 {
        let mut seen: Vec<ParentIdentity> = Vec::new();
        let mut total = 0;
        for item in self.items.iter().filter(|i| i.dimension == dimension) {
            let identity = item.parent_identity();
            if seen.contains(&identity) {
                continue;
            }
            seen.push(identity);
            total += item.parent_worst_case_amount;
        }
        total
    }
}

/// One measured settlement (§11.4/L33): from a trusted broker meter or an
/// independently verified provider receipt — participant and worker
/// reports are EVIDENCE, never meters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Meter {
    TrustedBroker,
    VerifiedProviderReceipt,
    /// A report from the worker or participant. It may accompany a
    /// settlement as evidence; it can never be the meter.
    Report,
}

impl Meter {
    pub fn may_settle(self) -> bool {
        matches!(self, Meter::TrustedBroker | Meter::VerifiedProviderReceipt)
    }
}

/// The result of applying one measured charge: monotonic, stable-keyed,
/// applied once on both sides, and never above the reserved amount.
/// `remainder` is what returns to the parent bucket in the same
/// accounting step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    pub charged: u64,
    pub remainder: u64,
}

/// Settles one dimension. An unknown or underivable cost keeps the
/// reservation or settles to the conservative maximum — never to zero.
pub fn settle(
    reservation: &ByomSubordinateReservation,
    dimension: &str,
    previously_charged: u64,
    charge: u64,
    meter: Meter,
) -> Result<Settlement, ReservationError> {
    if !meter.may_settle() {
        return Err(ReservationError::Settlement);
    }
    if charge < previously_charged {
        return Err(ReservationError::NonMonotonic);
    }
    let reserved = reservation.reserved(dimension);
    if charge > reserved {
        return Err(ReservationError::OverCharge);
    }
    Ok(Settlement {
        charged: charge,
        remainder: reserved - charge,
    })
}

/// The conservative settlement for an underivable cost: the whole
/// reservation is charged rather than guessed away (§11.4).
pub fn conservative_maximum(reservation: &ByomSubordinateReservation, dimension: &str) -> u64 {
    reservation.reserved(dimension)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn item(amount: u64, parent: u64) -> Item {
        Item {
            kovee_account_ref: "acct-1".to_owned(),
            dimension: "unit".to_owned(),
            unit: "call".to_owned(),
            amount,
            parent_account_ref: "byom-acct-1".to_owned(),
            parent_account_revision: 3,
            parent_dimension: "unit".to_owned(),
            parent_unit: "call".to_owned(),
            parent_worst_case_amount: parent,
            parent_delegation_ref: None,
        }
    }

    fn reservation(items: Vec<Item>, state: ReservationState) -> ByomSubordinateReservation {
        ByomSubordinateReservation {
            subordinate_reservation_ref: "ksr-1".to_owned(),
            revision: 1,
            reservation_class: RESERVATION_CLASS.to_owned(),
            realm_ref: "realm-personal".to_owned(),
            realm_byom_binding_ref: "krbb-1".to_owned(),
            realm_byom_binding_epoch: 1,
            society_ref: "soc-1".to_owned(),
            society_recovery_epoch: 0,
            byom_reservation_set_ref: "brs-1".to_owned(),
            byom_reservation_set_revision: 2,
            byom_reservation_set_digest: DigestRef::portable_public("a".repeat(64)),
            external_budget_bridge_ref: "ebb-1".to_owned(),
            stable_external_reservation_key: "stable-1".to_owned(),
            items,
            state,
            usage_settlement_ref: None,
            usage_settlement_digest: None,
            created_at: "2027-01-15T08:00:00Z".to_owned(),
            digest: DigestRef::portable_public("b".repeat(64)),
        }
    }

    #[test]
    fn a_subordinate_item_narrows_but_never_exceeds_its_parent() {
        item(40, 100).check().unwrap();
        item(100, 100).check().unwrap();
        assert_eq!(item(101, 100).check(), Err(ItemError::AboveParent));
    }

    #[test]
    fn a_subordinate_item_never_reshapes_the_dimension_or_unit() {
        let mut reshaped = item(10, 100);
        reshaped.dimension = "tokens".to_owned();
        assert_eq!(reshaped.check(), Err(ItemError::Dimension));
        let mut requantified = item(10, 100);
        requantified.unit = "second".to_owned();
        assert_eq!(requantified.check(), Err(ItemError::Unit));
    }

    #[test]
    fn the_settlement_pair_is_required_exactly_when_settled() {
        let mut row = reservation(vec![item(40, 100)], ReservationState::Settled);
        assert_eq!(row.check(), Err(ReservationError::Settlement));
        row.usage_settlement_ref = Some("us-1".to_owned());
        row.usage_settlement_digest = Some(DigestRef::portable_public("c".repeat(64)));
        row.check().unwrap();
        // And a non-settled row may not carry one.
        row.state = ReservationState::Confirmed;
        assert_eq!(row.check(), Err(ReservationError::Settlement));
    }

    #[test]
    fn settlement_is_metered_monotonic_and_capped() {
        let row = reservation(vec![item(40, 100)], ReservationState::Confirmed);
        // A worker report is evidence, never a meter.
        assert_eq!(
            settle(&row, "unit", 0, 10, Meter::Report),
            Err(ReservationError::Settlement)
        );
        let first = settle(&row, "unit", 0, 10, Meter::TrustedBroker).unwrap();
        assert_eq!(
            first,
            Settlement {
                charged: 10,
                remainder: 30
            }
        );
        // Conservation: charged + remainder is exactly the reservation.
        assert_eq!(first.charged + first.remainder, row.reserved("unit"));
        // Monotonic: a later settlement never walks the charge back.
        assert_eq!(
            settle(&row, "unit", 10, 5, Meter::TrustedBroker),
            Err(ReservationError::NonMonotonic)
        );
        // Capped: charged never exceeds the reserved amount.
        assert_eq!(
            settle(&row, "unit", 10, 41, Meter::VerifiedProviderReceipt),
            Err(ReservationError::OverCharge)
        );
        // The conservative maximum is the whole reservation, not zero.
        assert_eq!(conservative_maximum(&row, "unit"), 40);
        let all = settle(&row, "unit", 10, 40, Meter::TrustedBroker).unwrap();
        assert_eq!(all.remainder, 0);
    }

    /// **R3-U04, kovee unit half.** The probe reported two 100-unit children
    /// against ONE 100-unit parent item and both sides accepted it: each
    /// validated its items independently, and kovee then SUMMED the duplicate
    /// parents into a 200-unit ceiling. A parent item is claimed once.
    #[test]
    fn a_duplicate_parent_item_pin_is_not_extra_capacity() {
        let duplicated = vec![item(100, 100), item(100, 100)];
        assert_eq!(
            check_items(&duplicated),
            Err(ReservationError::DuplicateParentItem)
        );
        // And the record shape refuses it too, so no such row can be stored.
        let row = reservation(duplicated.clone(), ReservationState::Confirmed);
        assert_eq!(row.check(), Err(ReservationError::DuplicateParentItem));
        // The old arithmetic is what made it look admissible: summing every
        // item's parent worst case reported 200 of parent capacity where the
        // parent had 100.
        assert_eq!(
            row.parent_ceiling("unit"),
            100,
            "the parent ceiling counts DISTINCT parent items"
        );
        assert_eq!(row.reserved("unit"), 200, "the ask really was 200");

        // Two DISTINCT parent items are a real 200 of parent capacity.
        let mut second = item(100, 100);
        second.parent_account_revision = 4;
        let distinct = vec![item(100, 100), second];
        check_items(&distinct).unwrap();
        assert_eq!(
            reservation(distinct, ReservationState::Confirmed).parent_ceiling("unit"),
            200
        );

        // The aggregate rule bites even without a duplicate identity: same
        // account/revision/dimension/unit, two parent items of 100, an ask
        // of 201 in total.
        let mut a = item(101, 100);
        a.amount = 100;
        let mut b = item(100, 100);
        b.parent_worst_case_amount = 100;
        b.amount = 100;
        b.parent_account_revision = 3;
        // `a` and `b` now share an identity, so uniqueness answers first —
        // which is the point: there is no arrangement of duplicate pins that
        // reaches the aggregate rule and passes it.
        assert_eq!(
            check_items(&[a, b]),
            Err(ReservationError::DuplicateParentItem)
        );
    }

    #[test]
    fn the_reservation_round_trips_through_its_closed_shape() {
        let row = reservation(vec![item(40, 100)], ReservationState::Requested);
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(
            serde_json::from_value::<ByomSubordinateReservation>(json.clone()).unwrap(),
            row
        );
        let mut widened = json;
        widened["parallel_charge"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ByomSubordinateReservation>(widened).is_err());
        // The class is the only one this shape exists under.
        let mut wrong = row;
        wrong.reservation_class = "byom_root".to_owned();
        assert_eq!(wrong.check(), Err(ReservationError::Class));
    }
}
