//! The D10 greenfield enablement saga: `governance_enable`,
//! `governance_show`, `governance_disable` (amendment A5 wire names).
//!
//! The machine, exactly as `byom/spec/descriptors/greenfield-enablement.json`
//! commits it:
//!
//! ```text
//! absent ──governance_enable──▶ bindings_created ──owner_cas_none_to_byom──▶ active
//!              ▲                     │        │                                │
//!              │(new epoch)          │(retry: │(governance_enable_rollback)    │(retry: same
//!              │                     │ same   ▼                                │ binding)
//!              └────────────── rolled_back  (pre-CAS only)      governance_disable
//!                                    pending bindings)                         ▼
//!                                                                          disabled
//! ```
//!
//! One invocation, TWO §12.2 command transactions — so a crash between
//! them is observable and honest:
//!
//! 1. **create** (`<key>#create`) — durably write the `KoveeRealmByomBinding`
//!    and `KoveeSocietyMapping` INERT (`status: pending`) plus the saga
//!    slot; the `KoveeGovernanceOwnerBinding` still carries
//!    `governance_owner: none`, so nothing derived may be issued from
//!    them;
//! 2. **activate** (`<key>#activate`) — CAS the owner row `none → byom` at
//!    the expected revision under the expected binding epoch, atomically
//!    with marking binding and mapping `active` and setting
//!    `owner_endpoint_ref`/`owner_binding_ref`.
//!
//! Between them the saga RE-VERIFIES the Society through byomd's
//! projection surface. A definite mismatch (the Society is no longer
//! active, its recovery epoch moved, or the endpoint re-incarnated) is
//! the saga's own definite pre-CAS failure handling: it rolls back
//! (`<key>#rollback`), voiding the pending bindings and SPENDING the
//! epoch. An unknown answer (the endpoint did not reply) is not a
//! transition at all — the slot stays `bindings_created` and the caller
//! gets `unavailable`, because guessing is not a transition
//! (greenfield-saga §5).
//!
//! Kovee is NEVER the genesis governance actor (amendment A2): the
//! Society must already exist and be `active`, verified by a byomd
//! projection read, and no Kovee operation can establish one.

use kovee_byom::bpp::{self, BppError, Endpoint, Surface};
use kovee_byom::projection::{society_show, SocietyView};
use kovee_byom::records::{
    DependencySet, EnableSubject, GovernanceDigests, KoveeGovernanceOwnerBinding,
    KoveeRealmByomBinding, KoveeSocietyMapping, COMPATIBILITY_BUNDLE,
};
use kovee_byom::scope::{overlaps, Selector};
use kovee_core::event::{
    EVENT_GOVERNANCE_ACTIVATED, EVENT_GOVERNANCE_BINDINGS_CREATED, EVENT_GOVERNANCE_DISABLED,
    EVENT_GOVERNANCE_ROLLED_BACK,
};
use kovee_core::family::DigestRef;
use kovee_core::ops::{GovernanceDisableArgs, GovernanceEnableArgs, GovernanceShowArgs};
use kovee_core::problem::{Problem, ProblemKind};
use kovee_store::{new_id, Applied, CommandScope, CrashHooks, NewEvent, Store, OWNER_ACTOR_REF};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::{json, Value};

use crate::handlers::command_outcome_bytes;
use crate::state::{internal, not_found, stale_revision, store_problem, DEFAULT_CLASSIFICATION};

/// The saga states, verbatim from the descriptor.
pub const STATE_BINDINGS_CREATED: &str = "bindings_created";
pub const STATE_ACTIVE: &str = "active";
pub const STATE_ROLLED_BACK: &str = "rolled_back";
pub const STATE_DISABLED: &str = "disabled";

/// The recovery-authorization policy of the personal profile: historical
/// RestoreLineage lookup is off until C2 slice 2 wires it.
const RECOVERY_POLICY_REF: &str = "recovery-policy-personal-none";
const HISTORICAL_RECOVERY_MODE: &str = "disabled";

/// One byomd endpoint, as the daemon resolves it. Injected so tests can
/// point at a scripted stub without touching process env.
pub type EndpointResolver = dyn Fn(&str) -> Endpoint + Send + Sync;

/// Everything one saga invocation reads from outside the store.
struct Observed {
    endpoint: Endpoint,
    incarnation: String,
    society: SocietyView,
}

fn observe(
    resolver: &EndpointResolver,
    endpoint_ref: &str,
    society_ref: &str,
) -> Result<Observed, Problem> {
    let endpoint = resolver(endpoint_ref);
    let hello = endpoint
        .hello(Surface::Governance)
        .map_err(|e| bpp::passthrough(&e))?;
    let society = match society_show(&endpoint, society_ref) {
        Ok(view) => view,
        Err(BppError::Problem(p)) if p.kind == "not_found" => {
            // The DEFINITE answer that there is no such Society. Kovee
            // may not create one: it is never the genesis governance
            // actor (amendment A2; the saga's precondition, §1).
            return Err(Problem::new(
                ProblemKind::Forbidden,
                "no pre-existing Society at the byom endpoint",
            )
            .with_detail(
                "Kovee is never the genesis governance actor: establish the Society with \
                 native society_prepare/society_bootstrap under the bootstrap human's \
                 direct governance channel first (amendment A2)",
            ));
        }
        Err(e) => return Err(bpp::passthrough(&e)),
    };
    if !society.is_active() {
        return Err(
            Problem::new(ProblemKind::Forbidden, "the target Society is not active").with_detail(
                format!(
            "society_show reports state {:?}; governance_enable requires an already-active \
             Society (greenfield-saga §1)",
            society.state
        ),
            ),
        );
    }
    Ok(Observed {
        incarnation: hello.endpoint_incarnation,
        endpoint,
        society,
    })
}

// ------------------------------------------------------ saga slot rows ----

#[derive(Debug, Clone)]
struct Slot {
    enablement_id: String,
    exact_scope_digest_hex: String,
    exact_scope_selector: String,
    binding_epoch: u64,
    state: String,
    society_ref: String,
    society_recovery_epoch: u64,
    byom_endpoint_ref: String,
    endpoint_incarnation: String,
    binding_ref: String,
    mapping_id: String,
    expected_owner_revision: u64,
    subject_digest_hex: String,
    result: Value,
}

fn slot_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(Slot, String)> {
    Ok((
        Slot {
            enablement_id: r.get(0)?,
            exact_scope_digest_hex: r.get(1)?,
            exact_scope_selector: r.get(2)?,
            binding_epoch: r.get::<_, i64>(3)? as u64,
            state: r.get(4)?,
            society_ref: r.get(5)?,
            society_recovery_epoch: r.get::<_, i64>(6)? as u64,
            byom_endpoint_ref: r.get(7)?,
            endpoint_incarnation: r.get(8)?,
            binding_ref: r.get(9)?,
            mapping_id: r.get(10)?,
            expected_owner_revision: r.get::<_, i64>(11)? as u64,
            subject_digest_hex: r.get(12)?,
            result: Value::Null,
        },
        r.get::<_, String>(13)?,
    ))
}

const SLOT_COLUMNS: &str = "enablement_id, exact_scope_digest_hex, exact_scope_selector,
     binding_epoch, state, society_ref, society_recovery_epoch, byom_endpoint_ref,
     endpoint_incarnation, binding_ref, mapping_id, expected_owner_revision,
     subject_digest_hex, result";

/// The current slot for one exact scope: the highest binding epoch. A
/// rolled-back or disabled epoch stays in the table, spent.
fn current_slot(
    conn: &Connection,
    realm: &str,
    scope_digest_hex: &str,
) -> Result<Option<Slot>, Problem> {
    let row = conn
        .query_row(
            &format!(
                "SELECT {SLOT_COLUMNS} FROM greenfield_enablements
                 WHERE realm_ref = ?1 AND exact_scope_digest_hex = ?2
                 ORDER BY binding_epoch DESC LIMIT 1"
            ),
            params![realm, scope_digest_hex],
            slot_row,
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    Ok(row.map(|(mut slot, result)| {
        slot.result = serde_json::from_str(&result).unwrap_or(Value::Null);
        slot
    }))
}

fn all_live_slots(conn: &Connection, realm: &str) -> Result<Vec<Slot>, Problem> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {SLOT_COLUMNS} FROM greenfield_enablements
             WHERE realm_ref = ?1 AND state IN ('bindings_created', 'active')"
        ))
        .map_err(|e| store_problem(e.into()))?;
    let rows = stmt
        .query_map([realm], slot_row)
        .map_err(|e| store_problem(e.into()))?;
    let mut out = Vec::new();
    for row in rows {
        let (mut slot, result) = row.map_err(|e| store_problem(e.into()))?;
        slot.result = serde_json::from_str(&result).unwrap_or(Value::Null);
        out.push(slot);
    }
    Ok(out)
}

// -------------------------------------------------------------- helpers ----

fn digests_for(store: &Store, realm: &str) -> Result<GovernanceDigests, Problem> {
    let key = store.governance_scope_key().map_err(store_problem)?;
    Ok(GovernanceDigests::new(&key, realm))
}

fn txn_digests(
    txn: &kovee_store::CommandTxn<'_>,
    realm: &str,
) -> Result<GovernanceDigests, Problem> {
    let key = kovee_store::governance_scope_key_of(txn.conn()).map_err(store_problem)?;
    Ok(GovernanceDigests::new(&key, realm))
}

fn digest_json(digest: &DigestRef) -> String {
    serde_json::to_string(digest).unwrap_or_else(|_| "{}".to_owned())
}

fn parse_digest(text: &str) -> Result<DigestRef, Problem> {
    serde_json::from_str(text).map_err(|_| internal())
}

fn forbidden(title: &str, detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::Forbidden, title).with_detail(detail)
}

fn scope_of(selector: &str) -> Result<Selector, Problem> {
    Selector::parse(selector).map_err(|e| {
        Problem::new(ProblemKind::Invalid, "invalid operation arguments").with_detail(e.to_string())
    })
}

/// The scoped idempotency key of one saga step. Both steps ride the
/// caller's single key so an exact retry resumes rather than restarts.
fn step_scope(base: &CommandScope, step: &str) -> CommandScope {
    CommandScope {
        actor_scope: base.actor_scope.clone(),
        operation: format!("{}#{step}", base.operation),
        idempotency_key: base.idempotency_key.clone(),
        request_digest: base.request_digest.clone(),
    }
}

// ------------------------------------------------------ governance_enable ----

#[allow(clippy::too_many_arguments)]
pub fn governance_enable(
    store: &mut Store,
    resolver: &EndpointResolver,
    scope: CommandScope,
    realm: String,
    args: GovernanceEnableArgs,
    now: i64,
    hooks: impl Fn(&str) -> CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let selector = scope_of(&args.exact_scope_selector)?;
    for item in &args.allowed_project_and_space_selectors {
        scope_of(item)?;
    }
    let digests = digests_for(store, &realm)?;
    let scope_digest = digests.exact_scope(&selector).map_err(|_| internal())?;
    let scope_digest_hex = scope_digest.value_hex.clone();

    // A retry after activation returns the stored identical binding
    // before any check runs — the descriptor's active→active guard.
    if let Some(slot) = current_slot(store.conn(), &realm, &scope_digest_hex)? {
        if slot.state == STATE_ACTIVE && slot_targets(&slot, &args) {
            return reply_bytes(&slot.result, slot.expected_owner_revision + 1);
        }
    }

    // Step 0: observe the endpoint and the Society. Kovee is never the
    // genesis actor, so this must answer "already active".
    let observed = observe(resolver, &args.byom_endpoint_ref, &args.society_ref)?;

    let subject = EnableSubject {
        realm_ref: realm.clone(),
        society_ref: args.society_ref.clone(),
        society_recovery_epoch: observed.society.recovery_epoch,
        byom_endpoint_ref: args.byom_endpoint_ref.clone(),
        endpoint_incarnation: observed.incarnation.clone(),
        exact_scope_selector: selector.as_str().to_owned(),
        society_mapping_revision: 1,
        owner_binding_transition: "none->byom".to_owned(),
    };
    let subject_digest = digests.enable_subject(&subject).map_err(|_| internal())?;
    if let Some(confirmed) = &args.confirmed_subject_digest {
        if *confirmed != subject_digest.value_hex {
            return Err(forbidden(
                "the confirmed subject digest does not match",
                "the exact digest the human confirmed is not the digest this enablement \
                 would commit (family contract §2.A subject digest)",
            ));
        }
    }

    // ------------------------------------------------ step 1: create ----
    let create = {
        let realm = realm.clone();
        let args = args.clone();
        let selector = selector.clone();
        let scope_digest = scope_digest.clone();
        let subject_digest = subject_digest.clone();
        let incarnation = observed.incarnation.clone();
        let recovery_epoch = observed.society.recovery_epoch;
        store.command_transaction(
            &step_scope(&scope, "create"),
            now,
            hooks("governance_enable#create"),
            move |txn| {
                create_bindings(
                    txn,
                    &realm,
                    &args,
                    &selector,
                    &scope_digest,
                    &subject_digest,
                    &incarnation,
                    recovery_epoch,
                )
            },
        )
    };
    command_outcome_bytes(create)?;

    // Re-read the slot: an exact retry of a SPENT epoch replays step 1's
    // stored bytes, so the durable state — not the replay — decides.
    let slot = current_slot(store.conn(), &realm, &scope_digest_hex)?.ok_or_else(internal)?;
    match slot.state.as_str() {
        STATE_ACTIVE => return reply_bytes(&slot.result, slot.expected_owner_revision + 1),
        STATE_ROLLED_BACK => {
            return Err(forbidden(
                "this binding epoch is spent",
                format!(
                    "binding epoch {} was rolled back and is spent: it can never activate; \
                     re-enable under a fresh idempotency key, which opens a new epoch \
                     (greenfield-saga §4)",
                    slot.binding_epoch
                ),
            ))
        }
        STATE_DISABLED => {
            return Err(forbidden(
                "this governed scope was disabled",
                "re-enablement after a governed disable is a fresh saga row under a new \
                 binding epoch, not a transition of this machine (greenfield-saga §4)",
            ))
        }
        _ => {}
    }

    // --------------------------------- pre-CAS re-verification (§5) ----
    match reverify(&observed, &slot) {
        Verification::Unchanged => {}
        Verification::Unknown(problem) => return Err(problem),
        Verification::Definite(reason) => {
            let realm_c = realm.clone();
            let slot_c = slot.clone();
            let reason_c = reason.clone();
            let rolled = store.command_transaction(
                &step_scope(&scope, "rollback"),
                now,
                hooks("governance_enable#rollback"),
                move |txn| rollback_bindings(txn, &realm_c, &slot_c, &reason_c),
            );
            command_outcome_bytes(rolled)?;
            return Err(forbidden(
                "the enablement was rolled back before activation",
                format!(
                    "{reason}; binding epoch {} is spent and can never activate — re-enable \
                     under a new epoch (greenfield-saga §4)",
                    slot.binding_epoch
                ),
            ));
        }
    }

    // ---------------------------------------------- step 2: the CAS ----
    let realm_c = realm.clone();
    let slot_c = slot.clone();
    let scope_digest_c = scope_digest.clone();
    let activate = store.command_transaction(
        &step_scope(&scope, "activate"),
        now,
        hooks("governance_enable#activate"),
        move |txn| activate_binding(txn, &realm_c, &slot_c, &scope_digest_c),
    );
    command_outcome_bytes(activate)
}

/// Whether a stored slot names exactly this command's target — the
/// "expected absent-or-identical" half of the frozen dependency set.
fn slot_targets(slot: &Slot, args: &GovernanceEnableArgs) -> bool {
    slot.society_ref == args.society_ref
        && slot.byom_endpoint_ref == args.byom_endpoint_ref
        && slot.exact_scope_selector == args.exact_scope_selector
        && args
            .expected_binding_ref
            .as_ref()
            .is_none_or(|r| *r == slot.binding_ref)
}

enum Verification {
    Unchanged,
    /// byomd answered, and the answer contradicts the pending bindings.
    Definite(String),
    /// byomd did not answer: the CAS outcome is unknown, so nothing moves.
    Unknown(Problem),
}

/// Step 2's re-check against the live endpoint. Only a verified answer
/// drives retry or rollback (greenfield-saga §5).
fn reverify(observed: &Observed, slot: &Slot) -> Verification {
    let hello = match observed.endpoint.hello(Surface::Governance) {
        Ok(hello) => hello,
        Err(e) if e.is_definite() => {
            return Verification::Definite(format!("the byom endpoint refused: {e}"))
        }
        Err(e) => return Verification::Unknown(bpp::passthrough(&e)),
    };
    if hello.endpoint_incarnation != slot.endpoint_incarnation {
        return Verification::Definite(format!(
            "the byom endpoint re-incarnated ({} → {})",
            slot.endpoint_incarnation, hello.endpoint_incarnation
        ));
    }
    let society = match society_show(&observed.endpoint, &slot.society_ref) {
        Ok(view) => view,
        Err(e) if e.is_definite() => {
            return Verification::Definite(format!("the Society is no longer readable: {e}"))
        }
        Err(e) => return Verification::Unknown(bpp::passthrough(&e)),
    };
    if !society.is_active() {
        return Verification::Definite(format!(
            "the Society left the active state (now {:?})",
            society.state
        ));
    }
    if society.recovery_epoch != slot.society_recovery_epoch {
        return Verification::Definite(format!(
            "the Society recovery epoch moved ({} → {})",
            slot.society_recovery_epoch, society.recovery_epoch
        ));
    }
    Verification::Unchanged
}

// ------------------------------------------------------ the three commits ----

#[allow(clippy::too_many_arguments)]
fn create_bindings(
    txn: &mut kovee_store::CommandTxn<'_>,
    realm: &str,
    args: &GovernanceEnableArgs,
    selector: &Selector,
    scope_digest: &DigestRef,
    subject_digest: &DigestRef,
    incarnation: &str,
    recovery_epoch: u64,
) -> Result<Applied, Problem> {
    let scope_digest_hex = scope_digest.value_hex.clone();
    let digests = txn_digests(txn, realm)?;

    // Reuse a pending slot (retry before activation), or open a new
    // epoch after a spent one. Epochs are per exact scope and monotone.
    let previous = current_slot(txn.conn(), realm, &scope_digest_hex)?;
    if let Some(slot) = &previous {
        if slot.state == STATE_BINDINGS_CREATED {
            if !slot_targets(slot, args) {
                return Err(stale_revision(slot.expected_owner_revision));
            }
            // Idempotent over (realm, exact scope digest, binding epoch):
            // the identical pending bindings, never a second row.
            return Ok(Applied {
                result: slot.result.clone(),
                revision: Some(slot.expected_owner_revision),
                event_cursor: None,
            });
        }
    }
    let binding_epoch = previous.as_ref().map_or(1, |s| s.binding_epoch + 1);

    // Overlap rejection, BEFORE creating anything (§16.6 item 1).
    check_no_overlap(txn.conn(), realm, selector, &scope_digest_hex)?;

    // The owner row: absent (expect 0), already `none`, or FROZEN by a
    // governed disable — a frozen row retains its owner arm for audit but
    // holds no active selector, so a fresh saga may re-own the scope.
    let owner = read_owner(txn.conn(), realm, &scope_digest_hex)?;
    let owner_revision = match &owner {
        None => {
            if args.expected_owner_revision != 0 {
                return Err(stale_revision(0));
            }
            // The row is created at revision 1 below.
            1
        }
        Some(row) => {
            if row.governance_owner != "none" && row.status == "active" {
                return Err(forbidden(
                    "this governed scope already has an owner",
                    "no overlapping scope selector may hold an active owner binding \
                     (byom §16.6 item 1)",
                ));
            }
            if args.expected_owner_revision != row.revision {
                return Err(stale_revision(row.revision));
            }
            // Step 1 rewrites the row for this epoch, so its revision
            // advances before the CAS reads it.
            row.revision + 1
        }
    };

    let binding_ref = new_id("krbb").map_err(store_problem)?;
    let mapping_id = new_id("ksm").map_err(store_problem)?;
    let enablement_id = new_id("gfe").map_err(store_problem)?;
    let created_at = txn.now_ts();

    let dependency_digest = digests
        .dependency_set(&DependencySet {
            realm_ref: realm.to_owned(),
            realm_revision: realm_revision(txn.conn(), realm)?,
            society_ref: args.society_ref.clone(),
            society_recovery_epoch: recovery_epoch,
            byom_endpoint_ref: args.byom_endpoint_ref.clone(),
            endpoint_incarnation: incarnation.to_owned(),
            expected_binding_ref: args.expected_binding_ref.clone(),
            society_mapping_revision: 1,
        })
        .map_err(|_| internal())?;

    let mut binding = KoveeRealmByomBinding {
        binding_ref: binding_ref.clone(),
        realm_ref: realm.to_owned(),
        binding_revision: 1,
        binding_epoch,
        predecessor_binding_ref: previous.as_ref().map(|s| s.binding_ref.clone()),
        predecessor_binding_digest: None,
        binding_lineage_ref: None,
        binding_lineage_digest: None,
        byom_endpoint_ref: args.byom_endpoint_ref.clone(),
        endpoint_incarnation: incarnation.to_owned(),
        compatibility_bundle: COMPATIBILITY_BUNDLE.to_owned(),
        delegated_principal_audience: format!("byom:{}:governance", args.byom_endpoint_ref),
        external_authorization_audience: format!(
            "byom:{}:external-authorization",
            args.byom_endpoint_ref
        ),
        historical_recovery_mode: HISTORICAL_RECOVERY_MODE.to_owned(),
        recovery_authorization_policy_ref: RECOVERY_POLICY_REF.to_owned(),
        recovery_authorization_policy_digest: digests
            .digest(
                "kovee-recovery-policy-v1",
                &json!({"policy_ref": RECOVERY_POLICY_REF, "mode": HISTORICAL_RECOVERY_MODE}),
            )
            .map_err(|_| internal())?,
        // NOT authoritative: no derived channel, credential, or permit
        // may be issued from a pending binding (greenfield-saga §2).
        status: "pending".to_owned(),
        dependency_digest,
        digest: DigestRef::scope_erasure_safe(digests.key_ref(), "0".repeat(64)),
    };
    binding.digest = binding.compute_digest(&digests).map_err(|_| internal())?;

    // The owner row is written at `none` — step 1 never owns. A frozen
    // arm is cleared here, under the NEW epoch; the disable that froze it
    // stays in the event log and in the disabled slot's stored result.
    let mut owner_row = KoveeGovernanceOwnerBinding {
        realm_ref: realm.to_owned(),
        exact_scope_selector: selector.as_str().to_owned(),
        exact_scope_digest: scope_digest.clone(),
        revision: owner_revision,
        binding_epoch,
        governance_owner: "none".to_owned(),
        owner_endpoint_ref: None,
        owner_binding_ref: None,
        cutover_ref: None,
        status: "active".to_owned(),
        digest: DigestRef::scope_erasure_safe(digests.key_ref(), "0".repeat(64)),
    };
    owner_row.digest = owner_row.compute_digest(&digests).map_err(|_| internal())?;

    let mut mapping = KoveeSocietyMapping {
        realm_ref: realm.to_owned(),
        society_ref: args.society_ref.clone(),
        society_recovery_epoch: recovery_epoch,
        allowed_project_and_space_selectors: args.allowed_project_and_space_selectors.clone(),
        classification_binding_ref: args.classification_binding_ref.clone(),
        governance_owner_binding_ref: binding_ref.clone(),
        governance_owner_binding_digest: owner_row.digest.clone(),
        status: "pending".to_owned(),
        revision: 1,
        digest: DigestRef::scope_erasure_safe(digests.key_ref(), "0".repeat(64)),
    };
    mapping.digest = mapping.compute_digest(&digests).map_err(|_| internal())?;

    write_binding(txn.conn(), &binding, &scope_digest_hex, &created_at)?;
    write_mapping(txn.conn(), &mapping, &mapping_id, &binding_ref, &created_at)?;
    write_owner(txn.conn(), &owner_row, &created_at, owner.is_none())?;

    let result = json!({
        "enablement_id": enablement_id,
        "state": STATE_BINDINGS_CREATED,
        "binding": binding,
        "mapping": mapping,
        "owner_binding": owner_row,
        "subject_digest": subject_digest.value_hex,
        "society": {
            "society_ref": args.society_ref,
            "state": "active",
            "recovery_epoch": recovery_epoch,
        },
    });

    txn.conn()
        .execute(
            "INSERT INTO greenfield_enablements (enablement_id, realm_ref,
                 exact_scope_digest_hex, exact_scope_selector, binding_epoch, state,
                 society_ref, society_recovery_epoch, byom_endpoint_ref,
                 endpoint_incarnation, binding_ref, mapping_id, expected_owner_revision,
                 subject_digest_hex, dependency_digest_hex, result, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?17)",
            params![
                enablement_id,
                realm,
                scope_digest_hex,
                selector.as_str(),
                binding_epoch as i64,
                STATE_BINDINGS_CREATED,
                args.society_ref,
                recovery_epoch as i64,
                args.byom_endpoint_ref,
                incarnation,
                binding_ref,
                mapping_id,
                owner_row.revision as i64,
                subject_digest.value_hex,
                binding.dependency_digest.value_hex,
                serde_json::to_string(&result).map_err(|_| internal())?,
                created_at,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;

    txn.audit(
        "governance.bindings-created",
        &format!("enablement={enablement_id} epoch={binding_epoch}"),
    );
    txn.append_event(NewEvent {
        stream_id: enablement_id.clone(),
        project_id: None,
        actor_ref: Some(OWNER_ACTOR_REF.to_owned()),
        event_type: EVENT_GOVERNANCE_BINDINGS_CREATED.to_owned(),
        schema_ref: "schema:kovee-realm-byom-binding-v1".to_owned(),
        resource_ref: binding_ref.clone(),
        resource_revision: Some(1),
        causation_ref: None,
        correlation_ref: enablement_id.clone(),
        classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
        payload: json!({
            "enablement_id": enablement_id,
            "binding_ref": binding_ref,
            "binding_epoch": binding_epoch,
            "state": STATE_BINDINGS_CREATED,
        }),
    })
    .map_err(store_problem)?;

    Ok(Applied {
        result,
        revision: Some(owner_row.revision),
        event_cursor: None,
    })
}

fn activate_binding(
    txn: &mut kovee_store::CommandTxn<'_>,
    realm: &str,
    slot: &Slot,
    scope_digest: &DigestRef,
) -> Result<Applied, Problem> {
    let digests = txn_digests(txn, realm)?;
    // The slot must still be pre-activation at this exact epoch.
    let current =
        current_slot(txn.conn(), realm, &slot.exact_scope_digest_hex)?.ok_or_else(internal)?;
    if current.enablement_id != slot.enablement_id || current.state != STATE_BINDINGS_CREATED {
        return Err(stale_revision(current.expected_owner_revision));
    }

    // Exact-CAS: the owner row must still be `none`, at the expected
    // revision, under the expected epoch, at this exact scope digest. A
    // changed revision, epoch, or subject digest commits nothing.
    let owner =
        read_owner(txn.conn(), realm, &slot.exact_scope_digest_hex)?.ok_or_else(internal)?;
    if owner.governance_owner != "none"
        || owner.revision != slot.expected_owner_revision
        || owner.binding_epoch != slot.binding_epoch
        || owner.exact_scope_digest.value_hex != scope_digest.value_hex
    {
        return Err(stale_revision(owner.revision));
    }
    // The CAS re-checks the overlap rule: two overlapping sagas cannot
    // both win (NoOverlappingActiveOwners).
    let selector = scope_of(&slot.exact_scope_selector)?;
    check_no_overlap(txn.conn(), realm, &selector, &slot.exact_scope_digest_hex)?;

    let mut owner_row = owner;
    owner_row.revision += 1;
    owner_row.governance_owner = "byom".to_owned();
    owner_row.owner_endpoint_ref = Some(slot.byom_endpoint_ref.clone());
    owner_row.owner_binding_ref = Some(slot.binding_ref.clone());
    owner_row.status = "active".to_owned();
    owner_row.digest = DigestRef::scope_erasure_safe(digests.key_ref(), "0".repeat(64));
    owner_row.digest = owner_row.compute_digest(&digests).map_err(|_| internal())?;
    if !owner_row.owner_arm_is_coherent() {
        return Err(internal());
    }

    let mut binding = read_binding(txn.conn(), &slot.binding_ref)?.ok_or_else(internal)?;
    binding.binding_revision += 1;
    binding.status = "active".to_owned();
    binding.digest = binding.compute_digest(&digests).map_err(|_| internal())?;

    let mut mapping = read_mapping(txn.conn(), &slot.mapping_id)?.ok_or_else(internal)?;
    mapping.revision += 1;
    mapping.status = "active".to_owned();
    mapping.governance_owner_binding_digest = owner_row.digest.clone();
    mapping.digest = mapping.compute_digest(&digests).map_err(|_| internal())?;

    let updated_at = txn.now_ts();
    write_owner(txn.conn(), &owner_row, &updated_at, false)?;
    update_binding_status(txn.conn(), &binding)?;
    update_mapping_status(txn.conn(), &mapping, &slot.mapping_id)?;

    let result = json!({
        "enablement_id": slot.enablement_id,
        "state": STATE_ACTIVE,
        "binding": binding,
        "mapping": mapping,
        "owner_binding": owner_row,
        "subject_digest": slot.subject_digest_hex,
        "society": {
            "society_ref": slot.society_ref,
            "state": "active",
            "recovery_epoch": slot.society_recovery_epoch,
        },
    });
    set_slot_state(
        txn.conn(),
        &slot.enablement_id,
        STATE_ACTIVE,
        &result,
        &updated_at,
    )?;

    txn.audit(
        "governance.activated",
        &format!(
            "enablement={} epoch={} owner=byom",
            slot.enablement_id, slot.binding_epoch
        ),
    );
    txn.append_event(NewEvent {
        stream_id: slot.enablement_id.clone(),
        project_id: None,
        actor_ref: Some(OWNER_ACTOR_REF.to_owned()),
        event_type: EVENT_GOVERNANCE_ACTIVATED.to_owned(),
        schema_ref: "schema:kovee-governance-owner-binding-v1".to_owned(),
        resource_ref: slot.binding_ref.clone(),
        resource_revision: Some(owner_row.revision),
        causation_ref: None,
        correlation_ref: slot.enablement_id.clone(),
        classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
        payload: json!({
            "enablement_id": slot.enablement_id,
            "binding_ref": slot.binding_ref,
            "binding_epoch": slot.binding_epoch,
            "governance_owner": "byom",
            "state": STATE_ACTIVE,
        }),
    })
    .map_err(store_problem)?;

    Ok(Applied {
        result,
        revision: Some(owner_row.revision),
        event_cursor: None,
    })
}

fn rollback_bindings(
    txn: &mut kovee_store::CommandTxn<'_>,
    realm: &str,
    slot: &Slot,
    reason: &str,
) -> Result<Applied, Problem> {
    let current =
        current_slot(txn.conn(), realm, &slot.exact_scope_digest_hex)?.ok_or_else(internal)?;
    if current.enablement_id != slot.enablement_id {
        return Err(stale_revision(current.expected_owner_revision));
    }
    if current.state == STATE_ROLLED_BACK {
        return Ok(Applied {
            result: current.result,
            revision: Some(current.expected_owner_revision),
            event_cursor: None,
        });
    }
    if current.state != STATE_BINDINGS_CREATED {
        // Rollback exists ONLY from bindings_created. After the CAS there
        // is no rollback, only governance_disable.
        return Err(forbidden(
            "rollback exists only before activation",
            "after the owner CAS there is no rollback, only governance_disable \
             (greenfield-saga §4)",
        ));
    }

    let updated_at = txn.now_ts();
    // Void the pending bindings; the owner row stays `none`.
    txn.conn()
        .execute(
            "UPDATE kovee_realm_byom_bindings SET status = 'void' WHERE binding_ref = ?1",
            [&slot.binding_ref],
        )
        .map_err(|e| store_problem(e.into()))?;
    txn.conn()
        .execute(
            "UPDATE kovee_society_mappings SET status = 'void' WHERE mapping_id = ?1",
            [&slot.mapping_id],
        )
        .map_err(|e| store_problem(e.into()))?;

    let result = json!({
        "enablement_id": slot.enablement_id,
        "state": STATE_ROLLED_BACK,
        "binding_ref": slot.binding_ref,
        "binding_epoch": slot.binding_epoch,
        "reason": reason,
    });
    set_slot_state(
        txn.conn(),
        &slot.enablement_id,
        STATE_ROLLED_BACK,
        &result,
        &updated_at,
    )?;

    txn.audit(
        "governance.rolled-back",
        &format!(
            "enablement={} epoch={} spent",
            slot.enablement_id, slot.binding_epoch
        ),
    );
    txn.append_event(NewEvent {
        stream_id: slot.enablement_id.clone(),
        project_id: None,
        actor_ref: Some(OWNER_ACTOR_REF.to_owned()),
        event_type: EVENT_GOVERNANCE_ROLLED_BACK.to_owned(),
        schema_ref: "schema:kovee-realm-byom-binding-v1".to_owned(),
        resource_ref: slot.binding_ref.clone(),
        resource_revision: None,
        causation_ref: None,
        correlation_ref: slot.enablement_id.clone(),
        classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
        payload: json!({
            "enablement_id": slot.enablement_id,
            "binding_epoch": slot.binding_epoch,
            "state": STATE_ROLLED_BACK,
        }),
    })
    .map_err(store_problem)?;

    Ok(Applied {
        result,
        revision: Some(slot.expected_owner_revision),
        event_cursor: None,
    })
}

// ----------------------------------------------------- governance_disable ----

pub fn governance_disable(
    store: &mut Store,
    scope: CommandScope,
    realm: String,
    args: GovernanceDisableArgs,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let digests = txn_digests(txn, &realm)?;
        let slot = slot_by_binding(txn.conn(), &realm, &args.binding_ref)?.ok_or_else(not_found)?;
        if slot.state != STATE_ACTIVE {
            return Err(forbidden(
                "only an active binding can be disabled",
                format!(
                    "the enablement is {:?}; governance_disable exists only from active \
                     (greenfield-saga §4)",
                    slot.state
                ),
            ));
        }
        // Always step-up: in the personal profile the exact-digest
        // confirmation is the honest stand-in (developer assurance).
        if args.confirmed_subject_digest != slot.subject_digest_hex {
            return Err(forbidden(
                "the confirmed subject digest does not match",
                "governance_disable is always step-up: the exact subject digest of the \
                 active enablement must be confirmed",
            ));
        }
        let mut owner =
            read_owner(txn.conn(), &realm, &slot.exact_scope_digest_hex)?.ok_or_else(internal)?;
        if owner.revision != args.expected_owner_revision {
            return Err(stale_revision(owner.revision));
        }
        if owner.status != "active" {
            return Err(forbidden(
                "the owner binding is already frozen",
                "a frozen row retains its owner arm for audit and holds no active selector",
            ));
        }
        owner.revision += 1;
        // Freeze: status active→frozen, the owner arm RETAINED for audit.
        owner.status = "frozen".to_owned();
        owner.digest = owner.compute_digest(&digests).map_err(|_| internal())?;

        let mut binding = read_binding(txn.conn(), &slot.binding_ref)?.ok_or_else(internal)?;
        binding.binding_revision += 1;
        // Derived channels and permits invalidate with the binding.
        binding.status = "void".to_owned();
        binding.digest = binding.compute_digest(&digests).map_err(|_| internal())?;

        let updated_at = txn.now_ts();
        write_owner(txn.conn(), &owner, &updated_at, false)?;
        update_binding_status(txn.conn(), &binding)?;
        txn.conn()
            .execute(
                "UPDATE kovee_society_mappings SET status = 'void' WHERE mapping_id = ?1",
                [&slot.mapping_id],
            )
            .map_err(|e| store_problem(e.into()))?;
        // Every credential derived from this binding stops being usable.
        txn.conn()
            .execute(
                "UPDATE delegated_principal_credentials
                 SET consumed_at = COALESCE(consumed_at, ?2),
                     consumed_operation = COALESCE(consumed_operation, 'governance_disable')
                 WHERE binding_ref = ?1",
                params![slot.binding_ref, now],
            )
            .map_err(|e| store_problem(e.into()))?;

        let result = json!({
            "enablement_id": slot.enablement_id,
            "state": STATE_DISABLED,
            "binding": binding,
            "owner_binding": owner,
        });
        set_slot_state(
            txn.conn(),
            &slot.enablement_id,
            STATE_DISABLED,
            &result,
            &updated_at,
        )?;

        txn.audit(
            "governance.disabled",
            &format!(
                "enablement={} epoch={} owner-frozen",
                slot.enablement_id, slot.binding_epoch
            ),
        );
        txn.append_event(NewEvent {
            stream_id: slot.enablement_id.clone(),
            project_id: None,
            actor_ref: Some(OWNER_ACTOR_REF.to_owned()),
            event_type: EVENT_GOVERNANCE_DISABLED.to_owned(),
            schema_ref: "schema:kovee-governance-owner-binding-v1".to_owned(),
            resource_ref: slot.binding_ref.clone(),
            resource_revision: Some(owner.revision),
            causation_ref: None,
            correlation_ref: slot.enablement_id.clone(),
            classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
            payload: json!({
                "enablement_id": slot.enablement_id,
                "binding_epoch": slot.binding_epoch,
                "state": STATE_DISABLED,
            }),
        })
        .map_err(store_problem)?;

        let revision = owner.revision;
        Ok(Applied {
            result,
            revision: Some(revision),
            event_cursor: None,
        })
    });
    command_outcome_bytes(outcome)
}

// -------------------------------------------------------- governance_show ----

/// The query-first restore surface (greenfield-saga §5): the recorded
/// saga state, never a guess and never a mutation.
pub fn governance_show(
    store: &Store,
    realm: &str,
    args: &GovernanceShowArgs,
) -> Result<Vec<u8>, Problem> {
    let conn = store.conn();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {SLOT_COLUMNS} FROM greenfield_enablements
             WHERE realm_ref = ?1 ORDER BY binding_epoch ASC, enablement_id ASC"
        ))
        .map_err(|e| store_problem(e.into()))?;
    let rows = stmt
        .query_map([realm], slot_row)
        .map_err(|e| store_problem(e.into()))?;

    let mut enablements = Vec::new();
    let mut governance_owner = "none";
    for row in rows {
        let (slot, result) = row.map_err(|e| store_problem(e.into()))?;
        if let Some(want) = &args.binding_ref {
            if slot.binding_ref != *want {
                continue;
            }
        }
        if slot.state == STATE_ACTIVE {
            governance_owner = "byom";
        }
        let stored: Value = serde_json::from_str(&result).unwrap_or(Value::Null);
        enablements.push(json!({
            "enablement_id": slot.enablement_id,
            "state": slot.state,
            "binding_epoch": slot.binding_epoch,
            "exact_scope_selector": slot.exact_scope_selector,
            "exact_scope_digest": slot.exact_scope_digest_hex,
            "society_ref": slot.society_ref,
            "society_recovery_epoch": slot.society_recovery_epoch,
            "byom_endpoint_ref": slot.byom_endpoint_ref,
            "endpoint_incarnation": slot.endpoint_incarnation,
            "binding_ref": slot.binding_ref,
            "subject_digest": slot.subject_digest_hex,
            "record": stored,
        }));
    }
    if args.binding_ref.is_some() && enablements.is_empty() {
        return Err(not_found());
    }

    let owner_bindings = read_all_owners(conn, realm)?;
    crate::handlers::ok_reply(
        json!({
            "realm_id": realm,
            "governance_owner": governance_owner,
            "compatibility_bundle": COMPATIBILITY_BUNDLE,
            "enablements": enablements,
            "owner_bindings": owner_bindings,
        }),
        None,
    )
}

// ---------------------------------------------- the active governed seam ----

/// The realm's ACTIVE governed-work seam: the `KoveeRealmByomBinding` and
/// the `KoveeSocietyMapping` an `active` enablement slot points at. Every
/// slice-2 operation starts here — a pending, void, or frozen binding is
/// not a seam, and `None` means this realm has no governed work at all.
pub fn active_seam(
    conn: &Connection,
    realm: &str,
) -> Result<Option<(KoveeRealmByomBinding, KoveeSocietyMapping)>, Problem> {
    for slot in all_live_slots(conn, realm)? {
        if slot.state != STATE_ACTIVE {
            continue;
        }
        let Some(binding) = read_binding(conn, &slot.binding_ref)? else {
            continue;
        };
        let Some(mapping) = read_mapping(conn, &slot.mapping_id)? else {
            continue;
        };
        if binding.status == "active" && mapping.status == "active" {
            return Ok(Some((binding, mapping)));
        }
    }
    Ok(None)
}

// ------------------------------------------------------------- row access ----

fn realm_revision(conn: &Connection, realm: &str) -> Result<u64, Problem> {
    conn.query_row(
        "SELECT revision FROM realms WHERE realm_id = ?1",
        [realm],
        |r| r.get::<_, i64>(0),
    )
    .optional()
    .map_err(|e| store_problem(e.into()))?
    .map(|r| r as u64)
    .ok_or_else(not_found)
}

fn check_no_overlap(
    conn: &Connection,
    realm: &str,
    selector: &Selector,
    own_scope_digest_hex: &str,
) -> Result<(), Problem> {
    // Rejection is the absence of a transition: an overlapping ACTIVE
    // owner selector, or an overlapping pending enablement past step 1,
    // refuses before anything is created (§16.6 item 1).
    for slot in all_live_slots(conn, realm)? {
        if slot.exact_scope_digest_hex == own_scope_digest_hex {
            continue;
        }
        let other = scope_of(&slot.exact_scope_selector)?;
        if overlaps(selector, &other) {
            return Err(forbidden(
                "an overlapping governed scope is already enabled",
                format!(
                    "the scope {:?} overlaps {:?}, which is {} (byom §16.6 item 1: no \
                     overlapping active owner selectors)",
                    selector.as_str(),
                    slot.exact_scope_selector,
                    slot.state
                ),
            ));
        }
    }
    for owner in read_all_owner_rows(conn, realm)? {
        if owner.exact_scope_digest.value_hex == own_scope_digest_hex
            || owner.governance_owner == "none"
            || owner.status != "active"
        {
            continue;
        }
        let other = scope_of(&owner.exact_scope_selector)?;
        if overlaps(selector, &other) {
            return Err(forbidden(
                "an overlapping governed scope already has an owner",
                format!(
                    "the scope {:?} overlaps the active owner selector {:?}",
                    selector.as_str(),
                    owner.exact_scope_selector
                ),
            ));
        }
    }
    Ok(())
}

const BINDING_COLUMNS: &str = "binding_ref, realm_ref, binding_revision, binding_epoch,
     predecessor_binding_ref, byom_endpoint_ref, endpoint_incarnation, compatibility_bundle,
     delegated_principal_audience, external_authorization_audience, historical_recovery_mode,
     recovery_authorization_policy_ref, recovery_authorization_policy_digest, status,
     dependency_digest, digest";

fn binding_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Vec<String>> {
    let mut out = Vec::with_capacity(16);
    for i in 0..16 {
        out.push(match i {
            2 | 3 => r.get::<_, i64>(i)?.to_string(),
            4 => r.get::<_, Option<String>>(i)?.unwrap_or_default(),
            _ => r.get::<_, String>(i)?,
        });
    }
    Ok(out)
}

fn read_binding(
    conn: &Connection,
    binding_ref: &str,
) -> Result<Option<KoveeRealmByomBinding>, Problem> {
    let row = conn
        .query_row(
            &format!(
                "SELECT {BINDING_COLUMNS} FROM kovee_realm_byom_bindings WHERE binding_ref = ?1"
            ),
            [binding_ref],
            binding_from_row,
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    let Some(v) = row else { return Ok(None) };
    Ok(Some(KoveeRealmByomBinding {
        binding_ref: v[0].clone(),
        realm_ref: v[1].clone(),
        binding_revision: v[2].parse().unwrap_or(0),
        binding_epoch: v[3].parse().unwrap_or(0),
        predecessor_binding_ref: (!v[4].is_empty()).then(|| v[4].clone()),
        predecessor_binding_digest: None,
        binding_lineage_ref: None,
        binding_lineage_digest: None,
        byom_endpoint_ref: v[5].clone(),
        endpoint_incarnation: v[6].clone(),
        compatibility_bundle: v[7].clone(),
        delegated_principal_audience: v[8].clone(),
        external_authorization_audience: v[9].clone(),
        historical_recovery_mode: v[10].clone(),
        recovery_authorization_policy_ref: v[11].clone(),
        recovery_authorization_policy_digest: parse_digest(&v[12])?,
        status: v[13].clone(),
        dependency_digest: parse_digest(&v[14])?,
        digest: parse_digest(&v[15])?,
    }))
}

fn write_binding(
    conn: &Connection,
    binding: &KoveeRealmByomBinding,
    scope_digest_hex: &str,
    created_at: &str,
) -> Result<(), Problem> {
    conn.execute(
        "INSERT INTO kovee_realm_byom_bindings (binding_ref, realm_ref,
             exact_scope_digest_hex, binding_revision,
             binding_epoch, predecessor_binding_ref, byom_endpoint_ref, endpoint_incarnation,
             compatibility_bundle, delegated_principal_audience,
             external_authorization_audience, historical_recovery_mode,
             recovery_authorization_policy_ref, recovery_authorization_policy_digest,
             status, dependency_digest, digest, created_at)
         VALUES (?1,?2,?18,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
        params![
            binding.binding_ref,
            binding.realm_ref,
            binding.binding_revision as i64,
            binding.binding_epoch as i64,
            binding.predecessor_binding_ref,
            binding.byom_endpoint_ref,
            binding.endpoint_incarnation,
            binding.compatibility_bundle,
            binding.delegated_principal_audience,
            binding.external_authorization_audience,
            binding.historical_recovery_mode,
            binding.recovery_authorization_policy_ref,
            digest_json(&binding.recovery_authorization_policy_digest),
            binding.status,
            digest_json(&binding.dependency_digest),
            digest_json(&binding.digest),
            created_at,
            scope_digest_hex,
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

fn update_binding_status(
    conn: &Connection,
    binding: &KoveeRealmByomBinding,
) -> Result<(), Problem> {
    conn.execute(
        "UPDATE kovee_realm_byom_bindings
         SET binding_revision = ?2, status = ?3, digest = ?4 WHERE binding_ref = ?1",
        params![
            binding.binding_ref,
            binding.binding_revision as i64,
            binding.status,
            digest_json(&binding.digest),
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

type MappingTuple = (
    String,
    String,
    i64,
    String,
    String,
    String,
    String,
    String,
    i64,
    String,
);

fn read_mapping(
    conn: &Connection,
    mapping_id: &str,
) -> Result<Option<KoveeSocietyMapping>, Problem> {
    let row: Option<MappingTuple> = conn
        .query_row(
            "SELECT realm_ref, society_ref, society_recovery_epoch,
                    allowed_project_and_space_selectors, classification_binding_ref,
                    governance_owner_binding_ref, governance_owner_binding_digest, status,
                    revision, digest
             FROM kovee_society_mappings WHERE mapping_id = ?1",
            [mapping_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            },
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    let Some(v) = row else { return Ok(None) };
    Ok(Some(KoveeSocietyMapping {
        realm_ref: v.0,
        society_ref: v.1,
        society_recovery_epoch: v.2 as u64,
        allowed_project_and_space_selectors: serde_json::from_str(&v.3).map_err(|_| internal())?,
        classification_binding_ref: v.4,
        governance_owner_binding_ref: v.5,
        governance_owner_binding_digest: parse_digest(&v.6)?,
        status: v.7,
        revision: v.8 as u64,
        digest: parse_digest(&v.9)?,
    }))
}

fn write_mapping(
    conn: &Connection,
    mapping: &KoveeSocietyMapping,
    mapping_id: &str,
    binding_ref: &str,
    created_at: &str,
) -> Result<(), Problem> {
    conn.execute(
        "INSERT INTO kovee_society_mappings (mapping_id, realm_ref, society_ref,
             society_recovery_epoch, allowed_project_and_space_selectors,
             classification_binding_ref, governance_owner_binding_ref,
             governance_owner_binding_digest, status, revision, digest, binding_ref,
             created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            mapping_id,
            mapping.realm_ref,
            mapping.society_ref,
            mapping.society_recovery_epoch as i64,
            serde_json::to_string(&mapping.allowed_project_and_space_selectors)
                .map_err(|_| internal())?,
            mapping.classification_binding_ref,
            mapping.governance_owner_binding_ref,
            digest_json(&mapping.governance_owner_binding_digest),
            mapping.status,
            mapping.revision as i64,
            digest_json(&mapping.digest),
            binding_ref,
            created_at,
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

fn update_mapping_status(
    conn: &Connection,
    mapping: &KoveeSocietyMapping,
    mapping_id: &str,
) -> Result<(), Problem> {
    conn.execute(
        "UPDATE kovee_society_mappings
         SET revision = ?2, status = ?3, governance_owner_binding_digest = ?4, digest = ?5
         WHERE mapping_id = ?1",
        params![
            mapping_id,
            mapping.revision as i64,
            mapping.status,
            digest_json(&mapping.governance_owner_binding_digest),
            digest_json(&mapping.digest),
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

const OWNER_COLUMNS: &str = "realm_ref, exact_scope_selector, exact_scope_digest, revision,
     binding_epoch, governance_owner, owner_endpoint_ref, owner_binding_ref, cutover_ref,
     status, digest";

type OwnerTuple = (
    String,
    String,
    String,
    i64,
    i64,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    String,
);

fn owner_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<OwnerTuple> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
    ))
}

fn owner_from_tuple(v: OwnerTuple) -> Result<KoveeGovernanceOwnerBinding, Problem> {
    Ok(KoveeGovernanceOwnerBinding {
        realm_ref: v.0,
        exact_scope_selector: v.1,
        exact_scope_digest: parse_digest(&v.2)?,
        revision: v.3 as u64,
        binding_epoch: v.4 as u64,
        governance_owner: v.5,
        owner_endpoint_ref: v.6,
        owner_binding_ref: v.7,
        cutover_ref: v.8,
        status: v.9,
        digest: parse_digest(&v.10)?,
    })
}

fn read_owner(
    conn: &Connection,
    realm: &str,
    scope_digest_hex: &str,
) -> Result<Option<KoveeGovernanceOwnerBinding>, Problem> {
    let row = conn
        .query_row(
            &format!(
                "SELECT {OWNER_COLUMNS} FROM kovee_governance_owner_bindings
                 WHERE realm_ref = ?1 AND exact_scope_digest_hex = ?2"
            ),
            params![realm, scope_digest_hex],
            owner_from_row,
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    row.map(owner_from_tuple).transpose()
}

fn read_all_owner_rows(
    conn: &Connection,
    realm: &str,
) -> Result<Vec<KoveeGovernanceOwnerBinding>, Problem> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {OWNER_COLUMNS} FROM kovee_governance_owner_bindings
             WHERE realm_ref = ?1 ORDER BY exact_scope_digest_hex ASC"
        ))
        .map_err(|e| store_problem(e.into()))?;
    let rows = stmt
        .query_map([realm], owner_from_row)
        .map_err(|e| store_problem(e.into()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(owner_from_tuple(row.map_err(|e| store_problem(e.into()))?)?);
    }
    Ok(out)
}

fn read_all_owners(conn: &Connection, realm: &str) -> Result<Value, Problem> {
    Ok(Value::Array(
        read_all_owner_rows(conn, realm)?
            .into_iter()
            .map(|o| serde_json::to_value(o).unwrap_or(Value::Null))
            .collect(),
    ))
}

fn write_owner(
    conn: &Connection,
    owner: &KoveeGovernanceOwnerBinding,
    at: &str,
    insert: bool,
) -> Result<(), Problem> {
    let hex = owner.exact_scope_digest.value_hex.clone();
    if insert {
        conn.execute(
            "INSERT INTO kovee_governance_owner_bindings (realm_ref, exact_scope_digest_hex,
                 exact_scope_selector, exact_scope_digest, revision, binding_epoch,
                 governance_owner, owner_endpoint_ref, owner_binding_ref, cutover_ref,
                 status, digest, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13)",
            params![
                owner.realm_ref,
                hex,
                owner.exact_scope_selector,
                digest_json(&owner.exact_scope_digest),
                owner.revision as i64,
                owner.binding_epoch as i64,
                owner.governance_owner,
                owner.owner_endpoint_ref,
                owner.owner_binding_ref,
                owner.cutover_ref,
                owner.status,
                digest_json(&owner.digest),
                at,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
        return Ok(());
    }
    conn.execute(
        "UPDATE kovee_governance_owner_bindings
         SET revision = ?3, binding_epoch = ?4, governance_owner = ?5,
             owner_endpoint_ref = ?6, owner_binding_ref = ?7, status = ?8, digest = ?9,
             updated_at = ?10
         WHERE realm_ref = ?1 AND exact_scope_digest_hex = ?2",
        params![
            owner.realm_ref,
            hex,
            owner.revision as i64,
            owner.binding_epoch as i64,
            owner.governance_owner,
            owner.owner_endpoint_ref,
            owner.owner_binding_ref,
            owner.status,
            digest_json(&owner.digest),
            at,
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

fn slot_by_binding(
    conn: &Connection,
    realm: &str,
    binding_ref: &str,
) -> Result<Option<Slot>, Problem> {
    let row = conn
        .query_row(
            &format!(
                "SELECT {SLOT_COLUMNS} FROM greenfield_enablements
                 WHERE realm_ref = ?1 AND binding_ref = ?2"
            ),
            params![realm, binding_ref],
            slot_row,
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    Ok(row.map(|(mut slot, result)| {
        slot.result = serde_json::from_str(&result).unwrap_or(Value::Null);
        slot
    }))
}

fn set_slot_state(
    conn: &Connection,
    enablement_id: &str,
    state: &str,
    result: &Value,
    updated_at: &str,
) -> Result<(), Problem> {
    conn.execute(
        "UPDATE greenfield_enablements SET state = ?2, result = ?3, updated_at = ?4
         WHERE enablement_id = ?1",
        params![
            enablement_id,
            state,
            serde_json::to_string(result).map_err(|_| internal())?,
            updated_at,
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

fn reply_bytes(result: &Value, revision: u64) -> Result<Vec<u8>, Problem> {
    crate::handlers::ok_reply(result.clone(), Some(revision))
}
