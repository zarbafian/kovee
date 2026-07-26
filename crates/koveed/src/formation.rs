//! The endeavor-promotion saga client: `endeavor_promotion_prepare`,
//! `_start`, `_show`, `_cancel`, `_reconcile` (the A5 wire names for
//! §11.6's `mission_promotion_*` row), driving the
//! `EndeavorFormationIntent`/`Slot`/`Attempt` machine of
//! `byom/spec/descriptors/endeavor-formation.json` against a real byomd.
//!
//! The shape of one promotion, and where the durability lines fall:
//!
//! ```text
//! prepare   ── one commit ──▶ intent: prepared / slot: held
//!             (bundle + intent; NO external contact at all)
//!
//! cancel    ── one commit ──▶ canceled / released     (only from prepared)
//!
//! start     ─ commit #attempt ─▶ submitting  ← durable BEFORE any byte
//!                                              leaves Kovee
//!             │
//!             ├─ signed result ─ commit #result ─▶ byom_committed
//!             │                  commit #link   ─▶ linking ─▶ linked
//!             ├─ no reply ────── commit #unknown ─▶ remote_unknown
//!             └─ tombstone ───── commit #tombstone ─▶ canceled / released
//!
//! reconcile ─ external_command_result_query ─▶ one of five facts ─▶ one row
//!             (+ external_command_terminalize when asked, from ambiguous)
//! ```
//!
//! Three things this module makes structural rather than careful:
//!
//! 1. **The slot is released by exactly four things** — a pre-send cancel,
//!    a verified tombstone, a verified `historically_fenced_absent`, and a
//!    committed ExternalLink. There is no timeout path, so a lost reply
//!    can never be mistaken for "nothing happened".
//! 2. **`submitting` is durable before the send.** A crash mid-send leaves
//!    `submitting` plus an attempt row, which `reconcile` resolves from
//!    byom's own signed fact. Kovee never re-sends on its own guess.
//! 3. **The stable command bytes never change.** They are pinned at
//!    prepare, digested once, and every attempt replaces only the expiring
//!    authentication envelope — so a resubmission rides the SAME byom
//!    idempotency domain and cannot form a second Endeavor.

use kovee_byom::bpp::{self, BppError, Endpoint, Surface, BPP_VERSION};
use kovee_byom::credential::{
    DelegatedPrincipalCredential, Delegation, DpcMint, MintContext, SenderConstraint,
    GATEWAY_ISSUER_REF,
};
use kovee_byom::formation::{
    may_cancel, may_submit, resolve, AttemptState, Fact, IntentState, Move,
};
use kovee_byom::hostint::{self, BindingPin};
use kovee_byom::records::{GovernanceDigests, KoveeRealmByomBinding, KoveeSocietyMapping};
use kovee_core::event::{
    EVENT_FORMATION_AMBIGUOUS, EVENT_FORMATION_AWAITING_PRINCIPAL, EVENT_FORMATION_BYOM_COMMITTED,
    EVENT_FORMATION_CANCELED, EVENT_FORMATION_LINKED, EVENT_FORMATION_LINKING,
    EVENT_FORMATION_PREPARED, EVENT_FORMATION_REMOTE_UNKNOWN, EVENT_FORMATION_SUBMITTING,
};
use kovee_core::family::DigestRef;
use kovee_core::ops::{
    PromotionCancelArgs, PromotionPrepareArgs, PromotionReconcileArgs, PromotionShowArgs,
    PromotionStartArgs,
};
use kovee_core::problem::{Problem, ProblemKind};
use kovee_store::{new_id, Applied, CommandScope, CrashHooks, NewEvent, Store, OWNER_ACTOR_REF};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::{json, Value};

use crate::governance::{active_seam, EndpointResolver};
use crate::handlers::command_outcome_bytes;
use crate::state::{internal, not_found, stale_revision, store_problem, DEFAULT_CLASSIFICATION};

/// The one operation this saga drives on byom's governance surface.
pub const OPERATION: &str = "kovee_endeavor_form";

/// Kovee's own preimage tags for the rows it owns.
const TAG_INTENT: &str = "kovee-endeavor-formation-intent-v1";
const TAG_SLOT: &str = "kovee-endeavor-formation-slot-v1";
const TAG_ATTEMPT: &str = "kovee-endeavor-formation-attempt-v1";
const TAG_LINK: &str = "kovee-external-link-v1";
const TAG_DEPS: &str = "kovee-formation-dependency-set-v1";
const TAG_FRONTIER: &str = "kovee-formation-frontier-v1";
/// The per-Society IdempotencyDomain index tag (§14.2, PROFILE §5): the
/// digest is always the keyed `scope_erasure_safe` class.
const TAG_DOMAIN: &str = "kovee-idempotency-domain-v1";

/// The honest assurance label of the personal profile: the UID-checked
/// owner socket, not a phishing-resistant factor.
const ASSURANCE_LEVEL: &str = "personal-uds-owner";

/// The credential lifetime one attempt mints (§14.4 short expiry).
const CREDENTIAL_LIFETIME_SECONDS: u64 = 120;

// ------------------------------------------------------------ the rows ----

/// The durable formation intent, as the saga reads it.
#[derive(Debug, Clone)]
struct Intent {
    formation_id: String,
    revision: u64,
    realm_ref: String,
    project_id: String,
    space_id: String,
    branch_id: String,
    society_ref: String,
    society_recovery_epoch: u64,
    byom_endpoint_ref: String,
    command_endpoint_incarnation: String,
    realm_byom_binding_ref: String,
    requested_by_principal: String,
    source_actor_binding_digest: DigestRef,
    client_formation_key: String,
    byom_command_idempotency_key: String,
    idempotency_domain_digest: DigestRef,
    canonical_byom_command_digest: DigestRef,
    formation_slot_ref: String,
    formation_slot_generation: u64,
    latest_attempt_ref: Option<String>,
    latest_authentication_observation_ref: Option<String>,
    state: IntentState,
    command_bytes: Value,
    result_envelope: Option<Value>,
}

const INTENT_COLUMNS: &str = "formation_id, revision, realm_ref, project_id, space_id, branch_id,
     society_ref, society_recovery_epoch, byom_endpoint_ref, command_endpoint_incarnation,
     realm_byom_binding_ref, requested_by_principal, source_actor_binding_digest,
     client_formation_key, byom_command_idempotency_key, idempotency_domain_digest,
     canonical_byom_command_digest, formation_slot_ref, formation_slot_generation,
     latest_attempt_ref, latest_authentication_observation_ref, state,
     command_bytes, result_envelope";

fn intent_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Intent> {
    let digest = |text: String| -> DigestRef {
        serde_json::from_str(&text).unwrap_or_else(|_| DigestRef::portable_public("0".repeat(64)))
    };
    let state_text: String = r.get(21)?;
    Ok(Intent {
        formation_id: r.get(0)?,
        revision: r.get::<_, i64>(1)? as u64,
        realm_ref: r.get(2)?,
        project_id: r.get(3)?,
        space_id: r.get(4)?,
        branch_id: r.get(5)?,
        society_ref: r.get(6)?,
        society_recovery_epoch: r.get::<_, i64>(7)? as u64,
        byom_endpoint_ref: r.get(8)?,
        command_endpoint_incarnation: r.get(9)?,
        realm_byom_binding_ref: r.get(10)?,
        requested_by_principal: r.get(11)?,
        source_actor_binding_digest: digest(r.get(12)?),
        client_formation_key: r.get(13)?,
        byom_command_idempotency_key: r.get(14)?,
        idempotency_domain_digest: digest(r.get(15)?),
        canonical_byom_command_digest: digest(r.get(16)?),
        formation_slot_ref: r.get(17)?,
        formation_slot_generation: r.get::<_, i64>(18)? as u64,
        latest_attempt_ref: r.get(19)?,
        latest_authentication_observation_ref: r.get(20)?,
        state: IntentState::parse(&state_text).unwrap_or(IntentState::Ambiguous),
        command_bytes: serde_json::from_str(&r.get::<_, String>(22)?).unwrap_or(Value::Null),
        result_envelope: r
            .get::<_, Option<String>>(23)?
            .and_then(|t| serde_json::from_str(&t).ok()),
    })
}

fn read_intent(conn: &Connection, realm: &str, id: &str) -> Result<Option<Intent>, Problem> {
    conn.query_row(
        &format!(
            "SELECT {INTENT_COLUMNS} FROM endeavor_formation_intents
             WHERE realm_ref = ?1 AND formation_id = ?2"
        ),
        params![realm, id],
        intent_from_row,
    )
    .optional()
    .map_err(|e| store_problem(e.into()))
}

fn read_intent_by_key(
    conn: &Connection,
    realm: &str,
    principal: &str,
    client_formation_key: &str,
) -> Result<Option<Intent>, Problem> {
    conn.query_row(
        &format!(
            "SELECT {INTENT_COLUMNS} FROM endeavor_formation_intents
             WHERE realm_ref = ?1 AND requested_by_principal = ?2 AND client_formation_key = ?3"
        ),
        params![realm, principal, client_formation_key],
        intent_from_row,
    )
    .optional()
    .map_err(|e| store_problem(e.into()))
}

fn all_intents(conn: &Connection, realm: &str) -> Result<Vec<Intent>, Problem> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {INTENT_COLUMNS} FROM endeavor_formation_intents
             WHERE realm_ref = ?1 ORDER BY created_at ASC, formation_id ASC"
        ))
        .map_err(|e| store_problem(e.into()))?;
    let rows = stmt
        .query_map([realm], intent_from_row)
        .map_err(|e| store_problem(e.into()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| store_problem(e.into()))?);
    }
    Ok(out)
}

fn slot_state(conn: &Connection, slot_id: &str) -> Result<Option<(String, u64)>, Problem> {
    conn.query_row(
        "SELECT state, generation FROM endeavor_formation_slots WHERE slot_id = ?1",
        [slot_id],
        |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)),
    )
    .optional()
    .map_err(|e| store_problem(e.into()))
}

// ------------------------------------------------------------- helpers ----

fn digest_json(digest: &DigestRef) -> String {
    serde_json::to_string(digest).unwrap_or_else(|_| "{}".to_owned())
}

fn forbidden(title: &str, detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::Forbidden, title).with_detail(detail)
}

/// The scoped idempotency key of one saga step: every step rides the
/// caller's single key so an exact retry RESUMES rather than restarts.
fn step_scope(base: &CommandScope, step: &str) -> CommandScope {
    CommandScope {
        actor_scope: base.actor_scope.clone(),
        operation: format!("{}#{step}", base.operation),
        idempotency_key: base.idempotency_key.clone(),
        request_digest: base.request_digest.clone(),
    }
}

fn digests_of(conn: &Connection, realm: &str) -> Result<GovernanceDigests, Problem> {
    let key = kovee_store::governance_scope_key_of(conn).map_err(store_problem)?;
    Ok(GovernanceDigests::new(&key, realm))
}

/// The per-Society IdempotencyDomain digest: always the keyed
/// `scope_erasure_safe` class over the per-Society index key. Deriving it
/// from the stable command identity (never from a wall clock) is what
/// makes a resubmission ride the SAME domain.
fn domain_digest(
    digests: &GovernanceDigests,
    society_ref: &str,
    principal: &str,
    client_formation_key: &str,
) -> Result<DigestRef, Problem> {
    digests
        .digest(
            TAG_DOMAIN,
            &json!({
                "society_ref": society_ref,
                "requested_by_principal": principal,
                "client_formation_key": client_formation_key,
                "operation": OPERATION,
            }),
        )
        .map_err(|_| internal())
}

/// The byom command idempotency key — one Kovee intent, one byom key
/// (§16.3: no hidden multi-command saga behind the pair).
fn command_key(domain: &DigestRef) -> String {
    format!("kef-{}", &domain.value_hex[..32])
}

/// The narrow R42 recovery-workload token byomd publishes for the
/// installed binding. It is byomd-minted and read from the endpoint's own
/// channel directory — Kovee never chooses it.
///
/// Resolution: `$KOVEE_BYOM_RECOVERY_TOKEN`, else
/// `$KOVEE_BYOM_CHANNELS_DIR/recovery-workload-<binding_ref>.token`.
fn recovery_workload_token(binding_ref: &str) -> Option<String> {
    if let Some(token) = std::env::var_os("KOVEE_BYOM_RECOVERY_TOKEN") {
        let token = token.to_string_lossy().trim().to_owned();
        if !token.is_empty() {
            return Some(token);
        }
    }
    let dir = std::env::var_os("KOVEE_BYOM_CHANNELS_DIR")?;
    let path = std::path::Path::new(&dir).join(format!("recovery-workload-{binding_ref}.token"));
    std::fs::read_to_string(path)
        .ok()
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
}

fn event_type(state: IntentState) -> &'static str {
    match state {
        IntentState::Prepared => EVENT_FORMATION_PREPARED,
        IntentState::Submitting => EVENT_FORMATION_SUBMITTING,
        IntentState::RemoteUnknown => EVENT_FORMATION_REMOTE_UNKNOWN,
        IntentState::AwaitingPrincipal => EVENT_FORMATION_AWAITING_PRINCIPAL,
        IntentState::ByomCommitted => EVENT_FORMATION_BYOM_COMMITTED,
        IntentState::Linking => EVENT_FORMATION_LINKING,
        IntentState::Linked => EVENT_FORMATION_LINKED,
        IntentState::Ambiguous => EVENT_FORMATION_AMBIGUOUS,
        IntentState::Canceled => EVENT_FORMATION_CANCELED,
    }
}

/// The ONE paired write of this machine: intent and slot CAS together
/// under the slot generation, so no row can move one without the other.
#[allow(clippy::too_many_arguments)]
fn commit_pair(
    txn: &mut kovee_store::CommandTxn<'_>,
    intent: &Intent,
    to: IntentState,
    via: Move,
    releases_slot: bool,
    extra_intent: &[(&str, Value)],
    payload: Value,
) -> Result<Applied, Problem> {
    let digests = digests_of(txn.conn(), &intent.realm_ref)?;
    let at = txn.now_ts();
    let terminal_at = to.is_terminal().then(|| at.clone());

    let mut sets = vec![
        "state = :state".to_owned(),
        "revision = revision + 1".to_owned(),
        "digest = :digest".to_owned(),
        "terminal_at = :terminal_at".to_owned(),
    ];
    let mut binds: Vec<(String, Value)> = vec![
        (":state".to_owned(), json!(to.as_str())),
        (
            ":terminal_at".to_owned(),
            terminal_at.clone().map(Value::from).unwrap_or(Value::Null),
        ),
    ];
    for (column, value) in extra_intent {
        sets.push(format!("{column} = :{column}"));
        binds.push((format!(":{column}"), value.clone()));
    }
    let intent_digest = digests
        .digest(
            TAG_INTENT,
            &json!({
                "formation_id": intent.formation_id,
                "revision": intent.revision + 1,
                "state": to.as_str(),
                "canonical_byom_command_digest": intent.canonical_byom_command_digest,
                "formation_slot_generation": intent.formation_slot_generation,
            }),
        )
        .map_err(|_| internal())?;
    binds.push((":digest".to_owned(), json!(digest_json(&intent_digest))));

    // The CAS: the intent must still be in the state this step read, at
    // this exact slot generation.
    let sql = format!(
        "UPDATE endeavor_formation_intents SET {} WHERE formation_id = :id
         AND state = :from AND formation_slot_generation = :generation AND revision = :revision",
        sets.join(", ")
    );
    binds.push((":id".to_owned(), json!(intent.formation_id)));
    binds.push((":from".to_owned(), json!(intent.state.as_str())));
    binds.push((
        ":generation".to_owned(),
        json!(intent.formation_slot_generation),
    ));
    binds.push((":revision".to_owned(), json!(intent.revision)));
    let changed = execute_named(txn.conn(), &sql, &binds)?;
    if changed != 1 {
        return Err(stale_revision(intent.revision));
    }

    let slot_digest = digests
        .digest(
            TAG_SLOT,
            &json!({
                "slot_id": intent.formation_slot_ref,
                "generation": intent.formation_slot_generation,
                "state": to.slot().as_str(),
            }),
        )
        .map_err(|_| internal())?;
    let slot_changed = txn
        .conn()
        .execute(
            "UPDATE endeavor_formation_slots
             SET state = ?2, revision = revision + 1, released_at = ?3, digest = ?4
             WHERE slot_id = ?1 AND generation = ?5",
            params![
                intent.formation_slot_ref,
                to.slot().as_str(),
                if releases_slot {
                    terminal_at.clone()
                } else {
                    None
                },
                digest_json(&slot_digest),
                intent.formation_slot_generation as i64,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    if slot_changed != 1 {
        return Err(stale_revision(intent.revision));
    }

    txn.audit(
        &format!("formation.{}", to.as_str()),
        &format!(
            "formation={} via={} slot={}",
            intent.formation_id,
            via.as_str(),
            to.slot().as_str()
        ),
    );
    let mut event_payload = payload;
    if let Some(map) = event_payload.as_object_mut() {
        map.insert("formation_id".to_owned(), json!(intent.formation_id));
        map.insert("state".to_owned(), json!(to.as_str()));
        map.insert("slot_state".to_owned(), json!(to.slot().as_str()));
        map.insert("via".to_owned(), json!(via.as_str()));
    }
    txn.append_event(NewEvent {
        stream_id: intent.formation_id.clone(),
        project_id: Some(intent.project_id.clone()),
        actor_ref: Some(intent.requested_by_principal.clone()),
        event_type: event_type(to).to_owned(),
        schema_ref: "schema:kovee-endeavor-formation-intent-v1".to_owned(),
        resource_ref: intent.formation_id.clone(),
        resource_revision: Some(intent.revision + 1),
        causation_ref: None,
        correlation_ref: intent.formation_id.clone(),
        classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
        payload: event_payload,
    })
    .map_err(store_problem)?;

    Ok(Applied {
        result: promotion_view(txn.conn(), &intent.realm_ref, &intent.formation_id)?,
        revision: Some(intent.revision + 1),
        event_cursor: None,
    })
}

fn execute_named(
    conn: &Connection,
    sql: &str,
    binds: &[(String, Value)],
) -> Result<usize, Problem> {
    let mut stmt = conn.prepare(sql).map_err(|e| store_problem(e.into()))?;
    let owned: Vec<(&str, Box<dyn rusqlite::ToSql>)> = binds
        .iter()
        .map(|(name, value)| {
            let boxed: Box<dyn rusqlite::ToSql> = match value {
                Value::Null => Box::new(Option::<String>::None),
                Value::Number(n) => Box::new(n.as_i64().unwrap_or_default()),
                Value::String(s) => Box::new(s.clone()),
                other => Box::new(other.to_string()),
            };
            (name.as_str(), boxed)
        })
        .collect();
    let refs: Vec<(&str, &dyn rusqlite::ToSql)> =
        owned.iter().map(|(n, b)| (*n, b.as_ref())).collect();
    stmt.execute(refs.as_slice())
        .map_err(|e| store_problem(e.into()))
}

// -------------------------------------------------------------- the view ----

/// The saga's own read projection — the recorded state, never a guess.
fn promotion_view(conn: &Connection, realm: &str, id: &str) -> Result<Value, Problem> {
    let intent = read_intent(conn, realm, id)?.ok_or_else(not_found)?;
    let (slot, generation) = slot_state(conn, &intent.formation_slot_ref)?
        .unwrap_or_else(|| ("released".to_owned(), intent.formation_slot_generation));
    let mut stmt = conn
        .prepare(
            "SELECT attempt_id, attempt_ordinal, attempt_nonce, state,
                    authentication_observation_ref, prepared_at, sent_at, observed_at
             FROM endeavor_formation_attempts WHERE formation_id = ?1
             ORDER BY attempt_ordinal ASC",
        )
        .map_err(|e| store_problem(e.into()))?;
    let attempts: Vec<Value> = stmt
        .query_map([id], |r| {
            Ok(json!({
                "attempt_id": r.get::<_, String>(0)?,
                "attempt_ordinal": r.get::<_, i64>(1)?,
                "attempt_nonce": r.get::<_, String>(2)?,
                "state": r.get::<_, String>(3)?,
                "authentication_observation_ref": r.get::<_, String>(4)?,
                "prepared_at": r.get::<_, String>(5)?,
                "sent_at": r.get::<_, Option<String>>(6)?,
                "observed_at": r.get::<_, Option<String>>(7)?,
            }))
        })
        .map_err(|e| store_problem(e.into()))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| store_problem(e.into()))?;

    let link: Option<Value> = conn
        .query_row(
            "SELECT link_ref, endeavor_ref, endeavor_revision, endeavor_digest, result_digest,
                    source_cursor, created_at
             FROM external_links WHERE formation_id = ?1",
            [id],
            |r| {
                Ok(json!({
                    "link_ref": r.get::<_, String>(0)?,
                    "endeavor_ref": r.get::<_, String>(1)?,
                    "endeavor_revision": r.get::<_, i64>(2)?,
                    "endeavor_digest": serde_json::from_str::<Value>(&r.get::<_, String>(3)?)
                        .unwrap_or(Value::Null),
                    "result_digest": serde_json::from_str::<Value>(&r.get::<_, String>(4)?)
                        .unwrap_or(Value::Null),
                    "source_cursor": r.get::<_, String>(5)?,
                    "created_at": r.get::<_, String>(6)?,
                }))
            },
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;

    Ok(json!({
        "formation_id": intent.formation_id,
        "revision": intent.revision,
        "state": intent.state.as_str(),
        "slot": {
            "slot_ref": intent.formation_slot_ref,
            "state": slot,
            "generation": generation,
        },
        "society_ref": intent.society_ref,
        "society_recovery_epoch": intent.society_recovery_epoch,
        "byom_endpoint_ref": intent.byom_endpoint_ref,
        "command_endpoint_incarnation": intent.command_endpoint_incarnation,
        "client_formation_key": intent.client_formation_key,
        "byom_command_idempotency_key": intent.byom_command_idempotency_key,
        "canonical_byom_command_digest": intent.canonical_byom_command_digest,
        "idempotency_domain_digest": intent.idempotency_domain_digest,
        "project_id": intent.project_id,
        "space_id": intent.space_id,
        "branch_id": intent.branch_id,
        "attempts": attempts,
        "external_link": link,
        "byom_result": intent.result_envelope,
    }))
}

// ------------------------------------------- endeavor_promotion_prepare ----

/// Step 0: the bundle and the durable pair. It makes NO external contact
/// at all — every byom fact it pins (the endpoint incarnation, the Society
/// recovery epoch, the binding quadruple) is read from the ACTIVE seam the
/// greenfield saga already committed.
pub fn endeavor_promotion_prepare(
    store: &mut Store,
    scope: CommandScope,
    realm: String,
    args: PromotionPrepareArgs,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let (binding, mapping) = active_seam(txn.conn(), &realm)?.ok_or_else(|| {
            forbidden(
                "this realm has no active governed-work binding",
                "run governance_enable first: an endeavor promotion needs an ACTIVE \
                 KoveeRealmByomBinding and KoveeSocietyMapping (byom §16.3)",
            )
        })?;
        if mapping.society_ref != args.society_ref {
            return Err(forbidden(
                "the active KoveeSocietyMapping covers another Society",
                format!(
                    "the mapping covers {:?}; a formation names exactly the mapped Society",
                    mapping.society_ref
                ),
            ));
        }
        if binding.byom_endpoint_ref != args.byom_endpoint_ref {
            return Err(forbidden(
                "the active binding names another byom endpoint",
                format!("the binding names {:?}", binding.byom_endpoint_ref),
            ));
        }
        let principal = OWNER_ACTOR_REF.to_owned();

        // An exact retry of the SAME client formation key returns the
        // identical pair — the uniqueness scope deduplicates one explicit
        // human formation command (§16.3), nothing wider.
        if let Some(existing) =
            read_intent_by_key(txn.conn(), &realm, &principal, &args.client_formation_key)?
        {
            return Ok(Applied {
                result: promotion_view(txn.conn(), &realm, &existing.formation_id)?,
                revision: Some(existing.revision),
                event_cursor: None,
            });
        }

        prepare_pair(txn, &realm, &principal, &binding, &mapping, &args)
    });
    command_outcome_bytes(outcome)
}

#[allow(clippy::too_many_lines)]
fn prepare_pair(
    txn: &mut kovee_store::CommandTxn<'_>,
    realm: &str,
    principal: &str,
    binding: &KoveeRealmByomBinding,
    mapping: &KoveeSocietyMapping,
    args: &PromotionPrepareArgs,
) -> Result<Applied, Problem> {
    let digests = digests_of(txn.conn(), realm)?;

    // The bundle half: a pinned frontier and a Kovee ContextAssembly that
    // already exist. Nothing is invented for the formation.
    let frontier = crate::state::get_frontier(txn.conn(), &args.frontier_ref)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let (assembly_project, assembly) =
        crate::state::get_assembly_record(txn.conn(), &args.collaboration_context_bundle_ref)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
    let assembly_frontier = assembly
        .get("frontier_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if assembly_frontier != args.frontier_ref {
        return Err(forbidden(
            "the context bundle was assembled at another frontier",
            format!(
                "the bundle pins {assembly_frontier:?}; a formation pins ONE frontier and the \
                 bundle taken at it"
            ),
        ));
    }
    let space_id = frontier.space_id.clone();
    let branch_id = frontier.branch_id.clone();
    let project_id = assembly_project;

    // Every cross-boundary digest, derived so byomd recomputes the same.
    let proposal = Value::Object(args.endeavor_proposal.clone());
    let position = Value::Object(args.source_principal_position.clone());
    let proposal_digest =
        hostint::portable_digest(hostint::PROPOSAL_TAG, &proposal).map_err(|_| internal())?;
    let position_digest =
        hostint::portable_digest(hostint::POSITION_TAG, &position).map_err(|_| internal())?;
    let bundle_digest = hostint::portable_digest(
        hostint::PROPOSAL_TAG,
        &json!({"context_bundle_ref": args.collaboration_context_bundle_ref,
                "digest": assembly.get("digest").cloned().unwrap_or(Value::Null)}),
    )
    .map_err(|_| internal())?;
    let frontier_digest = digests
        .digest(
            TAG_FRONTIER,
            &json!({
                "frontier_ref": args.frontier_ref,
                "branch_id": branch_id,
                "branch_head_digest": frontier.branch_head_digest,
            }),
        )
        .map_err(|_| internal())?;
    let rule_set = proposal
        .get("governance_rule_set_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            Problem::new(ProblemKind::Invalid, "invalid operation arguments").with_detail(
                "endeavor_proposal must name its governance_rule_set_ref (the B0.1 \
                 endeavor_propose subject owns the shape)",
            )
        })?
        .to_owned();
    let sponsors: Vec<String> = proposal
        .get("sponsor_participant_refs")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let snapshot = hostint::slot_snapshot(
        &mapping.society_ref,
        mapping.society_recovery_epoch,
        &rule_set,
        &proposal_digest,
        &sponsors,
    );
    let snapshot_digest =
        hostint::portable_digest(hostint::SLOT_SNAPSHOT_TAG, &snapshot).map_err(|_| internal())?;
    let actor_binding = hostint::actor_binding_digest(
        realm,
        principal,
        &args.bound_participant_ref,
        args.participant_binding_epoch,
    )
    .map_err(|_| internal())?;
    let pin = BindingPin::of(&hostint::wire_binding(binding).map_err(|_| internal())?)
        .map_err(|_| internal())?;

    let domain = domain_digest(
        &digests,
        &mapping.society_ref,
        principal,
        &args.client_formation_key,
    )?;
    let idempotency_key = command_key(&domain);

    let formation_id = new_id("efi").map_err(store_problem)?;
    let slot_id = new_id("efs").map_err(store_problem)?;
    let deps_ref = new_id("fdeps").map_err(store_problem)?;
    let created_at = txn.now_ts();

    // The STABLE semantic command bytes — pinned once, digested once, and
    // never rewritten by any later attempt.
    let command = json!({
        "kovee_formation_intent_ref": formation_id,
        "byom_endpoint_ref": binding.byom_endpoint_ref,
        "command_endpoint_incarnation": binding.endpoint_incarnation,
        "realm_byom_binding_ref": pin.binding_ref,
        "realm_byom_binding_revision": pin.binding_revision,
        "realm_byom_binding_epoch": pin.binding_epoch,
        "realm_byom_binding_digest": pin.digest,
        "society_ref": mapping.society_ref,
        "society_recovery_epoch": mapping.society_recovery_epoch,
        "source_principal_ref": principal,
        "source_actor_binding_digest": actor_binding,
        "context_bundle_ref": args.collaboration_context_bundle_ref,
        "context_bundle_digest": bundle_digest,
        "endeavor_proposal": proposal,
        "endeavor_proposal_digest": proposal_digest,
        "source_principal_position": position,
        "source_principal_position_digest": position_digest,
        "expected_governance_rule_set_ref": rule_set,
        "expected_slot_snapshot_digest": snapshot_digest,
        "byom_command_idempotency_key": idempotency_key,
        "idempotency_domain_digest": domain,
    });
    let canonical = hostint::command_digest(&command).map_err(|_| internal())?;

    let authority = digests
        .digest(
            TAG_DEPS,
            &json!({
                "dependency_set_ref": deps_ref,
                "realm_ref": realm,
                "society_ref": mapping.society_ref,
                "society_recovery_epoch": mapping.society_recovery_epoch,
                "realm_byom_binding_ref": pin.binding_ref,
                "realm_byom_binding_epoch": pin.binding_epoch,
                "endpoint_incarnation": binding.endpoint_incarnation,
                "frontier_ref": args.frontier_ref,
                "context_bundle_ref": args.collaboration_context_bundle_ref,
                "canonical_byom_command_digest": canonical,
            }),
        )
        .map_err(|_| internal())?;
    let intent_digest = digests
        .digest(
            TAG_INTENT,
            &json!({
                "formation_id": formation_id,
                "revision": 1,
                "state": IntentState::Prepared.as_str(),
                "canonical_byom_command_digest": canonical,
                "formation_slot_generation": 1,
            }),
        )
        .map_err(|_| internal())?;
    let slot_digest = digests
        .digest(
            TAG_SLOT,
            &json!({"slot_id": slot_id, "generation": 1,
                    "state": IntentState::Prepared.slot().as_str()}),
        )
        .map_err(|_| internal())?;

    txn.conn()
        .execute(
            "INSERT INTO endeavor_formation_intents (formation_id, revision, realm_ref,
                 project_id, space_id, branch_id, frontier_ref, frontier_digest,
                 collaboration_context_bundle_ref, context_bundle_digest, society_ref,
                 society_recovery_epoch, endeavor_proposal_ref, endeavor_proposal_digest,
                 byom_endpoint_ref, command_endpoint_incarnation, realm_byom_binding_ref,
                 realm_byom_binding_revision, realm_byom_binding_epoch,
                 realm_byom_binding_digest, requested_by_principal,
                 bound_participant_ref, participant_binding_epoch,
                 source_actor_binding_digest, delegated_principal_subject_digest,
                 client_formation_key, byom_command_idempotency_key,
                 idempotency_domain_digest, canonical_byom_command_digest,
                 canonical_command_digest_hex, formation_slot_ref, formation_slot_generation,
                 authorization_dependency_set_ref, authority_digest, state, created_at,
                 digest, command_bytes)
             VALUES (?1,1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,
                 ?20,?35,?36,?21,?22,?23,?24,?25,?26,?27,?28,1,?29,?30,?31,?32,?33,?34)",
            params![
                formation_id,
                realm,
                project_id,
                space_id,
                branch_id,
                args.frontier_ref,
                digest_json(&frontier_digest),
                args.collaboration_context_bundle_ref,
                digest_json(&bundle_digest),
                mapping.society_ref,
                mapping.society_recovery_epoch as i64,
                args.endeavor_proposal_ref,
                digest_json(&proposal_digest),
                binding.byom_endpoint_ref,
                binding.endpoint_incarnation,
                pin.binding_ref,
                pin.binding_revision as i64,
                pin.binding_epoch as i64,
                digest_json(&pin.digest),
                principal,
                digest_json(&actor_binding),
                // §14.4: the credential is bound to the exact prepared
                // subject, which for this operation IS the command digest.
                digest_json(&canonical),
                args.client_formation_key,
                idempotency_key,
                digest_json(&domain),
                digest_json(&canonical),
                canonical.value_hex,
                slot_id,
                deps_ref,
                digest_json(&authority),
                IntentState::Prepared.as_str(),
                created_at,
                digest_json(&intent_digest),
                serde_json::to_string(&command).map_err(|_| internal())?,
                args.bound_participant_ref,
                args.participant_binding_epoch as i64,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;

    txn.conn()
        .execute(
            "INSERT INTO endeavor_formation_slots (slot_id, realm_ref,
                 requested_by_principal, client_formation_key, holder_formation_id, generation,
                 revision, society_ref, society_recovery_epoch, source_actor_binding_digest,
                 realm_byom_binding_ref, realm_byom_binding_revision,
                 realm_byom_binding_epoch, realm_byom_binding_digest,
                 canonical_byom_command_digest, byom_command_idempotency_key,
                 idempotency_domain_digest, state, acquired_at, digest)
             VALUES (?1,?2,?3,?4,?5,1,1,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                slot_id,
                realm,
                principal,
                args.client_formation_key,
                formation_id,
                mapping.society_ref,
                mapping.society_recovery_epoch as i64,
                digest_json(&actor_binding),
                pin.binding_ref,
                pin.binding_revision as i64,
                pin.binding_epoch as i64,
                digest_json(&pin.digest),
                digest_json(&canonical),
                idempotency_key,
                digest_json(&domain),
                IntentState::Prepared.slot().as_str(),
                created_at,
                digest_json(&slot_digest),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;

    txn.audit(
        "formation.prepared",
        &format!("formation={formation_id} slot={slot_id} generation=1"),
    );
    txn.append_event(NewEvent {
        stream_id: formation_id.clone(),
        project_id: Some(project_id.clone()),
        actor_ref: Some(principal.to_owned()),
        event_type: EVENT_FORMATION_PREPARED.to_owned(),
        schema_ref: "schema:kovee-endeavor-formation-intent-v1".to_owned(),
        resource_ref: formation_id.clone(),
        resource_revision: Some(1),
        causation_ref: None,
        correlation_ref: formation_id.clone(),
        classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
        payload: json!({
            "formation_id": formation_id,
            "state": IntentState::Prepared.as_str(),
            "slot_state": IntentState::Prepared.slot().as_str(),
            "via": Move::FormationPrepare.as_str(),
            "client_formation_key": args.client_formation_key,
        }),
    })
    .map_err(store_problem)?;

    Ok(Applied {
        result: promotion_view(txn.conn(), realm, &formation_id)?,
        revision: Some(1),
        event_cursor: None,
    })
}

// -------------------------------------------- endeavor_promotion_cancel ----

/// The ONE pre-send release (§16.3 table row 1): a local cancel that
/// durably precedes the first send. After bytes may have left, cancel is
/// not a row of this machine at all.
pub fn endeavor_promotion_cancel(
    store: &mut Store,
    scope: CommandScope,
    realm: String,
    args: PromotionCancelArgs,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let intent = read_intent(txn.conn(), &realm, &args.formation_id)?.ok_or_else(not_found)?;
        if intent.state == IntentState::Canceled {
            return Ok(Applied {
                result: promotion_view(txn.conn(), &realm, &intent.formation_id)?,
                revision: Some(intent.revision),
                event_cursor: None,
            });
        }
        if !may_cancel(intent.state) {
            return Err(forbidden(
                "cancel exists only before the first send",
                format!(
                    "the intent is {:?}: after bytes may have left Kovee, cancel is not a row of \
                     this machine — reconcile against byom's own fact instead (§16.3 table row 1)",
                    intent.state.as_str()
                ),
            ));
        }
        // Belt and braces: a slot that ever left `held` means a send may
        // have happened, whatever the intent row says.
        if let Some((state, _)) = slot_state(txn.conn(), &intent.formation_slot_ref)? {
            if state != IntentState::Prepared.slot().as_str() {
                return Err(forbidden(
                    "the uniqueness slot has already been acquired for a send",
                    format!("the slot is {state:?}; only a `held` slot cancels locally"),
                ));
            }
        }
        commit_pair(
            txn,
            &intent,
            IntentState::Canceled,
            Move::FormationCancel,
            true,
            &[],
            json!({"reason": args.reason}),
        )
    });
    command_outcome_bytes(outcome)
}

// ---------------------------------------------- endeavor_promotion_show ----

/// The query-first restore surface: the recorded state of every promotion,
/// never a guess and never a mutation.
pub fn endeavor_promotion_show(
    store: &Store,
    realm: &str,
    args: &PromotionShowArgs,
) -> Result<Vec<u8>, Problem> {
    let conn = store.conn();
    if let Some(id) = &args.formation_id {
        let view = promotion_view(conn, realm, id)?;
        return crate::handlers::ok_reply(view, None);
    }
    let mut promotions = Vec::new();
    for intent in all_intents(conn, realm)? {
        promotions.push(promotion_view(conn, realm, &intent.formation_id)?);
    }
    crate::handlers::ok_reply(json!({"realm_id": realm, "promotions": promotions}), None)
}

// --------------------------------------------- endeavor_promotion_start ----

/// Acquire the slot for a send, then send. The order is the whole point:
/// `submitting` is DURABLE before any byte leaves Kovee, so a crash
/// mid-send is recoverable from byom's own signed fact instead of being
/// indistinguishable from "never sent".
#[allow(clippy::too_many_arguments)]
pub fn endeavor_promotion_start(
    store: &mut Store,
    resolver: &EndpointResolver,
    scope: CommandScope,
    realm: String,
    args: PromotionStartArgs,
    now: i64,
    hooks: impl Fn(&str) -> CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let intent = read_intent(store.conn(), &realm, &args.formation_id)?.ok_or_else(not_found)?;

    // Terminal and resumable states first: an exact retry after a crash
    // RESUMES at the recorded state rather than re-sending.
    match intent.state {
        IntentState::Linked => {
            return crate::handlers::ok_reply(
                promotion_view(store.conn(), &realm, &intent.formation_id)?,
                Some(intent.revision),
            )
        }
        IntentState::Canceled => {
            return Err(forbidden(
                "this formation is terminal",
                "a canceled formation never sends again: its IdempotencyDomain is claimed or its \
                 slot was released before any send (§16.3)",
            ))
        }
        IntentState::ByomCommitted | IntentState::Linking => {
            // The result is already durable; finish the link.
            return commit_link(store, &scope, &realm, &intent, now, &hooks);
        }
        state if !may_submit(state) => {
            return Err(forbidden(
                "no send is admissible from this state",
                format!(
                    "the intent is {:?}; only `prepared` and `awaiting_principal` submit \
                     (§16.3 table row 2)",
                    state.as_str()
                ),
            ))
        }
        _ => {}
    }

    // §16.3: a resubmission needs a FRESH human authentication attempt.
    // Reusing the observation of the previous attempt is not freshness.
    if intent.latest_authentication_observation_ref.as_deref()
        == Some(args.authentication_observation_ref.as_str())
    {
        return Err(forbidden(
            "resubmission requires a freshly authenticated principal",
            "the attempt reuses the previous authentication observation; §16.3 requires a fresh \
             human authentication attempt over the unchanged semantic command",
        ));
    }

    // ---------------------------------------- commit #attempt: submitting ----
    let attempt_scope = step_scope(&scope, "attempt");
    let intent_c = intent.clone();
    let observation = args.authentication_observation_ref.clone();
    let realm_c = realm.clone();
    let opened = store.command_transaction(
        &attempt_scope,
        now,
        hooks("endeavor_promotion_start#attempt"),
        move |txn| open_attempt(txn, &realm_c, &intent_c, &observation, now),
    );
    command_outcome_bytes(opened)?;

    // Re-read: the DURABLE state decides what happens next, never the
    // in-memory copy this invocation started from.
    let intent = read_intent(store.conn(), &realm, &args.formation_id)?.ok_or_else(internal)?;
    if intent.state != IntentState::Submitting {
        // A concurrent resolution moved the pair; report the record.
        return crate::handlers::ok_reply(
            promotion_view(store.conn(), &realm, &intent.formation_id)?,
            Some(intent.revision),
        );
    }
    let attempt_ref = intent.latest_attempt_ref.clone().ok_or_else(internal)?;
    let attempt = read_attempt(store.conn(), &attempt_ref)?.ok_or_else(internal)?;
    let dpc = crate::credentials::read(store.conn(), GATEWAY_ISSUER_REF, &attempt.attempt_nonce)?
        .ok_or_else(internal)?;

    // -------------------------------------- the external call, unwrapped ----
    let endpoint = resolver(&intent.byom_endpoint_ref);
    let sent = submit(&endpoint, &intent, &attempt, &dpc);

    match sent {
        Ok(envelope) => {
            let committed = kovee_byom::formation::CommittedResult {
                digest: serde_json::from_value(
                    envelope.get("digest").cloned().unwrap_or(Value::Null),
                )
                .map_err(|_| {
                    Problem::new(
                        ProblemKind::Unavailable,
                        "the byom endpoint answered with an unusable reply",
                    )
                    .with_detail("the formation result carries no typed digest")
                })?,
                envelope,
                // A direct reply arrives on the authenticated channel
                // itself; the signature travels with the retained fact,
                // which `reconcile` re-reads and verifies.
                signature: "channel".to_owned(),
            };
            record_result(
                store,
                &scope,
                &realm,
                &intent,
                &attempt_ref,
                &dpc,
                &committed,
                now,
                &hooks,
            )?;
            let intent =
                read_intent(store.conn(), &realm, &args.formation_id)?.ok_or_else(internal)?;
            commit_link(store, &scope, &realm, &intent, now, &hooks)
        }
        Err(SendFailure::Tombstone { reference, digest }) => {
            // A DEFINITE pre-commit rejection: byom claimed the exact
            // IdempotencyDomain with a non-reexecuting tombstone, so there
            // is no Kovee-side Endeavor to recover and never will be.
            let outcome = {
                let intent_c = intent.clone();
                let attempt_c = attempt_ref.clone();
                let reference_c = reference.clone();
                let digest_c = digest.clone();
                let realm_c = realm.clone();
                store.command_transaction(
                    &step_scope(&scope, "tombstone"),
                    now,
                    hooks("endeavor_promotion_start#tombstone"),
                    move |txn| {
                        close_attempt(
                            txn.conn(),
                            &attempt_c,
                            AttemptState::ReplyReceived,
                            Some(&digest_c),
                            &txn.now_ts(),
                        )?;
                        let _ = &realm_c;
                        commit_pair(
                            txn,
                            &intent_c,
                            IntentState::Canceled,
                            Move::TombstoneVerified,
                            true,
                            &[],
                            json!({
                                "tombstone_ref": reference_c,
                                "tombstone_digest": digest_c,
                                "reason_kind": "formation_requires_participation",
                            }),
                        )
                    },
                )
            };
            command_outcome_bytes(outcome)?;
            Err(Problem::new(
                ProblemKind::Forbidden,
                "the computed formation needs another Participant's Position",
            )
            .with_detail(format!(
                "byom claimed this IdempotencyDomain with the non-reexecuting tombstone \
                 {reference}: no Endeavor was created and this formation key can never form one \
                 (§16.3). Use the ordinary endeavor_propose/position/finalize seat sequence."
            )))
        }
        Err(SendFailure::Unknown(problem)) => {
            let outcome = {
                let intent_c = intent.clone();
                let attempt_c = attempt_ref.clone();
                store.command_transaction(
                    &step_scope(&scope, "unknown"),
                    now,
                    hooks("endeavor_promotion_start#unknown"),
                    move |txn| {
                        let at = txn.now_ts();
                        close_attempt(
                            txn.conn(),
                            &attempt_c,
                            AttemptState::TransportUnknown,
                            None,
                            &at,
                        )?;
                        commit_pair(
                            txn,
                            &intent_c,
                            IntentState::RemoteUnknown,
                            Move::TransportOutcomeUnknown,
                            false,
                            &[],
                            json!({"outcome": "transport_unknown"}),
                        )
                    },
                )
            };
            command_outcome_bytes(outcome)?;
            Err(problem)
        }
        Err(SendFailure::Refused(problem)) => {
            // A definite refusal that claimed nothing: not a committed
            // result, not an absence, not a tombstone. Table row 6 covers
            // it — invalid result, conservative hold, slot NOT released.
            let outcome = {
                let intent_c = intent.clone();
                let attempt_c = attempt_ref.clone();
                store.command_transaction(
                    &step_scope(&scope, "refused"),
                    now,
                    hooks("endeavor_promotion_start#refused"),
                    move |txn| {
                        let at = txn.now_ts();
                        close_attempt(
                            txn.conn(),
                            &attempt_c,
                            AttemptState::ReplyReceived,
                            None,
                            &at,
                        )?;
                        commit_pair(
                            txn,
                            &intent_c,
                            IntentState::Ambiguous,
                            Move::UnknownResult,
                            false,
                            &[],
                            json!({"outcome": "definite_refusal"}),
                        )
                    },
                )
            };
            command_outcome_bytes(outcome)?;
            Err(problem)
        }
    }
}

/// What one send can fail as. The distinction is the whole safety
/// argument: only a definite answer may drive a state change that
/// forecloses the command.
enum SendFailure {
    /// byom installed a non-reexecuting tombstone over the domain.
    Tombstone { reference: String, digest: Value },
    /// A typed refusal that claimed nothing.
    Refused(Problem),
    /// No answer at all: the outcome is UNKNOWN and may not be guessed.
    Unknown(Problem),
}

/// One `kovee_endeavor_form` call: the stable command plus this attempt's
/// fresh authentication envelope, with the credential as CHANNEL material
/// on the governance socket's transport preamble.
fn submit(
    endpoint: &Endpoint,
    intent: &Intent,
    attempt: &Attempt,
    dpc: &DelegatedPrincipalCredential,
) -> Result<Value, SendFailure> {
    let proof = hostint::attempt_proof(
        &intent.canonical_byom_command_digest,
        &intent.idempotency_domain_digest,
        &attempt.attempt_nonce,
        &attempt.attempt_recovery_binding_digest,
        &dpc.source_actor_binding_digest,
    )
    .map_err(|e| SendFailure::Refused(Problem::new(ProblemKind::Internal, e.to_string())))?;
    let request = json!({
        "version": BPP_VERSION,
        "op": OPERATION,
        "meta": {
            "request_id": attempt.attempt_id,
            "idempotency_key": intent.byom_command_idempotency_key,
            "expected_endpoint_incarnation": intent.command_endpoint_incarnation,
            "expected_recovery_epoch": intent.society_recovery_epoch,
        },
        "command": intent.command_bytes,
        "canonical_command_digest": intent.canonical_byom_command_digest,
        "attempt_id": attempt.attempt_id,
        "attempt_nonce": attempt.attempt_nonce,
        "attempt_recovery_binding_ref": attempt.attempt_recovery_binding_ref,
        "attempt_recovery_binding_revision": attempt.attempt_recovery_binding_revision,
        "attempt_recovery_binding_epoch": attempt.attempt_recovery_binding_epoch,
        "attempt_recovery_binding_digest": attempt.attempt_recovery_binding_digest,
        "authentication_observation_ref": attempt.authentication_observation_ref,
        "authentication_observation_digest": dpc.authentication_observation_digest,
        "authentication_proof": proof,
    });
    match endpoint.call_with_preamble(Surface::Governance, Some(&dpc.preamble()), &request) {
        Ok(reply) => Ok(reply.result),
        Err(BppError::Problem(p)) => {
            if let Some(reference) = p
                .extension("tombstone_ref")
                .and_then(Value::as_str)
                .map(str::to_owned)
            {
                return Err(SendFailure::Tombstone {
                    reference,
                    digest: p
                        .extension("tombstone_digest")
                        .cloned()
                        .unwrap_or(Value::Null),
                });
            }
            Err(SendFailure::Refused(bpp::passthrough(&BppError::Problem(
                p,
            ))))
        }
        Err(e) if e.is_definite() => Err(SendFailure::Refused(bpp::passthrough(&e))),
        Err(e) => Err(SendFailure::Unknown(bpp::passthrough(&e))),
    }
}

// ----------------------------------------------------------- attempts ----

/// One immutable per-send envelope. Rows are APPEND-ONLY: resolving an
/// intent never rewrites an earlier attempt's evidence (§16.3).
#[derive(Debug, Clone)]
struct Attempt {
    attempt_id: String,
    attempt_nonce: String,
    attempt_recovery_binding_ref: String,
    attempt_recovery_binding_revision: u64,
    attempt_recovery_binding_epoch: u64,
    attempt_recovery_binding_digest: DigestRef,
    authentication_observation_ref: String,
}

fn read_attempt(conn: &Connection, attempt_id: &str) -> Result<Option<Attempt>, Problem> {
    conn.query_row(
        "SELECT attempt_id, attempt_nonce, attempt_recovery_binding_ref,
                attempt_recovery_binding_revision, attempt_recovery_binding_epoch,
                attempt_recovery_binding_digest, authentication_observation_ref
         FROM endeavor_formation_attempts WHERE attempt_id = ?1",
        [attempt_id],
        |r| {
            Ok(Attempt {
                attempt_id: r.get(0)?,
                attempt_nonce: r.get(1)?,
                attempt_recovery_binding_ref: r.get(2)?,
                attempt_recovery_binding_revision: r.get::<_, i64>(3)? as u64,
                attempt_recovery_binding_epoch: r.get::<_, i64>(4)? as u64,
                attempt_recovery_binding_digest: serde_json::from_str(&r.get::<_, String>(5)?)
                    .unwrap_or_else(|_| DigestRef::portable_public("0".repeat(64))),
                authentication_observation_ref: r.get(6)?,
            })
        },
    )
    .optional()
    .map_err(|e| store_problem(e.into()))
}

fn close_attempt(
    conn: &Connection,
    attempt_id: &str,
    state: AttemptState,
    reply_digest: Option<&Value>,
    observed_at: &str,
) -> Result<(), Problem> {
    conn.execute(
        "UPDATE endeavor_formation_attempts
         SET state = ?2, reply_digest = COALESCE(reply_digest, ?3),
             observed_at = COALESCE(observed_at, ?4)
         WHERE attempt_id = ?1",
        params![
            attempt_id,
            state.as_str(),
            reply_digest.map(|d| d.to_string()),
            observed_at,
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

/// Commit #attempt: append the immutable attempt envelope, mint this
/// attempt's short-lived credential, and CAS the pair into `submitting` —
/// all in ONE transaction, all before any byte leaves Kovee.
fn open_attempt(
    txn: &mut kovee_store::CommandTxn<'_>,
    realm: &str,
    intent: &Intent,
    observation_ref: &str,
    now: i64,
) -> Result<Applied, Problem> {
    let digests = digests_of(txn.conn(), realm)?;
    let (binding, mapping) = active_seam(txn.conn(), realm)?.ok_or_else(|| {
        forbidden(
            "this realm has no active governed-work binding",
            "a formation attempt needs an ACTIVE KoveeRealmByomBinding",
        )
    })?;
    // The binding must still be the one the intent pinned: a rotation
    // fences the send rather than silently re-binding it.
    let pin = BindingPin::of(&hostint::wire_binding(&binding).map_err(|_| internal())?)
        .map_err(|_| internal())?;
    if pin.binding_ref != intent.realm_byom_binding_ref
        || binding.endpoint_incarnation != intent.command_endpoint_incarnation
        || mapping.society_recovery_epoch != intent.society_recovery_epoch
    {
        return Err(forbidden(
            "the pinned binding, incarnation, or recovery epoch moved",
            "a formation submits only while its command endpoint incarnation and Society \
             recovery epoch are still active (§16.3 table row 2); binding rotation never \
             releases the slot",
        ));
    }

    let ordinal: u64 = txn
        .conn()
        .query_row(
            "SELECT COALESCE(MAX(attempt_ordinal), 0) + 1 FROM endeavor_formation_attempts
             WHERE formation_id = ?1",
            [&intent.formation_id],
            |r| r.get::<_, i64>(0),
        )
        .map_err(|e| store_problem(e.into()))? as u64;
    let attempt_id = new_id("efa").map_err(store_problem)?;
    let nonce = new_id("efn").map_err(store_problem)?;
    let prepared_at = txn.now_ts();
    let participant = participant_of(txn.conn(), &intent.formation_id)?;

    // The fresh envelope: this attempt's credential, bound to the exact
    // prepared command and to THIS nonce.
    let dpc = DpcMint {
        issuer_ref: GATEWAY_ISSUER_REF,
        nonce: &nonce,
        sender_constraint: SenderConstraint::channel_exporter(
            digests
                .digest(
                    "kovee-channel-exporter-v1",
                    &json!({"channel": "kovee-owner-uds", "realm_ref": realm}),
                )
                .map_err(|_| internal())?,
        ),
        delegation: Delegation {
            source_principal_ref: &intent.requested_by_principal,
            bound_participant_ref: &participant.0,
            participant_binding_epoch: participant.1,
            allowed_operations: &[OPERATION],
            authentication_observation_ref: observation_ref,
            assurance_level: ASSURANCE_LEVEL,
        },
        subject_digest: intent.canonical_byom_command_digest.clone(),
        issued_at: now,
        lifetime_seconds: CREDENTIAL_LIFETIME_SECONDS,
    }
    .issue(&MintContext {
        binding: &binding,
        society_ref: mapping.society_ref.clone(),
        society_recovery_epoch: mapping.society_recovery_epoch,
    })
    .map_err(|e| {
        forbidden(
            "the delegated-principal credential is not mintable",
            e.to_string(),
        )
    })?;
    if dpc.source_actor_binding_digest != intent.source_actor_binding_digest {
        // The intent pinned one actor binding; a credential for another
        // one would let a different human ride these bytes.
        return Err(forbidden(
            "the credential's actor binding is not the intent's",
            "§16.3: the authenticated delegated principal is the only author",
        ));
    }
    crate::credentials::record(txn.conn(), realm, &binding.binding_ref, &dpc)?;

    let proof = hostint::attempt_proof(
        &intent.canonical_byom_command_digest,
        &intent.idempotency_domain_digest,
        &nonce,
        &pin.digest,
        &dpc.source_actor_binding_digest,
    )
    .map_err(|_| internal())?;
    let proof_digest = digests
        .digest("kovee-attempt-proof-v1", &json!({"proof": proof}))
        .map_err(|_| internal())?;
    let attempt_digest = digests
        .digest(
            TAG_ATTEMPT,
            &json!({
                "attempt_id": attempt_id,
                "formation_id": intent.formation_id,
                "attempt_ordinal": ordinal,
                "attempt_nonce": nonce,
                "canonical_byom_command_digest": intent.canonical_byom_command_digest,
            }),
        )
        .map_err(|_| internal())?;

    txn.conn()
        .execute(
            "INSERT INTO endeavor_formation_attempts (attempt_id, formation_id,
                 attempt_ordinal, canonical_byom_command_digest, idempotency_domain_digest,
                 attempt_recovery_binding_ref, attempt_recovery_binding_revision,
                 attempt_recovery_binding_epoch, attempt_recovery_binding_digest,
                 authentication_observation_ref, authentication_observation_digest,
                 attempt_nonce, authentication_proof_digest, state, prepared_at, sent_at,
                 digest)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15,?16)",
            params![
                attempt_id,
                intent.formation_id,
                ordinal as i64,
                digest_json(&intent.canonical_byom_command_digest),
                digest_json(&intent.idempotency_domain_digest),
                pin.binding_ref,
                pin.binding_revision as i64,
                pin.binding_epoch as i64,
                digest_json(&pin.digest),
                observation_ref,
                digest_json(&dpc.authentication_observation_digest),
                nonce,
                digest_json(&proof_digest),
                // `sent` the moment the bytes MAY leave Kovee — the state
                // is durable before the write, never after it.
                AttemptState::Sent.as_str(),
                prepared_at,
                digest_json(&attempt_digest),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;

    commit_pair(
        txn,
        intent,
        IntentState::Submitting,
        Move::KoveeEndeavorForm,
        false,
        &[
            ("latest_attempt_ref", json!(attempt_id)),
            (
                "latest_authentication_observation_ref",
                json!(observation_ref),
            ),
        ],
        json!({"attempt_id": attempt_id, "attempt_ordinal": ordinal}),
    )
}

/// The bound Participant and its binding epoch, from the intent's own
/// columns. They are NOT recoverable from the stable command bytes: byom's
/// Position shape is closed and carries no epoch, and the actor-binding
/// digest is one-way. Every later attempt re-derives the same actor
/// binding from these two values, so a credential for a different human
/// or a superseded epoch cannot ride these bytes.
fn participant_of(conn: &Connection, formation_id: &str) -> Result<(String, u64), Problem> {
    conn.query_row(
        "SELECT bound_participant_ref, participant_binding_epoch
         FROM endeavor_formation_intents WHERE formation_id = ?1",
        [formation_id],
        |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)),
    )
    .map_err(|e| store_problem(e.into()))
}

// -------------------------------------------------- the result and link ----

/// Commit #result: persist the UNMODIFIED byom result envelope and CAS
/// into `byom_committed`. SQL loss after byom's commit is recovered from
/// exactly these bytes (§16.3).
#[allow(clippy::too_many_arguments)]
fn record_result(
    store: &mut Store,
    scope: &CommandScope,
    realm: &str,
    intent: &Intent,
    attempt_ref: &str,
    dpc: &DelegatedPrincipalCredential,
    committed: &kovee_byom::formation::CommittedResult,
    now: i64,
    hooks: &impl Fn(&str) -> CrashHooks,
) -> Result<(), Problem> {
    let intent_c = intent.clone();
    let attempt_c = attempt_ref.to_owned();
    let committed_c = committed.clone();
    let dpc_c = dpc.clone();
    let realm_c = realm.to_owned();
    let outcome = store.command_transaction(
        &step_scope(scope, "result"),
        now,
        hooks("endeavor_promotion_start#result"),
        move |txn| {
            let _ = &realm_c;
            let at = txn.now_ts();
            close_attempt(
                txn.conn(),
                &attempt_c,
                AttemptState::ReplyReceived,
                Some(&serde_json::to_value(&committed_c.digest).unwrap_or(Value::Null)),
                &at,
            )?;
            let envelope = serde_json::to_string(&committed_c.envelope).map_err(|_| internal())?;
            crate::credentials::mark_consumed(
                txn.conn(),
                &dpc_c,
                OPERATION,
                now,
                envelope.as_bytes(),
            )?;
            let step = resolve(
                intent_c.state,
                &Fact::Committed(Box::new(committed_c.clone())),
            )
            .ok_or_else(|| stale_revision(intent_c.revision))?;
            commit_pair(
                txn,
                &intent_c,
                step.intent,
                step.via,
                step.releases_slot,
                &[
                    (
                        "byom_result_ref",
                        committed_c
                            .envelope
                            .get("endeavor_ref")
                            .cloned()
                            .unwrap_or(Value::Null),
                    ),
                    (
                        "byom_result_digest",
                        json!(digest_json(&committed_c.digest)),
                    ),
                    ("result_envelope", json!(envelope)),
                ],
                json!({"endeavor_ref": committed_c.endeavor_ref()}),
            )
        },
    );
    command_outcome_bytes(outcome)?;
    Ok(())
}

/// Commit #link: `byom_committed → linking → linked`, with the
/// ExternalLink idempotent over its own digest, and the slot released only
/// by the committed link (§16.3 table rows 11–13).
fn commit_link(
    store: &mut Store,
    scope: &CommandScope,
    realm: &str,
    intent: &Intent,
    now: i64,
    hooks: &impl Fn(&str) -> CrashHooks,
) -> Result<Vec<u8>, Problem> {
    // `linking` first, so a crash between the two is visible as "the link
    // is being committed", not as "nothing happened".
    if intent.state == IntentState::ByomCommitted {
        let intent_c = intent.clone();
        let outcome = store.command_transaction(
            &step_scope(scope, "linking"),
            now,
            hooks("endeavor_promotion_start#linking"),
            move |txn| {
                commit_pair(
                    txn,
                    &intent_c,
                    IntentState::Linking,
                    Move::ExternalLinkBegin,
                    false,
                    &[],
                    json!({}),
                )
            },
        );
        command_outcome_bytes(outcome)?;
    }
    let intent = read_intent(store.conn(), realm, &intent.formation_id)?.ok_or_else(internal)?;
    let intent_c = intent.clone();
    let realm_c = realm.to_owned();
    let outcome = store.command_transaction(
        &step_scope(scope, "link"),
        now,
        hooks("endeavor_promotion_start#link"),
        move |txn| link_and_finish(txn, &realm_c, &intent_c),
    );
    command_outcome_bytes(outcome)
}

fn link_and_finish(
    txn: &mut kovee_store::CommandTxn<'_>,
    realm: &str,
    intent: &Intent,
) -> Result<Applied, Problem> {
    let digests = digests_of(txn.conn(), realm)?;
    let envelope = intent.result_envelope.clone().ok_or_else(internal)?;
    let endeavor_ref = envelope
        .get("endeavor_ref")
        .and_then(Value::as_str)
        .ok_or_else(internal)?
        .to_owned();
    let endeavor_revision = envelope
        .get("endeavor_revision")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let result_digest = envelope.get("digest").cloned().unwrap_or(Value::Null);
    let link_digest = digests
        .digest(
            TAG_LINK,
            &json!({
                "formation_id": intent.formation_id,
                "endeavor_ref": endeavor_ref,
                "endeavor_revision": endeavor_revision,
                "result_digest": result_digest,
            }),
        )
        .map_err(|_| internal())?;
    let link_ref = format!("xlink-{}", &link_digest.value_hex[..24]);
    // Idempotent over its digest: the same link never lands twice.
    txn.conn()
        .execute(
            "INSERT INTO external_links (link_ref, formation_id, realm_ref, endeavor_ref,
                 endeavor_revision, endeavor_digest, result_digest, link_digest_hex,
                 source_cursor, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(link_digest_hex) DO NOTHING",
            params![
                link_ref,
                intent.formation_id,
                realm,
                endeavor_ref,
                endeavor_revision as i64,
                envelope
                    .get("endeavor_digest")
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "null".to_owned()),
                result_digest.to_string(),
                link_digest.value_hex,
                envelope
                    .get("source_cursor")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                txn.now_ts(),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;

    commit_pair(
        txn,
        intent,
        IntentState::Linked,
        Move::ExternalLinkCommit,
        true,
        &[("external_link_ref", json!(link_ref))],
        json!({"external_link_ref": link_ref, "endeavor_ref": endeavor_ref}),
    )
}

// ----------------------------------------- endeavor_promotion_reconcile ----

/// The recovery operation: read byom's own signed fact and commit the ONE
/// row it authorizes. Optionally terminalize, which is the only liveness
/// mutation available after an ambiguous formation — and only for the same
/// source human, freshly authenticated.
#[allow(clippy::too_many_arguments)]
pub fn endeavor_promotion_reconcile(
    store: &mut Store,
    resolver: &EndpointResolver,
    scope: CommandScope,
    realm: String,
    args: PromotionReconcileArgs,
    now: i64,
    hooks: impl Fn(&str) -> CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let intent = read_intent(store.conn(), &realm, &args.formation_id)?.ok_or_else(not_found)?;
    if intent.state.is_terminal() {
        // Query-first restore: a terminal pair is reported, never re-driven.
        return crate::handlers::ok_reply(
            promotion_view(store.conn(), &realm, &intent.formation_id)?,
            Some(intent.revision),
        );
    }
    let endpoint = resolver(&intent.byom_endpoint_ref);
    let incarnation = endpoint
        .hello(Surface::Governance)
        .map_err(|e| bpp::passthrough(&e))?
        .endpoint_incarnation;
    let pin = current_pin(store.conn(), &realm)?;

    let fact = query_fact(&endpoint, &intent, &pin, &incarnation)?;
    apply_fact(store, &scope, &realm, &intent, &fact, "query", now, &hooks)?;

    if !args.terminalize {
        let intent = read_intent(store.conn(), &realm, &args.formation_id)?.ok_or_else(internal)?;
        return crate::handlers::ok_reply(
            promotion_view(store.conn(), &realm, &intent.formation_id)?,
            Some(intent.revision),
        );
    }

    // The terminalization path. It exists exactly where the descriptor's
    // `tombstone_verified` row does: any state whose outcome is still
    // ambiguous. Once a signed result exists there is nothing to deny —
    // the pair links it instead.
    let intent = read_intent(store.conn(), &realm, &args.formation_id)?.ok_or_else(internal)?;
    if !matches!(
        intent.state,
        IntentState::Prepared
            | IntentState::Submitting
            | IntentState::RemoteUnknown
            | IntentState::AwaitingPrincipal
            | IntentState::Ambiguous
    ) {
        return Err(forbidden(
            "terminalization exists only while the outcome is ambiguous",
            format!(
                "the intent is {:?}: a formation with a verified committed result is linked, not \
                 denied (§16.3 table rows 4 and 7)",
                intent.state.as_str()
            ),
        ));
    }
    let observation = args.authentication_observation_ref.clone().ok_or_else(|| {
        forbidden(
            "terminalization requires a freshly authenticated principal",
            "§16.3: the same source human, freshly authenticated through a current recovery \
             binding, is the only actor who may deny future execution",
        )
    })?;
    let reason = args
        .reason
        .clone()
        .unwrap_or_else(|| "the principal denies future execution of this formation".to_owned());

    // A fresh credential for THIS terminalization — a new nonce, minted
    // and recorded durably before the call.
    let terminalize_nonce = mint_terminalize_credential(
        store,
        &step_scope(&scope, "terminalize-credential"),
        &realm,
        &intent,
        &observation,
        now,
        &hooks,
    )?;
    let dpc = crate::credentials::read(store.conn(), GATEWAY_ISSUER_REF, &terminalize_nonce)?
        .ok_or_else(internal)?;
    let fact = terminalize(&endpoint, &intent, &pin, &dpc, &reason)?;
    apply_fact(
        store,
        &scope,
        &realm,
        &intent,
        &fact,
        "terminalize",
        now,
        &hooks,
    )?;
    let intent = read_intent(store.conn(), &realm, &args.formation_id)?.ok_or_else(internal)?;
    crate::handlers::ok_reply(
        promotion_view(store.conn(), &realm, &intent.formation_id)?,
        Some(intent.revision),
    )
}

fn current_pin(conn: &Connection, realm: &str) -> Result<BindingPin, Problem> {
    let (binding, _) = active_seam(conn, realm)?.ok_or_else(|| {
        forbidden(
            "this realm has no active governed-work binding",
            "reconciliation authenticates through the CURRENT recovery binding",
        )
    })?;
    BindingPin::of(&hostint::wire_binding(&binding).map_err(|_| internal())?)
        .map_err(|_| internal())
}

/// `external_command_result_query` — read-only, on the projection surface,
/// riding the narrow recovery workload. It cannot submit, terminalize,
/// modify, or impersonate the original human (R42).
fn query_fact(
    endpoint: &Endpoint,
    intent: &Intent,
    pin: &BindingPin,
    incarnation: &str,
) -> Result<Fact, Problem> {
    let token = recovery_workload_token(&pin.binding_ref).ok_or_else(|| {
        Problem::new(
            ProblemKind::Unavailable,
            "no byom recovery-workload token is available",
        )
        .with_detail(
            "external_command_result_query rides the narrow recovery workload byomd publishes \
             for the installed binding; point $KOVEE_BYOM_CHANNELS_DIR at the endpoint's \
             channel directory (or set $KOVEE_BYOM_RECOVERY_TOKEN)",
        )
    })?;
    let request = json!({
        "version": BPP_VERSION,
        "op": "external_command_result_query",
        "current_byom_endpoint_ref": intent.byom_endpoint_ref,
        "current_endpoint_incarnation": incarnation,
        "current_recovery_binding_ref": pin.binding_ref,
        "current_recovery_binding_revision": pin.binding_revision,
        "current_recovery_binding_epoch": pin.binding_epoch,
        "current_recovery_binding_digest": pin.digest,
        "kovee_formation_intent_ref": intent.formation_id,
        "target_byom_endpoint_ref": intent.byom_endpoint_ref,
        "target_endpoint_incarnation": intent.command_endpoint_incarnation,
        "target_realm_byom_binding_ref": pin.binding_ref,
        "target_realm_byom_binding_revision": pin.binding_revision,
        "target_realm_byom_binding_epoch": pin.binding_epoch,
        "target_realm_byom_binding_digest": pin.digest,
        "target_society_ref": intent.society_ref,
        "target_society_recovery_epoch": intent.society_recovery_epoch,
        "source_principal_ref": intent.requested_by_principal,
        "source_actor_binding_digest": intent.source_actor_binding_digest,
        "operation": OPERATION,
        "byom_command_idempotency_key": intent.byom_command_idempotency_key,
        "canonical_command_digest": intent.canonical_byom_command_digest,
        "idempotency_domain_digest": intent.idempotency_domain_digest,
    });
    match endpoint.call_with_preamble(Surface::Projection, Some(&token), &request) {
        Ok(reply) => Fact::from_query_result(&reply.result).map_err(|e| {
            Problem::new(
                ProblemKind::Unavailable,
                "the byom endpoint answered with an unusable recovery fact",
            )
            .with_detail(e.to_string())
        }),
        // An endpoint that cannot answer leaves the state UNKNOWN — and
        // unknown is a fact of the machine, not a failure of it.
        Err(e) if !e.is_definite() => Ok(Fact::Unknown),
        Err(e) => Err(bpp::passthrough(&e)),
    }
}

fn mint_terminalize_credential(
    store: &mut Store,
    scope: &CommandScope,
    realm: &str,
    intent: &Intent,
    observation_ref: &str,
    now: i64,
    hooks: &impl Fn(&str) -> CrashHooks,
) -> Result<String, Problem> {
    let nonce = new_id("ectn").map_err(store_problem)?;
    let nonce_c = nonce.clone();
    let intent_c = intent.clone();
    let realm_c = realm.to_owned();
    let observation = observation_ref.to_owned();
    let outcome = store.command_transaction(
        scope,
        now,
        hooks("endeavor_promotion_reconcile#credential"),
        move |txn| {
            let digests = digests_of(txn.conn(), &realm_c)?;
            let (binding, mapping) = active_seam(txn.conn(), &realm_c)?.ok_or_else(internal)?;
            let participant = participant_of(txn.conn(), &intent_c.formation_id)?;
            let dpc = DpcMint {
                issuer_ref: GATEWAY_ISSUER_REF,
                nonce: &nonce_c,
                sender_constraint: SenderConstraint::channel_exporter(
                    digests
                        .digest(
                            "kovee-channel-exporter-v1",
                            &json!({"channel": "kovee-owner-uds", "realm_ref": realm_c}),
                        )
                        .map_err(|_| internal())?,
                ),
                delegation: Delegation {
                    source_principal_ref: &intent_c.requested_by_principal,
                    bound_participant_ref: &participant.0,
                    participant_binding_epoch: participant.1,
                    allowed_operations: &["external_command_terminalize"],
                    authentication_observation_ref: &observation,
                    assurance_level: ASSURANCE_LEVEL,
                },
                subject_digest: intent_c.canonical_byom_command_digest.clone(),
                issued_at: now,
                lifetime_seconds: CREDENTIAL_LIFETIME_SECONDS,
            }
            .issue(&MintContext {
                binding: &binding,
                society_ref: mapping.society_ref.clone(),
                society_recovery_epoch: mapping.society_recovery_epoch,
            })
            .map_err(|e| {
                forbidden(
                    "the delegated-principal credential is not mintable",
                    e.to_string(),
                )
            })?;
            crate::credentials::record(txn.conn(), &realm_c, &binding.binding_ref, &dpc)?;
            Ok(Applied {
                result: json!({"nonce": nonce_c}),
                revision: None,
                event_cursor: None,
            })
        },
    );
    command_outcome_bytes(outcome)?;
    Ok(nonce)
}

/// `external_command_terminalize` — the same source human on a fresh
/// channel, over the exact original domain and command bytes.
fn terminalize(
    endpoint: &Endpoint,
    intent: &Intent,
    pin: &BindingPin,
    dpc: &DelegatedPrincipalCredential,
    reason: &str,
) -> Result<Fact, Problem> {
    let proof = hostint::attempt_proof(
        &intent.canonical_byom_command_digest,
        &intent.idempotency_domain_digest,
        &dpc.nonce,
        &pin.digest,
        &dpc.source_actor_binding_digest,
    )
    .map_err(|_| internal())?;
    let request = json!({
        "version": BPP_VERSION,
        "op": "external_command_terminalize",
        "meta": {
            "request_id": dpc.nonce,
            "idempotency_key": intent.byom_command_idempotency_key,
            "expected_endpoint_incarnation": intent.command_endpoint_incarnation,
            "expected_recovery_epoch": intent.society_recovery_epoch,
        },
        "kovee_formation_intent_ref": intent.formation_id,
        "current_recovery_binding_ref": pin.binding_ref,
        "current_recovery_binding_revision": pin.binding_revision,
        "current_recovery_binding_epoch": pin.binding_epoch,
        "current_recovery_binding_digest": pin.digest,
        "target_byom_endpoint_ref": intent.byom_endpoint_ref,
        "target_endpoint_incarnation": intent.command_endpoint_incarnation,
        "target_society_ref": intent.society_ref,
        "target_society_recovery_epoch": intent.society_recovery_epoch,
        "source_principal_ref": intent.requested_by_principal,
        "target_source_actor_binding_digest": intent.source_actor_binding_digest,
        "current_source_actor_binding_digest": dpc.source_actor_binding_digest,
        "operation": OPERATION,
        "byom_command_idempotency_key": intent.byom_command_idempotency_key,
        "canonical_command_digest": intent.canonical_byom_command_digest,
        "idempotency_domain_digest": intent.idempotency_domain_digest,
        "reason": reason,
        "authentication_observation_ref": dpc.authentication_observation_ref,
        "authentication_observation_digest": dpc.authentication_observation_digest,
        "authentication_proof": proof,
    });
    match endpoint.call_with_preamble(Surface::Governance, Some(&dpc.preamble()), &request) {
        Ok(reply) => Fact::from_terminalize_result(&reply.result).map_err(|e| {
            Problem::new(
                ProblemKind::Unavailable,
                "the byom endpoint answered with an unusable terminalization",
            )
            .with_detail(e.to_string())
        }),
        Err(e) if !e.is_definite() => Ok(Fact::Unknown),
        Err(e) => Err(bpp::passthrough(&e)),
    }
}

/// Commit the ONE row a verified fact authorizes. A fact with no row for
/// this state changes nothing — rejection is the absence of a transition.
#[allow(clippy::too_many_arguments)]
fn apply_fact(
    store: &mut Store,
    scope: &CommandScope,
    realm: &str,
    intent: &Intent,
    fact: &Fact,
    step: &str,
    now: i64,
    hooks: &impl Fn(&str) -> CrashHooks,
) -> Result<(), Problem> {
    let intent = read_intent(store.conn(), realm, &intent.formation_id)?.ok_or_else(internal)?;
    let Some(resolution) = resolve(intent.state, fact) else {
        return Ok(());
    };
    let fact_c = fact.clone();
    let intent_c = intent.clone();
    let outcome = store.command_transaction(
        &step_scope(scope, step),
        now,
        hooks(&format!("endeavor_promotion_reconcile#{step}")),
        move |txn| {
            let mut extra: Vec<(&str, Value)> = Vec::new();
            let mut payload = json!({"fact": fact_name(&fact_c)});
            if let Fact::Committed(result) = &fact_c {
                extra.push((
                    "byom_result_ref",
                    result
                        .envelope
                        .get("endeavor_ref")
                        .cloned()
                        .unwrap_or(Value::Null),
                ));
                extra.push(("byom_result_digest", json!(digest_json(&result.digest))));
                extra.push((
                    "result_envelope",
                    json!(serde_json::to_string(&result.envelope).map_err(|_| internal())?),
                ));
            }
            if let Fact::HistoricallyFencedAbsent { receipt_ref } = &fact_c {
                if let Some(map) = payload.as_object_mut() {
                    map.insert(
                        "historical_fence_receipt_ref".to_owned(),
                        json!(receipt_ref),
                    );
                }
            }
            if let Some(attempt_ref) = &intent_c.latest_attempt_ref {
                let at = txn.now_ts();
                close_attempt(txn.conn(), attempt_ref, AttemptState::Reconciled, None, &at)?;
            }
            commit_pair(
                txn,
                &intent_c,
                resolution.intent,
                resolution.via,
                resolution.releases_slot,
                &extra,
                payload,
            )
        },
    );
    command_outcome_bytes(outcome)?;

    // A committed fact discovered by recovery still needs its link.
    let refreshed = read_intent(store.conn(), realm, &intent.formation_id)?.ok_or_else(internal)?;
    if refreshed.state == IntentState::ByomCommitted || refreshed.state == IntentState::Linking {
        commit_link(store, scope, realm, &refreshed, now, hooks)?;
    }
    Ok(())
}

fn fact_name(fact: &Fact) -> &'static str {
    match fact {
        Fact::Committed(_) => "committed",
        Fact::Absent => "absent",
        Fact::HistoricallyFencedAbsent { .. } => "historically_fenced_absent",
        Fact::Tombstone => "non_reexecuting_tombstone",
        Fact::Unknown => "unknown",
        Fact::NotTerminalizable { .. } => "not_terminalizable",
    }
}
