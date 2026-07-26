//! The hosted-episode pipeline, as Kovee sees it: notification → Kovee
//! places → byom admits the placement → the Episode is requested, claimed,
//! and started, and from then on EVERY mutation presents BOTH fences.
//!
//! What you write (the whole activation, in order — and the order is the
//! point):
//!
//! ```no_run
//! # use koveed::episode::*;
//! # use kovee_byom::bpp::Endpoint;
//! # fn f(store: &mut kovee_store::Store, endpoint: &Endpoint) -> Result<(), kovee_core::problem::Problem> {
//! // 1. byom notified (or Kovee polled its projection): an admitted
//! //    WakeIntent with a kernel ResourceAllocation. Notification is not
//! //    a wake, and Kovee never invents either record.
//! let notice = Notice {
//!     society_ref: "soc-1".into(), recovery_epoch: 0,
//!     participant_ref: "part-1".into(), participant_binding_epoch: 1,
//!     manifestation_ref: "man-1".into(), activity_stream_ref: "as-1".into(),
//!     generation: 2, resource_allocation_ref: "alloc-1".into(),
//!     mandate_use_refs: vec!["mu-1".into()],
//!     byom_budget_reservation_ref: "brs-1".into(),
//!     external_budget_bridge_ref: "ebb-1".into(),
//!     context_manifest_ref: "cm-1".into(),
//! };
//! // 2. Kovee authors the PlacementBinding — the one activation record
//! //    it owns.
//! let placed = place(store, "realm-personal", &notice, "inv-1", 0)?;
//! // 3. byom's runtime adapter admits it. No episode work before this.
//! admit(store, endpoint, &placed.placement_id, 0)?;
//! // 4. request / claim / start — and every later mutation carries both
//! //    fences.
//! let bound = start(store, endpoint, &placed.placement_id, &notice, 0)?;
//! checkpoint(store, &bound.stable_binding_key, bound.fences, 0)?;
//! # Ok(()) }
//! ```
//!
//! Plumbing worth knowing:
//!
//! - **Stage order is checked, not assumed.** [`admit`] refuses a
//!   placement byom has not verified, and [`start`] refuses a placement
//!   that carries no admission — so "arrival, ranking, a host cron, or a
//!   model score cannot skip a stage" is a row lookup.
//! - **Dual fences on every mutation.** [`checkpoint`], [`yield_episode`],
//!   and [`complete`] each take the pair and refuse on either being stale,
//!   marking the binding `fenced` and retaining the row for audit: a stale
//!   worker keeps its bytes as local evidence but advances no head.
//! - **byomd does not serve the runtime surface yet** (its four sockets are
//!   governance/candidate/participant/projection; `placement_admit` and the
//!   Episode lease operations are byom's B0.3/B3 slice). A call therefore
//!   answers `unavailable` and this pipeline HOLDS — it never proceeds on
//!   the assumption that silence meant admission.

use kovee_byom::bpp::{self, Endpoint, Surface, BPP_VERSION};
use kovee_byom::episode::{
    local_commitments_are_closed, BindingState, ByomEpisodeBinding, FenceError, Fences,
    PlacementBinding, PLACEMENT_OWNER,
};
use kovee_byom::records::GovernanceDigests;
use kovee_core::event::{
    EVENT_EPISODE_BINDING_BOUND, EVENT_EPISODE_BINDING_FENCED, EVENT_EPISODE_BINDING_RELEASED,
};
use kovee_core::family::DigestRef;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::time::rfc3339_utc;
use kovee_store::{new_id, NewEvent, Store, OWNER_ACTOR_REF};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::{json, Value};

use crate::governance::active_seam;
use crate::state::{internal, not_found, store_problem, DEFAULT_CLASSIFICATION};

const TAG_PLACEMENT: &str = "kovee-placement-binding-v1";
const TAG_CONSTRAINT: &str = "kovee-placement-constraint-v1";
const TAG_BINDING: &str = "kovee-byom-episode-binding-v1";
const TAG_CONTEXT_SOURCE: &str = "kovee-episode-context-source-v1";

/// The local-commitment classes this profile grants a hosted child
/// (family contract L34–L37). Anything else goes through
/// `call_open`/`pledge_propose`/`act_intent_*`.
pub const ALLOWED_LOCAL_COMMITMENTS: [&str; 2] = ["contribution_append", "attention_mark"];

/// What byom told Kovee (or what Kovee read off byom's projection): an
/// Episode is eligible and its resources are allocated. Kovee authors
/// NEITHER the WakeIntent nor the ActivationAdmission nor the
/// ResourceAllocation — it only places.
#[derive(Debug, Clone)]
pub struct Notice {
    pub society_ref: String,
    pub recovery_epoch: u64,
    pub participant_ref: String,
    pub participant_binding_epoch: u64,
    pub manifestation_ref: String,
    pub activity_stream_ref: String,
    pub generation: u64,
    pub resource_allocation_ref: String,
    pub mandate_use_refs: Vec<String>,
    pub byom_budget_reservation_ref: String,
    pub external_budget_bridge_ref: String,
    pub context_manifest_ref: String,
}

/// One authored placement.
#[derive(Debug, Clone)]
pub struct Placed {
    pub placement_id: String,
    pub kovee_fence_epoch: u64,
    pub record: PlacementBinding,
}

/// One bound Episode attempt.
#[derive(Debug, Clone)]
pub struct Bound {
    pub stable_binding_key: String,
    pub episode_ref: String,
    pub byom_attempt_ref: String,
    pub fences: Fences,
    pub record: ByomEpisodeBinding,
}

fn digests_of(conn: &Connection, realm: &str) -> Result<GovernanceDigests, Problem> {
    let key = kovee_store::governance_scope_key_of(conn).map_err(store_problem)?;
    Ok(GovernanceDigests::new(&key, realm))
}

fn digest_json(digest: &DigestRef) -> String {
    serde_json::to_string(digest).unwrap_or_else(|_| "{}".to_owned())
}

fn forbidden(title: &str, detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::Forbidden, title).with_detail(detail)
}

fn stale_fence(error: FenceError) -> Problem {
    // A fence advance is exactly a stale lease: the presented binding no
    // longer authorizes any mutation, and no retry can revive it.
    Problem::new(ProblemKind::StaleLease, "the episode binding is fenced").with_detail(format!(
        "{error}; a successor attempt gets a NEW binding row under a new stable key"
    ))
}

// ------------------------------------------------------- stage 2: place ----

/// Kovee authors the `PlacementBinding` among already-eligible
/// Manifestations (byom §11.1 stage 4). It is the ONE activation record
/// Kovee owns.
pub fn place(
    store: &mut Store,
    realm: &str,
    notice: &Notice,
    kovee_invocation_ref: &str,
    now: i64,
) -> Result<Placed, Problem> {
    let digests = digests_of(store.conn(), realm)?;
    let (_, mapping) = active_seam(store.conn(), realm)?.ok_or_else(|| {
        forbidden(
            "this realm has no active governed-work binding",
            "an Episode is hosted only under an ACTIVE KoveeRealmByomBinding",
        )
    })?;
    if mapping.society_ref != notice.society_ref
        || mapping.society_recovery_epoch != notice.recovery_epoch
    {
        return Err(forbidden(
            "the notice names another Society or recovery epoch",
            format!(
                "the active mapping covers {:?} at epoch {}",
                mapping.society_ref, mapping.society_recovery_epoch
            ),
        ));
    }
    // An exact retry of the same allocation returns the identical
    // placement: Kovee never places one allocation twice.
    if let Some(existing) =
        read_placement_by_allocation(store.conn(), realm, &notice.resource_allocation_ref)?
    {
        return Ok(existing);
    }

    let placement_id = new_id("plc").map_err(store_problem)?;
    let constraint = digests
        .digest(
            TAG_CONSTRAINT,
            &json!({
                "activity_stream_ref": notice.activity_stream_ref,
                "generation": notice.generation,
                "manifestation_ref": notice.manifestation_ref,
                "mandate_use_refs": notice.mandate_use_refs,
            }),
        )
        .map_err(|_| internal())?;
    let allocation_digest = digests
        .digest(
            TAG_PLACEMENT,
            &json!({"resource_allocation_ref": notice.resource_allocation_ref}),
        )
        .map_err(|_| internal())?;
    let manifestation_digest = digests
        .digest(
            TAG_PLACEMENT,
            &json!({"selected_manifestation_ref": notice.manifestation_ref}),
        )
        .map_err(|_| internal())?;
    let mut record = PlacementBinding {
        owner_protocol: PLACEMENT_OWNER.to_owned(),
        placement_id: placement_id.clone(),
        revision: 1,
        resource_allocation_ref: notice.resource_allocation_ref.clone(),
        resource_allocation_digest: allocation_digest,
        selected_manifestation_ref: notice.manifestation_ref.clone(),
        selected_manifestation_digest: manifestation_digest,
        host_runtime_binding: format!("kovee-runtime:{realm}"),
        kovee_invocation_ref: kovee_invocation_ref.to_owned(),
        placement_constraint_digest: constraint,
        // The Kovee half of the dual fences starts at 1 and only ever
        // advances; a successor attempt gets a new one.
        kovee_fence_epoch: 1,
        state: "placed".to_owned(),
        created_at: rfc3339_utc(now),
        digest: DigestRef::portable_public("0".repeat(64)),
    };
    let projection = serde_json::to_value(&record).unwrap_or(Value::Null);
    record.digest = digests
        .digest(TAG_PLACEMENT, &projection)
        .map_err(|_| internal())?;

    store
        .conn()
        .execute(
            "INSERT INTO byom_placement_bindings (placement_id, realm_ref, owner_protocol,
                 revision, resource_allocation_ref, resource_allocation_digest,
                 selected_manifestation_ref, selected_manifestation_digest,
                 host_runtime_binding, kovee_invocation_ref, placement_constraint_digest,
                 kovee_fence_epoch, state, created_at, digest)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                record.placement_id,
                realm,
                record.owner_protocol,
                record.revision as i64,
                record.resource_allocation_ref,
                digest_json(&record.resource_allocation_digest),
                record.selected_manifestation_ref,
                digest_json(&record.selected_manifestation_digest),
                record.host_runtime_binding,
                record.kovee_invocation_ref,
                digest_json(&record.placement_constraint_digest),
                record.kovee_fence_epoch as i64,
                record.state,
                record.created_at,
                digest_json(&record.digest),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;

    Ok(Placed {
        placement_id,
        kovee_fence_epoch: record.kovee_fence_epoch,
        record,
    })
}

// ------------------------------------------------------- stage 3: admit ----

/// `placement_admit` (R33) on byom's runtime surface. byom records only
/// the `PlacementAdmission`, after verifying the source binding — and
/// until it answers, nothing downstream may run.
pub fn admit(
    store: &mut Store,
    endpoint: &Endpoint,
    placement_id: &str,
    now: i64,
) -> Result<(), Problem> {
    let placed = read_placement(store.conn(), placement_id)?.ok_or_else(not_found)?;
    if placed.admitted {
        return Ok(());
    }
    let request = json!({
        "version": BPP_VERSION,
        "op": "placement_admit",
        "meta": {
            "request_id": format!("req-{placement_id}"),
            "idempotency_key": format!("admit-{placement_id}"),
            "expected_endpoint_incarnation": placed.record.host_runtime_binding,
            "expected_recovery_epoch": 0,
        },
        "resource_allocation_ref": placed.record.resource_allocation_ref,
        "resource_allocation_digest": placed.record.resource_allocation_digest,
        "kovee_placement_ref": placed.record.placement_id,
        "kovee_placement_revision": placed.record.revision,
        "kovee_placement_digest": placed.record.digest,
        "kovee_fence_epoch": placed.record.kovee_fence_epoch,
    });
    let reply = endpoint
        .call(Surface::Runtime, &request)
        .map_err(|e| bpp::passthrough(&e))?;
    let admission_ref = reply
        .result
        .get("admission_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            Problem::new(
                ProblemKind::Unavailable,
                "the byom endpoint answered with an unusable placement admission",
            )
            .with_detail("placement_admit returned no admission_id")
        })?;
    // The admission must pin THIS placement revision: byom's verification
    // status is about these exact bytes or it is about nothing.
    if reply
        .result
        .get("kovee_placement_revision")
        .and_then(Value::as_u64)
        != Some(placed.record.revision)
    {
        return Err(forbidden(
            "the placement admission pins another placement revision",
            "byom records PlacementAdmission against the exact Kovee placement revision \
             (UNIQUE(kovee_placement_ref, kovee_placement_revision))",
        ));
    }
    store
        .conn()
        .execute(
            "UPDATE byom_placement_bindings
             SET admission_ref = ?2, admission_digest = ?3, admitted_at = ?4
             WHERE placement_id = ?1",
            params![
                placement_id,
                admission_ref,
                reply
                    .result
                    .get("digest")
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "null".to_owned()),
                rfc3339_utc(now),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

// ------------------------------------- stage 4: request / claim / start ----

/// `episode_request` → `episode_claim` → `episode_start`, then the binding
/// row committed at the exact claim/start CAS Kovee observed (§16.6 item
/// 3). Refuses outright when the placement carries no byom admission.
pub fn start(
    store: &mut Store,
    endpoint: &Endpoint,
    placement_id: &str,
    notice: &Notice,
    now: i64,
) -> Result<Bound, Problem> {
    let placed = read_placement(store.conn(), placement_id)?.ok_or_else(not_found)?;
    if !placed.admitted {
        return Err(forbidden(
            "no episode work before byom admits the placement",
            "byom §11.1: activation has four records and four owners, and nothing skips a stage \
             — placement_admit must have recorded a PlacementAdmission first (R33)",
        ));
    }
    let realm = placed.realm_ref.clone();

    // The three byom runtime calls. Each is a definite answer or nothing;
    // an unreachable runtime leaves the pipeline exactly where it was.
    let requested = runtime_call(
        endpoint,
        "episode_request",
        json!({
            "activity_stream_ref": notice.activity_stream_ref,
            "generation": notice.generation,
            "participant_ref": notice.participant_ref,
            "resource_allocation_ref": notice.resource_allocation_ref,
        }),
    )?;
    let episode_ref = string_of(&requested, "episode_ref")?;
    let claimed = runtime_call(
        endpoint,
        "episode_claim",
        json!({
            "episode_ref": episode_ref,
            "kovee_placement_ref": placement_id,
            "kovee_fence_epoch": placed.record.kovee_fence_epoch,
        }),
    )?;
    let byom_attempt_ref = string_of(&claimed, "byom_attempt_ref")?;
    let byom_fence_epoch = claimed
        .get("byom_fence_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            Problem::new(
                ProblemKind::Unavailable,
                "the byom endpoint answered with an unusable claim",
            )
            .with_detail("episode_claim returned no byom_fence_epoch")
        })?;
    let fences = Fences {
        byom: byom_fence_epoch,
        kovee: placed.record.kovee_fence_epoch,
    };
    // episode_start is already a DUAL-fence mutation.
    runtime_call(
        endpoint,
        "episode_start",
        json!({
            "episode_ref": episode_ref,
            "byom_attempt_ref": byom_attempt_ref,
            "byom_fence_epoch": fences.byom,
            "kovee_invocation_fence": fences.kovee,
        }),
    )?;

    bind(
        store,
        &realm,
        &placed,
        notice,
        &episode_ref,
        &byom_attempt_ref,
        fences,
        now,
    )
}

/// The idempotent binding create at the claim/start CAS (family contract
/// L22): an exact retry under the same `stable_binding_key` returns the
/// identical row, and a DIFFERENT key for the same (episode, attempt,
/// invocation) triple conflicts rather than double-binding.
#[allow(clippy::too_many_arguments)]
pub fn bind(
    store: &mut Store,
    realm: &str,
    placed: &PlacementRow,
    notice: &Notice,
    episode_ref: &str,
    byom_attempt_ref: &str,
    fences: Fences,
    now: i64,
) -> Result<Bound, Problem> {
    let digests = digests_of(store.conn(), realm)?;
    let stable_binding_key = format!(
        "ebk-{}",
        &digests
            .digest(
                TAG_BINDING,
                &json!({
                    "episode_ref": episode_ref,
                    "byom_attempt_ref": byom_attempt_ref,
                    "kovee_invocation_ref": placed.record.kovee_invocation_ref,
                }),
            )
            .map_err(|_| internal())?
            .value_hex[..32]
    );
    if let Some(existing) = read_binding(store.conn(), &stable_binding_key)? {
        return Ok(existing);
    }
    let allowed_local_commitments: Vec<String> = ALLOWED_LOCAL_COMMITMENTS
        .iter()
        .map(|c| (*c).to_owned())
        .collect();
    if !local_commitments_are_closed(&allowed_local_commitments) {
        return Err(internal());
    }
    let (binding_row, mapping) = active_seam(store.conn(), realm)?.ok_or_else(internal)?;
    let context_source = digests
        .digest(
            TAG_CONTEXT_SOURCE,
            &json!({
                "context_manifest_ref": notice.context_manifest_ref,
                "activity_stream_ref": notice.activity_stream_ref,
                "generation": notice.generation,
            }),
        )
        .map_err(|_| internal())?;
    let subordinate =
        crate::budget::reservation_of_bridge(store.conn(), &notice.external_budget_bridge_ref)?;
    let mut record = ByomEpisodeBinding {
        byom_endpoint_ref: binding_row.byom_endpoint_ref.clone(),
        endpoint_incarnation: binding_row.endpoint_incarnation.clone(),
        society_ref: mapping.society_ref.clone(),
        recovery_epoch: mapping.society_recovery_epoch,
        participant_ref: notice.participant_ref.clone(),
        participant_binding_epoch: notice.participant_binding_epoch,
        manifestation_ref: notice.manifestation_ref.clone(),
        activity_stream_ref: notice.activity_stream_ref.clone(),
        episode_ref: episode_ref.to_owned(),
        generation: notice.generation,
        byom_attempt_ref: byom_attempt_ref.to_owned(),
        byom_fence_epoch: fences.byom,
        kovee_invocation_ref: placed.record.kovee_invocation_ref.clone(),
        kovee_invocation_fence: fences.kovee,
        mandate_use_refs: notice.mandate_use_refs.clone(),
        context_source_digest: context_source,
        byom_budget_reservation_ref: notice.byom_budget_reservation_ref.clone(),
        byom_budget_reservation_digest: digests
            .digest(
                TAG_BINDING,
                &json!({"byom_budget_reservation_ref": notice.byom_budget_reservation_ref}),
            )
            .map_err(|_| internal())?,
        external_budget_bridge_ref: notice.external_budget_bridge_ref.clone(),
        kovee_subordinate_reservation_ref: subordinate
            .as_ref()
            .map(|(r, _)| r.clone())
            .unwrap_or_else(|| "ksr-absent".to_owned()),
        kovee_subordinate_reservation_digest: subordinate
            .as_ref()
            .map(|(_, d)| d.clone())
            .unwrap_or_else(|| DigestRef::portable_public("0".repeat(64))),
        dependency_digest: digests
            .digest(
                TAG_BINDING,
                &json!({
                    "placement_id": placed.record.placement_id,
                    "admission_ref": placed.admission_ref,
                    "resource_allocation_ref": notice.resource_allocation_ref,
                }),
            )
            .map_err(|_| internal())?,
        digest: DigestRef::portable_public("0".repeat(64)),
        stable_binding_key: stable_binding_key.clone(),
        allowed_local_commitments,
        context_manifest_ref: notice.context_manifest_ref.clone(),
        context_manifest_digest: digests
            .digest(
                TAG_BINDING,
                &json!({"context_manifest_ref": notice.context_manifest_ref}),
            )
            .map_err(|_| internal())?,
        kovee_context_assembly_ref: None,
        kovee_context_assembly_digest: None,
        provider_context_manifest_ref: None,
        provider_context_manifest_digest: None,
    };
    let mut projection = serde_json::to_value(&record).unwrap_or(Value::Null);
    if let Some(map) = projection.as_object_mut() {
        map.remove("digest");
    }
    record.digest = digests
        .digest(TAG_BINDING, &projection)
        .map_err(|_| internal())?;
    if !record.context_pairs_are_coherent() {
        return Err(internal());
    }

    let at = rfc3339_utc(now);
    store
        .conn()
        .execute(
            "INSERT INTO byom_episode_bindings (binding_id, realm_ref, stable_binding_key,
                 placement_id, episode_ref, byom_attempt_ref, kovee_invocation_ref,
                 byom_fence_epoch, kovee_invocation_fence, state, episode_state, record,
                 created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13)",
            params![
                new_id("beb").map_err(store_problem)?,
                realm,
                stable_binding_key,
                placed.record.placement_id,
                record.episode_ref,
                record.byom_attempt_ref,
                record.kovee_invocation_ref,
                record.byom_fence_epoch as i64,
                record.kovee_invocation_fence as i64,
                BindingState::Bound.as_str(),
                "running",
                serde_json::to_string(&record).map_err(|_| internal())?,
                at,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    store
        .conn()
        .execute(
            "UPDATE byom_placement_bindings SET state = 'started' WHERE placement_id = ?1",
            [&placed.record.placement_id],
        )
        .map_err(|e| store_problem(e.into()))?;
    emit(
        store,
        realm,
        &record,
        EVENT_EPISODE_BINDING_BOUND,
        json!({"episode_ref": record.episode_ref, "state": "bound"}),
        now,
    )?;

    Ok(Bound {
        stable_binding_key,
        episode_ref: record.episode_ref.clone(),
        byom_attempt_ref: record.byom_attempt_ref.clone(),
        fences,
        record,
    })
}

// -------------------------------------------- the dual-fenced mutations ----

/// Every intra-episode mutation goes through here: the presented pair must
/// equal the bound pair. Either fence stale means the binding is FENCED —
/// terminal, retained for audit, and unable to advance any head.
fn fenced_mutation(
    store: &mut Store,
    stable_binding_key: &str,
    presented: Fences,
    what: &str,
    now: i64,
) -> Result<Bound, Problem> {
    let bound = read_binding(store.conn(), stable_binding_key)?.ok_or_else(not_found)?;
    let state = binding_state(store.conn(), stable_binding_key)?;
    if state != BindingState::Bound {
        return Err(forbidden(
            "this episode binding is terminal",
            format!(
                "the binding is {:?}: {what} advances nothing",
                state.as_str()
            ),
        ));
    }
    if let Err(error) = bound.fences.check(&presented) {
        let realm = binding_realm(store.conn(), stable_binding_key)?;
        store
            .conn()
            .execute(
                "UPDATE byom_episode_bindings
                 SET state = ?2, fenced_reason = ?3, updated_at = ?4
                 WHERE stable_binding_key = ?1",
                params![
                    stable_binding_key,
                    BindingState::Fenced.as_str(),
                    error.to_string(),
                    rfc3339_utc(now),
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        emit(
            store,
            &realm,
            &bound.record,
            EVENT_EPISODE_BINDING_FENCED,
            json!({
                "presented_byom_fence_epoch": presented.byom,
                "presented_kovee_invocation_fence": presented.kovee,
                "bound_byom_fence_epoch": bound.fences.byom,
                "bound_kovee_invocation_fence": bound.fences.kovee,
                "refused": what,
            }),
            now,
        )?;
        return Err(stale_fence(error));
    }
    Ok(bound)
}

/// `checkpoint_commit` — honors both fences.
pub fn checkpoint(
    store: &mut Store,
    stable_binding_key: &str,
    presented: Fences,
    now: i64,
) -> Result<(), Problem> {
    let bound = fenced_mutation(
        store,
        stable_binding_key,
        presented,
        "checkpoint_commit",
        now,
    )?;
    set_episode_state(store.conn(), &bound.stable_binding_key, "running", now)
}

/// `episode_yield` — honors both fences and hands the Continuation off.
pub fn yield_episode(
    store: &mut Store,
    stable_binding_key: &str,
    presented: Fences,
    continuation_ref: &str,
    now: i64,
) -> Result<Value, Problem> {
    let bound = fenced_mutation(store, stable_binding_key, presented, "episode_yield", now)?;
    set_episode_state(store.conn(), &bound.stable_binding_key, "yielded", now)?;
    // The Continuation hand-off: Kovee records WHICH continuation the
    // yielded episode left behind. A successor attempt claims it under a
    // new byom fence and therefore a NEW binding row.
    Ok(json!({
        "stable_binding_key": bound.stable_binding_key,
        "episode_ref": bound.episode_ref,
        "continuation_ref": continuation_ref,
        "byom_fence_epoch": bound.fences.byom,
        "kovee_invocation_fence": bound.fences.kovee,
        "successor_requires_new_binding": true,
    }))
}

/// `episode_complete` — honors both fences, then releases the binding and
/// hands the budget reservations to §11.4 settlement.
pub fn complete(
    store: &mut Store,
    stable_binding_key: &str,
    presented: Fences,
    now: i64,
) -> Result<(), Problem> {
    let bound = fenced_mutation(
        store,
        stable_binding_key,
        presented,
        "episode_complete",
        now,
    )?;
    let realm = binding_realm(store.conn(), stable_binding_key)?;
    store
        .conn()
        .execute(
            "UPDATE byom_episode_bindings
             SET state = ?2, episode_state = 'completed', updated_at = ?3
             WHERE stable_binding_key = ?1",
            params![
                stable_binding_key,
                BindingState::Released.as_str(),
                rfc3339_utc(now),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    emit(
        store,
        &realm,
        &bound.record,
        EVENT_EPISODE_BINDING_RELEASED,
        json!({
            "episode_ref": bound.episode_ref,
            "byom_budget_reservation_ref": bound.record.byom_budget_reservation_ref,
            "kovee_subordinate_reservation_ref": bound.record.kovee_subordinate_reservation_ref,
            "settlement": "handed to §11.4 (usage_report is evidence only)",
        }),
        now,
    )
}

/// The successor attempt of a yielded or expired Episode: a NEW binding
/// row under a NEW stable key, never a re-binding of the fenced one.
#[allow(clippy::too_many_arguments)]
pub fn rebind(
    store: &mut Store,
    realm: &str,
    placement_id: &str,
    notice: &Notice,
    episode_ref: &str,
    successor_attempt_ref: &str,
    fences: Fences,
    now: i64,
) -> Result<Bound, Problem> {
    let placed = read_placement(store.conn(), placement_id)?.ok_or_else(not_found)?;
    bind(
        store,
        realm,
        &placed,
        notice,
        episode_ref,
        successor_attempt_ref,
        fences,
        now,
    )
}

// ------------------------------------------------------------ row access ----

/// One stored placement, plus whether byom admitted it.
#[derive(Debug, Clone)]
pub struct PlacementRow {
    pub realm_ref: String,
    pub record: PlacementBinding,
    pub admission_ref: Option<String>,
    pub admitted: bool,
}

fn placement_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<PlacementRow> {
    let digest = |t: String| -> DigestRef {
        serde_json::from_str(&t).unwrap_or_else(|_| DigestRef::portable_public("0".repeat(64)))
    };
    let admission_ref: Option<String> = r.get(13)?;
    Ok(PlacementRow {
        realm_ref: r.get(1)?,
        record: PlacementBinding {
            placement_id: r.get(0)?,
            owner_protocol: r.get(2)?,
            revision: r.get::<_, i64>(3)? as u64,
            resource_allocation_ref: r.get(4)?,
            resource_allocation_digest: digest(r.get(5)?),
            selected_manifestation_ref: r.get(6)?,
            selected_manifestation_digest: digest(r.get(7)?),
            host_runtime_binding: r.get(8)?,
            kovee_invocation_ref: r.get(9)?,
            placement_constraint_digest: digest(r.get(10)?),
            kovee_fence_epoch: r.get::<_, i64>(11)? as u64,
            state: r.get(12)?,
            created_at: r.get(14)?,
            digest: digest(r.get(15)?),
        },
        admitted: admission_ref.is_some(),
        admission_ref,
    })
}

const PLACEMENT_COLUMNS: &str = "placement_id, realm_ref, owner_protocol, revision,
     resource_allocation_ref, resource_allocation_digest, selected_manifestation_ref,
     selected_manifestation_digest, host_runtime_binding, kovee_invocation_ref,
     placement_constraint_digest, kovee_fence_epoch, state, admission_ref, created_at, digest";

pub fn read_placement(
    conn: &Connection,
    placement_id: &str,
) -> Result<Option<PlacementRow>, Problem> {
    conn.query_row(
        &format!("SELECT {PLACEMENT_COLUMNS} FROM byom_placement_bindings WHERE placement_id = ?1"),
        [placement_id],
        placement_from_row,
    )
    .optional()
    .map_err(|e| store_problem(e.into()))
}

fn read_placement_by_allocation(
    conn: &Connection,
    realm: &str,
    allocation_ref: &str,
) -> Result<Option<Placed>, Problem> {
    let row = conn
        .query_row(
            &format!(
                "SELECT {PLACEMENT_COLUMNS} FROM byom_placement_bindings
                 WHERE realm_ref = ?1 AND resource_allocation_ref = ?2"
            ),
            params![realm, allocation_ref],
            placement_from_row,
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    Ok(row.map(|row| Placed {
        placement_id: row.record.placement_id.clone(),
        kovee_fence_epoch: row.record.kovee_fence_epoch,
        record: row.record,
    }))
}

pub fn read_binding(conn: &Connection, key: &str) -> Result<Option<Bound>, Problem> {
    let text: Option<String> = conn
        .query_row(
            "SELECT record FROM byom_episode_bindings WHERE stable_binding_key = ?1",
            [key],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    let Some(text) = text else { return Ok(None) };
    let record: ByomEpisodeBinding = serde_json::from_str(&text).map_err(|_| internal())?;
    Ok(Some(Bound {
        stable_binding_key: record.stable_binding_key.clone(),
        episode_ref: record.episode_ref.clone(),
        byom_attempt_ref: record.byom_attempt_ref.clone(),
        fences: record.fences(),
        record,
    }))
}

fn binding_state(conn: &Connection, key: &str) -> Result<BindingState, Problem> {
    let text: String = conn
        .query_row(
            "SELECT state FROM byom_episode_bindings WHERE stable_binding_key = ?1",
            [key],
            |r| r.get(0),
        )
        .map_err(|e| store_problem(e.into()))?;
    BindingState::parse(&text).ok_or_else(internal)
}

fn binding_realm(conn: &Connection, key: &str) -> Result<String, Problem> {
    conn.query_row(
        "SELECT realm_ref FROM byom_episode_bindings WHERE stable_binding_key = ?1",
        [key],
        |r| r.get(0),
    )
    .map_err(|e| store_problem(e.into()))
}

fn set_episode_state(conn: &Connection, key: &str, state: &str, now: i64) -> Result<(), Problem> {
    conn.execute(
        "UPDATE byom_episode_bindings SET episode_state = ?2, updated_at = ?3
         WHERE stable_binding_key = ?1",
        params![key, state, rfc3339_utc(now)],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

fn emit(
    store: &mut Store,
    realm: &str,
    record: &ByomEpisodeBinding,
    event_type: &str,
    payload: Value,
    now: i64,
) -> Result<(), Problem> {
    let scope = kovee_store::CommandScope {
        actor_scope: format!("owner/{OWNER_ACTOR_REF}/{realm}"),
        operation: format!("episode_binding_event:{event_type}"),
        idempotency_key: format!("{}:{event_type}", record.stable_binding_key),
        request_digest: "0".repeat(64),
    };
    let record = record.clone();
    let event_type = event_type.to_owned();
    let outcome =
        store.command_transaction(&scope, now, kovee_store::CrashHooks::NONE, move |txn| {
            txn.audit(
                "episode-binding.transition",
                &format!("binding={} event={event_type}", record.stable_binding_key),
            );
            txn.append_event(NewEvent {
                stream_id: record.stable_binding_key.clone(),
                project_id: None,
                actor_ref: Some(OWNER_ACTOR_REF.to_owned()),
                event_type: event_type.clone(),
                schema_ref: "schema:kovee-byom-episode-binding-v1".to_owned(),
                resource_ref: record.stable_binding_key.clone(),
                resource_revision: Some(1),
                causation_ref: None,
                correlation_ref: record.episode_ref.clone(),
                classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
                payload: payload.clone(),
            })
            .map_err(store_problem)?;
            Ok(kovee_store::Applied {
                result: json!({"stable_binding_key": record.stable_binding_key}),
                revision: None,
                event_cursor: None,
            })
        });
    crate::handlers::command_outcome_bytes(outcome)?;
    Ok(())
}

fn runtime_call(endpoint: &Endpoint, op: &str, args: Value) -> Result<Value, Problem> {
    let mut request = json!({"version": BPP_VERSION, "op": op});
    if let (Some(target), Some(extra)) = (request.as_object_mut(), args.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    endpoint
        .call(Surface::Runtime, &request)
        .map(|reply| reply.result)
        .map_err(|e| bpp::passthrough(&e))
}

fn string_of(value: &Value, key: &str) -> Result<String, Problem> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            Problem::new(
                ProblemKind::Unavailable,
                "the byom endpoint answered with an unusable reply",
            )
            .with_detail(format!("the runtime reply carries no {key}"))
        })
}

// ------------------------------------------- byom_episode_binding_show ----

/// The read surface: the recorded bindings, their dual fences, and their
/// state — including `fenced` rows, which stay in the audit closure.
pub fn byom_episode_binding_show(
    store: &Store,
    realm: &str,
    args: &kovee_core::ops::EpisodeBindingShowArgs,
) -> Result<Vec<u8>, Problem> {
    let conn = store.conn();
    let mut sql = "SELECT stable_binding_key, episode_ref, byom_attempt_ref,
                          kovee_invocation_ref, byom_fence_epoch, kovee_invocation_fence,
                          state, episode_state, fenced_reason, record, created_at, updated_at
                   FROM byom_episode_bindings WHERE realm_ref = ?1"
        .to_owned();
    let mut binds: Vec<String> = vec![realm.to_owned()];
    if let Some(key) = &args.stable_binding_key {
        sql.push_str(" AND stable_binding_key = ?2");
        binds.push(key.clone());
    } else if let Some(episode) = &args.episode_ref {
        sql.push_str(" AND episode_ref = ?2");
        binds.push(episode.clone());
    }
    sql.push_str(" ORDER BY created_at ASC, stable_binding_key ASC");
    let mut stmt = conn.prepare(&sql).map_err(|e| store_problem(e.into()))?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok(json!({
                "stable_binding_key": r.get::<_, String>(0)?,
                "episode_ref": r.get::<_, String>(1)?,
                "byom_attempt_ref": r.get::<_, String>(2)?,
                "kovee_invocation_ref": r.get::<_, String>(3)?,
                "byom_fence_epoch": r.get::<_, i64>(4)?,
                "kovee_invocation_fence": r.get::<_, i64>(5)?,
                "state": r.get::<_, String>(6)?,
                "episode_state": r.get::<_, String>(7)?,
                "fenced_reason": r.get::<_, Option<String>>(8)?,
                "record": serde_json::from_str::<Value>(&r.get::<_, String>(9)?)
                    .unwrap_or(Value::Null),
                "created_at": r.get::<_, String>(10)?,
                "updated_at": r.get::<_, String>(11)?,
            }))
        })
        .map_err(|e| store_problem(e.into()))?;
    let mut bindings = Vec::new();
    for row in rows {
        bindings.push(row.map_err(|e| store_problem(e.into()))?);
    }
    if args.stable_binding_key.is_some() && bindings.is_empty() {
        return Err(not_found());
    }
    crate::handlers::ok_reply(json!({"realm_id": realm, "bindings": bindings}), None)
}
