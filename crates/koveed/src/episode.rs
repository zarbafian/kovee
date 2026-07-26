//! The hosted-episode pipeline, as Kovee sees it — driven against byom's
//! REAL runtime surface: an Episode is requested on byom's participant
//! channel, Kovee places, byom's narrow adapter admits the placement, the
//! lease is claimed and started, and from then on EVERY mutation presents
//! BOTH fences to byomd as well as to Kovee's own binding row.
//!
//! What you write (the whole activation, in order — and the order is the
//! point):
//!
//! ```no_run
//! # use koveed::episode::*;
//! # fn f(store: &mut kovee_store::Store, runtime: &Runtime, notice: &Notice)
//! #   -> Result<(), kovee_core::problem::Problem> {
//! // 1. Stages 1-3 are byom's: the participant channel authors the
//! //    WakeIntent, and byom's kernel admits it and allocates inside
//! //    `episode_request`. Kovee invents none of the three.
//! let channel = runtime.participant_channel(&notice.participant_ref)?;
//! let episode = request(store, runtime, &channel, notice, 0)?;
//! // 2. Kovee authors the PlacementBinding — the one activation record it
//! //    owns — over the allocation digest BYOM committed.
//! let placed = place(store, "realm-personal", notice, "kovee-inv-1", 0)?;
//! // 3. byom's runtime adapter admits it, carrying Kovee's subordinate
//! //    reservation outcome. No episode work before this answers.
//! admit(store, runtime, &placed.placement_id, notice, 0)?;
//! // 4. claim + start — and every later mutation carries both fences to
//! //    both daemons.
//! let bound = start(store, runtime, &placed.placement_id, notice,
//!                   &episode.episode_ref, 300, 0)?;
//! checkpoint(store, runtime, &bound.stable_binding_key, bound.fences,
//!            "ckpt-1", 0)?;
//! settle(store, runtime, &bound.stable_binding_key, bound.fences, 40, 0)?;
//! complete(store, runtime, &bound.stable_binding_key, bound.fences, 0)?;
//! # Ok(()) }
//! ```
//!
//! Plumbing worth knowing:
//!
//! - **Stage order is checked twice, on both sides.** [`admit`] refuses a
//!   placement byom has not verified and [`start`] refuses a placement
//!   that carries no admission — and byomd independently refuses a claim
//!   on an Episode that is not `queued`, which only an admitted placement
//!   with both exact reservation sets makes it.
//! - **Dual fences on every mutation.** [`checkpoint`], [`yield_episode`],
//!   and [`complete`] refuse locally on either fence being stale, marking
//!   the binding `fenced` and retaining the row for audit — and the same
//!   pair goes to byomd, which compares it against its own committed
//!   `ByomEpisodeBinding` (family contract L21).
//! - **The lease revision is byomd's.** Every protected command is a CAS
//!   on byom's one `EpisodeLeaseHead`, so the row carries the revision
//!   byomd last returned. Kovee never increments it.
//! - **The workload token is byomd's.** Runtime calls ride the
//!   subject-scoped token byomd published for this exact Episode or
//!   allocation ([`kovee_byom::runtime`]); there is no Kovee-side minting
//!   path.

use std::path::{Path, PathBuf};

use kovee_byom::bpp::{self, Endpoint, Surface, BPP_VERSION};
use kovee_byom::budget::Item;
use kovee_byom::channel::Channel;
use kovee_byom::episode::{
    local_commitments_are_closed, BindingState, ByomEpisodeBinding, FenceError, Fences,
    PlacementBinding, PLACEMENT_OWNER,
};
use kovee_byom::records::GovernanceDigests;
use kovee_byom::runtime::{self, Workload, WorkloadToken};
use kovee_core::event::{
    EVENT_EPISODE_BINDING_BOUND, EVENT_EPISODE_BINDING_FENCED, EVENT_EPISODE_BINDING_RELEASED,
};
use kovee_core::family::{hex, hmac_sha256, tagged_canonical, DigestRef};
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
const TAG_CLAIM_SUBJECT: &str = "kovee-episode-claim-subject-v1";
const TAG_CONTEXT_MANIFEST: &str = "kovee-episode-context-manifest-v1";
const TAG_CHECKPOINT: &str = "kovee-episode-checkpoint-v1";

/// The local-commitment classes this profile grants a hosted child
/// (family contract L34–L37). Anything else goes through
/// `call_open`/`pledge_propose`/`act_intent_*`.
pub const ALLOWED_LOCAL_COMMITMENTS: [&str; 2] = ["contribution_append", "attention_mark"];

/// byom's `usage_report` sources (§11.4 / family contract L33): a worker
/// report is EVIDENCE, only the trusted meter settles.
pub const SOURCE_WORKER: &str = "worker_report";
pub const SOURCE_METER: &str = "trusted_meter";

// ---------------------------------------------------------------- inputs ----

/// One byom endpoint plus the channel directory its workload tokens are
/// published in: everything a runtime call needs beyond the request.
#[derive(Debug, Clone)]
pub struct Runtime {
    endpoint: Endpoint,
    channels: PathBuf,
}

impl Runtime {
    pub fn new(endpoint: &Endpoint, channels: &Path) -> Runtime {
        Runtime {
            endpoint: endpoint.clone(),
            channels: channels.to_path_buf(),
        }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The same endpoint with the channel directory taken from
    /// `$KOVEE_BYOM_CHANNELS_DIR` — how the daemon is configured.
    pub fn configured(endpoint: &Endpoint) -> Result<Runtime, Problem> {
        let channels = runtime::channels_dir().map_err(|e| {
            Problem::new(
                ProblemKind::Unavailable,
                "no byom channel directory is configured",
            )
            .with_detail(e.to_string())
        })?;
        Ok(Runtime {
            endpoint: endpoint.clone(),
            channels,
        })
    }

    /// Claims the participant channel byomd published for one admitted
    /// Participant. ONE claim per process (the key is peer-bound and
    /// useless anywhere else), so the caller keeps the [`Channel`] and
    /// mints one fresh proof per call.
    pub fn participant_channel(&self, participant_ref: &str) -> Result<Channel, Problem> {
        Channel::participant(self.endpoint.runtime_dir(), &self.channels, participant_ref).map_err(
            |e| {
                Problem::new(
                    ProblemKind::Unavailable,
                    "the byom participant channel could not be claimed",
                )
                .with_detail(e.to_string())
            },
        )
    }

    fn token(&self, channel: Workload, subject: &str) -> Result<WorkloadToken, Problem> {
        runtime::token(&self.channels, channel, subject).map_err(|e| {
            // A missing token is a STATE answer: byomd removes it when the
            // subject leaves its live states.
            Problem::new(
                ProblemKind::Unavailable,
                "byom published no workload token for this subject",
            )
            .with_detail(e.to_string())
        })
    }

    fn call(&self, token: &WorkloadToken, request: &Value) -> Result<Value, Problem> {
        runtime::call(&self.endpoint, token, request)
            .map(|reply| reply.result)
            .map_err(|e| bpp::passthrough(&e))
    }
}

/// What byom told Kovee (or what Kovee read off byom's projection): an
/// Episode is eligible and its resources are allocated. Kovee authors
/// NEITHER the WakeIntent nor the ActivationAdmission nor the
/// ResourceAllocation — it only places, and every byom-owned reference and
/// digest here is ECHOED, never invented.
#[derive(Debug, Clone)]
pub struct Notice {
    pub society_ref: String,
    pub recovery_epoch: u64,
    pub participant_ref: String,
    pub participant_binding_epoch: u64,
    pub manifestation_ref: String,
    pub activity_stream_ref: String,
    pub generation: u64,
    /// Stage 1, byom's: the WakeIntent the participant channel authored.
    pub wake_intent_ref: String,
    /// Stage 2, byom's kernel: the derived ActivationAdmission id.
    pub activation_admission_ref: String,
    /// Stage 3, byom's kernel: the ResourceAllocation and the exact
    /// `local_erasure_safe` digest byom committed for it. `placement_admit`
    /// compares this digest against its own row, so Kovee can only echo
    /// what byom reported.
    pub resource_allocation_ref: String,
    pub resource_allocation_digest: DigestRef,
    pub mandate_use_refs: Vec<String>,
    /// byom's §11.4 parent reservation set and the bridge it persisted
    /// under its kernel-derived stable key BEFORE queueing.
    pub byom_budget_reservation_ref: String,
    pub byom_reservation_set_revision: u64,
    pub external_budget_bridge_ref: String,
    pub stable_external_reservation_key: String,
    /// The parent §11.4 items a subordinate reservation may narrow but
    /// never reshape or exceed.
    pub parent_reservation_items: Vec<ParentItem>,
    pub context_manifest_ref: String,
}

/// One byom-owned §11.4 reservation item, as byom committed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentItem {
    pub account_ref: String,
    pub account_revision: u64,
    pub dimension: String,
    pub unit: String,
    pub worst_case_amount: u64,
}

/// One authored placement.
#[derive(Debug, Clone)]
pub struct Placed {
    pub placement_id: String,
    pub kovee_fence_epoch: u64,
    pub record: PlacementBinding,
}

/// One requested Episode, as byom answered.
#[derive(Debug, Clone)]
pub struct Requested {
    pub episode_ref: String,
    pub generation: u64,
    pub state: String,
}

/// One admitted placement, as byom's adapter answered.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub admission_ref: String,
    pub bridge_state: String,
    pub episode_queued: bool,
    pub subordinate_reservation_ref: String,
}

/// One bound Episode attempt.
#[derive(Debug, Clone)]
pub struct Bound {
    pub stable_binding_key: String,
    pub episode_ref: String,
    pub byom_attempt_ref: String,
    pub fences: Fences,
    pub lease_revision: u64,
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

// ------------------------------------------------------- typed digests ----

/// The CROSS-BOUNDARY `portable_public` derivation byom's runtime schemas
/// require for the fields both sides can recompute (`kovee_placement_digest`,
/// `context_source_digest`, the subordinate reservation digest).
fn portable(tag: &str, projection: &Value) -> Result<DigestRef, Problem> {
    let preimage = tagged_canonical(tag, projection).map_err(|_| internal())?;
    Ok(DigestRef::portable_public(kovee_core::family::sha256_hex(
        &preimage,
    )))
}

/// The `local_erasure_safe` derivation byom's runtime schemas require for
/// the fields Kovee AUTHORS and byom only stores (`claim_subject_digest`,
/// `context_manifest_digest`, `checkpoint_digest`). Keyed under this
/// placement's own RANDOM per-object secret, wrapped under the realm key
/// (disposition D-R1-2): destroying that one blob erases exactly these
/// digests' verifiability and nothing else.
fn erasure_safe(
    placement_id: &str,
    secret: &[u8; 32],
    tag: &str,
    projection: &Value,
) -> Result<DigestRef, Problem> {
    let preimage = tagged_canonical(tag, projection).map_err(|_| internal())?;
    Ok(DigestRef::local_erasure_safe(
        &object_key_ref(placement_id),
        hex(&hmac_sha256(secret, &preimage)),
    ))
}

fn object_key_ref(placement_id: &str) -> String {
    format!("kovee-placement-object:{placement_id}")
}

/// This placement's per-object erasure secret, unwrapped. Absent means
/// erased: the digests it keyed can no longer be re-derived by anyone,
/// including a holder of the realm key.
fn object_secret(conn: &Connection, placement_id: &str) -> Result<[u8; 32], Problem> {
    let wrapped: Option<Vec<u8>> = conn
        .query_row(
            "SELECT object_secret FROM byom_placement_bindings WHERE placement_id = ?1",
            [placement_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?
        .flatten();
    let wrapped = wrapped.ok_or_else(|| {
        forbidden(
            "this placement's erasure secret is destroyed",
            "the local_erasure_safe episode digests can no longer be re-derived (D-R1-2)",
        )
    })?;
    let realm_key = kovee_store::realm_object_key_of(conn).map_err(store_problem)?;
    kovee_store::objkey::unwrap(&realm_key, &object_key_ref(placement_id), &wrapped)
        .map_err(store_problem)
}

// -------------------------------------------- stages 1-3: byom's, echoed ----

/// `episode_request` on byom's PARTICIPANT channel (R29): the entry point
/// of the four-stage activation. byom's kernel runs stages 2
/// (`activation_admit`) and 3 (`resource_allocate`) inside it and answers
/// with an Episode that is `eligible` but NOT queued — queueing needs both
/// exact reservation sets, which only Kovee's subordinate confirmation
/// completes at [`admit`].
///
/// Kovee names the stage ids byom DERIVED and can therefore only match
/// them: a request that invents an admission ref is refused there.
pub fn request(
    store: &mut Store,
    runtime: &Runtime,
    channel: &Channel,
    notice: &Notice,
    now: i64,
) -> Result<Requested, Problem> {
    let seam = seam_of(store.conn(), &notice.society_ref, notice.recovery_epoch)?;
    let request = json!({
        "version": BPP_VERSION,
        "op": "episode_request",
        "meta": create_meta(&seam, "ereq", &notice.wake_intent_ref),
        "activity_stream_ref": notice.activity_stream_ref,
        "generation": notice.generation,
        "wake_intent_ref": notice.wake_intent_ref,
        "activation_admission_ref": notice.activation_admission_ref,
    });
    let proof = channel
        .proof("episode_request", now_or_wall(now))
        .map_err(|e| {
            Problem::new(
                ProblemKind::Unavailable,
                "the byom participant channel could not mint a proof",
            )
            .with_detail(e.to_string())
        })?;
    let reply = runtime
        .endpoint
        .call_with_preamble(Surface::Participant, Some(&proof), &request)
        .map_err(|e| bpp::passthrough(&e))?;
    Ok(Requested {
        episode_ref: string_of(&reply.result, "episode_id")?,
        generation: reply
            .result
            .get("generation")
            .and_then(Value::as_u64)
            .unwrap_or(notice.generation),
        state: string_of(&reply.result, "state")?,
    })
}

// ------------------------------------------------------- stage 4: place ----

/// Kovee authors the `PlacementBinding` among already-eligible
/// Manifestations (byom §11.1 stage 4). It is the ONE activation record
/// Kovee owns — and it pins the allocation digest BYOM committed, which
/// `placement_admit` compares against its own row.
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
    // The selected Manifestation digest crosses the boundary, so it is the
    // recomputable `portable_public` class.
    let manifestation_digest = portable(
        TAG_PLACEMENT,
        &json!({"selected_manifestation_ref": notice.manifestation_ref}),
    )?;
    let mut record = PlacementBinding {
        owner_protocol: PLACEMENT_OWNER.to_owned(),
        placement_id: placement_id.clone(),
        revision: 1,
        resource_allocation_ref: notice.resource_allocation_ref.clone(),
        // ECHOED from byom, never derived here.
        resource_allocation_digest: notice.resource_allocation_digest.clone(),
        selected_manifestation_ref: notice.manifestation_ref.clone(),
        selected_manifestation_digest: manifestation_digest,
        host_runtime_binding: format!("kovee-runtime-{realm}"),
        kovee_invocation_ref: kovee_invocation_ref.to_owned(),
        placement_constraint_digest: constraint,
        // The Kovee half of the dual fences starts at 1 and only ever
        // advances; a successor attempt gets a new one.
        kovee_fence_epoch: 1,
        state: "placed".to_owned(),
        created_at: rfc3339_utc(now),
        digest: DigestRef::portable_public("0".repeat(64)),
    };
    let mut projection = serde_json::to_value(&record).unwrap_or(Value::Null);
    if let Some(map) = projection.as_object_mut() {
        map.remove("digest");
    }
    // `kovee_placement_digest` is the cross-boundary class byom pins: both
    // sides recompute it from these exact bytes.
    record.digest = portable(TAG_PLACEMENT, &projection)?;

    // One RANDOM per-object erasure secret for this placement's episode
    // digests, wrapped under the realm key (D-R1-2).
    let secret = kovee_store::objkey::new_object_secret().map_err(store_problem)?;
    let realm_key = kovee_store::realm_object_key_of(store.conn()).map_err(store_problem)?;
    let wrapped = kovee_store::objkey::wrap(&realm_key, &object_key_ref(&placement_id), &secret)
        .map_err(store_problem)?;

    store
        .conn()
        .execute(
            "INSERT INTO byom_placement_bindings (placement_id, realm_ref, owner_protocol,
                 revision, resource_allocation_ref, resource_allocation_digest,
                 selected_manifestation_ref, selected_manifestation_digest,
                 host_runtime_binding, kovee_invocation_ref, placement_constraint_digest,
                 kovee_fence_epoch, state, created_at, digest, object_secret)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
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
                wrapped.as_slice(),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;

    Ok(Placed {
        placement_id,
        kovee_fence_epoch: record.kovee_fence_epoch,
        record,
    })
}

/// The Kovee-side fence advance a successor attempt needs (family contract
/// L21): a NEW `kovee_invocation_ref` and a NEW `kovee_invocation_fence`,
/// so the successor's `stable_binding_key` is new and every binding of the
/// previous attempt is fenced for every further mutation.
pub fn advance_invocation(store: &mut Store, placement_id: &str) -> Result<Placed, Problem> {
    let placed = read_placement(store.conn(), placement_id)?.ok_or_else(not_found)?;
    let fence = placed.record.kovee_fence_epoch + 1;
    let invocation = new_id("kinv").map_err(store_problem)?;
    store
        .conn()
        .execute(
            "UPDATE byom_placement_bindings
             SET kovee_fence_epoch = ?2, kovee_invocation_ref = ?3, revision = revision + 1,
                 state = 'placed'
             WHERE placement_id = ?1",
            params![placement_id, fence as i64, invocation],
        )
        .map_err(|e| store_problem(e.into()))?;
    let refreshed = read_placement(store.conn(), placement_id)?.ok_or_else(internal)?;
    Ok(Placed {
        placement_id: placement_id.to_owned(),
        kovee_fence_epoch: refreshed.record.kovee_fence_epoch,
        record: refreshed.record,
    })
}

// ----------------------------------------------------- stage 4: admitted ----

/// `placement_admit` (R33) on byom's runtime surface, under the placement
/// workload token byomd minted for this exact allocation.
///
/// byom records only the `PlacementAdmission`, after verifying the source
/// binding — and the same call carries the `byom_subordinate` saga
/// outcome, because §14.6 defines no byom-side catalog operation for the
/// Kovee-owned saga verbs (byom's recorded deviation, its G46 note). So
/// Kovee commits its subordinate reservation FIRST — narrowed, never above
/// parent — and the confirmation rides this request. Until byom answers,
/// nothing downstream may run.
pub fn admit(
    store: &mut Store,
    runtime: &Runtime,
    placement_id: &str,
    notice: &Notice,
    now: i64,
) -> Result<Admitted, Problem> {
    let placed = read_placement(store.conn(), placement_id)?.ok_or_else(not_found)?;
    let realm = placed.realm_ref.clone();
    let seam = seam_of(store.conn(), &notice.society_ref, notice.recovery_epoch)?;

    // Kovee's own subordinate reservation, committed durably before the
    // confirmation is reported: a crash leaves a reservation Kovee can
    // query, never an unrecorded charge.
    let reservation = crate::budget::reserve(
        store,
        &realm,
        &crate::budget::Parent {
            byom_reservation_set_ref: notice.byom_budget_reservation_ref.clone(),
            byom_reservation_set_revision: notice.byom_reservation_set_revision,
            external_budget_bridge_ref: notice.external_budget_bridge_ref.clone(),
            stable_external_reservation_key: notice.stable_external_reservation_key.clone(),
            society_ref: notice.society_ref.clone(),
            society_recovery_epoch: notice.recovery_epoch,
        },
        subordinate_items(&realm, notice),
        now,
    )?;
    // byom pins the cross-boundary class for the reservation digest it
    // stores, so it is recomputed here in that class.
    let reservation_digest = portable(
        "kovee-byom-subordinate-reservation-wire-v1",
        &json!({
            "subordinate_reservation_ref": reservation.subordinate_reservation_ref,
            "revision": reservation.revision,
            "stable_external_reservation_key": reservation.stable_external_reservation_key,
            "items": serde_json::to_value(&reservation.items).unwrap_or(Value::Null),
        }),
    )?;

    if placed.admitted {
        return Ok(Admitted {
            admission_ref: placed.admission_ref.clone().unwrap_or_default(),
            bridge_state: "confirmed".to_owned(),
            episode_queued: true,
            subordinate_reservation_ref: reservation.subordinate_reservation_ref,
        });
    }

    let token = runtime.token(Workload::Placement, &notice.resource_allocation_ref)?;
    let request = json!({
        "version": BPP_VERSION,
        "op": "placement_admit",
        "meta": create_meta(&seam, "plc", placement_id),
        "resource_allocation_ref": placed.record.resource_allocation_ref,
        "resource_allocation_digest": placed.record.resource_allocation_digest,
        "kovee_placement_ref": placed.record.placement_id,
        "kovee_placement_revision": placed.record.revision,
        "kovee_placement_digest": placed.record.digest,
        "source_binding_epoch": seam.binding_epoch,
        "selected_manifestation_ref": placed.record.selected_manifestation_ref,
        "kovee_invocation_ref": placed.record.kovee_invocation_ref,
        "kovee_fence_epoch": placed.record.kovee_fence_epoch,
        "subordinate_reservation": {
            "stable_external_reservation_key": notice.stable_external_reservation_key,
            "outcome": "confirmed",
            "subordinate_reservation_ref": reservation.subordinate_reservation_ref,
            "revision": reservation.revision,
            "digest": reservation_digest,
            "items": serde_json::to_value(&reservation.items).unwrap_or(Value::Null),
        },
    });
    let result = runtime.call(&token, &request)?;

    let admission_ref = result
        .get("admission_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            Problem::new(
                ProblemKind::Unavailable,
                "the byom endpoint answered with an unusable placement admission",
            )
            .with_detail("placement_admit returned no admission_id")
        })?
        .to_owned();
    // The admission must pin THIS placement revision: byom's verification
    // status is about these exact bytes or it is about nothing.
    if result
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
                result
                    .get("digest")
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "null".to_owned()),
                rfc3339_utc(now),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok(Admitted {
        admission_ref,
        bridge_state: result
            .get("bridge_state")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        episode_queued: result
            .get("episode_queued")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        subordinate_reservation_ref: reservation.subordinate_reservation_ref,
    })
}

/// Kovee's subordinate items: one per byom parent item, NARROWED to what
/// Kovee's own capacity account grants and never reshaped.
fn subordinate_items(realm: &str, notice: &Notice) -> Vec<Item> {
    notice
        .parent_reservation_items
        .iter()
        .map(|parent| Item {
            kovee_account_ref: format!("kovee-capacity-{realm}"),
            dimension: parent.dimension.clone(),
            unit: parent.unit.clone(),
            // The narrowing this profile applies: half the parent worst
            // case, so "narrow but never exceed" is observable.
            amount: parent.worst_case_amount / 2,
            parent_account_ref: parent.account_ref.clone(),
            parent_account_revision: parent.account_revision,
            parent_dimension: parent.dimension.clone(),
            parent_unit: parent.unit.clone(),
            parent_worst_case_amount: parent.worst_case_amount,
            parent_delegation_ref: None,
        })
        .collect()
}

// ------------------------------------- the lease: request / claim / start ----

/// `episode_claim` → `episode_start` on byom's runtime surface, under the
/// worker workload token, then the binding row committed at the exact
/// claim/start CAS Kovee observed (§16.6 item 3). Refuses outright when
/// the placement carries no byom admission — and byomd independently
/// refuses a claim on an Episode that is not `queued`.
#[allow(clippy::too_many_arguments)]
pub fn claim(
    store: &mut Store,
    runtime: &Runtime,
    placement_id: &str,
    notice: &Notice,
    episode_ref: &str,
    lease_ttl_seconds: u64,
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
    let seam = seam_of(store.conn(), &notice.society_ref, notice.recovery_epoch)?;
    let secret = object_secret(store.conn(), placement_id)?;
    let token = runtime.token(Workload::Worker, episode_ref)?;

    // The stable key is derivable BEFORE the claim (byom keys the claim's
    // idempotency on it): the exact retry of this invocation returns the
    // identical binding, and a successor invocation is a new key.
    let stable_binding_key = stable_key(
        store.conn(),
        &realm,
        episode_ref,
        notice.generation,
        &placed.record,
    )?;
    let context_source = portable(
        TAG_CONTEXT_SOURCE,
        &json!({
            "context_manifest_ref": notice.context_manifest_ref,
            "activity_stream_ref": notice.activity_stream_ref,
            "generation": notice.generation,
        }),
    )?;
    let context_manifest_digest = erasure_safe(
        placement_id,
        &secret,
        TAG_CONTEXT_MANIFEST,
        &json!({"context_manifest_ref": notice.context_manifest_ref}),
    )?;
    let claim_subject = erasure_safe(
        placement_id,
        &secret,
        TAG_CLAIM_SUBJECT,
        &json!({
            "episode_ref": episode_ref,
            "generation": notice.generation,
            "kovee_placement_ref": placement_id,
            "kovee_invocation_ref": placed.record.kovee_invocation_ref,
            "kovee_invocation_fence": placed.record.kovee_fence_epoch,
        }),
    )?;
    let allowed_local_commitments: Vec<String> = ALLOWED_LOCAL_COMMITMENTS
        .iter()
        .map(|c| (*c).to_owned())
        .collect();
    if !local_commitments_are_closed(&allowed_local_commitments) {
        return Err(internal());
    }

    let claimed = runtime.call(
        &token,
        &json!({
            "version": BPP_VERSION,
            "op": "episode_claim",
            "meta": create_meta(&seam, "clm", &stable_binding_key),
            "episode_ref": episode_ref,
            "generation": notice.generation,
            "holder_runtime_binding": placed.record.host_runtime_binding,
            "claim_subject_digest": claim_subject,
            "lease_ttl_seconds": lease_ttl_seconds,
            "kovee_invocation_ref": placed.record.kovee_invocation_ref,
            "kovee_invocation_fence": placed.record.kovee_fence_epoch,
            "stable_binding_key": stable_binding_key,
            "context_manifest_ref": notice.context_manifest_ref,
            "context_manifest_digest": context_manifest_digest,
            "context_source_digest": context_source,
            "mandate_use_refs": notice.mandate_use_refs,
            "allowed_local_commitments": allowed_local_commitments,
        }),
    )?;
    let byom_attempt_ref = string_of(&claimed, "byom_attempt_ref")?;
    let fences = Fences {
        byom: number_of(&claimed, "byom_fence_epoch")?,
        kovee: number_of(&claimed, "kovee_invocation_fence")?,
    };
    if fences.kovee != placed.record.kovee_fence_epoch {
        return Err(forbidden(
            "the byom claim pins another Kovee invocation fence",
            "the binding is committed at the exact CAS Kovee observed (family contract L21)",
        ));
    }
    let lease_revision = number_of(&claimed, "lease_revision")?;

    bind(
        store,
        &realm,
        &placed,
        notice,
        episode_ref,
        &byom_attempt_ref,
        fences,
        lease_revision,
        &stable_binding_key,
        now,
    )
}

/// `episode_start` (runtime, update): the claimed lease begins running.
/// Already a DUAL-fence mutation, and an update — it names the exact lease
/// revision the claim returned.
pub fn begin(
    store: &mut Store,
    runtime: &Runtime,
    stable_binding_key: &str,
    presented: Fences,
    now: i64,
) -> Result<u64, Problem> {
    let bound = fenced_mutation(store, stable_binding_key, presented, "episode_start", now)?;
    let seam = seam_of(
        store.conn(),
        &bound.record.society_ref,
        bound.record.recovery_epoch,
    )?;
    let token = runtime.token(Workload::Worker, &bound.episode_ref)?;
    let started = runtime.call(
        &token,
        &json!({
            "version": BPP_VERSION,
            "op": "episode_start",
            "meta": update_meta(&seam, "srt", stable_binding_key, bound.lease_revision),
            "episode_ref": bound.episode_ref,
            "generation": bound.record.generation,
            "byom_attempt_ref": bound.byom_attempt_ref,
            "byom_fence_epoch": presented.byom,
            "kovee_invocation_fence": presented.kovee,
        }),
    )?;
    let lease_revision = number_of(&started, "lease_revision")?;
    set_lease(store.conn(), stable_binding_key, lease_revision, now)?;
    set_episode_state(store.conn(), stable_binding_key, "running", now)?;
    Ok(lease_revision)
}

/// The claim/start pair the pipeline runs together: `episode_claim` then
/// `episode_start`, with the binding committed at the claim CAS in
/// between.
#[allow(clippy::too_many_arguments)]
pub fn start(
    store: &mut Store,
    runtime: &Runtime,
    placement_id: &str,
    notice: &Notice,
    episode_ref: &str,
    lease_ttl_seconds: u64,
    now: i64,
) -> Result<Bound, Problem> {
    let mut bound = claim(
        store,
        runtime,
        placement_id,
        notice,
        episode_ref,
        lease_ttl_seconds,
        now,
    )?;
    bound.lease_revision = begin(store, runtime, &bound.stable_binding_key, bound.fences, now)?;
    Ok(bound)
}

/// The stable binding key (family contract L22). Derived from what is
/// known BEFORE the claim — byom keys the claim's own idempotency on it,
/// so it cannot name the attempt the claim is about to mint.
fn stable_key(
    conn: &Connection,
    realm: &str,
    episode_ref: &str,
    generation: u64,
    placed: &PlacementBinding,
) -> Result<String, Problem> {
    let digests = digests_of(conn, realm)?;
    Ok(format!(
        "ebk-{}",
        &digests
            .digest(
                TAG_BINDING,
                &json!({
                    "episode_ref": episode_ref,
                    "generation": generation,
                    "kovee_invocation_ref": placed.kovee_invocation_ref,
                    "kovee_invocation_fence": placed.kovee_fence_epoch,
                }),
            )
            .map_err(|_| internal())?
            .value_hex[..32]
    ))
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
    lease_revision: u64,
    stable_binding_key: &str,
    now: i64,
) -> Result<Bound, Problem> {
    let digests = digests_of(store.conn(), realm)?;
    if let Some(existing) = read_binding(store.conn(), stable_binding_key)? {
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
    let secret = object_secret(store.conn(), &placed.record.placement_id)?;
    let context_source = portable(
        TAG_CONTEXT_SOURCE,
        &json!({
            "context_manifest_ref": notice.context_manifest_ref,
            "activity_stream_ref": notice.activity_stream_ref,
            "generation": notice.generation,
        }),
    )?;
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
        stable_binding_key: stable_binding_key.to_owned(),
        allowed_local_commitments,
        context_manifest_ref: notice.context_manifest_ref.clone(),
        context_manifest_digest: erasure_safe(
            &placed.record.placement_id,
            &secret,
            TAG_CONTEXT_MANIFEST,
            &json!({"context_manifest_ref": notice.context_manifest_ref}),
        )?,
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
                 byom_fence_epoch, kovee_invocation_fence, lease_revision, state, episode_state,
                 record, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14)",
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
                lease_revision as i64,
                BindingState::Bound.as_str(),
                // byom's Episode is still `queued` at the claim CAS: only
                // `episode_start` moves it to `running`.
                "queued",
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
        json!({"episode_ref": record.episode_ref, "state": "bound",
               "lease_revision": lease_revision}),
        now,
    )?;

    Ok(Bound {
        stable_binding_key: stable_binding_key.to_owned(),
        episode_ref: record.episode_ref.clone(),
        byom_attempt_ref: record.byom_attempt_ref.clone(),
        fences,
        lease_revision,
        record,
    })
}

// -------------------------------------------- the dual-fenced mutations ----

/// Every intra-episode mutation goes through here: the presented pair must
/// equal the bound pair BEFORE anything is sent to byom. Either fence
/// stale means the binding is FENCED — terminal, retained for audit, and
/// unable to advance any head on either side.
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

/// `checkpoint_commit` (runtime, create) — honors both fences here and at
/// byomd, and names the exact lease revision it CASes against.
pub fn checkpoint(
    store: &mut Store,
    runtime: &Runtime,
    stable_binding_key: &str,
    presented: Fences,
    checkpoint_ref: &str,
    now: i64,
) -> Result<u64, Problem> {
    let bound = fenced_mutation(
        store,
        stable_binding_key,
        presented,
        "checkpoint_commit",
        now,
    )?;
    let placement_id = binding_placement(store.conn(), stable_binding_key)?;
    let secret = object_secret(store.conn(), &placement_id)?;
    let seam = seam_of(
        store.conn(),
        &bound.record.society_ref,
        bound.record.recovery_epoch,
    )?;
    let token = runtime.token(Workload::Worker, &bound.episode_ref)?;
    let digest = erasure_safe(
        &placement_id,
        &secret,
        TAG_CHECKPOINT,
        &json!({
            "checkpoint_ref": checkpoint_ref,
            "episode_ref": bound.episode_ref,
            "byom_attempt_ref": bound.byom_attempt_ref,
        }),
    )?;
    let result = runtime.call(
        &token,
        &json!({
            "version": BPP_VERSION,
            "op": "checkpoint_commit",
            "meta": create_meta(&seam, "ckpt", checkpoint_ref),
            "episode_ref": bound.episode_ref,
            "generation": bound.record.generation,
            "byom_attempt_ref": bound.byom_attempt_ref,
            "byom_fence_epoch": presented.byom,
            "kovee_invocation_fence": presented.kovee,
            "expected_lease_revision": bound.lease_revision,
            "checkpoint_ref": checkpoint_ref,
            "checkpoint_digest": digest,
        }),
    )?;
    let lease_revision = number_of(&result, "lease_revision")?;
    set_lease(store.conn(), stable_binding_key, lease_revision, now)?;
    set_episode_state(store.conn(), stable_binding_key, "running", now)?;
    Ok(lease_revision)
}

/// `usage_report` (runtime, create) on the METER channel — the only
/// channel byom lets settle (§11.4, family contract L33) — plus Kovee's
/// own measured settlement of the subordinate reservation.
pub fn settle(
    store: &mut Store,
    runtime: &Runtime,
    stable_binding_key: &str,
    presented: Fences,
    charge: u64,
    now: i64,
) -> Result<Value, Problem> {
    let bound = fenced_mutation(store, stable_binding_key, presented, "usage_report", now)?;
    let seam = seam_of(
        store.conn(),
        &bound.record.society_ref,
        bound.record.recovery_epoch,
    )?;
    let token = runtime.token(Workload::Meter, &bound.episode_ref)?;
    let stable_settlement_key = format!("kovee-settle-{stable_binding_key}");
    let result = runtime.call(
        &token,
        &json!({
            "version": BPP_VERSION,
            "op": "usage_report",
            "meta": create_meta(&seam, "usg", &stable_settlement_key),
            "episode_ref": bound.episode_ref,
            "generation": bound.record.generation,
            "byom_attempt_ref": bound.byom_attempt_ref,
            "byom_fence_epoch": presented.byom,
            "kovee_invocation_fence": presented.kovee,
            "source": SOURCE_METER,
            "stable_report_key": format!("kovee-report-{stable_binding_key}"),
            "quantities": [{"dimension": "unit", "unit": "unit", "amount": charge}],
            "meter_ref": format!("kovee-meter-{}", bound.record.society_ref),
            "meter_attestation_ref": format!("kovee-meter-attestation-{stable_binding_key}"),
            "stable_settlement_key": stable_settlement_key,
            "charged_quantities": [{"dimension": "unit", "unit": "unit", "amount": charge}],
        }),
    )?;
    // Kovee's own side of the same measured settlement: monotonic,
    // stable-keyed, never above the reserved amount.
    crate::budget::settle(
        store,
        &bound.record.kovee_subordinate_reservation_ref,
        "unit",
        charge,
        kovee_byom::budget::Meter::TrustedBroker,
        &stable_settlement_key,
        now,
    )?;
    Ok(result)
}

/// `episode_yield` (runtime, update) — honors both fences and hands the
/// Continuation off.
#[allow(clippy::too_many_arguments)]
pub fn yield_episode(
    store: &mut Store,
    runtime: &Runtime,
    stable_binding_key: &str,
    presented: Fences,
    continuation_ref: &str,
    now: i64,
) -> Result<Value, Problem> {
    let bound = fenced_mutation(store, stable_binding_key, presented, "episode_yield", now)?;
    let seam = seam_of(
        store.conn(),
        &bound.record.society_ref,
        bound.record.recovery_epoch,
    )?;
    let token = runtime.token(Workload::Worker, &bound.episode_ref)?;
    let result = runtime.call(
        &token,
        &json!({
            "version": BPP_VERSION,
            "op": "episode_yield",
            "meta": update_meta(&seam, "yld", stable_binding_key, bound.lease_revision),
            "episode_ref": bound.episode_ref,
            "generation": bound.record.generation,
            "byom_attempt_ref": bound.byom_attempt_ref,
            "byom_fence_epoch": presented.byom,
            "kovee_invocation_fence": presented.kovee,
            "target_state": "yielded",
            "reason_ref": continuation_ref,
        }),
    )?;
    let lease_revision = number_of(&result, "lease_revision")?;
    set_lease(store.conn(), stable_binding_key, lease_revision, now)?;
    set_episode_state(store.conn(), stable_binding_key, "yielded", now)?;
    // The Continuation hand-off: Kovee records WHICH continuation the
    // yielded episode left behind. A successor attempt claims it under a
    // new byom fence and therefore a NEW binding row.
    Ok(json!({
        "stable_binding_key": bound.stable_binding_key,
        "episode_ref": bound.episode_ref,
        "continuation_ref": continuation_ref,
        "byom_fence_epoch": bound.fences.byom,
        "kovee_invocation_fence": bound.fences.kovee,
        "byom_lease_state": result.get("lease_state").cloned().unwrap_or(Value::Null),
        "successor_requires_new_binding": true,
    }))
}

/// `episode_complete` (runtime, update) — honors both fences, then
/// releases the binding and hands the budget reservations to §11.4
/// settlement.
pub fn complete(
    store: &mut Store,
    runtime: &Runtime,
    stable_binding_key: &str,
    presented: Fences,
    now: i64,
) -> Result<Value, Problem> {
    let bound = fenced_mutation(
        store,
        stable_binding_key,
        presented,
        "episode_complete",
        now,
    )?;
    let realm = binding_realm(store.conn(), stable_binding_key)?;
    let seam = seam_of(
        store.conn(),
        &bound.record.society_ref,
        bound.record.recovery_epoch,
    )?;
    let token = runtime.token(Workload::Worker, &bound.episode_ref)?;
    let result = runtime.call(
        &token,
        &json!({
            "version": BPP_VERSION,
            "op": "episode_complete",
            "meta": update_meta(&seam, "cmp", stable_binding_key, bound.lease_revision),
            "episode_ref": bound.episode_ref,
            "generation": bound.record.generation,
            "byom_attempt_ref": bound.byom_attempt_ref,
            "byom_fence_epoch": presented.byom,
            "kovee_invocation_fence": presented.kovee,
            "output_refs": [],
            "evidence_refs": [format!("kovee-evidence-{stable_binding_key}")],
            "usage_report_refs": [],
        }),
    )?;
    store
        .conn()
        .execute(
            "UPDATE byom_episode_bindings
             SET state = ?2, episode_state = 'completed', lease_revision = ?3, updated_at = ?4
             WHERE stable_binding_key = ?1",
            params![
                stable_binding_key,
                BindingState::Released.as_str(),
                number_of(&result, "lease_revision").unwrap_or(bound.lease_revision) as i64,
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
            "byom_settlement": result.get("settlement").cloned().unwrap_or(Value::Null),
        }),
        now,
    )?;
    Ok(result)
}

// ------------------------------------------------------------ the seam ----

/// The active governed-work seam's wire facts every mutation's `meta`
/// pins: byomd's endpoint incarnation, the Society's recovery epoch, and
/// the binding epoch the placement adapter verifies its source against.
#[derive(Debug, Clone)]
struct Seam {
    endpoint_incarnation: String,
    recovery_epoch: u64,
    binding_epoch: u64,
}

fn seam_of(conn: &Connection, society_ref: &str, recovery_epoch: u64) -> Result<Seam, Problem> {
    let mut found: Option<Seam> = None;
    for realm in realms(conn)? {
        if let Some((binding, mapping)) = active_seam(conn, &realm)? {
            if mapping.society_ref == society_ref {
                found = Some(Seam {
                    endpoint_incarnation: binding.endpoint_incarnation.clone(),
                    recovery_epoch: mapping.society_recovery_epoch,
                    binding_epoch: binding.binding_epoch,
                });
                break;
            }
        }
    }
    let seam = found.ok_or_else(|| {
        forbidden(
            "this Society has no active governed-work binding",
            "an Episode is hosted only under an ACTIVE KoveeRealmByomBinding",
        )
    })?;
    if seam.recovery_epoch != recovery_epoch {
        return Err(Problem::new(
            ProblemKind::StaleRevision,
            "the notice names another Society recovery epoch",
        ));
    }
    Ok(seam)
}

fn realms(conn: &Connection) -> Result<Vec<String>, Problem> {
    let mut stmt = conn
        .prepare("SELECT realm_id FROM realms ORDER BY realm_id ASC")
        .map_err(|e| store_problem(e.into()))?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| store_problem(e.into()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| store_problem(e.into()))?);
    }
    Ok(out)
}

fn create_meta(seam: &Seam, what: &str, key: &str) -> Value {
    json!({
        "request_id": format!("kovee-{what}-{key}"),
        "idempotency_key": format!("kovee-{what}-{key}"),
        "expected_endpoint_incarnation": seam.endpoint_incarnation,
        "expected_recovery_epoch": seam.recovery_epoch,
    })
}

fn update_meta(seam: &Seam, what: &str, key: &str, expected_revision: u64) -> Value {
    let mut meta = create_meta(seam, what, key);
    if let Some(map) = meta.as_object_mut() {
        map.insert("expected_revision".to_owned(), json!(expected_revision));
    }
    meta
}

fn now_or_wall(now: i64) -> i64 {
    // A channel proof is accepted within 120 seconds of issue against
    // byomd's own clock, so it is minted on the wall clock even when the
    // caller passes a fixed test time.
    if now == 0 {
        kovee_core::time::unix_now()
    } else {
        now
    }
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
    let row: Option<(String, i64)> = conn
        .query_row(
            "SELECT record, lease_revision FROM byom_episode_bindings
             WHERE stable_binding_key = ?1",
            [key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    let Some((text, lease_revision)) = row else {
        return Ok(None);
    };
    let record: ByomEpisodeBinding = serde_json::from_str(&text).map_err(|_| internal())?;
    Ok(Some(Bound {
        stable_binding_key: record.stable_binding_key.clone(),
        episode_ref: record.episode_ref.clone(),
        byom_attempt_ref: record.byom_attempt_ref.clone(),
        fences: record.fences(),
        lease_revision: lease_revision.max(0) as u64,
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

fn binding_placement(conn: &Connection, key: &str) -> Result<String, Problem> {
    conn.query_row(
        "SELECT placement_id FROM byom_episode_bindings WHERE stable_binding_key = ?1",
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

/// byomd's lease-head revision as of the last accepted mutation. It is
/// byom's number: read from the reply, never incremented here.
fn set_lease(conn: &Connection, key: &str, lease_revision: u64, now: i64) -> Result<(), Problem> {
    conn.execute(
        "UPDATE byom_episode_bindings SET lease_revision = ?2, updated_at = ?3
         WHERE stable_binding_key = ?1",
        params![key, lease_revision as i64, rfc3339_utc(now)],
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

fn string_of(value: &Value, key: &str) -> Result<String, Problem> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| unusable(key))
}

fn number_of(value: &Value, key: &str) -> Result<u64, Problem> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| unusable(key))
}

fn unusable(key: &str) -> Problem {
    Problem::new(
        ProblemKind::Unavailable,
        "the byom endpoint answered with an unusable reply",
    )
    .with_detail(format!("the runtime reply carries no {key}"))
}

// ------------------------------------------- byom_episode_binding_show ----

/// The read surface: the recorded bindings, their dual fences, byom's
/// lease revision, and their state — including `fenced` rows, which stay
/// in the audit closure.
pub fn byom_episode_binding_show(
    store: &Store,
    realm: &str,
    args: &kovee_core::ops::EpisodeBindingShowArgs,
) -> Result<Vec<u8>, Problem> {
    let conn = store.conn();
    let mut sql = "SELECT stable_binding_key, episode_ref, byom_attempt_ref,
                          kovee_invocation_ref, byom_fence_epoch, kovee_invocation_fence,
                          state, episode_state, fenced_reason, record, created_at, updated_at,
                          lease_revision
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
                "byom_lease_revision": r.get::<_, i64>(12)?,
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
