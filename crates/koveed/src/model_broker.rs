//! The model broker, wired: the durable `model_*` records, byom's permit
//! consumption on the `rpm1.` runtime channel, the one egress, and the
//! metering report on the `rmt1.` meter channel.
//!
//! `kovee_effects` holds the decisions; this module holds the *order*,
//! because only the §12.2 command transaction can make the order
//! crash-honest.
//!
//! What you write (one governed model call, end to end):
//!
//! ```no_run
//! # use koveed::model_broker::{self, ActAuthorization, CompleteRequest};
//! # use kovee_effects::HttpsTransport;
//! # fn f(store: &mut kovee_store::Store, runtime: &koveed::episode::Runtime,
//! #      authorization: &ActAuthorization)
//! #   -> Result<(), kovee_core::problem::Problem> {
//! // The daemon's own wire. `complete` accepts nothing else in a production
//! // build: `&HttpsTransport` converts into the sealed `Egress`, and the
//! // recording double exists only under kovee-effects' `testing` feature.
//! let transport = HttpsTransport::new();
//! let completion = model_broker::complete(
//!     store, runtime, &transport,
//!     &CompleteRequest {
//!         realm: "realm-personal", project: Some("proj-1"),
//!         attempt_id: "invatt-1", fence_epoch: 1,
//!         model_profile_ref: "mp-anthropic-1",
//!         purpose_ref: "purpose-review", classification_ref: "class-public",
//!         system: Some("Be brief."), prompt: "Say OK.",
//!         max_output_tokens: 256,
//!         stable_binding_key: Some("ebk-0f8a1c2d"),
//!     },
//!     // byom's authorization for the model_egress act — a NOTICE, never
//!     // authority: byomd re-derives every member of it.
//!     authorization,
//!     0, model_broker::Fault::None,
//! )?;
//! // The worker gets text, usage, and refs. No key, no URL, no host.
//! assert!(completion.text.is_some());
//! # Ok(()) }
//! ```
//!
//! Plumbing worth knowing:
//!
//! - **The act is byom's; Kovee consumes.** [`ActAuthorization`] is a
//!   *notice*, exactly like [`crate::episode::Notice`]: every member is
//!   byom's, and byomd re-derives all of them inside
//!   `execution_permit_consume`. A caller naming another act's refs gains
//!   nothing — the digests will not match byom's committed act, and the
//!   permit token is byomd's own file keyed to that act's id.
//! - **The write order IS the safety property.** The `model_effects` row is
//!   committed before the permit is consumed; the attempt row is committed
//!   `dispatching` before the socket opens. Both are separate transactions
//!   on purpose: a crash between them must leave the earlier fact on disk.
//! - **Staging is deterministic.** The disclosure and provider-context ids
//!   and digests derive from their content, so the governance side that
//!   prepared byom's act and the broker that later dispatches compute the
//!   identical refs without passing them around.
//! - **Metering reports; byom settles.** The `usage_report` goes on the
//!   METER channel with the measured token counts. Kovee's row is evidence;
//!   the ledger move is byom's (§11.4, family contract L33).

use std::time::Duration;

use kovee_byom::bpp::BPP_VERSION;
use kovee_byom::runtime::Workload;
use kovee_core::event::{
    EVENT_MODEL_EFFECT_AMBIGUOUS, EVENT_MODEL_EFFECT_AUTHORIZED, EVENT_MODEL_EFFECT_COMPLETED,
    EVENT_MODEL_EFFECT_DISPATCHING, EVENT_MODEL_EFFECT_FAILED, EVENT_MODEL_EFFECT_PREPARED,
    EVENT_MODEL_EFFECT_RECONCILED, EVENT_MODEL_USAGE_REPORTED,
};
use kovee_core::family::{tagged_canonical, DigestRef};
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::time::rfc3339_utc;
use kovee_effects::{
    authorize, dispatch as dispatch_bytes, plan, ByomSourceFields, CallPlan, Claim,
    ConsumedReceipt, DisclosureItem, DisclosureManifest, EffectState, Egress, EpisodeFence,
    ExecutionConsumptionReceipt, ExecutionPermit, Expectation, ModelProfile, ModelProviderBinding,
    PlanInput, PlanKeys, ProviderClaims, ProviderContextManifest, ProviderKind, RecordDigestKey,
    RequestLimits, Segment, SegmentKind, SpentLedger, Usage, BROKER_DRIVER_AUDIENCE,
    OWNER_PROTOCOL_BYOM, PHASE_PRE_EGRESS,
};
use kovee_store::{new_id, NewEvent, Store};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::{json, Value};

use crate::episode::Runtime;
use crate::state::{internal, not_found, store_problem, DEFAULT_CLASSIFICATION};

/// The service identity the broker records outcomes under. §16.1: once the
/// broker has consumed the permit it owns recording the outcome "under the
/// broker's service identity, not the stale agent fence".
pub const BROKER_ACTOR_REF: &str = "svc-kovee-model-broker";

const TAG_DISCLOSURE_ID: &str = "kovee-disclosure-id-v1";
const TAG_CONTEXT_ID: &str = "kovee-provider-context-id-v1";
const SCHEMA_EFFECT: &str = "schema:kovee-model-effect-v1";

/// The per-call wall-clock budget.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Crash-honesty instruction for the tests that prove the write ORDER: stop
/// at an exact point in the chain. `None` in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    /// Die immediately after the prepared Effect is committed — before any
    /// permit is consumed and before any byte leaves.
    AbortAfterPrepare,
    /// Die immediately after the attempt row is committed `dispatching`.
    AbortAfterDispatchRecord,
}

// ------------------------------------------------------------- the notice ----

/// The byom-owned authorization for one `model_egress` act. Every member is
/// byom's; Kovee echoes it into `execution_permit_consume` and byomd rejects
/// any that is not its own committed value.
#[derive(Debug, Clone)]
pub struct ActAuthorization {
    /// The prepared-and-finalized `ActIntent`. Also the subject of the
    /// `rpm1.` permit channel byomd published for it.
    pub act_intent_ref: String,
    pub act_intent_digest: DigestRef,
    /// byomd's current act revision — the CAS `meta.expected_revision`.
    pub act_revision: u64,
    /// byom's authorized act subject digest.
    pub subject_digest: DigestRef,
    /// byom's kernel-derived one-shot key: the effect's identity.
    pub stable_execution_key: String,
    pub budget_reservation_set_ref: String,
}

/// What the worker asked for, after `dispatch_worker` has parsed it.
#[derive(Debug, Clone, Copy)]
pub struct CompleteRequest<'a> {
    pub realm: &'a str,
    pub project: Option<&'a str>,
    pub attempt_id: &'a str,
    pub fence_epoch: u64,
    pub model_profile_ref: &'a str,
    pub purpose_ref: &'a str,
    pub classification_ref: &'a str,
    pub system: Option<&'a str>,
    pub prompt: &'a str,
    pub max_output_tokens: u64,
    /// The governed Episode this call runs inside. `None` is an ungoverned
    /// local call, which byom's `model_egress` class does not authorize —
    /// so a request without it is refused when an authorization is present.
    pub stable_binding_key: Option<&'a str>,
}

/// What the worker gets back. No credential, no URL, no host, no header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    pub effect_id: String,
    pub effect_attempt_id: String,
    pub state: EffectState,
    pub text: Option<String>,
    pub usage: Usage,
    pub model: Option<String>,
    pub stop_reason: Option<String>,
    pub external_ref: Option<String>,
    pub disclosure_manifest_ref: String,
    pub provider_context_manifest_ref: String,
    pub latency_ms: u64,
    pub transport_profile: String,
    pub observation: Option<String>,
    pub retry_frozen: bool,
    pub usage_reported: bool,
}

impl Completion {
    /// The worker-visible projection: exactly what leaves the daemon on the
    /// worker socket.
    pub fn worker_view(&self) -> Value {
        let mut view = json!({
            "effect_id": self.effect_id,
            "effect_attempt_id": self.effect_attempt_id,
            "state": self.state.as_str(),
            "usage": {"input_tokens": self.usage.input_tokens,
                      "output_tokens": self.usage.output_tokens},
            "disclosure_manifest_ref": self.disclosure_manifest_ref,
            "provider_context_manifest_ref": self.provider_context_manifest_ref,
            "latency_ms": self.latency_ms,
            "retry_frozen": self.retry_frozen,
            "usage_reported": self.usage_reported,
        });
        if let Some(text) = &self.text {
            view["text"] = json!(text);
        }
        if let Some(model) = &self.model {
            view["model"] = json!(model);
        }
        if let Some(stop) = &self.stop_reason {
            view["stop_reason"] = json!(stop);
        }
        if let Some(reference) = &self.external_ref {
            view["provider_ref"] = json!(reference);
        }
        if let Some(observation) = &self.observation {
            view["observation"] = json!(observation);
        }
        view
    }
}

// ------------------------------------------------- bindings and profiles ----

/// Registers (or re-registers at a new revision) one provider binding and a
/// default profile for it. Operator-only: nothing on the worker surface
/// reaches this.
#[allow(clippy::too_many_arguments)]
pub fn register(
    store: &mut Store,
    realm: &str,
    kind: ProviderKind,
    claims: ProviderClaims,
    credential_secret_ref: &str,
    model_selector: &str,
    limits: RequestLimits,
    now: i64,
) -> Result<(ModelProviderBinding, ModelProfile), Problem> {
    let binding_id = format!("mpb-{}-{realm}", kind.as_str());
    let binding = ModelProviderBinding::new(
        &binding_id,
        realm,
        kind,
        kind.default_origin(),
        claims,
        credential_secret_ref,
        &format!("terms-{}", kind.as_str()),
    )
    .map_err(|e| {
        refuse(
            ProblemKind::Invalid,
            "the provider binding is not usable",
            e,
        )
    })?;
    let profile_id = format!("mp-{}-{realm}", kind.as_str());
    let profile = ModelProfile::new(&profile_id, &binding, model_selector, limits)
        .map_err(|e| refuse(ProblemKind::Invalid, "the model profile is not usable", e))?;
    let at = rfc3339_utc(now);
    store
        .conn()
        .execute(
            "INSERT INTO model_provider_bindings (model_provider_binding_id, realm_ref, revision,
                 provider_kind, endpoint_host, endpoint_port, credential_secret_ref, status,
                 record, digest, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?11)
             ON CONFLICT(model_provider_binding_id) DO UPDATE SET
                 revision = excluded.revision, endpoint_host = excluded.endpoint_host,
                 endpoint_port = excluded.endpoint_port,
                 credential_secret_ref = excluded.credential_secret_ref,
                 status = excluded.status, record = excluded.record,
                 digest = excluded.digest, updated_at = excluded.updated_at",
            params![
                binding.model_provider_binding_id,
                realm,
                binding.revision as i64,
                binding.provider_kind.as_str(),
                binding.endpoint.host,
                binding.endpoint.port as i64,
                binding.credential_secret_ref,
                binding.status.as_str(),
                serde_json::to_string(&binding).map_err(|_| internal())?,
                binding.digest.value_hex,
                at,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    store
        .conn()
        .execute(
            "INSERT INTO model_profiles (model_profile_id, realm_ref, revision,
                 provider_binding_ref, provider_binding_revision, model_selector, status,
                 record, digest, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)
             ON CONFLICT(model_profile_id) DO UPDATE SET
                 revision = excluded.revision,
                 provider_binding_revision = excluded.provider_binding_revision,
                 model_selector = excluded.model_selector, status = excluded.status,
                 record = excluded.record, digest = excluded.digest,
                 updated_at = excluded.updated_at",
            params![
                profile.model_profile_id,
                realm,
                profile.revision as i64,
                profile.provider_binding_ref,
                profile.provider_binding_revision as i64,
                profile.model_selector,
                profile.status.as_str(),
                serde_json::to_string(&profile).map_err(|_| internal())?,
                profile.digest.value_hex,
                at,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok((binding, profile))
}

/// Seeds the two provider bindings the daemon ships with, from the
/// environment the daemon itself was started in. A provider whose key is
/// absent is registered `disabled` — recorded and honest, rather than
/// missing and mysterious.
///
/// The credential reference is `env:ANTHROPIC_API_KEY` / `env:OPENAI_API_KEY`.
/// The daemon's environment is not a worker's: the supervisor never passes
/// it on, and the broker is the only reader.
pub fn seed_default_bindings(store: &mut Store, realm: &str, now: i64) -> Result<(), Problem> {
    for (kind, env_name, model, region, retention, training) in [
        (
            ProviderKind::Anthropic,
            "ANTHROPIC_API_KEY",
            kovee_effects::ANTHROPIC_MODEL,
            "us",
            // Anthropic's default API retention and training posture, as
            // ASSERTED claims (§16.2: recorded assertions, not proven facts).
            "30-days",
            "prohibited",
        ),
        (
            ProviderKind::Openai,
            "OPENAI_API_KEY",
            kovee_effects::OPENAI_MODEL,
            "us",
            "30-days",
            "prohibited",
        ),
    ] {
        let claims = ProviderClaims {
            region: region.to_owned(),
            retention: retention.to_owned(),
            training_use: training.to_owned(),
        };
        let (binding, _) = register(
            store,
            realm,
            kind,
            claims,
            &format!("env:{env_name}"),
            model,
            RequestLimits {
                input_tokens: 100_000,
                output_tokens: 8_192,
                calls: 1,
            },
            now,
        )?;
        if std::env::var_os(env_name).is_none_or(|v| v.is_empty()) {
            store
                .conn()
                .execute(
                    "UPDATE model_provider_bindings SET status = 'disabled' WHERE
                     model_provider_binding_id = ?1",
                    [&binding.model_provider_binding_id],
                )
                .map_err(|e| store_problem(e.into()))?;
        }
    }
    Ok(())
}

/// Reads one profile and the binding revision it pins. Both records are
/// re-validated against each other by the broker immediately before use.
pub fn read_profile(
    conn: &Connection,
    realm: &str,
    profile_ref: &str,
) -> Result<(ModelProfile, ModelProviderBinding), Problem> {
    let profile_text: String = conn
        .query_row(
            "SELECT record FROM model_profiles WHERE model_profile_id = ?1 AND realm_ref = ?2",
            params![profile_ref, realm],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?
        .ok_or_else(not_found)?;
    let profile: ModelProfile = serde_json::from_str(&profile_text).map_err(|_| internal())?;
    let binding_text: String = conn
        .query_row(
            "SELECT record FROM model_provider_bindings
             WHERE model_provider_binding_id = ?1 AND realm_ref = ?2",
            params![profile.provider_binding_ref, realm],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?
        .ok_or_else(not_found)?;
    let binding: ModelProviderBinding =
        serde_json::from_str(&binding_text).map_err(|_| internal())?;
    Ok((profile, binding))
}

// ----------------------------------------------------------- the staging ----

/// One committed §16.2 disclosure manifest. The ref/digest are what byom's
/// `model_egress` act is prepared against, which is why staging happens
/// BEFORE the act and is committed rather than recomputed.
///
/// There is no per-object secret here: the manifest digest is the
/// CROSS-BOUNDARY `portable_public` one byom re-derives (A8), so it is keyed
/// by nothing and the row stores no secret to destroy.
#[derive(Debug, Clone)]
pub struct Staged {
    pub disclosure: DisclosureManifest,
}

impl Staged {
    pub fn disclosure_manifest_ref(&self) -> &str {
        &self.disclosure.disclosure_id
    }
    pub fn disclosure_digest(&self) -> &DigestRef {
        &self.disclosure.digest
    }
}

/// Stages the §16.2 disclosure manifest for one call and COMMITS it, with a
/// random per-object secret keying its digest (D-R1-2).
///
/// This is the first step of the whole chain, and it is deliberately
/// separate: byom's `act_intent_prepare` binds `disclosure_manifest_ref` and
/// `disclosure_manifest_digest`, so the disclosure has to exist — committed,
/// with its digest fixed — before anyone can ask for authority over it. The
/// id is DERIVED from the call's content, so an exact retry of the same
/// logical call finds the same row instead of staging a second disclosure.
pub fn stage(
    store: &mut Store,
    request: &CompleteRequest<'_>,
    profile: &ModelProfile,
    binding: &ModelProviderBinding,
    now: i64,
) -> Result<Staged, Problem> {
    let attempt = crate::state::get_attempt(store.conn(), request.attempt_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let invocation = crate::state::get_invocation(store.conn(), &attempt.invocation_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    // `created_at` is the INVOCATION's, not the wall clock: stable across a
    // retry of the same logical call, so the derived id is stable too.
    let created_at = invocation.record["created_at"]
        .as_str()
        .unwrap_or("1970-01-01T00:00:00Z")
        .to_owned();

    // What actually leaves: the system instruction and the prompt, as exact
    // items with their own digests and byte sizes. A "topic name" would not
    // do — §16.2 binds the final bytes.
    let items = disclosed_items(request);
    let disclosure_id = derive_id(
        "disc",
        TAG_DISCLOSURE_ID,
        &json!({
            "attempt_ref": request.attempt_id,
            "model_profile_ref": profile.model_profile_id,
            "model_profile_digest": profile.digest,
            "purpose_ref": request.purpose_ref,
            "items": items,
            "provider_claims": binding.provider_claims,
        }),
    )?;
    // An exact retry finds the committed row.
    if let Some(existing) = read_disclosure(store.conn(), &disclosure_id)? {
        let staged = Staged {
            disclosure: existing,
        };
        staged.disclosure.verify().map_err(|e| {
            refuse(
                ProblemKind::Internal,
                "the staged disclosure no longer verifies",
                e,
            )
        })?;
        return Ok(staged);
    }

    let mut disclosure = DisclosureManifest::model_egress(
        &disclosure_id,
        request.realm,
        request.project,
        invocation.space_id.as_deref(),
        &format!("model-profile:{}", profile.model_profile_id),
        request.purpose_ref,
        &[request.classification_ref],
        items,
        Vec::new(),
        binding.provider_claims.clone(),
        &created_at,
    )
    .map_err(|e| {
        refuse(
            ProblemKind::Invalid,
            "the disclosure manifest is incomplete",
            e,
        )
    })?;
    if let Some(assembly_ref) = invocation.context_assembly_ref.clone() {
        let assembly_digest =
            DigestRef::portable_public(kovee_core::family::sha256_hex(assembly_ref.as_bytes()));
        disclosure = disclosure
            .with_context_assembly(&assembly_ref, assembly_digest)
            .map_err(|e| refuse(ProblemKind::Invalid, "the disclosure manifest", e))?;
    }
    store
        .conn()
        .execute(
            "INSERT INTO disclosure_manifests (disclosure_id, realm_id, recipient_kind, record,
                 digest_hex, total_bytes, object_secret, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                disclosure.disclosure_id,
                request.realm,
                disclosure.recipient_kind,
                serde_json::to_string(&disclosure).map_err(|_| internal())?,
                disclosure.digest.value_hex,
                disclosure.total_bytes as i64,
                // No object secret: the digest is unkeyed `portable_public`,
                // so there is nothing here whose destruction would erase it.
                Option::<Vec<u8>>::None,
                rfc3339_utc(now),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok(Staged { disclosure })
}

/// The exact items that leave, as §16.2 `exact_items[]`.
fn disclosed_items(request: &CompleteRequest<'_>) -> Vec<DisclosureItem> {
    let mut items = Vec::new();
    if let Some(system) = request.system {
        items.push(DisclosureItem {
            ref_: format!("{}#system", request.attempt_id),
            revision: Some(1),
            digest: DigestRef::portable_public(kovee_core::family::sha256_hex(system.as_bytes())),
            size: system.len() as u64,
        });
    }
    items.push(DisclosureItem {
        ref_: format!("{}#prompt", request.attempt_id),
        revision: Some(1),
        digest: DigestRef::portable_public(kovee_core::family::sha256_hex(
            request.prompt.as_bytes(),
        )),
        size: request.prompt.len() as u64,
    });
    items
}

/// The ordered §16.3 chain segments for one call: the assistant instruction,
/// the collaboration item, and the adapter's own deterministic wrapper.
/// Nothing else — "no convenience context is appended".
fn chain_segments(request: &CompleteRequest<'_>, profile: &ModelProfile) -> Vec<Segment> {
    let hash =
        |text: &str| DigestRef::portable_public(kovee_core::family::sha256_hex(text.as_bytes()));
    let mut segments = Vec::new();
    if let Some(system) = request.system {
        segments.push(Segment::new(
            SegmentKind::SystemInstruction,
            &format!("{}#system", request.attempt_id),
            1,
            hash(system),
            request.classification_ref,
        ));
    }
    segments.push(Segment::new(
        SegmentKind::CollaborationItem,
        &format!("{}#prompt", request.attempt_id),
        1,
        hash(request.prompt),
        request.classification_ref,
    ));
    segments.push(Segment::new(
        SegmentKind::AdapterWrapper,
        &profile.adapter_version,
        1,
        hash(&profile.adapter_version),
        request.classification_ref,
    ));
    segments
}

/// byom's §12.1 source fields for one bound Episode attempt, parsed from
/// what `episode_claim` reported. Kovee derives none of it, so an absent
/// fragment is a refusal.
fn byom_source_fields(conn: &Connection, key: &str) -> Result<ByomSourceFields, Problem> {
    if !crate::episode::binding_is_bound(conn, key)? {
        return Err(refuse_msg(
            ProblemKind::StaleLease,
            "this episode binding is not live",
            "a fenced or released binding authorizes no model call",
        ));
    }
    let side = crate::episode::read_byom_side(conn, key)?;
    let fields = side.source_fields.ok_or_else(|| {
        refuse_msg(
            ProblemKind::Unavailable,
            "byom reported no provider-context source fields for this Episode",
            "the §12.1 fragment comes from episode_claim / context_manifest_show; Kovee never \
             invents it (§16.6 item 5)",
        )
    })?;
    serde_json::from_value(fields).map_err(|e| {
        refuse(
            ProblemKind::Unavailable,
            "byom's provider-context source fragment is not the shape C2 fixes",
            e,
        )
    })
}

// ------------------------------------------------------------ the chain ----

/// One prepared model effect: committed, and not yet authorized. Not
/// `Clone`: it owns the sealed [`CallPlan`], which is not copyable either.
#[derive(Debug)]
pub struct Prepared {
    pub effect_id: String,
    pub plan: CallPlan,
    pub already_existed: bool,
}

/// Step 6: commits the disclosure manifest, the sealed provider-context
/// chain, and the `model_effects` row in state `prepared`, under byom's
/// one-shot execution key. **No permit is consumed and no byte leaves.**
///
/// A repeated execution key finds the existing effect and returns it rather
/// than preparing a second one — which is what makes a consumed byom permit
/// recoverable by key after a crash (§16.1 step 1).
#[allow(clippy::too_many_arguments)]
pub fn prepare(
    store: &mut Store,
    request: &CompleteRequest<'_>,
    authorization: &ActAuthorization,
    profile: &ModelProfile,
    binding: &ModelProviderBinding,
    staged: &Staged,
    now: i64,
) -> Result<Prepared, Problem> {
    let key = &authorization.stable_execution_key;
    let existing: Option<String> = store
        .conn()
        .query_row(
            "SELECT effect_id FROM model_effects WHERE execution_key = ?1",
            [key],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    let effect_id = match &existing {
        Some(id) => id.clone(),
        None => new_id("meff").map_err(store_problem)?,
    };

    // The byom half of the chain, READ from the committed Episode binding.
    let byom_source = match request.stable_binding_key {
        Some(binding_key) => Some(byom_source_fields(store.conn(), binding_key)?),
        None => None,
    };
    let segments = chain_segments(request, profile);
    let context_id = derive_id(
        "pcm",
        TAG_CONTEXT_ID,
        &json!({
            "attempt_ref": request.attempt_id,
            "disclosure_id": staged.disclosure.disclosure_id,
            "disclosure_digest": staged.disclosure.digest,
            "segments": segments,
            "model_profile_digest": profile.digest,
            "provider_binding_digest": binding.digest,
            "act_intent_ref": authorization.act_intent_ref,
        }),
    )?;
    let context_key_ref = kovee_effects::object_key_ref("provider-context", &context_id);
    let context_secret = match read_provider_context(store.conn(), &context_id)? {
        Some(_) => object_secret(
            store.conn(),
            "provider_context_manifests",
            "provider_context_id",
            &context_id,
            &context_key_ref,
        )?,
        None => kovee_store::objkey::new_object_secret().map_err(store_problem)?,
    };
    let created_at = staged.disclosure.created_at.clone();
    let context_manifest = ProviderContextManifest::build(
        &context_id,
        &crate::state::get_attempt(store.conn(), request.attempt_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?
            .invocation_id,
        request.attempt_id,
        request.fence_epoch,
        byom_source,
        segments,
        (
            &binding.model_provider_binding_id,
            binding.revision,
            binding.digest.clone(),
        ),
        (
            &profile.model_profile_id,
            profile.revision,
            profile.digest.clone(),
        ),
        &profile.adapter_version,
        &staged.disclosure.disclosure_id,
        staged.disclosure.digest.clone(),
        &format!("authdep-model-egress-{}", request.attempt_id),
        DigestRef::portable_public(kovee_core::family::sha256_hex(
            authorization.act_intent_ref.as_bytes(),
        )),
        &created_at,
        RecordDigestKey::Object {
            key_ref: &context_key_ref,
            secret: &context_secret,
        },
    )
    .map_err(|e| refuse(ProblemKind::Invalid, "the provider context chain", e))?;

    let planned = plan(
        &PlanInput {
            effect_id: &effect_id,
            execution_key: key,
            subject_digest: &authorization.subject_digest,
            system: request.system,
            prompt: request.prompt,
            max_output_tokens: request.max_output_tokens,
            classification_ref: request.classification_ref,
        },
        binding,
        profile,
        staged.disclosure.clone(),
        context_manifest,
        // Only the provider-context chain is a keyed local object now: the
        // disclosure digest and the host-effect digest are both the
        // cross-boundary `portable_public` values byom re-derives (A8).
        PlanKeys {
            context: RecordDigestKey::Object {
                key_ref: &context_key_ref,
                secret: &context_secret,
            },
        },
    )
    .map_err(|e| {
        refuse(
            ProblemKind::Forbidden,
            "the model call cannot be planned",
            e,
        )
    })?;
    if existing.is_some() {
        return Ok(Prepared {
            effect_id,
            plan: planned,
            already_existed: true,
        });
    }

    let at = rfc3339_utc(now);
    let bound = match request.stable_binding_key {
        Some(key) => crate::episode::read_binding(store.conn(), key)?,
        None => None,
    };
    let realm_key = kovee_store::realm_object_key_of(store.conn()).map_err(store_problem)?;
    let wrapped_context = kovee_store::objkey::wrap(&realm_key, &context_key_ref, &context_secret)
        .map_err(store_problem)?;
    let conn = store.conn();
    conn.execute(
        "INSERT INTO provider_context_manifests (provider_context_id, realm_ref, invocation_ref,
             attempt_ref, record, digest_hex, final_request_digest_hex, object_secret, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(provider_context_id) DO UPDATE SET
             record = excluded.record, digest_hex = excluded.digest_hex,
             final_request_digest_hex = excluded.final_request_digest_hex",
        params![
            planned.context_manifest().provider_context_id,
            request.realm,
            planned.context_manifest().invocation_id,
            planned.context_manifest().attempt_id,
            serde_json::to_string(planned.context_manifest()).map_err(|_| internal())?,
            planned.context_manifest().digest.value_hex,
            planned
                .context_manifest()
                .final_provider_request_typed_byte_digest,
            wrapped_context,
            at,
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    conn.execute(
        "INSERT INTO model_effects (effect_id, realm_ref, project_ref, invocation_ref,
             attempt_ref, kovee_invocation_fence, stable_binding_key, episode_ref,
             byom_fence_epoch, act_intent_ref, execution_key, external_idempotency_key,
             model_profile_ref, provider_binding_ref, subject_digest, host_effect_digest,
             disclosure_manifest_ref, disclosure_digest, provider_context_ref,
             provider_context_digest, state, object_secret, created_at, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?23)",
        params![
            effect_id,
            request.realm,
            request.project,
            planned.context_manifest().invocation_id,
            request.attempt_id,
            request.fence_epoch as i64,
            request.stable_binding_key,
            bound.as_ref().map(|b| b.episode_ref.clone()),
            bound.as_ref().map(|b| b.fences.byom as i64),
            authorization.act_intent_ref,
            key,
            planned.external_idempotency_key(),
            profile.model_profile_id,
            binding.model_provider_binding_id,
            digest_text(planned.subject_digest())?,
            digest_text(planned.host_effect_digest())?,
            planned.disclosure().disclosure_id,
            digest_text(&planned.disclosure().digest)?,
            planned.context_manifest().provider_context_id,
            digest_text(&planned.context_manifest().digest)?,
            EffectState::Prepared.as_str(),
            // No object secret: `host_effect_digest` is unkeyed
            // `portable_public`, so this row keys nothing (A8).
            Option::<Vec<u8>>::None,
            at,
        ],
    )
    .map_err(|e| store_problem(e.into()))?;

    emit(
        store,
        request.realm,
        request.project,
        &effect_id,
        EVENT_MODEL_EFFECT_PREPARED,
        json!({
            "state": EffectState::Prepared.as_str(),
            "execution_key": key,
            "act_intent_ref": authorization.act_intent_ref,
            "model_profile_ref": profile.model_profile_id,
            "provider_kind": binding.provider_kind.as_str(),
            "disclosure_manifest_ref": planned.disclosure().disclosure_id,
            "provider_context_manifest_ref": planned.context_manifest().provider_context_id,
            "final_provider_request_digest":
                planned.context_manifest().final_provider_request_typed_byte_digest,
            "permit_consumed": false,
            "dispatched": false,
        }),
        now,
    )?;
    Ok(Prepared {
        effect_id,
        plan: planned,
        already_existed: false,
    })
}

/// Steps 7-8: byom's `execution_permit_consume` on the `rpm1.` permit
/// channel, the receipt stored as `ExternalAuthorizationConsumption{phase:
/// pre_egress}`, and the fail-closed [`authorize`] gate over it.
///
/// The permit channel's token is byomd's own file, keyed to this exact
/// ActIntent. Kovee cannot mint one, so it cannot consume another act's
/// authority even by mistake.
pub fn consume_permit(
    store: &mut Store,
    runtime: &Runtime,
    request: &CompleteRequest<'_>,
    authorization: &ActAuthorization,
    prepared: &Prepared,
    now: i64,
) -> Result<(ExecutionPermit, String), Problem> {
    let bound = match request.stable_binding_key {
        Some(key) => Some(crate::episode::read_binding(store.conn(), key)?.ok_or_else(not_found)?),
        None => None,
    };
    let side = match request.stable_binding_key {
        Some(key) => crate::episode::read_byom_side(store.conn(), key)?,
        None => Default::default(),
    };
    let seam = crate::episode::seam_of_binding(store.conn(), request.realm)?;

    // Recover an already-stored consumption first: a crash after byom
    // consumed but before Kovee stored the reply is repaired by re-asking
    // with the same key, and byom replays the retained receipt.
    let stored = read_consumption(store.conn(), &authorization.stable_execution_key)?;
    let receipt = match stored {
        Some((_, receipt)) => receipt,
        None => {
            let token = runtime.token(Workload::Permit, &authorization.act_intent_ref)?;
            // The host-effect REGISTRATION authenticator (byom R3-A02): it
            // binds this consumption to the ONE Effect Kovee durably created,
            // under the permit-channel token byomd published for this act. A
            // caller that never held that token cannot mint it, so a
            // consumption can no longer name an Effect that does not exist.
            let credential = host_effect_credential(
                token.preamble(),
                &authorization.act_intent_ref,
                &authorization.stable_execution_key,
                &prepared.effect_id,
                prepared.plan.host_effect_digest(),
            )?;
            // A8, both directions (D-R3-3): byom's OWN digests — intent,
            // subject, episode fence — are NOT members. byomd recomputes each
            // from its committed act and publishes the committed value on the
            // receipt, so echoing them proved only that byom's value equals
            // itself. What byom DEMANDS from Kovee travels as
            // `portable_public` over a frozen fragment it can re-derive.
            let mut body = json!({
                "version": BPP_VERSION,
                "op": "execution_permit_consume",
                "meta": {
                    "request_id": format!("kovee-perm-{}", prepared.effect_id),
                    "idempotency_key": format!("kovee-perm-{}", authorization.stable_execution_key),
                    "expected_endpoint_incarnation": seam.endpoint_incarnation,
                    "expected_recovery_epoch": seam.recovery_epoch,
                    "expected_revision": authorization.act_revision,
                },
                "stable_execution_key": authorization.stable_execution_key,
                "intent_ref": authorization.act_intent_ref,
                "host_effect_ref": prepared.effect_id,
                "host_effect_digest": prepared.plan.host_effect_digest(),
                "host_effect_credential": credential,
                "disclosure_manifest_ref": prepared.plan.disclosure().disclosure_id,
                "disclosure_digest": prepared.plan.disclosure().digest,
                "driver_audience": BROKER_DRIVER_AUDIENCE,
                "budget_reservation_set_ref": authorization.budget_reservation_set_ref,
                "byom_fence_epoch": bound.as_ref().map_or(0, |b| b.fences.byom),
                "host_fence_epoch": bound.as_ref().map_or(0, |b| b.fences.kovee),
            });
            // The Episode reference now travels ALONE: its fence digest is
            // byom's own record and byomd recomputes it (A8).
            if let Some(b) = &bound {
                body["episode_ref"] = json!(b.episode_ref);
            }
            let reply = runtime.call(&token, &body)?;
            let receipt = ExecutionConsumptionReceipt::from_result(&reply).map_err(|e| {
                // The reply is byom's own record, not a credential: naming the
                // member that did not fit is what makes a shape drift
                // diagnosable instead of mysterious.
                refuse(
                    ProblemKind::Unavailable,
                    "byom's consumption receipt is not the shape Kovee can honor",
                    format!("{e}; reply was {}", bounded(&reply)),
                )
            })?;
            store_consumption(store, prepared, &receipt, now)?;
            receipt
        }
    };

    let already_spent = attempt_count(store.conn(), &prepared.effect_id)? > 0;
    let episode = match (&bound, &side.binding_digest) {
        (Some(b), Some(digest)) => Some(EpisodeFence {
            episode_ref: &b.episode_ref,
            fence_digest: digest,
            byom_fence_epoch: b.fences.byom,
            kovee_invocation_fence: b.fences.kovee,
        }),
        _ => None,
    };
    // The gate needs an ATTESTED receipt, not a receipt: the attestation is
    // keyed under a secret derived from the realm object key for this exact
    // committed consumption row, so a receipt that never went through the
    // permit channel and this store cannot mint a permit (D-R3-1).
    let consumption_id = read_consumption(store.conn(), prepared.plan.execution_key())?
        .map(|(id, _)| id)
        .ok_or_else(internal)?;
    let secret = consumption_secret(store.conn(), &consumption_id)?;
    let attested = ConsumedReceipt::attest(
        &receipt,
        &consumption_id,
        RecordDigestKey::Object {
            key_ref: &consumption_key_ref(&consumption_id),
            secret: &secret,
        },
    )
    .map_err(permit_problem)?;
    // The destination is bound HERE, from the provider binding re-read for
    // this call — never from the plan, which is what R3 changed after
    // authorization (R3-B02). The plan must already name the same origin.
    let (_, bound_binding) = read_profile(store.conn(), request.realm, request.model_profile_ref)?;
    let permit = authorize(
        Some(attested),
        &Expectation {
            execution_key: prepared.plan.execution_key(),
            subject_digest: prepared.plan.subject_digest(),
            disclosure_digest: &prepared.plan.disclosure().digest,
            driver_audience: BROKER_DRIVER_AUDIENCE,
            episode,
            endpoint_incarnation: &seam.endpoint_incarnation,
            recovery_epoch: seam.recovery_epoch,
            now: wall(now),
            already_spent,
            bound_origin: &bound_binding.endpoint,
        },
    )
    .map_err(permit_problem)?;
    // The local intersection permit, recorded once the gate has passed: it
    // carries every contributing digest AND `owner_unverified_digests`, so an
    // audit can see exactly which of byom's echoes could be re-checked here.
    store
        .conn()
        .execute(
            "UPDATE external_authorization_consumptions SET permit = ?2
             WHERE consumption_id = ?1",
            params![
                consumption_id,
                serde_json::to_string(&permit).map_err(|_| internal())?
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok((permit, consumption_id))
}

/// byom's `$domain` tag for the host-effect registration fragment.
const HOST_EFFECT_REGISTRATION_TAG: &str = "bpp-host-effect-registration-v0";

/// The host-effect registration authenticator `execution_permit_consume`
/// requires (byom R3-A02): `HMAC-SHA-256` over the `$domain`-tagged canonical
/// fragment `{host_effect_digest, host_effect_ref, intent_ref,
/// stable_execution_key}`, keyed by the **permit-channel token line** byomd
/// published for this ActIntent — a value only the addressed host holds.
///
/// It carries no key material: byomd recomputes it from the request's own
/// members plus its own token and refuses `forbidden` on a mismatch, before it
/// reads any state.
fn host_effect_credential(
    token_line: &str,
    intent_ref: &str,
    stable_execution_key: &str,
    host_effect_ref: &str,
    host_effect_digest: &DigestRef,
) -> Result<String, Problem> {
    let fragment = json!({
        "host_effect_digest": host_effect_digest,
        "host_effect_ref": host_effect_ref,
        "intent_ref": intent_ref,
        "stable_execution_key": stable_execution_key,
    });
    let preimage = tagged_canonical(HOST_EFFECT_REGISTRATION_TAG, &fragment).map_err(|e| {
        refuse(
            ProblemKind::Internal,
            "the host-effect registration fragment could not be canonicalized",
            e,
        )
    })?;
    Ok(kovee_core::family::hex(&kovee_core::family::hmac_sha256(
        token_line.as_bytes(),
        &preimage,
    )))
}

/// The `key_ref` the consumption attestation is keyed under, so an operator
/// reading a permit's `owner_receipt_provenance` can tell what keys it.
fn consumption_key_ref(consumption_id: &str) -> String {
    kovee_effects::object_key_ref("consumption", consumption_id)
}

/// The per-consumption attestation secret: domain-separated from the realm
/// object key. It is derived rather than stored because the receipt itself is
/// already durable — what the attestation adds is that only code holding the
/// daemon's realm key (never a worker-reachable path) can turn a receipt into
/// a permit.
fn consumption_secret(conn: &Connection, consumption_id: &str) -> Result<[u8; 32], Problem> {
    let realm_key = kovee_store::realm_object_key_of(conn).map_err(store_problem)?;
    Ok(kovee_core::family::hmac_sha256(
        &realm_key,
        format!("{CONSUMPTION_ATTESTATION_DOMAIN}:{consumption_id}").as_bytes(),
    ))
}

const CONSUMPTION_ATTESTATION_DOMAIN: &str = "dev.kovee.consumption-attestation.v1";

/// The durable one-shot ledger a permit's single use is claimed against
/// (D-R3-1). The claim is one conditional `UPDATE` in SQLite's autocommit, so
/// it is atomic and on disk before any byte leaves: a second permit value for
/// the same consumption finds `state = 'spent'` and sends nothing.
struct ConsumptionLedger<'a> {
    conn: &'a Connection,
}

impl SpentLedger for ConsumptionLedger<'_> {
    fn claim_single_use(&self, permit: &ExecutionPermit) -> Result<Claim, String> {
        let claimed = self
            .conn
            .execute(
                "UPDATE external_authorization_consumptions SET state = 'spent'
                 WHERE consumption_id = ?1 AND execution_key = ?2 AND state <> 'spent'",
                params![permit.consumption_ref(), permit.execution_key()],
            )
            .map_err(|e| e.to_string())?;
        Ok(if claimed == 1 {
            Claim::Claimed
        } else {
            Claim::AlreadySpent
        })
    }
}

/// The whole chain for one worker call. Every step in order, and each one a
/// refusal.
///
/// `egress` is not an arbitrary `Transport`: it converts into the sealed
/// [`Egress`], whose only variants are the daemon's own [`kovee_effects::HttpsTransport`]
/// and — under kovee-effects' `testing` feature — the recording double. A
/// production build therefore has exactly one wire to offer here (R3-B02).
#[allow(clippy::too_many_arguments)]
pub fn complete<'e>(
    store: &mut Store,
    runtime: &Runtime,
    egress: impl Into<Egress<'e>>,
    request: &CompleteRequest<'_>,
    authorization: &ActAuthorization,
    now: i64,
    fault: Fault,
) -> Result<Completion, Problem> {
    // 1. the worker's attempt binding must be current (§15.2).
    crate::invoke::check_binding(store.conn(), request.attempt_id, request.fence_epoch)?;
    // 2-5. profile, disclosure, chain.
    let (profile, binding) = read_profile(store.conn(), request.realm, request.model_profile_ref)?;
    let staged = stage(store, request, &profile, &binding, now)?;
    // 6. the prepared effect, COMMITTED.
    let prepared = prepare(
        store,
        request,
        authorization,
        &profile,
        &binding,
        &staged,
        now,
    )?;
    if fault == Fault::AbortAfterPrepare {
        // The crash-honesty point: the prepared effect is on disk, no permit
        // has been consumed, and nothing has been sent.
        std::process::abort();
    }
    // 7-8. byom consumes; the gate checks.
    let (permit, consumption_id) =
        consume_permit(store, runtime, request, authorization, &prepared, now)?;
    emit(
        store,
        request.realm,
        request.project,
        &prepared.effect_id,
        EVENT_MODEL_EFFECT_AUTHORIZED,
        json!({
            "state": EffectState::Prepared.as_str(),
            "owner_protocol": permit.owner_protocol(),
            "phase": permit.phase(),
            "owner_receipt_ref": permit.owner_receipt_ref(),
            "mandate_use_ref": permit.mandate_use_ref(),
            "max_uses": permit.max_uses(),
            "consumption_ref": permit.consumption_ref(),
            // NOT the bound origin: the destination host is not worker- or
            // event-visible state (§16.1). It lives in the stored permit,
            // where the audit needs it and a worker cannot read it.
            "permit_consumed": true,
            "dispatched": false,
        }),
        now,
    )?;
    // 9-13. the attempt row, then the one egress. The permit is HANDED OVER
    // here: `complete` cannot use it again after this line.
    dispatch_effect(
        store,
        runtime,
        egress,
        request,
        &prepared,
        permit,
        &consumption_id,
        now,
        fault,
    )
}

/// Steps 9-13: the attempt committed `dispatching` BEFORE the socket opens,
/// the credential resolved inside the broker, the one use claimed durably,
/// the one exchange, and the outcome recorded under the broker's own service
/// identity.
///
/// The permit arrives **by value** and is handed on to
/// [`kovee_effects::dispatch`], so no caller can dispatch the same one twice;
/// and the wire is the sealed [`Egress`], never an arbitrary `Transport`.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_effect<'e>(
    store: &mut Store,
    runtime: &Runtime,
    egress: impl Into<Egress<'e>>,
    request: &CompleteRequest<'_>,
    prepared: &Prepared,
    permit: ExecutionPermit,
    consumption_id: &str,
    now: i64,
    fault: Fault,
) -> Result<Completion, Problem> {
    let egress = egress.into();
    let (_, binding) = read_profile(store.conn(), request.realm, request.model_profile_ref)?;
    let credential_ref = binding.credential_ref().ok_or_else(|| {
        refuse_msg(
            ProblemKind::Invalid,
            "the provider binding has no usable credential reference",
            "credential_secret_ref must be `env:NAME` or `store:REF`; a literal key is never \
             recorded",
        )
    })?;
    // The credential is resolved HERE, in the broker, from the daemon's own
    // environment or secret table. It has never been in worker-reachable
    // state and is not part of any record below.
    let realm = request.realm.to_owned();
    let credential = {
        let conn = store.conn();
        kovee_effects::resolve(&credential_ref, |reference| {
            conn.query_row(
                "SELECT secret FROM provider_credentials WHERE credential_ref = ?1
                 AND realm_ref = ?2",
                params![reference, realm],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten()
        })
        .map_err(|e| {
            refuse(
                ProblemKind::Unavailable,
                "the provider credential is not configured",
                e,
            )
        })?
    };

    // 12. the attempt row, COMMITTED before the socket opens.
    let attempt_id = new_id("meffatt").map_err(store_problem)?;
    let ordinal = attempt_count(store.conn(), &prepared.effect_id)? + 1;
    let at = rfc3339_utc(now);
    store
        .conn()
        .execute(
            "INSERT INTO model_effect_attempts (effect_attempt_id, effect_id, attempt_ordinal,
                 consumption_ref, transport_profile, state, retry_frozen, started_at)
             VALUES (?1,?2,?3,?4,?5,?6,0,?7)",
            params![
                attempt_id,
                prepared.effect_id,
                ordinal as i64,
                consumption_id,
                egress.profile(),
                EffectState::Dispatching.as_str(),
                at,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    set_effect_state(
        store.conn(),
        &prepared.effect_id,
        EffectState::Dispatching,
        now,
    )?;
    emit(
        store,
        request.realm,
        request.project,
        &prepared.effect_id,
        EVENT_MODEL_EFFECT_DISPATCHING,
        json!({
            "state": EffectState::Dispatching.as_str(),
            "effect_attempt_id": attempt_id,
            "attempt_ordinal": ordinal,
            "transport_profile": egress.profile(),
            "permit_consumed": true,
            "dispatched": true,
        }),
        now,
    )?;
    if fault == Fault::AbortAfterDispatchRecord {
        std::process::abort();
    }

    // 13. the one use, claimed in the durable ledger inside `dispatch`, then
    //     the one exchange. The permit is moved in: this function cannot
    //     dispatch it again either.
    let outcome = {
        let ledger = ConsumptionLedger { conn: store.conn() };
        dispatch_bytes(
            &prepared.plan,
            permit,
            &egress,
            &credential,
            &ledger,
            CALL_TIMEOUT,
        )
    };
    let event_type = match outcome.state {
        EffectState::Completed => EVENT_MODEL_EFFECT_COMPLETED,
        EffectState::Ambiguous => EVENT_MODEL_EFFECT_AMBIGUOUS,
        _ => EVENT_MODEL_EFFECT_FAILED,
    };
    store
        .conn()
        .execute(
            "UPDATE model_effect_attempts SET state = ?2, retry_frozen = ?3, external_ref = ?4,
                 response_digest_hex = ?5, input_tokens = ?6, output_tokens = ?7,
                 latency_ms = ?8, observation = ?9, completed_at = ?10
             WHERE effect_attempt_id = ?1",
            params![
                attempt_id,
                outcome.state.as_str(),
                i64::from(outcome.state.retry_frozen()),
                outcome.external_ref,
                outcome.response_digest,
                outcome.usage.input_tokens as i64,
                outcome.usage.output_tokens as i64,
                outcome.latency_ms as i64,
                outcome.observation,
                rfc3339_utc(now),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    set_effect_state(store.conn(), &prepared.effect_id, outcome.state, now)?;
    // The consumption is already `spent`: `dispatch` claimed the single use
    // before it opened the socket, so a crash mid-exchange leaves it spent
    // too. Nothing to mark here.
    emit(
        store,
        request.realm,
        request.project,
        &prepared.effect_id,
        event_type,
        json!({
            "state": outcome.state.as_str(),
            "effect_attempt_id": attempt_id,
            "retry_frozen": outcome.state.retry_frozen(),
            "transport_profile": outcome.transport_profile,
            "response_digest": outcome.response_digest,
            "usage": {"input_tokens": outcome.usage.input_tokens,
                      "output_tokens": outcome.usage.output_tokens},
            "latency_ms": outcome.latency_ms,
            "observation": outcome.observation,
            "provider_ref": outcome.external_ref,
        }),
        now,
    )?;

    // 14. the metering report on byom's METER channel. Evidence from
    //     Kovee's side; the ledger move is byom's.
    let usage_reported = if outcome.usage.total() > 0 {
        report_usage(
            store,
            runtime,
            request,
            &prepared.effect_id,
            &attempt_id,
            outcome.usage,
            now,
        )?
    } else {
        false
    };

    Ok(Completion {
        effect_id: prepared.effect_id.clone(),
        effect_attempt_id: attempt_id,
        state: outcome.state,
        text: outcome.reply.as_ref().map(|r| r.text.clone()),
        usage: outcome.usage,
        model: outcome.reply.as_ref().and_then(|r| r.model.clone()),
        stop_reason: outcome.reply.as_ref().and_then(|r| r.stop_reason.clone()),
        external_ref: outcome.external_ref,
        disclosure_manifest_ref: prepared.plan.disclosure().disclosure_id.clone(),
        provider_context_manifest_ref: prepared.plan.context_manifest().provider_context_id.clone(),
        latency_ms: outcome.latency_ms,
        transport_profile: outcome.transport_profile.to_owned(),
        observation: outcome.observation,
        retry_frozen: outcome.state.retry_frozen(),
        usage_reported,
    })
}

// ------------------------------------------------------------- metering ----

/// `usage_report` on byom's METER channel (`rmt1.`), carrying the measured
/// token counts — and the SAME two-sided settlement saga on Kovee's own
/// subordinate reservation (R3-U02, disposition D-R3-2).
///
/// This path used to record `model_usage_reports` and stop. byom settled its
/// parent from the report while Kovee's subordinate stayed `confirmed,
/// charged = 0, released_lifetime = 0` — the scripted run charged byom 44
/// against a Kovee ledger that had never moved. A stable report key still
/// makes a re-report a replay rather than a second charge; what is new is that
/// the local half of the settlement now happens at all, in the saga order:
/// cap locally, record durably, call byom, apply byom's number.
fn report_usage(
    store: &mut Store,
    runtime: &Runtime,
    request: &CompleteRequest<'_>,
    effect_id: &str,
    attempt_id: &str,
    usage: Usage,
    now: i64,
) -> Result<bool, Problem> {
    let Some(key) = request.stable_binding_key else {
        // Nothing to meter against: an ungoverned call has no Episode.
        return Ok(false);
    };
    let bound = crate::episode::read_binding(store.conn(), key)?.ok_or_else(not_found)?;
    let seam = crate::episode::seam_of_binding(store.conn(), request.realm)?;
    let report_key = format!("kovee-model-usage-{effect_id}");
    if store
        .conn()
        .query_row(
            "SELECT 1 FROM model_usage_reports WHERE stable_report_key = ?1",
            [&report_key],
            |_| Ok(()),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?
        .is_some()
    {
        return Ok(true);
    }
    let token = runtime.token(Workload::Meter, &bound.episode_ref)?;
    let result = runtime.call(
        &token,
        &json!({
            "version": BPP_VERSION,
            "op": "usage_report",
            "meta": {
                "request_id": format!("kovee-usg-{effect_id}"),
                "idempotency_key": report_key,
                "expected_endpoint_incarnation": seam.endpoint_incarnation,
                "expected_recovery_epoch": seam.recovery_epoch,
            },
            "episode_ref": bound.episode_ref,
            "generation": bound.record.generation,
            "byom_attempt_ref": bound.byom_attempt_ref,
            "byom_fence_epoch": bound.fences.byom,
            "kovee_invocation_fence": bound.fences.kovee,
            "source": crate::episode::SOURCE_METER,
            "stable_report_key": report_key,
            "quantities": [
                {"dimension": "input_tokens", "unit": "token", "amount": usage.input_tokens},
                {"dimension": "output_tokens", "unit": "token", "amount": usage.output_tokens},
            ],
            "meter_ref": format!("kovee-model-broker-meter-{}", request.realm),
            "meter_attestation_ref": format!("kovee-model-meter-attestation-{attempt_id}"),
            "stable_settlement_key": format!("kovee-model-settle-{effect_id}"),
            "charged_quantities": [
                {"dimension": "unit", "unit": "unit", "amount": usage.total()},
            ],
        }),
    )?;
    let settled = result
        .pointer("/settlement/settled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    store
        .conn()
        .execute(
            "INSERT INTO model_usage_reports (stable_report_key, effect_attempt_id, episode_ref,
                 input_tokens, output_tokens, settled_by_byom, result, reported_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                report_key,
                attempt_id,
                bound.episode_ref,
                usage.input_tokens as i64,
                usage.output_tokens as i64,
                i64::from(settled),
                result.to_string(),
                rfc3339_utc(now),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    emit(
        store,
        request.realm,
        request.project,
        effect_id,
        EVENT_MODEL_USAGE_REPORTED,
        json!({
            "state": "reported",
            "effect_attempt_id": attempt_id,
            "stable_report_key": report_key,
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "settled_by_byom": settled,
        }),
        now,
    )?;
    Ok(true)
}

// -------------------------------------------- recovery and reconciliation ----

/// Startup sweep: any attempt the process left `dispatching` resolves to
/// `ambiguous` with retry frozen. A request may have been transmitted, and
/// "no receipt observed" is not proof of failure (§16.1).
pub fn recover_dispatching(store: &mut Store, now: i64) -> Result<usize, Problem> {
    // Whatever the process was doing when it died, that permit's use is
    // gone: bytes may have left. The claim normally happens inside
    // `dispatch`, but a crash between the attempt row and the claim would
    // otherwise leave the consumption reusable, so the sweep spends it too.
    store
        .conn()
        .execute(
            "UPDATE external_authorization_consumptions SET state = 'spent'
             WHERE state <> 'spent' AND consumption_id IN
                 (SELECT consumption_ref FROM model_effect_attempts
                  WHERE state = 'dispatching')",
            [],
        )
        .map_err(|e| store_problem(e.into()))?;
    let rows: Vec<(String, String)> = {
        let conn = store.conn();
        let mut stmt = conn
            .prepare(
                "SELECT a.effect_attempt_id, a.effect_id FROM model_effect_attempts a
                 WHERE a.state = 'dispatching'",
            )
            .map_err(|e| store_problem(e.into()))?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| store_problem(e.into()))?;
        let mut out = Vec::new();
        for row in mapped {
            out.push(row.map_err(|e| store_problem(e.into()))?);
        }
        out
    };
    for (attempt_id, effect_id) in &rows {
        let next = kovee_effects::next(
            EffectState::Dispatching,
            kovee_effects::EffectEvent::RecoverAfterCrash,
        )
        .map_err(|_| internal())?;
        store
            .conn()
            .execute(
                "UPDATE model_effect_attempts SET state = ?2, retry_frozen = 1,
                     observation = ?3, completed_at = ?4 WHERE effect_attempt_id = ?1",
                params![
                    attempt_id,
                    next.as_str(),
                    "the process died while dispatching; a request may have been transmitted \
                     and the provider may have been billed",
                    rfc3339_utc(now),
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        set_effect_state(store.conn(), effect_id, next, now)?;
        let realm = effect_realm(store.conn(), effect_id)?;
        emit(
            store,
            &realm,
            None,
            effect_id,
            EVENT_MODEL_EFFECT_AMBIGUOUS,
            json!({
                "state": next.as_str(),
                "effect_attempt_id": attempt_id,
                "retry_frozen": true,
                "recovered_at_startup": true,
            }),
            now,
        )?;
    }
    Ok(rows.len())
}

/// Operator reconciliation of one ambiguous attempt: records the
/// observation that resolves it and clears the retry freeze. It cannot
/// unconsume the byom permit — another attempt requires a new act
/// (§16.1).
pub fn reconcile(
    store: &mut Store,
    effect_attempt_id: &str,
    resolution: EffectState,
    observation: &str,
    now: i64,
) -> Result<(), Problem> {
    if !matches!(resolution, EffectState::Completed | EffectState::Failed) {
        return Err(refuse_msg(
            ProblemKind::Invalid,
            "an ambiguous attempt resolves to completed or failed",
            "reconciliation records what was observed; it never invents a third outcome",
        ));
    }
    let row: Option<(String, String)> = store
        .conn()
        .query_row(
            "SELECT effect_id, state FROM model_effect_attempts WHERE effect_attempt_id = ?1",
            [effect_attempt_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    let (effect_id, state) = row.ok_or_else(not_found)?;
    if state != EffectState::Ambiguous.as_str() {
        return Err(refuse_msg(
            ProblemKind::Forbidden,
            "only an ambiguous attempt is reconciled",
            "a completed, failed or canceled attempt is already resolved",
        ));
    }
    store
        .conn()
        .execute(
            "UPDATE model_effect_attempts SET state = ?2, retry_frozen = 0, reconciliation = ?3
             WHERE effect_attempt_id = ?1",
            params![effect_attempt_id, resolution.as_str(), observation],
        )
        .map_err(|e| store_problem(e.into()))?;
    set_effect_state(store.conn(), &effect_id, resolution, now)?;
    let realm = effect_realm(store.conn(), &effect_id)?;
    emit(
        store,
        &realm,
        None,
        &effect_id,
        EVENT_MODEL_EFFECT_RECONCILED,
        json!({
            "state": resolution.as_str(),
            "effect_attempt_id": effect_attempt_id,
            "retry_frozen": false,
            "observation": observation,
        }),
        now,
    )?;
    Ok(())
}

// ------------------------------------------------------------ row access ----

/// One stored model effect, for reads and for the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectRow {
    pub effect_id: String,
    pub state: String,
    pub execution_key: String,
    pub external_idempotency_key: String,
    pub act_intent_ref: String,
    pub disclosure_manifest_ref: String,
    pub provider_context_ref: String,
    pub episode_ref: Option<String>,
}

pub fn read_effect(conn: &Connection, effect_id: &str) -> Result<Option<EffectRow>, Problem> {
    conn.query_row(
        "SELECT effect_id, state, execution_key, external_idempotency_key, act_intent_ref,
                disclosure_manifest_ref, provider_context_ref, episode_ref
         FROM model_effects WHERE effect_id = ?1",
        [effect_id],
        |r| {
            Ok(EffectRow {
                effect_id: r.get(0)?,
                state: r.get(1)?,
                execution_key: r.get(2)?,
                external_idempotency_key: r.get(3)?,
                act_intent_ref: r.get(4)?,
                disclosure_manifest_ref: r.get(5)?,
                provider_context_ref: r.get(6)?,
                episode_ref: r.get(7)?,
            })
        },
    )
    .optional()
    .map_err(|e| store_problem(e.into()))
}

/// The effect under one execution key, if any.
pub fn effect_by_execution_key(
    conn: &Connection,
    execution_key: &str,
) -> Result<Option<EffectRow>, Problem> {
    let id: Option<String> = conn
        .query_row(
            "SELECT effect_id FROM model_effects WHERE execution_key = ?1",
            [execution_key],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    match id {
        Some(id) => read_effect(conn, &id),
        None => Ok(None),
    }
}

/// The stored disclosure manifest — the record
/// `disclosure_manifest_show` returns.
pub fn read_disclosure(
    conn: &Connection,
    disclosure_id: &str,
) -> Result<Option<DisclosureManifest>, Problem> {
    let text: Option<String> = conn
        .query_row(
            "SELECT record FROM disclosure_manifests WHERE disclosure_id = ?1",
            [disclosure_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    Ok(text.and_then(|t| serde_json::from_str(&t).ok()))
}

/// The stored provider-context manifest — the exact chain
/// `provider_context_manifest_show` returns. It never carries a credential.
pub fn read_provider_context(
    conn: &Connection,
    provider_context_id: &str,
) -> Result<Option<ProviderContextManifest>, Problem> {
    let text: Option<String> = conn
        .query_row(
            "SELECT record FROM provider_context_manifests WHERE provider_context_id = ?1",
            [provider_context_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    Ok(text.and_then(|t| serde_json::from_str(&t).ok()))
}

pub fn attempt_count(conn: &Connection, effect_id: &str) -> Result<u64, Problem> {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM model_effect_attempts WHERE effect_id = ?1",
            [effect_id],
            |r| r.get(0),
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok(n.max(0) as u64)
}

fn read_consumption(
    conn: &Connection,
    execution_key: &str,
) -> Result<Option<(String, ExecutionConsumptionReceipt)>, Problem> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT consumption_id, receipt FROM external_authorization_consumptions
             WHERE execution_key = ?1",
            [execution_key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    match row {
        Some((id, text)) => {
            // The SAME door the live reply uses: Kovee's durable copy of
            // byom's reply re-enters through `from_result`, because the
            // receipt type has no public `Deserialize` to go round it.
            let stored: Value = serde_json::from_str(&text).map_err(|_| internal())?;
            let receipt = ExecutionConsumptionReceipt::from_result(&stored).map_err(|e| {
                refuse(
                    ProblemKind::Internal,
                    "the stored consumption receipt is not the shape Kovee can honor",
                    e,
                )
            })?;
            Ok(Some((id, receipt)))
        }
        None => Ok(None),
    }
}

fn store_consumption(
    store: &mut Store,
    prepared: &Prepared,
    receipt: &ExecutionConsumptionReceipt,
    now: i64,
) -> Result<(), Problem> {
    store
        .conn()
        .execute(
            "INSERT INTO external_authorization_consumptions (consumption_id, effect_id,
                 owner_protocol, phase, owner_endpoint_ref, owner_intent_ref, execution_key,
                 owner_receipt_ref, owner_receipt_digest, mandate_use_ref, permit, receipt,
                 replayed, consumed_at, state)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,'consumed')",
            params![
                new_id("eac").map_err(store_problem)?,
                prepared.effect_id,
                OWNER_PROTOCOL_BYOM,
                PHASE_PRE_EGRESS,
                receipt.byom_endpoint_ref(),
                receipt.intent_ref(),
                receipt.stable_execution_key(),
                receipt.receipt_id(),
                receipt
                    .digest()
                    .map(|d| d.value_hex.clone())
                    .unwrap_or_default(),
                receipt.mandate_use_ref(),
                // The local intersection permit is minted by the gate, so it
                // is stored once the gate has passed; the receipt is stored
                // NOW, because byom has already spent the use.
                "",
                serde_json::to_string(receipt).map_err(|_| internal())?,
                i64::from(receipt.is_replay()),
                rfc3339_utc(now),
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

fn set_effect_state(
    conn: &Connection,
    effect_id: &str,
    state: EffectState,
    now: i64,
) -> Result<(), Problem> {
    conn.execute(
        "UPDATE model_effects SET state = ?2, updated_at = ?3 WHERE effect_id = ?1",
        params![effect_id, state.as_str(), rfc3339_utc(now)],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

fn effect_realm(conn: &Connection, effect_id: &str) -> Result<String, Problem> {
    conn.query_row(
        "SELECT realm_ref FROM model_effects WHERE effect_id = ?1",
        [effect_id],
        |r| r.get(0),
    )
    .map_err(|e| store_problem(e.into()))
}

// -------------------------------------------------------------- helpers ----

/// One broker object's per-object erasure secret, unwrapped under the realm
/// key (D-R1-2). Absent means erased: the digests it keyed can no longer be
/// re-derived by anyone, including a holder of the realm key — and the
/// broker then refuses rather than pretending the record still verifies.
fn object_secret(
    conn: &Connection,
    table: &str,
    id_column: &str,
    id: &str,
    key_ref: &str,
) -> Result<[u8; 32], Problem> {
    // The table and column names are compile-time literals from this module,
    // never caller input.
    let sql = format!("SELECT object_secret FROM {table} WHERE {id_column} = ?1");
    let wrapped: Option<Vec<u8>> = conn
        .query_row(&sql, [id], |r| r.get(0))
        .optional()
        .map_err(|e| store_problem(e.into()))?
        .flatten();
    let wrapped = wrapped.ok_or_else(|| {
        refuse_msg(
            ProblemKind::Forbidden,
            "this record's erasure secret is destroyed",
            "the local_erasure_safe digest it keyed can no longer be re-derived (D-R1-2)",
        )
    })?;
    let realm_key = kovee_store::realm_object_key_of(conn).map_err(store_problem)?;
    kovee_store::objkey::unwrap(&realm_key, key_ref, &wrapped).map_err(store_problem)
}

fn derive_id(prefix: &str, tag: &str, inputs: &Value) -> Result<String, Problem> {
    let preimage = tagged_canonical(tag, inputs).map_err(|_| internal())?;
    let hex = kovee_core::family::sha256_hex(&preimage);
    Ok(format!("{prefix}-{}", &hex[..32]))
}

/// A bounded rendering of one byom reply, for a problem detail.
fn bounded(value: &Value) -> String {
    value.to_string().chars().take(1024).collect()
}

fn digest_text(digest: &DigestRef) -> Result<String, Problem> {
    serde_json::to_string(digest).map_err(|_| internal())
}

fn wall(now: i64) -> i64 {
    if now == 0 {
        kovee_core::time::unix_now()
    } else {
        now
    }
}

fn refuse(kind: ProblemKind, title: &str, detail: impl std::fmt::Display) -> Problem {
    Problem::new(kind, title).with_detail(detail.to_string())
}

fn refuse_msg(kind: ProblemKind, title: &str, detail: &str) -> Problem {
    Problem::new(kind, title).with_detail(detail)
}

/// Maps a permit refusal to its §11.7 problem kind. Every one of them is a
/// refusal to call a provider, and the detail names exactly which check
/// failed — that is the audit record.
fn permit_problem(error: kovee_effects::PermitError) -> Problem {
    use kovee_effects::PermitError as E;
    let kind = match &error {
        E::NoPermit | E::SpentPermit | E::NotOneShot(_) => ProblemKind::Forbidden,
        E::WrongExecutionKey { .. }
        | E::WrongAudience { .. }
        | E::SubjectMismatch
        | E::DisclosureMismatch
        | E::EpisodeMismatch { .. }
        | E::Unbound => ProblemKind::StaleRevision,
        E::StaleFence => ProblemKind::StaleLease,
        E::Expired(_) | E::UnreadableExpiry(_) => ProblemKind::Forbidden,
        E::WrongEndpoint => ProblemKind::StaleRevision,
        E::Malformed(_) => ProblemKind::Unavailable,
        // A receipt Kovee cannot attest against its own committed consumption
        // is a receipt it will not authorize. These are internal wiring
        // faults, not the caller's: the broker refuses rather than dispatching
        // on an unattested value.
        E::UnkeyedProvenance | E::Unattestable => ProblemKind::Internal,
    };
    Problem::new(kind, "the model call is not authorized to leave").with_detail(error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn emit(
    store: &mut Store,
    realm: &str,
    project: Option<&str>,
    effect_id: &str,
    event_type: &str,
    payload: Value,
    now: i64,
) -> Result<(), Problem> {
    let scope = kovee_store::CommandScope {
        actor_scope: format!("owner/{BROKER_ACTOR_REF}/{realm}"),
        operation: format!("model_effect_event:{event_type}"),
        idempotency_key: format!("{effect_id}:{event_type}"),
        request_digest: "0".repeat(64),
    };
    let effect_id = effect_id.to_owned();
    let event_type = event_type.to_owned();
    // Realm-scoped, like the episode-binding events: a model effect is not a
    // space object, so it gets its own stream and no project sequence. The
    // project is recorded on the `model_effects` row instead.
    let _ = project;
    let outcome =
        store.command_transaction(&scope, now, kovee_store::CrashHooks::NONE, move |txn| {
            txn.audit(
                "model-effect.transition",
                &format!("effect={effect_id} event={event_type}"),
            );
            txn.append_event(NewEvent {
                stream_id: effect_id.clone(),
                project_id: None,
                actor_ref: Some(BROKER_ACTOR_REF.to_owned()),
                event_type: event_type.clone(),
                schema_ref: SCHEMA_EFFECT.to_owned(),
                resource_ref: effect_id.clone(),
                resource_revision: Some(1),
                causation_ref: None,
                correlation_ref: effect_id.clone(),
                classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
                payload: payload.clone(),
            })
            .map_err(store_problem)?;
            Ok(kovee_store::Applied {
                result: json!({"effect_id": effect_id}),
                revision: None,
                event_cursor: None,
            })
        });
    crate::handlers::command_outcome_bytes(outcome)?;
    Ok(())
}
