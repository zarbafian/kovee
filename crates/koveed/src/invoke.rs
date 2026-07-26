//! One-shot direct invocation (§10.6, §15.1 scoped to the K1 personal
//! profile) and the worker surface (§23.3): claim/complete supervisor
//! operations plus the fenced attempt binding the worker-surface
//! `contribution_append`/`relation_assert`/`context_assembly_create`
//! registry operations require.
//!
//! Honesty (developer profile): there is no scheduler, lease renewal, or
//! confinement in K1 — one local worker claims one attempt per
//! invocation (deterministic attempt id, fence epoch 1), and the
//! `EnforcementEvidence`-shaped fields say `developer`/unclaimed.

use kovee_core::canonical::canonical_object_digest;
use kovee_core::envelope::{CommandMeta, RawCommand};
use kovee_core::event::{
    EVENT_INVOCATION_CLAIMED, EVENT_INVOCATION_CREATED, EVENT_INVOCATION_SUCCEEDED,
};
use kovee_core::ops;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::{ContextAssembly, Invocation};
use kovee_core::time::rfc3339_utc;
use kovee_store::{new_id, Applied, CommandScope, CrashHooks, NewEvent, Store, PERSONAL_REALM_ID};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::Deserialize;
use serde_json::Value;

use crate::handlers::{command_outcome_bytes, ok_reply, scope_digest, WORKER_SURFACE};
use crate::state::*;

/// The deployment actor a worker attempt writes as (§10.2 attribution).
pub fn deployment_actor_ref() -> String {
    format!("asstdep-{LOCAL_DEPLOYMENT_ID}")
}

/// The worker idempotency scope: keys are scoped per logical invocation
/// (§14.1 — the supervisor combines the SDK `operation_key` with the
/// invocation id), so a re-attempt replays rather than duplicating.
pub fn worker_scope(cmd: &RawCommand, invocation_id: &str) -> Result<CommandScope, Problem> {
    let meta = cmd.meta.as_ref().ok_or_else(internal)?;
    Ok(CommandScope {
        actor_scope: format!("{WORKER_SURFACE}/{invocation_id}/{PERSONAL_REALM_ID}"),
        operation: cmd.op.clone(),
        idempotency_key: meta.idempotency_key.clone(),
        request_digest: kovee_core::canonical::idempotency_request_digest(cmd, WORKER_SURFACE)
            .map_err(|_| internal())?,
    })
}

fn stale_lease(detail: &str) -> Problem {
    Problem::new(ProblemKind::StaleLease, "attempt binding is not current").with_detail(detail)
}

/// Validates the §15.2 attempt binding inside an open transaction: the
/// attempt must exist, bind this invocation, carry the current fence
/// epoch, and the invocation must still be running.
pub fn check_binding(
    conn: &Connection,
    attempt_id: &str,
    fence_epoch: u64,
) -> Result<(AttemptRow, InvocationRow), Problem> {
    let attempt = get_attempt(conn, attempt_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    if attempt.fence_epoch != fence_epoch {
        return Err(stale_lease("fence epoch is not current"));
    }
    if attempt.state != "running" {
        return Err(stale_lease("attempt is not running"));
    }
    let invocation = get_invocation(conn, &attempt.invocation_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    if invocation.state != "running" {
        return Err(stale_lease("invocation is not running"));
    }
    Ok((attempt, invocation))
}

/// The §11.2 replay authorizer a worker-surface operation hands to
/// [`Store::command_transaction_guarded`] (KV-R1): the attempt binding is
/// re-validated against CURRENT state before any stored receipt byte is
/// released, so a completed attempt or an advanced fence gets
/// `stale-lease` instead of its old reply — and re-executes nothing.
pub fn binding_authorizer(
    attempt_id: &str,
    fence_epoch: u64,
) -> impl FnOnce(&Connection) -> Result<(), Problem> {
    let attempt_id = attempt_id.to_owned();
    move |conn| check_binding(conn, &attempt_id, fence_epoch).map(drop)
}

// ------------------------------------------------------ invocation_create ----

pub fn invocation_create(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::InvocationCreateArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        get_project(txn.conn(), &project_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        let deployment = get_deployment(txn.conn(), &args.assistant_deployment_id)
            .map_err(store_problem)?
            .filter(|d| d.status == "active")
            .ok_or_else(not_found)?;
        if args.assistant_deployment_revision != deployment.revision {
            // Dependency invalidation: the caller pinned a stale
            // deployment revision.
            return Err(stale_revision(deployment.revision));
        }
        // The exact assembly binding (§10.8: the invocation input is one
        // immutable ContextAssembly).
        let assembly: Option<ContextAssembly> = match &args.context_assembly_ref {
            None => None,
            Some(assembly_ref) => {
                let (owner_project, record) = get_assembly_record(txn.conn(), assembly_ref)
                    .map_err(store_problem)?
                    .ok_or_else(not_found)?;
                if owner_project != project_id {
                    return Err(not_found());
                }
                let assembly: ContextAssembly =
                    serde_json::from_value(record).map_err(|_| internal())?;
                if let Some(digest) = &args.context_assembly_digest {
                    if *digest != assembly.digest {
                        return Err(stale_revision(1)
                            .with_detail("context_assembly_digest does not match the assembly"));
                    }
                }
                if let Some(space_id) = &args.space_id {
                    if *space_id != assembly.space_id {
                        return Err(not_found());
                    }
                }
                Some(assembly)
            }
        };
        if let Some(space_id) = &args.space_id {
            visible_space(txn.conn(), &project_id, space_id)?;
        }
        let invocation_id = new_id("inv").map_err(store_problem)?;
        let manifest_id = new_id("inman").map_err(store_problem)?;
        let digest_of = |kind: &str, value: &Value| -> Result<String, Problem> {
            let (_, hexd) = canonical_object_digest(kind, INVOCATION_SCHEMA_REF, value)
                .map_err(|_| internal())?;
            Ok(hexd)
        };
        let config_digest =
            digest_of("kovee-effective-config", &serde_json::json!({"config": {}}))?;
        let secrets_digest =
            digest_of("kovee-secret-bindings", &serde_json::json!({"secrets": []}))?;
        let policy_digest = digest_of(
            "kovee-effective-policy",
            &serde_json::json!({"policy": "developer-local", "confinement": "unclaimed"}),
        )?;
        let (trigger_ref, trigger_digest) = match &assembly {
            Some(a) => (a.assembly_id.clone(), a.digest.clone()),
            None => {
                let digest = digest_of(
                    "kovee-manual-trigger",
                    &serde_json::json!({"invocation_id": invocation_id}),
                )?;
                (format!("manual-{invocation_id}"), digest)
            }
        };
        let created_at = txn.now_ts();
        // The §10.6 input manifest: the exact trigger/context/profile
        // snapshot this invocation was created with.
        let mut manifest = serde_json::json!({
            "input_manifest_id": manifest_id,
            "revision": 1,
            "invocation_id": invocation_id,
            "trigger_ref": trigger_ref,
            "trigger_digest": trigger_digest,
            "space_id": args.space_id,
            "branch_id": args.branch_id,
            "frontier_ref": assembly.as_ref().map(|a| a.frontier_ref.clone()),
            "frontier_digest": assembly.as_ref().map(|a| a.frontier_digest.clone()),
            "context_assembly_ref": args.context_assembly_ref,
            "context_assembly_digest": assembly.as_ref().map(|a| a.digest.clone()),
            "ordered_input_refs": assembly.as_ref().map(|a| a.items.clone()).unwrap_or_default(),
            "artifact_refs": [],
            "assistant_revision_id": deployment.assistant_revision_id,
            "deployment_revision": deployment.revision,
            "config_digest": config_digest,
            "secret_binding_set_digest": secrets_digest,
            "policy_digest": policy_digest,
            "model_tool_profile_bindings": [],
            "disclosure_rules_digest": args.disclosure_rules_digest,
            "deadline": args.deadline,
            "cancellation_policy": "none",
            "resource_limits": {},
            "budget_reservation_set_ref": args.budget_reservation_set_ref,
            "ancestry": [],
            "authorization_dependency_set_ref": crate::space_ops::AUTHZ_DEP_SET_REF,
            "authority_digest": digest_of(
                "kovee-authority",
                &serde_json::json!({
                    "actor": kovee_store::OWNER_ACTOR_REF,
                    "dependency_set": crate::space_ops::AUTHZ_DEP_SET_REF,
                    "operation": "invocation_create",
                }),
            )?,
            "created_at": created_at,
        });
        let manifest_digest = digest_of("kovee-input-manifest", &manifest)?;
        manifest["digest"] = Value::String(manifest_digest.clone());
        let invocation = Invocation {
            invocation_id: invocation_id.clone(),
            realm_id: txn.realm_id().to_owned(),
            project_id: project_id.clone(),
            space_id: args.space_id.clone(),
            branch_id: args.branch_id.clone(),
            assistant_deployment_id: deployment.deployment_id.clone(),
            assistant_deployment_revision: deployment.revision,
            assistant_revision_id: deployment.assistant_revision_id.clone(),
            effective_config_ref: "cfg-local-dev".to_owned(),
            effective_config_digest: config_digest,
            secret_binding_set_ref: "secrets-none".to_owned(),
            secret_binding_set_digest: secrets_digest,
            effective_policy_digest: policy_digest,
            // Labeled honesty: unclaimed confinement.
            effective_security_profile: deployment.security_profile.clone(),
            rollout_decision_ref: "rollout-local-dev".to_owned(),
            trigger_ref,
            trigger_digest,
            context_assembly_ref: args.context_assembly_ref.clone(),
            context_assembly_digest: assembly.as_ref().map(|a| a.digest.clone()),
            input_manifest_ref: manifest_id.clone(),
            input_digest: manifest_digest,
            correlation_ref: meta.request_id.clone(),
            causation_ref: meta.causation_event_ref.clone(),
            commitment_ref: None,
            work_realization_ref: None,
            state: "queued".to_owned(),
            revision: 1,
            priority: args.priority.unwrap_or(0),
            not_before: args.not_before.clone().unwrap_or_else(|| rfc3339_utc(now)),
            deadline: args.deadline.clone(),
            max_attempts: args.max_attempts.unwrap_or(1),
            budget_reservation_set_ref: args.budget_reservation_set_ref.clone(),
            created_at: created_at.clone(),
            terminal_at: None,
        };
        let record = serde_json::to_value(&invocation).map_err(|_| internal())?;
        txn.conn()
            .execute(
                "INSERT INTO invocations (invocation_id, realm_id, project_id,
                     space_id, branch_id, context_assembly_ref, state, revision,
                     record, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', 1, ?7, ?8)",
                params![
                    invocation.invocation_id,
                    invocation.realm_id,
                    invocation.project_id,
                    invocation.space_id,
                    invocation.branch_id,
                    invocation.context_assembly_ref,
                    serde_json::to_string(&record).map_err(|_| internal())?,
                    invocation.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        txn.conn()
            .execute(
                "INSERT INTO invocation_input_manifests (input_manifest_id,
                     invocation_id, record, digest, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    manifest_id,
                    invocation.invocation_id,
                    serde_json::to_string(&manifest).map_err(|_| internal())?,
                    invocation.input_digest,
                    invocation.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let event = txn
            .append_event(NewEvent {
                stream_id: invocation_id.clone(),
                project_id: Some(project_id.clone()),
                actor_ref: None,
                event_type: EVENT_INVOCATION_CREATED.to_owned(),
                schema_ref: INVOCATION_SCHEMA_REF.to_owned(),
                resource_ref: invocation_id.clone(),
                resource_revision: Some(1),
                causation_ref: meta.causation_event_ref.clone(),
                correlation_ref: meta.request_id.clone(),
                classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
                payload: serde_json::json!({
                    "invocation_id": invocation_id,
                    "state": "queued",
                    "assistant_deployment_id": invocation.assistant_deployment_id,
                    "context_assembly_ref": invocation.context_assembly_ref,
                }),
            })
            .map_err(store_problem)?;
        txn.audit(
            "command.invocation_created",
            &format!("invocation={invocation_id};{}", scope_digest(&meta)),
        );
        let cursor = txn
            .mint_project_cursor(&project_id, event.project_sequence.unwrap_or(0))
            .map_err(store_problem)?;
        Ok(Applied {
            result: record,
            revision: Some(1),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

// -------------------------------------------------------- invocation_show ----

pub fn invocation_show(
    store: &Store,
    project_id: &str,
    args: &ops::InvocationShowArgs,
) -> Result<Vec<u8>, Problem> {
    let invocation = get_invocation(store.conn(), &args.invocation_id)
        .map_err(store_problem)?
        .filter(|i| i.project_id == project_id)
        .ok_or_else(not_found)?;
    let revision = invocation.revision;
    ok_reply(invocation.record, Some(revision))
}

// ---------------------------------------------- worker: invocation_claim ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationClaimArgs {
    pub invocation_id: String,
}

/// `invocation_claim` (worker supervisor protocol, §23.3): binds ONE
/// deterministic attempt per invocation (K1: ordinal 1, fence epoch 1)
/// and returns the invocation, the exact bound assembly, its pinned
/// frontier, and the materialized items — everything the one-shot worker
/// may see. Idempotent under the §14.1 operation key; a re-claim after a
/// crash returns the same attempt binding.
pub fn invocation_claim(
    store: &mut Store,
    scope: CommandScope,
    args: InvocationClaimArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    // KV-R1: the claim's own current-resource check is also its replay
    // authorizer — a re-claim of a terminated invocation is refused, not
    // answered from the stored receipt.
    let replay_invocation = args.invocation_id.clone();
    let outcome = store.command_transaction_guarded(
        &scope,
        now,
        hooks,
        move |conn| claim_still_authorized(conn, &replay_invocation),
        move |txn| {
            let invocation = get_invocation(txn.conn(), &args.invocation_id)
                .map_err(store_problem)?
                .ok_or_else(not_found)?;
            if matches!(invocation.state.as_str(), "canceled" | "failed") {
                return Err(stale_lease("invocation is terminal"));
            }
            // Deterministic K1 attempt: the same id across re-claims, so a
            // retried worker replays instead of forking a second writer.
            let attempt_id = format!("att-{}", invocation.invocation_id);
            let existing = get_attempt(txn.conn(), &attempt_id).map_err(store_problem)?;
            let attempt = match existing {
                Some(attempt) => attempt,
                None => {
                    txn.conn()
                        .execute(
                            "INSERT INTO invocation_attempts (attempt_id, invocation_id,
                             ordinal, worker_instance_id, fence_epoch, state,
                             lease_expires_at, started_at, ended_at, result_ref)
                         VALUES (?1, ?2, 1, 'worker-local', 1, 'running', NULL,
                             ?3, NULL, NULL)",
                            params![attempt_id, invocation.invocation_id, txn.now_ts()],
                        )
                        .map_err(|e| store_problem(e.into()))?;
                    AttemptRow {
                        attempt_id: attempt_id.clone(),
                        invocation_id: invocation.invocation_id.clone(),
                        ordinal: 1,
                        fence_epoch: 1,
                        state: "running".to_owned(),
                    }
                }
            };
            let mut record = invocation.record.clone();
            if matches!(invocation.state.as_str(), "queued" | "claimed") {
                record["state"] = Value::String("running".to_owned());
                record["revision"] = Value::from(invocation.revision + 1);
                txn.conn()
                    .execute(
                        "UPDATE invocations SET state = 'running',
                         revision = revision + 1, record = ?2
                     WHERE invocation_id = ?1",
                        params![
                            invocation.invocation_id,
                            serde_json::to_string(&record).map_err(|_| internal())?
                        ],
                    )
                    .map_err(|e| store_problem(e.into()))?;
                // §10.2: the deployment becomes an addressable participant
                // of the space it will write into (contributor role).
                if let Some(space_id) = &invocation.space_id {
                    let participant_id = new_id("part").map_err(store_problem)?;
                    txn.conn()
                        .execute(
                            "INSERT OR IGNORE INTO space_participants (participant_id,
                             space_id, subject_ref, subject_revision, kind, role,
                             authority_source_ref, status, revision)
                         VALUES (?1, ?2, ?3, 1, 'assistant_deployment',
                             'contributor', ?4, 'active', 1)",
                            params![
                                participant_id,
                                space_id,
                                deployment_actor_ref(),
                                format!("invocation:{}", invocation.invocation_id),
                            ],
                        )
                        .map_err(|e| store_problem(e.into()))?;
                }
                txn.append_event(NewEvent {
                    stream_id: invocation.invocation_id.clone(),
                    project_id: Some(invocation.project_id.clone()),
                    actor_ref: Some(deployment_actor_ref()),
                    event_type: EVENT_INVOCATION_CLAIMED.to_owned(),
                    schema_ref: INVOCATION_SCHEMA_REF.to_owned(),
                    resource_ref: invocation.invocation_id.clone(),
                    resource_revision: Some(invocation.revision + 1),
                    causation_ref: meta.causation_event_ref.clone(),
                    correlation_ref: meta.request_id.clone(),
                    classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
                    payload: serde_json::json!({
                        "invocation_id": invocation.invocation_id,
                        "state": "running",
                        "attempt_id": attempt.attempt_id,
                        "fence_epoch": attempt.fence_epoch,
                    }),
                })
                .map_err(store_problem)?;
            }
            // Materialize the bound context: the assembly record, its pinned
            // frontier, and each included contribution (re-authorized here —
            // an assembly is never a bearer capability, §10.8).
            let mut assembly_value = Value::Null;
            let mut frontier_value = Value::Null;
            let mut items = Vec::new();
            if let Some(assembly_ref) = &invocation.context_assembly_ref {
                let (_, assembly_record) = get_assembly_record(txn.conn(), assembly_ref)
                    .map_err(store_problem)?
                    .ok_or_else(not_found)?;
                let assembly: ContextAssembly =
                    serde_json::from_value(assembly_record.clone()).map_err(|_| internal())?;
                let frontier = get_frontier(txn.conn(), &assembly.frontier_ref)
                    .map_err(store_problem)?
                    .ok_or_else(not_found)?;
                for item in &assembly.items {
                    let contribution = get_contribution(txn.conn(), &item.object_ref)
                        .map_err(store_problem)?
                        .filter(|c| c.space_id == assembly.space_id)
                        .ok_or_else(|| {
                            Problem::new(
                                ProblemKind::Unavailable,
                                "assembly is no longer materializable",
                            )
                        })?;
                    if contribution.content_digest != item.digest {
                        return Err(Problem::new(
                            ProblemKind::Unavailable,
                            "assembly is no longer materializable",
                        ));
                    }
                    items.push(serde_json::to_value(&contribution).map_err(|_| internal())?);
                }
                frontier_value = serde_json::to_value(&frontier).map_err(|_| internal())?;
                assembly_value = assembly_record;
            }
            txn.audit(
                "command.invocation_claimed",
                &format!(
                    "invocation={};attempt={};{}",
                    invocation.invocation_id,
                    attempt.attempt_id,
                    scope_digest(&meta)
                ),
            );
            Ok(Applied {
                result: serde_json::json!({
                    "invocation": record,
                    "attempt_id": attempt.attempt_id,
                    "fence_epoch": attempt.fence_epoch,
                    "assembly": assembly_value,
                    "frontier": frontier_value,
                    "items": items,
                }),
                revision: None,
                event_cursor: None,
            })
        },
    );
    command_outcome_bytes(outcome)
}

/// The replay authorization of `invocation_claim`: the invocation must
/// still exist and must not be terminal.
fn claim_still_authorized(conn: &Connection, invocation_id: &str) -> Result<(), Problem> {
    let invocation = get_invocation(conn, invocation_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    if matches!(invocation.state.as_str(), "canceled" | "failed") {
        return Err(stale_lease("invocation is terminal"));
    }
    Ok(())
}

// ------------------------------------------- worker: invocation_complete ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationCompleteArgs {
    pub invocation_id: String,
    pub attempt_id: String,
    pub fence_epoch: u64,
    #[serde(default)]
    pub result_ref: Option<String>,
}

/// `invocation_complete` (worker supervisor protocol): the fenced
/// attempt reports success; the invocation becomes terminal exactly once.
pub fn invocation_complete(
    store: &mut Store,
    scope: CommandScope,
    args: InvocationCompleteArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    // KV-R1: the fenced binding is re-checked before stored bytes are
    // released, so a completed attempt or an advanced fence cannot
    // collect its old success receipt.
    let replay_args = args.clone();
    let outcome = store.command_transaction_guarded(
        &scope,
        now,
        hooks,
        move |conn| {
            let (attempt, invocation) =
                check_binding(conn, &replay_args.attempt_id, replay_args.fence_epoch)?;
            if attempt.invocation_id != replay_args.invocation_id
                || invocation.invocation_id != replay_args.invocation_id
            {
                return Err(stale_lease("attempt does not bind this invocation"));
            }
            Ok(())
        },
        move |txn| {
            let (attempt, invocation) =
                check_binding(txn.conn(), &args.attempt_id, args.fence_epoch)?;
            if attempt.invocation_id != args.invocation_id
                || invocation.invocation_id != args.invocation_id
            {
                return Err(stale_lease("attempt does not bind this invocation"));
            }
            let mut record = invocation.record.clone();
            let now_ts = txn.now_ts();
            record["state"] = Value::String("succeeded".to_owned());
            record["revision"] = Value::from(invocation.revision + 1);
            record["terminal_at"] = Value::String(now_ts.clone());
            txn.conn()
                .execute(
                    "UPDATE invocations SET state = 'succeeded', revision = revision + 1,
                     record = ?2
                 WHERE invocation_id = ?1",
                    params![
                        invocation.invocation_id,
                        serde_json::to_string(&record).map_err(|_| internal())?
                    ],
                )
                .map_err(|e| store_problem(e.into()))?;
            txn.conn()
                .execute(
                    "UPDATE invocation_attempts SET state = 'succeeded', ended_at = ?2,
                     result_ref = ?3
                 WHERE attempt_id = ?1",
                    params![attempt.attempt_id, now_ts, args.result_ref],
                )
                .map_err(|e| store_problem(e.into()))?;
            txn.append_event(NewEvent {
                stream_id: invocation.invocation_id.clone(),
                project_id: Some(invocation.project_id.clone()),
                actor_ref: Some(deployment_actor_ref()),
                event_type: EVENT_INVOCATION_SUCCEEDED.to_owned(),
                schema_ref: INVOCATION_SCHEMA_REF.to_owned(),
                resource_ref: invocation.invocation_id.clone(),
                resource_revision: Some(invocation.revision + 1),
                causation_ref: meta.causation_event_ref.clone(),
                correlation_ref: meta.request_id.clone(),
                classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
                payload: serde_json::json!({
                    "invocation_id": invocation.invocation_id,
                    "state": "succeeded",
                    "result_ref": args.result_ref,
                }),
            })
            .map_err(store_problem)?;
            txn.audit(
                "command.invocation_succeeded",
                &format!(
                    "invocation={};attempt={};{}",
                    invocation.invocation_id,
                    attempt.attempt_id,
                    scope_digest(&meta)
                ),
            );
            Ok(Applied {
                result: record,
                revision: Some(invocation.revision + 1),
                event_cursor: None,
            })
        },
    );
    command_outcome_bytes(outcome)
}

/// Resolves the invocation id an attempt binds — the worker scope needs
/// it before the transaction opens. Uniform `not-found` when absent.
/// One RUNNING invocation and its claimed attempt, inserted directly — the
/// state a worker-surface operation needs to exist before it can be called.
///
/// Test/fixture use only (the `budget::seam_fixture` convention): the real
/// path is `invocation_create` then `invocation_claim` over the two sockets.
/// It exists so a library-level suite can exercise a worker-surface operation
/// without also re-driving the whole §10.6 registry pipeline.
pub fn attempt_fixture(
    store: &mut Store,
    project_id: &str,
    space_id: Option<&str>,
    context_assembly_ref: Option<&str>,
) -> Result<(String, String, u64), Problem> {
    let invocation_id = new_id("inv").map_err(store_problem)?;
    let attempt_id = new_id("invatt").map_err(store_problem)?;
    let created_at = rfc3339_utc(0);
    let record = serde_json::json!({
        "invocation_id": invocation_id,
        "realm_id": PERSONAL_REALM_ID,
        "project_id": project_id,
        "space_id": space_id,
        "context_assembly_ref": context_assembly_ref,
        "state": "running",
        "revision": 1,
        "created_at": created_at,
    });
    store
        .conn()
        .execute(
            "INSERT INTO invocations (invocation_id, realm_id, project_id, space_id,
                 branch_id, context_assembly_ref, state, revision, record, created_at)
             VALUES (?1,?2,?3,?4,NULL,?5,'running',1,?6,?7)",
            params![
                invocation_id,
                PERSONAL_REALM_ID,
                project_id,
                space_id,
                context_assembly_ref,
                serde_json::to_string(&record).map_err(|_| internal())?,
                created_at,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    store
        .conn()
        .execute(
            "INSERT INTO invocation_attempts (attempt_id, invocation_id, ordinal,
                 worker_instance_id, fence_epoch, state, lease_expires_at, started_at,
                 ended_at, result_ref)
             VALUES (?1,?2,1,'worker-local',1,'running',NULL,?3,NULL,NULL)",
            params![attempt_id, invocation_id, created_at],
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok((invocation_id, attempt_id, 1))
}

/// Advances one attempt's fence, leaving the presented fence stale — the
/// fixture a "stale fence is refused" proof needs.
pub fn advance_attempt_fence(store: &mut Store, attempt_id: &str) -> Result<u64, Problem> {
    store
        .conn()
        .execute(
            "UPDATE invocation_attempts SET fence_epoch = fence_epoch + 1
             WHERE attempt_id = ?1",
            [attempt_id],
        )
        .map_err(|e| store_problem(e.into()))?;
    let fence: i64 = store
        .conn()
        .query_row(
            "SELECT fence_epoch FROM invocation_attempts WHERE attempt_id = ?1",
            [attempt_id],
            |r| r.get(0),
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok(fence.max(0) as u64)
}

pub fn attempt_invocation_id(store: &Store, attempt_id: &str) -> Result<String, Problem> {
    Ok(get_attempt(store.conn(), attempt_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?
        .invocation_id)
}

pub fn invocation_exists(conn: &Connection, invocation_id: &str) -> Result<bool, Problem> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM invocations WHERE invocation_id = ?1",
            [invocation_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    Ok(found.is_some())
}
