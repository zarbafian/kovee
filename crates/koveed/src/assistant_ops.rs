//! Slice-3 developer_assistant_v1 mutations: assistant definitions,
//! deterministic revision registration (§14.2), deployments (developer
//! profile only — the personal daemon offers no confinement and refuses
//! to claim one), project alias bindings (§10.5), `invocation_cancel`
//! (§15.4: exactly one terminal state wins), and the worker-surface
//! `application_event_emit` (§14.1 `ctx.events.emit`). Operator-surface
//! registry entries bind to the owner principal in the personal profile
//! (registry-README resolutions 5/6).

use kovee_core::envelope::{CommandMeta, RawCommand};
use kovee_core::event::*;
use kovee_core::ops;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::{AssistantAliasBinding, AssistantDefinition, AssistantRevision};
use kovee_store::{
    new_id, Applied, CommandScope, CommandTxn, CrashHooks, NewEvent, Store, OWNER_ACTOR_REF,
};
use rusqlite::{params, OptionalExtension as _};
use serde_json::Value;

use crate::handlers::{command_outcome_bytes, ok_reply, scope_digest};
use crate::invoke;
use crate::state::*;

const DEFINITION_SCHEMA_REF: &str = "schema:assistant-definition-v1";
const REVISION_SCHEMA_REF: &str = "schema:assistant-revision-v1";
const DEPLOYMENT_SCHEMA_REF: &str = "schema:assistant-deployment-v1";
const ALIAS_SCHEMA_REF: &str = "schema:assistant-alias-binding-v1";
/// Emitted application events are validated against no registered payload
/// schema in K1; the envelope pins this placeholder ref (KG15).
const APP_EVENT_SCHEMA_REF: &str = "schema:application-event-v1";

fn check_expected_revision(meta: &CommandMeta, current: u64) -> Result<(), Problem> {
    if let Some(expected) = meta.expected_revision {
        if expected != current {
            return Err(stale_revision(current));
        }
    }
    Ok(())
}

fn refused(detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::Invalid, "invalid transition").with_detail(detail)
}

/// Appends one realm-level (project-less) registry event.
#[allow(clippy::too_many_arguments)]
fn realm_event(
    txn: &mut CommandTxn<'_>,
    stream_id: &str,
    event_type: &str,
    schema_ref: &str,
    resource_ref: &str,
    resource_revision: u64,
    payload: &Value,
    meta: &CommandMeta,
    audit_event: &str,
) -> Result<(), Problem> {
    txn.append_event(NewEvent {
        stream_id: stream_id.to_owned(),
        project_id: None,
        actor_ref: None,
        event_type: event_type.to_owned(),
        schema_ref: schema_ref.to_owned(),
        resource_ref: resource_ref.to_owned(),
        resource_revision: Some(resource_revision),
        causation_ref: meta.causation_event_ref.clone(),
        correlation_ref: meta.request_id.clone(),
        classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
        payload: payload.clone(),
    })
    .map_err(store_problem)?;
    txn.audit(
        audit_event,
        &format!("resource={resource_ref};{}", scope_digest(meta)),
    );
    Ok(())
}

// ------------------------------------------------------ assistant_create ----

pub fn assistant_create(
    store: &mut Store,
    scope: CommandScope,
    args: ops::AssistantCreateArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let definition = AssistantDefinition {
            definition_id: new_id("asst").map_err(store_problem)?,
            realm_id: txn.realm_id().to_owned(),
            owner_ref: OWNER_ACTOR_REF.to_owned(),
            revision: 1,
            name: args.name.clone(),
            description: args.description.clone(),
            status: "active".to_owned(),
            created_at: txn.now_ts(),
        };
        txn.conn()
            .execute(
                "INSERT INTO assistant_definitions (definition_id, realm_id,
                     owner_ref, revision, name, description, status, created_at)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, 'active', ?6)",
                params![
                    definition.definition_id,
                    definition.realm_id,
                    definition.owner_ref,
                    definition.name,
                    definition.description,
                    definition.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&definition).map_err(|_| internal())?;
        realm_event(
            txn,
            &definition.definition_id,
            EVENT_ASSISTANT_CREATED,
            DEFINITION_SCHEMA_REF,
            &definition.definition_id,
            1,
            &payload,
            &meta,
            "command.assistant_created",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(1),
            event_cursor: None,
        })
    });
    command_outcome_bytes(outcome)
}

pub fn assistant_show(store: &Store, args: &ops::AssistantShowArgs) -> Result<Vec<u8>, Problem> {
    let definition = get_assistant_definition(store.conn(), &args.definition_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let revision = definition.revision;
    ok_reply(
        serde_json::to_value(&definition).map_err(|_| internal())?,
        Some(revision),
    )
}

// --------------------------------------------- assistant_revision_register ----

pub fn assistant_revision_register(
    store: &mut Store,
    scope: CommandScope,
    args: ops::AssistantRevisionRegisterArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let definition = get_assistant_definition(txn.conn(), &args.definition_id)
            .map_err(store_problem)?
            .filter(|d| d.status == "active")
            .ok_or_else(not_found)?;
        // §14.2 deterministic validation: the manifest must bind exactly
        // this definition, version, and package digest.
        if args.manifest.definition_id != args.definition_id {
            return Err(refused(
                "manifest.definition_id does not match definition_id",
            ));
        }
        if args.manifest.version != args.version {
            return Err(refused("manifest.version does not match version"));
        }
        if args.manifest.package_digest != args.package_digest {
            return Err(refused(
                "manifest.package_digest does not match package_digest",
            ));
        }
        let duplicate: Option<i64> = txn
            .conn()
            .query_row(
                "SELECT 1 FROM assistant_revisions
                 WHERE definition_id = ?1 AND version = ?2",
                params![args.definition_id, args.version],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| store_problem(e.into()))?;
        if duplicate.is_some() {
            return Err(refused("this definition version is already registered"));
        }
        // Rebuild the manifest value from the raw args map is not needed:
        // the typed mirror re-serializes losslessly (closed shape).
        let manifest_value =
            serde_json::to_value(RevisionManifestEcho(&args)).map_err(|_| internal())?;
        let revision = AssistantRevision {
            assistant_revision_id: new_id("asstrev").map_err(store_problem)?,
            definition_id: definition.definition_id.clone(),
            version: args.version.clone(),
            manifest: manifest_value,
            package_artifact_ref: args.package_artifact_ref.clone(),
            package_digest: args.package_digest.clone(),
            config_schema_digest: args.config_schema_digest.clone(),
            sdk_protocol_range: args.sdk_protocol_range.clone(),
            signature_refs: args.signature_refs.clone().unwrap_or_default(),
            created_by: OWNER_ACTOR_REF.to_owned(),
            created_at: txn.now_ts(),
        };
        let payload = serde_json::to_value(&revision).map_err(|_| internal())?;
        txn.conn()
            .execute(
                "INSERT INTO assistant_revisions (assistant_revision_id,
                     definition_id, version, record, created_by, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    revision.assistant_revision_id,
                    revision.definition_id,
                    revision.version,
                    serde_json::to_string(&payload).map_err(|_| internal())?,
                    revision.created_by,
                    revision.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        realm_event(
            txn,
            &revision.definition_id,
            EVENT_ASSISTANT_REVISION_REGISTERED,
            REVISION_SCHEMA_REF,
            &revision.assistant_revision_id,
            1,
            &payload,
            &meta,
            "command.assistant_revision_registered",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(1),
            event_cursor: None,
        })
    });
    command_outcome_bytes(outcome)
}

/// Serializes the validated manifest back to its schema value.
struct RevisionManifestEcho<'a>(&'a ops::AssistantRevisionRegisterArgs);

impl serde::Serialize for RevisionManifestEcho<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let m = &self.0.manifest;
        let value = serde_json::json!({
            "schema_version": m.schema_version,
            "definition_id": m.definition_id,
            "version": m.version,
            "entrypoint": m.entrypoint,
            "package_digest": m.package_digest,
            "runtime": m.runtime,
            "supported_worker_protocols": m.supported_worker_protocols,
            "input_schema_ref": m.input_schema_ref,
            "output_schema_ref": m.output_schema_ref,
            "skills": m.skills,
            "attention_proposals": m.attention_proposals,
            "requested_capabilities": m.requested_capabilities,
            "model_profiles": m.model_profiles,
            "tool_profiles": m.tool_profiles,
            "network_policy": m.network_policy,
            "resource_limits": {
                "cpu": m.resource_limits.cpu,
                "memory": m.resource_limits.memory,
                "disk": m.resource_limits.disk,
                "output_bytes": m.resource_limits.output_bytes,
            },
            "default_timeout": m.default_timeout,
            "max_concurrency": m.max_concurrency,
            "causal_concurrency_policy": m.causal_concurrency_policy,
            "checkpoint_support": m.checkpoint_support,
            "cancellation_support": m.cancellation_support,
            "security_profiles": m.security_profiles,
        });
        value.serialize(serializer)
    }
}

pub fn assistant_revision_show(
    store: &Store,
    args: &ops::AssistantRevisionShowArgs,
) -> Result<Vec<u8>, Problem> {
    let record = get_assistant_revision_record(store.conn(), &args.assistant_revision_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    ok_reply(record, Some(1))
}

// ----------------------------------------------------- deployment_create ----

pub fn deployment_create(
    store: &mut Store,
    scope: CommandScope,
    args: ops::DeploymentCreateArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        get_assistant_revision_record(txn.conn(), &args.assistant_revision_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        // Labeled honesty (§14.4, milestone assurance profile): this
        // daemon provides no confinement boundary and refuses to claim
        // one — only the developer profile is deployable in K1.
        if args.security_profile != "developer" {
            return Err(Problem::new(
                ProblemKind::Forbidden,
                "only the developer security profile is deployable in the K1 personal profile",
            )
            .with_detail("confined/secure enforcement evidence would be unclaimed"));
        }
        let deployment_id = new_id("dep").map_err(store_problem)?;
        let record = serde_json::json!({
            "assistant_deployment_id": deployment_id,
            "assistant_revision_id": args.assistant_revision_id,
            "realm_id": txn.realm_id(),
            "revision": 1,
            "config_ref": args.config_ref,
            "config_digest": args.config_digest,
            "secret_binding_set_ref": args.secret_binding_set_ref,
            "secret_binding_set_digest": args.secret_binding_set_digest,
            "policy_ref": args.policy_ref,
            "pool_ref": args.pool_ref,
            "security_profile": args.security_profile,
            "concurrency_policy": args.concurrency_policy,
            "rollout_policy": args.rollout_policy,
            "status": "created",
        });
        txn.conn()
            .execute(
                "INSERT INTO assistant_deployments (deployment_id, realm_id,
                     revision, assistant_revision_id, security_profile, status,
                     created_at, record)
                 VALUES (?1, ?2, 1, ?3, ?4, 'created', ?5, ?6)",
                params![
                    deployment_id,
                    txn.realm_id(),
                    args.assistant_revision_id,
                    args.security_profile,
                    txn.now_ts(),
                    serde_json::to_string(&record).map_err(|_| internal())?,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        realm_event(
            txn,
            &deployment_id,
            EVENT_DEPLOYMENT_CREATED,
            DEPLOYMENT_SCHEMA_REF,
            &deployment_id,
            1,
            &record,
            &meta,
            "command.deployment_created",
        )?;
        Ok(Applied {
            result: record,
            revision: Some(1),
            event_cursor: None,
        })
    });
    command_outcome_bytes(outcome)
}

pub fn deployment_show(store: &Store, args: &ops::DeploymentIdArgs) -> Result<Vec<u8>, Problem> {
    let deployment = get_deployment(store.conn(), &args.assistant_deployment_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let record = deployment.record.ok_or_else(internal)?;
    ok_reply(record, Some(deployment.revision))
}

/// Shared deployment lifecycle transition (`activate` / `drain`).
pub fn deployment_transition(
    store: &mut Store,
    scope: CommandScope,
    args: ops::DeploymentIdArgs,
    activate: bool,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let deployment = get_deployment(txn.conn(), &args.assistant_deployment_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        check_expected_revision(&meta, deployment.revision)?;
        let (new_status, event_type, audit_event) = if activate {
            if !["created", "drained"].contains(&deployment.status.as_str()) {
                return Err(refused(format!("deployment is {}", deployment.status)));
            }
            (
                "active",
                EVENT_DEPLOYMENT_ACTIVATED,
                "command.deployment_activated",
            )
        } else {
            if deployment.status != "active" {
                return Err(refused(format!("deployment is {}", deployment.status)));
            }
            (
                "drained",
                EVENT_DEPLOYMENT_DRAINED,
                "command.deployment_drained",
            )
        };
        let mut record = deployment.record.ok_or_else(internal)?;
        let new_revision = deployment.revision + 1;
        record["status"] = Value::String(new_status.to_owned());
        record["revision"] = Value::from(new_revision);
        if activate {
            record["activated_at"] = Value::String(txn.now_ts());
        }
        txn.conn()
            .execute(
                "UPDATE assistant_deployments SET status = ?2,
                     revision = revision + 1, record = ?3
                 WHERE deployment_id = ?1",
                params![
                    deployment.deployment_id,
                    new_status,
                    serde_json::to_string(&record).map_err(|_| internal())?,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        realm_event(
            txn,
            &deployment.deployment_id,
            event_type,
            DEPLOYMENT_SCHEMA_REF,
            &deployment.deployment_id,
            new_revision,
            &record,
            &meta,
            audit_event,
        )?;
        Ok(Applied {
            result: record,
            revision: Some(new_revision),
            event_cursor: None,
        })
    });
    command_outcome_bytes(outcome)
}

// --------------------------------------------------------- alias binding ----

/// Deterministic server-side alias normalization (§10.5): trim,
/// casefold to lowercase, collapse internal whitespace runs.
pub fn normalize_alias(display: &str) -> String {
    display
        .split_whitespace()
        .map(|part| part.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn active_alias_exists(
    txn: &CommandTxn<'_>,
    project_id: &str,
    normalized: &str,
    exclude: Option<&str>,
) -> Result<bool, Problem> {
    let found: Option<i64> = txn
        .conn()
        .query_row(
            "SELECT 1 FROM assistant_aliases
             WHERE project_id = ?1 AND normalized_alias = ?2 AND status = 'active'
               AND (?3 IS NULL OR alias_binding_id != ?3)",
            params![project_id, normalized, exclude],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    Ok(found.is_some())
}

/// Validates the pinned deployment binding: the deployment must exist and
/// the caller must pin its current revision.
fn check_deployment_pin(
    txn: &CommandTxn<'_>,
    deployment_id: &str,
    pinned_revision: u64,
) -> Result<(), Problem> {
    let deployment = get_deployment(txn.conn(), deployment_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    if deployment.revision != pinned_revision {
        return Err(stale_revision(deployment.revision)
            .with_detail("deployment_revision pins a stale deployment"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn alias_event(
    txn: &mut CommandTxn<'_>,
    project_id: &str,
    alias: &AssistantAliasBinding,
    event_type: &str,
    meta: &CommandMeta,
    audit_event: &str,
) -> Result<Applied, Problem> {
    let payload = serde_json::to_value(alias).map_err(|_| internal())?;
    let event = txn
        .append_event(NewEvent {
            stream_id: alias.alias_binding_id.clone(),
            project_id: Some(project_id.to_owned()),
            actor_ref: None,
            event_type: event_type.to_owned(),
            schema_ref: ALIAS_SCHEMA_REF.to_owned(),
            resource_ref: alias.alias_binding_id.clone(),
            resource_revision: Some(alias.revision),
            causation_ref: meta.causation_event_ref.clone(),
            correlation_ref: meta.request_id.clone(),
            classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
            payload: payload.clone(),
        })
        .map_err(store_problem)?;
    txn.audit(
        audit_event,
        &format!("alias={};{}", alias.alias_binding_id, scope_digest(meta)),
    );
    let cursor = txn
        .mint_project_cursor(project_id, event.project_sequence.unwrap_or(0))
        .map_err(store_problem)?;
    Ok(Applied {
        result: payload,
        revision: Some(alias.revision),
        event_cursor: Some(cursor),
    })
}

pub fn alias_bind(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::AliasBindArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        get_project(txn.conn(), &project_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        check_deployment_pin(txn, &args.assistant_deployment_id, args.deployment_revision)?;
        let normalized = normalize_alias(&args.display_alias);
        if normalized.is_empty() {
            return Err(refused("display_alias normalizes to the empty alias"));
        }
        if active_alias_exists(txn, &project_id, &normalized, None)? {
            return Err(refused(
                "an active binding already holds this normalized alias in the project",
            ));
        }
        let alias = AssistantAliasBinding {
            alias_binding_id: new_id("alias").map_err(store_problem)?,
            realm_id: txn.realm_id().to_owned(),
            project_id: project_id.clone(),
            revision: 1,
            normalized_alias: normalized,
            display_alias: args.display_alias.clone(),
            assistant_deployment_id: args.assistant_deployment_id.clone(),
            deployment_revision: args.deployment_revision,
            status: "active".to_owned(),
            created_by: OWNER_ACTOR_REF.to_owned(),
            created_at: txn.now_ts(),
        };
        txn.conn()
            .execute(
                "INSERT INTO assistant_aliases (alias_binding_id, realm_id,
                     project_id, revision, normalized_alias, display_alias,
                     assistant_deployment_id, deployment_revision, status,
                     created_by, created_at)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, 'active', ?8, ?9)",
                params![
                    alias.alias_binding_id,
                    alias.realm_id,
                    alias.project_id,
                    alias.normalized_alias,
                    alias.display_alias,
                    alias.assistant_deployment_id,
                    alias.deployment_revision as i64,
                    alias.created_by,
                    alias.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        alias_event(
            txn,
            &project_id,
            &alias,
            EVENT_ALIAS_BOUND,
            &meta,
            "command.assistant_alias_bound",
        )
    });
    command_outcome_bytes(outcome)
}

pub fn alias_update(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::AliasUpdateArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let mut alias = get_alias(txn.conn(), &args.alias_binding_id)
            .map_err(store_problem)?
            .filter(|a| a.project_id == project_id)
            .ok_or_else(not_found)?;
        check_expected_revision(&meta, alias.revision)?;
        if alias.status != "active" {
            return Err(refused(format!("alias binding is {}", alias.status)));
        }
        check_deployment_pin(txn, &args.assistant_deployment_id, args.deployment_revision)?;
        alias.assistant_deployment_id = args.assistant_deployment_id.clone();
        alias.deployment_revision = args.deployment_revision;
        alias.revision += 1;
        txn.conn()
            .execute(
                "UPDATE assistant_aliases SET assistant_deployment_id = ?2,
                     deployment_revision = ?3, revision = revision + 1
                 WHERE alias_binding_id = ?1",
                params![
                    alias.alias_binding_id,
                    alias.assistant_deployment_id,
                    alias.deployment_revision as i64,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        alias_event(
            txn,
            &project_id,
            &alias,
            EVENT_ALIAS_UPDATED,
            &meta,
            "command.assistant_alias_updated",
        )
    });
    command_outcome_bytes(outcome)
}

pub fn alias_revoke(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::AliasIdArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let mut alias = get_alias(txn.conn(), &args.alias_binding_id)
            .map_err(store_problem)?
            .filter(|a| a.project_id == project_id)
            .ok_or_else(not_found)?;
        check_expected_revision(&meta, alias.revision)?;
        if alias.status != "active" {
            return Err(refused(format!("alias binding is {}", alias.status)));
        }
        alias.status = "revoked".to_owned();
        alias.revision += 1;
        txn.conn()
            .execute(
                "UPDATE assistant_aliases SET status = 'revoked',
                     revision = revision + 1
                 WHERE alias_binding_id = ?1",
                [&alias.alias_binding_id],
            )
            .map_err(|e| store_problem(e.into()))?;
        alias_event(
            txn,
            &project_id,
            &alias,
            EVENT_ALIAS_REVOKED,
            &meta,
            "command.assistant_alias_revoked",
        )
    });
    command_outcome_bytes(outcome)
}

pub fn alias_show(
    store: &Store,
    project_id: &str,
    args: &ops::AliasIdArgs,
) -> Result<Vec<u8>, Problem> {
    let alias = get_alias(store.conn(), &args.alias_binding_id)
        .map_err(store_problem)?
        .filter(|a| a.project_id == project_id)
        .ok_or_else(not_found)?;
    let revision = alias.revision;
    ok_reply(
        serde_json::to_value(&alias).map_err(|_| internal())?,
        Some(revision),
    )
}

// ----------------------------------------------------- invocation_cancel ----

/// External-surface cancel (§15.4): exactly one terminal state wins; a
/// cancel of an already-terminal invocation is a stale-revision.
pub fn invocation_cancel(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::InvocationCancelArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let invocation = get_invocation(txn.conn(), &args.invocation_id)
            .map_err(store_problem)?
            .filter(|i| i.project_id == project_id)
            .ok_or_else(not_found)?;
        check_expected_revision(&meta, invocation.revision)?;
        if !["queued", "claimed", "running"].contains(&invocation.state.as_str()) {
            return Err(stale_revision(invocation.revision).with_detail(format!(
                "invocation is already terminal ({})",
                invocation.state
            )));
        }
        let now_ts = txn.now_ts();
        let mut record = invocation.record.clone();
        let new_revision = invocation.revision + 1;
        record["state"] = Value::String("canceled".to_owned());
        record["revision"] = Value::from(new_revision);
        record["terminal_at"] = Value::String(now_ts.clone());
        txn.conn()
            .execute(
                "UPDATE invocations SET state = 'canceled', revision = revision + 1,
                     record = ?2
                 WHERE invocation_id = ?1",
                params![
                    invocation.invocation_id,
                    serde_json::to_string(&record).map_err(|_| internal())?,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        // Fencing: running attempts lose their lease — a post-cancel
        // worker write fails `stale-lease` inside its own transaction.
        txn.conn()
            .execute(
                "UPDATE invocation_attempts SET state = 'canceled', ended_at = ?2
                 WHERE invocation_id = ?1 AND state = 'running'",
                params![invocation.invocation_id, now_ts],
            )
            .map_err(|e| store_problem(e.into()))?;
        let event = txn
            .append_event(NewEvent {
                stream_id: invocation.invocation_id.clone(),
                project_id: Some(project_id.clone()),
                actor_ref: None,
                event_type: EVENT_INVOCATION_CANCELED.to_owned(),
                schema_ref: INVOCATION_SCHEMA_REF.to_owned(),
                resource_ref: invocation.invocation_id.clone(),
                resource_revision: Some(new_revision),
                causation_ref: meta.causation_event_ref.clone(),
                correlation_ref: meta.request_id.clone(),
                classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
                payload: serde_json::json!({
                    "invocation_id": invocation.invocation_id,
                    "state": "canceled",
                    "cancellation_scope": args.cancellation_scope,
                    "reason": args.reason,
                }),
            })
            .map_err(store_problem)?;
        txn.audit(
            "command.invocation_canceled",
            &format!(
                "invocation={};scope={};{}",
                invocation.invocation_id,
                args.cancellation_scope.as_deref().unwrap_or("default"),
                scope_digest(&meta)
            ),
        );
        let cursor = txn
            .mint_project_cursor(&project_id, event.project_sequence.unwrap_or(0))
            .map_err(store_problem)?;
        Ok(Applied {
            result: record,
            revision: Some(new_revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

/// Worker-surface cancel: the fenced attempt may cancel ONLY its own
/// exact child invocation under an explicit parent linkage (§11.6.1).
/// K1 records no invocation ancestry — no child exists, so after the
/// binding is validated the target is uniformly not-found. The dispatch
/// arm exists (registry parity); the capability is honestly inert.
pub fn worker_invocation_cancel(
    store: &mut Store,
    cmd: &RawCommand,
    args: ops::InvocationCancelArgs,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let (Some(attempt_id), Some(fence)) = (args.attempt_id.as_deref(), args.fence_epoch) else {
        return Err(Problem::new(
            ProblemKind::ForbiddenSurface,
            "worker operations require the attempt binding (§15.2)",
        ));
    };
    let invocation_id = invoke::attempt_invocation_id(store, attempt_id)?;
    let scope = invoke::worker_scope(cmd, &invocation_id)?;
    let attempt_id = attempt_id.to_owned();
    // KV-R1: a worker-surface operation carries its replay authorizer even
    // when it is inert — the arm exists for registry parity, and a future
    // implementation must not inherit an unguarded replay path.
    let outcome = store.command_transaction_guarded(
        &scope,
        now,
        hooks,
        invoke::binding_authorizer(&attempt_id, fence),
        move |txn| {
            invoke::check_binding(txn.conn(), &attempt_id, fence)?;
            // No parent→child ancestry exists in K1: the target can never
            // be this attempt's child invocation.
            Err(not_found())
        },
    );
    command_outcome_bytes(outcome)
}

// ------------------------------------------------- application_event_emit ----

/// Worker-surface `application_event_emit` (§14.1 `ctx.events.emit`):
/// the fenced attempt appends ONE registered-namespace event to its
/// invocation's project ledger. The reserved `dev.kovee.*` namespace is
/// refused — a worker can never counterfeit a Kovee lifecycle event.
///
/// KV-R1: like every other worker-surface operation this runs through
/// [`Store::command_transaction_guarded`], so an exact replay from an
/// attempt that has completed (or whose fence has moved) is refused with
/// `stale-lease` BEFORE the stored receipt is released.
pub fn application_event_emit(
    store: &mut Store,
    cmd: &RawCommand,
    args: ops::ApplicationEventEmitArgs,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let invocation_id = invoke::attempt_invocation_id(store, &args.attempt_id)?;
    let scope = invoke::worker_scope(cmd, &invocation_id)?;
    let meta = cmd.meta.clone().ok_or_else(internal)?;
    let project_id = cmd.project_id.clone().ok_or_else(internal)?;
    let replay = (
        args.attempt_id.clone(),
        args.fence_epoch,
        project_id.clone(),
    );
    let outcome = store.command_transaction_guarded(
        &scope,
        now,
        hooks,
        move |conn| {
            let (attempt_id, fence, project_id) = replay;
            let (_, invocation) = invoke::check_binding(conn, &attempt_id, fence)?;
            // The ledger the receipt names must still be this attempt's.
            if invocation.project_id != project_id {
                return Err(not_found());
            }
            Ok(())
        },
        move |txn| {
            if args.event_type.starts_with(RESERVED_EVENT_NAMESPACE) {
                return Err(Problem::new(
                    ProblemKind::Forbidden,
                    "the dev.kovee namespace is reserved (§11.3)",
                ));
            }
            let (attempt, invocation) =
                invoke::check_binding(txn.conn(), &args.attempt_id, args.fence_epoch)?;
            if invocation.project_id != project_id {
                return Err(not_found());
            }
            let stream_id = invocation
                .space_id
                .clone()
                .unwrap_or_else(|| invocation.invocation_id.clone());
            let event = txn
                .append_event(NewEvent {
                    stream_id,
                    project_id: Some(project_id.clone()),
                    actor_ref: Some(invoke::deployment_actor_ref()),
                    event_type: args.event_type.clone(),
                    schema_ref: APP_EVENT_SCHEMA_REF.to_owned(),
                    resource_ref: invocation.invocation_id.clone(),
                    resource_revision: None,
                    causation_ref: meta.causation_event_ref.clone(),
                    correlation_ref: meta.request_id.clone(),
                    classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
                    payload: args.payload.clone(),
                })
                .map_err(store_problem)?;
            txn.audit(
                "command.application_event_emitted",
                &format!(
                    "event={};invocation={};attempt={};type={};{}",
                    event.event_id,
                    invocation.invocation_id,
                    attempt.attempt_id,
                    args.event_type,
                    scope_digest(&meta)
                ),
            );
            let cursor = txn
                .mint_project_cursor(&project_id, event.project_sequence.unwrap_or(0))
                .map_err(store_problem)?;
            Ok(Applied {
                result: serde_json::json!({
                    "event_id": event.event_id,
                    "stream_id": event.stream_id,
                    "stream_sequence": event.stream_sequence,
                    "project_sequence": event.project_sequence,
                    "occurred_at": event.occurred_at,
                }),
                revision: None,
                event_cursor: Some(cursor),
            })
        },
    );
    command_outcome_bytes(outcome)
}
