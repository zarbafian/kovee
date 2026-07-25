//! Slice-3 lifecycle mutations: project metadata, the §10.1 prepared
//! project access-policy change flow, the §10.2 space lifecycle
//! (update/freeze/reopen/archive/restrict/policy-narrow — none deletes
//! history), and the §10.2 prepared space access-widening flow. Direct
//! mutations may only hold or narrow access; every widening runs through
//! prepare → confirm against an exact pinned subject.

use kovee_core::canonical::canonical_object_digest;
use kovee_core::envelope::CommandMeta;
use kovee_core::event::*;
use kovee_core::ops;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::{ProjectAccessPolicyChange, Space, SpaceAccessWidening};
use kovee_store::{
    new_id, Applied, CommandScope, CommandTxn, CrashHooks, NewEvent, Store, OWNER_ACTOR_REF,
};
use rusqlite::params;
use serde_json::Value;

use crate::handlers::{command_outcome_bytes, ok_reply, scope_digest};
use crate::state::*;

fn check_expected_revision(meta: &CommandMeta, current: u64) -> Result<(), Problem> {
    if let Some(expected) = meta.expected_revision {
        if expected != current {
            return Err(stale_revision(current));
        }
    }
    Ok(())
}

fn invalid_transition(detail: String) -> Problem {
    Problem::new(ProblemKind::StaleRevision, "invalid lifecycle transition").with_detail(detail)
}

// ---------------------------------------------- project_update_metadata ----

pub fn project_update_metadata(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ProjectUpdateMetadataArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let project = get_project(txn.conn(), &project_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        if project.status == "archived" {
            return Err(invalid_transition("project is archived".to_owned()));
        }
        check_expected_revision(&meta, project.revision)?;
        txn.conn()
            .execute(
                "UPDATE projects SET name = ?2, revision = revision + 1
                 WHERE project_id = ?1",
                params![project_id, args.name],
            )
            .map_err(|e| store_problem(e.into()))?;
        let updated = get_project(txn.conn(), &project_id)
            .map_err(store_problem)?
            .ok_or_else(internal)?;
        let payload = serde_json::to_value(&updated).map_err(|_| internal())?;
        let event = txn
            .append_event(NewEvent {
                stream_id: project_id.clone(),
                project_id: Some(project_id.clone()),
                actor_ref: None,
                event_type: EVENT_PROJECT_UPDATED.to_owned(),
                schema_ref: PROJECT_SCHEMA_REF.to_owned(),
                resource_ref: project_id.clone(),
                resource_revision: Some(updated.revision),
                causation_ref: meta.causation_event_ref.clone(),
                correlation_ref: meta.request_id.clone(),
                classification_ref: updated.default_classification_ref.clone(),
                payload: payload.clone(),
            })
            .map_err(store_problem)?;
        txn.audit(
            "command.project_updated",
            &format!("project={project_id};{}", scope_digest(&meta)),
        );
        let cursor = txn
            .mint_project_cursor(&project_id, event.project_sequence.unwrap_or(0))
            .map_err(store_problem)?;
        Ok(Applied {
            result: payload,
            revision: Some(updated.revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

// ------------------------------------------------------ space lifecycle ----

/// Which lifecycle mutation is being applied (shared plumbing).
pub enum SpaceLifecycle {
    UpdateMetadata(ops::SpaceUpdateMetadataArgs),
    Freeze,
    Reopen,
    Archive,
    Restrict,
    PolicyNarrow(ops::SpacePolicyNarrowArgs),
}

impl SpaceLifecycle {
    fn event_type(&self) -> &'static str {
        match self {
            SpaceLifecycle::UpdateMetadata(_) => EVENT_SPACE_UPDATED,
            SpaceLifecycle::Freeze => EVENT_SPACE_FROZEN,
            SpaceLifecycle::Reopen => EVENT_SPACE_REOPENED,
            SpaceLifecycle::Archive => EVENT_SPACE_ARCHIVED,
            SpaceLifecycle::Restrict => EVENT_SPACE_RESTRICTED,
            SpaceLifecycle::PolicyNarrow(_) => EVENT_SPACE_POLICY_NARROWED,
        }
    }

    fn audit_event(&self) -> &'static str {
        match self {
            SpaceLifecycle::UpdateMetadata(_) => "command.space_updated",
            SpaceLifecycle::Freeze => "command.space_frozen",
            SpaceLifecycle::Reopen => "command.space_reopened",
            SpaceLifecycle::Archive => "command.space_archived",
            SpaceLifecycle::Restrict => "command.space_restricted",
            SpaceLifecycle::PolicyNarrow(_) => "command.space_policy_narrowed",
        }
    }

    /// Validates the transition and applies the column updates. §10.2:
    /// none of these deletes history; restrict/policy-narrow only hold or
    /// narrow — widening has its own prepared flow.
    fn apply(&self, txn: &CommandTxn<'_>, space: &Space) -> Result<(), Problem> {
        let conn = txn.conn();
        match self {
            SpaceLifecycle::UpdateMetadata(args) => {
                if space.status == "archived" {
                    return Err(invalid_transition("space is archived".to_owned()));
                }
                if let Some(purpose) = &args.purpose_contribution_ref {
                    resolve_space_object(conn, &space.space_id, purpose)?;
                }
                conn.execute(
                    "UPDATE spaces SET title = COALESCE(?2, title),
                         purpose_contribution_ref =
                             COALESCE(?3, purpose_contribution_ref),
                         revision = revision + 1
                     WHERE space_id = ?1",
                    params![space.space_id, args.title, args.purpose_contribution_ref],
                )
                .map_err(|e| store_problem(e.into()))?;
            }
            SpaceLifecycle::Freeze => {
                if space.status != "open" {
                    return Err(invalid_transition(format!(
                        "cannot freeze a {} space",
                        space.status
                    )));
                }
                set_status(conn, &space.space_id, "frozen")?;
            }
            SpaceLifecycle::Reopen => {
                if space.status != "frozen" {
                    return Err(invalid_transition(format!(
                        "cannot reopen a {} space",
                        space.status
                    )));
                }
                set_status(conn, &space.space_id, "open")?;
            }
            SpaceLifecycle::Archive => {
                if space.status == "archived" {
                    return Err(invalid_transition("space is already archived".to_owned()));
                }
                set_status(conn, &space.space_id, "archived")?;
            }
            SpaceLifecycle::Restrict => {
                if space.visibility == "restricted" {
                    return Err(invalid_transition("space is already restricted".to_owned()));
                }
                conn.execute(
                    "UPDATE spaces SET visibility = 'restricted',
                         revision = revision + 1
                     WHERE space_id = ?1",
                    [&space.space_id],
                )
                .map_err(|e| store_problem(e.into()))?;
            }
            SpaceLifecycle::PolicyNarrow(args) => {
                if space.status == "archived" {
                    return Err(invalid_transition("space is archived".to_owned()));
                }
                conn.execute(
                    "UPDATE spaces SET policy_set_ref = COALESCE(?2, policy_set_ref),
                         default_classification_ref =
                             COALESCE(?3, default_classification_ref),
                         revision = revision + 1
                     WHERE space_id = ?1",
                    params![
                        space.space_id,
                        args.policy_set_ref,
                        args.default_classification_ref
                    ],
                )
                .map_err(|e| store_problem(e.into()))?;
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn space_lifecycle(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    space_id: String,
    lifecycle: SpaceLifecycle,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let space = visible_space(txn.conn(), &project_id, &space_id)?;
        check_expected_revision(&meta, space.revision)?;
        lifecycle.apply(txn, &space)?;
        let updated = get_space(txn.conn(), &space_id)
            .map_err(store_problem)?
            .ok_or_else(internal)?;
        let payload = serde_json::to_value(&updated).map_err(|_| internal())?;
        let event = txn
            .append_event(NewEvent {
                stream_id: space_id.clone(),
                project_id: Some(project_id.clone()),
                actor_ref: None,
                event_type: lifecycle.event_type().to_owned(),
                schema_ref: SPACE_SCHEMA_REF.to_owned(),
                resource_ref: space_id.clone(),
                resource_revision: Some(updated.revision),
                causation_ref: meta.causation_event_ref.clone(),
                correlation_ref: meta.request_id.clone(),
                classification_ref: updated.default_classification_ref.clone(),
                payload: payload.clone(),
            })
            .map_err(store_problem)?;
        txn.audit(
            lifecycle.audit_event(),
            &format!("space={space_id};{}", scope_digest(&meta)),
        );
        let cursor = txn
            .mint_project_cursor(&project_id, event.project_sequence.unwrap_or(0))
            .map_err(store_problem)?;
        Ok(Applied {
            result: payload,
            revision: Some(updated.revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

fn set_status(conn: &rusqlite::Connection, space_id: &str, status: &str) -> Result<(), Problem> {
    conn.execute(
        "UPDATE spaces SET status = ?2, revision = revision + 1 WHERE space_id = ?1",
        params![space_id, status],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

// ---------------------------------------------- prepared-change shared ----

/// The exact item set of one space at preparation time: every
/// contribution (ref, digest), ordered by space sequence — the digest a
/// confirm binds ("item-level policies remain intersected"; a changed
/// item set makes the intent stale).
fn item_set_digest(txn: &CommandTxn<'_>, space_ids: &[String]) -> Result<String, Problem> {
    let mut items: Vec<Value> = Vec::new();
    for space_id in space_ids {
        let mut stmt = txn
            .conn()
            .prepare(
                "SELECT contribution_id, content_digest FROM contributions
                 WHERE space_id = ?1 ORDER BY space_sequence ASC",
            )
            .map_err(|e| store_problem(e.into()))?;
        let rows = stmt
            .query_map([space_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(|e| store_problem(e.into()))?;
        for row in rows {
            let (id, digest) = row.map_err(|e| store_problem(e.into()))?;
            items.push(serde_json::json!({"ref": id, "digest": digest}));
        }
    }
    let (_, digest) = canonical_object_digest(
        "kovee-item-set",
        "schema:kovee-item-set-v1",
        &serde_json::json!({"items": items}),
    )
    .map_err(|_| internal())?;
    Ok(digest)
}

fn frontier_refs(txn: &CommandTxn<'_>, space_ids: &[String]) -> Result<Vec<String>, Problem> {
    let mut refs = Vec::new();
    for space_id in space_ids {
        let mut stmt = txn
            .conn()
            .prepare(
                "SELECT frontier_id FROM space_frontiers WHERE space_id = ?1
                 ORDER BY frontier_id ASC",
            )
            .map_err(|e| store_problem(e.into()))?;
        let rows = stmt
            .query_map([space_id], |r| r.get::<_, String>(0))
            .map_err(|e| store_problem(e.into()))?;
        for row in rows {
            refs.push(row.map_err(|e| store_problem(e.into()))?);
        }
    }
    Ok(refs)
}

fn audience_digest(subject: &Value) -> Result<String, Problem> {
    let (_, digest) = canonical_object_digest(
        "kovee-destination-audience",
        "schema:kovee-audience-v1",
        subject,
    )
    .map_err(|_| internal())?;
    Ok(digest)
}

fn subject_digest_of(subject: &Value) -> Result<String, Problem> {
    let (_, digest) = canonical_object_digest(
        "kovee-prepared-subject",
        "schema:kovee-prepared-subject-v1",
        subject,
    )
    .map_err(|_| internal())?;
    Ok(digest)
}

#[allow(clippy::too_many_arguments)]
fn prepared_change_event(
    txn: &mut CommandTxn<'_>,
    project_id: &str,
    stream_id: &str,
    event_type: &str,
    schema_ref: &str,
    resource_ref: &str,
    revision: u64,
    payload: &Value,
    meta: &CommandMeta,
    audit_event: &str,
) -> Result<(u64, String), Problem> {
    let event = txn
        .append_event(NewEvent {
            stream_id: stream_id.to_owned(),
            project_id: Some(project_id.to_owned()),
            actor_ref: None,
            event_type: event_type.to_owned(),
            schema_ref: schema_ref.to_owned(),
            resource_ref: resource_ref.to_owned(),
            resource_revision: Some(revision),
            causation_ref: meta.causation_event_ref.clone(),
            correlation_ref: meta.request_id.clone(),
            classification_ref: DEFAULT_CLASSIFICATION.to_owned(),
            payload: payload.clone(),
        })
        .map_err(store_problem)?;
    txn.audit(
        audit_event,
        &format!("change={resource_ref};{}", scope_digest(meta)),
    );
    let cursor = txn
        .mint_project_cursor(project_id, event.project_sequence.unwrap_or(0))
        .map_err(store_problem)?;
    Ok((revision, cursor))
}

const PAPC_SCHEMA_REF: &str = "schema:project-access-policy-change-v1";
const WIDENING_SCHEMA_REF: &str = "schema:space-access-widening-v1";

// -------------------------------------- project_access_policy_change_* ----

pub fn papc_prepare(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::PapcPrepareArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let project = get_project(txn.conn(), &project_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        check_expected_revision(&meta, project.revision)?;
        let space_ids: Vec<String> = {
            let mut stmt = txn
                .conn()
                .prepare("SELECT space_id FROM spaces WHERE project_id = ?1 ORDER BY space_id")
                .map_err(|e| store_problem(e.into()))?;
            let rows = stmt
                .query_map([&project_id], |r| r.get::<_, String>(0))
                .map_err(|e| store_problem(e.into()))?;
            rows.collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?
        };
        let proposed_policy = args
            .proposed_policy_set_ref
            .clone()
            .unwrap_or_else(|| project.policy_set_ref.clone());
        let proposed_classification = args
            .proposed_default_classification_ref
            .clone()
            .unwrap_or_else(|| project.default_classification_ref.clone());
        // K1 has no policy comparator: an unchanged proposal is a
        // narrowing (no effective change); anything else is recorded
        // `incomparable` and must run the full confirm path.
        let effective_change = if proposed_policy == project.policy_set_ref
            && proposed_classification == project.default_classification_ref
        {
            "narrowing"
        } else {
            "incomparable"
        };
        let affected_frontiers = frontier_refs(txn, &space_ids)?;
        let item_digest = item_set_digest(txn, &space_ids)?;
        let subject = serde_json::json!({
            "project_id": project_id,
            "expected_project_revision": project.revision,
            "prior_policy_set_ref": project.policy_set_ref,
            "proposed_policy_set_ref": proposed_policy,
            "prior_default_classification_ref": project.default_classification_ref,
            "proposed_default_classification_ref": proposed_classification,
            "affected_space_frontier_refs": affected_frontiers,
            "affected_item_set_digest": item_digest,
        });
        let change = ProjectAccessPolicyChange {
            change_id: new_id("papc").map_err(store_problem)?,
            project_id: project_id.clone(),
            expected_project_revision: project.revision,
            prior_policy_set_ref: project.policy_set_ref.clone(),
            proposed_policy_set_ref: proposed_policy,
            prior_default_classification_ref: project.default_classification_ref.clone(),
            proposed_default_classification_ref: proposed_classification,
            affected_space_frontier_refs: affected_frontiers,
            affected_item_set_digest: item_digest,
            effective_change: effective_change.to_owned(),
            classification_join_ref: project.default_classification_ref.clone(),
            destination_audience_digest: audience_digest(&serde_json::json!({
                "scope": "project", "project_id": project_id,
            }))?,
            subject_digest: subject_digest_of(&subject)?,
            prepared_by_principal: OWNER_ACTOR_REF.to_owned(),
            state: "prepared".to_owned(),
            revision: 1,
            created_at: txn.now_ts(),
        };
        let payload = serde_json::to_value(&change).map_err(|_| internal())?;
        txn.conn()
            .execute(
                "INSERT INTO project_policy_changes (change_id, project_id, state,
                     revision, record, created_at)
                 VALUES (?1, ?2, 'prepared', 1, ?3, ?4)",
                params![
                    change.change_id,
                    project_id,
                    serde_json::to_string(&payload).map_err(|_| internal())?,
                    change.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let (revision, cursor) = prepared_change_event(
            txn,
            &project_id,
            &project_id,
            EVENT_PROJECT_POLICY_CHANGE_PREPARED,
            PAPC_SCHEMA_REF,
            &change.change_id,
            1,
            &payload,
            &meta,
            "command.project_policy_change_prepared",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

/// Loads one prepared project change scoped to the envelope project.
fn papc_row(
    conn: &rusqlite::Connection,
    project_id: &str,
    change_id: &str,
) -> Result<PreparedChangeRow, Problem> {
    get_prepared_change(
        conn,
        "project_policy_changes",
        "project_id",
        "change_id",
        change_id,
    )
    .map_err(store_problem)?
    .filter(|row| row.scope_id == project_id)
    .ok_or_else(not_found)
}

pub fn papc_confirm(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::PapcConfirmArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let row = papc_row(txn.conn(), &project_id, &args.change_id)?;
        if row.state != "prepared" {
            return Err(invalid_transition(format!("change is {}", row.state)));
        }
        check_expected_revision(&meta, row.revision)?;
        let mut change: ProjectAccessPolicyChange =
            serde_json::from_value(row.record.clone()).map_err(|_| internal())?;
        let project = get_project(txn.conn(), &project_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        // §10.1: confirm binds the exact prepared subject — a moved
        // project or item set is a dependency invalidation.
        if project.revision != change.expected_project_revision {
            return Err(stale_revision(project.revision)
                .with_detail("the project moved after preparation; the intent is stale"));
        }
        let space_ids: Vec<String> = {
            let mut stmt = txn
                .conn()
                .prepare("SELECT space_id FROM spaces WHERE project_id = ?1 ORDER BY space_id")
                .map_err(|e| store_problem(e.into()))?;
            let rows = stmt
                .query_map([&project_id], |r| r.get::<_, String>(0))
                .map_err(|e| store_problem(e.into()))?;
            rows.collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?
        };
        if item_set_digest(txn, &space_ids)? != change.affected_item_set_digest {
            return Err(stale_revision(project.revision)
                .with_detail("the affected item set changed after preparation"));
        }
        txn.conn()
            .execute(
                "UPDATE projects SET policy_set_ref = ?2,
                     default_classification_ref = ?3, revision = revision + 1
                 WHERE project_id = ?1",
                params![
                    project_id,
                    change.proposed_policy_set_ref,
                    change.proposed_default_classification_ref,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        change.state = "confirmed".to_owned();
        change.revision = row.revision + 1;
        let payload = serde_json::to_value(&change).map_err(|_| internal())?;
        txn.conn()
            .execute(
                "UPDATE project_policy_changes SET state = 'confirmed',
                     revision = ?2, record = ?3
                 WHERE change_id = ?1",
                params![
                    change.change_id,
                    change.revision as i64,
                    serde_json::to_string(&payload).map_err(|_| internal())?,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        // The decision receipt travels in the audit trail (§9.3 step 6);
        // the record shape itself is closed.
        txn.audit(
            "command.project_policy_change_receipt",
            &format!(
                "change={};receipt={}",
                change.change_id, args.decision_receipt_ref
            ),
        );
        let (revision, cursor) = prepared_change_event(
            txn,
            &project_id,
            &project_id,
            EVENT_PROJECT_POLICY_CHANGE_CONFIRMED,
            PAPC_SCHEMA_REF,
            &change.change_id,
            change.revision,
            &payload,
            &meta,
            "command.project_policy_change_confirmed",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

pub fn papc_cancel(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ChangeIdArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let row = papc_row(txn.conn(), &project_id, &args.change_id)?;
        if row.state != "prepared" {
            return Err(invalid_transition(format!("change is {}", row.state)));
        }
        check_expected_revision(&meta, row.revision)?;
        let mut change: ProjectAccessPolicyChange =
            serde_json::from_value(row.record.clone()).map_err(|_| internal())?;
        change.state = "canceled".to_owned();
        change.revision = row.revision + 1;
        let payload = serde_json::to_value(&change).map_err(|_| internal())?;
        txn.conn()
            .execute(
                "UPDATE project_policy_changes SET state = 'canceled', revision = ?2,
                     record = ?3
                 WHERE change_id = ?1",
                params![
                    change.change_id,
                    change.revision as i64,
                    serde_json::to_string(&payload).map_err(|_| internal())?,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let (revision, cursor) = prepared_change_event(
            txn,
            &project_id,
            &project_id,
            EVENT_PROJECT_POLICY_CHANGE_CANCELED,
            PAPC_SCHEMA_REF,
            &change.change_id,
            change.revision,
            &payload,
            &meta,
            "command.project_policy_change_canceled",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

pub fn papc_show(
    store: &Store,
    project_id: &str,
    args: &ops::ChangeIdArgs,
) -> Result<Vec<u8>, Problem> {
    let row = papc_row(store.conn(), project_id, &args.change_id)?;
    let revision = row.revision;
    ok_reply(row.record, Some(revision))
}

// ------------------------------------------------ space_access_widen_* ----

pub fn widen_prepare(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::WidenPrepareArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let space = visible_space(txn.conn(), &project_id, &args.space_id)?;
        if space.status == "archived" {
            return Err(invalid_transition("space is archived".to_owned()));
        }
        check_expected_revision(&meta, space.revision)?;
        let proposed_visibility = args
            .proposed_visibility
            .clone()
            .unwrap_or_else(|| space.visibility.clone());
        let proposed_policy = args
            .proposed_policy_set_ref
            .clone()
            .unwrap_or_else(|| space.policy_set_ref.clone());
        let proposed_classification = args
            .proposed_default_classification_ref
            .clone()
            .unwrap_or_else(|| space.default_classification_ref.clone());
        let space_ids = vec![space.space_id.clone()];
        let affected_frontiers = frontier_refs(txn, &space_ids)?;
        let item_digest = item_set_digest(txn, &space_ids)?;
        let subject = serde_json::json!({
            "space_id": space.space_id,
            "expected_space_revision": space.revision,
            "prior_visibility": space.visibility,
            "proposed_visibility": proposed_visibility,
            "prior_policy_set_ref": space.policy_set_ref,
            "proposed_policy_set_ref": proposed_policy,
            "prior_default_classification_ref": space.default_classification_ref,
            "proposed_default_classification_ref": proposed_classification,
            "affected_frontier_refs": affected_frontiers,
            "affected_item_set_digest": item_digest,
        });
        let widening = SpaceAccessWidening {
            widening_id: new_id("widen").map_err(store_problem)?,
            space_id: space.space_id.clone(),
            expected_space_revision: space.revision,
            prior_visibility: space.visibility.clone(),
            proposed_visibility,
            prior_policy_set_ref: space.policy_set_ref.clone(),
            proposed_policy_set_ref: proposed_policy,
            prior_default_classification_ref: space.default_classification_ref.clone(),
            proposed_default_classification_ref: proposed_classification,
            affected_frontier_refs: affected_frontiers,
            affected_item_set_digest: item_digest,
            classification_join_ref: space.default_classification_ref.clone(),
            destination_audience_digest: audience_digest(&serde_json::json!({
                "scope": "space",
                "space_id": space.space_id,
                "visibility": subject["proposed_visibility"],
            }))?,
            subject_digest: subject_digest_of(&subject)?,
            prepared_by_principal: OWNER_ACTOR_REF.to_owned(),
            state: "prepared".to_owned(),
            revision: 1,
            created_at: txn.now_ts(),
        };
        let payload = serde_json::to_value(&widening).map_err(|_| internal())?;
        txn.conn()
            .execute(
                "INSERT INTO space_access_widenings (widening_id, space_id, state,
                     revision, record, created_at)
                 VALUES (?1, ?2, 'prepared', 1, ?3, ?4)",
                params![
                    widening.widening_id,
                    widening.space_id,
                    serde_json::to_string(&payload).map_err(|_| internal())?,
                    widening.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let (revision, cursor) = prepared_change_event(
            txn,
            &project_id,
            &widening.space_id,
            EVENT_SPACE_WIDENING_PREPARED,
            WIDENING_SCHEMA_REF,
            &widening.widening_id,
            1,
            &payload,
            &meta,
            "command.space_access_widening_prepared",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

/// Loads one widening whose space is visible in this project.
fn widening_row(
    conn: &rusqlite::Connection,
    project_id: &str,
    widening_id: &str,
) -> Result<PreparedChangeRow, Problem> {
    let row = get_prepared_change(
        conn,
        "space_access_widenings",
        "space_id",
        "widening_id",
        widening_id,
    )
    .map_err(store_problem)?
    .ok_or_else(not_found)?;
    visible_space(conn, project_id, &row.scope_id)?;
    Ok(row)
}

pub fn widen_confirm(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::WidenConfirmArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let row = widening_row(txn.conn(), &project_id, &args.widening_id)?;
        if row.state != "prepared" {
            return Err(invalid_transition(format!("widening is {}", row.state)));
        }
        check_expected_revision(&meta, row.revision)?;
        let mut widening: SpaceAccessWidening =
            serde_json::from_value(row.record.clone()).map_err(|_| internal())?;
        let space = visible_space(txn.conn(), &project_id, &widening.space_id)?;
        if space.revision != widening.expected_space_revision {
            return Err(stale_revision(space.revision)
                .with_detail("the space moved after preparation; the intent is stale"));
        }
        if item_set_digest(txn, std::slice::from_ref(&space.space_id))?
            != widening.affected_item_set_digest
        {
            return Err(stale_revision(space.revision)
                .with_detail("the affected item set changed after preparation"));
        }
        txn.conn()
            .execute(
                "UPDATE spaces SET visibility = ?2, policy_set_ref = ?3,
                     default_classification_ref = ?4, revision = revision + 1
                 WHERE space_id = ?1",
                params![
                    widening.space_id,
                    widening.proposed_visibility,
                    widening.proposed_policy_set_ref,
                    widening.proposed_default_classification_ref,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        widening.state = "confirmed".to_owned();
        widening.revision = row.revision + 1;
        let payload = serde_json::to_value(&widening).map_err(|_| internal())?;
        txn.conn()
            .execute(
                "UPDATE space_access_widenings SET state = 'confirmed', revision = ?2,
                     record = ?3
                 WHERE widening_id = ?1",
                params![
                    widening.widening_id,
                    widening.revision as i64,
                    serde_json::to_string(&payload).map_err(|_| internal())?,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        txn.audit(
            "command.space_access_widening_receipt",
            &format!(
                "widening={};receipt={}",
                widening.widening_id, args.decision_receipt_ref
            ),
        );
        let (revision, cursor) = prepared_change_event(
            txn,
            &project_id,
            &widening.space_id,
            EVENT_SPACE_WIDENING_CONFIRMED,
            WIDENING_SCHEMA_REF,
            &widening.widening_id,
            widening.revision,
            &payload,
            &meta,
            "command.space_access_widening_confirmed",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

pub fn widen_cancel(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::WideningIdArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let row = widening_row(txn.conn(), &project_id, &args.widening_id)?;
        if row.state != "prepared" {
            return Err(invalid_transition(format!("widening is {}", row.state)));
        }
        check_expected_revision(&meta, row.revision)?;
        let mut widening: SpaceAccessWidening =
            serde_json::from_value(row.record.clone()).map_err(|_| internal())?;
        widening.state = "canceled".to_owned();
        widening.revision = row.revision + 1;
        let payload = serde_json::to_value(&widening).map_err(|_| internal())?;
        txn.conn()
            .execute(
                "UPDATE space_access_widenings SET state = 'canceled', revision = ?2,
                     record = ?3
                 WHERE widening_id = ?1",
                params![
                    widening.widening_id,
                    widening.revision as i64,
                    serde_json::to_string(&payload).map_err(|_| internal())?,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let (revision, cursor) = prepared_change_event(
            txn,
            &project_id,
            &widening.space_id,
            EVENT_SPACE_WIDENING_CANCELED,
            WIDENING_SCHEMA_REF,
            &widening.widening_id,
            widening.revision,
            &payload,
            &meta,
            "command.space_access_widening_canceled",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

pub fn widen_show(
    store: &Store,
    project_id: &str,
    args: &ops::WideningIdArgs,
) -> Result<Vec<u8>, Problem> {
    let row = widening_row(store.conn(), project_id, &args.widening_id)?;
    let revision = row.revision;
    ok_reply(row.record, Some(revision))
}
