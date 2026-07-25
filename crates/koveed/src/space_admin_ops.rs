//! Slice-3 space administration: §10.2 participant CRUD (addressability
//! and role presentation, never execution authority), operator-family
//! space access grants (owner-principal-bound in the personal profile,
//! registry-README resolution 6), lens CRUD (saved query/presentation
//! config — §10.4: presentation only, never authority), and `reaction_set`
//! (a lightweight mutable presentation signal, §10.2).

use kovee_core::envelope::CommandMeta;
use kovee_core::event::*;
use kovee_core::ops;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::{Reaction, Space, SpaceAccessGrant, SpaceLens, SpaceParticipant};
use kovee_store::{
    new_id, Applied, CommandScope, CommandTxn, CrashHooks, NewEvent, Store, OWNER_ACTOR_REF,
};
use rusqlite::{params, OptionalExtension as _};
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

fn refused(detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::Invalid, "invalid transition").with_detail(detail)
}

fn admin_space(txn: &CommandTxn<'_>, project_id: &str, space_id: &str) -> Result<Space, Problem> {
    let space = visible_space(txn.conn(), project_id, space_id)?;
    if space.status == "archived" {
        return Err(refused("space is archived"));
    }
    Ok(space)
}

#[allow(clippy::too_many_arguments)]
fn space_scoped_event(
    txn: &mut CommandTxn<'_>,
    project_id: &str,
    space_id: &str,
    event_type: &str,
    schema_ref: &str,
    resource_ref: &str,
    resource_revision: u64,
    payload: &Value,
    meta: &CommandMeta,
    audit_event: &str,
) -> Result<String, Problem> {
    let event = txn
        .append_event(NewEvent {
            stream_id: space_id.to_owned(),
            project_id: Some(project_id.to_owned()),
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
        &format!(
            "resource={resource_ref};space={space_id};{}",
            scope_digest(meta)
        ),
    );
    txn.mint_project_cursor(project_id, event.project_sequence.unwrap_or(0))
        .map_err(store_problem)
}

const PARTICIPANT_SCHEMA_REF: &str = "schema:space-participant-v1";
const GRANT_SCHEMA_REF: &str = "schema:space-access-grant-v1";
const LENS_SCHEMA_REF: &str = "schema:space-lens-v1";
const REACTION_SCHEMA_REF: &str = "schema:reaction-v1";

// ------------------------------------------------- space_participant_add ----

pub fn participant_add(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ParticipantAddArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let space = admin_space(txn, &project_id, &args.space_id)?;
        check_expected_revision(&meta, space.revision)?;
        let duplicate: Option<i64> = txn
            .conn()
            .query_row(
                "SELECT 1 FROM space_participants
                 WHERE space_id = ?1 AND subject_ref = ?2",
                params![space.space_id, args.subject_ref],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| store_problem(e.into()))?;
        if duplicate.is_some() {
            return Err(refused("subject is already a participant of this space"));
        }
        let participant = SpaceParticipant {
            participant_id: new_id("part").map_err(store_problem)?,
            space_id: space.space_id.clone(),
            subject_ref: args.subject_ref.clone(),
            subject_revision: args.subject_revision,
            kind: args.kind.clone(),
            role: args.role.clone(),
            authority_source_ref: "auth-local-uds".to_owned(),
            status: "proposed".to_owned(),
            revision: 1,
        };
        let subject_digest = participant_subject_digest(&participant)?;
        txn.conn()
            .execute(
                "INSERT INTO space_participants (participant_id, space_id,
                     subject_ref, subject_revision, kind, role,
                     authority_source_ref, status, revision, subject_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'proposed', 1, ?8)",
                params![
                    participant.participant_id,
                    participant.space_id,
                    participant.subject_ref,
                    participant.subject_revision.map(|r| r as i64),
                    participant.kind,
                    participant.role,
                    participant.authority_source_ref,
                    subject_digest,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&participant).map_err(|_| internal())?;
        let cursor = space_scoped_event(
            txn,
            &project_id,
            &space.space_id,
            EVENT_PARTICIPANT_ADDED,
            PARTICIPANT_SCHEMA_REF,
            &participant.participant_id,
            1,
            &payload,
            &meta,
            "command.space_participant_added",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(1),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

/// Loads a participant whose space is visible in this project.
fn visible_participant(
    txn: &CommandTxn<'_>,
    project_id: &str,
    participant_id: &str,
) -> Result<(SpaceParticipant, Option<String>, Space), Problem> {
    let (participant, digest) = get_participant(txn.conn(), participant_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let space = admin_space(txn, project_id, &participant.space_id)?;
    Ok((participant, digest, space))
}

#[allow(clippy::too_many_arguments)]
fn participant_mutation(
    txn: &mut CommandTxn<'_>,
    project_id: &str,
    participant: SpaceParticipant,
    space: &Space,
    event_type: &str,
    meta: &CommandMeta,
    audit_event: &str,
) -> Result<Applied, Problem> {
    let payload = serde_json::to_value(&participant).map_err(|_| internal())?;
    let cursor = space_scoped_event(
        txn,
        project_id,
        &space.space_id,
        event_type,
        PARTICIPANT_SCHEMA_REF,
        &participant.participant_id,
        participant.revision,
        &payload,
        meta,
        audit_event,
    )?;
    Ok(Applied {
        result: payload,
        revision: Some(participant.revision),
        event_cursor: Some(cursor),
    })
}

// -------------------------------------------- space_participant_activate ----

/// Operator decision family (owner-bound in the personal profile): binds
/// the exact prepared subject digest (KG19) — a changed proposal fails
/// the match.
pub fn participant_activate(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ParticipantActivateArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let (mut participant, stored_digest, space) =
            visible_participant(txn, &project_id, &args.participant_id)?;
        check_expected_revision(&meta, participant.revision)?;
        if participant.status != "proposed" {
            return Err(refused(format!(
                "participant is {}, not proposed",
                participant.status
            )));
        }
        let expected = match stored_digest {
            Some(digest) => digest,
            None => participant_subject_digest(&participant)?,
        };
        if args.subject_digest != expected {
            return Err(stale_revision(participant.revision)
                .with_detail("subject_digest does not match the exact prepared subject"));
        }
        participant.status = "active".to_owned();
        participant.revision += 1;
        txn.conn()
            .execute(
                "UPDATE space_participants SET status = 'active',
                     revision = revision + 1
                 WHERE participant_id = ?1",
                [&participant.participant_id],
            )
            .map_err(|e| store_problem(e.into()))?;
        participant_mutation(
            txn,
            &project_id,
            participant,
            &space,
            EVENT_PARTICIPANT_ACTIVATED,
            &meta,
            "command.space_participant_activated",
        )
    });
    command_outcome_bytes(outcome)
}

// ---------------------------------------------- space_participant_update ----

pub fn participant_update(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ParticipantUpdateArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let (mut participant, _, space) =
            visible_participant(txn, &project_id, &args.participant_id)?;
        check_expected_revision(&meta, participant.revision)?;
        if participant.status == "revoked" {
            return Err(refused("participant is revoked"));
        }
        if let Some(status) = &args.status {
            // KG19: activation and removal have their own operations —
            // update may only move between active and muted.
            if !["active", "muted"].contains(&status.as_str())
                || !["active", "muted"].contains(&participant.status.as_str())
            {
                return Err(refused(
                    "status updates move only between active and muted (KG19)",
                ));
            }
            participant.status = status.clone();
        }
        if let Some(role) = &args.role {
            participant.role = role.clone();
        }
        participant.revision += 1;
        txn.conn()
            .execute(
                "UPDATE space_participants SET role = ?2, status = ?3,
                     revision = revision + 1
                 WHERE participant_id = ?1",
                params![
                    participant.participant_id,
                    participant.role,
                    participant.status
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        participant_mutation(
            txn,
            &project_id,
            participant,
            &space,
            EVENT_PARTICIPANT_UPDATED,
            &meta,
            "command.space_participant_updated",
        )
    });
    command_outcome_bytes(outcome)
}

// ---------------------------------------------- space_participant_remove ----

pub fn participant_remove(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ParticipantIdArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let (mut participant, _, space) =
            visible_participant(txn, &project_id, &args.participant_id)?;
        check_expected_revision(&meta, participant.revision)?;
        if participant.status == "revoked" {
            return Err(refused("participant is already revoked"));
        }
        participant.status = "revoked".to_owned();
        participant.revision += 1;
        txn.conn()
            .execute(
                "UPDATE space_participants SET status = 'revoked',
                     revision = revision + 1
                 WHERE participant_id = ?1",
                [&participant.participant_id],
            )
            .map_err(|e| store_problem(e.into()))?;
        participant_mutation(
            txn,
            &project_id,
            participant,
            &space,
            EVENT_PARTICIPANT_REMOVED,
            &meta,
            "command.space_participant_removed",
        )
    });
    command_outcome_bytes(outcome)
}

// ------------------------------------------------ space_access_grant_* ----

pub fn grant_create(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::GrantCreateArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let space = admin_space(txn, &project_id, &args.space_id)?;
        check_expected_revision(&meta, space.revision)?;
        let grant = SpaceAccessGrant {
            space_access_id: new_id("sgrant").map_err(store_problem)?,
            space_id: space.space_id.clone(),
            subject_ref: args.subject_ref.clone(),
            revision: 1,
            source_membership_or_policy_ref: "policy-owner-local".to_owned(),
            allowed_actions: args.allowed_actions.clone(),
            classification_ceiling_ref: args.classification_ceiling_ref.clone(),
            authorization_epoch: 1,
            expires_at: args.expires_at.clone(),
            status: "active".to_owned(),
            granted_by_or_policy_use_ref: OWNER_ACTOR_REF.to_owned(),
            created_at: txn.now_ts(),
        };
        txn.conn()
            .execute(
                "INSERT INTO space_access_grants (space_access_id, space_id,
                     subject_ref, revision, source_membership_or_policy_ref,
                     allowed_actions, classification_ceiling_ref,
                     authorization_epoch, expires_at, status,
                     granted_by_or_policy_use_ref, created_at)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 1, ?7, 'active', ?8, ?9)",
                params![
                    grant.space_access_id,
                    grant.space_id,
                    grant.subject_ref,
                    grant.source_membership_or_policy_ref,
                    serde_json::to_string(&grant.allowed_actions).map_err(|_| internal())?,
                    grant.classification_ceiling_ref,
                    grant.expires_at,
                    grant.granted_by_or_policy_use_ref,
                    grant.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&grant).map_err(|_| internal())?;
        let cursor = space_scoped_event(
            txn,
            &project_id,
            &space.space_id,
            EVENT_GRANT_CREATED,
            GRANT_SCHEMA_REF,
            &grant.space_access_id,
            1,
            &payload,
            &meta,
            "command.space_access_grant_created",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(1),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

pub fn grant_revoke(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::GrantRevokeArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let mut grant = get_grant(txn.conn(), &args.space_access_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        let space = visible_space(txn.conn(), &project_id, &grant.space_id)?;
        check_expected_revision(&meta, grant.revision)?;
        if grant.status != "active" {
            return Err(refused(format!("grant is {}", grant.status)));
        }
        grant.status = "revoked".to_owned();
        grant.revision += 1;
        txn.conn()
            .execute(
                "UPDATE space_access_grants SET status = 'revoked',
                     revision = revision + 1
                 WHERE space_access_id = ?1",
                [&grant.space_access_id],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&grant).map_err(|_| internal())?;
        let cursor = space_scoped_event(
            txn,
            &project_id,
            &space.space_id,
            EVENT_GRANT_REVOKED,
            GRANT_SCHEMA_REF,
            &grant.space_access_id,
            grant.revision,
            &payload,
            &meta,
            "command.space_access_grant_revoked",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(grant.revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

// ---------------------------------------------------------- lens CRUD ----

pub fn lens_create(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::LensCreateArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let space = admin_space(txn, &project_id, &args.space_id)?;
        check_expected_revision(&meta, space.revision)?;
        let lens = SpaceLens {
            lens_id: new_id("lens").map_err(store_problem)?,
            space_id: space.space_id.clone(),
            owner_ref: Some(OWNER_ACTOR_REF.to_owned()),
            revision: 1,
            kind: args.kind.clone(),
            query_ast: args.query_ast.clone(),
            sort_spec: args.sort_spec.clone(),
            presentation_options: args.presentation_options.clone(),
            visibility: args.visibility.clone(),
            status: "active".to_owned(),
            created_at: txn.now_ts(),
        };
        txn.conn()
            .execute(
                "INSERT INTO space_lenses (lens_id, space_id, owner_ref, revision,
                     kind, query_ast, sort_spec, presentation_options, visibility,
                     status, created_at)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, 'active', ?9)",
                params![
                    lens.lens_id,
                    lens.space_id,
                    OWNER_ACTOR_REF,
                    lens.kind,
                    serde_json::to_string(&lens.query_ast).map_err(|_| internal())?,
                    serde_json::to_string(&lens.sort_spec).map_err(|_| internal())?,
                    serde_json::to_string(&lens.presentation_options).map_err(|_| internal())?,
                    lens.visibility,
                    lens.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&lens).map_err(|_| internal())?;
        let cursor = space_scoped_event(
            txn,
            &project_id,
            &space.space_id,
            EVENT_LENS_CREATED,
            LENS_SCHEMA_REF,
            &lens.lens_id,
            1,
            &payload,
            &meta,
            "command.lens_created",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(1),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

pub fn lens_update(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::LensUpdateArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let mut lens = get_lens_full(txn.conn(), &args.lens_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        let space = admin_space(txn, &project_id, &lens.space_id)?;
        check_expected_revision(&meta, lens.revision)?;
        if let Some(query_ast) = &args.query_ast {
            lens.query_ast = query_ast.clone();
        }
        if let Some(sort_spec) = &args.sort_spec {
            lens.sort_spec = sort_spec.clone();
        }
        if let Some(options) = &args.presentation_options {
            lens.presentation_options = options.clone();
        }
        if let Some(visibility) = &args.visibility {
            lens.visibility = visibility.clone();
        }
        lens.revision += 1;
        txn.conn()
            .execute(
                "UPDATE space_lenses SET query_ast = ?2, sort_spec = ?3,
                     presentation_options = ?4, visibility = ?5,
                     revision = revision + 1
                 WHERE lens_id = ?1",
                params![
                    lens.lens_id,
                    serde_json::to_string(&lens.query_ast).map_err(|_| internal())?,
                    serde_json::to_string(&lens.sort_spec).map_err(|_| internal())?,
                    serde_json::to_string(&lens.presentation_options).map_err(|_| internal())?,
                    lens.visibility,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&lens).map_err(|_| internal())?;
        let cursor = space_scoped_event(
            txn,
            &project_id,
            &space.space_id,
            EVENT_LENS_UPDATED,
            LENS_SCHEMA_REF,
            &lens.lens_id,
            lens.revision,
            &payload,
            &meta,
            "command.lens_updated",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(lens.revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

pub fn lens_revoke(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::LensIdArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let mut lens = get_lens_full(txn.conn(), &args.lens_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        let space = admin_space(txn, &project_id, &lens.space_id)?;
        check_expected_revision(&meta, lens.revision)?;
        lens.status = "revoked".to_owned();
        lens.revision += 1;
        txn.conn()
            .execute(
                "UPDATE space_lenses SET status = 'revoked', revision = revision + 1
                 WHERE lens_id = ?1",
                [&lens.lens_id],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&lens).map_err(|_| internal())?;
        let cursor = space_scoped_event(
            txn,
            &project_id,
            &space.space_id,
            EVENT_LENS_REVOKED,
            LENS_SCHEMA_REF,
            &lens.lens_id,
            lens.revision,
            &payload,
            &meta,
            "command.lens_revoked",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(lens.revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

pub fn lens_show(
    store: &Store,
    project_id: &str,
    args: &ops::LensIdArgs,
) -> Result<Vec<u8>, Problem> {
    let lens = get_lens_full(store.conn(), &args.lens_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    visible_space(store.conn(), project_id, &lens.space_id)?;
    let revision = lens.revision;
    ok_reply(
        serde_json::to_value(&lens).map_err(|_| internal())?,
        Some(revision),
    )
}

// --------------------------------------------------------- reaction_set ----

/// §10.2 `reaction_set`: an idempotent upsert under
/// `UNIQUE(target_ref, actor_ref, key)` against an exact pinned target
/// revision/digest — a moved target is a dependency invalidation.
pub fn reaction_set(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ReactionSetArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let space = visible_space(txn.conn(), &project_id, &args.space_id)?;
        if space.status != "open" {
            return Err(Problem::new(
                ProblemKind::StaleRevision,
                "space is not open for reactions",
            ));
        }
        check_expected_revision(&meta, space.revision)?;
        let target = resolve_space_object(txn.conn(), &space.space_id, &args.target_ref)?;
        if args.target_revision != target.revision() {
            return Err(stale_revision(target.revision())
                .with_detail("target_revision pins a stale target"));
        }
        if args.target_digest != target.digest() {
            return Err(stale_revision(target.revision())
                .with_detail("target_digest does not match the visible target"));
        }
        let existing = get_reaction(txn.conn(), &args.target_ref, OWNER_ACTOR_REF, &args.key)
            .map_err(store_problem)?;
        let reaction = match existing {
            Some(mut reaction) => {
                if reaction.state == args.state {
                    // Same state: the upsert converges without a new event.
                    return Ok(Applied {
                        revision: Some(reaction.revision),
                        result: serde_json::to_value(&reaction).map_err(|_| internal())?,
                        event_cursor: None,
                    });
                }
                reaction.state = args.state.clone();
                reaction.target_revision = args.target_revision;
                reaction.target_digest = args.target_digest.clone();
                reaction.revision += 1;
                reaction.updated_at = txn.now_ts();
                txn.conn()
                    .execute(
                        "UPDATE reactions SET state = ?2, target_revision = ?3,
                             target_digest = ?4, revision = revision + 1,
                             updated_at = ?5
                         WHERE reaction_id = ?1",
                        params![
                            reaction.reaction_id,
                            reaction.state,
                            reaction.target_revision as i64,
                            reaction.target_digest,
                            reaction.updated_at,
                        ],
                    )
                    .map_err(|e| store_problem(e.into()))?;
                reaction
            }
            None => {
                let reaction = Reaction {
                    reaction_id: new_id("react").map_err(store_problem)?,
                    space_id: space.space_id.clone(),
                    target_ref: args.target_ref.clone(),
                    target_revision: args.target_revision,
                    target_digest: args.target_digest.clone(),
                    actor_ref: OWNER_ACTOR_REF.to_owned(),
                    key: args.key.clone(),
                    state: args.state.clone(),
                    revision: 1,
                    updated_at: txn.now_ts(),
                };
                txn.conn()
                    .execute(
                        "INSERT INTO reactions (reaction_id, space_id, target_ref,
                             target_revision, target_digest, actor_ref, key, state,
                             revision, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
                        params![
                            reaction.reaction_id,
                            reaction.space_id,
                            reaction.target_ref,
                            reaction.target_revision as i64,
                            reaction.target_digest,
                            reaction.actor_ref,
                            reaction.key,
                            reaction.state,
                            reaction.updated_at,
                        ],
                    )
                    .map_err(|e| store_problem(e.into()))?;
                reaction
            }
        };
        let payload = serde_json::to_value(&reaction).map_err(|_| internal())?;
        let cursor = space_scoped_event(
            txn,
            &project_id,
            &space.space_id,
            EVENT_REACTION_SET,
            REACTION_SCHEMA_REF,
            &reaction.reaction_id,
            reaction.revision,
            &payload,
            &meta,
            "command.reaction_set",
        )?;
        Ok(Applied {
            result: payload,
            revision: Some(reaction.revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}
