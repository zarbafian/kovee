//! The K1 core operation handlers (slice 1, updated for the slice-2
//! branch tables). Reads answer from normalized state and never mutate
//! (§11.2); mutations run §12.2 through
//! [`kovee_store::Store::command_transaction`] — state, event(s),
//! idempotency record, and outbox commit atomically or not at all.

use kovee_core::canonical;
use kovee_core::envelope::{CommandResult, RawCommand};
use kovee_core::event::{EVENT_CONTRIBUTION_APPENDED, EVENT_PROJECT_CREATED, EVENT_SPACE_CREATED};
use kovee_core::ops;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::{Contribution, ContributionPart, HelloResult, Project, Space};
use kovee_store::{
    new_id, privacy, Applied, CommandError, CommandScope, CrashHooks, NewEvent, Store,
    OWNER_ACTOR_REF,
};
use rusqlite::{params, Connection};
use serde_json::Value;

use crate::state::*;

/// The primary authority surface of the local socket (§11.6.1): an
/// external client channel for the same-UID owner principal.
pub const SURFACE: &str = "external_client";
/// The worker surface (§23.3): a separate socket, fenced attempt actors.
pub const WORKER_SURFACE: &str = "worker";

pub fn command_outcome_bytes(
    outcome: Result<kovee_store::CommandOutcome, CommandError>,
) -> Result<Vec<u8>, Problem> {
    match outcome {
        Ok(o) => Ok(o.bytes().to_vec()),
        Err(CommandError::Problem(p)) => Err(p),
        Err(CommandError::Store(e)) => Err(store_problem(e)),
    }
}

pub fn ok_reply(result: Value, revision: Option<u64>) -> Result<Vec<u8>, Problem> {
    serde_json::to_vec(&CommandResult::Ok {
        result,
        revision,
        event_cursor: None,
    })
    .map_err(|_| internal())
}

pub fn scope_for(cmd: &RawCommand, realm_id: &str) -> Result<CommandScope, Problem> {
    let meta = cmd.meta.as_ref().ok_or_else(internal)?;
    Ok(CommandScope {
        // §11.2: idempotency keys are scoped by authenticated actor,
        // operation, and realm; the actor is channel-derived (§9.1).
        actor_scope: format!("{SURFACE}/{OWNER_ACTOR_REF}/{realm_id}"),
        operation: cmd.op.clone(),
        idempotency_key: meta.idempotency_key.clone(),
        request_digest: canonical::idempotency_request_digest(cmd, SURFACE)
            .map_err(|_| internal())?,
    })
}

pub fn scope_digest(meta: &kovee_core::envelope::CommandMeta) -> String {
    // Body-free audit detail: the idempotency key names the command
    // without carrying content.
    format!("idem={}", meta.idempotency_key)
}

// ------------------------------------------------------------- hello ----

pub fn hello(store: &Store, args: &ops::HelloArgs, now: i64) -> Result<Vec<u8>, Problem> {
    if !args
        .supported_versions
        .iter()
        .any(|v| v == kovee_core::PROTOCOL_VERSION)
    {
        return Err(Problem::new(
            ProblemKind::UnsupportedVersion,
            "no common protocol version",
        ));
    }
    // §11.8 limits object; its digest construction is a recorded K0 gap
    // (shape-only), pinned here as a canonical-object digest over the
    // §11.8 caps this daemon enforces.
    let limits = serde_json::json!({
        "request_bytes": kovee_core::limits::REQUEST_MAX_BYTES,
        "reply_bytes": kovee_core::limits::REPLY_MAX_BYTES,
        "identifier_bytes": 128,
        "display_name_scalars": 256,
        "inline_content_scalars": kovee_core::limits::INLINE_TEXT_MAX_SCALARS,
        "list_items": kovee_core::limits::LIST_MAX_ITEMS,
        "page_limit": kovee_core::limits::PAGE_MAX_LIMIT,
    });
    let (_, limits_digest) =
        canonical::canonical_object_digest("kcp-limits", "schema:kcp-limits-v1", &limits)
            .map_err(|_| internal())?;
    let result = HelloResult {
        selected_version: kovee_core::PROTOCOL_VERSION.to_owned(),
        implementation: "koveed".to_owned(),
        implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
        // Honesty (§11.6): bundles are atomic — K1 slice 2 still
        // implements only part of shared_space_v1/developer_assistant_v1
        // (no dispositions, lifecycle, participants CRUD, snapshots), so
        // nothing is advertised yet.
        features: Vec::new(),
        limits_digest,
        server_time: kovee_core::time::rfc3339_utc(now),
        installation_id: store.installation_id().map_err(store_problem)?,
    };
    ok_reply(serde_json::to_value(&result).map_err(|_| internal())?, None)
}

// -------------------------------------------------------- realm_show ----

pub fn realm_show(store: &Store, realm_id: &str) -> Result<Vec<u8>, Problem> {
    let realm = store
        .get_realm(realm_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let revision = realm.revision;
    ok_reply(
        serde_json::to_value(&realm).map_err(|_| internal())?,
        Some(revision),
    )
}

// ---------------------------------------------------- project_create ----

pub fn project_create(
    store: &mut Store,
    cmd: &RawCommand,
    args: &ops::ProjectCreateArgs,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let realm_id = cmd.realm_id.clone().ok_or_else(internal)?;
    let scope = scope_for(cmd, &realm_id)?;
    let args = args.clone();
    let meta = cmd.meta.clone().ok_or_else(internal)?;
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        if let Some(expected) = meta.expected_revision {
            // The aggregate does not exist yet; only 0 can match.
            if expected != 0 {
                return Err(stale_revision(0));
            }
        }
        let project_id = new_id("proj").map_err(store_problem)?;
        let project = Project {
            project_id: project_id.clone(),
            realm_id: txn.realm_id().to_owned(),
            revision: 1,
            name: args.name.clone(),
            status: "active".to_owned(),
            default_classification_ref: args
                .default_classification_ref
                .clone()
                .unwrap_or_else(|| DEFAULT_CLASSIFICATION.to_owned()),
            policy_set_ref: args
                .policy_set_ref
                .clone()
                .unwrap_or_else(|| DEFAULT_POLICY_SET.to_owned()),
            created_by: OWNER_ACTOR_REF.to_owned(),
            created_at: txn.now_ts(),
        };
        txn.conn()
            .execute(
                "INSERT INTO projects (project_id, realm_id, revision, name, status,
                     default_classification_ref, policy_set_ref, created_by,
                     created_at, next_project_sequence)
                 VALUES (?1, ?2, 1, ?3, 'active', ?4, ?5, ?6, ?7, 1)",
                params![
                    project.project_id,
                    project.realm_id,
                    project.name,
                    project.default_classification_ref,
                    project.policy_set_ref,
                    project.created_by,
                    project.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&project).map_err(|_| internal())?;
        let event = txn
            .append_event(NewEvent {
                stream_id: project_id.clone(),
                project_id: Some(project_id.clone()),
                actor_ref: None,
                event_type: EVENT_PROJECT_CREATED,
                schema_ref: PROJECT_SCHEMA_REF.to_owned(),
                resource_ref: project_id.clone(),
                resource_revision: Some(1),
                causation_ref: meta.causation_event_ref.clone(),
                correlation_ref: meta.request_id.clone(),
                classification_ref: project.default_classification_ref.clone(),
                payload: payload.clone(),
            })
            .map_err(store_problem)?;
        txn.audit(
            "command.project_created",
            &format!("project={project_id};{}", scope_digest(&meta)),
        );
        let cursor = txn
            .mint_project_cursor(&project_id, event.project_sequence.unwrap_or(0))
            .map_err(store_problem)?;
        Ok(Applied {
            result: payload,
            revision: Some(1),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

// ------------------------------------------------------ space_create ----

pub fn space_create(
    store: &mut Store,
    cmd: &RawCommand,
    args: &ops::SpaceCreateArgs,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let realm_id = cmd.realm_id.clone().ok_or_else(internal)?;
    let project_id = cmd.project_id.clone().ok_or_else(internal)?;
    let scope = scope_for(cmd, &realm_id)?;
    let args = args.clone();
    let meta = cmd.meta.clone().ok_or_else(internal)?;
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let project = get_project(txn.conn(), &project_id)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        if let Some(expected) = meta.expected_revision {
            if expected != 0 {
                return Err(stale_revision(0));
            }
        }
        let space_id = new_id("space").map_err(store_problem)?;
        let main_branch_id = new_id("branch").map_err(store_problem)?;
        let head = kovee_core::branch::genesis_head(&main_branch_id);
        let space = Space {
            space_id: space_id.clone(),
            realm_id: txn.realm_id().to_owned(),
            project_id: project_id.clone(),
            revision: 1,
            title: args.title.clone(),
            purpose_contribution_ref: args.purpose_contribution_ref.clone(),
            visibility: args.visibility.clone(),
            status: "open".to_owned(),
            main_branch_id: main_branch_id.clone(),
            next_space_sequence: 1,
            default_classification_ref: args
                .default_classification_ref
                .clone()
                .unwrap_or(project.default_classification_ref),
            policy_set_ref: args
                .policy_set_ref
                .clone()
                .unwrap_or(project.policy_set_ref),
            created_by: OWNER_ACTOR_REF.to_owned(),
            created_at: txn.now_ts(),
        };
        txn.conn()
            .execute(
                "INSERT INTO spaces (space_id, realm_id, project_id, revision, title,
                     purpose_contribution_ref, visibility, status, main_branch_id,
                     next_space_sequence, default_classification_ref,
                     policy_set_ref, created_by, created_at)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 'open', ?7, 1, ?8, ?9, ?10, ?11)",
                params![
                    space.space_id,
                    space.realm_id,
                    space.project_id,
                    space.title,
                    space.purpose_contribution_ref,
                    space.visibility,
                    space.main_branch_id,
                    space.default_classification_ref,
                    space.policy_set_ref,
                    space.created_by,
                    space.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        // §10.3: every space starts with a main branch; the head CAS
        // lives on the branch row.
        txn.conn()
            .execute(
                "INSERT INTO reasoning_branches (branch_id, space_id, revision,
                     purpose_contribution_ref, parent_branch_id, base_frontier_ref,
                     base_frontier_digest, next_branch_sequence, head_digest,
                     status, created_by, created_at)
                 VALUES (?1, ?2, 1, NULL, NULL, NULL, NULL, 1, ?3, 'open', ?4, ?5)",
                params![
                    space.main_branch_id,
                    space.space_id,
                    head,
                    space.created_by,
                    space.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        // §10.2: the creator is the space's first participant (steward).
        let participant_id = new_id("part").map_err(store_problem)?;
        txn.conn()
            .execute(
                "INSERT INTO space_participants (participant_id, space_id,
                     subject_ref, subject_revision, kind, role,
                     authority_source_ref, status, revision)
                 VALUES (?1, ?2, ?3, NULL, 'principal', 'steward',
                     'auth-local-uds', 'active', 1)",
                params![participant_id, space.space_id, OWNER_ACTOR_REF],
            )
            .map_err(|e| store_problem(e.into()))?;
        // §10.4/§10.7-in-plan: the two built-in presentation lenses with
        // deterministic ids — saved query/presentation config, never a
        // second content model and never authority.
        for (kind, query, render) in [
            ("stream", "contributions", "chronological"),
            ("workbench", "typed_cards", "cards_with_relations"),
        ] {
            txn.conn()
                .execute(
                    "INSERT INTO space_lenses (lens_id, space_id, owner_ref,
                         revision, kind, query_ast, sort_spec,
                         presentation_options, visibility, status, created_at)
                     VALUES (?1, ?2, ?3, 1, ?4, ?5,
                         '{\"order_by\":\"branch_sequence\"}', ?6, ?7, 'active', ?8)",
                    params![
                        format!("lens-{kind}-{}", space.space_id),
                        space.space_id,
                        space.created_by,
                        kind,
                        format!("{{\"select\":\"{query}\"}}"),
                        format!("{{\"render\":\"{render}\"}}"),
                        space.visibility,
                        space.created_at,
                    ],
                )
                .map_err(|e| store_problem(e.into()))?;
        }
        let payload = serde_json::to_value(&space).map_err(|_| internal())?;
        let event = txn
            .append_event(NewEvent {
                stream_id: space_id.clone(),
                project_id: Some(project_id.clone()),
                actor_ref: None,
                event_type: EVENT_SPACE_CREATED,
                schema_ref: SPACE_SCHEMA_REF.to_owned(),
                resource_ref: space_id.clone(),
                resource_revision: Some(1),
                causation_ref: meta.causation_event_ref.clone(),
                correlation_ref: meta.request_id.clone(),
                classification_ref: space.default_classification_ref.clone(),
                payload: payload.clone(),
            })
            .map_err(store_problem)?;
        txn.audit(
            "command.space_created",
            &format!("space={space_id};{}", scope_digest(&meta)),
        );
        let cursor = txn
            .mint_project_cursor(&project_id, event.project_sequence.unwrap_or(0))
            .map_err(store_problem)?;
        Ok(Applied {
            result: payload,
            revision: Some(1),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

// -------------------------------------------------------- space_show ----

pub fn space_show(
    store: &Store,
    project_id: &str,
    args: &ops::SpaceShowArgs,
) -> Result<Vec<u8>, Problem> {
    let space = visible_space(store.conn(), project_id, &args.space_id)?;
    let revision = space.revision;
    ok_reply(
        serde_json::to_value(&space).map_err(|_| internal())?,
        Some(revision),
    )
}

// ------------------------------------------------ contribution_append ----

/// Who a contribution append is attributed to and bound by.
pub struct AppendAuthor {
    pub actor_ref: String,
    pub invocation_ref: Option<String>,
    pub context_assembly_ref: Option<String>,
    /// The worker attempt binding `(attempt_id, fence_epoch)` (§15.2);
    /// its currency is re-checked inside the command transaction, after
    /// the idempotency replay check — a replayed result needs no live
    /// lease.
    pub binding: Option<(String, u64)>,
}

impl AppendAuthor {
    pub fn owner() -> AppendAuthor {
        AppendAuthor {
            actor_ref: OWNER_ACTOR_REF.to_owned(),
            invocation_ref: None,
            context_assembly_ref: None,
            binding: None,
        }
    }

    /// Validates the attempt binding (when present) inside an open
    /// command transaction.
    pub fn check(&self, conn: &Connection) -> Result<(), Problem> {
        if let Some((attempt_id, fence)) = &self.binding {
            let (attempt, invocation) = crate::invoke::check_binding(conn, attempt_id, *fence)?;
            if Some(&invocation.invocation_id) != self.invocation_ref.as_ref()
                || attempt.invocation_id != invocation.invocation_id
            {
                return Err(Problem::new(
                    ProblemKind::StaleLease,
                    "attempt binding is not current",
                ));
            }
        }
        Ok(())
    }
}

/// The shared §10.2/§10.3 append core, used by both surfaces: validates
/// same-space references, CASes the branch head, appends the branch
/// entry, and advances the space aggregate.
#[allow(clippy::too_many_arguments)]
pub fn append_contribution(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ContributionAppendArgs,
    meta: kovee_core::envelope::CommandMeta,
    author: AppendAuthor,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        author.check(txn.conn())?;
        let space = visible_space(txn.conn(), &project_id, &args.space_id)?;
        if space.status != "open" {
            return Err(Problem::new(
                ProblemKind::StaleRevision,
                "space is not open for contributions",
            )
            .with_detail(format!("space status is {}", space.status)));
        }
        let branch = visible_branch(txn.conn(), &space, &args.branch_id)?;
        if let Some(expected) = meta.expected_revision {
            if expected != space.revision {
                return Err(stale_revision(space.revision));
            }
        }
        // §10.3/§11.2: every branch append presents the expected head
        // digest and compare-and-swaps; a stale writer must rebase.
        if args.expected_head_digest != branch.head_digest {
            return Err(stale_revision(space.revision)
                .with_detail("expected_head_digest does not match the current branch head"));
        }
        // §10.4: only services may append a system_notice; neither the
        // external client nor a worker attempt is one.
        if args.kind == "system_notice" {
            return Err(Problem::new(
                ProblemKind::Forbidden,
                "system_notice is service-only (§10.4)",
            ));
        }
        // §10.2: every referenced object must be visible in this space;
        // an artifact part may only name an available artifact (§10.10).
        validate_parts(txn.conn(), &space, &args.body_parts)?;
        for refs in [&args.subject_refs, &args.source_refs] {
            for object_ref in refs.iter().flatten() {
                resolve_space_object(txn.conn(), &space.space_id, object_ref)?;
            }
        }
        let contribution_id = new_id("contrib").map_err(store_problem)?;
        let branch_sequence = branch.next_branch_sequence;
        let space_sequence = space.next_space_sequence;
        let subject_refs = args.subject_refs.clone().unwrap_or_default();
        let source_refs = args.source_refs.clone().unwrap_or_default();
        // §11.8: the content digest projection is implementation-pinned
        // (recorded K0 gap). A5 note: this is a plaintext canonical-object
        // digest; when contribution redaction lands, the digest class
        // must move to the family's erasure-safe class.
        let content_projection = serde_json::json!({
            "space_id": args.space_id,
            "origin_branch_id": args.branch_id,
            "origin_branch_sequence": branch_sequence,
            "kind": args.kind,
            "body_parts": args.body_parts,
            "subject_refs": subject_refs,
            "source_refs": source_refs,
            "epistemic_posture": args.epistemic_posture,
        });
        let (_, content_digest) = canonical::canonical_object_digest(
            "kovee-contribution-content",
            CONTRIBUTION_SCHEMA_REF,
            &content_projection,
        )
        .map_err(|_| internal())?;
        let contribution = Contribution {
            contribution_id: contribution_id.clone(),
            revision: 1,
            realm_id: txn.realm_id().to_owned(),
            project_id: project_id.clone(),
            space_id: args.space_id.clone(),
            origin_branch_id: args.branch_id.clone(),
            origin_branch_sequence: branch_sequence,
            space_sequence,
            author_actor_ref: author.actor_ref.clone(),
            kind: args.kind.clone(),
            schema_ref: args
                .schema_ref
                .clone()
                .unwrap_or_else(|| CONTRIBUTION_SCHEMA_REF.to_owned()),
            body_parts: args.body_parts.clone(),
            subject_refs,
            source_refs,
            epistemic_posture: args.epistemic_posture.clone(),
            invocation_ref: author.invocation_ref.clone(),
            context_assembly_ref: author.context_assembly_ref.clone(),
            causation_ref: meta.causation_event_ref.clone(),
            classification_ref: args
                .classification_ref
                .clone()
                .unwrap_or_else(|| space.default_classification_ref.clone()),
            retention_policy_ref: args
                .retention_policy_ref
                .clone()
                .unwrap_or_else(|| DEFAULT_RETENTION.to_owned()),
            content_digest: content_digest.clone(),
            created_at: txn.now_ts(),
        };
        txn.conn()
            .execute(
                "INSERT INTO contributions (contribution_id, revision, realm_id,
                     project_id, space_id, origin_branch_id, origin_branch_sequence,
                     space_sequence, author_actor_ref, kind, schema_ref, body_parts,
                     subject_refs, source_refs, epistemic_posture, invocation_ref,
                     context_assembly_ref, causation_ref, classification_ref,
                     retention_policy_ref, content_digest, created_at)
                 VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                     ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                params![
                    contribution.contribution_id,
                    contribution.realm_id,
                    contribution.project_id,
                    contribution.space_id,
                    contribution.origin_branch_id,
                    contribution.origin_branch_sequence as i64,
                    contribution.space_sequence as i64,
                    contribution.author_actor_ref,
                    contribution.kind,
                    contribution.schema_ref,
                    serde_json::to_string(&contribution.body_parts).map_err(|_| internal())?,
                    serde_json::to_string(&contribution.subject_refs).map_err(|_| internal())?,
                    serde_json::to_string(&contribution.source_refs).map_err(|_| internal())?,
                    contribution.epistemic_posture,
                    contribution.invocation_ref,
                    contribution.context_assembly_ref,
                    contribution.causation_ref,
                    contribution.classification_ref,
                    contribution.retention_policy_ref,
                    contribution.content_digest,
                    contribution.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        advance_branch(
            txn.conn(),
            &branch,
            &contribution_id,
            1,
            &content_digest,
            &contribution.created_at,
        )?;
        let new_revision = space.revision + 1;
        txn.conn()
            .execute(
                "UPDATE spaces SET next_space_sequence = next_space_sequence + 1,
                     revision = ?2
                 WHERE space_id = ?1",
                params![space.space_id, new_revision as i64],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&contribution).map_err(|_| internal())?;
        let event = txn
            .append_event(NewEvent {
                stream_id: space.space_id.clone(),
                project_id: Some(project_id.clone()),
                actor_ref: Some(author.actor_ref.clone()),
                event_type: EVENT_CONTRIBUTION_APPENDED,
                schema_ref: CONTRIBUTION_SCHEMA_REF.to_owned(),
                resource_ref: contribution_id.clone(),
                resource_revision: Some(1),
                causation_ref: meta.causation_event_ref.clone(),
                correlation_ref: meta.request_id.clone(),
                classification_ref: contribution.classification_ref.clone(),
                payload: payload.clone(),
            })
            .map_err(store_problem)?;
        txn.audit(
            "command.contribution_appended",
            &format!(
                "contribution={contribution_id};space={};digest={content_digest};{}",
                space.space_id,
                scope_digest(&meta)
            ),
        );
        let cursor = txn
            .mint_project_cursor(&project_id, event.project_sequence.unwrap_or(0))
            .map_err(store_problem)?;
        Ok(Applied {
            result: payload,
            revision: Some(new_revision),
            event_cursor: Some(cursor),
        })
    });
    command_outcome_bytes(outcome)
}

/// Advances one branch: inserts the dense branch entry and CASes the
/// head fold (§10.3).
pub fn advance_branch(
    conn: &Connection,
    branch: &BranchRow,
    object_ref: &str,
    object_revision: u64,
    object_digest: &str,
    created_at: &str,
) -> Result<String, Problem> {
    let sequence = branch.next_branch_sequence;
    conn.execute(
        "INSERT INTO branch_entries (branch_id, branch_sequence, object_ref,
             object_revision, object_digest, origin_branch_id, admission,
             merge_commit_ref, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?1, 'origin', NULL, ?6)",
        params![
            branch.branch_id,
            sequence as i64,
            object_ref,
            object_revision as i64,
            object_digest,
            created_at,
        ],
    )
    .map_err(|e| store_problem(e.into()))?;
    let new_head = kovee_core::branch::next_head(&branch.head_digest, sequence, object_digest);
    let changed = conn
        .execute(
            "UPDATE reasoning_branches SET head_digest = ?2,
                 next_branch_sequence = next_branch_sequence + 1,
                 revision = revision + 1
             WHERE branch_id = ?1 AND head_digest = ?3",
            params![branch.branch_id, new_head, branch.head_digest],
        )
        .map_err(|e| store_problem(e.into()))?;
    if changed != 1 {
        return Err(
            stale_revision(branch.revision).with_detail("branch head moved inside the transaction")
        );
    }
    Ok(new_head)
}

/// §10.2/§10.10 body-part validation: artifact parts may only name an
/// available artifact; a structured mention must resolve to a visible
/// target (there is no alias registry in K1, so `assistant_alias`
/// mentions resolve to nothing).
fn validate_parts(
    conn: &Connection,
    space: &Space,
    parts: &[ContributionPart],
) -> Result<(), Problem> {
    for part in parts {
        match part {
            ContributionPart::Artifact { artifact_ref, .. } => {
                let artifact = kovee_artifacts::get_artifact(conn, artifact_ref)
                    .map_err(store_problem)?
                    .ok_or_else(not_found)?;
                if artifact.state != "available" {
                    // §10.10: no contribution may reference an artifact
                    // as available until finalization completes.
                    return Err(
                        Problem::new(ProblemKind::Invalid, "artifact is not available")
                            .with_detail(format!("artifact state is {}", artifact.state)),
                    );
                }
            }
            ContributionPart::Reference { object_ref, .. } => {
                resolve_space_object(conn, &space.space_id, object_ref)?;
            }
            ContributionPart::Mention {
                target_kind,
                target_ref,
                ..
            } => match target_kind.as_str() {
                "principal" if target_ref == OWNER_ACTOR_REF => {}
                // No alias registry exists in K1; an unresolvable
                // mention target is a uniform not-found (§10.4: a
                // mention resolves an exact visible alias revision in
                // the same transaction — or the append fails).
                _ => return Err(not_found()),
            },
            ContributionPart::Text { .. } | ContributionPart::Data { .. } => {}
        }
    }
    Ok(())
}

// -------------------------------------------------- contribution_show ----

pub fn contribution_show(
    store: &mut Store,
    project_id: &str,
    args: &ops::ContributionShowArgs,
    now: i64,
) -> Result<Vec<u8>, Problem> {
    let found = get_contribution(store.conn(), &args.contribution_id).map_err(store_problem)?;
    let query = serde_json::json!({"contribution_id": args.contribution_id});
    match found {
        Some(c) if c.project_id == project_id => {
            let payload = serde_json::to_value(&c).map_err(|_| internal())?;
            if c.classification_ref == privacy::SENSITIVE_CLASSIFICATION {
                // PROFILE §7 release rule: the allowed record commits
                // BEFORE sensitive bytes are released; a failed commit
                // means the bytes are never served.
                let bytes = serde_json::to_vec(&payload).map_err(|_| internal())?.len();
                record_access(
                    store,
                    "contribution_show",
                    query,
                    1,
                    bytes as u64,
                    true,
                    now,
                )?;
            }
            ok_reply(payload, Some(1))
        }
        Some(c) => {
            // A denied sensitive read still chains a record (PROFILE §7).
            if c.classification_ref == privacy::SENSITIVE_CLASSIFICATION {
                record_access(store, "contribution_show", query, 0, 0, false, now)?;
            }
            Err(not_found())
        }
        None => Err(not_found()),
    }
}

/// Appends one privacy access record; on failure the caller must NOT
/// release sensitive bytes (`privacy_access_record_commit_failed`).
pub fn record_access(
    store: &mut Store,
    operation: &str,
    query: Value,
    count: u64,
    bytes: u64,
    allowed: bool,
    now: i64,
) -> Result<(), Problem> {
    privacy::append_record(
        store,
        &privacy::Access {
            operation: operation.to_owned(),
            purpose_ref: "purpose-owner-read".to_owned(),
            actor_scope: format!(
                "{SURFACE}/{OWNER_ACTOR_REF}/{}",
                kovee_store::PERSONAL_REALM_ID
            ),
            query,
            result_object_count: count,
            result_bytes: bytes,
            outcome: if allowed {
                privacy::Outcome::Allowed
            } else {
                privacy::Outcome::Denied
            },
        },
        now,
    )
    .map_err(|e| {
        eprintln!("koveed: privacy_access_record_commit_failed: {e}");
        Problem::new(
            ProblemKind::Unavailable,
            "privacy access record could not be committed; sensitive bytes withheld",
        )
    })?;
    Ok(())
}

// -------------------------------------------------------- events_read ----

pub fn events_read(
    store: &Store,
    envelope_project_id: Option<&str>,
    args: &ops::EventsReadArgs,
) -> Result<Vec<u8>, Problem> {
    // Slice-1 sources are project streams: `source` names the project
    // whose dense Kovee-owned sequence is read (§11.3/§11.4).
    let project = get_project(store.conn(), &args.source)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    for narrowing in [envelope_project_id, args.project_id.as_deref()]
        .into_iter()
        .flatten()
    {
        if narrowing != project.project_id {
            // Narrowing to a different project reveals nothing.
            return Err(not_found());
        }
    }
    let after_seq = match &args.after_cursor {
        Some(cursor) => store.parse_project_cursor(cursor, &project.project_id)?,
        None => 0,
    };
    let events = store
        .list_project_events(
            &project.project_id,
            after_seq,
            args.type_prefixes.as_deref(),
            args.limit,
        )
        .map_err(store_problem)?;
    let last_seq = events
        .iter()
        .filter_map(|e| e.project_sequence)
        .max()
        .unwrap_or(after_seq);
    let next_cursor = store
        .mint_project_cursor(&project.project_id, last_seq)
        .map_err(store_problem)?;
    let result = serde_json::json!({
        "events": events,
        "next_cursor": next_cursor,
        "snapshot_epoch": "epoch-1",
    });
    ok_reply(result, None)
}
