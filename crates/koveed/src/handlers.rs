//! The K1 slice-1 operation handlers. Reads answer from normalized state
//! and never mutate (§11.2); mutations run §12.2 through
//! [`kovee_store::Store::command_transaction`] — state, event(s),
//! idempotency record, and outbox commit atomically or not at all.

use kovee_core::branch;
use kovee_core::canonical;
use kovee_core::envelope::{CommandResult, RawCommand};
use kovee_core::event::{EVENT_CONTRIBUTION_APPENDED, EVENT_PROJECT_CREATED, EVENT_SPACE_CREATED};
use kovee_core::ops;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::{Contribution, HelloResult, Project, Space};
use kovee_core::time::rfc3339_utc;
use kovee_store::{
    new_id, Applied, CommandError, CommandScope, CrashHooks, NewEvent, Store, StoreError,
    OWNER_ACTOR_REF,
};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::Value;

/// The one authority surface this binding serves (§11.6.1): the local
/// socket is an external client channel for the same-UID owner principal.
pub const SURFACE: &str = "external_client";

const DEFAULT_CLASSIFICATION: &str = "class-default";
const DEFAULT_POLICY_SET: &str = "policy-default";
const DEFAULT_RETENTION: &str = "ret-default";
const CONTRIBUTION_SCHEMA_REF: &str = "schema:contribution-body-v1";
const PROJECT_SCHEMA_REF: &str = "schema:project-v1";
const SPACE_SCHEMA_REF: &str = "schema:space-v1";

fn internal() -> Problem {
    // §11.7: `internal` does not leak paths, tokens, policy internals,
    // or peer existence — no detail at all.
    Problem::new(ProblemKind::Internal, "internal fault")
}

fn store_problem(e: StoreError) -> Problem {
    eprintln!("koveed: store fault: {e}");
    internal()
}

fn not_found() -> Problem {
    Problem::new(ProblemKind::NotFound, "no visible resource")
}

fn stale_revision(current: u64) -> Problem {
    // §11.7: stale-revision includes the current visible revision.
    Problem::new(ProblemKind::StaleRevision, "optimistic revision mismatch")
        .with_detail(format!("current visible revision is {current}"))
}

pub fn command_outcome_bytes(
    outcome: Result<kovee_store::CommandOutcome, CommandError>,
) -> Result<Vec<u8>, Problem> {
    match outcome {
        Ok(o) => Ok(o.bytes().to_vec()),
        Err(CommandError::Problem(p)) => Err(p),
        Err(CommandError::Store(e)) => Err(store_problem(e)),
    }
}

fn ok_reply(result: Value, revision: Option<u64>) -> Result<Vec<u8>, Problem> {
    serde_json::to_vec(&CommandResult::Ok {
        result,
        revision,
        event_cursor: None,
    })
    .map_err(|_| internal())
}

fn scope_for(cmd: &RawCommand, realm_id: &str) -> Result<CommandScope, Problem> {
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
        // Honesty (§11.6): bundles are atomic — this slice implements only
        // part of core_v1/shared_space_v1, so nothing is advertised yet.
        features: Vec::new(),
        limits_digest,
        server_time: rfc3339_utc(now),
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
            &format!(
                "project={project_id};request_digest={}",
                scope_digest(&meta)
            ),
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

fn scope_digest(meta: &kovee_core::envelope::CommandMeta) -> String {
    // Body-free audit detail: the idempotency key names the command
    // without carrying content.
    format!("idem={}", meta.idempotency_key)
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
        let head = branch::genesis_head(&main_branch_id);
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
                     next_space_sequence, main_branch_head_digest,
                     next_branch_sequence, default_classification_ref,
                     policy_set_ref, created_by, created_at)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 'open', ?7, 1, ?8, 1, ?9, ?10,
                     ?11, ?12)",
                params![
                    space.space_id,
                    space.realm_id,
                    space.project_id,
                    space.title,
                    space.purpose_contribution_ref,
                    space.visibility,
                    space.main_branch_id,
                    head,
                    space.default_classification_ref,
                    space.policy_set_ref,
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
        let payload = serde_json::to_value(&space).map_err(|_| internal())?;
        let event = txn
            .append_event(NewEvent {
                stream_id: space_id.clone(),
                project_id: Some(project_id.clone()),
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
    let (space, _, _) = get_space(store.conn(), &args.space_id)
        .map_err(store_problem)?
        .filter(|(s, _, _)| s.project_id == project_id)
        .ok_or_else(not_found)?;
    let revision = space.revision;
    ok_reply(
        serde_json::to_value(&space).map_err(|_| internal())?,
        Some(revision),
    )
}

// ------------------------------------------------ contribution_append ----

pub fn contribution_append(
    store: &mut Store,
    cmd: &RawCommand,
    args: &ops::ContributionAppendArgs,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    // Registry rule (§11.6.1, gap note KG14): the worker-surface binding
    // members are schema-valid but not acceptable on this surface.
    if args.attempt_id.is_some() || args.fence_epoch.is_some() {
        return Err(Problem::new(
            ProblemKind::ForbiddenSurface,
            "worker-surface binding on an external client channel",
        ));
    }
    let realm_id = cmd.realm_id.clone().ok_or_else(internal)?;
    let project_id = cmd.project_id.clone().ok_or_else(internal)?;
    let scope = scope_for(cmd, &realm_id)?;
    let args = args.clone();
    let meta = cmd.meta.clone().ok_or_else(internal)?;
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let (space, head, next_branch_sequence) = get_space(txn.conn(), &args.space_id)
            .map_err(store_problem)?
            .filter(|(s, _, _)| s.project_id == project_id)
            .ok_or_else(not_found)?;
        if args.branch_id != space.main_branch_id {
            // Hidden or unknown branches are non-enumerable (§10.2).
            return Err(not_found());
        }
        if let Some(expected) = meta.expected_revision {
            if expected != space.revision {
                return Err(stale_revision(space.revision));
            }
        }
        // §10.3/§11.2: every branch append presents the expected head
        // digest and compare-and-swaps; a stale writer must rebase.
        if args.expected_head_digest != head {
            return Err(stale_revision(space.revision)
                .with_detail("expected_head_digest does not match the current branch head"));
        }
        let contribution_id = new_id("contrib").map_err(store_problem)?;
        let branch_sequence = next_branch_sequence;
        let space_sequence = space.next_space_sequence;
        let subject_refs = args.subject_refs.clone().unwrap_or_default();
        let source_refs = args.source_refs.clone().unwrap_or_default();
        // §11.8: the content digest projection is implementation-pinned
        // (recorded K0 gap). A5 note: this is a plaintext canonical-object
        // digest; when contribution redaction lands (later K1 slice), the
        // digest class must move to the family's erasure-safe class.
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
            author_actor_ref: OWNER_ACTOR_REF.to_owned(),
            kind: args.kind.clone(),
            schema_ref: args
                .schema_ref
                .clone()
                .unwrap_or_else(|| CONTRIBUTION_SCHEMA_REF.to_owned()),
            body_parts: args.body_parts.clone(),
            subject_refs,
            source_refs,
            epistemic_posture: args.epistemic_posture.clone(),
            invocation_ref: None,
            context_assembly_ref: None,
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
                     ?14, NULL, NULL, ?15, ?16, ?17, ?18, ?19)",
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
                    contribution.causation_ref,
                    contribution.classification_ref,
                    contribution.retention_policy_ref,
                    contribution.content_digest,
                    contribution.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        // Advance the space: one dense branch sequence, one dense space
        // sequence, the CASed head, and the aggregate revision (§11.2).
        let new_head = branch::next_head(&head, branch_sequence, &content_digest);
        let new_revision = space.revision + 1;
        txn.conn()
            .execute(
                "UPDATE spaces SET next_space_sequence = next_space_sequence + 1,
                     next_branch_sequence = next_branch_sequence + 1,
                     main_branch_head_digest = ?2,
                     revision = ?3
                 WHERE space_id = ?1",
                params![space.space_id, new_head, new_revision as i64],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&contribution).map_err(|_| internal())?;
        let event = txn
            .append_event(NewEvent {
                stream_id: space.space_id.clone(),
                project_id: Some(project_id.clone()),
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

// -------------------------------------------------- contribution_show ----

pub fn contribution_show(
    store: &Store,
    project_id: &str,
    args: &ops::ContributionShowArgs,
) -> Result<Vec<u8>, Problem> {
    let contribution = get_contribution(store.conn(), &args.contribution_id)
        .map_err(store_problem)?
        .filter(|c| c.project_id == project_id)
        .ok_or_else(not_found)?;
    ok_reply(
        serde_json::to_value(&contribution).map_err(|_| internal())?,
        Some(1),
    )
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

// ------------------------------------------------------- row readers ----

fn get_project(conn: &Connection, project_id: &str) -> Result<Option<Project>, StoreError> {
    conn.query_row(
        "SELECT project_id, realm_id, revision, name, status,
                default_classification_ref, policy_set_ref, created_by, created_at
         FROM projects WHERE project_id = ?1",
        [project_id],
        |r| {
            Ok(Project {
                project_id: r.get(0)?,
                realm_id: r.get(1)?,
                revision: r.get::<_, i64>(2)? as u64,
                name: r.get(3)?,
                status: r.get(4)?,
                default_classification_ref: r.get(5)?,
                policy_set_ref: r.get(6)?,
                created_by: r.get(7)?,
                created_at: r.get(8)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

/// One space row plus its main-branch CAS state
/// `(space, head_digest, next_branch_sequence)`.
fn get_space(
    conn: &Connection,
    space_id: &str,
) -> Result<Option<(Space, String, u64)>, StoreError> {
    conn.query_row(
        "SELECT space_id, realm_id, project_id, revision, title,
                purpose_contribution_ref, visibility, status, main_branch_id,
                next_space_sequence, default_classification_ref, policy_set_ref,
                created_by, created_at, main_branch_head_digest,
                next_branch_sequence
         FROM spaces WHERE space_id = ?1",
        [space_id],
        |r| {
            Ok((
                Space {
                    space_id: r.get(0)?,
                    realm_id: r.get(1)?,
                    project_id: r.get(2)?,
                    revision: r.get::<_, i64>(3)? as u64,
                    title: r.get(4)?,
                    purpose_contribution_ref: r.get(5)?,
                    visibility: r.get(6)?,
                    status: r.get(7)?,
                    main_branch_id: r.get(8)?,
                    next_space_sequence: r.get::<_, i64>(9)? as u64,
                    default_classification_ref: r.get(10)?,
                    policy_set_ref: r.get(11)?,
                    created_by: r.get(12)?,
                    created_at: r.get(13)?,
                },
                r.get::<_, String>(14)?,
                r.get::<_, i64>(15)? as u64,
            ))
        },
    )
    .optional()
    .map_err(StoreError::from)
}

fn get_contribution(
    conn: &Connection,
    contribution_id: &str,
) -> Result<Option<Contribution>, StoreError> {
    let row = conn
        .query_row(
            "SELECT contribution_id, revision, realm_id, project_id, space_id,
                    origin_branch_id, origin_branch_sequence, space_sequence,
                    author_actor_ref, kind, schema_ref, body_parts, subject_refs,
                    source_refs, epistemic_posture, invocation_ref,
                    context_assembly_ref, causation_ref, classification_ref,
                    retention_policy_ref, content_digest, created_at
             FROM contributions WHERE contribution_id = ?1",
            [contribution_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, String>(12)?,
                    r.get::<_, String>(13)?,
                    r.get::<_, Option<String>>(14)?,
                    r.get::<_, Option<String>>(15)?,
                    r.get::<_, Option<String>>(16)?,
                    r.get::<_, Option<String>>(17)?,
                    r.get::<_, String>(18)?,
                    r.get::<_, String>(19)?,
                    r.get::<_, String>(20)?,
                    r.get::<_, String>(21)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(Contribution {
        contribution_id: row.0,
        revision: row.1 as u64,
        realm_id: row.2,
        project_id: row.3,
        space_id: row.4,
        origin_branch_id: row.5,
        origin_branch_sequence: row.6 as u64,
        space_sequence: row.7 as u64,
        author_actor_ref: row.8,
        kind: row.9,
        schema_ref: row.10,
        body_parts: serde_json::from_str(&row.11)?,
        subject_refs: serde_json::from_str(&row.12)?,
        source_refs: serde_json::from_str(&row.13)?,
        epistemic_posture: row.14,
        invocation_ref: row.15,
        context_assembly_ref: row.16,
        causation_ref: row.17,
        classification_ref: row.18,
        retention_policy_ref: row.19,
        content_digest: row.20,
        created_at: row.21,
    }))
}
