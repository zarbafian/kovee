//! Shared row readers and problem helpers for the K1 handlers. Reads
//! answer from normalized state; every reader scopes visibility (project
//! and space membership) so hidden resources stay non-enumerable (§10.2).

use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::{
    AssistantAliasBinding, AssistantDefinition, Contribution, Project, Reaction, Space,
    SpaceAccessGrant, SpaceFrontier, SpaceLens, SpaceParticipant, SpaceRelation,
};
use kovee_store::StoreError;
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::Value;

pub const DEFAULT_CLASSIFICATION: &str = "class-default";
pub const DEFAULT_POLICY_SET: &str = "policy-default";
pub const DEFAULT_RETENTION: &str = "ret-default";
pub const CONTRIBUTION_SCHEMA_REF: &str = "schema:contribution-body-v1";
pub const RELATION_SCHEMA_REF: &str = "schema:space-relation-v1";
pub const PROJECT_SCHEMA_REF: &str = "schema:project-v1";
pub const SPACE_SCHEMA_REF: &str = "schema:space-v1";
pub const FRONTIER_SCHEMA_REF: &str = "schema:space-frontier-v1";
pub const ASSEMBLY_SCHEMA_REF: &str = "schema:context-assembly-v1";
pub const INVOCATION_SCHEMA_REF: &str = "schema:invocation-v1";
/// The bootstrap-provisioned local developer deployment (V2 migration);
/// assistant/deployment registration ops are out of K1 scope.
pub const LOCAL_DEPLOYMENT_ID: &str = "dep-local-dev";

pub fn internal() -> Problem {
    // §11.7: `internal` does not leak paths, tokens, policy internals,
    // or peer existence — no detail at all.
    Problem::new(ProblemKind::Internal, "internal fault")
}

pub fn store_problem(e: StoreError) -> Problem {
    eprintln!("koveed: store fault: {e}");
    internal()
}

pub fn not_found() -> Problem {
    Problem::new(ProblemKind::NotFound, "no visible resource")
}

pub fn stale_revision(current: u64) -> Problem {
    // §11.7: stale-revision includes the current visible revision.
    Problem::new(ProblemKind::StaleRevision, "optimistic revision mismatch")
        .with_detail(format!("current visible revision is {current}"))
}

// -------------------------------------------------------------- projects ----

pub fn get_project(conn: &Connection, project_id: &str) -> Result<Option<Project>, StoreError> {
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

/// The current project-stream head sequence (0 when no event exists).
pub fn project_head_seq(conn: &Connection, project_id: &str) -> Result<u64, StoreError> {
    let next: Option<i64> = conn
        .query_row(
            "SELECT next_project_sequence FROM projects WHERE project_id = ?1",
            [project_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(next.map(|n| (n - 1) as u64).unwrap_or(0))
}

// ---------------------------------------------------------------- spaces ----

pub fn get_space(conn: &Connection, space_id: &str) -> Result<Option<Space>, StoreError> {
    conn.query_row(
        "SELECT space_id, realm_id, project_id, revision, title,
                purpose_contribution_ref, visibility, status, main_branch_id,
                next_space_sequence, default_classification_ref, policy_set_ref,
                created_by, created_at
         FROM spaces WHERE space_id = ?1",
        [space_id],
        |r| {
            Ok(Space {
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
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

/// A space visible in this project, or the uniform `not-found` (§11.7).
pub fn visible_space(
    conn: &Connection,
    project_id: &str,
    space_id: &str,
) -> Result<Space, Problem> {
    get_space(conn, space_id)
        .map_err(store_problem)?
        .filter(|s| s.project_id == project_id)
        .ok_or_else(not_found)
}

// -------------------------------------------------------------- branches ----

/// The §10.3 branch head CAS state, on the branch row since V2.
#[derive(Debug, Clone)]
pub struct BranchRow {
    pub branch_id: String,
    pub space_id: String,
    pub revision: u64,
    pub next_branch_sequence: u64,
    pub head_digest: String,
    pub status: String,
}

pub fn get_branch(conn: &Connection, branch_id: &str) -> Result<Option<BranchRow>, StoreError> {
    conn.query_row(
        "SELECT branch_id, space_id, revision, next_branch_sequence, head_digest,
                status
         FROM reasoning_branches WHERE branch_id = ?1",
        [branch_id],
        |r| {
            Ok(BranchRow {
                branch_id: r.get(0)?,
                space_id: r.get(1)?,
                revision: r.get::<_, i64>(2)? as u64,
                next_branch_sequence: r.get::<_, i64>(3)? as u64,
                head_digest: r.get(4)?,
                status: r.get(5)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

/// A branch visible inside this exact space, or `not-found` — hidden or
/// foreign branches are non-enumerable (§10.2).
pub fn visible_branch(
    conn: &Connection,
    space: &Space,
    branch_id: &str,
) -> Result<BranchRow, Problem> {
    get_branch(conn, branch_id)
        .map_err(store_problem)?
        .filter(|b| b.space_id == space.space_id)
        .ok_or_else(not_found)
}

// ---------------------------------------------------------- contributions ----

pub fn get_contribution(
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
            row_to_contribution_tuple,
        )
        .optional()?;
    row.map(tuple_to_contribution).transpose()
}

type ContributionTuple = (
    String,
    i64,
    String,
    String,
    String,
    String,
    i64,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
    String,
);

pub(crate) fn row_to_contribution_tuple(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<ContributionTuple> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
        r.get(13)?,
        r.get(14)?,
        r.get(15)?,
        r.get(16)?,
        r.get(17)?,
        r.get(18)?,
        r.get(19)?,
        r.get(20)?,
        r.get(21)?,
    ))
}

pub(crate) fn tuple_to_contribution(row: ContributionTuple) -> Result<Contribution, StoreError> {
    Ok(Contribution {
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
    })
}

/// Contributions of one space ordered by `space_sequence`, within
/// `(after_seq, boundary_seq]`, optionally filtered.
pub fn list_contributions(
    conn: &Connection,
    space_id: &str,
    branch_id: Option<&str>,
    kind: Option<&str>,
    after_seq: u64,
    boundary_seq: u64,
    limit: u64,
) -> Result<Vec<Contribution>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT contribution_id, revision, realm_id, project_id, space_id,
                origin_branch_id, origin_branch_sequence, space_sequence,
                author_actor_ref, kind, schema_ref, body_parts, subject_refs,
                source_refs, epistemic_posture, invocation_ref,
                context_assembly_ref, causation_ref, classification_ref,
                retention_policy_ref, content_digest, created_at
         FROM contributions
         WHERE space_id = ?1 AND space_sequence > ?2 AND space_sequence <= ?3
           AND (?4 IS NULL OR origin_branch_id = ?4)
           AND (?5 IS NULL OR kind = ?5)
         ORDER BY space_sequence ASC
         LIMIT ?6",
    )?;
    let rows = stmt.query_map(
        params![
            space_id,
            after_seq as i64,
            boundary_seq as i64,
            branch_id,
            kind,
            limit as i64
        ],
        row_to_contribution_tuple,
    )?;
    let mut out = Vec::new();
    for row in rows {
        out.push(tuple_to_contribution(row?)?);
    }
    Ok(out)
}

// -------------------------------------------------------------- relations ----

pub fn get_relation(
    conn: &Connection,
    relation_id: &str,
) -> Result<Option<SpaceRelation>, StoreError> {
    let row = conn
        .query_row(
            "SELECT relation_id, revision, space_id, origin_branch_id,
                    branch_sequence, author_actor_ref, kind, from_ref, to_ref,
                    rationale_ref, relation_class, classification_ref, schema_ref,
                    digest, created_at
             FROM space_relations WHERE relation_id = ?1",
            [relation_id],
            row_to_relation_tuple,
        )
        .optional()?;
    row.map(tuple_to_relation).transpose()
}

type RelationTuple = (
    String,
    i64,
    String,
    String,
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    String,
);

fn row_to_relation_tuple(r: &rusqlite::Row<'_>) -> rusqlite::Result<RelationTuple> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
        r.get(13)?,
        r.get(14)?,
    ))
}

fn tuple_to_relation(row: RelationTuple) -> Result<SpaceRelation, StoreError> {
    Ok(SpaceRelation {
        relation_id: row.0,
        revision: row.1 as u64,
        space_id: row.2,
        origin_branch_id: row.3,
        branch_sequence: row.4 as u64,
        author_actor_ref: row.5,
        kind: row.6,
        from_ref: serde_json::from_str(&row.7)?,
        to_ref: serde_json::from_str(&row.8)?,
        rationale_ref: row.9,
        relation_class: row.10,
        classification_ref: row.11,
        schema_ref: row.12,
        digest: row.13,
        created_at: row.14,
    })
}

/// All relations of one space touching the given contribution ids.
pub fn relations_touching(
    conn: &Connection,
    space_id: &str,
) -> Result<Vec<SpaceRelation>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT relation_id, revision, space_id, origin_branch_id,
                branch_sequence, author_actor_ref, kind, from_ref, to_ref,
                rationale_ref, relation_class, classification_ref, schema_ref,
                digest, created_at
         FROM space_relations WHERE space_id = ?1
         ORDER BY branch_sequence ASC",
    )?;
    let rows = stmt.query_map([space_id], row_to_relation_tuple)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(tuple_to_relation(row?)?);
    }
    Ok(out)
}

// -------------------------------------------------- same-space endpoints ----

/// A same-space visible object a relation endpoint or subject/source ref
/// may pin (§10.2): a contribution or an asserted relation.
pub enum SpaceObject {
    Contribution(Box<Contribution>),
    Relation(Box<SpaceRelation>),
}

impl SpaceObject {
    pub fn digest(&self) -> &str {
        match self {
            SpaceObject::Contribution(c) => &c.content_digest,
            SpaceObject::Relation(r) => &r.digest,
        }
    }

    pub fn revision(&self) -> u64 {
        match self {
            SpaceObject::Contribution(c) => c.revision,
            SpaceObject::Relation(r) => r.revision,
        }
    }

    pub fn branch_sequence(&self) -> u64 {
        match self {
            SpaceObject::Contribution(c) => c.origin_branch_sequence,
            SpaceObject::Relation(r) => r.branch_sequence,
        }
    }

    pub fn origin_branch_id(&self) -> &str {
        match self {
            SpaceObject::Contribution(c) => &c.origin_branch_id,
            SpaceObject::Relation(r) => &r.origin_branch_id,
        }
    }
}

/// Resolves a ref to a visible object in exactly this space, or the
/// uniform `not-found` — cross-space refs reveal nothing (§10.2).
pub fn resolve_space_object(
    conn: &Connection,
    space_id: &str,
    object_ref: &str,
) -> Result<SpaceObject, Problem> {
    if let Some(c) = get_contribution(conn, object_ref).map_err(store_problem)? {
        if c.space_id == space_id {
            return Ok(SpaceObject::Contribution(Box::new(c)));
        }
        return Err(not_found());
    }
    if let Some(r) = get_relation(conn, object_ref).map_err(store_problem)? {
        if r.space_id == space_id {
            return Ok(SpaceObject::Relation(Box::new(r)));
        }
    }
    Err(not_found())
}

// -------------------------------------------------------------- frontiers ----

pub fn get_frontier(
    conn: &Connection,
    frontier_id: &str,
) -> Result<Option<SpaceFrontier>, StoreError> {
    conn.query_row(
        "SELECT frontier_id, revision, space_id, branch_id, branch_sequence,
                branch_head_digest, project_event_cursor,
                external_source_cursors, created_at, digest
         FROM space_frontiers WHERE frontier_id = ?1",
        [frontier_id],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, String>(9)?,
            ))
        },
    )
    .optional()
    .map_err(StoreError::from)?
    .map(|row| {
        Ok::<_, StoreError>(SpaceFrontier {
            frontier_id: row.0,
            revision: row.1 as u64,
            space_id: row.2,
            branch_id: row.3,
            branch_sequence: row.4 as u64,
            branch_head_digest: row.5,
            project_event_cursor: row.6,
            external_source_cursors: serde_json::from_str(&row.7)?,
            created_at: row.8,
            digest: row.9,
        })
    })
    .transpose()
}

// ------------------------------------------------------------------ lenses ----

#[derive(Debug, Clone)]
pub struct LensRow {
    pub lens_id: String,
    pub space_id: String,
    pub kind: String,
}

pub fn get_lens(conn: &Connection, lens_id: &str) -> Result<Option<LensRow>, StoreError> {
    conn.query_row(
        "SELECT lens_id, space_id, kind FROM space_lenses
         WHERE lens_id = ?1 AND status = 'active'",
        [lens_id],
        |r| {
            Ok(LensRow {
                lens_id: r.get(0)?,
                space_id: r.get(1)?,
                kind: r.get(2)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

// -------------------------------------------------------------- assemblies ----

pub fn get_assembly_record(
    conn: &Connection,
    assembly_id: &str,
) -> Result<Option<(String, Value)>, StoreError> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT project_id, record FROM context_assemblies WHERE assembly_id = ?1",
            [assembly_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        Some((project, text)) => Ok(Some((project, serde_json::from_str(&text)?))),
        None => Ok(None),
    }
}

// -------------------------------------------------------------- invocations ----

#[derive(Debug, Clone)]
pub struct InvocationRow {
    pub invocation_id: String,
    pub project_id: String,
    pub space_id: Option<String>,
    pub branch_id: Option<String>,
    pub context_assembly_ref: Option<String>,
    pub state: String,
    pub revision: u64,
    pub record: Value,
}

type InvocationTuple = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    i64,
    String,
);

pub fn get_invocation(
    conn: &Connection,
    invocation_id: &str,
) -> Result<Option<InvocationRow>, StoreError> {
    let row: Option<InvocationTuple> = conn
        .query_row(
            "SELECT invocation_id, project_id, space_id, branch_id,
                    context_assembly_ref, state, revision, record
             FROM invocations WHERE invocation_id = ?1",
            [invocation_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            },
        )
        .optional()?;
    match row {
        Some(row) => Ok(Some(InvocationRow {
            invocation_id: row.0,
            project_id: row.1,
            space_id: row.2,
            branch_id: row.3,
            context_assembly_ref: row.4,
            state: row.5,
            revision: row.6 as u64,
            record: serde_json::from_str(&row.7)?,
        })),
        None => Ok(None),
    }
}

#[derive(Debug, Clone)]
pub struct AttemptRow {
    pub attempt_id: String,
    pub invocation_id: String,
    pub ordinal: u64,
    pub fence_epoch: u64,
    pub state: String,
}

pub fn get_attempt(conn: &Connection, attempt_id: &str) -> Result<Option<AttemptRow>, StoreError> {
    conn.query_row(
        "SELECT attempt_id, invocation_id, ordinal, fence_epoch, state
         FROM invocation_attempts WHERE attempt_id = ?1",
        [attempt_id],
        |r| {
            Ok(AttemptRow {
                attempt_id: r.get(0)?,
                invocation_id: r.get(1)?,
                ordinal: r.get::<_, i64>(2)? as u64,
                fence_epoch: r.get::<_, i64>(3)? as u64,
                state: r.get(4)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

#[derive(Debug, Clone)]
pub struct DeploymentRow {
    pub deployment_id: String,
    pub revision: u64,
    pub assistant_revision_id: String,
    pub security_profile: String,
    pub status: String,
    /// The full AssistantDeployment record JSON (V3 column).
    pub record: Option<Value>,
}

pub fn get_deployment(
    conn: &Connection,
    deployment_id: &str,
) -> Result<Option<DeploymentRow>, StoreError> {
    let row: Option<(String, i64, String, String, String, Option<String>)> = conn
        .query_row(
            "SELECT deployment_id, revision, assistant_revision_id, security_profile,
                    status, record
             FROM assistant_deployments WHERE deployment_id = ?1",
            [deployment_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?;
    match row {
        Some((
            deployment_id,
            revision,
            assistant_revision_id,
            security_profile,
            status,
            record,
        )) => Ok(Some(DeploymentRow {
            deployment_id,
            revision: revision as u64,
            assistant_revision_id,
            security_profile,
            status,
            record: record.map(|r| serde_json::from_str(&r)).transpose()?,
        })),
        None => Ok(None),
    }
}

// ------------------------------------------------------- participants ----

pub fn get_participant(
    conn: &Connection,
    participant_id: &str,
) -> Result<Option<(SpaceParticipant, Option<String>)>, StoreError> {
    conn.query_row(
        "SELECT participant_id, space_id, subject_ref, subject_revision, kind,
                role, authority_source_ref, status, revision, subject_digest
         FROM space_participants WHERE participant_id = ?1",
        [participant_id],
        |r| {
            Ok((
                SpaceParticipant {
                    participant_id: r.get(0)?,
                    space_id: r.get(1)?,
                    subject_ref: r.get(2)?,
                    subject_revision: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                    kind: r.get(4)?,
                    role: r.get(5)?,
                    authority_source_ref: r.get(6)?,
                    status: r.get(7)?,
                    revision: r.get::<_, i64>(8)? as u64,
                },
                r.get::<_, Option<String>>(9)?,
            ))
        },
    )
    .optional()
    .map_err(StoreError::from)
}

// ------------------------------------------------------------- grants ----

pub fn get_grant(
    conn: &Connection,
    space_access_id: &str,
) -> Result<Option<SpaceAccessGrant>, StoreError> {
    let row = conn
        .query_row(
            "SELECT space_access_id, space_id, subject_ref, revision,
                    source_membership_or_policy_ref, allowed_actions,
                    classification_ceiling_ref, authorization_epoch, expires_at,
                    status, granted_by_or_policy_use_ref, created_at
             FROM space_access_grants WHERE space_access_id = ?1",
            [space_access_id],
            row_to_grant_tuple,
        )
        .optional()?;
    row.map(tuple_to_grant).transpose()
}

type GrantTuple = (
    String,
    String,
    String,
    i64,
    String,
    String,
    Option<String>,
    i64,
    Option<String>,
    String,
    String,
    String,
);

pub(crate) fn row_to_grant_tuple(r: &rusqlite::Row<'_>) -> rusqlite::Result<GrantTuple> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
    ))
}

pub(crate) fn tuple_to_grant(row: GrantTuple) -> Result<SpaceAccessGrant, StoreError> {
    Ok(SpaceAccessGrant {
        space_access_id: row.0,
        space_id: row.1,
        subject_ref: row.2,
        revision: row.3 as u64,
        source_membership_or_policy_ref: row.4,
        allowed_actions: serde_json::from_str(&row.5)?,
        classification_ceiling_ref: row.6,
        authorization_epoch: row.7 as u64,
        expires_at: row.8,
        status: row.9,
        granted_by_or_policy_use_ref: row.10,
        created_at: row.11,
    })
}

// -------------------------------------------------------- full lenses ----

type LensTuple = (
    String,
    String,
    Option<String>,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

pub fn get_lens_full(conn: &Connection, lens_id: &str) -> Result<Option<SpaceLens>, StoreError> {
    let row: Option<LensTuple> = conn
        .query_row(
            "SELECT lens_id, space_id, owner_ref, revision, kind, query_ast,
                    sort_spec, presentation_options, visibility, status, created_at
             FROM space_lenses WHERE lens_id = ?1 AND status != 'revoked'",
            [lens_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            },
        )
        .optional()?;
    match row {
        Some(row) => Ok(Some(SpaceLens {
            lens_id: row.0,
            space_id: row.1,
            owner_ref: row.2,
            revision: row.3 as u64,
            kind: row.4,
            query_ast: serde_json::from_str(&row.5)?,
            sort_spec: serde_json::from_str(&row.6)?,
            presentation_options: serde_json::from_str(&row.7)?,
            visibility: row.8,
            status: row.9,
            created_at: row.10,
        })),
        None => Ok(None),
    }
}

// ----------------------------------------------------------- reactions ----

pub fn get_reaction(
    conn: &Connection,
    target_ref: &str,
    actor_ref: &str,
    key: &str,
) -> Result<Option<Reaction>, StoreError> {
    conn.query_row(
        "SELECT reaction_id, space_id, target_ref, target_revision, target_digest,
                actor_ref, key, state, revision, updated_at
         FROM reactions WHERE target_ref = ?1 AND actor_ref = ?2 AND key = ?3",
        params![target_ref, actor_ref, key],
        |r| {
            Ok(Reaction {
                reaction_id: r.get(0)?,
                space_id: r.get(1)?,
                target_ref: r.get(2)?,
                target_revision: r.get::<_, i64>(3)? as u64,
                target_digest: r.get(4)?,
                actor_ref: r.get(5)?,
                key: r.get(6)?,
                state: r.get(7)?,
                revision: r.get::<_, i64>(8)? as u64,
                updated_at: r.get(9)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

// ---------------------------------------------------- prepared changes ----

/// One prepared-change lookup row (`project_policy_changes` /
/// `space_access_widenings`): scope id, state, revision, full record.
pub struct PreparedChangeRow {
    pub scope_id: String,
    pub state: String,
    pub revision: u64,
    pub record: Value,
}

pub fn get_prepared_change(
    conn: &Connection,
    table: &str,
    scope_column: &str,
    id_column: &str,
    id: &str,
) -> Result<Option<PreparedChangeRow>, StoreError> {
    let sql = format!(
        "SELECT {scope_column}, state, revision, record FROM {table} WHERE {id_column} = ?1"
    );
    let row: Option<(String, String, i64, String)> = conn
        .query_row(&sql, [id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()?;
    match row {
        Some((scope_id, state, revision, record)) => Ok(Some(PreparedChangeRow {
            scope_id,
            state,
            revision: revision as u64,
            record: serde_json::from_str(&record)?,
        })),
        None => Ok(None),
    }
}

// ----------------------------------------------------------- assistants ----

pub fn get_assistant_definition(
    conn: &Connection,
    definition_id: &str,
) -> Result<Option<AssistantDefinition>, StoreError> {
    conn.query_row(
        "SELECT definition_id, realm_id, owner_ref, revision, name, description,
                status, created_at
         FROM assistant_definitions WHERE definition_id = ?1",
        [definition_id],
        |r| {
            Ok(AssistantDefinition {
                definition_id: r.get(0)?,
                realm_id: r.get(1)?,
                owner_ref: r.get(2)?,
                revision: r.get::<_, i64>(3)? as u64,
                name: r.get(4)?,
                description: r.get(5)?,
                status: r.get(6)?,
                created_at: r.get(7)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

pub fn get_assistant_revision_record(
    conn: &Connection,
    assistant_revision_id: &str,
) -> Result<Option<Value>, StoreError> {
    let text: Option<String> = conn
        .query_row(
            "SELECT record FROM assistant_revisions WHERE assistant_revision_id = ?1",
            [assistant_revision_id],
            |r| r.get(0),
        )
        .optional()?;
    text.map(|t| serde_json::from_str(&t).map_err(StoreError::from))
        .transpose()
}

pub fn get_alias(
    conn: &Connection,
    alias_binding_id: &str,
) -> Result<Option<AssistantAliasBinding>, StoreError> {
    conn.query_row(
        "SELECT alias_binding_id, realm_id, project_id, revision, normalized_alias,
                display_alias, assistant_deployment_id, deployment_revision,
                status, created_by, created_at
         FROM assistant_aliases WHERE alias_binding_id = ?1",
        [alias_binding_id],
        |r| {
            Ok(AssistantAliasBinding {
                alias_binding_id: r.get(0)?,
                realm_id: r.get(1)?,
                project_id: r.get(2)?,
                revision: r.get::<_, i64>(3)? as u64,
                normalized_alias: r.get(4)?,
                display_alias: r.get(5)?,
                assistant_deployment_id: r.get(6)?,
                deployment_revision: r.get::<_, i64>(7)? as u64,
                status: r.get(8)?,
                created_by: r.get(9)?,
                created_at: r.get(10)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

/// The canonical activation subject digest of one participant proposal
/// (KG19 "exact prepared subject digest").
pub fn participant_subject_digest(participant: &SpaceParticipant) -> Result<String, Problem> {
    let projection = serde_json::json!({
        "participant_id": participant.participant_id,
        "space_id": participant.space_id,
        "subject_ref": participant.subject_ref,
        "kind": participant.kind,
        "role": participant.role,
    });
    let (_, digest) = kovee_core::canonical::canonical_object_digest(
        "kovee-participant-subject",
        "schema:space-participant-v1",
        &projection,
    )
    .map_err(|_| internal())?;
    Ok(digest)
}
