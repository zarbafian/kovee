//! Slice-2 space mutations: `relation_assert` (§10.2 closed semantic
//! enum, exact pinned endpoints), `frontier_pin` (§10.2 SpaceFrontier),
//! and `context_assembly_create` (§10.8 `explicit_refs_v1`: exact refs
//! in, immutable assembly out with included/omitted/reasons recorded).

use kovee_core::canonical::canonical_object_digest;
use kovee_core::envelope::CommandMeta;
use kovee_core::event::{
    EVENT_CONTEXT_ASSEMBLY_CREATED, EVENT_FRONTIER_PINNED, EVENT_RELATION_ASSERTED,
};
use kovee_core::ops;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::{
    AssemblyItem, AssemblyRelation, AssemblyTotals, ContextAssembly, ObjectRefTriple,
    SpaceFrontier, SpaceRelation,
};
use kovee_store::{new_id, Applied, CommandScope, CommandTxn, CrashHooks, NewEvent, Store};

use crate::handlers::{advance_branch, command_outcome_bytes, scope_digest, AppendAuthor};
use crate::state::*;

/// The one built-in K1 selection policy (§10.8).
pub const EXPLICIT_REFS_POLICY: &str = "explicit_refs_v1";
/// Recorded assembler identity.
pub const ASSEMBLER_VERSION: &str = "koveed-explicit-refs-v1";
/// The same-UID owner dependency set (developer profile).
pub const AUTHZ_DEP_SET_REF: &str = "authz-owner-local-v1";

// ------------------------------------------------------ relation_assert ----

/// Validates one endpoint triple against the visible same-space object:
/// exact revision and digest pins (§10.2 "relations pin exact visible
/// endpoint revisions"). A changed object is a dependency invalidation.
fn check_endpoint(
    txn: &CommandTxn<'_>,
    space_id: &str,
    field: &str,
    triple: &ops::RefTripleArgs,
) -> Result<(), Problem> {
    let object = resolve_space_object(txn.conn(), space_id, &triple.object_ref)?;
    if triple.revision != object.revision() {
        return Err(stale_revision(object.revision())
            .with_detail(format!("{field} pins a stale endpoint revision")));
    }
    if triple.digest != object.digest() {
        return Err(stale_revision(object.revision())
            .with_detail(format!("{field}.digest does not match the visible object")));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn relation_assert(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::RelationAssertArgs,
    meta: CommandMeta,
    author: AppendAuthor,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let replay_author = author.clone();
    let outcome = store.command_transaction_guarded(
        &scope,
        now,
        hooks,
        move |conn| replay_author.check(conn),
        move |txn| {
            author.check(txn.conn())?;
            let space = visible_space(txn.conn(), &project_id, &args.space_id)?;
            if space.status != "open" {
                return Err(Problem::new(
                    ProblemKind::StaleRevision,
                    "space is not open for relations",
                ));
            }
            let branch = visible_branch(txn.conn(), &space, &args.branch_id)?;
            if let Some(expected) = meta.expected_revision {
                if expected != space.revision {
                    return Err(stale_revision(space.revision));
                }
            }
            if args.expected_head_digest != branch.head_digest {
                return Err(stale_revision(space.revision)
                    .with_detail("expected_head_digest does not match the current branch head"));
            }
            check_endpoint(txn, &space.space_id, "from_ref", &args.from_ref)?;
            check_endpoint(txn, &space.space_id, "to_ref", &args.to_ref)?;
            if let Some(rationale) = &args.rationale_ref {
                resolve_space_object(txn.conn(), &space.space_id, rationale)?;
            }
            let relation_id = new_id("rel").map_err(store_problem)?;
            let branch_sequence = branch.next_branch_sequence;
            let schema_ref = args
                .schema_ref
                .clone()
                .unwrap_or_else(|| RELATION_SCHEMA_REF.to_owned());
            let projection = serde_json::json!({
                "space_id": space.space_id,
                "origin_branch_id": branch.branch_id,
                "branch_sequence": branch_sequence,
                "kind": args.kind,
                "from_ref": {
                    "object_ref": args.from_ref.object_ref,
                    "revision": args.from_ref.revision,
                    "digest": args.from_ref.digest,
                },
                "to_ref": {
                    "object_ref": args.to_ref.object_ref,
                    "revision": args.to_ref.revision,
                    "digest": args.to_ref.digest,
                },
                "rationale_ref": args.rationale_ref,
            });
            let (_, digest) = canonical_object_digest("kovee-relation", &schema_ref, &projection)
                .map_err(|_| internal())?;
            let relation = SpaceRelation {
                relation_id: relation_id.clone(),
                revision: 1,
                space_id: space.space_id.clone(),
                origin_branch_id: branch.branch_id.clone(),
                branch_sequence,
                author_actor_ref: author.actor_ref.clone(),
                kind: args.kind.clone(),
                from_ref: ObjectRefTriple {
                    object_ref: args.from_ref.object_ref.clone(),
                    revision: args.from_ref.revision,
                    digest: args.from_ref.digest.clone(),
                },
                to_ref: ObjectRefTriple {
                    object_ref: args.to_ref.object_ref.clone(),
                    revision: args.to_ref.revision,
                    digest: args.to_ref.digest.clone(),
                },
                rationale_ref: args.rationale_ref.clone(),
                // §10.2: the public/worker surface always creates
                // semantic_assertion — structural relations are service-only.
                relation_class: "semantic_assertion".to_owned(),
                classification_ref: space.default_classification_ref.clone(),
                schema_ref: schema_ref.clone(),
                digest: digest.clone(),
                created_at: txn.now_ts(),
            };
            txn.conn()
                .execute(
                    "INSERT INTO space_relations (relation_id, revision, space_id,
                     origin_branch_id, branch_sequence, author_actor_ref, kind,
                     from_ref, to_ref, rationale_ref, relation_class,
                     classification_ref, schema_ref, digest, created_at)
                 VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                     'semantic_assertion', ?10, ?11, ?12, ?13)",
                    rusqlite::params![
                        relation.relation_id,
                        relation.space_id,
                        relation.origin_branch_id,
                        relation.branch_sequence as i64,
                        relation.author_actor_ref,
                        relation.kind,
                        serde_json::to_string(&relation.from_ref).map_err(|_| internal())?,
                        serde_json::to_string(&relation.to_ref).map_err(|_| internal())?,
                        relation.rationale_ref,
                        relation.classification_ref,
                        relation.schema_ref,
                        relation.digest,
                        relation.created_at,
                    ],
                )
                .map_err(|e| store_problem(e.into()))?;
            advance_branch(
                txn.conn(),
                &branch,
                &relation_id,
                1,
                &digest,
                &relation.created_at,
            )?;
            let new_revision = space.revision + 1;
            txn.conn()
                .execute(
                    "UPDATE spaces SET revision = ?2 WHERE space_id = ?1",
                    rusqlite::params![space.space_id, new_revision as i64],
                )
                .map_err(|e| store_problem(e.into()))?;
            let payload = serde_json::to_value(&relation).map_err(|_| internal())?;
            let event = txn
                .append_event(NewEvent {
                    stream_id: space.space_id.clone(),
                    project_id: Some(project_id.clone()),
                    actor_ref: Some(author.actor_ref.clone()),
                    event_type: EVENT_RELATION_ASSERTED.to_owned(),
                    schema_ref: RELATION_SCHEMA_REF.to_owned(),
                    resource_ref: relation_id.clone(),
                    resource_revision: Some(1),
                    causation_ref: meta.causation_event_ref.clone(),
                    correlation_ref: meta.request_id.clone(),
                    classification_ref: relation.classification_ref.clone(),
                    payload: payload.clone(),
                })
                .map_err(store_problem)?;
            txn.audit(
                "command.relation_asserted",
                &format!(
                    "relation={relation_id};space={};digest={digest};{}",
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
        },
    );
    command_outcome_bytes(outcome)
}

// --------------------------------------------------------- frontier_pin ----

/// Builds and inserts one SpaceFrontier row pinning the branch's current
/// head inside an open command transaction.
pub fn pin_frontier_in_txn(
    txn: &mut CommandTxn<'_>,
    project_id: &str,
    space_id: &str,
    branch: &BranchRow,
) -> Result<SpaceFrontier, Problem> {
    let frontier_id = new_id("front").map_err(store_problem)?;
    let head_seq = project_head_seq(txn.conn(), project_id).map_err(store_problem)?;
    let cursor = txn
        .mint_project_cursor(project_id, head_seq)
        .map_err(store_problem)?;
    let branch_sequence = branch.next_branch_sequence - 1;
    let projection = serde_json::json!({
        "frontier_id": frontier_id,
        "space_id": space_id,
        "branch_id": branch.branch_id,
        "branch_sequence": branch_sequence,
        "branch_head_digest": branch.head_digest,
        "project_event_sequence": head_seq,
    });
    let (_, digest) = canonical_object_digest("kovee-frontier", FRONTIER_SCHEMA_REF, &projection)
        .map_err(|_| internal())?;
    let frontier = SpaceFrontier {
        frontier_id: frontier_id.clone(),
        revision: 1,
        space_id: space_id.to_owned(),
        branch_id: branch.branch_id.clone(),
        branch_sequence,
        branch_head_digest: branch.head_digest.clone(),
        project_event_cursor: cursor,
        external_source_cursors: Vec::new(),
        created_at: txn.now_ts(),
        digest,
    };
    txn.conn()
        .execute(
            "INSERT INTO space_frontiers (frontier_id, revision, space_id,
                 branch_id, branch_sequence, branch_head_digest,
                 project_event_cursor, external_source_cursors, created_at,
                 digest)
             VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, '[]', ?7, ?8)",
            rusqlite::params![
                frontier.frontier_id,
                frontier.space_id,
                frontier.branch_id,
                frontier.branch_sequence as i64,
                frontier.branch_head_digest,
                frontier.project_event_cursor,
                frontier.created_at,
                frontier.digest,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    Ok(frontier)
}

pub fn frontier_pin(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::FrontierPinArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let space = visible_space(txn.conn(), &project_id, &args.space_id)?;
        if let Some(expected) = meta.expected_revision {
            if expected != space.revision {
                return Err(stale_revision(space.revision));
            }
        }
        let branch = visible_branch(txn.conn(), &space, &args.branch_id)?;
        let frontier = pin_frontier_in_txn(txn, &project_id, &space.space_id, &branch)?;
        let payload = serde_json::to_value(&frontier).map_err(|_| internal())?;
        let event = txn
            .append_event(NewEvent {
                stream_id: space.space_id.clone(),
                project_id: Some(project_id.clone()),
                actor_ref: None,
                event_type: EVENT_FRONTIER_PINNED.to_owned(),
                schema_ref: FRONTIER_SCHEMA_REF.to_owned(),
                resource_ref: frontier.frontier_id.clone(),
                resource_revision: Some(1),
                causation_ref: meta.causation_event_ref.clone(),
                correlation_ref: meta.request_id.clone(),
                classification_ref: space.default_classification_ref.clone(),
                payload: payload.clone(),
            })
            .map_err(store_problem)?;
        txn.audit(
            "command.frontier_pinned",
            &format!(
                "frontier={};space={};{}",
                frontier.frontier_id,
                space.space_id,
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

// ---------------------------------------------- context_assembly_create ----

#[allow(clippy::too_many_arguments)]
pub fn context_assembly_create(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ContextAssemblyCreateArgs,
    meta: CommandMeta,
    author: AppendAuthor,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let replay_author = author.clone();
    let outcome = store.command_transaction_guarded(
        &scope,
        now,
        hooks,
        move |conn| replay_author.check(conn),
        move |txn| {
            author.check(txn.conn())?;
            if args.selection_policy_ref != EXPLICIT_REFS_POLICY {
                return Err(
                    Problem::new(ProblemKind::Invalid, "unknown selection policy")
                        .with_detail("K1 serves exactly the built-in explicit_refs_v1 policy"),
                );
            }
            if args.recipe_ref.is_some() || args.recipe_revision.is_some() {
                // §10.8: K1 direct invocation needs no saved recipe; reusable
                // recipe-bound assemblies are a K2 capability.
                return Err(Problem::new(
                    ProblemKind::Invalid,
                    "recipe binding is a K2 capability",
                ));
            }
            let space = visible_space(txn.conn(), &project_id, &args.space_id)?;
            let branch = visible_branch(txn.conn(), &space, &args.branch_id)?;
            if let Some(expected) = meta.expected_revision {
                if expected != space.revision {
                    return Err(stale_revision(space.revision));
                }
            }
            // The assembly pins its own frontier in this same transaction:
            // every included item is at or below that exact boundary.
            let frontier = pin_frontier_in_txn(txn, &project_id, &space.space_id, &branch)?;

            let required = args.required_refs.clone().unwrap_or_default();
            let triggers = args.trigger_refs.clone().unwrap_or_default();
            let mut items: Vec<AssemblyItem> = Vec::new();
            let mut relations: Vec<AssemblyRelation> = Vec::new();
            let mut classifications: Vec<String> = Vec::new();
            let mut total_bytes = 0u64;
            for (order, object_ref) in required.iter().enumerate() {
                // §10.8: required refs are never silently replaced or
                // dropped — an unresolvable, cross-space, or wrong-branch
                // ref fails assembly creation (no omission record can stand
                // in for required content).
                let object = resolve_space_object(txn.conn(), &space.space_id, object_ref)?;
                if object.origin_branch_id() != branch.branch_id {
                    return Err(not_found());
                }
                if object.branch_sequence() > frontier.branch_sequence {
                    return Err(stale_revision(space.revision)
                        .with_detail("required ref is beyond the pinned frontier"));
                }
                match object {
                    SpaceObject::Contribution(c) => {
                        let size = serde_json::to_string(&c.body_parts)
                            .map_err(|_| internal())?
                            .len() as u64;
                        total_bytes += size;
                        classifications.push(c.classification_ref.clone());
                        items.push(AssemblyItem {
                            object_ref: c.contribution_id.clone(),
                            revision: c.revision,
                            digest: c.content_digest.clone(),
                            size,
                            classification_ref: c.classification_ref.clone(),
                            role: "required".to_owned(),
                            order: order as u64,
                            inclusion_reason: "explicit_ref".to_owned(),
                        });
                    }
                    SpaceObject::Relation(r) => {
                        relations.push(AssemblyRelation {
                            relation_ref: r.relation_id.clone(),
                            digest: r.digest.clone(),
                        });
                    }
                }
            }
            for trigger in &triggers {
                resolve_space_object(txn.conn(), &space.space_id, trigger)?;
            }
            // The classification join of the included set (uniform K1 set;
            // a mixed set joins to the space default ceiling).
            let classification_join_ref = match classifications.first() {
                Some(first) if classifications.iter().all(|c| c == first) => first.clone(),
                _ => space.default_classification_ref.clone(),
            };
            let (_, policy_digest) = canonical_object_digest(
                "kovee-selection-policy",
                "schema:kovee-selection-policy-v1",
                &serde_json::json!({"policy": EXPLICIT_REFS_POLICY, "version": 1}),
            )
            .map_err(|_| internal())?;
            let (_, authority_digest) = canonical_object_digest(
                "kovee-authority",
                "schema:kovee-authority-v1",
                &serde_json::json!({
                    "actor": author.actor_ref,
                    "dependency_set": AUTHZ_DEP_SET_REF,
                    "space_id": space.space_id,
                    "branch_id": branch.branch_id,
                }),
            )
            .map_err(|_| internal())?;
            let assembly_id = new_id("casm").map_err(store_problem)?;
            let mut assembly = ContextAssembly {
                assembly_id: assembly_id.clone(),
                revision: 1,
                realm_id: txn.realm_id().to_owned(),
                project_id: project_id.clone(),
                space_id: space.space_id.clone(),
                branch_id: branch.branch_id.clone(),
                audience_ref: args.audience_ref.clone(),
                purpose: args.purpose.clone(),
                trigger_refs: triggers.clone(),
                frontier_ref: frontier.frontier_id.clone(),
                frontier_digest: frontier.digest.clone(),
                recipe_ref: None,
                recipe_revision: None,
                recipe_digest: None,
                selection_policy_ref: EXPLICIT_REFS_POLICY.to_owned(),
                selection_policy_digest: policy_digest,
                totals: AssemblyTotals {
                    items: items.len() as u64,
                    bytes: total_bytes,
                    estimated_tokens: total_bytes / 4,
                },
                items,
                relations,
                transformations: Vec::new(),
                // explicit_refs_v1 admits no visible-candidate omission: a
                // required ref either includes or fails the assembly.
                omissions: Vec::new(),
                classification_join_ref,
                selection_policy_version: "v1".to_owned(),
                assembler_version: ASSEMBLER_VERSION.to_owned(),
                authorization_dependency_set_ref: AUTHZ_DEP_SET_REF.to_owned(),
                authority_digest,
                created_at: txn.now_ts(),
                digest: String::new(),
            };
            let mut projection = serde_json::to_value(&assembly).map_err(|_| internal())?;
            projection
                .as_object_mut()
                .ok_or_else(internal)?
                .remove("digest");
            let (_, digest) =
                canonical_object_digest("kovee-context-assembly", ASSEMBLY_SCHEMA_REF, &projection)
                    .map_err(|_| internal())?;
            assembly.digest = digest;
            let payload = serde_json::to_value(&assembly).map_err(|_| internal())?;
            txn.conn()
                .execute(
                    "INSERT INTO context_assemblies (assembly_id, realm_id, project_id,
                     space_id, branch_id, frontier_ref, digest, record, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    rusqlite::params![
                        assembly.assembly_id,
                        assembly.realm_id,
                        assembly.project_id,
                        assembly.space_id,
                        assembly.branch_id,
                        assembly.frontier_ref,
                        assembly.digest,
                        serde_json::to_string(&payload).map_err(|_| internal())?,
                        assembly.created_at,
                    ],
                )
                .map_err(|e| store_problem(e.into()))?;
            let event = txn
                .append_event(NewEvent {
                    stream_id: space.space_id.clone(),
                    project_id: Some(project_id.clone()),
                    actor_ref: None,
                    event_type: EVENT_CONTEXT_ASSEMBLY_CREATED.to_owned(),
                    schema_ref: ASSEMBLY_SCHEMA_REF.to_owned(),
                    resource_ref: assembly_id.clone(),
                    resource_revision: Some(1),
                    causation_ref: meta.causation_event_ref.clone(),
                    correlation_ref: meta.request_id.clone(),
                    classification_ref: assembly.classification_join_ref.clone(),
                    payload: serde_json::json!({
                        "assembly_id": assembly.assembly_id,
                        "space_id": assembly.space_id,
                        "frontier_ref": assembly.frontier_ref,
                        "digest": assembly.digest,
                        "totals": assembly.totals,
                    }),
                })
                .map_err(store_problem)?;
            txn.audit(
                "command.context_assembly_created",
                &format!(
                    "assembly={assembly_id};space={};digest={};{}",
                    assembly.space_id,
                    assembly.digest,
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
        },
    );
    command_outcome_bytes(outcome)
}
