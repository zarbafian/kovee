//! §10.2 dispositions (slice 3): `contribution_withdraw`,
//! `contribution_supersede`, `contribution_redact`, `relation_retract`.
//! Dispositions are append-only records beside the content — they never
//! delete or rewrite provenance — with ONE deliberate exception:
//! redaction (amendment A5) removes the retained plaintext payload and
//! replaces the plaintext canonical `content_digest` with a typed
//! `local_erasure_safe` digest (HMAC under a random per-object secret),
//! closing the K1 gap recorded at `contribution_append`. Destroying that
//! secret later erases exactly that object's verifiability.

use kovee_core::envelope::CommandMeta;
use kovee_core::event::{
    EVENT_CONTRIBUTION_REDACTED, EVENT_CONTRIBUTION_SUPERSEDED, EVENT_CONTRIBUTION_WITHDRAWN,
    EVENT_RELATION_RETRACTED,
};
use kovee_core::family::{hex, hmac_sha256, tagged_canonical, DigestRef};
use kovee_core::ops;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::{
    Contribution, ContributionDisposition, ContributionPart, RelationDisposition,
};
use kovee_store::{
    new_id, Applied, CommandScope, CommandTxn, CrashHooks, NewEvent, Store, OWNER_ACTOR_REF,
};
use rusqlite::params;
use serde_json::Value;

use crate::handlers::{command_outcome_bytes, scope_digest};
use crate::state::*;

/// The placeholder body of a redacted contribution: schema-valid (one
/// text part), carrying no plaintext.
pub const REDACTED_MEDIA_TYPE: &str = "application/x.kovee.redacted";

fn already_disposed(detail: &str) -> Problem {
    Problem::new(ProblemKind::Invalid, "invalid disposition").with_detail(detail.to_owned())
}

/// Loads the target contribution, visible in this project, and its open
/// space. `require_open` enforces the space/content-mutation family rule;
/// redaction (a retention/compliance action) skips it.
fn disposition_target(
    txn: &CommandTxn<'_>,
    project_id: &str,
    contribution_ref: &str,
    require_open: bool,
) -> Result<(Contribution, kovee_core::records::Space), Problem> {
    let contribution = get_contribution(txn.conn(), contribution_ref)
        .map_err(store_problem)?
        .filter(|c| c.project_id == project_id)
        .ok_or_else(not_found)?;
    let space = visible_space(txn.conn(), project_id, &contribution.space_id)?;
    if require_open && space.status != "open" {
        return Err(Problem::new(
            ProblemKind::StaleRevision,
            "space is not open for dispositions",
        )
        .with_detail(format!("space status is {}", space.status)));
    }
    Ok((contribution, space))
}

fn check_expected_revision(meta: &CommandMeta, current: u64) -> Result<(), Problem> {
    if let Some(expected) = meta.expected_revision {
        if expected != current {
            return Err(stale_revision(current));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_contribution_disposition(
    txn: &mut CommandTxn<'_>,
    project_id: &str,
    space_revision: u64,
    space_id: &str,
    classification_ref: &str,
    disposition: &ContributionDisposition,
    meta: &CommandMeta,
    event_type: &str,
    audit_event: &str,
) -> Result<Applied, Problem> {
    txn.conn()
        .execute(
            "INSERT INTO contribution_dispositions (disposition_id, contribution_ref,
                 space_id, kind, replacement_ref, reason_class, authorized_by_ref,
                 payload_removed_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                disposition.disposition_id,
                disposition.contribution_ref,
                space_id,
                disposition.kind,
                disposition.replacement_ref,
                disposition.reason_class,
                disposition.authorized_by_ref,
                disposition.payload_removed_at,
                disposition.created_at,
            ],
        )
        .map_err(|e| store_problem(e.into()))?;
    let new_revision = space_revision + 1;
    txn.conn()
        .execute(
            "UPDATE spaces SET revision = ?2 WHERE space_id = ?1",
            params![space_id, new_revision as i64],
        )
        .map_err(|e| store_problem(e.into()))?;
    let payload = serde_json::to_value(disposition).map_err(|_| internal())?;
    let event = txn
        .append_event(NewEvent {
            stream_id: space_id.to_owned(),
            project_id: Some(project_id.to_owned()),
            actor_ref: None,
            event_type: event_type.to_owned(),
            schema_ref: "schema:contribution-disposition-v1".to_owned(),
            resource_ref: disposition.disposition_id.clone(),
            resource_revision: Some(1),
            causation_ref: meta.causation_event_ref.clone(),
            correlation_ref: meta.request_id.clone(),
            classification_ref: classification_ref.to_owned(),
            payload: payload.clone(),
        })
        .map_err(store_problem)?;
    txn.audit(
        audit_event,
        &format!(
            "disposition={};contribution={};{}",
            disposition.disposition_id,
            disposition.contribution_ref,
            scope_digest(meta)
        ),
    );
    let cursor = txn
        .mint_project_cursor(project_id, event.project_sequence.unwrap_or(0))
        .map_err(store_problem)?;
    Ok(Applied {
        result: payload,
        revision: Some(new_revision),
        event_cursor: Some(cursor),
    })
}

// ------------------------------------------------ contribution_withdraw ----

pub fn contribution_withdraw(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ContributionDispositionArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let (contribution, space) =
            disposition_target(txn, &project_id, &args.contribution_ref, true)?;
        check_expected_revision(&meta, space.revision)?;
        if disposition_exists(txn, &args.contribution_ref, "withdraw")? {
            return Err(already_disposed("contribution is already withdrawn"));
        }
        let disposition = ContributionDisposition {
            disposition_id: new_id("cdisp").map_err(store_problem)?,
            contribution_ref: args.contribution_ref.clone(),
            kind: "withdraw".to_owned(),
            replacement_ref: None,
            reason_class: args.reason_class.clone(),
            authorized_by_ref: OWNER_ACTOR_REF.to_owned(),
            payload_removed_at: None,
            created_at: txn.now_ts(),
        };
        record_contribution_disposition(
            txn,
            &project_id,
            space.revision,
            &space.space_id,
            &contribution.classification_ref,
            &disposition,
            &meta,
            EVENT_CONTRIBUTION_WITHDRAWN,
            "command.contribution_withdrawn",
        )
    });
    command_outcome_bytes(outcome)
}

// ----------------------------------------------- contribution_supersede ----

pub fn contribution_supersede(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ContributionSupersedeArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let (contribution, space) =
            disposition_target(txn, &project_id, &args.contribution_ref, true)?;
        check_expected_revision(&meta, space.revision)?;
        if args.replacement_ref == args.contribution_ref {
            return Err(already_disposed("a contribution cannot supersede itself"));
        }
        // §10.2: the replacement must be a visible same-space contribution.
        let replacement = get_contribution(txn.conn(), &args.replacement_ref)
            .map_err(store_problem)?
            .filter(|c| c.space_id == space.space_id)
            .ok_or_else(not_found)?;
        if disposition_exists(txn, &args.contribution_ref, "supersede")? {
            return Err(already_disposed("contribution is already superseded"));
        }
        let disposition = ContributionDisposition {
            disposition_id: new_id("cdisp").map_err(store_problem)?,
            contribution_ref: args.contribution_ref.clone(),
            kind: "supersede".to_owned(),
            replacement_ref: Some(replacement.contribution_id.clone()),
            reason_class: args.reason_class.clone(),
            authorized_by_ref: OWNER_ACTOR_REF.to_owned(),
            payload_removed_at: None,
            created_at: txn.now_ts(),
        };
        record_contribution_disposition(
            txn,
            &project_id,
            space.revision,
            &space.space_id,
            &contribution.classification_ref,
            &disposition,
            &meta,
            EVENT_CONTRIBUTION_SUPERSEDED,
            "command.contribution_superseded",
        )
    });
    command_outcome_bytes(outcome)
}

// -------------------------------------------------- contribution_redact ----

/// Amendment A5 erasure-safe redaction. Inside ONE command transaction:
/// the plaintext body parts are replaced by the schema-valid redaction
/// placeholder; the plaintext canonical `content_digest` (and its branch
/// ledger copy) is replaced by a typed `local_erasure_safe` HMAC digest
/// under a fresh per-object secret; the retained event-ledger payloads
/// carrying the plaintext are re-projected; and the disposition (kind
/// `redact`, `payload_removed_at` set) plus its event are recorded.
/// Assemblies pinning the old digest correctly become unmaterializable
/// (§10.8) — erasure wins over replay.
pub fn contribution_redact(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::ContributionDispositionArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        // Redaction is a retention/compliance action: a frozen or archived
        // space does not shield plaintext from erasure.
        let (contribution, space) =
            disposition_target(txn, &project_id, &args.contribution_ref, false)?;
        check_expected_revision(&meta, space.revision)?;
        let state: String = txn
            .conn()
            .query_row(
                "SELECT content_state FROM contributions WHERE contribution_id = ?1",
                [&contribution.contribution_id],
                |r| r.get(0),
            )
            .map_err(|e| store_problem(e.into()))?;
        if state == "redacted" {
            return Err(already_disposed("contribution is already redacted"));
        }

        // The erasure-safe re-digest (A5): HMAC over the exact original
        // content projection, under a fresh per-object secret, BEFORE the
        // plaintext is removed.
        let content_projection = serde_json::json!({
            "space_id": contribution.space_id,
            "origin_branch_id": contribution.origin_branch_id,
            "origin_branch_sequence": contribution.origin_branch_sequence,
            "kind": contribution.kind,
            "body_parts": contribution.body_parts,
            "subject_refs": contribution.subject_refs,
            "source_refs": contribution.source_refs,
            "epistemic_posture": contribution.epistemic_posture,
        });
        let preimage = tagged_canonical("kovee-contribution-content", &content_projection)
            .map_err(|_| internal())?;
        let secret = object_secret().map_err(store_problem)?;
        let value_hex = hex(&hmac_sha256(&secret, &preimage));
        let key_ref = format!("kovee-contribution-object:{}", contribution.contribution_id);
        let digest_ref = DigestRef::local_erasure_safe(&key_ref, value_hex.clone());

        let redacted_parts = vec![ContributionPart::Text {
            media_type: REDACTED_MEDIA_TYPE.to_owned(),
            text: String::new(),
            language: None,
        }];
        let now_ts = txn.now_ts();
        txn.conn()
            .execute(
                "UPDATE contributions SET body_parts = ?2, content_digest = ?3,
                     content_state = 'redacted', content_digest_ref = ?4,
                     object_secret = ?5
                 WHERE contribution_id = ?1",
                params![
                    contribution.contribution_id,
                    serde_json::to_string(&redacted_parts).map_err(|_| internal())?,
                    value_hex,
                    serde_json::to_string(&digest_ref).map_err(|_| internal())?,
                    secret.as_slice(),
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        // The branch-ledger copy of the plaintext digest moves to the
        // erasure-safe value too (the already-folded head chain keeps its
        // computed values; verifying this entry now requires the
        // per-object secret — destroying it erases that verifiability).
        txn.conn()
            .execute(
                "UPDATE branch_entries SET object_digest = ?3
                 WHERE branch_id = ?1 AND branch_sequence = ?2",
                params![
                    contribution.origin_branch_id,
                    contribution.origin_branch_sequence as i64,
                    value_hex,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        // Retained event payloads carrying the plaintext are re-projected:
        // the ledger keeps the event (history is not deleted), the
        // payload bytes are gone.
        scrub_event_payloads(txn, &contribution, &redacted_parts, &value_hex)?;

        let disposition = ContributionDisposition {
            disposition_id: new_id("cdisp").map_err(store_problem)?,
            contribution_ref: args.contribution_ref.clone(),
            kind: "redact".to_owned(),
            replacement_ref: None,
            reason_class: args.reason_class.clone(),
            authorized_by_ref: OWNER_ACTOR_REF.to_owned(),
            payload_removed_at: Some(now_ts),
            created_at: txn.now_ts(),
        };
        record_contribution_disposition(
            txn,
            &project_id,
            space.revision,
            &space.space_id,
            &contribution.classification_ref,
            &disposition,
            &meta,
            EVENT_CONTRIBUTION_REDACTED,
            "command.contribution_redacted",
        )
    });
    command_outcome_bytes(outcome)
}

/// Replaces the payload of every retained ledger event that embeds the
/// contribution's plaintext (`resource_ref` = the contribution) with the
/// redacted projection, recomputing the stored payload digest over the
/// new payload so the pair stays coherent.
fn scrub_event_payloads(
    txn: &CommandTxn<'_>,
    contribution: &Contribution,
    redacted_parts: &[ContributionPart],
    erasure_digest_hex: &str,
) -> Result<(), Problem> {
    let rows: Vec<(String, String, String)> = {
        let mut stmt = txn
            .conn()
            .prepare(
                "SELECT event_id, schema_ref, payload FROM events
                 WHERE resource_ref = ?1",
            )
            .map_err(|e| store_problem(e.into()))?;
        let mapped = stmt
            .query_map([&contribution.contribution_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .map_err(|e| store_problem(e.into()))?;
        mapped
            .collect::<Result<_, _>>()
            .map_err(|e| store_problem(e.into()))?
    };
    for (event_id, schema_ref, payload_text) in rows {
        let mut payload: Value = serde_json::from_str(&payload_text).map_err(|_| internal())?;
        let Some(object) = payload.as_object_mut() else {
            continue;
        };
        if object.contains_key("body_parts") {
            object.insert(
                "body_parts".to_owned(),
                serde_json::to_value(redacted_parts).map_err(|_| internal())?,
            );
        }
        if object.contains_key("content_digest") {
            object.insert(
                "content_digest".to_owned(),
                Value::String(erasure_digest_hex.to_owned()),
            );
        }
        let (_, payload_digest) = kovee_core::canonical::canonical_object_digest(
            "kcp-event-payload",
            &schema_ref,
            &payload,
        )
        .map_err(|_| internal())?;
        txn.conn()
            .execute(
                "UPDATE events SET payload = ?2, payload_digest = ?3 WHERE event_id = ?1",
                params![
                    event_id,
                    serde_json::to_string(&payload).map_err(|_| internal())?,
                    payload_digest,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
    }
    Ok(())
}

fn object_secret() -> Result<[u8; 32], kovee_store::StoreError> {
    use std::io::Read as _;
    let mut secret = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut secret))
        .map_err(kovee_store::StoreError::Entropy)?;
    Ok(secret)
}

fn disposition_exists(
    txn: &CommandTxn<'_>,
    contribution_ref: &str,
    kind: &str,
) -> Result<bool, Problem> {
    use rusqlite::OptionalExtension as _;
    let found: Option<i64> = txn
        .conn()
        .query_row(
            "SELECT 1 FROM contribution_dispositions
             WHERE contribution_ref = ?1 AND kind = ?2",
            params![contribution_ref, kind],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    Ok(found.is_some())
}

// ------------------------------------------------------ relation_retract ----

pub fn relation_retract(
    store: &mut Store,
    scope: CommandScope,
    project_id: String,
    args: ops::RelationRetractArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        let relation = get_relation(txn.conn(), &args.relation_ref)
            .map_err(store_problem)?
            .ok_or_else(not_found)?;
        let space = visible_space(txn.conn(), &project_id, &relation.space_id)?;
        if space.status != "open" {
            return Err(Problem::new(
                ProblemKind::StaleRevision,
                "space is not open for dispositions",
            ));
        }
        check_expected_revision(&meta, space.revision)?;
        {
            use rusqlite::OptionalExtension as _;
            let found: Option<i64> = txn
                .conn()
                .query_row(
                    "SELECT 1 FROM relation_dispositions WHERE relation_ref = ?1",
                    [&args.relation_ref],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| store_problem(e.into()))?;
            if found.is_some() {
                return Err(already_disposed("relation is already retracted"));
            }
        }
        let disposition = RelationDisposition {
            disposition_id: new_id("rdisp").map_err(store_problem)?,
            relation_ref: args.relation_ref.clone(),
            kind: "retract".to_owned(),
            authorized_by_ref: OWNER_ACTOR_REF.to_owned(),
            reason_class: args.reason_class.clone(),
            created_at: txn.now_ts(),
        };
        txn.conn()
            .execute(
                "INSERT INTO relation_dispositions (disposition_id, relation_ref,
                     space_id, kind, reason_class, authorized_by_ref, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    disposition.disposition_id,
                    disposition.relation_ref,
                    space.space_id,
                    disposition.kind,
                    disposition.reason_class,
                    disposition.authorized_by_ref,
                    disposition.created_at,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        let new_revision = space.revision + 1;
        txn.conn()
            .execute(
                "UPDATE spaces SET revision = ?2 WHERE space_id = ?1",
                params![space.space_id, new_revision as i64],
            )
            .map_err(|e| store_problem(e.into()))?;
        let payload = serde_json::to_value(&disposition).map_err(|_| internal())?;
        let event = txn
            .append_event(NewEvent {
                stream_id: space.space_id.clone(),
                project_id: Some(project_id.clone()),
                actor_ref: None,
                event_type: EVENT_RELATION_RETRACTED.to_owned(),
                schema_ref: "schema:relation-disposition-v1".to_owned(),
                resource_ref: disposition.disposition_id.clone(),
                resource_revision: Some(1),
                causation_ref: meta.causation_event_ref.clone(),
                correlation_ref: meta.request_id.clone(),
                classification_ref: relation.classification_ref.clone(),
                payload: payload.clone(),
            })
            .map_err(store_problem)?;
        txn.audit(
            "command.relation_retracted",
            &format!(
                "disposition={};relation={};{}",
                disposition.disposition_id,
                disposition.relation_ref,
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
