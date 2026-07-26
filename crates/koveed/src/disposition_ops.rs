//! §10.2 dispositions (slice 3): `contribution_withdraw`,
//! `contribution_supersede`, `contribution_redact`, `relation_retract`.
//! Dispositions are append-only records beside the content — they never
//! delete or rewrite provenance — with ONE deliberate exception:
//! redaction (amendment A5, D-R1-2) removes the retained plaintext
//! payload wherever it is retained.
//!
//! The content digest never has to move: a contribution's
//! `content_digest` is `local_erasure_safe` from its FIRST append (an
//! HMAC under this object's own random secret, wrapped under the realm
//! key — see [`mint_content_digest`]), so no plaintext-derived digest of
//! a contribution exists to be copied into replay results, audit rows,
//! relations, event payloads, or branch folds. Redaction removes the
//! plaintext, every retained copy of it, AND this object's wrapped
//! secret — erasing exactly that object's verifiability, and nothing
//! else's.
//!
//! Why the secret dies with the plaintext (KV-A5-1): a wrap retained
//! beside a redacted row is not erasure. Anyone with the realm key —
//! which is right there in `meta` — unwraps it, HMACs a guess of the
//! removed text, and compares with the stored digest. The R1
//! confirmation did exactly that. `NULL`ing the wrap removes the only
//! copy of that object's key material, so the digest becomes
//! unreproducible; every other object keeps its own wrap and stays
//! verifiable.

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

/// Mints one contribution's `local_erasure_safe` content digest: a fresh
/// **random** per-object secret, **wrapped under the realm key**, and the
/// HMAC of the tagged canonical content projection under that secret
/// (family PROFILE §6.1, D-R1-2). Returns
/// `(value_hex, digest_ref, wrapped_secret)`.
///
/// Used by `contribution_append` from the FIRST append, so no
/// plaintext-derived digest of a contribution ever exists to be copied
/// into a replay result, an audit row, a relation, an event, or a branch
/// fold.
pub fn mint_content_digest(
    conn: &rusqlite::Connection,
    contribution_id: &str,
    content_projection: &Value,
) -> Result<(String, DigestRef, Vec<u8>), Problem> {
    let preimage = tagged_canonical("kovee-contribution-content", content_projection)
        .map_err(|_| internal())?;
    let secret = kovee_store::objkey::new_object_secret().map_err(store_problem)?;
    let key_ref = format!("kovee-contribution-object:{contribution_id}");
    let realm_key = kovee_store::realm_object_key_of(conn).map_err(store_problem)?;
    let wrapped =
        kovee_store::objkey::wrap(&realm_key, &key_ref, &secret).map_err(store_problem)?;
    let value_hex = hex(&hmac_sha256(&secret, &preimage));
    Ok((
        value_hex.clone(),
        DigestRef::local_erasure_safe(&key_ref, value_hex),
        wrapped,
    ))
}

/// Amendment A5 + D-R1-2 erasure-safe redaction. Inside ONE command
/// transaction:
///
/// - the plaintext body parts are replaced by the schema-valid redaction
///   placeholder, and any artifact part's bytes and per-object secret are
///   erased with it;
/// - **this object's wrapped secret is destroyed** (`object_secret =
///   NULL`), so its `local_erasure_safe` digest can no longer be
///   re-derived from the removed plaintext by anyone — including a holder
///   of the realm key (KV-A5-1);
/// - the content digest is already `local_erasure_safe` (keyed from the
///   first append), so nothing plaintext-derived has to be replaced; a
///   pre-V5 row that still carries a plaintext canonical digest is
///   re-keyed here (under a secret that is never stored) and every
///   retained copy of the old value is scrubbed with the plaintext;
/// - every retention-graph copy is scrubbed transactionally: the stored
///   idempotency result bytes (a replay returns the redacted projection,
///   never the erased plaintext), the retained event payloads with their
///   recomputed payload digests, the audit details (re-linked), and the
///   assembly/invocation records;
/// - the branch head is recomputed as the fold over the branch entries,
///   so the keyed chain stays recomputable by any authorized reader. The
///   redacted entry's own digest is no longer verifiable (its secret is
///   gone — that is the erasure semantics, D-R1-2); every unrelated entry
///   still folds and still verifies.
///
/// The file-level compaction that removes freed plaintext pages runs
/// straight after the commit ([`kovee_store::Store::compact_after_erasure`]);
/// a crash in between leaves the pending flag set and the next open
/// finishes it.
#[allow(clippy::too_many_arguments)]
pub fn contribution_redact(
    store: &mut Store,
    paths: &kovee_artifacts::ArtifactPaths,
    scope: CommandScope,
    project_id: String,
    args: ops::ContributionDispositionArgs,
    meta: CommandMeta,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let paths = paths.clone();
    let outcome = store.command_transaction(&scope, now, hooks, move |txn| {
        // Redaction is a retention/compliance action: a frozen or archived
        // space does not shield plaintext from erasure.
        let (contribution, space) =
            disposition_target(txn, &project_id, &args.contribution_ref, false)?;
        check_expected_revision(&meta, space.revision)?;
        let (state, wrapped_secret): (String, Option<Vec<u8>>) = txn
            .conn()
            .query_row(
                "SELECT content_state, object_secret FROM contributions
                 WHERE contribution_id = ?1",
                [&contribution.contribution_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| store_problem(e.into()))?;
        if state == "redacted" {
            return Err(already_disposed("contribution is already redacted"));
        }

        let old_digest = contribution.content_digest.clone();
        // Keyed from the first append (V5 and later): the digest does not
        // move, so no copy of it anywhere is a plaintext-derived value.
        // A pre-V5 row has no wrapped secret and a plaintext canonical
        // digest — re-key it now and sweep the old value out with the
        // plaintext.
        let (value_hex, digest_ref) = match wrapped_secret {
            Some(_) => {
                let key_ref = format!("kovee-contribution-object:{}", contribution.contribution_id);
                (
                    old_digest.clone(),
                    DigestRef::local_erasure_safe(&key_ref, old_digest.clone()),
                )
            }
            None => {
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
                let (value_hex, digest_ref, _destroyed_with_the_plaintext) = mint_content_digest(
                    txn.conn(),
                    &contribution.contribution_id,
                    &content_projection,
                )?;
                // The fresh wrap is never stored: it is minted only to
                // give the erased object a stable address that is not
                // plaintext-derived, and dropped in this same statement.
                (value_hex, digest_ref)
            }
        };
        let rekeyed = value_hex != old_digest;

        let redacted_parts = vec![ContributionPart::Text {
            media_type: REDACTED_MEDIA_TYPE.to_owned(),
            text: String::new(),
            language: None,
        }];
        let now_ts = txn.now_ts();
        // KV-A5-1: `object_secret = NULL` is the erasure. Keeping the wrap
        // beside the redacted row left the whole promise on the realm key:
        // the R1 confirmation unwrapped the retained 84-byte blob and
        // recomputed the erased plaintext's stored HMAC digest from a
        // guess. Destroying the wrap destroys this object's key material,
        // so that digest can never be re-derived — by us or by anyone
        // holding the realm key. The digest VALUE stays as the object's
        // address; it is now unverifiable, which is what erasure means.
        txn.conn()
            .execute(
                "UPDATE contributions SET body_parts = ?2, content_digest = ?3,
                     content_state = 'redacted', content_digest_ref = ?4,
                     object_secret = NULL
                 WHERE contribution_id = ?1",
                params![
                    contribution.contribution_id,
                    serde_json::to_string(&redacted_parts).map_err(|_| internal())?,
                    value_hex,
                    serde_json::to_string(&digest_ref).map_err(|_| internal())?,
                ],
            )
            .map_err(|e| store_problem(e.into()))?;
        // Artifact parts hold the same plaintext as bytes on disk:
        // erasing the contribution erases them (blob removed, per-object
        // secret destroyed, tombstone row left).
        for part in &contribution.body_parts {
            if let ContributionPart::Artifact { artifact_ref, .. } = part {
                kovee_artifacts::erase_artifact(txn.conn(), &paths, artifact_ref, now, &now_ts)
                    .map_err(store_problem)?;
            }
        }
        // The branch-ledger copy follows the (possibly re-keyed) value and
        // the head is recomputed as the fold over the stored entries, so
        // the chain a reader recomputes from the ledger still matches.
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
        recompute_branch_head(txn.conn(), &contribution.origin_branch_id)?;

        // Every retained copy in the retention graph, in this same
        // transaction.
        let needles = plaintext_needles(&contribution.body_parts, &old_digest, rekeyed);
        scrub_retention_graph(txn, &contribution, &redacted_parts, &value_hex, &needles)?;
        kovee_store::mark_erasure_compaction_pending(txn.conn()).map_err(store_problem)?;

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
    let bytes = command_outcome_bytes(outcome)?;
    // The rows are gone; now the freed pages and the WAL images of them.
    store.compact_after_erasure().map_err(store_problem)?;
    Ok(bytes)
}

/// Recomputes a branch head as the §10.3 fold over its stored entries —
/// the same fold an authorized reader derives from the ledger. Called
/// after erasure so the keyed chain stays recomputable.
fn recompute_branch_head(conn: &rusqlite::Connection, branch_id: &str) -> Result<(), Problem> {
    let entries: Vec<(i64, String)> = {
        let mut stmt = conn
            .prepare(
                "SELECT branch_sequence, object_digest FROM branch_entries
                 WHERE branch_id = ?1 ORDER BY branch_sequence ASC",
            )
            .map_err(|e| store_problem(e.into()))?;
        let mapped = stmt
            .query_map([branch_id], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| store_problem(e.into()))?;
        mapped
            .collect::<Result<_, _>>()
            .map_err(|e| store_problem(e.into()))?
    };
    let mut head = kovee_core::branch::genesis_head(branch_id);
    for (sequence, digest) in entries {
        head = kovee_core::branch::next_head(&head, sequence as u64, &digest);
    }
    conn.execute(
        "UPDATE reasoning_branches SET head_digest = ?2 WHERE branch_id = ?1",
        params![branch_id, head],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

/// The literal strings that must not survive anywhere: every plaintext
/// leaf of the removed body, plus the superseded digest when a pre-V5 row
/// had to be re-keyed. Short leaves (< 4 bytes) are left to the
/// structural rewrite — a blind substring sweep for them would corrupt
/// unrelated rows without erasing anything meaningful.
fn plaintext_needles(parts: &[ContributionPart], old_digest: &str, rekeyed: bool) -> Vec<String> {
    fn leaves(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::String(s) => out.push(s.clone()),
            Value::Array(items) => items.iter().for_each(|i| leaves(i, out)),
            Value::Object(map) => map.values().for_each(|i| leaves(i, out)),
            _ => {}
        }
    }
    let mut needles = Vec::new();
    for part in parts {
        match part {
            ContributionPart::Text { text, .. } => needles.push(text.clone()),
            ContributionPart::Data { value, .. } => {
                needles.push(serde_json::to_string(value).unwrap_or_default());
                leaves(value, &mut needles);
            }
            _ => {}
        }
    }
    if rekeyed {
        needles.push(old_digest.to_owned());
    }
    needles.retain(|n| n.len() >= 4);
    needles.sort();
    needles.dedup();
    // Longest first: a leaf inside a serialized data value is removed
    // with the value it sits in.
    needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
    needles
}

/// The marker a scrubbed literal leaves behind.
const SCRUBBED: &str = "[redacted]";

/// Replaces every retained copy of this contribution's content, in one
/// transaction: the structural rewrite for the two places a body is
/// projected (ledger events, stored idempotency results) and a literal
/// sweep as the safety net over every other text column that could carry
/// a copy.
fn scrub_retention_graph(
    txn: &CommandTxn<'_>,
    contribution: &Contribution,
    redacted_parts: &[ContributionPart],
    digest_hex: &str,
    needles: &[String],
) -> Result<(), Problem> {
    let id = &contribution.contribution_id;
    let redacted_value = serde_json::to_value(redacted_parts).map_err(|_| internal())?;

    // 1. Ledger events: history is kept, the payload copy is not. The
    //    stored payload digest is recomputed over the new payload so the
    //    pair stays coherent.
    let events: Vec<(String, String, String)> = {
        let mut stmt = txn
            .conn()
            .prepare("SELECT event_id, schema_ref, payload FROM events")
            .map_err(|e| store_problem(e.into()))?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| store_problem(e.into()))?;
        mapped
            .collect::<Result<_, _>>()
            .map_err(|e| store_problem(e.into()))?
    };
    for (event_id, schema_ref, payload_text) in events {
        let Some(new_text) = rewrite_json(&payload_text, id, &redacted_value, digest_hex, needles)?
        else {
            continue;
        };
        let payload: Value = serde_json::from_str(&new_text).map_err(|_| internal())?;
        let (_, payload_digest) = kovee_core::canonical::canonical_object_digest(
            "kcp-event-payload",
            &schema_ref,
            &payload,
        )
        .map_err(|_| internal())?;
        txn.conn()
            .execute(
                "UPDATE events SET payload = ?2, payload_digest = ?3 WHERE event_id = ?1",
                params![event_id, new_text, payload_digest],
            )
            .map_err(|e| store_problem(e.into()))?;
    }

    // 2. Stored idempotency results — the §11.2 replay bytes. Erasure
    //    wins over byte-identical replay: a replay after redaction
    //    returns the redacted projection, never the erased plaintext.
    let records: Vec<(String, String, String, Vec<u8>)> = {
        let mut stmt = txn
            .conn()
            .prepare(
                "SELECT actor_scope, operation, idempotency_key, result
                 FROM idempotency_records",
            )
            .map_err(|e| store_problem(e.into()))?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map_err(|e| store_problem(e.into()))?;
        mapped
            .collect::<Result<_, _>>()
            .map_err(|e| store_problem(e.into()))?
    };
    for (actor_scope, operation, key, result) in records {
        let text = String::from_utf8_lossy(&result).into_owned();
        let Some(new_text) = rewrite_json(&text, id, &redacted_value, digest_hex, needles)? else {
            continue;
        };
        txn.conn()
            .execute(
                "UPDATE idempotency_records SET result = ?4
                 WHERE actor_scope = ?1 AND operation = ?2 AND idempotency_key = ?3",
                params![actor_scope, operation, key, new_text.as_bytes()],
            )
            .map_err(|e| store_problem(e.into()))?;
    }

    // 3. The remaining columns that can hold a copy: the DEPENDENT
    //    records that pin this object's digest — relations created before
    //    the redaction, reactions, assemblies, invocation manifests — and
    //    the body-free audit log (whose chain is re-linked after any
    //    rewrite). Where the digest moved (a pre-V5 re-key) these follow
    //    it to the keyed value; a dependent record whose own digest was
    //    derived from the erased plaintext correctly stops verifying.
    for (table, id_col, text_col) in [
        ("space_relations", "relation_id", "from_ref"),
        ("space_relations", "relation_id", "to_ref"),
        ("reactions", "reaction_id", "target_digest"),
        ("context_assemblies", "assembly_id", "record"),
        ("invocations", "invocation_id", "record"),
        ("invocation_input_manifests", "input_manifest_id", "record"),
    ] {
        sweep_literals(txn, table, id_col, text_col, needles, digest_hex)?;
    }
    sweep_audit(txn, needles, digest_hex)?;
    Ok(())
}

/// Rewrites one stored JSON document: every embedded projection of this
/// contribution gets the redacted body and current digest, then any
/// residual literal is swept. `None` when nothing changed.
fn rewrite_json(
    text: &str,
    contribution_id: &str,
    redacted_parts: &Value,
    digest_hex: &str,
    needles: &[String],
) -> Result<Option<String>, Problem> {
    let mentions = text.contains(contribution_id) || needles.iter().any(|n| text.contains(n));
    if !mentions {
        return Ok(None);
    }
    let mut value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        // Not JSON: fall back to the literal sweep alone.
        Err(_) => {
            let swept = sweep_text(text, needles, digest_hex);
            return Ok((swept != text).then_some(swept));
        }
    };
    redact_projections(&mut value, contribution_id, redacted_parts, digest_hex);
    let rendered = serde_json::to_string(&value).map_err(|_| internal())?;
    let swept = sweep_text(&rendered, needles, digest_hex);
    Ok((swept != text).then_some(swept))
}

/// Replaces `body_parts` (and any superseded `content_digest`) inside
/// every object of `value` that projects this contribution.
fn redact_projections(
    value: &mut Value,
    contribution_id: &str,
    redacted_parts: &Value,
    digest_hex: &str,
) {
    match value {
        Value::Array(items) => items
            .iter_mut()
            .for_each(|i| redact_projections(i, contribution_id, redacted_parts, digest_hex)),
        Value::Object(map) => {
            let is_this = map
                .get("contribution_id")
                .and_then(Value::as_str)
                .is_some_and(|v| v == contribution_id);
            if is_this {
                if map.contains_key("body_parts") {
                    map.insert("body_parts".to_owned(), redacted_parts.clone());
                }
                if map.contains_key("content_digest") {
                    map.insert(
                        "content_digest".to_owned(),
                        Value::String(digest_hex.to_owned()),
                    );
                }
            }
            for item in map.values_mut() {
                redact_projections(item, contribution_id, redacted_parts, digest_hex);
            }
        }
        _ => {}
    }
}

/// The literal safety net: the removed plaintext (and any superseded
/// digest, which maps to the current keyed value) leaves the text.
/// Deliberately over-inclusive — a literal that also occurs in an
/// unrelated record is scrubbed there too. Erasure that misses a copy is
/// a broken promise; erasure that removes one copy too many is not.
fn sweep_text(text: &str, needles: &[String], digest_hex: &str) -> String {
    let mut out = text.to_owned();
    for needle in needles {
        if !out.contains(needle.as_str()) {
            continue;
        }
        // A superseded 64-hex digest becomes the current one; plaintext
        // becomes the marker.
        let replacement = if needle.len() == 64
            && needle
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            digest_hex
        } else {
            SCRUBBED
        };
        out = out.replace(needle.as_str(), replacement);
    }
    out
}

fn sweep_literals(
    txn: &CommandTxn<'_>,
    table: &str,
    id_col: &str,
    text_col: &str,
    needles: &[String],
    digest_hex: &str,
) -> Result<(), Problem> {
    if needles.is_empty() {
        return Ok(());
    }
    let rows: Vec<(String, String)> = {
        let mut stmt = txn
            .conn()
            .prepare(&format!("SELECT {id_col}, {text_col} FROM {table}"))
            .map_err(|e| store_problem(e.into()))?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| store_problem(e.into()))?;
        mapped
            .collect::<Result<_, _>>()
            .map_err(|e| store_problem(e.into()))?
    };
    for (row_id, text) in rows {
        let swept = sweep_text(&text, needles, digest_hex);
        if swept == text {
            continue;
        }
        txn.conn()
            .execute(
                &format!("UPDATE {table} SET {text_col} = ?2 WHERE {id_col} = ?1"),
                params![row_id, swept],
            )
            .map_err(|e| store_problem(e.into()))?;
    }
    Ok(())
}

/// Sweeps the body-free audit log and re-links the chain when a detail
/// actually changed (the log carries digests and identifiers, so this is
/// normally a no-op — it exists so no retained copy can hide there).
fn sweep_audit(txn: &CommandTxn<'_>, needles: &[String], digest_hex: &str) -> Result<(), Problem> {
    if needles.is_empty() {
        return Ok(());
    }
    let rows: Vec<(i64, String)> = {
        let mut stmt = txn
            .conn()
            .prepare("SELECT seq, detail FROM audit ORDER BY seq ASC")
            .map_err(|e| store_problem(e.into()))?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| store_problem(e.into()))?;
        mapped
            .collect::<Result<_, _>>()
            .map_err(|e| store_problem(e.into()))?
    };
    let rewrites: Vec<(i64, String)> = rows
        .into_iter()
        .filter_map(|(seq, detail)| {
            let swept = sweep_text(&detail, needles, digest_hex);
            (swept != detail).then_some((seq, swept))
        })
        .collect();
    kovee_store::audit::rewrite_details(txn.conn(), &rewrites)
        .map_err(|e| store_problem(e.into()))?;
    Ok(())
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
