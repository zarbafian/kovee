//! Slice-2 reads: cursored lists (§11.5 opaque snapshot pagination —
//! HMAC tokens, never offsets), the two built-in lens reads (§10.4:
//! presentation only, never authority), frontier and assembly shows, and
//! the `events_wait` long-poll (§11.4).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use kovee_core::ops;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::ContextAssembly;
use kovee_store::{privacy, Store, Token};
use serde_json::Value;

use crate::handlers::{ok_reply, record_access};
use crate::state::*;

/// Long-poll ceiling: `timeout_ms` is honored up to 30 s (KG28 — the
/// design pins no ceiling; this is the installation limit).
const WAIT_MAX_MS: u64 = 30_000;
const WAIT_POLL_MS: u64 = 20;

// ------------------------------------------------------- pagination ----

/// Opens (or resumes) the §11.5 logical snapshot for one list query.
fn open_snapshot(
    store: &Store,
    source: &str,
    current_domain_seq: u64,
    current_event_seq: u64,
    snapshot_arg: &Option<String>,
) -> Result<Token, Problem> {
    match snapshot_arg {
        Some(raw) => {
            let token = store.parse_token(raw, source)?;
            if token.boundary.is_none() {
                return Err(Problem::new(
                    ProblemKind::SnapshotExpired,
                    "not a snapshot token for this query",
                ));
            }
            Ok(token)
        }
        None => Ok(Token {
            source: source.to_owned(),
            seq: current_domain_seq,
            boundary: Some(current_event_seq),
            key: None,
        }),
    }
}

/// Decodes the `after` cursor against the open snapshot; §11.5: further
/// pages must see the same logical boundary.
fn after_key(
    store: &Store,
    source: &str,
    snap: &Token,
    after: &Option<String>,
) -> Result<Option<String>, Problem> {
    match after {
        None => Ok(None),
        Some(raw) => {
            let token = store.parse_token(raw, source)?;
            if token.seq != snap.seq || token.boundary != snap.boundary {
                return Err(Problem::new(
                    ProblemKind::SnapshotExpired,
                    "cursor belongs to a different snapshot boundary",
                ));
            }
            Ok(token.key)
        }
    }
}

struct PageTokens {
    snapshot: String,
    next: Option<String>,
    boundary_event_cursor: String,
}

fn page_tokens(
    store: &Store,
    project_id: &str,
    snap: &Token,
    last_key: Option<String>,
    has_more: bool,
) -> Result<PageTokens, Problem> {
    let snapshot = store
        .mint_token(&Token {
            key: None,
            ..snap.clone()
        })
        .map_err(store_problem)?;
    let next = if has_more {
        Some(
            store
                .mint_token(&Token {
                    key: last_key,
                    ..snap.clone()
                })
                .map_err(store_problem)?,
        )
    } else {
        None
    };
    let boundary_event_cursor = store
        .mint_project_cursor(project_id, snap.boundary.unwrap_or(0))
        .map_err(store_problem)?;
    Ok(PageTokens {
        snapshot,
        next,
        boundary_event_cursor,
    })
}

fn list_reply(items: Vec<Value>, tokens: PageTokens) -> Result<Vec<u8>, Problem> {
    let mut result = serde_json::Map::new();
    result.insert("items".into(), Value::Array(items));
    if let Some(next) = tokens.next {
        result.insert("next".into(), Value::String(next));
    }
    result.insert("snapshot".into(), Value::String(tokens.snapshot));
    result.insert(
        "boundary_event_cursor".into(),
        Value::String(tokens.boundary_event_cursor),
    );
    ok_reply(Value::Object(result), None)
}

// -------------------------------------------------------- space_list ----

pub fn space_list(
    store: &Store,
    project_id: &str,
    args: &ops::SpaceListArgs,
) -> Result<Vec<u8>, Problem> {
    get_project(store.conn(), project_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let source = format!("list:spaces:{project_id}");
    let max_rowid: i64 = store
        .conn()
        .query_row(
            "SELECT COALESCE(MAX(rowid), 0) FROM spaces WHERE project_id = ?1",
            [project_id],
            |r| r.get(0),
        )
        .map_err(|e| store_problem(e.into()))?;
    let event_seq = project_head_seq(store.conn(), project_id).map_err(store_problem)?;
    let snap = open_snapshot(store, &source, max_rowid as u64, event_seq, &args.snapshot)?;
    let after = after_key(store, &source, &snap, &args.after)?;

    let mut stmt = store
        .conn()
        .prepare(
            "SELECT space_id FROM spaces
             WHERE project_id = ?1 AND rowid <= ?2
               AND (?3 IS NULL OR space_id > ?3)
             ORDER BY space_id ASC LIMIT ?4",
        )
        .map_err(|e| store_problem(e.into()))?;
    let ids: Vec<String> = stmt
        .query_map(
            rusqlite::params![project_id, snap.seq as i64, after, args.limit as i64 + 1],
            |r| r.get(0),
        )
        .map_err(|e| store_problem(e.into()))?
        .collect::<Result<_, _>>()
        .map_err(|e| store_problem(e.into()))?;
    let has_more = ids.len() as u64 > args.limit;
    let page: Vec<&String> = ids.iter().take(args.limit as usize).collect();
    let mut items = Vec::new();
    for space_id in &page {
        let space = visible_space(store.conn(), project_id, space_id)?;
        items.push(serde_json::to_value(&space).map_err(|_| internal())?);
    }
    let last_key = page.last().map(|s| (*s).clone());
    let tokens = page_tokens(store, project_id, &snap, last_key, has_more)?;
    list_reply(items, tokens)
}

// ------------------------------------------------- contribution_list ----

pub fn contribution_list(
    store: &mut Store,
    project_id: &str,
    args: &ops::ContributionListArgs,
    now: i64,
) -> Result<Vec<u8>, Problem> {
    let space = visible_space(store.conn(), project_id, &args.space_id)?;
    if let Some(branch_id) = &args.branch_id {
        visible_branch(store.conn(), &space, branch_id)?;
    }
    let source = format!("list:contributions:{}", space.space_id);
    let event_seq = project_head_seq(store.conn(), project_id).map_err(store_problem)?;
    let snap = open_snapshot(
        store,
        &source,
        space.next_space_sequence - 1,
        event_seq,
        &args.snapshot,
    )?;
    let after_seq = match after_key(store, &source, &snap, &args.after)? {
        Some(key) => key.parse::<u64>().map_err(|_| {
            Problem::new(ProblemKind::Invalid, "invalid cursor")
                .with_detail("cursor position is not a sequence")
        })?,
        None => 0,
    };
    let contributions = list_contributions(
        store.conn(),
        &space.space_id,
        args.branch_id.as_deref(),
        args.kind.as_deref(),
        after_seq,
        snap.seq,
        args.limit + 1,
    )
    .map_err(store_problem)?;
    let has_more = contributions.len() as u64 > args.limit;
    let page = &contributions[..contributions.len().min(args.limit as usize)];

    // Internal privacy chain (developer-labeled): reading sensitive
    // items commits an allowed record before release (PROFILE §7).
    let sensitive: Vec<_> = page
        .iter()
        .filter(|c| c.classification_ref == privacy::SENSITIVE_CLASSIFICATION)
        .collect();
    if !sensitive.is_empty() {
        let bytes: usize = sensitive
            .iter()
            .map(|c| {
                serde_json::to_string(&c.body_parts)
                    .map(|s| s.len())
                    .unwrap_or(0)
            })
            .sum();
        record_access(
            store,
            "contribution_list",
            serde_json::json!({"space_id": space.space_id, "kind": args.kind}),
            sensitive.len() as u64,
            bytes as u64,
            true,
            now,
        )?;
    }

    let mut items = Vec::new();
    for c in page {
        items.push(serde_json::to_value(c).map_err(|_| internal())?);
    }
    let last_key = page.last().map(|c| c.space_sequence.to_string());
    let tokens = page_tokens(store, project_id, &snap, last_key, has_more)?;
    list_reply(items, tokens)
}

// ---------------------------------------------------------- lens_read ----

/// The two built-in presentation lenses (§10.4): Stream renders visible
/// contributions chronologically; Workbench renders typed cards (every
/// non-utterance kind) with their asserted relations attached. Items are
/// projections — they confer no visibility, authority, or invocation.
pub fn lens_read(
    store: &mut Store,
    project_id: &str,
    args: &ops::LensReadArgs,
    now: i64,
) -> Result<Vec<u8>, Problem> {
    let lens = get_lens(store.conn(), &args.lens_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let space = visible_space(store.conn(), project_id, &lens.space_id)?;
    let source = format!("list:lens:{}", lens.lens_id);
    let event_seq = project_head_seq(store.conn(), project_id).map_err(store_problem)?;
    let snap = open_snapshot(
        store,
        &source,
        space.next_space_sequence - 1,
        event_seq,
        &args.snapshot,
    )?;
    let after_seq = match after_key(store, &source, &snap, &args.after)? {
        Some(key) => key.parse::<u64>().map_err(|_| {
            Problem::new(ProblemKind::Invalid, "invalid cursor")
                .with_detail("cursor position is not a sequence")
        })?,
        None => 0,
    };
    let contributions = list_contributions(
        store.conn(),
        &space.space_id,
        None,
        None,
        after_seq,
        snap.seq,
        args.limit + 1,
    )
    .map_err(store_problem)?;
    let (page, has_more) = match lens.kind.as_str() {
        "stream" => {
            let has_more = contributions.len() as u64 > args.limit;
            (
                contributions[..contributions.len().min(args.limit as usize)].to_vec(),
                has_more,
            )
        }
        "workbench" => {
            // Typed cards: every kind except plain utterances.
            let cards: Vec<_> = contributions
                .iter()
                .filter(|c| c.kind != "utterance")
                .cloned()
                .collect();
            let has_more = contributions.len() as u64 > args.limit;
            (
                cards
                    .into_iter()
                    .take(args.limit as usize)
                    .collect::<Vec<_>>(),
                has_more,
            )
        }
        _ => return Err(not_found()),
    };

    let sensitive: Vec<_> = page
        .iter()
        .filter(|c| c.classification_ref == privacy::SENSITIVE_CLASSIFICATION)
        .collect();
    if !sensitive.is_empty() {
        let bytes: usize = sensitive
            .iter()
            .map(|c| {
                serde_json::to_string(&c.body_parts)
                    .map(|s| s.len())
                    .unwrap_or(0)
            })
            .sum();
        let count = sensitive.len() as u64;
        record_access(
            store,
            "lens_read",
            serde_json::json!({"lens_id": lens.lens_id}),
            count,
            bytes as u64,
            true,
            now,
        )?;
    }

    let relations = if lens.kind == "workbench" {
        relations_touching(store.conn(), &space.space_id).map_err(store_problem)?
    } else {
        Vec::new()
    };
    let mut items = Vec::new();
    for c in &page {
        let projection = serde_json::to_value(c).map_err(|_| internal())?;
        let item = if lens.kind == "stream" {
            serde_json::json!({
                "item_kind": "contribution",
                "branch_sequence": c.origin_branch_sequence,
                "contribution": projection,
            })
        } else {
            let outgoing: Vec<&kovee_core::records::SpaceRelation> = relations
                .iter()
                .filter(|r| r.from_ref.object_ref == c.contribution_id)
                .collect();
            let incoming: Vec<&kovee_core::records::SpaceRelation> = relations
                .iter()
                .filter(|r| r.to_ref.object_ref == c.contribution_id)
                .collect();
            serde_json::json!({
                "item_kind": "card",
                "card_kind": c.kind,
                "branch_sequence": c.origin_branch_sequence,
                "contribution": projection,
                "relations_out": outgoing,
                "relations_in": incoming,
            })
        };
        items.push(item);
    }
    let last_key = page.last().map(|c| c.space_sequence.to_string());
    let tokens = page_tokens(store, project_id, &snap, last_key, has_more)?;
    list_reply(items, tokens)
}

// ------------------------------------------------------ frontier_show ----

pub fn frontier_show(
    store: &Store,
    project_id: &str,
    args: &ops::FrontierShowArgs,
) -> Result<Vec<u8>, Problem> {
    let frontier = get_frontier(store.conn(), &args.frontier_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    // Visibility through the owning space's project.
    visible_space(store.conn(), project_id, &frontier.space_id)?;
    ok_reply(
        serde_json::to_value(&frontier).map_err(|_| internal())?,
        Some(1),
    )
}

// ----------------------------------------------- context_assembly_show ----

pub fn context_assembly_show(
    store: &Store,
    project_id: &str,
    args: &ops::ContextAssemblyShowArgs,
) -> Result<Vec<u8>, Problem> {
    let (owner_project, record) = get_assembly_record(store.conn(), &args.assembly_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    if owner_project != project_id {
        return Err(not_found());
    }
    let assembly: ContextAssembly =
        serde_json::from_value(record.clone()).map_err(|_| internal())?;
    // §10.8: materialization never drops or substitutes an included
    // item — a stale or missing included item makes the whole assembly
    // unavailable rather than serving a silently different selection.
    for item in &assembly.items {
        let object = resolve_space_object(store.conn(), &assembly.space_id, &item.object_ref)
            .map_err(|_| {
                Problem::new(
                    ProblemKind::Unavailable,
                    "assembly is no longer materializable",
                )
                .with_detail("an included item is no longer visible")
            })?;
        if object.digest() != item.digest {
            return Err(Problem::new(
                ProblemKind::Unavailable,
                "assembly is no longer materializable",
            )
            .with_detail("an included item changed under its pinned digest"));
        }
    }
    ok_reply(record, Some(1))
}

// -------------------------------------------------------- events_wait ----

/// §11.4 long-poll: returns as soon as events exist after the cursor,
/// else waits up to the (capped) timeout. The store lock is released
/// between polls so mutations proceed while a waiter sleeps.
pub fn events_wait(
    store: &Mutex<Store>,
    envelope_project_id: Option<&str>,
    args: &ops::EventsWaitArgs,
) -> Result<Vec<u8>, Problem> {
    let prefixes = args.type_prefixes()?;
    let deadline = Instant::now() + Duration::from_millis(args.timeout_ms.min(WAIT_MAX_MS));
    loop {
        let reply = {
            let store = store.lock().map_err(|_| internal())?;
            let project = get_project(store.conn(), &args.source)
                .map_err(store_problem)?
                .ok_or_else(not_found)?;
            if let Some(narrowing) = envelope_project_id {
                if narrowing != project.project_id {
                    return Err(not_found());
                }
            }
            let after_seq = store.parse_project_cursor(&args.after_cursor, &project.project_id)?;
            let events = store
                .list_project_events(
                    &project.project_id,
                    after_seq,
                    prefixes.as_deref(),
                    kovee_core::limits::PAGE_MAX_LIMIT,
                )
                .map_err(store_problem)?;
            if events.is_empty() && Instant::now() < deadline {
                None
            } else {
                let last_seq = events
                    .iter()
                    .filter_map(|e| e.project_sequence)
                    .max()
                    .unwrap_or(after_seq);
                let next_cursor = store
                    .mint_project_cursor(&project.project_id, last_seq)
                    .map_err(store_problem)?;
                Some(ok_reply(
                    serde_json::json!({"events": events, "next_cursor": next_cursor}),
                    None,
                ))
            }
        };
        match reply {
            Some(result) => return result,
            None => std::thread::sleep(Duration::from_millis(WAIT_POLL_MS)),
        }
    }
}
