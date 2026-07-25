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
pub(crate) fn open_snapshot(
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
pub(crate) fn after_key(
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

pub(crate) struct PageTokens {
    snapshot: String,
    next: Option<String>,
    boundary_event_cursor: String,
}

/// Mints the §11.5 page tokens. `boundary_project` names the project
/// whose event stream bounds the snapshot; `None` for realm-level lists
/// (the boundary cursor then binds the realm's own source and no reader
/// consumes it in K1).
pub(crate) fn page_tokens(
    store: &Store,
    boundary_project: Option<&str>,
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
    let boundary_event_cursor = match boundary_project {
        Some(project_id) => store
            .mint_project_cursor(project_id, snap.boundary.unwrap_or(0))
            .map_err(store_problem)?,
        None => store
            .mint_token(&Token {
                source: "events:realm".to_owned(),
                seq: snap.boundary.unwrap_or(0),
                boundary: None,
                key: None,
            })
            .map_err(store_problem)?,
    };
    Ok(PageTokens {
        snapshot,
        next,
        boundary_event_cursor,
    })
}

pub(crate) fn list_reply(items: Vec<Value>, tokens: PageTokens) -> Result<Vec<u8>, Problem> {
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
    let tokens = page_tokens(store, Some(project_id), &snap, last_key, has_more)?;
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
    let tokens = page_tokens(store, Some(project_id), &snap, last_key, has_more)?;
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
        // Every other kind serves the chronological projection: the AST
        // grammar is unpinned in K1 (KG25) and a lens is presentation
        // config only — never a second content model (§10.4).
        _ => {
            let has_more = contributions.len() as u64 > args.limit;
            (
                contributions[..contributions.len().min(args.limit as usize)].to_vec(),
                has_more,
            )
        }
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
        let item = if lens.kind != "workbench" {
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
    let tokens = page_tokens(store, Some(project_id), &snap, last_key, has_more)?;
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

// ================================================== slice-3 keyed lists ----

/// One §11.5 keyed list query: token source, snapshot boundary (max
/// rowid of the filtered table + the bounding event sequence), and the
/// project whose stream mints the boundary cursor (`None` = realm-level).
pub(crate) struct KeyedQuery<'a> {
    pub source: String,
    pub boundary_project: Option<&'a str>,
    pub max_rowid: i64,
    pub event_seq: u64,
}

/// Runs a keyed list: `fetch(conn, boundary_rowid, after_key, fetch_n)`
/// returns at most `fetch_n` `(key, item)` pairs in ascending key order,
/// restricted to rows with `rowid <= boundary_rowid` and `key > after`.
pub(crate) fn keyed_list<F>(
    store: &Store,
    query: KeyedQuery<'_>,
    after_arg: &Option<String>,
    snapshot_arg: &Option<String>,
    limit: u64,
    fetch: F,
) -> Result<Vec<u8>, Problem>
where
    F: Fn(&rusqlite::Connection, i64, Option<&str>, i64) -> Result<Vec<(String, Value)>, Problem>,
{
    let snap = open_snapshot(
        store,
        &query.source,
        query.max_rowid as u64,
        query.event_seq,
        snapshot_arg,
    )?;
    let after = after_key(store, &query.source, &snap, after_arg)?;
    let rows = fetch(
        store.conn(),
        snap.seq as i64,
        after.as_deref(),
        limit as i64 + 1,
    )?;
    let has_more = rows.len() as u64 > limit;
    let page = &rows[..rows.len().min(limit as usize)];
    let items: Vec<Value> = page.iter().map(|(_, item)| item.clone()).collect();
    let last_key = page.last().map(|(key, _)| key.clone());
    let tokens = page_tokens(store, query.boundary_project, &snap, last_key, has_more)?;
    list_reply(items, tokens)
}

pub(crate) fn max_rowid(conn: &rusqlite::Connection, table: &str) -> Result<i64, Problem> {
    conn.query_row(
        &format!("SELECT COALESCE(MAX(rowid), 0) FROM {table}"),
        [],
        |r| r.get(0),
    )
    .map_err(|e| store_problem(e.into()))
}

// -------------------------------------------------------- project_list ----

pub fn project_list(store: &Store, args: &ops::PageArgs) -> Result<Vec<u8>, Problem> {
    let query = KeyedQuery {
        source: "list:projects".to_owned(),
        boundary_project: None,
        max_rowid: max_rowid(store.conn(), "projects")?,
        event_seq: 0,
    };
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT project_id FROM projects
                 WHERE rowid <= ?1 AND (?2 IS NULL OR project_id > ?2)
                 ORDER BY project_id ASC LIMIT ?3",
                )
                .map_err(|e| store_problem(e.into()))?;
            let ids: Vec<String> = stmt
                .query_map(rusqlite::params![bound, after, n], |r| r.get(0))
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            let mut rows = Vec::new();
            for id in ids {
                let project = get_project(conn, &id)
                    .map_err(store_problem)?
                    .ok_or_else(internal)?;
                rows.push((id, serde_json::to_value(&project).map_err(|_| internal())?));
            }
            Ok(rows)
        },
    )
}

// -------------------------------------------------------- project_show ----

pub fn project_show(store: &Store, project_id: &str) -> Result<Vec<u8>, Problem> {
    let project = get_project(store.conn(), project_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let revision = project.revision;
    ok_reply(
        serde_json::to_value(&project).map_err(|_| internal())?,
        Some(revision),
    )
}

// ------------------------------------- prepared-change and admin lists ----

pub fn papc_list(
    store: &Store,
    project_id: &str,
    args: &ops::PageArgs,
) -> Result<Vec<u8>, Problem> {
    get_project(store.conn(), project_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let event_seq = project_head_seq(store.conn(), project_id).map_err(store_problem)?;
    let query = KeyedQuery {
        source: format!("list:papc:{project_id}"),
        boundary_project: Some(project_id),
        max_rowid: max_rowid(store.conn(), "project_policy_changes")?,
        event_seq,
    };
    let project_id = project_id.to_owned();
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        move |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT change_id, record FROM project_policy_changes
                 WHERE project_id = ?1 AND rowid <= ?2
                   AND (?3 IS NULL OR change_id > ?3)
                 ORDER BY change_id ASC LIMIT ?4",
                )
                .map_err(|e| store_problem(e.into()))?;
            let rows: Vec<(String, String)> = stmt
                .query_map(rusqlite::params![project_id, bound, after, n], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            rows.into_iter()
                .map(|(key, record)| {
                    Ok((key, serde_json::from_str(&record).map_err(|_| internal())?))
                })
                .collect()
        },
    )
}

pub fn widen_list(
    store: &Store,
    project_id: &str,
    args: &ops::WidenListArgs,
) -> Result<Vec<u8>, Problem> {
    get_project(store.conn(), project_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    if let Some(space_id) = &args.space_id {
        visible_space(store.conn(), project_id, space_id)?;
    }
    let event_seq = project_head_seq(store.conn(), project_id).map_err(store_problem)?;
    let query = KeyedQuery {
        source: format!("list:widenings:{project_id}"),
        boundary_project: Some(project_id),
        max_rowid: max_rowid(store.conn(), "space_access_widenings")?,
        event_seq,
    };
    let project_id = project_id.to_owned();
    let space_filter = args.space_id.clone();
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        move |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT w.widening_id, w.record FROM space_access_widenings w
                 JOIN spaces s ON s.space_id = w.space_id
                 WHERE s.project_id = ?1 AND w.rowid <= ?2
                   AND (?3 IS NULL OR w.widening_id > ?3)
                   AND (?4 IS NULL OR w.space_id = ?4)
                 ORDER BY w.widening_id ASC LIMIT ?5",
                )
                .map_err(|e| store_problem(e.into()))?;
            let rows: Vec<(String, String)> = stmt
                .query_map(
                    rusqlite::params![project_id, bound, after, space_filter, n],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            rows.into_iter()
                .map(|(key, record)| {
                    Ok((key, serde_json::from_str(&record).map_err(|_| internal())?))
                })
                .collect()
        },
    )
}

pub fn participant_list(
    store: &Store,
    project_id: &str,
    args: &ops::SpacePageArgs,
) -> Result<Vec<u8>, Problem> {
    let space = visible_space(store.conn(), project_id, &args.space_id)?;
    let event_seq = project_head_seq(store.conn(), project_id).map_err(store_problem)?;
    let query = KeyedQuery {
        source: format!("list:participants:{}", space.space_id),
        boundary_project: Some(project_id),
        max_rowid: max_rowid(store.conn(), "space_participants")?,
        event_seq,
    };
    let space_id = space.space_id.clone();
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        move |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT participant_id FROM space_participants
                 WHERE space_id = ?1 AND rowid <= ?2
                   AND (?3 IS NULL OR participant_id > ?3)
                 ORDER BY participant_id ASC LIMIT ?4",
                )
                .map_err(|e| store_problem(e.into()))?;
            let ids: Vec<String> = stmt
                .query_map(rusqlite::params![space_id, bound, after, n], |r| r.get(0))
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            let mut rows = Vec::new();
            for id in ids {
                let (participant, _) = get_participant(conn, &id)
                    .map_err(store_problem)?
                    .ok_or_else(internal)?;
                rows.push((
                    id,
                    serde_json::to_value(&participant).map_err(|_| internal())?,
                ));
            }
            Ok(rows)
        },
    )
}

pub fn grant_list(
    store: &Store,
    project_id: &str,
    args: &ops::SpacePageArgs,
) -> Result<Vec<u8>, Problem> {
    let space = visible_space(store.conn(), project_id, &args.space_id)?;
    let event_seq = project_head_seq(store.conn(), project_id).map_err(store_problem)?;
    let query = KeyedQuery {
        source: format!("list:grants:{}", space.space_id),
        boundary_project: Some(project_id),
        max_rowid: max_rowid(store.conn(), "space_access_grants")?,
        event_seq,
    };
    let space_id = space.space_id.clone();
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        move |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT space_access_id, space_id, subject_ref, revision,
                        source_membership_or_policy_ref, allowed_actions,
                        classification_ceiling_ref, authorization_epoch,
                        expires_at, status, granted_by_or_policy_use_ref,
                        created_at
                 FROM space_access_grants
                 WHERE space_id = ?1 AND rowid <= ?2
                   AND (?3 IS NULL OR space_access_id > ?3)
                 ORDER BY space_access_id ASC LIMIT ?4",
                )
                .map_err(|e| store_problem(e.into()))?;
            let tuples = stmt
                .query_map(
                    rusqlite::params![space_id, bound, after, n],
                    row_to_grant_tuple,
                )
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| store_problem(e.into()))?;
            let mut rows = Vec::new();
            for tuple in tuples {
                let grant = tuple_to_grant(tuple).map_err(store_problem)?;
                rows.push((
                    grant.space_access_id.clone(),
                    serde_json::to_value(&grant).map_err(|_| internal())?,
                ));
            }
            Ok(rows)
        },
    )
}

pub fn lens_list(
    store: &Store,
    project_id: &str,
    args: &ops::SpacePageArgs,
) -> Result<Vec<u8>, Problem> {
    let space = visible_space(store.conn(), project_id, &args.space_id)?;
    let event_seq = project_head_seq(store.conn(), project_id).map_err(store_problem)?;
    let query = KeyedQuery {
        source: format!("list:lenses:{}", space.space_id),
        boundary_project: Some(project_id),
        max_rowid: max_rowid(store.conn(), "space_lenses")?,
        event_seq,
    };
    let space_id = space.space_id.clone();
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        move |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT lens_id FROM space_lenses
                 WHERE space_id = ?1 AND status != 'revoked' AND rowid <= ?2
                   AND (?3 IS NULL OR lens_id > ?3)
                 ORDER BY lens_id ASC LIMIT ?4",
                )
                .map_err(|e| store_problem(e.into()))?;
            let ids: Vec<String> = stmt
                .query_map(rusqlite::params![space_id, bound, after, n], |r| r.get(0))
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            let mut rows = Vec::new();
            for id in ids {
                let lens = get_lens_full(conn, &id)
                    .map_err(store_problem)?
                    .ok_or_else(internal)?;
                rows.push((id, serde_json::to_value(&lens).map_err(|_| internal())?));
            }
            Ok(rows)
        },
    )
}

// ----------------------------------------------------- assistant reads ----

pub fn assistant_list(store: &Store, args: &ops::PageArgs) -> Result<Vec<u8>, Problem> {
    let query = KeyedQuery {
        source: "list:assistants".to_owned(),
        boundary_project: None,
        max_rowid: max_rowid(store.conn(), "assistant_definitions")?,
        event_seq: 0,
    };
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT definition_id FROM assistant_definitions
                 WHERE rowid <= ?1 AND (?2 IS NULL OR definition_id > ?2)
                 ORDER BY definition_id ASC LIMIT ?3",
                )
                .map_err(|e| store_problem(e.into()))?;
            let ids: Vec<String> = stmt
                .query_map(rusqlite::params![bound, after, n], |r| r.get(0))
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            let mut rows = Vec::new();
            for id in ids {
                let definition = get_assistant_definition(conn, &id)
                    .map_err(store_problem)?
                    .ok_or_else(internal)?;
                rows.push((
                    id,
                    serde_json::to_value(&definition).map_err(|_| internal())?,
                ));
            }
            Ok(rows)
        },
    )
}

pub fn assistant_revision_list(
    store: &Store,
    args: &ops::AssistantRevisionListArgs,
) -> Result<Vec<u8>, Problem> {
    let query = KeyedQuery {
        source: "list:assistant-revisions".to_owned(),
        boundary_project: None,
        max_rowid: max_rowid(store.conn(), "assistant_revisions")?,
        event_seq: 0,
    };
    let filter = args.definition_id.clone();
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        move |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT assistant_revision_id, record FROM assistant_revisions
                 WHERE rowid <= ?1 AND (?2 IS NULL OR assistant_revision_id > ?2)
                   AND (?3 IS NULL OR definition_id = ?3)
                 ORDER BY assistant_revision_id ASC LIMIT ?4",
                )
                .map_err(|e| store_problem(e.into()))?;
            let rows: Vec<(String, String)> = stmt
                .query_map(rusqlite::params![bound, after, filter, n], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            rows.into_iter()
                .map(|(key, record)| {
                    Ok((key, serde_json::from_str(&record).map_err(|_| internal())?))
                })
                .collect()
        },
    )
}

pub fn deployment_list(store: &Store, args: &ops::DeploymentListArgs) -> Result<Vec<u8>, Problem> {
    let query = KeyedQuery {
        source: "list:deployments".to_owned(),
        boundary_project: None,
        max_rowid: max_rowid(store.conn(), "assistant_deployments")?,
        event_seq: 0,
    };
    let filter = args.assistant_revision_id.clone();
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        move |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT deployment_id, record FROM assistant_deployments
                 WHERE rowid <= ?1 AND (?2 IS NULL OR deployment_id > ?2)
                   AND (?3 IS NULL OR assistant_revision_id = ?3)
                 ORDER BY deployment_id ASC LIMIT ?4",
                )
                .map_err(|e| store_problem(e.into()))?;
            let rows: Vec<(String, Option<String>)> = stmt
                .query_map(rusqlite::params![bound, after, filter, n], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            rows.into_iter()
                .map(|(key, record)| {
                    let record = record.ok_or_else(internal)?;
                    Ok((key, serde_json::from_str(&record).map_err(|_| internal())?))
                })
                .collect()
        },
    )
}

pub fn alias_list(
    store: &Store,
    project_id: &str,
    args: &ops::AliasListArgs,
) -> Result<Vec<u8>, Problem> {
    get_project(store.conn(), project_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let event_seq = project_head_seq(store.conn(), project_id).map_err(store_problem)?;
    let query = KeyedQuery {
        source: format!("list:aliases:{project_id}"),
        boundary_project: Some(project_id),
        max_rowid: max_rowid(store.conn(), "assistant_aliases")?,
        event_seq,
    };
    let project_id = project_id.to_owned();
    let filter = args.assistant_deployment_id.clone();
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        move |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT alias_binding_id FROM assistant_aliases
                 WHERE project_id = ?1 AND rowid <= ?2
                   AND (?3 IS NULL OR alias_binding_id > ?3)
                   AND (?4 IS NULL OR assistant_deployment_id = ?4)
                 ORDER BY alias_binding_id ASC LIMIT ?5",
                )
                .map_err(|e| store_problem(e.into()))?;
            let ids: Vec<String> = stmt
                .query_map(
                    rusqlite::params![project_id, bound, after, filter, n],
                    |r| r.get(0),
                )
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            let mut rows = Vec::new();
            for id in ids {
                let alias = get_alias(conn, &id)
                    .map_err(store_problem)?
                    .ok_or_else(internal)?;
                rows.push((id, serde_json::to_value(&alias).map_err(|_| internal())?));
            }
            Ok(rows)
        },
    )
}

pub fn invocation_list(
    store: &Store,
    project_id: &str,
    args: &ops::InvocationListArgs,
) -> Result<Vec<u8>, Problem> {
    get_project(store.conn(), project_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    if let Some(space_id) = &args.space_id {
        visible_space(store.conn(), project_id, space_id)?;
    }
    let event_seq = project_head_seq(store.conn(), project_id).map_err(store_problem)?;
    let query = KeyedQuery {
        source: format!("list:invocations:{project_id}"),
        boundary_project: Some(project_id),
        max_rowid: max_rowid(store.conn(), "invocations")?,
        event_seq,
    };
    let project_id = project_id.to_owned();
    let space_filter = args.space_id.clone();
    let state_filter = args.state.clone();
    let deployment_filter = args.assistant_deployment_id.clone();
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        move |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT invocation_id, record FROM invocations
                 WHERE project_id = ?1 AND rowid <= ?2
                   AND (?3 IS NULL OR invocation_id > ?3)
                   AND (?4 IS NULL OR space_id = ?4)
                   AND (?5 IS NULL OR state = ?5)
                 ORDER BY invocation_id ASC LIMIT ?6",
                )
                .map_err(|e| store_problem(e.into()))?;
            let rows: Vec<(String, String)> = stmt
                .query_map(
                    rusqlite::params![project_id, bound, after, space_filter, state_filter, n],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            let mut out = Vec::new();
            for (key, record) in rows {
                let record: Value = serde_json::from_str(&record).map_err(|_| internal())?;
                if let Some(deployment) = &deployment_filter {
                    if record["assistant_deployment_id"].as_str() != Some(deployment.as_str()) {
                        continue;
                    }
                }
                out.push((key, record));
            }
            Ok(out)
        },
    )
}

// ------------------------------------------------------- snapshot_read ----

/// §11.5 `snapshot_read` (KG28): `source` names the registered resource
/// collection. K1 registers exactly one snapshot collection per project —
/// its space set — mirroring `events_read.source` (the project id).
pub fn snapshot_read(
    store: &Store,
    envelope_project_id: Option<&str>,
    args: &ops::SnapshotReadArgs,
) -> Result<Vec<u8>, Problem> {
    let project = get_project(store.conn(), &args.source)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    if let Some(narrowing) = envelope_project_id {
        if narrowing != project.project_id {
            return Err(not_found());
        }
    }
    let event_seq = project_head_seq(store.conn(), &project.project_id).map_err(store_problem)?;
    let query = KeyedQuery {
        source: format!("snap:spaces:{}", project.project_id),
        boundary_project: Some(&project.project_id),
        max_rowid: max_rowid(store.conn(), "spaces")?,
        event_seq,
    };
    let project_id = project.project_id.clone();
    keyed_list(
        store,
        query,
        &args.after,
        &args.snapshot,
        args.limit,
        move |conn, bound, after, n| {
            let mut stmt = conn
                .prepare(
                    "SELECT space_id FROM spaces
                 WHERE project_id = ?1 AND rowid <= ?2
                   AND (?3 IS NULL OR space_id > ?3)
                 ORDER BY space_id ASC LIMIT ?4",
                )
                .map_err(|e| store_problem(e.into()))?;
            let ids: Vec<String> = stmt
                .query_map(rusqlite::params![project_id, bound, after, n], |r| r.get(0))
                .map_err(|e| store_problem(e.into()))?
                .collect::<Result<_, _>>()
                .map_err(|e| store_problem(e.into()))?;
            let mut rows = Vec::new();
            for id in ids {
                let space = get_space(conn, &id)
                    .map_err(store_problem)?
                    .ok_or_else(internal)?;
                rows.push((id, serde_json::to_value(&space).map_err(|_| internal())?));
            }
            Ok(rows)
        },
    )
}

// ------------------------------------------------------- event_payload ----

/// `event_payload` (§11.3/§11.4): the stored payload members of one
/// event. Sensitive payloads chain a PrivacyAccessRecord before release
/// (PROFILE §7).
pub fn event_payload(
    store: &mut Store,
    envelope_project_id: Option<&str>,
    args: &ops::EventPayloadArgs,
    now: i64,
) -> Result<Vec<u8>, Problem> {
    use rusqlite::OptionalExtension as _;
    let row: Option<(Option<String>, String, String, String, String)> = store
        .conn()
        .query_row(
            "SELECT project_id, schema_ref, payload_digest, payload,
                    classification_ref
             FROM events WHERE event_id = ?1",
            [&args.event_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    let Some((event_project, schema_ref, payload_digest, payload_text, classification)) = row
    else {
        return Err(not_found());
    };
    if let Some(narrowing) = envelope_project_id {
        if event_project.as_deref() != Some(narrowing) {
            return Err(not_found());
        }
    }
    let payload: Value = serde_json::from_str(&payload_text).map_err(|_| internal())?;
    if classification == privacy::SENSITIVE_CLASSIFICATION {
        record_access(
            store,
            "event_payload",
            serde_json::json!({"event_id": args.event_id}),
            1,
            payload_text.len() as u64,
            true,
            now,
        )?;
    }
    ok_reply(
        serde_json::json!({
            "event_id": args.event_id,
            "schema_ref": schema_ref,
            "payload_digest": payload_digest,
            "payload": payload,
        }),
        None,
    )
}

// -------------------------------------------- disclosure_manifest_show ----

/// §16.2 read surface. No K1 operation writes a DisclosureManifest
/// (creation arrives with secure effects, K4), so every lookup against
/// the empty collection is the uniform not-found — the operation itself
/// is fully dispatched and shaped.
pub fn disclosure_manifest_show(
    store: &Store,
    args: &ops::DisclosureManifestShowArgs,
) -> Result<Vec<u8>, Problem> {
    use rusqlite::OptionalExtension as _;
    let record: Option<String> = store
        .conn()
        .query_row(
            "SELECT record FROM disclosure_manifests WHERE disclosure_id = ?1",
            [&args.disclosure_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    match record {
        Some(text) => {
            let value: Value = serde_json::from_str(&text).map_err(|_| internal())?;
            ok_reply(value, Some(1))
        }
        None => Err(not_found()),
    }
}
