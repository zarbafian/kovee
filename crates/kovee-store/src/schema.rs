//! Schema DDL, `user_version` migrations, and the `meta` key/value
//! helpers — the akson pattern (numbered steps, DDL and version bump in
//! one transaction), plain SQLite WAL for the kovee personal profile
//! (design §8: no envelope encryption; the database is same-UID data).

use rusqlite::Connection;

/// Version 1: the K1 slice-1 core tables (design §12.1 subset).
///
/// Naming follows DESIGN.md §12.1 with two recorded deviations:
/// - `idempotency_records` (the milestone's name for §12.1
///   `idempotency_results`) — same row meaning, keyed
///   `(actor_scope, operation, idempotency_key)`;
/// - the main-branch head lives on `spaces`
///   (`main_branch_head_digest`, `next_branch_sequence`): slice 1 has
///   exactly one branch per space, so the `reasoning_branches` /
///   `branch_entries` tables arrive with the K2 branch operations and the
///   §10.3 CAS discipline is enforced on the space row until then.
const V1: &str = r#"
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE audit (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    event     TEXT NOT NULL,
    detail    TEXT NOT NULL,
    prev_hash BLOB NOT NULL,
    hash      BLOB NOT NULL
) STRICT;

CREATE TABLE realms (
    realm_id             TEXT PRIMARY KEY,
    installation_id      TEXT NOT NULL,
    revision             INTEGER NOT NULL,
    name                 TEXT NOT NULL,
    status               TEXT NOT NULL,
    home_region          TEXT NOT NULL,
    auth_policy_ref      TEXT NOT NULL,
    retention_policy_ref TEXT NOT NULL,
    encryption_key_ref   TEXT NOT NULL,
    created_at           TEXT NOT NULL
) STRICT;

CREATE TABLE projects (
    project_id                 TEXT PRIMARY KEY,
    realm_id                   TEXT NOT NULL REFERENCES realms(realm_id),
    revision                   INTEGER NOT NULL,
    name                       TEXT NOT NULL,
    status                     TEXT NOT NULL,
    default_classification_ref TEXT NOT NULL,
    policy_set_ref             TEXT NOT NULL,
    created_by                 TEXT NOT NULL,
    created_at                 TEXT NOT NULL,
    -- §11.3: the reference SQL implementation serializes project-sequence
    -- assignment under the project head row; this is that head.
    next_project_sequence      INTEGER NOT NULL
) STRICT;

CREATE TABLE spaces (
    space_id                   TEXT PRIMARY KEY,
    realm_id                   TEXT NOT NULL REFERENCES realms(realm_id),
    project_id                 TEXT NOT NULL REFERENCES projects(project_id),
    revision                   INTEGER NOT NULL,
    title                      TEXT NOT NULL,
    purpose_contribution_ref   TEXT,
    visibility                 TEXT NOT NULL,
    status                     TEXT NOT NULL,
    main_branch_id             TEXT NOT NULL,
    next_space_sequence        INTEGER NOT NULL,
    main_branch_head_digest    TEXT NOT NULL,
    next_branch_sequence       INTEGER NOT NULL,
    default_classification_ref TEXT NOT NULL,
    policy_set_ref             TEXT NOT NULL,
    created_by                 TEXT NOT NULL,
    created_at                 TEXT NOT NULL
) STRICT;

CREATE TABLE space_participants (
    participant_id       TEXT PRIMARY KEY,
    space_id             TEXT NOT NULL REFERENCES spaces(space_id),
    subject_ref          TEXT NOT NULL,
    subject_revision     INTEGER,
    kind                 TEXT NOT NULL,
    role                 TEXT NOT NULL,
    authority_source_ref TEXT NOT NULL,
    status               TEXT NOT NULL,
    revision             INTEGER NOT NULL,
    UNIQUE(space_id, subject_ref)
) STRICT;

CREATE TABLE contributions (
    contribution_id        TEXT PRIMARY KEY,
    revision               INTEGER NOT NULL,
    realm_id               TEXT NOT NULL,
    project_id             TEXT NOT NULL REFERENCES projects(project_id),
    space_id               TEXT NOT NULL REFERENCES spaces(space_id),
    origin_branch_id       TEXT NOT NULL,
    origin_branch_sequence INTEGER NOT NULL,
    space_sequence         INTEGER NOT NULL,
    author_actor_ref       TEXT NOT NULL,
    kind                   TEXT NOT NULL,
    schema_ref             TEXT NOT NULL,
    body_parts             TEXT NOT NULL,
    subject_refs           TEXT NOT NULL,
    source_refs            TEXT NOT NULL,
    epistemic_posture      TEXT,
    invocation_ref         TEXT,
    context_assembly_ref   TEXT,
    causation_ref          TEXT,
    classification_ref     TEXT NOT NULL,
    retention_policy_ref   TEXT NOT NULL,
    content_digest         TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    UNIQUE(space_id, space_sequence),
    UNIQUE(origin_branch_id, origin_branch_sequence)
) STRICT;

CREATE TABLE space_relations (
    relation_id        TEXT PRIMARY KEY,
    revision           INTEGER NOT NULL,
    space_id           TEXT NOT NULL REFERENCES spaces(space_id),
    origin_branch_id   TEXT NOT NULL,
    branch_sequence    INTEGER NOT NULL,
    author_actor_ref   TEXT NOT NULL,
    kind               TEXT NOT NULL,
    from_ref           TEXT NOT NULL,
    to_ref             TEXT NOT NULL,
    rationale_ref      TEXT,
    relation_class     TEXT NOT NULL,
    classification_ref TEXT NOT NULL,
    schema_ref         TEXT NOT NULL,
    digest             TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    UNIQUE(origin_branch_id, branch_sequence)
) STRICT;

CREATE TABLE events (
    event_id           TEXT PRIMARY KEY,
    installation_id    TEXT NOT NULL,
    realm_id           TEXT NOT NULL,
    project_id         TEXT,
    stream_id          TEXT NOT NULL,
    stream_sequence    INTEGER NOT NULL,
    project_sequence   INTEGER,
    type               TEXT NOT NULL,
    schema_ref         TEXT NOT NULL,
    resource_ref       TEXT NOT NULL,
    resource_revision  INTEGER,
    actor_ref          TEXT NOT NULL,
    causation_ref      TEXT,
    correlation_ref    TEXT NOT NULL,
    occurred_at        TEXT NOT NULL,
    classification_ref TEXT NOT NULL,
    payload_digest     TEXT NOT NULL,
    payload            TEXT NOT NULL,
    UNIQUE(stream_id, stream_sequence),
    UNIQUE(project_id, project_sequence)
) STRICT;

CREATE TABLE stream_heads (
    stream_id     TEXT PRIMARY KEY,
    next_sequence INTEGER NOT NULL
) STRICT;

CREATE TABLE idempotency_records (
    actor_scope     TEXT NOT NULL,
    operation       TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest  TEXT NOT NULL,
    result          BLOB NOT NULL,
    revision        INTEGER,
    event_cursor    TEXT,
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (actor_scope, operation, idempotency_key)
) STRICT;

CREATE TABLE outbox (
    outbox_seq   INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id  TEXT NOT NULL UNIQUE,
    kind         TEXT NOT NULL,
    payload      TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    claimed_at   INTEGER,
    published_at INTEGER
) STRICT;
"#;

/// Each numbered migration and the `user_version` it establishes.
const MIGRATIONS: &[(i64, &str)] = &[(1, V1)];

/// Opens pragmas and applies pending migrations. Returns the resulting
/// journal mode so the caller can fail closed when WAL did not take
/// effect (a network filesystem silently downgrades it).
pub fn open_and_migrate(conn: &Connection) -> rusqlite::Result<String> {
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    // Durability over raw speed: an acknowledged command must survive a
    // crash (§12.2 step 10 commits before replying).
    conn.pragma_update(None, "synchronous", "FULL")?;

    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (target, ddl) in MIGRATIONS {
        if version < *target {
            // DDL and the version bump commit together, so a crash between
            // them cannot leave a database the next open cannot migrate.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(ddl)?;
            tx.execute_batch(&format!("PRAGMA user_version = {target}"))?;
            tx.commit()?;
        }
    }
    Ok(mode)
}

pub fn meta_get(conn: &Connection, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
    use rusqlite::OptionalExtension as _;
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()
}

pub fn meta_set(conn: &Connection, key: &str, value: &[u8]) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )?;
    Ok(())
}

pub fn meta_get_text(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    Ok(meta_get(conn, key)?.map(|b| String::from_utf8_lossy(&b).into_owned()))
}
