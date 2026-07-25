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

/// Version 2: the K1 slice-2 domain tables.
///
/// - §10.3 `reasoning_branches` / `branch_entries`: the branch head CAS
///   moves off the space row onto the branch row (the slice-1 columns
///   `spaces.main_branch_head_digest` / `next_branch_sequence` are
///   dropped after backfill); `spaces.main_branch_id` stays as the
///   compatibility pointer to the main branch.
/// - §10.2 `space_lenses`: the two built-in presentation lenses (Stream,
///   Workbench) are provisioned per space with deterministic ids
///   `lens-stream-<space_id>` / `lens-workbench-<space_id>` — saved
///   query/presentation config only, never authority.
/// - §10.2 `space_frontiers`, §10.8 `context_assemblies` (full canonical
///   record beside the lookup columns).
/// - §10.10 artifacts: `artifacts` / `artifact_uploads` /
///   `artifact_verifications`. Amendment A5: the content address is a
///   typed `local_erasure_safe` DigestRef under `object_secret` (random
///   per-object HMAC key); no retained plaintext hash column exists.
/// - §10.6 `invocations` / `invocation_attempts` /
///   `invocation_input_manifests`, plus the bootstrap-provisioned local
///   developer deployment row (`dep-local-dev`) — assistant/deployment
///   registration ops are operator-surface and out of K1 scope.
/// - `privacy_access_records`: the internal, developer-labeled
///   PrivacyAccessRecord chain (family PROFILE §7, scope_erasure_safe).
const V2: &str = r#"
CREATE TABLE reasoning_branches (
    branch_id                TEXT PRIMARY KEY,
    space_id                 TEXT NOT NULL REFERENCES spaces(space_id),
    revision                 INTEGER NOT NULL,
    purpose_contribution_ref TEXT,
    parent_branch_id         TEXT,
    base_frontier_ref        TEXT,
    base_frontier_digest     TEXT,
    next_branch_sequence     INTEGER NOT NULL,
    head_digest              TEXT NOT NULL,
    status                   TEXT NOT NULL,
    created_by               TEXT NOT NULL,
    created_at               TEXT NOT NULL
) STRICT;

CREATE TABLE branch_entries (
    branch_id        TEXT NOT NULL REFERENCES reasoning_branches(branch_id),
    branch_sequence  INTEGER NOT NULL,
    object_ref       TEXT NOT NULL,
    object_revision  INTEGER NOT NULL,
    object_digest    TEXT NOT NULL,
    origin_branch_id TEXT NOT NULL,
    admission        TEXT NOT NULL,
    merge_commit_ref TEXT,
    created_at       TEXT NOT NULL,
    PRIMARY KEY (branch_id, branch_sequence)
) STRICT;

INSERT INTO reasoning_branches (branch_id, space_id, revision,
    purpose_contribution_ref, parent_branch_id, base_frontier_ref,
    base_frontier_digest, next_branch_sequence, head_digest, status,
    created_by, created_at)
SELECT main_branch_id, space_id, 1, NULL, NULL, NULL, NULL,
    next_branch_sequence, main_branch_head_digest, 'open',
    created_by, created_at
FROM spaces;

INSERT INTO branch_entries (branch_id, branch_sequence, object_ref,
    object_revision, object_digest, origin_branch_id, admission,
    merge_commit_ref, created_at)
SELECT origin_branch_id, origin_branch_sequence, contribution_id, 1,
    content_digest, origin_branch_id, 'origin', NULL, created_at
FROM contributions;

ALTER TABLE spaces DROP COLUMN main_branch_head_digest;
ALTER TABLE spaces DROP COLUMN next_branch_sequence;

CREATE TABLE space_lenses (
    lens_id              TEXT PRIMARY KEY,
    space_id             TEXT NOT NULL REFERENCES spaces(space_id),
    owner_ref            TEXT NOT NULL,
    revision             INTEGER NOT NULL,
    kind                 TEXT NOT NULL,
    query_ast            TEXT NOT NULL,
    sort_spec            TEXT NOT NULL,
    presentation_options TEXT NOT NULL,
    visibility           TEXT NOT NULL,
    status               TEXT NOT NULL,
    created_at           TEXT NOT NULL
) STRICT;

INSERT INTO space_lenses (lens_id, space_id, owner_ref, revision, kind,
    query_ast, sort_spec, presentation_options, visibility, status,
    created_at)
SELECT 'lens-stream-' || space_id, space_id, created_by, 1, 'stream',
    '{"select":"contributions"}', '{"order_by":"branch_sequence"}',
    '{"render":"chronological"}', visibility, 'active', created_at
FROM spaces;

INSERT INTO space_lenses (lens_id, space_id, owner_ref, revision, kind,
    query_ast, sort_spec, presentation_options, visibility, status,
    created_at)
SELECT 'lens-workbench-' || space_id, space_id, created_by, 1, 'workbench',
    '{"select":"typed_cards"}', '{"order_by":"branch_sequence"}',
    '{"render":"cards_with_relations"}', visibility, 'active', created_at
FROM spaces;

CREATE TABLE space_frontiers (
    frontier_id             TEXT PRIMARY KEY,
    revision                INTEGER NOT NULL,
    space_id                TEXT NOT NULL REFERENCES spaces(space_id),
    branch_id               TEXT NOT NULL,
    branch_sequence         INTEGER NOT NULL,
    branch_head_digest      TEXT NOT NULL,
    project_event_cursor    TEXT NOT NULL,
    external_source_cursors TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    digest                  TEXT NOT NULL
) STRICT;

CREATE TABLE context_assemblies (
    assembly_id  TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL,
    project_id   TEXT NOT NULL,
    space_id     TEXT NOT NULL,
    branch_id    TEXT NOT NULL,
    frontier_ref TEXT NOT NULL,
    digest       TEXT NOT NULL,
    record       TEXT NOT NULL,
    created_at   TEXT NOT NULL
) STRICT;

CREATE TABLE artifacts (
    artifact_id            TEXT PRIMARY KEY,
    realm_id               TEXT NOT NULL,
    owner_ref              TEXT NOT NULL,
    revision               INTEGER NOT NULL,
    state                  TEXT NOT NULL,
    size                   INTEGER,
    media_type             TEXT,
    classification_ref     TEXT NOT NULL,
    sealed_storage_ref     TEXT,
    sealed_storage_version TEXT,
    verification_digest    TEXT,
    encryption_key_ref     TEXT NOT NULL,
    content_digest_ref     TEXT,
    object_secret          BLOB,
    created_by             TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    available_at           TEXT,
    retention_until        TEXT
) STRICT;

CREATE TABLE artifact_uploads (
    upload_id                        TEXT PRIMARY KEY,
    artifact_id                      TEXT NOT NULL REFERENCES artifacts(artifact_id),
    realm_id                         TEXT NOT NULL,
    owner_ref                        TEXT NOT NULL,
    revision                         INTEGER NOT NULL,
    declared_raw_sha256              TEXT NOT NULL,
    declared_size                    INTEGER NOT NULL,
    declared_media_type              TEXT NOT NULL,
    classification_ref               TEXT NOT NULL,
    staging_storage_ref              TEXT NOT NULL,
    provider_upload_ref              TEXT,
    state                            TEXT NOT NULL,
    sealed_storage_version           TEXT,
    seal_observation_digest          TEXT,
    authorization_dependency_set_ref TEXT NOT NULL,
    authority_digest                 TEXT NOT NULL,
    max_bytes                        INTEGER NOT NULL,
    expires_at                       TEXT NOT NULL,
    idempotency_key                  TEXT NOT NULL,
    created_at                       TEXT NOT NULL,
    sealed_at                        TEXT,
    terminal_at                      TEXT
) STRICT;

CREATE TABLE artifact_verifications (
    verification_id             TEXT PRIMARY KEY,
    upload_id                   TEXT NOT NULL REFERENCES artifact_uploads(upload_id),
    sealed_storage_ref          TEXT NOT NULL,
    sealed_storage_version      TEXT NOT NULL,
    observed_size               INTEGER NOT NULL,
    observed_media_type         TEXT NOT NULL,
    observed_content_digest_ref TEXT NOT NULL,
    raw_match                   INTEGER NOT NULL,
    verifier_identity_ref       TEXT NOT NULL,
    scanner_set_digest          TEXT NOT NULL,
    scan_results                TEXT NOT NULL,
    outcome                     TEXT NOT NULL,
    observation_digest          TEXT NOT NULL,
    observed_at                 TEXT NOT NULL,
    UNIQUE(upload_id, sealed_storage_version, scanner_set_digest)
) STRICT;

CREATE TABLE assistant_deployments (
    deployment_id         TEXT PRIMARY KEY,
    realm_id              TEXT NOT NULL,
    revision              INTEGER NOT NULL,
    assistant_revision_id TEXT NOT NULL,
    security_profile      TEXT NOT NULL,
    status                TEXT NOT NULL,
    created_at            TEXT NOT NULL
) STRICT;

INSERT INTO assistant_deployments (deployment_id, realm_id, revision,
    assistant_revision_id, security_profile, status, created_at)
VALUES ('dep-local-dev', 'realm-personal', 1, 'asstrev-local-dev',
    'developer', 'active', '1970-01-01T00:00:00Z');

CREATE TABLE invocations (
    invocation_id        TEXT PRIMARY KEY,
    realm_id             TEXT NOT NULL,
    project_id           TEXT NOT NULL,
    space_id             TEXT,
    branch_id            TEXT,
    context_assembly_ref TEXT,
    state                TEXT NOT NULL,
    revision             INTEGER NOT NULL,
    record               TEXT NOT NULL,
    created_at           TEXT NOT NULL
) STRICT;

CREATE TABLE invocation_attempts (
    attempt_id         TEXT PRIMARY KEY,
    invocation_id      TEXT NOT NULL REFERENCES invocations(invocation_id),
    ordinal            INTEGER NOT NULL,
    worker_instance_id TEXT NOT NULL,
    fence_epoch        INTEGER NOT NULL,
    state              TEXT NOT NULL,
    lease_expires_at   TEXT,
    started_at         TEXT,
    ended_at           TEXT,
    result_ref         TEXT,
    UNIQUE(invocation_id, ordinal)
) STRICT;

CREATE TABLE invocation_input_manifests (
    input_manifest_id TEXT PRIMARY KEY,
    invocation_id     TEXT NOT NULL,
    record            TEXT NOT NULL,
    digest            TEXT NOT NULL,
    created_at        TEXT NOT NULL
) STRICT;

CREATE TABLE privacy_access_records (
    internal_access_sequence INTEGER PRIMARY KEY,
    record                   TEXT NOT NULL,
    record_digest_hex        TEXT NOT NULL,
    created_at               INTEGER NOT NULL
) STRICT;
"#;

/// Each numbered migration and the `user_version` it establishes.
const MIGRATIONS: &[(i64, &str)] = &[(1, V1), (2, V2)];

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
