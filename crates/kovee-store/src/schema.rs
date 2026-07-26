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

/// Version 3: the K1 slice-3 domain tables — the registry remainder.
///
/// - §10.2 dispositions: `contribution_dispositions` /
///   `relation_dispositions` (append-only records; kinds
///   withdraw/supersede/redact and retract).
/// - Amendment A5 erasure-safe redaction: `contributions` gains
///   `content_state` (`present` | `redacted`), `content_digest_ref` (the
///   typed `local_erasure_safe` DigestRef JSON), and `object_secret` (the
///   random per-object HMAC key). On redaction the plaintext body and the
///   plaintext canonical `content_digest` are REPLACED by the keyed
///   digest; destroying the per-object secret later erases exactly that
///   object's verifiability.
/// - §10.2 `reactions` (upsert under UNIQUE(target_ref, actor_ref, key)).
/// - §10.1/§10.2 prepared changes: `project_policy_changes`,
///   `space_access_widenings` (full record beside lookup columns).
/// - §10.2 `space_access_grants`; `space_participants` gains the
///   activation `subject_digest` column (KG19 exact prepared subject).
/// - §10.5 `assistant_definitions` / `assistant_revisions` /
///   `assistant_aliases`; `assistant_deployments` gains the full `record`
///   column. The V2 bootstrap deployment `dep-local-dev` gets a coherent
///   definition + revision + record backfill.
/// - §16.2 `disclosure_manifests` (read surface only: no K1 operation
///   writes a disclosure — creation arrives with secure effects, K4).
const V3: &str = r#"
CREATE TABLE contribution_dispositions (
    disposition_id     TEXT PRIMARY KEY,
    contribution_ref   TEXT NOT NULL REFERENCES contributions(contribution_id),
    space_id           TEXT NOT NULL,
    kind               TEXT NOT NULL,
    replacement_ref    TEXT,
    reason_class       TEXT NOT NULL,
    authorized_by_ref  TEXT NOT NULL,
    payload_removed_at TEXT,
    created_at         TEXT NOT NULL
) STRICT;

CREATE TABLE relation_dispositions (
    disposition_id    TEXT PRIMARY KEY,
    relation_ref      TEXT NOT NULL REFERENCES space_relations(relation_id),
    space_id          TEXT NOT NULL,
    kind              TEXT NOT NULL,
    reason_class      TEXT NOT NULL,
    authorized_by_ref TEXT NOT NULL,
    created_at        TEXT NOT NULL
) STRICT;

ALTER TABLE contributions ADD COLUMN content_state TEXT NOT NULL DEFAULT 'present';
ALTER TABLE contributions ADD COLUMN content_digest_ref TEXT;
ALTER TABLE contributions ADD COLUMN object_secret BLOB;

CREATE TABLE reactions (
    reaction_id     TEXT PRIMARY KEY,
    space_id        TEXT NOT NULL REFERENCES spaces(space_id),
    target_ref      TEXT NOT NULL,
    target_revision INTEGER NOT NULL,
    target_digest   TEXT NOT NULL,
    actor_ref       TEXT NOT NULL,
    key             TEXT NOT NULL,
    state           TEXT NOT NULL,
    revision        INTEGER NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE(target_ref, actor_ref, key)
) STRICT;

CREATE TABLE project_policy_changes (
    change_id  TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    state      TEXT NOT NULL,
    revision   INTEGER NOT NULL,
    record     TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE space_access_widenings (
    widening_id TEXT PRIMARY KEY,
    space_id    TEXT NOT NULL REFERENCES spaces(space_id),
    state       TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    record      TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

CREATE TABLE space_access_grants (
    space_access_id                 TEXT PRIMARY KEY,
    space_id                        TEXT NOT NULL REFERENCES spaces(space_id),
    subject_ref                     TEXT NOT NULL,
    revision                        INTEGER NOT NULL,
    source_membership_or_policy_ref TEXT NOT NULL,
    allowed_actions                 TEXT NOT NULL,
    classification_ceiling_ref      TEXT,
    authorization_epoch             INTEGER NOT NULL,
    expires_at                      TEXT,
    status                          TEXT NOT NULL,
    granted_by_or_policy_use_ref    TEXT NOT NULL,
    created_at                      TEXT NOT NULL
) STRICT;

ALTER TABLE space_participants ADD COLUMN subject_digest TEXT;

CREATE TABLE assistant_definitions (
    definition_id TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL,
    owner_ref     TEXT NOT NULL,
    revision      INTEGER NOT NULL,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL,
    status        TEXT NOT NULL,
    created_at    TEXT NOT NULL
) STRICT;

CREATE TABLE assistant_revisions (
    assistant_revision_id TEXT PRIMARY KEY,
    definition_id         TEXT NOT NULL REFERENCES assistant_definitions(definition_id),
    version               TEXT NOT NULL,
    record                TEXT NOT NULL,
    created_by            TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    UNIQUE(definition_id, version)
) STRICT;

CREATE TABLE assistant_aliases (
    alias_binding_id        TEXT PRIMARY KEY,
    realm_id                TEXT NOT NULL,
    project_id              TEXT NOT NULL REFERENCES projects(project_id),
    revision                INTEGER NOT NULL,
    normalized_alias        TEXT NOT NULL,
    display_alias           TEXT NOT NULL,
    assistant_deployment_id TEXT NOT NULL,
    deployment_revision     INTEGER NOT NULL,
    status                  TEXT NOT NULL,
    created_by              TEXT NOT NULL,
    created_at              TEXT NOT NULL
) STRICT;

CREATE TABLE disclosure_manifests (
    disclosure_id TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL,
    record        TEXT NOT NULL,
    created_at    TEXT NOT NULL
) STRICT;

ALTER TABLE assistant_deployments ADD COLUMN record TEXT;

INSERT INTO assistant_definitions (definition_id, realm_id, owner_ref,
    revision, name, description, status, created_at)
VALUES ('asst-local-dev', 'realm-personal', 'prin-owner', 1,
    'Local developer assistant',
    'Bootstrap-provisioned local development assistant (V2 deployment backfill).',
    'active', '1970-01-01T00:00:00Z');

INSERT INTO assistant_revisions (assistant_revision_id, definition_id,
    version, record, created_by, created_at)
VALUES ('asstrev-local-dev', 'asst-local-dev', 'v0',
    '{"assistant_revision_id":"asstrev-local-dev","definition_id":"asst-local-dev","version":"v0","manifest":{"schema_version":"kovee-manifest-v1","definition_id":"asst-local-dev","version":"v0","entrypoint":"local-dev","package_digest":"0000000000000000000000000000000000000000000000000000000000000000","runtime":{},"supported_worker_protocols":["kcp-worker-0.1"],"input_schema_ref":"schema:any-v1","output_schema_ref":"schema:any-v1","skills":[],"attention_proposals":[],"requested_capabilities":[],"model_profiles":[],"tool_profiles":[],"network_policy":{},"resource_limits":{"cpu":0,"memory":0,"disk":0,"output_bytes":0},"default_timeout":0,"max_concurrency":1,"causal_concurrency_policy":"serial-branch","checkpoint_support":false,"cancellation_support":false,"security_profiles":["developer"]},"package_artifact_ref":"artifact-local-dev","package_digest":"0000000000000000000000000000000000000000000000000000000000000000","config_schema_digest":"0000000000000000000000000000000000000000000000000000000000000000","sdk_protocol_range":"kcp-worker-0.1","signature_refs":[],"created_by":"prin-owner","created_at":"1970-01-01T00:00:00Z"}',
    'prin-owner', '1970-01-01T00:00:00Z');

UPDATE assistant_deployments SET record =
    '{"assistant_deployment_id":"dep-local-dev","assistant_revision_id":"asstrev-local-dev","realm_id":"realm-personal","revision":1,"config_ref":"cfg-local-dev","config_digest":"0000000000000000000000000000000000000000000000000000000000000000","secret_binding_set_ref":"secrets-none","secret_binding_set_digest":"0000000000000000000000000000000000000000000000000000000000000000","policy_ref":"policy-default","pool_ref":"pool-local","security_profile":"developer","concurrency_policy":"serial-branch","rollout_policy":{},"status":"active","activated_at":"1970-01-01T00:00:00Z"}'
WHERE deployment_id = 'dep-local-dev';
"#;

/// Version 4: the K2 slice-1 governed-work binding tables (byom §16.6 as
/// frozen in `byom/spec/governed-work/*.schema.json`).
///
/// - `kovee_realm_byom_bindings` / `kovee_society_mappings`: step 1 of the
///   D10 greenfield saga writes both durably and INERTLY (`status`
///   `pending`); they become `active` only atomically with the owner CAS.
///   `UNIQUE(realm_ref, exact_scope_digest_hex, binding_epoch)` makes an
///   epoch single-use PER GOVERNED SCOPE, so a rolled-back epoch can
///   never mint a second binding (epochs are per exact scope, not per
///   realm — one realm may govern many disjoint scopes at epoch 1).
/// - `kovee_governance_owner_bindings`: the CAS row. Its identity is
///   `(realm_ref, exact_scope_digest)` — the §16.6 uniqueness rule — so
///   that pair is the primary key; there is no surrogate id. `revision`
///   is the exact-CAS field.
/// - `delegated_principal_credentials`: the minted DPCs with the family
///   contract L5–L6 atomic key `UNIQUE(issuer_ref, nonce)` and the
///   stored result a replay returns instead of executing twice.
/// - `greenfield_enablements`: the saga's slot/state table — one row per
///   `(realm, exact scope, binding epoch)` carrying the descriptor state
///   (`bindings_created | active | rolled_back | disabled`) and the
///   canonical result an exact retry returns byte-identically.
///
/// Digests are stored as the typed family `DigestRef` JSON (never a bare
/// hash); the `_hex` columns beside them are lookup keys only.
const V4: &str = r#"
CREATE TABLE kovee_realm_byom_bindings (
    binding_ref                          TEXT PRIMARY KEY,
    realm_ref                            TEXT NOT NULL REFERENCES realms(realm_id),
    exact_scope_digest_hex               TEXT NOT NULL,
    binding_revision                     INTEGER NOT NULL,
    binding_epoch                        INTEGER NOT NULL,
    predecessor_binding_ref              TEXT,
    byom_endpoint_ref                    TEXT NOT NULL,
    endpoint_incarnation                 TEXT NOT NULL,
    compatibility_bundle                 TEXT NOT NULL,
    delegated_principal_audience         TEXT NOT NULL,
    external_authorization_audience      TEXT NOT NULL,
    historical_recovery_mode             TEXT NOT NULL,
    recovery_authorization_policy_ref    TEXT NOT NULL,
    recovery_authorization_policy_digest TEXT NOT NULL,
    status                               TEXT NOT NULL,
    dependency_digest                    TEXT NOT NULL,
    digest                               TEXT NOT NULL,
    created_at                           TEXT NOT NULL,
    UNIQUE(realm_ref, exact_scope_digest_hex, binding_epoch)
) STRICT;

CREATE TABLE kovee_society_mappings (
    mapping_id                         TEXT PRIMARY KEY,
    realm_ref                          TEXT NOT NULL REFERENCES realms(realm_id),
    society_ref                        TEXT NOT NULL,
    society_recovery_epoch             INTEGER NOT NULL,
    allowed_project_and_space_selectors TEXT NOT NULL,
    classification_binding_ref         TEXT NOT NULL,
    governance_owner_binding_ref       TEXT NOT NULL,
    governance_owner_binding_digest    TEXT NOT NULL,
    status                             TEXT NOT NULL,
    revision                           INTEGER NOT NULL,
    digest                             TEXT NOT NULL,
    binding_ref                        TEXT NOT NULL
        REFERENCES kovee_realm_byom_bindings(binding_ref),
    created_at                         TEXT NOT NULL,
    UNIQUE(realm_ref, society_ref, binding_ref)
) STRICT;

CREATE TABLE kovee_governance_owner_bindings (
    realm_ref              TEXT NOT NULL REFERENCES realms(realm_id),
    exact_scope_digest_hex TEXT NOT NULL,
    exact_scope_selector   TEXT NOT NULL,
    exact_scope_digest     TEXT NOT NULL,
    revision               INTEGER NOT NULL,
    binding_epoch          INTEGER NOT NULL,
    governance_owner       TEXT NOT NULL,
    owner_endpoint_ref     TEXT,
    owner_binding_ref      TEXT,
    cutover_ref            TEXT,
    status                 TEXT NOT NULL,
    digest                 TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,
    PRIMARY KEY (realm_ref, exact_scope_digest_hex)
) STRICT;

CREATE TABLE delegated_principal_credentials (
    credential_id      TEXT PRIMARY KEY,
    issuer_ref         TEXT NOT NULL,
    nonce              TEXT NOT NULL,
    realm_ref          TEXT NOT NULL,
    binding_ref        TEXT NOT NULL
        REFERENCES kovee_realm_byom_bindings(binding_ref),
    record             TEXT NOT NULL,
    digest_hex         TEXT NOT NULL,
    issued_at          TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    consumed_at        INTEGER,
    consumed_operation TEXT,
    consumed_result    BLOB,
    UNIQUE(issuer_ref, nonce)
) STRICT;

CREATE TABLE greenfield_enablements (
    enablement_id           TEXT PRIMARY KEY,
    realm_ref               TEXT NOT NULL REFERENCES realms(realm_id),
    exact_scope_digest_hex  TEXT NOT NULL,
    exact_scope_selector    TEXT NOT NULL,
    binding_epoch           INTEGER NOT NULL,
    state                   TEXT NOT NULL,
    society_ref             TEXT NOT NULL,
    society_recovery_epoch  INTEGER NOT NULL,
    byom_endpoint_ref       TEXT NOT NULL,
    endpoint_incarnation    TEXT NOT NULL,
    binding_ref             TEXT NOT NULL,
    mapping_id              TEXT NOT NULL,
    expected_owner_revision INTEGER NOT NULL,
    subject_digest_hex      TEXT NOT NULL,
    dependency_digest_hex   TEXT NOT NULL,
    result                  TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    UNIQUE(realm_ref, exact_scope_digest_hex, binding_epoch)
) STRICT;
"#;

/// Version 5: the R1 erasure corrections (KV-A5-1, KV-A5-2, D-R1-2).
///
/// - `artifact_uploads.declared_raw_sha256` is DROPPED: the caller's raw
///   checksum is transient (compared once, during sealing) and never
///   durable. Its place is taken by `declared_raw_commitment` — the HMAC
///   of the declared checksum under the artifact's own per-object secret,
///   so finalization can still verify the declaration while destroying
///   the secret destroys the commitment's meaning.
/// - Pre-V5 rows kept the RAW per-object secret beside the object (the
///   KV-A5-2 finding). Those raw secrets are destroyed here; from V5 on
///   `artifacts.object_secret` / `contributions.object_secret` hold the
///   secret WRAPPED under the realm key (`kovee_store::objkey`). A
///   pre-V5 artifact therefore keeps its row and its bytes but loses
///   keyed verifiability — the honest cost of removing a secret that
///   should never have been stored in the clear.
/// - A pre-V5 contribution keeps whatever `content_digest` it was
///   written with (SQL cannot recompute HMACs). `contribution_redact`
///   re-keys such a row under a fresh wrapped secret and scrubs every
///   retained copy of the old plaintext digest; contributions appended
///   from V5 on are keyed from their FIRST append and never carry a
///   plaintext-derived digest at all.
const V5: &str = r#"
ALTER TABLE artifact_uploads ADD COLUMN declared_raw_commitment TEXT;
ALTER TABLE artifact_uploads DROP COLUMN declared_raw_sha256;

UPDATE artifacts SET object_secret = NULL WHERE object_secret IS NOT NULL;
UPDATE contributions SET object_secret = NULL WHERE object_secret IS NOT NULL;
"#;

/// Version 6: the K2 slice-2 governed-work tables — the formation saga's
/// paired recovery records, the hosted-episode binding, and the
/// `byom_subordinate` budget bridge (byom §16.3/§16.6 as frozen in
/// `byom/spec/governed-work/*.schema.json`).
///
/// The uniqueness rules ARE the safety properties, so they are indexes
/// rather than code:
///
/// - `endeavor_formation_intents`: `UNIQUE(realm_ref,
///   requested_by_principal, client_formation_key)` — one explicit human
///   formation command deduplicated. The scope says nothing about one
///   Endeavor per Branch, frontier, purpose, or Society (§16.3).
/// - `endeavor_formation_slots`: the same triple, but `WHERE state !=
///   'released'` (a partial index) — a released slot leaves the intent
///   in place, and only a pre-send cancel, a verified tombstone, a
///   verified historically fenced absence, or a committed ExternalLink
///   releases one. There is deliberately no timeout release.
/// - `endeavor_formation_attempts`: `UNIQUE(formation_id,
///   attempt_ordinal)` and `UNIQUE(attempt_nonce)`. Rows are APPEND-ONLY:
///   resolving an intent never rewrites an earlier attempt's send or
///   authentication evidence, so a crash mid-send stays visible.
/// - `external_links`: `UNIQUE(formation_id)` and `UNIQUE(link_digest_hex)`
///   — link creation is idempotent over its digest (§16.3 table row 13).
/// - `byom_placement_bindings`: `UNIQUE(resource_allocation_ref,
///   revision)`; the admission columns stay NULL until byom's runtime
///   adapter answers, which is what makes "no episode work before
///   placement admission" checkable.
/// - `byom_episode_bindings`: `UNIQUE(stable_binding_key)` AND
///   `UNIQUE(episode_ref, byom_attempt_ref, kovee_invocation_ref)` — the
///   L22 idempotent create in both directions, so a different key for the
///   same triple conflicts instead of double-binding.
/// - `byom_subordinate_reservations`:
///   `UNIQUE(stable_external_reservation_key)` — CreateOnce.
const V6: &str = r#"
CREATE TABLE endeavor_formation_intents (
    formation_id                        TEXT PRIMARY KEY,
    revision                            INTEGER NOT NULL,
    realm_ref                           TEXT NOT NULL REFERENCES realms(realm_id),
    project_id                          TEXT NOT NULL,
    space_id                            TEXT NOT NULL,
    branch_id                           TEXT NOT NULL,
    frontier_ref                        TEXT NOT NULL,
    frontier_digest                     TEXT NOT NULL,
    collaboration_context_bundle_ref    TEXT NOT NULL,
    context_bundle_digest               TEXT NOT NULL,
    society_ref                         TEXT NOT NULL,
    society_recovery_epoch              INTEGER NOT NULL,
    endeavor_proposal_ref               TEXT NOT NULL,
    endeavor_proposal_digest            TEXT NOT NULL,
    byom_endpoint_ref                   TEXT NOT NULL,
    command_endpoint_incarnation        TEXT NOT NULL,
    realm_byom_binding_ref              TEXT NOT NULL,
    realm_byom_binding_revision         INTEGER NOT NULL,
    realm_byom_binding_epoch            INTEGER NOT NULL,
    realm_byom_binding_digest           TEXT NOT NULL,
    requested_by_principal              TEXT NOT NULL,
    bound_participant_ref               TEXT NOT NULL,
    participant_binding_epoch           INTEGER NOT NULL,
    source_actor_binding_digest         TEXT NOT NULL,
    delegated_principal_subject_digest  TEXT NOT NULL,
    client_formation_key                TEXT NOT NULL,
    byom_command_idempotency_key        TEXT NOT NULL,
    idempotency_domain_digest           TEXT NOT NULL,
    canonical_byom_command_digest       TEXT NOT NULL,
    canonical_command_digest_hex        TEXT NOT NULL,
    formation_slot_ref                  TEXT NOT NULL,
    formation_slot_generation           INTEGER NOT NULL,
    authorization_dependency_set_ref    TEXT NOT NULL,
    authority_digest                    TEXT NOT NULL,
    latest_attempt_ref                  TEXT,
    latest_authentication_observation_ref TEXT,
    byom_result_ref                     TEXT,
    byom_result_digest                  TEXT,
    external_link_ref                   TEXT,
    state                               TEXT NOT NULL,
    created_at                          TEXT NOT NULL,
    terminal_at                         TEXT,
    digest                              TEXT NOT NULL,
    command_bytes                       TEXT NOT NULL,
    result_envelope                     TEXT,
    UNIQUE(realm_ref, requested_by_principal, client_formation_key)
) STRICT;

CREATE TABLE endeavor_formation_slots (
    slot_id                       TEXT PRIMARY KEY,
    realm_ref                     TEXT NOT NULL REFERENCES realms(realm_id),
    requested_by_principal        TEXT NOT NULL,
    client_formation_key          TEXT NOT NULL,
    holder_formation_id           TEXT NOT NULL
        REFERENCES endeavor_formation_intents(formation_id),
    generation                    INTEGER NOT NULL,
    revision                      INTEGER NOT NULL,
    society_ref                   TEXT NOT NULL,
    society_recovery_epoch        INTEGER NOT NULL,
    source_actor_binding_digest   TEXT NOT NULL,
    realm_byom_binding_ref        TEXT NOT NULL,
    realm_byom_binding_revision   INTEGER NOT NULL,
    realm_byom_binding_epoch      INTEGER NOT NULL,
    realm_byom_binding_digest     TEXT NOT NULL,
    canonical_byom_command_digest TEXT NOT NULL,
    byom_command_idempotency_key  TEXT NOT NULL,
    idempotency_domain_digest     TEXT NOT NULL,
    state                         TEXT NOT NULL,
    byom_result_ref               TEXT,
    byom_result_digest            TEXT,
    external_link_ref             TEXT,
    acquired_at                   TEXT NOT NULL,
    released_at                   TEXT,
    digest                        TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX endeavor_formation_slots_live
    ON endeavor_formation_slots (realm_ref, requested_by_principal, client_formation_key)
    WHERE state != 'released';

CREATE TABLE endeavor_formation_attempts (
    attempt_id                          TEXT PRIMARY KEY,
    formation_id                        TEXT NOT NULL
        REFERENCES endeavor_formation_intents(formation_id),
    attempt_ordinal                     INTEGER NOT NULL,
    canonical_byom_command_digest       TEXT NOT NULL,
    idempotency_domain_digest           TEXT NOT NULL,
    attempt_recovery_binding_ref        TEXT NOT NULL,
    attempt_recovery_binding_revision   INTEGER NOT NULL,
    attempt_recovery_binding_epoch      INTEGER NOT NULL,
    attempt_recovery_binding_digest     TEXT NOT NULL,
    authentication_observation_ref      TEXT NOT NULL,
    authentication_observation_digest   TEXT NOT NULL,
    attempt_nonce                       TEXT NOT NULL,
    authentication_proof_digest         TEXT NOT NULL,
    state                               TEXT NOT NULL,
    reply_digest                        TEXT,
    reconciliation_digest               TEXT,
    prepared_at                         TEXT NOT NULL,
    sent_at                             TEXT,
    observed_at                         TEXT,
    digest                              TEXT NOT NULL,
    UNIQUE(formation_id, attempt_ordinal),
    UNIQUE(attempt_nonce)
) STRICT;

CREATE TABLE external_links (
    link_ref        TEXT PRIMARY KEY,
    formation_id    TEXT NOT NULL
        REFERENCES endeavor_formation_intents(formation_id),
    realm_ref       TEXT NOT NULL REFERENCES realms(realm_id),
    endeavor_ref    TEXT NOT NULL,
    endeavor_revision INTEGER NOT NULL,
    endeavor_digest TEXT NOT NULL,
    result_digest   TEXT NOT NULL,
    link_digest_hex TEXT NOT NULL,
    source_cursor   TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    UNIQUE(formation_id),
    UNIQUE(link_digest_hex)
) STRICT;

CREATE TABLE byom_placement_bindings (
    placement_id                  TEXT PRIMARY KEY,
    realm_ref                     TEXT NOT NULL REFERENCES realms(realm_id),
    owner_protocol                TEXT NOT NULL,
    revision                      INTEGER NOT NULL,
    resource_allocation_ref       TEXT NOT NULL,
    resource_allocation_digest    TEXT NOT NULL,
    selected_manifestation_ref    TEXT NOT NULL,
    selected_manifestation_digest TEXT NOT NULL,
    host_runtime_binding          TEXT NOT NULL,
    kovee_invocation_ref          TEXT NOT NULL,
    placement_constraint_digest   TEXT NOT NULL,
    kovee_fence_epoch             INTEGER NOT NULL,
    state                         TEXT NOT NULL,
    admission_ref                 TEXT,
    admission_digest              TEXT,
    admitted_at                   TEXT,
    created_at                    TEXT NOT NULL,
    digest                        TEXT NOT NULL,
    UNIQUE(resource_allocation_ref, revision)
) STRICT;

CREATE TABLE byom_episode_bindings (
    binding_id                          TEXT PRIMARY KEY,
    realm_ref                           TEXT NOT NULL REFERENCES realms(realm_id),
    stable_binding_key                  TEXT NOT NULL,
    placement_id                        TEXT NOT NULL
        REFERENCES byom_placement_bindings(placement_id),
    episode_ref                         TEXT NOT NULL,
    byom_attempt_ref                    TEXT NOT NULL,
    kovee_invocation_ref                TEXT NOT NULL,
    byom_fence_epoch                    INTEGER NOT NULL,
    kovee_invocation_fence              INTEGER NOT NULL,
    state                               TEXT NOT NULL,
    episode_state                       TEXT NOT NULL,
    record                              TEXT NOT NULL,
    fenced_reason                       TEXT,
    created_at                          TEXT NOT NULL,
    updated_at                          TEXT NOT NULL,
    UNIQUE(stable_binding_key),
    UNIQUE(episode_ref, byom_attempt_ref, kovee_invocation_ref)
) STRICT;

CREATE TABLE byom_subordinate_reservations (
    subordinate_reservation_ref     TEXT PRIMARY KEY,
    realm_ref                       TEXT NOT NULL REFERENCES realms(realm_id),
    stable_external_reservation_key TEXT NOT NULL,
    external_budget_bridge_ref      TEXT NOT NULL,
    byom_reservation_set_ref        TEXT NOT NULL,
    realm_byom_binding_ref          TEXT NOT NULL,
    realm_byom_binding_epoch        INTEGER NOT NULL,
    revision                        INTEGER NOT NULL,
    state                           TEXT NOT NULL,
    charged                         INTEGER NOT NULL,
    released_lifetime               INTEGER NOT NULL,
    record                          TEXT NOT NULL,
    created_at                      TEXT NOT NULL,
    updated_at                      TEXT NOT NULL,
    UNIQUE(stable_external_reservation_key)
) STRICT;
"#;

/// Version 7: what driving byom's REAL runtime surface needs the episode
/// tables to carry.
///
/// - `byom_episode_bindings.lease_revision`: byomd's `EpisodeLeaseHead`
///   revision as of the last accepted mutation. Every protected runtime
///   command is a CAS on that head (`checkpoint_commit` names it as
///   `expected_lease_revision`; the terminal transitions name it in
///   `meta.expected_revision`), so Kovee has to carry the exact number
///   byomd last returned — it can never be guessed or incremented locally.
/// - `byom_placement_bindings.object_secret`: one RANDOM per-object
///   erasure secret, wrapped under the realm key (disposition D-R1-2), for
///   the `local_erasure_safe` digests byom's runtime schemas require on
///   fields Kovee AUTHORS (`claim_subject_digest`,
///   `context_manifest_digest`, `checkpoint_digest`). A root-derived
///   per-object key would be the forbidden scope-key substitution, so the
///   secret is minted at placement time and destroyed with the row.
const V7: &str = r#"
ALTER TABLE byom_episode_bindings ADD COLUMN lease_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE byom_placement_bindings ADD COLUMN object_secret BLOB;
"#;

/// Each numbered migration and the `user_version` it establishes.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, V1),
    (2, V2),
    (3, V3),
    (4, V4),
    (5, V5),
    (6, V6),
    (7, V7),
];

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
    // Erasure honesty (amendment A5, D-R1-2): freed cells are zeroed
    // rather than left as readable residue, so redacted plaintext does
    // not survive in the file as a deleted-but-intact record.
    conn.pragma_update(None, "secure_delete", true)?;

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
