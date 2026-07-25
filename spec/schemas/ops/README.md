# Per-operation schemas — K0 (`core_v1`, `shared_space_v1`, `developer_assistant_v1`)

One closed request and one closed result schema per operation
(`<op>-request.schema.json`, `<op>-result.schema.json`; the result schema is
the `CommandResult.result` payload of the §11.2 ok arm — the envelope's
`revision`/`event_cursor` members live outside it). Slice 1 delivered
`core_v1` + `developer_assistant_v1` (gap notes KG1–KG15); slice 2 delivered
`shared_space_v1` (gap notes KG16–KG30), completing the per-operation suite
named as remaining K0 work in `plan/sheets/K0.md`: both runners'
`COVERED_BUNDLES` lists now cover all three K1 bundles and their coverage
gates assert that every one of the registry's 90 `(operation, surface)`
entries is schema-covered.

Each request schema embeds the §11.2 command envelope (exact `op` const,
closed per-operation `args`) and applies the read/mutation rule of
`kcp-command.schema.json` (R0 KENV-01): mutations require `meta`; reads have
no `meta` member at all, so a read carrying an idempotency key fails. Field
names are verbatim from the pinned DESIGN.md record shapes (§10.5, §10.6,
§11.1, §14.2) wherever DESIGN.md spells them; surface, actor kind, and
assurance come from the K0-frozen registry (`spec/registry.json`) and are
quoted in each schema's description — they are registry-enforced, not
schema-expressible. Requests carry only caller-supplied arguments: the
server derives actor, surface, and every record-identity field from the
channel and the transaction, and a request field naming those can never
override the binding — the wrong-surface-args negative vectors under
`spec/vectors/ops/` pin that.

Both rederivers (`xcheck/run.py`, `tscheck/check.mjs`) enforce bundle
coverage against the registry: every covered entry's operation has a
request+result pair, the request pins the exact op const, reads carry no
meta, mutations require it.

## Gap notes (explicit derivations beyond DESIGN.md's spelled text)

DESIGN.md defines record shapes, envelope semantics, and authority rows —
not per-operation argument or result payloads. Where an operation's args or
result are not spelled out they are derived minimally from the record shape
plus its §11.6.1 row. Every such derivation is listed here and freezes with
the bundle; a conflicting later registry/spec freeze wins.

- **KG1 — pre-auth command framing.** §11.1 defines `HelloRequest` /
  `HelloResult` as standalone negotiation shapes (pinned by
  `kcp-hello.schema.json`) and never renders `hello` as a Command; the
  registry nevertheless lists `hello` and public `protocol_info` as
  operations. Derived: their request schemas carry the §11.1 field lists as
  command `args` under the envelope members, and the closed pre-auth shape
  has **no `realm_id` or `project_id` member**: §11.2's `realm_id`
  requirement binds authenticated realm-scoped commands, while the pre-auth
  row is installation-scoped with an empty dependency set (registry).
  Realm-scoping a pre-auth request fails the closed shape (vector). No
  identity or credential member exists (§11.1: authentication is never an
  identity claim in `HelloRequest`).
- **KG2 — protocol_info payloads.** Nothing beyond "bounded public
  installation metadata" (§11.6.1) is spelled. Derived: args are the closed
  empty object; the result encodes that metadata as the §11.1 `HelloResult`
  members minus `selected_version` (nothing was negotiated) plus
  `supported_versions`.
- **KG3 — diagnose classification and payloads.** No diagnose payload is
  spelled anywhere. Classified as a **read** (no `meta`): it changes no
  authoritative domain or user-visible state, and §11.2 explicitly lets
  reads append security/audit access records. Derived args: optional
  narrowing `checks[]` selection of registered diagnostics (realm scoping
  travels in the envelope `realm_id`; the registry constraint binds realm
  and role dependencies only where the diagnostic is realm-scoped). Derived
  result: `{status, checks[]: {check, status, detail?}, generated_at}` with
  a pass/warn/fail verdict. `audit_export` and its step-up bind
  `installation_admin_v1` (K3), per registry ambiguity note 1.
- **KG4 — result payloads generally.** Every result is a minimal projection
  of the §10.5/§10.6 record the operation creates, moves, or reads;
  DESIGN.md enumerates result fields for none of these operations. Records
  are projected with exactly the record's unmarked fields required and its
  `?`-marked fields optional.
- **KG5 — server/channel-derived record fields never in requests.** Record
  ids on create (`definition_id`, `assistant_revision_id`,
  `assistant_deployment_id`, `alias_binding_id`, `invocation_id`), actor
  fields (`owner_ref`, `created_by`), `revision`, `status`,
  `normalized_alias` (§10.5 deterministic normalization), and
  invocation-resolution fields (`assistant_revision_id`, `effective_*`,
  `rollout_decision_ref`, `trigger_ref`/`trigger_digest`,
  `input_manifest_ref`/`input_digest`, `correlation_ref`, `causation_ref`)
  are server/channel-derived (§11.2 actor scoping; §15.1 the server builds
  and digests the input manifest before scheduling) and are not request
  fields; the closed schemas reject them.
- **KG6 — status value spaces.** `AssistantDefinition.status`,
  `AssistantDeployment.status`, and `AssistantAliasBinding.status` are
  named by §10.5 with no value space anywhere in DESIGN.md. Pinned as a
  bounded lowercase token (`^[a-z][a-z0-9_]{0,63}$`); no enum invented.
  `Invocation.state` **is** spelled (§10.6) and uses that closed enum
  verbatim. Safety-relevant enums stay closed (§11.8): the spelled enums
  (`security_profile` §14.4, `concurrency_policy` §15.3, invocation state
  §10.6) are closed in the schemas.
- **KG7 — manifest typed encoding.** §14.2 lists the manifest fields as
  prose lines. Derived typing: "runtime + locked dependency metadata"
  becomes the open `runtime` object (packaging format unpinned);
  `network_policy` stays open pending `secure_effects_v1` (K4);
  `attention_proposals[]` items stay open pending
  `attention_coordination_v1` (K2) — all inert, carrying no authority
  (§14.2); `resource_limits` is the closed `{cpu, memory, disk,
  output_bytes}` object with safe non-negative integers, units unpinned;
  `default_timeout` likewise carries no pinned unit;
  `causal_concurrency_policy` takes the closed §15.3 policy set;
  `security_profiles[]` the closed §14.4 names.
- **KG8 — free-text, range, and priority encodings.** `description`,
  `reason`, and `detail` are bounded free text (≤ 4096 Unicode scalar
  values; §11.8 bounds free text again at admission — the ceiling is this
  slice's recorded extraction bound). `sdk_protocol_range` is an opaque
  identifier-shaped expression (no range grammar is pinned).
  `Invocation.priority` is a safe non-negative integer (no encoding
  pinned). Timestamps restate the K0 RFC 3339 decision
  (`spec/schemas/README.md` item 7).
- **KG9 — pagination and filters.** `*_list` args take §11.5's
  `{after?, limit, snapshot?}` verbatim with `limit` 1..512 (§11.8) and
  opaque cursors ≤ 4096 chars (the K0 cursor-cap decision,
  `spec/schemas/README.md` item 9); list results take
  `{items[], next?, snapshot, boundary_event_cursor}` verbatim. The
  narrowing-only filter fields are derived: `assistant_revision_list
  .definition_id`, `deployment_list.assistant_revision_id`,
  `assistant_alias_list.assistant_deployment_id`, and `invocation_list
  .{assistant_deployment_id, space_id, state}`. Filters never widen
  visibility; offset pagination is prohibited (§11.5).
- **KG10 — deployment_create args.** The caller-suppliable
  `AssistantDeployment` fields (§10.5 record shape); `rollout_policy` is an
  open object pending `durable_runtime_v1`'s `deployment_update/rollout`
  (K2).
- **KG11 — deployment_activate/drain payloads.** Args carry the target id
  only; the exact deployment revision is pinned by
  `meta.expected_revision` (§11.2 optimistic concurrency). Step-up for
  production activation is registry assurance, not schema-expressible.
  Drain's resulting status mirrors the design-wide draining vocabulary
  (§10.9, §9.5); the deployment machine itself is unpinned (KG6).
- **KG12 — alias payloads.** `assistant_alias_bind`/`_update` supply
  `{display_alias | alias_binding_id, assistant_deployment_id,
  deployment_revision}`; `normalized_alias` is server-derived; changing the
  target creates a new alias-binding revision (§10.5). The envelope
  `project_id` is required on all alias (and invocation) operations because
  the records scope it non-optionally (§10.5/§10.6; v0.1 alias uniqueness
  at `(project_id, normalized_alias)`). `assistant_alias_show` reads by
  `alias_binding_id`; alias-name resolution is not a wire operation in this
  slice.
- **KG13 — invocation_create args.** The §11.6.1 direct-invocation row's
  required inputs mapped onto §10.6 field names: required
  `{assistant_deployment_id, assistant_deployment_revision, deadline}`
  (deadline and max_attempts are committed before the first attempt,
  §15.4); optional `{space_id, branch_id, context_assembly_ref +
  context_assembly_digest, budget_reservation_set_ref,
  disclosure_rules_digest, priority, not_before, max_attempts}`. Whether
  budget/disclosure are required for a given target is an authorization
  rule, mirroring the record's `?`-marks. No requester or commitment member
  exists: a direct invocation cannot name a worker as requester or create a
  Commitment (§11.6.1) — vector.
- **KG14 — dual-surface operations and worker binding.**
  `invocation_cancel` exists on `external_client` and `worker` (registry).
  The registry key is `(operation, surface)`, but schema names key by
  operation (the byom G35 pattern): one request/result pair, per-surface
  actor documented in the schema, enforced by the registry — surface is not
  schema-expressible. The worker clause binds the parent attempt: every
  worker operation carries `{attempt_id, fence_epoch}` (§15.2), so those
  are schema fields, required on the worker surface and forbidden on
  `external_client` by registry rule (the schema keeps them optional).
  `cancellation_scope` is a bounded token with no invented value space
  (§15.4: child work follows its recorded cancellation policy); inherited
  ceilings are server-side, never wire args. The `shared_space_v1`
  dual-surface operations (`contribution_append`, `relation_assert`,
  `context_assembly_create`) follow this pattern in their slice.
- **KG15 — application_event_emit payloads.** Args
  `{attempt_id, fence_epoch, type, payload}`: the wire form of
  `ctx.events.emit(type, payload)` (§14.1) with the §15.2 worker binding.
  The SDK `operation_key` is sugar the supervisor combines with the
  invocation id into the durable deduplication key — carried as
  `meta.idempotency_key` on the wire. The 64 KiB registered-payload cap
  (§11.8) is enforced at admission (the acceptance layer's inline-content
  class covers the event envelope's root `payload`; command-args payloads
  re-bound in code). The `dev.kovee.*` reservation and per-deployment
  namespace grants (§11.3) are policy/registry checks the type pattern
  cannot express. The result is a derived identity projection of the
  committed event `{event_id, stream_id, stream_sequence,
  project_sequence?, occurred_at}` (§11.3); emitted events remain
  non-authoritative until consumed through a typed command.
- **KG16 — envelope-scoped read targets and project scoping.** `realm_show`
  and `project_show` read the resource the §11.2 envelope already names:
  their `args` is the closed empty object, and `project_show` requires the
  envelope `project_id`. The project-collection operations have no
  `project_id` member at all: `project_list` is realm-scoped, and
  `project_create` cannot carry one because the created record's identity is
  server-derived (KG5). Every space-scoped operation (space, participant,
  grant, contribution, relation, frontier, lens, context-assembly, and
  reaction operations) requires the envelope `project_id` — the KG12
  pattern: the §10.2 records scope `project_id` non-optionally through
  their Space. Event, snapshot, artifact, and disclosure-manifest
  operations keep the ordinary optional envelope `project_id`.
- **KG17 — prepared-change payloads.** `space_access_widen_prepare` and
  `project_access_policy_change_prepare` args carry only the proposal
  deltas (`proposed_*`, §10.1/§10.2 field names verbatim): DESIGN.md spells
  that Kovee pins the prior values, exact affected frontiers/item-set,
  classification join, and destination audience server-side, and the exact
  project/Space revision travels as `meta.expected_revision` (KG11
  pattern). Neither proposed member is individually required — a change may
  alter policy only or classification only; requiring a non-empty delta is
  an admission rule the closed shape does not encode. Confirm consumes
  `{change_id|widening_id, decision_receipt_ref}` — the §11.6.1 rows name
  the authorization decision receipt — and carries no `proposed_*` member
  because changing content makes the prepared intent stale; cancel takes
  the id only and consumes no receipt.
- **KG18 — lifecycle and narrow payloads.** `space_freeze/reopen/archive`
  and `space_restrict` take `{space_id}` only: the state transition is the
  operation itself and the exact revision is `meta.expected_revision` (KG11
  pattern); no status/visibility member exists. `space_policy_narrow`
  supplies the narrower `{policy_set_ref?, default_classification_ref?}`
  (record field names verbatim); the kernel's narrowing proof is
  server-side. `space_update_metadata` carries only `{space_id, title?,
  purpose_contribution_ref?}` and `project_update_metadata` only `{name}` —
  the §10.1/§10.2 prohibitions (status, policy, classification, visibility)
  leave exactly those metadata fields.
- **KG19 — participant and grant payloads.** `space_participant_add`
  supplies the caller-suppliable §10.2 SpaceParticipant fields `{space_id,
  subject_ref, kind, role, subject_revision?}`; `participant_id`,
  `authority_source_ref`, `status`, and `revision` are server-derived
  (KG5). `space_participant_update` takes `{participant_id, role?,
  status?}` with the record's closed status enum; the activation and
  removal transitions have their own operations and the kernel rejects them
  here — state-machine narrowing is not schema-expressible.
  `space_participant_activate` (operator activation row) consumes the exact
  prepared subject as `{participant_id, subject_digest}`; the acceptance
  receipt or standing-policy use is authority material bound by the
  surface, never a wire argument. `space_access_grant_create` supplies
  `{space_id, subject_ref, allowed_actions[], classification_ceiling_ref?,
  expires_at?}`; `allowed_actions` items are bounded tokens — no action
  vocabulary is pinned, and a grant is intersected with current source
  authority on every use (§10.2).
- **KG20 — branch-append arguments.** Appending a contribution or relation
  presents the target branch and expected head digest (§10.3: "Every branch
  append presents the expected head digest and uses compare-and-swap";
  §11.2). Derived arg names: `branch_id` (the §10.3 branch key, recorded on
  the created record as `origin_branch_id`) and `expected_head_digest`
  (from `ReasoningBranch.head_digest`). The allocated sequences
  (`origin_branch_sequence`, `space_sequence`, `branch_sequence`),
  `author_actor_ref`, and `content_digest` are server-derived (KG5).
- **KG21 — contribution_append payloads.** Caller-suppliable §10.2
  Contribution fields only: `{kind, body_parts[], schema_ref?,
  subject_refs[]?, source_refs[]?, epistemic_posture?, classification_ref?,
  retention_policy_ref?}`; classification/retention default from the Space
  and policy when omitted and are required in the result projection, and
  `schema_ref` is server-defaulted when omitted. `body_parts` items are the
  §10.2 ContributionPart union discriminated structurally by the five arms'
  disjoint closed required member sets — no type tag exists in the record
  model (§14.1's `{"type": "text"}` literal is SDK sugar). `TextPart.text`
  carries the §11.8 64 KiB contribution-inline-content cap as a
  65536-scalar `maxLength` (bytes re-checked at admission);
  `DataPart.value` stays open, validated by its `schema_ref`.
  `media_type` and `language` encodings (RFC 6838 type/subtype, BCP
  47-shaped tag) are recorded extraction bounds. `invocation_ref`,
  `context_assembly_ref`, and `causation_ref` are server/channel-derived on
  the worker surface (KG5).
- **KG22 — disposition payloads.** `contribution_withdraw/supersede/redact`
  and `relation_retract` map onto ContributionDisposition /
  RelationDisposition (§10.2): args `{contribution_ref|relation_ref,
  reason_class}` plus `replacement_ref` (required) for supersede only. The
  disposition kind is pinned by the operation — each result schema pins the
  matching const — and `authorized_by_ref` / `payload_removed_at` are
  server-derived. `reason_class` is a bounded token (no value space
  pinned).
- **KG23 — relation_assert payloads.** The §10.2 spelled exclusion: no
  `relation_class` member exists on the request, and the result pins
  `relation_class` const `semantic_assertion` — an external caller cannot
  request, spoof, or upgrade a structural relation. `from_ref`/`to_ref`
  take the record's exact `{object_ref, revision, digest}` triple.
- **KG24 — frontier payloads.** `frontier_pin` takes `{space_id,
  branch_id}`: the pinned sequence, head digest, and cursors are
  observations of the pinning transaction (KG5). `frontier_show` reads a
  pinned frontier by `frontier_id`. `external_source_cursors[]` items stay
  open — no item shape is spelled in §10.2.
- **KG25 — lens payloads.** `lens_create/update` supply the
  caller-suppliable §10.2 SpaceLens fields; `query_ast`, `sort_spec`, and
  `presentation_options` stay open objects (the closed query AST over
  indexed fields has no pinned grammar in this slice — KG7 pattern, inert
  and carrying no authority), and lens `visibility`/`status` are bounded
  tokens (KG6). `lens_read` pages the lens materialization under the §11.5
  page envelope with open items: the item shape is the lens's declarative
  presentation projection, and every item passes ordinary authorization
  item-by-item (§10.2/§10.4). The stored query cannot be substituted from
  the read request.
- **KG26 — context_assembly_create payloads.** The §11.6.1
  context-assembly-request row's inputs mapped onto §10.8 field names:
  required `{space_id, branch_id, audience_ref, purpose,
  selection_policy_ref}`, optional `{required_refs[], trigger_refs[],
  recipe_ref + recipe_revision}` (K1 uses the built-in `explicit_refs_v1`
  policy and needs no saved recipe, §10.8). `frontier_ref`/`frontier_digest`,
  the item/relation/transformation/omission lists, classification join,
  totals, versions, authority members, and the assembly digest are
  server-derived selection evidence (KG5); §10.8 spells that assembly fails
  rather than silently truncating. Worker binding `{attempt_id,
  fence_epoch}` per KG14; the SDK `operation_key` travels as
  `meta.idempotency_key` (KG15 pattern).
- **KG27 — reaction_set payload.** The §10.2 Reaction upsert keyed
  `UNIQUE(target_ref, actor_ref, key)`: args `{space_id, target_ref,
  target_revision, target_digest, key, state}` with the closed
  `present|removed` enum; `reaction_id`, `actor_ref`, `revision`, and
  `updated_at` are server-derived (KG5). `key` is a bounded token (no
  vocabulary pinned).
- **KG28 — event, wait, payload, and snapshot surfaces.** `events_read` and
  `events_wait` take the §11.4 arg lists verbatim — including
  `events_read`'s args-level `project_id?` — and their results embed the
  §11.3 event envelope per operation (ops schemas are self-contained, no
  cross-file `$ref`). `filters` stays an open object (no filter grammar is
  spelled) that narrows, never widens, the authorized set; `timeout_ms`
  carries no pinned ceiling. `event_payload` dereferences one stored
  payload by `event_id`; the derived result `{event_id, schema_ref,
  payload_digest, payload}` restates the envelope's payload members with
  the payload validated by its `schema_ref`. `snapshot_read` takes
  `{source, after?, limit, snapshot?}` — the §11.5 query members plus an
  events_read-style collection selector — and returns the §11.5 page with
  open items: each collection's typed projection is pinned by its own
  `*_list` result, so the generic snapshot item stays open and carries no
  authority.
- **KG29 — artifact upload payloads.** `artifact_upload_begin` args are the
  `declared_*` fields of the §10.10 ArtifactUpload plus optional
  `classification_ref`; `max_bytes`, expiry, and the staging key are
  server-derived from realm policy. Its result is the §10.10 spelled narrow
  canonical projection — "only the durable upload/artifact refs and
  constraints", never a credential. The non-mutating
  `artifact_upload_credential` read returns the derived fresh-credential
  shape `{upload_id, credential, max_bytes, audience, expires_at}` with an
  open provider-specific `credential` object that is never stored in a
  canonical result. `artifact_upload_show/finalize/abort` and
  `artifact_show` project the full records per KG4: the storage/authority
  members are durable references, never credentials (artifact ids are not
  bearer secrets and every fetch reauthorizes, §10.10).
  `declared_raw_sha256`/`raw_sha256` are ordinary raw checksum fields —
  §11.8 makes them a different field type from the typed digests, never
  interchangeable.
- **KG30 — immutable-record revisions.** Result projections follow KG4
  verbatim (unmarked fields required, `?`-marked optional); immutable
  records additionally pin `revision` const 1 per the §10 preamble ("every
  independently addressable immutable Kovee record carries fixed
  `revision: 1`") — Contribution, SpaceRelation, SpaceFrontier, and
  ContextAssembly.
