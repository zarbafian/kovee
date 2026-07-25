# Per-operation schemas — K0 slice 1 (`core_v1`, `developer_assistant_v1`)

One closed request and one closed result schema per operation
(`<op>-request.schema.json`, `<op>-result.schema.json`; the result schema is
the `CommandResult.result` payload of the §11.2 ok arm — the envelope's
`revision`/`event_cursor` members live outside it). This is the first slice
of the per-operation suite named as remaining K0 work in `plan/sheets/K0.md`;
the `shared_space_v1` slice extends this directory and the runners'
`COVERED_BUNDLES` lists when it lands.

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
