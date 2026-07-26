# Operation registry — extraction notes (K0, extended at K2 slices 1-2)

`registry.json` is the machine-readable operation registry. It carries the
three K0-frozen K1 bundles — `core_v1`, `shared_space_v1`,
`developer_assistant_v1` — plus, from K2 slice 1, the greenfield-binding
half of `governed_work_binding_v1` and, from slice 2, its formation half. It resolves the pinned `DESIGN.md` §11.6
(feature-bundle command/query sets) and §11.6.1 (normative authority matrix)
together with amendment A5
(`design/2026-07-25-amendment-governance-owner.md`), and for the K2 rows the
**frozen `governance_enable` authority row** of the family contract §2.A
(`byom/design/2026-07-25-family-contract.md`). It is the source of all later
counts (K0 milestone sheet). Structural invariants — including the frozen
exact `(bundle, operation, surface)` set and every closed field enum — are
enforced by `crates/kovee-core/tests/registry_parity.rs`.

Registry version `k0-2` applies R0 findings KREG-01 (canonical dependency
tokens; `action_scope`/`constraints` fields) and KREG-02 (connector authority
split; connector redaction decision). The `k0-1` prose-valued
`dependency_categories` field no longer exists.

Registry version `k2-1` adds three entries and changes nothing else; the
K1 rows are byte-identical to `k0-2`. Its extraction is documented in
"K2 slice 1" below.

A minimal entry, and where each field comes from:

```json
{
  "operation": "contribution_append",            // §11.6 compact notation, expanded
  "bundle": "shared_space_v1",                   // §11.6 bundle table
  "surface": "external_client",                  // §11.6.1 row, before the slash
  "allowed_actor_kinds": ["principal", "mapped connector (…)"],
  "action_scope": ["exact action and space scope"],
  "dependency_categories": ["principal_status", "membership", "…"],
  "constraints": ["this family excludes project status and …"],
  "fence": "none",                               // §11.6.1 fence column
  "assurance": "current login (principal); workload identity (mapped connector)",
  "offline": "queueable",                        // §11.6.1 offline column
  "source": "DESIGN.md §11.6 (shared_space_v1 row) + §11.6.1 (family: …)"
}
```

## The closed §9.2 dependency-kind enum

DESIGN.md §9.2, verbatim:

> `kind` is a closed enum whose initial categories include principal status,
> authentication-binding security epoch, current authentication observation,
> service identity/capability, installation recovery epoch, realm status/kill
> epoch, project status/revision, target resource revision, membership, space
> access/participant binding, branch status/frontier, contribution/relation
> endpoint visibility, lens scope, attention revision/acceptance,
> context-item visibility, commitment terms/acceptance,
> classification/retention policy, remaining-use grant, Kovee policy set,
> realm authority binding, and external Sage visibility proof.

`dependency_categories` values are drawn from exactly these 21 categories,
tokenized (frozen in `registry.json` `dependency_category_tokens`, §9.2
order; the parity test carries an independent copy):

| # | §9.2 category (verbatim) | Token |
|---:|---|---|
| 1 | principal status | `principal_status` |
| 2 | authentication-binding security epoch | `authentication_binding_security_epoch` |
| 3 | current authentication observation | `current_authentication_observation` |
| 4 | service identity/capability | `service_identity_capability` |
| 5 | installation recovery epoch | `installation_recovery_epoch` |
| 6 | realm status/kill epoch | `realm_status_kill_epoch` |
| 7 | project status/revision | `project_status_revision` |
| 8 | target resource revision | `target_resource_revision` |
| 9 | membership | `membership` |
| 10 | space access/participant binding | `space_access_participant_binding` |
| 11 | branch status/frontier | `branch_status_frontier` |
| 12 | contribution/relation endpoint visibility | `contribution_relation_endpoint_visibility` |
| 13 | lens scope | `lens_scope` |
| 14 | attention revision/acceptance | `attention_revision_acceptance` |
| 15 | context-item visibility | `context_item_visibility` |
| 16 | commitment terms/acceptance | `commitment_terms_acceptance` |
| 17 | classification/retention policy | `classification_retention_policy` |
| 18 | remaining-use grant | `remaining_use_grant` |
| 19 | Kovee policy set | `kovee_policy_set` |
| 20 | realm authority binding | `realm_authority_binding` |
| 21 | external Sage visibility proof | `external_visibility_proof` |

Category 21: §9.2 (pinned) writes "external Sage visibility proof";
amendment A1 retargets every governance-authority Sage reference to byom,
and the §11.6.1 read row itself writes "external visibility proof" — the
token is frozen protocol-neutral as `external_visibility_proof`. This is the
A1 descriptive retargeting, not a new category.

The enum is design-wide. Tokens unused by these three bundles (e.g.
`authentication_binding_security_epoch`, `lens_scope`) become load-bearing
when later bundles (K2+) are extracted; the parity test validates membership,
not coverage.

## Extraction rules

1. **One entry per `(operation, surface)`** — §11.6.1: "No `(operation,
   authority_surface)` pair may match more than one clause." Operations
   exposed on two surfaces (e.g. `contribution_append` for principals and for
   fenced workers) get two entries with the same operation name.
2. **Compact notation expanded.** `space_create/show/list` in §11.6 is three
   closed operations, never a wildcard; `*_show`/`*_list` in §11.6.1 is
   "specification shorthand for an explicit generated row per operation" —
   the registry is that generation, for these three bundles only.
3. **Surfaces normalized to three tokens** for these bundles:
   `external_client` (§11.6.1 "external client", including the pre-auth
   channel for `hello`/public `protocol_info`), `operator`, and `worker`
   (§11.6.1 writes both "worker surface" and "worker SDK"; they are the same
   distinct surface per §11.6's administrative/worker surface split).
4. **The row's "Required action, scope, and dependencies" cell splits into
   three fields.**
   - `dependency_categories`: canonical §9.2 tokens **only** (the table
     above). Every phrase in the cell that names an authority input is
     interpreted against the closed enum via the mapping tables below; no
     token was invented.
   - `action_scope`: the required action, exact subject/scope material
     (digests, manifests, prepared subjects), and required non-category
     inputs — decision receipts, budgets/ceilings, disclosure, invocation
     manifests. §9.3's authorization order checks these at steps 5–6
     ("resource revision, grant, participant, classification, and retention
     policy"; "any required exact decision receipt, budget, or disclosure
     authorization") separately from the §9.2 category set, so they are not
     dependency-kind tokens.
   - `constraints`: pure constraint clauses, verbatim (e.g. "item-level
     policies remain intersected", "cannot name a worker as requester or
     create a Commitment"), plus recorded R0 decisions. They remain
     normative in DESIGN.md; the registry now carries them explicitly
     instead of hiding them inside a category list.
5. **`offline` uses three tokens**: `no`, `cached_draft_only` (row text "no
   mutation; cached draft only" for the read family), `queueable` (row text
   "only `contribution_append` and `reaction_set`").
6. **Row-internal qualifiers naming a specific operation are applied only to
   that operation's entry**; sibling entries take the family base value
   (fully listed under "Per-operation expansions" below).
7. **Token order is frozen**: each entry's `dependency_categories` list is
   sorted by §9.2 enum position, without duplicates. `dependency_categories`
   is empty only for the two pre-auth entries (`hello`, `protocol_info`),
   whose row names no authority input.

## Phrase-to-token mapping (rule 4, per family clause)

Each table row is a verbatim phrase from the family's "Required action,
scope, and dependencies" cell and its disposition. Phrases can both scope
the action and name a dependency; those appear in both columns.

**Pre-auth (`hello`, public `protocol_info`)** — "protocol negotiation only",
"bounded public installation metadata" → `action_scope`; no dependency
categories.

**`diagnose`** — "installation diagnostics/audit" → `action_scope`;
"principal" → `principal_status`; "auth observation" →
`current_authentication_observation`; "installation recovery epoch" →
`installation_recovery_epoch`; "realm and role where scoped" →
`realm_status_kill_epoch` + `membership`, with the "where scoped" qualifier
recorded as a constraint.

**Read family** — "exact resource read/resume action", "resume cursor where
applicable" → `action_scope`; "principal or service identity" →
`principal_status` + `service_identity_capability`; "realm/project/space" →
`realm_status_kill_epoch` + `project_status_revision` +
`space_access_participant_binding`; "membership and space access" →
`membership` + `space_access_participant_binding`; "target and endpoint
visibility" → `target_resource_revision` +
`contribution_relation_endpoint_visibility`; "classification/retention" →
`classification_retention_policy`; "external visibility proof where
applicable" → `external_visibility_proof` + a constraint carrying the
qualifier.

**Space-mutation family** — "exact action and space scope" → `action_scope`;
"identity" → `principal_status` (plus `service_identity_capability` on
connector-capable entries — see the connector section); "membership" →
`membership`; "space access" → `space_access_participant_binding`;
"branch/frontier" → `branch_status_frontier`; "target revision" →
`target_resource_revision`; "referenced-object visibility" →
`contribution_relation_endpoint_visibility`; "policy/classification" →
`kovee_policy_set` + `classification_retention_policy`; "this family
excludes project status and every prepared access-widening operation" →
`constraints`.

**`space_access_widen_prepare`/`_cancel`** — "exact Space revision" →
`target_resource_revision`; "prior/proposed visibility/policy/classification"
→ `action_scope` (the prepared subject) + `kovee_policy_set` +
`classification_retention_policy`; "affected frontier/item/audience digests"
→ `action_scope`; "current read/disclosure dependencies" → `membership` +
`space_access_participant_binding` +
`contribution_relation_endpoint_visibility` + `context_item_visibility` +
`classification_retention_policy`.

**`space_access_widen_confirm`** — "exact prepared widening subject",
"authorization decision receipt" → `action_scope`; "unchanged Space/item-set
revisions" → `target_resource_revision`; "item-level policies remain
intersected" → `constraints`.

**`project_access_policy_change_*`** — "exact Project revision" →
`project_status_revision`; "prior/proposed policy/default classification" →
`action_scope` + `kovee_policy_set` + `classification_retention_policy`;
"affected Space frontier/item/audience digests", "effective-change class" →
`action_scope`; "decision receipt for confirm" → `action_scope`
("authorization decision receipt") on the confirm entry only.

**Prepare/propose family** (`context_assembly_create`) — "exact
prepare/propose action", "subject digest" → `action_scope`;
"space/branch/context/terms revision" → `target_resource_revision` +
`branch_status_frontier` + `context_item_visibility` +
`commitment_terms_acceptance`. Worker entry adds the row's worker-binding
phrases ("current invocation", "fence", "assembly", "ceilings", "output
scope") to `action_scope` and `service_identity_capability` (the invocation
capability) to the categories.

**Operator decision family** (`space_participant_activate`) — "exact
prepared subject digest", "budget/disclosure union" → `action_scope`;
"current target acceptance" → `attention_revision_acceptance`;
"space/branch/frontier/terms revisions" → `target_resource_revision` +
`branch_status_frontier` + `commitment_terms_acceptance`; "use account" →
`remaining_use_grant`; "complete dependency set" → `constraints`.

**Operator administration family** (`space_access_grant_create/revoke`) —
"exact administrative/governance action", "prepared subject digest" →
`action_scope`; "complete identity" → `principal_status` +
`current_authentication_observation`; "realm/project/space" →
`realm_status_kill_epoch` + `project_status_revision` +
`space_access_participant_binding`; "membership/role" → `membership`;
"target revision" → `target_resource_revision`; "policy/grant/binding
dependencies" → `kovee_policy_set` + `classification_retention_policy` +
`remaining_use_grant` + `realm_authority_binding`; the family-exclusion
clause → `constraints`.

**Assistant author/deploy family** — "exact author/deploy action" →
`action_scope`; "identity" → `principal_status`; "realm/project" →
`realm_status_kill_epoch` + `project_status_revision`; "membership" →
`membership`; "target/config/policy revisions" → `target_resource_revision`
+ `kovee_policy_set`.

**Direct invocation** (`invocation_create`) — "exact manual/deployment-test
create action", "ContextAssembly/input manifest", "budget", "disclosure" →
`action_scope`; "full target deployment/revision" →
`target_resource_revision`; "ContextAssembly/input manifest" additionally →
`context_item_visibility`; "policy and authorization dependencies" →
`kovee_policy_set` + a completeness constraint; "it cannot name a worker as
requester or create a Commitment" → `constraints`.

**Cancel family** (`invocation_cancel`) — "ancestry", "cancellation scope" →
`action_scope`; "exact current invocation/commitment/realization revisions"
→ `target_resource_revision`; "terms" → `commitment_terms_acceptance`.
Worker entry adds "parent attempt binding", "inherited ceilings" to
`action_scope` and `service_identity_capability` to the categories.

**Worker-operations family** — "exact operation and space/object scope
listed in the invocation capability", "invocation manifest", "attempt",
"budget" → `action_scope`; "attempt" (the instance identity + invocation
capability) → `service_identity_capability`; "deployment/config" →
`target_resource_revision`; "branch/context" → `branch_status_frontier` +
`context_item_visibility`; "policy and authorization dependencies" →
`kovee_policy_set` + a completeness constraint.

## Connector authority (R0 KREG-02)

§9.1: "Connectors use a dedicated service identity and installation scope,
not the installing human's reusable credential." A `current login` assurance
therefore cannot authorize a connector actor. The registry encodes the split
explicitly:

- **Reads** keep the §11.6.1 row's own alternation, `current login or
  workload identity` — principal via login, connector service via workload
  identity, resource-scoped by "only for its mapped resources".
- **Connector-capable mutations** (`contribution_append`,
  `contribution_withdraw`, `contribution_supersede`, `reaction_set`,
  `artifact_upload_begin`, `artifact_upload_finalize`,
  `artifact_upload_abort` — 7 entries) carry the split assurance value
  `current login (principal); workload identity (mapped connector)`: each
  clause binds its actor kind, never the other. These entries also carry
  `service_identity_capability` in `dependency_categories` — the mapped
  connector's dedicated service identity is an authority input.
- **Connector redaction is disallowed pending a design amendment**
  (R0 KREG-02 decision). `contribution_redact`'s assurance is "current
  login; policy may require step-up" and §11.6.1 defines no non-human
  step-up, so a connector cannot satisfy a step-up-capable redact clause.
  The `contribution_redact` entry lists only the `principal` actor kind and
  records the decision in `constraints`. Re-admitting connectors to redact
  requires a design amendment defining non-human step-up semantics.

The parity test enforces the split in both directions: every entry naming
the mapped-connector actor carries the split assurance and
`service_identity_capability`, and every entry carrying the split assurance
names the mapped-connector actor; `contribution_redact` must not name it.

## Closed field enums (validated by the parity test)

- `surface`: `external_client` | `operator` | `worker`.
- `offline`: `no` | `cached_draft_only` | `queueable`.
- `dependency_categories[]`: the 21 tokens above, §9.2 order, no duplicates.
- `allowed_actor_kinds[]` and `assurance`: closed lists of the exact strings
  used by the 90 entries, frozen in `registry_parity.rs`. A new actor kind
  or assurance wording is a deliberate registry revision, not drift.

## A5 resolution

Amendment A5's wire-name table was checked against every operation extracted:

- `personal_governed_work_enable/show/disable` → `governance_enable/show/disable`
- `mission_promotion_prepare/start/show/cancel/reconcile` → `endeavor_promotion_*`
- `sage_turn_binding_show` → `byom_episode_binding_show`

Every left-hand operation belongs to `governed_work_binding_v1` (§11.6), so
no rename applied to the three K1 bundles. **K2 slice 1 applies the first
three**, and `a5_renames_applied` in `registry.json` now records exactly
those three pairs. The remaining left-hand names — and the unchanged-name
rows (`collaboration_context_bundle_prepare/show`, `workspace_*`) — belong to
the bundle's formation half and are reserved for K2 slice 2. No operation
name in this registry contains `sage` or `mission` (asserted by the parity
test), so no Sage-era wire name survives.

Amendment **A1** (byom is the sole governance owner) does touch two
descriptive fields: the §11.6.1 fence cells "Sage fence when bound" (worker
cancel family, worker-operations family) are recorded as "byom fence when
bound". This is a retargeting of descriptive prose, not a wire rename.

## Ambiguities hit, and how each was resolved

1. **`diagnose` assurance.** Its §11.6.1 row (`diagnose`, `audit_export`)
   gives only "step-up for export". Export is `audit_export`
   (`installation_admin_v1`, K3). Resolved: `diagnose` takes the
   authenticated-operator default `current login`; the step-up clause binds
   `audit_export` when K3 is extracted.
2. **`project_access_policy_change_prepare/cancel` assurance.** The row
   specifies only "risk-required step-up for confirm". Resolved: prepare and
   cancel take `current login`, consistent with the space-access-widening
   prepare/cancel row; `confirm` alone carries the step-up and the
   "decision receipt" scope material ("decision receipt for confirm").
3. **Which operations get `worker`-surface entries.** §11.6.1's worker row
   names families ("checkpoint/contribution/semantic-relation/model/tool/
   `application_event_emit` worker operations"), not exact K1 operations.
   Resolved against §14.1's closed mediated SDK surface: `ctx.contribute` →
   `contribution_append`, `ctx.relate` → `relation_assert` (assert only —
   §14.1 grants no worker withdraw/supersede/redact/retract),
   `ctx.events.emit` → `application_event_emit`, `ctx.assemble_context` →
   `context_assembly_create` (via the preparation family's "context assembly
   request" + "fenced worker" clause). Checkpoint recording and model/tool
   worker operations have no wire operation in these three bundles
   (`checkpoint_show` etc. are K2+). `invocation_cancel` gets a worker entry
   from its own row's explicit "worker SDK only for its exact child
   invocation" clause. Per §11.6.1, an operation missing a worker entry is
   not callable on the worker surface.
4. **Connector actors are not a surface.** "connector service only for its
   mapped resources" (read family) and "mapped connector only for
   contribution/reaction/upload operations granted to it" (space-mutation
   family) appear after the slash in the surface/actor cell and no distinct
   connector surface exists anywhere in the matrix. Resolved: they are actor
   kinds on `external_client`. The mapped-connector actor is carried on all
   contribution mutations **except `contribution_redact`** (KREG-02
   decision above), on `reaction_set`, and on the three artifact-upload
   mutations (the row scopes it by family word, with "granted to it"
   carrying the per-grant restriction), and on every read entry
   (resource-scoped by "its mapped resources").
5. **`space_participant_activate` splits from its §11.6 group.**
   "participant proposal/update/removal" is in the external-client
   space-mutation family, but "participant activation" is listed in the
   operator decision family ("attention accept/…; participant activation").
   Resolved: `add/update/remove` → `external_client`; `activate` →
   `operator` with the decision family's actor/fence/assurance.
6. **`space_access_grant_create/revoke` are operator administration.**
   "space-access-grant administration" appears in the operator/principal-only
   administration family, while `space_access_grant_list` falls under the
   generated `*_list` read row. Resolved accordingly (create/revoke:
   `operator`, risk-required step-up; list: `external_client` read).
7. **`protocol_info` exists only as the public pre-auth entry** ("public
   `protocol_info`" in the matrix). No authenticated variant is listed, and
   an operation missing an entry is not callable, so exactly one entry.
8. **`invocation_create` actor kinds.** Its row reads "external client /
   authenticated principal/operator only" — `operator` here is an actor
   role on the external client surface (the surface precedes the slash), so
   `allowed_actor_kinds` is `["authenticated principal", "authenticated
   operator"]` on `surface: external_client`.
9. **Split fence/assurance in dual-surface rows.** Cells like "current
   attempt fence for worker-originated proposals" and "current login or
   worker capability" qualify the worker clause only. Resolved: the
   external-client entry takes `fence: none` / `assurance: current login`;
   the worker entry takes the attempt fence / capability assurance, and the
   worker-only binding phrases ("worker proposals bind current invocation,
   fence, assembly, ceilings, and output scope"; "worker cancellation binds
   the parent attempt and inherited ceilings") appear only on the worker
   entry's `action_scope`.
10. **`core_v1`'s non-operation items.** "envelopes, problems, idempotency,
    revisions, cursors" in the §11.6 `core_v1` cell are envelope semantics,
    not callable operations — no entries.
11. **Decision receipts and budgets are not dependency-kind tokens.** The
    §9.2 closed enum names no decision-receipt or budget category; §9.3
    checks them at authorization steps 5–6 as their own inputs. Rows naming
    them ("authorization decision receipt", "budget", "budget/disclosure
    union", "inherited ceilings") keep those phrases in `action_scope`.

## Per-operation expansions (rule 6 applied)

| Entry | Deviation from family base |
|---|---|
| `contribution_redact` | assurance "current login; policy may require step-up"; principal-only (KREG-02 decision) |
| `contribution_append`, `reaction_set` (external) | offline `queueable` |
| `space_access_widen_prepare` | assurance "current login; policy may require step-up" (row: "step-up to prepare") |
| `project_access_policy_change_confirm` | assurance "risk-required step-up"; + "authorization decision receipt" in `action_scope` |
| `deployment_activate` | assurance "current login; step-up for production activation" (the row's "rollback" half binds `deployment_update/rollout`, K2) |

## K2 slice 1 — the `governed_work_binding_v1` binding half

Three entries, extracted from ONE source: the **frozen
`governance_enable` authority row** stated field-complete in the family
contract §2.A, read together with the D10 saga
(`byom/spec/governed-work/greenfield-saga.md`) and the machine committed in
`byom/spec/descriptors/greenfield-enablement.json`. The row covers all three
operations ("`governance_enable` (and `governance_show` read;
`governance_disable` with step-up)"), so all three entries inherit its actor,
dependency set, and scope material; only the assurance and fence cells split
per operation.

**Bundle completeness.** These three operations are the binding half only;
the formation half arrives with slice 2 (below). Because §11.6 makes bundles
atomic, `governed_work_binding_v1` is deliberately **not advertised** by
`hello`/`protocol_info` until every one of its operations is callable;
`crates/koveed/tests/k1_bundles.rs::the_incomplete_k2_bundle_is_not_advertised_but_its_operations_dispatch`
asserts both halves of that statement.

### Surface (rule 3 applied)

The frozen row's surface cell reads "KCP admin (personal: owner principal
over the UID-checked local socket; team: realm `owner` role over the
authenticated gateway)". The registry's closed surface enum has no `admin`
token; "KCP admin" normalizes to **`operator`**, exactly as resolutions 5/6
already do for `space_participant_activate` and
`space_access_grant_create/revoke` — in the personal profile an operator
entry binds to the owner principal over the client socket. All three
entries take `operator`, including the `governance_show` read: the frozen row
scopes the whole family to the admin surface, so `governance_show` does not
fall into the generated `*_show` read family.

### Phrase-to-token mapping (rule 4, from the frozen row)

The row's "Authorization dependency set" cell, phrase by phrase:

| Frozen-row phrase | Disposition |
|---|---|
| "realm revision" | `realm_status_kill_epoch` |
| "target `society_ref` + Society recovery epoch" | `external_visibility_proof` (the byomd projection read that proves the Society exists and is active) + `action_scope` |
| "byomd endpoint identity/incarnation" | `external_visibility_proof` + `action_scope` |
| "expected absent-or-identical `KoveeRealmByomBinding`" | `realm_authority_binding` (§9.2 category 20 — the `RealmAuthorityBinding` this record implements, family contract L2) + `action_scope` |
| "`KoveeSocietyMapping` revision" | `target_resource_revision` + `action_scope` |
| "a human realm-owner principal only …" (Allowed actor) | `principal_status` + `constraints` (verbatim) |
| "fresh step-up/challenge …; explicit confirmation …" (Assurance) | `current_authentication_observation` + the `assurance` cell |
| "Subject digest" cell (the exact digest the confirming human sees) | `action_scope` |
| "Service authority: recovery-only …" | `constraints` (verbatim) |

Token order is the frozen §9.2 order, as everywhere else:
`principal_status`, `current_authentication_observation`,
`realm_status_kill_epoch`, `target_resource_revision`,
`realm_authority_binding`, `external_visibility_proof`.

### New closed-enum values (frozen in `registry_parity.rs`)

| Field | New value | Source |
|---|---|---|
| `allowed_actor_kinds[]` | `human realm-owner principal only` | Allowed-actor cell, condensed; the "never a service identity, session, assistant, or connector" half is carried verbatim in `constraints` |
| `assurance` | `explicit confirmation in personal mode; fresh step-up/challenge in team mode` | Assurance cell (enable) |
| `assurance` | `always step-up` | Assurance cell ("`governance_disable` always step-up") |

`governance_show` takes the authenticated-operator default `current login`:
the frozen row names no separate read assurance, resolved as for `diagnose`
(ambiguity 1 above).

### Ambiguities hit, and how each was resolved

1. **Which surface token.** Resolved above: `operator`, by rule 3 plus
   resolutions 5/6.
2. **`governance_show`'s assurance.** The row states assurance for enable and
   disable only. Resolved: `current login`, the same default `diagnose` takes.
3. **Personal-mode "explicit confirmation".** The personal profile has no
   second factor to step up to. Resolved honestly rather than by claiming
   one: `governance_enable`'s `confirmed_subject_digest` argument is
   **optional** — the UID-checked owner channel is itself the explicit
   confirmation — and, when supplied, must equal the server-recomputed
   subject digest exactly; `governance_disable`'s is **required**, because
   its assurance cell is unconditional step-up. The developer assurance
   profile labels this for what it is; a real step-up arrives with K3's team
   mode.
4. **The Society facts are not arguments.** "target `society_ref` + Society
   recovery epoch" and "byomd endpoint identity/incarnation" are dependency
   inputs, not caller assertions. Resolved: only `society_ref` and
   `byom_endpoint_ref` are wire arguments; the recovery epoch and the
   endpoint incarnation are read from byomd's projection surface and
   server-recomputed. The `governance-enable-invalid-wrong-surface-args`
   vector pins that.
5. **Selector grammar.** byom pins only the bounded opaque wire shape of a
   scope selector (≤256 visible-ASCII bytes); the grammar
   (`realm | project:<id|*>[/space:<id|*>]`) and the overlap predicate the
   no-overlapping-active-owner rule needs are Kovee-owned and live in
   `kovee_byom::scope`, not in the registry.
6. **`governance_enable_rollback` is not a wire operation.** The descriptor
   names it as a transition; §11.6 names no such operation and A5's rename
   table does not list one. Resolved: it is the saga's own definite pre-CAS
   failure handling, invoked internally by `governance_enable` when the
   pre-CAS re-verification gets a DEFINITE contradiction, and it is not
   callable. No registry row exists for it.

## K2 slice 2 — the `governed_work_binding_v1` formation half

Six entries, extracted from byom DESIGN.md §16.3 (the
`EndeavorFormationIntent`/`Slot`/`Attempt` machine, the
`KoveeEndeavorFormCommand` stable-command/fresh-attempt split, and the
five-fact `ExternalCommandResultQuery` union) and §16.6 item 3
(`ByomEpisodeBinding`), read against the Kovee-owned descriptors
`byom/spec/descriptors/endeavor-formation.json` and
`byom/spec/descriptors/byom-episode-binding.json`.

### A5 wire names (rule 1 applied)

| Pinned in §11.6 | Resolved wire name |
|---|---|
| `mission_promotion_prepare` | `endeavor_promotion_prepare` |
| `mission_promotion_start` | `endeavor_promotion_start` |
| `mission_promotion_show` | `endeavor_promotion_show` |
| `mission_promotion_cancel` | `endeavor_promotion_cancel` |
| `mission_promotion_reconcile` | `endeavor_promotion_reconcile` |
| `sage_turn_binding_show` | `byom_episode_binding_show` |

Amendment A1 retargets the governance owner from Sage to byom, so the
Sage-named row becomes the byom-named one; there is no `sage_*` operation in
this stack.

### Surface and placement

Same "KCP admin" → `operator` normalization as slice 1 (resolutions 5/6). All
six are **realm-scoped and project-free**: a promotion's project, space, and
branch are read from the pinned `SpaceFrontier`, never from the envelope, so
one command cannot name one project and pin another's frontier.

### Resolutions this slice adds

7. **No operation for the `byom_subordinate` reservation saga.** §16.6 item 4
   names the reservation set and the reserve/query/settle/uncertain/release
   steps, but the byom kernel initiates it internally at
   `resource_allocate`, and §11.4 is explicit that Kovee platform capacity
   lives under another owner and is never part of the byom transaction.
   Resolved: Kovee executes the saga as a host transaction inside the episode
   pipeline; there is deliberately **no KCP row** for it, and none for
   `placement_admit`/`episode_*` either (those are byom runtime-surface
   operations Kovee CALLS, not operations it serves).
8. **One assurance cell for `endeavor_promotion_reconcile`.** The recovery
   query alone would be `current login`, but the same entry may drive
   `external_command_terminalize`, which is always step-up with a fresh
   challenge. A registry entry carries ONE assurance cell, so the row takes
   the stronger of the two and the split is stated in its constraints.

### Bundle completeness (still incomplete)

The bundle's remaining operations —
`collaboration_context_bundle_prepare/show`,
`workspace_provider_manifest_show/list`, and
`workspace_allocation_binding_show` — have **no entry here**, so
`governed_work_binding_v1` is still not advertised. The formation half's own
operations are live and dispatch.

## Counts (frozen)

| Bundle | Operations | Entries (operation × surface) |
|---|---:|---:|
| `core_v1` | 3 | 3 |
| `shared_space_v1` | 62 | 65 |
| `developer_assistant_v1` | 21 | 22 |
| `governed_work_binding_v1` (binding + formation halves; K2 slices 1-2) | 9 | 9 |
| **Total** | **95** | **99** |

Dual-surface operations: `contribution_append`, `relation_assert`,
`context_assembly_create` (external + worker), `invocation_cancel`
(external + worker). The nine K2 entries are single-surface.
