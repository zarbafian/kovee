# Operation registry — extraction notes (K0)

`registry.json` is the K0-frozen machine-readable operation registry for the
three K1 bundles: `core_v1`, `shared_space_v1`, `developer_assistant_v1`.
It resolves the pinned `DESIGN.md` §11.6 (feature-bundle command/query sets)
and §11.6.1 (normative authority matrix) together with amendment A5
(`design/2026-07-25-amendment-governance-owner.md`). It is the source of all
later counts (K0 milestone sheet). Structural invariants are enforced by
`crates/kovee-core/tests/registry_parity.rs`.

A minimal entry, and where each field comes from:

```json
{
  "operation": "contribution_append",            // §11.6 compact notation, expanded
  "bundle": "shared_space_v1",                   // §11.6 bundle table
  "surface": "external_client",                  // §11.6.1 row, before the slash
  "allowed_actor_kinds": ["principal", "mapped connector (…)"],
  "dependency_categories": ["exact action and space scope", "identity", "…"],
  "fence": "none",                               // §11.6.1 fence column
  "assurance": "current login",                  // §11.6.1 assurance column
  "offline": "queueable",                        // §11.6.1 offline column
  "source": "DESIGN.md §11.6 (shared_space_v1 row) + §11.6.1 (family: …)"
}
```

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
4. **`dependency_categories` are verbatim phrase splits** of the row's
   "Required action, scope, and dependencies" cell, interpreted against the
   §9.2 closed `AuthorizationDependencySet` category enum. No category token
   was invented. Pure constraint clauses in that cell that are not
   dependencies (e.g. "it cannot name a worker as requester or create a
   Commitment" for direct invocation, "this family excludes project status
   and every prepared access-widening operation") stay normative in
   DESIGN.md and are reachable through the entry's `source`; they are not
   registry fields.
5. **`offline` uses three tokens**: `no`, `cached_draft_only` (row text "no
   mutation; cached draft only" for the read family), `queueable` (row text
   "only `contribution_append` and `reaction_set`").
6. **Row-internal qualifiers naming a specific operation are applied only to
   that operation's entry**; sibling entries take the family base value
   (fully listed under "Per-operation expansions" below).

## A5 resolution: no rename applied in these bundles

Amendment A5's wire-name table was checked against every operation extracted:

- `personal_governed_work_enable/show/disable` → `governance_enable/show/disable`
- `mission_promotion_prepare/start/show/cancel/reconcile` → `endeavor_promotion_*`
- `sage_turn_binding_show` → `byom_episode_binding_show`

Every left-hand operation belongs to `governed_work_binding_v1` (K2, §11.6),
which is **not** one of the three K1 bundles, so `a5_renames_applied` in
`registry.json` is empty. The unchanged-name rows of the A5 table
(`collaboration_context_bundle_prepare/show`, `workspace_*`) are also all in
`governed_work_binding_v1`. Consequently no operation name in this registry
contains `sage` or `mission` (asserted by the parity test), and no Sage-era
wire name survives — vacuously for this registry, normatively once the K2
bundle is extracted.

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
   "decision receipt" dependency ("decision receipt for confirm").
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
   contribution mutations, `reaction_set`, and the three artifact-upload
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
   worker-only dependency phrases ("worker proposals bind current
   invocation, fence, assembly, ceilings, and output scope"; "worker
   cancellation binds the parent attempt and inherited ceilings") appear
   only on the worker entry.
10. **`core_v1`'s non-operation items.** "envelopes, problems, idempotency,
    revisions, cursors" in the §11.6 `core_v1` cell are envelope semantics,
    not callable operations — no entries.

## Per-operation expansions (rule 6 applied)

| Entry | Deviation from family base |
|---|---|
| `contribution_redact` | assurance "current login; policy may require step-up" |
| `contribution_append`, `reaction_set` (external) | offline `queueable` |
| `space_access_widen_prepare` | assurance "current login; policy may require step-up" (row: "step-up to prepare") |
| `project_access_policy_change_confirm` | assurance "risk-required step-up"; + "decision receipt" dependency |
| `deployment_activate` | assurance "current login; step-up for production activation" (the row's "rollback" half binds `deployment_update/rollout`, K2) |

## Counts (frozen)

| Bundle | Operations | Entries (operation × surface) |
|---|---:|---:|
| `core_v1` | 3 | 3 |
| `shared_space_v1` | 62 | 65 |
| `developer_assistant_v1` | 21 | 22 |
| **Total** | **86** | **90** |

Dual-surface operations: `contribution_append`, `relation_assert`,
`context_assembly_create` (external + worker), `invocation_cancel`
(external + worker).
