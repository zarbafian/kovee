# Specification

The normative, machine-checkable extraction of [DESIGN.md](../DESIGN.md) with
amendments A1–A5 (`design/2026-07-25-amendment-governance-owner.md`) folded
in. Until that extraction is complete, the amendment record overrides the
design text wherever they conflict.

What lives here (per the K0 milestone sheet, `plan/sheets/K0.md`):

- **The operation registry** (`registry.json`, extraction notes in
  [`registry-README.md`](registry-README.md)) — the pinned §11.6 `core_v1`, `shared_space_v1`,
  and `developer_assistant_v1` command/query sets and the minimal worker
  protocol, resolved together with amendment A5's wire-name table into one
  registry (operation × surface × actor × AuthorizationDependencySet). No
  Sage-era wire name survives: `governance_enable/show/disable`,
  `endeavor_promotion_*`, `byom_episode_binding_show`. The K0-frozen
  registry is the source of all later counts.
- **`schemas/`** — JSON Schemas for every command, result, event, problem,
  record, and manifest in the K1 bundles.
- **`vectors/`** — golden vectors and per-operation negative vectors (wrong
  surface, wrong actor, dependency invalidation, replay); limits/errors/
  digest vectors aligned to C1 (typed artifact digest classes per amendment
  A5 — no retained plaintext `raw_sha256`). Independently re-derived by
  `xcheck/` (Python) and `tscheck/` (TypeScript) in CI.
- **`adr/`** — architecture decision records ([index](adr/README.md)).
- **`family-lock.pin.json`** — the vendored family-lock pointer (plan D3):
  the pinned manifest binding kovee's spec surface to the byom/akson family
  contract.

Review records live in [`../reviews/`](../reviews/README.md).
