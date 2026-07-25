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
- **`schemas/`** — the five generic KCP envelope schemas (command, result,
  event, problem, hello — extraction notes in `schemas/README.md`). The
  per-operation command/result schema suite for the three K1 bundles is
  **not yet delivered**; it is remaining K0 work (see `plan/sheets/K0.md`).
- **`vectors/`** — golden envelope vectors: schema valid/invalid cases,
  acceptance boundary/negative cases for every §11.8 and family cap, and
  digest derivations aligned to C1 (typed artifact digest classes per
  amendment A5 — no retained plaintext `raw_sha256`). Independently
  re-derived by `xcheck/` (Python) and `tscheck/` (TypeScript) in CI. The
  per-operation negative matrices (wrong surface, wrong actor, dependency
  invalidation, replay) are **not yet delivered** — remaining K0 work with
  the per-operation schemas.
- **`adr/`** — architecture decision records ([index](adr/README.md)).
- **`family-lock.pin.json`** — the vendored family-lock pointer (plan D3):
  the pinned manifest binding kovee's spec surface to the byom/akson family
  contract.

Review records live in [`../reviews/`](../reviews/README.md).
