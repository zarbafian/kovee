# Specification

The normative, machine-checkable extraction of [DESIGN.md](../DESIGN.md)
with amendments A1–A5 (`design/2026-07-25-amendment-governance-owner.md`)
folded in. For material extracted here, the [Amendment
resolution](#amendment-resolution) below is the record of where each
amendment item landed; for design material not yet extracted (the K2+
bundles), the amendment record continues to override the design text
wherever they conflict.

What lives here (per the K0 milestone sheet, `plan/sheets/K0.md`):

- **The operation registry** (`registry.json`, extraction notes in
  [`registry-README.md`](registry-README.md)) — the pinned §11.6 `core_v1`, `shared_space_v1`,
  and `developer_assistant_v1` command/query sets and the minimal worker
  protocol, resolved together with amendment A5's wire-name table into one
  registry (operation × surface × actor × AuthorizationDependencySet). No
  superseded pre-amendment wire name survives; the resolved names
  (`governance_enable/show/disable`, `endeavor_promotion_*`,
  `byom_episode_binding_show`) are reserved for the K2 bundle. The
  K0-frozen registry is the source of all later counts.
- **`schemas/`** — the five generic KCP envelope schemas (command, result,
  event, problem, hello — extraction notes in `schemas/README.md`) plus
  the complete per-operation command/result suite for the three K1
  bundles under [`schemas/ops/`](schemas/ops/README.md) (gap notes
  KG1–KG30; both rederivers gate registry coverage of all 90
  `(operation, surface)` entries).
- **`vectors/`** — golden vectors: envelope schema valid/invalid cases,
  acceptance boundary/negative cases for every §11.8 and family cap,
  digest derivations aligned to C1 (typed artifact digest classes per
  amendment A5 — no retained plaintext `raw_sha256`), and the `ops/`
  family: per-operation valid instances plus the negative matrices
  (wrong-surface args, missing-required, replay/dependency-invalidation
  shapes). Independently re-derived by `xcheck/` (Python) and `tscheck/`
  (TypeScript) in CI.
- **`adr/`** — architecture decision records ([index](adr/README.md)).
- **`family-lock.pin.json`** — the vendored family-lock pointer (plan D3):
  the pinned manifest binding kovee's spec surface to the byom/akson family
  contract.

The K0 threat model — byom as governance owner throughout — lives at
[`../design/2026-07-26-threat-model.md`](../design/2026-07-26-threat-model.md).
Review records live in [`../reviews/`](../reviews/README.md).

## Amendment resolution

The extracted spec — `registry.json`, `schemas/`, `vectors/` — **resolves**
the pinned `DESIGN.md` (sha256 `40820c…`, as pinned by the amendment
record) together with amendments A1–A5. Each amendment item below names
where it is realized; where an item is future work, the owning milestone
is stated plainly and nothing is claimed as delivered.

| Amendment item | Where realized | Status |
|---|---|---|
| **A1** — `kovee-byom` is the adapter crate; no `kovee-sage`, ever | Workspace members in `Cargo.toml`; decision recorded in [`adr/0001-workspace-conventions.md`](adr/0001-workspace-conventions.md) | Delivered (K0 scaffold) |
| **A1** — governance-owner rows retargeted to byom | Registry descriptive retargeting: the §11.6.1 worker-family fence cells read "byom fence when bound"; §9.2 category 21 frozen protocol-neutral as `external_visibility_proof` (`registry-README.md`) | Delivered |
| **A1** — `governed_work_binding_v1` keeps its name, implemented by the byom adapter; `ByomEpisodeBinding` supersedes `SageTurnBinding` | Authority rows carry over in intent and freeze (exact actor/dependency/assurance) in the C2 bundle; adapter implementation is K2 | Future — C2 (contract), K2 (implementation) |
| **A2** — greenfield enablement saga (not a cutover; Kovee never the genesis governance actor) | C2 bundle: `KoveeRealmByomBinding` + `KoveeSocietyMapping`, CAS `KoveeGovernanceOwnerBinding` `none → byom` with exact-CAS/retry/overlapping-scope/rollback/restore proofs, and the frozen KCP authority-registry row for greenfield enablement; runs at K2. The never-genesis rule is carried as trust-boundary tier 5 of the threat model | Future — tracked to C2 (contract), K2 (implementation) |
| **A3** — naming (`sage`→byom vocabulary, `mission`→`endeavor`, `axon`→`akson`) | Grep sweep over `spec/`: **no `sage`/`mission_`/`axon` identifier survives in any machine-consumed file** — registry operation names (also machine-asserted by `registry_parity::no_sage_era_operation_name_survives`), schemas, and vectors are clean. Remaining prose mentions are the superseded-name references in this resolution table itself, the verbatim §9.2 quote and the A5 rename-resolution record in `registry-README.md`, and ADR-0001's decision context — historical statements about the superseded design text, not live identifiers | Delivered |
| **A4** — ontology deltas Δ1–Δ6 (byom's architectural inversion) | None touches the three K1 bundles. Δ1 formation machines, Δ4 act-class subject taxonomy, and Δ5 `BriefingManifest` dissolution are C2 bundle items; Δ2 plan-as-lens and Δ3 wake inversion (`WakeIntent` → byom kernel admission → `placement_admit`) shape the K2 exit; Δ6 directory-as-evidence renders at K5 with C4/B5 trust-suspension machinery | Future — tracked to C2/K2 (Δ6: K5/C4) |
| **A5** — wire-operation renames | Registry `a5_renames_applied` is empty with the reason recorded in `a5_note` and `registry-README.md`: every operation in the rename table belongs to `governed_work_binding_v1` (K2), so no rename applies to the K1 bundles; the resolved K2 names (`governance_enable/show/disable`, `endeavor_promotion_*`, `byom_episode_binding_show`) are reserved; the parity test asserts no superseded operation name | Delivered for the K1 bundles (vacuously); binding at the K2 bundle extraction |
| **A5** — digest classes (no retained plaintext `raw_sha256`) | C1 family vectors (CI `family-vectors` job at the `family-lock.pin.json` row), including forbidden-substitution negatives; KG29 in `schemas/ops/README.md` keeps `declared_raw_sha256`/`raw_sha256` an ordinary upload-checksum field type never interchangeable with typed digests; `vectors/envelope/digest-typed-bytes-artifact.json` binds artifact authorization to the typed artifact-bytes digest | Delivered |
| **A5** — canonical CLI verb | `kovee governance enable --byom local [--society <id>]` — reserved verbatim for the K2 CLI schema, bound to C2's frozen enablement registry row | Future — reserved for K2 |
