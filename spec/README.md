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
  registry (operation × surface × actor × AuthorizationDependencySet), plus
  — from K2 slice 1 (`registry_version` `k2-1`) — the greenfield-binding
  half of `governed_work_binding_v1` (`governance_enable/show/disable`),
  extracted from the frozen family-contract §2.A authority row. No
  superseded pre-amendment wire name survives; the bundle's remaining
  resolved names (`endeavor_promotion_*`, `byom_episode_binding_show`) stay
  reserved for K2 slice 2, so the bundle is incomplete and is not
  advertised by `hello`/`protocol_info` (§11.6: bundles are atomic). The
  registry is the source of all later counts.
- **`schemas/`** — the five generic KCP envelope schemas (command, result,
  event, problem, hello — extraction notes in `schemas/README.md`) plus
  the complete per-operation command/result suite for the three K1
  bundles and the K2 binding half under
  [`schemas/ops/`](schemas/ops/README.md) (gap notes KG1–KG33; both
  rederivers gate registry coverage of all 93 `(operation, surface)`
  entries).
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
| **A1** — `kovee-byom` is the one governance adapter crate, and there is never a second | Workspace members in `Cargo.toml`; decision recorded in [`adr/0001-workspace-conventions.md`](adr/0001-workspace-conventions.md) | Delivered (K0 scaffold) |
| **A1** — governance-owner rows retargeted to byom | Registry descriptive retargeting: the §11.6.1 worker-family fence cells read "byom fence when bound"; §9.2 category 21 frozen protocol-neutral as `external_visibility_proof` (`registry-README.md`) | Delivered |
| **A1** — `governed_work_binding_v1` keeps its name, implemented by the byom adapter; `ByomEpisodeBinding` is its own record, not an overloaded predecessor shape | Authority rows carry over in intent and freeze (exact actor/dependency/assurance) in the C2 bundle; adapter implementation is K2 | Future — C2 (contract), K2 (implementation) |
| **A2** — greenfield enablement saga (not a cutover; Kovee never the genesis governance actor) | Implemented at K2 slice 1: `KoveeRealmByomBinding` + `KoveeSocietyMapping` created inert, then `KoveeGovernanceOwnerBinding` CAS `none → byom` at the expected revision (`crates/koveed/src/governance.rs`), with every descriptor branch proven in `crates/koveed/tests/k2_greenfield.rs`, the commit-point crash matrix in `k2_binding_crash.rs`, and an end-to-end run against a real `byomd` in `k2_byomd_integration.rs`. The never-genesis rule is enforced by a byomd projection read and carried as trust-boundary tier 5 of the threat model | Delivered (binding half; formation half is K2 slice 2) |
| **A3** — naming (predecessor vocabulary→byom, `mission`→`endeavor`, `axon`→`akson`) | Grep sweep over `spec/`: **no superseded-era identifier survives in any machine-consumed file** — registry operation names (also machine-asserted by `registry_parity::no_superseded_era_operation_name_survives`), schemas, and vectors are clean. The only remaining spellings are where the record's job is to carry them: the verbatim §9.2 quote and the A5 pinned→resolved tables in `registry-README.md`, which map the frozen `DESIGN.md` text onto the live registry and would be false if rewritten while that text is pinned | Delivered |
| **A4** — ontology deltas Δ1–Δ6 (byom's architectural inversion) | None touches the three K1 bundles. Δ1 formation machines, Δ4 act-class subject taxonomy, and Δ5 `BriefingManifest` dissolution are C2 bundle items; Δ2 plan-as-lens and Δ3 wake inversion (`WakeIntent` → byom kernel admission → `placement_admit`) shape the K2 exit; Δ6 directory-as-evidence renders at K5 with C4/B5 trust-suspension machinery | Future — tracked to C2/K2 (Δ6: K5/C4) |
| **A5** — wire-operation renames | No rename applies to the three K1 bundles (every operation in the table belongs to `governed_work_binding_v1`). K2 slice 1 applies the first three: registry `a5_renames_applied` records `personal_governed_work_enable/show/disable` → `governance_enable/show/disable`; `endeavor_promotion_*` and `byom_episode_binding_show` stay reserved for slice 2. The parity test asserts no superseded operation name | Delivered for the K1 bundles and the K2 binding half; binding for the rest at the slice-2 extraction |
| **A5** — digest classes (no retained plaintext `raw_sha256`) | C1 family vectors (CI `family-vectors` job at the `family-lock.pin.json` row), including forbidden-substitution negatives; KG29 in `schemas/ops/README.md` keeps `declared_raw_sha256`/`raw_sha256` an ordinary upload-checksum field type never interchangeable with typed digests; `vectors/envelope/digest-typed-bytes-artifact.json` binds artifact authorization to the typed artifact-bytes digest | Delivered |
| **A5** — canonical CLI verb | `kovee governance enable --byom local [--society <id>]` — the wire operation `governance_enable` is live at K2 slice 1 and takes exactly this verb's arguments (`byom_endpoint_ref`, `society_ref`); the CLI surface itself is still reserved | Wire operation delivered; CLI verb reserved |
| **A9** (byom amendment, `design/2026-07-27-amendment-governance-owner-enum.md`) — the governance owner enum is `byom \| none` | Registry revision `k2-4`: `schemas/ops/governance-{show,enable,disable}-result.schema.json` narrow the owner enum; `kovee-byom`'s `GOVERNANCE_OWNERS` carries two arms and `owner_arm_is_coherent` rejects any other. byom publishes the narrowed record as the `kovee-governance-owner-binding-v2` successor schema with a negative vector proving the withdrawn arm is refused; v1 stays published unchanged | Delivered (K2 binding half) |
