# Specification

The normative, machine-checkable extraction of [DESIGN.md](../DESIGN.md)
with amendments A1–A5 (`design/2026-07-25-amendment-governance-owner.md`)
and A9 (`design/2026-07-27-amendment-governance-owner-enum.md`) folded in.
For material extracted here, the [Amendment
resolution](#amendment-resolution) below is the record of where each
amendment item landed; for design material not yet extracted (the
unextracted remainder of `governed_work_binding_v1` and the K3+ bundles),
the amendment record continues to override the design text wherever they
conflict.

Two DESIGN.md digests are in play, deliberately. The amendment record
amends sha256 `40820c…` — the byte-frozen ratified v0.1 that the family
contract and the implementation plan still pin — and the resolution table
below reads against that text. The `DESIGN.md` in this tree is v0.1.2
(sha256 `22c469…`, lock row `kovee-design-v0.1.2`), which folds A1/A3/A5
and A9 into the prose with no scope change.

What lives here (per the K0 milestone sheet, `plan/sheets/K0.md`, extended
by the K2 slices):

- **The operation registry** (`registry.json`, extraction notes in
  [`registry-README.md`](registry-README.md)) — the pinned §11.6 `core_v1`, `shared_space_v1`,
  and `developer_assistant_v1` command/query sets and the minimal worker
  protocol, resolved together with amendment A5's wire-name table into one
  registry (operation × surface × actor × AuthorizationDependencySet), plus
  the K2 extensions. At `registry_version` `k2-4` it carries **96
  operations over 100 `(operation, surface)` entries** in four bundles: the
  three complete K1 bundles, and `governed_work_binding_v1` at 9 of its 14
  operations — the greenfield-binding half from slice 1
  (`governance_enable/show/disable`, extracted from the frozen
  family-contract §2.A authority row) and the formation half from slice 2
  (`endeavor_promotion_prepare/start/show/cancel/reconcile`,
  `byom_episode_binding_show`). `k2-3` added the `developer_assistant_v1`
  worker row `model_complete` for the K2 model broker; `k2-4` changed no
  entry and records amendment A9's schema narrowing. No superseded
  pre-amendment wire name survives, and all nine A5 renames are applied.
  The bundle's five remaining operations —
  `collaboration_context_bundle_prepare/show`,
  `workspace_provider_manifest_show/list` and
  `workspace_allocation_binding_show` — are unbuilt, so
  `governed_work_binding_v1` is still not advertised by
  `hello`/`protocol_info` (§11.6: bundles are atomic) even though its nine
  operations dispatch. The registry is the source of all later counts.
- **`schemas/`** — the five generic KCP envelope schemas (command, result,
  event, problem, hello — extraction notes in `schemas/README.md`) plus
  the complete per-operation command/result suite for the three K1
  bundles (including the K2-added `model_complete` worker row) and the nine
  `governed_work_binding_v1` operations under
  [`schemas/ops/`](schemas/ops/README.md) (gap notes KG1–KG33; both
  rederivers gate registry coverage of all 100 `(operation, surface)`
  entries, 197 schemas in total).
- **`vectors/`** — golden vectors: envelope schema valid/invalid cases,
  acceptance boundary/negative cases for every §11.8 and family cap,
  digest derivations aligned to C1 (typed artifact digest classes per
  amendment A5 — no retained plaintext `raw_sha256`), and the `ops/`
  family: per-operation valid instances plus the negative matrices
  (wrong-surface args, missing-required, replay/dependency-invalidation
  shapes). 415 vectors, independently re-derived by `xcheck/` (Python) and
  `tscheck/` (TypeScript) in CI.
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
| **A1** — `governed_work_binding_v1` keeps its name, implemented by the byom adapter; `ByomEpisodeBinding` is its own record, not an overloaded predecessor shape | Authority rows carry over in intent and freeze (exact actor/dependency/assurance) in the C2 bundle. K2 slices 1–2 extracted and implemented nine of the bundle's fourteen operations in `crates/kovee-byom`; `byom_episode_binding_show` is its own registry row and its own record shape | Delivered for 9 of 14 operations; the five `collaboration_context_bundle_*` / `workspace_*` operations remain unbuilt, so the bundle stays unadvertised |
| **A2** — greenfield enablement saga (not a cutover; Kovee never the genesis governance actor) | Implemented at K2 slice 1: `KoveeRealmByomBinding` + `KoveeSocietyMapping` created inert, then `KoveeGovernanceOwnerBinding` CAS `none → byom` at the expected revision (`crates/koveed/src/governance.rs`), with every descriptor branch proven in `crates/koveed/tests/k2_greenfield.rs`, the commit-point crash matrix in `k2_binding_crash.rs`, and an end-to-end run against a real `byomd` in `k2_byomd_integration.rs`. The never-genesis rule is enforced by a byomd projection read and carried as trust-boundary tier 5 of the threat model | Delivered. Slice 2 added the formation half (`crates/koveed/src/formation.rs`, `crates/koveed/tests/k2_formation.rs`) on the same never-genesis rule |
| **A3** — naming (predecessor vocabulary→byom, `mission`→`endeavor`, `axon`→`akson`) | Grep sweep over `spec/`: **no superseded-era identifier survives in any machine-consumed file** — registry operation names (also machine-asserted by `registry_parity::no_superseded_era_operation_name_survives`), schemas, and vectors are clean. The only remaining spellings are where the record's job is to carry them: the verbatim §9.2 quote and the A5 pinned→resolved tables in `registry-README.md`, which map the frozen `DESIGN.md` text onto the live registry and would be false if rewritten while that text is pinned | Delivered |
| **A4** — ontology deltas Δ1–Δ6 (byom's architectural inversion) | None touches the three K1 bundles. Δ1 formation machines, Δ4 act-class subject taxonomy, and Δ5 `BriefingManifest` dissolution are C2 bundle items; Δ2 plan-as-lens and Δ3 wake inversion (`WakeIntent` → byom kernel admission → `placement_admit`) shape the K2 exit; Δ6 directory-as-evidence renders at K5 with C4/B5 trust-suspension machinery | Future — tracked to C2/K2 (Δ6: K5/C4) |
| **A5** — wire-operation renames | No rename applies to the three K1 bundles (every operation in the table belongs to `governed_work_binding_v1`). All nine renames are now applied and recorded in the registry's `a5_renames_applied`: slice 1's `personal_governed_work_enable/show/disable` → `governance_enable/show/disable`, and slice 2's `mission_promotion_prepare/start/show/cancel/reconcile` → `endeavor_promotion_*` and `sage_turn_binding_show` → `byom_episode_binding_show`. The parity test asserts no superseded operation name | Delivered — every A5 rename is bound to a live registry entry |
| **A5** — digest classes (no retained plaintext `raw_sha256`) | C1 family vectors (CI `family-vectors` job at the `family-lock.pin.json` row), including forbidden-substitution negatives; KG29 in `schemas/ops/README.md` keeps `declared_raw_sha256`/`raw_sha256` an ordinary upload-checksum field type never interchangeable with typed digests; `vectors/envelope/digest-typed-bytes-artifact.json` binds artifact authorization to the typed artifact-bytes digest | Delivered |
| **A5** — canonical CLI verb | `kovee governance enable --byom local [--society <id>]` — the wire operation `governance_enable` is live at K2 slice 1 and takes exactly this verb's arguments (`byom_endpoint_ref`, `society_ref`); the CLI surface itself is still reserved | Wire operation delivered; CLI verb reserved |
| **A9** (byom amendment, `design/2026-07-27-amendment-governance-owner-enum.md`) — the governance owner enum is `byom \| none` | Registry revision `k2-4`: `schemas/ops/governance-{show,enable,disable}-result.schema.json` narrow the owner enum; `kovee-byom`'s `GOVERNANCE_OWNERS` carries two arms and `owner_arm_is_coherent` rejects any other. byom publishes the narrowed record as the `kovee-governance-owner-binding-v2` successor schema with a negative vector proving the withdrawn arm is refused; v1 stays published unchanged | Delivered (K2 binding half) |
