# Amendment: governance owner, naming, and greenfield enablement

Status: proposed (C0 revision work; becomes normative on C0 ratification)

Date: 2026-07-25

Amends: `kovee/DESIGN.md` at sha256
`40820c476d59ebdd458955fd5939289b3ef2bff03c3d1266f5e80f3087935860`.
Until the amended text is folded into the K0 spec extraction, **this record
overrides the design text wherever they conflict.** Authority: the family
contract (`byom/design/2026-07-25-family-contract.md`) and plan decisions
D1, D9, D10 (`2026-07-25-kovee-byom-implementation-plan.md`, sha256
`d5e73952ac90a67a4e4a060052ca66d4be729dec500436b86623b89c54afb2d2`).

## A1 — Byom is the sole governance owner (plan D1)

Every reference to **Sage** as kovee's governance authority — the Sage
application adapter (§7.1), the `kovee-sage` crate (§24), the Sage Session
Protocol consumption (§11.10, §17), `SageTurnBinding` (§17.2), the §17.5 Sage
protocol gap list, the audited local `saged` bootstrap (`kovee mission enable
--sage local`, §26 K2), and the K5 "complete Sage product integration" — is
re-targeted to **byom** and the **Byom Participation Protocol (BPP)**:

- the adapter crate is **`kovee-byom`**; there is no `kovee-sage`;
- the KCP feature bundle keeps its name `governed_work_binding_v1` and is
  implemented by the byom adapter speaking BPP;
- §17.5's gap list is superseded by the family contract's field-level
  operation × authority matrix;
- `SageTurnBinding` is superseded by `ByomEpisodeBinding` (C2 bundle);
- Sage itself is never wired in. `KoveeGovernanceOwnerBinding` implements the
  full `sage | byom | none` enum for spec fidelity; the `sage` arm is never
  exercised in this stack, and byom §25's Sage migration stays documented,
  unbuilt.

## A2 — Greenfield enablement is not the cutover (plan D10)

`kovee governance enable --byom local` (formerly `mission enable --sage
local`) performs the **greenfield enablement saga** specified in the C2
bundle: create `KoveeRealmByomBinding` + `KoveeSocietyMapping`, then CAS
`KoveeGovernanceOwnerBinding` `none → byom`, with exact-CAS, retry,
overlapping-scope rejection, rollback-before-activation, and restore behavior
proven. It is a different machine from byom §25's `GovernanceCutover`
(`sage → none → byom`). Kovee is **never the genesis governance actor**: a
Society is established first through native `society_prepare`/
`society_bootstrap` under the bootstrap human's direct governance channel;
Kovee may start/configure/bind `byomd` and supply inert context only.

## A3 — Vocabulary and naming (plan D9)

- kovee **mission** vocabulary → byom **endeavor** vocabulary: `mission
  promote` → `endeavor promote`; the `MissionBootstrap` /
  `MissionPromotionIntent` / `MissionPromotionSlot` shapes (§10) are
  superseded by the C2 bundle's `EndeavorFormationIntent` /
  `EndeavorFormationSlot` / `EndeavorFormationAttempt` (byom §16.3), which
  carry the five-fact recovery union and terminalization semantics;
- `axon` → `akson` wherever the design or README references the gateway
  (`../axon/README.md` → `../akson/README.md`); the README's stack diagram
  line "Sage missions · aspects · sessions · gates · knowledge" reads
  "Byom societies · endeavors · pledges · mandates · decisions · memory";
- the workspace-root `kovee-design.md` sketch is superseded (already
  discarded by DESIGN.md §27).

## A4 — Ontology re-scoping under byom's architectural inversion

Per the family contract's ratified deltas (Δ1–Δ6):

- **No member-enrolling bootstrap (Δ1).** `MissionBootstrap` with `members[]`
  and `approval_rule` is superseded: Societies and Participants pre-exist
  (byom onboarding); `kovee_endeavor_form` fills exactly one human formation
  seat; multi-party formation falls back to `endeavor_propose/position/
  finalize` via `formation_requires_participation`. The promotion confirmation
  screen (§17.3) renders the Society's standing decision rules in place of
  members/approval-rule.
- **Plan is a lens (Δ2).** There is no canonical plan object and no aspect
  record: aspects → Pledges; `aspect_generation` → pledge revision plus
  activity/episode generation fences; plan gates → Endeavor/act decisions.
  K2's exit reads: one Endeavor formed by `kovee_endeavor_form`, one governed
  decision, two fenced Pledge episodes, a base-bound deliverable through
  `delivery_submit`/`review_record` — kill-survival and no-duplicate-formation
  criteria unchanged. K5/K6 exit language maps per family contract L66–L69.
- **Wake ownership inverts (Δ3).** §17.2/§17.4's "Sage alone admits the event
  and creates the next TurnRun" is replaced: participants (or their adopted
  ActivationPolicies) author `WakeIntent`; the byom kernel admits and
  allocates; Kovee places (`placement_admit`). Kovee attention only notifies.
- **Gate kinds become act classes (Δ4).** The typed gate-kind catalog
  (`model_egress/share/outbound/apply/budget`) and per-mission
  `gate_policy_ref` become BPA-1-expressible act/effect classes carried in
  ActIntent subjects and bounded by Mandates; the gate inbox renders pending
  prepared intents and eligible seats.
- **`BriefingManifest` dissolves (Δ5)** into ContextAssembly (Kovee) +
  ContextManifest (byom) + the byom source fields of `ProviderContextManifest`
  + context refs on `ByomEpisodeBinding`.
- **Directory is evidence (Δ6).** §17.8's observed-outcome directory maps to
  byom §7.5 evidence + the B4 claim/evidence directory, rendered by Kovee at
  K5; trust suspension on Akson binding change is C4/B5 machinery.

## A5 — Wire names, digest classes, canonical verbs

**Wire-operation renames** (the K0 spec extraction resolves the pinned design
**plus this table** into one registry; no Sage-era wire name survives):

| Kovee §11.6 (pinned) | Resolved wire name |
|---|---|
| `personal_governed_work_enable/show/disable` | `governance_enable/show/disable` |
| `mission_promotion_prepare/start/show/cancel/reconcile` | `endeavor_promotion_prepare/start/show/cancel/reconcile` |
| `sage_turn_binding_show` | `byom_episode_binding_show` |
| `collaboration_context_bundle_prepare/show` | unchanged (protocol-neutral) |
| `workspace_provider_manifest_show/list`, `workspace_allocation_binding_show` | unchanged |
| KCP bundle `governed_work_binding_v1` | name kept; implemented by the byom adapter |

Authority rows for the renamed operations carry over unchanged in intent and
are frozen (exact actor/dependency/assurance) in the C2 bundle.

**Digest classes for content addressing.** §10.10's retained plaintext
`raw_sha256` is amended: artifact content addressing uses the family digest
classes (byom §14.2) — `local_erasure_safe` (HMAC, per-object secret) for
erasable plaintext, `ciphertext_public` for sealed blobs, `portable_public`
only after explicit durable-identifier disclosure. Retained raw plaintext
hashes are removed on erasure; no public SHA-256 over ordinary erasable
low-entropy content.

**Canonical CLI verb** for greenfield enablement:
`kovee governance enable --byom local [--society <id>]` (plan, sheets, and
future CLI schema use exactly this).

## Follow-through

The full-text integration of A1–A5 into `DESIGN.md` happens at K0, when the
normative material is extracted into `kovee/spec/`; the K0 milestone sheet
lists it. R0 reviews this amendment together with the family contract.
