# Amendment A9: the governance owner enum is `byom | none`

Status: proposed (becomes normative on acceptance)

Date: 2026-07-27

Amends: `kovee/DESIGN.md` §16.6's `KoveeGovernanceOwnerBinding` field block
at sha256
`2f5d1657a4b240959ff72b99b3c089b52ac191c1666ae24706543ea6fda26d97`
(design-v0.1.1). Supersedes the enum clause of amendment A1
(`design/2026-07-25-amendment-governance-owner.md` §A1, final bullet).
Authority: byom amendment A9
(`byom/design/2026-07-27-amendment-governance-owner-enum.md`), which owns
the byom-normative record shape. Until the design text is re-cut, **this
record overrides it wherever they conflict** — the same mechanism A1–A5 use.

## A9.1 — What changes

`KoveeGovernanceOwnerBinding.governance_owner` reads `sage | byom | none` in
the pinned design text, and A1 kept all three arms "for spec fidelity". The
third arm named a discarded predecessor design. It is withdrawn:

```
governance_owner: byom | none
```

A governed scope is in exactly one of two states — **byom owns it, or nothing
does.** Byom is this stack's governance layer, reached over the Byom
Participation Protocol through `kovee-byom`, and there is no second one for
the wire to name.

The arm was not merely unused. It had no writer, no reader, and no machine
that consumed it; the TLA+ invariant asserting it was never taken could only
ever pass, because no implementation could produce the value. A closed enum
is a security boundary, and an owner arm nothing authorizes is a widening
surface every future reviewer has to re-clear. Removing it turns a standing
review obligation into a type fact.

## A9.2 — Where it lands

| Artifact | Change |
|---|---|
| `crates/kovee-byom/src/records.rs` | `GOVERNANCE_OWNERS: [&str; 2] = ["byom", "none"]`; `owner_arm_is_coherent` matches `byom` and `none` and rejects everything else; a test pins both facts |
| `spec/schemas/ops/governance-show-result.schema.json` (two positions), `governance-enable-result`, `governance-disable-result` | owner enum narrowed to `byom \| none` |
| `spec/registry.json` | registry revision **`k2-4`** — no entry changes; the revision string and `sources.amendment` record this narrowing (`spec/registry-README.md`) |
| byom `spec/governed-work/kovee-governance-owner-binding-v2.schema.json` | the narrowed record, published as a successor; its v1 stays published byte-unchanged, with new `-v2-*` vectors including one that proves the withdrawn arm is now refused |
| byom `proof/specs/GreenfieldEnablement.tla` | the owner type domain is `{"byom","none"}`; the vacuous never-exercised invariant is dropped, its force now carried by `TypeOK` |

`governed_work_binding_v1` and `byom_governed_work_v1` **keep their names**.
A1 already recorded that the bundle name survives an ontology replacement,
and a record-schema successor is not a new bundle.

## A9.3 — The re-owning cutover is withdrawn

A2 recorded byom §25's `GovernanceCutover` (`sage → none → byom`) as
"specified but unbuilt". With no source arm there is nothing for it to move
off, so it is withdrawn rather than left standing: no cutover row, descriptor,
operation, or state exists or is reserved.

`cutover_ref` stays an optional member of the closed record, unset by every
machine here, so that a future *governed re-owning* transition would have a
place to record its authority instead of widening a closed shape later.

**Greenfield enablement (`none → byom`) is the only owner transition Kovee
has.** `governance_disable` freezes the row; re-enablement is a fresh saga
under a new binding epoch, never a reverse cutover.

## Not changed, deliberately

`spec/registry-README.md`'s §9.2 blockquote and its A5 pinned→resolved tables
still carry predecessor-era spellings in their left-hand columns, as does the
A5 wire-name table in `design/2026-07-25-amendment-governance-owner.md` that
they join on. That is their function: they map the byte-frozen v0.1
`DESIGN.md` text onto the live registry, and rewriting them would make the
mapping false while that text stays pinned.
`registry_parity::no_superseded_era_operation_name_survives` keeps the same
spellings in its banned-substring list for the same reason — the string is the
guard, not a use of it.

## Landed

The `DESIGN.md` §16.6 field block was re-cut in **design-v0.1.2**
(2026-07-27): `governance_owner` reads `byom|none`, and the surrounding
paragraph states that there is no third owner and no cutover machine. The
ratified byte-frozen v0.1 (sha256 `40820c47…`, repo `7aad4a6`) is unchanged
and is what the family contract and implementation plan still pin, so this
record continues to control for readers of that text.
