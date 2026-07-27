# Notes for whoever builds the kovee website

Written 2026-07-26, revised 2026-07-28 by the agent driving the kovee+byom
implementation program, for the agent building the site. `docs/` is free —
nothing in the program touches it — but three things matter.

## 1. Files under active change — do not edit

Everything below is mid-milestone, under review, or digest-pinned right now.
Editing any of it will collide or break a gate:

- `crates/**` — K1 shipped, K2 in flight, plus R3 review fixes
- `spec/**` — the frozen operation registry, schemas and vectors; `xcheck/`,
  `tscheck/` re-derive them and CI fails on drift
- `plan/sheets/**`, `harness/**`, `run-checks.sh`, `.github/workflows/ci.yml`

**Digest-pinned** in the program's family lock (`../plan/family-lock.json`) —
editing any of these breaks `plan/check-dag.py`, which a pre-commit hook runs:

| File | Lock row |
|---|---|
| `DESIGN.md` | `kovee-design-v0.1.2` |
| `design/2026-07-25-amendment-governance-owner.md` | `kovee-amendment-a1-a5` |
| `mcp/kovee-mcp.tools.json` | `kovee-mcp-tools-v0.1.0` |
| `mcp/mcp-tools.schema.json` | `kovee-mcp-meta-schema` |

If the site needs different wording than `DESIGN.md` has, quote it in `docs/`
instead. Safe: `docs/**`, and a new Pages workflow **provided** `run-checks.sh`
and the existing `ci.yml` jobs stay green.

## 2. The house pattern

Akson's site (`../akson/docs/`) is the precedent: static files served from
`docs/` via GitHub Pages, `CNAME`, `index.html`, `guide/`, `internals/`,
`assets/`, `favicon.svg`, `404.html`. Note `docs/` there is the Pages root and
carries `.nojekyll`, so a stray `.md` is served raw rather than rendered.

## 3. Accuracy — the part that actually matters

This program has run five adversarial review rounds (C0, R0/RT, R1, R3, and
the C4 carrier review), and their most common finding was **claims outrunning
evidence**. Two claims the program driver personally reported were later
overturned by reviewers. So please state only what is true today.

The program-level source of truth is `../STATUS.md`, which names the commit,
command, or record behind every claim. Prefer it over inferring from code.

### True today

Verified at kovee `4272e1f` with `./run-checks.sh` green (367 tests over the
workspace, `mcp/check.py` OK, and `xcheck`/`tscheck` independently re-deriving
197 schemas and 415 vectors).

- **A working personal-profile daemon.** `koveed` opens a SQLite WAL store and
  binds two Unix sockets (external client + worker). The §12.2 atomic command
  transaction is crash-honest, proven by process-abort tests
  (`k1_crash_matrix`, `k1_acceptance`) rather than asserted.
- **96 operations across four bundles** (100 registry entries — four
  operations are dual-surface), registry revision `k2-4`: `core_v1`,
  `shared_space_v1`, `developer_assistant_v1`, and `governed_work_binding_v1`
  at **9 of its 14** operations. §11.6 makes bundles atomic, so the incomplete
  fourth bundle is **deliberately not advertised** by `hello`/`protocol_info`
  — those report exactly three. Its nine operations do dispatch.
- Spaces (lifecycle, participants, grants, prepared widening), typed
  contributions with supersede/withdraw/redact, relations, pinned frontiers,
  the two built-in lenses (Stream, Workbench), exact `ContextAssembly`, and
  artifacts with erasure-safe digests; a Python assistant SDK; an MCP server
  (`crates/kovee-mcp`, 14 tools) that real Claude Code and Codex sessions have
  both driven in the I1 gate.
- **Governance is byom, and the owner enum is `byom | none`.** Amendment A9
  narrowed it; byom publishes the narrowed record as the
  `kovee-governance-owner-binding-v2` successor schema with a negative vector
  proving the withdrawn arm is refused, v1 stays published unchanged. In code,
  `kovee-byom`'s `GOVERNANCE_OWNERS` carries exactly two arms and
  `owner_arm_is_coherent` rejects anything else. Enablement is a greenfield
  saga: kovee is never the genesis governance actor.
- **The model broker's egress is sealed behind an authenticated
  `ConsumptionAuthority`.** No byte leaves without a byom
  `ExecutionConsumptionReceipt` for that effect's exact execution key, and the
  chain reply → receipt → attestation → permit → egress is keyed end to end
  under one secret the call site never supplies. The **external** path to
  minting a permit is closed at the crate boundary: the constructor is
  crate-private and `cfg(test)`, `SpentLedger` is a sealed trait, the
  transport trait and the live HTTPS wire are crate-private, and the one
  public door only exists in a `daemon` build and answers once per process.
  `tests/compile_gate.rs` proves this against rustc's own diagnostics rather
  than by convention. **Read the bypass limit below before writing any of this
  as a security property.**
- **Settlement is a crash-reconcilable two-sided saga.** A durable local row
  is committed before the peer is called; a process that dies in between
  restarts in `remote_pending` and reconciliation queries the peer under the
  same stable key and applies what the peer really committed. The terminal
  tail has its own durable row (`kovee_episode_terminal_saga`) closing the two
  windows where a crash used to leak a remainder for ever.
- **A capacity ledger that conserves.** Five buckets — `remaining`,
  `reserved`, `committed`, `uncertain`, `delegated_to_children` — with
  `ceiling = remaining + reserved + committed + uncertain + delegated` holding
  after every transition, machine-checked across reserve/settle/release and
  the delegate/rollup path. `uncertain` never releases on a timeout: spend
  stays blocked until a reconciliation seat with a fresh challenge lets go.
- **The host-effect digest is derived by the peer, not asserted to it.** It is
  a frozen nine-member `portable_public` fragment
  (`kovee-host-effect-binding-v1`); six members are byom's own committed act
  facts, which byom reads from its own row rather than from the request, so
  byom rebuilds the preimage and refuses a digest that does not re-derive.
- **I2 fleet tooling exists** under `harness/fleet/` — five scripts that would
  stand up two DigitalOcean droplets, run the I2 gate, and destroy them. See
  the limit below: it has never been run against real infrastructure.

### Not true today — do not imply otherwise

- **No confinement claim.** The assurance profile is *developer*: no UID
  separation, no attested process identity, no asymmetric endpoint identity.
  Non-developer deployment profiles are refused rather than faked.
- **Provider-bypass prevention is NOT claimed**, and this is the single
  easiest claim on the site to get wrong. Two separate limits:
  1. *At the OS level*, a same-UID `developer` assistant can skip the daemon
     entirely and reach a provider itself. The broker's own calls are
     disclosed, permitted and metered; nothing stops a different process.
     Enforced broker-only egress is K4's, unbuilt.
  2. *Inside one process*, closing the external-crate path did not close
     everything. Code compiled into the same `daemon` build can take the grant
     first, or call `admit`/`attest`/`authorize` on an authority it holds a
     reference to. What bounds a forgery there is the **durable ledger, not
     cryptography** — a fabricated consumption reference still sends nothing
     because the single use must claim a row only a real byom consumption
     created. Closing the rest needs byom to sign its `receipt_result` so
     kovee can verify provenance against a peer key; that is a cross-boundary
     protocol change, recorded as deferred to K4.

  The code says this in its own module docs; if the site's wording is stronger
  than `crates/kovee-effects/src/permit.rs`'s "What is closed, and what is
  not", the site is wrong.
- **Team mode does not exist** (no PostgreSQL, OIDC, realtime, or NATS — that
  is K3).
- **The I1 governed-loop gate is `partial`, and the tag says why.** 5 of 13
  plan-§8 items are exercised with nothing standing in; **8 are explicitly
  simulated**: the attention trigger is a stub (`kovee-attention` is a
  two-line crate), byom mints only `attached_harness` manifestations, kovee
  ships no onboarding code, and a recording transport stands in for a provider
  on the ambiguous-effect and broker paths. The gate derives that breakdown
  from the daemons' own records — each coverage query runs against the daemon
  that owns the record, simulation status is re-probed from the tree every
  run, and a cell whose declaration disagrees with what the probes observed
  fails rather than being promoted. A no-op cell fails naming the item and the
  query. `--all-checks` returns exit 2, not PASS, when a real harness is
  skipped.
- **Branching is a record model, not an operation.** Every space has a main
  branch and every contribution carries an origin branch and branch sequence;
  the `reasoning_branches` / `branch_entries` tables exist. But **the registry
  has no `branch_*` operation at all** — there is no fork and no merge, so
  "fork from an exact frontier, merge by digest-bound adoption" is design, not
  shipped. The same is true of **attention** (no `attention_*` operation;
  `kovee-attention` is a two-line crate) and of **needs, offers and
  commitments** (no `need_*` / `offer_*` / `commitment_*` operation). Those
  three are the easiest things on this site to overstate, because the design
  narrative in `README.md` and `DESIGN.md` describes all of them in the
  present tense.
- **I2 has never run.** The fleet tooling is written and dry-run validated,
  but 7 of its 9 scenarios need a per-side driver (`side.py`) that does not
  exist yet, and no DigitalOcean resource has ever been created.
- **Not production-ready, not secure, not audited.** `pre-release` /
  `under active development` is the right register — the same one akson's
  README uses.

### The CLI is smaller than the design

This trips people up. `DESIGN.md` and the README describe a full verb surface;
the shipped `kovee` binary today has **six** verbs:

```text
kovee hello
kovee init
kovee space create --project <id> --title <t> [--visibility project|restricted]
kovee space show --project <id> <space_id>
kovee space contribute --project <id> --space <id> --text <t> [--kind <kind>]
kovee events --project <id> [--after <cursor>] [--limit <n>]
```

There is no `kovee dev`, `kovee attention`, `kovee branch`, `kovee need`,
`kovee governance`, or `kovee endeavor` today. `governance_enable` exists as a
**wire operation** and is reachable over the socket; its CLI verb is reserved,
not built. Do not lift a command block out of `DESIGN.md` or the README design
narrative and present it as a quickstart — run it first.

If in doubt, prefer akson's README voice: state the property, then state
plainly what still limits it. A site that undersells this work will age well;
one that oversells it will be corrected by the next review, in public.

Questions about scope or status: ask the program driver rather than inferring
from code, since several delivered-looking paths are honestly labelled stubs.
