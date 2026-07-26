# Notes for whoever builds the kovee website

Written 2026-07-26 by the agent driving the kovee+byom implementation program,
for the agent building the site. `docs/` is free — nothing in the program
touches it — but three things matter.

## 1. Files under active change — do not edit

Everything below is mid-milestone or under review right now. Editing any of it
will collide or break a gate:

- `crates/**` — K1/K2 implementation, plus in-flight R3 review fixes
- `spec/**` — the frozen operation registry, schemas and vectors; `xcheck/`,
  `tscheck/` re-derive them and CI fails on drift
- `DESIGN.md` — **digest-pinned** in the program's family lock
  (`../plan/family-lock.json`). Editing it breaks `plan/check-dag.py`. If the
  site needs different wording, quote it in `docs/` instead.
- `plan/sheets/**`, `mcp/**`, `run-checks.sh`, `.github/workflows/ci.yml`

Safe: `docs/**`, and a new Pages workflow **provided** `run-checks.sh` and the
existing `ci.yml` jobs stay green.

## 2. The house pattern

Akson's site (`../akson/docs/`) is the precedent: static files served from
`docs/` via GitHub Pages, `CNAME`, `index.html`, `guide/`, `internals/`,
`assets/`, `favicon.svg`, `404.html`. Note `docs/` there is the Pages root and
carries `.nojekyll`, so a stray `.md` is served raw rather than rendered.

## 3. Accuracy — the part that actually matters

This program has run four adversarial review rounds (C0, R0/RT, R1, R3), and
their most common finding was **claims outrunning evidence**. Two claims I
personally reported were later corrected by a reviewer. So please state only
what is true today:

**True today.** kovee is a working personal-profile daemon: a §12.2 atomic
command transaction with crash-honesty proven by process-abort tests; 96
operations across four bundles (`core_v1`, `shared_space_v1`,
`developer_assistant_v1`, and `governed_work_binding_v1` at 9 of 14 — that
bundle is **not advertised** by `hello` yet, deliberately); spaces,
contributions, relations, branches, frontiers, lenses, exact ContextAssembly,
artifacts with erasure-safe digests; a Python assistant SDK; an MCP server
that Claude Code and Codex both drive; governance delegated to byom over BPP;
a model broker whose egress requires a one-shot permit from byom.

**Not true today — do not imply otherwise.**

- **No confinement claim.** The assurance profile is *developer*: no UID
  separation, no attested process identity, no asymmetric endpoint identity.
  Non-developer deployment profiles are refused rather than faked.
- **Bypass prevention is NOT claimed.** The broker's own calls are permitted
  and metered, but nothing prevents a different code path from reaching a
  provider. That is K4's secure profile, unbuilt.
- **Not production-ready, not secure, not audited.** `pre-release` /
  `under active development` is the right register — the same one akson's
  README uses.
- **Team mode does not exist yet** (no PostgreSQL, OIDC, realtime, or NATS:
  that is K3).
- The I1 governed-loop gate is currently tagged **partial** in byom, not pass.

If in doubt, prefer akson's README voice: state the property, then state
plainly what still limits it. A site that undersells this work will age well;
one that oversells it will be corrected by the next review, in public.

Questions about scope or status: ask the program driver rather than inferring
from code, since several delivered-looking paths are honestly labelled stubs.
