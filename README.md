# Kovee

**An agent-native, durable collaboration environment for people and agents.**

Pre-release, under active development. The sections that follow describe the
design; [what runs today](#what-runs-today) is a subset of it, and
[Status and limits](#status-and-limits) says where the edges are.

Kovee organizes collaboration around a shared **Space**, the primary unit of
collaboration and visibility inside a project. People and agents append typed
**Contributions**—goals, questions, claims, evidence, proposals, critiques,
syntheses, and results—and connect exact revisions with attributed
**Relations**. These records are claims and work products, not hidden
chain-of-thought or automatically accepted truth.

A familiar chronological **Stream** is one lens over a Space, alongside
workbench, pulse, branch-comparison, ensemble, and provenance lenses. A lens
changes presentation, never visibility or authority. Reasoning can fork from an
exact frontier into a **Branch** and later merge by digest-bound adoption;
origin, dissent, and unresolved conflicts remain inspectable.

Agent participation is explicit and bounded:

- An **AttentionContract** says which committed changes may notify or wake an
  assistant, under exact rate, budget, lineage, and target-acceptance limits.
- Each wake receives an immutable **ContextAssembly** recording exactly what
  was selected, transformed, omitted, and authorized at a pinned frontier.
- A **Need** can gather **Offers**; a **FormationProposal** selects compatible
  offers, and accepted terms become **Commitments**. Their scope is always
  `local_non_governed`.
- An assistant commitment creates a pinned **WorkRealization** beneath the
  collaboration agreement. Runtime success delivers a result; it does not by
  itself fulfill the commitment or accept governed work.

```text
people · agents · web/CLI
            |
Kovee Spaces · lenses · attention · local commitments
            |
Kovee context · runtime · artifacts · effects
            |
Byom societies · endeavors · pledges · mandates · decisions · memory
            |
Akson signed remote contracts · sovereign federation
```

[Byom](../byom/README.md) is the governance authority for governed endeavors,
pledges, mandates, episodes, leases, act decisions, endeavor budgets,
governed-deliverable review, evidence directories, and engrams. Kovee reaches
it over the **Byom Participation Protocol (BPP)** through the `kovee-byom`
adapter; Kovee never decides governance itself.
Promoting an exact Space/Branch frontier forms a Byom Endeavor; Kovee then
renders source-qualified endeavor views rather than duplicating Byom state.
Cross-installation work remains Byom delegation carried through
[Akson](../akson/README.md), never a Kovee commitment or shared broker subject.

The safety substrate is intentionally conventional: authenticated commands,
SQL authority, immutable records, idempotency, admission boundaries, durable
effects, leases, fencing, and transactional outboxes. NATS/JetStream is optional
internal delivery in clustered installations—not a client API, database,
authorization boundary, or federation protocol.

## What runs today

Start the daemon and drive it with the CLI. Every command below was run
against this tree:

```text
koveed &                                     # personal profile, SQLite WAL store
kovee hello                                  # negotiated version + advertised bundles
kovee init                                   # installation, realm, personal project
kovee space create --project <project-id> --title "Test diagnosis"
kovee space contribute --project <project-id> --space <space-id> \
  --kind question --text "Why are these tests failing?"
kovee events --project <project-id> --limit 3
```

`koveed` stores state under `$XDG_DATA_HOME/kovee` and binds its two sockets
under `$XDG_RUNTIME_DIR/kovee`; `KOVEE_DATA_DIR` and `KOVEE_RUNTIME_DIR`
override either. Keep the runtime directory short — a Unix socket path has a
hard length limit and a long one fails the bind.

`kovee hello` reports the three complete feature bundles — `core_v1`,
`shared_space_v1`, `developer_assistant_v1`. The fourth,
`governed_work_binding_v1`, has 9 of its 14 operations built; §11.6 makes
bundles atomic, so it is deliberately **not advertised** even though its nine
operations dispatch.

Those six verbs are the whole shipped CLI. Beyond them, the daemon serves
spaces (lifecycle, participants, grants, prepared widening), typed
contributions with supersede/withdraw/redact, relations, pinned frontiers, the
two built-in lenses, exact `ContextAssembly`, artifacts, and — over the
`kovee-byom` adapter — governance enablement and endeavor promotion.

Three things this README describes are **design, not shipped**, and are easy
to read as present tense:

- **Branch fork and merge.** Every space has a main branch and every
  contribution carries an origin branch, but there is no `branch_*` operation
  in the registry — nothing forks and nothing merges.
- **AttentionContract.** There is no `attention_*` operation;
  `crates/kovee-attention` is a stub.
- **Needs, Offers, FormationProposals and Commitments.** No operation for any
  of them exists yet.

`governance_enable` and `endeavor_promotion_*` are real wire operations
reachable over the socket today; their CLI verbs are reserved, not built.

The daemon runs in same-user developer mode, not production isolation. The
complete design specifies immutable production packages, confined workers, and
brokered model/tool egress.

## Verifying

```sh
./run-checks.sh
```

`cargo fmt` / `clippy -D warnings` / `cargo test --workspace --locked`, the
C3a MCP tool-bundle check, and two independent re-derivers of the golden
vectors — `xcheck/` (Python) and `tscheck/` (TypeScript), which share no code
with the Rust workspace and re-derive 197 schemas and 415 vectors.

See [DESIGN.md](DESIGN.md) for the normative design and
[spec/](spec/README.md) for its machine-checkable extraction.

## Status and limits

**Pre-release, under active development.** Not production-ready, not audited.
No compatibility claim is made. Read these before quoting any capability:

- **The assurance profile is `developer`**: no UID separation, no attested
  process identity, no asymmetric endpoint identity. Non-developer profiles
  are refused rather than faked.
- **Provider-bypass prevention is not claimed.** The broker's own calls are
  disclosed, permitted and metered, and the external path to minting an
  execution permit is closed at the crate boundary — sealed `SpentLedger`
  trait, crate-private transport, no public authority constructor. But a
  same-UID assistant can skip the daemon entirely, and inside one process code
  compiled into the same crate can still obtain the authority. What bounds a
  forgery there is the durable ledger, not cryptography. Closing the rest
  needs byom to sign its receipts; that is deferred to K4.
- **Team mode does not exist** — no PostgreSQL, OIDC, realtime, or NATS. That
  is K3.
- **The I1 governed-loop gate is partial.** 5 of 13 plan items are exercised
  with nothing standing in; 8 are explicitly simulated — the attention trigger
  is a stub, byom mints only `attached_harness` manifestations, kovee ships no
  onboarding code, and a recording transport stands in for a provider.
