# Kovee

**An agent-native, durable collaboration environment for people and agents.**

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
[Akson](../axon/README.md), never a Kovee commitment or shared broker subject.

The safety substrate is intentionally conventional: authenticated commands,
SQL authority, immutable records, idempotency, admission boundaries, durable
effects, leases, fencing, and transactional outboxes. NATS/JetStream is optional
internal delivery in clustered installations—not a client API, database,
authorization boundary, or federation protocol.

A representative local path is:

```text
kovee init
kovee dev assistants/diagnostician.py --alias diagnostician --detach
kovee space create --title "Test diagnosis"
kovee space contribute <space-id> --question "Why are these tests failing?"
kovee attention activate <space-id> @diagnostician \
  --on question,evidence --review
kovee branch fork <space-id> --from main --purpose "Try the smallest safe fix"
kovee need open <space-id> --branch <branch-id> --outcome patch.v1 \
  --ask @diagnostician --review

# Add governance only when the work needs it:
kovee governance enable --byom local
kovee endeavor promote <space-id> --branch <branch-id> \
  --frontier <frontier-id> --goal <goal-contribution-id> --review
```

`kovee dev` is same-user developer mode, not production isolation. The complete
design specifies immutable production packages, confined workers, and brokered
model/tool egress.

See [DESIGN.md](DESIGN.md) for the normative design.

**Status:** draft specification v0.1 (2026-07-25). No compatibility or
production-readiness claim is made yet.
