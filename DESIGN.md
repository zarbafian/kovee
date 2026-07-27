# Kovee: an agent-native collaboration environment

Status: **Draft specification v0.1.2** — v0.1's scope, with the governance-owner
amendment's naming and ontology corrections (A1, A3, A5) and the owner-enum
narrowing (A9: `governance_owner` is `byom | none`) folded into the text.
The ratified byte-frozen **v0.1** remains sha256
`40820c476d59ebdd458955fd5939289b3ef2bff03c3d1266f5e80f3087935860` (repo
`7aad4a6`), which is what the family contract and the implementation plan pin.

Date: 2026-07-25 (v0.1.1: 2026-07-27; v0.1.2: 2026-07-27)

Companion designs:

- [Byom: a living society of autonomous participants](../byom/DESIGN.md)
- [Byom Participation Protocol specification](../byom/spec/README.md)
- [The akson + kovee + byom family contract](../byom/design/2026-07-25-family-contract.md)
  and its [amendments A1–A8](../byom/design/2026-07-25-amendment-family-contract.md)
- [Kovee governance-owner amendment A1–A5](design/2026-07-25-amendment-governance-owner.md)
- [Akson gateway](../akson/README.md)

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are normative requirements when capitalized. Examples are illustrative unless
marked normative. JSON Schemas and conformance vectors will become normative
with the first implemented protocol milestone; until then this document is the
source of truth.

## 1. Decision

Kovee is a multi-user collaboration environment and distributed execution
runtime for humans, code-defined assistants, and attached agent harnesses. Its
primary object is a durable **shared space**: people and agents externalize
questions, goals, hypotheses, evidence, proposals, critiques, and results as
typed contributions; direct attention through bounded contracts; explore
alternative branches; assemble exact context; and negotiate local commitments.
Conversation is one lens over that space, not the architecture's center.

Kovee also supplies the parts Byom intentionally does not own: hosted identity,
assistant packaging and deployment, worker placement, realtime delivery,
connectors, collaboration views, and clustered operations.

Kovee is **not** a replacement for Byom or Akson:

- **Kovee** owns shared spaces, contributions, relations, local attention,
  deliberation branches, non-governed collaboration commitments, and assistant
  execution inside one administered installation.
- **Byom** owns governed work: societies, charters, participants, assemblies,
  endeavors, calls, pledges, mandates, episodes-as-authority, budgets, engrams,
  and decisions.
- **Akson** owns sovereign endpoint and peer identity, introduction, signed
  remote contracts, consent, evidence, and carriage between independently
  administered installations.

The shorthand “Kovee backend, Byom frontend” is therefore inaccurate. Byom is a
protocol and a deterministic governance kernel; it has no frontend to speak of,
and Kovee is not its skin. The accurate relationship is:

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Kovee product                                                       │
│ shared spaces · lenses · attention · commitments · assistant runtime│
├─────────────────────────────────────────────────────────────────────┤
│ Kovee collaboration semantics                                      │
│ contributions · relations · context assemblies · branches · merges │
├─────────────────────────────────────────────────────────────────────┤
│ Byom bounded context                                                │
│ societies · endeavors · pledges · mandates · decisions · memory     │
├─────────────────────────────────────────────────────────────────────┤
│ Kovee infrastructure                                                │
│ authn/z · SQL state · artifacts · workers · internal event delivery │
├─────────────────────────────────────────────────────────────────────┤
│ Akson federation                                                     │
│ peer identity · signed contracts · consent · evidence · verification│
└─────────────────────────────────────────────────────────────────────┘
```

Byom remains independently implementable through the Byom Participation
Protocol (BPP). Kovee is its reference product host and distributed runtime, not
the definition of Byom.

The control substrate deliberately uses conventional transactional engineering:
SQL authority, immutable records, idempotency, leases, fencing, and outboxes.
The innovation belongs above that substrate. Kovee does not model collaboration
as chat plus agent RPC; it models a causal, forkable, inspectable shared
situation in which attention and commitments are explicit scarce resources.

## 2. Why the brainstorm must change

The original `kovee-design.md` contains a good product seed—a Python assistant
with a tiny API, events, durable conversations, and cross-machine reach—but its
backend model conflates concerns that need different guarantees.

| Brainstorm assumption | Resolution in this specification |
|---|---|
| Everything is a publish or subscribe on a NATS subject. | Clients issue authenticated, versioned commands. A transactional service commits state and a domain event. The bus only distributes committed notifications and work hints. |
| Subject names encode who may receive data. | Resource authorization derives from authenticated identity, project membership, grants, and policy. Subjects are private routing partitions and never grant authority. |
| Web, CLI, and Telegram are thin bus clients. | External clients use HTTP plus WebSocket/SSE. Connectors are authenticated services. No browser, connector, or assistant receives general NATS credentials. |
| The same chat subject carries input and output. | Commands and events are distinct. An utterance is a typed contribution shown through a conversation lens; goals, evidence, critiques, and results do not have to masquerade as chat messages. |
| `agent.<name>.rpc` is inter-agent request/reply. | `request_work` opens a Need with exact outcome, context, budget, deadline, and disclosure ceilings; an optional solicitation invites a target to submit an Offer. Only a fully assented Formation creates a Commitment and pinned WorkRealization, so retry transport is not the collaboration contract. |
| Every matching event should wake an agent. | An attention contract defines eligible changes, target acceptance, context recipe, rate, budget, coalescing, and wake behavior. Semantic ranking may prioritize eligible candidates but cannot create authority. |
| One shared transcript is collective memory. | A space is a causal contribution graph with explicit frontiers, provenance, branches, and saved lenses. Context is assembled and digested for an audience; it is never “whatever the chat contains now.” |
| A heartbeat says `blocked/working/done/idle`. | Heartbeats report instance presence only. Durable run and Byom Pledge/Episode states come from fenced controller transitions. “Done” is never accepted from presence. |
| JetStream replay is session persistence. | SQLite is authoritative locally; PostgreSQL is authoritative in team mode. State, event, idempotency record, and outbox commit atomically. JetStream is rebuildable delivery state. |
| NATS accounts make cross-user access safe. | NATS credentials isolate backend workloads. Kovee authenticates people and performs per-resource authorization. Cross-installation trust uses Akson. |
| Loading arbitrary Python into a server is production hosting. | Drop-a-file import is a developer mode. Production runs immutable, digest-pinned packages in confined workers without database, broker, model, or cloud credentials. |
| Cross-user inbox delivery is a handoff. | Delivery is not consent. Same-installation handoffs use exact offers and recipient admission; cross-installation handoffs use Byom act decisions and Akson contracts. |
| PostgreSQL `LISTEN/NOTIFY` is single-machine only. | It works across machines but is nondurable and unsuitable as the work/event log. It MAY be a wakeup optimization, never authoritative delivery. |

The subject pattern in the brainstorm is discarded rather than versioned. In
particular, `*.event.*` does not match `ws.<workspace>.event.<dotted.type>`, and
`ws.>` would expose all matching subjects in an account rather than prove
cross-workspace permission.

The brainstorm uses the external `akson-ai` Python project as authoring
inspiration, while the sibling Rust project in `../akson` also names itself
**Akson**. This specification calls the former **akson-ai** and the latter the
**Akson Gateway**. `Akson`, `aksond`, `akson-*`, and Akson's protocol namespaces
are canonical here; any drafts using the historical spelling “Axon” must be
updated rather than creating a documentation-only alias (family-contract
amendment A1, plan decision D9).

## 3. Product thesis

A person should be able to open a shared situation, add a goal or question, and
let people and agents contribute useful structure without forcing every thought
through one chat transcript or one central orchestrator. The environment should
show what is known, contested, attempted, promised, and still unattended; let
participants explore alternatives concurrently; and make the exact context and
authority behind every action inspectable.

Assistants should be as easy to author locally as in the brainstorm, but safe to
deploy across a worker fleet. They are persistent participants only through
their durable external records: an assistant process may disappear and return
without the shared space losing contributions, attention, commitments, or causal
history.

Kovee offers two connected modes of collaboration:

1. **Open-space mode** — fluid exploration through typed contributions,
   relations, attention, branches, context views, conversation lenses, and
   non-governed local commitments.
2. **Endeavor mode** — an exact goal and space frontier become a Byom
   **Endeavor**; calls, pledges, mandates, episode leases, act decisions,
   review, delegation, and engrams use Byom's stronger authoritative semantics.

A contribution or relation is not true because an agent asserted it. An
attention match is not work acceptance. A branch merge is not a governed
decision. A local commitment is not a Byom Pledge or a contract binding another
organization. A natural-language imperative cannot decide a governed act, change a
budget, mark work accepted, grant a mandate, or dispatch data to a peer.
Those actions require typed commands on the owning authority surface.

### 3.1 Agent-native interaction model

Each project contains one or more **spaces**. A space has three cooperating
planes:

```text
epistemic plane   contributions · relations · frontiers · branches · merges
attention plane   attention contracts · candidates · activations · context assemblies
commitment plane  needs · offers · formations · commitments · deliveries/reviews
```

The planes are connected but not conflated. A question may cause an attention
candidate; an authorized activation may invoke an assistant; the assistant may
contribute a proposal; that proposal may lead to a commitment offer; an accepted
assistant commitment may create runtime work; a delivery returns as evidence.
No arrow implicitly grants visibility, budget, execution permission, acceptance,
or truth.

Humans and assistants use the same contribution and relation formats so their
work can be compared and composed. They do not have symmetric authority: only
authenticated principals can make required human decisions, and only the
semantic owner can commit governed state. A dynamic team is the current graph of
accepted commitments around goals, not a mutable role list that an agent can
rewrite.

Conversation, timelines, evidence maps, open-question boards, branch comparisons,
and commitment boards are **lenses** over the same records. A lens may change
presentation and ordering but never visibility, provenance, or authority.

Kovee records externalized reasoning products—claims, rationale, evidence,
alternatives, and syntheses. It does not request, expose, or treat hidden model
chain-of-thought, provider scratchpads, system prompts, credentials, or internal
tokens as collaboration state.

### 3.2 Primary users

- A person using assistants alone on one machine.
- A team collaborating with people and assistants in shared projects.
- An assistant author shipping a Python package with a small, stable contract.
- An operator running a self-hosted Kovee installation and worker fleet.
- A Byom Participant or attached CLI harness performing governed long-running work.
- An organization delegating bounded work to another sovereign Akson endpoint.

### 3.3 Goals

Kovee MUST provide:

- A coherent space-and-lens experience for humans and agents, including a
  familiar conversation lens without making chat the canonical world model.
- Local-first personal operation without a required hosted control plane.
- Authenticated multi-user projects and realtime updates in team mode.
- An approachable Python authoring API backed by a versioned worker protocol.
- Typed, provenance-bearing contributions and bounded relation traversal.
- Durable attention contracts, exact context assemblies, fork/merge reasoning,
  and negotiated commitments with retry-safe runtime realization.
- Append-only event/contribution envelopes and audit metadata, with causal links,
  resumable cursors, and policy-governed payload erasure.
- Explicit authority, disclosure, admission, and audit boundaries.
- Fenced execution, crash-honest effects, bounded retries, and budgets.
- A clean Byom integration without duplicating Byom authority.
- Akson-based federation between independent installations.
- Replaceable internal infrastructure; public clients MUST NOT depend on NATS.

### 3.4 Non-goals

Kovee does not provide:

- A global identity, global assistant namespace, or global reputation system.
- Cross-organization trust by sharing a broker or NATS account.
- A new peer wire protocol alongside Akson/A2A.
- Distributed consensus between sovereign installations.
- A claim of exactly-once computation or exactly-once external side effects.
- Arbitrary multi-master document editing; a future document service must name
  and specify its CRDT rather than treating pub-sub as one.
- A universal tool registry or prompt/role DSL.
- A universal ontology, truth engine, autonomous organization, or requirement to
  store hidden chain-of-thought.
- A live multi-writer space across realms or sovereign installations. Such
  boundaries use immutable handoffs and admitted projections.
- A replacement for Byom's endeavor, decision, participant-evidence, or engram
  semantics.
- PTY rendering or terminal multiplexing. CLI harnesses remain supported through
  typed providers and `session_attach`; their terminals are not Kovee's state.
- Secure execution in the `developer` profile.

## 4. Invariants

These properties shape identifiers, APIs, storage, scheduling, and tests from
the first milestone.

1. **Commands are not events.** A caller requests a transition; the owning
   service authenticates, authorizes, validates, commits, and then emits the
   resulting event. Publishing an event can never bypass a command invariant.
2. **The database is authoritative.** Accepted state survives loss of NATS and
   every projection. Broker contents can be recreated from the event/outbox log.
3. **The authenticated channel supplies the actor.** A body may refer to actors
   for correlation, but it cannot select the effective principal, invocation attempt, or
   service identity.
4. **Aliases are not identities.** Display names such as `researcher` resolve
   under an authorized project registry to opaque, immutable references before
   work is committed.
5. **Arrival is not admission.** An offer, contribution from another space, peer
   artifact, or Akson outcome stays inert until the receiving policy admits it.
6. **Presence is not work state.** Liveness is expiring and advisory; completion
   is a durable, fenced transition accepted by the controller.
7. **Every mutation is retry-safe.** It carries a request id and idempotency key;
   exact replay never re-executes. While the full result is retained it returns
   that result when the actor remains authorized; afterward it returns the
   durable result-expired tombstone. Key reuse with changed input fails.
8. **Every execution is fenced.** Outputs, child commitments/realizations, effects, progress,
   checkpoint writes, and completion carry the current attempt and fence epoch.
9. **Effects are durable before effect.** An exact intent and its authorization
   commit before execution. Unknown non-idempotent outcomes become `ambiguous`
   and are never retried blindly.
10. **Disclosure is an action.** Cross-space/project, model-provider, connector,
    and peer egress binds an exact disclosure manifest to policy or a human decision.
11. **One semantic owner per record.** Kovee may cache Byom or Akson views, but a
    projection never becomes a second writer or an alternate authority.
12. **Intelligence cannot manufacture authority.** Models MAY rank already
    eligible attention candidates, propose relations, assemble a synthesis, or
    estimate relevance. Deterministic kernels still own eligibility, visibility,
    budgets, deduplication, state transitions, and effects; a score or generated
    statement can never widen them.
13. **No hosted service is required for personal use.** Local mode retains the
    same protocol and safety semantics that do not depend on multi-user auth.
14. **Security claims name their profile.** Same-UID developer guardrails are
    never described as confinement or complete egress control.
15. **The graph is not truth.** Contributions and semantic relations are
    attributed assertions. Verification, admission, review, and acceptance stay
    explicit and owned by their respective protocols.
16. **Attention is not obligation.** An attention contract grants bounded
    permission to consider or wake on eligible change. It is not a lease,
    commitment, progress record, or authority to act.
17. **Context is an immutable selection manifest.** Every invocation sees an
    exact, audience-authorized assembly at a recorded frontier—not ambient space
    contents, a mutable transcript, or a semantic-search side channel.
    Possession grants nothing; every materialization/read rechecks current
    dependencies and erasure.
18. **Branches preserve alternatives.** Fork and merge never rewrite origin,
    erase dissent, resolve authority conflicts, or make a synthesis accepted.
19. **Commitment precedes realization.** Collaboration terms bind an exact need,
    parties, outcome, context, budget, disclosure, deadline, and cancellation
    policy before runtime work is created. Runtime success is only a delivery
    claim until the applicable reviewer accepts it. Kovee terms remain bounded
    local contribution/draft-artifact work and never replace Byom or Akson.
20. **Binding acceptance is typed and attributable.** Activating/widening
    attention and recording each Formation/amendment party assent require an
    exact authenticated principal decision, bounded current requester
    capability, or active standing-policy use as applicable. Finalization needs
    the complete separately attributable assent set. Model output,
    natural-language assent, a relation, or assistant self-assertion is inert.

## 5. Vocabulary and identity

| Term | Meaning |
|---|---|
| **installation** | One independently administered Kovee system. An installation is a security and failure boundary and has one stable installation id. |
| **realm** | The top-level tenancy, policy, data-residency, and billing boundary inside an installation. A personal installation has one realm. |
| **principal** | An authenticated human identity. Only principals may satisfy human-governance decisions. This maps to the source-qualified human filling a Byom human-authority seat, not an Akson peer. |
| **service identity** | An authenticated backend workload or connector. It can receive narrow machine permissions but is not a human approver. |
| **actor** | The attributable local author of a collaboration action: a principal, fenced Kovee invocation attempt, bound Byom Manifestation, or service identity. An imported Akson peer author remains source-qualified provenance and never authenticates as a local actor. Identity is stamped by the owning service. |
| **project** | An administrative ownership, policy, billing, and deployment scope containing spaces and optional Byom links. Space is the normal collaboration/visibility boundary. It is deliberately not called a workspace. |
| **workspace allocation** | Byom's logical grant of a bounded filesystem snapshot/worktree for one execution attempt, authored by the kernel at `resource_allocate`. It is not a Kovee project, and Kovee owns only its physical materialization ledger. |
| **space** | A realm/project-owned shared situation containing typed contributions, relations, branches, lenses, attention, and local commitments. It has one home write boundary. |
| **contribution** | An immutable, attributed externalized unit such as an utterance, goal, question, observation, hypothesis, proposal, critique, evidence, synthesis, or delivery. It is a claim or work product, not hidden chain-of-thought. |
| **relation** | An immutable, attributed typed edge between exact object revisions. Structural edges record facts Kovee observed; semantic edges remain assertions. Neither grants transitive authority. |
| **frontier** | A digest-bound stable boundary over one space/branch and its source cursors, used to assemble context or fork work. |
| **lens** | A saved authorized presentation/query over a space. Conversation is an ordered lens; evidence maps and commitment boards are other lenses. |
| **conversation** | A familiar linear lens whose entries reference canonical contributions. It may be linked to Byom objects but is not the collective memory or authority ledger. |
| **reasoning branch** | An isolated line of explicit contributions based on an exact frontier. A merge admits references into another branch without rewriting origin. |
| **attention contract** | Revocable bounded permission for eligible committed changes to create notifications, candidates, or local invocations under an exact context recipe, budget, and wake policy. |
| **context assembly** | An immutable audience-specific selection manifest of exact authorized contributions, relations, transformations, omissions, limits, and digests. It grants nothing; every use reauthorizes. Provider instructions live in a separate recorded provider-context chain. |
| **collaboration commitment** | A Kovee-local, non-governance agreement around an exact need and terms. It requires a principal decision or exact active standing-policy use and cannot replace a Byom Pledge/act decision or Akson contract. |
| **assistant definition** | Stable Kovee identity and metadata for a code-defined assistant. It is not a process or a Byom Participant. |
| **assistant revision** | An immutable package, manifest, configuration schema, and digest for one version of an assistant definition. |
| **assistant deployment** | A revision activated under exact realm/project policy, placement, configuration, and concurrency settings. |
| **worker instance** | An ephemeral process or container able to run one or more permitted assistant deployments. Its lease represents presence only. |
| **invocation** | One durable bounded execution of an assistant deployment, caused by an authenticated direct command, admitted AttentionActivation, WorkRealization from an accepted commitment, deployment test, or Byom Episode. A mention alone is inert. |
| **attempt** | One worker's fenced claim on an invocation. A retried invocation has a new attempt and fence epoch. |
| **work realization** | The pinned Kovee runtime record created for an accepted assistant commitment. It is an execution mechanism, not the semantic agreement. |
| **presence** | Expiring liveness and availability hints for principals, clients, or worker instances. Never authoritative progress. |
| **society/charter/participant/endeavor/call/pledge/mandate/episode/decision/engram** | The exact Byom meanings; Kovee does not overload them. |
| **peer** | An independently operated Akson endpoint, identified and bound by Akson rather than Kovee. |

All wire identifiers are opaque, lowercase, and globally collision-resistant.
The reference implementation uses a type prefix plus UUIDv7 encoded without
subject metacharacters, for example `inv_01k...`. Names and aliases are mutable
display metadata. An internal NATS subject MUST use an independently derived
opaque routing token rather than interpolating user-provided ids or event types.

References that can cross installations include the issuing installation and realm,
or use the owning protocol's qualified reference. Akson peer ids and Byom object
ids are never rewritten into Kovee ids.

```text
ActorRef {
  owner_protocol: kovee|byom|akson,
  owner_endpoint_ref,
  kind: principal|invocation_attempt|byom_manifestation|service|akson_peer_projection,
  object_id
}

EventRef {
  owner_protocol: kovee|byom|akson,
  owner_endpoint_ref,
  event_id,
  cursor?
}

CorrelationRef { owner_protocol, owner_endpoint_ref, correlation_id }
```

The allowed actor kinds are protocol-specific: for example, an Akson peer
projection cannot become a Kovee principal. Cross-protocol causation always uses
`EventRef`; a bare event id is meaningful only inside one already identified
source stream.

## 6. End-to-end experience

### 6.1 Target ten-minute path

This is the product acceptance transcript, not a separate shell-based protocol:

```text
$ cd existing-repo
$ kovee init
created personal realm/project and space sp-1; main branch ready

$ kovee dev assistants/diagnostician.py --alias diagnostician --detach
registered dev revision as @diagnostician (developer profile)

$ kovee space contribute sp-1 --goal "Fix the failing tests safely"
contribution ct-1 appended on main

$ kovee space contribute sp-1 --question "Why are these tests failing?" \
    --addresses ct-1
contribution ct-2 appended on main

$ kovee attention activate sp-1 @diagnostician \
    --on question,evidence --context focused --max-wakes 3 --review
attention ac-1 active; principal decision dc-1 and target policy-use pu-1 recorded

$ kovee space show sp-1 --lens workbench
@diagnostician added claim ct-3, evidence ct-4, relation ct-4 supports ct-3

$ kovee branch fork sp-1 --from main --purpose "Try the smallest safe fix"
branch br-2 pinned at frontier sf-4

$ kovee need open sp-1 --branch br-2 --outcome patch.v1 \
    --ask @diagnostician --review
need nd-1; offer of-1; formation fm-1 accepted by dc-2/pu-2;
commitment cm-1 active; realization wr-1 queued

$ kovee governance enable --byom local --society soc-1
bound realm to byomd endpoint local (society soc-1, active); governed_work enabled

$ kovee endeavor promote sp-1 --branch br-2 --frontier sf-7 \
    --goal ct-1 --review
context bundle cb-1; exact frontier/decision-rules/budget/workspace shown;
endeavor en-1 formed (one human seat filled by you)

$ kovee inbox
act ai-1 (class model_egress) awaits your human-authority seat; exact subject digest ...
$ kovee act position ai-1 --value assent
position recorded; act ai-1 finalized deterministically

$ kovee daemon stop --force-test && kovee daemon start
recovered en-1; stale attempt fenced; current episode resumed

$ kovee endeavor show en-1 --open
deliverable cs-1 (base ..., 2 files) awaiting review_record; causal timeline available
```

The normal web product renders the same records through complementary lenses:
**Pulse** for attention, offers, results, conflicts, and pending act decisions;
**Workbench** for
the current synthesis, questions, claims, evidence, and commitments; **Stream**
for familiar chronological conversation; **Branch compare** for exact deltas and
merge proposals; and **Ensemble** for the dynamic graph of commitments, spend,
wait conditions, and context seen. Assistant registry, artifact review, endeavor
governance, provenance, and engram admission remain focused views. A graph
canvas is optional and is never the only usable interface.

K1 ships spaces, contributions, relations, and the Stream/Workbench lenses. K2
adds branches, reusable context recipes and attention-driven assemblies,
commitments, promotion, act decisions, pledge episodes, crash recovery, and
review; a complete source-qualified causal trail is the K2 exit criterion.
The K1 acceptance assistant is deterministic and does not call a model. A local
model-backed assistant requires the optional K2 `model_broker_v1` bundle; its
developer profile is auditable but not an egress-confinement claim. Enforced
model egress is a K4 capability.

### 6.2 Contribute, attend, and respond

1. A principal or fenced assistant appends a typed contribution to a space
   branch. Free-form chat is `kind:utterance` in a Stream lens.
2. Kovee authenticates the actor, checks space/object visibility and limits,
   assigns a BranchEntry sequence, Space contribution sequence, and project
   event sequence, and commits the contribution, structural
   relations, event, and outbox atomically.
3. Active attention contracts deterministically identify eligible changes. A
   durable Candidate records why a change was eligible, coalesced, suppressed,
   or selected; one Activation records the authorized notify/wake. Optional
   semantic triage can rank only that eligible set.
4. Before a wake, Kovee rechecks authorization, target acceptance, rate,
   concurrency, loop lineage, and budget, then materializes an immutable
   audience-specific `ContextAssembly` at an exact frontier.
5. A worker claims the invocation. The assistant may contribute claims,
   evidence, proposals, critiques, relations, or results; offer bounded work;
   and call a model through the broker when `model_broker_v1` is advertised.
6. Committed contributions and run transitions reach clients through authorized
   lenses/realtime delivery. A reconnect resumes from the canonical cursor.
7. If the worker dies, the lease expires and another attempt re-invokes
   `run(ctx)` from the immutable input, optionally using an application-defined
   compatible checkpoint. Stable operation keys return prior committed results,
   so replay does not repeat contributions, commitments, realizations, or
   effects. The old attempt
   can no longer write.

### 6.3 Promote a space frontier to governed work

1. A principal calls `endeavor_promotion_prepare` for an exact authorized
   Space/branch frontier, ContextAssembly, collaboration bundle, budget, and
   workspace terms; Kovee infers none of this from prose. The Society and its
   Participants already exist — promotion never enrolls members.
2. After reviewing that digest-bound subject, the principal calls
   `endeavor_promotion_start`. The Kovee byom adapter acquires the durable branch
   slot and executes only the stored `kovee_endeavor_form` command through the
   delegated principal binding. That one governance-surface command atomically
   commits the source principal's Position, the Decision, and the Endeavor,
   filling exactly one computed human seat; the space link does not make Kovee
   authoritative for Endeavor state.
3. Work decomposition is a lens, not a plan record: a Participant opens a Call
   and performers propose Pledges. Kovee renders the board; Byom owns the seats.
4. Consequential steps are **acts**, not gates. Byom server-prepares an ActIntent
   subject with its PreparationTrace; Kovee renders the inbox and exact diff; the
   eligible human fills its own seat with `act_intent_position` against the
   current subject digest under a fresh challenge, and `act_intent_finalize`
   commits deterministically. `endeavor_finalize` is formation, never a decision.
5. Accepted Pledges run concurrently as fenced Byom Episodes backed by Kovee
   invocations or attached harnesses. Kovee presence never overrides Byom state.
6. Deliverables are submitted with `delivery_submit` against the exact Episode
   fence and accepted with `review_record`. Kovee renders patches and artifacts
   against the recorded base digest.
7. Apply, outbound disclosure, budget changes, and closure are act classes with
   their own prepared subjects and eligible seats. Comments alone do not decide
   them.

### 6.4 Local assistant-to-assistant work

`ctx.request_work("researcher", need=..., outcome_schema=..., deadline=...)` is
SDK sugar for a directed Need, an exact Offer by the resolved deployment, and a
FormationProposal with separate requester and performer assent slots. The
current worker may fill only its own requester slot under its fenced bounded-
child-work capability; the policy service may fill the helper's performer slot
only from an exact active standing-policy use. A coordinator then finalizes the
complete set; that one transaction creates the Commitment, reservation, and
WorkRealization. The terms bind the context assembly, outcome/evidence schema,
reviewer, disclosure, budget, deadline, cancellation, and target revision.
Without the independent helper assent, the workflow remains visibly pending.
Waiting is a resumable SDK convenience, not ephemeral NATS request/reply. Parent
deadline, budget, ancestry, cancellation, and maximum depth bound child
commitments.

An open Need can solicit several deployments. Their offers record approach,
deliverables, cost, timing, capabilities, and disclosures. A
`FormationProposal` selects compatible offers and review/dependency edges; an
exact separately attributable assent fills every derived requester/performer
slot, after which finalization creates the commitments that form the current
agent team. Recomposition creates a new
formation revision and supersedes exact terms rather than silently retargeting
running work.

### 6.5 Cross-project and cross-realm work

- Inside one project, spaces remain separate visibility scopes; a relation or
  lens never bypasses their membership and object grants.
- Between projects in one realm, an exact handoff offer names the
  recipient, permitted actions, disclosure digest, uses, and expiry. The
  recipient admits it before an assistant wakes.
- Between realms under the same installation, the same offer/admission boundary
  carries only inert content or solicitation. It creates no obligation or work;
  governed cross-realm work additionally uses a Byom Mandate chain. A project belongs
  to exactly one realm in v0.1; there are no cross-realm joint projects or
  implicit guest memberships.
- Between independently administered installations, Byom authorizes the outbound
  act and Kovee's narrow `byom_akson_dispatch_v1` driver stages it, while Akson
  carries a signed contract. Raw NATS traffic never crosses this boundary.

### 6.6 Human intervention

When the owning state machine permits it, an authorized principal may intervene
without converting prose, graph position, or model ranking into authority.
Contributing, challenging, pinning, selecting an offer, and reviewing a local
commitment are Kovee collaboration;
endeavor hold/release, budget change, act decision, deliverable review, and
engram admission are Byom operations. Kovee invocations expose graceful
cancel and privileged force-cancel, not a generic “pause.” Reassignment never
mutates pinned terms: it cancels/supersedes the commitment and creates a new
offer/realization, or asks Byom for a new Pledge revision or Mandate derivation.
Every typed action records the authenticated principal, current revision, and
causal request. The UI enables only actions valid for that owner and state.

## 7. Architecture

```text
 web / CLI / mobile / connectors                 Python SDK / CLI harnesses
                  |                                        |
             HTTPS + WS/SSE                         worker protocol
                  |                                        |
┌─────────────────────────────────────────────────────────────────────────┐
│ Kovee API and realtime gateway                                          │
│ authentication · authorization · rate limits · command/query routing    │
├───────────────────────────────┬─────────────────────────────────────────┤
│ Space semantics               │ Byom governance adapter                 │
│ contributions · branches     │ BPP · act inbox · endeavor views        │
│ local commitments            │                                          │
├───────────────────────────────┼─────────────────────────────────────────┤
│ Lenses and context compiler   │ Runtime control                         │
│ views · context · attention   │ registry · scheduler · leases           │
├───────────────────────────────┼─────────────────────────────────────────┤
│ Effect and egress brokers     │ Artifact service                        │
│ models · tools · connectors   │ immutable verified bytes                │
├───────────────────────────────┴─────────────────────────────────────────┤
│ SQL transaction/event/outbox kernel · content-addressed artifact store  │
├─────────────────────────────────────────────────────────────────────────┤
│ Internal delivery: in-process (local) or NATS/JetStream (team)          │
└───────────────────────────────┬─────────────────────────────────────────┘
                                |
                      Akson adapter / aksond
                                |
                 independently administered peers
```

### 7.1 Component responsibilities

The boxes below are ownership modules, not a mandate for one microservice per
box. Through K4 the reference topology is a modular `koveed` control/API process,
separate confined worker processes, separate `byomd` and optional `aksond`, and
the selected SQL/object-store/delivery dependencies. A module may split into an
independent service only for measured scale, regional placement, or isolation;
its protocol, workload identity, transaction boundary, and state ownership must
then remain explicit. Co-location never permits cross-module table writes.

**API and realtime gateway**

- Terminates authenticated client connections.
- Negotiates protocol versions and features.
- Derives actor identity from the channel.
- Authorizes every command, query, replay, and live event delivery.
- Routes commands to their single semantic owner.
- Exposes snapshots, cursored events, WebSocket/SSE, and upload tickets.
- Never converts client-published data directly into a system event.

**Space semantics**

- Owns realms, projects, space access/participants, contributions, relations,
  branch entries/merges, lenses, local Needs/Offers/Formations/Commitments,
  links, handoffs, and their Kovee events.
- Treats semantic relations, syntheses, confidence, and model scores as
  attributed data. Only closed structural transitions affect the state machine.
- Assigns dense Contribution order per Space and BranchEntry order per branch; the shared
  transaction/ledger kernel assigns Kovee project sequences for every owner.
- Compiles accepted assistant commitments into pinned runtime realizations but
  never compiles Kovee records into Byom authority without a BPP command.

**Lenses and context compiler**

- Produces authorized Stream, Workbench, Pulse, Branch compare, Ensemble, search,
  and provenance views over the canonical records.
- Evaluates deterministic attention eligibility, records optional semantic
  triage as an attributable invocation, and materializes exact context
  assemblies for an audience at a pinned frontier.
- Owns context recipes/assemblies and attention contracts/candidates/activations;
  it cannot activate a widening contract without the target's exact receipt.
- Stores embeddings, ranking features, summaries, and saved view indexes only as
  rebuildable projections. A similarity result neither proves visibility nor
  creates a relation, wake, or claim.
- Never adds ambient space history, hidden instructions, current object
  revisions, or inaccessible relation endpoints to an assembly.

**Byom governance adapter** (`kovee-byom`)

- Speaks the Byom Participation Protocol over byomd's per-surface sockets —
  governance, candidate, participant, projection, and runtime — without changing
  their semantics. The sixth BPP surface, admin, belongs to the byomd operator
  and Kovee never calls it.
- Exposes those commands and views through the unified Kovee gateway. BPP
  envelopes are never nested inside KCP ones and the two problem namespaces stay
  distinct (`https://byom.dev/problems/*` versus `urn:kovee:error:*`).
- Converts Byom journal entries into read-only Kovee projections carrying the
  source cursor, revision, and digest.
- Implements the Kovee worker as a Byom Manifestation — a hosted episodic
  participant or an attached harness.
- Owns the C2 host records (`KoveeRealmByomBinding`, `KoveeSocietyMapping`,
  `KoveeGovernanceOwnerBinding`, `ByomEpisodeBinding`, `PlacementBinding`,
  `EndeavorFormationIntent/Slot/Attempt`, the `byom_subordinate` reservation
  bridge) and the `byom_akson_dispatch_v1` driver.
- Never fills a Byom seat, forges a Participant actor, authors Society state, or
  writes Byom tables from a UI projection. Kovee is never the genesis governance
  actor: a Society is established through native `society_prepare`/
  `society_bootstrap` under the bootstrap human's own governance channel.

**Runtime control**

- Owns assistant definitions, immutable revisions, deployments, invocations,
  attempts, worker leases, checkpoints, commitment work realizations,
  reservations, and usage.
- Resolves deployment aliases and placement deterministically.
- Treats NATS deliveries as wakeups; a worker must claim authoritative SQL state
  before executing.

**Effect and egress brokers**

- Execute prepared, authorized effects through narrow drivers.
- Keep model, connector, tool, storage, and cloud credentials outside agent code.
- Bind every effect to a current fence, idempotency key, policy/decision, budget,
  and disclosure manifest.
- Reconcile ambiguous non-idempotent outcomes.

**Artifact service**

- Issues bounded upload/download capabilities.
- Verifies size and digest, records media type and classification, runs configured
  malware/active-content/secret checks, and exposes only finalized artifacts.
- Stores immutable bytes addressed by digest; owner records control visibility.

**Delivery fabric**

- Carries committed event notifications, work hints, projection jobs, and lossy
  presence signals between trusted services.
- Is replaceable. No public compatibility guarantee includes a subject name,
  JetStream sequence, consumer name, or NATS header.

### 7.2 State ownership

| State | Authoritative owner |
|---|---|
| Realm, principal binding, project membership | Kovee identity/collaboration service |
| Space/access/participant, contribution/relation, branch/merge, lens, local Need/Offer/Formation/TermsAssent/Commitment, handoff | Kovee space semantics |
| Context recipe/assembly, attention contract/candidate/activation/triage/use account | Kovee attention/context compiler |
| CollaborationContextBundle, EndeavorFormationIntent/Slot/Attempt, ExternalLink, KoveeRealmByomBinding, KoveeSocietyMapping, KoveeGovernanceOwnerBinding, ByomEpisodeBinding, PlacementBinding, WorkspaceProviderManifest/AllocationBinding | Kovee byom integration/runtime adapter; the referenced Endeavor, ResourceAllocation/WorkspaceAllocation, and act outcome remain Byom-owned |
| Assistant definition/revision/deployment, invocation, attempt, work realization, Kovee runtime budget/usage, EnforcementEvidence | Kovee runtime control/supervisor |
| Kovee authorization policy, action intent/decision, policy ceiling, effect/receipt, model-provider binding, model/tool/connector profile | Kovee effect/policy/egress service |
| ProviderContextManifest | Kovee egress broker; the source ContextAssembly is Kovee-owned and the referenced Byom ContextManifest remains Byom-owned |
| Artifact metadata, upload session, grant/use | Kovee artifact service |
| Kovee event/project-sequence allocation, idempotency, outbox/inbox | Shared Kovee transaction/ledger kernel |
| Society, Charter, Participant/Manifestation, Assembly, Endeavor, Call, Pledge, Mandate/StandingMandate, ActIntent/Decision, Activity/Episode/EpisodeLease, ResourceAllocation, Byom budget account, engram | Byom implementation (`byomd` in the reference product) |
| Peer identity/binding, contract, signed remote outcome/evidence | Akson (`aksond`) |
| Artifact bytes | Content-addressed object store; metadata/access remain with Kovee artifact service |
| NATS message | No domain ownership; it is a delivery copy |
| Search/embedding/lens/context candidate projection | No authority; every result is reauthorized and Kovee-owned indexes are rebuildable; external views require a source-authorized snapshot and boundary cursor |

No record has two writers. A projection MUST expose its source owner, source
revision, source cursor, and staleness. If a Byom or Akson projection disagrees
with its source, the source wins and the projection is invalidated. It is rebuilt
only if that source supplies an authorized full snapshot plus boundary cursor;
otherwise Kovee reports rebuild unavailable or replays a separately retained,
governed integration journal within its declared coverage.

The transaction/ledger kernel is the sole allocator of Kovee project sequences.
While modules share `koveed` and SQL, each owner validates its transition and
uses the kernel inside the same database transaction. If a module later moves to
another process but retains the same KCP ordering guarantee, its mutation still
commits through this single transactional write boundary; an asynchronous event
cannot reserve a project sequence retroactively. A module with an independent
database instead exposes its own source cursor and requires a protocol revision
before dropping or redefining dense Kovee project order.

### 7.3 Byom integration forms

Initial integration runs `byomd` as a separate service with its own store, one
dedicated instance per realm. Kovee MAY later embed a conformant alternate Byom
implementation in the same Rust process/PostgreSQL cluster, but doing so requires
a Byom storage/hosting ADR and the full BPP conformance suite; an unmodified
`byomd` cannot simply use Kovee's tables. In either form:

- BPP and Byom's state machines remain the semantic source of truth.
- A future embedded module owns separate tables/migrations and commits its own
  state, journal entries, and outbox in one SQL transaction.
- A separate service publishes from its own transactional outbox and Kovee
  consumes by durable Byom cursor (`events_read`/`events_wait`). There is no
  cross-service dual write.
- Kovee clients reach Byom through the adapter over an authenticated per-surface
  binding; they never read Byom tables.
- Byom events can be replayed into Kovee projections within source retention.
  Full rebuild additionally requires an authorized snapshot (`snapshot_get`) plus
  boundary cursor, with `cursor_recover` and `recovery_checkpoint_show` covering
  expired cursors, endpoint incarnation, and recovery epoch.

### 7.4 Language split

“Python” is an authoring decision, not a requirement that the correctness kernel
import Python modules.

- The reference Kovee control plane is Rust, matching Byom's implementation and
  allowing shared protocol/conformance discipline.
- The first assistant SDK and worker runtime are Python.
- A TypeScript client SDK serves web and connector authors.
- Any language may implement the public or worker protocols after passing the
  conformance suite.
- LiteLLM MAY be one model-broker adapter. It is neither the public Kovee model
  contract nor a dependency of the control kernel.

## 8. Installation profiles

| Profile | Authoritative state | Delivery | Client access | Federation |
|---|---|---|---|---|
| **personal** | SQLite WAL + local content-addressed files | In-process durable queue/wakeup | UDS and loopback HTTP/WS; same-user authentication | Optional local Akson |
| **team** | PostgreSQL + S3-compatible object store | Internal NATS/JetStream | HTTPS + WS/SSE; OIDC/passkeys; service mTLS | Akson adapter |
| **federated** | Independent personal/team installations | Separate internal fabrics | Each installation controls its own clients | Akson/A2A only |

Personal and team modes implement the same resource and command semantics.
Differences in authentication and availability are negotiated features, not
different domain models. An installation can be self-hosted; no Kovee-operated
control plane is required.

Team mode assigns every realm a home write region. Writes route to that region
or fail closed during a partition; Kovee v0.1 does not perform active-active
multi-master mutation. Read projections MAY replicate to other regions and MUST
show their source cursor/staleness.

## 9. Authentication and authorization

### 9.1 Authentication

- Human principals authenticate with installation-configured OIDC and/or passkeys.
  Local mode may bind one principal to Unix peer credentials.
- A browser session uses short-lived, audience-bound session credentials with
  CSRF and origin protections; tokens MUST NOT be stored in event payloads.
- Backend services use mTLS or equivalent short-lived workload identity.
- Connectors use a dedicated service identity and installation scope, not the
  installing human's reusable credential.
- Worker instances receive an expiring instance identity. Assistant code receives
  only a per-invocation capability channel/token bound to the installation,
  invocation, attempt, fence, audience, expiry, and exact allowed operations.
- Akson peers retain Akson issuer-qualified identity and binding epochs. A Kovee
  display actor for a peer cannot be used as local authentication.

The authenticated identity and active delegation determine the actor. A request
field named `actor_id`, `principal_id`, `agent_id`, or `peer_id` is never enough
to act as that identity.

### 9.2 Authorization dependency sets

Authorization never depends on one magic epoch. Every derived token, attention
activation, context assembly, snapshot, invocation, handoff, and effect binds a canonical set of
the exact authority inputs used:

```text
AuthorizationDependencySet {
  dependency_set_id,
  actor_ref, operation, resource_refs[],
  dependencies[]: {
    owner_protocol,
    kind,
    ref,
    revision?, epoch?, digest?
  },
  evaluated_at,
  authority_digest
}
```

`kind` is a closed enum whose initial categories include principal status,
authentication-binding security epoch, current authentication observation,
service identity/capability, installation recovery epoch, realm status/kill
epoch, project status/revision, target resource revision, membership, space
access/participant binding, branch status/frontier, contribution/relation
endpoint visibility, lens scope, attention revision/acceptance, context-item
visibility, commitment terms/acceptance, classification/retention policy,
remaining-use grant, Kovee policy set, realm governance binding, and
external Byom visibility proof (Byom's own visibility closure on every projected
read). The operation defines its required categories;
an implementation cannot omit a category merely because it is inconvenient to
load. An absent required dependency fails closed.

`authority_digest` is the section 11.8 `CanonicalObjectDigest` for kind
`authorization-dependency-set` over `{actor_ref, operation, resource_refs,
dependencies}` only. It excludes `dependency_set_id` and `evaluated_at` so a
fresh evaluation of unchanged authority has the same digest. Resource refs and
dependencies are normalized and sorted by their closed tuple keys; duplicates,
ambiguous owner names, and multiple revisions for one dependency are rejected.
The record is immutable. A new evaluation gets a new id and audit time even when
its authority digest is unchanged.

Immediately before a protected read, delivery, mutation, or effect, the owner
loads the current dependencies and compares/re-evaluates them transactionally.
Changing any component invalidates the derived authorization even when other
epochs remain equal. Coarse realm/recovery epochs provide emergency invalidation
but never replace membership, participant, grant-use, policy, or binding checks.

Sets are operation-specific, not blindly inherited. A current authentication
observation is required for the human command it authenticates, but an already
accepted durable invocation subsequently uses its worker capability plus current
persistent membership/grant/policy dependencies; ordinary browser-session expiry
does not rewrite history or necessarily cancel pure computation. A later human
decision or effect still requires fresh assurance when its row requires it.
Likewise, an allocation operation may depend on a grant's remaining-use counter,
while an already issued access session depends on its own use row plus the
grant's revocation security epoch. Telemetry and unrelated counter changes are
never added merely to force broad invalidation.

### 9.3 Membership and roles

Kovee defines realm roles `owner | admin | member | auditor` and project roles
`owner | maintainer | contributor | viewer | guest`. Permissions are closed,
versioned actions such as `space.read`, `contribution.append`,
`relation.assert`, `branch.merge`, `attention.activate`, `formation.accept`,
`commitment.review`,
`assistant.deploy`, and `handoff.offer`; roles expand to declared action sets.

Byom Participant admission and Society decision rules remain Byom records. A
Kovee project owner is not automatically eligible for a Byom human-authority
seat, and no Kovee role manufactures Participant membership. The UI must show
both scopes when they differ.

Authorization is deny-by-default and checks, in order:

1. Installation and realm status.
2. Authenticated identity status and session assurance.
3. Resource realm/project and current membership.
4. Operation-specific role/capability.
5. Resource revision, grant, participant, classification, and retention policy.
6. Any required exact decision receipt, budget, or disclosure authorization.

Revocation increments the affected membership/realm epoch. Long-lived attention
contracts and worker tokens bind an authorization-dependency-set digest and
are closed or rejected when any dependency changes. Each live event delivery is
rechecked; authorizing only at WebSocket setup is insufficient.

### 9.4 Human approval

Only an authenticated principal with the required role and assurance may make a
human-governance decision. Service identities, assistants, peer claims,
contributions, model prose, and application events cannot satisfy one. High-risk
policies MAY require step-up
authentication. Decisions record the authentication reference without storing
reusable authentication secrets.

Byom act decisions use Byom's decision rules, subject digests, seat eligibility,
separation of duties, Mandates, and StandingMandateRevisions. Kovee may render
and route them — it prepares nothing and fills no seat — but the position and the
deterministic finalization are committed by Byom. For a Kovee-owned effect, Kovee
uses the same exact-intent pattern defined in section 16.

### 9.5 Kovee policy revisions

Kovee-owned standing authorization uses immutable, digest-addressed revisions:

```text
AuthorizationPolicyRevision {
  policy_id, revision, previous_digest?, realm_id, project_id?,
  effect: allow|deny,
  subject_selector, actions[], resource_selector,
  conditions {
    space_refs[], target_participant_or_deployment_refs[],
    classification_refs[], context_recipe_or_schema_refs[],
    outcome_schema_refs[], recipients[], model_or_tool_profiles[],
    regions[], maximum_deadline?, assurance_level?, time_window?
  },
  ceilings {
    uses?, bytes?, cost_by_unit?, concurrency?, expires_at
  },
  ceiling_account_ref?, accounting_epoch?, ceiling_spec_digest?,
  proposed_by_actor, proposer_invocation_ref?, approved_by_decision?,
  digest, status: proposed|active|revoked|superseded
}

PolicyCeilingAccount {
  account_id, policy_id, accounting_epoch,
  realm_id, project_id?, ceiling_spec_digest,
  limits {uses?, bytes?, cost_by_unit[]: {unit, limit}, concurrency?},
  counters {
    uses: {reserved, committed, uncertain},
    bytes: {reserved, committed, uncertain},
    cost_by_unit[]: {unit, reserved, committed, uncertain},
    concurrency: {held, active}
  },
  state: active|draining|closed, revision
}

PolicyCeilingReservation {
  reservation_id, account_id, accounting_epoch,
  policy_revision_ref, policy_digest,
  intent_id, intent_digest, decision_id, use_key, use_ordinal,
  authorized_action_kind: domain_transition|effect_execution,
  authorized_action_ref?, authorized_action_digest?,
  allocated {uses, bytes, cost_by_unit[]: {unit, amount}},
  committed {uses, bytes, cost_by_unit[]},
  uncertain {uses, bytes, cost_by_unit[]},
  released {uses, bytes, cost_by_unit[]},
  remaining {uses, bytes, cost_by_unit[]},
  concurrency_units,
  concurrency_state: none|held|active|released,
  domain_transition_ref?, effect_id?, execution_permit_ref?,
  state: held|active|settled|ambiguous|released|expired,
  expires_at, settlement_revision,
  UNIQUE(account_id, intent_id, use_key),
  UNIQUE(decision_id, use_key)
}
```

The v0.1 selector language is closed and conjunctive; it contains no arbitrary
code, network lookup, regex supplied by assistants, or payload prose. Evaluation
is deterministic against an exact intent snapshot. An applicable deny wins. If
no deny applies, at least one allow must match every requested action and
condition; multiple allows do not union into broader authority unless one policy
revision explicitly contains that combined grant. Ceiling reservations are
atomic.

An assistant or service may author only an inert `proposed` policy revision,
with its attributable actor/invocation provenance. `approved_by_decision` is
absent until an authenticated principal adopts that exact digest; only `active`
revisions authorize. Adopting, replacing, or revoking a policy requires an
authenticated principal decision on its exact digest. A new revision invalidates unused derived permits
from its predecessor. Every match mints a decision receipt for the exact intent,
records the policy digest, decrements/reserves its ceilings, and remains visible
in the audit trail. Assistants and service identities may propose a policy but
cannot activate or widen one.

Ceilings use a ledger, not a mutable counter hidden in the evaluator. `uses`
counts consumed authorized domain transitions or execution permits; byte and
cost dimensions use the exact quantity vector defined by the action schema;
concurrency counts only a declared held/active lifecycle. Instantaneous domain
transitions declare zero concurrency. Quantities are bounded integers or registered fixed-point units,
never floats. A policy-derived decision selects one authorizing policy revision,
locks all ceiling and budget accounts in canonical id order, and atomically
reserves every applicable dimension or none.

For every cumulative dimension `d`,
`committed[d] + reserved[d] + uncertain[d] <= limit[d]`; each reservation obeys
`allocated[d] = committed[d] + uncertain[d] + released[d] + remaining[d]`.
Concurrency obeys `held + active <= limit`, and account counters equal the sum
of reservation rows. Authorized-action consumption moves one use to committed;
effect-permit consumption also moves declared concurrency from held to active
before egress. Known settlement commits actual bytes/cost and releases the
remainder/concurrency once; an ambiguous effect outcome moves the maximum
possibly spent amount to `uncertain` until explicit reconciliation.
Cancellation, denial, expiry, or revocation before consumption releases
remaining amounts once. Stable use/settlement keys make all transitions
idempotent.

Policy revisions share their policy's `accounting_epoch` by default; editing or
re-adopting cannot reset usage. An exact principal decision is required to open a
new epoch and must show prior committed/reserved/uncertain totals. A lowered
limit already exceeded by live totals enters `draining` and authorizes nothing
new. Existing and ambiguous uses settle against their original epoch. V0.1 has
no implicit rolling-window reset.

For a non-effect domain transition authorized by standing policy—such as an
Attention activation, recording an exact Formation/amendment `TermsAssent`, or
a policy-based review—the owning domain transaction consumes policy
authority atomically with the transition. It locks the decision and ceiling
account, derives a stable `use_key` from the action kind, target id/revision, and
subject digest, inserts one
`DecisionUse{authorized_action: DomainTransition{...}}`, commits the
declared use/quantity counters, and writes state, event, and outbox rows together.
A retry returns that same use/transition; a different digest cannot reuse it.
There is no `ExecutionPermit` or `Effect` on this path. Concurrency is zero unless
the registered action schema explicitly binds it to a durable lifecycle, in
which case settlement/release is tied to that exact terminal transition. Failure
before commit consumes nothing; an ambiguous external outcome is impossible
because this path is one local authoritative transaction.

In field names and prose, `policy_use_ref` or “policy-use receipt” means the
exact authorizing `DecisionReceipt` plus its consumed
`DecisionUse{authorized_action:DomainTransition}`; it is not a second record
type. The ref stored on a transition points to that `DecisionUse`.

## 10. Authoritative data model

Fields below define the minimum abstract model. Physical tables may normalize
them differently, but implementations MUST preserve the identities, revisions,
constraints, and ownership semantics.

Every independently addressable immutable Kovee record carries fixed
`revision: 1` even where an abbreviated block omits the field; every mutable
aggregate root carries a monotonic revision used for compare-and-swap. A mutable
subordinate row either carries its own revision or is updated only under its
owner root's revision/fence plus a declared unique transition key; no mutable
state is written unfenced. Exact object refs always include the applicable
revision and canonical digest—immutability never means “revision unknown.”

### 10.1 Realm and project

```text
Principal {
  principal_id, installation_id, revision,
  display_name, status, created_at
}

PrincipalAuthBinding {
  auth_binding_id, installation_id, principal_id, revision,
  canonical_issuer, provider_subject_ref, assurance_ceiling,
  status, security_epoch, created_at
}

AuthenticationObservation {
  observation_id, auth_binding_id,
  authenticated_at, observed_assurance_level, methods[],
  channel_binding_digest?, provider_event_ref?, expires_at
}

ServiceIdentity {
  service_identity_id, installation_id, realm_id?, revision,
  service_kind, workload_issuer, workload_subject,
  allowed_surfaces[], capability_set_digest,
  security_epoch, status, expires_at?
}

InvocationCapability {
  capability_id, invocation_id, attempt_id, fence_epoch,
  worker_service_identity_ref, audience,
  allowed_operations[], resource_scope_digest,
  authorization_dependency_set_ref, authority_digest,
  issued_at, expires_at, status, digest
}

Realm {
  realm_id, installation_id, revision, name, status,
  home_region, auth_policy_ref, retention_policy_ref,
  encryption_key_ref, created_at
}

Project {
  project_id, realm_id, revision, name,
  status: active|suspended|archived,
  default_classification_ref, policy_set_ref,
  created_by, created_at
}

ProjectAccessPolicyChange {
  change_id, project_id, expected_project_revision,
  prior_policy_set_ref, proposed_policy_set_ref,
  prior_default_classification_ref, proposed_default_classification_ref,
  affected_space_frontier_refs[], affected_item_set_digest,
  effective_change: narrowing|widening|incomparable,
  classification_join_ref, destination_audience_digest,
  subject_digest, prepared_by_principal, decision_receipt_ref?,
  state: prepared|confirmed|canceled|stale,
  revision, created_at, terminal_at?
}

Membership {
  membership_id, subject_ref, realm_id, project_id?,
  role, authorization_epoch, status, expires_at?, revision
}

EnrollmentInvitation {
  invitation_id, realm_id, project_id?, revision,
  recipient_constraint, proposed_role,
  token_hash, invited_by_principal, expires_at,
  state: pending|accepted|declined|expired|revoked
}

JoinRequest {
  join_request_id, realm_id, project_id?, principal_id,
  requested_role, state, decided_by?, revision
}

KoveeRealmByomBinding {
  binding_ref, realm_ref, binding_revision, binding_epoch,
  predecessor_binding_ref?, predecessor_binding_digest?,
  binding_lineage_ref?, binding_lineage_digest?,
  byom_endpoint_ref, endpoint_incarnation,
  compatibility_bundle,
  delegated_principal_audience, external_authorization_audience,
  historical_recovery_mode: disabled|exact_formation_intent_only,
  recovery_authorization_policy_ref, recovery_authorization_policy_digest,
  status: pending|active|void,
  dependency_digest, digest
}

KoveeSocietyMapping {
  realm_ref, society_ref, society_recovery_epoch,
  allowed_project_and_space_selectors[],
  classification_binding_ref,
  governance_owner_binding_ref, governance_owner_binding_digest,
  status: pending|active|void, revision, digest
}

KoveeGovernanceOwnerBinding {
  realm_ref, exact_scope_selector, exact_scope_digest,
  revision, binding_epoch,
  governance_owner: byom|none,
  owner_endpoint_ref?, owner_binding_ref?, cutover_ref?,
  status: active|frozen, digest
}

RealmAksonBinding {
  binding_id, realm_id, revision, status,
  akson_endpoint_ref, akson_binding_epoch,
  isolation_mode: dedicated|verified-multitenant
}
```

A project is the administrative container for ownership, policy, billing, and
deployment. A space is the normal collaboration and content-visibility boundary
inside it. Project membership makes a subject eligible for space access; it does
not by itself reveal a restricted space. Moving content between projects or
spaces is a handoff/copy with a disclosure and admission record, never an
in-place id change. Deleting access does not delete authored history; it removes
future access and invalidates credentials derived from it.

`project_update_metadata` cannot change status, `policy_set_ref`, or default
classification. Project policy/default changes use a prepared
`ProjectAccessPolicyChange` over the exact affected Space frontiers/item set and
effective audience. Even a provable narrowing requires the typed confirm path;
a widening/incomparable change additionally requires the configured disclosure
assurance and shows the impact set. Confirmation compare-and-swaps the Project
revision; changing content/policy makes it stale. It never overrides Space or
item-level restrictions. Project suspension/recovery is an installation-admin
operation, not metadata editing.

Principal creation requires a verified authentication-provider binding plus
realm enrollment policy, an accepted invitation, or an approved join request.
An invitation token is stored only as a hash and does not itself authenticate a
principal; acceptance checks the authenticated provider identity against its
recipient constraint and atomically creates the membership. Open invitations,
role widening, reuse, and acceptance after expiry are forbidden in v0.1. The
first installation owner is created by an audited one-use bootstrap action.

Every realm has zero or one active Byom governance binding in v0.1 and at most
one active Akson binding. Without Byom, the negotiated `governed_work` feature is
absent and Endeavor operations are unavailable; open-space mode still works. A
project can link only to Endeavors and peer operations under its realm's current
binding. Endpoint credentials are secret-manager references, not fields in these
portable records. Changing the endpoint, its incarnation, or the Society mapping
increments the binding epoch and invalidates derived channels and permits.

The three records are one saga, not three independent settings.
`KoveeRealmByomBinding` and `KoveeSocietyMapping` are created inert (`pending`),
and the `KoveeGovernanceOwnerBinding` is then compare-and-swapped from `none` to
`byom` at an exact expected revision; only that CAS activates them. Overlapping
`exact_scope_selector` scopes are rejected, an exact retry returns the identical
binding, and a failure before activation rolls back rather than leaving a
half-owned realm. The enum has exactly these two arms: a governed scope is
owned by byom or by nothing (amendment A9). There is no third owner and no
cutover machine — greenfield enablement is the only owner transition, and
`governance_disable` freezes the row rather than handing it to anyone else.
Byom is this stack's governance owner from day one (kovee amendment A1,
family-contract amendment A2). Kovee is
never the genesis governance actor — the Society must already be `active` when
the binding is created, which the adapter proves with a `society_show` read.

`security_epoch` changes only when the issuer/subject binding, status, assurance
policy, or another security-relevant property changes. Login timestamps are
append-only telemetry in `AuthenticationObservation`; ordinary authentication
does not bump the epoch or invalidate every active attention contract and
invocation.

There is at most one active binding for
`(installation_id, canonical_issuer, provider_subject_ref)`, enforced by a
database uniqueness constraint. Issuer canonicalization follows the configured
provider metadata; display email, name, and unverified claims never merge
principals. Linking a new binding requires a current step-up observation on the
existing principal, a fresh proof from the new provider, and confirmation of the
exact issuer/subject pair. A collision with another principal fails closed.

`assurance_ceiling` caps what the binding may assert. Each sensitive command and
human decision references a current `AuthenticationObservation` and uses the
lower of its observed assurance and that ceiling; the mutable binding record is
not evidence that step-up occurred for this command. Recovery is an audited,
one-use ceremony under installation policy (recovery code in personal mode or
separated administrators/strong factor in team mode), revokes old sessions,
rotates the binding security epoch, and never infers identity from email. Kovee
v0.1 does not merge two principals or rewrite authored history; a future merge
requires an exact, reviewable merge plan and dedicated protocol operation.

### 10.2 Spaces, contributions, relations, and lenses

```text
Space {
  space_id, realm_id, project_id, revision,
  title, purpose_contribution_ref?,
  visibility: project|restricted,
  status: open|frozen|archived,
  main_branch_id, next_space_sequence,
  default_classification_ref, policy_set_ref,
  created_by, created_at
}

SpaceParticipant {
  participant_id, space_id, subject_ref,
  subject_revision?,
  kind: principal|assistant_deployment|service|peer_projection,
  role: steward|contributor|observer,
  authority_source_ref,
  status: proposed|active|muted|revoked, revision
}

SpaceAccessGrant {
  space_access_id, space_id, subject_ref, revision,
  source_membership_or_policy_ref,
  allowed_actions[], classification_ceiling_ref?,
  authorization_epoch, expires_at?, status: active|revoked|expired,
  granted_by_or_policy_use_ref, created_at
}

SpaceAccessWidening {
  widening_id, space_id, expected_space_revision,
  prior_visibility, proposed_visibility,
  prior_policy_set_ref, proposed_policy_set_ref,
  prior_default_classification_ref, proposed_default_classification_ref,
  affected_frontier_refs[], affected_item_set_digest,
  classification_join_ref, destination_audience_digest,
  subject_digest, prepared_by_principal,
  decision_receipt_ref?,
  state: prepared|confirmed|canceled|stale,
  revision, created_at, terminal_at?
}

ContributionKind =
  utterance|goal|question|claim|observation|evidence|
  proposal|critique|synthesis|result|decision_reference|system_notice

Contribution {
  contribution_id, revision: 1, realm_id, project_id, space_id,
  origin_branch_id, origin_branch_sequence, space_sequence,
  author_actor_ref, kind: ContributionKind,
  schema_ref, body_parts[], subject_refs[], source_refs[],
  epistemic_posture?: asserted|tentative|observed|reported|contested,
  invocation_ref?, context_assembly_ref?, causation_ref?,
  classification_ref, retention_policy_ref,
  content_digest, created_at
}

ContributionPart =
  TextPart {media_type, text, language?}
  | DataPart {schema_ref, value}
  | ArtifactPart {artifact_ref, title?}
  | ReferencePart {object_ref, object_revision?, digest?}
  | MentionPart {
      target_kind: principal|assistant_alias,
      target_ref, target_revision, display_text
    }

ContributionDisposition {
  disposition_id, contribution_ref,
  kind: withdraw|supersede|redact,
  replacement_ref?, reason_class,
  authorized_by_ref, payload_removed_at?, created_at
}

RelationKind =
  addresses|supports|challenges|refines|qualifies|supersedes|
  depends_on|derived_from|produced_by|quotes|evaluates

SpaceRelation {
  relation_id, revision: 1, space_id, origin_branch_id, branch_sequence,
  author_actor_ref, kind: RelationKind,
  from_ref: {object_ref, revision, digest},
  to_ref: {object_ref, revision, digest},
  rationale_ref?, relation_class: structural|semantic_assertion,
  classification_ref, schema_ref, digest, created_at
}

RelationDisposition {
  disposition_id, relation_ref, kind: retract,
  authorized_by_ref, reason_class, created_at
}

Reaction {
  reaction_id, space_id,
  target_ref, target_revision, target_digest,
  actor_ref, key, state: present|removed,
  revision, updated_at,
  UNIQUE(target_ref, actor_ref, key)
}

SpaceFrontier {
  frontier_id, revision: 1, space_id, branch_id,
  branch_sequence, branch_head_digest,
  project_event_cursor, external_source_cursors[],
  created_at, digest
}

SpaceLens {
  lens_id, space_id, owner_ref?, revision,
  kind: stream|workbench|pulse|branch_compare|ensemble|provenance|custom,
  query_ast, sort_spec, presentation_options,
  visibility, status, created_at
}
```

A space belongs to exactly one realm, project, and home write boundary. A
cross-realm or cross-installation “shared space” is an immutable disclosed bundle
and admitted local projection, never live multi-writer state or distributed
consensus. `restricted` additionally requires an active `SpaceParticipant`;
project administration alone does not make an ordinary content read. An active
`SpaceAccessGrant` supplies the restricted-space action set but is intersected
with current realm/project membership, policy, object classification, and source
authorization on every use; it cannot outlive or widen its source authority.
Participation supplies addressability, role presentation, and a revocation
anchor—not authentication or execution authority. A principal still needs a
current authenticated membership/access decision; an assistant still needs a
fenced invocation capability; a peer projection can never act as a local actor.

Ordinary `space_update_metadata` cannot change visibility, policy, or default
classification. `space_restrict` proves the one-way narrowing
`project -> restricted`; `space_policy_narrow` succeeds only when the kernel
proves that every effective access/disclosure rule is no broader. Any broader or
incomparable change uses a prepared `SpaceAccessWidening`: Kovee pins the exact affected frontiers/item-set,
classification join, current Space revision, and destination project audience;
an authorized steward/owner reviews that subject under required assurance before
`space_access_widen_confirm` compare-and-swaps the revision. Every item-level
classification/retention/source rule still applies, so widening the Space never
declassifies an object. A changed item set or revision makes the intent stale.

Space lifecycle is typed and compare-and-swapped. `space_freeze` changes
`open -> frozen`, rejects new contributions, relations, Needs/Offers/Formations,
attention activations, and direct invocations in that Space, and holds queued
work; administrative restriction, redaction/withdrawal, cancellation,
reconciliation, and terminal accounting remain available. Running attempts lose
their content/delivery write scope and must yield or be canceled rather than
smuggling output into the frozen Space. `space_reopen` alone changes
`frozen -> open` after reauthorization. `space_archive` requires `frozen`, fences
remaining work, and is terminal/read-only except retention, erasure, audit, and
reconciliation. None of these operations deletes history or widens access.

Contributions are immutable externalized collaboration objects. Hypothesis is a
`claim` with `epistemic_posture:tentative`; evidence records provenance but Kovee
does not infer that it proves a claim. Corrections append a new contribution and
disposition/relation. Authorized erasure may remove payload bytes while retaining
the minimum permitted tombstone and digest. Unknown extension kinds remain inert
data until a negotiated schema gives them presentation semantics; extensions can
never add authority-bearing relation behavior.
`decision_reference` points to an owner-protocol decision and `system_notice`
reports a Kovee-observed condition; neither record decides or authorizes anything
by its own presence.

Every `subject_ref`, `source_ref`, `ReferencePart`, `ArtifactPart`, and structured
address points to an object in the same space or to an immutable local copy
already admitted into that space. A foreign owner-protocol ref may appear only
inside an authorized `ExternalLink` whose existence/classification the audience
may see; rendering never dereferences it without current source authorization.
Appending a contribution reauthorizes every referenced object and joins its
classification. Bare cross-space ids, revisions, digests, counts, or error
differences are forbidden because metadata can itself disclose existence.

Relations use the closed enum above and pin exact visible endpoint revisions.
Both endpoints belong to the same space; a cross-space or cross-realm reference
must first arrive through an explicit handoff/admission and points to the local
admitted copy. A relation never imports its target.
Kovee may create `structural` relations only for facts its transaction observed,
such as `produced_by`; `supports`, `challenges`, `refines`, and other semantic
edges remain attributed assertions even when a model assigns them. A relation
does not confer visibility, admission, truth, trust, acceptance, scheduling,
execution, or permission transitively. Hidden endpoints are non-enumerable
through traversal errors, counts, ranking, or search.
Retraction appends a `RelationDisposition`; it never deletes or rewrites the
assertion or its provenance.

The public/worker `relation_assert` schema excludes `relation_class` and always
creates `semantic_assertion` under an attributable actor. The internal
`structural_relation_record`/`structural_relation_dispose` operations are callable
only by the owning Kovee service; the service derives both the structural kind
and endpoints from a fact committed in the same transaction. An external caller
cannot request, spoof, or upgrade a structural relation.

A Reaction is a lightweight mutable presentation signal by one actor. It obeys
the same-space/reference visibility rules and idempotent revision checks, but it
is not evidence, a vote, consensus, acceptance, attention, or authority.

Graph queries have installation limits for depth, fan-out, returned nodes,
cycles, cost, and wall time. Semantic cycles may exist, but no scheduler follows
them as executable control flow. Every read, relation traversal, search result,
replay, and live delivery rechecks space membership, object visibility,
classification, linked Byom/Akson source authorization, and the caller's exact
operation.

A lens is a declarative, schema-bounded presentation over authorized canonical
records in one space. It cannot traverse into another space without an admitted
local copy. Saved custom lenses use a closed query AST over indexed fields and
bounded relation traversal; they contain no arbitrary code. Embeddings, model
summaries, ranks, and cached “current synthesis” are projections. They cannot add
objects to a result before those objects pass ordinary authorization.

### 10.3 Reasoning branches and merge

```text
ReasoningBranch {
  branch_id, space_id, revision, purpose_contribution_ref,
  parent_branch_id?, base_frontier_ref, base_frontier_digest,
  next_branch_sequence, head_digest,
  status: open|frozen|archived,
  created_by, created_at
}

BranchEntry {
  branch_id, branch_sequence,
  object_ref, object_revision, object_digest,
  origin_branch_id,
  admission: origin|merge,
  merge_commit_ref?, created_at,
  UNIQUE(branch_id, branch_sequence)
}

MergeProposal {
  merge_id, revision, source_branch_id, target_branch_id,
  source_head_digest, target_head_digest,
  adopted_object_refs[], supersession_pairs[],
  unresolved_conflict_refs[], synthesis_ref?,
  producer_ref?, producer_version?,
  proposed_by_actor, subject_digest,
  state: proposed|accepted|rejected|stale|withdrawn
}

MergeCommit {
  merge_commit_id, merge_id, proposal_digest,
  target_prior_head_digest,
  appended_branch_entries[], resulting_head_digest,
  committed_by_actor, review_ref?, committed_at
}
```

Every space starts with a main branch. A fork pins an exact parent frontier;
later parent changes never leak invisibly into the fork. Contributions originate
on one branch and retain that provenance forever. Every branch append presents
the expected head digest and uses compare-and-swap; a stale writer must rebase or
fork. A merge does not copy or
rewrite them: compare-and-swap on the target head appends exact adoption refs,
explicit supersessions, unresolved conflicts, and an optional synthesis. A
changed source or target head makes the proposal stale and requires rebase or a
new proposal.

Model-generated comparison or synthesis records its producing invocation,
context, model/algorithm version, and output digest and remains untrusted data.
A merge cannot establish truth, erase a dissenting branch, resolve a policy
conflict, accept a commitment, revise a Pledge, decide a governed act, apply a
workspace, or disclose data. Authority-bearing conflicts never use
last-writer-wins, vote-by-text-volume, or model judgment. Origin branches and
unresolved challenges remain inspectable subject to retention and authorization.

### 10.4 Stream is a lens, not a second content model

There is no authoritative `Conversation`, `Message`, conversation participant,
or conversation sequence. `Stream` is a standard `SpaceLens` preset that selects
visible contributions from one branch or an explicit branch set, normally sorts
them by branch sequence and causal relation, and renders utterances and typed
cards in a familiar chronological interface. A saved Stream stores only its
closed query and presentation configuration; its results are authorized
item-by-item whenever read.

`Chat.say(...)`, `Chat.ask(...)`, and a UI action labelled “send message” are
compatibility conveniences over `contribution_append(kind: utterance|question)`.
They do not create a second body, membership scope, or authority boundary.
Replying appends an `addresses` relation. Redaction appends a
`ContributionDisposition`; it never rewrites the original ledger record. Existing
chat-oriented clients may receive synthetic message-shaped projections, but
those projections have no independent ids or mutation API in KCP.

A structured mention resolves an exact visible alias/deployment revision in the
same contribution transaction. If an authenticated principal also issues a
direct invocation command, that command may wake the resolved deployment once.
Otherwise the mention is inert address data unless an active, target-accepted
`AttentionContract` admits it. Plain `@text`, model prose, a semantic relation,
or a lens match has no invocation semantics. Later alias changes cannot retarget
recorded contributions. Only services may append a `system_notice`, and that
kind does not make its content authoritative.

### 10.5 Assistant definition, revision, and deployment

```text
AssistantDefinition {
  definition_id, realm_id, owner_ref, revision,
  name, description, status, created_at
}

AssistantRevision {
  assistant_revision_id, definition_id, version,
  manifest, package_artifact_ref, package_digest,
  config_schema_digest, sdk_protocol_range,
  signature_refs[], created_by, created_at
}

AssistantDeployment {
  assistant_deployment_id, assistant_revision_id, realm_id, project_id?, revision,
  config_ref, config_digest,
  secret_binding_set_ref, secret_binding_set_digest,
  policy_ref, pool_ref, security_profile,
  concurrency_policy, rollout_policy, status, activated_at?
}

AssistantAliasBinding {
  alias_binding_id, realm_id, project_id, revision,
  normalized_alias, display_alias,
  assistant_deployment_id, deployment_revision,
  status, created_by, created_at
}
```

An `AssistantRevision` is immutable. Configuration secrets are represented only
by broker-owned references and are excluded from the portable revision and event
payloads. Updating code, dependencies, manifest, or non-secret configuration
creates a new revision or deployment revision. Existing invocations remain
pinned to the exact assistant revision and effective deployment policy with
which they began.

`config_ref` resolves to immutable, schema-validated non-secret configuration.
The secret-binding set contains only broker profile names and secret versions;
workers receive neither its backing credentials nor a generic secret-read
operation. Invocation manifests bind both digests so rotation affects new work
under an explicit deployment revision while existing work remains auditable.

An alias names an assistant deployment, not a definition or worker. In v0.1 it
is unique among active bindings at `(project_id, normalized_alias)`; Unicode
normalization and confusable-display warnings are deterministic. Changing the
target creates a new alias-binding revision. An accepted Offer and its
`WorkRealization` contain the resolved deployment id/revision, assistant
revision, config digest, and policy digest; neither relies on resolving the alias
again during retry.

### 10.6 Invocation, attempt, and checkpoint

```text
Invocation {
  invocation_id, realm_id, project_id, space_id?, branch_id?,
  assistant_deployment_id, assistant_deployment_revision,
  assistant_revision_id, effective_config_ref, effective_config_digest,
  secret_binding_set_ref, secret_binding_set_digest,
  effective_policy_digest, effective_security_profile,
  rollout_decision_ref,
  trigger_ref, trigger_digest,
  context_assembly_ref?, context_assembly_digest?,
  input_manifest_ref, input_digest,
  correlation_ref, causation_ref?, commitment_ref?, work_realization_ref?,
  state, revision, priority, not_before,
  deadline, max_attempts, budget_reservation_set_ref?,
  created_at, terminal_at?
}

InvocationAttempt {
  attempt_id, invocation_id, ordinal, worker_instance_id,
  fence_epoch, state, lease_expires_at,
  started_at?, last_renewed_at?, ended_at?,
  checkpoint_ref?, result_ref?, diagnostics_ref?
}

Checkpoint {
  checkpoint_id, invocation_id, attempt_id, fence_epoch,
  sequence, state_schema_ref, state_artifact_ref,
  state_digest, created_at
}

InvocationInputManifest {
  input_manifest_id, revision: 1, invocation_id,
  trigger_ref, trigger_digest,
  space_id?, branch_id?, frontier_ref?, frontier_digest?,
  context_assembly_ref?, context_assembly_digest?,
  ordered_input_refs[]: {ref, revision, digest, classification_ref},
  artifact_refs[]: {ref, revision, digest, size, classification_ref},
  assistant_revision_id, deployment_revision,
  config_digest, secret_binding_set_digest, policy_digest,
  model_tool_profile_bindings[]: {kind, ref, revision, digest},
  disclosure_rules_digest,
  deadline, cancellation_policy, resource_limits,
  budget_reservation_set_ref?, ancestry[],
  byom_episode_binding_ref?, byom_episode_binding_digest?,
  authorization_dependency_set_ref, authority_digest,
  created_at, digest
}
```

`invocation_input_manifest_show` is the canonical inspectability query for the
exact trigger, context, profiles, limits, policy, and authorization snapshot an
invocation was created with. It reauthorizes every referenced item; the manifest
is audit evidence, not a capability to retrieve now-revoked bytes.

Invocation state:

```text
queued -> claimed -> running
                    |  |
                    |  +-> waiting_commitment | waiting_human | waiting_resource
                    |                         |
                    +-------------------------+
                    |
                    +-> succeeded | failed | canceled | ambiguous
```

An attempt state may end `yielded`, `lost`, or `superseded` while its invocation continues.
`succeeded` means the runtime accepted the exact fenced result; it does not mean
a Byom Pledge or Endeavor is accepted. That is Byom's separate `delivery_submit`/
`review_record` transition.

### 10.7 Needs, offers, commitments, and work realization

```text
Need {
  need_id, realm_id, project_id, space_id, branch_id, revision,
  opened_by_actor, goal_or_question_ref,
  outcome_schema_ref, acceptance_criteria_refs[],
  input_frontier_ref, input_frontier_digest,
  context_assembly_ref, context_assembly_digest,
  required_capabilities[], required_security_profile?,
  eligible_performer_selector, reviewer_ref?, review_rubric_ref?,
  budget_ceiling_set_ref?, disclosure_ceiling_ref?,
  deadline, cancellation_terms, idempotency_key,
  state: draft|open|forming|underway|review|satisfied|exhausted|withdrawn,
  created_at
}

Offer {
  offer_id, need_id, need_revision, revision,
  proposed_by_actor, performer_ref,
  performer_binding_revision?,
  approach_contribution_refs[], output_schema_refs[], evidence_schema_refs[],
  requested_budget_set, required_disclosure_manifest_ref?,
  proposed_start?, deadline, dependencies[],
  terms_digest, expires_at,
  state: proposed|selected|declined|withdrawn|expired|superseded,
  created_at
}

FormationProposal {
  formation_id, space_id, branch_id, revision,
  need_revision_refs[], selected_offer_revision_refs[],
  dependency_and_review_edges[],
  commitment_terms[]: {
    slot_group_id, need_ref, offer_ref,
    requester_actor_ref, performer_ref, terms_digest
  },
  aggregate_budget_set, disclosure_union_digest,
  subject_digest, proposed_by_actor,
  required_assent_slots[]: {
    slot_id, slot_group_id, party_role: requester|performer,
    party_ref, terms_digest, disclosed_subject_digest
  },
  finalized_by_actor?,
  state: proposed|accepted|rejected|withdrawn|stale|superseded
}

TermsAssent {
  assent_id, revision,
  owner_kind: formation|commitment_amendment,
  owner_ref, owner_revision, proposal_subject_digest,
  slot_id, party_role: requester|performer, party_ref,
  need_ref?, offer_ref?, commitment_ref?,
  terms_digest, disclosed_subject_digest,
  assent_authority:
    PrincipalDecision {decision_receipt_ref}
    | StandingPolicy {decision_use_ref}
    | BoundedRequesterCapability {
        invocation_capability_ref, invocation_attempt_id,
        fence_epoch, operation_key
      },
  authorization_dependency_set_ref, authority_digest,
  state: active|withdrawn|consumed|invalidated,
  created_at, terminal_at?,
  UNIQUE(owner_kind, owner_ref, owner_revision,
         proposal_subject_digest, slot_id)
}

CollaborationCommitment {
  commitment_id, scope: local_non_governed,
  need_id, need_revision, offer_id, offer_revision,
  formation_ref?, requester_actor_ref, performer_ref,
  performer_binding_revision?, reviewer_ref?, review_rubric_ref?,
  input_frontier_ref, input_frontier_digest,
  context_assembly_ref, context_assembly_digest,
  outcome_and_evidence_schema_refs[],
  budget_reservation_set_ref?, disclosure_manifest_ref?,
  deadline, cancellation_terms, ancestry[], depth,
  requester_assent_ref, performer_assent_ref,
  terms_digest, amendment_head?, revision,
  state: active|waiting|submitted|revision_requested|
         fulfilled|failed|canceled|superseded|expired,
  created_at, terminal_at?
}

CommitmentAmendment {
  amendment_id, revision, commitment_id, prior_terms_digest,
  proposed_terms, proposed_terms_digest, proposed_by_actor,
  required_assent_slots[]: {
    slot_id, party_role: requester|performer, party_ref,
    terms_digest, disclosed_subject_digest
  },
  finalized_by_actor?,
  state: proposed|accepted|rejected|withdrawn|expired|superseded,
  created_at
}

CommitmentDelivery {
  delivery_id, commitment_id, commitment_revision, terms_digest,
  delivered_by_actor, contribution_refs[], evidence_refs[],
  work_realization_ref?, usage_digest?,
  state: submitted|superseded|withdrawn,
  submitted_at
}

CommitmentReview {
  review_id, commitment_id, commitment_revision, terms_digest,
  delivery_id, reviewer_actor_ref,
  rubric_ref?, reviewed_subject_digest,
  outcome: fulfilled|revision_requested|rejected,
  rationale_contribution_ref?,
  decision_receipt_or_policy_use_ref,
  created_at,
  UNIQUE(delivery_id, reviewed_subject_digest)
}

NeedReview {
  need_review_id, need_id, need_revision, formation_ref,
  commitment_review_refs[], aggregate_evidence_digest,
  reviewer_actor_ref, rubric_ref?,
  outcome: satisfied|reopen|exhausted,
  decision_receipt_or_policy_use_ref,
  created_at,
  UNIQUE(need_id, need_revision, aggregate_evidence_digest)
}

WorkRealization {
  work_realization_id, commitment_id, commitment_revision, terms_digest,
  parent_invocation_id?, parent_attempt_id?, parent_fence_epoch?,
  target_assistant_deployment_id, target_deployment_revision,
  target_assistant_revision_id, target_config_ref, target_config_digest,
  target_secret_binding_set_ref, target_secret_binding_set_digest,
  target_policy_digest, target_security_profile,
  context_assembly_ref, context_assembly_digest,
  disclosure_manifest_ref?, disclosure_digest?,
  byom_episode_binding_ref?, byom_episode_binding_digest?,
  correlation_ref, causation_ref, ancestry[], depth,
  deadline, budget_reservation_set_ref?, cancellation_policy,
  state: prepared|queued|claimed|running|delivered|failed|timed_out|canceled|superseded|ambiguous,
  revision, child_invocation_id?, result_ref?, created_at, terminal_at?
}
```

A Need says what useful contribution is missing without assigning a worker. An
Offer is a candidate performer's immutable proposal: exact deployment/principal,
approach, deliverables, evidence, cost, timing, dependencies, and disclosure.
Discovery may use manifest capabilities, current capacity, and Byom participant
evidence (`participant_show`, `engram_search`) where authorized, but ranking
never assigns work. Solicitations and
offers are rate-limited attention traffic, not ambient broadcast.

Acceptance binds both sides to one terms digest, but no caller may authenticate
both sides by submitting one finalization command. The service derives a
requester and performer `required_assent_slot` for every prospective Commitment.
Each exact party separately records a `TermsAssent`: a human party uses an
authenticated explicit decision receipt; an assistant performer requires an
exact active standing-policy use covering compute, data classes, deadline,
budget, and output destination; a current worker may fill only its own requester
slot when its fenced InvocationCapability expressly allows bounded child work,
and that assent is bounded by the parent deadline, budget, disclosure, ancestry,
and Byom fence when present. The assent binds the proposal revision and
subject digest, its role/party/slot, the exact local terms digest, the
party-visible disclosed-subject digest, and current authorization dependencies.
It is inert until the full set is atomically consumed. Model output, assistant
prose, a coordinator, or a merely `proposed` record cannot fill another party's
slot. Any proposal/amendment change invalidates the old slots and assents.
Acceptance creates no external effect permit and cannot bind another project,
realm, or organization.

An accepted `CommitmentAmendment` never edits running terms in place. Proposal
creates fresh requester and performer assent slots; even the proposer must fill
its own slot separately. `commitment_amendment_accept` is only a finalizer. Its
transaction locks the amendment, both active `TermsAssent` rows, the prior
Commitment revision, terms digest, reservation set, and WorkRealization;
verifies the exact current dependencies and consumes both assents; supersedes
the prior commitment/realization; revokes future
child/effect permits; allocates replacement budget; and creates a new Commitment
revision plus assistant WorkRealization atomically. A running child invocation
is canceled/fenced and any later output is retained only as late evidence against
the old terms. An amendment cannot undo a disclosure or effect already committed,
and it cannot relabel old evidence as satisfying the new digest.

Kovee commitments are explicitly `local_non_governed`. If a Need changes an
Endeavor's decomposition, budget, deliverable, or delegation, it becomes work
only through the corresponding Byom operation — `call_open`, `pledge_propose`,
`act_intent_prepare/position/finalize`, or a Mandate derivation; Kovee shows a
source-qualified projection rather than a duplicate commitment. Remote terms
become effective only through a Byom Mandate chain and act decision plus an Akson
signed contract and endpoint-local consent.

V0.1 local commitments request bounded contributions or draft artifacts inside
one Kovee space. The closed set a hosted episode may make intra-turn is named by
`allowed_local_commitments` on its `ByomEpisodeBinding`; anything outside it goes
through `call_open`/`pledge_propose`/`act_intent_*`. They cannot allocate an
independent Byom workspace, own an Endeavor deliverable, authorize an effect,
apply a change set, alter admitted engrams, or claim organizational/
cross-sovereign obligation. Their review can mark only the local terms fulfilled.
It never accepts or completes a Byom Pledge, even when the same contribution is
later admitted to an Endeavor.

A FormationProposal selects compatible offers for one or more Needs, including
dependencies and reviewers, and deterministically derives the prospective
Commitment terms plus every required assent slot. Each requester and performer
uses `formation_assent` for only its own slot; `formation_assent_withdraw` is
effective only before finalization. Assents to a stale proposal, changed term,
expired decision, revoked policy, or changed authority dependency are invalid.
`formation_accept` is a coordinator finalization command, not party assent.
Inside one Kovee transaction/authority boundary it locks the proposal and all
required slots, queries `TermsAssent` by the immutable
`(owner_kind, owner_ref, owner_revision, proposal_subject_digest)` key, proves
exactly one current active assent per slot, consumes the
whole set, revalidates every exact offer and budget/disclosure union, and creates
the commitments, reservations, and any assistant WorkRealizations atomically—or
does nothing. The team is a projection of those active commitments.
Recomposition supersedes exact commitments with a new formation; it never
silently changes a performer or terms already running. Cross-owner formation
uses inert preparation and receipt-driven sagas, never a claimed distributed
transaction.

Need lifecycle is explicit and compare-and-swapped: `draft -> open` publishes
the solicitation; preparing a Formation moves `open -> forming`; rejecting or
withdrawing all live formations returns it to `open`; accepting one moves it to
`underway` and creates Commitments directly in `active`. When every required
Commitment in the accepted Formation is `fulfilled`, the Need enters `review`.
A failed/canceled/expired Commitment returns the Need to `open` for reforming or
allows its authorized reviewer to mark it `exhausted`. From `review`, only the
NeedReview outcomes above select `satisfied`, `open`, or `exhausted`. Withdrawal
may move any nonterminal Need to `withdrawn` and cancels bounded child work under
its recorded terms.

An accepted assistant commitment creates exactly one pinned `WorkRealization`;
a human commitment creates an inbox obligation but no worker. The same
commitment/idempotency key returns the same realization. Runtime success creates
a `CommitmentDelivery`; it does not fulfill the commitment until its recorded
reviewer or exact standing acceptance rule reviews the promised evidence.
Completion prose is not evidence, and a late delivery cannot satisfy superseded
terms.

An assistant delivery MUST name the current Commitment revision's exact
WorkRealization and its bound child invocation; the fenced performer attempt must
be that invocation's current attempt. A human delivery has no WorkRealization
ref and is authorized as the authenticated performer principal. Merely matching
the same deployment or participant is insufficient.

Delivery submission compare-and-swaps from `active` or `waiting` to `submitted`
against the current terms. Review uses
compare-and-swap on the exact current Commitment revision, terms
digest, and unsuperseded delivery. `fulfilled` transitions
`submitted -> fulfilled`; `revision_requested` transitions to
`revision_requested`, after which no further delivery or assistant execution may
use that Commitment revision. Fresh requester/performer acceptance of a
`CommitmentAmendment` creates the next revision and WorkRealization and
supersedes the reviewed delivery;
`rejected` transitions the Commitment terminally to `failed`. A new attempt after
rejection needs a fresh amendment/Commitment, not reinterpretation of that
delivery. A stale/superseded delivery cannot be reviewed, and the uniqueness key
permits one effective outcome for a delivery subject.

A Need entering `review` is not automatically satisfied when its commitments
finish. Its designated reviewer or exact standing policy commits a `NeedReview`
over the complete required CommitmentReview set and aggregate evidence digest.
`satisfied` closes the Need; `reopen` returns it to `open` for new Offers;
`exhausted` closes it unsuccessfully. A failed/canceled Commitment leaves the
Need open/reformable or explicitly exhausted; counts, majority text, and model
judgment never choose that transition.

Child commitments cannot exceed the parent's remaining deadline, budget,
disclosure ceiling, or cancellation scope. Default maximum depth is 8. A target
already in ancestry is a cycle and is rejected; detached work retains origin
ancestry and needs independent authorization/budget. Parent cancellation
propagates by default. A timed-out/late result is retained but cannot reactivate
the parent, fulfill changed terms, or satisfy a Byom Pledge.

### 10.8 Attention and context assembly

```text
ContextRecipe {
  recipe_id, realm_id, project_id, space_id, owner_ref, revision,
  branch_selector,
  required_refs[], contribution_kind_filter[], relation_kind_filter[],
  watched_refs[], traversal_limits {depth, fanout, nodes},
  selection_strategy: pinned_then_recent|relation_neighborhood|semantic_ranked,
  semantic_rank_profile_ref?, priority_rules[],
  transformations[], omission_policy,
  limits {items, bytes, tokens},
  allowed_classification_refs[],
  status, created_at
}

ContextAssembly {
  assembly_id, revision: 1, realm_id, project_id, space_id, branch_id,
  audience_ref, purpose, trigger_refs[],
  frontier_ref, frontier_digest,
  recipe_ref?, recipe_revision?, recipe_digest?,
  selection_policy_ref, selection_policy_digest,
  items[]: {object_ref, revision, digest, size, classification_ref,
            role, order, inclusion_reason},
  relations[]: {relation_ref, digest},
  transformations[]: {kind, instruction_ref?, version, source_digest, result_digest},
  omissions[]: {visible_candidate_ref?, reason},
  classification_join_ref,
  totals {items, bytes, estimated_tokens},
  selection_policy_version, assembler_version,
  authorization_dependency_set_ref, authority_digest,
  created_at, digest
}

AttentionContract {
  contract_id, realm_id, project_id, space_id, revision,
  proposed_by_actor, owner_ref,
  target_participant_ref, target_assistant_deployment_id?, target_deployment_revision?,
  target_acceptance_receipt_or_policy_use_ref?,
  branch_selector, contribution_kind_filter[], relation_kind_filter[],
  watched_refs[], activation_cursor,
  context_recipe_ref, context_recipe_revision,
  behavior: notify|invoke,
  batch_policy, cooldown, max_in_flight, max_wakes,
  max_causal_depth, rate_limit_ref, wake_budget_reservation_ref?,
  attention_use_account_ref, accounting_epoch,
  semantic_triage_profile_ref?, expires_at?,
  subject_digest,
  authorization_dependency_set_ref, authority_digest,
  state: draft|offered|active|suspended|declined|expired|revoked,
  created_at
}

AttentionCandidate {
  candidate_id, contract_id, contract_revision,
  source_event_refs[], source_object_refs[], source_batch_digest,
  deterministic_match_reasons[], eligibility_digest,
  frontier_ref, automation_lineage,
  triage_ref?, suppression_reason?,
  state: eligible|selected|suppressed|expired,
  created_at,
  UNIQUE(contract_id, contract_revision, source_batch_digest)
}

AttentionTriage {
  triage_id, contract_id, contract_revision,
  invocation_ref, eligible_source_refs[], eligible_set_digest,
  rank_profile_ref, rank_profile_revision,
  ranked_results[]: {source_ref, score, reason_digest?},
  result_digest, created_at
}

AttentionActivation {
  activation_id, candidate_id,
  contract_id, contract_revision,
  target_participant_ref, target_deployment_revision?,
  context_assembly_ref?, context_assembly_digest?,
  authorization_dependency_set_ref, authority_digest,
  attention_use_ref, wake_use_ordinal, invocation_ref?,
  state: prepared|queued|notified|invoked|settled|failed|canceled,
  created_at, terminal_at?,
  UNIQUE(candidate_id)
}

AttentionUseAccount {
  account_id, contract_id, accounting_epoch,
  limits {max_wakes, max_in_flight},
  counters {wakes_reserved, wakes_committed,
            in_flight_held, in_flight_active},
  next_wake_ordinal, state: active|draining|closed, revision
}

AttentionUse {
  use_id, account_id, accounting_epoch,
  contract_id, contract_revision, activation_id, wake_use_ordinal,
  state: reserved|committed|settled|released,
  created_at, settled_at?,
  UNIQUE(account_id, activation_id),
  UNIQUE(account_id, wake_use_ordinal),
  UNIQUE(contract_id, contract_revision, wake_use_ordinal)
}

AttentionReplay {
  replay_id, contract_id, contract_revision, contract_subject_digest,
  source_cursor_start, source_cursor_end,
  max_source_events, max_candidates, max_wakes,
  context_recipe_ref, context_recipe_revision,
  attention_use_account_ref, accounting_epoch,
  requested_by_actor, acceptance_receipt_or_policy_use_ref?,
  authorization_dependency_set_ref, authority_digest,
  subject_digest, idempotency_key,
  next_cursor?, observed_events, created_candidates, committed_wakes,
  state: prepared|running|completed|canceled|failed,
  revision, created_at, terminal_at?
}
```

```text
AttentionContract: draft -> offered -> active <-> suspended
                              \-> declined      \-> revoked|expired
```

A recipe is a bounded, versioned selection program over records already visible
to its audience. Required refs are never silently replaced by current revisions;
stale, erased, reclassified, or unauthorized inputs cause an explicit omission
or failure during assembly creation according to the recorded policy. If
required content cannot fit, assembly fails rather than silently truncating it.
Omission records reveal refs only when the audience may know they exist. After
the assembly digest is committed, materialization never drops or substitutes an
included item: any newly stale, erased, reclassified, or unauthorized included
item makes that assembly unavailable. A caller may request a new assembly whose
new digest records policy-permitted omissions.

K1 direct invocation uses the built-in `explicit_refs_v1` selection policy and
therefore needs no saved recipe. Reusable/dynamic K2 assemblies bind an exact
`ContextRecipe` revision; every assembly always binds one selection-policy
identifier and digest.
For `semantic_ranked`, deterministic authorized enumeration produces the
candidate set first; an attributable brokered model invocation may only order or
drop that set. Its profile/context/disclosure/budget and result digest are
recorded, and deterministic fallback cannot introduce a candidate.

`ContextAssembly` is immutable evidence of selection, not a bearer capability.
Materialization reauthorizes the intersection of requester access, target
deployment/session capability, source visibility, classification, and
destination disclosure policy. It records exact order, transformations, policy
and assembler versions, token/byte limits, and the classification join. Hidden
adapter instructions, tool schemas, and provider transformations live in the
separate `ProviderContextManifest` chain; the model broker binds both before
egress. Only admitted data enters automatic context, and possession of an old
assembly never preserves access to erased or revoked bytes.

Attention selectors use a closed deterministic language over typed envelope
fields, exact refs, and bounded relations—never arbitrary code, raw broker
wildcards, or untrusted prose. An assistant may propose or narrow its contract
but cannot activate it or widen access, classifications, compute, budget,
disclosure, or expiry. The target must accept the exact contract, or an exact
standing policy must do so, before it can impose notifications or compute. The
receipt binds `subject_digest`, target participant/deployment revision, selector,
data classes, behavior, rates, wake/budget ceilings, context recipe, and expiry;
any widening revision requires a new receipt. Model output cannot manufacture
acceptance. The receipt is absent while a contract is `draft`, `offered`, or
`declined` and is mandatory for `active` or `suspended`; activation rejects any
state/receipt mismatch.
`attention_contract_narrow` succeeds only when the deterministic kernel proves
set inclusion for selectors/data classes and non-increase for rate, wake,
concurrency, budget, disclosure, duration, and causal depth. Extending expiry is
also widening. Any incomparable change fails that operation and must use
`attention_contract_widen` with fresh exact acceptance.
`behavior:invoke` requires an active assistant-deployment participant and exact
deployment revision; `notify` may target an eligible principal or service
participant but grants no invocation. Muting/revoking the participant or changing
the deployment revision invalidates unused activations.
Before an invoke activation can enter `queued` or `invoked`, the activation
transaction creates and binds one exact `ContextAssembly` ref/digest under the
contract recipe and frontier; that same assembly is pinned in the child
InvocationInputManifest. Failure to assemble leaves no queued invocation.
`notify` may omit an assembly because it creates no model/worker input.

An optional semantic triage is itself a bounded, attributable assistant
invocation over the deterministic eligible set. It may prioritize or coalesce
that set under the contract's fixed maximum but cannot introduce an ineligible
object, grant visibility, exceed wake budget, or authorize an effect. Its model,
context, scores, version, and digest remain inspectable; deterministic fallback
and failure behavior are part of the contract.

Candidate delivery is at least once internally. The unique batch key, activation
cursor, and recorded coalescing produce at most one logical candidate and one
activation/invocation for a contract revision. Every use rechecks authorization, target acceptance,
revocation, rate, concurrency, budget, and loop lineage both at match and before
wake. Updates create a new revision/activation boundary and do not reinterpret
earlier events. Bounded replay is a separate prepared operation with exact
cursors, budget, and idempotency key.

An `AttentionReplay` binds one currently active, accepted contract revision,
closed cursor interval, recipe revision, ordinary batch policy, use-account
epoch, and strict event/candidate/wake maxima. Start consumes an exact principal
or standing-policy receipt and current authorization. Replay feeds retained
events through the same deterministic eligibility, candidate unique key,
Activation, and AttentionUse transactions as live delivery; it cannot create a
different batch digest to evade deduplication or ceilings. Progress CASes
`next_cursor`; cancellation/retry resumes the same replay id and never rewinds
committed uses. Expired history fails explicitly. The replay receipt is absent
in `prepared`; `start` records it atomically with `prepared -> running`. Every
`running` or `completed` replay therefore names the exact consumed receipt,
while canceling a prepared replay consumes none.

Activation preparation locks the `AttentionUseAccount`, checks
`wakes_reserved + wakes_committed < max_wakes` and
`in_flight_held + in_flight_active < max_in_flight`, allocates the next ordinal,
increments `wakes_reserved` and `in_flight_held`, and creates the Activation/use
atomically. Notify/invoke moves the wake reserved→committed and in-flight
held→active once; terminal settlement decrements active, while pre-wake failure
decrements held and releases the wake reservation. Retry of the same candidate returns the same use. Contract
revisions share their accounting epoch by default, so editing cannot reset
usage; a reset or wider ceiling needs a new target-accepted subject digest.
Account counters must equal their use rows;
`wakes_reserved + wakes_committed <= max_wakes` and
`in_flight_held + in_flight_active <= max_in_flight` always hold.

Automation lineage records ordered attention-contract ids, causal depth, and cumulative
invocation/effect counts. Repeated lineage, default depth over 16, rate/budget
breach, poison delivery, or circuit-breaker failure suppresses/suspends and
alerts rather than creating a wake storm. Attention may invoke only Kovee-local
work. It may notify the byom adapter of admitted change, but wake ownership is
inverted: a Participant (or an ActivationPolicy it adopted, recorded as
provenance) authors the `WakeIntent`, and the Byom kernel admits it and allocates
resources. Kovee attention only notifies — it never wakes governed work. Peer
attention requires a Byom Mandate chain and local admission.

### 10.9 Presence and worker instance

```text
WorkerInstance {
  instance_id, service_identity_ref, pool_id,
  supported_runtimes[], supported_profiles[],
  capacity, version, lease_epoch, lease_expires_at,
  state: starting|ready|draining|lost
}

PresenceSignal {
  subject_ref, device_or_instance_ref, state,
  emitted_at, expires_at, sequence
}
```

Presence MAY be carried over Core NATS because loss is acceptable. Durable
records retain only coarse last-seen information where policy permits. UI
activity rollups combine current presence with authoritative invocation and Byom
Episode/Pledge states and must label stale or unknown data. There is no durable assistant state
called `done`; recent completion is a timeline event.

### 10.10 Artifact

```text
Artifact {
  artifact_id, realm_id, owner_ref, revision,
  state: pending|verifying|scanning|available|quarantined|rejected|unavailable|erased,
  raw_sha256?, typed_byte_digest?, size?, media_type?, classification_ref,
  sealed_storage_ref?, sealed_storage_version?,
  verification_digest?, encryption_key_ref,
  created_by, created_at, available_at?, retention_until?
}

ArtifactUpload {
  upload_id, artifact_id, realm_id, owner_ref, revision,
  declared_raw_sha256, declared_size, declared_media_type, classification_ref,
  staging_storage_ref, provider_upload_ref?,
  state: prepared|uploading|sealing|sealed|verifying|completed|rejected|expired|aborted,
  sealed_storage_version?, seal_observation_digest?,
  authorization_dependency_set_ref, authority_digest,
  max_bytes, expires_at, idempotency_key,
  created_at, sealed_at?, terminal_at?
}

ArtifactVerification {
  verification_id, upload_id,
  sealed_storage_ref, sealed_storage_version,
  observed_raw_sha256, observed_typed_byte_digest,
  observed_size, observed_media_type,
  verifier_identity_ref, scanner_set_digest, scan_results[],
  outcome: clean|quarantined|rejected,
  observation_digest, observed_at,
  UNIQUE(upload_id, sealed_storage_version, scanner_set_digest)
}

ArtifactGrant {
  grant_id, artifact_id, artifact_revision, artifact_digest,
  grantee_ref, operations[]: content_read|copy,
  max_uses, consumed_uses,
  status: active|exhausted|revoked|expired,
  expires_at, revision, security_epoch,
  authorization_dependency_set_ref, authority_digest
}

ArtifactGrantUse {
  grant_use_id, grant_id, use_ordinal,
  actor_scope, operation, idempotency_key,
  access_session_id, issued_at, use_expires_at,
  state: issued|expired|revoked,
  UNIQUE(grant_id, use_ordinal),
  UNIQUE(grant_id, actor_scope, operation, idempotency_key)
}

ArtifactAccessSession {
  access_session_id, grant_use_id,
  artifact_id, artifact_revision,
  sealed_storage_ref, sealed_storage_version,
  audience, operations[], max_bytes,
  authorization_dependency_set_ref, authority_digest,
  issued_at, expires_at, status: active|expired|revoked
}
```

Artifact ids are not bearer secrets. Every fetch reauthorizes the caller or uses
a short-lived, exact, audience-bound access session. No contribution, delivery,
or effect may reference an artifact as available until the following finalization
state machine completes.

`artifact_upload_begin` atomically creates the pending artifact/upload,
idempotency result, event, and outbox row. Its canonical result contains only the
durable upload/artifact refs and constraints; replay returns that same result and
never mints a credential. The separate non-mutating
`artifact_upload_credential` query reauthenticates the current actor and the
appropriate principal-authentication or service-identity dependencies plus all
current upload dependencies, then returns a fresh short-lived provider credential for
the already recorded staging key, byte ceiling, audience, and expiry. It may add
only audit/rate accounting under section 11.2. The credential is neither stored
in nor attached to any canonical `CommandResult` and grants no operation beyond
the existing upload. Credentials never target the canonical object.
The reference binding derives/signs this credential without creating provider
state. A storage backend that requires a mutable credential-issuance call must
model it as a separately recorded broker effect and cannot claim the query has
these semantics.
`artifact_upload_finalize` commits `uploading -> sealing`;
the artifact service then seals an immutable object version, prevents further
writes, reads the trusted bytes, and verifies raw and typed digests, size, media
type, encryption, and the exact scanner/policy versions. ETag and client metadata
are not verification.

The final SQL transaction locks the upload/artifact, rechecks authorization and
sealed version, stores `ArtifactVerification`, and commits one terminal
availability/quarantine/rejection event and idempotency result. A crash after
sealing but before that transaction is reconciled from the same upload id and
version. Expired staging and unreferenced sealed objects are removed only by an
idempotent mark-and-sweep job after a retry grace period and a fresh database
reference check. A missing or changed available object is failed closed as
`unavailable`, raises an integrity incident, and is restored/reconciled rather
than silently recreated.

Canonical storage/deduplication is scoped to a realm and encryption-key version;
there is no cross-realm existence oracle or plaintext deduplication. Within a
realm, an identical sealed version may be reused only after authorization and
verification under a scanner set acceptable to current policy, while each owner
keeps distinct metadata and access control.

A grant use is consumed when an `ArtifactAccessSession` is committed, because a
capability may escape immediately afterward—not when all bytes finish
transferring. That transaction locks the grant, rechecks artifact availability,
grantee and dependencies, allocates a row-locked ordinal under `max_uses`, inserts
the use/session, and increments `consumed_uses` atomically. A stable idempotency
key returns the same session; `consumed_uses = COUNT(ArtifactGrantUse)` and never
exceeds `max_uses`. Ranges and transport retries inside one session count as one
use. Revocation blocks new sessions and future fetches, but cannot retract bytes
already transferred. Direct presigned reads are forbidden unless storage can
enforce current audience, expiry, and revocation.

Grant `security_epoch` changes for revocation, grantee/scope widening or
narrowing, and other authority changes—not for the ordinary `consumed_uses`
counter. An access session expires no later than its grant and binds its own use
row plus that security epoch, so another valid use does not invalidate it while
revocation does.

Active renderable formats are served inertly or sandboxed. The default policy
blocks external fetches, active scripts, event handlers, dangerous URL schemes,
and XML entity expansion. Secret scanning and malware scanning are policy
inputs, not proof that arbitrary content is safe.

### 10.11 Space handoff and admission

```text
HandoffRecipient =
  PrincipalRecipient {
    principal_ref, auth_binding_ref?, auth_binding_security_epoch?
  }
  | SpaceRecipient {space_id, space_revision}

HandoffScope =
  ObjectBundle {
    items[]: {object_ref, revision?, digest, size, classification_ref}
  }
  | SpaceFrontierBundle {
    source_space_id, branch_id, frontier_ref, frontier_digest,
    items[]: {object_ref, revision?, digest, size, classification_ref}
  }
  | SolicitationBundle {
    input_bundle_ref, input_bundle_digest,
    requested_result_schema_ref, deadline?, budget_ceiling_set_ref?
  }

HandoffOffer {
  handoff_id, realm_id, source_project_id, source_space_id,
  sender_actor_ref, recipient: HandoffRecipient,
  scope: HandoffScope,
  permitted_actions[]: inspect|copy_into_space|respond_with_handoff,
  disclosure_manifest_ref,
  classification_mapping_ref?, classification_mapping_digest?,
  subject_digest, max_uses: 1, expires_at,
  authorization_dependency_set_ref, authority_digest,
  acceptance_required: true, state, revision
}

HandoffUse {
  handoff_id, transfer_id, use_ordinal: 1,
  accepted_by_principal, recipient_project_id, recipient_space_id,
  admission_id, destination_copy_refs[],
  action, result_digest, used_at,
  UNIQUE(handoff_id, use_ordinal)
}

HandoffTransfer {
  transfer_id, handoff_id, use_ordinal: 1,
  source_realm_id, source_project_id, source_space_id,
  destination_realm_id, destination_project_id, destination_space_id,
  subject_digest, disclosure_manifest_digest,
  classification_mapping_digest?,
  source_authorization_dependency_set_ref, source_authority_digest,
  copy_authorization?: {
    authorization_id, source_dependency_set_ref, authority_digest,
    transfer_subject_digest, issued_at, digest
  },
  copy_started_at?,
  recipient_acceptance_decision_ref,
  destination_authorization_dependency_set_ref?, destination_authority_digest?,
  state: reserved|transferring|destination_prepared|source_committed|destination_active|canceled|ambiguous,
  destination_prepare_receipt_ref?, destination_prepare_receipt_digest?,
  source_use_ref?, revision, created_at, expires_at?,
  UNIQUE(handoff_id, use_ordinal)
}

SpaceAdmissionRecord {
  admission_id,
  source:
    SameInstallationHandoff {handoff_id}
    | VerifiedPeerOutcome {
        akson_verification_ref, akson_verification_digest,
        byom_effect_outcome_admission_ref, byom_effect_outcome_admission_digest,
        original_act_intent_ref, original_intent_digest
      },
  recipient_project_id, recipient_space_id,
  verified_digest, decision: admit|decline,
  decision_receipt_or_policy_use_ref, decided_by_actor,
  classification_mapping_ref?, classification_mapping_digest?,
  admitted_refs[], state: prepared|active|declined|revoked,
  revision, decided_at
}
```

The records have separate state machines:

```text
HandoffOffer: prepared -> offered -> accepted -> completed
                    \-> declined | expired | revoked | canceled

HandoffTransfer: reserved -> transferring -> destination_prepared
                    -> source_committed -> destination_active
                    -> ambiguous
                reserved -> canceled

SpaceAdmissionRecord: prepared -> active
                             \-> declined | revoked
```

A `SolicitationBundle` is inert disclosed data. Accepting or admitting it creates
no obligation or execution. A destination may independently open a local Need,
while governed work crossing a realm uses a Byom Mandate chain plus exact Kovee
handoff/admission; crossing an independent installation additionally requires
Akson consent and carriage. Kovee never claims cross-owner atomic commitment
formation.

Acceptance acknowledges the offer; admission determines which exact content can
enter a space, become attention-eligible, or become available for explicit
admission to a Byom ContextManifest. The two may be one UI action but remain
separate records. Revocation prevents new uses; it cannot erase an already committed
disclosure.
`space_admission_decide` records the authenticated admission decision before any
cross-boundary copy. `state:prepared` therefore already has a required
`decision:admit`, receipt, actor, and decision time; “prepared” means only that
the admitted copies remain inert pending the source-use proof. A decline creates
no prepared copies. Activation never invents or changes the admission decision.

Kovee v0.1 handoffs are single-use. A principal recipient must authenticate as
that exact principal and choose a destination space for which they have
admission authority. A space recipient can be accepted only by a principal with
that space's admission action. Acceptance alone does not consume the use. Every
space has exactly one home realm/write boundary; a handoff creates local
immutable copies and never a live cross-realm multi-writer space.

Within one transactional database/home-region boundary, admission may lock the
offer, recheck expiry/recipient/digest/current authorization, create destination
copies, and commit `SpaceAdmissionRecord`, `HandoffTransfer`, and `HandoffUse`
with their events atomically. Across realm home regions or databases, pretending
that transaction is global is forbidden; the same logical operation uses this
recoverable saga:

1. The source transaction locks the offer, rechecks authority, and creates the
   deterministic single-use `HandoffTransfer(state:reserved)`. A duplicate
   admission key returns that transfer.
2. Immediately before bytes cross, the source rechecks revocation/expiry and
   atomically changes `reserved -> transferring`, binding an exact, one-shot copy
   authorization/receipt to the transfer, destination, item, classification, and
   disclosure digests. That transition is the last source permission check before
   disclosure and records `copy_started_at`. A reserved transfer may
   expire/cancel; a transferring one cannot be released merely because a reply
   was lost or source authority later changes.
3. The destination idempotently re-encrypts/copies under `transfer_id`, applies
   the exact mapping, and commits inert destination objects plus
   `SpaceAdmissionRecord(state:prepared)` and an authenticated prepare receipt.
   Prepared objects are neither readable to assistants nor eligible to wake one.
4. The source verifies that receipt and the persisted one-shot copy
   authorization, then commits the sole `HandoffUse`, destination refs/digest,
   and `source_committed` event. This transition accounts for an already-observed
   disclosure; it MUST complete even if membership/policy was revoked after
   `copy_started_at`. If the source crashed, querying the destination by transfer
   id recovers the same receipt. A post-copy revocation is audited and may block
   destination activation, but cannot omit the use record or release a second use.
5. The destination verifies the source-use receipt and atomically changes the
   admission/copies to active, emits visibility/outbox events, and may then wake
   authorized work. A lost reply repeats activation without another copy/use.

Once transfer begins, revocation cannot erase a disclosure already made. A
transfer with unknown destination outcome becomes `ambiguous`, blocks another
use, and is reconciled by exact transfer id; it is never automatically released.
`handoff_transfer_show` exposes that exact state and receipts to an authorized
audience. `handoff_transfer_reconcile` is the only recovery mutation: the Kovee
handoff service (or an authorized operator) re-queries the recorded destination
under the same transfer id and may advance only the existing saga; it cannot
allocate another use, choose another destination, or substitute bytes.
An authenticated destination-prepare receipt always causes the observed source
use to be recorded from the persisted copy authorization, even after later
source revocation. Current destination authorization is still rechecked before
activation; failure leaves the copies inert/revoked and raises an audit incident.
If both realms share the fast-path transaction, it must still produce the same
records and externally observable states. A uniqueness conflict at any step
returns the existing transfer/use rather than repeating disclosure.

Destination copies receive new local ids, destination-realm encryption keys,
classification selected by the exact recipient-approved mapping revision in the
admission, and provenance back to the handoff/item digests. They are not aliases
to source rows. Later source
revocation or erasure produces a retraction/erasure notice where policy permits
but cannot pretend an already disclosed destination copy vanished. Ongoing live
source access is a separate, explicitly revocable grant that reauthorizes at the
source on every read; it is never implied by a handoff or admission.

The classification mapping fields are mandatory when source and destination
realm/policy revisions differ. They may be omitted only when every item already
uses the destination's identical policy revision.

The offer, transfer, destination-prepare receipt, and source-use receipt bind the
exact source/destination realm, project, and space ids plus bundle, disclosure,
and classification-mapping digests. No receipt for another destination space can
activate the prepared copies.
The source and destination dependency sets are operation-specific snapshots, not
bearer grants: reservation and pre-copy re-evaluate current source dependencies,
and destination prepare/activation re-evaluate current destination dependencies.
After bytes cross, source commit verifies the authenticated prepare receipt and
already-consumed exact copy authorization instead of pretending revocation can
undo disclosure. The
recipient acceptance decision binds the exact destination and transfer subject;
changing either prepares a new transfer rather than reusing consent.

The `VerifiedPeerOutcome` branch is valid only when Akson has verified the exact
outcome/evidence and Byom has admitted it through `effect_outcome_admit` against
the original ActIntent and the current Pledge/Episode generation. Kovee verifies
both source records directly and includes them in its authorization dependency
set. A generic peer ref, signed bytes without Byom admission, or a Kovee principal
decision alone cannot admit a peer result, expose it to a model, or wake an
invocation. A late outcome is verified but cannot satisfy an advanced generation;
an ambiguous or late-judged one goes to `effect_reconcile`, which produces an
`EffectGovernanceDisposition` — the admission head locks first.

### 10.12 Byom and Akson links

Kovee links to foreign bounded contexts without copying their identity:

```text
ExternalLink {
  link_id, revision, local_resource_ref, local_branch_id?,
  promotion_ref?, supersedes_link_ref?,
  owner_protocol: byom|akson,
  owner_endpoint_ref, owner_object_ref,
  owner_revision?, owner_cursor?, owner_digest?,
  link_kind, status: active|superseded|revoked,
  subject_digest, created_at, terminal_at?
}
```

A link is correlation, not authority. A Kovee contribution linked to
`act_intent:ai-77` cannot decide it; an Akson task link cannot prove an outcome
without the Akson verification record.
For `link_kind:endeavor`, a partial unique constraint permits one active link per
`(local_branch_id, owner_protocol:byom)`. Promotion/link reconciliation locks
that active-link key and compare-and-swaps the exact expected prior link. The
same promotion id returns the same link; replacing one requires an explicitly
confirmed `supersedes_link_ref` and atomically marks the prior link superseded
while creating the new active link. Historical rows remain immutable. Revoking
a local link changes no Byom Endeavor state.

## 11. Kovee Collaboration Protocol

The Kovee Collaboration Protocol (KCP) is the normative, transport-independent
surface for Kovee-owned resources. Initial protocol version is `0.1`. It does
not absorb the Byom Participation Protocol or the Akson A2A profile; the gateway
exposes those bounded contexts through their own negotiated versions, and a BPP
envelope is never nested inside a KCP one.

### 11.1 Negotiation

Every connection-oriented binding begins with `hello`; one-shot HTTP requests
carry the selected major/minor version in the media type or version header.

```text
HelloRequest {
  supported_versions[], implementation, implementation_version,
  requested_features[]
}

HelloResult {
  selected_version, implementation, implementation_version,
  features[], limits_digest, server_time, installation_id
}
```

The server selects the highest mutually supported version or returns
`unsupported-version`. Authentication occurs in the transport before `hello` or
through a binding-defined credential, never an identity claim in `HelloRequest`.
A one-request-per-connection binding MUST carry the negotiated version on every
request; it must not require a handshake on a connection it immediately closes.

### 11.2 Command envelope

```text
Command {
  version,
  op,
  meta: {
    request_id,
    idempotency_key,
    expected_revision?,
    causation_event_ref?,
    traceparent?
  },
  realm_id,
  project_id?,
  args,
  ext?
}

CommandResult =
  { outcome: "ok", result, revision?, event_cursor? }
  | { outcome: "problem", problem }
```

Every state-changing operation requires `meta`. Reads do not carry an
idempotency key and MUST NOT mutate authoritative domain or user-visible state.
They MAY append security/audit access records, update abuse/rate counters, and
populate non-authoritative caches; those effects cannot grant authority, change
a resource revision, or alter the logical read result. “Last viewed” and other
user-visible records require their own command.

Idempotency keys are scoped by authenticated actor, operation, and realm. The
server stores the canonical request digest and complete canonical result or a
durable result reference in the same transaction as the mutation. While that
result is retained, exact replay returns the original logical result and
revision. It never re-executes after expiry. Reusing the key with different
arguments returns `idempotency-mismatch`.

The idempotency request digest is the section 11.8 `CanonicalObjectDigest` for
kind `kcp-command-idempotency` and covers
`{version, authority_surface, op, realm_id, project_id?, expected_revision?,
args, ext}`. It excludes `request_id`, `traceparent`, transport headers,
and causation telemetry so a transport retry may have a fresh attempt id/trace
without changing the logical command. Actor identity is not client-provided
digest material because it is already part of the server-side scope.

Before returning a stored replay result, the service reauthorizes the actor
against the current resource and complete authorization dependency set.
Revocation returns
`forbidden` without re-executing or deleting the stored result. Replayable
results contain durable refs, not expiring upload/download/bearer grants; a
currently authorized client requests a fresh short-lived grant separately.

The full replay result for an ordinary command lives at least seven days. A
compact tombstone containing the scoped key, canonical request digest, resulting
resource/effect ref and revision, and expiry status remains for the owning
resource's retention lifetime. If the result can no longer be reconstructed, a
matching replay returns `idempotency-result-expired` and never executes as new;
clients never reuse an idempotency key. Keys and replayable results protecting
durable commitments, work realizations, handoffs, dispatches, and external effects live for the
full resource/effect retention period. An implementation cannot expire the only
record preventing repetition of an irreversible effect.

Mutable aggregates use optimistic concurrency. `expected_revision` mismatch is
`stale-revision`; the service never silently merges. Appending a contribution
requires the expected open branch/head frontier and allocates one dense
BranchEntry sequence plus one dense Contribution sequence in the Space, so
concurrent causal forks are explicit rather than silently ordered into a
fictitious conversation.

### 11.3 Event envelope and ordering

```text
Event {
  event_id,
  installation_id, realm_id, project_id?,
  stream_id, stream_sequence,
  project_sequence?,
  type,
  schema_ref,
  resource_ref, resource_revision?,
  actor_ref,
  causation_ref?, correlation_ref,
  occurred_at,
  classification_ref,
  payload_digest,
  payload | payload_ref,
  ext?
}
```

Event type names are reverse-domain names ending in a major version, for example
`dev.kovee.space.contribution-appended.v1`. The `dev.kovee.*` namespace is
reserved for system-generated events. Application assistants may emit only a
registered namespace granted to their deployment, and those events remain
non-authoritative until consumed through a typed command.

Ordering guarantees:

- `stream_sequence` is dense and monotonic within one aggregate stream.
- `project_sequence` is dense and monotonic for all Kovee-owned events committed
  in one project. The reference SQL implementation serializes assignment under
  the project head row; aborted transactions consume no sequence. Byom and Akson
  events keep their own source sequences and do not consume this counter.
- A multi-event transaction assigns consecutive project sequences.
- There is no global event order across projects or owners. Causation and
  correlation express cross-stream relationships.
- Byom and Akson retain their own cursors; a composite timeline merges them with
  source labels and causal links rather than inventing a false total order.

The public cursor is an opaque, authenticated encoding of source stream,
sequence, snapshot epoch, and filter boundary. It is never a NATS sequence.

### 11.4 Event reads and realtime delivery

```text
events_read {
  source, after_cursor?, project_id?, type_prefixes?, limit
} -> {events[], next_cursor, snapshot_epoch}

events_wait {
  source, after_cursor, filters?, timeout_ms
} -> {events[], next_cursor}
```

HTTP supplies snapshots and reads. WebSocket or SSE supplies live authorized
delivery. Clients always recover by calling `events_read` from their last
durable cursor; the realtime socket is an optimization, not the source of truth.

Event metadata is retained for the owning resource's audit period. Payload
retention may be shorter by classification. If a cursor predates available
history, the server returns `cursor-expired` with the oldest cursor and a
snapshot boundary. The client fetches an authorized snapshot and continues from
that boundary. It must not guess that its local cache is current.

Revocation applies to replay as well as live data. Historical access is checked
at read time; possession of an old cursor does not grant access.

### 11.5 Snapshots and pagination

List and snapshot queries use opaque cursor pagination:

```text
{ after?, limit, snapshot? }
  -> { items[], next?, snapshot, boundary_event_cursor }
```

The first page creates a stable snapshot token with an expiry of at least 15
minutes. Further pages see the same logical boundary or return
`snapshot-expired`; offset pagination is prohibited. Authorization is rechecked
for every page. Snapshot tokens are audience-bound and are not bearer grants to
the underlying resources.

“Stable snapshot” is a logical as-of view, not a database transaction held open
between HTTP requests. The token binds the owner/source, query+filter+sort digest,
as-of event boundary, authorization actor/dependency-set digest, and last key.
The service
either queries retained resource-version history as of that boundary or
materializes the ordered resource-id/version set for the token lifetime. New or
updated resources after the boundary do not appear and sort order cannot shift.
Current revocation or erasure may remove an item even from the historical set;
snapshot stability never preserves access to now-forbidden payload. The token is
MACed/encrypted or stored server-side and contains no reusable authority.

### 11.6 Initial operations

KCP `0.1` requires only the `core_v1` envelope/negotiation/problem semantics.
Product capabilities are atomic negotiated feature bundles; an implementation
MUST implement every operation/schema/conformance case in a listed bundle or not
advertise it. This lets each delivery phase specify its surface before code
without making K0 a schema waterfall for K6.

In the table, compact notation such as `space_create/show/list/update` expands
to four closed operations; it is not a runtime wildcard.

| Feature bundle | First phase | Commands/queries |
|---|---:|---|
| `core_v1` | K0 | `hello`, `protocol_info`, `diagnose`; envelopes, problems, idempotency, revisions, cursors |
| `shared_space_v1` | K1 | `realm_show`, `project_create/show/list`, `project_update_metadata`, `project_access_policy_change_prepare/show/list/confirm/cancel`, `space_create/show/list`, `space_update_metadata`, `space_freeze/reopen/archive`, `space_restrict`, `space_policy_narrow`, `space_access_widen_prepare/show/list/confirm/cancel`, `space_participant_add/activate/update/remove/list`, `space_access_grant_create/revoke/list`, `contribution_append/show/list/withdraw/supersede/redact`, `relation_assert/retract`, `frontier_pin/show`, `lens_create/show/list/update/revoke/read`, `context_assembly_create/show`, `reaction_set`, `events_read/wait`, `event_payload`, `snapshot_read`, `artifact_upload_begin/show/credential/finalize/abort`, `artifact_show`, `disclosure_manifest_show` |
| `developer_assistant_v1` | K1 | `assistant_create/show/list`, `assistant_revision_register/show/list`, `deployment_create/show/list/activate/drain`, `assistant_alias_bind/show/list/update/revoke`, `invocation_create/show/list/cancel`, `application_event_emit` |
| `deliberation_v1` | K2 | `branch_fork/show/list/freeze/reopen/archive`, `merge_prepare/show/list/accept/reject/withdraw` |
| `durable_runtime_v1` | K2 | `deployment_update/rollout`, `work_realization_show/list/cancel`, `invocation_input_manifest_show`, `checkpoint_show`, `budget_account_show`, `budget_reservation_show`, `usage_show`, `enforcement_evidence_show`, `effect_prepare/show/authorize/reconcile`, `invocation_force_cancel` |
| `standing_policy_v1` | K2 | `policy_propose/show/list/adopt/revoke`, `policy_ceiling_account_show`, `policy_ceiling_reservation_show` |
| `attention_coordination_v1` | K2 | `context_recipe_create/update/show/list/revoke`, `attention_contract_prepare/offer/accept/decline/narrow/widen/suspend/resume/revoke/show/list`, `attention_candidate_show/list/dismiss/activate`, `attention_use_account_show`, bounded `attention_replay_prepare/start/show/cancel` |
| `local_commitment_v1` | K2 | `need_create/open/show/list/update/withdraw/review`, `offer_create/show/list/update/decline/withdraw`, `formation_prepare/show/assent/assent_withdraw/accept/reject/withdraw`, `commitment_show/list/cancel`, `commitment_amendment_propose/assent/assent_withdraw/accept/reject/withdraw`, `commitment_delivery_submit/show/withdraw`, `commitment_review` |
| `governed_work_binding_v1` | K2 | `governance_enable/show/disable`, `collaboration_context_bundle_prepare/show`, `endeavor_promotion_prepare/start/show/cancel/reconcile`, `byom_episode_binding_show`, `workspace_provider_manifest_show/list`, `workspace_allocation_binding_show` |
| `model_broker_v1` | K2 | `model_provider_binding_create/show/list/update/disable`, `model_profile_create/show/list/update/disable`, `model_usage_show`, `provider_context_manifest_show` |
| `team_identity_v1` | K3 | `invitation_create/show/list/accept/decline/revoke`, `join_request_create/show/list/decide`, `membership_add/show/list/update/revoke`, `principal_binding_show/link_prepare/link_complete/revoke`, `artifact_grant_create/show/revoke`, `artifact_access_session_create/show` |
| `installation_admin_v1` | K3 | `realm_create/update/suspend`, `project_suspend/restore/archive`, `principal_recovery_prepare/complete`, `service_identity_show/rotate/revoke`, `realm_governance_binding_prepare/show/list/activate/rotate/disable`, `realm_akson_binding_prepare/show/list/activate/rotate/disable`, `audit_export` |
| `team_realtime_v1` | K3 | `realtime_resume`, `presence_list` |
| `space_handoff_v1` | K3 | `classification_mapping_propose/show/adopt/revoke`, `handoff_prepare/offer/show/list/accept/decline/revoke/cancel`, `handoff_transfer_show/reconcile`, `space_admission_show/decide/revoke` |
| `secure_effects_v1` | K4 | `tool_profile_create/show/list/update/disable`, `connector_profile_create/show/list/update/disable` |

Bundle dependencies are normative:

```text
core_v1
  -> shared_space_v1
       -> deliberation_v1
       -> developer_assistant_v1
            -> durable_runtime_v1
       -> team_identity_v1
            -> installation_admin_v1
            -> team_realtime_v1

shared_space_v1 + durable_runtime_v1
  -> standing_policy_v1

shared_space_v1 + durable_runtime_v1 + standing_policy_v1
  -> attention_coordination_v1
  -> local_commitment_v1

deliberation_v1 + durable_runtime_v1
  -> governed_work_binding_v1

durable_runtime_v1
  -> model_broker_v1

team_identity_v1 + shared_space_v1
  -> space_handoff_v1

durable_runtime_v1 + standing_policy_v1 + model_broker_v1
  -> secure_effects_v1
```

The graph does not make governed work depend on the model broker.
An installation advertises the transitive prerequisites with a feature. Byom and
Akson protocol-matrix entries additionally name the KCP bundles they require.

`governance_enable` is a deliberately narrow bootstrap. Its authority row is
frozen field-complete in the `byom_governed_work_v1` bundle: the surface is KCP
admin (personal mode, the owner principal over the UID-checked local socket; team
mode, the realm `owner` role over the authenticated gateway); the allowed actor is
a human realm-owner principal only — never a service identity, session, assistant,
or connector; the authorization dependency set is the realm revision, the target
`society_ref` plus Society recovery epoch, the byomd endpoint identity and
incarnation, the expected absent-or-identical `KoveeRealmByomBinding`, and the
`KoveeSocietyMapping` revision; the subject digest the confirming human sees
covers exactly the (realm, `society_ref`, recovery epoch, byom endpoint, mapping
revision, owner transition `none->byom`) tuple; assurance is a fresh step-up
challenge in team mode and explicit confirmation in personal mode, with
`governance_disable` always step-up; the fence is a binding-epoch CAS at the
expected revision, rejecting overlap and returning the identical binding on
retry; and service authority is recovery-only — a service may *query* saga state,
never create or activate a binding. In personal mode it may start or select a
daemon-managed local `byomd`, but it cannot bind an arbitrary endpoint, map
another principal, or establish the Society. Endpoint and principal-mapping
administration remains in `installation_admin_v1`.

Byom K2/K5 and Akson K6 capabilities appear as separate entries in the protocol
matrix, not KCP operations. Operations from an unadvertised feature return
`unknown-op`; clients never infer availability from product version alone.

Authority-bearing administrative commands and worker commands use distinct
surfaces. A principal administrator does not impersonate an agent attempt merely
because the operator surface “dominates” it. Overrides are explicit commands
such as `invocation_force_cancel`, require a reason, and emit an audit event.

BPP operations remain BPP operations. The Kovee gateway may route
`byom.kovee_endeavor_form`, for example, but its request and result schemas come
from the negotiated Byom protocol rather than this table.

#### 11.6.1 Normative authority matrix

Every protocol operation has exactly one entry in the versioned operation
registry. An entry may contain several disjoint authority clauses when the same
operation is exposed on different surfaces; the table renders those clauses as
separate family rows. No `(operation, authority_surface)` pair may match more
than one clause. The registry expands the compact bundle notation above and fixes
its surface, allowed authenticated actor kinds, action/scope, required
authorization dependency categories, fence, assurance, and offline behavior. An
operation missing an entry is not callable. The initial families are:

| Operations | Allowed surface / actor | Required action, scope, and dependencies | Fence | Assurance | Offline queue |
|---|---|---|---|---|---|
| `hello`, public `protocol_info` | external client / pre-auth channel | protocol negotiation only; bounded public installation metadata | none | none | no |
| `diagnose`, `audit_export` | operator / principal | installation diagnostics/audit; principal, auth observation, installation recovery epoch, realm and role where scoped | none | step-up for export | no |
| `*_show`, `*_list`, `lens_read`, `events_read`, `events_wait`, `event_payload`, `snapshot_read`, `presence_list`, `realtime_resume`, `artifact_upload_credential` | external client / principal; connector service only for its mapped resources | exact resource read/resume action; principal or service identity, realm/project/space, membership and space access, target and endpoint visibility, classification/retention, external visibility proof, and resume cursor where applicable | none | current login or workload identity | no mutation; cached draft only |
| project/Space creation and metadata; Space lifecycle/restrict/policy-narrow; participant proposal/update/removal; contribution/disposition; semantic-relation/disposition; lens, reaction, frontier, and artifact-upload mutations | external client / principal; mapped connector only for contribution/reaction/upload operations granted to it | exact action and space scope; identity, membership, space access, branch/frontier, target revision, referenced-object visibility, policy/classification; this family excludes project status and every prepared access-widening operation | none | current login; policy may require step-up for redact | only `contribution_append` and `reaction_set` |
| `space_access_widen_prepare`, `space_access_widen_cancel` | external client / authenticated steward/owner principal | exact Space revision, prior/proposed visibility/policy/classification, affected frontier/item/audience digests, and current read/disclosure dependencies | none | current login; policy may require step-up to prepare | no |
| `space_access_widen_confirm` | external client / authenticated steward/owner principal only | exact prepared widening subject and unchanged Space/item-set revisions plus authorization decision receipt; item-level policies remain intersected | none | risk-required current step-up | no |
| `project_access_policy_change_prepare`, `project_access_policy_change_cancel`, `project_access_policy_change_confirm` | external client / authenticated project owner principal only | exact Project revision, prior/proposed policy/default classification, affected Space frontier/item/audience digests, effective-change class, and decision receipt for confirm | none | risk-required step-up for confirm | no |
| branch fork/freeze/reopen/archive; merge prepare/reject/withdraw; context assembly request; context-recipe mutation; Need create/open/update/withdraw, Offer create/update/decline/withdraw, Formation preparation/reject/withdraw; Commitment amendment proposal/reject/withdraw; attention prepare/offer/narrow/suspend/revoke, candidate dismiss, and replay prepare/cancel | external client / principal; fenced worker only for an exact listed proposal operation in its capability | exact prepare/propose action, space/branch/context/terms revision and subject digest; worker proposals bind current invocation, fence, assembly, ceilings, and output scope | current attempt fence for worker-originated proposals | current login or worker capability | no |
| assistant definition/revision/deployment/alias mutations | operator / principal | exact author/deploy action; identity, realm/project, membership, target/config/policy revisions | none | step-up for production activation/rollback | no |
| policy proposal | external client / principal; fenced worker or service identity only with an exact proposal capability | exact inert policy subject, realm/project scope, current policy-set digest, provenance and proposer identity; creates no active authority | current attempt fence for worker proposals | current login or workload identity | no |
| policy adoption/revocation; model-provider binding and model/tool/connector profile create/update/disable | operator / authenticated principal only | exact policy/binding/profile revision and digest, realm/project scope, credential-binding metadata, destination/classification restrictions, and affected deployment dependencies | none | current risk-required step-up for adoption, production activation, or disable | no |
| Formation or Commitment-amendment assent/assent-withdraw | external client / exact authenticated party principal; worker surface / current fenced attempt only for its own requester slot under an explicit bounded-child-work capability; narrow policy service for an exact assistant party slot | exact proposal revision/subject, party role/ref/slot, terms and disclosed-subject digests, decision/policy use or requester capability, and complete current dependency set; worker assent additionally binds its InvocationCapability, parent WorkRealization/ByomEpisodeBinding if any, and inherited budget/deadline/disclosure ceilings | current Kovee attempt fence and Byom fence when requester work is Byom-bound; neither worker nor policy service may fill another human/assistant slot | current assurance, workload identity, and capability/policy required by the terms | no |
| Formation or Commitment-amendment final acceptance | external client / authenticated coordinator principal or owning Kovee commitment service | exact proposal revision/subject and complete locked set of one active assent per derived requester/performer slot; finalizer supplies no party assent | none | current login or workload identity | no |
| attention accept/decline/resume/widen/candidate-activate/replay-start; merge acceptance; Commitment/Need review; participant activation | operator / authenticated principal, or narrow policy service consuming an exact active standing-policy/contract receipt | exact prepared subject digest, current target acceptance, space/branch/frontier/terms revisions, use account, budget/disclosure union, and complete dependency set | none; never model prose or a worker self-decision | current assurance required by policy | no |
| Commitment delivery submit/withdraw | external client / authenticated principal performer, or worker SDK / current attempt of the exact WorkRealization child invocation | current Commitment revision/terms digest, performer binding, required WorkRealization+child invocation for assistant delivery, outcome/evidence schema, space/context visibility, and delivery subject digest | current bound attempt fence for worker delivery | current login or exact worker capability | no |
| direct invocation | external client / authenticated principal/operator only | exact manual/deployment-test create action; full target deployment/revision, ContextAssembly/input manifest, budget, disclosure, policy and authorization dependencies; it cannot name a worker as requester or create a Commitment | none | current login; production test may require step-up | no |
| Invocation, Commitment, and WorkRealization cancel | external client / authenticated creator or authorized principal; worker SDK only for its exact child invocation/Commitment/WorkRealization under an explicit parent capability | exact current invocation/commitment/realization revisions, terms, ancestry and cancellation scope; worker cancellation binds the parent attempt and inherited ceilings | current attempt fence for worker-originated child cancellation, plus Byom fence when bound | current login or worker capability | no |
| effect prepare | external client / authenticated principal, or worker SDK / current attempt where its capability permits the exact effect kind | exact canonical subject/revision/digest, profile binding, preconditions, disclosure, budget, policy set and authorization dependencies; preparation grants no execution | current Kovee fence and Byom fence for worker-originated Byom-bound effects | current login or worker capability | no |
| artifact access-session create | external client / authenticated grant recipient principal or mapped service | exact active ArtifactGrant revision, grantee binding, artifact/version/digest, purpose/action, use key, expiry/max-use counter, current source visibility and authorization dependencies | none; session capability is audience/action/TTL-bound | current login or workload identity | no |
| checkpoint/contribution/semantic-relation/model/tool/`application_event_emit` worker operations | worker surface / invocation attempt only | exact operation and space/object scope listed in the invocation capability; invocation manifest, deployment/config, attempt, branch/context, budget, policy and authorization dependencies | current Kovee fence and Byom fence when bound | workload identity plus invocation capability | no |
| `structural_relation_record`, `structural_relation_dispose` (internal registry only) | owning Kovee service only | transactionally observed structural fact and visible exact endpoints; kind/class are service-derived and absent from external schemas | owning transaction fence/revision | workload identity | no |
| force-cancel, realm/binding, project-status, identity/membership, invitation/join, space-access-grant administration, classification mapping, artifact grant, handoff offer/admission decisions, effect authorization/reconciliation | operator / principal only | exact administrative/governance action; complete identity, realm/project/space, membership/role, target revision, policy/grant/binding dependencies and prepared subject digest; this family excludes access-widening confirms and handoff-transfer reconciliation | none; cannot impersonate a worker | current step-up observation at risk-required level | no |
| `governance_enable`, `governance_disable` | KCP admin / human realm-owner principal only (personal: owner over the UID-checked local socket; team: realm `owner` role over the authenticated gateway) — never a service identity, session, assistant, or connector | realm revision, target `society_ref` + Society recovery epoch, byomd endpoint identity/incarnation, expected absent-or-identical `KoveeRealmByomBinding`, `KoveeSocietyMapping` revision, and the exact enable subject digest the confirming human sees; a service may only *query* saga state, never create or activate a binding | binding-epoch CAS at the expected revision; overlapping scope rejected; retry returns the identical binding | fresh step-up in team mode, explicit confirmation in personal mode; `governance_disable` always step-up | no |
| handoff transfer reconcile | Kovee handoff service, or authorized operator/principal | exact persisted transfer/offer/destination preparation/source-use ids, digests, dependency sets, and stable reconciliation key; may only recover the existing transfer outcome | transfer revision | workload identity or risk-required current login | no |
| collaboration-context-bundle and endeavor-promotion prepare/start/cancel | external client / authenticated principal | exact Space frontier/assembly, destination `KoveeRealmByomBinding` + `KoveeSocietyMapping`, `kovee_endeavor_form` command digest, bound Participant, rendered Society decision rules, and budget/workspace terms, plus current Kovee/Byom authorization dependencies; cancel only while `prepared` and no slot was ever acquired | none; the BPP command derives its own `DelegatedPrincipalCredential` | Byom-required current assurance (fresh attempt proof over the stable command/idempotency domain) | no |
| endeavor-promotion reconcile | narrow Kovee recovery workload on the byom projection surface, or authenticated mapped principal | exact stored formation intent id, byom endpoint, bound Participant, canonical command digest and IdempotencyDomain; the workload may only run the read-only five-fact `external_command_result_query` and finish its link, while only a fresh principal request may resubmit the unchanged stored command when byom reports `absent`; `external_command_terminalize` is the same-source human's terminal claim and never executes | formation intent revision paired with the slot generation; never releases the branch slot on a timeout | workload mTLS for read-only recovery, or Byom-required current principal assurance for resubmission | no |
| effect execution, model/tool/connector egress | broker surface / effect-driver service only | unconsumed local execution permit or persisted external-authority consumption plus current restriction dependency set, budget and disclosure | current bound attempt fences before egress | workload identity | no |
| BPP operations | byom governance/participant/candidate surface / bound Participant or seated human principal, or byom runtime surface / byomd-minted subject-scoped workload channel | the BPP operation's own registry row governs actor, closure, fence, and assurance; every composed/projected read additionally intersects current Kovee project/space/object visibility, classification/retention, and byom's D-closure source proof | the Byom fence the row demands, plus the Kovee fence on every runtime mutation (dual fences) | Byom-required principal observation with fresh challenge, or attested workload identity | no |
| Akson stage/dispatch/consent | no KCP or generic operator/worker surface; Kovee's narrow `byom_akson_dispatch_v1` driver only | the current finalized Byom ActIntent, its consumed `ExecutionConsumptionReceipt`, and the Akson-owned binding plus consent reference; Byom's delegation engine authorizes and never calls, Kovee's driver calls and never decides | source-required Mandate generation/fence | dedicated workload identity | no |

Here `*_show`, `*_list`, and the named families are specification shorthand for
an explicit generated row per operation; they are not runtime wildcard matches.
The `AuthorizationDependencySet` category list in section 9.2 is mandatory input
to those rows. A policy may require stronger assurance or a narrower scope but
cannot add an actor kind or surface. Conformance enumerates every operation
against every surface/actor kind and requires all pairings absent from its row to
fail with `forbidden-surface` or `forbidden` without revealing the resource.

### 11.7 Problem details

Errors use RFC 9457 Problem Details with
`type: urn:kovee:error:<kind>`. Initial kinds:

| Kind | Status | Meaning |
|---|---:|---|
| `invalid` | 422 | Invalid I-JSON, envelope, schema, closed enum, or limit. |
| `unauthenticated` | 401 | No valid channel identity. |
| `forbidden` | 403 | Actor cannot perform the operation or see the resource. |
| `not-found` | 404 | No visible resource; responses do not reveal cross-tenant existence. |
| `unsupported-version` | 400 | No common protocol version. |
| `unknown-op` | 400 | Operation absent at the negotiated version. |
| `forbidden-surface` | 403 | Operation exists but not on this authority surface. |
| `stale-revision` | 409 | Optimistic revision mismatch; includes current visible revision. |
| `stale-lease` | 409 | Attempt or fence no longer owns the invocation. |
| `idempotency-mismatch` | 409 | Same scoped key, different canonical request. |
| `idempotency-result-expired` | 410 | Matching command was committed but its full result is no longer retained; it was not re-executed. |
| `authorization-stale` | 409 | At least one bound authorization dependency changed or can no longer be checked. |
| `budget-exceeded` | 409 | Reservation would exceed the applicable ceiling. |
| `deadline-exceeded` | 409 | Work cannot start or continue within its deadline. |
| `cycle` | 409 | Commitment/realization ancestry would create a forbidden cycle. |
| `cursor-expired` | 410 | Durable replay is no longer available; includes snapshot recovery data. |
| `snapshot-expired` | 410 | Stable pagination boundary expired. |
| `rate-limited` | 429 | Rate or abuse limit; includes bounded retry guidance. |
| `ambiguous` | 409 | External effect outcome is unknown and needs reconciliation. |
| `unavailable` | 503 | Required authoritative component cannot safely accept the operation. |
| `internal` | 500 | Implementation fault; does not leak paths, tokens, policy internals, or peer existence. |

### 11.8 Encoding and limits

- JSON is UTF-8 strict I-JSON: duplicate keys, non-finite numbers, unsafe
  integers, and unpaired surrogates are rejected.
- Canonical request/event/decision digests use the typed RFC 8785 JCS and
  SHA-256 construction below.
- Request body: 256 KiB maximum. Reply: 1 MiB maximum. Larger content uses an
  artifact or paginated resource.
- Identifier: 128 bytes. Display name: 256 Unicode scalar values. Contribution inline
  content: 64 KiB. Registered application event payload: 64 KiB.
- A request contains at most 256 list items. Page/event read limit is at most
  512. Artifact limits come from realm policy and are enforced before upload.
- Free text and peer-sourced metadata are length-bounded again at admission.
- Safety-relevant enums are closed. Unknown extension data is preserved where
  specified but never creates authority.

Every security-sensitive `*_digest` has a schema-registry entry with an exact
field projection and one of two non-interchangeable types:

```text
CanonicalObjectDigest(kind, schema_ref, projection) =
  SHA-256(JCS({
    "$domain": "dev.kovee.canonical-object-digest.v1",
    "protocol_major": 0,
    "object_kind": kind,
    "schema_ref": schema_ref,
    "projection": projection
  }))

TypedByteDigest(domain, media_or_schema_ref, bytes) =
  SHA-256(frame("dev.kovee.typed-bytes-digest.v1") ||
          frame(domain) || frame("0") ||
          frame(media_or_schema_ref) || frame(bytes))

frame(x) = uint64_be(byte_length(x)) || x
```

The projection registry declares every included field; “serialize the current
struct” is not a digest definition. Unknown `ext`, database ids, timestamps, and
telemetry are excluded unless that digest's schema explicitly includes them.
Conversely, any field that can change the authorized subject, recipient,
classification, precondition, budget, or effect must be in its projection.

Artifacts also retain ordinary `raw_sha256 = SHA-256(bytes)` for integrity and
content-addressing, but authorization binds an
`artifact-bytes` `TypedByteDigest`. Provider request/response bytes use distinct
`provider-request-bytes` and `provider-response-bytes` domains. A raw checksum,
canonical-object digest, and typed-byte digest are different field types and
cannot satisfy one another even when their 32-byte values happen to match.
Portable records encode a digest with its declared digest type/domain (or in a
schema field whose type is fixed); a bare 32-byte string cannot be substituted
across digest fields.
Conformance includes cross-kind, cross-schema, artifact/provider, omitted-field,
numeric, Unicode, and concatenation-substitution vectors.

### 11.9 Compatibility and extensions

- Minor versions are additive. Existing fields and operations do not change
  meaning within a major version.
- Clients ignore unknown optional response fields but fail on unknown values in
  closed safety enums.
- Extensions live under `ext` keyed by a reverse-domain namespace. Unknown
  extensions are round-tripped where the operation promises preservation and
  are never interpreted as identity, authorization, budget, or policy.
- Event and content payload schemas have immutable ids/digests. A breaking
  payload change uses a new major event type.
- A feature must be negotiated before use.
- Deprecation lasts at least one minor release before a major-version removal.
- Public subject names, SQL layout, worker pool names, and NATS configuration are
  explicitly outside compatibility.

### 11.10 Protocol composition at the gateway

KCP, the Byom Participation Protocol, and Akson's local protocol remain
separately named and versioned. A client discovers a protocol matrix:

```text
ProtocolMatrix {
  kovee: {versions[], features[]},
  byom?: {versions[], features[], authority_endpoint_ref, surfaces[]},
  akson_projection?: {versions[], features[], source_endpoint_ref}
}
```

The HTTP binding uses an unambiguous protocol route/media type and version for
every request. A BPP command keeps byom's own `{version, op, meta?}` envelope
with its arguments at the top level, its operation name, its IdempotencyDomain,
its digest rules, its result, and its `https://byom.dev/problems/*` problems; it
is never nested inside a KCP mutation whose semantics could disagree, and its
problems are never renamed into `urn:kovee:error:*` kinds. The gateway
authenticates the network client, resolves the realm's current
`KoveeRealmByomBinding` and `KoveeSocietyMapping`, mints a short-lived
`DelegatedPrincipalCredential` bound to the acting human's admitted Participant,
and sends the command to the correct byomd surface socket. No binding means the
command is forbidden.

Kovee-owned follow-up state, such as linking an exact space frontier/context
assembly to a newly formed Endeavor, is a recoverable saga rather than a
distributed transaction:

1. Record a Kovee `EndeavorFormationIntent` with correlation and idempotency
   keys, and an append-only `EndeavorFormationAttempt` per send.
2. Execute the idempotent `kovee_endeavor_form` command and persist its exact
   signed result/reference.
3. Commit the Kovee `ExternalLink` under its own command transaction.
4. If step 3 is interrupted, reconciliation repeats only the link commit; it
   never forms a second Endeavor.

Composite reads return source-qualified objects and cursors. They may be exposed
in one UI response, but no composite envelope rewrites source ids, revisions,
digests, problems, or authority.

## 12. Persistence and consistency

### 12.1 Storage choices

Personal mode uses SQLite with WAL, foreign keys, explicit migrations, and a
single-writer transaction discipline. Team mode uses PostgreSQL. JetStream KV is
not an interchangeable session store and MUST NOT be used as the authoritative
store for memberships, spaces, contributions, commitments, gates, revisions,
leases, budgets, idempotency, or effects.

The reference schema has, at minimum, tables for:

```text
realms                 realm_akson_bindings    principals
principal_auth_bindings authentication_observations service_identities
invocation_capabilities
enrollment_invitations join_requests           projects
project_access_policy_changes
memberships            authorization_dependency_sets
spaces                 space_participants      space_access_grants
space_access_widenings
contributions          contribution_dispositions space_relations
relation_dispositions
space_frontiers        space_lenses             reactions
reasoning_branches     branch_entries           merge_proposals
merge_commits          context_recipes          context_assemblies
attention_contracts    attention_candidates     attention_activations
attention_triages      attention_use_accounts   attention_uses
attention_replays
assistant_definitions  assistant_revisions    assistant_deployments
assistant_alias_bindings
worker_instances       invocations            invocation_attempts
invocation_input_manifests run_leases          concurrency_slots
checkpoints
needs                  need_reviews           offers
formation_proposals    terms_assents
collaboration_commitments commitment_amendments commitment_deliveries
commitment_reviews     work_realizations
collaboration_context_bundles endeavor_formation_intents endeavor_formation_slots
endeavor_formation_attempts external_links
handoff_offers         handoff_transfers       handoff_uses
space_admission_records
classification_mapping_revisions
artifact_metadata      artifact_uploads        artifact_verifications
artifact_grants        artifact_grant_uses     artifact_access_sessions
disclosure_manifests   policy_revisions        policy_ceiling_accounts
policy_ceiling_reservations action_intents     decisions
decision_uses          execution_permits       effects
model_provider_bindings model_profiles          tool_profiles
connector_profiles
enforcement_evidence   provider_context_manifests
kovee_realm_byom_bindings kovee_society_mappings
kovee_governance_owner_bindings
byom_episode_bindings  placement_bindings
byom_subordinate_reservations
workspace_provider_manifests workspace_allocation_bindings
external_authorization_consumptions
effect_attempts        effect_receipts         budget_accounts
budget_reservation_sets usage_records
events                 event_payloads          stream_heads
idempotency_results    outbox                 consumer_inbox
audit_records          schema_registry        migration_history
```

Byom and Akson own additional schemas through their own migrations. Table
co-location in one PostgreSQL cluster does not weaken ownership or authorize
cross-module writes.

Required uniqueness includes:

- `(branch_id, branch_sequence)`, `(space_id, space_sequence)`, and
  `(stream_id, stream_sequence)`.
- `(project_id, project_sequence)` where a project sequence exists.
- `(actor_scope, operation, idempotency_key)`.
- One active `(installation_id, canonical_issuer, provider_subject_ref)`
  principal authentication binding.
- `(contract_id, contract_revision, source_batch_digest)` for one logical
  candidate; activation and bounded replay add their separate ids.
- `(account_id, activation_id)`, `(account_id, wake_use_ordinal)`, and
  `(contract_id, contract_revision, wake_use_ordinal)` for attention use.
- `(invocation_id, operation_key)` for all agent-visible mutating operations.
- `(consumer_name, delivery_id)` for internal broker-delivery deduplication.
- `(commitment_id, commitment_revision)` for a realization's deterministic
  creation key and `UNIQUE(child_invocation_id)` when present.
- One active `(local_branch_id, owner_protocol:byom, link_kind:endeavor)`
  ExternalLink; replacement compare-and-swaps and supersedes the exact prior id.
- One non-released EndeavorFormationSlot per local branch; it is never
  timeout-released after external submission.
- `(realm_ref, exact_scope_selector)` for KoveeGovernanceOwnerBinding, with
  overlapping governed scopes rejected.
- `(episode_ref, byom_attempt_ref, kovee_invocation_ref)` for a
  ByomEpisodeBinding's idempotent create key.
- `(decision_id, use_key)` and `(decision_id, use_ordinal)`.
- The artifact upload/version, grant-use/idempotency, and policy-ceiling
  uniqueness constraints declared in sections 10.10 and 9.5.
- `UNIQUE(execution_permit_ref)` on the logical effect; retry attempts reference
  that same effect rather than consuming another permit.
- One current lease/fence head per invocation.

### 12.2 Command transaction

An authoritative mutation performs one transaction:

1. Authenticate the channel and derive actor.
2. Build and authorize against the complete current
   `AuthorizationDependencySet` required by the operation.
3. Canonicalize the command and check its idempotency record.
4. Lock or compare the aggregate head and any budget/lease rows.
5. Validate the requested transition and preconditions.
6. Update normalized state.
7. Append typed domain and audit events with their sequences.
8. Insert outbox notifications/jobs.
9. Persist the canonical result for idempotent replay.
10. Commit before replying.

If the process dies after commit and before reply, replay returns the stored
result. If it dies before commit, none of state, event, outbox, budget, or
idempotency result exists.

Kovee is not required to be a pure event-sourced system. Normalized state is the
query model, and the immutable ledger is the audit/attention record. They
commit together and recovery tests prove they cannot diverge.

### 12.3 Consistency guarantees

Kovee v0.1 guarantees:

- Strong consistency for an authoritative aggregate in its home region.
- Read-your-writes from the authoritative API after a successful command.
- Dense monotonic BranchEntry ordering per branch and Contribution ordering per
  Space.
- Dense monotonic event ordering per Kovee project and per aggregate stream.
- Compare-and-swap branch heads and merge acceptance against exact source/target
  frontier digests.
- Atomic attention-use reservation with candidate activation; accepted wake and
  in-flight ceilings cannot be overrun by concurrent candidates.
- Atomic exact-offer acceptance, commitment creation, budget reservation, and
  WorkRealization creation where the performer is an assistant.
- At-least-once internal notification and work delivery.
- Idempotent state transitions and observable effects under redelivery.
- Eventual consistency for search, notification, analytics, and remote read
  projections, with a visible source cursor.

It does not guarantee:

- A total order across projects, Byom, and Akson.
- Exactly-once agent computation.
- Exactly-once effects in an external system that has neither idempotency nor a
  reconciliation API.
- Writes during loss of the authoritative SQL primary.
- Automatic multi-master conflict merging.

### 12.4 Transactional outbox and inbox

The outbox publisher:

1. Claims committed outbox rows with a bounded lease.
2. Publishes a minimal envelope with stable `delivery_id` derived from the
   logical `event_id` or `job_id`; that is the broker deduplication id.
3. Waits for the configured durable publish acknowledgement.
4. Records delivery status. A crash may publish twice, so consumers still dedupe.

A durable consumer:

1. Receives under explicit acknowledgement.
2. Opens a SQL transaction and inserts `(consumer_name, delivery_id)` into its
   inbox.
3. If the row already exists, commits and acknowledges without applying again.
4. Otherwise validates the envelope, loads authoritative state as needed,
   applies an idempotent transition or projection, and commits.
5. Acknowledges only after commit.

A message that repeatedly violates schema or deterministic processing moves to
a quarantine/dead-letter record after bounded attempts. It cannot block the
consumer forever. Operators can inspect, repair, skip with an audited reason, or
re-publish the same logical delivery id after a versioned repair. Re-driving
under a new business idempotency identity is prohibited because it could repeat
an effect; transport-attempt ids may change while the logical id remains fixed.

Broker work is only a hint over authoritative SQL. A fenced scheduler sweep
periodically scans runnable invocations, expired attempt/job leases, and missing
or quarantined dispatch notifications. It inserts the deterministic outbox job
id if no current delivery exists. Loss of a broker job therefore delays work but
cannot strand authoritative `queued` state. If the payload itself is impossible
under the current schema, the invocation becomes a visible platform fault rather
than being silently skipped or recreated as different work.

## 13. Internal NATS/JetStream binding

NATS is a clustered team-mode implementation choice, not part of KCP. Another
delivery system may replace it if it passes the same failure and conformance
tests.

### 13.1 Subject topology

Illustrative private subjects:

```text
kv.v1.<environment>.evt.<service-family>.<shard>
kv.v1.<environment>.job.<handler-family>.<shard>
kv.v1.<environment>.wake.<pool>.<runtime>
kv.v1.<environment>.signal.presence.<shard>
```

Subjects route to a service family and shard. They do not encode human-readable
realm, project, space, branch, lens, participant alias, Need, Commitment, user,
assistant alias, or arbitrary event type.
The validated envelope contains opaque resource references, and the receiving
service reauthorizes or loads the authoritative record.

No frontend, connector handler, assistant package, or third-party plugin obtains
a wildcard service credential. Backend components receive short-lived,
least-privilege credentials for exact publish/subscribe families. Dedicated
accounts or clusters MAY provide defense in depth for high-isolation realms but
do not replace API authorization.

### 13.2 Streams and consumers

The reference team installation uses:

- Durable event notification streams with bounded limits retention and one
  durable consumer per projector/integration.
- Work-queue streams for runtime and projection jobs, explicit ack, bounded
  maximum delivery, exponential backoff, and quarantine after exhaustion.
- Core NATS only for reconstructable presence and wakeup hints.
- At least three replicas for production streams in a three-failure-domain
  cluster, with storage and fsync choices documented and monitored.

Retention is an operational replay window, not the application audit lifetime.
PostgreSQL is the backfill and rebuild source. Kovee never exposes a JetStream
consumer sequence as a client cursor.

Queue groups or work-queue consumers load-balance a delivery, but delivery alone
does not authorize execution. A worker must atomically claim the SQL invocation
and receive the next fence epoch. Ordinary pub-sub fanout must never cause every
worker to run the same invocation.

### 13.3 Broker outage

If SQL commits while NATS is unavailable, the command succeeds as accepted and
queued, and the outbox retains delivery. The API surfaces increasing delivery
lag and applies configured backpressure before storage is exhausted. It does not
roll back a committed contribution merely because realtime notification is late.

If the authoritative database is unavailable, consumers do not acknowledge and
the API accepts no mutation. A broker backlog after recovery is deduplicated by
the database inbox and effect keys.

Kovee does not stretch one NATS cluster into a synchronous global database.
Regions use the realm's home write region; sovereign installations use Akson.

## 14. Assistant authoring and packaging

### 14.1 The small API

Kovee retains the brainstorm's approachable Python surface as SDK sugar over
durable protocol operations. This model-backed example requires
`model_broker_v1`; a K1-only assistant uses the same `run(ctx)` shape without
`ctx.model`:

```python
from kovee import Assistant, InvocationContext


class Summarizer(Assistant):
    async def run(self, ctx: InvocationContext) -> None:
        question = ctx.context.trigger_contribution
        research = await ctx.request_work(
            "researcher",
            need={"goal_or_question_ref": question.ref,
                  "outcome_schema_ref": "schema:research-note-v1"},
            deadline=ctx.deadline,
            operation_key="research-v1",
        )
        model_context = await ctx.assemble_context(
            selection_policy="explicit_refs_v1",
            required_refs=[question.ref, research.delivery_ref],
            operation_key="summary-context-v1",
        )
        summary = await ctx.model.complete(
            profile="default",
            context=model_context,
            instruction_ref="instruction:summarize-v1",
            operation_key="summary-model-v1",
        )
        synthesis = await ctx.contribute(
            kind="synthesis",
            parts=[{"type": "text", "text": summary}],
            addresses=[question.ref],
            operation_key="summary-contribution-v1",
        )

        await ctx.relate(
            "derived_from", synthesis.ref, research.delivery_ref,
            operation_key="research-relation-v1",
        )
        await ctx.events.emit(
            "com.example.document.summarized.v1",
            {"space_id": ctx.space_id,
             "delivery_ref": research.delivery_ref},
            operation_key="event-v1",
        )
```

`InvocationContext` exposes only mediated operations:

- Read the immutable `ContextAssembly`, its exact contributions/relations, and
  currently authorized artifact refs through `ctx.context`.
- Request a new explicitly selected/authorized assembly with
  `ctx.assemble_context`; it never mutates or appends to the current assembly.
- Append an attributed typed contribution with `ctx.contribute` and assert a
  permitted semantic relation with `ctx.relate`.
- Open and await bounded local collaboration through `ctx.request_work` sugar.
- Emit a validated, namespaced application event.
- Request model use under a named broker policy.
- Request a registered tool/connector effect.
- Record progress, a checkpoint, or a typed wait reason.
- Observe cancellation, deadline, remaining budget, and lease health.
- Return structured output or failure diagnostics.

Every mutating SDK operation requires an `operation_key` unique within the logical
invocation. The supervisor combines it with the invocation id and uses it as the
durable deduplication key. The assistant derives the key deterministically from
the logical step; it must not generate a fresh random key on each attempt.
Retries after a lost reply return the first result.

The context is a view over immutable refs, not a mutable serialized `Chat`
object. `ctx.context` reads the recorded assembly, so a concurrent contribution
does not silently change the invocation input. An assistant that needs newer
state requests a new authorized assembly explicitly. `ctx.reply` and
`Chat.say/ask` may exist as convenience wrappers over `contribute` plus an
`addresses` relation; they are not a separate content model.

`ctx.request_work` is narrow sugar, not agent RPC: when an exact standing policy
already permits a named local helper, the SDK orchestrates replay-safe typed
steps: open the Need, obtain/select the exact Offer, prepare the Formation,
record the caller's requester assent under its bounded child-work capability,
and ask the independent policy service to record the helper-performer assent.
The final `formation_accept` transaction consumes the complete assent set and
creates the `local_non_governed` Commitment, reservation, and WorkRealization
atomically. These are not one end-to-end transaction, and the caller never
manufactures the helper's assent. If either assent or any current dependency is
missing, the call returns the open/pending Need/Offer/Formation workflow for
review instead of silently assigning an agent. It cannot create Byom Endeavor
work, remote work, a workspace, or effect authority.

### 14.2 Manifest

Each assistant revision includes a validated manifest:

```text
schema_version
definition_id
version
entrypoint
package_digest
runtime + locked dependency metadata
supported_worker_protocols
input_schema_ref
output_schema_ref
skills[]
attention_proposals[]
requested_capabilities[]
model_profiles[]
tool_profiles[]
network_policy
resource_limits {cpu, memory, disk, output_bytes}
default_timeout
max_concurrency
causal_concurrency_policy
checkpoint_support
cancellation_support
security_profiles[]
```

Skills and aliases advertise routing suitability; they never grant permission.
Attention declarations are inert proposals. Deployment may activate one only
after deterministic validation and an exact target/principal acceptance or
standing-policy use; packages never select raw subjects or install their own
wake authority.

### 14.3 Development and production

`kovee dev assistants/summarizer.py` MAY import local source under the operator's
UID and provide hot reload. It prints an explicit `developer` security warning
and cannot be represented as tenant-isolated or egress-controlled.

Developer convenience does not make revisions mutable. On initial load and
every reload, Kovee snapshots the source plus its resolved local dependency
manifest into a content-addressed development package, mints a new immutable
`AssistantRevision` and deployment revision, and atomically advances the alias
for future invocations. Existing invocations remain pinned to the prior package,
config, and dependency digests. A file watcher never changes code underneath a
running or retrying invocation.

Production deployment is:

```text
source + locked dependencies + manifest
  -> reproducible package
  -> digest and optional signature
  -> policy/security scan
  -> immutable assistant revision
  -> explicit deployment revision
  -> gradual activation / rollback
```

The control plane never imports the package. A confined worker or sandboxed
runtime loads it. Existing invocations stay pinned during rollout; new
invocations select a revision under a deterministic rollout rule recorded in the
invocation.

### 14.4 Security profiles

| Profile | Boundary | Honest claim |
|---|---|---|
| `developer` | Same UID, local source, ambient process authority may exist | Convenience and audit for cooperating code; no confinement claim |
| `confined` | Isolated process/container, bounded filesystem, no broker/DB credentials | Agent cannot directly access Kovee authority surfaces |
| `secure` | Confined plus default-deny network, brokered models/tools/connectors, no ambient secrets, immutable package | Declared egress and capabilities are enforced by the supervisor boundary |

The names and meanings align with Byom's Manifestation profiles. A Byom
Manifestation can claim “holds no authority” only when both its harness and
underlying Kovee worker satisfy the required profile; byom sees the
`ManifestationRevision` plus Kovee's enforcement evidence, never the manifest's
self-assertion. Declaring `secure` in a manifest is insufficient. A worker's
compatibility advertisement is only an eligibility hint; enforcement evidence
comes from the trusted supervisor/orchestrator or a verified platform-attestation
mechanism outside assistant code. The scheduler refuses missing or mismatched
evidence.

## 15. Runtime, scheduling, and fencing

### 15.1 Invocation creation

An invocation is created only by an authenticated direct command, an admitted
`AttentionActivation`, a `WorkRealization` from an accepted assistant
Commitment, an explicit
deployment test, or a Byom `episode_request` for a hosted Manifestation.
Admission of peer material never wakes
work by itself; a later local attention activation may do so. Its input manifest
binds:

- Trigger/candidate/commitment refs and digests.
- Space, branch, exact frontier, and immutable `ContextAssembly` ref/digest,
  including the ordered contribution/relation refs and recorded omissions.
- Artifact refs, sizes, digests, and classifications.
- Assistant and deployment revisions, immutable config ref/digest, and secret-
  binding-set ref/digest (never the secret values).
- Effective policy digests plus the authorization dependency-set ref/digest.
- Model/tool profiles and disclosure rules.
- Deadline, cancellation policy, resource limits, and budget reservation.
- Correlation, causation, and parent ancestry.

The manifest is canonicalized and its digest recorded before scheduling. A
worker never receives “whatever the space contains now.” Every materialization
reauthorizes the assembly's items and target; loss of access fails explicitly.

### 15.2 Claim and lease

The scheduler chooses eligible worker pools by declared runtime, security
profile, realm isolation, data region, capacity, and policy. Within the eligible
set it uses declared priorities and fairness; no model makes placement choices.

A worker delivery contains only an invocation id and wake token. The worker
calls `attempt_claim`; the SQL transaction checks eligibility and state, then
increments the invocation fence head and returns:

```text
RunLease {
  invocation_id,
  attempt_id,
  ordinal,
  worker_instance_id,
  fence_epoch,
  acquired_at,
  renew_after,
  expires_at
}
```

Every checkpoint, contribution append, relation assertion, Offer or delivery,
model/tool request, progress update, result, and completion carries
`{attempt_id, fence_epoch}`. The
authoritative service checks it immediately before commit or broker execution.
An expired or superseded attempt receives `stale-lease` even if its credential is
otherwise valid.

Lease renewal is a database compare-and-swap, not a heartbeat conclusion. Worker
clock is advisory; the server's trusted clock determines expiry. The normal
lease is short enough to recover promptly and long enough to tolerate transient
latency; reference defaults are 30 seconds with renewal by 10 seconds, tunable by
pool. A worker that cannot renew stops requesting new effects and yields before
expiry.

### 15.3 Concurrency

Default causal policy is at most one active invocation per
`(space_id, branch_id, assistant_deployment_id)`. Deployments may instead declare:

- `serial-branch` — the default; preserves causal processing on one branch.
- `parallel-independent` — each event may run concurrently; outputs remain
  independently sequenced.
- `causal-keyed` — serialization by a schema-validated key and frontier lineage.

```text
ConcurrencySlot {
  scope_kind: space_branch_deployment|deployment|causal_key,
  scope_id, normalized_key_hash,
  holder_invocation_id, holder_generation,
  acquired_at, released_at?
}
```

A partial unique constraint over active `(scope_kind, scope_id,
normalized_key_hash)` is the enforcement point. Invocation admission acquires
the required logical slot in the same transaction or remains queued; completion
or cancellation releases it and schedules the next waiter deterministically.
`waiting_commitment` releases worker capacity but retains a serial/keyed logical
slot, so a causally later activation cannot overtake it. Recovery derives held slots from
authoritative nonterminal invocations and repairs only under a fenced scheduler
sweep; a worker heartbeat never owns the slot.

Changing policy affects new invocations only. Parallel runs may not share a
mutable Python object or filesystem allocation. Byom Pledge/Episode concurrency
remains governed by Byom's EpisodeLease and generation fences, even when each
Episode is implemented by a Kovee invocation.

### 15.4 Retry and cancellation

Failures are classified:

- `transient-platform`: retry with bounded exponential backoff and jitter.
- `transient-provider`: retry only within provider policy and remaining budget.
- `invalid-input` or `deterministic-agent`: terminal unless a new input/revision
  is submitted.
- `resource-exhausted`: retry only after capacity or budget changes.
- `lease-lost`: old attempt ends; scheduler may start a new attempt.
- `ambiguous-effect`: no automatic retry; reconcile.

Maximum attempts, deadline, and retry classifications are committed before the
first attempt. A retry is a new attempt/fence on the same logical invocation and
assistant revision.

Cancellation is a durable command. The supervisor signals cooperative
cancellation, revokes future effect permits, waits a bounded grace period, then
terminates the worker allocation. A completion racing with cancellation is
resolved by the authoritative revision transition; exactly one terminal state
wins. Child work follows its recorded cancellation policy.

### 15.5 Checkpoints and streaming

Checkpoints are immutable, sequence-numbered, schema-validated application state.
Kovee does not serialize a Python frame, coroutine, open socket, or arbitrary
interpreter heap. A new attempt invokes `run(ctx)` again with the same immutable
input and exposes the latest compatible checkpoint to the assistant. The
assistant may branch from that state; without one it replays from the beginning.
All mediated mutations return retained original results under stable operation keys,
and time/random/external input needed across replay must come from recorded SDK
operations or the checkpoint. Native interpreter or harness resume is an
optimization, never the recovery contract.

`await ctx.request_work(...)` uses bounded inline waiting. If the child
commitment/realization is not terminal by the pool's short inline-wait limit, the
SDK durably marks the parent `waiting_commitment`, checkpoints any explicitly supplied state, ends the current
attempt as `yielded`, and releases its worker allocation. When the child becomes
terminal, the scheduler starts a new fenced attempt of the same invocation; code
replay reaches the same `operation_key`, receives the existing child result, and
continues. Waiting on a human or a pending act decision inside a Byom-bound
Episode instead yields a typed `episode_yield` result: the next wake is authored
by a Participant `wake_intent_submit` and admitted by the Byom kernel, never
chosen by Kovee.

A Byom `Continuation` remains Byom's portable logical state between Episodes and
may be included in a Kovee invocation manifest — it can even resume across
Manifestations. It is distinct from an intra-Episode Kovee checkpoint.

Streaming tokens/chunks are advisory presentation signals with bounded sequence,
size, and TTL. They may be lossy and are never the final collaboration record.
The assistant commits a final immutable contribution or delivery through a
fenced command.
After reconnect, a client displays committed state and may discard incomplete
advisory chunks. The final record is a contribution or commitment delivery, not
a privileged “assistant answer” message.

### 15.6 Budgets and fairness

The records in this section are Kovee runtime budgets. Byom separately owns the
governed budget accounts and their top-level reservations, which its kernel
creates at `resource_allocate`; section 17.4 defines the subordinate bridge
without copying ownership. A Kovee `BudgetAccount`
declares one unit—provider currency, tokens, wall time, CPU time, or another
registered dimension—and stores `ceiling`, `outstanding_reserved`, and
`committed`, and `uncertain`, with
`committed + outstanding_reserved + uncertain <= ceiling`.
An invocation reserves worst-case bounded usage atomically before queueing,
settles metered actual use, and releases the remainder. Child work transfers or
reserves within the parent's available ceiling.

```text
BudgetAccount {
  account_id, owner_scope_ref, unit,
  ceiling, outstanding_reserved, committed, uncertain,
  policy_revision_ref?, state, revision
}

BudgetReservationSet {
  reservation_set_id, owner_protocol: kovee|byom_subordinate,
  parent_reservation_set_ref?, external_authority_ref?,
  dimensions[]: {
    dimension_key, account_ref, parent_dimension_ref?, unit,
    ceiling, allocated, committed, uncertain, released, remaining,
    delegated_to_children,
    settlement_revision
  },
  subject_ref, subject_digest, expires_at, state, revision
}

UsageRecord {
  usage_id, revision, owner_protocol: kovee|byom_subordinate,
  realm_id, project_id?, space_id?,
  invocation_id?, attempt_id?, fence_epoch?,
  commitment_ref?, work_realization_ref?, effect_ref?,
  source_kind: worker|model|tool|connector|storage,
  profile_or_driver_ref?, observation_refs[], observation_digest,
  dimensions[]: {dimension_key, unit, quantity},
  reservation_set_ref, settlement_key,
  state: observed|settled|ambiguous,
  created_at, digest
}
```

Every dimension names its own account; a multi-unit set never relies on one
ambiguous `owner_account_ref`. For a local set, `account_ref` is a Kovee account.
For `byom_subordinate`, it is a source-qualified Byom reservation-dimension ref
and `external_authority_ref` identifies the exact Byom set/digest; Kovee changes
only its subordinate ledger and settles through Byom's operation. A subordinate
set may narrow or deny but never reshape or parallel-charge: its dimension and
unit equal the parent's, and its amount never exceeds the parent's worst case.

All local dimensions are reserved in one transaction or none are. Usage in one unit
cannot be silently converted to another; exchange rates, if allowed, are an
explicit policy revision and observation. Settlement is monotonic and
idempotent, and each dimension checks
`allocated = committed + uncertain + released + remaining + delegated_to_children`
as an
invariant. Only `remaining` is spendable. When an outcome is ambiguous, the
maximum quantity that may have been spent moves atomically from
`outstanding_reserved`/`remaining` to `uncertain`; reconciliation later moves it
once to `committed` or `released`. Cancellation, timeout, retry, or an account
epoch change cannot make uncertain quantity available again. Creating a child
locks the parent dimensions and atomically moves an amount from parent
`remaining` to parent `delegated_to_children` while creating the equal child
`allocated`; live child allocations must sum exactly to that delegated field. A
parent cannot spend or release delegated quantity. Terminal child settlement,
under one stable roll-up key, decrements parent `delegated_to_children`, moves
the child's actual/maximum possible spend once into parent
`committed`/`uncertain`, and returns only the known remainder to parent
`remaining`; the child row remains historical and cannot be rolled up twice. An
ambiguous child keeps its allocation delegated until that one roll-up places the
maximum possible use in parent/account `uncertain`, which remains unavailable
until explicit reconciliation.

`BudgetAccount.outstanding_reserved` counts only live root reservation quantity,
including its remaining and delegated partitions; nested child rows repartition
that quantity and never increment the account again. Account counters equal the
roll-up of root reservation rows, preventing either double counting or hidden
child spend.

`UsageRecord` is canonical metering/settlement evidence owned by Kovee runtime
accounting; brokers and workers submit bounded observations but cannot edit
settlement. `usage_show` queries authorized records, while `model_usage_show` is
the filtered `source_kind:model` view rather than a second model-usage object. A
delivery's `usage_digest` is the canonical digest of its sorted exact
UsageRecord refs/digests. Byom-subordinate records additionally bind and settle
against the parent Byom reservation as section 17.4 requires. A worker's
`usage_report` to byom is **evidence only**; settlement commits from a trusted
broker meter or an independently verified provider receipt, and disagreement or a
stale lease blocks further spend until a governance reconciliation seat releases
it.

Pools define maximum running work globally and per realm/project/assistant deployment,
provider rate limits, queue limits, and a deterministic fairness algorithm. The
reference scheduler uses weighted fair queuing with aging inside priority bands;
weights and maximum starvation time are configuration recorded in diagnostics.
Backpressure rejects or defers new low-priority work before accepted queues
exhaust database, broker, or provider capacity.

## 16. Effects, models, tools, and disclosure

### 16.1 Intent and effect lifecycle

Every Kovee-owned decision/standing-policy use binds a prepared `ActionIntent`;
domain transitions consume it as section 9.5 specifies, while external or
irreversible effects additionally use the permit/effect records below:

```text
ActionIntent {
  intent_id, owner_service, realm_id, project_id?,
  kind, execution_kind: domain_transition|external_effect,
  requested_by_actor, invocation_ref?,
  subject_ref, subject_revision, subject_digest,
  preconditions[], disclosure_manifest_ref?,
  broker_profile_binding?: {kind, ref, revision, digest,
                            driver_ref?, driver_version?},
  budget_reservation_set_ref?, idempotency_key,
  authorization_provider, policy_set_digest,
  authorization_dependency_set_ref, authority_digest,
  expires_at, state, revision
}

DecisionReceipt {
  decision_id, intent_id, intent_digest,
  principal_or_policy_ref, decision,
  policy_revision_digest?, authentication_observation_ref?,
  ceiling_reservation_ref?, ceiling_reservation_digest?,
  issued_at, expires_at, max_uses, decision_digest
}

DecisionUse {
  decision_id, use_key, use_ordinal, intent_id,
  authorized_action:
    DomainTransition {owner_service, transition_ref, transition_digest}
    | EffectExecution {effect_id},
  consumed_at,
  UNIQUE(decision_id, use_key),
  UNIQUE(decision_id, use_ordinal)
}

ExecutionPermit {
  permit_id, intent_id, subject_digest,
  authorization_owner, decision_refs[], decision_digests[],
  external_consumption_refs[], external_consumption_digests[],
  restriction_policy_digests[],
  authorization_dependency_set_ref, authority_digest,
  invocation_attempt_id?, fence_epoch?,
  driver, budget_reservation_set_ref?,
  ceiling_reservation_ref?, ceiling_reservation_digest?,
  expires_at,
  max_uses: 1, digest
}

Effect {
  effect_id, intent_id,
  execution_permit_ref?, execution_permit_digest?,
  external_idempotency_key,
  state, revision
}

ExternalAuthorizationConsumption {
  consumption_id, effect_id,
  owner_protocol: byom|akson,
  phase: pre_egress|atomic_with_egress,
  owner_endpoint_ref, owner_intent_ref, owner_decision_ref,
  execution_key, owner_receipt_ref, owner_receipt_digest,
  consumed_at, state,
  UNIQUE(owner_protocol, owner_endpoint_ref, execution_key)
}

EffectAttempt {
  effect_attempt_id, effect_id, driver, attempt_ordinal,
  execution_permit_ref, execution_permit_digest,
  invocation_attempt_id?, fence_epoch?,
  state, started_at
}

EffectReceipt {
  effect_attempt_id, outcome, external_ref?,
  observed_result_digest?, observation_ref?, usage?, completed_at
}
```

Lifecycle:

```text
prepared -> awaiting_authorization -> authorizing_external? -> authorized -> executing
   |                 |                         |              |           |
   +-> canceled      +-> denied/expired        +--------------+-----------+-> succeeded|failed|ambiguous
```

The service, not the assistant, canonicalizes the actual subject and calculates
its digest. A caller cannot ask for approval of an arbitrary digest and later
attach a different object. Any material subject/precondition/disclosure change
creates a new intent and requires new authorization.

Authorization may be a current narrow standing policy or an exact human
decision. A policy match still creates a derived decision bound to both digests.
An assistant cannot authorize its own intent, widen a policy, or provide its own
effective principal.

`ActionIntent` and `DecisionUse` are generic authorization records. Section 9.5
defines atomic `DomainTransition` consumption. For a Kovee-owned decision,
starting an external effect transactionally checks expiry,
the complete current authorization dependencies, current fences/preconditions,
remaining decision uses, and budget; inserts `DecisionUse`, the logical
`ExecutionPermit`, `Effect`, and first `EffectAttempt`; and reserves the use
before any driver call. A uniqueness conflict means the permit was already
consumed and returns the existing effect rather than executing again. A retry
creates a new `EffectAttempt` under the same logical effect and external
idempotency key. A failed or ambiguous attempt need not have a result digest; it
records the exact observations that justify that classification.

For a decision with `max_uses > 1`, the stable `use_key` identifies one logical
use and all of its retries. The transaction locks the decision, returns the
existing use/effect for a repeated key, otherwise allocates the next ordinal only
when it does not exceed `max_uses`, and binds a deterministic permit/effect
identity to that row. Both uniqueness constraints are required; an ordinal alone
is not an idempotency key. Any policy-ceiling reservation moves its use,
concurrency, and quantity counters in this same transaction.

A Byom-owned decision—a finalized `ActIntent`—or another external approval that
authorizes a later Kovee broker call cannot be consumed atomically in Kovee's SQL
transaction. It therefore uses this mandatory one-shot saga before egress:

1. Kovee commits the prepared `Effect`, stable external idempotency key, exact
   subject/disclosure/restriction digests, and a deterministic `execution_key`.
   No attempt or driver call exists yet.
2. Kovee calls the authority owner's narrow `execution_permit_consume` operation
   with that key and the exact owner intent/decision, subject, disclosure,
   budget, and required fence digests. The owner transactionally rechecks its
   live state and consumes at most one use.
3. The owner returns an immutable consumption receipt. Repeating the same
   `execution_key` returns the same receipt; a different key cannot consume the
   spent decision. If Kovee crashes after consumption but before storing the
   reply, its reconciler repeats step 2 and recovers that receipt.
4. Kovee stores `ExternalAuthorizationConsumption`, rechecks all Kovee-owned
   dependencies/restrictions, mints the local intersection `ExecutionPermit`,
   and only then creates an `EffectAttempt` for the broker.

The pre-existing `Effect` makes every consumed owner permit recoverable by key.
The owner receipt binds its protocol/endpoint, intent and decision digests,
execution key, subject/disclosure digests, broker/driver audience, expiry, and
`max_uses:1`; a receipt for another driver or service identity is unusable.
Byom exposes exactly this operation: `execution_permit_consume` on its runtime
surface, callable only by the trusted host effect service over a byomd-minted
workload channel whose subject **is** the exact `ActIntent`, so a permit token for
one act cannot consume another act's authority. It demands both fences, is keyed
one-shot, and returns the identical kernel-issued `ExecutionConsumptionReceipt` on
retry. `phase` is a Kovee field on Kovee's consumption row, never a member of
byom's receipt. Akson is different: its one-shot consent is consumed atomically by
the dispatch effect itself, so that call is an `EffectAttempt` and its idempotent
dispatch receipt is recorded as `phase:atomic_with_egress`, not fabricated as a
pre-egress ticket. Akson dispatch first requires the persisted Byom consumption
for the delegation act, and it is Kovee's narrow `byom_akson_dispatch_v1` driver
that makes the call — Byom's delegation engine authorizes and never calls out. Its
outcome is recorded in the Kovee-owned `ByomAksonDispatchOutcomeReceipt` head, a
closed union. A generic Kovee worker can invoke neither owner surface.
Cancellation or a newly stricter platform rule may safely leave a consumed
permit unused, but it cannot unconsume or replace it; `act_intent_cancel` cannot
claim effect rollback, and another external attempt requires the semantic owner to
prepare a new authority intent. Kovee never treats signature verification of an
old receipt as a substitute for the consume call.

Once the broker has atomically consumed the permit and marked the effect
`executing`, it owns recording the external outcome even if the requesting worker
loses its lease or is canceled. The receipt updates the logical effect under the
broker's service identity, not the stale agent fence. It is delivered only to the
current invocation/reconciler; the old attempt cannot append output or start a
follow-up. Cancellation revokes effects not yet started but cannot pretend an
already transmitted request did not occur.

Idempotent drivers may retry with the same external idempotency key. When a
driver cannot determine whether a non-idempotent effect occurred, it records
`ambiguous`, freezes automatic retry, and exposes reconciliation evidence and an
operator command. “No receipt observed” is not proof of failure.

An effect has exactly one semantic authorization owner:

- For a Byom-bound Episode and a Byom act class (`model_egress`, `share`,
  `outbound`, `apply`, `budget`, or another act in the closed subject taxonomy),
  Byom server-prepares the `ActIntent` subject with its field-complete
  `PreparationTrace`, the eligible human or resource owner fills only its own
  prepared seat with `act_intent_position` against that exact digest, and
  `act_intent_finalize` commits deterministically without authoring a seat. Kovee
  obtains and persists Byom's one-shot consumption receipt for that exact
  digest/execution key, then applies its platform restrictions; a local
  `DecisionUse` cannot consume Byom authority. Kovee MUST NOT ask the human to
  approve the same disclosure a second time.
- For a standalone Kovee space/runtime effect, Kovee's policy/decision service
  owns authorization. A relation, attention activation, Commitment, delivery,
  or review never supplies that authorization; it requires its own exact intent
  and decision/standing-policy use.
- For Akson dispatch, Byom authorizes the outbound act under its Mandate chain and
  Akson's own authority surface issues the required transport consent. These are
  different boundaries shown together as one compound risk card, not two services
  claiming the same decision.

Post-egress ownership is separate again. The source facts of an external outcome
enter Byom through `effect_outcome_admit`, called by a narrow trusted
effect-admission adapter that carries no judgmental field; that admission head
locks first. Only an ambiguous or late-judged outcome goes on to
`effect_reconcile` at a governance reconciliation seat, which produces an
`EffectGovernanceDisposition`. Both records stay in the authorization closure and
budget settlement remains conservative while the outcome is ambiguous.

Lower layers may always deny because a fence, classification, budget, provider,
or infrastructure policy is stricter. They can never broaden the owning
decision. The final `ExecutionPermit` is an intersection of the owner's exact
receipt and all current lower-layer restrictions; it records every contributing
digest. If any digest or precondition changes, execution stops and the semantic
owner prepares a new intent. This rule prevents both authority gaps and duplicate
approval fatigue.

### 16.2 Disclosure manifest

Every model, connector, cross-space/project, artifact-export, and peer disclosure has:

```text
DisclosureManifest {
  disclosure_id, sender_realm, sender_project?, sender_space?,
  recipient_kind, recipient_binding,
  purpose, data_classes[],
  context_assembly_ref?, context_assembly_digest?, commitment_ref?,
  exact_items[]: {ref, revision?, digest, size},
  transformations[]: {kind, source_digest, result_digest},
  provider_claims?: {region, retention, training_use},
  total_bytes, created_at, digest
}
```

Provider claims are recorded assertions, not independently proven facts. A
redaction or summarization is explicit transformation output; calling something
“redacted” without a result digest is insufficient. The authorization binds the
final bytes/references that leave, not merely a broad topic name.

### 16.3 Model broker

```text
ModelProviderBinding {
  model_provider_binding_id, realm_id, project_id?, revision,
  provider_kind, endpoint_ref, account_ref?, allowed_regions[],
  capability_set[], provider_claims {retention, training_use},
  compatible_adapter_versions[], transport_security_profile_ref,
  credential_secret_ref, credential_binding_digest,
  provider_terms_digest,
  status: active|disabled, created_at, digest
}

ModelProfile {
  model_profile_id, realm_id, project_id?, revision,
  provider_binding_ref, provider_binding_revision, provider_binding_digest,
  model_selector,
  allowed_classification_refs[], allowed_regions[],
  provider_claims {retention, training_use},
  request_limits {input_tokens, output_tokens, calls, cost_by_unit[]},
  pricing_schedule_ref?,
  adapter_version, policy_digest,
  status: active|disabled, created_at, digest
}

ToolProfile {
  tool_profile_id, realm_id, project_id?, revision,
  driver_ref, driver_version, input_schema_ref, output_schema_ref,
  effect_class: read_disclosure|reversible_write|irreversible_write,
  idempotency_mode, reconciliation_mode,
  allowed_destinations[], allowed_classification_refs[],
  credential_secret_ref?, limits, policy_digest,
  status: active|disabled, created_at, digest
}

ConnectorProfile {
  connector_profile_id, realm_id, project_id?, revision,
  provider_kind, driver_ref, driver_version,
  inbound_verification_profile_ref?,
  outbound_schema_ref, idempotency_mode, reconciliation_mode,
  recipient_scope[], allowed_classification_refs[],
  credential_secret_ref, limits, policy_digest,
  status: active|disabled, created_at, digest
}

EnforcementEvidence {
  evidence_id, revision: 1, invocation_id, attempt_id, worker_instance_id,
  requested_profile, actual_isolation_mechanism,
  supervisor_version, platform_attestation_ref?,
  package_digest, filesystem_scope_digest, network_policy_digest,
  broker_endpoint_set_digest, effective_policy_digest,
  observed_at, digest
}

ProviderContextManifest {
  provider_context_id, revision: 1,
  invocation_id, attempt_id, kovee_fence_epoch,
  byom_episode_binding_ref?, byom_fence_epoch?,
  context_assembly_ref?, context_assembly_digest?,
  byom_context_manifest_ref?, byom_context_manifest_digest?,
  collaboration_context_bundle_ref?, bundle_digest?,
  ordered_segments[]: {
    kind: collaboration_item|system_instruction|assistant_instruction|
          tool_schema|adapter_wrapper|transformation,
    ref, revision, digest, classification_ref, order
  },
  provider_binding: {ref, revision, digest},
  model_profile: {ref, revision, digest}, adapter_version,
  disclosure_manifest_ref,
  authorization_dependency_set_ref, authority_digest,
  final_provider_request_typed_byte_digest,
  created_at, digest
}
```

Model-provider bindings and profiles are revisioned records owned by the Kovee
effect/egress broker; update creates a new revision and disable blocks new
egress without rewriting old receipts. A ModelProfile selects an exact binding
revision/digest and cannot override its endpoint, account, region, transport, or
provider terms. The model credential lives only on that binding; all credential
fields are secret-manager refs and never enter workers, events, or portable
manifests. The broker validates current binding/profile status, schemas, destination,
classification, limits, idempotency, and reconciliation immediately before each
use. `EnforcementEvidence` is emitted by the trusted supervisor/runtime—not
assistant code—and `enforcement_evidence_show` returns the exact record used for
the run's security claim.

The egress broker owns and persists `ProviderContextManifest`. It is the complete
ordered chain from the source context — an ordinary Kovee `ContextAssembly`, and
for governed work the Byom `ContextManifest` that names it — through all
non-user-visible instructions, tool schemas, wrappers, and transformations to the
final provider-request byte digest. There is no separate briefing object: Byom's
`ContextManifest` is rechecked at materialization, and the context refs live on
`ByomEpisodeBinding`. An absent segment, changed order, or
digest mismatch blocks egress; the manifest is audit data, not a bearer grant.
`provider_context_manifest_show` returns that exact chain to an authorized
principal/operator, subject to current classification and source visibility; it
never returns provider credentials or hidden content the caller cannot read.

Agent code calls a logical model profile. The broker:

1. Verifies the current Kovee invocation lease/fence and, for a Byom-bound
   Episode, the current Byom generation/fence epoch. Both must be current: one
   fence is not "mostly current", it is fenced.
2. For ordinary Kovee work, reauthorizes every item in the bound
   `ContextAssembly`; for a Byom-bound Episode, accepts only the items named by
   Byom's exact `ContextManifest` and the Kovee assembly explicitly referenced by
   an admitted `CollaborationContextBundle`. It adds assistant/system
   instructions, tool schemas, and deterministic adapter transformations into a
   recorded `ProviderContextManifest` chain. The chain binds the source assembly
   and Byom context-manifest digests, every transformation/instruction revision,
   and the final `provider-request-bytes` `TypedByteDigest`; no convenience
   context is appended.
3. Calculates the disclosure manifest. A Byom-bound call uses Byom as
   `authorization_provider`, and the Byom act decision or StandingMandate receipt
   must bind the identical final digest and be consumed by the section 16.1 owner
   saga. Kovee policy may restrict but not substitute.
4. Atomically consumes the resulting execution permit, reserves tokens/cost, and
   enforces model/provider/region/retention policy immediately before egress.
5. Injects the credential outside the worker and makes the provider request.
6. Records provider, model revision where known, request/response digests, usage,
   latency, and retention claims under the transcript policy.
7. Settles the budget and returns bounded output through the supervisor.

In the `secure` profile, the worker cannot reach the provider around the broker.
In `developer`, Kovee may only surface and audit the intent if the ambient
process can bypass it; the UI and documentation must state that limitation.

LiteLLM may implement provider translation inside the broker. Kovee's model
profile, authorization, accounting, and disclosure records remain the contract.
Semantic ranking for attention candidates uses this same broker and exact
context/disclosure/budget path; a scheduler never calls a hidden model inline.

### 16.4 Tool and connector broker

Tools and connectors are registered effect drivers with closed input/output
schemas, size limits, declared idempotency behavior, credential owner, data
classification, timeout, and reconciliation support. The assistant requests an
effect; it does not receive the underlying OAuth token, cloud key, database
password, or connector webhook secret.

Read-like tools can still disclose data or cause cost and therefore have policy.
Write-like tools always prepare an intent before execution. Shell access is not
a generic secure tool; workspace commands require a bounded Byom
`WorkspaceAllocation` or a declared confined execution profile.

For a Byom-bound action the same authorization-owner and dual-fence rules apply to
tools and connectors. Akson stage, consent, and dispatch are not registered as
generic Kovee tools; only the narrow `byom_akson_dispatch_v1` driver described in
section 18.2 may invoke them, and only against a current finalized Byom act plus
its consumed receipt.

## 17. Byom integration specification

Byom is the governance owner of this stack from day one. Kovee never had a
predecessor governance layer wired in, and it is never the genesis governance
actor. This section specifies Kovee's side of the seam; the normative authority
map is the family contract's operation × authority matrix, which binds every
Kovee requirement to an exact BPP operation, a named kernel transition, a
Kovee-owned contract record, or an already-identical constraint in both designs.

### 17.1 Realm-to-Society topology

A Kovee realm maps, when `governed_work` is enabled, through at most one active
`KoveeRealmByomBinding` plus its `KoveeSocietyMapping` to one Byom Society at one
`byomd` endpoint, and — when federation is enabled — one Akson endpoint. In v0.1
this is an isolation rule, not merely routing metadata:

- Personal mode with governed work binds its one realm to one local `byomd` and
  optional `aksond`; open-space mode has no governance binding.
- Team mode uses a dedicated `byomd` process, store, and security identity per
  realm. A shared multi-tenant Byom service is permitted only after a
  realm-scoped profile exists and is proven; there is no such profile today.
- Team federation likewise uses a dedicated Akson sovereign endpoint per realm
  unless Akson itself defines and proves a multi-tenant authority profile. Kovee
  cannot simulate this separation with NATS or UI filtering.
- The principal mapping is explicit and revisioned. A Kovee project role never
  manufactures Byom Participant membership, and a Kovee service identity never
  fills a human-authority seat. Human seats exist only where BPP's registry says
  they do: Society bootstrap and hold/release, charter and control-domain and
  procedure positions, governance finalization, and the human-authority arm of
  mandate and act-intent positions.
- A project and all its Endeavor links use the realm's binding. Moving work to
  another realm is a disclosed handoff/delegation, not a routing-field edit.

Byom exposes six surfaces, each its own socket with its own admissible actors:
**governance**, **candidate**, **participant**, **projection**, **runtime**, and
**admin**. Kovee speaks the first five. The admin surface belongs to the
infrastructure administrator under a separate identity and authors no Society
state, so Kovee never calls it. Every surface answers `hello`, `protocol_info`,
and `feature_info` to a bounded pre-auth client; unlisted `(operation, surface)`
pairings are forbidden by absence rather than by a filter.

The team-mode governance binding authenticates principals in one of two declared
profiles: `byomd` validates the realm's OIDC assertion itself, or it validates a
short-lived delegated-principal credential minted by the realm's configured Kovee
identity issuer and presented as transport-preamble channel material — never as a
member of a closed request schema:

```text
DelegatedPrincipalCredential {
  credential_id, issuer_ref, nonce,
  sender_constraint,
  source_principal_ref, source_actor_binding_digest,
  bound_participant_ref, participant_binding_epoch,
  society_ref, society_recovery_epoch, endpoint_incarnation,
  realm_byom_binding_ref, realm_byom_binding_revision,
  realm_byom_binding_epoch, realm_byom_binding_digest,
  audience, surface, allowed_operations[],
  delegated_principal_subject_digest,
  authentication_observation_ref, authentication_observation_digest,
  assurance_level, issued_at, expires_at, digest
}
```

The credential is audience-, surface-, sender-, realm-, binding-, and
operation-bound, short-lived, and minted only for a currently authenticated user
request acting for its own admitted Participant; it is not a generic Kovee
service credential. Byom atomically consumes `(issuer_ref, nonce)` with the exact
sender constraint and command digest. A retry of that same tuple returns the
stored command result; reuse for a different channel, command, or actor is
rejected. Byom derives the effective actor from the validated channel — the
request body never selects it. Projection consumers use a different realm-scoped,
read-only identity that can decide no act and mutate no Episode, and the recovery
workload's projection token is narrower still: read-only, and unable to submit to
a superseded incarnation.

The gateway validates the binding before every BPP command, projection read, and
provider launch, presenting the four-member pin `byomd` rechecks on every use —
binding ref, revision, epoch, and digest. Endpoint re-incarnation, Society
recovery-epoch change, or mapping rotation increments the binding epoch, closes
derived channels, invalidates cached authorization and permits, and requires
reconciliation of in-flight Episodes. This prevents a broad operator surface or a
same-UID socket from becoming a cross-realm escape hatch.

Kovee may supply `byomd` with an inert host-binding document — the wire
projections of its two binding records, its delegated-principal issuer refs, the
recovery pin, and the endpoint root id. That document is *configuration*: `byomd`
re-validates every field on every use, and no Kovee operation can author Society
state through it.

### 17.2 Ownership mapping

| Kovee concept | Byom relationship |
|---|---|
| Realm/project | Administrative identity, ownership, policy, and deployment container; does not replace Participant admission or workspace allocation |
| Space | Kovee collaboration/visibility unit. An exact branch frontier may be linked to an Endeavor, but a Space is never an Endeavor |
| Contribution/relation | Attributed collaborative assertion or work product. It enters a Byom ContextManifest, act subject, or deliverable only after exact Byom admission; a relation never proves truth or authority |
| Branch/merge | Preserves competing local reasoning. Merge acceptance is local inclusion only; changing governed work still requires a Pledge revision or an act decision |
| ContextAssembly | Ordinary Kovee selection manifest. Byom may admit an exact assembly through a `CollaborationContextBundle` and name it in a `ContextManifest` rechecked at materialization; Kovee cannot append later convenience context |
| AttentionContract | May notify/invoke Kovee-local assistants. For governed state it may only notify the adapter; a Participant authors the `WakeIntent` and the Byom kernel admits it |
| Need/Offer/Formation | Non-authoritative local coordination proposal. Governed decomposition becomes work only through `call_open` and `pledge_propose/position/finalize` |
| CollaborationCommitment/WorkRealization | Bounded local contribution/draft-artifact work only, inside the closed `allowed_local_commitments` set; never a duplicate Pledge, Activity, workspace, or deliverable acceptance |
| Assistant definition/revision | A code-defined provider implementation or a Byom `Manifestation` of a Participant; not the Participant itself |
| Invocation | One runtime execution; a Byom Episode attempt may be backed by one invocation |
| Attempt/fence | Protects Kovee runtime writes; a Byom-bound Episode additionally carries its Byom generation and fence epoch, and every runtime mutation presents **both** |
| Kovee effect intent | Protects Kovee-owned effects; Byom acts protect governed actions |
| Presence | UI liveness only; Byom Activity/Episode state remains authoritative |
| Application event | Advisory unless translated by an authorized BPP command |
| Artifact | Byte storage for Byom refs; Byom records decide governed visibility and acceptance |

There is no plan object and no aspect record. Work structure is a lens over
Calls and Pledges: what was an aspect is a Pledge, what was an aspect generation
is a pledge revision plus activity/episode generation fences, and what was a plan
gate is a server-prepared act subject decided by an eligible seat.

Kovee and Byom fence proofs MUST be kept distinct but correlated. A Byom-backed
invocation input includes:

```text
ByomEpisodeBinding {
  byom_endpoint_ref, endpoint_incarnation,
  society_ref, recovery_epoch,
  participant_ref, participant_binding_epoch,
  manifestation_ref, activity_stream_ref,
  episode_ref, generation,
  byom_attempt_ref, byom_fence_epoch,
  kovee_invocation_ref, kovee_invocation_fence,
  mandate_use_refs[], context_source_digest,
  byom_budget_reservation_ref, byom_budget_reservation_digest,
  external_budget_bridge_ref,
  kovee_subordinate_reservation_ref, kovee_subordinate_reservation_digest,
  dependency_digest, digest,
  stable_binding_key,
  allowed_local_commitments[],
  context_manifest_ref, context_manifest_digest,
  kovee_context_assembly_ref?, kovee_context_assembly_digest?,
  provider_context_manifest_ref?, provider_context_manifest_digest?,
  state: bound|fenced|released
}
```

Kovee persists each `ByomEpisodeBinding` as an immutable, source-qualified
binding record referenced by the InvocationInputManifest and any permitted child
WorkRealization. Its create key is
`UNIQUE(episode_ref, byom_attempt_ref, kovee_invocation_ref)`, and an exact retry
returns the identical row. Each optional context pair is all-or-none: a ref
without its digest is a malformed row, not a half-known context. It does not copy
or advance Byom Activity/Episode state; every use loads the named Byom records and
revalidates their current fence and dependencies. Either fence advancing moves the
binding to `fenced`, which is terminal for every further mutation — a successor
attempt gets a new binding row. `byom_episode_binding_show` exposes the binding
and source refs/digests under the intersection of current Kovee visibility and
Byom source authorization.

The Kovee runtime must hold a current Kovee attempt to contact the supervisor, and
every Byom mutation must also present the current Byom fence the operation's
registry row demands. Presenting one current fence and one stale one is not
"mostly current", it is fenced. Losing either fence stops the Episode. Kovee
success submits the provider result; it does not accept the Byom deliverable.

### 17.3 Space-frontier-to-Endeavor formation

Promotion is an explicit cross-context saga over an immutable input. The Society
and its Participants already exist through Byom onboarding, so formation enrolls
nobody:

```text
CollaborationContextBundle {
  bundle_id, realm_id, project_id, space_id, branch_id,
  frontier_ref, frontier_digest,
  context_assembly_ref, context_assembly_digest,
  selected_by_principal, selection_reason,
  source_authorization_dependency_set_ref, source_authority_digest,
  created_at, digest
}

EndeavorFormationIntent {
  formation_id, realm_id, project_id, space_id, branch_id,
  frontier_ref, frontier_digest,
  context_bundle_ref, context_bundle_digest,
  byom_endpoint_ref, society_ref, society_recovery_epoch,
  bound_participant_ref, participant_binding_epoch,
  canonical_command_digest, idempotency_domain_digest,
  computed_slot_snapshot_digest,
  expected_active_link_ref?, supersedes_link_ref?,
  formation_slot_ref?, formation_slot_generation?,
  requested_by_principal, authentication_observation_ref,
  authorization_dependency_set_ref, authority_digest,
  byom_result_ref?, byom_result_digest?, external_link_ref?,
  state: prepared|submitting|remote_unknown|awaiting_principal
        |byom_committed|linking|linked|ambiguous|canceled,
  revision, created_at, terminal_at?
}

EndeavorFormationSlot {
  slot_id, local_branch_id, holder_formation_id,
  expected_active_link_ref?, generation,
  state: held|submitting|remote_unknown|awaiting_principal
        |byom_committed|linking|ambiguous|released,
  revision, acquired_at, released_at?,
  UNIQUE(local_branch_id) WHERE state != released
}

EndeavorFormationAttempt {
  attempt_id, formation_id, attempt_ordinal,
  attempt_nonce, attempt_recovery_binding_digest,
  attempt_authentication_proof,
  sent_at?, reply_digest?, reply_signature?,
  state: prepared|sent|reply_received|transport_unknown
        |reconciled|canceled
}
```

The intent and the slot are one machine: every row compare-and-swaps both under
the slot generation, and the slot state is the intent state's pair, never an
independent decision. The attempt machine is separate and append-only — resolving
an intent never rewrites an earlier attempt's send or authentication evidence.

The promotion screen shows and requires confirmation of the exact goal
contribution, branch/frontier, immutable ContextAssembly with its included and
omitted items, classifications, the Society's rendered standing decision rules
and the sole computed human seat, budget, and either an exact workspace
provider/source/base binding or `workspace_mode:none` for non-code work, plus any
active Endeavor link that would be superseded. Every displayed truth is
server-recomputed: the caller supplies refs and the service derives the digests,
so a confirmation screen cannot show one subject while the command carries
another. Kovee reauthorizes every assembly item for the submitting principal and
the Endeavor destination; stale, erased, or inaccessible inputs fail explicitly
rather than being replaced by newer revisions. The submitter is not silently made
sole approver — the Society's own decision rules determine that, and Kovee only
renders them.

Byom's idempotent `kovee_endeavor_form` is a single governance-surface command
that atomically commits the source principal's Position, the resulting Decision,
and the Endeavor, filling exactly the one computed human seat and admitting the
context-bundle reference. It requires an active Society, the pinned bindings, and
the ContextBundle, and it authenticates a source-qualified human over the exact
Kovee delegated-principal channel acting for its own admitted Participant. When
`formation_requires_participation` demands more than one seat, formation falls
back to `endeavor_propose` / `endeavor_position` / `endeavor_finalize`. Kovee then
commits its `ExternalLink` as section 11.10 specifies. New contributions,
relations, or branch changes after the frontier never enter the Endeavor or a
model context merely because the space remains linked; a principal or Participant
must prepare and admit a new exact assembly and bundle. One branch has at most one
active authoritative Endeavor link, while historical links remain auditable.

`endeavor_promotion_prepare` creates the bundle and
`EndeavorFormationIntent(state:prepared)` with the exact canonical command digest
but does not contact Byom. `endeavor_promotion_start` reauthorizes the principal
and intent and, in one transaction, acquires the branch's durable
`EndeavorFormationSlot` and changes `prepared -> submitting` before any external
submission. `endeavor_promotion_cancel` succeeds only from `prepared` when no slot
has ever been acquired. Another non-released slot blocks start, link replacement,
and link revocation for that branch. The command itself is sent under a
per-attempt authentication proof over the canonical command digest, the
IdempotencyDomain digest, a fresh attempt nonce, the attempt recovery binding, and
the server-derived actor binding — so a replaced command, nonce, recovery binding,
or actor binding cannot ride an old proof. Thus the one-line CLI is an explicit
public workflow, not a hidden dual-protocol mutation or a distributed transaction.

After the durable `submitting` transition, the service reconciler may use only the
read-only `external_command_result_query` on the projection surface, keyed by the
stored Participant, canonical command digest, and IdempotencyDomain. It returns
one of five facts, and each drives exactly one transition:

| Fact | Meaning | Effect |
|---|---|---|
| `committed` | a signed `KoveeEndeavorFormResult` envelope | verified against its own bytes, then persisted and linked |
| `absent` | a complete query of the live domain found neither result nor tombstone | `awaiting_principal`; it proves nothing about later arrival, so the slot is retained |
| `historically_fenced_absent` | an externally witnessed `RestoreLineage` proof found no row and every predecessor domain is permanently fenced | releases the slot |
| `non_reexecuting_tombstone` | Byom's durable terminal claim over the exact IdempotencyDomain | `canceled`; releases the slot |
| `unknown` | in flight, incomplete retention, unavailable, or unverifiable | `ambiguous`; nothing is released |

The `committed` fact is verified, never trusted: Kovee re-derives the envelope's
digest from its exact bytes and refuses a mismatch. Only a freshly authenticated
mapped principal may resubmit, minting a new short-lived delegated credential and
sending the unchanged stored command under the same IdempotencyDomain; the service
cannot impersonate that principal. `external_command_terminalize` is the same
source human's terminal claim over a historical domain — it locks the idempotency
and journal heads and never executes; answering `not_terminalizable` with one
closed blocking state is a Byom no-op. Exactly four things release a slot: a
pre-send cancel, a verified tombstone, a verified `historically_fenced_absent`,
and a committed `ExternalLink`. Timeout, absence, authentication expiry, binding
rotation, an unverified historical lookup, and `ambiguous` never do. The slot moves
to `byom_committed` before link reconciliation and is released only after that
exact result is linked, so a crash or lost reply forces recovery by the same
formation id and two prepared intents cannot form two Endeavors and orphan one.

For a Byom-bound Episode, every model-visible Kovee item is referenced by an
admitted `CollaborationContextBundle` and named in Byom's `ContextManifest`, which
is rechecked at materialization. A separate `ProviderContextManifest` records the
Kovee assistant instructions, system prompt, tool schemas, adapter wrappers, and
their digests. The Episode's act subjects bind these manifests, and the broker
additionally digests the final provider request after deterministic adapter
transformations. Kovee must not append linked space content or hidden instructions
outside this recorded chain.

### 17.4 Episode lifecycle mapping

Byom owns Activity and Episode cadence; Kovee owns process placement and retries
inside one requested Episode attempt. The adapter first registers a versioned
provider manifest containing provider/worker protocol ranges, supported KCP and
BPP versions, assistant revisions, input/output schemas,
checkpoint/cancellation/yield capabilities, enforced security profiles, resource
limits, and diagnostics and usage schemas. That manifest is Kovee-owned; Byom sees
the `ManifestationRevision` and Kovee's enforcement evidence, and admits a
Manifestation only through `manifestation_admit`.

Activation has four stages, four records, and four owners — and Kovee owns exactly
one of them:

```text
1  WakeIntent            the Participant's (or an adopted ActivationPolicy's,
                         recorded as provenance ordinal)  -> wake_intent_submit
2  ActivationAdmission   the Byom kernel (activation_admit)   \  reached through
3  ResourceAllocation    the Byom kernel (resource_allocate)  /  episode_request
4  PlacementBinding      KOVEE, then Byom's narrow runtime adapter records the
                         matching admission                   -> placement_admit
   then episode_claim -> episode_start -> checkpoint_commit ->
        usage_report -> episode_yield | episode_complete | episode_fail
```

`episode_request` comes **before** placement, because `placement_admit` needs the
`ResourceAllocation` that `episode_request` creates and publishes. Nothing skips a
stage: `byomd` refuses an Episode claim whose placement was not admitted. Kovee
attention only notifies; it never wakes governed work.

The exact execution mapping is:

- One committed Byom Episode attempt maps to exactly one logical Kovee
  `Invocation`, created with idempotency key
  `(byom_endpoint_ref, episode_ref, generation, provider_contract_version)`.
- Multiple Kovee attempts may retry that invocation only while the Byom Episode
  lease, deadline, and Kovee invocation remain current. They do not create a new
  Episode, extend its budget/deadline, or select a different assistant revision.
  `episode_claim` compare-and-swaps the lease head and advances the Byom fence, so
  a stale worker is fenced rather than racing.
- A Kovee checkpoint resumes a crashed attempt within one Episode. A Byom
  `Continuation`, written with `continuation_write` under a `ContinuationHead` CAS,
  is the portable state passed between Episodes and can resume across
  Manifestations. Native Python/harness transcript state is optional in both cases.
- Kovee's `waiting_resource` during an active provider attempt is an execution
  detail. A logical wait on a human, an act decision, or a peer is returned as a
  typed `episode_yield`. The next wake is authored by a Participant `WakeIntent`
  and admitted by the kernel; Kovee neither schedules nor infers it.
- A Kovee `AttentionContract` may notify the byom adapter that admitted source
  state changed, but no Kovee candidate or activation wakes a governed model. The
  adapter records or forwards the exact source event.
- Byom cancellation through `activity_hold`/`activity_close`, or an
  `episode_fail`, cancels the Kovee invocation and revokes its effect permits; a
  fence advance revokes outstanding permits by itself. Where the outcome cannot be
  known, both records expose interruption or ambiguity rather than inventing
  success or claiming a rollback.
- Kovee commits the immutable provider result first, then submits it with
  `delivery_submit` against the exact Episode fence. If Byom has fenced the
  Episode, the result is retained as an orphan diagnostic and cannot become a
  deliverable. Acceptance is a separate `review_record`.

The effective deadline is the earlier of the two systems' recorded deadlines, and
the effective security/resource profile is their restrictive intersection. Only
Byom can admit the next Episode; only Kovee can assign a worker attempt within the
current invocation.

Every runtime-surface call authenticates through a `byomd`-minted, subject-scoped
workload channel that Kovee cannot derive: the worker channel is bound to one
exact episode and generation; the meter channel is the only one whose
`usage_report` may settle; the placement channel is bound to one exact
`ResourceAllocation` and carries only `placement_admit`; and the permit channel's
subject is one exact `ActIntent`. A token file disappears when its subject leaves
its live states, so a missing token is a state answer, not a configuration one.
Presenting the wrong channel class is refused at both ends.

For budgets, Byom's account is authoritative. The kernel reserves a maximum in
every applicable dimension at `resource_allocate` and the reservation refs appear
on `ByomEpisodeBinding`. Kovee creates one subordinate
`BudgetReservationSet {owner_protocol:byom_subordinate}` idempotently against that
reservation through the `byom_subordinate` bridge saga, maps every dimension to
its exact Byom parent-dimension ref, never allocates above the parent worst case,
and may apply a lower realm/platform ceiling. A subordinate set may narrow or
deny; it may never reshape a dimension or charge in parallel. Kovee-only budget
accounts are not debited for the same governed usage. Model, tool, child-work,
CPU, and wall-time usage settle against the subordinate set. A worker's
`usage_report` is **evidence only**: settlement commits from a trusted broker
meter or an independently verified provider receipt. A lost reply repeats the same
settlement, not the charge. Disagreement or a stale lease blocks further spend and
leaves the bridge `uncertain` with the Byom parent still reserved; only a
governance reconciliation seat — never a timeout — releases it. Kovee can lower
priority or capacity but cannot raise Byom's budget, deadline, or priority.

`ctx.request_work` inside a Byom-bound invocation is denied unless
`allowed_local_commitments` explicitly names the commitment class, and the terms
stay within a same-realm target selector, data classes, count/depth, deadline,
subordinate budget, and exact outcome schema. An allowed commitment/realization is
an intra-Episode helper result only: its deadline and cancellation are bounded by
the current Episode, it creates no Pledge, cannot own a deliverable or workspace,
and provides no decomposition or acceptance authority. It binds the exact
`ByomEpisodeBinding` and both current fences; loss of either fence cancels and
fences the child. Governed input, purpose, or budget keeps Byom as the
authorization owner for every model/tool/disclosure effect — the local Kovee terms
can restrict that authority but never convert it into a standalone Kovee decision.
Its Need, Offer, policy-use, Commitment, delivery, and usage refs enter the Episode
record and any later provider-context manifest. Work that changes governed
decomposition, needs an independent Activity or workspace, survives the Episode,
reaches a peer, or produces a governed deliverable must use `call_open`,
`pledge_propose`, or `act_intent_prepare/position/finalize` — not Kovee local
commitments.

### 17.5 Protocol prerequisites, discharged

An earlier generation of this design carried a list of protocol gaps to be
resolved before Kovee could claim compatible governed work. Every one of them is
now discharged by a named BPP operation, kernel transition, or Kovee-owned
contract, and the family contract's matrix — not this list — is the normative
record:

| Prerequisite | Discharge |
|---|---|
| One-shot socket framing that cannot require `hello` first on the same connection | Per-surface sockets; the version travels in every request, or persistent framing follows an explicit `hello` |
| Multi-human principals with no silent impersonation | Six surfaces; human seats bind source-qualified humans with fresh challenges, and the admin surface never crosses into Society authorship |
| Explicit lease proofs for lease-protected mutations | `EpisodeLeaseHead` CAS plus fence epochs; every runtime mutation presents both the Byom and the host fence |
| Decisions bound to a server-prepared subject, never a caller-supplied unattached digest | Server-prepared subjects with a field-complete `PreparationTrace`; a position fills only the authenticated actor's own seat |
| An idempotent one-shot `execution_permit_consume` | Exactly that operation, on the runtime surface, over a permit channel whose subject is the act |
| A typed operation set covering the whole governed lifecycle | The endeavor, call/pledge, activity, runtime, knowledge, and recovery operation families |
| One atomic formation command | `kovee_endeavor_form` against a pre-existing Society; Society genesis is native and never Kovee's |
| Read-only command-result reconciliation that cannot submit or grant | `external_command_result_query`, five facts, read-only |
| Durable idempotency whose irreversible keys outlive the effect | `IdempotencyDomain` plus `idempotency_result`, with declared retention |
| Cursor/snapshot epochs and expired-cursor recovery | `cursor_recover` and `recovery_checkpoint_show`, with endpoint incarnation and recovery epoch |
| Normative MCP and harness schemas | The candidate and participant MCP profiles, plus the `attached_harness` `ManifestationRevision` |

Kovee may contribute further changes through Byom's own spec process. It MUST NOT
invent incompatible private meanings while advertising Byom compatibility, and it
MUST NOT advertise a capability whose BPP operations do not yet exist — ranked
routing over published profile claims is the current example.

### 17.6 Act inbox

Kovee renders a pending Byom act decision with:

- The act class and its Endeavor/Pledge context.
- The exact prepared subject digest and a human-readable diff from the prior
  revision.
- The eligible seat this principal may fill, and the seats it may not.
- Recipient and binding for disclosures/delegations.
- Disclosure manifest: items, sizes, classes, transformations, destination.
- The governing Mandate chain or StandingMandateRevision, and budget and
  concurrency effects.
- Preconditions, expiry, and separation-of-duties requirements.
- Causal events and evidence refs.

`act_intent_position` is sent to Byom and includes the subject digest the
principal reviewed, filling only that principal's own prepared seat under a fresh
challenge. A stale revision or changed digest is re-rendered and cannot reuse the
old confirmation. Finalization is a separate deterministic
`act_intent_finalize` that authors no seat.

Immediately before rendering a decision control and again before submitting it,
the gateway reloads the current intent and authorization directly from Byom; a
cached projection can never be the decision subject.

### 17.7 Read projections and timeline

Kovee consumes Byom `events_read`/`events_wait` by durable, opaque cursor. A
projection row stores the Byom endpoint id and incarnation, object ref/revision,
event id/cursor, payload digest, source visibility scope/revision, and projection
time. A full rebuild is possible only when Byom supplies an authorized
`snapshot_get` plus boundary cursor; otherwise the view is rebuilt only within the
declared coverage of Kovee's governed integration journal and is marked incomplete
outside it. An expired cursor recovers through `cursor_recover`, and
`recovery_checkpoint_show` reports the incarnation and recovery epoch a projection
is valid against.

Every projected read, replay, live event, search result, act view, and artifact
fetch must pass the intersection of current Kovee project/space/object access and
Byom's own visibility closure on that read. Project membership alone grants no
governed read access; Participant standing alone grants no Kovee space access.
Visibility and membership events invalidate affected projection grants
immediately, and inability to recheck the source fails closed rather than serving
a stale payload.

The user-facing timeline merges:

- Kovee contribution/relation/attention/commitment/runtime events.
- Byom society/endeavor/pledge/act/episode journal events.
- Akson delegation/delivery/verification events.

It preserves each source sequence and causation links. Wall-clock sorting is a
view and MUST NOT be represented as a cross-system consensus order. This merged
timeline is a later product capability, not a first-milestone deliverable.

### 17.8 Participant evidence and the assistant registry

The Kovee assistant registry describes deployable code and current placement. Byom
supplies evidence about participants, not a ranked directory: `participant_show`
and `engram_search` are what exist today, and routing is evidence rather than
authority. A Kovee manifest's `skills` are self-asserted routing metadata; copying
them into Byom never upgrades them to observed evidence. Typed profile-claim
publish, read, and search operations are a tracked Byom design obligation; until
they exist, Kovee advertises no ranked-routing claim beyond what those two reads
support, and ranked routing UI is a later milestone. A change to an Akson binding
suspends the associated Byom trust through the federation surface's binding epochs
and capability matrix.

### 17.9 Engrams

Byom remains authoritative for portable engram revisions, local admission,
attestations, disclosure, policy conflicts, and context selection. Admission is
quarantine-first. Kovee may:

- Store engram bytes as artifacts while preserving Byom's canonical digest.
- Render and edit proposed engrams through `engram_propose`.
- Show quarantine, admission, attestation, hold, and retirement state with
  provenance.
- Index admitted, authorized views for search and rebuild them only from a Byom
  snapshot/cursor or the governed integration journal within its known coverage.

Kovee MUST NOT treat a chat memory, embedding, or peer-supplied Markdown as an
admitted engram or as binding policy.

### 17.10 Workspace provider

Byom owns workspace allocation and apply semantics: the logical
`WorkspaceAllocation` is authored by the kernel at `resource_allocate`, admitted
through `placement_admit`, and bounded by the Episode lifecycle. There is
deliberately no workspace-named BPP operation. Kovee supplies a versioned
`WorkspaceProvider` infrastructure driver and owns the physical materialization
ledger:

```text
WorkspaceProviderManifest {
  provider_id, revision, version, supported_source_kinds,
  supported_regions, isolation_profiles,
  max_bytes, snapshot_digest_algorithms,
  change_set_formats, cleanup_guarantees,
  status: active|disabled, digest
}

WorkspaceAllocationBinding {
  binding_id, revision,
  byom_workspace_allocation_ref,
  byom_workspace_allocation_revision, byom_workspace_allocation_digest,
  source_ref, base_ref, base_tree_digest,
  kovee_invocation_id, attempt_id, fence_epoch,
  provider_ref, provider_revision, provider_digest,
  materialization_ref, region, expires_at,
  state: allocated|sealed|cleaned|failed,
  change_set_ref?, change_set_digest?, created_at, terminal_at?
}
```

These two records are owned and persisted by the Kovee byom integration/runtime
adapter with typed KCP transitions. The manifest describes the local driver; the
binding is Kovee's fenced materialization and cleanup ledger. Neither record
allocates a Byom workspace, authorizes apply, or changes Byom state.

The admitted allocation authorizes an exact workspace. The driver snapshots or
verifies the immutable base, creates an isolated per-attempt materialization on
the selected worker, exposes only declared paths/capabilities, and records the
binding above. A retry gets a fresh materialization from the same base plus a
committed compatible checkpoint/change-set; concurrent attempts never share a
mutable directory.

On yield or completion the driver extracts a bounded change-set, binds it to the
base tree digest, stores it as an artifact, and returns the digest to Byom for
review. Cleanup is idempotent and retention-policy driven; failure leaves a
sealed, expiring allocation rather than granting another worker access. Applying
the change-set is never a workspace-provider convenience: it is an act. Byom
server-prepares an `apply` ActIntent against the current target/base/change-set
digests, an eligible seat positions on it, `act_intent_finalize` commits, the host
effect service consumes the one-shot `execution_permit_consume`, and the effect
driver refuses a moved target or a stale fence.

## 18. Akson federation

### 18.1 Boundary

Kovee's NATS fabric ends at its installation. Cross-installation work uses Byom's
Mandate chain and act decision plus Akson's paired, signed, consent-gated
transport. Machine location inside a Kovee worker fleet is topology, not peer
identity; an Akson peer is sovereign and can independently refuse, verify, hold,
approve bounded execution, and disclose. Higher-layer admission remains
Byom/Kovee policy.

The outbound flow is:

```text
a Kovee/Byom Episode proposes exact remote work
  -> Byom prepares the disclosure and derives the Mandate
  -> Byom server-prepares the outbound ActIntent; an eligible seat positions;
     act_intent_finalize commits
  -> the host effect service consumes the one-shot execution_permit_consume
  -> KOVEE's byom_akson_dispatch_v1 driver stages an inert Akson contract
     (Byom's delegation engine authorizes and never calls out)
  -> local Akson consent for the exact staged digest
  -> Akson dispatch, atomic with consent consumption
  -> remote Akson verifies and holds inert
  -> remote authority approves bounded execution
  -> remote Byom/Kovee admits before any higher-layer model wake, if used
  -> signed outcome/evidence returns
  -> local Akson verifies
  -> Byom admits it with effect_outcome_admit against the original ActIntent
  -> result enters review
```

The dispatch outcome is recorded in Kovee's `ByomAksonDispatchOutcomeReceipt`
head, a closed union, alongside the Byom `ExecutionConsumptionReceipt` and the
Kovee `ExternalAuthorizationConsumption{phase: atomic_with_egress}` row.

Kovee consumes projections at each step and can notify people, but it never
short-circuits either endpoint's authority.

### 18.2 Required Akson surface

A least-privilege Akson coordination surface with one-shot consent receipts
remains a dependency. Until Akson exposes verified peer/card reads, inert
idempotent staging, receipt-consuming dispatch, and durable coordination events,
Kovee MUST NOT connect to Akson's broad admin socket or claim automated
federation.

`kovee-akson` is not an independent federation writer. It exposes a read-only
projection consumer plus the narrow `byom_akson_dispatch_v1` infrastructure
driver, callable only with a current finalized Byom ActIntent, its consumed
`ExecutionConsumptionReceipt`, and the Akson-owned consent reference. Byom's
delegation engine *authorizes*; this driver *calls*, and Kovee is its sole caller.
It has no public KCP stage/dispatch operation and cannot create a contract,
consume consent, or dispatch from a generic Kovee effect.

Inbound peer work executing a full Byom/Kovee assistant remains blocked until
Akson's confined agent-worker policy is normative. The default remote-performer
path is the Akson-confined worker. A weaker, honestly labelled **manual developer
profile** also exists: the remote performer forms its own finalized local Pledge,
executes through its own attached harness, discloses through its own outbound
act and permit chain, and returns the result as an Akson manual fulfillment — a
signed manifest over exact output bytes, with **no execution evidence claimed**
and evidence slots left empty unless genuinely supplied. No inbound object authors
the performer-side Standing, Pledge, WakeIntent, or execution authority, and the
capability matrix records which profile a given peer exchange used. The safe v0.1
federation claim is requester-side delegation plus verified/admitted outcomes, not
an unattended cross-organization shared swarm.

### 18.3 Cancellation, expiry, and late results

Remote cancellation is advisory once dispatch occurred unless the Akson contract
defines a stronger operation. `act_intent_cancel` records the cancellation and the
remote status; it cannot claim effect rollback or that execution stopped without
verified evidence. Expired, superseded, or late outcomes are retained and verified
but cannot satisfy an advanced Pledge or Episode generation. They enter explicit
review or quarantine through `effect_outcome_admit`, and an ambiguous or
late-judged one goes to `effect_reconcile` for an
`EffectGovernanceDisposition`; they may inform participant evidence only under Byom
policy.

## 19. Offline clients and edge workers

### 19.1 Client resynchronization

A disconnected UI may queue only commands in the negotiated `offline_safe`
allowlist—initially `contribution_append` and non-authoritative `reaction_set`—with
stable idempotency keys. On reconnect it:

1. Refreshes authentication and re-evaluates the complete authorization
   dependency set.
2. Replays only allowlisted commands in causal order.
3. Treats original results, conflicts, revocation, and expiry explicitly.
4. Reads events after its last durable cursor.
5. If the cursor expired, replaces affected caches from an authorized snapshot
   and continues from the snapshot boundary.

A contribution replay succeeds only against its recorded branch/frontier
precondition. If that frontier moved, the client explicitly rebases, forks, or
abandons the draft; Kovee does not silently use last-write-wins or pretend that
commit time supplied the intended causality. Mutable metadata with a stale
`expected_revision` likewise requires user resolution.

Act positions, policy adoption/revocation, membership or role changes, budget
changes, deployment activation, effect authorization/reconciliation, handoff
acceptance, admission, and any disclosure command are never automatically
replayed. A client may preserve them as local drafts, but after reconnect it must
reload the exact current subject, render changes and current policy, obtain any
required step-up authentication, and ask the principal to confirm a new command.
An old click or queued form is not durable authority.

Local optimistic rendering is visibly pending until the server returns the
committed contribution id and branch sequence. A failed command is removed or shown failed;
it is never fabricated into the authoritative timeline.

### 19.2 Remote worker edge

A worker host separated by an unreliable network uses a small edge supervisor
with a durable SQLite inbox/outbox. A broker reconnect buffer in memory is not
durable acceptance. The edge stores only encrypted, scoped invocation manifests
and outputs required by its leases, enforces expiry while disconnected, and
cannot acquire new authority during a partition.

An invocation may continue local pure computation while its lease is certainly
valid. It must not perform a brokered external effect unless the effect broker
can recheck the current fence. If lease status becomes uncertain or expires, the
worker checkpoints locally, stops effects, and waits for reconciliation.

## 20. Security and privacy

### 20.1 Trust boundaries

The reference threat model distinguishes:

1. Untrusted internet clients and connector payloads.
2. Authenticated principals who may still access only some realms/projects.
3. Untrusted contribution, relation, peer, model, and artifact content, including prompt
   injection.
4. Assistant code, which is trusted only according to its execution profile.
5. Trusted Kovee control services with narrow workload identity.
6. Installation operators, who can normally access plaintext and infrastructure.
7. Model/tool providers and Akson peers outside the installation trust boundary.

Normal server-side assistant processing is incompatible with opaque end-to-end
encryption from all operators. Kovee may later add projects whose content cannot
be processed server-side, but it MUST NOT market ordinary encrypted-at-rest team
mode as operator-blind E2EE.

### 20.2 Required controls

- TLS on external network bindings; mTLS or equivalent workload authentication
  internally.
- Encryption at rest with realm-scoped data keys in team mode; keys live in a
  KMS/secret manager, not database rows or event payloads.
- Short-lived, audience-bound user, service, worker, upload, and artifact grants.
- Tenant/project/space filters and authorization on every read, mutation, event replay,
  live delivery, search result, and artifact fetch.
- Database defense in depth such as row-level policies where practical, plus
  application authorization and cross-tenant tests.
- Strict JSON/schema/size/depth validation before persistence or publication.
- Default-deny production worker network and no ambient database, NATS, cloud,
  model, connector, or Akson credentials.
- Brokered model/tool access with exact intent, current fence, disclosure, and
  budget enforcement.
- Immutable assistant packages, dependency locks, provenance/signature recording,
  vulnerability/policy scanning, and explicit rollout.
- Content-type verification, artifact scanning, inert rendering, safe download
  disposition, and no automatic external resource loading.
- Rate limits and quotas by source, principal, realm, project, connector,
  assistant, and operation; bounded unauthenticated parsing before identity.
- Audit records for authentication, authorization result, policy/decision,
  causation, request id, effect, administrative override, and data disclosure.
- Secrets and credentials excluded from logs, prompts, argv, environment visible
  to assistants, exception strings, events, and artifacts.

### 20.3 Prompt injection and untrusted data

Inbound contributions and relations, application events, model output, assistant claims, connector
payloads, peer content, artifacts, skills, and engrams are data. They cannot:

- Select the authenticated actor.
- Grant a capability or project membership.
- Decide a governed act or approve an effect.
- Increase a budget or deadline.
- Widen a disclosure manifest.
- Change an assistant/security policy.
- Mark a commitment fulfilled, a Byom deliverable accepted, or evidence verified.
- Wake an assistant across an admission boundary.

The secure worker's lack of ambient authority is the enforcement; a system
prompt asking the model not to exfiltrate is not.

### 20.4 Data classification, retention, and deletion

Every realm defines a closed classification vocabulary and policy mapping for
storage, model use, connectors, project sharing, and Akson disclosure. The
vocabulary MUST form a finite join-semilattice or a total order with an explicit
join. Each contribution, relation, artifact, invocation manifest, checkpoint,
context assembly, attention candidate/activation/triage input, commitment,
delivery, WorkRealization, and disclosure item carries or derives a known
member. Unknown labels fail closed; mixed inputs
use the declared join rather than an implementation's guess about which label is
“more restrictive.”

The realm policy defines a deterministic classification lattice and `join`.
Every assistant/model/tool-derived output inherits at least the join of all
source contributions, relations, briefing items, artifacts, tool results,
checkpoints, and hidden adapter instructions that influenced it. Incomparable classes join to a
declared restrictive mixed class or block the operation. An assistant-supplied
lower label is ignored.

Classification labels are source-qualified:

```text
ClassificationRef {realm_id, policy_revision_ref, label}

ClassificationMappingRevision {
  mapping_id, revision,
  source_realm_id, source_policy_revision_ref,
  destination_realm_id, destination_policy_revision_ref,
  entries[]: {source_label, destination_label},
  approved_by_destination_decision_ref,
  status, digest
}
```

Labels from different realms are never compared by spelling or rank. Every
cross-realm handoff/disclosure and admission binds an active immutable mapping
revision that covers every source label; the destination approves it and may map
only to a label at least as restrictive under its own policy. A lowering needs
the explicit declassification effect below. Missing, stale, incomparable, or
peer-supplied unknown mappings fail closed. Remote Akson labels remain untrusted
metadata until local Byom/Kovee admission applies a destination mapping.
Revocation blocks new disclosures/admissions; it cannot relabel or erase a copy
already admitted under the recorded mapping revision.

Lowering classification is a `declassify` effect over exact source and transformed
output digests, with a principal/policy decision, reason, transformation record,
and disclosure analysis. It creates a new derived object with provenance; it
never relabels the source in place. Redaction, summarization, or a model's claim
that content is safe does not automatically declassify it.

Retention separates:

- Domain state lifetime.
- Event metadata/audit lifetime.
- Event payload lifetime.
- Model transcript lifetime.
- Artifact/checkpoint lifetime.
- Idempotency/effect-dedupe lifetime.

Edits and normal deletion use immutable revisions/tombstones. Authorized erasure
removes or cryptographically shreds payloads and blobs while retaining only the
minimum permitted audit metadata and digests. Backup expiration and replica
deletion are part of the erasure policy. Legal hold, if supported, is an explicit
operator-visible state rather than an invisible failure to delete.

### 20.5 Security profile claims

Security posture is reported per invocation and worker, not just configured per
installation. The run record includes actual isolation mechanism, worker version,
policy digest, network mode, package digest, and broker endpoints. If the host
cannot enforce the requested profile, scheduling fails; it does not silently
downgrade.

## 21. Operations and observability

### 21.1 Causal telemetry

Domain events are not logs, and model transcripts are not operational traces.
Kovee correlates them without conflating them:

- Domain ledger: authoritative transitions and actor/causation.
- Audit ledger: authentication, authorization, disclosure, decisions, overrides.
- Distributed traces: request, SQL, outbox, broker, worker, provider, connector.
- Metrics: attention candidate/activation/coalescing rates, context-assembly
  failures, open commitments, unresolved merge conflicts, queue depth/age,
  outbox lag, consumer lag, lease churn, retries, budget, provider usage,
  realtime fanout, auth failures, and cross-tenant probes.
- Logs: bounded diagnostics with ids/digests, never raw secrets or unrestricted
  prompts/content by default.

Every attention candidate/activation, Commitment, WorkRealization, and invocation
has source-qualified correlation and causation refs. The operator can answer:
why it is queued, which deterministic filter made it eligible, who accepted the
contract/terms, what woke it, which exact context it saw, who authorized
disclosure, what is reserved/spent, which attempt owns the lease, and whether an
effect is ambiguous.

### 21.2 Health and readiness

Health distinguishes:

- Process liveness.
- Ability to read/write authoritative SQL.
- Outbox and consumer delivery lag.
- Object-store read/write/finalize ability.
- Worker capacity per runtime/security profile/region.
- Model/tool provider degradation.
- Byom and Akson integration cursor lag.

An API node that cannot reach authoritative SQL is not ready for mutations. A
NATS outage may leave collaboration writes ready but marks asynchronous execution
degraded and triggers backlog backpressure.

### 21.3 Initial service objectives

These are reference team-mode targets, not protocol guarantees:

- 99.9% monthly availability for authoritative command/query API in the home
  region, excluding declared maintenance.
- p95 accepted local contribution append under 300 ms at the API boundary.
- p95 committed-event notification under 1 s while delivery is healthy.
- No acknowledged authoritative mutation lost (RPO 0 for committed SQL under the
  configured synchronous HA boundary).
- Restore a realm from tested backup plus logs within four hours (RTO 4 h) at
  initial production maturity.
- Alert before oldest queued work, outbox lag, consumer lag, or storage usage
  crosses its policy threshold.

Installations publish their actual topology, backup guarantees, and provider
dependencies. A single-node personal profile cannot claim team HA.

### 21.4 Backup and restore

Backups cover SQL, object-store bytes and metadata, encryption key recovery,
schema registry, and installation configuration. NATS streams and projections are
not primary backup sources.

A restore procedure:

1. Restores SQL to a consistent point and validates migration/version metadata.
2. Restores referenced artifacts and checks digest completeness.
3. Restores key access without copying reusable runtime credentials.
4. Rotates service/worker credentials and increments the installation recovery epoch.
5. Rebuilds Kovee-owned projections and broker streams from authoritative
   event/outbox data; restores external projections only from an authorized
   source snapshot/boundary or the governed integration journal, otherwise marks
   them unavailable until resynchronized.
6. Preserves idempotency/effect records so recovery does not repeat effects.
7. Reconciles in-flight effects and marks uncertain ones `ambiguous`.
8. Runs invariant checks before enabling mutations.

Restore drills are part of release readiness, not documentation-only work.

## 22. Failure semantics

| Failure | Required result |
|---|---|
| SQL commit succeeds; reply is lost | Retried idempotent command returns the original result/revision while retained, or the non-reexecuting expiry tombstone afterward. |
| Process dies before SQL commit | No state, event, outbox job, budget reservation, or idempotency result partially exists. |
| NATS unavailable after commit | Outbox retains delivery; accepted work is not lost; lag/backpressure becomes visible. |
| Notification or job is delivered twice | Consumer inbox and business idempotency/effect keys reduce the duplicate to a no-op. |
| Projector dies after applying but before ack | Redelivery observes the inbox/result and only acknowledges. |
| Worker dies before committing output | Lease expires; a new fenced attempt may resume from a committed checkpoint. |
| Old worker returns after replacement | Every mutation/effect fails `stale-lease`. |
| Worker commits output and its reply/ack is lost | SDK retry with the same operation key returns the committed output; no second contribution/delivery/effect is created. |
| Target assistant is offline | The created WorkRealization remains queued until its bounded deadline, cancellation, or capacity recovery; the Commitment does not imply execution occurred. |
| Delivery arrives after timeout or supersession | It is retained as late evidence and does not resume the parent, satisfy changed terms, or satisfy Byom work. |
| Branch head changes during merge acceptance | Compare-and-swap fails with a stale proposal; no partial adoption or model-chosen conflict resolution occurs. |
| Attention source is delivered repeatedly | One candidate/activation key absorbs duplicates; rate, lineage, and circuit breakers prevent a wake storm. |
| Attention target or authorization changes before wake | Activation fails closed; a prior candidate or assembly is not a bearer grant. |
| Context input is erased, reclassified, or revoked | Materialization of the immutable assembly fails. A separately requested new assembly may record a policy-permitted omission under a new digest; neither path substitutes a current revision or leaks existence. |
| Formation acceptance crashes | Exact commitments, reservations, and assistant realizations exist all together or not at all inside one Kovee boundary. |
| Amendment races a running or delivered realization | Exact revision locking chooses one transition; accepted new terms fence/supersede old execution, whose late output remains attributable but cannot satisfy the new digest. |
| Two promotions start on one branch | The durable `EndeavorFormationSlot` admits one; the other cannot call Byom. Slot acquisition and `prepared -> submitting` are atomic; after that point cancel/release is forbidden. The recovery workload can recover an existing committed result through the read-only five-fact query; a verified `absent` leaves the slot held at `awaiting_principal` until a freshly authenticated principal resubmits only the stored command under the same IdempotencyDomain. |
| Poison delivery | Bounded retries, quarantine, terminal diagnostic where applicable, operator alert; consumer continues. |
| SQL primary is unavailable | No mutation is accepted; broker consumers do not ack authoritative work. |
| Artifact upload is partial or digest-mismatched | Finalize fails; no visible resource may reference it as available. |
| Artifact bytes seal but final SQL commit is lost | Reconciliation verifies the exact sealed version and commits once, or later garbage-collects the unreferenced object; it never exposes staging bytes. |
| Membership is revoked with a live socket/token | The authorization dependency changes; live stream closes/rechecks; future command, replay, and fetch fail. |
| Assistant is redeployed | Existing invocations stay pinned; new invocations use the recorded rollout decision. |
| Non-idempotent provider/tool outcome is unknown | Effect becomes `ambiguous`; no blind retry; reconciliation is explicit. |
| Byom consumes a one-shot permit and Kovee loses the reply | The pre-existing effect's execution key recovers the same kernel-issued `ExecutionConsumptionReceipt`; no second use or driver call is created. |
| Home-region partition | Writes route to the authoritative side or fail; no multi-master merge or split-brain effect permit. |
| Clock skew on a worker | Server time controls lease, expiry, deadline, and policy decisions. |
| Byom/Akson projection is stale | UI labels source cursor/lag; commands go to the source; projection never authorizes. |
| Cross-installation material arrives | It remains inert until Akson verification and local Byom/Kovee admission. |
| Cross-realm handoff partitions after destination prepare | Destination copies remain inert; transfer-id reconciliation commits the one source use and then activates once, or remains ambiguous without a second disclosure. |
| Restore occurs with in-flight work | Recovery epoch fences old credentials/leases; effects are reconciled before retry. |

## 23. Public bindings and SDKs

### 23.1 HTTP and realtime

The first network binding uses authenticated HTTPS JSON for commands, queries,
snapshots, and artifacts; WebSocket or SSE carries event notifications and
advisory streaming. Illustrative routes map to protocol operations:

```text
GET  /v1/protocol
POST /v1/projects
POST /v1/projects/{id}/memberships
POST /v1/spaces
POST /v1/spaces/{id}/participants
POST /v1/spaces/{id}/access-grants
POST /v1/spaces/{id}/access-widenings:prepare
POST /v1/spaces/{id}/contributions
POST /v1/spaces/{id}/relations
POST /v1/spaces/{id}/context-assemblies
POST /v1/branches
POST /v1/merges:prepare
POST /v1/attention-contracts
POST /v1/attention-candidates/{id}:activate
POST /v1/needs
POST /v1/offers
POST /v1/formations/{id}/assents
POST /v1/formations/{id}:accept
GET  /v1/commitments/{id}
POST /v1/commitments/{id}:review
GET  /v1/work-realizations/{id}
POST /v1/collaboration-context-bundles:prepare
POST /v1/endeavor-promotions:prepare
POST /v1/endeavor-promotions/{id}:start
POST /v1/endeavor-promotions/{id}:cancel
POST /v1/endeavor-promotions/{id}:reconcile
GET  /v1/events?source=&project_id=&after=&limit=
WS   /v1/realtime
POST /v1/assistants
POST /v1/assistants/{id}/revisions
POST /v1/deployments
POST /v1/invocations
POST /v1/invocations/{id}:cancel
POST /v1/handoffs
POST /v1/handoffs/{id}:accept
POST /v1/space-admissions/{id}:decide
POST /v1/artifacts:begin
POST /v1/artifact-uploads/{id}:finalize
```

The schemas and operation names, not the REST path layout, are normative. A
binding specification defines HTTP status mapping, headers, authentication,
content types, retry guidance, CORS/CSRF, and streaming frames.

### 23.2 Local binding

Personal mode exposes a `0600` Unix socket in a `0700` runtime directory and MAY
also bind a loopback HTTP server for the web UI. The UDS binding uses persistent
length-delimited or newline-delimited I-JSON after `hello`, or includes an
explicit negotiated version on each one-shot request. It must not repeat the
impossible “hello first, one request per connection” combination that an earlier
draft protocol required; BPP resolved the same problem the same way.

Unix peer credentials bind the local principal only in personal mode. They do
not distinguish multiple humans or provide team-mode governance identity.

### 23.3 Worker binding

Workers use a separate mutually authenticated supervisor protocol. It contains
only:

- Worker register/renew/drain.
- Invocation claim/input/checkpoint/yield/complete/fail.
- Fenced context-assembly requests and contribution/relation/offer/delivery/
  event/model/tool operations allowed by the invocation.
- Cancellation/deadline notifications.
- Usage and diagnostics reporting.

It excludes realm/project administration, membership, assistant deployment,
human decisions, Byom governance or admin operations, Akson administration, raw
SQL, and raw NATS. Enumeration of a forbidden operation on this surface is a conformance
failure.

### 23.4 Connectors

Telegram, email, Slack-like systems, and webhooks are connector services, not bus
subscribers. A connector:

- Authenticates and verifies inbound provider requests before parsing deeply.
- Maps a provider installation and remote conversation/user to an explicit
  Kovee Space, SpaceParticipant projection, and Stream lens under an
  installation policy. Provider threads do not become a second canonical
  conversation model.
- Derives idempotency keys from the connector binding/provider installation and
  provider message id; a raw provider id is not assumed globally unique.
- Applies size, rate, abuse, and admission rules.
- Uses an effect driver for outbound sends and handles ambiguous outcomes.
- Never lets a remote display name select a Kovee principal or assistant actor.

## 24. Repository and implementation shape

The proposed reference layout is:

```text
kovee/
  spec/
    collaboration-protocol.md
    worker-protocol.md
    http-binding.md
    schemas/
    vectors/
  crates/
    kovee-core          ids, canonicalization, records, transitions
    kovee-store         SQLite/PostgreSQL, migrations, ledger, outbox/inbox
    kovee-auth          principals, memberships, capability tokens; policy client/evaluator
    kovee-space         spaces, contributions, relations, branches, lenses, handoffs
    kovee-attention     recipes, assemblies, contracts, candidates, activations
    kovee-commitment    needs, offers, formations, commitments, reviews
    kovee-runtime       registry, invocations, scheduler, leases, budgets
    kovee-effects       policy revisions/ceilings, intents, decisions, model/tool/connector brokers
    kovee-artifacts     content-addressed storage and validation
    kovee-bus           in-process and NATS private bindings
    kovee-byom          BPP protocol/provider/projection adapter
    kovee-akson         least-privilege federation adapter
    koveed              reference API/control daemon
    kovee-cli           thin operator/client CLI
  sdk/python/
  sdk/typescript/
  web/
  conformance/
  xcheck/
```

Bounded contexts should depend on protocol/core types, not each other's SQL
tables. Database transactions may share a kernel, but only the owning module can
construct its state transitions. The Python SDK and TypeScript client are
independent conformance clients, not generated wrappers around Rust internals.

## 25. Conformance and verification

### 25.1 Protocol conformance

Conformance follows negotiated features, not the delivery-plan horizon. Before
an implementation advertises a feature bundle, the repository contains JSON
Schemas and positive/negative vectors for every command, result, event, problem,
record, manifest, and applicable worker message in that bundle. It also contains
idempotent replay/crash fixtures for each mutation and all security invariants
made reachable by the bundle. An unadvertised K3–K6 feature is not required for
`core_v1` interoperability and cannot be partially advertised.

Every `0.1` implementation, even one advertising only `core_v1`, passes:

- Golden envelope and JCS/SHA-256 vectors cross-checked by Rust, Python, and
  TypeScript.
- Old/new minor negotiation, unknown-extension, closed-enum, problem, limit, and
  forbidden-authority-surface fixtures.
- Cursor-token integrity and generic idempotency-key scope/digest fixtures.
- Two independent clients exercising the same reference server.

Bundles containing snapshots, replay, authorization, or mutations additionally
test snapshot/cursor expiry, authorization-dependency invalidation, pagination,
replay, and process death after commit and before reply. Worker protocol
profiles are conformed independently and are advertised only with their complete
message/state/fencing suite.

### 25.2 Invariant suites

Release tests MUST prove every invariant made reachable by the installation's
advertised bundles, worker profiles, Byom/Akson matrix entries, and deployment
topology. A phase cannot claim its exit criterion until the corresponding cases
below pass; unsupported later features are omitted rather than skipped as
passing. The applicable suites prove:

1. Cross-realm/project/space reads, writes, replay, live delivery, search,
   relation traversal, artifacts, counts, and existence probes fail closed.
2. A request body cannot claim another principal, invocation attempt, service, or peer.
3. Same idempotency key plus different canonical arguments is rejected.
4. Every accepted mutation survives daemon and broker restart without partial
   state or lost outbox work.
5. Two claimants race and exactly one fence wins; stale attempts cannot append a
   contribution/relation/offer/delivery, create child work, call a model/tool,
   checkpoint, or complete.
6. Every broker delivery may be duplicated, delayed, and reordered without
   duplicate domain transitions or observable effects.
7. Crash injection at every intent/effect boundary never converts unknown into
   success or blindly repeats a non-idempotent effect.
8. BranchEntry sequences per branch, Contribution sequences per Space, and
   project/aggregate event cursors have
   no gaps or reordering within their promised scope across restart.
9. Membership, space access, participant, grant, attention acceptance, or target
   revision changes terminate future command, replay, activation, worker
   operation, and artifact access as applicable.
10. Production assistant code cannot reach NATS, SQL, cloud/model/connector
    credentials, undeclared filesystem paths, or network destinations.
11. Budget reservation races cannot overcommit, and canceled/failed work releases
    only the unspent reservation once.
12. Parent deadline, cancellation, ancestry, depth, disclosure, and budget bound
    every child Commitment/WorkRealization; late deliveries do not resurrect work.
13. Cross-installation arrival never becomes visible or wakes an assistant before
    verification, classification mapping, and local space admission.
14. Kovee can rebuild every Kovee-owned projection and NATS stream from its
    authoritative records without projections acquiring write authority;
    Byom/Akson rebuild tests run only when the source advertises the required
    snapshot/boundary capability or within the integration journal's coverage.
15. A backup restore preserves ids, digests, idempotency, effect ambiguity, and
    fencing while invalidating pre-restore credentials.
16. Concurrent identity linking cannot bind one active issuer/subject to two
    principals; decisions cannot reuse an expired or lower-assurance login
    observation.
17. Crash injection at every artifact seal/verify/SQL boundary never exposes
    unverified bytes, and concurrent grant-use creation never exceeds
    `max_uses` or returns two sessions for one stable use key.
18. Concurrent policy-ceiling and budget reservations preserve every account
    equation; ambiguous usage is not released. A crash after Byom consumes a
    permit but before Kovee records it recovers the same receipt and never asks
    Byom for another use, and a subordinate reservation never exceeds its parent
    dimension.
19. Crash/partition injection at every cross-realm handoff saga step produces at
    most one source use and one destination copy set; destination objects cannot
    wake work before both receipts, and an uncertain transfer is never released
    into a second disclosure.
20. Relations and lenses never reveal hidden endpoint existence, cross a space,
    confer visibility, create authority, or become executable graph edges.
21. A branch pins its exact base; stale-source or stale-target merges fail
    compare-and-swap, origin/dissent remain inspectable, and synthesis never
    resolves truth, policy, plan, acceptance, or apply authority.
22. Attention eligibility is deterministic and bounded; duplicates/coalescing
    yield one candidate/activation, semantic ranking can only order eligible
    items, concurrent candidates cannot exceed wake/in-flight accounts, widening
    needs fresh target acceptance, and revocation prevents wake.
23. ContextAssembly vectors preserve exact refs/revisions/digests/order,
    transformations, omissions, cursors, classification join, limits, and
    versions; every materialization reauthorizes, erasure fails explicitly, and
    provider-context vectors bind the final request digest without hidden input.
24. Formation/amendment finalization is atomic and requires exactly one current
    separately authored TermsAssent for every derived requester/performer slot;
    one caller, coordinator, worker, duplicate slot, partial set, or model prose
    cannot impersonate another party. Runtime delivery cannot satisfy a
    Commitment, accepted amendments fence/supersede old realizations under fresh
    terms, and no Kovee review can accept Byom work.
25. Kovee attention, merge, Commitment, delivery, effect, or projection cannot
    author a WakeIntent, admit an activation, revise a Pledge, position on or
    finalize an act, allocate a workspace, accept a deliverable, apply a change
    set, or bypass Akson consent. Kovee is never the genesis governance actor: a
    `governance_enable` attempt against an absent or non-active Society fails, and
    every runtime mutation missing either fence is refused.

### 25.3 Chaos and scale

The initial production gate runs at least 100 concurrent scripted assistants
with injected duplicates, response loss, worker kills, NATS outages, SQL
failover, slow consumers, poison messages, membership revocation, and provider
timeouts. It asserts no lost accepted mutation, stale write, duplicated effect,
budget overcommit, unauthorized delivery, starvation beyond policy, or silently
truncated audit trail.

Load claims are published only with the exact topology, workload, payload sizes,
latency percentiles, queue age, error rate, and durability configuration used.

## 26. Delivery plan

Each phase ships a coherent vertical slice and keeps identity/tenancy in the
model from day one.

### K0 — specification and threat model

- Ratify this boundary with the Byom and Akson owners.
- Write `core_v1`, `shared_space_v1`, and
  `developer_assistant_v1` schemas, the minimal worker protocol, limits, errors,
  digest vectors, threat model, authorization actions, data classifications, and
  conformance harness. Each later feature bundle becomes normative before its
  implementation phase starts.
- Resolve the section 17.5 protocol prerequisites in Byom's own spec process
  rather than hiding them in an adapter.

Exit: two clients negotiate and pass envelope/digest/error/surface tests; the
state-ownership and threat-model reviews have no unresolved critical issue.

### K1 — personal shared-space wedge

- SQLite/store kernel, local binding, one realm/project/space, participants,
  typed contributions/relations, pinned frontiers, Stream and Workbench lenses,
  exact ContextAssembly, event ledger, artifacts, and thin CLI/web view.
- Python developer worker reached by an authenticated one-shot direct invocation
  with one immutable ContextAssembly and an idempotent deterministic synthesis;
  the K1 acceptance path has no model dependency.
- No NATS and no production isolation claim.

Exit: a new user initializes a repo, opens a Space, appends a question, invokes
one assistant over an inspectable assembly, kills/restarts the daemon, and sees
one synthesis contribution plus its `addresses` relation and causal provenance
with no duplication.

### K2 — durable runtime and the governed-work wedge

- Deliberation branches and compare-and-swap merge; reusable context recipes and
  AttentionContracts/candidates/activations; Needs, Offers, Formations,
  separately attributable terms assents, local-only Commitments and
  WorkRealizations; model-independent standing policies/ceiling ledgers;
  invocation state, leases/fencing, checkpoints, budgets, cancellations, and
  effect intents.
- `governed_work_binding_v1` and the audited personal/local `byomd` bootstrap used
  by `kovee governance enable --byom local`, which binds an already-active Society
  and never establishes one.
- A minimal confined supervisor and `WorkspaceProvider` for an
  installation-supplied scripted worker, plus its crash matrix. This slice
  demonstrates enforced workspace boundaries and denial of Kovee authority
  surfaces; it does not claim default-deny network or broker-only effect/egress
  confinement and does not host arbitrary user packages.
- Optional `model_broker_v1` for local development. Calls through it are
  disclosed, metered, and audited, but a same-UID `developer` assistant can
  bypass it; only K4 makes broker-only egress an enforced claim.
- The first byom adapter/provider: explicitly promote one exact Space branch
  frontier and ContextAssembly to one local Endeavor through
  `kovee_endeavor_form`, decide one governed act (server-prepared subject →
  eligible human `act_intent_position` at the current digest under a fresh
  challenge → deterministic `act_intent_finalize`), run two fenced Pledge
  episodes, and submit a base-bound deliverable through
  `delivery_submit`/`review_record`. Engrams, participant evidence, peers, and
  production model egress remain later phases.

Exit: dual-claim and stale-fence tests pass; recursive work is bounded; mixed
worker restart resumes from a portable checkpoint; ambiguous effect path is
demonstrated; the frontier-to-Endeavor wedge survives a daemon or worker kill
without duplicate Endeavor formation, lost act state, or false acceptance.

### K3 — team collaboration

- PostgreSQL, OIDC/passkeys, realm/project roles plus space access/participants,
  realtime gateway, revocation, space handoff/admission, S3-compatible artifacts,
  audit and retention.
- Transactional outbox/inbox and internal NATS/JetStream.
- Team realms may run only installation-supplied, operator-approved confined
  workers from immutable images. Same-UID developer workers are restricted to
  personal loopback mode, and tenant-supplied assistant code remains disabled
  until K4.

Exit: multi-user isolation/revocation suite and broker-loss recovery pass; no
frontend or assistant has bus/database credentials.

### K4 — production assistant hosting

- Reproducible packages, confined/secure workers, short-lived capabilities,
  enforced broker-only model/tool/connector egress, disclosure manifests, usage
  settlement, rollout/rollback, and tenant-supplied package admission.

Exit: hostile assistant tests fail to reach undeclared resources; actual-profile
attestation is recorded; provider/tool crash and reconciliation suites pass.

### K5 — complete Byom product integration

- Harden the byom provider/network binding from K2; complete the act inbox,
  endeavor/pledge views, patch review, causal projections, the merged timeline,
  participant-evidence routing UI, and the Engram UI.
- Preserve Byom ids, digests, and cursors, and read through Byom source cursors.

Exit: the frontier-to-Endeavor workflow survives daemon/worker kills, a governed
act is decided by an authenticated principal filling its own eligible seat, two
fenced Pledge episodes run, and a base-bound deliverable reaches patch review
without Kovee becoming a second authority. Cursor-loss/staleness tests rebuild or
explicitly invalidate every Byom projection from an authorized source boundary; an
authorized participant-evidence query and the Engram quarantine/admission flow
preserve their Byom ids, digests, classifications, and source cursors.

### K6 — federation

- Akson coordination surface/consent prerequisite, the `byom_akson_dispatch_v1`
  driver over a frozen exchange surface, disclosure/admission views, verified
  outcome projection.

Exit: the exact outbound ActIntent maps to the exact Akson staged digest, neither
side wakes before admission, duplicates do not redispatch, binding changes suspend
trust, and a late result cannot satisfy an advanced Pledge or Episode generation.

### K7 — HA and operations

- PostgreSQL HA/backup, production JetStream topology, home-region routing,
  restore/rebuild tooling, SLO dashboards, capacity/fairness tuning, chaos soak.

Exit: backup restore and region/broker/database failure drills meet published
RPO/RTO and invariant requirements.

## 27. Migration from the current designs

The repository is early enough to converge without compatibility debt. Migration
is therefore conceptual:

1. Keep **Kovee** as the product/runtime name and **Byom** as the governed-work
   bounded context, with **BPP** as its protocol. Byom is the governance owner
   from day one; there is no predecessor governance layer to migrate from, and
   the `kovee-byom` adapter is the only governance adapter.
2. Preserve Byom ids, states, digest rules and classes, event shapes, decision
   rules, and engram format. Fix protocol gaps through Byom's spec process.
3. Add Kovee Realm/administrative Project, Space/access/participant,
   Contribution/Relation/Frontier/Lens, Branch/Merge, Context/Attention,
   local Commitment/WorkRealization, assistant/deployment/invocation, artifact,
   and space-handoff records around Byom rather than renaming Byom objects.
4. Remove the brainstorm's canonical chat/RPC ontology before implementation:
   `Conversation -> Stream SpaceLens`, `Message -> Contribution(kind:utterance)`,
   `WorkRequest -> Need/Offer/Formation/Commitment + WorkRealization`,
   `Subscription(action:invoke) -> AttentionContract/Candidate/Activation`,
   legacy conversation-snapshot selection -> `ContextAssembly`, and
   `ProjectAdmissionRecord -> SpaceAdmissionRecord`. Existing chat imports map
   messages one-to-one and never infer semantic relations.
   `CollaborationContextBundle` remains only the Byom admission wrapper around
   one exact ContextAssembly; it is not a competing selection model.
5. Implement the Python runtime as both a Kovee assistant worker and a Byom
   Manifestation — a hosted episodic participant or an attached harness.
6. Keep byom's own CLI as an expert/compatibility surface. The Kovee UI/CLI
   composes it through the protocol and never bypasses it.
7. Treat every subject in `kovee-design.md` as a discarded private sketch.
8. Use SQLite/in-process delivery personally and PostgreSQL/outbox/NATS for team
   mode. Do not introduce a JetStream-KV state phase.
9. Use Akson for independent-installation federation; do not build a shared NATS
   account bridge.
10. Normalize documentation to **Akson** for the local federation component and
   describe any external authoring inspiration without making it an architectural
   dependency.

If existing Byom data is projected into Kovee, create a default personal realm,
administrative project, and an explicitly empty Space only when the user asks for
a collaboration projection. Preserve every Byom id/digest/cursor and add nullable
correlation links. No importer rewrites engram content, manufactures semantic
relations, or treats a Byom journal as a Kovee Stream.

## 28. Resolved decisions and honest dependencies

Resolved in this design:

1. Kovee is the collaboration product and distributed assistant runtime; Byom is
   the governed-work kernel; Akson is federation.
2. Public clients use versioned authenticated APIs, never raw NATS.
3. SQLite/PostgreSQL is authoritative; NATS/JetStream is internal delivery.
4. Python is the first assistant SDK; the reference correctness kernel is Rust.
5. `run(ctx)` remains the convenience surface, while the worker protocol is the
   real lifecycle contract.
6. Shared Space is the product unit; Stream conversation and presence are lenses,
   not authority or the coordination ledger.
7. Cross-machine inside an installation uses the worker fleet; cross-installation
   uses Akson.
8. Production code runs as an immutable revision under an enforced profile.
9. Kovee promises at-least-once delivery plus idempotent effects, not magical
   exactly-once execution.
10. A single home write region is the v0.1 consistency model.

Dependencies that constrain delivery rather than reopen the architecture:

- Byom's tracked design obligations — chiefly the typed profile-claim/evidence
  publish, read, and search operations behind ranked routing — must land before
  the capabilities that depend on them are advertised.
- Akson must land its least-privilege coordination/consent surface before K6.
- Inbound remote execution remains blocked on Akson's agent-worker baseline.
- Exact provider retention/region guarantees are installation/realm policy inputs and
  recorded claims; Kovee cannot manufacture them.

These dependencies are surfaced in capabilities and product claims. Missing
support disables the affected workflow; it never causes a silent fallback to a
broader authority surface or an unconfined worker.

## 29. The design in one sentence

**Kovee gives people and agents forkable shared spaces, explicit attention,
reproducible context, and negotiated local commitments; Byom governs consequential
work, Akson crosses sovereign boundaries, and the classical runtime safely
delivers what those authoritative records decided.**
