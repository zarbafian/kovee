# Kovee threat model (K0)

Companion to `DESIGN.md` §20 (security and privacy), extracted at K0 per the
K0 milestone sheet. It names what Kovee protects, whom it defends against,
and where each defense is realized — in the delivered K0 spec artifacts or
in a named later milestone. Section references (§) point at `DESIGN.md`;
governance authority is **byom** throughout, per amendment A1
(`design/2026-07-25-amendment-governance-owner.md`) and A9
(`design/2026-07-27-amendment-governance-owner-enum.md`) — byom is the only
governance layer this stack has, and `KoveeGovernanceOwnerBinding` admits
exactly two owner arms, `byom` and `none` (C2 bundle).

K0 delivers **shape enforcement**: the frozen operation registry, the
envelope/acceptance caps, and the per-operation schema + negative-vector
suite, each re-derived by two independent checkers. Behavioral enforcement
is the engines' job; every mitigation row below says honestly whether it is
enforced today or lands with K1/K2/K3/K4 (or a C-track contract). A row
marked "lands with …" is **not enforced yet** and must not be claimed.

## What we protect (assets)

1. **Space content** — contributions, relations, branches, artifacts,
   context assemblies, and their classification labels (§10, §20.4).
2. **The authority model** — who may perform which operation on which
   surface: actor bindings, memberships, grants, authorization dependency
   sets, fences (§9, §11.6.1). A hostile input must never widen it.
3. **Governance bindings** — `KoveeGovernanceOwnerBinding`, realm↔Society
   mappings, episode bindings. Byom owns governance; Kovee must be unable
   to mint, forge, or bypass these bindings (amendments A1/A2; C2 bundle).
4. **Credentials** — model/connector/artifact-store credentials and worker
   capabilities; excluded from logs, prompts, argv, events, and artifacts
   (§20.2).
5. **Provenance and audit** — an honest causal record of what happened,
   including *ambiguous* effect outcomes (§4.9, §21.1).
6. **Erasability** — the ability to actually delete: erasure must not be
   defeated by retained plaintext digests over erasable content
   (§20.4; amendment A5).

## Actors and trust boundaries

The §20.1 tiers, with the byom placement made explicit:

1. **Untrusted internet clients and connector payloads** — adversarial
   bytes before any identity is established.
2. **Authenticated principals** — real users who may still access only
   some realms/projects; authorization is per-operation, never ambient.
3. **Untrusted content** — contributions, relations, peer content, model
   output, and artifacts, including prompt injection. Content is data;
   it carries no authority (§20.3).
4. **Assistant code** — trusted only according to its declared execution
   profile (§14.4, §20.5); through K1 that profile is `developer`
   (same-UID, no confinement claim).
5. **Trusted control services with narrow workload identity** — koveed's
   own services **and `byomd`**. Byomd sits in this tier as a separate
   process with its own narrow identity: it is the governance owner
   (admits activations, allocates budgets, owns seats, mandates, and
   decisions) and is reached only through the two contracted seams —
   **C2** (`byom_governed_work_v1`: the `kovee-byom` adapter speaking BPP,
   the only governance seam that exists) and **C3** (C3a MCP candidate/participant
   profiles, C3b worker/episode binding with `ByomEpisodeBinding` dual
   fences). The trust is narrow in both directions: byomd never calls a
   model, never executes effects, and never holds Akson credentials
   (family contract ownership table); Kovee never decides governance and
   is never the genesis governance actor (amendment A2).
6. **Installation operators** — can normally access plaintext and
   infrastructure. Kovee MUST NOT market ordinary encrypted-at-rest team
   mode as operator-blind E2EE (§20.1); the operator threat modeled here
   is *silent* overreach — action outside the audit record, or privacy
   defeat via retained digests — not plaintext access as such.
7. **Model/tool providers and Akson peers** — outside the installation
   trust boundary; semi-trusted plaintext boundaries reached only through
   brokers and the C4 exchange surface (K4/K6 scope).

## Adversaries modeled

- **A prompt-injected assistant** — tier-4 code steered by tier-3 content;
  it holds only its invocation capability and fence, and its output is
  data (§20.3, §4.12).
- **Hostile contributions/relations/artifacts** — tier-3 content trying to
  select actors, assert authority, or smuggle context (§20.3).
- **A malicious or compromised connector** — tier-1 payloads under a
  mapped, dedicated service identity — never the installing human's
  credential (§9.1; registry KREG-02 split).
- **A curious operator** — tier 6; bounded by audit, classification, and
  the A5 digest classes rather than by encryption claims Kovee does not
  make.
- **Hostile pre-auth clients** — parser/resource attacks before identity;
  bounded unauthenticated parsing (§20.2, §11.8 caps).
- **External providers and peers** — tier 7; modeled concretely at K4
  (broker enforcement) and K6/C4 (federation), not before.

## Threats → mitigations

One row per §4 invariant family, plus the A5 privacy row. "Enforced now"
means delivered K0 artifacts checked in CI (`registry_parity`,
`xcheck/run.py`, `tscheck/check.mjs`); "lands with …" names the owning
milestone and is not yet enforcement.

| # | §4 | Threat (attacker → goal) | Mitigation (where) | Status |
|---|----|---|---|---|
| T1 | 1 Commands are not events | Publish or inject an event to create state without command authorization | The registry is deny-by-default: an operation without a row is not callable, and no client-facing event-publish operation exists except `application_event_emit`, whose rows bind principal authority and the worker fence (`spec/registry.json`). The single-writer command transaction + outbox make events derivations, never inputs. | Rows enforced now; kernel lands with K1 (outbox/NATS with K3) |
| T2 | 2 Database is authoritative | Broker or projection compromise/loss rewrites accepted state | SQLite command transaction and event ledger are the authority; NATS/JetStream contents are recreatable from the log (§12, §13). | Lands with K1 (ledger) / K3 (outbox, broker rebuild) |
| T3 | 3 Channel supplies the actor | Prompt-injected assistant or hostile client names a different actor in the body | Per-operation schemas close every `args` object — actor and server-derived identity fields are rejected as unknown members (`spec/schemas/ops/`, wrong-surface-args negatives in `spec/vectors/ops/`); the registry binds `allowed_actor_kinds` × surface × assurance per entry. Runtime channel binding is the K1 auth layer (`k1_no_authority`). | Schemas + rows enforced now; engine lands with K1 |
| T4 | 4 Aliases are not identities | Display-name spoof (`researcher`) misroutes authority or attribution | `assistant_alias_*` operations carry authority rows; schemas bind aliases to opaque immutable refs before work commits. | Rows + schemas now; resolution engine lands with K1 |
| T5 | 5 Arrival is not admission | Peer artifact, offer, or Akson outcome takes effect on receipt | No admission-free ingest operation exists in the K0 registry. Admission machinery: space handoff/attention (K2/K3); Akson admission via C4's inert idempotent staging (K6). | Deny-by-default now; engines land with K2/K3/K6 |
| T6 | 6 Presence is not work state | Forged liveness claim marks work complete | Completion is a durable fenced transition accepted by the controller; presence is expiring and advisory. K1's one-shot invocation records completion in the command transaction; leased completion is K2. | Lands with K1 (one-shot) / K2 (leases) |
| T7 | 7 Retry-safe mutations | Replay, or idempotency-key reuse with changed input, double-executes or corrupts state | The command envelope requires `meta.idempotency_key` on mutations and forbids `meta` on reads (closed read shape, R0 KENV-01); idempotency-domain digest vectors and replay negatives are delivered (`spec/vectors/envelope/`, `spec/vectors/ops/`). Retained-result/tombstone behavior is K1 (`k1_crash_matrix`: byte-identical replay). | Caps + vectors enforced now; engine lands with K1 |
| T8 | 8 Fenced execution | Zombie worker with a stale lease writes outputs after fencing | Worker-surface registry rows carry the attempt fence — "byom fence when bound" per A1's retargeting; the fencing engine is K2, with dual Kovee+byom fences on episodes proven at C3b. | Rows enforced now; engine lands with K2/C3b |
| T9 | 9 Durable before effect | Crash mid-effect double-executes an external action | Exact intent + authorization commit before execution; unknown non-idempotent outcomes become `ambiguous` and are never blindly retried; budget settlement stays conservative while ambiguous (C2). | Lands with K2 (contract frozen at C2) |
| T10 | 10 Disclosure is an action | Content reaches a model, connector, or peer without an exact manifest | Disclosure material is `action_scope` on the relevant registry rows. The K2 broker discloses/meters/audits but a same-UID `developer` assistant can bypass it — an honest limit; broker-only egress becomes an enforced claim only at K4. Peer disclosure binds the C4 surface (K6). | Rows now; audited K2 → enforced K4/K6 |
| T11 | 11 One semantic owner | A cached byom/Akson projection becomes a second writer | No mutation operation over cached views exists in the registry; the family-contract ownership table is pinned via `spec/family-lock.pin.json`; the `kovee-byom` adapter (K2) mirrors, never owns. | Deny-by-default now; adapter lands with K2 |
| T12 | 12 Intelligence cannot manufacture authority | Prompt-injected model output widens eligibility, budgets, or visibility | No registry operation accepts model output as an authority input; deterministic kernels own transitions. K1's acceptance assistant is deterministic by construction (no model dependency); `k1_no_authority` proves hostile contributions select/wake/widen nothing. | Rows now; engines land with K1 (K2 for attention/policy) |
| T13 | 13 Local-first | Forced hosted dependency exfiltrates personal data | K1 local Unix-socket binding with the same protocol and safety semantics; no hosted service required for personal use. | Lands with K1 |
| T14 | 14 Claims name their profile | Overclaimed confinement invites misplaced trust | The assurance profile is declared in every artifact (K0 scaffold: `developer` only); K1's `EnforcementEvidence` fields label confinement as unclaimed; §20.5 per-invocation posture reporting and fail-not-downgrade scheduling land at K4. | Declaration policy now; evidence fields K1; enforced claims K4 |
| T15 | 15 The graph is not truth | Hostile `supports`/`evaluates` relation passes as verification or acceptance | `relation_assert` rows grant attributed assertion only; verification, review, and acceptance are separate explicit operations (K2 commitments; byom-side `review_record` via C2). | Rows now; engines land with K2/C2 |
| T16 | 16 Attention is not obligation | An attention contract is abused to wake or act across an admission boundary | Attention grants bounded permission to consider; wake ownership is byom's (A4 Δ3): participants author `WakeIntent`, the byom kernel admits and allocates, Kovee only notifies and places. | Lands with K2 (C2/C3 contracts) |
| T17 | 17 Immutable context manifest | Ambient reads or smuggled context bypass audience authorization | `context_assembly_create` schemas + rows carry the `context_item_visibility` dependency; K1 builds the exact `ContextAssembly` engine with current-dependency and erasure recheck on every materialization/read. | Schemas + rows now; engine lands with K1 |
| T18 | 18 Branches preserve alternatives | Merge erases dissent or forges an accepted synthesis | No K0 operation can rewrite origin; the CAS branch/merge engine (fork/merge without rewriting, erasing dissent, or auto-accepting synthesis) is K2. | Deny-by-default now; engine lands with K2 |
| T19 | 19 Commitment precedes realization | Runtime work is created without terms, or a delivery self-accepts | Commitments bind need, parties, outcome, budget, disclosure, and deadline before invocation (K2); runtime success stays a delivery claim until the applicable reviewer accepts (byom review via C2). `invocation_create` cannot name a worker as requester or create a Commitment (registry constraint). | Constraint row now; engines land with K2/C2 |
| T20 | 20 Typed, attributable acceptance | Natural-language assent, a relation, or assistant self-assertion is counted as binding assent | Acceptance operations carry exact decision receipts in `action_scope` (registry); formation/assent machinery is K2, and cross-system seat sequences (fresh challenge, separately attributable seats) are frozen in the C2 bundle. | Rows now; engines land with K2/C2 |
| T21 | A5 (privacy) | Curious operator or peer confirms erased/low-entropy content by dictionary-hashing a retained plaintext `raw_sha256` | Amendment A5 removes retained plaintext hashes: content addressing uses the family digest classes (byom §14.2) — `local_erasure_safe` (HMAC under a per-object secret) for erasable plaintext, `ciphertext_public` for sealed blobs, `portable_public` only after explicit durable-identifier disclosure. Realized: C1 family vectors incl. forbidden-substitution negatives, re-derived in CI at the pinned lock row (`spec/family-lock.pin.json`); KG29 keeps `declared_raw_sha256`/`raw_sha256` a distinct upload-checksum field type never interchangeable with typed digests (`spec/schemas/ops/README.md`); the envelope digest vectors bind artifact authorization to the typed artifact-bytes digest (`spec/vectors/envelope/digest-typed-bytes-artifact.json`). | Digest classes + vectors enforced now (C1); K1 artifact store uses them; erasure choreography (backups, replicas) lands with K3 |

## What data cannot do (§20.3)

Inbound contributions, relations, application events, model output,
assistant claims, connector payloads, peer content, artifacts, skills, and
engrams are data. They cannot: select the authenticated actor; grant a
capability or membership; decide a gate or approve an effect; increase a
budget or deadline; widen a disclosure manifest; change an assistant or
security policy; mark a commitment fulfilled, a **byom** deliverable
accepted, or evidence verified; or wake an assistant across an admission
boundary. The enforcement is the worker's lack of ambient authority — not
a system prompt asking the model to behave.

## Assumptions and residual risks

- **The assurance profile is `developer` through K1.** Same-UID guardrails
  are never described as confinement (§4.14); a developer-profile
  assistant can bypass the (K2) broker, read what its UID can read, and
  reach the network. Confinement and broker-only egress become claims only
  at K4.
- **K0 enforces shape, not behavior.** Registry, schema, cap, and vector
  conformance is delivered and CI-checked; every row above marked "lands
  with …" is future work owned by the named milestone, and nothing in this
  document claims otherwise.
- **Operators see plaintext.** Team-mode encryption at rest is not
  operator-blind E2EE and is never marketed as such (§20.1). The A5 digest
  classes narrow what a curious operator (or a backup holder) can confirm
  after erasure; they do not hide live plaintext.
- **Byomd shares the machine in the personal profile.** The
  Kovee↔byom boundary is process- and identity-level, not hardware-level;
  its teeth are the C2/C3 contracts and C3a's negative tests proving that
  Kovee, MCP elicitation, a participant token, and candidate acceptance
  can each *not* perform `participant_admit` — no harness prompt
  substitutes for a candidate- or governance-surface operation.
- **The governance owner enum is closed at two arms.**
  `KoveeGovernanceOwnerBinding.governance_owner` is `byom | none` (A9): a
  governed scope is owned by byom or by nothing, and there is no third
  owner a confused-deputy path could name. The narrowing is machine-checked
  on both sides — byom's `kovee-governance-owner-binding-v2` schema and its
  negative vector, and `kovee-byom`'s `GOVERNANCE_OWNERS` constant. Only the
  `kovee-byom` adapter reaches governance; no other adapter crate exists
  (ADR-0001).
- **Rate limits, quotas, and DoS handling** (§20.2) are K3 team-mode work;
  the K0/K1 surface is a local socket.
- **Physical access, kernel compromise, and side channels** are out of
  scope, as in the akson model.

Review evidence: R0 covered the spec extraction (L1, L4); the K0 exit
criterion — no unresolved critical issue in the state-ownership and
threat-model reviews — binds this document.
