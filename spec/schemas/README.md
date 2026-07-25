# KCP envelope schemas — extraction notes (K0)

Five schemas pin the DESIGN.md §11 envelope surface, verbatim where the
design is exact and with every unpinned choice recorded here. Conventions
follow akson/byom: draft 2020-12, `$id` on every file, closed objects
(`additionalProperties: false` wherever `properties` appear), self-contained
(internal `$ref` only). Instances must pass strict I-JSON acceptance and the
§11.8 byte limits before schema validation. Byte caps a JSON Schema cannot
express are enforced by both rederivers' acceptance layers and pinned by
boundary + negative vectors (R0 KENV-04): the full family order (256 KiB
request / 1 MiB reply, UTF-8, token-order error classes, surrogates, depth
64, 65 536 nodes — family PROFILE section 1) plus the kovee contextual caps
(256 list items per request; 64 KiB inline event `payload` content — the
one envelope member carrying inline content in these five schemas).
Contribution inline content (also 64 KiB, §11.8) binds through
`contribution_append`'s own operation schema, which is remaining K0 work
(plan/sheets/K0.md); admission re-bounding of free text stays code-side.

| Schema | Pins | Source |
|---|---|---|
| `kcp-command.schema.json` | Command envelope + meta; `#/$defs/mutationCommand` requires meta | §11.2 |
| `kcp-command-result.schema.json` | ok/problem result union | §11.2 (problem: §11.7) |
| `kcp-event.schema.json` | Event envelope, `payload \| payload_ref` alternation, event-type shape | §11.3 |
| `kcp-problem.schema.json` | RFC 9457 problem, closed 21-kind `urn:kovee:error:<kind>` enum, per-kind status table | §11.7 |
| `kcp-hello.schema.json` | HelloRequest / HelloResult | §11.1 |

## Ambiguities and gaps in the pinned text, and what K0 did

1. **Reads and `meta`.** §11.2 renders `meta` unmarked in the Command
   struct, but the prose scopes the requirement to state-changing
   operations and says reads "do not carry an idempotency key" — while
   meta's own shape makes `idempotency_key` unconditional. Resolved: reads
   omit `meta` entirely (a read carrying meta would be forced to carry the
   very key it must not); the generic envelope leaves `meta` optional,
   mutations validate against `#/$defs/mutationCommand`, and reads against
   the closed `#/$defs/readCommand`, which has no `meta` member at all — a
   read carrying `meta.idempotency_key` fails (R0 KENV-01). Mirrors byom's
   request/mutationRequest split.
2. **Problem recovery members (normative).** §11.7 requires
   `stale-revision` to include the current visible revision,
   `cursor-expired` snapshot recovery data (§11.4: the oldest cursor and a
   snapshot boundary), and `rate-limited` bounded retry guidance, without
   naming members. Resolved (R0 KENV-02): the members are defined under
   reverse-domain `ext` branches, conditionally REQUIRED by kind in
   `kcp-problem.schema.json`:
   - `ext["dev.kovee.recovery.stale-revision"]` = `{current_revision}` (a
     safe non-negative integer);
   - `ext["dev.kovee.recovery.cursor-expired"]` = `{oldest_cursor,
     snapshot_boundary}` (opaque cursors, 1–4096 chars — the event_cursor
     ceiling of item 9);
   - `ext["dev.kovee.recovery.rate-limited"]` = `{retry_after_seconds}`
     (0–86 400; the 24-hour ceiling is the recorded extraction bound
     making the guidance "bounded").
   A problem of one of these kinds without its branch is invalid; other
   reverse-domain `ext` branches remain open and carry no authority.
3. **No separate `kind` member.** §11.7 puts the kind inside the `type`
   URN (`urn:kovee:error:<kind>`) and defines no standalone member (unlike
   byom §14.9). The schema enums the 21 exact URNs; `#/$defs/problemKind`
   exists for documentation/reuse, not as a wire field.
4. **`limits_digest` construction.** §11.1 names the field; §11.8 requires
   every security-sensitive `*_digest` to have a schema-registry entry with
   an exact projection, but DESIGN.md never defines the limits object or
   which of the two §11.8 constructions covers it. Gap recorded; K0 pins
   only the 64-hex value shape, and no vector binds the field to any
   derivation (R0 KENV-03 removed an invented `kcp-limits` binding).
   Assigning the limits object, projection, and construction is a spec
   revision with a real registry/schema entry.
5. **`payload_digest` construction.** Same gap as 4: §11.3 names the
   field, §11.8 defines the two digest types, but the event-payload digest
   is never assigned a construction/projection. K0 pins the value shape.
6. **Identifier alphabet.** §11.8 pins "Identifier: 128 bytes" and no
   alphabet. Pinned here as visible ASCII (`^[\x21-\x7e]{1,128}$`),
   mirroring the byom family convention so byte length and schema length
   coincide. A wider alphabet would be a spec revision, not a silent
   schema change. Both `implementation_version` fields use this identifier
   shape (R0 KENV-05): the earlier character-count bound admitted 128
   emoji — 512 UTF-8 bytes — past the 128-byte cap.
7. **Timestamp encoding.** §11.3/§11.1 (`occurred_at`, `server_time`) pin
   no encoding. Pinned as RFC 3339 date-time per I-JSON's (RFC 7493 §4.3)
   recommendation, which §11.8 adopts by requiring strict I-JSON.
   Semantic validity is enforced (R0 KENV-05): the pattern constrains
   every field to its real range and `format: date-time` requires real
   calendar dates (month lengths, leap years; second 60 admitted per the
   RFC 3339 leap-second grammar), checked by both rederivers — an
   impossible instant such as `2026-99-99T99:99:99+99:99` or
   `2026-02-30T12:00:00Z` fails.
8. **Event-type major version.** §11.3 shows only `.v1`-style majors;
   whether `.v0` exists is unstated. Pinned: majors start at 1.
9. **Cursor byte cap.** §11.3 makes cursors opaque and authenticated but
   pins no size. `event_cursor` takes a 4096-char ceiling (byom's
   source_cursor cap) so the field is bounded at all.
10. **`hello` negotiation shapes exist** (§11.1 defines both field lists),
    so no gap README entry for the shapes themselves — but §11.1 pins only
    the names; every type/bound choice on those fields is listed above
    (arrays capped at the §11.8 256-list-item limit, feature ids shaped
    like the §11.6 bundle names, `implementation` bounded by the §11.8
    display-name cap).
11. **`args` value space.** §11.2 writes `args` with no type. Pinned as a
    JSON object (every §11.6 operation takes named arguments); each
    operation's own schema restates and closes it.

Digest derivations (the `dev.kovee.canonical-object-digest.v1` and
`dev.kovee.typed-bytes-digest.v1` constructions of §11.8, including the
`kcp-command-idempotency` projection of §11.2) are pinned by the family
profile (`byom/family-vectors/PROFILE.md`, consumed via
`spec/family-lock.pin.json`) and re-derived by the golden vectors under
`../vectors/envelope/`.
