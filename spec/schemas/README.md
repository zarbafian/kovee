# KCP envelope schemas — extraction notes (K0)

Five schemas pin the DESIGN.md §11 envelope surface, verbatim where the
design is exact and with every unpinned choice recorded here. Conventions
follow akson/byom: draft 2020-12, `$id` on every file, closed objects
(`additionalProperties: false` wherever `properties` appear), self-contained
(internal `$ref` only). Instances must pass strict I-JSON acceptance and the
§11.8 byte limits before schema validation; byte caps a JSON Schema cannot
express (256 KiB request, 1 MiB reply, 64 KiB inline content, 256 list
items, admission re-bounding of free text) are enforced in code and covered
by acceptance vectors.

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
   very key it must not); the generic envelope leaves `meta` optional and
   mutations validate against `#/$defs/mutationCommand`. Mirrors byom's
   request/mutationRequest split.
2. **Problem "includes" data with no named members.** §11.7 says
   `stale-revision` "includes current visible revision", `cursor-expired`
   "includes … snapshot recovery data", `rate-limited` "includes bounded
   retry guidance", but names no members. Not invented: the problem object
   is closed over the RFC 9457 members plus the §11.9 `ext` mechanism,
   which carries that data until a spec revision names dedicated members.
3. **No separate `kind` member.** §11.7 puts the kind inside the `type`
   URN (`urn:kovee:error:<kind>`) and defines no standalone member (unlike
   byom §14.9). The schema enums the 21 exact URNs; `#/$defs/problemKind`
   exists for documentation/reuse, not as a wire field.
4. **`limits_digest` construction.** §11.1 names the field; §11.8 requires
   every security-sensitive `*_digest` to have a schema-registry entry with
   an exact projection, but DESIGN.md never defines the limits object or
   which of the two §11.8 constructions covers it. Gap recorded; K0 pins
   only the 64-hex value shape.
5. **`payload_digest` construction.** Same gap as 4: §11.3 names the
   field, §11.8 defines the two digest types, but the event-payload digest
   is never assigned a construction/projection. K0 pins the value shape.
6. **Identifier alphabet.** §11.8 pins "Identifier: 128 bytes" and no
   alphabet. Pinned here as visible ASCII (`^[\x21-\x7e]{1,128}$`),
   mirroring the byom family convention so byte length and schema length
   coincide. A wider alphabet would be a spec revision, not a silent
   schema change.
7. **Timestamp encoding.** §11.3/§11.1 (`occurred_at`, `server_time`) pin
   no encoding. Pinned as RFC 3339 date-time per I-JSON's (RFC 7493 §4.3)
   recommendation, which §11.8 adopts by requiring strict I-JSON.
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
