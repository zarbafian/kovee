# kovee-mcp — C3a participant tool schemas

The versioned MCP tool bundle for the C3a kovee-mcp **participant
profile** (`../../plan/sheets/C3a.md`, in the family plan repository): one
profile, 14 tools, bound to the K0-frozen registry's operation names.

## Try it

```sh
python3 mcp/check.py
```

Expected output ends with `OK` (meta-validation, sheet-list equality,
derivation fidelity, access markings, registry-surface rules, 4 vectors,
and a 10-mutation self-test).

A tool call looks like this (see `vectors/`):

```json
{
  "profile": "participant",
  "tool": "kovee_contribution_append",
  "input": {
    "space_id": "space-9",
    "branch_id": "branch-main",
    "expected_head_digest": "b1946ac9…2611184",
    "kind": "observation",
    "body_parts": [{ "media_type": "text/markdown", "text": "…" }]
  }
}
```

What you write is only the operation's own arguments. The plumbing — the
KCP envelope `{version, op, meta, realm_id, project_id, ext}` — is
derived by the bridge from protocol negotiation and the authenticated
participant channel, never supplied by the caller.

## Sheet-name → registry-name mappings

The C3a sheet lists ten kovee-mcp ops; the registry
(`spec/registry.json`) is the naming authority. Every mapping, explicit:

| C3a sheet op            | Registry operation(s)                                                                                                     |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `contribution_append`   | `contribution_append`                                                                                                      |
| `contribution_show`     | `contribution_show`                                                                                                        |
| `contribution_list`     | `contribution_list`                                                                                                        |
| `relation_add`          | `relation_assert` (the registry has no `relation_add`)                                                                     |
| `space_show`            | `space_show`                                                                                                               |
| `context_assembly_show` | `context_assembly_show`                                                                                                    |
| `artifact_upload`       | `artifact_upload_begin`, `artifact_upload_show`, `artifact_upload_credential`, `artifact_upload_finalize`, `artifact_upload_abort` — the registry decomposes the §10.10 upload flow; no single `artifact_upload` operation exists |
| `artifact_show`         | `artifact_show`                                                                                                            |
| `events_read`           | `events_read`                                                                                                              |
| `events_wait`           | `events_wait`                                                                                                              |

**Sheet ops with no registry counterpart: none.** Every sheet op maps to
at least one registry operation; nothing was invented. So 10 sheet ops →
14 registry ops → 14 tools (`kovee_<registry-op>`). The mapping is
const-pinned in the document (`sheet_ops`, and per-tool `sheet_op`) and
re-checked against an independent transcription in `check.py`.

## Derivation rule

For each tool: **input schema = the op request `args` object, minus
channel-derived fields**, with its `$defs` transitive closure copied
verbatim. Never tool arguments:

- the envelope `{version, op, meta, realm_id, project_id, ext}` — bridge
  and channel supply it (the participant-scoped binding pins `realm_id`
  and `project_id`; `meta` idempotency comes from channel state);
- `{attempt_id, fence_epoch}` — the §15.2 worker binding, forbidden on
  `external_client` (gap note KG14);
- `events_read`'s args-level `project_id` — the binding already pins the
  project scope;
- server-derived actor fields (gap note KG5).

Binding envelope: authenticated participant channel, `external_client`
surface only — zero worker- or operator-surface tools (deny-by-absence:
closed 14-name enum in the meta-schema, re-derived from the registry's
per-surface rows in `check.py`).

## Access markings

Reads are `safe_to_allow`; mutations (ops whose request requires `meta`,
R0 KENV-01) are `gated`. One recorded exception:
`kovee_artifact_upload_credential` is a non-mutating read but its result
carries a live storage credential (gap note KG29) — authority-bearing,
so it stays `gated`.

## Files

- `kovee-mcp.tools.json` — the tool bundle (a lock-manifest row per the
  C3a sheet).
- `mcp-tools.schema.json` — closed meta-schema: exact tool-name enum
  (14), closed profile object, const-pinned `sheet_ops` mapping.
- `check.py` — standalone check (rules JSON Schema cannot express:
  field subsets, access, registry surfaces, vectors, mutation
  self-test).
- `vectors/` — 1 valid + 3 negative tool-call shapes.

## Server

`crates/kovee-mcp` serves this bundle: an MCP stdio server over the
koveed client socket. The document is embedded at build time
(`include_str!`) and is the server's entire tool table — names, input
schemas, and gating flags are parsed from it, tools absent from it do
not exist, and every input is validated against its closed schema
before dispatch.

## Runner wiring

`run-checks.sh` runs `python3 mcp/check.py` as its own step (the wiring
deferred while K1 was in flight, now landed). `xcheck/run.py` and
`tscheck/check.mjs` stay untouched — they rederive `spec/vectors`, not
this bundle.

Both files here are now **digest-pinned** in the family lock
(`../../plan/family-lock.json`), as required rows
`kovee-mcp-tools-v0.1.0` (`kovee-mcp.tools.json`) and
`kovee-mcp-meta-schema` (`mcp-tools.schema.json`), both at release tag
`c3a-r1`. Editing either without re-pinning the manifest fails
`plan/check-dag.py`, which a pre-commit hook runs.

One gap, stated rather than papered over: `mcp/check.py` is a step in
`run-checks.sh` but **not** a job in `.github/workflows/ci.yml`, so the
bundle is gated locally and by the lock, not by CI.
