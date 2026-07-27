#!/usr/bin/env python3
"""Standalone C3a check for the kovee-mcp participant tool schemas.

Run:  python3 mcp/check.py

Asserts, against the committed repo state only (no network, no writes):

1. transcription — the C3a sheet's ten kovee-mcp ops (transcribed
   verbatim below) each map to registry operation(s); every mapped
   operation exists in spec/registry.json with an external_client row.
2. meta-validation — mcp/kovee-mcp.tools.json is strict I-JSON and
   validates against the closed meta-schema mcp/mcp-tools.schema.json.
3. sheet-list equality — the document's sheet_ops mapping equals the
   transcription, and the tool list is exactly its expansion in sheet
   order (names kovee_<op>, per-tool sheet_op consistent).
4. derivation fidelity — each tool's input schema is the op request
   `args` minus channel-derived fields: properties a subset with
   verbatim-equal bodies, required equal, $defs exactly the transitive
   closure copied verbatim, every $ref resolving locally; no envelope
   ({version, op, meta, realm_id, project_id, ext}) or channel-derived
   ({realm_id, project_id, attempt_id, fence_epoch, actor_ref,
   author_actor_ref}) field anywhere in properties.
5. read/mutation marking — mutation iff the committed request schema
   requires `meta` (R0 KENV-01); mutations gated, reads safe_to_allow,
   except the credential-minting artifact_upload_credential read which
   stays gated.
6. zero worker/operator-surface ops — every bound op has an
   external_client registry row; no operator-surface or worker-only
   operation is bound (deny-by-absence re-derived from the registry).
7. vectors — mcp/vectors/*.json tool-call shapes replay against the
   committed document (at least one valid and one negative).
8. self-test — ten in-memory document mutations must each be caught.

Standalone by design: it shares no code with xcheck/run.py or
tscheck/check.mjs, which rederive spec/vectors rather than this bundle.
run-checks.sh runs it as its own step; ci.yml does not (see mcp/README.md).
"""

import copy
import json
import re
import sys
from pathlib import Path

MCP_DIR = Path(__file__).resolve().parent
ROOT = MCP_DIR.parent
OPS_DIR = ROOT / "spec" / "schemas" / "ops"
REGISTRY = ROOT / "spec" / "registry.json"

# ---------------------------------------------------------- transcription --
# The C3a sheet's kovee-mcp participant list, transcribed verbatim from
# ../plan/sheets/C3a.md (closed — this exact list, nothing else), mapped
# onto the K0-frozen registry operation names:
#   - relation_add        -> relation_assert (the registry has no
#     relation_add; KG23 pins the assert payload)
#   - artifact_upload     -> the §10.10 upload flow, which the registry
#     decomposes into begin/show/credential/finalize/abort (registry
#     order; no single artifact_upload operation exists)
#   - every other sheet name is also the registry name (verified below).
# No sheet op is without a registry counterpart.
SHEET_TO_REGISTRY = {
    "contribution_append": ("contribution_append",),
    "contribution_show": ("contribution_show",),
    "contribution_list": ("contribution_list",),
    "relation_add": ("relation_assert",),
    "space_show": ("space_show",),
    "context_assembly_show": ("context_assembly_show",),
    "artifact_upload": ("artifact_upload_begin", "artifact_upload_show",
                        "artifact_upload_credential",
                        "artifact_upload_finalize", "artifact_upload_abort"),
    "artifact_show": ("artifact_show",),
    "events_read": ("events_read",),
    "events_wait": ("events_wait",),
}
EXPECTED_OPS = tuple(op for ops in SHEET_TO_REGISTRY.values() for op in ops)

# The §11.2 command envelope the kovee-mcp bridge derives (protocol
# version from negotiation; meta, realm and project scope from the
# authenticated participant channel): never tool args.
ENVELOPE_FIELDS = frozenset({"version", "op", "meta", "realm_id",
                             "project_id", "ext"})
# Channel-derived / surface-forbidden fields that may never appear in an
# input schema or a caller input: the worker binding {attempt_id,
# fence_epoch} (KG14: forbidden on external_client), the binding-pinned
# scope {realm_id, project_id} (covers events_read's args-level
# project_id), and the server-derived actor fields (KG5).
CHANNEL_DERIVED = frozenset({"realm_id", "project_id", "attempt_id",
                             "fence_epoch", "actor_ref", "author_actor_ref"})
# Reads whose result mints live authority (a fresh storage credential,
# KG29): gated despite being non-mutating.
CREDENTIAL_MINTING_READS = frozenset({"artifact_upload_credential"})

REF_RE = re.compile(r'"#/\$defs/([A-Za-z0-9_]+)"')


# ---------------------------------------------------------------- I-JSON ---

def _reject_dup_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate object key: {key!r}")
        out[key] = value
    return out


def _check_numbers(value):
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite number")
    if isinstance(value, int) and abs(value) > 9007199254740991:
        raise ValueError(f"integer outside I-JSON safe range: {value}")
    if isinstance(value, dict):
        for v in value.values():
            _check_numbers(v)
    elif isinstance(value, list):
        for v in value:
            _check_numbers(v)


def strict_parse(text):
    value = json.loads(text, object_pairs_hook=_reject_dup_pairs,
                       parse_constant=lambda c: (_ for _ in ()).throw(
                           ValueError(f"non-finite literal {c}")))
    _check_numbers(value)
    return value


# --------------------------------------------- mini draft-2020-12 subset ---
# Fallback validator when the jsonschema package is absent. Covers exactly
# the keywords used by mcp-tools.schema.json and the embedded input
# schemas; unknown keywords are annotations.

def _json_type(value):
    if isinstance(value, bool):
        return "boolean"
    if value is None:
        return "null"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def mini_valid(root, schema, value):
    if schema is True:
        return True
    if schema is False:
        return False
    ref = schema.get("$ref")
    if ref is not None:
        if not ref.startswith("#/$defs/"):
            return False
        target = root.get("$defs", {}).get(ref[len("#/$defs/"):])
        if target is None or not mini_valid(root, target, value):
            return False
    if "type" in schema:
        want = schema["type"]
        want = want if isinstance(want, list) else [want]
        got = _json_type(value)
        if got not in want and not (got == "integer" and "number" in want):
            return False
    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            return False
        if "minLength" in schema and len(value) < schema["minLength"]:
            return False
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            return False
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return False
        if schema.get("uniqueItems"):
            seen = [json.dumps(v, sort_keys=True) for v in value]
            if len(set(seen)) != len(seen):
                return False
        if "items" in schema:
            if not all(mini_valid(root, schema["items"], v) for v in value):
                return False
    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                return False
        props = schema.get("properties", {})
        for key, sub in props.items():
            if key in value and not mini_valid(root, sub, value[key]):
                return False
        if "propertyNames" in schema:
            names_schema = schema["propertyNames"]
            if not all(mini_valid(root, names_schema, k) for k in value):
                return False
        ap = schema.get("additionalProperties")
        if ap is not None:
            for key in value:
                if key not in props:
                    if ap is False:
                        return False
                    if ap is not True and not mini_valid(root, ap,
                                                         value[key]):
                        return False
    if "oneOf" in schema:
        hits = sum(1 for sub in schema["oneOf"]
                   if mini_valid(root, sub, value))
        if hits != 1:
            return False
    return True


try:
    import jsonschema as _jsonschema
except ImportError:  # pragma: no cover - environment-dependent
    _jsonschema = None


def validate(schema, value):
    if _jsonschema is not None:
        return _jsonschema.Draft202012Validator(schema).is_valid(value)
    return mini_valid(schema, schema, value)


# ------------------------------------------------------------ repo state ---

def load_registry_surfaces():
    reg = strict_parse(REGISTRY.read_text(encoding="utf-8"))
    surfaces = {}
    for entry in reg["entries"]:
        surfaces.setdefault(entry["operation"], set()).add(entry["surface"])
    return surfaces


def load_request_schema(op):
    path = OPS_DIR / f"{op.replace('_', '-')}-request.schema.json"
    if not path.is_file():
        return None
    return strict_parse(path.read_text(encoding="utf-8"))


def defs_closure(fragment, all_defs):
    seen = set()
    frontier = set(REF_RE.findall(json.dumps(fragment)))
    while frontier:
        name = frontier.pop()
        if name in seen or name not in all_defs:
            continue
        seen.add(name)
        frontier |= set(REF_RE.findall(json.dumps(all_defs[name])))
    return seen


# ---------------------------------------------------------- doc checking ---

def check_document(doc, meta_schema, surfaces, requests):
    """All document-dependent assertions; returns a list of failures."""
    errs = []

    def fail(msg):
        errs.append(msg)

    if not validate(meta_schema, doc):
        fail("kovee-mcp.tools.json does not validate against the closed "
             "meta-schema mcp/mcp-tools.schema.json")
        return errs

    # sheet-list equality with the recorded name mappings
    recorded = {k: tuple(v) for k, v in doc["sheet_ops"].items()}
    transcribed = dict(SHEET_TO_REGISTRY)
    if recorded != transcribed:
        fail(f"sheet_ops mapping != transcribed C3a mapping\n"
             f"      document:    {recorded}\n"
             f"      transcribed: {transcribed}")
    if tuple(doc["sheet_ops"]) != tuple(SHEET_TO_REGISTRY):
        fail("sheet_ops keys are not in C3a sheet order")

    tools = doc["profiles"]["participant"]["tools"]
    bound = tuple(t["op"] for t in tools)
    if bound != EXPECTED_OPS:
        fail(f"tool op list != expansion of the sheet mapping in sheet "
             f"order\n      bound:    {bound}\n"
             f"      expected: {EXPECTED_OPS}")
        return errs

    op_to_sheet = {op: sheet for sheet, ops in SHEET_TO_REGISTRY.items()
                   for op in ops}
    for tool in tools:
        _check_tool(tool, op_to_sheet, requests, fail)

    # zero worker/operator-surface ops (deny-by-absence, re-derived)
    operator_ops = {op for op, s in surfaces.items() if "operator" in s}
    worker_only = {op for op, s in surfaces.items() if s == {"worker"}}
    bound_set = set(bound)
    for op in bound_set:
        if "external_client" not in surfaces.get(op, set()):
            fail(f"{op}: no external_client row in the registry — the "
                 "participant binding cannot reach it")
    hits = bound_set & operator_ops
    if hits:
        fail(f"operator-surface operation(s) bound as tools: "
             f"{sorted(hits)}")
    hits = bound_set & worker_only
    if hits:
        fail(f"worker-only operation(s) bound as tools: {sorted(hits)}")
    return errs


def _check_tool(tool, op_to_sheet, requests, fail):
    op = tool["op"]
    name = tool["name"]
    if name != f"kovee_{op}":
        fail(f"{name}: tool name does not equal kovee_{op}")
    if tool["sheet_op"] != op_to_sheet.get(op):
        fail(f"{name}: sheet_op {tool['sheet_op']!r} != recorded mapping "
             f"{op_to_sheet.get(op)!r}")
    request = requests.get(op)
    if request is None:
        fail(f"{name}: no committed {op.replace('_', '-')}-request schema")
        return
    if tool["op_request_schema"] != f"{op.replace('_', '-')}-request":
        fail(f"{name}: op_request_schema is {tool['op_request_schema']!r}, "
             f"expected '{op.replace('_', '-')}-request'")

    # read/mutation marking (R0 KENV-01: mutations require meta; reads
    # have no meta member at all)
    top_props = set(request.get("properties", {}))
    top_req = set(request.get("required", []))
    if ("meta" in top_props) != ("meta" in top_req):
        fail(f"{name}: request schema meta presence/requirement disagree "
             "(KENV-01)")
    mutation = "meta" in top_req
    want_access = ("gated" if mutation or op in CREDENTIAL_MINTING_READS
                   else "safe_to_allow")
    if tool["access"] != want_access:
        fail(f"{name}: access is {tool['access']!r}, expected "
             f"{want_access!r} (mutations gated, reads safe_to_allow, "
             "credential-minting reads gated)")

    # derivation fidelity vs the op request args
    args = request["properties"]["args"]
    input_schema = tool["input_schema"]
    props = input_schema.get("properties", {})
    required = set(input_schema.get("required", []))
    smuggled = set(props) & (ENVELOPE_FIELDS | CHANNEL_DERIVED)
    if smuggled:
        fail(f"{name}: input schema carries envelope/channel-derived "
             f"field(s) {sorted(smuggled)} (the credential and bridge "
             "supply them, never the caller)")
    allowed = set(args.get("properties", {})) - CHANNEL_DERIVED
    invented = set(props) - allowed
    if invented:
        fail(f"{name}: input schema invents field(s) {sorted(invented)} "
             "not in the request args")
    want_required = set(args.get("required", [])) - CHANNEL_DERIVED
    if required != want_required:
        fail(f"{name}: required {sorted(required)} != request args "
             f"required {sorted(want_required)}")
    for key, body in props.items():
        if key in args.get("properties", {}) and \
                body != args["properties"][key]:
            fail(f"{name}: property {key!r} differs from the request args "
                 "schema (copies must be verbatim)")
    # $defs: exactly the transitive closure, copied verbatim, resolving
    req_defs = request.get("$defs", {})
    want_defs = defs_closure(props, req_defs)
    got_defs = input_schema.get("$defs", {})
    if set(got_defs) != want_defs:
        fail(f"{name}: $defs {sorted(got_defs)} != transitive closure "
             f"{sorted(want_defs)}")
    for dname, body in got_defs.items():
        if dname in req_defs and body != req_defs[dname]:
            fail(f"{name}: $defs/{dname} differs from the request schema "
                 "(copies must be verbatim)")
    for ref in REF_RE.findall(json.dumps(input_schema)):
        if ref not in got_defs:
            fail(f"{name}: unresolved $ref #/$defs/{ref}")


# --------------------------------------------------------------- vectors ---

def eval_tool_call(doc, call):
    """A tool call is valid only when the tool exists in exactly the named
    profile's closed tool list AND the input validates against the tool's
    embedded closed input schema AND carries no channel-derived field."""
    env = doc["profiles"].get(call.get("profile"))
    if env is None:
        return False
    tool = next((t for t in env["tools"] if t["name"] == call.get("tool")),
                None)
    if tool is None:
        return False
    value = call.get("input")
    if not validate(tool["input_schema"], value):
        return False
    if isinstance(value, dict) and set(value) & CHANNEL_DERIVED:
        return False
    return True


def run_vectors(doc, fail):
    vec_dir = MCP_DIR / "vectors"
    paths = sorted(vec_dir.glob("*.json"))
    if not paths:
        fail("no vectors found under mcp/vectors/")
        return 0, 0
    valid = negative = 0
    for path in paths:
        rel = f"vectors/{path.name}"
        try:
            vec = strict_parse(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            fail(f"{rel}: not strict I-JSON: {exc}")
            continue
        expected = vec["expected"]["valid"]
        got = eval_tool_call(doc, vec["input"]["tool_call"])
        if got != expected:
            fail(f"{rel}: expected valid={expected}, got {got}")
            continue
        if expected:
            valid += 1
        else:
            negative += 1
    if valid == 0:
        fail("vectors: no passing valid tool-call vector")
    if negative == 0:
        fail("vectors: no passing negative tool-call vector")
    return valid, negative


# -------------------------------------------------------------- self-test --

def _mutations(doc):
    """Yield (label, mutated-copy) pairs; every one must be caught."""

    def clone():
        return copy.deepcopy(doc)

    def tool(d, name):
        return next(t for t in d["profiles"]["participant"]["tools"]
                    if t["name"] == name)

    m = clone()
    tool(m, "kovee_contribution_append")["access"] = "safe_to_allow"
    yield "mutation ungated (contribution_append safe_to_allow)", m

    m = clone()
    tool(m, "kovee_artifact_upload_credential")["access"] = "safe_to_allow"
    yield "credential-minting read ungated", m

    m = clone()
    tool(m, "kovee_contribution_show")["input_schema"]["properties"][
        "actor_ref"] = {"$ref": "#/$defs/identifier"}
    yield "channel-derived field added (actor_ref)", m

    m = clone()
    t = tool(m, "kovee_relation_assert")
    t["input_schema"]["properties"]["attempt_id"] = {
        "$ref": "#/$defs/identifier"}
    yield "worker-binding field added (attempt_id)", m

    m = clone()
    t = tool(m, "kovee_events_read")
    t["input_schema"]["properties"]["project_id"] = {
        "$ref": "#/$defs/identifier"}
    yield "binding-pinned scope re-added (events_read project_id)", m

    m = clone()
    tool(m, "kovee_events_wait")["input_schema"]["properties"]["meta"] = {
        "type": "object"}
    yield "envelope field added (meta)", m

    m = clone()
    tool(m, "kovee_relation_assert")["input_schema"]["required"].remove(
        "expected_head_digest")
    yield "required arg dropped (expected_head_digest)", m

    m = clone()
    t = tool(m, "kovee_relation_assert")
    t["name"] = "kovee_relation_add"
    yield "tool renamed to the sheet name (kovee_relation_add)", m

    m = clone()
    m["sheet_ops"]["artifact_upload"] = [
        "artifact_upload_begin", "artifact_upload_show",
        "artifact_upload_credential", "artifact_upload_finalize"]
    yield "sheet mapping drift (upload abort dropped)", m

    m = clone()
    show = tool(m, "kovee_space_show")
    admin = copy.deepcopy(show)
    admin.update(name="kovee_space_participant_activate",
                 op="space_participant_activate",
                 op_request_schema="space-participant-activate-request")
    m["profiles"]["participant"]["tools"].append(admin)
    yield "operator-surface op bound (space_participant_activate)", m


def run_self_test(doc, meta_schema, surfaces, requests, fail):
    requests = dict(requests)
    requests.setdefault("space_participant_activate",
                        load_request_schema("space_participant_activate"))
    caught = total = 0
    for label, mutated in _mutations(doc):
        total += 1
        if check_document(mutated, meta_schema, surfaces, requests):
            caught += 1
        else:
            fail(f"self-test: mutation NOT caught: {label}")
    return caught, total


# ------------------------------------------------------------------ main ---

def main():
    failures = []

    def fail(msg):
        failures.append(msg)

    surfaces = load_registry_surfaces()
    for sheet_op, ops in SHEET_TO_REGISTRY.items():
        for op in ops:
            if op not in surfaces:
                fail(f"transcription: {sheet_op} -> {op}: not a registry "
                     "operation")
            elif "external_client" not in surfaces[op]:
                fail(f"transcription: {sheet_op} -> {op}: no "
                     "external_client registry row")

    try:
        meta_schema = strict_parse(
            (MCP_DIR / "mcp-tools.schema.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"meta-schema mcp/mcp-tools.schema.json unusable: {exc}")
        meta_schema = None
    try:
        doc = strict_parse(
            (MCP_DIR / "kovee-mcp.tools.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"kovee-mcp.tools.json unusable: {exc}")
        doc = None

    requests = {op: load_request_schema(op) for op in EXPECTED_OPS}
    doc_errs = []
    vec_counts = (0, 0)
    self_test = (0, 0)
    if not failures and doc is not None and meta_schema is not None:
        doc_errs = check_document(doc, meta_schema, surfaces, requests)
        failures.extend(doc_errs)
        vec_counts = run_vectors(doc, fail)
        if not doc_errs:
            self_test = run_self_test(doc, meta_schema, surfaces, requests,
                                      fail)

    validator = "jsonschema" if _jsonschema is not None else "mini"
    print(f"kovee-mcp C3a check ({validator} validator)")
    print(f"  sheet ops: {len(SHEET_TO_REGISTRY)} -> "
          f"{len(EXPECTED_OPS)} registry ops -> "
          f"{len(EXPECTED_OPS)} tools (participant profile only)")
    print(f"  vectors: {vec_counts[0]} valid + {vec_counts[1]} negative")
    print(f"  self-test: {self_test[0]}/{self_test[1]} mutations caught")
    if failures:
        print(f"FAIL ({len(failures)}):")
        for msg in failures:
            print(f"  - {msg}")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
