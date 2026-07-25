#!/usr/bin/env python3
"""Independent cross-checker for the golden vectors under spec/vectors/.

Checks, in order:

1. every file in spec/schemas/ parses as strict I-JSON, follows the spec
   conventions (draft 2020-12, $id present, closed objects, no remote $ref,
   resolvable internal $refs, compilable patterns), and compiles — with
   `jsonschema` when installed, otherwise against this file's structural
   validator;
2. every vector under spec/vectors/ (one `family/name.json` per case, an
   object whose `name` matches its path and which carries `description`,
   `input`, and `expected`) passes its family checker: schema vectors match
   their expected verdict, raw/synthetic vectors match strict I-JSON +
   §11.8 limit acceptance, digest vectors re-derive the family-PROFILE
   canonical bytes (RFC 8785 JCS with the reserved $domain member injected
   at top level) and their SHA-256, plus the §11.8 framed typed-bytes
   digests.

An empty vector tree is a failure (akson behavior), as is a vector in a
family with no registered checker. This runner shares no code with the Rust
workspace: stdlib only, plus `jsonschema` when available.

Run: python3 xcheck/run.py spec/vectors
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

FAILURES: list[str] = []

SAFE_MAX = 2**53 - 1
MAX_REQUEST_BYTES = 262144  # DESIGN.md §11.8: request body at most 256 KiB
DRAFT = "https://json-schema.org/draft/2020-12/schema"


def fail(name: str, message: str) -> None:
    FAILURES.append(f"{name}: {message}")


# ---------------------------------------------------------------- I-JSON ----


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
    if isinstance(value, int) and abs(value) > SAFE_MAX:
        raise ValueError(f"unsafe integer: {value}")
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        raise ValueError("non-finite number")
    if isinstance(value, list):
        for item in value:
            _check_numbers(item)
    if isinstance(value, dict):
        for item in value.values():
            _check_numbers(item)


def strict_parse(text: str):
    """Strict I-JSON acceptance: duplicate keys, non-finite numbers, and
    unsafe integers fail closed (DESIGN.md §11.8)."""

    def _const(name):
        raise ValueError(f"non-finite number: {name}")

    value = json.loads(text, object_pairs_hook=_reject_dup_pairs, parse_constant=_const)
    _check_numbers(value)
    return value


def accept_request_bytes(raw: bytes):
    """Pre-schema acceptance of one request envelope's exact bytes."""
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError(f"request over 256 KiB: {len(raw)} bytes")
    return strict_parse(raw.decode("utf-8"))


# ------------------------------------------------------------------- JCS ----

_SHORT_ESCAPES = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: '\\"', 0x5C: "\\\\",
}


def _es_number(v: float) -> str:
    """ECMAScript Number::toString(10) for a finite double (RFC 8785)."""
    if v != v or v in (float("inf"), float("-inf")):
        raise ValueError("non-finite number in JCS input")
    if v == 0.0:
        return "0"
    sign = "-" if v < 0 else ""
    r = repr(abs(v))
    if "e" in r:
        mant, _, exp_s = r.partition("e")
        exp = int(exp_s)
    else:
        mant, exp = r, 0
    ip, _, fp = mant.partition(".")
    digits = (ip + fp).lstrip("0")
    stripped = digits.rstrip("0")
    trailing = len(digits) - len(stripped)
    k = len(stripped)
    n = k + trailing + exp - len(fp)
    s = stripped
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s
    else:
        e = n - 1
        out = s[0] + ("." + s[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[cp])
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value) -> bytes:
    """RFC 8785 JCS over the I-JSON value space (family PROFILE section 2):
    object keys sorted by UTF-16 code units, ES minimal number form."""
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, str):
        return _jcs_string(value).encode("utf-8")
    if isinstance(value, int):
        if abs(value) > SAFE_MAX:
            raise ValueError("unsafe integer")
        return str(value).encode("utf-8")
    if isinstance(value, float):
        return _es_number(value).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(jcs(v) for v in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return b"{" + b",".join(
            _jcs_string(k).encode("utf-8") + b":" + jcs(v) for k, v in items
        ) + b"}"
    raise TypeError(f"unsupported type: {type(value)}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------- kovee digest derivations ----

COD_DOMAIN = "dev.kovee.canonical-object-digest.v1"
TBD_DOMAIN = b"dev.kovee.typed-bytes-digest.v1"


def kovee_canonical_object(object_kind: str, schema_ref: str, projection) -> bytes:
    """DESIGN.md §11.8 CanonicalObjectDigest input bytes: the reserved
    $domain member injected at top level per the family PROFILE type-tag
    rule, then JCS. Fails closed on a $domain collision."""
    obj = {
        "protocol_major": 0,
        "object_kind": object_kind,
        "schema_ref": schema_ref,
        "projection": projection,
    }
    if "$domain" in obj:
        raise ValueError("object already carries a $domain member")
    return jcs({**obj, "$domain": COD_DOMAIN})


def _frame(b: bytes) -> bytes:
    return len(b).to_bytes(8, "big") + b


def kovee_typed_bytes_digest(domain: str, media_or_schema_ref: str, data: bytes) -> str:
    """DESIGN.md §11.8 TypedByteDigest: SHA-256 over uint64_be length-framed
    (domain-const, domain, "0", media_or_schema_ref, bytes)."""
    return sha256_hex(
        _frame(TBD_DOMAIN)
        + _frame(domain.encode("utf-8"))
        + _frame(b"0")
        + _frame(media_or_schema_ref.encode("utf-8"))
        + _frame(data)
    )


def derive_digest(d: dict) -> dict:
    kind = d["kind"]
    if kind == "dev.kovee.canonical-object-digest.v1":
        c = kovee_canonical_object(d["object_kind"], d["schema_ref"], d["projection"])
        return {"canonical": c.decode("utf-8"), "sha256_hex": sha256_hex(c)}
    if kind == "kcp-command-idempotency":
        if "projection" in d:
            projection = d["projection"]
        else:
            raw = d["raw_command"]
            projection = {k: raw[k] for k in d["projection_fields"] if k in raw}
        c = kovee_canonical_object("kcp-command-idempotency", d["schema_ref"], projection)
        return {"canonical": c.decode("utf-8"), "sha256_hex": sha256_hex(c)}
    if kind == "dev.kovee.typed-bytes-digest.v1":
        data = d["bytes_utf8"].encode("utf-8")
        return {"digest_hex": kovee_typed_bytes_digest(d["domain"], d["media_or_schema_ref"], data)}
    raise ValueError(f"unknown derivation kind {kind!r}")


def _primary_hex(result: dict) -> str:
    return result.get("sha256_hex") or result["digest_hex"]


# ------------------------------------------------- schema conventions -------


def _walk_dicts(node, exempt: bool = False):
    """Yield (dict, exempt) pairs; exempt marks if/then/else subtrees, whose
    property lists refine an already-closed parent object and deliberately
    do not repeat additionalProperties false."""
    if isinstance(node, dict):
        yield node, exempt
        for key, value in node.items():
            yield from _walk_dicts(value, exempt or key in ("if", "then", "else"))
    elif isinstance(node, list):
        for value in node:
            yield from _walk_dicts(value, exempt)


def _resolve_pointer(root, ref: str):
    if not ref.startswith("#"):
        raise KeyError(ref)
    node = root
    for part in [p for p in ref[1:].split("/") if p]:
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[part]
    return node


def convention_errors(schema: dict) -> list[str]:
    errs = []
    if schema.get("$schema") != DRAFT:
        errs.append(f"$schema must be {DRAFT}")
    if not schema.get("$id"):
        errs.append("$id is required")
    for node, exempt in _walk_dicts(schema):
        ref = node.get("$ref")
        if isinstance(ref, str):
            if not ref.startswith("#"):
                errs.append(f"remote $ref forbidden: {ref}")
            else:
                try:
                    _resolve_pointer(schema, ref)
                except KeyError:
                    errs.append(f"unresolvable $ref: {ref}")
        if not exempt and isinstance(node.get("properties"), dict):
            if node.get("additionalProperties") is not False:
                errs.append(
                    "object schema with properties must set additionalProperties "
                    f"false (near {sorted(node['properties'])[:3]})"
                )
        pattern = node.get("pattern")
        if isinstance(pattern, str):
            try:
                re.compile(pattern)
            except re.error as exc:
                errs.append(f"invalid pattern {pattern!r}: {exc}")
    return errs


# ---------------------------------------------------- structural validator --


def _is_type(instance, name: str) -> bool:
    if name == "object":
        return isinstance(instance, dict)
    if name == "array":
        return isinstance(instance, list)
    if name == "string":
        return isinstance(instance, str)
    if name == "boolean":
        return isinstance(instance, bool)
    if name == "null":
        return instance is None
    if name == "integer":
        if isinstance(instance, bool):
            return False
        return isinstance(instance, int) or (
            isinstance(instance, float) and instance.is_integer()
        )
    if name == "number":
        return not isinstance(instance, bool) and isinstance(instance, (int, float))
    return False


def _equal(a, b) -> bool:
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def mini_valid(root: dict, schema, instance) -> bool:
    """Just enough of draft 2020-12 for the keyword set these schemas use:
    boolean schemas, internal $ref, type, const, enum, pattern, min/max
    Length, minimum/maximum, required, properties, additionalProperties,
    propertyNames, items, minItems, maxItems, uniqueItems, oneOf, allOf,
    if/then/else."""
    if schema is True:
        return True
    if schema is False:
        return False

    ref = schema.get("$ref")
    if ref is not None:
        try:
            target = _resolve_pointer(root, ref)
        except KeyError:
            return False
        if not mini_valid(root, target, instance):
            return False

    typ = schema.get("type")
    if typ is not None:
        names = typ if isinstance(typ, list) else [typ]
        if not any(_is_type(instance, n) for n in names):
            return False

    if "const" in schema and not _equal(instance, schema["const"]):
        return False
    if "enum" in schema and not any(_equal(instance, e) for e in schema["enum"]):
        return False

    for sub in schema.get("allOf", []):
        if not mini_valid(root, sub, instance):
            return False
    if "oneOf" in schema:
        matches = sum(1 for sub in schema["oneOf"] if mini_valid(root, sub, instance))
        if matches != 1:
            return False
    if "if" in schema:
        if mini_valid(root, schema["if"], instance):
            if "then" in schema and not mini_valid(root, schema["then"], instance):
                return False
        elif "else" in schema and not mini_valid(root, schema["else"], instance):
            return False

    if isinstance(instance, str):
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            return False
        if "minLength" in schema and len(instance) < schema["minLength"]:
            return False
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            return False

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            return False
        if "maximum" in schema and instance > schema["maximum"]:
            return False

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                return False
        props = schema.get("properties", {})
        for key, sub in props.items():
            if key in instance and not mini_valid(root, sub, instance[key]):
                return False
        if "propertyNames" in schema:
            for key in instance:
                if not mini_valid(root, schema["propertyNames"], key):
                    return False
        addl = schema.get("additionalProperties")
        if addl is False:
            if any(k not in props for k in instance):
                return False
        elif isinstance(addl, dict):
            for k, v in instance.items():
                if k not in props and not mini_valid(root, addl, v):
                    return False

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            return False
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            return False
        if schema.get("uniqueItems"):
            seen = [json.dumps(i, sort_keys=True) for i in instance]
            if len(set(seen)) != len(seen):
                return False
        items = schema.get("items")
        if items is not None:
            if not all(mini_valid(root, items, i) for i in instance):
                return False

    return True


# ---------------------------------------------------------------- runner ----


class Runner:
    def __init__(self, vectors_root: pathlib.Path):
        self.vectors_root = vectors_root
        self.schemas_dir = vectors_root.parent / "schemas"
        self.schemas: dict[str, dict] = {}
        self.counts = {"schema-valid": 0, "schema-invalid": 0, "acceptance": 0, "digest": 0}
        try:
            import jsonschema  # noqa: F401

            self.jsonschema = jsonschema
        except ImportError:
            self.jsonschema = None

    # -- schemas --

    def load_schemas(self) -> int:
        paths = sorted(self.schemas_dir.glob("*.schema.json"))
        if not paths:
            fail(str(self.schemas_dir), "no schemas found")
            return 0
        for path in paths:
            name = path.name.removesuffix(".schema.json")
            try:
                schema = strict_parse(path.read_text(encoding="utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                fail(path.name, f"not strict I-JSON: {exc}")
                continue
            for err in convention_errors(schema):
                fail(path.name, err)
            if self.jsonschema is not None:
                try:
                    cls = self.jsonschema.validators.validator_for(schema)
                    cls.check_schema(schema)
                except Exception as exc:
                    fail(path.name, f"does not compile: {exc}")
                    continue
            self.schemas[name] = schema
        return len(paths)

    def validate(self, schema_name: str, ref: str | None, value) -> bool:
        schema = self.schemas[schema_name]
        if self.jsonschema is not None:
            target = schema if ref is None else {"$ref": ref, "$defs": schema["$defs"]}
            return self.jsonschema.Draft202012Validator(target).is_valid(value)
        if ref is None:
            return mini_valid(schema, schema, value)
        return mini_valid(schema, _resolve_pointer(schema, ref), value)

    # -- envelope family --

    def check_envelope(self, name: str, case: dict) -> None:
        inp = case.get("input", {})
        expected = case.get("expected", {})
        if "schema" in inp:
            self._check_schema_vector(name, inp, expected)
        elif "raw" in inp or "synthetic" in inp:
            self._check_acceptance_vector(name, inp, expected)
        elif "derivations" in inp:
            self._check_digest_vector(name, inp, expected)
        else:
            fail(name, f"unknown vector kind (input keys {sorted(inp)})")

    def _check_schema_vector(self, name, inp, expected):
        schema_name = inp["schema"]
        if schema_name not in self.schemas:
            fail(name, f"references unknown schema {schema_name!r}")
            return
        verdict = self.validate(schema_name, inp.get("ref"), inp["value"])
        if verdict != expected.get("valid"):
            fail(name, f"expected valid={expected.get('valid')}, got {verdict}")
            return
        self.counts["schema-valid" if verdict else "schema-invalid"] += 1

    def _check_acceptance_vector(self, name, inp, expected):
        if "raw" in inp:
            raw = inp["raw"].encode("utf-8")
        else:
            if inp["synthetic"] != "oversized_request":
                fail(name, f"unknown synthetic kind {inp['synthetic']!r}")
                return
            prefix = '{"version":"0.1","op":"diagnose","realm_id":"realm-0001","args":{"pad":"'
            suffix = '"}}'
            pad = inp["target_bytes"] - len(prefix) - len(suffix)
            if pad < 0:
                fail(name, "target_bytes too small to synthesize")
                return
            raw = (prefix + "a" * pad + suffix).encode("utf-8")
            if len(raw) != inp["target_bytes"]:
                fail(name, f"synthesized {len(raw)} bytes, wanted {inp['target_bytes']}")
                return
        try:
            accept_request_bytes(raw)
            verdict = True
        except ValueError:
            verdict = False
        if verdict != expected.get("valid"):
            fail(name, f"expected valid={expected.get('valid')}, got {verdict}")
            return
        self.counts["acceptance"] += 1

    def _check_digest_vector(self, name, inp, expected):
        try:
            results = [derive_digest(d) for d in inp["derivations"]]
        except (KeyError, TypeError, ValueError) as exc:
            fail(name, f"derivation failed: {exc}")
            return
        ok = True
        if results != expected.get("results"):
            fail(
                name,
                "derived results differ\n"
                f"      derived:  {results}\n"
                f"      expected: {expected.get('results')}",
            )
            ok = False
        relation = expected.get("relation")
        if relation:
            hexes = [_primary_hex(r) for r in results]
            if relation == "equal":
                if len(set(hexes)) != 1:
                    fail(name, f"expected equal digests, got {hexes}")
                    ok = False
            elif relation == "distinct":
                if len(set(hexes)) != len(hexes):
                    fail(name, f"expected pairwise-distinct digests, got {hexes}")
                    ok = False
            else:
                fail(name, f"unknown relation {relation!r}")
                ok = False
        if ok:
            self.counts["digest"] += 1

    # -- vectors --

    def check_shape(self, path: pathlib.Path):
        """Validate the vector-file envelope; return the parsed case or None."""
        try:
            case = strict_parse(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            fail(str(path), f"not strict I-JSON: {exc}")
            return None
        if not isinstance(case, dict):
            fail(str(path), "vector root must be a JSON object")
            return None
        family = path.relative_to(self.vectors_root).parts[0]
        expected_name = f"{family}/{path.stem}"
        if case.get("name") != expected_name:
            fail(str(path), f"vector name {case.get('name')!r} != {expected_name!r}")
        if not isinstance(case.get("description"), str):
            fail(str(path), "missing or non-string 'description'")
        for key in ("input", "expected"):
            if not isinstance(case.get(key), dict):
                fail(str(path), f"missing or non-object {key!r}")
                return None
        return case

    def run(self) -> int:
        checkers = {"envelope": self.check_envelope}
        if self.jsonschema is not None:
            from importlib.metadata import version

            backend = f"jsonschema {version('jsonschema')}"
        else:
            backend = "structural validator (jsonschema not installed)"
        n_schemas = self.load_schemas()
        count = 0
        for path in sorted(self.vectors_root.rglob("*.json")):
            if path.parent == self.vectors_root:
                fail(str(path), "vectors live under a family directory, not the root")
                continue
            case = self.check_shape(path)
            if case is None:
                continue
            family = path.relative_to(self.vectors_root).parts[0]
            checker = checkers.get(family)
            if checker is None:
                fail(str(path), f"no checker registered for family {family!r}")
                continue
            checker(case.get("name", str(path)), case)
            count += 1

        print(f"xcheck: schemas {len(self.schemas)}/{n_schemas} compiled ({backend})")
        if FAILURES:
            print(f"xcheck: {len(FAILURES)} failure(s) across {count} vector(s)")
            for f in FAILURES:
                print(f"  FAIL {f}")
            return 1
        if count == 0:
            # Fail closed on an empty tree (akson behavior; the K0 scaffold's
            # success-on-empty exception ended with the first vector family).
            print(f"xcheck: no vectors under {self.vectors_root} — FAIL")
            return 1
        c = self.counts
        print(
            f"xcheck: {count} vectors OK — "
            f"{c['schema-valid']} schema-valid, {c['schema-invalid']} schema-invalid, "
            f"{c['acceptance']} acceptance, {c['digest']} digest"
        )
        return 0


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "spec/vectors")
    if not root.is_dir():
        print(f"xcheck: vectors root {root} does not exist")
        return 1
    return Runner(root).run()


if __name__ == "__main__":
    sys.exit(main())
