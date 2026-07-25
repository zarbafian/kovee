#!/usr/bin/env python3
"""Independent cross-checker for the golden vectors under spec/vectors/.

K0 scaffold placeholder: validates the vector-file envelope shape (mirroring
akson's `family/name.json` layout — a JSON object whose `name` matches its
path and which carries `description`, `input`, and `expected`) and exits 0
when no vectors exist yet. Once the first K0 vectors land, per-family
re-derivation checkers register in CHECKERS (stdlib-free-of-workspace-code,
like akson's xcheck) and the empty-tree success flips to a failure so a
vectorless repo can never pass as "checked".

Run: python3 xcheck/run.py spec/vectors
"""

import json
import pathlib
import sys

FAILURES = []

# family -> checker(name, case). Empty until the K0 vectors land; a vector in
# a family with no registered checker is a failure, never a skip.
CHECKERS = {}


def fail(name: str, message: str) -> None:
    FAILURES.append(f"{name}: {message}")


def check_shape(path: pathlib.Path, root: pathlib.Path):
    """Validate the vector envelope; return the parsed case or None."""
    try:
        case = json.loads(path.read_text())
    except (ValueError, UnicodeDecodeError) as exc:
        fail(str(path), f"not valid JSON: {exc}")
        return None
    if not isinstance(case, dict):
        fail(str(path), "vector root must be a JSON object")
        return None
    family = path.relative_to(root).parts[0]
    expected_name = f"{family}/{path.stem}"
    if case.get("name") != expected_name:
        fail(str(path), f"vector name {case.get('name')!r} != {expected_name!r}")
    if not isinstance(case.get("description"), str):
        fail(str(path), "missing or non-string 'description'")
    for key in ("input", "expected"):
        if not isinstance(case.get(key), dict):
            fail(str(path), f"missing or non-object {key!r}")
    return case


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "spec/vectors")
    if not root.is_dir():
        print(f"xcheck: vectors root {root} does not exist")
        return 1
    count = 0
    for path in sorted(root.rglob("*.json")):
        if path.parent == root:
            fail(str(path), "vectors live under a family directory, not the root")
            continue
        case = check_shape(path, root)
        if case is None:
            continue
        family = path.relative_to(root).parts[0]
        checker = CHECKERS.get(family)
        if checker is None:
            fail(str(path), f"no checker registered for family {family!r}")
            continue
        checker(case.get("name", str(path)), case)
        count += 1

    if FAILURES:
        print(f"xcheck: {len(FAILURES)} failure(s) across {count} vector(s)")
        for f in FAILURES:
            print(f"  FAIL {f}")
        return 1
    if count == 0:
        # Scaffold-only exception: no vectors exist yet. This branch becomes
        # `return 1` (akson behavior) with the first landed vector family.
        print(f"xcheck: no vectors under {root} yet (K0 scaffold) — OK")
        return 0
    print(f"xcheck: {count} vectors OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
