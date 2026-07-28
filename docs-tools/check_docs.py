#!/usr/bin/env python3
"""Fail when the website's claims stop matching the code.

The site marks every machine-checkable claim in the HTML itself, and this
script re-derives each one from the tree:

    <span data-claim="op_count">96</span>          a number or string from a source
    <code data-op="space_create">…</code>          an operation that must exist
    <strong data-absent="branch_">…</strong>       operations that must NOT exist
    <code data-generated="cli-usage">…</code>      a block copied from source
    <code data-observed="toolchain">…</code>       an observation with a source

It also regenerates docs/reference/index.html and fails if the committed page
differs, checks that every internal link and fragment resolves, and checks that
every page's markup is balanced.

    python3 docs-tools/check_docs.py

Run from anywhere; paths are resolved against the repository root.
"""

from __future__ import annotations

import html
import json
import pathlib
import re
import subprocess
import sys
from html.parser import HTMLParser

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
TOOLS = ROOT / "docs-tools"

VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)


# ------------------------------------------------------------- the sources --


def registry() -> dict:
    return json.loads((ROOT / "spec" / "registry.json").read_text())


def source(path: str) -> str:
    return (ROOT / path).read_text()


def const_array_len(path: str, name: str) -> int:
    """`pub const NAME: [&str; N] = [...]` → N."""
    m = re.search(rf"{name}: \[&str; (\d+)\]", source(path))
    if not m:
        sys.exit(f"check_docs: cannot find {name} in {path}")
    return int(m.group(1))


def cli_usage_lines() -> list[str]:
    m = re.search(r'const USAGE: &str = "(.*?)";', source("crates/kovee-cli/src/main.rs"), re.S)
    if not m:
        sys.exit("check_docs: cannot find the CLI USAGE const")
    return [ln.strip() for ln in m.group(1).split("\n")[1:] if ln.strip()]


def computed_claims() -> dict[str, str]:
    reg = registry()
    ops = {e["operation"] for e in reg["entries"]}

    advertised = re.search(
        r"K1_FEATURE_BUNDLES: \[&str; (\d+)\]", source("crates/koveed/src/handlers.rs")
    )
    if not advertised:
        sys.exit("check_docs: cannot find K1_FEATURE_BUNDLES")

    migrations = re.search(
        r"const MIGRATIONS: &\[\(i64, &str\)\] = &\[(.*?)\];",
        source("crates/kovee-store/src/schema.rs"),
        re.S,
    )
    if not migrations:
        sys.exit("check_docs: cannot find MIGRATIONS")

    gate = re.search(
        r'#\[cfg\(not\(feature = "daemon"\)\)\]\nconst EXPECTED_CASES: usize = (\d+);',
        source("crates/kovee-effects/tests/compile_gate.rs"),
    )
    if not gate:
        sys.exit("check_docs: cannot find EXPECTED_CASES")

    upload = re.search(
        r"MAX_UPLOAD_BYTES: u64 = (\d+) \* 1024 \* 1024;",
        source("crates/kovee-artifacts/src/lib.rs"),
    )
    reply = re.search(
        r"REPLY_MAX_BYTES: usize = (\d+) \* 1024;", source("crates/kovee-core/src/limits.rs")
    )
    page = re.search(
        r"PAGE_MAX_LIMIT: u64 = (\d+);", source("crates/kovee-core/src/limits.rs")
    )
    if not (upload and reply and page):
        sys.exit("check_docs: cannot find the §11.8 limit constants")

    mcp = json.loads((ROOT / "mcp" / "kovee-mcp.tools.json").read_text())
    mcp_tools = sum(len(p["tools"]) for p in mcp["profiles"].values())

    problem_kinds = re.search(
        r"ALL: \[ProblemKind; (\d+)\]", source("crates/kovee-core/src/problem.rs")
    )
    if not problem_kinds:
        sys.exit("check_docs: cannot find ProblemKind::ALL")

    members = re.search(r"members = \[(.*?)\]", source("Cargo.toml"), re.S)
    if not members:
        sys.exit("check_docs: cannot find the workspace members list")
    crate_count = len(re.findall(r'"[^"]+"', members.group(1)))

    toolchain = re.search(r'channel = "([^"]+)"', source("rust-toolchain.toml"))
    if not toolchain:
        sys.exit("check_docs: cannot find the pinned toolchain channel")

    return {
        "op_count": str(len(ops)),
        "entry_count": str(len(reg["entries"])),
        "bundle_count": str(len(reg["bundles"])),
        "registry_version": reg["registry_version"],
        "advertised_bundle_count": advertised.group(1),
        "gwb_built": str(reg["entry_counts"]["governed_work_binding_v1"]),
        "cli_verb_count": str(len(cli_usage_lines())),
        "cli_default_kind": cli_default("--kind"),
        "cli_default_visibility": cli_default("--visibility"),
        "cli_default_limit": cli_default_limit(),
        "schema_count": str(len(list((ROOT / "spec" / "schemas").rglob("*.schema.json")))),
        "vector_count": str(len(list((ROOT / "spec" / "vectors").rglob("*.json")))),
        "mcp_tool_count": str(mcp_tools),
        "problem_kind_count": problem_kinds.group(1),
        "crate_count": str(crate_count),
        "migration_count": str(len(re.findall(r"\(\d+, V\d+\)", migrations.group(1)))),
        "compile_gate_cases": gate.group(1),
        "max_upload_mib": upload.group(1),
        "reply_max_mib": str(int(reply.group(1)) // 1024),
        "events_limit_max": page.group(1),
        "lens_kind_count": str(const_array_len("crates/kovee-core/src/ops.rs", "LENS_KINDS")),
        "contribution_kind_count": str(
            const_array_len("crates/kovee-core/src/ops.rs", "CONTRIBUTION_KINDS")
        ),
        "relation_kind_count": str(
            const_array_len("crates/kovee-core/src/ops.rs", "RELATION_KINDS")
        ),
    }


def cli_default(flag: str) -> str:
    m = re.search(
        re.escape(f'opts.get("{flag}")') + r'\.unwrap_or\("([^"]+)"\)',
        source("crates/kovee-cli/src/main.rs"),
    )
    if not m:
        sys.exit(f"check_docs: cannot find the CLI default for {flag}")
    return m.group(1)


def cli_default_limit() -> str:
    m = re.search(
        r'opts\.get\("--limit"\)(?:.|\n)*?None => (\d+),', source("crates/kovee-cli/src/main.rs")
    )
    if not m:
        sys.exit("check_docs: cannot find the CLI default for --limit")
    return m.group(1)


def computed_observations() -> dict[str, str]:
    channel = re.search(r'channel = "([^"]+)"', source("rust-toolchain.toml")).group(1)
    return {"toolchain": f"cargo {channel} / rustc {channel}"}


# --------------------------------------------------------------- the pages --


class Page(HTMLParser):
    """Collects claims, ids, links — and checks the markup balances."""

    def __init__(self, path: pathlib.Path) -> None:
        super().__init__(convert_charrefs=False)
        self.path = path
        self.stack: list[tuple[str, int]] = []
        self.ids: set[str] = set()
        self.links: list[tuple[str, int]] = []
        self.claims: list[tuple[str, str, str, int]] = []  # kind, key, text, line
        self.absent: list[tuple[str, int]] = []
        self.ops: list[tuple[str, int]] = []
        self._capture: tuple[str, str, int] | None = None
        self._buf: list[str] = []
        self.feed(path.read_text())
        self.close()
        for name, line in self.stack:
            fail(f"{self.rel}: <{name}> opened at line {line} is never closed")

    @property
    def rel(self) -> str:
        return str(self.path.relative_to(ROOT))

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if "href" in a:
            self.links.append((a["href"], self.getpos()[0]))
        for kind in ("data-claim", "data-observed", "data-generated"):
            if kind in a:
                if self._capture:
                    fail(f"{self.rel}:{self.getpos()[0]}: nested {kind}")
                self._capture = (kind, a[kind], self.getpos()[0])
                self._buf = []
        if "data-absent" in a:
            self.absent.append((a["data-absent"], self.getpos()[0]))
        if "data-op" in a:
            self.ops.append((a["data-op"], self.getpos()[0]))
        if tag not in VOID and not self.get_starttag_text().endswith("/>"):
            self.stack.append((tag, self.getpos()[0]))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if self._capture:
            kind, key, line = self._capture
            self.claims.append((kind, key, "".join(self._buf).strip(), line))
            self._capture = None
        if tag in VOID:
            return
        if not self.stack:
            fail(f"{self.rel}:{self.getpos()[0]}: </{tag}> with nothing open")
            return
        name, line = self.stack.pop()
        if name != tag:
            fail(
                f"{self.rel}:{self.getpos()[0]}: </{tag}> closes <{name}> "
                f"opened at line {line}"
            )

    def handle_data(self, data):
        if self._capture:
            self._buf.append(data)

    def handle_entityref(self, name):
        if self._capture:
            self._buf.append(html.unescape(f"&{name};"))

    def handle_charref(self, name):
        if self._capture:
            self._buf.append(html.unescape(f"&#{name};"))


def check_links(pages: dict[pathlib.Path, Page]) -> None:
    ids = {p: page.ids for p, page in pages.items()}
    for path, page in pages.items():
        for href, line in page.links:
            if re.match(r"^(https?:|mailto:|data:)", href):
                continue
            target, _, frag = href.partition("#")
            if not target:
                if frag and frag not in page.ids:
                    fail(f"{page.rel}:{line}: #{frag} has no target on this page")
                continue
            if target.startswith("/"):
                dest = DOCS / target.lstrip("/")
            else:
                dest = (path.parent / target).resolve()
            if dest.is_dir() or target.endswith("/"):
                dest = dest / "index.html"
            if not dest.exists():
                fail(f"{page.rel}:{line}: {href} → missing {dest}")
                continue
            if frag:
                if dest not in ids:
                    if dest.suffix == ".html":
                        fail(f"{page.rel}:{line}: {href} → {dest} was not parsed")
                    continue
                if frag not in ids[dest]:
                    fail(f"{page.rel}:{line}: {href} → no id {frag!r} in {dest.name}")


def main() -> int:
    print("== docs: reference is generated from the spec")
    gen = subprocess.run(
        [sys.executable, str(TOOLS / "gen_reference.py"), "--check"],
        capture_output=True,
        text=True,
    )
    sys.stdout.write(gen.stdout)
    sys.stderr.write(gen.stderr)
    if gen.returncode != 0:
        fail("docs/reference/index.html is stale (see above)")

    pages = {}
    for path in sorted(DOCS.rglob("*.html")):
        pages[path.resolve()] = Page(path)
    print(f"== docs: parsed {len(pages)} pages")

    claims = computed_claims()
    observations = computed_observations()
    usage = "\n".join(cli_usage_lines())
    reg_ops = {e["operation"] for e in registry()["entries"]}

    seen_keys: set[str] = set()
    n_claims = 0
    for page in pages.values():
        for kind, key, text, line in page.claims:
            n_claims += 1
            if kind == "data-claim":
                if key not in claims:
                    fail(f"{page.rel}:{line}: unknown claim key {key!r}")
                    continue
                seen_keys.add(key)
                if text != claims[key]:
                    fail(
                        f"{page.rel}:{line}: claim {key} says {text!r}, "
                        f"the tree says {claims[key]!r}"
                    )
            elif kind == "data-observed":
                if key not in observations:
                    fail(f"{page.rel}:{line}: unknown observation key {key!r}")
                elif text != observations[key]:
                    fail(
                        f"{page.rel}:{line}: observation {key} says {text!r}, "
                        f"the tree says {observations[key]!r}"
                    )
            elif kind == "data-generated":
                if key != "cli-usage":
                    fail(f"{page.rel}:{line}: unknown generated block {key!r}")
                elif text != usage:
                    fail(f"{page.rel}:{line}: the CLI usage block no longer matches the source")

        for name, line in page.ops:
            if name not in reg_ops:
                fail(f"{page.rel}:{line}: operation {name!r} is not in the registry")

        for spec, line in page.absent:
            for prefix in spec.split(","):
                hits = sorted(o for o in reg_ops if o.startswith(prefix))
                if hits:
                    fail(
                        f"{page.rel}:{line}: the page says no {prefix}* operation exists, "
                        f"but the registry now has: {', '.join(hits)}"
                    )
    print(f"== docs: checked {n_claims} tagged claims against the tree")

    unused = sorted(set(claims) - seen_keys)
    if unused:
        print(f"   (claim keys defined but unused: {', '.join(unused)})")

    check_links(pages)
    print("== docs: internal links and fragments")

    for required in ("index.html", "404.html", "robots.txt", "sitemap.xml", ".nojekyll", "CNAME"):
        if not (DOCS / required).exists():
            fail(f"docs/{required} is missing")
    sitemap = (DOCS / "sitemap.xml").read_text()
    for section in ("guide", "concepts", "reference", "internals", "security"):
        page = DOCS / section / "index.html"
        if not page.exists():
            fail(f"docs/{section}/index.html is missing")
        elif f"https://kovee.cc/{section}/" not in sitemap:
            fail(f"docs/sitemap.xml does not list /{section}/")
    print("== docs: site files and sitemap")

    if failures:
        sys.stdout.flush()
        print(f"\ndocs check: FAIL ({len(failures)})", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("docs check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
