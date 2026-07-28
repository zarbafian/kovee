#!/usr/bin/env python3
"""Generate docs/reference/index.html from the pinned sources.

Nothing on the reference page is typed by hand: the operation list, the
per-operation authority metadata, the argument names, the bundle counts and
the CLI grammar are all read out of

    spec/registry.json                 the frozen operation registry
    spec/schemas/ops/*.schema.json     the per-operation command/result suite
    crates/kovee-cli/src/main.rs       the CLI's own USAGE const and verbs
    crates/koveed/src/handlers.rs      the bundles hello advertises

Run it after any change to those files:

    python3 docs-tools/gen_reference.py            # write the page
    python3 docs-tools/gen_reference.py --check    # fail if the page is stale

`docs-tools/check_docs.py` runs --check, so a source change that is not
reflected on the site turns run-checks.sh red.
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "spec" / "registry.json"
OPS_SCHEMA_DIR = ROOT / "spec" / "schemas" / "ops"
ENVELOPE_SCHEMA_DIR = ROOT / "spec" / "schemas"
CLI_MAIN = ROOT / "crates" / "kovee-cli" / "src" / "main.rs"
DAEMON_HANDLERS = ROOT / "crates" / "koveed" / "src" / "handlers.rs"
OUT = ROOT / "docs" / "reference" / "index.html"

GH = "https://github.com/zarbafian/kovee/blob/main"


# --------------------------------------------------------------- sources ---


def read_registry() -> dict:
    return json.loads(REGISTRY.read_text())


def read_op_schema(op: str, side: str) -> dict:
    path = OPS_SCHEMA_DIR / f"{op.replace('_', '-')}-{side}.schema.json"
    if not path.exists():
        sys.exit(f"gen_reference: missing schema {path}")
    return json.loads(path.read_text())


def read_cli_usage() -> list[str]:
    """The USAGE const from the CLI source, verbatim, minus the 'usage:' line."""
    src = CLI_MAIN.read_text()
    m = re.search(r'const USAGE: &str = "(.*?)";', src, re.S)
    if not m:
        sys.exit("gen_reference: could not find `const USAGE` in the CLI source")
    lines = m.group(1).split("\n")
    if lines[0].strip() != "usage:":
        sys.exit("gen_reference: USAGE no longer starts with 'usage:'")
    return [ln.strip() for ln in lines[1:] if ln.strip()]


def read_cli_verb_ops() -> dict[str, list[str]]:
    """Map each `fn cmd_*` in the CLI to the wire operations it sends.

    Derived, not asserted: every `read("op"` / `mutation("op"` string literal
    inside the function body, in call order, plus the ops of any helper the
    body calls.
    """
    src = CLI_MAIN.read_text()
    bodies: dict[str, str] = {}
    for m in re.finditer(r"\nfn (\w+)\([^)]*\)[^{]*\{", src):
        name = m.group(1)
        start = m.end()
        depth = 1
        i = start
        while i < len(src) and depth:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        bodies[name] = src[start:i]

    def ops_in(body: str, seen: set[str]) -> list[str]:
        """Wire ops in call order; a helper call expands where it is called."""
        found: list[str] = []
        pattern = r'(?:read|mutation)\(\s*"(\w+)"|\b(derive_branch_head)\('
        for m in re.finditer(pattern, body):
            if m.group(1):
                found.append(m.group(1))
            else:
                helper = m.group(2)
                if helper in bodies and helper not in seen:
                    found.extend(ops_in(bodies[helper], seen | {helper}))
        out: list[str] = []
        for op in found:
            if op not in out:
                out.append(op)
        return out

    return {
        name[len("cmd_") :]: ops_in(body, set())
        for name, body in bodies.items()
        if name.startswith("cmd_")
    }


def read_cli_defaults() -> dict[str, str]:
    """Flag defaults taken from the CLI source, not from prose."""
    src = CLI_MAIN.read_text()
    out = {}
    for flag in ("--visibility", "--kind"):
        m = re.search(
            re.escape(f'opts.get("{flag}")') + r'\.unwrap_or\("([^"]+)"\)', src
        )
        if not m:
            sys.exit(f"gen_reference: no default found for {flag}")
        out[flag] = m.group(1)
    m = re.search(r'opts\.get\("--limit"\)(?:.|\n)*?None => (\d+),', src)
    if not m:
        sys.exit("gen_reference: no default found for --limit")
    out["--limit"] = m.group(1)
    return out


def read_problem_kinds() -> list[tuple[str, str]]:
    """(urn token, status) for every §11.7 problem kind, from problem.rs."""
    src = (ROOT / "crates" / "kovee-core" / "src" / "problem.rs").read_text()
    tok = re.search(r"pub fn token\(self\) -> &'static str \{\s*match self \{(.*?)\n        \}", src, re.S)
    st = re.search(r"pub fn status\(self\) -> u16 \{\s*match self \{(.*?)\n        \}", src, re.S)
    if not (tok and st):
        sys.exit("gen_reference: cannot parse ProblemKind::token/status")
    tokens = dict(re.findall(r"ProblemKind::(\w+) => \"([^\"]+)\"", tok.group(1)))
    status: dict[str, str] = {}
    for arm in st.group(1).split(","):
        m = re.search(r"=>\s*(\d+)", arm)
        if not m:
            continue
        for variant in re.findall(r"ProblemKind::(\w+)", arm):
            status[variant] = m.group(1)
    order = re.search(r"ALL: \[ProblemKind; \d+\] = \[(.*?)\];", src, re.S)
    if not order:
        sys.exit("gen_reference: cannot parse ProblemKind::ALL")
    out = []
    for variant in re.findall(r"ProblemKind::(\w+)", order.group(1)):
        if variant not in tokens or variant not in status:
            sys.exit(f"gen_reference: ProblemKind::{variant} has no token or status")
        out.append((tokens[variant], status[variant]))
    return out


def read_mcp_tools() -> list[tuple[str, str, str]]:
    """(tool, operation, access) for every tool in the pinned MCP bundle."""
    doc = json.loads((ROOT / "mcp" / "kovee-mcp.tools.json").read_text())
    tools = []
    for profile in doc["profiles"].values():
        for tool in profile["tools"]:
            tools.append((tool["name"], tool["op"], tool["access"]))
    return tools


def read_advertised_bundles() -> list[str]:
    src = DAEMON_HANDLERS.read_text()
    m = re.search(r"K1_FEATURE_BUNDLES: \[&str; \d+\] = \[(.*?)\];", src, re.S)
    if not m:
        sys.exit("gen_reference: could not find K1_FEATURE_BUNDLES")
    return re.findall(r'"([^"]+)"', m.group(1))


# ---------------------------------------------------------------- render ---


def e(text: str) -> str:
    return html.escape(str(text), quote=True)


def anchor(op: str) -> str:
    return "op-" + op.replace("_", "-")


def op_block(op: str, entries: list[dict]) -> str:
    """One operation card. Everything in it comes from registry + schema."""
    req = read_op_schema(op, "request")
    res = read_op_schema(op, "result")
    args = req.get("properties", {}).get("args", {})
    arg_props = list(args.get("properties", {}).keys())
    arg_required = list(args.get("required", []))
    is_mutation = "meta" in req.get("required", [])
    surfaces = sorted({en["surface"] for en in entries})
    actors = sorted({a for en in entries for a in en["allowed_actor_kinds"]})
    scope = sorted({s for en in entries for s in en["action_scope"]})
    deps = sorted({d for en in entries for d in en["dependency_categories"]})
    cons = sorted({c for en in entries for c in en["constraints"]})
    assurance = sorted({en["assurance"] for en in entries})
    fence = sorted({en["fence"] for en in entries})
    offline = sorted({en["offline"] for en in entries})

    def arglist() -> str:
        if not arg_props:
            return "<em>none</em>"
        bits = []
        for name in arg_props:
            mark = "" if name in arg_required else "?"
            bits.append(f"<code>{e(name)}{mark}</code>")
        return " ".join(bits)

    dashed = op.replace("_", "-")
    rows = [
        ("Surface", ", ".join(f"<code>{e(s)}</code>" for s in surfaces)),
        ("Actor", ", ".join(e(a) for a in actors)),
        ("Kind", "mutation — <code>meta</code> required" if is_mutation else "query"),
        ("Args", arglist()),
        ("Scope", "; ".join(e(s) for s in scope)),
        ("Assurance", "; ".join(e(a) for a in assurance)),
        ("Dependencies", ", ".join(f"<code>{e(d)}</code>" for d in deps) or "<em>none</em>"),
        ("Constraints", "; ".join(e(c) for c in cons) or "<em>none</em>"),
        ("Fence", "; ".join(e(f) for f in fence)),
        ("Offline", ", ".join(f"<code>{e(o)}</code>" for o in offline)),
        (
            "Schemas",
            f'<a href="{GH}/spec/schemas/ops/{dashed}-request.schema.json">request</a> · '
            f'<a href="{GH}/spec/schemas/ops/{dashed}-result.schema.json">result</a>',
        ),
        ("Source", e(entries[0]["source"])),
    ]
    dl = "\n".join(f"      <dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
    meta = " ".join(
        f'<span class="b">{e(entries[0]["bundle"])}</span>'
        if i == 0
        else f"<span>{e(x)}</span>"
        for i, x in enumerate(["bundle"] + surfaces)
    )
    dual = (
        '<span title="one operation, two surfaces">dual-surface</span>'
        if len(entries) > 1
        else ""
    )
    title = e(res.get("title", ""))
    return f"""  <div class="op" id="{anchor(op)}" data-op="{e(op)}" data-bundle="{e(entries[0]['bundle'])}" data-surface="{e(' '.join(surfaces))}">
    <p class="opname"><a href="#{anchor(op)}">{e(op)}</a></p>
    <div class="opmeta">{meta} {dual}</div>
    <p class="opdesc">{title}</p>
    <dl>
{dl}
    </dl>
  </div>"""


def render() -> str:
    reg = read_registry()
    entries = reg["entries"]
    by_op: dict[str, list[dict]] = {}
    for en in entries:
        by_op.setdefault(en["operation"], []).append(en)
    bundles = reg["bundles"]
    advertised = read_advertised_bundles()
    usage = read_cli_usage()
    verb_ops = read_cli_verb_ops()
    defaults = read_cli_defaults()

    op_count = len(by_op)
    entry_count = len(entries)
    envelope_schemas = sorted(
        p.name for p in ENVELOPE_SCHEMA_DIR.glob("kcp-*.schema.json")
    )
    schema_count = len(list((ROOT / "spec" / "schemas").rglob("*.schema.json")))

    bundle_rows = []
    for b in bundles:
        ops_in_bundle = sorted(o for o, es in by_op.items() if es[0]["bundle"] == b)
        n_entries = sum(1 for en in entries if en["bundle"] == b)
        adv = (
            '<span class="yes">advertised</span>'
            if b in advertised
            else '<span class="no">not advertised</span>'
        )
        bundle_rows.append(
            f"    <tr><td><code>{e(b)}</code></td><td>{len(ops_in_bundle)}</td>"
            f"<td>{n_entries}</td><td>{adv}</td></tr>"
        )

    verb_rows = []
    verb_for_usage = {
        "hello": "hello",
        "init": "init",
        "space create": "space_create",
        "space show": "space_show",
        "space contribute": "space_contribute",
        "events": "events",
    }
    for line in usage:
        verb = None
        for prefix, fn in verb_for_usage.items():
            if line.startswith(f"kovee {prefix}") and (
                verb is None or len(prefix) > len(verb[0])
            ):
                verb = (prefix, fn)
        if verb is None:
            sys.exit(f"gen_reference: unmapped CLI usage line {line!r}")
        ops = verb_ops.get(verb[1], [])
        ops_html = ", ".join(
            f'<a href="#{anchor(o)}"><code>{e(o)}</code></a>'
            if o in by_op
            else f"<code>{e(o)}</code>"
            for o in ops
        )
        verb_rows.append(
            f"    <tr><td class=\"wrap\"><code>{e(line)}</code></td>"
            f"<td class=\"wrap\">{ops_html}</td></tr>"
        )

    op_sections = []
    for b in bundles:
        ops_in_bundle = sorted(o for o, es in by_op.items() if es[0]["bundle"] == b)
        blocks = "\n".join(op_block(o, by_op[o]) for o in ops_in_bundle)
        op_sections.append(
            f'<h3 id="bundle-{e(b.replace("_", "-"))}"><code>{e(b)}</code> '
            f"— {len(ops_in_bundle)} operations</h3>\n{blocks}"
        )

    problems = read_problem_kinds()
    problem_rows = "\n".join(
        f'    <tr><td><code>urn:kovee:error:{e(t)}</code></td><td>{e(s)}</td></tr>'
        for t, s in problems
    )
    mcp_tools = read_mcp_tools()
    gated_html = '<span class="no">gated</span>'
    mcp_rows = "\n".join(
        f'    <tr><td><code>{e(name)}</code></td>'
        f'<td><a href="#{anchor(op)}"><code>{e(op)}</code></a></td>'
        f'<td>{gated_html if access == "gated" else "safe to allow"}</td></tr>'
        for name, op, access in mcp_tools
    )

    envelope_rows = "\n".join(
        f'    <tr><td><code>{e(n)}</code></td>'
        f'<td><a href="{GH}/spec/schemas/{e(n)}">source</a></td></tr>'
        for n in envelope_schemas
    )

    nav_bundles = "\n".join(
        f'    <a href="#bundle-{e(b.replace("_", "-"))}"><code>{e(b)}</code></a>'
        for b in bundles
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reference — kovee</title>
<meta name="description" content="The kovee operation registry and CLI, generated from spec/registry.json, the per-operation schemas and the CLI source.">
<link rel="canonical" href="https://kovee.cc/reference/">
<meta property="og:type" content="article">
<meta property="og:title" content="Reference — kovee">
<meta property="og:description" content="{op_count} operations over {entry_count} registry entries, and the six shipped CLI verbs.">
<meta property="og:url" content="https://kovee.cc/reference/">
<meta property="og:site_name" content="kovee.">
<meta property="og:image" content="https://kovee.cc/og.png">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" type="image/svg+xml" href="../favicon.svg">
<script>
(function (root) {{
  try {{
    var saved = localStorage.getItem("kovee-theme");
    if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
  }} catch (e) {{}}
}})(document.documentElement);
</script>
<link rel="stylesheet" href="../assets/site.css">
</head>
<body>
<a class="skip" href="#top">Skip to content</a>

<div class="shell">
<aside class="rail">
  <div class="rail-head">
    <a class="rail-mark" href="../">kovee<span class="dot">.</span></a>
    <button class="themer" id="themer" type="button" aria-label="Switch colour theme">theme</button>
  </div>
  <p class="rail-sub">Reference</p>
  <nav id="nav" aria-label="Documentation">
    <div class="grp">Docs</div>
    <a href="../">Home</a>
    <a href="../guide/">Guide</a>
    <a href="../concepts/">Concepts</a>
    <a href="./" class="here" aria-current="page">Reference</a>
    <a href="../internals/">Internals</a>
    <a href="../security/">Security &amp; limits</a>
    <a href="https://github.com/zarbafian/kovee">GitHub</a>
    <div class="grp">On this page</div>
    <a href="#how">How to read this</a>
    <a href="#cli">CLI</a>
    <a href="#envelope">Envelope schemas</a>
    <a href="#problems">Problems</a>
    <a href="#mcp">MCP tools</a>
    <a href="#bundles">Bundles</a>
    <a href="#operations">Operations</a>
{nav_bundles}
  </nav>
</aside>

<main id="top">

<header class="hero">
  <p class="eyebrow">Reference · generated</p>
  <h1>Every operation kovee answers, and every CLI verb it ships.</h1>
  <p class="lede">
    The registry below is the authority on what exists: <strong data-claim="op_count">{op_count}</strong>
    operations over <strong data-claim="entry_count">{entry_count}</strong>
    <code>(operation, surface)</code> entries in
    <strong data-claim="bundle_count">{len(bundles)}</strong> bundles, at registry revision
    <code data-claim="registry_version">{e(reg['registry_version'])}</code>.
    If an operation is not on this page, kovee does not have it.
  </p>
  <div class="pills">
    <span class="pill on">{op_count} operations</span>
    <span class="pill on"><span data-claim="cli_verb_count">{len(usage)}</span> CLI verbs</span>
    <span class="pill on"><span data-claim="schema_count">{schema_count}</span> schemas</span>
    <span class="pill">pre-release</span>
  </div>
</header>

<div class="gen">
  This page is generated by <code>docs-tools/gen_reference.py</code> from
  <code>spec/registry.json</code>, <code>spec/schemas/</code>,
  <code>crates/kovee-cli/src/main.rs</code> and
  <code>crates/koveed/src/handlers.rs</code>. Editing it by hand is pointless —
  <code>docs-tools/check_docs.py</code> regenerates it and fails on any difference.
</div>

<h2 id="how">How to read this</h2>
<p>
  An entry is one <code>(operation, surface)</code> pair. A few operations are
  reachable from two surfaces with different authority, so there are more entries
  than operations. Each card carries the registry's own fields:
</p>
<div class="tw">
<table>
  <tr><th>Field</th><th>What it means</th></tr>
  <tr><td><code>Surface</code></td><td class="wrap">Which socket and channel may carry it: <code>external_client</code>, <code>worker</code>, or <code>operator</code>.</td></tr>
  <tr><td><code>Actor</code></td><td class="wrap">The actor kinds the registry admits for that surface.</td></tr>
  <tr><td><code>Kind</code></td><td class="wrap">Mutation or query. A mutation requires <code>meta</code> (<code>request_id</code> and <code>idempotency_key</code>); a query does not.</td></tr>
  <tr><td><code>Args</code></td><td class="wrap">Argument names taken from the operation's request schema. A trailing <code>?</code> marks an optional one.</td></tr>
  <tr><td><code>Dependencies</code></td><td class="wrap">The AuthorizationDependencySet categories re-read at authorization time; a change to any of them invalidates the decision.</td></tr>
  <tr><td><code>Fence</code></td><td class="wrap">The compare-and-swap or epoch the operation is bound to, where it has one.</td></tr>
  <tr><td><code>Offline</code></td><td class="wrap"><code>no</code>, <code>queueable</code>, or <code>cached_draft_only</code>.</td></tr>
</table>
</div>

<h2 id="cli" class="chapter-start">CLI</h2>
<p>
  The shipped <code>kovee</code> binary has
  <strong data-claim="cli_verb_count">{len(usage)}</strong> verbs. This is its own
  <code>USAGE</code> string, read out of
  <a href="{GH}/crates/kovee-cli/src/main.rs"><code>crates/kovee-cli/src/main.rs</code></a>:
</p>

<div class="cmd">
  <div class="cmd-head"><span class="who">kovee</span> — usage</div>
<pre><code data-generated="cli-usage">{e(chr(10).join(usage))}</code></pre>
</div>

<p>
  There is no <code>--help</code> flag: any unrecognised verb prints this block on
  stderr and exits <code>2</code>. Each verb is a thin client — it writes one JSON
  command line to the daemon socket and prints the <code>result</code> (or the
  <code>problem</code>) it reads back. These are the wire operations each verb
  actually sends, in order:
</p>

<div class="tw">
<table>
  <tr><th>Verb</th><th>Operations sent</th></tr>
{chr(10).join(verb_rows)}
</table>
</div>

<p>Defaults, taken from the same source:</p>
<ul>
  <li><code>--visibility</code> defaults to <code data-claim="cli_default_visibility">{e(defaults['--visibility'])}</code>.</li>
  <li><code>--kind</code> defaults to <code data-claim="cli_default_kind">{e(defaults['--kind'])}</code>.</li>
  <li><code>--limit</code> defaults to <code data-claim="cli_default_limit">{e(defaults['--limit'])}</code>.</li>
</ul>
<p>
  Two flags are accepted but not advertised in the usage block:
  <code>space create</code> and <code>space contribute</code> both take
  <code>--idempotency-key &lt;key&gt;</code>, which replaces the random key the CLI
  would otherwise mint — replay the same key and you get the stored result back
  rather than a second record.
</p>

<h2 id="envelope" class="chapter-start">Envelope schemas</h2>
<p>
  Five schemas describe the envelope every operation shares — the command, its
  result, an event, a problem, and the <code>hello</code> exchange. The
  per-operation schemas linked from each card below describe only the
  <code>args</code> and <code>result</code> payloads inside them.
</p>
<div class="tw">
<table>
  <tr><th>Schema</th><th></th></tr>
{envelope_rows}
</table>
</div>

<h2 id="problems" class="chapter-start">Problems</h2>
<p>
  A refused command comes back as
  <code>{{"outcome":"problem","problem":{{…}}}}</code> with a typed
  <code>type</code>, a title, and usually a detail line naming the rule that was
  broken. The kinds are closed — there are
  <strong data-claim="problem_kind_count">{len(problems)}</strong> of them, each with
  a pinned status:
</p>
<div class="tw">
<table>
  <tr><th>Type</th><th>Status</th></tr>
{problem_rows}
</table>
</div>

<h2 id="mcp" class="chapter-start">MCP tools</h2>
<p>
  <code>kovee-mcp</code> binds <strong data-claim="mcp_tool_count">{len(mcp_tools)}</strong>
  operations as MCP tools, all on the participant profile — no worker- or
  operator-surface operation is ever bound. Each tool's input schema is derived
  from the operation's request schema minus the fields the channel already fixes.
  Mutations are gated for your harness to prompt on; reads are marked safe to
  allow, with one exception whose result carries a live storage credential.
</p>
<div class="tw">
<table>
  <tr><th>Tool</th><th>Operation</th><th>Access</th></tr>
{mcp_rows}
</table>
</div>

<h2 id="bundles" class="chapter-start">Bundles</h2>
<p>
  A bundle is atomic: a client may assume every operation in it, or none. That is
  why an incomplete bundle is not advertised even when its operations dispatch —
  <code>hello</code> and <code>protocol_info</code> report exactly the bundles
  named <code>K1_FEATURE_BUNDLES</code> in
  <a href="{GH}/crates/koveed/src/handlers.rs"><code>crates/koveed/src/handlers.rs</code></a>.
</p>
<div class="tw">
<table>
  <tr><th>Bundle</th><th>Operations</th><th>Entries</th><th>In <code>hello</code></th></tr>
{chr(10).join(bundle_rows)}
</table>
</div>
<div class="note limit">
  <span class="tag">Limit</span>
  <p>
    <code>governed_work_binding_v1</code> is the incomplete one. Its operations
    dispatch over the socket, but a client that discovers capabilities the
    supported way — by reading <code>hello</code> — will not see it, and should
    not depend on it.
  </p>
</div>

<h2 id="operations" class="chapter-start">Operations</h2>
<div class="opfilter no-js-hide">
  <input id="opq" type="search" placeholder="filter operations…" aria-label="Filter operations">
  <span class="count" id="opcount"></span>
</div>
{chr(10).join(op_sections)}

<footer class="page">
  <p>
    Generated from the pinned spec at registry revision <code>{e(reg['registry_version'])}</code>.
    Source: <a href="https://github.com/zarbafian/kovee">github.com/zarbafian/kovee</a>.
    Pre-release, under active development — see <a href="../security/">security &amp; limits</a>.
  </p>
</footer>

</main>
</div>

<script>
(function () {{
  document.documentElement.classList.add("has-js");
  var t = document.getElementById("themer");
  if (t) {{
    t.addEventListener("click", function () {{
      var root = document.documentElement;
      var now = root.getAttribute("data-theme");
      if (!now) {{
        now = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
      }}
      var next = now === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try {{ localStorage.setItem("kovee-theme", next); }} catch (e) {{}}
    }});
  }}
  var q = document.getElementById("opq");
  var count = document.getElementById("opcount");
  var ops = Array.prototype.slice.call(document.querySelectorAll(".op"));
  function apply() {{
    var needle = (q.value || "").trim().toLowerCase();
    var shown = 0;
    ops.forEach(function (el) {{
      var hay = (el.getAttribute("data-op") + " " + el.getAttribute("data-bundle") + " " +
                 el.getAttribute("data-surface")).toLowerCase();
      var on = !needle || hay.indexOf(needle) !== -1;
      el.style.display = on ? "" : "none";
      if (on) shown++;
    }});
    document.querySelectorAll("h3[id^='bundle-']").forEach(function (h) {{
      var any = false, n = h.nextElementSibling;
      while (n && n.tagName === "DIV" && n.classList.contains("op")) {{
        if (n.style.display !== "none") any = true;
        n = n.nextElementSibling;
      }}
      h.style.display = any ? "" : "none";
    }});
    count.textContent = shown + " of " + ops.length;
  }}
  if (q) {{ q.addEventListener("input", apply); apply(); }}
}})();
</script>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if the page is stale")
    args = ap.parse_args()
    page = render()
    if args.check:
        if not OUT.exists():
            print(f"gen_reference: {OUT} does not exist", file=sys.stderr)
            return 1
        current = OUT.read_text()
        if current != page:
            print(
                "gen_reference: docs/reference/index.html is stale — the spec, the CLI\n"
                "  or the daemon's advertised bundles changed and the page did not.\n"
                "  Regenerate it with: python3 docs-tools/gen_reference.py",
                file=sys.stderr,
            )
            import difflib

            diff = list(
                difflib.unified_diff(
                    current.splitlines(),
                    page.splitlines(),
                    "docs/reference/index.html (committed)",
                    "docs/reference/index.html (generated)",
                    lineterm="",
                    n=1,
                )
            )
            for line in diff[:40]:
                print("  " + line, file=sys.stderr)
            if len(diff) > 40:
                print(f"  … {len(diff) - 40} more diff lines", file=sys.stderr)
            return 1
        print("gen_reference: docs/reference/index.html is current")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(page)
    print(f"gen_reference: wrote {OUT.relative_to(ROOT)} ({len(page):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
