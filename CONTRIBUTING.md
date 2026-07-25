# Contributing

Thanks for your interest. Kovee is early — the fastest way to help is to read
the [design](DESIGN.md) with its
[governance amendment](design/2026-07-25-amendment-governance-owner.md) and
the [milestone sheets](plan/sheets/), then pick up a milestone task or file a
focused issue.

## Ground rules

- **Standards first.** Don't add a Kovee-specific format when an established
  one fits. New wire fields need an ADR (`spec/adr/`).
- **Fail closed.** Missing, malformed, or downgraded state resolves to no
  effect — never a warning-and-continue path.
- **No hand-rolled crypto.** Cryptographic primitives come from the reviewed
  libraries pinned in the workspace; we test configuration, not math.
- **Vectors with code.** Anything canonicalized, digested, or signed lands
  with golden vectors under `spec/vectors/` that the independent `xcheck/`
  (Python) and `tscheck/` (TypeScript) implementations verify in CI.
- **State machines are modeled.** Protocol state machines land with TLA+
  specs and model-to-code conformance tests, akson-style: `cargo test
  --workspace` must fail when the Rust machines and the specs drift apart.
- **Hostile parsers are fuzzed.** Anything that parses untrusted bytes gets
  a fuzz target (cargo-fuzz, outside the normal workspace build).

## Development

~~~text
cargo build --workspace
cargo test --workspace
cargo fmt --all && cargo clippy --workspace --all-targets
cargo deny check          # licenses, advisories, sources
python3 xcheck/run.py spec/vectors
~~~

The toolchain is pinned in `rust-toolchain.toml`. CI runs all of the above
`--locked` against the committed `Cargo.lock`.

## Pull requests

- Keep PRs scoped to one milestone task where possible.
- Security-sensitive areas (crypto, identity, authorization, governance
  bindings, artifacts, effects) additionally require updated threat cases
  and vectors.
- By contributing you agree your contribution is licensed under the
  repository license (Apache-2.0).
