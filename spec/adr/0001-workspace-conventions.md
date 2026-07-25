# ADR-0001: Workspace conventions mirrored from akson

Status: accepted
Date: 2026-07-25

## Context

K0 requires a repo scaffold "mirroring akson M0" (`plan/sheets/K0.md`). Akson
is the family's proven repository shape: a Cargo workspace of small crates,
a pinned toolchain, `cargo-deny` dependency policy, CI that runs everything
`--locked` against a committed `Cargo.lock`, and golden vectors re-derived by
independent non-Rust checkers. Kovee's design fixes the crate list
(DESIGN.md §24) but names `kovee-sage` as the governance adapter; amendment
A1 (`design/2026-07-25-amendment-governance-owner.md`, plan D1) re-targets
governance to byom and the Byom Participation Protocol. The alternative —
inventing kovee-local conventions — was not seriously considered: family
repos should differ only where their designs differ.

## Decision

Kovee is a Cargo workspace (`resolver = "2"`) of fourteen crates under
`crates/`, adopting akson's conventions verbatim:

- **Members** (DESIGN.md §24 with A1's substitution): `kovee-core`,
  `kovee-store`, `kovee-auth`, `kovee-space`, `kovee-attention`,
  `kovee-commitment`, `kovee-runtime`, `kovee-effects`, `kovee-artifacts`,
  `kovee-bus`, **`kovee-byom`**, `kovee-akson`, and the binaries `koveed`
  and `kovee-cli` (binary name `kovee`). There is no `kovee-sage` crate and
  never will be; the `sage` arm of `KoveeGovernanceOwnerBinding` stays
  spec-only.
- **Toolchain**: `rust-toolchain.toml` pins 1.95.0 with rustfmt and clippy
  (akson's exact pin; installed and used for this scaffold's green build —
  no delta); `rust-version = "1.85"` in `[workspace.package]`.
- **Package fields**: workspace-inherited `version = "0.0.1"`,
  `edition = "2021"`, `license = "Apache-2.0"`, `repository`; every crate
  `publish = false` with `[lints] workspace = true`.
- **Lints**: `unsafe_code = "deny"` workspace-wide;
  `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic` at `warn`
  (CI escalates via `RUSTFLAGS: -D warnings`).
- **Dependency policy**: `deny.toml` copied from akson — same OSI license
  allowlist, `wildcards = "deny"`, `unknown-registry`/`unknown-git` denied,
  yanked advisories denied. External dependencies are pinned in
  `[workspace.dependencies]`; exact versions live in the committed
  `Cargo.lock` and CI runs `--locked`.
- **CI** (`.github/workflows/ci.yml`): `check` (fmt / clippy / test),
  `deny` (EmbarkStudios cargo-deny-action), `xcheck` (Python re-deriver over
  `spec/vectors`), `tscheck` (TypeScript re-deriver). The akson `proof` job
  (TLA+/Apalache) is added when kovee's first state machine lands, as a
  workspace conformance member plus a `proof/` Makefile job, per akson's
  pattern.

Deliberate deltas from akson, all scaffold-temporary:

1. `xcheck/run.py` validates only the vector envelope shape and exits 0 on
   an empty `spec/vectors` tree; akson's fails when zero vectors are found.
   The success-on-empty branch is removed with the first landed vector
   family (K0 spec half), restoring fail-closed behavior.
2. The `tscheck` job is a guarded placeholder (green with a note until
   `tscheck/package.json` exists).
3. `[workspace.dependencies]` carries only the internal path entries — the
   scaffold is dependency-free.
4. Akson's repo carries a `LICENSE` file; kovee does not yet. The manifests
   declare Apache-2.0 (akson's license, referenced by CONTRIBUTING.md);
   adding the file is tracked for the repository owner.

## Consequences

- Family contributors context-switch between akson and kovee without
  relearning layout, lint posture, or CI; drift from akson conventions is
  a deliberate, ADR-recorded act.
- `cargo test --workspace --locked` is green on the scaffold (K0
  verification line); every later milestone inherits `--locked` CI and the
  committed lockfile.
- Bounded contexts depend on `kovee-core` protocol types, never on each
  other's SQL tables (§24); the workspace-dependency table makes internal
  edges explicit and reviewable.
- The three scaffold-temporary deltas above must be paid down by the K0
  spec half (deltas 1–2) and the first external dependency (delta 3);
  leaving them past those points is a policy violation, not a default.
