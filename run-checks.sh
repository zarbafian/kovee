#!/usr/bin/env bash
# Local, on-demand validation for kovee — the akson run-checks.sh pattern,
# mirroring .github/workflows/ci.yml job for job.
set -euo pipefail
cd "$(dirname "$0")"

echo "== cargo fmt"
cargo fmt --all --check

echo "== cargo clippy"
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --locked

echo "== cargo test"
cargo test --workspace --locked

echo "== mcp check (C3a tool bundle)"
python3 mcp/check.py

echo "== docs check (site claims vs. the tree)"
python3 docs-tools/check_docs.py

echo "== xcheck (Python independent rederiver)"
python3 xcheck/run.py spec/vectors

echo "== tscheck (TypeScript independent rederiver)"
node tscheck/check.mjs

echo "run-checks: OK"
