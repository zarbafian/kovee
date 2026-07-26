#!/usr/bin/env bash
# Local, on-demand validation for kovee — the akson run-checks.sh pattern,
# mirroring .github/workflows/ci.yml job for job.
set -euo pipefail
cd "$(dirname "$0")"

# Heavy suites write large fixtures; this box's /tmp is a quota-limited
# tmpfs, so keep them on the data disk when it is available.
if [ -d /data/tmp ] && [ -z "${TMPDIR:-}" ]; then
  export TMPDIR=/data/tmp
fi

echo "== cargo fmt"
cargo fmt --all --check

echo "== cargo clippy"
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --locked

echo "== cargo test"
cargo test --workspace --locked

echo "== mcp check (C3a tool bundle)"
python3 mcp/check.py

echo "== xcheck (Python independent rederiver)"
python3 xcheck/run.py spec/vectors

echo "== tscheck (TypeScript independent rederiver)"
node tscheck/check.mjs

echo "run-checks: OK"
