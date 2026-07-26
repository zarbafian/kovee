#!/usr/bin/env bash
# Proves the token rule instead of asserting it in a comment.
#
#   ./test-no-token-leak.sh
#
# A rule that is only stated in a comment is not enforced. This test plants a
# FAKE DigitalOcean token, exercises every fleet script's --dry-run path end to
# end, and then fails if the token's value appears in any byte of output or in
# any file the run generated.
#
# Four layers, weakest to strongest:
#
#   1  fail-closed        with no token file at all, provision.sh refuses and
#                         says where to put one — and never prompts
#   2  argv vs env        a stub `doctl` on PATH dumps its own /proc/self/cmdline
#                         and environ: the token must be in the environ and
#                         ABSENT from the cmdline (this is the `ps` property)
#   3  full dry run       all five scripts, every byte of stdout+stderr and
#                         every generated file grepped for the token value
#   4  never committed    the evidence directory is git-ignored, and no tracked
#                         file in harness/fleet/ contains a token shape
#
# No DigitalOcean API call is made and nothing is created: layer 3 runs in
# --dry-run and layer 2 runs against a stub binary.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
FAKE_TOKEN='dop_v1_f4k3t0k3nf0rl34kt3st1ngonly00000000000000000000000000000000000'
TMP="$(mktemp -d "${TMPDIR:-/tmp}/i2-token-leak.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() {
  PASS=$((PASS + 1))
  printf '  PASS  %s\n' "$1"
}
bad() {
  FAIL=$((FAIL + 1))
  printf '  FAIL  %s\n' "$1"
}

printf '\n== layer 1: fail closed with no token file, and never prompt\n'
OUT="$TMP/l1.txt"
if DO_TOKEN_FILE="$TMP/absent" FLEET_EVIDENCE_DIR="$TMP/ev1" \
  "$HERE/provision.sh" alice bob --dry-run >"$OUT" 2>&1; then
  bad "provision.sh succeeded with no token file (must fail closed)"
else
  if grep -q 'no DigitalOcean token at' "$OUT"; then
    ok "provision.sh fails closed and names the expected path"
  else
    bad "provision.sh failed but not with the fail-closed message"
  fi
fi
# "never prompt" — nothing was read from stdin, so a closed stdin changes nothing.
if DO_TOKEN_FILE="$TMP/absent" FLEET_EVIDENCE_DIR="$TMP/ev1b" \
  "$HERE/provision.sh" alice bob --dry-run </dev/null >/dev/null 2>&1; then
  bad "provision.sh succeeded with stdin closed and no token"
else
  ok "no prompt: behaviour is identical with stdin closed"
fi

printf '\n== layer 2: the token reaches doctl'"'"'s environment, never its argv\n'
install -m 0600 /dev/null "$TMP/do"
printf '%s\n' "$FAKE_TOKEN" >"$TMP/do"
mkdir -p "$TMP/bin"
cat >"$TMP/bin/doctl" <<'STUB'
#!/usr/bin/env bash
# Stub doctl: records how it was actually invoked. Makes no network call.
# /proc/$$ is THIS process (the stub); /proc/self inside the redirect would be
# `tr`, whose argv is not what we are asking about.
tr '\0' '\n' </proc/$$/cmdline >"$DOCTL_ARGV_DUMP"
tr '\0' '\n' </proc/$$/environ >"$DOCTL_ENV_DUMP"
printf 'stub\n'
STUB
chmod +x "$TMP/bin/doctl"

(
  # A subshell so PATH and the sourced library stay out of the test's own scope.
  export PATH="$TMP/bin:$PATH"
  export DOCTL_ARGV_DUMP="$TMP/argv.txt" DOCTL_ENV_DUMP="$TMP/environ.txt"
  export DO_TOKEN_FILE="$TMP/do" FLEET_EVIDENCE_DIR="$TMP/ev2" FLEET_DRY_RUN=0
  # shellcheck source=lib.sh
  source "$HERE/lib.sh"
  doctl_run compute droplet list --format ID,Name --no-header >"$TMP/l2.txt" 2>&1
)

# The dumps must exist and be non-empty, or every check below is vacuous.
if [[ -s $TMP/argv.txt && -s $TMP/environ.txt ]]; then
  ok "the stub recorded its own argv ($(wc -l <"$TMP/argv.txt") words) and environment ($(wc -l <"$TMP/environ.txt") entries)"
else
  bad "the stub doctl was never invoked — layer 2 would be vacuous"
fi
if grep -qF "$FAKE_TOKEN" "$TMP/environ.txt"; then
  ok "the token IS in doctl's environment (so doctl can authenticate)"
else
  bad "the token never reached doctl's environment"
fi
if grep -qF "$FAKE_TOKEN" "$TMP/argv.txt"; then
  bad "the token appears in doctl's argv — \`ps\` would show it"
else
  ok "the token is ABSENT from doctl's argv (\`ps\` cannot show it)"
fi
if grep -qF "$FAKE_TOKEN" "$TMP/l2.txt"; then
  bad "the token was echoed into the wrapper's own output"
else
  ok "the wrapper's output shows the token's PATH, not its value"
fi
# The token must be in exactly one variable, not scattered through the environment.
COUNT="$(grep -cF "$FAKE_TOKEN" "$TMP/environ.txt" || true)"
if [[ $COUNT == 1 ]]; then
  ok "exactly one environment entry carries the token (DIGITALOCEAN_ACCESS_TOKEN)"
else
  bad "$COUNT environment entries carry the token (expected exactly 1)"
fi

printf '\n== layer 3: full --dry-run of every script, every byte grepped\n'
EV="$TMP/evidence"
LOGS="$TMP/logs"
mkdir -p "$LOGS"
run_dry() { # <label> <script> <args…>
  local label="$1"
  shift
  DO_TOKEN_FILE="$TMP/do" FLEET_EVIDENCE_DIR="$EV" \
    "$HERE/$1" "${@:2}" --dry-run >"$LOGS/$label.txt" 2>&1
  local rc=$?
  printf '  ran   %-16s exit %s  (%s bytes of transcript)\n' \
    "$label" "$rc" "$(wc -c <"$LOGS/$label.txt")"
  return 0
}
run_dry provision provision.sh alice bob
run_dry serve-alice serve.sh alice
run_dry serve-bob serve.sh bob
run_dry introduce introduce.sh alice bob
for s in no-credentials round-trip late-result advisory-cancel binding-change \
  restore-lineage bench-matrix; do
  run_dry "scenario-$s" run-scenario.sh "$s"
done
run_dry crash-dispatch run-scenario.sh crash dispatch
run_dry crash-admission run-scenario.sh crash admission
run_dry teardown-keep teardown.sh --keep
run_dry teardown teardown.sh

# Every byte of every transcript.
HITS="$(grep -rlF "$FAKE_TOKEN" "$LOGS" || true)"
if [[ -z $HITS ]]; then
  ok "no transcript contains the token ($(find "$LOGS" -type f | wc -l) transcripts, $(cat "$LOGS"/* | wc -c) bytes)"
else
  bad "the token appears in: $HITS"
fi

# Every file the run generated — evidence, state, reports.
GEN="$(find "$EV" -type f 2>/dev/null | wc -l)"
HITS="$(grep -rlF "$FAKE_TOKEN" "$EV" 2>/dev/null || true)"
if [[ -z $HITS ]]; then
  ok "no generated file contains the token ($GEN files under evidence/)"
else
  bad "the token appears in generated file(s): $HITS"
fi

# And the whole scratch tree except the token file itself and layer 2's dumps,
# which exist precisely to prove the env/argv split.
HITS="$(grep -rlF "$FAKE_TOKEN" "$TMP" 2>/dev/null |
  grep -vxF "$TMP/do" | grep -vxF "$TMP/environ.txt" || true)"
if [[ -z $HITS ]]; then
  ok "the token exists nowhere in the scratch tree but the file it was written to"
else
  bad "stray copies of the token: $HITS"
fi

# The fail-closed message must name the path, never quote the value.
if grep -rqF "$FAKE_TOKEN" "$TMP/l1.txt" 2>/dev/null; then
  bad "the fail-closed path echoed a token value"
else
  ok "the fail-closed path echoes no token value"
fi

printf '\n== layer 4: never committed\n'
# A path INSIDE the directory: `evidence/` with a trailing slash matches
# directories, and check-ignore treats a nonexistent bare name as a file.
if git -C "$HERE" check-ignore -q evidence/fleet-state.json 2>/dev/null; then
  ok "harness/fleet/evidence/ is git-ignored (evidence and state cannot be committed)"
else
  bad "harness/fleet/evidence/ is NOT git-ignored"
fi
# No tracked file in this directory may contain anything token-shaped. The test's
# own fake token is the one allowed occurrence, and only in this file.
SHAPED="$(grep -rlE 'dop_v1_[A-Za-z0-9]{16,}' "$HERE" --include='*.sh' --include='*.md' 2>/dev/null |
  grep -vxF "$HERE/test-no-token-leak.sh" || true)"
if [[ -z $SHAPED ]]; then
  ok "no tracked fleet file contains a token-shaped string"
else
  bad "token-shaped string in: $SHAPED"
fi
# The only reader of the token file is the doctl wrapper pair in lib.sh.
# shellcheck disable=SC2016  # matching the literal shell text `<"$DO_TOKEN_FILE"`
READ_RE='<[[:space:]]*"\$DO_TOKEN_FILE"'
READERS="$(grep -cE "$READ_RE" "$HERE/lib.sh" || true)"
if [[ $READERS == 2 ]]; then
  ok "lib.sh reads the token file in exactly 2 places (doctl_run, doctl_out)"
else
  bad "lib.sh reads the token file in $READERS places (expected 2)"
fi
OTHER="$(grep -lE "$READ_RE" "$HERE"/*.sh |
  grep -vxF "$HERE/lib.sh" | grep -vxF "$HERE/test-no-token-leak.sh" || true)"
if [[ -z $OTHER ]]; then
  ok "no other fleet script reads the token file at all"
else
  bad "these scripts read the token file directly: $OTHER"
fi

printf '\n%s\n' "── $PASS passed, $FAIL failed"
((FAIL == 0)) || exit 1
printf 'token-leak test: the rule is enforced, not merely documented.\n'
