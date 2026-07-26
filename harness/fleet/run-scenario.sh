#!/usr/bin/env bash
# I2 scenario runner — one of the sheet's test ids per invocation.
#
#   ./run-scenario.sh no-credentials   [--dry-run]     → i2-no-credentials
#   ./run-scenario.sh round-trip       [--dry-run]     → i2-round-trip
#   ./run-scenario.sh late-result      [--dry-run]     → i2-late-result
#   ./run-scenario.sh advisory-cancel  [--dry-run]     → i2-cancel
#   ./run-scenario.sh binding-change   [--dry-run]     → i2-binding-change
#   ./run-scenario.sh crash dispatch   [--dry-run]     → i2-crash-dispatch
#   ./run-scenario.sh crash admission  [--dry-run]     → i2-crash-admission
#   ./run-scenario.sh restore-lineage  [--dry-run]     → i2-restore-lineage
#   ./run-scenario.sh bench-matrix     [--dry-run]     → i2-bench-regression
#
# Evidence discipline (mirrors I0/I1, plan/fleet/README.md §run-scenario.sh):
#
#   evidence/<test-id>/
#     steps.jsonl            what the driver did, in order
#     assertions.jsonl       one line per named assertion, with its evidence path
#     result.json            passed/failed
#     alice/                 ALICE's own daemons' records — nothing else
#     bob/                   BOB's own daemons' records — nothing else
#
# The two side directories are never folded into one view, and every assertion
# below reads a daemon's own extract, never the driver's prose about it.
# `assert_ledgers_unmerged` checks the structural half of that at the end.
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

usage() {
  sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

fleet_common_args "$@"
((${#FLEET_ARGS[@]} >= 1)) || usage
SCENARIO="${FLEET_ARGS[0]}"
SCENARIO_ARG="${FLEET_ARGS[1]:-}"

case $SCENARIO in
no-credentials) TEST_ID=i2-no-credentials ;;
round-trip) TEST_ID=i2-round-trip ;;
late-result) TEST_ID=i2-late-result ;;
advisory-cancel) TEST_ID=i2-cancel ;;
binding-change) TEST_ID=i2-binding-change ;;
restore-lineage) TEST_ID=i2-restore-lineage ;;
bench-matrix) TEST_ID=i2-bench-regression ;;
crash)
  case $SCENARIO_ARG in
  dispatch) TEST_ID=i2-crash-dispatch ;;
  admission) TEST_ID=i2-crash-admission ;;
  *) die "crash needs a commit point: dispatch | admission" ;;
  esac
  ;;
*) usage ;;
esac

fleet_banner
evidence_reset "$TEST_ID"
EV="$(evidence_for "$TEST_ID")"
step "$TEST_ID  (scenario: $SCENARIO ${SCENARIO_ARG:+$SCENARIO_ARG})"

ALICE_SSH="$(host_target alice)"
BOB_SSH="$(host_target bob)"
ALICE_PRIV="$(host_private_ip alice)"
BOB_PRIV="$(host_private_ip bob)"

# ═══════════════════════════ assertion helpers ═══════════════════════════════
# Each takes the file the claim is read FROM, so the evidence path travels with
# the assertion into assertions.jsonl.

count_in() { # <file> <extended-regex>
  [[ -f $1 ]] || {
    printf '0'
    return 0
  }
  grep -cE "$2" "$1" || true
}

assert_count() { # <assertion> <file> <regex> <expected> <note>
  local got
  got="$(count_in "$2" "$3")"
  if [[ $got == "$4" ]]; then
    assert_that "$TEST_ID" "$1" ok "$5 (found $got)" "$2"
  else
    assert_that "$TEST_ID" "$1" fail "$5 (found $got, expected $4)" "$2"
  fi
}

assert_present() { # <assertion> <file> <regex> <note>
  if [[ $(count_in "$2" "$3") -gt 0 ]]; then
    assert_that "$TEST_ID" "$1" ok "$4" "$2"
  else
    assert_that "$TEST_ID" "$1" fail "$4 — not present in the record" "$2"
  fi
}

assert_absent() { # <assertion> <file> <regex> <note>
  if [[ $(count_in "$2" "$3") -eq 0 ]]; then
    assert_that "$TEST_ID" "$1" ok "$4" "$2"
  else
    assert_that "$TEST_ID" "$1" fail "$4 — but the record contains it" "$2"
  fi
}

# ═════════════════════ the per-side transcript driver ════════════════════════
# The op-level transcript (act chain, permits, staged contracts, Pledges,
# deliveries, reviews) is authored on each host through that host's OWN daemon
# surfaces. The fleet driver never speaks those surfaces itself — it would then
# be the author, and the manual-local model (D-RT-1) forbids that. Instead each
# side runs its own driver locally, under this contract:
#
#   I2_SIDE=<alice|bob> I2_TEST_ID=<test-id> I2_PEER=<peer private addr> \
#   I2_OUT=<remote evidence dir> \
#     python3 ~/byom/conformance/i2-sovereign-pair/side.py --step <step-name>
#
# It writes its records through byomd/koveed and leaves its own extracts in
# $I2_OUT, which this script pulls into evidence/<test-id>/<side>/.
SIDE_DRIVER="\$HOME/byom/conformance/i2-sovereign-pair/side.py"
REMOTE_OUT='/tmp/i2-evidence'

require_side_driver() { # <side> <ssh target>
  run_ssh "$2" side-driver "test -f $SIDE_DRIVER || {
    echo 'MISSING: $SIDE_DRIVER'
    echo 'The per-side transcript driver is the cross-host wiring I2 still needs'
    echo 'from byom/kovee (I2 sheet, Size: \"the new work is ... the cross-host wiring\").'
    exit 1; }" >>"$EV/$1/side-driver-preflight.txt" 2>&1 ||
    die "no per-side transcript driver on $1 at $SIDE_DRIVER.
run-scenario.sh drives it under the documented contract (see the comment above
SIDE_DRIVER in this script); it is owned by byom/kovee, not by harness/fleet.
Scenarios that need no side driver — no-credentials, bench-matrix — run today."
}

side_step() { # <side> <ssh target> <step-name>
  local side="$1" target="$2" name="$3" peer
  peer=$([[ $side == alice ]] && printf '%s' "$BOB_PRIV" || printf '%s' "$ALICE_PRIV")
  emit_step "$TEST_ID" "$side/$name" started ''
  run_ssh "$target" side-driver "set -e
    mkdir -p $REMOTE_OUT/$TEST_ID
    I2_SIDE=$side I2_TEST_ID=$TEST_ID I2_PEER=$peer I2_OUT=$REMOTE_OUT/$TEST_ID \\
      python3 $SIDE_DRIVER --step $name" \
    >>"$EV/$side/transcript.txt" 2>&1 ||
    { emit_step "$TEST_ID" "$side/$name" failed ''; die "$side failed at step '$name' — see $EV/$side/transcript.txt"; }
  emit_step "$TEST_ID" "$side/$name" ok ''
}

# The cross-host hop is akson's, and only akson's.
akson_step() { # <side> <ssh target> <label> <akson args…>
  local side="$1" target="$2" label="$3"
  shift 3
  emit_step "$TEST_ID" "$side/$label" started "akson $*"
  run_ssh "$target" "akson-$label" "akson $*" >>"$EV/$side/akson-$label.txt" 2>&1 ||
    { emit_step "$TEST_ID" "$side/$label" failed "akson $*"; die "$side: akson $* failed"; }
  emit_step "$TEST_ID" "$side/$label" ok "akson $*"
}

# ═══════════════════════ ledger extraction, per side ═════════════════════════
# Every claim is read from the owning daemon's own records: kovee facts from
# koveed, byom facts from byomd, akson facts from aksond — per source, per side,
# never merged.
collect_side_ledgers() { # <side> <ssh target>
  local side="$1" target="$2" dir="$EV/$1"
  mkdir -p "$dir"
  step "collecting $side's own ledgers (never merged with the other side's)"

  run_ssh "$target" "kovee-events-$side" "kovee events --limit 512" \
    >"$dir/kovee-events.jsonl" 2>&1 || true
  run_ssh "$target" "byom-events-$side" "byom events" \
    >"$dir/byom-events.jsonl" 2>&1 || true
  run_ssh "$target" akson-task-sent "akson task sent" \
    >"$dir/akson-task-sent.txt" 2>&1 || true
  run_ssh "$target" akson-task-outcomes "akson task outcomes" \
    >"$dir/akson-task-outcomes.txt" 2>&1 || true
  run_ssh "$target" akson-peer-list "akson peer list" \
    >"$dir/akson-peer-list.txt" 2>&1 || true

  # Anything the side driver wrote locally stays inside this side's directory.
  _show "scp -r $target:$REMOTE_OUT/$TEST_ID/. $dir/side-driver/"
  mkdir -p "$dir/side-driver"
  if dry; then
    fixture replay-digest >"$dir/side-driver/replay-digest.txt"
  else
    scp -q -r "${SSH_OPTS[@]}" "$target:$REMOTE_OUT/$TEST_ID/." "$dir/side-driver/" 2>/dev/null || true
  fi

  jq -nc --arg side "$side" \
    '{side:$side, sources:{
        "kovee-events.jsonl":"koveed on this host, via `kovee events`",
        "byom-events.jsonl":"byomd on this host, via `byom events`",
        "akson-task-sent.txt":"aksond on this host, via `akson task sent`",
        "akson-task-outcomes.txt":"aksond on this host, via `akson task outcomes`",
        "akson-peer-list.txt":"aksond on this host, via `akson peer list`"},
      merged_with_other_side:false}' >"$dir/source.json"
}

collect_both_ledgers() {
  collect_side_ledgers alice "$ALICE_SSH"
  collect_side_ledgers bob "$BOB_SSH"
  assert_ledgers_unmerged "$TEST_ID"
}

# ═════════════════════════════ the scenarios ═════════════════════════════════

# ---- i2-no-credentials ------------------------------------------------------
# A0.6's confined half, on a permissive host at last. The planted-credential
# probe must return CLEAN inside the worker on BOTH droplets, and the
# unconfined control must find the plants — otherwise the pass is vacuous.
scenario_no_credentials() {
  local side target out
  for side in alice bob; do
    target=$([[ $side == alice ]] && printf '%s' "$ALICE_SSH" || printf '%s' "$BOB_SSH")
    out="$EV/$side/no-inherited-credentials.txt"
    step "$side: A0.6 confined-credential probe (with its unconfined control)"
    run_ssh "$target" a06-probe "set -o pipefail
      export PATH=\$HOME/.cargo/bin:\$PATH
      cd ~/akson && cargo test -p akson-harness --test no_inherited_credentials \\
        -- --ignored --nocapture" >"$out" 2>&1 || true

    assert_present "$side/probe-clean" "$out" 'worker report: CLEAN' \
      "the confined worker reached no inherited credential"
    assert_present "$side/control-found-plants" "$out" 'unconfined control found [1-9][0-9]* leak' \
      "the unconfined control found the plants, so CLEAN is not vacuous"
    assert_absent "$side/probe-not-skipped" "$out" '\[a0\.6\]\[skip\]' \
      "the host could answer the question (no skip)"
    emit_step "$TEST_ID" "$side/a06-probe" ok ''
  done
  collect_both_ledgers
}

# ---- i2-round-trip ----------------------------------------------------------
# The §0.2 transcript end to end. Two independently formed Pledges, two human
# decisions on bob's side, bob's Codex attached locally. No inbound akson task,
# remote byom object, remote agent or kovee notification may author bob's
# Standing, Pledge, WakeIntent or execution authority (D-RT-1, manual-local).
scenario_round_trip() {
  require_side_driver alice "$ALICE_SSH"
  require_side_driver bob "$BOB_SSH"

  # alice authors her own chain, locally.
  side_step alice "$ALICE_SSH" act-chain
  side_step alice "$ALICE_SSH" consume-permit
  side_step alice "$ALICE_SSH" stage-inert-contract
  side_step alice "$ALICE_SSH" akson-consent

  # the ONLY cross-host hop.
  akson_step alice "$ALICE_SSH" task-send task send /tmp/i2-round-trip.json

  # bob's arrival is inert until bob's own humans decide, twice.
  side_step bob "$BOB_SSH" assert-arrival-inert
  side_step bob "$BOB_SSH" human-admit         # decision 1
  side_step bob "$BOB_SSH" form-own-pledge     # decision 2, bob's own society
  side_step bob "$BOB_SSH" perform-locally     # Codex, attached on bob
  side_step bob "$BOB_SSH" delivery-and-review
  side_step bob "$BOB_SSH" outbound-disclosure-act
  akson_step bob "$BOB_SSH" task-deliver task deliver "\$(akson task inbox | head -1 | cut -d' ' -f1)"
  side_step bob "$BOB_SSH" manual-fulfilment

  # alice verifies and admits, from her own records.
  side_step alice "$ALICE_SSH" verify-result
  side_step alice "$ALICE_SSH" admit-result

  collect_both_ledgers

  # Alice's side, from alice's ledgers only.
  assert_count alice/one-dispatch "$EV/alice/kovee-events.jsonl" 'dispatch' 1 \
    "exactly one dispatch in alice's own kovee ledger"
  assert_count alice/one-permit-consumed "$EV/alice/kovee-events.jsonl" 'permit.*consum' 1 \
    "exactly one consumed permit in alice's own kovee ledger"
  assert_present alice/outcome-verified "$EV/alice/akson-task-outcomes.txt" 'verified' \
    "alice's aksond records the outcome as verified"

  # Bob's side, from bob's ledgers only.
  assert_present bob/own-standing-admitted "$EV/bob/byom-events.jsonl" 'standing.*admit' \
    "bob's own byom records the admission (decision 1)"
  assert_present bob/own-pledge-finalized "$EV/bob/byom-events.jsonl" 'pledge.*finaliz' \
    "bob's own society formed and finalized its own Pledge (decision 2)"
  assert_present bob/outbound-disclosure "$EV/bob/byom-events.jsonl" 'disclosure' \
    "bob authored an outbound disclosure act"
  assert_absent bob/no-remote-authorship "$EV/bob/byom-events.jsonl" \
    '"authored_by"[^,]*(remote|inbound|peer)|remote_authority' \
    "no inbound task, remote object or remote agent authored anything on bob (D-RT-1)"
}

# ---- i2-late-result ---------------------------------------------------------
scenario_late_result() {
  require_side_driver alice "$ALICE_SSH"
  require_side_driver bob "$BOB_SSH"
  side_step alice "$ALICE_SSH" dispatch
  side_step bob "$BOB_SSH" perform-slowly
  side_step alice "$ALICE_SSH" advance-aspect-generation
  side_step bob "$BOB_SSH" deliver-late-result
  side_step alice "$ALICE_SSH" verify-late-result
  collect_both_ledgers
  assert_present alice/late-result-verified "$EV/alice/kovee-events.jsonl" 'result.*verif' \
    "the late result verifies"
  assert_absent alice/cannot-satisfy-new-generation "$EV/alice/kovee-events.jsonl" \
    'aspect.*satisfied.*generation' \
    "it cannot satisfy the advanced aspect generation"
  assert_present alice/retained-and-quarantined "$EV/alice/kovee-events.jsonl" \
    'quarantin' "it is retained and quarantined, not discarded"
}

# ---- i2-cancel -------------------------------------------------------------
scenario_advisory_cancel() {
  require_side_driver alice "$ALICE_SSH"
  side_step alice "$ALICE_SSH" dispatch
  side_step alice "$ALICE_SSH" cancel-after-dispatch
  collect_both_ledgers
  assert_present alice/cancel-is-advisory "$EV/alice/kovee-events.jsonl" 'advisory' \
    "post-dispatch cancellation is recorded as advisory"
  assert_absent alice/no-remote-stop-claim "$EV/alice/kovee-events.jsonl" \
    '(remote|peer).*(execution|work).*(stopped|halted|aborted)' \
    "no claim that remote execution stopped"
}

# ---- i2-binding-change -----------------------------------------------------
scenario_binding_change() {
  require_side_driver alice "$ALICE_SSH"
  require_side_driver bob "$BOB_SSH"
  side_step alice "$ALICE_SSH" dispatch
  side_step bob "$BOB_SSH" change-peer-binding
  side_step alice "$ALICE_SSH" observe-binding-change
  collect_both_ledgers
  assert_present alice/trust-suspended "$EV/alice/kovee-events.jsonl" 'suspend' \
    "a peer binding change mid-flight suspends trust"
  assert_present alice/capability-matrix-records-profile "$EV/alice/kovee-events.jsonl" \
    'capability_matrix|capability.*profile' \
    "the capability matrix records which profile the exchange used"
}

# ---- i2-crash-dispatch / i2-crash-admission -------------------------------
scenario_crash() {
  local point="$1" side target unit
  case $point in
  dispatch) side=alice ;;
  admission) side=bob ;;
  esac
  target=$([[ $side == alice ]] && printf '%s' "$ALICE_SSH" || printf '%s' "$BOB_SSH")
  require_side_driver "$side" "$target"

  # Arm the commit-point crash in the side driver, then kill the daemons from
  # the driver so the kill is genuinely external to the process under test.
  side_step "$side" "$target" "arm-crash-$point"
  step "$side: killing the stack at the $point commit point"
  for unit in akson-daemon.service byom-i2.service kovee-i2.service; do
    run_ssh "$target" '' "sudo systemctl kill -s SIGKILL $unit || true"
  done
  emit_step "$TEST_ID" "$side/killed" ok "SIGKILL at the $point commit point"

  # Restart through serve.sh, so recovery uses the same path an operator does.
  local serve_args=("$side")
  dry && serve_args+=(--dry-run)
  "$FLEET_DIR/serve.sh" "${serve_args[@]}" >>"$EV/$side/restart.txt" 2>&1 ||
    die "$side did not come back up — see $EV/$side/restart.txt"
  side_step "$side" "$target" "replay-after-$point"

  collect_both_ledgers
  case $point in
  dispatch)
    assert_count alice/exactly-one-dispatch "$EV/alice/kovee-events.jsonl" 'dispatch' 1 \
      "killing at the dispatch commit point leaves exactly one dispatch"
    assert_count alice/no-double-consent "$EV/alice/kovee-events.jsonl" 'consent.*consum' 1 \
      "no double consent consumption"
    assert_present alice/byte-identical-replay "$EV/alice/side-driver/replay-digest.txt" \
      'identical' "the replay is byte-identical"
    ;;
  admission)
    assert_count bob/admits-exactly-once "$EV/bob/byom-events.jsonl" 'admi(t|ssion)' 1 \
      "killing at the admission commit point admits exactly once"
    assert_present bob/ambiguity-recorded "$EV/bob/byom-events.jsonl" 'ambigu' \
      "ambiguity is recorded where required"
    ;;
  esac
}

# ---- i2-restore-lineage ---------------------------------------------------
scenario_restore_lineage() {
  require_side_driver alice "$ALICE_SSH"
  require_side_driver bob "$BOB_SSH"
  side_step alice "$ALICE_SSH" restore-lineage-complete
  side_step bob "$BOB_SSH" verify-lineage-complete
  side_step alice "$ALICE_SSH" restore-lineage-incomplete
  side_step bob "$BOB_SSH" refuse-lineage-incomplete
  collect_both_ledgers
  assert_present bob/complete-hop-verified "$EV/bob/byom-events.jsonl" \
    'restore.?lineage.*verif' "a complete RestoreLineage hop verifies across the pair"
  assert_present bob/incomplete-hop-refused "$EV/bob/byom-events.jsonl" \
    'restore.?lineage.*refus' "an incomplete hop is refused"
  assert_absent bob/never-relabelled-tombstone "$EV/bob/byom-events.jsonl" \
    'restore.?lineage.*tombstone|tombstone.*restore.?lineage' \
    "the incomplete hop is never relabelled as a tombstone"
}

# ---- i2-bench-regression --------------------------------------------------
# akson's own bench matrix on the pair: proof the layer below did not regress
# under the hardened profile.
scenario_bench_matrix() {
  local out="$EV/alice/bench-matrix.txt"
  step "alice: akson's bench matrix against bob"
  run_ssh "$ALICE_SSH" bench-matrix "set -o pipefail
    export PATH=\$HOME/.cargo/bin:\$HOME/akson/target/release:\$PATH
    cd ~/akson/bench && BOB_PRIV=$BOB_PRIV PROVIDERS='${FLEET_PROVIDERS:-openai}' \\
      ITERS=${FLEET_ITERS:-10} ./bench-matrix.sh" >"$out" 2>&1 || true
  # Read the pass from the matrix's own ok/n columns, not from an exit code.
  assert_absent alice/no-failed-cells "$out" '/0/|FAIL|error' \
    "every matrix cell reports ok == n"
  assert_present alice/matrix-ran "$out" 'p50|p95' \
    "the matrix produced per-cell timings"
  collect_both_ledgers
}

# ═════════════════════════════════ dispatch ══════════════════════════════════
case $SCENARIO in
no-credentials) scenario_no_credentials ;;
round-trip) scenario_round_trip ;;
late-result) scenario_late_result ;;
advisory-cancel) scenario_advisory_cancel ;;
binding-change) scenario_binding_change ;;
crash) scenario_crash "$SCENARIO_ARG" ;;
restore-lineage) scenario_restore_lineage ;;
bench-matrix) scenario_bench_matrix ;;
esac

assert_finish "$TEST_ID"
