#!/usr/bin/env bash
# I2 `i2-teardown` — DESTROYS BY DEFAULT.
#
#   ./teardown.sh [--dry-run]     destroy the pair, the firewall and any volumes
#   ./teardown.sh --keep          keep them, and print the exact command to
#                                 destroy them later, loudly
#
# Spec: plan/fleet/README.md §teardown.sh. Teardown is part of I2's pass
# criteria: a run that fails mid-scenario still tears down.
#
# Two independent ways to find the resources, so a crashed driver can never
# orphan a paid host:
#
#   1. evidence/fleet-state.json — written the instant the droplets existed,
#      before anything else could fail
#   2. the `akson-i2` tag — survives a lost state file entirely
#
# It uses the UNION of both, then verifies deletion with a fresh listing and
# exits non-zero if anything survived.
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

TEST_ID=i2-teardown
KEEP=0

fleet_common_args "$@"
for a in ${FLEET_ARGS[@]+"${FLEET_ARGS[@]}"}; do
  case $a in
  --keep) KEEP=1 ;;
  -h | --help)
    sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
    ;;
  *) die "unknown argument '$a' (--keep | --dry-run)" ;;
  esac
done

((KEEP == 1)) || evidence_reset "$TEST_ID"
EV="$(evidence_for "$TEST_ID")"
fleet_banner

# ═══ elapsed time and cost ═══════════════════════════════════════════════════
STARTED_EPOCH="$(state_get '.created_at_epoch' 2>/dev/null || true)"
[[ -n ${STARTED_EPOCH:-} && $STARTED_EPOCH != null ]] || STARTED_EPOCH=""
RATE="$(state_get '.hourly_usd_per_droplet' 2>/dev/null || true)"
[[ -n ${RATE:-} && $RATE != null ]] || RATE="$FLEET_HOURLY_USD"

report_cost() {
  local now elapsed
  now="$(date -u +%s)"
  if [[ -z $STARTED_EPOCH ]]; then
    note "elapsed: unknown (no fleet-state.json — resolving by tag only)"
    return 0
  fi
  elapsed=$((now - STARTED_EPOCH))
  printf '    elapsed: %02d:%02d:%02d   estimated cost: $%s (2 x $%s/h)\n' \
    $((elapsed / 3600)) $((elapsed % 3600 / 60)) $((elapsed % 60)) \
    "$(awk -v r="$RATE" -v s="$elapsed" 'BEGIN{printf "%.4f", 2*r*s/3600}')" "$RATE" >&2
}

# ═══ --keep: loud, with the exact command ════════════════════════════════════
if ((KEEP == 1)); then
  report_cost
  cat >&2 <<KEEP_NOTICE

  ############################################################################
  ##                                                                        ##
  ##   THE PAIR IS STILL RUNNING AND STILL BILLING.                         ##
  ##                                                                        ##
  ##   Destroy it when you are done — this is the exact command:             ##
  ##                                                                        ##
  ##       $FLEET_DIR/teardown.sh
  ##                                                                        ##
  ##   Find an orphan from anywhere with one command:                        ##
  ##                                                                        ##
  ##       doctl compute droplet list --tag-name $FLEET_TAG
  ##                                                                        ##
  ##   Teardown is part of I2's pass criteria: the gate does not pass while  ##
  ##   these droplets exist.                                                ##
  ##                                                                        ##
  ############################################################################

KEEP_NOTICE
  [[ -f $STATE_FILE ]] && state_patch '.kept = true'
  emit_step "$TEST_ID" kept ok "--keep: nothing destroyed"
  exit 0
fi

require_do_token

# ═══ 1. resolve targets: state file ∪ tag ════════════════════════════════════
step "1/5 resolve targets from evidence/fleet-state.json AND the '$FLEET_TAG' tag"

STATE_IDS=()
if [[ -f $STATE_FILE ]]; then
  mapfile -t STATE_IDS < <(jq -r '.hosts[]? | select(.droplet_id != null) | .droplet_id' "$STATE_FILE" 2>/dev/null || true)
  note "from state file: ${STATE_IDS[*]:-none}"
else
  warn "no $STATE_FILE — a crashed driver may never have written one; using the tag"
fi

mapfile -t TAG_IDS < <(doctl_out droplet-list-tag compute droplet list \
  --tag-name "$FLEET_TAG" --format ID,Name --no-header | awk 'NF {print $1}')
note "from tag:        ${TAG_IDS[*]:-none}"

mapfile -t ALL_IDS < <(printf '%s\n' \
  ${STATE_IDS[@]+"${STATE_IDS[@]}"} ${TAG_IDS[@]+"${TAG_IDS[@]}"} | awk 'NF' | sort -u)
if ((${#ALL_IDS[@]} == 0)); then
  note "no droplets found by either route — nothing to destroy"
else
  note "destroying: ${ALL_IDS[*]}"
fi
emit_step "$TEST_ID" resolved ok "ids: ${ALL_IDS[*]:-none}"

# ═══ 2. droplets ═════════════════════════════════════════════════════════════
step "2/5 destroy the droplets"
for id in ${ALL_IDS[@]+"${ALL_IDS[@]}"}; do
  doctl_run compute droplet delete "$id" --force || warn "delete of droplet $id reported an error"
done

# ═══ 3. firewall ═════════════════════════════════════════════════════════════
step "3/5 destroy the firewall"
FW_ID="$(state_get '.firewall_id' 2>/dev/null || true)"
if [[ -z ${FW_ID:-} || $FW_ID == null ]]; then
  FW_ID="$(doctl_out firewall-list compute firewall list --format ID,Name --no-header |
    awk -v n="$FLEET_FIREWALL_NAME" '$2 == n {print $1; exit}' || true)"
fi
if [[ -n ${FW_ID:-} ]]; then
  doctl_run compute firewall delete "$FW_ID" --force || warn "firewall $FW_ID delete reported an error"
else
  note "no firewall named '$FLEET_FIREWALL_NAME' to delete"
fi

# ═══ 4. volumes ══════════════════════════════════════════════════════════════
step "4/5 destroy any volumes"
mapfile -t VOL_IDS < <(doctl_out volume-list compute volume list --format ID,Name,Tags --no-header |
  awk -v t="$FLEET_TAG" '$3 ~ t || $2 ~ ("^" t) {print $1}')
if ((${#VOL_IDS[@]} > 0)); then
  for id in "${VOL_IDS[@]}"; do
    doctl_run compute volume delete "$id" --force || warn "volume $id delete reported an error"
  done
else
  note "no volumes tagged or named '$FLEET_TAG'"
fi

# ═══ 5. verify — and fail if anything survived ═══════════════════════════════
step "5/5 verify deletion"
sleep_a_moment() { dry || sleep 5; }
sleep_a_moment

SURVIVORS=0

doctl_out droplet-list-tag-empty compute droplet list --tag-name "$FLEET_TAG" \
  --format ID,Name,Status --no-header >"$EV/verify-droplets-by-tag.txt" || true
if [[ -s $EV/verify-droplets-by-tag.txt ]]; then
  assert_that "$TEST_ID" droplets-gone-by-tag fail \
    "droplets still tagged $FLEET_TAG: $(tr '\n' ' ' <"$EV/verify-droplets-by-tag.txt")" \
    "$EV/verify-droplets-by-tag.txt"
  SURVIVORS=1
else
  assert_that "$TEST_ID" droplets-gone-by-tag ok \
    "\`doctl compute droplet list --tag-name $FLEET_TAG\` is empty" \
    "$EV/verify-droplets-by-tag.txt"
fi

# And by name, so the evidence is a listing that names neither host.
doctl_out droplet-list-names compute droplet list --format ID,Name --no-header \
  >"$EV/verify-droplets-by-name.txt" || true
NAMED=""
if [[ -f $STATE_FILE ]]; then
  for n in $(jq -r '.hosts[]?.name // empty' "$STATE_FILE"); do
    if awk -v n="$n" '$2 == n {found=1} END {exit !found}' "$EV/verify-droplets-by-name.txt"; then
      NAMED="$NAMED $n"
    fi
  done
fi
if [[ -z $NAMED ]]; then
  assert_that "$TEST_ID" droplets-gone-by-name ok \
    "the droplet listing names neither host" "$EV/verify-droplets-by-name.txt"
else
  assert_that "$TEST_ID" droplets-gone-by-name fail \
    "still listed:$NAMED" "$EV/verify-droplets-by-name.txt"
  SURVIVORS=1
fi

doctl_out firewall-list compute firewall list --format ID,Name --no-header \
  >"$EV/verify-firewalls.txt" || true
if grep -Fxq "$FLEET_FIREWALL_NAME" <(awk '{print $2}' "$EV/verify-firewalls.txt"); then
  assert_that "$TEST_ID" firewall-gone fail "firewall '$FLEET_FIREWALL_NAME' survived" "$EV/verify-firewalls.txt"
  SURVIVORS=1
else
  assert_that "$TEST_ID" firewall-gone ok "no firewall named '$FLEET_FIREWALL_NAME'" "$EV/verify-firewalls.txt"
fi

doctl_out volume-list compute volume list --format ID,Name,Tags --no-header \
  >"$EV/verify-volumes.txt" || true
if [[ -s $EV/verify-volumes.txt ]] && grep -q "$FLEET_TAG" "$EV/verify-volumes.txt"; then
  assert_that "$TEST_ID" volumes-gone fail "a volume tagged $FLEET_TAG survived" "$EV/verify-volumes.txt"
  SURVIVORS=1
else
  assert_that "$TEST_ID" volumes-gone ok "no volume tagged $FLEET_TAG" "$EV/verify-volumes.txt"
fi

report_cost
if [[ -f $STATE_FILE ]]; then
  # shellcheck disable=SC2016  # jq filter: $ts is jq's variable, not the shell's
  state_patch '.torn_down_at = $ts' --arg ts "$(now_iso)"
fi

{
  printf '# I2 teardown\n\n'
  printf -- '- at: %s%s\n' "$(now_iso)" "$(dry && printf ' (DRY RUN — nothing was destroyed)')"
  printf -- '- resolved by: state file (%s) ∪ tag %s (%s)\n' \
    "${STATE_IDS[*]:-none}" "$FLEET_TAG" "${TAG_IDS[*]:-none}"
  printf -- '- firewall: %s\n' "${FW_ID:-none}"
  printf -- '- volumes: %s\n' "${VOL_IDS[*]:-none}"
  report_cost 2>&1 | sed 's/^  */- /'
} >"$EV/teardown-report.md"

if ((SURVIVORS == 1)); then
  warn "SOMETHING SURVIVED. Find it and destroy it:"
  warn "    doctl compute droplet list --tag-name $FLEET_TAG"
  warn "    $FLEET_DIR/teardown.sh"
fi
assert_finish "$TEST_ID"
