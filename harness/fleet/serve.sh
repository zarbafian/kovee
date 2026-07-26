#!/usr/bin/env bash
# I2 — start one side's stack: koveed, byomd, aksond, in dependency order,
# each under its own Unix identity.
#
#   ./serve.sh alice [--dry-run]
#   ./serve.sh bob   [--dry-run]
#
# Spec: plan/fleet/README.md §serve.sh. Idempotent: a second run reports the
# running stack and starts nothing.
#
# Order and why:
#   koveed   the governance/provenance store the seam binds to
#   byomd    binds a Kovee host binding and publishes its channel token files
#   aksond   the federation seam — last, so it never advertises a RECEIVE
#            surface for a stack that is not yet assembled
#
# Identities: koveed runs as `kovee`, byomd as `byom` (transient system units
# via systemd-run, because kovee/byom ship no unit yet), aksond as `akson` from
# the hardened unit akson/deploy/akson-daemon.service that provision.sh
# installed as root. kovee's and byom's sockets are AF_UNIX and never cross the
# wire — structural, not configured.
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

usage() {
  printf 'usage: ./serve.sh <alice|bob> [--dry-run]\n' >&2
  exit 2
}

fleet_common_args "$@"
((${#FLEET_ARGS[@]} == 1)) || usage
ROLE="${FLEET_ARGS[0]}"
case $ROLE in alice | bob) ;; *) usage ;; esac
fleet_banner

TARGET="$(host_target "$ROLE")"
PRIV="$(host_private_ip "$ROLE")"
PORT="$(receive_port_for "$ROLE")"

KOVEE_SOCKETS=(/run/kovee/kovee.sock /run/kovee/kovee-worker.sock)
BYOM_SOCKETS=(
  /run/byom/governance.sock /run/byom/candidate.sock /run/byom/participant.sock
  /run/byom/runtime.sock /run/byom/projection.sock
)
AKSON_SOCKETS=(/run/akson/admin.sock /run/akson/coord.sock)

# ------------------------------------------------------------- idempotence ---
# One remote probe answers "is the stack already up?" — three unit states plus
# every socket. A second serve.sh must never start a duplicate.
step "probing $ROLE for an already-running stack"
# FLEET_DRY_STACK_UP=1 selects the "already up" fixture, so the idempotent
# branch below is exercisable in --dry-run too.
STACK_FIXTURE=stack-status
[[ ${FLEET_DRY_STACK_UP:-0} == 1 ]] && STACK_FIXTURE=stack-status-up
STATUS="$(run_ssh "$TARGET" "$STACK_FIXTURE" "
  for u in kovee-i2.service byom-i2.service akson-daemon.service; do
    printf '%s %s\n' \"\$u\" \"\$(systemctl is-active \"\$u\" 2>/dev/null || true)\"
  done
  for s in ${KOVEE_SOCKETS[*]} ${BYOM_SOCKETS[*]} ${AKSON_SOCKETS[*]}; do
    [ -S \"\$s\" ] && printf 'socket %s present\n' \"\$s\" || printf 'socket %s absent\n' \"\$s\"
  done" 2>/dev/null || true)"

ACTIVE_COUNT="$(printf '%s\n' "$STATUS" | grep -c ' active$' || true)"
if ((ACTIVE_COUNT >= 3)); then
  step "$ROLE: stack already running — reporting it, starting nothing"
  printf '%s\n' "$STATUS"
  run_ssh "$TARGET" akson-whoami "akson whoami" || true
  exit 0
fi
note "$ROLE: $ACTIVE_COUNT/3 daemons active — starting the rest"

# The RECEIVE address drop-in provision.sh wrote; without it aksond binds
# 127.0.0.1:18443 and the pair can never introduce.
step "checking the akson unit drop-in names this host's RECEIVE address"
run_ssh "$TARGET" '' "set -e
  grep -q 'AKSON_RECEIVE_ADDR=$PRIV:$PORT' /etc/systemd/system/akson-daemon.service.d/10-fleet.conf \\
    || { echo 'akson-daemon drop-in does not name $PRIV:$PORT — rerun provision.sh'; exit 1; }"

# ------------------------------------------------------------ 1. koveed ------
step "1/3 koveed as user 'kovee'"
run_ssh "$TARGET" '' "set -e
  sudo systemctl reset-failed kovee-i2.service 2>/dev/null || true
  sudo systemd-run --unit=kovee-i2 --collect \\
    --uid=kovee --gid=kovee \\
    -p RuntimeDirectory=kovee -p RuntimeDirectoryMode=0700 \\
    -p StateDirectory=kovee  -p StateDirectoryMode=0700 \\
    -p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=yes \\
    -p ReadWritePaths=/var/lib/kovee -p PrivateTmp=yes \\
    --setenv=KOVEE_RUNTIME_DIR=/run/kovee \\
    --setenv=KOVEE_DATA_DIR=/var/lib/kovee \\
    /usr/local/bin/koveed"

# --------------------------------------------------------------- 2. byomd ----
step "2/3 byomd as user 'byom'"
run_ssh "$TARGET" '' "set -e
  sudo systemctl reset-failed byom-i2.service 2>/dev/null || true
  sudo systemd-run --unit=byom-i2 --collect \\
    --uid=byom --gid=byom \\
    -p RuntimeDirectory=byom -p RuntimeDirectoryMode=0700 \\
    -p StateDirectory=byom  -p StateDirectoryMode=0700 \\
    -p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=yes \\
    -p ReadWritePaths=/var/lib/byom -p PrivateTmp=yes \\
    --setenv=BYOM_RUNTIME_DIR=/run/byom \\
    --setenv=BYOM_DATA_DIR=/var/lib/byom \\
    /usr/local/bin/byomd"

# -------------------------------------------------------------- 3. aksond ----
step "3/3 aksond as user 'akson' from the hardened unit"
run_ssh "$TARGET" '' "set -e
  sudo systemctl start akson-daemon.service
  sudo systemctl start akson-coord.service"

# ------------------------------------------------- wait for every socket -----
step "waiting for every socket"
wait_sockets() { # <fixture> <socket…>
  local fixture="$1"
  shift
  run_ssh "$TARGET" "$fixture" "
    for s in $*; do
      ok=0
      for i in \$(seq 1 100); do [ -S \"\$s\" ] && { ok=1; break; }; sleep 0.1; done
      [ \$ok = 1 ] || { echo \"socket did not appear: \$s\"; exit 1; }
      printf 'up %s\n' \"\$s\"
    done"
}
wait_sockets '' "${KOVEE_SOCKETS[@]}"
wait_sockets '' "${BYOM_SOCKETS[@]}"
# coord.sock exists only when AKSON_COORD_UID is set — provision.sh sets it.
wait_sockets '' "${AKSON_SOCKETS[@]}"

# ---------------------------------------------------- report the endpoint ----
step "$ROLE is up"
run_ssh "$TARGET" akson-whoami "akson whoami"
printf '\n'

cat <<REPORT
  role                 $ROLE
  private address      $PRIV
  akson RECEIVE        $PRIV:$PORT   (the ONLY listener on the wire)
  akson identity token (public, exchange out of band with ./introduce.sh)
$(run_ssh "$TARGET" akson-token "akson token" | sed 's/^/      /')

  credential and token file paths the harness uses on $ROLE:
    kovee store          /var/lib/kovee/kovee.db          (user kovee)
    kovee control socket /run/kovee/kovee.sock            (AF_UNIX, never on the wire)
    kovee worker socket  /run/kovee/kovee-worker.sock     (AF_UNIX)
    byom store           /var/lib/byom/byom.db            (user byom)
    byom channel tokens  /var/lib/byom/channels/*.token   (0700 dir, 0600 files, NO key material)
    byom recovery token  /var/lib/byom/channels/recovery-workload-*.token
    byom surfaces        /run/byom/{governance,candidate,participant,runtime,projection}.sock
    akson store          /var/lib/akson                   (user akson, 0700)
    akson admin socket   /run/akson/admin.sock            (SO_PEERCRED same-UID)
    akson coord socket   /run/akson/coord.sock            (only AKSON_COORD_UID=akson-coord)
    provider keys        /var/lib/akson/creds/*.key       (0600 akson:akson, if placed)

  logs:  ssh $TARGET 'journalctl -u kovee-i2 -u byom-i2 -u akson-daemon -f'
  stop:  ssh $TARGET 'sudo systemctl stop akson-coord akson-daemon byom-i2 kovee-i2'
REPORT
