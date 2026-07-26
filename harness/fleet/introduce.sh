#!/usr/bin/env bash
# I2 `i2-introduce` — exchange akson identity tokens out of band, then run the
# ADR-0015 introduction on the RECEIVE surface.
#
#   ./introduce.sh alice bob [--dry-run]
#
# Passes when: tokens exchanged out of band, the introduction completes on the
# RECEIVE surface, each side pins the other, and NO PAIR PORT was opened —
# asserted from the firewall rule dump and from what is actually bound on each
# host, not assumed.
#
# The out-of-band channel is this driver: it reads each side's public identity
# token over ssh and hands it to the other side. The token is public (it names
# a root thumbprint and an endpoint hint); no key material moves.
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

TEST_ID=i2-introduce

usage() {
  printf 'usage: ./introduce.sh <alice-role> <bob-role> [--dry-run]\n' >&2
  exit 2
}

fleet_common_args "$@"
((${#FLEET_ARGS[@]} == 2)) || usage
A_ROLE="${FLEET_ARGS[0]}"
B_ROLE="${FLEET_ARGS[1]}"
fleet_banner

evidence_reset "$TEST_ID"
EV="$(evidence_for "$TEST_ID")"
A_SSH="$(host_target "$A_ROLE")"
B_SSH="$(host_target "$B_ROLE")"
A_PRIV="$(host_private_ip "$A_ROLE")"
B_PRIV="$(host_private_ip "$B_ROLE")"
A_PORT="$(receive_port_for "$A_ROLE")"
B_PORT="$(receive_port_for "$B_ROLE")"

# ═══ 1. both stacks must be up ════════════════════════════════════════════════
step "1/5 both stacks up?"
for pair in "$A_ROLE:$A_SSH" "$B_ROLE:$B_SSH"; do
  role="${pair%%:*}"
  target="${pair#*:}"
  run_ssh "$target" akson-whoami "akson status && akson whoami" \
    >"$EV/$role/akson-status.txt" 2>&1 ||
    die "$role's akson daemon is not ready — run ./serve.sh $role first"
done
emit_step "$TEST_ID" stacks-up ok "both daemons answer on their admin sockets"

# ═══ 2. read each side's public token (out of band, via this driver) ══════════
step "2/5 fetch each side's identity token (out of band)"
A_TOKEN="$(run_ssh "$A_SSH" akson-token "akson token" |
  grep -oE 'akson1[a-z0-9]+(@[^ ]+)?' | head -1)"
B_TOKEN="$(run_ssh "$B_SSH" akson-token "akson token" |
  grep -oE 'akson1[a-z0-9]+(@[^ ]+)?' | head -1)"
[[ -n $A_TOKEN && -n $B_TOKEN ]] || die "could not parse an identity token from \`akson token\`"
printf '%s\n' "$A_TOKEN" >"$EV/$A_ROLE/identity-token.txt"
printf '%s\n' "$B_TOKEN" >"$EV/$B_ROLE/identity-token.txt"
note "$A_ROLE token → $EV/$A_ROLE/identity-token.txt"
note "$B_ROLE token → $EV/$B_ROLE/identity-token.txt"
emit_step "$TEST_ID" tokens-fetched ok "public tokens only; no key material crosses the driver"

# ═══ 3. import: each side adds the other ══════════════════════════════════════
step "3/5 out-of-band import (one per side)"
run_ssh "$A_SSH" '' "akson peer add '$B_TOKEN' $B_ROLE --endpoint $B_PRIV:$B_PORT" \
  >"$EV/$A_ROLE/peer-add.txt" 2>&1 || true
run_ssh "$B_SSH" '' "akson peer add '$A_TOKEN' $A_ROLE --endpoint $A_PRIV:$A_PORT" \
  >"$EV/$B_ROLE/peer-add.txt" 2>&1 || true
emit_step "$TEST_ID" tokens-imported ok "$A_ROLE imported $B_ROLE and vice versa"

# ═══ 4. the ADR-0015 introduction, on the RECEIVE surface ════════════════════
step "4/5 introduction on the RECEIVE surface (ADR-0015)"
# `peer ping` dials the introduction; there is no pairing listener to dial.
run_ssh "$A_SSH" '' "akson peer ping $B_ROLE" >"$EV/$A_ROLE/peer-ping.txt" 2>&1 ||
  { dry || die "the introduction did not complete — see $EV/$A_ROLE/peer-ping.txt"; }

for pair in "$A_ROLE:$A_SSH:$B_ROLE" "$B_ROLE:$B_SSH:$A_ROLE"; do
  role="${pair%%:*}"
  rest="${pair#*:}"
  target="${rest%%:*}"
  other="${rest#*:}"
  out="$EV/$role/akson-peer-list.txt"
  run_ssh "$target" akson-peer-list "akson peer list" >"$out" 2>&1 || true
  # Read the claim from the daemon's own peer record, not from our own prose.
  if grep -q 'pinned' "$out" && grep -q 'introduced' "$out"; then
    assert_that "$TEST_ID" "$role/pins-$other" ok \
      "$role's own peer record shows the peer pinned and introduced" "$out"
  else
    assert_that "$TEST_ID" "$role/pins-$other" fail \
      "$role's peer record does not show pinned+introduced" "$out"
  fi
done

# ═══ 5. no PAIR port, and no pairing listener was ever bound ═════════════════
step "5/5 assert no PAIR port and no pairing listener"

# 5a — from the firewall's own rule dump, not from the request we made.
FW_ID="$(state_get '.firewall_id')"
doctl_out firewall-json compute firewall get "$FW_ID" -o json >"$EV/firewall-rules.json"
assert_no_pair_port "$TEST_ID" "$EV/firewall-rules.json"
assert_receive_scoped_to_peer "$TEST_ID" "$EV/firewall-rules.json" "$A_PORT" "$B_PRIV"
assert_receive_scoped_to_peer "$TEST_ID" "$EV/firewall-rules.json" "$B_PORT" "$A_PRIV"

# 5b — from each host: the only TCP listener on a routable address is that
#      host's RECEIVE port (ssh aside). kovee's and byom's sockets are AF_UNIX,
#      so their absence from this list is structural.
for pair in "$A_ROLE:$A_SSH:$A_PORT:ss-listen-alice" "$B_ROLE:$B_SSH:$B_PORT:ss-listen-bob"; do
  role="${pair%%:*}"
  rest="${pair#*:}"
  target="${rest%%:*}"
  rest="${rest#*:}"
  port="${rest%%:*}"
  fixture="${rest#*:}"
  out="$EV/$role/listening-tcp.txt"
  run_ssh "$target" "$fixture" "ss -ltn" >"$out" 2>&1 || true
  # Every listening port, minus ssh and this host's RECEIVE port. The trailing
  # `|| true` matters: an EMPTY result is the passing case, and grep exits 1 on
  # no match.
  unexpected="$({
    awk '{print $4}' "$out" | grep -oE '[0-9]+$' | sort -u |
      grep -vxE "22|$port" || true
  } | tr '\n' ' ' | sed 's/ *$//')"
  if [[ -z $unexpected ]]; then
    assert_that "$TEST_ID" "$role/no-pairing-listener" ok \
      "the only listening TCP ports are ssh and RECEIVE $port" "$out"
  else
    assert_that "$TEST_ID" "$role/no-pairing-listener" fail \
      "unexpected listening port(s) on $role: $unexpected" "$out"
  fi

  # And the daemon's own log must never mention binding a pairing surface.
  jlog="$EV/$role/akson-journal.txt"
  run_ssh "$target" '' "journalctl -u akson-daemon.service --no-pager -o short-iso" \
    >"$jlog" 2>&1 || true
  if grep -qiE 'pairing (listener|surface|port)|bound pair' "$jlog"; then
    assert_that "$TEST_ID" "$role/never-bound-pairing" fail \
      "the daemon's own log mentions a pairing listener" "$jlog"
  else
    assert_that "$TEST_ID" "$role/never-bound-pairing" ok \
      "the daemon's own log never mentions binding a pairing surface" "$jlog"
  fi
done

assert_ledgers_unmerged "$TEST_ID"
assert_finish "$TEST_ID"
step "next: ./run-scenario.sh round-trip"
