#!/usr/bin/env bash
# Shared plumbing for the I2 fleet scripts (spec: plan/fleet/README.md).
# Sourced by provision.sh / serve.sh / introduce.sh / run-scenario.sh /
# teardown.sh — never executed on its own.
#
# What you write in a fleet script:
#
#     source "$(dirname "$0")/lib.sh"
#     fleet_common_args "$@"                       # eats --dry-run
#     doctl_run compute droplet list               # token: env of doctl only
#     run_ssh alice akson-whoami 'akson whoami'    # 2nd arg = dry-run fixture
#     assert_that i2-introduce pins-peer ok 'alice pinned bob'
#
# The one rule this file exists to enforce: the DigitalOcean token is read
# from $DO_TOKEN_FILE into the environment of ONE `doctl` process and nowhere
# else. Never an argv word (`ps` would show it), never a file on a droplet,
# never a log line, never a byte of evidence, never committed. `doctl_run` is
# the only reader; `run_ssh`/`run_scp` refuse to carry anything that looks
# like a DO token to a droplet.

set -euo pipefail

# --------------------------------------------------------------- refusals ---
# xtrace would print doctl_run's command substitution, i.e. the token. Refuse
# rather than leak; --dry-run is the debugging mode.
case $- in
*x*)
  cat >&2 <<'TRACE'
fleet: refusing to run under xtrace — the DO token substitution would be traced.
       Use --dry-run to see the exact command sequence instead.
TRACE
  exit 2
  ;;
esac

# --------------------------------------------------------------- constants ---
FLEET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
FLEET_TAG="${FLEET_TAG:-akson-i2}"
FLEET_FIREWALL_NAME="${FLEET_FIREWALL_NAME:-$FLEET_TAG}"
FLEET_REGION="${FLEET_REGION:-fra1}"
FLEET_SIZE="${FLEET_SIZE:-s-2vcpu-4gb}"
# Ubuntu 22.04, not 24.04: 24.04 gates unprivileged user namespaces behind
# kernel.apparmor_restrict_unprivileged_userns and akson's clean worker needs
# them (I2 sheet, Topology). provision.sh applies the sysctl if overridden.
FLEET_IMAGE="${FLEET_IMAGE:-ubuntu-22-04-x64}"
FLEET_VPC="${FLEET_VPC:-}"                       # empty ⇒ resolve region default
FLEET_OPERATOR="${FLEET_OPERATOR:-ops}"          # non-root sudo user, enable-linger
FLEET_HOURLY_USD="${FLEET_HOURLY_USD:-0.036}"    # per droplet, s-2vcpu-4gb
FLEET_RELEASE_TAG="${FLEET_RELEASE_TAG:-}"       # set ⇒ verified-release path
FLEET_RELEASE_REPO="${FLEET_RELEASE_REPO:-zarbafian/akson}"

# akson's RECEIVE ports (akson/bench/README.md). There is no PAIR port and no
# pairing listener: first contact is the ADR-0015 introduction on RECEIVE.
RECEIVE_PORT_ALICE="${RECEIVE_PORT_ALICE:-18443}"
RECEIVE_PORT_BOB="${RECEIVE_PORT_BOB:-18444}"
# Ports that must be absent from the inbound rule dump in addition to the
# exact-set check below. Empty by default: akson never had a pairing port, so
# the real assertion is "the inbound set is exactly {ssh, receive_a, receive_b}".
FLEET_FORBIDDEN_PORTS="${FLEET_FORBIDDEN_PORTS:-}"

DO_TOKEN_FILE="${DO_TOKEN_FILE:-$HOME/.api/do}"
EVIDENCE_DIR="${FLEET_EVIDENCE_DIR:-$FLEET_DIR/evidence}"
STATE_FILE="$EVIDENCE_DIR/fleet-state.json"

# The three workspaces the pair runs. Resolved relative to this repo's parent
# so a checkout layout of ~/agentic/{kovee,byom,akson} just works.
# (Read by provision.sh, hence exported rather than left as bare globals.)
FAMILY_ROOT="${FLEET_FAMILY_ROOT:-$(cd "$FLEET_DIR/../../.." && pwd)}"
export AKSON_REPO="${FLEET_AKSON_REPO:-$FAMILY_ROOT/akson}"
export BYOM_REPO="${FLEET_BYOM_REPO:-$FAMILY_ROOT/byom}"
export KOVEE_REPO="${FLEET_KOVEE_REPO:-$(cd "$FLEET_DIR/../.." && pwd)}"

DRY_RUN="${FLEET_DRY_RUN:-0}"
FLEET_ARGS=()
FLEET_ASSERT_FAIL=0
FLEET_ASSERT_TOTAL=0

SSH_OPTS=(
  -o BatchMode=yes
  -o StrictHostKeyChecking=accept-new
  -o ControlMaster=auto
  -o ControlPath="$HOME/.ssh/kovee-i2-%r@%h:%p"
  -o ControlPersist=300
)

# ----------------------------------------------------------------- logging ---
# The driver's narration goes to a descriptor duplicated from stderr when this
# file is sourced. That matters: callers write `run_ssh … >file 2>&1` to capture
# a REMOTE command's output into evidence, and the driver's own `+ ssh …` lines
# must not end up inside that evidence file — they belong on the operator's
# terminal, in order, next to everything else.
exec {FLEET_LOG_FD}>&2

log() { printf '%s\n' "$*" >&"$FLEET_LOG_FD"; }
step() { printf '\n==> %s\n' "$*" >&"$FLEET_LOG_FD"; }
note() { printf '    %s\n' "$*" >&"$FLEET_LOG_FD"; }
warn() { printf '!!  %s\n' "$*" >&"$FLEET_LOG_FD"; }
die() {
  printf '\nfleet: %s\n' "$*" >&"$FLEET_LOG_FD"
  exit 1
}

# `+ cmd` — the exact command line, printed in both dry-run and live mode so a
# log always says what ran.
_show() { printf '  + %s\n' "$*" >&"$FLEET_LOG_FD"; }

dry() { [[ ${DRY_RUN:-0} == 1 ]]; }

# Shell-quote for display: readable when it can be, correct when it cannot.
shq() {
  local a parts=()
  for a in "$@"; do
    if [[ $a =~ ^[A-Za-z0-9_@%+=:,./-]+$ ]]; then
      parts+=("$a")
    else
      parts+=("'${a//\'/\'\\\'\'}'")
    fi
  done
  printf '%s' "${parts[*]}"
}

fleet_common_args() {
  FLEET_ARGS=()
  while (($#)); do
    case $1 in
    --dry-run) DRY_RUN=1 ;;
    --live) DRY_RUN=0 ;;
    *) FLEET_ARGS+=("$1") ;;
    esac
    shift
  done
}

fleet_banner() {
  if dry; then
    log "── DRY RUN: no DigitalOcean API call is made, nothing is created, \$0.00 is spent."
  else
    log "── LIVE: this creates billable DigitalOcean resources. teardown.sh destroys them."
  fi
}

# ------------------------------------------------------------- the token ----
# Fail closed, never prompt.
require_do_token() {
  [[ -f $DO_TOKEN_FILE ]] || die "no DigitalOcean token at $DO_TOKEN_FILE

The fleet scripts read the token from that file at runtime and never prompt.
Create it with the token as its only content:

    install -m 0600 /dev/null $DO_TOKEN_FILE
    # paste the token into it, no trailing newline needed

Override the location with DO_TOKEN_FILE=/path/to/token."
  [[ -s $DO_TOKEN_FILE ]] || die "$DO_TOKEN_FILE is empty"
  local mode
  mode="$(stat -c '%a' "$DO_TOKEN_FILE")"
  case $mode in
  600 | 400) ;;
  *) warn "$DO_TOKEN_FILE is mode $mode — tighten it: chmod 600 $DO_TOKEN_FILE" ;;
  esac
}

# What the log shows in place of the token: the path it is read from. The
# printed form is literal shell, deliberately unexpanded.
# shellcheck disable=SC2016
_token_prefix() { printf 'DIGITALOCEAN_ACCESS_TOKEN="$(tr -d '"'"'[:space:]'"'"' < %s)"' "$DO_TOKEN_FILE"; }

# doctl_run <doctl args…>
#   The token enters the environment of this one process by an assignment
#   prefix — it is never an argv word, so `ps` cannot see it. Dry-run prints
#   and returns without calling the API at all.
doctl_run() {
  _show "$(_token_prefix) doctl $(shq "$@")"
  dry && return 0
  require_do_token
  DIGITALOCEAN_ACCESS_TOKEN="$(tr -d '[:space:]' <"$DO_TOKEN_FILE")" doctl "$@"
}

# doctl_out <fixture-name> <doctl args…>
#   Same, for calls whose stdout the script consumes. In dry-run the canned
#   fixture stands in, so the assertion code downstream is genuinely executed.
doctl_out() {
  local fixture="$1"
  shift
  _show "$(_token_prefix) doctl $(shq "$@")"
  if dry; then
    fixture "$fixture"
    return 0
  fi
  require_do_token
  DIGITALOCEAN_ACCESS_TOKEN="$(tr -d '[:space:]' <"$DO_TOKEN_FILE")" doctl "$@"
}

# A remote command must never carry a DO token to a droplet. Checked by shape,
# not by value: loading the token to compare it would be the very thing we are
# avoiding.
_guard_remote() {
  local cmd="$*"
  case $cmd in
  *dop_v1_* | *dop_v1* | *DIGITALOCEAN_ACCESS_TOKEN* | *DIGITALOCEAN_TOKEN* | *"$DO_TOKEN_FILE"*)
    die "refusing to send a DigitalOcean token to a droplet.
The droplets create no infrastructure and hold no DO token (plan/fleet/README.md).
Offending remote command: $cmd"
    ;;
  esac
}

# run_ssh <target> <fixture-name> <remote command…>
# The remote command is a string built here on purpose (the house pattern from
# akson/bench: the droplets run no agent, the driver composes what they run), so
# client-side expansion is intended, not a mistake.
# shellcheck disable=SC2029
run_ssh() {
  local target="$1" fixture="$2"
  shift 2
  _guard_remote "$@"
  _show "ssh $target $(shq "$*")"
  if dry; then
    fixture "$fixture"
    return 0
  fi
  ssh "${SSH_OPTS[@]}" "$target" "$@"
}

# run_ssh_stdin <target> <fixture> <local-file> <remote command…>
#   Streams a local file to the remote command's stdin. Used for provider API
#   keys: the secret never appears in argv on either side.
# shellcheck disable=SC2029
run_ssh_stdin() {
  local target="$1" fixture="$2" src="$3"
  shift 3
  _guard_remote "$@"
  _show "ssh $target $(shq "$*") < $src"
  if dry; then
    fixture "$fixture"
    return 0
  fi
  ssh "${SSH_OPTS[@]}" "$target" "$@" <"$src"
}

run_scp() {
  _show "scp $(shq "$@")"
  dry && return 0
  scp "${SSH_OPTS[@]}" "$@"
}

run_rsync() {
  _show "rsync $(shq "$@")"
  dry && return 0
  rsync "$@"
}

# ---------------------------------------------------------------- fixtures ---
# Canned stdout for dry-run, so every script's control flow, parsing and
# assertions run end to end with no API call and no droplet.
fixture() {
  case ${1:-} in
  vpcs-list) printf '9d76b1c4-4b3f-4e1a-9f0a-3c2b1a0d9e8f    %s    true\n' "$FLEET_REGION" ;;
  ssh-key-list) printf '31415926    kovee-i2    3d:41:59:26:53:58:97:93:23:84:62:64:33:83:27:95\n' ;;
  droplet-list-names) printf '' ;;
  firewall-list) printf '' ;;
  droplet-create) printf '501000001    alice\n501000002    bob\n' ;;
  droplet-get-alice) printf 'active    203.0.113.11    10.114.0.2\n' ;;
  droplet-get-bob) printf 'active    203.0.113.12    10.114.0.3\n' ;;
  firewall-create) printf 'f1e2d3c4-0a1b-4c2d-8e3f-5a6b7c8d9e0f\n' ;;
  firewall-json) fixture_firewall_json ;;
  # FLEET_DRY_SURVIVOR=1 makes the post-delete listing non-empty, so the
  # "exit non-zero if anything survived" branch is exercisable in --dry-run.
  droplet-list-tag-empty)
    [[ ${FLEET_DRY_SURVIVOR:-0} == 1 ]] && printf '501000001    alice    active\n'
    ;;
  droplet-list-tag) printf '501000001    alice\n501000002    bob\n' ;;
  volume-list) printf '' ;;
  akson-doctor) printf 'akson doctor — sandbox capabilities, as seen by the CLI\n  unprivileged userns  available\n  bubblewrap           available\n  delegated cgroup     available\n\nready: every required capability is available.\n' ;;
  deploy-verify) printf '== host sandbox preconditions\n  unprivileged userns: available\n== systemd-analyze security (if systemd is present)\n  -- deploy/akson-daemon.service\n     no sandbox-hostile directive active\n  -- deploy/akson-coord.service\n     no sandbox-hostile directive active\nverify: done\n' ;;
  systemd-analyze-security) printf 'Overall exposure level for akson-daemon.service: 3.9 OK 🙂\n' ;;
  a06-probe) printf '[a0.6] confined worker ran to completion\n[a0.6] worker report: CLEAN — no credential file, no secret env var\n[a0.6] unconfined control found 11 leak(s) — the probe works, the sandbox is what stops it\ntest result: ok. 1 passed; 0 failed\n' ;;
  akson-token) printf 'akson1qqxw8yv3k2m9r7t5s4h6j8l0p2n4b6v8c0x2z4a6s8d0f2g4h6\n' ;;
  akson-whoami) printf 'agent:     alice\nissuer:    orgA\ninterface: https://10.114.0.2:18443/a2a\n' ;;
  akson-peer-list) printf 'imported bob  root sha256:9f86d081884c7d659a2feaa0c55ad015  pinned  introduced\n' ;;
  ss-listen-alice) printf 'LISTEN 0 128 10.114.0.2:18443 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:22 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n' ;;
  ss-listen-bob) printf 'LISTEN 0 128 10.114.0.3:18444 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n' ;;
  stack-status) printf 'koveed inactive\nbyomd inactive\naksond inactive\n' ;;
  stack-status-up) printf 'koveed active\nbyomd active\naksond active\n' ;;
  kovee-events-alice) fixture_kovee_events_alice ;;
  kovee-events-bob) printf '{"type":"kovee.contribution.appended","project_sequence":1}\n' ;;
  byom-events-alice) printf '{"type":"byom.pledge.finalized","revision":7,"authored_by":"alice-society"}\n' ;;
  byom-events-bob) fixture_byom_events_bob ;;
  akson-task-sent) printf 'task-7f3a  to bob  delivered\n' ;;
  akson-task-outcomes) printf 'task-7f3a  outcome verified  signed by bob\n' ;;
  akson-task-send) printf 'sent task-7f3a to bob (consent receipt: cr-4a1)\n' ;;
  akson-task-deliver) printf 'delivered task-7f3a\n' ;;
  git-describe) printf 'source-build 0000000000000000000000000000000000000000 clean\n' ;;
  bench-matrix) printf 'provider x scenario  n/ok/p50/p95\nopenai s1-security 10/10/2.11/2.60\n' ;;
  side-driver) printf '{"step":"ok","records":"written through this side own daemons"}\n' ;;
  replay-digest) printf 'replay: byte-identical to the pre-crash transcript\n' ;;
  '') printf '' ;;
  *) printf '' ;;
  esac
}

# Ledger shapes the scenario assertions read, so a dry run exercises the
# assertion logic itself and not just the command printing.
fixture_kovee_events_alice() {
  cat <<'JSONL'
{"type":"kovee.act_intent.finalized","project_sequence":11}
{"type":"kovee.permit.consumed","permit_ref":"prm-4a1"}
{"type":"kovee.consent.consumed","receipt":"cr-4a1"}
{"type":"kovee.effect.dispatched","aspect_generation":3}
{"type":"kovee.result.verified","generation":2}
{"type":"kovee.result.quarantined","retained":true,"reason":"generation_advanced"}
{"type":"kovee.cancellation.recorded","mode":"advisory"}
{"type":"kovee.trust.suspended","reason":"peer_binding_changed"}
{"type":"kovee.capability_matrix.recorded","profile":"confined-worker"}
JSONL
}

fixture_byom_events_bob() {
  cat <<'JSONL'
{"type":"byom.standing.admitted","surface":"governance","authored_by":"bob-governance"}
{"type":"byom.pledge.finalized","seats":2,"authored_by":"bob-society"}
{"type":"byom.disclosure.act.recorded","authored_by":"bob-participant"}
{"type":"byom.commit.ambiguous","point":"standing-commit"}
{"type":"byom.restore_lineage.verified","complete":true}
{"type":"byom.restore_lineage.refused","reason":"incomplete"}
JSONL
}

# The rule dump the firewall we ask for produces. assert_no_pair_port runs
# against this in dry-run, so the assertion itself is exercised.
fixture_firewall_json() {
  cat <<'JSON'
[
  {
    "id": "f1e2d3c4-0a1b-4c2d-8e3f-5a6b7c8d9e0f",
    "name": "akson-i2",
    "status": "succeeded",
    "inbound_rules": [
      {"protocol": "tcp", "ports": "22", "sources": {"addresses": ["203.0.113.9/32"]}},
      {"protocol": "tcp", "ports": "18443", "sources": {"addresses": ["10.114.0.3/32"]}},
      {"protocol": "tcp", "ports": "18444", "sources": {"addresses": ["10.114.0.2/32"]}}
    ],
    "outbound_rules": [
      {"protocol": "tcp", "ports": "443", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
      {"protocol": "udp", "ports": "53", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
      {"protocol": "tcp", "ports": "53", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}}
    ],
    "droplet_ids": [501000001, 501000002],
    "tags": ["akson-i2"]
  }
]
JSON
}

# ------------------------------------------------------------------ state ---
# evidence/fleet-state.json is written the instant the droplets exist, before
# anything else can fail, so teardown.sh can always find them (plan §teardown).
state_init() {
  mkdir -p "$EVIDENCE_DIR"
  local json="$1"
  if dry; then
    _show "write $STATE_FILE"
    printf '%s\n' "$json" >"$STATE_FILE.dry"
    mv "$STATE_FILE.dry" "$STATE_FILE"
    return 0
  fi
  printf '%s\n' "$json" >"$STATE_FILE.tmp"
  mv "$STATE_FILE.tmp" "$STATE_FILE"
  sync_dir "$EVIDENCE_DIR"
  note "state: $STATE_FILE"
}

# state_patch <jq filter> [jq args…] — atomic read-modify-write.
state_patch() {
  [[ -f $STATE_FILE ]] || die "no $STATE_FILE to patch"
  local filter="$1"
  shift
  jq "$@" "$filter" "$STATE_FILE" >"$STATE_FILE.tmp"
  mv "$STATE_FILE.tmp" "$STATE_FILE"
  sync_dir "$EVIDENCE_DIR"
}

state_get() {
  [[ -f $STATE_FILE ]] || return 1
  jq -r "$1" "$STATE_FILE"
}

sync_dir() {
  if command -v sync >/dev/null 2>&1; then
    sync "$1" 2>/dev/null || true
  fi
}

# ssh target for a role, from the state file (public IP + operator account).
host_target() {
  local role="$1" ip
  ip="$(state_get ".hosts[] | select(.role==\"$role\") | .public_ip")" ||
    die "no host '$role' in $STATE_FILE — run provision.sh first"
  [[ -n $ip && $ip != null ]] || die "host '$role' has no public IP yet in $STATE_FILE"
  printf '%s@%s' "$FLEET_OPERATOR" "$ip"
}

host_private_ip() { state_get ".hosts[] | select(.role==\"$1\") | .private_ip"; }
host_receive_port() { state_get ".hosts[] | select(.role==\"$1\") | .receive_port"; }

receive_port_for() {
  case $1 in
  alice) printf '%s' "$RECEIVE_PORT_ALICE" ;;
  bob) printf '%s' "$RECEIVE_PORT_BOB" ;;
  *) die "unknown role '$1' (alice|bob)" ;;
  esac
}

# --------------------------------------------------------------- evidence ---
# One directory per test id on the driver, never on the droplets. Per-side
# subdirectories: each side's ledger extracts stay in their own directory and
# are never folded into a single view (I2 sheet: "verified from each side's own
# ledgers, never merged").
evidence_for() {
  local test_id="$1" dir
  dir="$EVIDENCE_DIR/$test_id"
  mkdir -p "$dir/alice" "$dir/bob"
  printf '%s' "$dir"
}

# Start a test id from a clean slate, so steps.jsonl / assertions.jsonl are the
# record of THIS run and never an accumulation across runs.
evidence_reset() {
  local dir="$EVIDENCE_DIR/$1"
  rm -rf "$dir"
  evidence_for "$1" >/dev/null
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

emit_step() { # <test-id> <step> <status> <detail>
  local dir
  dir="$(evidence_for "$1")"
  jq -nc --arg ts "$(now_iso)" --arg step "$2" --arg status "$3" --arg detail "${4:-}" \
    '{ts:$ts, step:$step, status:$status, detail:$detail}' >>"$dir/steps.jsonl"
}

# assert_that <test-id> <assertion> <ok|fail> <note> [evidence-path]
assert_that() {
  local dir ok
  dir="$(evidence_for "$1")"
  ok=$([[ $3 == ok ]] && echo true || echo false)
  FLEET_ASSERT_TOTAL=$((FLEET_ASSERT_TOTAL + 1))
  [[ $3 == ok ]] || FLEET_ASSERT_FAIL=$((FLEET_ASSERT_FAIL + 1))
  jq -nc --arg ts "$(now_iso)" --arg id "$2" --argjson ok "$ok" \
    --arg note "${4:-}" --arg ev "${5:-}" \
    '{ts:$ts, assertion:$id, ok:$ok, note:$note, evidence:$ev}' >>"$dir/assertions.jsonl"
  if [[ $3 == ok ]]; then
    note "PASS  $2 — ${4:-}"
  else
    warn "FAIL  $2 — ${4:-}"
  fi
}

# Report and exit non-zero if anything failed. Writes result.json.
assert_finish() { # <test-id>
  local dir
  dir="$(evidence_for "$1")"
  local status=passed
  ((FLEET_ASSERT_FAIL == 0)) || status=failed
  jq -nc --arg ts "$(now_iso)" --arg test "$1" --arg status "$status" \
    --argjson total "$FLEET_ASSERT_TOTAL" --argjson failed "$FLEET_ASSERT_FAIL" \
    --argjson dry "$(dry && echo true || echo false)" \
    '{ts:$ts, test_id:$test, status:$status, assertions:$total, failed:$failed, dry_run:$dry}' \
    >"$dir/result.json"
  step "$1: $status ($FLEET_ASSERT_TOTAL assertions, $FLEET_ASSERT_FAIL failed)"
  note "evidence: $dir"
  ((FLEET_ASSERT_FAIL == 0)) || exit 1
}

# Save a captured blob under a side's own directory and echo the path.
save_side() { # <test-id> <side> <filename> ; content on stdin
  local dir
  dir="$(evidence_for "$1")/$2"
  mkdir -p "$dir"
  cat >"$dir/$3"
  printf '%s' "$dir/$3"
}

# The structural half of "never merged": both sides present, neither empty,
# and no file directly under the test-id directory holding ledger extracts.
assert_ledgers_unmerged() { # <test-id>
  local dir a b stray
  dir="$(evidence_for "$1")"
  a="$(find "$dir/alice" -type f 2>/dev/null | wc -l)"
  b="$(find "$dir/bob" -type f 2>/dev/null | wc -l)"
  stray="$(find "$dir" -maxdepth 1 -type f \( -name '*ledger*' -o -name '*merged*' -o -name '*combined*' \) 2>/dev/null | wc -l)"
  if ((a > 0 && b > 0 && stray == 0)); then
    assert_that "$1" ledgers-per-side-unmerged ok \
      "alice: $a file(s), bob: $b file(s), no combined view" "$dir"
  else
    assert_that "$1" ledgers-per-side-unmerged fail \
      "alice: $a file(s), bob: $b file(s), stray combined files: $stray" "$dir"
  fi
}

# ----------------------------------------------------- firewall assertions ---
# No PAIR port. akson has no pairing listener at all (ADR-0015: first contact
# is the introduction on RECEIVE), so there is no historical port number to
# look for — the honest, machine-checkable claim is that the inbound rule set
# is EXACTLY {ssh, alice's RECEIVE, bob's RECEIVE} and nothing else, each
# scoped to one source address. FLEET_FORBIDDEN_PORTS adds explicit names.
assert_no_pair_port() { # <test-id> <firewall-json-file>
  local test_id="$1" file="$2" allowed extra ranges p
  allowed="$(printf '["22","%s","%s"]' "$RECEIVE_PORT_ALICE" "$RECEIVE_PORT_BOB")"

  extra="$(jq -r --argjson allowed "$allowed" \
    '[.[0].inbound_rules[].ports] - $allowed | join(",")' "$file")"
  if [[ -z $extra ]]; then
    assert_that "$test_id" no-pair-port ok \
      "inbound rules are exactly ssh/$RECEIVE_PORT_ALICE/$RECEIVE_PORT_BOB — no pairing surface is reachable" "$file"
  else
    assert_that "$test_id" no-pair-port fail \
      "unexpected inbound port(s) in the rule dump: $extra" "$file"
  fi

  # A range or "all ports" would smuggle a pairing port past the set check.
  ranges="$(jq -r '[.[0].inbound_rules[].ports | select(test("-") or . == "0" or . == "all")] | join(",")' "$file")"
  if [[ -z ${ranges:-} ]]; then
    assert_that "$test_id" no-inbound-port-range ok \
      "every inbound rule names a single port" "$file"
  else
    assert_that "$test_id" no-inbound-port-range fail \
      "inbound rule uses a range or all-ports: $ranges" "$file"
  fi

  for p in ${FLEET_FORBIDDEN_PORTS:-}; do
    if jq -e --arg p "$p" 'any(.[0].inbound_rules[]; .ports == $p)' "$file" >/dev/null; then
      assert_that "$test_id" "no-port-$p" fail "port $p is open inbound" "$file"
    else
      assert_that "$test_id" "no-port-$p" ok "port $p is absent from the rule dump" "$file"
    fi
  done
}

# Each RECEIVE port is reachable from exactly one address: the other droplet.
assert_receive_scoped_to_peer() { # <test-id> <firewall-json> <port> <peer-ip>
  local got
  got="$(jq -r --arg p "$3" '.[0].inbound_rules[] | select(.ports==$p) | .sources.addresses | join(",")' "$2")"
  if [[ $got == "$4/32" ]]; then
    assert_that "$1" "receive-$3-peer-only" ok "port $3 reachable only from $4/32" "$2"
  else
    assert_that "$1" "receive-$3-peer-only" fail "port $3 sources are [$got], expected $4/32" "$2"
  fi
}

# ------------------------------------------------------------- preflight ----
require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "missing required command: $c"
  done
}

# doctl must exist; its version goes into the run report.
doctl_version() {
  require_cmd doctl
  doctl version 2>/dev/null | head -1
}
