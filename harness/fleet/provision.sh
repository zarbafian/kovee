#!/usr/bin/env bash
# I2 `i2-provision` — stand up the sovereign pair on DigitalOcean.
#
#   ./provision.sh alice bob [--dry-run]
#
# Spec: plan/fleet/README.md §provision.sh. Seven phases, in this order:
#
#   1 preflight on the driver     doctl, token, ssh key, names free
#   2 create droplets             ids written to evidence/fleet-state.json
#                                 IMMEDIATELY, before anything else can fail
#   3 firewall                    RECEIVE between the two droplets + ssh from
#                                 the driver; no PAIR port
#   4 users                       akson/akson-coord/kovee/byom + enable-linger
#   5 artifacts                   verified release, else recorded source build
#   6 install units               akson/deploy/*, daemon-reload, DO NOT start
#   7 acceptance, per host        akson doctor + deploy/verify.sh + A0.6 probe
#
# Provisioning is NOT done until all three phase-7 checks pass on each host. A
# host that fails any of them is left `ready: false` in the state file and this
# script exits non-zero.
#
# The DigitalOcean token is read from ~/.api/do into the environment of each
# doctl process and nowhere else. It is never written to a droplet, never an
# argv word, never logged. Absent ⇒ fail closed, no prompt.
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

TEST_ID=i2-provision

usage() {
  cat <<'USAGE' >&2
usage: ./provision.sh <alice-name> <bob-name> [--dry-run]

  --dry-run   print the exact command sequence and make no API call at all

env overrides: FLEET_REGION FLEET_SIZE FLEET_IMAGE FLEET_VPC FLEET_TAG
               FLEET_SSH_KEY_NAME FLEET_DRIVER_CIDR FLEET_OPERATOR
               FLEET_RELEASE_TAG (verified-release path; else source build)
               FLEET_PROVIDER_KEYS=1 (place ~/.api/{claude,openai} on the hosts)
USAGE
  exit 2
}

fleet_common_args "$@"
((${#FLEET_ARGS[@]} == 2)) || usage
ALICE_NAME="${FLEET_ARGS[0]}"
BOB_NAME="${FLEET_ARGS[1]}"
fleet_banner

evidence_reset "$TEST_ID"
EV="$(evidence_for "$TEST_ID")"
STARTED_EPOCH="$(date -u +%s)"

# ═══ 1. preflight on the driver ══════════════════════════════════════════════
step "1/7 preflight on the driver"
require_cmd jq ssh scp rsync date find
note "doctl:     $(doctl_version)"
require_do_token
note "do token:  $DO_TOKEN_FILE (read into doctl's environment only, never argv)"

# Authenticated? A read-only account call; the first proof the token works.
doctl_run account get --format Email,Status --no-header >"$EV/account.txt" 2>/dev/null ||
  { dry || die "doctl could not authenticate with the token in $DO_TOKEN_FILE"; }

# The SSH key to inject: named in DO, fingerprint resolved from DO's own list.
SSH_KEY_NAME="${FLEET_SSH_KEY_NAME:-kovee-i2}"
SSH_FINGERPRINT="$(doctl_out ssh-key-list compute ssh-key list --format ID,Name,FingerPrint --no-header |
  awk -v n="$SSH_KEY_NAME" '$2 == n {print $3; exit}')"
[[ -n $SSH_FINGERPRINT ]] ||
  die "no DigitalOcean SSH key named '$SSH_KEY_NAME'.
Add your public key in the DO control panel (or \`doctl compute ssh-key import\`)
and set FLEET_SSH_KEY_NAME to its name. provision.sh never creates one for you:
the key that can log into the pair is your decision, not the script's."
note "ssh key:   $SSH_KEY_NAME ($SSH_FINGERPRINT)"

# SSH is open only to the driver's own address.
DRIVER_CIDR="${FLEET_DRIVER_CIDR:-}"
if [[ -z $DRIVER_CIDR ]]; then
  if dry; then
    DRIVER_CIDR="203.0.113.9/32"
    note "driver:    $DRIVER_CIDR (dry-run placeholder; live mode asks api.ipify.org)"
  else
    _show "curl -sS https://api.ipify.org"
    DRIVER_CIDR="$(curl -sS --max-time 10 https://api.ipify.org)/32" ||
      die "could not determine this driver's public address; set FLEET_DRIVER_CIDR=x.y.z.w/32"
    note "driver:    $DRIVER_CIDR"
  fi
fi

# Never silently reuse a host.
EXISTING="$(doctl_out droplet-list-names compute droplet list --format Name --no-header |
  grep -Fx -e "$ALICE_NAME" -e "$BOB_NAME" || true)"
[[ -z $EXISTING ]] ||
  die "a droplet already exists with one of the requested names: ${EXISTING//$'\n'/ }
Refusing to reuse a host. Destroy it (./teardown.sh) or pick other names."

EXISTING_FW="$(doctl_out firewall-list compute firewall list --format Name --no-header |
  grep -Fx "$FLEET_FIREWALL_NAME" || true)"
[[ -z $EXISTING_FW ]] ||
  die "a firewall named '$FLEET_FIREWALL_NAME' already exists — ./teardown.sh first"

# Same region, same VPC, explicitly — not by luck.
VPC_UUID="$FLEET_VPC"
if [[ -z $VPC_UUID ]]; then
  VPC_UUID="$(doctl_out vpcs-list vpcs list --format ID,Region,Default --no-header |
    awk -v r="$FLEET_REGION" '$2 == r && $3 == "true" {print $1; exit}')"
  [[ -n $VPC_UUID ]] || die "no default VPC in $FLEET_REGION; set FLEET_VPC=<uuid>"
fi
note "region:    $FLEET_REGION   vpc: $VPC_UUID   size: $FLEET_SIZE   image: $FLEET_IMAGE"
[[ $FLEET_IMAGE == ubuntu-22-04-* ]] ||
  warn "image is $FLEET_IMAGE, not Ubuntu 22.04 — phase 6 will apply
    kernel.apparmor_restrict_unprivileged_userns=0 and record it (I2 sheet, Topology)."
emit_step "$TEST_ID" preflight ok "region=$FLEET_REGION vpc=$VPC_UUID image=$FLEET_IMAGE"

# ═══ 2. create the droplets ══════════════════════════════════════════════════
step "2/7 create two droplets (tag $FLEET_TAG)"
# Deliberately WITHOUT --wait: the ids come back immediately and go into
# fleet-state.json before we block on anything. A crash while waiting for the
# droplets to become active must never orphan a paid host.
CREATED="$(doctl_out droplet-create compute droplet create "$ALICE_NAME" "$BOB_NAME" \
  --image "$FLEET_IMAGE" \
  --size "$FLEET_SIZE" \
  --region "$FLEET_REGION" \
  --vpc-uuid "$VPC_UUID" \
  --ssh-keys "$SSH_FINGERPRINT" \
  --tag-name "$FLEET_TAG" \
  --enable-monitoring \
  --format ID,Name --no-header)"

ALICE_ID="$(printf '%s\n' "$CREATED" | awk -v n="$ALICE_NAME" '$2 == n {print $1; exit}')"
BOB_ID="$(printf '%s\n' "$CREATED" | awk -v n="$BOB_NAME" '$2 == n {print $1; exit}')"
[[ -n $ALICE_ID && -n $BOB_ID ]] || die "could not parse droplet ids from:
$CREATED"

state_init "$(jq -nc \
  --arg schema kovee-fleet-state/1 \
  --arg tag "$FLEET_TAG" \
  --arg region "$FLEET_REGION" \
  --arg image "$FLEET_IMAGE" \
  --arg size "$FLEET_SIZE" \
  --arg vpc "$VPC_UUID" \
  --arg fw_name "$FLEET_FIREWALL_NAME" \
  --arg key "$SSH_FINGERPRINT" \
  --arg driver "$DRIVER_CIDR" \
  --arg operator "$FLEET_OPERATOR" \
  --arg created "$(now_iso)" \
  --argjson created_epoch "$STARTED_EPOCH" \
  --argjson rate "$FLEET_HOURLY_USD" \
  --arg aname "$ALICE_NAME" --arg aid "$ALICE_ID" --argjson aport "$RECEIVE_PORT_ALICE" \
  --arg bname "$BOB_NAME" --arg bid "$BOB_ID" --argjson bport "$RECEIVE_PORT_BOB" \
  --argjson dry "$(dry && echo true || echo false)" \
  '{schema:$schema, tag:$tag, region:$region, image:$image, size:$size,
    vpc_uuid:$vpc, firewall_name:$fw_name, firewall_id:null,
    ssh_key_fingerprint:$key, driver_cidr:$driver, operator:$operator,
    created_at:$created, created_at_epoch:$created_epoch,
    hourly_usd_per_droplet:$rate, dry_run:$dry, kept:false,
    hosts:[
      {role:"alice", name:$aname, droplet_id:$aid, public_ip:null, private_ip:null,
       receive_port:$aport, ready:false, acceptance:{}},
      {role:"bob",   name:$bname, droplet_id:$bid, public_ip:null, private_ip:null,
       receive_port:$bport, ready:false, acceptance:{}}
    ]}')"
note "fleet-state.json written with droplet ids $ALICE_ID, $BOB_ID — teardown.sh can find them now"
emit_step "$TEST_ID" droplets-created ok "alice=$ALICE_ID bob=$BOB_ID"

# Now it is safe to block.
wait_for_active() { # <role> <droplet-id> <fixture>
  local role="$1" id="$2" fixture="$3" out status pub priv i
  for i in $(seq 1 60); do
    out="$(doctl_out "$fixture" compute droplet get "$id" \
      --format Status,PublicIPv4,PrivateIPv4 --no-header)"
    status="$(printf '%s' "$out" | awk '{print $1}')"
    pub="$(printf '%s' "$out" | awk '{print $2}')"
    priv="$(printf '%s' "$out" | awk '{print $3}')"
    if [[ $status == active && -n $pub && -n $priv ]]; then
      state_patch ".hosts |= map(if .role == \"$role\" then .public_ip = \"$pub\" | .private_ip = \"$priv\" else . end)"
      note "$role: $status  public $pub  private $priv"
      return 0
    fi
    dry && {
      warn "$role never reported active (dry-run fixture)"
      return 1
    }
    log "    waiting for $role ($status), attempt $i/60…"
    sleep 5
  done
  die "$role (droplet $id) never became active — ./teardown.sh"
}
step "2b/7 wait for both droplets to be active"
wait_for_active alice "$ALICE_ID" droplet-get-alice
wait_for_active bob "$BOB_ID" droplet-get-bob

ALICE_PRIV="$(host_private_ip alice)"
BOB_PRIV="$(host_private_ip bob)"
ALICE_SSH="$(host_target alice)"
BOB_SSH="$(host_target bob)"

# ═══ 3. firewall ═════════════════════════════════════════════════════════════
step "3/7 firewall: RECEIVE between the two droplets only, ssh from the driver only"
# Inbound: each host's RECEIVE port from the OTHER host's private address, plus
# ssh from the driver. NO PAIR PORT — akson has no pairing listener at all
# (ADR-0015), and run-scenario/introduce assert its absence from this dump.
# Outbound: 443 (packages, model providers) and DNS.
FW_ID="$(doctl_out firewall-create compute firewall create \
  --name "$FLEET_FIREWALL_NAME" \
  --tag-names "$FLEET_TAG" \
  --inbound-rules "protocol:tcp,ports:22,address:${DRIVER_CIDR} protocol:tcp,ports:${RECEIVE_PORT_ALICE},address:${BOB_PRIV}/32 protocol:tcp,ports:${RECEIVE_PORT_BOB},address:${ALICE_PRIV}/32" \
  --outbound-rules "protocol:tcp,ports:443,address:0.0.0.0/0,address:::/0 protocol:udp,ports:53,address:0.0.0.0/0,address:::/0 protocol:tcp,ports:53,address:0.0.0.0/0,address:::/0" \
  --format ID --no-header)"
[[ -n $FW_ID ]] || die "firewall creation returned no id — ./teardown.sh"
state_patch ".firewall_id = \"$FW_ID\""
emit_step "$TEST_ID" firewall-created ok "id=$FW_ID"

doctl_out firewall-json compute firewall get "$FW_ID" -o json >"$EV/firewall-rules.json"
note "rule dump: $EV/firewall-rules.json"
assert_no_pair_port "$TEST_ID" "$EV/firewall-rules.json"
assert_receive_scoped_to_peer "$TEST_ID" "$EV/firewall-rules.json" "$RECEIVE_PORT_ALICE" "$BOB_PRIV"
assert_receive_scoped_to_peer "$TEST_ID" "$EV/firewall-rules.json" "$RECEIVE_PORT_BOB" "$ALICE_PRIV"

# ═══ 4. users ════════════════════════════════════════════════════════════════
step "4/7 identities: akson, akson-coord, kovee, byom + operator with linger"
# The droplets are reachable as root first; the operator account is created so
# the rest runs as a non-root sudo user (unprivileged userns is happiest that
# way — akson/bench/README.md).
for role in alice bob; do
  ip="$(state_get ".hosts[] | select(.role==\"$role\") | .public_ip")"
  root="root@$ip"
  run_ssh "$root" '' "set -e
    id -u $FLEET_OPERATOR >/dev/null 2>&1 || adduser --disabled-password --gecos '' $FLEET_OPERATOR
    usermod -aG sudo $FLEET_OPERATOR
    install -d -m 0700 -o $FLEET_OPERATOR -g $FLEET_OPERATOR /home/$FLEET_OPERATOR/.ssh
    install -m 0600 -o $FLEET_OPERATOR -g $FLEET_OPERATOR /root/.ssh/authorized_keys /home/$FLEET_OPERATOR/.ssh/authorized_keys
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' $FLEET_OPERATOR > /etc/sudoers.d/90-$FLEET_OPERATOR
    chmod 0440 /etc/sudoers.d/90-$FLEET_OPERATOR
    loginctl enable-linger $FLEET_OPERATOR"
done

# akson's own sysusers fragment, verbatim from akson/deploy — one Unix identity
# per role, so the C4 coordination socket's admission rule is an OS access
# domain and not just a token check (akson/deploy/README.md).
for target in "$ALICE_SSH" "$BOB_SSH"; do
  run_scp "$AKSON_REPO/deploy/sysusers.d/akson.conf" "$target:/tmp/akson.conf"
  run_ssh "$target" '' "set -e
    sudo install -m 0644 /tmp/akson.conf /etc/sysusers.d/akson.conf && rm -f /tmp/akson.conf
    printf 'u kovee - \"Kovee daemon\" /var/lib/kovee -\nu byom  - \"Byom daemon\"  /var/lib/byom  -\n' \\
      | sudo install -m 0644 /dev/stdin /etc/sysusers.d/kovee-i2.conf
    sudo systemd-sysusers
    id akson && id akson-coord && id kovee && id byom
    sudo install -d -m 0700 -o kovee -g kovee /var/lib/kovee
    sudo install -d -m 0700 -o byom  -g byom  /var/lib/byom"
done
emit_step "$TEST_ID" identities ok "akson akson-coord kovee byom $FLEET_OPERATOR(linger)"

# ═══ 5. artifacts ════════════════════════════════════════════════════════════
ARTIFACT_SOURCE=source-build
if [[ -n $FLEET_RELEASE_TAG ]]; then
  step "5/7 artifacts: cut release $FLEET_RELEASE_TAG (digests + attestation)"
  ARTIFACT_SOURCE="verified-release:$FLEET_RELEASE_TAG"
  for target in "$ALICE_SSH" "$BOB_SSH"; do
    run_ssh "$target" '' "set -e
      command -v gh >/dev/null || { sudo apt-get update -qq && sudo apt-get install -y -qq gh; }
      rm -rf ~/akson-release && mkdir -p ~/akson-release && cd ~/akson-release
      gh release download $FLEET_RELEASE_TAG --repo $FLEET_RELEASE_REPO --dir .
      sha256sum --check --ignore-missing SHA256SUMS
      for f in *; do
        gh attestation verify \"\$f\" --repo $FLEET_RELEASE_REPO \\
          --signer-workflow $FLEET_RELEASE_REPO/.github/workflows/release.yml || { echo \"ATTESTATION FAILED: \$f\"; exit 1; }
      done"
  done
  # The A0.6 probe is a test binary, not a release asset, so the akson source
  # tree still has to be present for phase 7c. Recorded, not hidden.
  note "syncing akson source anyway: the A0.6 probe is a cargo test, not a release asset"
else
  step "5/7 artifacts: rsync the three workspaces and build --locked --release"
  warn "SOURCE BUILD, not a verified artifact (A0.1 has a release workflow but no cut
    release yet). Recorded as such in the run report — do not imply provenance."
fi

for target in "$ALICE_SSH" "$BOB_SSH"; do
  run_ssh "$target" '' "set -e
    command -v cargo >/dev/null || { curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal; }
    sudo apt-get update -qq
    sudo apt-get install -y -qq bubblewrap build-essential pkg-config libssl-dev git curl jq"
  for repo in "$AKSON_REPO" "$BYOM_REPO" "$KOVEE_REPO"; do
    run_rsync -a --delete --exclude target/ --exclude .git/ \
      -e "ssh ${SSH_OPTS[*]}" "$repo/" "$target:~/$(basename "$repo")/"
  done
  run_ssh "$target" '' "set -e
    export PATH=\$HOME/.cargo/bin:\$PATH
    CARGO_INCREMENTAL=0 cargo build --locked --release --manifest-path ~/akson/Cargo.toml \\
      -p aksond -p akson-cli
    CARGO_INCREMENTAL=0 cargo build --locked --release --manifest-path ~/byom/Cargo.toml \\
      -p byomd -p byom-cli -p byom-mcp
    CARGO_INCREMENTAL=0 cargo build --locked --release --manifest-path ~/kovee/Cargo.toml \\
      -p koveed -p kovee-cli -p kovee-mcp"
done

# Exactly what was deployed, from git, per repo — for the run report.
{
  printf '| repo | commit | dirty |\n|---|---|---|\n'
  for repo in "$AKSON_REPO" "$BYOM_REPO" "$KOVEE_REPO"; do
    if [[ -d $repo/.git ]]; then
      printf '| %s | %s | %s |\n' "$(basename "$repo")" \
        "$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)" \
        "$([[ -n $(git -C "$repo" status --porcelain 2>/dev/null) ]] && echo yes || echo no)"
    fi
  done
} >"$EV/artifacts.md"
emit_step "$TEST_ID" artifacts ok "$ARTIFACT_SOURCE"

# ═══ 6. install the hardened units (root); do NOT start ══════════════════════
step "6/7 install akson/deploy units as root, daemon-reload, do not start"
for role in alice bob; do
  target="$(host_target "$role")"
  priv="$(host_private_ip "$role")"
  port="$(receive_port_for "$role")"
  issuer=$([[ $role == alice ]] && echo orgA || echo orgB)
  run_ssh "$target" '' "set -e
    sudo install -m 0755 ~/akson/target/release/aksond /usr/local/bin/aksond
    sudo install -m 0755 ~/akson/target/release/akson  /usr/local/bin/akson
    sudo install -m 0755 ~/byom/target/release/byomd   /usr/local/bin/byomd
    sudo install -m 0755 ~/byom/target/release/byom    /usr/local/bin/byom
    sudo install -m 0755 ~/kovee/target/release/koveed /usr/local/bin/koveed
    sudo install -m 0755 ~/kovee/target/release/kovee  /usr/local/bin/kovee
    sudo install -m 0644 ~/akson/deploy/akson-daemon.service /etc/systemd/system/akson-daemon.service
    sudo install -m 0644 ~/akson/deploy/akson-coord.service  /etc/systemd/system/akson-coord.service
    sudo install -d -m 0755 /etc/systemd/system/akson-daemon.service.d
    printf '[Service]\nEnvironment=AKSON_COORD_UID=%s\nEnvironment=AKSON_AGENT=$role\nEnvironment=AKSON_ISSUER=$issuer\nEnvironment=AKSON_RECEIVE_ADDR=$priv:$port\nEnvironment=AKSON_INTERFACE_URL=https://$priv:$port/a2a\n' \"\$(id -u akson-coord)\" \\
      | sudo install -m 0644 /dev/stdin /etc/systemd/system/akson-daemon.service.d/10-fleet.conf
    sudo systemctl daemon-reload
    systemctl is-enabled akson-daemon.service || true"
  # If the image is not 22.04, the sysctl dance is required and recorded.
  if [[ $FLEET_IMAGE != ubuntu-22-04-* ]]; then
    run_ssh "$target" '' "set -e
      printf 'kernel.apparmor_restrict_unprivileged_userns=0\n' \\
        | sudo install -m 0644 /dev/stdin /etc/sysctl.d/99-akson-userns.conf
      sudo sysctl --system | grep apparmor_restrict_unprivileged_userns" |
      tee "$EV/$role/sysctl-userns.txt" >/dev/null || true
    note "$role: apparmor_restrict_unprivileged_userns=0 applied and recorded (non-22.04 image)"
  fi
done
emit_step "$TEST_ID" units-installed ok "akson-daemon.service + akson-coord.service, not started"

# Provider API keys, only if a scenario needs model egress on the droplet. The
# secret goes over ssh stdin — never argv on either side — lands 0600 owned by
# the service user, and is NAMED in the run report so it can be rotated after.
PLACED_KEYS=()
if [[ ${FLEET_PROVIDER_KEYS:-0} == 1 ]]; then
  step "6b/7 place provider API keys (0600, owned by akson, named in the report)"
  for role in alice bob; do
    target="$(host_target "$role")"
    for provider in claude openai; do
      src="$HOME/.api/$provider"
      [[ -f $src ]] || continue
      run_ssh "$target" '' "sudo install -d -m 0700 -o akson -g akson /var/lib/akson/creds"
      run_ssh_stdin "$target" '' "$src" \
        "sudo install -m 0600 -o akson -g akson /dev/stdin /var/lib/akson/creds/$provider.key"
      PLACED_KEYS+=("$role:/var/lib/akson/creds/$provider.key (from ~/.api/$provider — ROTATE AFTER THE RUN)")
    done
  done
fi

# ═══ 7. acceptance, per host — all three, or the host is not ready ═══════════
step "7/7 acceptance per host: akson doctor + deploy/verify.sh + A0.6 probe"

host_accept() { # <role> → 0 if all three pass
  local role="$1" target ok=1 doctor verify analyze
  target="$(host_target "$role")"

  # (a) akson doctor — the sandbox must be usable.
  doctor="$EV/$role/akson-doctor.txt"
  run_ssh "$target" akson-doctor \
    "XDG_RUNTIME_DIR=\${XDG_RUNTIME_DIR:-/run/user/\$(id -u)} akson doctor" \
    >"$doctor" 2>&1 || true
  if grep -q 'ready: every required capability is available' "$doctor"; then
    assert_that "$TEST_ID" "$role/akson-doctor" ok "sandbox usable" "$doctor"
  else
    assert_that "$TEST_ID" "$role/akson-doctor" fail "sandbox NOT usable" "$doctor"
    ok=0
  fi

  # (b) deploy/verify.sh — no sandbox-hostile directive active. systemd-analyze
  #     security is finally meaningful here: the units are installed as root.
  verify="$EV/$role/deploy-verify.txt"
  run_ssh "$target" deploy-verify \
    "cd ~/akson && AKSON=target/release/akson AKSOND=target/release/aksond ./deploy/verify.sh" \
    >"$verify" 2>&1 || true
  if grep -q 'no sandbox-hostile directive active' "$verify" &&
    ! grep -q 'unprivileged userns: RESTRICTED' "$verify"; then
    assert_that "$TEST_ID" "$role/deploy-verify" ok "no sandbox-hostile directive active" "$verify"
  else
    assert_that "$TEST_ID" "$role/deploy-verify" fail "verify.sh reported a blocker" "$verify"
    ok=0
  fi

  analyze="$EV/$role/systemd-analyze-security.txt"
  run_ssh "$target" systemd-analyze-security \
    "systemd-analyze security akson-daemon.service akson-coord.service" \
    >"$analyze" 2>&1 || true
  note "$role: systemd-analyze security recorded (units installed as root — closes A0.5's gap)"

  state_patch ".hosts |= map(if .role == \"$role\" then .acceptance.doctor = $([[ -s $doctor ]] && echo true || echo false) else . end)"
  return $((1 - ok))
}

ACCEPT_FAIL=0
for role in alice bob; do
  host_accept "$role" || ACCEPT_FAIL=1
done

# (c) The A0.6 confined-credential probe, on BOTH hosts, with its unconfined
#     control — the i2-no-credentials test id. The sheet makes i2-provision
#     depend on it, so provisioning runs it rather than asserting it by prose.
step "7c/7 A0.6 confined-credential probe (delegates to run-scenario.sh no-credentials)"
NC_ARGS=(no-credentials)
dry && NC_ARGS+=(--dry-run)
if "$FLEET_DIR/run-scenario.sh" "${NC_ARGS[@]}"; then
  assert_that "$TEST_ID" a06-confined-credential-probe ok \
    "i2-no-credentials green on both hosts" "$EVIDENCE_DIR/i2-no-credentials"
else
  assert_that "$TEST_ID" a06-confined-credential-probe fail \
    "i2-no-credentials FAILED — see its evidence" "$EVIDENCE_DIR/i2-no-credentials"
  ACCEPT_FAIL=1
fi

# A host is reported ready only if all three of its checks passed.
for role in alice bob; do
  passed="$(jq -r --arg r "$role" \
    '[.[] | select(.assertion | startswith($r + "/")) | .ok] | if length == 0 then false else all end' \
    <(jq -s '.' "$EV/assertions.jsonl"))"
  a06="$(jq -r 'select(.assertion == "a06-confined-credential-probe") | .ok' "$EV/assertions.jsonl" | tail -1)"
  ready=$([[ $passed == true && $a06 == true ]] && echo true || echo false)
  state_patch ".hosts |= map(if .role == \"$role\" then .ready = $ready else . end)"
  if [[ $ready == true ]]; then
    note "$role: READY"
  else
    warn "$role: NOT ready — provisioning is not done for this host"
  fi
done

# ═══ run report ══════════════════════════════════════════════════════════════
DRY_NOTE=""
dry && DRY_NOTE=" (DRY RUN — nothing was created)"
COST_SO_FAR="$(awk -v r="$FLEET_HOURLY_USD" -v s="$(($(date -u +%s) - STARTED_EPOCH))" \
  'BEGIN{printf "%.4f", 2*r*s/3600}')"
{
  cat <<REPORT
# I2 run report — provisioning

- generated: $(now_iso)$DRY_NOTE
- region: \`$FLEET_REGION\`   vpc: \`$VPC_UUID\`
- image: \`$FLEET_IMAGE\`   size: \`$FLEET_SIZE\` x2
- tag: \`$FLEET_TAG\`   firewall: \`$FLEET_FIREWALL_NAME\` (\`$FW_ID\`)
- droplets: alice \`$ALICE_ID\` ($ALICE_PRIV), bob \`$BOB_ID\` ($BOB_PRIV)
- ssh inbound: \`$DRIVER_CIDR\` only. RECEIVE $RECEIVE_PORT_ALICE/$RECEIVE_PORT_BOB
  between the droplets only. **No PAIR port.**
- artifact provenance: **$ARTIFACT_SOURCE**
- estimated cost so far: \$$COST_SO_FAR (2 x \$$FLEET_HOURLY_USD/h)
- assurance labelling: developer/confined (I2 sheet). akson's key custody is
  interim (A0.3); that residual is carried into every I2 claim.
REPORT
  if [[ $ARTIFACT_SOURCE == source-build ]]; then
    cat <<'REPORT'
- **this is a SOURCE BUILD, not a verified release artifact** (A0.1: the release
  workflow exists, no cut release yet). No digest or attestation was checked.
REPORT
  fi
  printf '\n## Provider credentials placed on the droplets\n\n'
  if ((${#PLACED_KEYS[@]})); then
    printf 'Rotate every one of these after the run.\n\n'
    printf -- '- %s\n' "${PLACED_KEYS[@]}"
  else
    printf 'None.\n'
  fi
  printf '\n## Deployed artifacts\n\n'
  cat "$EV/artifacts.md"
  printf '\n## Teardown\n\n'
  cat <<REPORT
\`\`\`sh
$FLEET_DIR/teardown.sh
\`\`\`
REPORT
} >"$EV/run-report.md"
note "run report: $EV/run-report.md"

((ACCEPT_FAIL == 0)) || warn "at least one host failed acceptance — it is NOT ready"
assert_finish "$TEST_ID"
step "next: ./serve.sh alice && ./serve.sh bob, then ./introduce.sh alice bob"
