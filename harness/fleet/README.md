# I2 fleet tooling — the sovereign pair on DigitalOcean

Five scripts that stand up two droplets, run the I2 gate against them, and
destroy them. Specified by [`plan/fleet/README.md`](../../../plan/fleet/README.md);
the test ids and pass criteria are [`plan/sheets/I2.md`](../../../plan/sheets/I2.md).
Conventions extend `akson/bench/`: **ssh-driven from this workstation, no agent
on the droplets, `enable-linger` so user units survive logout.**

Everything runs from *here*, on the driver. Evidence lands here too, never on
the droplets.

## Status: written and dry-run validated, never run for real

Read this before quoting the gate. **No DigitalOcean resource has ever been
created by these scripts.** They are exercised only through `--dry-run` and
`test-no-token-leak.sh`, both of which make no API call.

Of the nine scenarios, **two run today** — `no-credentials` and
`bench-matrix`. The other seven need the per-side transcript driver
(`side.py`), which does not exist yet in any repository; see *Where the
cross-host transcript comes from* below. So the "full gate, start to finish"
sequence in the next section is the intended shape, not a sequence anyone has
completed. I2 has not passed and is not claimed to have.

## See it before you spend anything

Every script takes `--dry-run`, which prints the exact command sequence and
makes **no** DigitalOcean API call:

```sh
./provision.sh alice bob --dry-run
```

That is also how the scripts are tested — see *Tests* below.

## A full gate, start to finish

```sh
# once: the DO token, read at runtime and never passed in argv
install -m 0600 /dev/null ~/.api/do && $EDITOR ~/.api/do

./provision.sh alice bob         # i2-provision      (creates: ~$0.036/h x2)
./serve.sh alice && ./serve.sh bob
./introduce.sh alice bob         # i2-introduce

./run-scenario.sh no-credentials    # i2-no-credentials
./run-scenario.sh round-trip        # i2-round-trip
./run-scenario.sh late-result       # i2-late-result
./run-scenario.sh advisory-cancel   # i2-cancel
./run-scenario.sh binding-change    # i2-binding-change
./run-scenario.sh crash dispatch    # i2-crash-dispatch
./run-scenario.sh crash admission   # i2-crash-admission
./run-scenario.sh restore-lineage   # i2-restore-lineage
./run-scenario.sh bench-matrix      # i2-bench-regression

./teardown.sh                    # i2-teardown — DESTROYS. Part of the criteria.
```

Each script exits non-zero if any of its named assertions failed, so
`&&`-chaining the whole gate is safe. Budget: under two hours, **well under
$0.20**. The gate does not pass while the droplets exist.

## What each script does

| Script | Test id | What it does |
|---|---|---|
| `provision.sh alice bob` | `i2-provision` | preflight → create → firewall → identities → artifacts → install units (not started) → three acceptance checks per host |
| `serve.sh <role>` | — | starts `koveed`, `byomd`, `aksond` in that order, each under its own Unix identity; waits for every socket; prints the endpoint identity and the token/credential file paths. Idempotent. |
| `introduce.sh alice bob` | `i2-introduce` | exchanges public identity tokens out of band, runs the ADR-0015 introduction on the RECEIVE surface, asserts mutual pinning and that **no PAIR port** exists |
| `run-scenario.sh <name>` | the rest | one scenario per invocation, writing `evidence/<test-id>/` |
| `teardown.sh` | `i2-teardown` | **destroys by default**, verifies deletion, prints elapsed time and cost |

`provision.sh` is not done until, on **each** host, all three pass:
`akson doctor` reports the sandbox usable, `deploy/verify.sh` reports no
sandbox-hostile directive active, and the A0.6 confined-credential probe is
green (it runs `./run-scenario.sh no-credentials` rather than asserting it in
prose). A host that fails any of them stays `ready: false` in
`evidence/fleet-state.json` and the script exits non-zero.

## The token rule

The DigitalOcean token lives at `~/.api/do` on this driver. It is read at
runtime into the environment of one `doctl` process:

```sh
DIGITALOCEAN_ACCESS_TOKEN="$(tr -d '[:space:]' < ~/.api/do)" doctl …
```

- **never in argv** — an assignment prefix is environment, not arguments, so
  `ps` cannot show it
- **never on a droplet** — `run_ssh` refuses to carry anything token-shaped;
  the droplets create no infrastructure and have no reason to hold a DO token
- **never in a log or evidence file** — logs print the *path* it is read from
- **never committed** — `evidence/` is git-ignored
- **absent ⇒ fail closed**, with a message saying where to put it. No prompt.
- **xtrace is refused** — `set -x` would trace the substitution; use
  `--dry-run` to debug instead

`lib.sh`'s `doctl_run`/`doctl_out` are the only two readers of the file, and
`test-no-token-leak.sh` proves all of the above.

Provider API keys (`~/.api/claude`, `~/.api/openai`) go to a droplet only when
a scenario needs model egress there (`FLEET_PROVIDER_KEYS=1`). They travel over
ssh **stdin**, so they are never in argv on either side, land `0600` owned by
the service user, and are **named in the run report** so they can be rotated
afterwards.

## Recovering from a crashed driver

The one failure mode that costs money is an orphaned droplet. Two independent
routes exist so it cannot happen:

1. `provision.sh` writes `evidence/fleet-state.json` **the instant the droplet
   ids exist** — before it waits for the droplets to boot, before the firewall,
   before anything else can fail. (That is why `droplet create` runs *without*
   `--wait`.)
2. Every resource is tagged `akson-i2`, which survives a lost state file, a
   deleted evidence directory, and a driver reinstall.

So, whatever happened:

```sh
./teardown.sh                                   # uses state file ∪ tag
doctl compute droplet list --tag-name akson-i2  # one command, from anywhere
```

`teardown.sh` takes the **union** of both routes, deletes droplets → firewall →
volumes, then re-lists and **exits non-zero if anything survived**, telling you
exactly what to run next. It works with no state file at all (tag only) and
with a state file whose tag was lost (ids only).

If the driver died mid-run and you are not sure which stage it reached, just run
`./teardown.sh`. It is idempotent, and destroying nothing is a pass.

`--keep` exists for debugging a failing scenario. It destroys nothing and
prints a loud banner with the exact teardown command. Use it knowing the meter
is running.

## Evidence discipline

Mirrors I0/I1. Every claim is read from the owning daemon's own records — kovee
facts from `koveed`, byom facts from `byomd`, akson facts from `aksond` — never
from a harness's prose about them.

```
evidence/
  fleet-state.json          droplet ids, addresses, per-host `ready`
  i2-provision/
    firewall-rules.json     the firewall's own dump (the no-PAIR-port source)
    run-report.md           region, image, sizes, cost, artifact provenance
    artifacts.md            per-repo commit + dirty flag
    assertions.jsonl        one line per named assertion + its evidence path
    steps.jsonl  result.json
    alice/  bob/            akson doctor, deploy/verify.sh, systemd-analyze
  i2-round-trip/
    alice/                  ALICE's own ledgers — and nothing else
    bob/                    BOB's own ledgers — and nothing else
```

**The two sides are never merged.** Each side's extracts live only in its own
directory, each directory carries a `source.json` naming the daemon every file
came from, and `assert_ledgers_unmerged` fails the scenario if a combined view
appears at the top level. A cross-side claim is made by citing two paths, never
by folding them into one file.

## Tests

```sh
./test-no-token-leak.sh    # 15 checks, no API call, nothing created
shellcheck -x *.sh         # clean at shellcheck 0.10.0
```

A green run of the first prints `── 15 passed, 0 failed` and removes its
scratch tree.

`test-no-token-leak.sh` plants a **fake** token and checks four layers:

1. **fail closed** — with no token file, `provision.sh` refuses and says where
   to put one; identical behaviour with stdin closed, i.e. it never prompts
2. **argv vs env** — a stub `doctl` on `PATH` dumps its own `/proc/$$/cmdline`
   and `/proc/$$/environ`: the token must be in the environ (exactly one entry)
   and absent from the cmdline. This is the `ps` property, tested rather than
   asserted, and the dumps are checked non-empty so the pass cannot be vacuous.
3. **full dry run** — all five scripts and all nine scenarios, then every byte
   of every transcript and every generated file grepped for the token value
4. **never committed** — `evidence/` is git-ignored, no tracked file holds a
   token-shaped string, and `lib.sh` is the only reader of the token file

## Knobs

| Variable | Default | Meaning |
|---|---|---|
| `FLEET_REGION` | `fra1` | DO region; both droplets, one VPC |
| `FLEET_SIZE` | `s-2vcpu-4gb` | smallest that comfortably builds three Rust workspaces |
| `FLEET_IMAGE` | `ubuntu-22-04-x64` | **not 24.04** — see below |
| `FLEET_VPC` | region default | resolved explicitly, never left to luck |
| `FLEET_TAG` | `akson-i2` | the teardown-safety tag |
| `FLEET_SSH_KEY_NAME` | `kovee-i2` | name of the key **already registered** in DO |
| `FLEET_DRIVER_CIDR` | this host's public IP | the only source allowed to ssh in |
| `FLEET_OPERATOR` | `ops` | non-root sudo account, `enable-linger` |
| `FLEET_RELEASE_TAG` | unset | fetch + verify a cut release instead of source-building |
| `FLEET_PROVIDER_KEYS` | `0` | place `~/.api/{claude,openai}` on the hosts |
| `DO_TOKEN_FILE` | `~/.api/do` | where the token is read from |
| `FLEET_EVIDENCE_DIR` | `harness/fleet/evidence` | where evidence lands — resolved from the *scripts'* own directory, not the working directory, so it is the same path wherever you invoke from |
| `FLEET_HOURLY_USD` | `0.036` | per-droplet rate the cost lines above are computed from |

`lib.sh` and `run-scenario.sh` carry further knobs the gate does not normally
need: `FLEET_FIREWALL_NAME`, `FLEET_RELEASE_REPO`, `RECEIVE_PORT_ALICE` /
`RECEIVE_PORT_BOB`, `FLEET_FORBIDDEN_PORTS`, `FLEET_ITERS`, `FLEET_DRY_RUN`.

On a non-22.04 image, `provision.sh` applies
`kernel.apparmor_restrict_unprivileged_userns=0` and records it in the
evidence, because akson's clean worker needs unprivileged user namespaces.
22.04 avoids the sysctl entirely.

## What this tooling does not claim

- **Assurance is developer/confined** (I2 sheet). akson's key custody is still
  interim (A0.3) and that residual is carried into every I2 claim.
- **No automatic agent-to-agent handoff.** The model is manual-local (D-RT-1):
  bob's remote performer is a locally attached harness under bob's own human's
  two decisions. `run-scenario.sh` therefore never authors on a host's
  surfaces itself — each side's own driver does, and the runner asserts the
  absence of remote authorship from bob's own ledger.
- **Source build ≠ verified artifact.** Without `FLEET_RELEASE_TAG` the hosts
  build from rsync'd sources and the run report says so, in those words (A0.1
  has a release workflow but no cut release yet).
- **Bypass prevention is K4's,** not I2's. Model egress on each side goes
  through that side's own broker; that is the whole claim.

## Where the cross-host transcript comes from

The scenarios that walk the §0.2 transcript (`round-trip`, `late-result`,
`advisory-cancel`, `binding-change`, `restore-lineage`, `crash …`) drive a
**per-side** driver on each host, under this contract:

```sh
I2_SIDE=<alice|bob> I2_TEST_ID=<test-id> I2_PEER=<peer private addr> \
I2_OUT=<remote evidence dir> \
  python3 ~/byom/conformance/i2-sovereign-pair/side.py --step <step-name>
```

That is deliberate, not a shortcut: if the fleet driver spoke a host's own
governance and participant surfaces, the *driver* would be the author, and
manual-local forbids exactly that. The fleet driver owns the provisioning, the
cross-host akson hop, the evidence and the assertions; each side owns its own
authorship.

`side.py` is the cross-host wiring the I2 sheet lists as its new work and it
lives in byom/kovee, not here. `run-scenario.sh` preflights for it and fails
with a precise message if it is absent. `no-credentials` and `bench-matrix`
need no side driver and run today.
