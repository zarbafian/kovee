//! The REAL `byomd`, spawned for the K2 suites: build byom's daemon from
//! the sibling checkout, run it on its own five sockets, and speak byom's
//! own wire to it.
//!
//! Gated on the byom repository being present — `$KOVEE_BYOM_REPO`, else
//! the sibling `../byom` — mirroring the plan's env-gated real-harness
//! discipline (§8). When present it always runs; it never silently passes
//! on a byomd failure.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

pub const BPP_VERSION: &str = "0.2";

/// The byom repository root, or `None` when this checkout is standalone.
pub fn byom_repo() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("KOVEE_BYOM_REPO") {
        let path = PathBuf::from(dir);
        return path.join("Cargo.toml").is_file().then_some(path);
    }
    let sibling = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("byom");
    sibling.join("Cargo.toml").is_file().then_some(sibling)
}

/// Builds `byomd` in the byom workspace and returns its binary path.
/// `$BYOMD_BIN` short-circuits both steps.
pub fn byomd_binary(repo: &Path) -> PathBuf {
    if let Some(bin) = std::env::var_os("BYOMD_BIN") {
        return PathBuf::from(bin);
    }
    let manifest = repo.join("Cargo.toml");
    // The byom workspace pins its own target dir in `.cargo/config.toml`;
    // an inherited CARGO_TARGET_DIR from the outer cargo would override
    // it, so drop it and ask cargo where the target dir actually is.
    let mut meta = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()));
    meta.args([
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
        "--offline",
        "--manifest-path",
    ])
    .arg(&manifest)
    .env_remove("CARGO_TARGET_DIR")
    .env_remove("RUSTFLAGS");
    let out = meta
        .output()
        .expect("cargo metadata for the byom workspace");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    let target_dir = PathBuf::from(parsed["target_directory"].as_str().unwrap());
    let binary = target_dir.join("debug").join("byomd");

    let build = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))
        .args(["build", "--offline", "-p", "byomd", "--manifest-path"])
        .arg(&manifest)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTFLAGS")
        .stdout(Stdio::null())
        .status()
        .expect("cargo build -p byomd");
    assert!(build.success(), "building byomd failed");
    assert!(binary.is_file(), "byomd missing at {}", binary.display());
    binary
}

pub struct Byomd {
    child: Option<Child>,
    binary: PathBuf,
    pub data_dir: PathBuf,
    pub run_dir: PathBuf,
}

impl Byomd {
    pub fn start(binary: &Path, data_dir: &Path, run_dir: &Path) -> Byomd {
        std::fs::create_dir_all(data_dir).unwrap();
        std::fs::create_dir_all(run_dir).unwrap();
        let mut daemon = Byomd {
            child: None,
            binary: binary.to_path_buf(),
            data_dir: data_dir.to_path_buf(),
            run_dir: run_dir.to_path_buf(),
        };
        daemon.spawn(&[]);
        daemon
    }

    fn spawn(&mut self, env: &[(&str, &str)]) {
        let mut cmd = Command::new(&self.binary);
        cmd.env("BYOM_DATA_DIR", &self.data_dir)
            .env("BYOM_RUNTIME_DIR", &self.run_dir)
            .env_remove("BYOMD_ABORT")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in env {
            cmd.env(key, value);
        }
        self.child = Some(cmd.spawn().expect("spawn byomd"));
        self.wait_ready();
    }

    /// Stops and restarts the daemon — how a freshly written
    /// `host-binding.json` gets picked up and its recovery-workload token
    /// published. The endpoint incarnation is persistent, so a restart is
    /// NOT a re-incarnation.
    pub fn restart(&mut self, env: &[(&str, &str)]) {
        self.stop();
        self.spawn(env);
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Whether the daemon has exited on its own (an armed `BYOMD_ABORT`).
    pub fn exited(&mut self) -> bool {
        match &mut self.child {
            Some(child) => matches!(child.try_wait(), Ok(Some(_))),
            None => true,
        }
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let all_up = [
                "governance",
                "candidate",
                "participant",
                "runtime",
                "projection",
            ]
            .iter()
            .all(|s| UnixStream::connect(self.run_dir.join(format!("{s}.sock"))).is_ok());
            if all_up {
                // Stronger than "the socket exists": a real round trip.
                if let Ok(reply) = self.try_call(
                    "governance",
                    &json!({"version": BPP_VERSION, "op": "hello"}),
                ) {
                    assert_eq!(reply["outcome"], json!("ok"), "byomd hello: {reply}");
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "byomd never came up in {}",
                self.run_dir.display()
            );
            std::thread::sleep(Duration::from_millis(30));
        }
    }

    pub fn socket(&self, surface: &str) -> PathBuf {
        self.run_dir.join(format!("{surface}.sock"))
    }

    pub fn try_call(&self, surface: &str, request: &Value) -> Result<Value, String> {
        self.try_call_with(surface, None, request)
    }

    /// One request, optionally behind a transport preamble line (the
    /// delegated-principal credential on governance, the narrow
    /// recovery-workload token on projection).
    pub fn try_call_with(
        &self,
        surface: &str,
        preamble: Option<&str>,
        request: &Value,
    ) -> Result<Value, String> {
        let path = self.socket(surface);
        let mut stream = UnixStream::connect(&path).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .map_err(|e| e.to_string())?;
        let mut line = String::new();
        if let Some(token) = preamble {
            line.push_str(token.trim());
            line.push('\n');
        }
        line.push_str(&request.to_string());
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut reply = String::new();
        BufReader::new(stream)
            .read_line(&mut reply)
            .map_err(|e| e.to_string())?;
        if reply.trim().is_empty() {
            return Err("byomd closed without a reply".to_owned());
        }
        serde_json::from_str(reply.trim_end()).map_err(|e| e.to_string())
    }

    pub fn call_ok(&self, surface: &str, request: &Value) -> Value {
        let reply = self.try_call(surface, request).expect("byomd replied");
        assert_eq!(reply["outcome"], json!("ok"), "byomd refused: {reply}");
        reply
    }

    pub fn incarnation(&self) -> String {
        self.call_ok(
            "governance",
            &json!({"version": BPP_VERSION, "op": "hello"}),
        )["result"]["endpoint_incarnation"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// Writes the inert host-binding configuration amendment A2 lets Kovee
    /// supply. byomd re-validates every field on every use; no Kovee
    /// operation can author Society state through it.
    pub fn install_host_binding(&self, document: &Value) {
        let dir = self.data_dir.join("kovee");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("host-binding.json"), document.to_string()).unwrap();
    }

    pub fn channels_dir(&self) -> PathBuf {
        self.data_dir.join("channels")
    }

    /// One column out of byomd's OWN database — the same inspection
    /// channel byom's test fixtures use ("the daemon owns the data
    /// directory, the SQLite file is readable beside it"). Every assertion
    /// made through this reads byom's record, not Kovee's.
    pub fn row(&self, sql: &str, key: &str) -> Option<String> {
        let conn = rusqlite::Connection::open(self.data_dir.join("byom.db")).unwrap();
        conn.query_row(sql, [key], |r| r.get::<_, Option<String>>(0))
            .ok()
            .flatten()
    }

    pub fn number(&self, sql: &str, key: &str) -> Option<i64> {
        let conn = rusqlite::Connection::open(self.data_dir.join("byom.db")).unwrap();
        conn.query_row(sql, [key], |r| r.get::<_, i64>(0)).ok()
    }

    pub fn count(&self, sql: &str) -> i64 {
        let conn = rusqlite::Connection::open(self.data_dir.join("byom.db")).unwrap();
        conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap()
    }

    /// The committed `ResourceAllocation` digest `placement_admit` makes
    /// Kovee pin. byom exposes it on NO wire surface — its own runtime
    /// fixture reads it out of the store the same way — so the
    /// notification Kovee is handed carries it from here (recorded
    /// deviation: byom has no outbound Kovee client and no projection read
    /// for the allocation head).
    pub fn allocation_digest(&self, allocation_ref: &str) -> Value {
        let text = self
            .row(
                "SELECT digest FROM resource_allocations WHERE allocation_id = ?1",
                allocation_ref,
            )
            .unwrap_or_else(|| panic!("no committed allocation {allocation_ref}"));
        serde_json::from_str(&text).unwrap()
    }

    /// byom's §11.4 conservation ledger row for one account.
    pub fn ledger(&self, account_ref: &str) -> Ledger {
        let conn = rusqlite::Connection::open(self.data_dir.join("byom.db")).unwrap();
        conn.query_row(
            "SELECT ceiling, remaining, reserved, committed, uncertain, delegated_to_children
             FROM budget_accounts WHERE account_ref = ?1 AND dimension = 'unit'",
            [account_ref],
            |r| {
                Ok(Ledger {
                    ceiling: r.get(0)?,
                    remaining: r.get(1)?,
                    reserved: r.get(2)?,
                    committed: r.get(3)?,
                    uncertain: r.get(4)?,
                    delegated: r.get(5)?,
                })
            },
        )
        .expect("byom budget account")
    }

    /// The narrow recovery-workload token byomd publishes for an installed
    /// binding, once it has loaded the configuration at least once.
    pub fn recovery_token(&self, binding_ref: &str) -> Option<String> {
        std::fs::read_to_string(
            self.channels_dir()
                .join(format!("recovery-workload-{binding_ref}.token")),
        )
        .ok()
        .map(|t| t.trim().to_owned())
    }

    /// Hides the governance socket PATH while the listener stays bound to
    /// its inode: a Kovee send then fails at `connect` with the outcome
    /// UNKNOWN, while the projection surface keeps answering. Restoring
    /// the path brings the socket back — no re-incarnation, no data loss.
    pub fn hide_governance_socket(&self) {
        std::fs::rename(
            self.socket("governance"),
            self.run_dir.join("governance.sock.hidden"),
        )
        .unwrap();
    }

    pub fn restore_governance_socket(&self) {
        std::fs::rename(
            self.run_dir.join("governance.sock.hidden"),
            self.socket("governance"),
        )
        .unwrap();
    }

    /// The same for the projection surface: the recovery query then cannot
    /// be answered at all, which is the honest `unknown` — an endpoint that
    /// does not answer proves nothing either way.
    pub fn hide_projection_socket(&self) {
        std::fs::rename(
            self.socket("projection"),
            self.run_dir.join("projection.sock.hidden"),
        )
        .unwrap();
    }

    pub fn restore_projection_socket(&self) {
        std::fs::rename(
            self.run_dir.join("projection.sock.hidden"),
            self.socket("projection"),
        )
        .unwrap();
    }
}

impl Drop for Byomd {
    fn drop(&mut self) {
        self.stop();
    }
}

fn digest(seed: &str) -> Value {
    let mut hex = String::new();
    while hex.len() < 64 {
        for b in seed.bytes() {
            hex.push_str(&format!("{b:02x}"));
            if hex.len() >= 64 {
                break;
            }
        }
    }
    json!({
        "class": "local_erasure_safe",
        "algorithm": "hmac-sha-256",
        "key_ref": "k-0001",
        "value_hex": hex[..64].to_owned(),
    })
}

/// The native genesis path — `society_prepare` then `society_bootstrap`
/// under the bootstrap human's own governance channel. Kovee is never
/// allowed to take it (amendment A2), which is why the TEST does it.
pub fn bootstrap_society(byomd: &Byomd, incarnation: &str) -> String {
    let prepared = byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION,
            "op": "society_prepare",
            "meta": {
                "request_id": "req-k2-boot-1",
                "idempotency_key": "idem-k2-boot-1",
                "expected_endpoint_incarnation": incarnation,
                "expected_recovery_epoch": 0,
            },
            "home_authority_ref": "auth-home-k2",
            "kovee_realm_binding": "realm-personal",
            "proposed_charter_ref": "charter-draft-k2",
            "proposed_charter_digest": digest("charter"),
            "classification_binding_ref": "class-bind-k2",
            "classification_binding_digest": digest("classification"),
        }),
    );
    let society_id = prepared["result"]["society_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let bootstrapped = byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION,
            "op": "society_bootstrap",
            "meta": {
                "request_id": "req-k2-boot-2",
                "idempotency_key": "idem-k2-boot-2",
                "expected_endpoint_incarnation": incarnation,
                "expected_recovery_epoch": 0,
                "expected_revision": prepared["result"]["revision"].as_u64().unwrap(),
            },
            "society_id": society_id,
            "preparation_ref": prepared["result"]["preparation_ref"],
            "subject_digest": prepared["result"]["subject_digest"],
        }),
    );
    assert_eq!(bootstrapped["result"]["state"], json!("active"));
    assert_eq!(bootstrapped["result"]["recovery_epoch"], json!(0));
    society_id
}

/// byom's §11.4 conservation ledger row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ledger {
    pub ceiling: i64,
    pub remaining: i64,
    pub reserved: i64,
    pub committed: i64,
    pub uncertain: i64,
    pub delegated: i64,
}

impl Ledger {
    /// §11.4: `ceiling = remaining + reserved + committed + uncertain +
    /// delegated_to_children`, at every observation.
    pub fn conserves(&self) -> bool {
        self.ceiling
            == self.remaining + self.reserved + self.committed + self.uncertain + self.delegated
    }
}

/// The parent §11.4 account every Episode of this fixture reserves against
/// (the Mandate's `budget_ceiling_set_ref`).
pub const PARENT_ACCOUNT: &str = "budget-mandate-live";
/// byom's per-Episode worst case (`EPISODE_WORST_CASE_UNITS`).
pub const EPISODE_WORST_CASE: u64 = 256;

/// The byom-side state the FOUR-STAGE activation starts from: one Society,
/// one admitted agent Participant with an issued Mandate, and one open
/// exploration ActivityStream — all established through byomd's own
/// surfaces, with Kovee's channel-proof client doing the participant and
/// candidate calls.
pub struct AgentSociety {
    pub society_id: String,
    pub incarnation: String,
    pub participant_ref: String,
    pub participant_binding_epoch: u64,
    pub manifestation_ref: String,
    pub mandate_id: String,
    pub activity_stream_ref: String,
    /// The claimed participant channel: Kovee's own reimplementation of
    /// byom's `bpk1`/`bpb1`/`bpx1` construction, interoperating with the
    /// real daemon.
    pub channel: kovee_byom::channel::Channel,
    tag: String,
}

impl AgentSociety {
    pub fn meta(&self, key: &str, expected_revision: Option<u64>) -> Value {
        let mut m = json!({
            "request_id": format!("req-{}-{key}", self.tag),
            "idempotency_key": format!("idem-{}-{key}", self.tag),
            "expected_endpoint_incarnation": self.incarnation,
            "expected_recovery_epoch": 0,
        });
        if let Some(rev) = expected_revision {
            m["expected_revision"] = json!(rev);
        }
        m
    }
}

/// One participant-surface call under a freshly minted channel proof.
pub fn participant_call(
    byomd: &Byomd,
    channel: &kovee_byom::channel::Channel,
    request: &Value,
) -> Value {
    let op = request["op"].as_str().unwrap_or_default();
    let proof = channel
        .proof(op, kovee_core::time::unix_now())
        .expect("mint a participant channel proof");
    byomd
        .try_call_with("participant", Some(&proof), request)
        .unwrap_or_else(|e| panic!("participant {op}: {e}"))
}

fn ok(what: &str, reply: &Value) {
    assert_eq!(reply["outcome"], json!("ok"), "{what}: {reply}");
}

fn local_digest(seed: u8) -> Value {
    json!({
        "class": "local_erasure_safe",
        "algorithm": "hmac-sha-256",
        "key_ref": format!("kovee-live-key-{seed}"),
        "value_hex": format!("{seed:02x}").repeat(32),
    })
}

/// Bootstraps the byom-side four-stage precondition. Every mutation goes
/// over byomd's own sockets; the two channel-scoped ones (`membership_accept`
/// on candidate, `mandate_prepare`/`activity_open` on participant) ride
/// Kovee's channel-proof client.
pub fn bootstrap_agent_society(byomd: &Byomd, tag: &str) -> AgentSociety {
    let incarnation = byomd.incarnation();
    let society_id = bootstrap_society(byomd, &incarnation);
    let meta = |key: &str, rev: Option<u64>| {
        let mut m = json!({
            "request_id": format!("req-{tag}-{key}"),
            "idempotency_key": format!("idem-{tag}-{key}"),
            "expected_endpoint_incarnation": incarnation,
            "expected_recovery_epoch": 0,
        });
        if let Some(rev) = rev {
            m["expected_revision"] = json!(rev);
        }
        m
    };

    // -- onboarding: offer, accept (candidate channel), admit -----------
    let subject = local_digest(0xb1);
    let offered = byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION, "op": "membership_offer",
            "meta": meta("offer", None),
            "participant_ref": "part-agent-live",
            "proposed_standing_ref": "standing-proposal-live",
            "subject_digest": subject,
            "offered_by_decision_ref": format!("dec-society-{society_id}"),
            "expires_at": "2030-01-01T00:00:00Z",
        }),
    );
    let offer_id = offered["result"]["offer_id"].as_str().unwrap().to_owned();
    let candidate =
        kovee_byom::channel::Channel::candidate(&byomd.run_dir, &byomd.channels_dir(), &offer_id)
            .expect("claim the candidate channel byomd published");
    let accept_proof = candidate
        .proof("membership_accept", kovee_core::time::unix_now())
        .unwrap();
    let accepted = byomd
        .try_call_with(
            "candidate",
            Some(&accept_proof),
            &json!({
                "version": BPP_VERSION, "op": "membership_accept",
                "meta": meta("accept", Some(1)),
                "offer_ref": offer_id,
                "subject_digest": subject,
            }),
        )
        .expect("membership_accept");
    ok("membership_accept", &accepted);
    let admitted = byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION, "op": "participant_admit",
            "meta": meta("admit", Some(2)),
            "offer_ref": offer_id,
            "membership_acceptance_ref": accepted["result"]["acceptance_id"],
            "admitted_by_decision_ref": format!("dec-offer-{offer_id}"),
            "admission_subject_digest": subject,
        }),
    );
    let participant_ref = "part-agent-live".to_owned();
    let _ = admitted;

    // The proposed Manifestation admission created (read from byom's own
    // store, as byom's fixtures do).
    let manifestation_ref = byomd
        .row(
            "SELECT manifestation_id FROM manifestation_revisions
             WHERE participant_ref = ?1 LIMIT 1",
            &participant_ref,
        )
        .expect("the proposed manifestation");
    byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION, "op": "manifestation_admit",
            "meta": meta("manif", Some(1)),
            "manifestation_ref": manifestation_ref,
            "admitted_by_decision_ref": format!("dec-manif-{manifestation_ref}"),
        }),
    );

    // -- the participant channel byomd publishes for the admitted agent --
    let channel = kovee_byom::channel::Channel::participant(
        &byomd.run_dir,
        &byomd.channels_dir(),
        &participant_ref,
    )
    .expect("claim the participant channel byomd published");
    let participant_binding_epoch = byomd
        .number(
            "SELECT binding_epoch FROM participants WHERE participant_id = ?1",
            &participant_ref,
        )
        .unwrap_or(1)
        .max(0) as u64;

    // -- the mandate chain: prepare (participant) / position / issue -----
    let prepared = participant_call(
        byomd,
        &channel,
        &json!({
            "version": BPP_VERSION, "op": "mandate_prepare",
            "meta": meta("mprep", None),
            "grantee_participant_ref": participant_ref,
            "purpose_ref": "purpose-explore-live",
            // The Δ4 act classes a Mandate grants are named here too: byom's
            // `act_intent_prepare` refuses a class outside the grant, so the
            // model broker's `model_egress` has to be in it.
            "allowed_operations": ["activity_open", "continuation_write", "wake_intent_submit",
                                   "model_egress"],
            "resource_selectors": ["res-repo-live"],
            "data_class_selectors": ["class-public"],
            "destination_selectors": [],
            "budget_ceiling_set_ref": PARENT_ACCOUNT,
            "concurrency_ceiling": 8,
            "delegation": {"allowed": false, "max_depth": 0, "max_children": 0,
                           "grantee_selectors": []},
            "expires_at": "2030-01-01T00:00:00Z",
        }),
    );
    ok("mandate_prepare", &prepared);
    let mandate_id = prepared["result"]["mandate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let seat = prepared["result"]["required_seat_refs"][0]
        .as_str()
        .unwrap()
        .to_owned();
    byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION, "op": "mandate_position",
            "meta": meta("mpos", None),
            "proposal_ref": mandate_id,
            "proposal_revision": 1,
            "subject_digest": prepared["result"]["subject_digest"],
            "seat_ref": seat,
            "value": "assent",
        }),
    );
    byomd.call_ok(
        "governance",
        &json!({
            "version": BPP_VERSION, "op": "mandate_issue",
            "meta": meta("missue", Some(1)),
            "mandate_id": mandate_id,
            "subject_digest": prepared["result"]["subject_digest"],
        }),
    );

    // -- the ActivityStream the Episodes run under ----------------------
    let opened = participant_call(
        byomd,
        &channel,
        &json!({
            "version": BPP_VERSION, "op": "activity_open",
            "meta": meta("explore", None),
            "kind": "exploration",
            "purpose_ref": "purpose-explore-live",
            "purpose_digest": local_digest(0xc0),
            "mandate_refs": [mandate_id],
            "budget_account_set_ref": PARENT_ACCOUNT,
        }),
    );
    ok("activity_open", &opened);
    let activity_stream_ref = opened["result"]["activity_stream_id"]
        .as_str()
        .unwrap()
        .to_owned();

    AgentSociety {
        society_id,
        incarnation,
        participant_ref,
        participant_binding_epoch,
        manifestation_ref,
        mandate_id,
        activity_stream_ref,
        channel,
        tag: tag.to_owned(),
    }
}

/// Stage 1: the participant channel — and nothing else — authors a
/// WakeIntent (§11.1). Returns the committed `wake_intent_id`.
pub fn wake_intent(byomd: &Byomd, agent: &AgentSociety, key: &str) -> String {
    let reply = participant_call(
        byomd,
        &agent.channel,
        &json!({
            "version": BPP_VERSION, "op": "wake_intent_submit",
            "meta": agent.meta(&format!("wake-{key}"), None),
            "activity_stream_ref": agent.activity_stream_ref,
            "generation": 1,
            "origin": "direct_participant",
            "exact_cause_ref": format!("cause-{key}"),
            "exact_cause_digest": local_digest(0xc2),
            "purpose_ref": "purpose-explore-live",
            "stable_wake_key": format!("wake-live-{key}"),
            "expires_at": "2030-01-01T00:00:00Z",
        }),
    );
    ok("wake_intent_submit", &reply);
    reply["result"]["wake_intent_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The bootstrap human Participant `society_bootstrap` admitted: the one
/// `kovee_endeavor_form` may act for. Returns `(participant_ref,
/// binding_epoch)`.
pub fn sovereign_participant(byomd: &Byomd, society_id: &str) -> (String, u64) {
    let snapshot = byomd.call_ok(
        "projection",
        &json!({"version": BPP_VERSION, "op": "snapshot_get",
                "society_id": society_id, "kinds": ["participants"]}),
    );
    let participant = snapshot["result"]["participants"]
        .as_array()
        .expect("participants")
        .iter()
        .find(|p| p["kind"] == json!("human"))
        .expect("the bootstrap human Participant")
        .clone();
    (
        participant["participant_id"].as_str().unwrap().to_owned(),
        participant["binding_epoch"].as_u64().unwrap_or(1),
    )
}
