//! The REAL `byomd`, spawned for the K2 suites: build byom's daemon from
//! the sibling checkout, run it on its own four sockets, and speak byom's
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
            let all_up = ["governance", "candidate", "participant", "projection"]
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
