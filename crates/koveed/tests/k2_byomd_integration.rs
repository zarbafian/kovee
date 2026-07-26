//! K2 slice 1 — the greenfield saga end to end against the REAL `byomd`.
//!
//! No stub: this test builds and spawns byom's daemon, bootstraps a
//! Society through its own governance socket
//! (`society_prepare` → `society_bootstrap`, the native genesis path
//! Kovee is never allowed to take), then runs `kovee governance_enable`
//! against that live endpoint and checks that the binding Kovee committed
//! pins exactly what byomd reports.
//!
//! It is gated on the byom repository being present — `$KOVEE_BYOM_REPO`,
//! else the sibling `../byom` — mirroring the plan's env-gated
//! real-harness discipline (§8). When present it always runs; it never
//! silently passes on a byomd failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{json, Value};

const BPP_VERSION: &str = "0.2";
const SCOPE: &str = "project:proj-1";

/// The byom repository root, or `None` when this checkout is standalone.
fn byom_repo() -> Option<PathBuf> {
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
fn byomd_binary(repo: &Path) -> PathBuf {
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

struct Byomd {
    child: Child,
    run_dir: PathBuf,
}

impl Byomd {
    fn start(binary: &Path, data_dir: &Path, run_dir: &Path) -> Byomd {
        std::fs::create_dir_all(data_dir).unwrap();
        std::fs::create_dir_all(run_dir).unwrap();
        let child = Command::new(binary)
            .env("BYOM_DATA_DIR", data_dir)
            .env("BYOM_RUNTIME_DIR", run_dir)
            .env_remove("BYOMD_ABORT")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn byomd");
        let daemon = Byomd {
            child,
            run_dir: run_dir.to_path_buf(),
        };
        daemon.wait_ready();
        daemon
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
                    &json!({
                        "version": BPP_VERSION, "op": "hello",
                    }),
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

    fn try_call(&self, surface: &str, request: &Value) -> Result<Value, String> {
        let path = self.run_dir.join(format!("{surface}.sock"));
        let mut stream = UnixStream::connect(&path).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .map_err(|e| e.to_string())?;
        // byom's wire: one newline-terminated JSON request per connection;
        // governance and projection take no token preamble.
        stream
            .write_all(format!("{request}\n").as_bytes())
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

    fn call_ok(&self, surface: &str, request: &Value) -> Value {
        let reply = self.try_call(surface, request).expect("byomd replied");
        assert_eq!(reply["outcome"], json!("ok"), "byomd refused: {reply}");
        reply
    }
}

impl Drop for Byomd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn digest(seed: &str) -> Value {
    let mut hex = String::new();
    while hex.len() < 64 {
        for b in seed.bytes() {
            hex.push_str(&format!("{:02x}", b));
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
fn bootstrap_society(byomd: &Byomd, incarnation: &str) -> String {
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

fn enable(key: &str, society_ref: &str, expected_owner_revision: u64) -> Value {
    mutation(
        "governance_enable",
        None,
        key,
        json!({
            "byom_endpoint_ref": "local",
            "society_ref": society_ref,
            "exact_scope_selector": SCOPE,
            "allowed_project_and_space_selectors": [SCOPE],
            "classification_binding_ref": "class-bind-k2",
            "expected_owner_revision": expected_owner_revision,
        }),
    )
}

#[test]
fn greenfield_enablement_runs_end_to_end_against_a_real_byomd() {
    let Some(repo) = byom_repo() else {
        println!(
            "k2_byomd_integration: skipped — no byom repository \
             (set KOVEE_BYOM_REPO or check out ../byom)"
        );
        return;
    };
    let binary = byomd_binary(&repo);
    let base = tmp("k2-byomd-integration");

    // 1. The real byomd, on its own four sockets.
    let byomd = Byomd::start(&binary, &base.join("byom-data"), &base.join("byom-run"));
    let hello = byomd.call_ok(
        "governance",
        &json!({"version": BPP_VERSION, "op": "hello"}),
    );
    let incarnation = hello["result"]["endpoint_incarnation"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(hello["result"]["versions"], json!([BPP_VERSION]));
    assert_eq!(hello["result"]["surface"], json!("governance"));

    // 2. A Society, established natively — never by Kovee.
    let society_id = bootstrap_society(&byomd, &incarnation);
    let seen = byomd.call_ok(
        "projection",
        &json!({"version": BPP_VERSION, "op": "society_show", "society_id": society_id}),
    );
    assert_eq!(seen["result"]["state"], json!("active"));

    // 3. koveed, pointed at that live endpoint.
    let byom_run = base.join("byom-run").to_string_lossy().into_owned();
    let daemon = DaemonProc::start_with_env(
        &base.join("kovee-data"),
        &base.join("kovee-run"),
        None,
        &[("KOVEE_BYOM_RUNTIME_DIR", byom_run.as_str())],
    );

    // Kovee is never the genesis actor: an unknown Society is refused by
    // the REAL byomd's `not_found`, not by a stub.
    let refused = daemon.expect_problem(
        &enable("idem-genesis", "soc-does-not-exist", 0),
        "forbidden",
    );
    assert!(
        refused["problem"]["detail"]
            .as_str()
            .unwrap()
            .contains("never the genesis governance actor"),
        "{refused}"
    );

    // 4. The saga, end to end.
    let enabled = daemon.expect_ok(&enable("idem-enable-1", &society_id, 0));
    let result = &enabled["result"];
    assert_eq!(result["state"], json!("active"));
    assert_eq!(result["society"]["society_ref"], json!(society_id));
    assert_eq!(result["society"]["state"], json!("active"));
    // The binding pins exactly what byomd reported — server-recomputed,
    // never taken from the wire.
    assert_eq!(
        result["binding"]["endpoint_incarnation"],
        json!(incarnation)
    );
    assert_eq!(
        result["mapping"]["society_recovery_epoch"],
        seen["result"]["recovery_epoch"]
    );
    assert_eq!(result["owner_binding"]["governance_owner"], json!("byom"));
    assert_eq!(
        result["owner_binding"]["owner_endpoint_ref"],
        json!("local")
    );

    // 5. Retry against the live endpoint stays byte-identical.
    let a = daemon
        .request_raw(&enable("idem-enable-1", &society_id, 0))
        .unwrap();
    let b = daemon
        .request_raw(&enable("idem-enable-1", &society_id, 0))
        .unwrap();
    assert_eq!(a, b);

    // 6. And the read surface reports the live binding.
    let shown = daemon.expect_ok(&read_cmd("governance_show", None, json!({})));
    assert_eq!(shown["result"]["governance_owner"], json!("byom"));
    let slot = &shown["result"]["enablements"].as_array().unwrap()[0];
    assert_eq!(slot["state"], json!("active"));
    assert_eq!(slot["society_ref"], json!(society_id));
    assert_eq!(slot["endpoint_incarnation"], json!(incarnation));
}
