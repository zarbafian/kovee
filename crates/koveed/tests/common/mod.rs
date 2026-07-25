//! Shared harness for the K1 daemon integration tests: spawn the real
//! `koveed` binary, speak one-line JSON over both Unix sockets, and
//! build well-formed commands.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

pub struct DaemonProc {
    child: Child,
    runtime_dir: PathBuf,
}

impl DaemonProc {
    pub fn start(data_dir: &Path, runtime_dir: &Path, abort: Option<&str>) -> DaemonProc {
        std::fs::create_dir_all(data_dir).unwrap();
        std::fs::create_dir_all(runtime_dir).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_koveed"));
        cmd.args(["--data-dir", &data_dir.to_string_lossy()])
            .env("KOVEE_RUNTIME_DIR", runtime_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match abort {
            Some(spec) => {
                cmd.env("KOVEED_ABORT", spec);
            }
            None => {
                cmd.env_remove("KOVEED_ABORT");
            }
        }
        let child = cmd.spawn().expect("spawn koveed");
        let daemon = DaemonProc {
            child,
            runtime_dir: runtime_dir.to_path_buf(),
        };
        daemon.wait_ready();
        daemon
    }

    pub fn socket(&self) -> PathBuf {
        self.runtime_dir.join("kovee.sock")
    }

    pub fn worker_socket(&self) -> PathBuf {
        self.runtime_dir.join("kovee-worker.sock")
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if UnixStream::connect(self.socket()).is_ok()
                && UnixStream::connect(self.worker_socket()).is_ok()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("koveed did not come up on {}", self.socket().display());
    }

    /// One request line, one raw reply line (`None` when the daemon died
    /// before replying — the crash hooks do exactly that).
    pub fn request_raw_at(&self, socket: &Path, command: &Value) -> Option<String> {
        let mut stream = UnixStream::connect(socket).ok()?;
        let mut line = serde_json::to_string(command).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).ok()?;
        stream.shutdown(std::net::Shutdown::Write).ok()?;
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply).ok()?;
        if reply.is_empty() {
            return None;
        }
        Some(reply.trim_end().to_owned())
    }

    pub fn request_raw(&self, command: &Value) -> Option<String> {
        self.request_raw_at(&self.socket(), command)
    }

    pub fn request(&self, command: &Value) -> Value {
        let raw = self
            .request_raw(command)
            .expect("daemon replied with a line");
        serde_json::from_str(&raw).expect("reply is JSON")
    }

    pub fn worker_request(&self, command: &Value) -> Value {
        let raw = self
            .request_raw_at(&self.worker_socket(), command)
            .expect("daemon replied with a line");
        serde_json::from_str(&raw).expect("reply is JSON")
    }

    pub fn expect_ok(&self, command: &Value) -> Value {
        let reply = self.request(command);
        assert_eq!(
            reply["outcome"].as_str(),
            Some("ok"),
            "expected ok, got {reply}"
        );
        reply
    }

    pub fn worker_expect_ok(&self, command: &Value) -> Value {
        let reply = self.worker_request(command);
        assert_eq!(
            reply["outcome"].as_str(),
            Some("ok"),
            "expected ok, got {reply}"
        );
        reply
    }

    pub fn expect_problem(&self, command: &Value, kind: &str) -> Value {
        let reply = self.request(command);
        assert_eq!(reply["outcome"].as_str(), Some("problem"), "got {reply}");
        assert_eq!(
            reply["problem"]["type"].as_str(),
            Some(format!("urn:kovee:error:{kind}").as_str()),
            "got {reply}"
        );
        reply
    }

    pub fn worker_expect_problem(&self, command: &Value, kind: &str) -> Value {
        let reply = self.worker_request(command);
        assert_eq!(reply["outcome"].as_str(), Some("problem"), "got {reply}");
        assert_eq!(
            reply["problem"]["type"].as_str(),
            Some(format!("urn:kovee:error:{kind}").as_str()),
            "got {reply}"
        );
        reply
    }

    /// Reaps the child after an expected abort.
    pub fn wait_dead(mut self) {
        let _ = self.child.wait();
        self.child = spawned_dummy();
        drop(self);
    }

    /// Waits until the child exits on its own (armed aborts).
    pub fn wait_exit(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

fn spawned_dummy() -> Child {
    Command::new("true").spawn().expect("spawn true")
}

impl Drop for DaemonProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ------------------------------------------------- command builders ----

pub fn mutation(op: &str, project: Option<&str>, key: &str, args: Value) -> Value {
    let mut cmd = serde_json::Map::new();
    cmd.insert("version".into(), json!("0.1"));
    cmd.insert("op".into(), json!(op));
    cmd.insert(
        "meta".into(),
        json!({"request_id": format!("req-{key}"), "idempotency_key": key}),
    );
    cmd.insert("realm_id".into(), json!("realm-personal"));
    if let Some(p) = project {
        cmd.insert("project_id".into(), json!(p));
    }
    cmd.insert("args".into(), args);
    Value::Object(cmd)
}

pub fn read_cmd(op: &str, project: Option<&str>, args: Value) -> Value {
    let mut cmd = serde_json::Map::new();
    cmd.insert("version".into(), json!("0.1"));
    cmd.insert("op".into(), json!(op));
    cmd.insert("realm_id".into(), json!("realm-personal"));
    if let Some(p) = project {
        cmd.insert("project_id".into(), json!(p));
    }
    cmd.insert("args".into(), args);
    Value::Object(cmd)
}

pub fn events_read(project: &str) -> Value {
    read_cmd(
        "events_read",
        Some(project),
        json!({"source": project, "limit": 512}),
    )
}

/// Sets up project + space and returns
/// `(project_id, space_id, branch_id, genesis_head)`.
pub fn setup_space(daemon: &DaemonProc) -> (String, String, String, String) {
    let project = daemon.expect_ok(&mutation(
        "project_create",
        None,
        "idem-setup-project",
        json!({"name": "personal"}),
    ));
    let project_id = project["result"]["project_id"].as_str().unwrap().to_owned();
    let space = daemon.expect_ok(&mutation(
        "space_create",
        Some(&project_id),
        "idem-setup-space",
        json!({"title": "Garden", "visibility": "project"}),
    ));
    let space_id = space["result"]["space_id"].as_str().unwrap().to_owned();
    let branch_id = space["result"]["main_branch_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let head = kovee_core::branch::genesis_head(&branch_id);
    (project_id, space_id, branch_id, head)
}

/// Appends a contribution and returns `(id, digest, new_head)`.
#[allow(clippy::too_many_arguments)]
pub fn append(
    daemon: &DaemonProc,
    project: &str,
    space: &str,
    branch: &str,
    head: &str,
    key: &str,
    kind: &str,
    text: &str,
    extra: Value,
) -> (String, String, String) {
    let mut args = json!({
        "space_id": space,
        "branch_id": branch,
        "expected_head_digest": head,
        "kind": kind,
        "body_parts": [{"media_type": "text/plain", "text": text}],
    });
    if let Some(extra) = extra.as_object() {
        for (k, v) in extra {
            args[k.as_str()] = v.clone();
        }
    }
    let reply = daemon.expect_ok(&mutation("contribution_append", Some(project), key, args));
    let id = reply["result"]["contribution_id"].as_str().unwrap();
    let digest = reply["result"]["content_digest"].as_str().unwrap();
    let seq = reply["result"]["origin_branch_sequence"].as_u64().unwrap();
    let new_head = kovee_core::branch::next_head(head, seq, digest);
    (id.to_owned(), digest.to_owned(), new_head)
}
