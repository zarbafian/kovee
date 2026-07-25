//! K1 slice-1 end-to-end over a real Unix socket: init → space create →
//! contribution append → events_read shows the dense sequences → an exact
//! idempotent replay returns the stored byte-identical result with no
//! duplicate event — plus kill-and-restart honesty at both §12.2 commit
//! points (die before commit: nothing exists; die after commit, before
//! the reply: the committed event survives exactly once and the retry
//! replays the stored result). WAL recovery is exercised by reopening the
//! same database after each abort.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

struct DaemonProc {
    child: Child,
    runtime_dir: PathBuf,
}

impl DaemonProc {
    fn start(data_dir: &Path, runtime_dir: &Path, abort: Option<&str>) -> DaemonProc {
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

    fn socket(&self) -> PathBuf {
        self.runtime_dir.join("kovee.sock")
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if UnixStream::connect(self.socket()).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("koveed did not come up on {}", self.socket().display());
    }

    /// One request line, one raw reply line (`None` when the daemon died
    /// before replying — the crash hooks do exactly that).
    fn request_raw(&self, command: &Value) -> Option<String> {
        let mut stream = UnixStream::connect(self.socket()).ok()?;
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

    fn request(&self, command: &Value) -> Value {
        let raw = self
            .request_raw(command)
            .expect("daemon replied with a line");
        serde_json::from_str(&raw).expect("reply is JSON")
    }

    fn expect_ok(&self, command: &Value) -> Value {
        let reply = self.request(command);
        assert_eq!(
            reply["outcome"].as_str(),
            Some("ok"),
            "expected ok, got {reply}"
        );
        reply
    }

    fn expect_problem(&self, command: &Value, kind: &str) -> Value {
        let reply = self.request(command);
        assert_eq!(reply["outcome"].as_str(), Some("problem"), "got {reply}");
        assert_eq!(
            reply["problem"]["type"].as_str(),
            Some(format!("urn:kovee:error:{kind}").as_str()),
            "got {reply}"
        );
        reply
    }

    /// Reaps the child after an expected abort.
    fn wait_dead(mut self) {
        let _ = self.child.wait();
        // Forget the runtime dir; Drop must not kill an already-reaped pid.
        self.child = spawned_dummy();
        drop(self);
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

fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn hello_cmd() -> Value {
    json!({
        "version": "0.1", "op": "hello",
        "args": {
            "supported_versions": ["0.1"],
            "implementation": "k1-slice1-test",
            "implementation_version": "0.0.1",
            "requested_features": [],
        },
    })
}

fn mutation(op: &str, project: Option<&str>, key: &str, args: Value) -> Value {
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

fn read_cmd(op: &str, project: Option<&str>, args: Value) -> Value {
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

fn events_read(project: &str) -> Value {
    read_cmd(
        "events_read",
        Some(project),
        json!({"source": project, "limit": 512}),
    )
}

/// The append command used throughout: one utterance on the main branch.
fn append_cmd(project: &str, space: &str, branch: &str, head: &str, key: &str) -> Value {
    mutation(
        "contribution_append",
        Some(project),
        key,
        json!({
            "space_id": space,
            "branch_id": branch,
            "expected_head_digest": head,
            "kind": "utterance",
            "body_parts": [{"media_type": "text/plain", "text": "hello, space"}],
        }),
    )
}

/// Project sequences must be dense and monotonic (§11.3): 1..=n.
fn assert_dense(events: &[Value]) {
    for (i, event) in events.iter().enumerate() {
        assert_eq!(
            event["project_sequence"].as_u64(),
            Some(i as u64 + 1),
            "project sequence not dense at index {i}: {event}"
        );
    }
}

#[test]
fn end_to_end_flow_idempotency_and_dense_sequences() {
    let base = tmp("k1-flow");
    let daemon = DaemonProc::start(&base.join("data"), &base.join("run"), None);

    // hello: negotiation, honest (empty) feature set, installation id.
    let hello = daemon.expect_ok(&hello_cmd());
    assert_eq!(hello["result"]["selected_version"].as_str(), Some("0.1"));
    assert_eq!(
        hello["result"]["features"].as_array().map(Vec::len),
        Some(0)
    );
    let installation = hello["result"]["installation_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // realm_show on the bootstrapped personal realm.
    let realm = daemon.expect_ok(&read_cmd("realm_show", None, json!({})));
    assert_eq!(realm["result"]["realm_id"].as_str(), Some("realm-personal"));
    assert_eq!(
        realm["result"]["installation_id"].as_str(),
        Some(installation.as_str())
    );

    // project_create.
    let project = daemon.expect_ok(&mutation(
        "project_create",
        None,
        "idem-project",
        json!({"name": "personal"}),
    ));
    let project_id = project["result"]["project_id"].as_str().unwrap().to_owned();
    assert_eq!(project["revision"].as_u64(), Some(1));

    // space_create.
    let space = daemon.expect_ok(&mutation(
        "space_create",
        Some(&project_id),
        "idem-space",
        json!({"title": "Garden", "visibility": "project"}),
    ));
    let space_id = space["result"]["space_id"].as_str().unwrap().to_owned();
    let branch_id = space["result"]["main_branch_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(space["result"]["next_space_sequence"].as_u64(), Some(1));

    // space_show round-trips the record.
    let shown = daemon.expect_ok(&read_cmd(
        "space_show",
        Some(&project_id),
        json!({"space_id": space_id}),
    ));
    assert_eq!(shown["result"], space["result"]);

    // contribution_append against the genesis head.
    let head = kovee_core::branch::genesis_head(&branch_id);
    let append = append_cmd(&project_id, &space_id, &branch_id, &head, "idem-append");
    let raw_first = daemon.request_raw(&append).unwrap();
    let first: Value = serde_json::from_str(&raw_first).unwrap();
    assert_eq!(first["outcome"].as_str(), Some("ok"), "{first}");
    let contribution = &first["result"];
    assert_eq!(contribution["origin_branch_sequence"].as_u64(), Some(1));
    assert_eq!(contribution["space_sequence"].as_u64(), Some(1));
    assert_eq!(
        contribution["author_actor_ref"].as_str(),
        Some("prin-owner")
    );
    let contribution_id = contribution["contribution_id"].as_str().unwrap().to_owned();

    // contribution_show returns the same record.
    let shown = daemon.expect_ok(&read_cmd(
        "contribution_show",
        Some(&project_id),
        json!({"contribution_id": contribution_id}),
    ));
    assert_eq!(&shown["result"], contribution);

    // events_read: dense project sequence over the three commits, dense
    // stream sequences per aggregate stream.
    let events = daemon.expect_ok(&events_read(&project_id));
    let list = events["result"]["events"].as_array().unwrap().clone();
    assert_eq!(list.len(), 3, "{events}");
    assert_dense(&list);
    assert_eq!(
        list[0]["type"].as_str(),
        Some("dev.kovee.project.created.v1")
    );
    assert_eq!(list[1]["type"].as_str(), Some("dev.kovee.space.created.v1"));
    assert_eq!(
        list[2]["type"].as_str(),
        Some("dev.kovee.space.contribution-appended.v1")
    );
    assert_eq!(list[1]["stream_sequence"].as_u64(), Some(1));
    assert_eq!(list[2]["stream_sequence"].as_u64(), Some(2));
    assert_eq!(
        list[2]["resource_ref"].as_str(),
        Some(contribution_id.as_str())
    );

    // Exact idempotent replay: byte-identical reply, no new event.
    let raw_replay = daemon.request_raw(&append).unwrap();
    assert_eq!(raw_first, raw_replay, "replay must be byte-identical");
    let events_after = daemon.expect_ok(&events_read(&project_id));
    assert_eq!(
        events_after["result"]["events"].as_array().unwrap().len(),
        3
    );

    // Same key, changed covered values → idempotency-mismatch, no event.
    let mismatch = append_cmd(&project_id, &space_id, &branch_id, &head, "idem-append");
    let mut mismatch = mismatch;
    mismatch["args"]["kind"] = json!("question");
    daemon.expect_problem(&mismatch, "idempotency-mismatch");

    // A second append with the stale genesis head → stale-revision (the
    // §10.3 compare-and-swap), and nothing committed.
    daemon.expect_problem(
        &append_cmd(&project_id, &space_id, &branch_id, &head, "idem-append-2"),
        "stale-revision",
    );

    // Chained head: the fold any reader can compute admits the next append.
    let digest = contribution["content_digest"].as_str().unwrap();
    let head2 = kovee_core::branch::next_head(&head, 1, digest);
    let second = daemon.expect_ok(&append_cmd(
        &project_id,
        &space_id,
        &branch_id,
        &head2,
        "idem-append-3",
    ));
    assert_eq!(second["result"]["origin_branch_sequence"].as_u64(), Some(2));
    assert_eq!(second["result"]["space_sequence"].as_u64(), Some(2));

    // Registry meta rule: a read carrying meta is refused …
    let mut bad_read = read_cmd(
        "space_show",
        Some(&project_id),
        json!({"space_id": space_id}),
    );
    bad_read["meta"] = json!({"request_id": "r", "idempotency_key": "k"});
    daemon.expect_problem(&bad_read, "invalid");
    // … and a mutation without an idempotency key is refused.
    let mut bad_mutation = mutation(
        "space_create",
        Some(&project_id),
        "k",
        json!({"title": "x", "visibility": "project"}),
    );
    bad_mutation["meta"] = json!({"request_id": "r"});
    daemon.expect_problem(&bad_mutation, "invalid");

    // Worker-surface binding members on the external socket are refused.
    let mut worker_append = append_cmd(&project_id, &space_id, &branch_id, &head2, "idem-worker");
    worker_append["args"]["attempt_id"] = json!("att-1");
    worker_append["args"]["fence_epoch"] = json!(1);
    daemon.expect_problem(&worker_append, "forbidden-surface");

    // A foreign realm is an invisible resource; an unknown op is closed.
    let mut foreign = read_cmd("realm_show", None, json!({}));
    foreign["realm_id"] = json!("realm-other");
    daemon.expect_problem(&foreign, "not-found");
    daemon.expect_problem(
        &read_cmd("space_freeze", Some(&project_id), json!({})),
        "unknown-op",
    );
}

#[test]
fn crash_before_commit_leaves_nothing_and_retry_executes_once() {
    let base = tmp("k1-crash-before");
    let data = base.join("data");
    let run = base.join("run");

    // Phase 1: a healthy daemon sets up project + space.
    let daemon = DaemonProc::start(&data, &run, None);
    let project = daemon.expect_ok(&mutation(
        "project_create",
        None,
        "idem-p",
        json!({"name": "p"}),
    ));
    let project_id = project["result"]["project_id"].as_str().unwrap().to_owned();
    let space = daemon.expect_ok(&mutation(
        "space_create",
        Some(&project_id),
        "idem-s",
        json!({"title": "t", "visibility": "project"}),
    ));
    let space_id = space["result"]["space_id"].as_str().unwrap().to_owned();
    let branch_id = space["result"]["main_branch_id"]
        .as_str()
        .unwrap()
        .to_owned();
    drop(daemon);

    // Phase 2: a daemon armed to abort contribution_append BEFORE commit.
    let armed = DaemonProc::start(&data, &run, Some("before_commit:contribution_append"));
    let head = kovee_core::branch::genesis_head(&branch_id);
    let append = append_cmd(&project_id, &space_id, &branch_id, &head, "idem-a");
    assert!(
        armed.request_raw(&append).is_none(),
        "the daemon must die before replying"
    );
    armed.wait_dead();

    // Phase 3: restart on the same database — WAL recovers; nothing of
    // the aborted transaction exists (no state, no event, no idempotency
    // record, no outbox).
    let recovered = DaemonProc::start(&data, &run, None);
    let events = recovered.expect_ok(&events_read(&project_id));
    let list = events["result"]["events"].as_array().unwrap().clone();
    assert_eq!(list.len(), 2, "no contribution event may exist: {events}");
    assert_dense(&list);

    // The retry with the SAME key executes fresh (no stored record) and
    // commits exactly one event, with a dense (gap-free) sequence.
    let retried = recovered.expect_ok(&append);
    assert_eq!(retried["result"]["space_sequence"].as_u64(), Some(1));
    let events = recovered.expect_ok(&events_read(&project_id));
    let list = events["result"]["events"].as_array().unwrap().clone();
    assert_eq!(list.len(), 3);
    assert_dense(&list);
    assert_eq!(
        list[2]["resource_ref"].as_str(),
        retried["result"]["contribution_id"].as_str()
    );
}

#[test]
fn crash_after_commit_keeps_the_event_once_and_replays_the_result() {
    let base = tmp("k1-crash-after");
    let data = base.join("data");
    let run = base.join("run");

    let daemon = DaemonProc::start(&data, &run, None);
    let project = daemon.expect_ok(&mutation(
        "project_create",
        None,
        "idem-p",
        json!({"name": "p"}),
    ));
    let project_id = project["result"]["project_id"].as_str().unwrap().to_owned();
    let space = daemon.expect_ok(&mutation(
        "space_create",
        Some(&project_id),
        "idem-s",
        json!({"title": "t", "visibility": "project"}),
    ));
    let space_id = space["result"]["space_id"].as_str().unwrap().to_owned();
    let branch_id = space["result"]["main_branch_id"]
        .as_str()
        .unwrap()
        .to_owned();
    drop(daemon);

    // Abort AFTER commit, before the reply: the client sees no reply, but
    // the transaction is durable.
    let armed = DaemonProc::start(&data, &run, Some("after_commit:contribution_append"));
    let head = kovee_core::branch::genesis_head(&branch_id);
    let append = append_cmd(&project_id, &space_id, &branch_id, &head, "idem-a");
    assert!(
        armed.request_raw(&append).is_none(),
        "the daemon must die after committing, before replying"
    );
    armed.wait_dead();

    // Restart: the committed event survives exactly once; the retry with
    // the same key replays the stored result (§12.2: “if the process dies
    // after commit and before reply, replay returns the stored result”).
    let recovered = DaemonProc::start(&data, &run, None);
    let events = recovered.expect_ok(&events_read(&project_id));
    let list = events["result"]["events"].as_array().unwrap().clone();
    assert_eq!(list.len(), 3, "exactly one committed append: {events}");
    assert_dense(&list);

    let replay = recovered.expect_ok(&append);
    assert_eq!(
        replay["result"]["contribution_id"].as_str(),
        list[2]["resource_ref"].as_str(),
        "the replayed result names the committed contribution"
    );
    // No duplicate event was created by the replay.
    let events_after = recovered.expect_ok(&events_read(&project_id));
    assert_eq!(
        events_after["result"]["events"].as_array().unwrap().len(),
        3
    );

    // The stored result is byte-stable across further replays.
    let raw_one = recovered.request_raw(&append).unwrap();
    let raw_two = recovered.request_raw(&append).unwrap();
    assert_eq!(raw_one, raw_two);
}
