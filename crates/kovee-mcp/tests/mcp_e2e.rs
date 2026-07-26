//! End-to-end MCP tests: spawn a real `koveed` (test profile), run the
//! `kovee-mcp` binary as a child over stdio pipes, and drive the MCP
//! conversation — initialize, tools/list against the document,
//! tools/call against the live daemon, and the refusal paths
//! (deny-by-absence, channel-derived fields in tool input).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// The contract the server must expose, loaded independently here.
const DOCUMENT_JSON: &str = include_str!("../../../mcp/kovee-mcp.tools.json");

fn document_tools() -> Vec<Value> {
    let doc: Value = serde_json::from_str(DOCUMENT_JSON).unwrap();
    doc["profiles"]["participant"]["tools"]
        .as_array()
        .unwrap()
        .clone()
}

fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `koveed` lives in another crate, so no `CARGO_BIN_EXE_koveed` here;
/// resolve it next to this test binary (built by `cargo test
/// --workspace`, which run-checks.sh uses).
fn koveed_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps/
    path.pop(); // debug/
    let bin = path.join("koveed");
    assert!(
        bin.exists(),
        "koveed binary not found at {}; run `cargo test --workspace` \
         (or `cargo build -p koveed`) first",
        bin.display()
    );
    bin
}

// ------------------------------------------------------------- daemon ----

struct DaemonProc {
    child: Child,
    runtime_dir: PathBuf,
}

impl DaemonProc {
    fn start(data_dir: &Path, runtime_dir: &Path) -> DaemonProc {
        let child = Command::new(koveed_bin())
            .args(["--data-dir", &data_dir.to_string_lossy()])
            .env("KOVEE_RUNTIME_DIR", runtime_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn koveed");
        let daemon = DaemonProc {
            child,
            runtime_dir: runtime_dir.to_path_buf(),
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if UnixStream::connect(daemon.socket()).is_ok() {
                return daemon;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("koveed did not come up on {}", daemon.socket().display());
    }

    fn socket(&self) -> PathBuf {
        self.runtime_dir.join("kovee.sock")
    }

    /// One request line, one reply line — asserts outcome ok.
    fn expect_ok(&self, command: &Value) -> Value {
        let mut stream = UnixStream::connect(self.socket()).unwrap();
        let mut line = command.to_string();
        line.push('\n');
        stream.write_all(line.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply).unwrap();
        let parsed: Value = serde_json::from_str(reply.trim_end()).unwrap();
        assert_eq!(
            parsed["outcome"].as_str(),
            Some("ok"),
            "expected ok, got {parsed}"
        );
        parsed
    }
}

impl Drop for DaemonProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
    if let Some(project) = project {
        cmd.insert("project_id".into(), json!(project));
    }
    cmd.insert("args".into(), args);
    Value::Object(cmd)
}

/// Creates project + space directly on the daemon socket; returns
/// `(project_id, space_id, branch_id, genesis_head)`.
fn setup_space(daemon: &DaemonProc) -> (String, String, String, String) {
    let project = daemon.expect_ok(&mutation(
        "project_create",
        None,
        "idem-mcp-project",
        json!({"name": "personal"}),
    ));
    let project_id = project["result"]["project_id"].as_str().unwrap().to_owned();
    let space = daemon.expect_ok(&mutation(
        "space_create",
        Some(&project_id),
        "idem-mcp-space",
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

// --------------------------------------------------------- MCP server ----

struct McpServer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpServer {
    fn start(runtime_dir: &Path) -> McpServer {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kovee-mcp"))
            .env("KOVEE_RUNTIME_DIR", runtime_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn kovee-mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        McpServer {
            child,
            stdin,
            stdout,
            next_id: 0,
        }
    }

    /// One JSON-RPC request, one response; asserts the ids match (so a
    /// stray reply to a notification would be caught).
    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let mut line =
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
        let mut reply = String::new();
        self.stdout.read_line(&mut reply).unwrap();
        assert!(!reply.is_empty(), "server closed the stream on {method}");
        let parsed: Value = serde_json::from_str(reply.trim_end()).unwrap();
        assert_eq!(parsed["id"].as_u64(), Some(id), "got {parsed}");
        parsed
    }

    fn notify(&mut self, method: &str) {
        let mut line = json!({"jsonrpc": "2.0", "method": method}).to_string();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
    }

    fn initialize(&mut self) {
        let reply = self.rpc(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp_e2e", "version": "0"},
            }),
        );
        assert_eq!(
            reply["result"]["protocolVersion"].as_str(),
            Some("2025-06-18")
        );
        assert_eq!(
            reply["result"]["serverInfo"]["name"].as_str(),
            Some("kovee-mcp")
        );
        self.notify("notifications/initialized");
    }

    /// A tools/call, returning `(text, is_error)`.
    fn call(&mut self, name: &str, arguments: Value) -> (String, bool) {
        let reply = self.rpc("tools/call", json!({"name": name, "arguments": arguments}));
        let result = &reply["result"];
        let text = result["content"][0]["text"].as_str().unwrap().to_owned();
        (text, result["isError"].as_bool().unwrap())
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// -------------------------------------------------------------- tests ----

/// tools/list is the document, verbatim — and the refusal paths need no
/// daemon: they must trigger before any socket dial.
#[test]
fn tools_list_matches_the_document_and_refusals_precede_dispatch() {
    // No koveed runs behind this runtime dir.
    let runtime = tmp("mcp-list-runtime");
    let mut server = McpServer::start(&runtime);
    server.initialize();

    let reply = server.rpc("tools/list", json!({}));
    let listed = reply["result"]["tools"].as_array().unwrap().clone();
    let expected = document_tools();
    assert_eq!(listed.len(), 14, "exactly the 14 C3a tools");
    assert_eq!(listed.len(), expected.len());
    for (tool, row) in listed.iter().zip(&expected) {
        let name = row["name"].as_str().unwrap();
        assert_eq!(tool["name"].as_str(), Some(name), "name/order drift");
        // Description verbatim — it carries the gated marking.
        assert_eq!(
            tool["description"].as_str(),
            row["description"].as_str(),
            "{name} description drift"
        );
        // Input schema verbatim from the document.
        assert_eq!(
            tool["inputSchema"], row["input_schema"],
            "{name} schema drift"
        );
        // Gated marking: access flag ⇔ readOnlyHint ⇔ description text.
        let gated = row["access"].as_str().unwrap() == "gated";
        assert_eq!(
            tool["annotations"]["readOnlyHint"].as_bool(),
            Some(!gated),
            "{name} readOnlyHint drift"
        );
        assert_eq!(
            tool["description"].as_str().unwrap().contains("gated"),
            gated,
            "{name} description gating marking drift"
        );
    }
    // The gated-but-non-mutating credential read carries its gating note.
    let credential = listed
        .iter()
        .find(|t| t["name"] == "kovee_artifact_upload_credential")
        .unwrap();
    let note = credential["description"].as_str().unwrap();
    assert!(note.contains("stays gated"), "gating note missing: {note}");
    assert_eq!(
        credential["annotations"]["readOnlyHint"].as_bool(),
        Some(false)
    );

    // Deny-by-absence: a real daemon op outside the document is not a
    // tool (and no daemon is even reachable — the refusal is local).
    let (text, is_error) = server.call("kovee_realm_show", json!({}));
    assert!(is_error);
    assert!(text.contains("unknown tool"), "{text}");
    assert!(text.contains("deny-by-absence"), "{text}");

    // Channel-derived fields in tool input are refused before dispatch.
    let (text, is_error) = server.call(
        "kovee_space_show",
        json!({"space_id": "space-1", "actor_ref": "prin-owner"}),
    );
    assert!(is_error);
    assert!(text.contains("actor_ref"), "{text}");
    assert!(text.contains("closed shape"), "{text}");
    let (text, is_error) = server.call(
        "kovee_space_show",
        json!({"space_id": "space-1", "realm_id": "realm-other"}),
    );
    assert!(is_error);
    assert!(text.contains("realm_id"), "{text}");
}

/// tools/call reaches the live daemon: a read, a mutation appended
/// end-to-end, the readback, and a §11.7 problem carrying its kind.
#[test]
fn tool_calls_reach_the_live_daemon() {
    let data = tmp("mcp-e2e-data");
    let runtime = tmp("mcp-e2e-runtime");
    let daemon = DaemonProc::start(&data, &runtime);
    let (_project_id, space_id, branch_id, head) = setup_space(&daemon);

    let mut server = McpServer::start(&runtime);
    server.initialize();

    // Read: kovee_space_show.
    let (text, is_error) = server.call("kovee_space_show", json!({"space_id": space_id}));
    assert!(!is_error, "{text}");
    let space: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(space["space_id"].as_str(), Some(space_id.as_str()));
    assert_eq!(space["title"].as_str(), Some("Garden"));
    assert_eq!(space["main_branch_id"].as_str(), Some(branch_id.as_str()));

    // Mutation: kovee_contribution_append (server-side envelope, fresh
    // idempotency key, §10.3 compare-and-swap against the genesis head).
    let (text, is_error) = server.call(
        "kovee_contribution_append",
        json!({
            "space_id": space_id,
            "branch_id": branch_id,
            "expected_head_digest": head,
            "kind": "observation",
            "body_parts": [{"media_type": "text/markdown", "text": "Appended over MCP."}],
        }),
    );
    assert!(!is_error, "{text}");
    let appended: Value = serde_json::from_str(&text).unwrap();
    let contribution_id = appended["contribution_id"].as_str().unwrap().to_owned();
    assert_eq!(appended["origin_branch_sequence"].as_u64(), Some(1));

    // Readback through a second tool: the append landed in the daemon.
    let (text, is_error) = server.call(
        "kovee_contribution_show",
        json!({"contribution_id": contribution_id}),
    );
    assert!(!is_error, "{text}");
    let shown: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(shown["kind"].as_str(), Some("observation"));
    assert_eq!(
        shown["body_parts"][0]["text"].as_str(),
        Some("Appended over MCP.")
    );

    // A daemon problem surfaces as a tool error carrying the §11.7 kind.
    let (text, is_error) = server.call("kovee_space_show", json!({"space_id": "space-none"}));
    assert!(is_error);
    assert!(text.contains("urn:kovee:error:not-found"), "{text}");

    // A stale head is a §10.3 conflict, kind carried verbatim.
    let (text, is_error) = server.call(
        "kovee_contribution_append",
        json!({
            "space_id": space_id,
            "branch_id": branch_id,
            "expected_head_digest": head,
            "kind": "observation",
            "body_parts": [{"media_type": "text/plain", "text": "stale writer"}],
        }),
    );
    assert!(is_error);
    assert!(text.contains("urn:kovee:error:"), "{text}");
}

/// MCP-1 / D-R1-3: the logical-call idempotency key. Two identical tool
/// calls in one session are ONE logical call — an ambiguous transport
/// retry lands on the daemon's §11.2 replay instead of minting a second
/// artifact, upload, or contribution — while a different input is a
/// different call.
#[test]
fn identical_tool_calls_in_one_session_are_one_logical_call() {
    let data = tmp("mcp-logical-key-data");
    let runtime = tmp("mcp-logical-key-runtime");
    let daemon = DaemonProc::start(&data, &runtime);
    let (_project_id, space_id, branch_id, head) = setup_space(&daemon);

    let mut server = McpServer::start(&runtime);
    server.initialize();

    // An upload: the case that used to mint a second artifact per retry.
    let begin_args = json!({
        "declared_raw_sha256": "ab".repeat(32),
        "declared_size": 11,
        "declared_media_type": "text/plain",
    });
    let (first_text, is_error) = server.call("kovee_artifact_upload_begin", begin_args.clone());
    assert!(!is_error, "{first_text}");
    let first: Value = serde_json::from_str(&first_text).unwrap();
    let (retry_text, is_error) = server.call("kovee_artifact_upload_begin", begin_args.clone());
    assert!(!is_error, "{retry_text}");
    let retry: Value = serde_json::from_str(&retry_text).unwrap();
    assert_eq!(
        first["upload_id"], retry["upload_id"],
        "an ambiguous retry must reuse the logical call, not mint a second upload"
    );
    assert_eq!(
        first["artifact_id"], retry["artifact_id"],
        "…and not a second artifact"
    );
    // One upload row, still at its first revision: the retry replayed,
    // it did not execute again.
    let (shown_text, is_error) = server.call(
        "kovee_artifact_upload_show",
        json!({"upload_id": first["upload_id"]}),
    );
    assert!(!is_error, "{shown_text}");
    let shown: Value = serde_json::from_str(&shown_text).unwrap();
    assert_eq!(shown["revision"].as_u64(), Some(1));

    // A different input is a different logical call — a different key,
    // a different upload.
    let (other_text, is_error) = server.call(
        "kovee_artifact_upload_begin",
        json!({
            "declared_raw_sha256": "ab".repeat(32),
            "declared_size": 12,
            "declared_media_type": "text/plain",
        }),
    );
    assert!(!is_error, "{other_text}");
    let other: Value = serde_json::from_str(&other_text).unwrap();
    assert_ne!(
        first["upload_id"], other["upload_id"],
        "a different input must not collapse onto the same key"
    );

    // The same contract on a space mutation: one contribution, not two.
    let append_args = json!({
        "space_id": space_id,
        "branch_id": branch_id,
        "expected_head_digest": head,
        "kind": "observation",
        "body_parts": [{"media_type": "text/plain", "text": "one logical append"}],
    });
    let (a_text, is_error) = server.call("kovee_contribution_append", append_args.clone());
    assert!(!is_error, "{a_text}");
    let a: Value = serde_json::from_str(&a_text).unwrap();
    let (b_text, is_error) = server.call("kovee_contribution_append", append_args);
    assert!(!is_error, "{b_text}");
    let b: Value = serde_json::from_str(&b_text).unwrap();
    assert_eq!(
        a["contribution_id"], b["contribution_id"],
        "the retry replayed the same append"
    );
    let (listed_text, is_error) = server.call(
        "kovee_contribution_list",
        json!({"space_id": space_id, "limit": 100}),
    );
    assert!(!is_error, "{listed_text}");
    let listed: Value = serde_json::from_str(&listed_text).unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        1,
        "exactly one contribution exists after the retried call"
    );
}
