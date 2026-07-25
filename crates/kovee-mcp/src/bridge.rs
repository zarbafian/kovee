//! The client-socket bridge: assembles the KCP envelope server-side
//! around already-validated tool args and speaks koveed's
//! one-newline-JSON-request-per-connection protocol (the kovee-cli
//! client shape).
//!
//! Envelope derivation — the C3a binding envelope, personal profile:
//! - `realm_id` is the daemon's personal realm
//!   (`kovee_store::PERSONAL_REALM_ID`);
//! - `project_id` is the channel-pinned project scope: `$KOVEE_PROJECT`
//!   when set, else the single project of the personal realm
//!   (`project_list`), resolved once and cached for the session;
//! - `meta` appears only on mutations (kovee-core's registry-derived
//!   read/mutation rule) and carries a fresh `idempotency_key` per tool
//!   call. A harness retry of a tool call is therefore a NEW command
//!   with a new key: §11.2 idempotent replay safety lives in the
//!   daemon, never simulated here.
//!
//! Whether `realm_id`/`project_id` may appear at all comes from
//! `kovee_core::ops::op_spec` per op — the same table the daemon
//! enforces placement with.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use kovee_core::ops::{op_spec, FieldRule, OpKind};
use serde_json::{json, Map, Value};

/// A failed bridge call.
pub enum BridgeError {
    /// Transport or local failure: koveed unreachable, malformed reply…
    Io(String),
    /// The daemon answered a §11.7 problem — carried verbatim so the
    /// MCP tool error keeps the problem kind.
    Problem(Value),
}

/// The daemon connection state: socket path plus the cached
/// channel-pinned project.
pub struct Bridge {
    socket: PathBuf,
    project: Option<String>,
}

impl Default for Bridge {
    fn default() -> Bridge {
        Bridge::new()
    }
}

impl Bridge {
    pub fn new() -> Bridge {
        Bridge {
            // The same resolution rules the daemon binds with
            // ($KOVEE_RUNTIME_DIR, else $XDG_RUNTIME_DIR/kovee, …).
            socket: koveed::socket::socket_path(),
            project: None,
        }
    }

    /// Runs one tool invocation as its client-socket op: envelope
    /// assembled here, `args` passed through verbatim.
    pub fn call(&mut self, version: &str, op: &str, args: Value) -> Result<Value, BridgeError> {
        let Some(spec) = op_spec(op) else {
            return Err(BridgeError::Io(format!(
                "op {op:?} is not a K1 registry operation"
            )));
        };
        let mut cmd = Map::new();
        cmd.insert("version".into(), json!(version));
        cmd.insert("op".into(), json!(op));
        if spec.kind == OpKind::Mutation {
            let key = fresh_idempotency_key()?;
            cmd.insert(
                "meta".into(),
                json!({"request_id": format!("req-{key}"), "idempotency_key": key}),
            );
        }
        if spec.realm_id != FieldRule::Forbidden {
            cmd.insert("realm_id".into(), json!(kovee_store::PERSONAL_REALM_ID));
        }
        if spec.project_id != FieldRule::Forbidden {
            let project = self.project(version)?;
            cmd.insert("project_id".into(), json!(project));
        }
        cmd.insert("args".into(), args);
        self.request(&Value::Object(cmd))
    }

    /// The channel-pinned project scope, resolved once.
    fn project(&mut self, version: &str) -> Result<String, BridgeError> {
        if let Some(project) = &self.project {
            return Ok(project.clone());
        }
        let resolved = match std::env::var("KOVEE_PROJECT") {
            Ok(project) if !project.is_empty() => project,
            _ => self.single_project(version)?,
        };
        self.project = Some(resolved.clone());
        Ok(resolved)
    }

    fn single_project(&self, version: &str) -> Result<String, BridgeError> {
        let result = self.request(&json!({
            "version": version,
            "op": "project_list",
            "realm_id": kovee_store::PERSONAL_REALM_ID,
            "args": {"limit": 512},
        }))?;
        let items = result.get("items").and_then(Value::as_array);
        let mut ids = items
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("project_id").and_then(Value::as_str));
        match (ids.next(), ids.next()) {
            (Some(only), None) => Ok(only.to_owned()),
            (None, _) => Err(BridgeError::Io(
                "no project exists in the personal realm; run `kovee init` once \
                 (or set KOVEE_PROJECT)"
                    .to_owned(),
            )),
            (Some(_), Some(_)) => Err(BridgeError::Io(
                "more than one project exists; set KOVEE_PROJECT to pin the \
                 binding's project scope"
                    .to_owned(),
            )),
        }
    }

    /// One request line in, one reply line out (the whole protocol).
    fn request(&self, command: &Value) -> Result<Value, BridgeError> {
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| {
            BridgeError::Io(format!(
                "could not reach koveed at {} ({e}); is the daemon running?",
                self.socket.display()
            ))
        })?;
        let mut line = command.to_string();
        line.push('\n');
        stream.write_all(line.as_bytes()).map_err(io_error)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(io_error)?;
        let mut reply = String::new();
        BufReader::new(stream)
            .read_line(&mut reply)
            .map_err(io_error)?;
        let parsed: Value = serde_json::from_str(reply.trim_end())
            .map_err(|e| BridgeError::Io(format!("malformed daemon reply: {e}")))?;
        match parsed.get("outcome").and_then(Value::as_str) {
            Some("ok") => Ok(parsed.get("result").cloned().unwrap_or(Value::Null)),
            Some("problem") => Err(BridgeError::Problem(
                parsed.get("problem").cloned().unwrap_or(Value::Null),
            )),
            _ => Err(BridgeError::Io(
                "malformed daemon reply: no outcome".to_owned(),
            )),
        }
    }
}

fn io_error(e: std::io::Error) -> BridgeError {
    BridgeError::Io(format!("daemon socket io: {e}"))
}

/// A fresh key per mutation call (kovee-cli's shape, `mcp-` prefixed).
fn fresh_idempotency_key() -> Result<String, BridgeError> {
    let mut bytes = [0u8; 12];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(io_error)?;
    let mut hex = String::with_capacity(24);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(format!("mcp-{hex}"))
}
