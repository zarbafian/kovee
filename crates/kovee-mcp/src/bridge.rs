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
//!   read/mutation rule) and carries the **logical-call idempotency
//!   key** described below.
//!
//! Whether `realm_id`/`project_id` may appear at all comes from
//! `kovee_core::ops::op_spec` per op — the same table the daemon
//! enforces placement with.
//!
//! # The logical-call idempotency key (D-R1-3)
//!
//! ```text
//! idempotency_key = "mcp-" ‖ hex(HMAC-SHA-256(session_salt,
//!                                 JCS({"input": args, "tool": name})))[..24]
//! ```
//!
//! - **tool name** — the MCP tool the harness called, so two different
//!   tools can never collide;
//! - **canonical input** — RFC 8785 JCS of the validated tool arguments,
//!   so member order and formatting cannot fork the key;
//! - **per-server-session salt** — 32 random bytes minted once per
//!   `kovee-mcp` process, so the key is unguessable, is not a content
//!   hash of the caller's data, and does not silently collapse calls
//!   from a *different* session into one command.
//!
//! The contract this buys: **an ambiguous transport retry reuses the
//! key**. If the daemon commits and the reply is lost, the harness
//! calling the same tool with the same input again lands on the same
//! §11.2 idempotency record and receives the SAME artifact, upload, or
//! contribution — it does not mint a second one. A fresh random key per
//! invocation (the withdrawn behaviour) made every retry a new command
//! and every lost reply a double-commit hazard.
//!
//! The other side of the same contract: within one session, a
//! deliberately repeated identical call is ONE logical call. A caller
//! who means a genuinely new object must vary the input (a new title, a
//! new body, a different declared upload) — which is what varying input
//! means for every other idempotent API.

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

/// The daemon connection state: socket path, the cached channel-pinned
/// project, and the per-server-session salt the logical-call key derives
/// from.
pub struct Bridge {
    socket: PathBuf,
    project: Option<String>,
    session_salt: [u8; 32],
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
            // One salt for the life of this server process: the logical
            // call is "this tool, this input, this session".
            session_salt: session_salt(),
        }
    }

    /// Runs one tool invocation as its client-socket op: envelope
    /// assembled here, `args` passed through verbatim. `tool` is the MCP
    /// tool name — one third of the logical-call key.
    pub fn call(
        &mut self,
        version: &str,
        tool: &str,
        op: &str,
        args: Value,
    ) -> Result<Value, BridgeError> {
        let Some(spec) = op_spec(op) else {
            return Err(BridgeError::Io(format!(
                "op {op:?} is not a K1 registry operation"
            )));
        };
        let mut cmd = Map::new();
        cmd.insert("version".into(), json!(version));
        cmd.insert("op".into(), json!(op));
        if spec.kind == OpKind::Mutation {
            let key = self.logical_call_key(tool, &args)?;
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

    /// The D-R1-3 logical-call idempotency key: deterministic in (tool,
    /// canonical input, session), so an ambiguous transport retry of the
    /// same logical call reuses it instead of minting a second command.
    pub fn logical_call_key(&self, tool: &str, args: &Value) -> Result<String, BridgeError> {
        let preimage = kovee_core::canonical::jcs(&json!({"input": args, "tool": tool}))
            .map_err(|e| BridgeError::Io(format!("canonical tool input: {e}")))?;
        let mac = kovee_core::family::hmac_sha256(&self.session_salt, &preimage);
        Ok(format!(
            "mcp-{}",
            kovee_core::family::hex(&mac)
                .chars()
                .take(24)
                .collect::<String>()
        ))
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

/// 32 random bytes, minted once per server process. Entropy is not
/// available in a `const`, and a server that cannot read entropy must
/// not fall back to a predictable salt: the all-zero fallback below is
/// unreachable in practice (`/dev/urandom` is always readable on the
/// platforms this daemon binds a Unix socket on) and keeps key
/// derivation total.
fn session_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut salt))
        .is_err()
    {
        eprintln!("kovee-mcp: no entropy for the session salt; logical-call keys are weak");
    }
    salt
}
