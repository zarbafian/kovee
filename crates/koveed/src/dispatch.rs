//! Per-connection request handling: admission caps, strict I-JSON, the
//! §11.2 envelope shapes, the registry read/mutation meta rule, per-op
//! argument validation, and dispatch into the handlers.

use std::io::{BufRead as _, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

use kovee_core::envelope::{CommandResult, RawCommand};
use kovee_core::limits;
use kovee_core::ops::{self, OpKind};
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::time::unix_now;
use kovee_store::{CrashHooks, Store, PERSONAL_REALM_ID};

use crate::handlers;
use crate::peercred::{authenticate_same_uid, current_uid};

/// A crash-honesty instruction from the environment
/// (`KOVEED_ABORT=<before_commit|after_commit>:<op>`): abort the process
/// at the named §12.2 commit point of the named operation. Test-only; the
/// variable is absent in production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbortSpec {
    pub phase: String,
    pub op: String,
}

impl AbortSpec {
    pub fn from_env() -> Option<AbortSpec> {
        let raw = std::env::var("KOVEED_ABORT").ok()?;
        let (phase, op) = raw.split_once(':')?;
        Some(AbortSpec {
            phase: phase.to_owned(),
            op: op.to_owned(),
        })
    }

    fn hooks_for(&self, op: &str) -> CrashHooks {
        CrashHooks {
            abort_before_commit: self.phase == "before_commit" && self.op == op,
            abort_after_commit: self.phase == "after_commit" && self.op == op,
        }
    }
}

/// The daemon: one store, one dispatch surface.
pub struct Daemon {
    store: Store,
    abort: Option<AbortSpec>,
}

impl Daemon {
    pub fn new(store: Store, abort: Option<AbortSpec>) -> Daemon {
        Daemon { store, abort }
    }

    /// Serves connections until the listener errors. One request per
    /// connection: read one line, write one line, close.
    pub fn serve(&mut self, listener: &UnixListener) {
        let uid = current_uid();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            // §12.2 step 1: authenticate the channel. A foreign UID is
            // dropped before a byte is read, and learns nothing.
            if authenticate_same_uid(&stream, uid).is_err() {
                continue;
            }
            if let Err(e) = self.handle_connection(stream) {
                eprintln!("koveed: connection error: {e}");
            }
        }
    }

    fn handle_connection(&mut self, stream: UnixStream) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        // §11.8 request cap, enforced at admission: read at most one byte
        // past the cap so an oversized request is detected, not buffered.
        let mut bounded = (&mut reader as &mut dyn Read).take(limits::REQUEST_MAX_BYTES as u64 + 1);
        read_line_limited(&mut bounded, &mut line)?;
        let reply = self.dispatch_line(&line);
        let mut stream = stream;
        stream.write_all(&reply)?;
        stream.write_all(b"\n")?;
        Ok(())
    }

    /// One request line to one reply line (no trailing newline).
    pub fn dispatch_line(&mut self, line: &str) -> Vec<u8> {
        match self.dispatch_inner(line) {
            Ok(reply) => {
                if reply.len() > limits::REPLY_MAX_BYTES {
                    // §11.8 reply cap: fail closed rather than stream an
                    // over-cap reply.
                    problem_bytes(Problem::new(
                        ProblemKind::Internal,
                        "reply exceeds the §11.8 cap",
                    ))
                } else {
                    reply
                }
            }
            Err(problem) => problem_bytes(problem),
        }
    }

    fn dispatch_inner(&mut self, line: &str) -> Result<Vec<u8>, Problem> {
        if line.len() > limits::REQUEST_MAX_BYTES {
            return Err(Problem::new(
                ProblemKind::Invalid,
                "request exceeds the §11.8 256 KiB cap",
            ));
        }
        // Strict I-JSON acceptance (§11.8).
        let value = kovee_core::ijson::parse_strict(line).map_err(|e| {
            Problem::new(ProblemKind::Invalid, "not strict I-JSON").with_detail(e.to_string())
        })?;
        let cmd = RawCommand::from_value(value)?;
        // Version before op: a client speaking another major/minor gets
        // unsupported-version, not unknown-op noise.
        if cmd.version != kovee_core::PROTOCOL_VERSION {
            return Err(Problem::new(
                ProblemKind::UnsupportedVersion,
                "no common protocol version",
            ));
        }
        // §11.6.1: an operation missing a registry entry is not callable.
        let Some(spec) = ops::op_spec(&cmd.op) else {
            return Err(Problem::new(
                ProblemKind::UnknownOp,
                "operation absent at the negotiated version",
            ));
        };
        // Envelope shape: mutations require meta, reads reject it (§11.2).
        cmd.validate(spec.shape())?;
        spec.check_placement(&cmd.realm_id, &cmd.project_id)?;
        ops::validate_op_args(&cmd.op, &cmd.args)?;
        // The personal profile has exactly one realm; any other realm id
        // is an invisible resource (§11.7 not-found does not reveal
        // cross-tenant existence).
        if cmd.op != "hello" && cmd.realm_id.as_deref() != Some(PERSONAL_REALM_ID) {
            return Err(Problem::new(ProblemKind::NotFound, "no visible resource"));
        }
        let now = unix_now();
        let hooks = self
            .abort
            .as_ref()
            .map(|a| a.hooks_for(&cmd.op))
            .unwrap_or(CrashHooks::NONE);
        match (spec.name, spec.kind) {
            ("hello", _) => {
                let args = ops::HelloArgs::from_args(&cmd.args)?;
                handlers::hello(&self.store, &args, now)
            }
            ("realm_show", _) => {
                let realm = cmd.realm_id.as_deref().unwrap_or_default();
                handlers::realm_show(&self.store, realm)
            }
            ("project_create", OpKind::Mutation) => {
                let args = ops::ProjectCreateArgs::from_args(&cmd.args)?;
                handlers::project_create(&mut self.store, &cmd, &args, now, hooks)
            }
            ("space_create", OpKind::Mutation) => {
                let args = ops::SpaceCreateArgs::from_args(&cmd.args)?;
                handlers::space_create(&mut self.store, &cmd, &args, now, hooks)
            }
            ("space_show", _) => {
                let args = ops::SpaceShowArgs::from_args(&cmd.args)?;
                let project = cmd.project_id.as_deref().unwrap_or_default();
                handlers::space_show(&self.store, project, &args)
            }
            ("contribution_append", OpKind::Mutation) => {
                let args = ops::ContributionAppendArgs::from_args(&cmd.args)?;
                handlers::contribution_append(&mut self.store, &cmd, &args, now, hooks)
            }
            ("contribution_show", _) => {
                let args = ops::ContributionShowArgs::from_args(&cmd.args)?;
                let project = cmd.project_id.as_deref().unwrap_or_default();
                handlers::contribution_show(&self.store, project, &args)
            }
            ("events_read", _) => {
                let args = ops::EventsReadArgs::from_args(&cmd.args)?;
                handlers::events_read(&self.store, cmd.project_id.as_deref(), &args)
            }
            _ => Err(Problem::new(
                ProblemKind::UnknownOp,
                "operation absent at the negotiated version",
            )),
        }
    }
}

fn problem_bytes(problem: Problem) -> Vec<u8> {
    serde_json::to_vec(&CommandResult::problem(problem)).unwrap_or_else(|_| {
        // Serializing a problem cannot fail; keep a hand-written fallback
        // anyway so the daemon never panics on the reply path.
        br#"{"outcome":"problem","problem":{"type":"urn:kovee:error:internal","title":"internal fault","status":500}}"#
            .to_vec()
    })
}

fn read_line_limited(reader: &mut dyn Read, line: &mut String) -> std::io::Result<()> {
    let mut buffered = BufReader::new(reader);
    buffered.read_line(line)?;
    if line.ends_with('\n') {
        line.pop();
    }
    Ok(())
}
