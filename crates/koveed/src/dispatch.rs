//! Per-connection request handling: admission caps, strict I-JSON, the
//! §11.2 envelope shapes, the registry read/mutation meta rule, per-op
//! argument validation, and dispatch into the handlers — for BOTH
//! authority surfaces: the external client socket and the separate
//! worker socket (§23.3). Connections are served on threads; the store
//! sits behind a mutex so `events_wait` can long-poll without blocking
//! mutations.

use std::io::{BufRead as _, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use kovee_artifacts::{ArtifactPaths, Fault, FinalizeHooks};
use kovee_core::envelope::{CommandResult, RawCommand, Shape};
use kovee_core::limits;
use kovee_core::ops::{self, OpKind};
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::time::unix_now;
use kovee_store::{CrashHooks, Store, PERSONAL_REALM_ID};

use crate::handlers::{self, AppendAuthor};
use crate::invoke;
use crate::peercred::{authenticate_same_uid, current_uid};
use crate::reads;
use crate::space_ops;
use crate::state;
use crate::{artifact_ops, state::internal};

/// Which socket a request arrived on (§11.6.1 authority surfaces).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    External,
    Worker,
}

/// A crash-honesty instruction from the environment
/// (`KOVEED_ABORT=<phase>:<op>` with phase one of `before_commit`,
/// `after_commit`, `after_seal_txn`, `after_seal`): abort the process at
/// the named commit/pipeline point of the named operation. Test-only.
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

    fn finalize_hooks_for(&self, op: &str) -> FinalizeHooks {
        FinalizeHooks {
            after_sealing_txn: if self.phase == "after_seal_txn" && self.op == op {
                Fault::ProcessAbort
            } else {
                Fault::None
            },
            after_seal: if self.phase == "after_seal" && self.op == op {
                Fault::ProcessAbort
            } else {
                Fault::None
            },
            store: self.hooks_for(op),
        }
    }
}

/// The daemon: one store behind a mutex, two dispatch surfaces.
pub struct Daemon {
    store: Mutex<Store>,
    abort: Option<AbortSpec>,
    paths: ArtifactPaths,
}

impl Daemon {
    pub fn new(store: Store, abort: Option<AbortSpec>, data_dir: &Path) -> Daemon {
        Daemon {
            store: Mutex::new(store),
            abort,
            paths: ArtifactPaths::new(data_dir),
        }
    }

    /// Serves connections until the listener errors, one thread per
    /// connection: read one line, write one line, close.
    pub fn serve(self: &Arc<Self>, listener: UnixListener, surface: Surface) {
        let uid = current_uid();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            // §12.2 step 1: authenticate the channel. A foreign UID is
            // dropped before a byte is read, and learns nothing.
            if authenticate_same_uid(&stream, uid).is_err() {
                continue;
            }
            let daemon = Arc::clone(self);
            std::thread::spawn(move || {
                if let Err(e) = daemon.handle_connection(stream, surface) {
                    eprintln!("koveed: connection error: {e}");
                }
            });
        }
    }

    fn handle_connection(&self, stream: UnixStream, surface: Surface) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        // §11.8 request cap, enforced at admission: read at most one byte
        // past the cap so an oversized request is detected, not buffered.
        let mut bounded = (&mut reader as &mut dyn Read).take(limits::REQUEST_MAX_BYTES as u64 + 1);
        read_line_limited(&mut bounded, &mut line)?;
        let reply = self.dispatch_line(&line, surface);
        let mut stream = stream;
        stream.write_all(&reply)?;
        stream.write_all(b"\n")?;
        Ok(())
    }

    /// One request line to one reply line (no trailing newline).
    pub fn dispatch_line(&self, line: &str, surface: Surface) -> Vec<u8> {
        match self.dispatch_inner(line, surface) {
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

    fn dispatch_inner(&self, line: &str, surface: Surface) -> Result<Vec<u8>, Problem> {
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
        match surface {
            Surface::External => self.dispatch_external(&cmd),
            Surface::Worker => self.dispatch_worker(&cmd),
        }
    }

    fn lock_store(&self) -> Result<std::sync::MutexGuard<'_, Store>, Problem> {
        self.store.lock().map_err(|_| internal())
    }

    fn hooks(&self, op: &str) -> CrashHooks {
        self.abort
            .as_ref()
            .map(|a| a.hooks_for(op))
            .unwrap_or(CrashHooks::NONE)
    }

    fn finalize_hooks(&self, op: &str) -> FinalizeHooks {
        self.abort
            .as_ref()
            .map(|a| a.finalize_hooks_for(op))
            .unwrap_or(FinalizeHooks::NONE)
    }

    // ---------------------------------------------- external surface ----

    fn dispatch_external(&self, cmd: &RawCommand) -> Result<Vec<u8>, Problem> {
        // §11.6.1: an operation missing a registry entry is not callable.
        let Some(spec) = ops::op_spec(&cmd.op) else {
            return Err(unknown_op());
        };
        // Envelope shape: mutations require meta, reads reject it (§11.2).
        cmd.validate(spec.shape())?;
        spec.check_placement(&cmd.realm_id, &cmd.project_id)?;
        ops::validate_op_args(&cmd.op, &cmd.args)?;
        // The personal profile has exactly one realm; any other realm id
        // is an invisible resource (§11.7 not-found does not reveal
        // cross-tenant existence).
        if cmd.op != "hello" && cmd.realm_id.as_deref() != Some(PERSONAL_REALM_ID) {
            return Err(state::not_found());
        }
        let now = unix_now();
        let hooks = self.hooks(&cmd.op);
        let realm = cmd.realm_id.clone().unwrap_or_default();
        let project = cmd.project_id.clone().unwrap_or_default();
        match (spec.name, spec.kind) {
            ("hello", _) => {
                let args = ops::HelloArgs::from_args(&cmd.args)?;
                handlers::hello(&*self.lock_store()?, &args, now)
            }
            ("realm_show", _) => handlers::realm_show(&*self.lock_store()?, &realm),
            ("project_create", OpKind::Mutation) => {
                let args = ops::ProjectCreateArgs::from_args(&cmd.args)?;
                handlers::project_create(&mut *self.lock_store()?, cmd, &args, now, hooks)
            }
            ("space_create", OpKind::Mutation) => {
                let args = ops::SpaceCreateArgs::from_args(&cmd.args)?;
                handlers::space_create(&mut *self.lock_store()?, cmd, &args, now, hooks)
            }
            ("space_show", _) => {
                let args = ops::SpaceShowArgs::from_args(&cmd.args)?;
                handlers::space_show(&*self.lock_store()?, &project, &args)
            }
            ("space_list", _) => {
                let args = ops::SpaceListArgs::from_args(&cmd.args)?;
                reads::space_list(&*self.lock_store()?, &project, &args)
            }
            ("contribution_append", OpKind::Mutation) => {
                let args = ops::ContributionAppendArgs::from_args(&cmd.args)?;
                // Registry rule (§11.6.1, gap note KG14): worker-surface
                // binding members are schema-valid but not acceptable
                // on this surface.
                if args.attempt_id.is_some() || args.fence_epoch.is_some() {
                    return Err(forbidden_surface());
                }
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                handlers::append_contribution(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    AppendAuthor::owner(),
                    now,
                    hooks,
                )
            }
            ("contribution_show", _) => {
                let args = ops::ContributionShowArgs::from_args(&cmd.args)?;
                handlers::contribution_show(&mut *self.lock_store()?, &project, &args, now)
            }
            ("contribution_list", _) => {
                let args = ops::ContributionListArgs::from_args(&cmd.args)?;
                reads::contribution_list(&mut *self.lock_store()?, &project, &args, now)
            }
            ("relation_assert", OpKind::Mutation) => {
                let args = ops::RelationAssertArgs::from_args(&cmd.args)?;
                if args.attempt_id.is_some() || args.fence_epoch.is_some() {
                    return Err(forbidden_surface());
                }
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_ops::relation_assert(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    AppendAuthor::owner(),
                    now,
                    hooks,
                )
            }
            ("frontier_pin", OpKind::Mutation) => {
                let args = ops::FrontierPinArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_ops::frontier_pin(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("frontier_show", _) => {
                let args = ops::FrontierShowArgs::from_args(&cmd.args)?;
                reads::frontier_show(&*self.lock_store()?, &project, &args)
            }
            ("lens_read", _) => {
                let args = ops::LensReadArgs::from_args(&cmd.args)?;
                reads::lens_read(&mut *self.lock_store()?, &project, &args, now)
            }
            ("context_assembly_create", OpKind::Mutation) => {
                let args = ops::ContextAssemblyCreateArgs::from_args(&cmd.args)?;
                if args.attempt_id.is_some() || args.fence_epoch.is_some() {
                    return Err(forbidden_surface());
                }
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_ops::context_assembly_create(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    AppendAuthor::owner(),
                    now,
                    hooks,
                )
            }
            ("context_assembly_show", _) => {
                let args = ops::ContextAssemblyShowArgs::from_args(&cmd.args)?;
                reads::context_assembly_show(&*self.lock_store()?, &project, &args)
            }
            ("events_read", _) => {
                let args = ops::EventsReadArgs::from_args(&cmd.args)?;
                handlers::events_read(&*self.lock_store()?, cmd.project_id.as_deref(), &args)
            }
            ("events_wait", _) => {
                let args = ops::EventsWaitArgs::from_args(&cmd.args)?;
                // Takes the mutex itself: the lock is released between
                // polls so mutations proceed while this waiter sleeps.
                reads::events_wait(&self.store, cmd.project_id.as_deref(), &args)
            }
            ("artifact_upload_begin", OpKind::Mutation) => {
                let args = ops::ArtifactUploadBeginArgs::from_args(&cmd.args)?;
                artifact_ops::artifact_upload_begin(
                    &mut *self.lock_store()?,
                    &self.paths,
                    cmd,
                    &args,
                    now,
                    hooks,
                )
            }
            ("artifact_upload_credential", _) => {
                let args = ops::UploadIdArgs::from_args(&cmd.args)?;
                artifact_ops::artifact_upload_credential(
                    &*self.lock_store()?,
                    &self.paths,
                    &args,
                    now,
                )
            }
            ("artifact_upload_finalize", OpKind::Mutation) => {
                let args = ops::UploadIdArgs::from_args(&cmd.args)?;
                artifact_ops::artifact_upload_finalize(
                    &mut *self.lock_store()?,
                    &self.paths,
                    cmd,
                    &args,
                    now,
                    self.finalize_hooks(&cmd.op),
                )
            }
            ("artifact_upload_abort", OpKind::Mutation) => {
                let args = ops::ArtifactUploadAbortArgs::from_args(&cmd.args)?;
                artifact_ops::artifact_upload_abort(
                    &mut *self.lock_store()?,
                    &self.paths,
                    cmd,
                    &args,
                    now,
                    hooks,
                )
            }
            ("artifact_upload_show", _) => {
                let args = ops::UploadIdArgs::from_args(&cmd.args)?;
                artifact_ops::artifact_upload_show(&*self.lock_store()?, &args)
            }
            ("artifact_show", _) => {
                let args = ops::ArtifactShowArgs::from_args(&cmd.args)?;
                artifact_ops::artifact_show(&*self.lock_store()?, &args)
            }
            ("invocation_create", OpKind::Mutation) => {
                let args = ops::InvocationCreateArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                invoke::invocation_create(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("invocation_show", _) => {
                let args = ops::InvocationShowArgs::from_args(&cmd.args)?;
                invoke::invocation_show(&*self.lock_store()?, &project, &args)
            }
            _ => Err(unknown_op()),
        }
    }

    // ------------------------------------------------ worker surface ----

    /// The §23.3 worker surface: ONLY the supervisor operations
    /// (claim/complete) and the registry worker-surface content
    /// operations under an attempt binding. Everything else — realm and
    /// project administration, direct invocation, reads — is closed
    /// (`unknown-op`): a worker never enumerates the client surface.
    fn dispatch_worker(&self, cmd: &RawCommand) -> Result<Vec<u8>, Problem> {
        let now = unix_now();
        let hooks = self.hooks(&cmd.op);
        match cmd.op.as_str() {
            "hello" => {
                let args = ops::HelloArgs::from_args(&cmd.args)?;
                cmd.validate(Shape::PreAuth)?;
                handlers::hello(&*self.lock_store()?, &args, now)
            }
            "invocation_claim" => {
                cmd.validate(Shape::Mutation)?;
                require_realm(cmd)?;
                let args: invoke::InvocationClaimArgs = parse_worker_args(&cmd.args)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                let mut store = self.lock_store()?;
                if !invoke::invocation_exists(store.conn(), &args.invocation_id)? {
                    return Err(state::not_found());
                }
                let scope = invoke::worker_scope(cmd, &args.invocation_id)?;
                invoke::invocation_claim(&mut store, scope, args, meta, now, hooks)
            }
            "invocation_complete" => {
                cmd.validate(Shape::Mutation)?;
                require_realm(cmd)?;
                let args: invoke::InvocationCompleteArgs = parse_worker_args(&cmd.args)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                let mut store = self.lock_store()?;
                if !invoke::invocation_exists(store.conn(), &args.invocation_id)? {
                    return Err(state::not_found());
                }
                let scope = invoke::worker_scope(cmd, &args.invocation_id)?;
                invoke::invocation_complete(&mut store, scope, args, meta, now, hooks)
            }
            "contribution_append" => {
                let spec = ops::op_spec("contribution_append").ok_or_else(internal)?;
                cmd.validate(spec.shape())?;
                spec.check_placement(&cmd.realm_id, &cmd.project_id)?;
                require_realm(cmd)?;
                let args = ops::ContributionAppendArgs::from_args(&cmd.args)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                let mut store = self.lock_store()?;
                let (author, invocation_id) =
                    worker_author(&store, &args.attempt_id, args.fence_epoch)?;
                let scope = invoke::worker_scope(cmd, &invocation_id)?;
                handlers::append_contribution(
                    &mut store,
                    scope,
                    cmd.project_id.clone().unwrap_or_default(),
                    args,
                    meta,
                    author,
                    now,
                    hooks,
                )
            }
            "relation_assert" => {
                let spec = ops::op_spec("relation_assert").ok_or_else(internal)?;
                cmd.validate(spec.shape())?;
                spec.check_placement(&cmd.realm_id, &cmd.project_id)?;
                require_realm(cmd)?;
                let args = ops::RelationAssertArgs::from_args(&cmd.args)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                let mut store = self.lock_store()?;
                let (author, invocation_id) =
                    worker_author(&store, &args.attempt_id, args.fence_epoch)?;
                let scope = invoke::worker_scope(cmd, &invocation_id)?;
                space_ops::relation_assert(
                    &mut store,
                    scope,
                    cmd.project_id.clone().unwrap_or_default(),
                    args,
                    meta,
                    author,
                    now,
                    hooks,
                )
            }
            "context_assembly_create" => {
                let spec = ops::op_spec("context_assembly_create").ok_or_else(internal)?;
                cmd.validate(spec.shape())?;
                spec.check_placement(&cmd.realm_id, &cmd.project_id)?;
                require_realm(cmd)?;
                let args = ops::ContextAssemblyCreateArgs::from_args(&cmd.args)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                let mut store = self.lock_store()?;
                let (author, invocation_id) =
                    worker_author(&store, &args.attempt_id, args.fence_epoch)?;
                let scope = invoke::worker_scope(cmd, &invocation_id)?;
                space_ops::context_assembly_create(
                    &mut store,
                    scope,
                    cmd.project_id.clone().unwrap_or_default(),
                    args,
                    meta,
                    author,
                    now,
                    hooks,
                )
            }
            _ => Err(unknown_op()),
        }
    }
}

/// Builds the worker append author from an attempt binding: the binding
/// members must be present (their currency is re-checked inside the
/// command transaction so idempotent replays bypass nothing they
/// shouldn't). Returns the author and the invocation id for scoping.
fn worker_author(
    store: &Store,
    attempt_id: &Option<String>,
    fence_epoch: Option<u64>,
) -> Result<(AppendAuthor, String), Problem> {
    let (Some(attempt_id), Some(fence)) = (attempt_id.as_deref(), fence_epoch) else {
        return Err(Problem::new(
            ProblemKind::ForbiddenSurface,
            "worker operations require the attempt binding (§15.2)",
        ));
    };
    let invocation_id = invoke::attempt_invocation_id(store, attempt_id)?;
    let invocation = state::get_invocation(store.conn(), &invocation_id)
        .map_err(state::store_problem)?
        .ok_or_else(state::not_found)?;
    Ok((
        AppendAuthor {
            actor_ref: invoke::deployment_actor_ref(),
            invocation_ref: Some(invocation_id.clone()),
            context_assembly_ref: invocation.context_assembly_ref,
            binding: Some((attempt_id.to_owned(), fence)),
        },
        invocation_id,
    ))
}

fn require_realm(cmd: &RawCommand) -> Result<(), Problem> {
    if cmd.realm_id.as_deref() != Some(PERSONAL_REALM_ID) {
        return Err(state::not_found());
    }
    Ok(())
}

fn parse_worker_args<T: for<'de> serde::Deserialize<'de>>(
    args: &kovee_core::envelope::JsonMap,
) -> Result<T, Problem> {
    serde_json::from_value(serde_json::Value::Object(args.clone())).map_err(|e| {
        Problem::new(ProblemKind::Invalid, "invalid operation arguments").with_detail(e.to_string())
    })
}

fn unknown_op() -> Problem {
    Problem::new(
        ProblemKind::UnknownOp,
        "operation absent at the negotiated version",
    )
}

fn forbidden_surface() -> Problem {
    Problem::new(
        ProblemKind::ForbiddenSurface,
        "worker-surface binding on an external client channel",
    )
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
