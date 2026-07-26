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
use kovee_byom::bpp::Endpoint;
use kovee_core::envelope::{CommandResult, RawCommand, Shape};
use kovee_core::limits;
use kovee_core::ops::{self, OpKind};
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::time::unix_now;
use kovee_effects::HttpsTransport;
use kovee_store::{CrashHooks, Store, PERSONAL_REALM_ID};

use crate::episode;
use crate::formation;
use crate::governance;
use crate::handlers::{self, AppendAuthor};
use crate::invoke;
use crate::model_broker;
use crate::peercred::{authenticate_same_uid, current_uid};
use crate::reads;
use crate::space_ops;
use crate::state;
use crate::{artifact_ops, state::internal};
use crate::{assistant_ops, disposition_ops, lifecycle_ops, space_admin_ops};

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

/// The daemon: one store behind a mutex, two dispatch surfaces, and ONE
/// egress transport. The transport lives here — not in the worker path —
/// because it is the only thing that holds a provider credential, and
/// `Daemon` never lends it out (§16.3 step 5).
pub struct Daemon {
    store: Mutex<Store>,
    abort: Option<AbortSpec>,
    paths: ArtifactPaths,
    egress: HttpsTransport,
}

impl Daemon {
    /// Opens the daemon and runs two startup sweeps:
    ///
    /// 1. the **mark-and-sweep for orphaned staging blobs** (KV-C1): a
    ///    crash between an artifact's finalize commit and its staging
    ///    tidy-up leaves a second plaintext copy on disk, and the sweep
    ///    removes it on the next start against a fresh reference check;
    /// 2. the **ambiguous-effect sweep** (§16.1): any model-effect attempt
    ///    the previous process left `dispatching` may have transmitted a
    ///    request, so it resolves to `ambiguous` with retry frozen rather
    ///    than being retried or written off as a failure.
    ///
    /// It also seeds the two shipped provider bindings from the daemon's own
    /// environment; a provider whose key is absent is recorded `disabled`.
    pub fn new(store: Store, abort: Option<AbortSpec>, data_dir: &Path) -> Daemon {
        let paths = ArtifactPaths::new(data_dir);
        match kovee_artifacts::sweep_staging(&store, &paths) {
            Ok(0) => {}
            Ok(n) => eprintln!("koveed: swept {n} orphaned staging blob(s)"),
            Err(e) => eprintln!("koveed: staging sweep: {e}"),
        }
        let mut store = store;
        match model_broker::recover_dispatching(&mut store, unix_now()) {
            Ok(0) => {}
            Ok(n) => eprintln!("koveed: {n} model effect(s) recovered as ambiguous (retry frozen)"),
            Err(e) => eprintln!("koveed: ambiguous-effect sweep: {}", e.title),
        }
        if let Err(e) =
            model_broker::seed_default_bindings(&mut store, PERSONAL_REALM_ID, unix_now())
        {
            eprintln!("koveed: model provider bindings: {}", e.title);
        }
        // 3. the realm's CAPACITY CEILING. A subordinate reservation is
        //    debited against this account, so it has to exist before any
        //    episode can be placed — and it is granted here, once, rather
        //    than conjured by the code that wants to spend it (R3-U03).
        match crate::budget::provision_realm_capacity(&mut store, PERSONAL_REALM_ID, unix_now()) {
            Ok(account) => {
                if !account.conserves() {
                    eprintln!(
                        "koveed: capacity ledger does NOT conserve on {}/{}: ceiling {} vs buckets",
                        account.account_ref, account.dimension, account.ceiling
                    );
                }
            }
            Err(e) => eprintln!("koveed: realm capacity ledger: {}", e.title),
        }
        // 4. the SETTLEMENT-SAGA sweep (R3-U02). A process that died between
        //    the two sides of a settlement left a durable local record; the
        //    sweep asks byom what it really committed under the same stable
        //    settlement key and applies exactly that. Unknown stays unknown.
        match crate::budget::unresolved_sagas(store.conn()) {
            Ok(rows) if rows.is_empty() => {}
            Ok(rows) => {
                eprintln!(
                    "koveed: {} settlement saga row(s) unresolved; reconciling against byom",
                    rows.len()
                );
                let endpoint = Endpoint::local("local");
                match episode::Runtime::configured(&endpoint) {
                    Ok(runtime) => {
                        match episode::reconcile_settlements(&mut store, &runtime, unix_now()) {
                            Ok(done) => eprintln!(
                                "koveed: settlement reconciliation: {} settled, {} denied, {} \
                                 still unknown of {}",
                                done.settled, done.denied, done.still_unknown, done.examined
                            ),
                            Err(e) => eprintln!("koveed: settlement reconciliation: {}", e.title),
                        }
                    }
                    Err(e) => eprintln!(
                        "koveed: settlement reconciliation deferred, no byom runtime: {}",
                        e.title
                    ),
                }
            }
            Err(e) => eprintln!("koveed: settlement saga sweep: {}", e.title),
        }
        Daemon {
            store: Mutex::new(store),
            abort,
            paths,
            egress: HttpsTransport::new(),
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
        // Surface acceptance precedes everything else: an operation whose
        // only registry entry is worker-surface is unknown here.
        if spec.name == "application_event_emit" {
            return Err(unknown_op());
        }
        // Envelope shape: mutations require meta, reads reject it (§11.2).
        cmd.validate(spec.shape())?;
        spec.check_placement(&cmd.realm_id, &cmd.project_id)?;
        ops::validate_op_args(&cmd.op, &cmd.args)?;
        // The personal profile has exactly one realm; any other realm id
        // is an invisible resource (§11.7 not-found does not reveal
        // cross-tenant existence). Pre-auth ops carry no realm at all.
        if spec.shape() != Shape::PreAuth && cmd.realm_id.as_deref() != Some(PERSONAL_REALM_ID) {
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
            // ------------------------------------------------ slice 3 ----
            ("protocol_info", _) => handlers::protocol_info(&*self.lock_store()?, now),
            ("diagnose", _) => {
                let args = ops::DiagnoseArgs::from_args(&cmd.args)?;
                handlers::diagnose(&*self.lock_store()?, &self.paths.staging_dir(), &args, now)
            }
            ("project_show", _) => reads::project_show(&*self.lock_store()?, &project),
            ("project_list", _) => {
                let args = ops::PageArgs::from_args(&cmd.args)?;
                reads::project_list(&*self.lock_store()?, &args)
            }
            ("project_update_metadata", OpKind::Mutation) => {
                let args = ops::ProjectUpdateMetadataArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                lifecycle_ops::project_update_metadata(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("project_access_policy_change_prepare", OpKind::Mutation) => {
                let args = ops::PapcPrepareArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                lifecycle_ops::papc_prepare(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("project_access_policy_change_confirm", OpKind::Mutation) => {
                let args = ops::PapcConfirmArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                lifecycle_ops::papc_confirm(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("project_access_policy_change_cancel", OpKind::Mutation) => {
                let args = ops::ChangeIdArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                lifecycle_ops::papc_cancel(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("project_access_policy_change_show", _) => {
                let args = ops::ChangeIdArgs::from_args(&cmd.args)?;
                lifecycle_ops::papc_show(&*self.lock_store()?, &project, &args)
            }
            ("project_access_policy_change_list", _) => {
                let args = ops::PageArgs::from_args(&cmd.args)?;
                reads::papc_list(&*self.lock_store()?, &project, &args)
            }
            ("space_update_metadata", OpKind::Mutation) => {
                let args = ops::SpaceUpdateMetadataArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                let space_id = args.space_id.clone();
                lifecycle_ops::space_lifecycle(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    space_id,
                    lifecycle_ops::SpaceLifecycle::UpdateMetadata(args),
                    meta,
                    now,
                    hooks,
                )
            }
            (
                "space_freeze" | "space_reopen" | "space_archive" | "space_restrict",
                OpKind::Mutation,
            ) => {
                let args = ops::SpaceIdArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                let lifecycle = match spec.name {
                    "space_freeze" => lifecycle_ops::SpaceLifecycle::Freeze,
                    "space_reopen" => lifecycle_ops::SpaceLifecycle::Reopen,
                    "space_archive" => lifecycle_ops::SpaceLifecycle::Archive,
                    _ => lifecycle_ops::SpaceLifecycle::Restrict,
                };
                lifecycle_ops::space_lifecycle(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args.space_id,
                    lifecycle,
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_policy_narrow", OpKind::Mutation) => {
                let args = ops::SpacePolicyNarrowArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                let space_id = args.space_id.clone();
                lifecycle_ops::space_lifecycle(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    space_id,
                    lifecycle_ops::SpaceLifecycle::PolicyNarrow(args),
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_access_widen_prepare", OpKind::Mutation) => {
                let args = ops::WidenPrepareArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                lifecycle_ops::widen_prepare(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_access_widen_confirm", OpKind::Mutation) => {
                let args = ops::WidenConfirmArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                lifecycle_ops::widen_confirm(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_access_widen_cancel", OpKind::Mutation) => {
                let args = ops::WideningIdArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                lifecycle_ops::widen_cancel(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_access_widen_show", _) => {
                let args = ops::WideningIdArgs::from_args(&cmd.args)?;
                lifecycle_ops::widen_show(&*self.lock_store()?, &project, &args)
            }
            ("space_access_widen_list", _) => {
                let args = ops::WidenListArgs::from_args(&cmd.args)?;
                reads::widen_list(&*self.lock_store()?, &project, &args)
            }
            ("space_participant_add", OpKind::Mutation) => {
                let args = ops::ParticipantAddArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_admin_ops::participant_add(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_participant_activate", OpKind::Mutation) => {
                let args = ops::ParticipantActivateArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_admin_ops::participant_activate(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_participant_update", OpKind::Mutation) => {
                let args = ops::ParticipantUpdateArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_admin_ops::participant_update(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_participant_remove", OpKind::Mutation) => {
                let args = ops::ParticipantIdArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_admin_ops::participant_remove(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_participant_list", _) => {
                let args = ops::SpacePageArgs::from_args(&cmd.args)?;
                reads::participant_list(&*self.lock_store()?, &project, &args)
            }
            ("space_access_grant_create", OpKind::Mutation) => {
                let args = ops::GrantCreateArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_admin_ops::grant_create(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_access_grant_revoke", OpKind::Mutation) => {
                let args = ops::GrantRevokeArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_admin_ops::grant_revoke(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("space_access_grant_list", _) => {
                let args = ops::SpacePageArgs::from_args(&cmd.args)?;
                reads::grant_list(&*self.lock_store()?, &project, &args)
            }
            ("contribution_withdraw", OpKind::Mutation) => {
                let args = ops::ContributionDispositionArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                disposition_ops::contribution_withdraw(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("contribution_supersede", OpKind::Mutation) => {
                let args = ops::ContributionSupersedeArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                disposition_ops::contribution_supersede(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("contribution_redact", OpKind::Mutation) => {
                let args = ops::ContributionDispositionArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                disposition_ops::contribution_redact(
                    &mut *self.lock_store()?,
                    &self.paths,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("relation_retract", OpKind::Mutation) => {
                let args = ops::RelationRetractArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                disposition_ops::relation_retract(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("lens_create", OpKind::Mutation) => {
                let args = ops::LensCreateArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_admin_ops::lens_create(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("lens_update", OpKind::Mutation) => {
                let args = ops::LensUpdateArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_admin_ops::lens_update(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("lens_revoke", OpKind::Mutation) => {
                let args = ops::LensIdArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_admin_ops::lens_revoke(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("lens_show", _) => {
                let args = ops::LensIdArgs::from_args(&cmd.args)?;
                space_admin_ops::lens_show(&*self.lock_store()?, &project, &args)
            }
            ("lens_list", _) => {
                let args = ops::SpacePageArgs::from_args(&cmd.args)?;
                reads::lens_list(&*self.lock_store()?, &project, &args)
            }
            ("reaction_set", OpKind::Mutation) => {
                let args = ops::ReactionSetArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                space_admin_ops::reaction_set(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("event_payload", _) => {
                let args = ops::EventPayloadArgs::from_args(&cmd.args)?;
                reads::event_payload(
                    &mut *self.lock_store()?,
                    cmd.project_id.as_deref(),
                    &args,
                    now,
                )
            }
            ("snapshot_read", _) => {
                let args = ops::SnapshotReadArgs::from_args(&cmd.args)?;
                reads::snapshot_read(&*self.lock_store()?, cmd.project_id.as_deref(), &args)
            }
            ("disclosure_manifest_show", _) => {
                let args = ops::DisclosureManifestShowArgs::from_args(&cmd.args)?;
                reads::disclosure_manifest_show(&*self.lock_store()?, &args)
            }
            ("assistant_create", OpKind::Mutation) => {
                let args = ops::AssistantCreateArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                assistant_ops::assistant_create(
                    &mut *self.lock_store()?,
                    scope,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("assistant_show", _) => {
                let args = ops::AssistantShowArgs::from_args(&cmd.args)?;
                assistant_ops::assistant_show(&*self.lock_store()?, &args)
            }
            ("assistant_list", _) => {
                let args = ops::PageArgs::from_args(&cmd.args)?;
                reads::assistant_list(&*self.lock_store()?, &args)
            }
            ("assistant_revision_register", OpKind::Mutation) => {
                let args = ops::AssistantRevisionRegisterArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                assistant_ops::assistant_revision_register(
                    &mut *self.lock_store()?,
                    scope,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("assistant_revision_show", _) => {
                let args = ops::AssistantRevisionShowArgs::from_args(&cmd.args)?;
                assistant_ops::assistant_revision_show(&*self.lock_store()?, &args)
            }
            ("assistant_revision_list", _) => {
                let args = ops::AssistantRevisionListArgs::from_args(&cmd.args)?;
                reads::assistant_revision_list(&*self.lock_store()?, &args)
            }
            ("deployment_create", OpKind::Mutation) => {
                let args = ops::DeploymentCreateArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                assistant_ops::deployment_create(
                    &mut *self.lock_store()?,
                    scope,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("deployment_show", _) => {
                let args = ops::DeploymentIdArgs::from_args(&cmd.args)?;
                assistant_ops::deployment_show(&*self.lock_store()?, &args)
            }
            ("deployment_list", _) => {
                let args = ops::DeploymentListArgs::from_args(&cmd.args)?;
                reads::deployment_list(&*self.lock_store()?, &args)
            }
            ("deployment_activate" | "deployment_drain", OpKind::Mutation) => {
                let args = ops::DeploymentIdArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                assistant_ops::deployment_transition(
                    &mut *self.lock_store()?,
                    scope,
                    args,
                    spec.name == "deployment_activate",
                    meta,
                    now,
                    hooks,
                )
            }
            ("assistant_alias_bind", OpKind::Mutation) => {
                let args = ops::AliasBindArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                assistant_ops::alias_bind(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("assistant_alias_update", OpKind::Mutation) => {
                let args = ops::AliasUpdateArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                assistant_ops::alias_update(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("assistant_alias_revoke", OpKind::Mutation) => {
                let args = ops::AliasIdArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                assistant_ops::alias_revoke(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            ("assistant_alias_show", _) => {
                let args = ops::AliasIdArgs::from_args(&cmd.args)?;
                assistant_ops::alias_show(&*self.lock_store()?, &project, &args)
            }
            ("assistant_alias_list", _) => {
                let args = ops::AliasListArgs::from_args(&cmd.args)?;
                reads::alias_list(&*self.lock_store()?, &project, &args)
            }
            ("invocation_list", _) => {
                let args = ops::InvocationListArgs::from_args(&cmd.args)?;
                reads::invocation_list(&*self.lock_store()?, &project, &args)
            }
            ("invocation_cancel", OpKind::Mutation) => {
                let args = ops::InvocationCancelArgs::from_args(&cmd.args)?;
                // Registry rule (§11.6.1): the worker attempt binding is
                // not acceptable on the external client surface.
                if args.attempt_id.is_some() || args.fence_epoch.is_some() {
                    return Err(forbidden_surface());
                }
                let scope = handlers::scope_for(cmd, &realm)?;
                let meta = cmd.meta.clone().ok_or_else(internal)?;
                assistant_ops::invocation_cancel(
                    &mut *self.lock_store()?,
                    scope,
                    project,
                    args,
                    meta,
                    now,
                    hooks,
                )
            }
            // ---------------------- K2 slice 1: governed-work binding ----
            // The frozen `governance_enable` row's surface is "KCP admin";
            // in the personal profile that is the owner principal over
            // this UID-checked local socket (registry-README resolutions
            // 5/6, as for every other operator-surface entry).
            ("governance_enable", OpKind::Mutation) => {
                let args = ops::GovernanceEnableArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let resolver = |endpoint_ref: &str| Endpoint::local(endpoint_ref);
                governance::governance_enable(
                    &mut *self.lock_store()?,
                    &resolver,
                    scope,
                    realm,
                    args,
                    now,
                    |op| self.hooks(op),
                )
            }
            ("governance_show", _) => {
                let args = ops::GovernanceShowArgs::from_args(&cmd.args)?;
                governance::governance_show(&*self.lock_store()?, &realm, &args)
            }
            ("governance_disable", OpKind::Mutation) => {
                let args = ops::GovernanceDisableArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                governance::governance_disable(
                    &mut *self.lock_store()?,
                    scope,
                    realm,
                    args,
                    now,
                    hooks,
                )
            }
            // -------------------- K2 slice 2: the formation saga client ----
            // Same operator-surface resolution as the binding half: in the
            // personal profile the owner principal over this UID-checked
            // local socket (registry-README resolutions 5/6).
            ("endeavor_promotion_prepare", OpKind::Mutation) => {
                let args = ops::PromotionPrepareArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                formation::endeavor_promotion_prepare(
                    &mut *self.lock_store()?,
                    scope,
                    realm,
                    args,
                    now,
                    hooks,
                )
            }
            ("endeavor_promotion_start", OpKind::Mutation) => {
                let args = ops::PromotionStartArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let resolver = |endpoint_ref: &str| Endpoint::local(endpoint_ref);
                formation::endeavor_promotion_start(
                    &mut *self.lock_store()?,
                    &resolver,
                    scope,
                    realm,
                    args,
                    now,
                    |op| self.hooks(op),
                )
            }
            ("endeavor_promotion_show", _) => {
                let args = ops::PromotionShowArgs::from_args(&cmd.args)?;
                formation::endeavor_promotion_show(&*self.lock_store()?, &realm, &args)
            }
            ("endeavor_promotion_cancel", OpKind::Mutation) => {
                let args = ops::PromotionCancelArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                formation::endeavor_promotion_cancel(
                    &mut *self.lock_store()?,
                    scope,
                    realm,
                    args,
                    now,
                    hooks,
                )
            }
            ("endeavor_promotion_reconcile", OpKind::Mutation) => {
                let args = ops::PromotionReconcileArgs::from_args(&cmd.args)?;
                let scope = handlers::scope_for(cmd, &realm)?;
                let resolver = |endpoint_ref: &str| Endpoint::local(endpoint_ref);
                formation::endeavor_promotion_reconcile(
                    &mut *self.lock_store()?,
                    &resolver,
                    scope,
                    realm,
                    args,
                    now,
                    |op| self.hooks(op),
                )
            }
            ("byom_episode_binding_show", _) => {
                let args = ops::EpisodeBindingShowArgs::from_args(&cmd.args)?;
                episode::byom_episode_binding_show(&*self.lock_store()?, &realm, &args)
            }
            // `application_event_emit` has ONLY a worker-surface registry
            // entry — the external fallback answers unknown-op (§11.6.1).
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
            "invocation_cancel" => {
                let spec = ops::op_spec("invocation_cancel").ok_or_else(internal)?;
                cmd.validate(spec.shape())?;
                spec.check_placement(&cmd.realm_id, &cmd.project_id)?;
                require_realm(cmd)?;
                let args = ops::InvocationCancelArgs::from_args(&cmd.args)?;
                assistant_ops::worker_invocation_cancel(
                    &mut *self.lock_store()?,
                    cmd,
                    args,
                    now,
                    hooks,
                )
            }
            "application_event_emit" => {
                let spec = ops::op_spec("application_event_emit").ok_or_else(internal)?;
                cmd.validate(spec.shape())?;
                spec.check_placement(&cmd.realm_id, &cmd.project_id)?;
                require_realm(cmd)?;
                let args = ops::ApplicationEventEmitArgs::from_args(&cmd.args)?;
                assistant_ops::application_event_emit(
                    &mut *self.lock_store()?,
                    cmd,
                    args,
                    now,
                    hooks,
                )
            }
            // §16.3: agent code calls a logical model profile; the broker
            // does everything else. The worker's request never names a
            // provider, a host, a header, or a credential, and the reply
            // (§16.3 step 7) is bounded output through the supervisor.
            "model_complete" => {
                let spec = ops::op_spec("model_complete").ok_or_else(internal)?;
                cmd.validate(spec.shape())?;
                spec.check_placement(&cmd.realm_id, &cmd.project_id)?;
                require_realm(cmd)?;
                let args = ops::ModelCompleteArgs::from_args(&cmd.args)?;
                self.model_complete(cmd, args, now)
            }
            _ => Err(unknown_op()),
        }
    }

    /// The worker-surface model call. The byom RUNTIME endpoint and the
    /// daemon's own egress transport are supplied HERE: a worker cannot
    /// reach either.
    fn model_complete(
        &self,
        cmd: &RawCommand,
        args: ops::ModelCompleteArgs,
        now: i64,
    ) -> Result<Vec<u8>, Problem> {
        // The byom RUNTIME socket directory comes from
        // `$KOVEE_BYOM_RUNTIME_DIR` and the workload-token directory from
        // `$KOVEE_BYOM_CHANNELS_DIR` — both the daemon's own configuration,
        // neither reachable from a worker request.
        let endpoint = Endpoint::local("local");
        let runtime = episode::Runtime::configured(&endpoint)?;
        let authorization = model_broker::ActAuthorization {
            act_intent_ref: args.act_intent_ref.clone(),
            act_intent_digest: args.act_intent_digest.clone(),
            act_revision: args.act_revision,
            subject_digest: args.subject_digest.clone(),
            stable_execution_key: args.stable_execution_key.clone(),
            budget_reservation_set_ref: args.budget_reservation_set_ref.clone(),
        };
        let request = model_broker::CompleteRequest {
            realm: PERSONAL_REALM_ID,
            project: cmd.project_id.as_deref(),
            attempt_id: &args.attempt_id,
            fence_epoch: args.fence_epoch,
            model_profile_ref: &args.model_profile_ref,
            purpose_ref: &args.purpose_ref,
            classification_ref: &args.classification_ref,
            system: args.system.as_deref(),
            prompt: &args.prompt,
            max_output_tokens: args.max_output_tokens,
            stable_binding_key: args.stable_binding_key.as_deref(),
        };
        let mut store = self.lock_store()?;
        let completion = model_broker::complete(
            &mut store,
            &runtime,
            &self.egress,
            &request,
            &authorization,
            now,
            model_broker::Fault::None,
        )?;
        handlers::ok_reply(completion.worker_view(), None)
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
