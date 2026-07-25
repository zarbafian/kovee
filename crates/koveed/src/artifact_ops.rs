//! Artifact operation handlers: thin envelope wrappers over the
//! `kovee-artifacts` local content-addressed store (§10.10 state
//! machine, amendment A5 typed digest classes).

use kovee_artifacts::{ArtifactPaths, FinalizeError, FinalizeHooks};
use kovee_core::envelope::RawCommand;
use kovee_core::ops;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_store::{CommandError, CrashHooks, Store};

use crate::handlers::{command_outcome_bytes, ok_reply, scope_for};
use crate::state::*;

pub fn artifact_upload_begin(
    store: &mut Store,
    paths: &ArtifactPaths,
    cmd: &RawCommand,
    args: &ops::ArtifactUploadBeginArgs,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let realm_id = cmd.realm_id.clone().ok_or_else(internal)?;
    let scope = scope_for(cmd, &realm_id)?;
    let meta = cmd.meta.as_ref().ok_or_else(internal)?;
    let outcome = kovee_artifacts::upload_begin(
        store,
        paths,
        &scope,
        &args.declared_raw_sha256,
        args.declared_size,
        &args.declared_media_type,
        args.classification_ref.as_deref(),
        &meta.request_id,
        now,
        hooks,
    );
    command_outcome_bytes(outcome)
}

/// `artifact_upload_credential` (read, §10.10): reauthenticates the
/// current actor and returns a fresh short-lived credential for the
/// already recorded staging key. In the personal profile the "provider"
/// is the local filesystem: the credential names the exact staging file
/// the same-UID owner may write. Never stored in a canonical result.
pub fn artifact_upload_credential(
    store: &Store,
    paths: &ArtifactPaths,
    args: &ops::UploadIdArgs,
    now: i64,
) -> Result<Vec<u8>, Problem> {
    let upload = kovee_artifacts::get_upload(store.conn(), &args.upload_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    match upload.state.as_str() {
        "prepared" | "uploading" => {}
        other => {
            return Err(
                Problem::new(ProblemKind::StaleRevision, "upload no longer accepts bytes")
                    .with_detail(format!("upload state is {other}")),
            )
        }
    }
    paths
        .ensure_dirs()
        .map_err(|_| Problem::new(ProblemKind::Internal, "internal fault"))?;
    let staging = paths.staging_path(&upload.upload_id);
    let result = serde_json::json!({
        "upload_id": upload.upload_id,
        "credential": {
            "kind": "local-staging-file",
            "path": staging.to_string_lossy(),
            "write_mode": "truncate-then-write",
        },
        "max_bytes": upload.max_bytes,
        "audience": kovee_store::OWNER_ACTOR_REF,
        "expires_at": kovee_core::time::rfc3339_utc(
            now + kovee_artifacts::UPLOAD_EXPIRY_SECS,
        ),
    });
    ok_reply(result, None)
}

pub fn artifact_upload_finalize(
    store: &mut Store,
    paths: &ArtifactPaths,
    cmd: &RawCommand,
    args: &ops::UploadIdArgs,
    now: i64,
    hooks: FinalizeHooks,
) -> Result<Vec<u8>, Problem> {
    let realm_id = cmd.realm_id.clone().ok_or_else(internal)?;
    let scope = scope_for(cmd, &realm_id)?;
    let meta = cmd.meta.as_ref().ok_or_else(internal)?;
    match kovee_artifacts::upload_finalize(
        store,
        paths,
        &scope,
        &args.upload_id,
        &meta.request_id,
        now,
        hooks,
    ) {
        Ok(outcome) => Ok(outcome.bytes().to_vec()),
        Err(FinalizeError::Command(CommandError::Problem(p))) => Err(p),
        Err(FinalizeError::Command(CommandError::Store(e))) => Err(store_problem(e)),
        Err(FinalizeError::SimulatedCrash) => {
            // Only reachable with soft-crash hooks (library tests); the
            // daemon uses process aborts.
            Err(internal())
        }
    }
}

pub fn artifact_upload_abort(
    store: &mut Store,
    paths: &ArtifactPaths,
    cmd: &RawCommand,
    args: &ops::ArtifactUploadAbortArgs,
    now: i64,
    hooks: CrashHooks,
) -> Result<Vec<u8>, Problem> {
    let realm_id = cmd.realm_id.clone().ok_or_else(internal)?;
    let scope = scope_for(cmd, &realm_id)?;
    let meta = cmd.meta.as_ref().ok_or_else(internal)?;
    let outcome = kovee_artifacts::upload_abort(
        store,
        paths,
        &scope,
        &args.upload_id,
        &meta.request_id,
        now,
        hooks,
    );
    command_outcome_bytes(outcome)
}

pub fn artifact_upload_show(store: &Store, args: &ops::UploadIdArgs) -> Result<Vec<u8>, Problem> {
    let upload = kovee_artifacts::get_upload(store.conn(), &args.upload_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let revision = upload.revision;
    ok_reply(
        serde_json::to_value(&upload).map_err(|_| internal())?,
        Some(revision),
    )
}

pub fn artifact_show(store: &Store, args: &ops::ArtifactShowArgs) -> Result<Vec<u8>, Problem> {
    let artifact = kovee_artifacts::get_artifact(store.conn(), &args.artifact_id)
        .map_err(store_problem)?
        .ok_or_else(not_found)?;
    let revision = artifact.revision;
    ok_reply(
        serde_json::to_value(&artifact).map_err(|_| internal())?,
        Some(revision),
    )
}
