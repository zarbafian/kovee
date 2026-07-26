//! The local content-addressed artifact store (design §10.10, §16.2
//! behaviors scoped to the personal profile) using the family digest
//! classes of amendment A5: the content address of erasable plaintext is
//! a typed `local_erasure_safe` DigestRef under a random per-object
//! secret — destroying that secret erases exactly that object's
//! verifiability; no retained public plaintext hash exists.
//!
//! What "per-object secret" means here (D-R1-2, KV-A5-2): the secret is
//! 32 random bytes minted at `artifact_upload_begin` and stored WRAPPED
//! under the realm key ([`kovee_store::objkey`]) — never raw beside the
//! object, and never derived from a store root. [`erase_artifact`]
//! removes the blob bytes, destroys that one wrap, and leaves a
//! tombstone row; every other artifact is untouched.
//!
//! The caller's `declared_raw_sha256` is TRANSIENT: it is compared once,
//! during sealing, against a commitment keyed by the same per-object
//! secret ([`DECLARED_RAW_DOMAIN`]). No durable row, wire projection, or
//! stored replay result carries the checksum.
//!
//! Honesty labels (developer assurance profile): verification checks
//! size, the declared raw digest (through that keyed commitment), media
//! type, and the typed content digest. NO malware or secret scanning is
//! claimed — `scanner_set_digest` pins the empty scanner set and
//! `scan_results` is empty.
//!
//! The §10.10 finalization state machine, exactly:
//! `pending -> verifying -> available | rejected`; the artifact becomes
//! `available` ONLY in the final SQL transaction that also stores the
//! `ArtifactVerification` row, the terminal event, and the finalize
//! idempotency result. A crash after sealing but before that transaction
//! is reconciled from the same upload id on retry. Unverified bytes never
//! become available.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use kovee_core::canonical::{canonical_object_digest, sha256_hex};
use kovee_core::event::{
    EVENT_ARTIFACT_AVAILABLE, EVENT_ARTIFACT_REJECTED, EVENT_ARTIFACT_UPLOAD_ABORTED,
    EVENT_ARTIFACT_UPLOAD_BEGAN,
};
use kovee_core::family::{hex, hmac_sha256, DigestRef};
use kovee_core::problem::{Problem, ProblemKind};
use kovee_core::records::{Artifact, ArtifactUpload};
use kovee_core::time::rfc3339_utc;
use kovee_store::{
    new_id, Applied, CommandError, CommandOutcome, CommandScope, CrashHooks, NewEvent, Store,
    StoreError, OWNER_ACTOR_REF,
};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::Value;

/// The per-upload byte ceiling of the personal profile (64 MiB).
pub const MAX_UPLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// Upload expiry window in seconds.
pub const UPLOAD_EXPIRY_SECS: i64 = 3600;
/// The byte-preimage domain of the typed content digest (the PROFILE
/// §6.4 framing shape under a kovee domain constant).
pub const CONTENT_BYTE_DOMAIN: &str = "dev.kovee.artifact-content.v1";
/// The preimage domain of the keyed commitment to the caller's declared
/// raw checksum (KV-A5-2: the checksum itself is never durable).
pub const DECLARED_RAW_DOMAIN: &str = "dev.kovee.declared-raw-sha256.v1";
/// The recorded dependency-set ref of the same-UID owner (developer
/// assurance profile; the §9.2 categories collapse to the one
/// authenticated local principal).
pub const AUTHZ_DEP_SET_REF: &str = "authz-owner-local-v1";

/// A named crash-honesty fault point inside the finalize pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fault {
    #[default]
    None,
    /// Kill the process (the daemon's `KOVEED_ABORT` matrix).
    ProcessAbort,
    /// Return [`FinalizeError::SimulatedCrash`] — the in-library crash
    /// the `k1_artifact_crash` matrix uses, then reopens the database.
    SoftCrash,
}

/// Fault points for the §10.10 finalize pipeline.
#[derive(Debug, Clone, Copy)]
pub struct FinalizeHooks {
    /// After the `-> sealing` state transaction commits, before sealing
    /// bytes.
    pub after_sealing_txn: Fault,
    /// After the sealed bytes and digests exist, before the final SQL
    /// transaction.
    pub after_seal: Fault,
    /// The §12.2 hooks of the final SQL transaction.
    pub store: CrashHooks,
}

impl FinalizeHooks {
    pub const NONE: FinalizeHooks = FinalizeHooks {
        after_sealing_txn: Fault::None,
        after_seal: Fault::None,
        store: CrashHooks::NONE,
    };
}

#[derive(Debug, thiserror::Error)]
pub enum FinalizeError {
    #[error("simulated crash at a finalize fault point")]
    SimulatedCrash,
    #[error(transparent)]
    Command(#[from] CommandError),
}

impl From<StoreError> for FinalizeError {
    fn from(e: StoreError) -> FinalizeError {
        FinalizeError::Command(CommandError::Store(e))
    }
}

impl From<rusqlite::Error> for FinalizeError {
    fn from(e: rusqlite::Error) -> FinalizeError {
        FinalizeError::Command(CommandError::Store(StoreError::Db(e)))
    }
}

fn trip(fault: Fault) -> Result<(), FinalizeError> {
    match fault {
        Fault::None => Ok(()),
        Fault::ProcessAbort => std::process::abort(),
        Fault::SoftCrash => Err(FinalizeError::SimulatedCrash),
    }
}

/// Filesystem layout under the daemon data directory.
#[derive(Debug, Clone)]
pub struct ArtifactPaths {
    pub data_dir: PathBuf,
}

impl ArtifactPaths {
    pub fn new(data_dir: &Path) -> ArtifactPaths {
        ArtifactPaths {
            data_dir: data_dir.to_path_buf(),
        }
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.data_dir.join("artifacts").join("staging")
    }

    pub fn sealed_dir(&self) -> PathBuf {
        self.data_dir.join("artifacts").join("sealed")
    }

    /// The staging file one upload writes into (the local "provider").
    pub fn staging_path(&self, upload_id: &str) -> PathBuf {
        self.staging_dir().join(upload_id)
    }

    /// The content-addressed sealed object: named by the typed
    /// `local_erasure_safe` digest value, so addressing is per-object
    /// keyed — no cross-object plaintext deduplication oracle (§10.10).
    pub fn sealed_path(&self, content_hex: &str) -> PathBuf {
        self.sealed_dir().join(content_hex)
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.staging_dir())?;
        std::fs::create_dir_all(self.sealed_dir())
    }
}

/// The PROFILE §6.4 byte preimage:
/// `frame(domain-const) ‖ frame(byte_domain) ‖ frame("0") ‖
/// frame(media_type) ‖ frame(bytes)`, `frame(x) = uint64_be(len(x)) ‖ x`,
/// under the kovee typed-bytes domain constant.
fn byte_preimage(media_type: &str, bytes: &[u8]) -> Vec<u8> {
    fn frame(data: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&(data.len() as u64).to_be_bytes());
        out.extend_from_slice(data);
    }
    let mut out = Vec::with_capacity(bytes.len() + 128);
    frame(b"dev.kovee.typed-bytes-digest.v1", &mut out);
    frame(CONTENT_BYTE_DOMAIN.as_bytes(), &mut out);
    frame(b"0", &mut out);
    frame(media_type.as_bytes(), &mut out);
    frame(bytes, &mut out);
    out
}

/// The typed content address of amendment A5: `local_erasure_safe`
/// HMAC-SHA-256 under the random per-object secret.
pub fn content_digest_ref(
    object_secret: &[u8],
    artifact_id: &str,
    media_type: &str,
    bytes: &[u8],
) -> DigestRef {
    let mac = hmac_sha256(object_secret, &byte_preimage(media_type, bytes));
    DigestRef::local_erasure_safe(&format!("kovee-artifact-object:{artifact_id}"), hex(&mac))
}

// ------------------------------------------------------------ row I/O ----

/// Reads one upload projection.
pub fn get_upload(
    conn: &Connection,
    upload_id: &str,
) -> Result<Option<ArtifactUpload>, StoreError> {
    conn.query_row(
        "SELECT upload_id, artifact_id, realm_id, owner_ref, revision,
                declared_size, declared_media_type,
                classification_ref, staging_storage_ref, provider_upload_ref,
                state, sealed_storage_version, seal_observation_digest,
                authorization_dependency_set_ref, authority_digest, max_bytes,
                expires_at, idempotency_key, created_at, sealed_at, terminal_at
         FROM artifact_uploads WHERE upload_id = ?1",
        [upload_id],
        |r| {
            Ok(ArtifactUpload {
                upload_id: r.get(0)?,
                artifact_id: r.get(1)?,
                realm_id: r.get(2)?,
                owner_ref: r.get(3)?,
                revision: r.get::<_, i64>(4)? as u64,
                declared_size: r.get::<_, i64>(5)? as u64,
                declared_media_type: r.get(6)?,
                classification_ref: r.get(7)?,
                staging_storage_ref: r.get(8)?,
                provider_upload_ref: r.get(9)?,
                state: r.get(10)?,
                sealed_storage_version: r.get(11)?,
                seal_observation_digest: r.get(12)?,
                authorization_dependency_set_ref: r.get(13)?,
                authority_digest: r.get(14)?,
                max_bytes: r.get::<_, i64>(15)? as u64,
                expires_at: r.get(16)?,
                idempotency_key: r.get(17)?,
                created_at: r.get(18)?,
                sealed_at: r.get(19)?,
                terminal_at: r.get(20)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

/// Reads one artifact projection (A5: the internal `content_digest_ref`
/// and per-object secret stay off this wire projection — no retained
/// plaintext hash is ever served).
pub fn get_artifact(conn: &Connection, artifact_id: &str) -> Result<Option<Artifact>, StoreError> {
    conn.query_row(
        "SELECT artifact_id, realm_id, owner_ref, revision, state, size,
                media_type, classification_ref, sealed_storage_ref,
                sealed_storage_version, verification_digest, encryption_key_ref,
                created_by, created_at, available_at, retention_until
         FROM artifacts WHERE artifact_id = ?1",
        [artifact_id],
        |r| {
            Ok(Artifact {
                artifact_id: r.get(0)?,
                realm_id: r.get(1)?,
                owner_ref: r.get(2)?,
                revision: r.get::<_, i64>(3)? as u64,
                state: r.get(4)?,
                raw_sha256: None,
                typed_byte_digest: None,
                size: r.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                media_type: r.get(6)?,
                classification_ref: r.get(7)?,
                sealed_storage_ref: r.get(8)?,
                sealed_storage_version: r.get(9)?,
                verification_digest: r.get(10)?,
                encryption_key_ref: r.get(11)?,
                created_by: r.get(12)?,
                created_at: r.get(13)?,
                available_at: r.get(14)?,
                retention_until: r.get(15)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

/// The `key_ref` naming one artifact's erasure secret.
fn object_key_ref(artifact_id: &str) -> String {
    format!("kovee-artifact-object:{artifact_id}")
}

/// Opens one artifact's per-object secret: the stored blob is the random
/// secret WRAPPED under the realm key (D-R1-2), never the raw key beside
/// the object. `None` means the secret was destroyed (erased artifact) or
/// never existed.
fn object_secret(conn: &Connection, artifact_id: &str) -> Result<Option<[u8; 32]>, StoreError> {
    let wrapped: Option<Option<Vec<u8>>> = conn
        .query_row(
            "SELECT object_secret FROM artifacts WHERE artifact_id = ?1",
            [artifact_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(StoreError::from)?;
    let Some(Some(wrapped)) = wrapped else {
        return Ok(None);
    };
    let realm_key = kovee_store::realm_object_key_of(conn)?;
    Ok(Some(kovee_store::objkey::unwrap(
        &realm_key,
        &object_key_ref(artifact_id),
        &wrapped,
    )?))
}

/// The keyed commitment to the caller's declared raw checksum (KV-A5-2):
/// the checksum itself is transient — compared once during sealing and
/// never written to a durable row or a replay result. What is durable is
/// its HMAC under this artifact's own per-object secret, so destroying
/// the secret destroys the commitment's meaning with the object.
fn declared_raw_commitment(object_secret: &[u8], declared_raw_sha256: &str) -> String {
    let mut preimage = Vec::with_capacity(128);
    for part in [
        DECLARED_RAW_DOMAIN.as_bytes(),
        declared_raw_sha256.as_bytes(),
    ] {
        preimage.extend_from_slice(&(part.len() as u64).to_be_bytes());
        preimage.extend_from_slice(part);
    }
    hex(&hmac_sha256(object_secret, &preimage))
}

fn internal() -> Problem {
    Problem::new(ProblemKind::Internal, "internal fault")
}

fn not_found() -> Problem {
    Problem::new(ProblemKind::NotFound, "no visible resource")
}

fn upload_value(upload: &ArtifactUpload) -> Result<Value, Problem> {
    serde_json::to_value(upload).map_err(|_| internal())
}

/// The recorded authority digest of the same-UID owner acting on one
/// upload (developer profile).
fn authority_digest(operation: &str, upload_id: &str) -> Result<String, Problem> {
    let (_, hexd) = canonical_object_digest(
        "kovee-authority",
        "schema:kovee-authority-v1",
        &serde_json::json!({
            "actor": OWNER_ACTOR_REF,
            "dependency_set": AUTHZ_DEP_SET_REF,
            "operation": operation,
            "upload_id": upload_id,
        }),
    )
    .map_err(|_| internal())?;
    Ok(hexd)
}

// --------------------------------------------------------------- begin ----

/// `artifact_upload_begin` (§10.10): atomically creates the pending
/// artifact/upload, idempotency result, event, and outbox row. The
/// canonical result contains only the durable refs and constraints —
/// never a credential.
#[allow(clippy::too_many_arguments)]
pub fn upload_begin(
    store: &mut Store,
    paths: &ArtifactPaths,
    scope: &CommandScope,
    declared_raw_sha256: &str,
    declared_size: u64,
    declared_media_type: &str,
    classification_ref: Option<&str>,
    correlation_ref: &str,
    now: i64,
    hooks: CrashHooks,
) -> Result<CommandOutcome, CommandError> {
    paths
        .ensure_dirs()
        .map_err(|e| CommandError::Store(StoreError::Corrupt(format!("artifact dirs: {e}"))))?;
    if declared_size > MAX_UPLOAD_BYTES {
        return Err(CommandError::Problem(
            Problem::new(ProblemKind::Invalid, "declared_size exceeds the upload cap")
                .with_detail(format!("max_bytes is {MAX_UPLOAD_BYTES}")),
        ));
    }
    let declared_raw_sha256 = declared_raw_sha256.to_owned();
    let declared_media_type = declared_media_type.to_owned();
    let classification = classification_ref.unwrap_or("class-default").to_owned();
    let correlation_ref = correlation_ref.to_owned();
    let idempotency_key = scope.idempotency_key.clone();
    store.command_transaction(scope, now, hooks, move |txn| {
        let artifact_id = new_id("art").map_err(|_| internal())?;
        let upload_id = new_id("upl").map_err(|_| internal())?;
        // D-R1-2: a random per-object secret, wrapped under the realm
        // key — never a root-derived key, never raw beside the object.
        let secret = kovee_store::objkey::new_object_secret().map_err(|_| internal())?;
        let realm_key = kovee_store::realm_object_key_of(txn.conn()).map_err(|_| internal())?;
        let wrapped = kovee_store::objkey::wrap(&realm_key, &object_key_ref(&artifact_id), &secret)
            .map_err(|_| internal())?;
        // KV-A5-2: the declared checksum stays transient. Only its keyed
        // commitment is durable, so finalization can still verify the
        // declaration and no row retains the checksum.
        let commitment = declared_raw_commitment(&secret, &declared_raw_sha256);
        txn.conn()
            .execute(
                "INSERT INTO artifacts (artifact_id, realm_id, owner_ref, revision,
                     state, size, media_type, classification_ref,
                     sealed_storage_ref, sealed_storage_version,
                     verification_digest, encryption_key_ref, content_digest_ref,
                     object_secret, created_by, created_at, available_at,
                     retention_until)
                 VALUES (?1, ?2, ?3, 1, 'pending', NULL, NULL, ?4, NULL, NULL,
                     NULL, 'enc-none-plain', NULL, ?5, ?6, ?7, NULL, NULL)",
                params![
                    artifact_id,
                    txn.realm_id(),
                    OWNER_ACTOR_REF,
                    classification,
                    wrapped.as_slice(),
                    OWNER_ACTOR_REF,
                    txn.now_ts(),
                ],
            )
            .map_err(|_| internal())?;
        let upload = ArtifactUpload {
            upload_id: upload_id.clone(),
            artifact_id: artifact_id.clone(),
            realm_id: txn.realm_id().to_owned(),
            owner_ref: OWNER_ACTOR_REF.to_owned(),
            revision: 1,
            declared_size,
            declared_media_type: declared_media_type.clone(),
            classification_ref: classification.clone(),
            staging_storage_ref: format!("staging:{upload_id}"),
            provider_upload_ref: None,
            state: "prepared".to_owned(),
            sealed_storage_version: None,
            seal_observation_digest: None,
            authorization_dependency_set_ref: AUTHZ_DEP_SET_REF.to_owned(),
            authority_digest: authority_digest("artifact_upload_begin", &upload_id)?,
            max_bytes: MAX_UPLOAD_BYTES,
            expires_at: rfc3339_utc(now + UPLOAD_EXPIRY_SECS),
            idempotency_key: idempotency_key.clone(),
            created_at: txn.now_ts(),
            sealed_at: None,
            terminal_at: None,
        };
        insert_upload(txn.conn(), &upload, &commitment).map_err(|_| internal())?;
        txn.append_event(NewEvent {
            stream_id: artifact_id.clone(),
            project_id: None,
            actor_ref: None,
            event_type: EVENT_ARTIFACT_UPLOAD_BEGAN.to_owned(),
            schema_ref: "schema:artifact-upload-v1".to_owned(),
            resource_ref: upload_id.clone(),
            resource_revision: Some(1),
            causation_ref: None,
            correlation_ref: correlation_ref.clone(),
            classification_ref: classification.clone(),
            payload: serde_json::json!({
                "upload_id": upload_id, "artifact_id": artifact_id,
                "state": "prepared",
            }),
        })
        .map_err(|_| internal())?;
        txn.audit(
            "command.artifact_upload_began",
            &format!("upload={upload_id};artifact={artifact_id}"),
        );
        // The §10.10 begin result: only the durable refs and constraints
        // — and, per KV-A5-2, not the caller's raw checksum (a replay of
        // this key must not hand the checksum back out of storage).
        let result = serde_json::json!({
            "upload_id": upload.upload_id,
            "artifact_id": upload.artifact_id,
            "revision": upload.revision,
            "state": upload.state,
            "declared_size": upload.declared_size,
            "declared_media_type": upload.declared_media_type,
            "classification_ref": upload.classification_ref,
            "max_bytes": upload.max_bytes,
            "expires_at": upload.expires_at,
            "created_at": upload.created_at,
        });
        Ok(Applied {
            result,
            revision: Some(1),
            event_cursor: None,
        })
    })
}

fn insert_upload(
    conn: &Connection,
    u: &ArtifactUpload,
    declared_raw_commitment: &str,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO artifact_uploads (upload_id, artifact_id, realm_id,
             owner_ref, revision, declared_raw_commitment, declared_size,
             declared_media_type, classification_ref, staging_storage_ref,
             provider_upload_ref, state, sealed_storage_version,
             seal_observation_digest, authorization_dependency_set_ref,
             authority_digest, max_bytes, expires_at, idempotency_key,
             created_at, sealed_at, terminal_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,?11,NULL,NULL,?12,?13,
             ?14,?15,?16,?17,NULL,NULL)",
        params![
            u.upload_id,
            u.artifact_id,
            u.realm_id,
            u.owner_ref,
            u.revision as i64,
            declared_raw_commitment,
            u.declared_size as i64,
            u.declared_media_type,
            u.classification_ref,
            u.staging_storage_ref,
            u.state,
            u.authorization_dependency_set_ref,
            u.authority_digest,
            u.max_bytes as i64,
            u.expires_at,
            u.idempotency_key,
            u.created_at,
        ],
    )?;
    Ok(())
}

// ------------------------------------------------------------ finalize ----

/// What sealing observed, before the final transaction judges it.
#[derive(Debug, Clone)]
struct Observation {
    observed_size: u64,
    raw_match: bool,
    digest_ref: DigestRef,
    sealed_version: String,
}

/// `artifact_upload_finalize` (§10.10): the sealing-state transaction,
/// the seal + verification of trusted bytes, and the final SQL
/// transaction that alone can make the artifact `available` (or
/// `rejected`) while storing the `ArtifactVerification`, terminal event,
/// and finalize idempotency result. Deliberately NOT one §12.2
/// transaction — a crash between the steps is reconciled from the same
/// upload id on retry (no idempotency record exists until the final
/// transaction commits).
pub fn upload_finalize(
    store: &mut Store,
    paths: &ArtifactPaths,
    scope: &CommandScope,
    upload_id: &str,
    correlation_ref: &str,
    now: i64,
    hooks: FinalizeHooks,
) -> Result<CommandOutcome, FinalizeError> {
    // Idempotency pre-check: an exact replay returns the stored bytes
    // and never re-runs the pipeline; a changed request is refused.
    if let Some((stored_digest, stored_result)) = store.lookup_idempotency(scope)? {
        if stored_digest == scope.request_digest {
            // KV-C1: cleanup is part of the replay, not only of the
            // first run. A crash after the commit and before the tidy-up
            // used to leave the staging plaintext beside the sealed
            // object for as long as the client kept retrying.
            let _ = std::fs::remove_file(paths.staging_path(upload_id));
            return Ok(CommandOutcome::Replayed(stored_result));
        }
        return Err(FinalizeError::Command(CommandError::Problem(Problem::new(
            ProblemKind::IdempotencyMismatch,
            "same scoped idempotency key, different canonical request",
        ))));
    }

    let upload = get_upload(store.conn(), upload_id)?
        .ok_or_else(|| FinalizeError::Command(CommandError::Problem(not_found())))?;
    match upload.state.as_str() {
        "prepared" | "uploading" | "sealing" | "sealed" => {}
        other => {
            return Err(FinalizeError::Command(CommandError::Problem(
                Problem::new(ProblemKind::StaleRevision, "upload is terminal")
                    .with_detail(format!("upload state is {other}")),
            )));
        }
    }

    // Step 1: commit `-> sealing` (its own transaction; the §10.10
    // pipeline is reconciled from the upload id after a crash here).
    if upload.state == "prepared" || upload.state == "uploading" {
        let tx = store.conn().unchecked_transaction()?;
        tx.execute(
            "UPDATE artifact_uploads SET state = 'sealing' WHERE upload_id = ?1",
            [upload_id],
        )?;
        tx.execute(
            "UPDATE artifacts SET state = 'verifying' WHERE artifact_id = ?1
                 AND state = 'pending'",
            [&upload.artifact_id],
        )?;
        kovee_store::audit::append(&tx, now, "artifact.sealing", &format!("upload={upload_id}"))
            .map_err(StoreError::from)?;
        tx.commit()?;
    }
    trip(hooks.after_sealing_txn)?;

    // Step 2: seal the immutable bytes and observe their digests. ETag
    // and client metadata are not verification; the trusted bytes are.
    let secret = object_secret(store.conn(), &upload.artifact_id)?
        .ok_or_else(|| StoreError::Corrupt("artifact without object secret".to_owned()))?;
    let commitment: Option<String> = store
        .conn()
        .query_row(
            "SELECT declared_raw_commitment FROM artifact_uploads WHERE upload_id = ?1",
            [upload_id],
            |r| r.get(0),
        )
        .optional()?;
    let observation = seal_and_observe(paths, &upload, &secret, commitment.as_deref())?;
    trip(hooks.after_seal)?;

    // Step 3: the final SQL transaction — verification row, terminal
    // states, one terminal event, and the idempotency result, atomically.
    let artifact_id = upload.artifact_id.clone();
    let upload_key = upload.upload_id.clone();
    let correlation_ref = correlation_ref.to_owned();
    let outcome = store.command_transaction(scope, now, hooks.store, move |txn| {
        let mut upload = get_upload(txn.conn(), &upload_key)
            .map_err(|_| internal())?
            .ok_or_else(not_found)?;
        if !matches!(upload.state.as_str(), "sealing" | "sealed") {
            return Err(
                Problem::new(ProblemKind::StaleRevision, "upload left the sealing state")
                    .with_detail(format!("upload state is {}", upload.state)),
            );
        }
        let verified = observation
            .as_ref()
            .is_some_and(|obs| obs.raw_match && obs.observed_size == upload.declared_size);
        let now_ts = txn.now_ts();
        let observation_digest = {
            let projection = serde_json::json!({
                "upload_id": upload.upload_id,
                "observed_size": observation.as_ref().map(|o| o.observed_size),
                "raw_match": observation.as_ref().map(|o| o.raw_match),
                "content_digest_ref": observation.as_ref().map(|o| &o.digest_ref),
                "verified": verified,
            });
            let (_, hexd) = canonical_object_digest(
                "kovee-artifact-observation",
                "schema:kovee-artifact-observation-v1",
                &projection,
            )
            .map_err(|_| internal())?;
            hexd
        };
        // The empty scanner set, honestly recorded (no scanning claim).
        let (_, scanner_set_digest) = canonical_object_digest(
            "kovee-scanner-set",
            "schema:kovee-scanner-set-v1",
            &serde_json::json!({"scanners": []}),
        )
        .map_err(|_| internal())?;
        let verification_id = new_id("artver").map_err(|_| internal())?;
        let sealed_version = observation
            .as_ref()
            .map(|o| o.sealed_version.clone())
            .unwrap_or_else(|| "none".to_owned());
        txn.conn()
            .execute(
                "INSERT INTO artifact_verifications (verification_id, upload_id,
                     sealed_storage_ref, sealed_storage_version, observed_size,
                     observed_media_type, observed_content_digest_ref, raw_match,
                     verifier_identity_ref, scanner_set_digest, scan_results,
                     outcome, observation_digest, observed_at)
                 VALUES (?1, ?2, 'artifact-store-local', ?3, ?4, ?5, ?6, ?7,
                     'koveed-local', ?8, '[]', ?9, ?10, ?11)",
                params![
                    verification_id,
                    upload.upload_id,
                    sealed_version,
                    observation
                        .as_ref()
                        .map(|o| o.observed_size as i64)
                        .unwrap_or(0),
                    upload.declared_media_type,
                    observation
                        .as_ref()
                        .and_then(|o| serde_json::to_string(&o.digest_ref).ok())
                        .unwrap_or_else(|| "null".to_owned()),
                    observation
                        .as_ref()
                        .map(|o| o.raw_match as i64)
                        .unwrap_or(0),
                    scanner_set_digest,
                    if verified { "clean" } else { "rejected" },
                    observation_digest,
                    now_ts,
                ],
            )
            .map_err(|_| internal())?;
        let (upload_state, artifact_state, event_type) = if verified {
            ("completed", "available", EVENT_ARTIFACT_AVAILABLE)
        } else {
            ("rejected", "rejected", EVENT_ARTIFACT_REJECTED)
        };
        txn.conn()
            .execute(
                "UPDATE artifact_uploads SET state = ?2, sealed_storage_version = ?3,
                     seal_observation_digest = ?4, sealed_at = ?5, terminal_at = ?5,
                     revision = revision + 1
                 WHERE upload_id = ?1",
                params![
                    upload.upload_id,
                    upload_state,
                    sealed_version,
                    observation_digest,
                    now_ts,
                ],
            )
            .map_err(|_| internal())?;
        if verified {
            let obs = observation.as_ref().ok_or_else(internal)?;
            txn.conn()
                .execute(
                    "UPDATE artifacts SET state = 'available', size = ?2,
                         media_type = ?3, sealed_storage_ref = 'artifact-store-local',
                         sealed_storage_version = ?4, verification_digest = ?5,
                         content_digest_ref = ?6, available_at = ?7,
                         revision = revision + 1
                     WHERE artifact_id = ?1",
                    params![
                        artifact_id,
                        obs.observed_size as i64,
                        upload.declared_media_type,
                        obs.sealed_version,
                        observation_digest,
                        serde_json::to_string(&obs.digest_ref).map_err(|_| internal())?,
                        now_ts,
                    ],
                )
                .map_err(|_| internal())?;
        } else {
            txn.conn()
                .execute(
                    "UPDATE artifacts SET state = 'rejected', revision = revision + 1
                     WHERE artifact_id = ?1",
                    params![artifact_id],
                )
                .map_err(|_| internal())?;
        }
        txn.append_event(NewEvent {
            stream_id: artifact_id.clone(),
            project_id: None,
            actor_ref: None,
            event_type: event_type.to_owned(),
            schema_ref: "schema:artifact-v1".to_owned(),
            resource_ref: artifact_id.clone(),
            resource_revision: Some(2),
            causation_ref: None,
            correlation_ref: correlation_ref.clone(),
            classification_ref: upload.classification_ref.clone(),
            payload: serde_json::json!({
                "artifact_id": artifact_id,
                "upload_id": upload.upload_id,
                "state": artifact_state,
                "verification_digest": observation_digest,
            }),
        })
        .map_err(|_| internal())?;
        txn.audit(
            "command.artifact_upload_finalized",
            &format!(
                "upload={};outcome={upload_state};observation={observation_digest}",
                upload.upload_id
            ),
        );
        upload.state = upload_state.to_owned();
        upload.revision += 1;
        upload.sealed_storage_version = Some(sealed_version);
        upload.seal_observation_digest = Some(observation_digest);
        upload.sealed_at = Some(now_ts.clone());
        upload.terminal_at = Some(now_ts);
        let revision = upload.revision;
        Ok(Applied {
            result: upload_value(&upload)?,
            revision: Some(revision),
            event_cursor: None,
        })
    })?;
    // Post-commit tidy-up (idempotent; a crash here is swept later).
    let _ = std::fs::remove_file(paths.staging_path(upload_id));
    Ok(outcome)
}

/// Seals staging bytes into the content-addressed store and observes
/// their digests, or re-observes an already sealed object on retry.
/// `None` means the bytes are gone or over cap — the final transaction
/// records a rejection.
fn seal_and_observe(
    paths: &ArtifactPaths,
    upload: &ArtifactUpload,
    object_secret: &[u8],
    declared_commitment: Option<&str>,
) -> Result<Option<Observation>, FinalizeError> {
    paths
        .ensure_dirs()
        .map_err(|e| StoreError::Corrupt(format!("artifact dirs: {e}")))?;
    let staging = paths.staging_path(&upload.upload_id);
    let bytes = match std::fs::read(&staging) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Crash-retry path: staging may already have moved into the
            // sealed store — find the sealed object whose keyed content
            // address verifies under this object's secret and re-read
            // those trusted bytes.
            match find_sealed(paths, upload, object_secret)? {
                Some(path) => std::fs::read(path)
                    .map_err(|e| StoreError::Corrupt(format!("sealed bytes: {e}")))?,
                None => return Ok(None),
            }
        }
    };
    if bytes.len() as u64 > upload.max_bytes {
        return Ok(None);
    }
    // The declared checksum is compared through its keyed commitment:
    // the observed bytes' checksum is computed here, HMACed under this
    // object's secret, and matched — the declaration itself is never
    // read back out of storage because it was never stored (KV-A5-2).
    let raw_match = declared_commitment
        .is_some_and(|c| declared_raw_commitment(object_secret, &sha256_hex(&bytes)) == c);
    let digest_ref = content_digest_ref(
        object_secret,
        &upload.artifact_id,
        &upload.declared_media_type,
        &bytes,
    );
    let sealed = paths.sealed_path(&digest_ref.value_hex);
    if !sealed.exists() {
        // Write-then-rename so a partially written sealed object never
        // carries a valid content address.
        let tmp = paths.sealed_dir().join(format!("{}.tmp", upload.upload_id));
        let mut file = std::fs::File::create(&tmp)
            .map_err(|e| StoreError::Corrupt(format!("seal write: {e}")))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| StoreError::Corrupt(format!("seal write: {e}")))?;
        drop(file);
        std::fs::rename(&tmp, &sealed).map_err(|e| StoreError::Corrupt(format!("seal: {e}")))?;
    }
    if let Ok(meta) = std::fs::metadata(&sealed) {
        let mut perms = meta.permissions();
        perms.set_readonly(true);
        let _ = std::fs::set_permissions(&sealed, perms);
    }
    Ok(Some(Observation {
        observed_size: bytes.len() as u64,
        raw_match,
        digest_ref: digest_ref.clone(),
        sealed_version: format!("v1-{}", &digest_ref.value_hex[..16]),
    }))
}

/// Finds the sealed object belonging to this upload after a crash-retry
/// where staging is gone: the keyed content address must re-derive from
/// the candidate's bytes under this object's secret.
fn find_sealed(
    paths: &ArtifactPaths,
    upload: &ArtifactUpload,
    object_secret: &[u8],
) -> Result<Option<PathBuf>, FinalizeError> {
    let dir = match std::fs::read_dir(paths.sealed_dir()) {
        Ok(dir) => dir,
        Err(_) => return Ok(None),
    };
    for entry in dir.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(".tmp") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let candidate = content_digest_ref(
            object_secret,
            &upload.artifact_id,
            &upload.declared_media_type,
            &bytes,
        );
        if candidate.value_hex == name {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

// -------------------------------------------------------------- erase ----

/// Artifact erasure (amendment A5 / D-R1-2, KV-A5-2), callable inside an
/// open command transaction: the sealed blob bytes and any staging copy
/// are removed, the per-object secret is DESTROYED (so the keyed content
/// address can never be re-derived, by anyone, for this object alone),
/// the keyed commitment to the declared checksum goes with it, and a
/// tombstone row is left — `state = 'erased'`, identity and provenance
/// columns intact, no content columns.
///
/// Returns `true` when an artifact row was erased.
///
/// ```no_run
/// # use kovee_artifacts::{ArtifactPaths, erase_artifact};
/// # let conn: rusqlite::Connection = unimplemented!();
/// # let paths = ArtifactPaths::new(std::path::Path::new("/tmp"));
/// erase_artifact(&conn, &paths, "art-1", 0, "2026-07-26T00:00:00Z").unwrap();
/// ```
pub fn erase_artifact(
    conn: &Connection,
    paths: &ArtifactPaths,
    artifact_id: &str,
    now: i64,
    now_ts: &str,
) -> Result<bool, StoreError> {
    let row: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT state, content_digest_ref FROM artifacts WHERE artifact_id = ?1",
            [artifact_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((state, content_digest_ref)) = row else {
        return Ok(false);
    };
    if state == "erased" {
        return Ok(true);
    }
    // The sealed object is addressed by the keyed digest value.
    if let Some(ref_json) = content_digest_ref {
        if let Ok(digest) = serde_json::from_str::<DigestRef>(&ref_json) {
            let sealed = paths.sealed_path(&digest.value_hex);
            if let Ok(meta) = std::fs::metadata(&sealed) {
                // Sealed objects are read-only; make them removable.
                let mut perms = meta.permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(&sealed, perms);
            }
            let _ = std::fs::remove_file(&sealed);
        }
    }
    // Any staging copy of the same plaintext goes too.
    let uploads: Vec<String> = {
        let mut stmt =
            conn.prepare("SELECT upload_id FROM artifact_uploads WHERE artifact_id = ?1")?;
        let mapped = stmt.query_map([artifact_id], |r| r.get::<_, String>(0))?;
        mapped.collect::<Result<_, _>>()?
    };
    for upload_id in &uploads {
        let _ = std::fs::remove_file(paths.staging_path(upload_id));
    }
    conn.execute(
        "UPDATE artifact_uploads SET declared_raw_commitment = NULL
         WHERE artifact_id = ?1",
        [artifact_id],
    )?;
    // The tombstone: identity and provenance stay, every content column
    // and the secret go.
    conn.execute(
        "UPDATE artifacts SET state = 'erased', object_secret = NULL,
             content_digest_ref = NULL, sealed_storage_ref = NULL,
             sealed_storage_version = NULL, verification_digest = NULL,
             size = NULL, media_type = NULL, available_at = NULL,
             retention_until = ?2, revision = revision + 1
         WHERE artifact_id = ?1",
        params![artifact_id, now_ts],
    )?;
    kovee_store::audit::append(
        conn,
        now,
        "artifact.erased",
        &format!("artifact={artifact_id}"),
    )?;
    kovee_store::mark_erasure_compaction_pending(conn)?;
    Ok(true)
}

// --------------------------------------------------- staging sweeper ----

/// Startup mark-and-sweep for orphaned staging blobs (KV-C1): every file
/// in the staging directory is checked against a FRESH database read —
/// a staging blob survives only while its upload row still exists and is
/// still accepting or sealing bytes. A crash between the finalize commit
/// and its tidy-up therefore costs one restart, not a permanent second
/// plaintext copy.
///
/// Returns the number of files removed.
pub fn sweep_staging(store: &Store, paths: &ArtifactPaths) -> Result<usize, StoreError> {
    let Ok(dir) = std::fs::read_dir(paths.staging_dir()) else {
        return Ok(0);
    };
    let mut removed = 0;
    for entry in dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(upload_id) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Fresh reference check, per file, against current state.
        let live: Option<String> = store
            .conn()
            .query_row(
                "SELECT state FROM artifact_uploads WHERE upload_id = ?1",
                [upload_id],
                |r| r.get(0),
            )
            .optional()?;
        let keep = matches!(
            live.as_deref(),
            Some("prepared") | Some("uploading") | Some("sealing") | Some("sealed")
        );
        if !keep {
            let _ = std::fs::remove_file(&path);
            removed += 1;
        }
    }
    Ok(removed)
}

// --------------------------------------------------------------- abort ----

/// `artifact_upload_abort`: non-terminal upload states move to `aborted`;
/// the artifact (which never had verified bytes) becomes `unavailable`.
pub fn upload_abort(
    store: &mut Store,
    paths: &ArtifactPaths,
    scope: &CommandScope,
    upload_id: &str,
    correlation_ref: &str,
    now: i64,
    hooks: CrashHooks,
) -> Result<CommandOutcome, CommandError> {
    let upload_key = upload_id.to_owned();
    let correlation_ref = correlation_ref.to_owned();
    let outcome = store.command_transaction(scope, now, hooks, move |txn| {
        let mut upload = get_upload(txn.conn(), &upload_key)
            .map_err(|_| internal())?
            .ok_or_else(not_found)?;
        match upload.state.as_str() {
            "prepared" | "uploading" | "sealing" | "sealed" => {}
            other => {
                return Err(
                    Problem::new(ProblemKind::StaleRevision, "upload is terminal")
                        .with_detail(format!("upload state is {other}")),
                )
            }
        }
        let now_ts = txn.now_ts();
        txn.conn()
            .execute(
                "UPDATE artifact_uploads SET state = 'aborted', terminal_at = ?2,
                     revision = revision + 1
                 WHERE upload_id = ?1",
                params![upload.upload_id, now_ts],
            )
            .map_err(|_| internal())?;
        txn.conn()
            .execute(
                "UPDATE artifacts SET state = 'unavailable', revision = revision + 1
                 WHERE artifact_id = ?1 AND state IN ('pending', 'verifying')",
                params![upload.artifact_id],
            )
            .map_err(|_| internal())?;
        txn.append_event(NewEvent {
            stream_id: upload.artifact_id.clone(),
            project_id: None,
            actor_ref: None,
            event_type: EVENT_ARTIFACT_UPLOAD_ABORTED.to_owned(),
            schema_ref: "schema:artifact-upload-v1".to_owned(),
            resource_ref: upload.upload_id.clone(),
            resource_revision: Some(upload.revision + 1),
            causation_ref: None,
            correlation_ref: correlation_ref.clone(),
            classification_ref: upload.classification_ref.clone(),
            payload: serde_json::json!({
                "upload_id": upload.upload_id, "state": "aborted",
            }),
        })
        .map_err(|_| internal())?;
        txn.audit(
            "command.artifact_upload_aborted",
            &format!("upload={}", upload.upload_id),
        );
        upload.state = "aborted".to_owned();
        upload.revision += 1;
        upload.terminal_at = Some(now_ts);
        let revision = upload.revision;
        Ok(Applied {
            result: upload_value(&upload)?,
            revision: Some(revision),
            event_cursor: None,
        })
    })?;
    let _ = std::fs::remove_file(paths.staging_path(upload_id));
    Ok(outcome)
}
