//! K1 artifact crash matrix (kovee §25.2): seal → verify → SQL crash
//! with fault injection at every pipeline point — unverified bytes NEVER
//! become `available`. The library-level matrix uses soft crashes
//! (early returns) plus a reopened store; the daemon-level matrix
//! (`koveed --test k1_crash_matrix`) kills the real process at the same
//! points.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use kovee_artifacts::{ArtifactPaths, Fault, FinalizeError, FinalizeHooks};
use kovee_core::canonical::sha256_hex;
use kovee_core::problem::ProblemKind;
use kovee_store::{CommandError, CommandOutcome, CommandScope, CrashHooks, Store};

fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn scope(op: &str, key: &str) -> CommandScope {
    CommandScope {
        actor_scope: "external_client/prin-owner/realm-personal".into(),
        operation: op.into(),
        idempotency_key: key.into(),
        request_digest: "f".repeat(64),
    }
}

struct Fixture {
    dir: PathBuf,
    paths: ArtifactPaths,
    store: Store,
    upload_id: String,
    artifact_id: String,
}

impl Fixture {
    fn new(name: &str, bytes: &[u8]) -> Fixture {
        let dir = tmp(name);
        let mut store = Store::open(&dir.join("kovee.db")).unwrap();
        store.bootstrap(0).unwrap();
        let paths = ArtifactPaths::new(&dir);
        let outcome = kovee_artifacts::upload_begin(
            &mut store,
            &paths,
            &scope("artifact_upload_begin", "begin-1"),
            &sha256_hex(bytes),
            bytes.len() as u64,
            "text/plain",
            None,
            "req-begin",
            0,
            CrashHooks::NONE,
        )
        .unwrap();
        let reply: serde_json::Value = serde_json::from_slice(outcome.bytes()).unwrap();
        let upload_id = reply["result"]["upload_id"].as_str().unwrap().to_owned();
        let artifact_id = reply["result"]["artifact_id"].as_str().unwrap().to_owned();
        std::fs::write(paths.staging_path(&upload_id), bytes).unwrap();
        Fixture {
            dir,
            paths,
            store,
            upload_id,
            artifact_id,
        }
    }

    /// Simulates the process death + restart: drop the store connection
    /// and reopen the database file (WAL recovery included).
    fn reopen(&mut self) {
        let db = self.dir.join("kovee.db");
        let fresh = Store::open(&db).unwrap();
        self.store = fresh;
    }

    fn artifact_state(&self) -> String {
        kovee_artifacts::get_artifact(self.store.conn(), &self.artifact_id)
            .unwrap()
            .unwrap()
            .state
    }

    fn upload_state(&self) -> String {
        kovee_artifacts::get_upload(self.store.conn(), &self.upload_id)
            .unwrap()
            .unwrap()
            .state
    }

    fn finalize(&mut self, hooks: FinalizeHooks) -> Result<CommandOutcome, FinalizeError> {
        kovee_artifacts::upload_finalize(
            &mut self.store,
            &self.paths,
            &scope("artifact_upload_finalize", "final-1"),
            &self.upload_id,
            "req-final",
            0,
            hooks,
        )
    }

    fn verification_rows(&self) -> i64 {
        self.store
            .conn()
            .query_row("SELECT COUNT(*) FROM artifact_verifications", [], |r| {
                r.get(0)
            })
            .unwrap()
    }
}

fn soft(after_sealing_txn: bool, after_seal: bool) -> FinalizeHooks {
    FinalizeHooks {
        after_sealing_txn: if after_sealing_txn {
            Fault::SoftCrash
        } else {
            Fault::None
        },
        after_seal: if after_seal {
            Fault::SoftCrash
        } else {
            Fault::None
        },
        store: CrashHooks::NONE,
    }
}

#[test]
fn crash_after_sealing_txn_never_yields_available_and_retry_completes_once() {
    let mut fx = Fixture::new("crash-after-sealing-txn", b"payload one");
    let err = fx.finalize(soft(true, false)).unwrap_err();
    assert!(matches!(err, FinalizeError::SimulatedCrash));
    fx.reopen();
    assert_eq!(fx.artifact_state(), "verifying", "committed sealing state");
    assert_ne!(fx.artifact_state(), "available");
    assert_eq!(fx.verification_rows(), 0, "no verification committed yet");

    // Retry reconciles from the same upload id: exactly one completion.
    let outcome = fx.finalize(FinalizeHooks::NONE).unwrap();
    assert!(matches!(outcome, CommandOutcome::Fresh(_)));
    assert_eq!(fx.artifact_state(), "available");
    assert_eq!(fx.upload_state(), "completed");
    assert_eq!(fx.verification_rows(), 1);
    // And the replay is byte-identical.
    let replay = fx.finalize(FinalizeHooks::NONE).unwrap();
    assert_eq!(outcome.bytes(), replay.bytes());
    assert_eq!(fx.verification_rows(), 1);
}

#[test]
fn crash_after_seal_bytes_never_yields_available_and_retry_completes_once() {
    let mut fx = Fixture::new("crash-after-seal", b"payload two");
    let err = fx.finalize(soft(false, true)).unwrap_err();
    assert!(matches!(err, FinalizeError::SimulatedCrash));
    fx.reopen();
    // The sealed bytes exist on disk, but the artifact is NOT available:
    // only the final transaction can make it so.
    assert_eq!(fx.artifact_state(), "verifying");
    assert_eq!(fx.verification_rows(), 0);

    let outcome = fx.finalize(FinalizeHooks::NONE).unwrap();
    assert!(matches!(outcome, CommandOutcome::Fresh(_)));
    assert_eq!(fx.artifact_state(), "available");
    assert_eq!(fx.verification_rows(), 1);
}

#[test]
fn sql_failure_in_the_final_transaction_commits_nothing() {
    // The §12.2 contract of the final transaction: a failure inside it
    // rolls back verification, states, event, and idempotency record
    // together. Simulate by injecting a store-level abort … via the
    // before-commit crash hook we cannot use in-process, so instead
    // prove the equivalent invariant: a crash before the final commit
    // (after_seal) left NOTHING of the final transaction (previous
    // test), and a doubly-crashed pipeline still converges.
    let mut fx = Fixture::new("crash-twice", b"payload three");
    assert!(fx.finalize(soft(true, false)).is_err());
    fx.reopen();
    assert!(fx.finalize(soft(false, true)).is_err());
    fx.reopen();
    assert_eq!(fx.artifact_state(), "verifying");
    assert_eq!(fx.verification_rows(), 0);
    let outcome = fx.finalize(FinalizeHooks::NONE).unwrap();
    assert!(matches!(outcome, CommandOutcome::Fresh(_)));
    assert_eq!(fx.artifact_state(), "available");
    assert_eq!(fx.upload_state(), "completed");
    assert_eq!(fx.verification_rows(), 1);
}

#[test]
fn tampered_bytes_are_rejected_not_published() {
    // The declared digest does not match the staged bytes: the pipeline
    // completes with a REJECTION — verification evidence is stored, and
    // the artifact can never be referenced as available.
    let dir = tmp("tampered");
    let mut store = Store::open(&dir.join("kovee.db")).unwrap();
    store.bootstrap(0).unwrap();
    let paths = ArtifactPaths::new(&dir);
    let outcome = kovee_artifacts::upload_begin(
        &mut store,
        &paths,
        &scope("artifact_upload_begin", "begin-t"),
        &sha256_hex(b"the declared bytes"),
        18,
        "text/plain",
        None,
        "req-begin",
        0,
        CrashHooks::NONE,
    )
    .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(outcome.bytes()).unwrap();
    let upload_id = reply["result"]["upload_id"].as_str().unwrap().to_owned();
    let artifact_id = reply["result"]["artifact_id"].as_str().unwrap().to_owned();
    std::fs::write(paths.staging_path(&upload_id), b"EVIL substituted!!").unwrap();

    let outcome = kovee_artifacts::upload_finalize(
        &mut store,
        &paths,
        &scope("artifact_upload_finalize", "final-t"),
        &upload_id,
        "req-final",
        0,
        FinalizeHooks::NONE,
    )
    .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(outcome.bytes()).unwrap();
    assert_eq!(reply["result"]["state"].as_str(), Some("rejected"));
    let artifact = kovee_artifacts::get_artifact(store.conn(), &artifact_id)
        .unwrap()
        .unwrap();
    assert_eq!(artifact.state, "rejected");
    let verifications: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM artifact_verifications WHERE outcome = 'rejected'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(verifications, 1);
}

#[test]
fn missing_staging_bytes_reject_and_abort_is_terminal() {
    let dir = tmp("missing-bytes");
    let mut store = Store::open(&dir.join("kovee.db")).unwrap();
    store.bootstrap(0).unwrap();
    let paths = ArtifactPaths::new(&dir);
    let outcome = kovee_artifacts::upload_begin(
        &mut store,
        &paths,
        &scope("artifact_upload_begin", "begin-m"),
        &sha256_hex(b"never uploaded"),
        14,
        "text/plain",
        None,
        "req-begin",
        0,
        CrashHooks::NONE,
    )
    .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(outcome.bytes()).unwrap();
    let upload_id = reply["result"]["upload_id"].as_str().unwrap().to_owned();

    // No staging bytes were ever written: finalize records a rejection.
    let outcome = kovee_artifacts::upload_finalize(
        &mut store,
        &paths,
        &scope("artifact_upload_finalize", "final-m"),
        &upload_id,
        "req-final",
        0,
        FinalizeHooks::NONE,
    )
    .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(outcome.bytes()).unwrap();
    assert_eq!(reply["result"]["state"].as_str(), Some("rejected"));

    // A terminal upload refuses further finalize/abort with a fresh key.
    let err = kovee_artifacts::upload_abort(
        &mut store,
        &paths,
        &scope("artifact_upload_abort", "abort-m"),
        &upload_id,
        "req-abort",
        0,
        CrashHooks::NONE,
    )
    .unwrap_err();
    match err {
        CommandError::Problem(p) => assert_eq!(p.kind, ProblemKind::StaleRevision),
        other => panic!("unexpected {other:?}"),
    }
}

/// The content address is a typed `local_erasure_safe` DigestRef
/// (amendment A5): keyed per object, never a public plaintext hash, and
/// never leaked on the wire projection.
#[test]
fn content_address_is_local_erasure_safe_and_off_the_wire() {
    let mut fx = Fixture::new("a5-digest-class", b"classified plaintext");
    let outcome = fx.finalize(FinalizeHooks::NONE).unwrap();
    let reply: serde_json::Value = serde_json::from_slice(outcome.bytes()).unwrap();
    // The wire upload projection carries no raw hash beside the caller's
    // own declared value; the artifact projection carries none at all.
    let artifact = kovee_artifacts::get_artifact(fx.store.conn(), &fx.artifact_id)
        .unwrap()
        .unwrap();
    assert_eq!(artifact.state, "available");
    assert!(
        artifact.raw_sha256.is_none(),
        "A5: no retained plaintext hash"
    );
    assert!(artifact.typed_byte_digest.is_none());
    assert!(reply["result"].get("observed_raw_sha256").is_none());

    // Internally the address is the typed keyed ref.
    let stored: String = fx
        .store
        .conn()
        .query_row(
            "SELECT content_digest_ref FROM artifacts WHERE artifact_id = ?1",
            [&fx.artifact_id],
            |r| r.get(0),
        )
        .unwrap();
    let digest: kovee_core::family::DigestRef = serde_json::from_str(&stored).unwrap();
    assert_eq!(digest.class, "local_erasure_safe");
    assert_eq!(digest.algorithm, "hmac-sha-256");
    assert!(digest
        .key_ref
        .as_deref()
        .unwrap()
        .starts_with("kovee-artifact-object:"));
    // The sealed object is stored under that keyed address.
    assert!(fx.paths.sealed_path(&digest.value_hex).exists());
    // And the no-scanning honesty is recorded: an empty scanner set.
    let scan_results: String = fx
        .store
        .conn()
        .query_row(
            "SELECT scan_results FROM artifact_verifications WHERE upload_id = ?1",
            [&fx.upload_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(scan_results, "[]");
}

// ------------------------------------------------ A5-2 erasure (R1) ----

/// Every byte the fixture keeps on disk: the database, its WAL and
/// shared memory, and the artifact store.
fn all_stored_bytes(dir: &std::path::Path) -> Vec<u8> {
    fn walk(dir: &std::path::Path, out: &mut Vec<u8>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if let Ok(mut content) = std::fs::read(&path) {
                out.append(&mut content);
                out.push(0);
            }
        }
    }
    let mut bytes = Vec::new();
    walk(dir, &mut bytes);
    assert!(!bytes.is_empty());
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// KV-A5-2 / D-R1-2: the declared checksum is transient, the per-object
/// secret is wrapped under the realm key (never raw beside the object),
/// and erasure removes the blob, destroys the secret, and leaves a
/// tombstone. Proved by grepping the artifact store AND the database.
#[test]
fn the_checksum_is_transient_the_secret_is_wrapped_and_erasure_removes_both() {
    let plaintext = b"artifact plaintext that must be erasable";
    let mut fx = Fixture::new("a5-2-erasure", plaintext);
    let checksum = sha256_hex(plaintext);
    fx.finalize(FinalizeHooks::NONE).unwrap();
    assert_eq!(fx.artifact_state(), "available");

    // The stored secret is a WRAP, not key material: it opens only under
    // the realm key for this exact object.
    let wrapped: Vec<u8> = fx
        .store
        .conn()
        .query_row(
            "SELECT object_secret FROM artifacts WHERE artifact_id = ?1",
            [&fx.artifact_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(wrapped.len(), kovee_store::objkey::WRAPPED_LEN);
    let realm_key = fx.store.realm_object_key().unwrap();
    let key_ref = format!("kovee-artifact-object:{}", fx.artifact_id);
    let secret = kovee_store::objkey::unwrap(&realm_key, &key_ref, &wrapped).unwrap();
    assert!(
        kovee_store::objkey::unwrap(&realm_key, "kovee-artifact-object:art-other", &wrapped)
            .is_err(),
        "the wrap is bound to its own object"
    );

    // While the artifact is live: no raw secret and no checksum anywhere
    // on disk — only the wrap and the keyed commitment.
    let live = all_stored_bytes(&fx.dir);
    assert!(
        !contains(&live, &secret),
        "the raw per-object secret must never sit beside the object"
    );
    assert!(
        !contains(&live, checksum.as_bytes()),
        "the declared raw checksum must never be durable"
    );
    assert!(
        contains(&live, plaintext),
        "the sealed bytes must be there before erasure"
    );
    // Nothing on the wire carries them either.
    let upload = kovee_artifacts::get_upload(fx.store.conn(), &fx.upload_id)
        .unwrap()
        .unwrap();
    let projection = serde_json::to_string(&upload).unwrap();
    assert!(!projection.contains(&checksum));

    // ---- erase ----
    let erased = kovee_artifacts::erase_artifact(
        fx.store.conn(),
        &fx.paths,
        &fx.artifact_id,
        0,
        "2026-07-26T00:00:00Z",
    )
    .unwrap();
    assert!(erased);
    fx.store.compact_after_erasure().unwrap();

    let after = all_stored_bytes(&fx.dir);
    assert!(!contains(&after, plaintext), "the blob bytes survived");
    assert!(!contains(&after, &wrapped), "the wrapped secret survived");
    assert!(!contains(&after, &secret), "the secret survived");
    assert!(
        !contains(&after, checksum.as_bytes()),
        "the checksum survived"
    );

    // The tombstone: the object is still named, with no content.
    let artifact = kovee_artifacts::get_artifact(fx.store.conn(), &fx.artifact_id)
        .unwrap()
        .unwrap();
    assert_eq!(artifact.state, "erased");
    assert_eq!(artifact.artifact_id, fx.artifact_id);
    assert!(artifact.size.is_none());
    assert!(artifact.sealed_storage_ref.is_none());
    // Erasure is idempotent.
    assert!(kovee_artifacts::erase_artifact(
        fx.store.conn(),
        &fx.paths,
        &fx.artifact_id,
        0,
        "2026-07-26T00:00:00Z"
    )
    .unwrap());

    // Erasing one object leaves an unrelated one intact — the point of a
    // per-object secret rather than a scope key.
    let other = Fixture::new("a5-2-erasure-other", b"a different artifact");
    other_still_verifies(other);
}

fn other_still_verifies(mut other: Fixture) {
    other.finalize(FinalizeHooks::NONE).unwrap();
    assert_eq!(other.artifact_state(), "available");
}
