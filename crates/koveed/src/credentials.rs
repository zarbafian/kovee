//! Delegated-principal credentials, recorded locally with the family
//! contract's atomic `(issuer_ref, nonce)` rule (L5–L6).
//!
//! What you write:
//! ```
//! # use koveed::credentials::{issue, consume, Consumed};
//! # use kovee_byom::credential::{Delegation, DpcMint, SenderConstraint};
//! # use kovee_core::family::DigestRef;
//! # use kovee_byom::hostint;
//! # let mut store = kovee_store::Store::open_in_memory().unwrap();
//! # store.bootstrap(0).unwrap();
//! # let binding = koveed::credentials::doc_binding(&mut store);
//! let mint = DpcMint {
//!     issuer_ref: "kovee-gateway:realm-personal",
//!     nonce: "nonce-0001",
//!     sender_constraint: SenderConstraint::channel_exporter(
//!         DigestRef::portable_public("a".repeat(64))),
//!     delegation: Delegation {
//!         source_principal_ref: "prin-owner",
//!         bound_participant_ref: "part-1",
//!         participant_binding_epoch: 1,
//!         allowed_operations: &["kovee_endeavor_form"],
//!         authentication_observation_ref: "authobs-1",
//!         assurance_level: "personal-uds-owner",
//!     },
//!     subject_digest: hostint::command_digest(&serde_json::json!({"n": 1})).unwrap(),
//!     issued_at: 1_800_000_000,
//!     lifetime_seconds: 120,
//! };
//! let dpc = issue(&mut store, "realm-personal", &binding, "soc-1", 0, &mint).unwrap();
//!
//! // First use executes; every later use returns the stored result.
//! let first = consume(&mut store, &dpc, "kovee_endeavor_form", 0,
//!                     || Ok(b"{\"endeavor_ref\":\"end-1\"}".to_vec())).unwrap();
//! let again = consume(&mut store, &dpc, "kovee_endeavor_form", 1,
//!                     || panic!("a consumed nonce never re-executes")).unwrap();
//! assert!(matches!(first, Consumed::Fresh(_)));
//! assert_eq!(first.bytes(), again.bytes());
//! ```
//!
//! Plumbing: `delegated_principal_credentials` carries `UNIQUE(issuer_ref,
//! nonce)`, and the consume is a single conditional `UPDATE … WHERE
//! consumed_at IS NULL` inside one transaction — so two racing consumes
//! cannot both execute, and the loser reads the winner's stored bytes.
//! `governance_disable` marks every credential of a voided binding
//! consumed, which is how a disabled binding invalidates its derived
//! channels.

use kovee_byom::credential::{CredentialError, DelegatedPrincipalCredential, DpcMint, MintContext};
use kovee_byom::records::KoveeRealmByomBinding;
use kovee_core::problem::{Problem, ProblemKind};
use kovee_store::Store;
use rusqlite::{params, OptionalExtension as _};

use crate::state::{internal, not_found, store_problem};

/// The outcome of one `(issuer, nonce)` consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consumed {
    /// This call executed the operation; its bytes are now stored.
    Fresh(Vec<u8>),
    /// The pair was already spent; these are the stored bytes.
    Replayed(Vec<u8>),
}

impl Consumed {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Consumed::Fresh(b) | Consumed::Replayed(b) => b,
        }
    }
}

/// Mints one credential against an ACTIVE binding and records it. The
/// `UNIQUE(issuer_ref, nonce)` index makes a second minting under the
/// same pair impossible.
pub fn issue(
    store: &mut Store,
    realm: &str,
    binding: &KoveeRealmByomBinding,
    society_ref: &str,
    society_recovery_epoch: u64,
    mint: &DpcMint<'_>,
) -> Result<DelegatedPrincipalCredential, Problem> {
    let context = MintContext {
        binding,
        society_ref: society_ref.to_owned(),
        society_recovery_epoch,
    };
    let dpc = mint.issue(&context).map_err(credential_problem)?;
    dpc.check_against(binding).map_err(credential_problem)?;
    store
        .conn()
        .execute(
            "INSERT INTO delegated_principal_credentials (credential_id, issuer_ref, nonce,
                 realm_ref, binding_ref, record, digest_hex, issued_at, expires_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                dpc.credential_id,
                dpc.issuer_ref,
                dpc.nonce,
                realm,
                binding.binding_ref,
                serde_json::to_string(&dpc).map_err(|_| internal())?,
                dpc.digest.value_hex,
                dpc.issued_at,
                dpc.expires_at,
            ],
        )
        .map_err(|e| {
            if is_unique_violation(&e) {
                Problem::new(
                    ProblemKind::IdempotencyMismatch,
                    "this (issuer, nonce) pair is already minted",
                )
            } else {
                store_problem(e.into())
            }
        })?;
    Ok(dpc)
}

/// Records one already-minted credential INSIDE an open transaction — the
/// formation saga mints its per-attempt credential in the same commit that
/// makes the attempt durable, so no credential can exist for a send that
/// is not itself recorded.
pub fn record(
    conn: &rusqlite::Connection,
    realm: &str,
    binding_ref: &str,
    dpc: &DelegatedPrincipalCredential,
) -> Result<(), Problem> {
    conn.execute(
        "INSERT INTO delegated_principal_credentials (credential_id, issuer_ref, nonce,
             realm_ref, binding_ref, record, digest_hex, issued_at, expires_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            dpc.credential_id,
            dpc.issuer_ref,
            dpc.nonce,
            realm,
            binding_ref,
            serde_json::to_string(dpc).map_err(|_| internal())?,
            dpc.digest.value_hex,
            dpc.issued_at,
            dpc.expires_at,
        ],
    )
    .map_err(|e| {
        if is_unique_violation(&e) {
            Problem::new(
                ProblemKind::IdempotencyMismatch,
                "this (issuer, nonce) pair is already minted",
            )
        } else {
            store_problem(e.into())
        }
    })?;
    Ok(())
}

/// The recorded credential of one `(issuer, nonce)` pair.
pub fn read(
    conn: &rusqlite::Connection,
    issuer_ref: &str,
    nonce: &str,
) -> Result<Option<DelegatedPrincipalCredential>, Problem> {
    let text: Option<String> = conn
        .query_row(
            "SELECT record FROM delegated_principal_credentials
             WHERE issuer_ref = ?1 AND nonce = ?2",
            params![issuer_ref, nonce],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    text.map(|t| serde_json::from_str(&t).map_err(|_| internal()))
        .transpose()
}

/// Marks a pair consumed with the exact bytes a replay must return, inside
/// an open transaction.
pub fn mark_consumed(
    conn: &rusqlite::Connection,
    dpc: &DelegatedPrincipalCredential,
    operation: &str,
    now: i64,
    result: &[u8],
) -> Result<(), Problem> {
    let (issuer, nonce) = dpc.consume_key();
    conn.execute(
        "UPDATE delegated_principal_credentials
         SET consumed_at = COALESCE(consumed_at, ?3),
             consumed_operation = COALESCE(consumed_operation, ?4),
             consumed_result = COALESCE(consumed_result, ?5)
         WHERE issuer_ref = ?1 AND nonce = ?2",
        params![issuer, nonce, now, operation, result],
    )
    .map_err(|e| store_problem(e.into()))?;
    Ok(())
}

/// Consumes the credential exactly once. `execute` runs only on the first
/// consumption; every later call returns the stored bytes verbatim.
pub fn consume(
    store: &mut Store,
    dpc: &DelegatedPrincipalCredential,
    operation: &str,
    now: i64,
    execute: impl FnOnce() -> Result<Vec<u8>, Problem>,
) -> Result<Consumed, Problem> {
    if !dpc.allowed_operations.iter().any(|op| op == operation) {
        return Err(Problem::new(
            ProblemKind::Forbidden,
            "the credential does not allow this operation",
        )
        .with_detail(format!(
            "allowed_operations is {:?}",
            dpc.allowed_operations
        )));
    }
    let (issuer, nonce) = dpc.consume_key();
    let tx = store
        .conn()
        .unchecked_transaction()
        .map_err(|e| store_problem(e.into()))?;
    let stored: Option<Option<Vec<u8>>> = tx
        .query_row(
            "SELECT consumed_result FROM delegated_principal_credentials
             WHERE issuer_ref = ?1 AND nonce = ?2 AND consumed_at IS NOT NULL",
            params![issuer, nonce],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| store_problem(e.into()))?;
    if let Some(result) = stored {
        // Already spent — including by a governance_disable, which stores
        // no result and so leaves the pair unusable.
        return match result {
            Some(bytes) => Ok(Consumed::Replayed(bytes)),
            None => Err(Problem::new(
                ProblemKind::Forbidden,
                "the credential was invalidated before use",
            )),
        };
    }
    let bytes = execute()?;
    let claimed = tx
        .execute(
            "UPDATE delegated_principal_credentials
             SET consumed_at = ?3, consumed_operation = ?4, consumed_result = ?5
             WHERE issuer_ref = ?1 AND nonce = ?2 AND consumed_at IS NULL",
            params![issuer, nonce, now, operation, bytes],
        )
        .map_err(|e| store_problem(e.into()))?;
    if claimed == 0 {
        return Err(not_found());
    }
    tx.commit().map_err(|e| store_problem(e.into()))?;
    Ok(Consumed::Fresh(bytes))
}

fn credential_problem(e: CredentialError) -> Problem {
    Problem::new(
        ProblemKind::Forbidden,
        "the delegated-principal credential is not mintable",
    )
    .with_detail(e.to_string())
}

fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                ..
            },
            _
        )
    )
}

/// An active binding row inserted into `store`, for the doc example and
/// the tests — real bindings come from the greenfield saga.
#[doc(hidden)]
#[allow(clippy::expect_used)]
pub fn doc_binding(store: &mut Store) -> KoveeRealmByomBinding {
    let binding = kovee_byom::records::sample_active_binding();
    store
        .conn()
        .execute(
            "INSERT INTO kovee_realm_byom_bindings (binding_ref, realm_ref,
                 exact_scope_digest_hex, binding_revision, binding_epoch,
                 byom_endpoint_ref, endpoint_incarnation, compatibility_bundle,
                 delegated_principal_audience, external_authorization_audience,
                 historical_recovery_mode, recovery_authorization_policy_ref,
                 recovery_authorization_policy_digest, status, dependency_digest, digest,
                 created_at)
             VALUES (?1,'realm-personal','00',2,1,'local','inc-1','byom_governed_work_v1',
                 ?2,'aud-x','disabled','pol',?3,'active',?3,?3,'1970-01-01T00:00:00Z')",
            params![
                binding.binding_ref,
                binding.delegated_principal_audience,
                // A well-formed typed DigestRef: the fixture must be
                // readable by the row readers, not just insertable.
                serde_json::to_string(&binding.digest).unwrap_or_default(),
            ],
        )
        .expect("insert binding fixture");
    binding
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use kovee_byom::credential::{Delegation, SenderConstraint};
    use kovee_core::family::DigestRef;

    fn mint<'a>(nonce: &'a str, ops: &'a [&'a str]) -> DpcMint<'a> {
        DpcMint {
            issuer_ref: "kovee-gateway:realm-personal",
            nonce,
            sender_constraint: SenderConstraint::channel_exporter(DigestRef::portable_public(
                "a".repeat(64),
            )),
            delegation: Delegation {
                source_principal_ref: "prin-owner",
                bound_participant_ref: "part-1",
                participant_binding_epoch: 1,
                allowed_operations: ops,
                authentication_observation_ref: "authobs-1",
                assurance_level: "personal-uds-owner",
            },
            subject_digest: kovee_byom::hostint::command_digest(&serde_json::json!({"n": 1}))
                .unwrap(),
            issued_at: 1_800_000_000,
            lifetime_seconds: 120,
        }
    }

    fn store() -> (Store, KoveeRealmByomBinding) {
        let mut store = Store::open_in_memory().unwrap();
        store.bootstrap(0).unwrap();
        let binding = doc_binding(&mut store);
        (store, binding)
    }

    #[test]
    fn the_issuer_nonce_pair_is_atomic_and_single_use() {
        let (mut store, binding) = store();
        let dpc = issue(
            &mut store,
            "realm-personal",
            &binding,
            "soc-1",
            0,
            &mint("nonce-1", &["kovee_endeavor_form"]),
        )
        .unwrap();

        let first = consume(&mut store, &dpc, "kovee_endeavor_form", 0, || {
            Ok(b"first".to_vec())
        })
        .unwrap();
        assert_eq!(first, Consumed::Fresh(b"first".to_vec()));

        // Second use never re-executes and returns the stored bytes.
        let second = consume(&mut store, &dpc, "kovee_endeavor_form", 1, || {
            panic!("a spent nonce must never re-execute")
        })
        .unwrap();
        assert_eq!(second, Consumed::Replayed(b"first".to_vec()));
        assert_eq!(first.bytes(), second.bytes());
    }

    #[test]
    fn a_second_minting_under_the_same_pair_is_refused() {
        let (mut store, binding) = store();
        issue(
            &mut store,
            "realm-personal",
            &binding,
            "soc-1",
            0,
            &mint("nonce-1", &["kovee_endeavor_form"]),
        )
        .unwrap();
        let err = issue(
            &mut store,
            "realm-personal",
            &binding,
            "soc-1",
            0,
            &mint("nonce-1", &["external_command_terminalize"]),
        )
        .unwrap_err();
        assert_eq!(err.kind, ProblemKind::IdempotencyMismatch);
    }

    #[test]
    fn a_credential_cannot_drive_an_operation_it_does_not_name() {
        let (mut store, binding) = store();
        let dpc = issue(
            &mut store,
            "realm-personal",
            &binding,
            "soc-1",
            0,
            &mint("nonce-1", &["kovee_endeavor_form"]),
        )
        .unwrap();
        let err = consume(&mut store, &dpc, "external_command_terminalize", 0, || {
            panic!("never reached")
        })
        .unwrap_err();
        assert_eq!(err.kind, ProblemKind::Forbidden);
    }

    #[test]
    fn an_invalidated_credential_is_unusable() {
        // governance_disable marks the pair consumed with NO stored
        // result: the derived channel is dead, not replayable.
        let (mut store, binding) = store();
        let dpc = issue(
            &mut store,
            "realm-personal",
            &binding,
            "soc-1",
            0,
            &mint("nonce-1", &["kovee_endeavor_form"]),
        )
        .unwrap();
        store
            .conn()
            .execute(
                "UPDATE delegated_principal_credentials
                 SET consumed_at = 1, consumed_operation = 'governance_disable'
                 WHERE binding_ref = ?1",
                params![binding.binding_ref],
            )
            .unwrap();
        let err = consume(&mut store, &dpc, "kovee_endeavor_form", 2, || {
            panic!("never reached")
        })
        .unwrap_err();
        assert_eq!(err.kind, ProblemKind::Forbidden);
    }

    #[test]
    fn a_failed_execution_leaves_the_nonce_unspent() {
        let (mut store, binding) = store();
        let dpc = issue(
            &mut store,
            "realm-personal",
            &binding,
            "soc-1",
            0,
            &mint("nonce-1", &["kovee_endeavor_form"]),
        )
        .unwrap();
        let err = consume(&mut store, &dpc, "kovee_endeavor_form", 0, || {
            Err(Problem::new(
                ProblemKind::Unavailable,
                "byom did not answer",
            ))
        })
        .unwrap_err();
        assert_eq!(err.kind, ProblemKind::Unavailable);
        // Unspent: the retry executes.
        let retried = consume(&mut store, &dpc, "kovee_endeavor_form", 1, || {
            Ok(b"done".to_vec())
        })
        .unwrap();
        assert_eq!(retried, Consumed::Fresh(b"done".to_vec()));
    }
}
