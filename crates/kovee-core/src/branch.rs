//! The §10.3 branch head chain: every branch append presents the expected
//! head digest and compare-and-swaps it.
//!
//! The head is a fold any authorized reader can recompute from the event
//! ledger, so a client derives the current expected head from
//! `events_read` without a privileged read:
//!
//! ```
//! use kovee_core::branch::{genesis_head, next_head};
//! let mut head = genesis_head("branch-0001");
//! // fold each committed entry: (branch_sequence, object_digest)
//! head = next_head(&head, 1, &"ab".repeat(32));
//! assert_eq!(head.len(), 64);
//! ```
//!
//! Construction (implementation-pinned): the §11.8 `TypedByteDigest` under
//! the `branch-head` domain. The digest registry has no branch-head entry
//! yet — DESIGN.md pins only that the digest exists and is CASed; the
//! exact projection is a recorded K0 gap, so this file is the single
//! authority for the chain until a registry entry lands (K2 deliberation).

use crate::canonical::typed_byte_digest;

/// The typed-digest domain of the branch head chain.
pub const BRANCH_HEAD_DOMAIN: &str = "branch-head";
/// The `media_or_schema_ref` naming this chain construction.
pub const BRANCH_HEAD_REF: &str = "https://kovee.example/kcp/v0/branch-head.v1";

/// The head digest of a branch with no entries.
pub fn genesis_head(branch_id: &str) -> String {
    typed_byte_digest(
        BRANCH_HEAD_DOMAIN,
        BRANCH_HEAD_REF,
        format!("genesis:{branch_id}").as_bytes(),
    )
}

/// The head after appending the entry `(branch_sequence, object_digest)`
/// on top of `prev_head`.
pub fn next_head(prev_head: &str, branch_sequence: u64, object_digest: &str) -> String {
    typed_byte_digest(
        BRANCH_HEAD_DOMAIN,
        BRANCH_HEAD_REF,
        format!("{prev_head}:{branch_sequence}:{object_digest}").as_bytes(),
    )
}
