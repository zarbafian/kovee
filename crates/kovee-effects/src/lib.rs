//! The Kovee effect and egress brokers (design §16). K2 delivers the
//! **model broker**: the only path from an assistant to a model provider.
//!
//! The one sentence that explains the crate: **a model call is an Effect,
//! and no byte leaves without a byom `ExecutionConsumptionReceipt` for that
//! effect's exact execution key.**
//!
//! What you write (the whole chain, in the order it must happen):
//!
//! ```no_run
//! use std::time::Duration;
//! use kovee_effects::*;
//! # fn f(binding: &ModelProviderBinding, profile: &ModelProfile,
//! #      disclosure: DisclosureManifest, chain: ProviderContextManifest,
//! #      subject: &kovee_core::family::DigestRef,
//! #      byom_reply: &serde_json::Value,
//! #      credential: &Credential, keys: PlanKeys,
//! #      authority: &ConsumptionAuthority<'_>)
//! #   -> Result<(), Box<dyn std::error::Error>> {
//! // 1. plan: profile re-validated, disclosure verified, provider bytes
//! //    built, and the context chain SEALED over exactly those bytes.
//! let plan = plan(&PlanInput {
//!     effect_id: "meff-1",
//!     execution_key: "exec-abc",       // byom's kernel-derived one-shot key
//!     act_intent_ref: "actint-1",      // byom's authorizing act
//!     subject_digest: subject,         // byom's authorized subject, echoed
//!     context_manifest_ref: "ctxman-1",       // the pair the seats assented
//!     context_manifest_digest: subject,       // to, as byom committed it
//!     system: Some("Be brief."), prompt: "Say OK.",
//!     max_output_tokens: 256, classification_ref: "class-public",
//! }, binding, profile, disclosure, chain, keys)?;
//! // `plan.host_effect_digest()` is the portable_public digest of the FROZEN
//! // `kovee-host-effect-binding-v1` fragment above: byom rebuilds the same
//! // preimage from its own committed act and re-derives it (R3-L01).
//!
//! // 2. …the caller COMMITS the prepared effect, then byom consumes the
//! //    permit for `plan.execution_key()`. byom's reply becomes a receipt
//! //    only through the daemon's own authority, and is attested against
//! //    the committed consumption row:
//! let receipt = authority.admit(byom_reply)?;
//! let consumed = authority.attest(&receipt, "eac-1")?;
//!
//! // 3. gate: the only way to obtain an ExecutionPermit.
//! let permit = authority.authorize(Some(consumed), &Expectation {
//!     execution_key: plan.execution_key(),
//!     subject_digest: plan.subject_digest(),
//!     disclosure_digest: &plan.disclosure().digest,
//!     driver_audience: BROKER_DRIVER_AUDIENCE,
//!     episode: None, endpoint_incarnation: "inst-1", recovery_epoch: 0,
//!     now: kovee_core::time::unix_now(), already_spent: false,
//!     bound_origin: &binding.endpoint,   // the destination, bound HERE
//! })?;
//!
//! // 4. …the caller COMMITS the attempt as `dispatching`, then hands the
//! //    permit over — by value, exactly once, to the same authority:
//! let outcome = dispatch(&plan, permit, &Egress::live(), credential, authority,
//!                        Duration::from_secs(60));
//! # let _ = outcome; Ok(()) }
//! ```
//!
//! Plumbing worth knowing:
//!
//! - **The gate is a keyed chain, not a type (D-R3-1).** [`dispatch`] needs
//!   an [`ExecutionPermit`]; the only constructor is
//!   [`ConsumptionAuthority::authorize`], which needs a [`ConsumedReceipt`],
//!   which needs a receipt the **same** authority admitted. Each link
//!   verifies the previous one's keyed tag, the permit carries the
//!   authority's seal, and `dispatch` re-checks it and claims the single use
//!   in **that authority's** durable [`SpentLedger`]. There is no ledger
//!   argument and no key argument anywhere a caller can reach. (R3's
//!   confirmation authored the receipt JSON, chose the attestation secret,
//!   and supplied a ledger that forgot — all three are gone.)
//! - **The destination is bound at authorization.** The permit carries the
//!   provider binding's own origin and the one-origin egress policy derived
//!   from it, and `dispatch` dials *that* and refuses a plan that names
//!   anything else. [`CallPlan`] is immutable besides (R3-B02).
//! - **The wire is sealed.** The transport trait, the live HTTPS wire, and
//!   the raw response type are all crate-private. The one public egress
//!   value is [`Egress`], it has no method that sends, and the only function
//!   that moves a byte through one is `dispatch` (R3-B02).
//! - **The credential is a type too.** [`Credential`] has no `Serialize`,
//!   no `Clone`, and a redacting `Debug`, so the ways a key usually escapes
//!   — a record serialized into an event, a `{:?}` in a problem detail, a
//!   copy stashed somewhere — cannot leak it. Its one exit, `expose()`, is
//!   crate-private: only the transport's header writer can call it.
//! - **The destination is the binding's, never the worker's.**
//!   [`ModelProfile`] has no endpoint member at all, and the egress
//!   allowlist *is* the binding's own origin
//!   ([`ModelProviderBinding::egress_policy`]).
//! - **Ambiguity is a state, not an exception.** A transport failure after
//!   the first flush is [`EffectState::Ambiguous`]: retry frozen, evidence
//!   recorded, an operator reconciles.
//! - **Where the durable rows live.** This crate is the pure core; the
//!   `model_*` tables and the byom runtime-channel calls are `koveed`'s
//!   (`koveed::model_broker`), because they need the §12.2 command
//!   transaction to be crash-honest.

pub mod attempt;
pub mod binding;
pub mod broker;
pub mod credential;
pub mod disclosure;
pub mod driver;
pub mod egress;
pub mod keying;
pub mod manifest;
pub mod permit;
pub mod transport;

/// The exact `serde_json` this build links, re-exported so
/// `tests/compile_gate.rs` compiles its snippets against **this** crate's own
/// dependency instead of picking one out of a shared target directory. Not
/// part of the supported surface.
#[doc(hidden)]
pub use serde_json;

/// A compile-time fingerprint of this crate's own source and feature set.
///
/// It exists for one reason: `tests/compile_gate.rs` runs `rustc` against a
/// `libkovee_effects-*.rlib` it finds on disk, and a shared target directory
/// can hold several. Picking "the newest" is a guess, and R3's confirmation
/// caught that guess reading a stale artifact and reporting a `Clone` mutant
/// green. The gate now compiles a snippet that asserts this constant equals
/// the value the test binary itself was linked with, so the artifact it reads
/// is provably the one Cargo linked — or the gate refuses to run.
///
/// `the_fingerprint_covers_every_source_file` keeps the list honest.
pub const SOURCE_FINGERPRINT: u64 = {
    let mut h = 0xcbf2_9ce4_8422_2325;
    h = fnv1a(h, include_bytes!("lib.rs"));
    h = fnv1a(h, include_bytes!("attempt.rs"));
    h = fnv1a(h, include_bytes!("binding.rs"));
    h = fnv1a(h, include_bytes!("broker.rs"));
    h = fnv1a(h, include_bytes!("credential.rs"));
    h = fnv1a(h, include_bytes!("disclosure.rs"));
    h = fnv1a(h, include_bytes!("driver.rs"));
    h = fnv1a(h, include_bytes!("egress.rs"));
    h = fnv1a(h, include_bytes!("keying.rs"));
    h = fnv1a(h, include_bytes!("manifest.rs"));
    h = fnv1a(h, include_bytes!("permit.rs"));
    h = fnv1a(h, include_bytes!("transport.rs"));
    // Feature sets change the public surface, so two rlibs from identical
    // source are still different artifacts.
    h = fnv1a(
        h,
        if cfg!(feature = "testing") {
            b"+testing"
        } else {
            b"-testing"
        },
    );
    h
};

/// FNV-1a, because it is four lines of `const fn` and this is an identity
/// check against artifacts on the same disk, not a security boundary.
const fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    hash
}

pub use attempt::{next, EffectEvent, EffectState, TransitionError};
pub use binding::{
    BindingError, CredentialRef, ModelProfile, ModelProviderBinding, ProfileError, ProviderKind,
    RequestLimits, Status,
};
pub use broker::{
    dispatch, external_idempotency_key, host_effect_binding, host_effect_binding_digest, plan,
    BrokerError, CallPlan, Outcome, PlanInput, PlanKeys, DEFAULT_TIMEOUT,
    HOST_EFFECT_BINDING_FIELDS, HOST_EFFECT_BINDING_TAG,
};
pub use credential::{resolve, Credential, CredentialError};
pub use disclosure::{
    DisclosureError, DisclosureItem, DisclosureManifest, ProviderClaims, Transformation,
};
pub use driver::{
    adapter_version, driver_for, AuthScheme, DriverError, ModelDriver, ModelReply, ModelRequest,
    PreparedRequest, Usage, ANTHROPIC, ANTHROPIC_MODEL, ANTHROPIC_VERSION, OPENAI, OPENAI_MODEL,
};
pub use egress::{
    check_origin, check_resolved_address, check_resolved_for, EgressError, EgressPolicy, Origin,
};
pub use keying::{object_key_ref, record_digest, RecordDigestKey};
pub use manifest::{
    ByomSourceFields, ManifestError, ProviderContextManifest, RecordRef, Segment, SegmentKind,
    SourceItem,
};
#[cfg(any(test, feature = "testing"))]
pub use permit::MemorySpentLedger;
pub use permit::{
    Claim, ConsumedReceipt, ConsumptionAuthority, EpisodeFence, ExecutionConsumptionReceipt,
    ExecutionPermit, Expectation, PermitError, SpentLedger, BROKER_DRIVER_AUDIENCE,
    OWNER_PROTOCOL_BYOM, PERMIT_SEAL_TAG, PHASE_PRE_EGRESS, RECEIPT_ADMISSION_TAG,
    RECEIPT_PROVENANCE_TAG,
};
pub use transport::{Egress, PROFILE_HTTPS, PROFILE_RECORDING};
#[cfg(any(test, feature = "testing"))]
pub use transport::{RecordingTransport, SentRequest};

#[cfg(test)]
#[allow(clippy::expect_used)]
mod fingerprint_tests {
    /// The `include_bytes!` list above is written by hand, so a new module
    /// could silently leave the gate identifying the wrong artifact. This
    /// fails the moment `src/` and the list disagree.
    #[test]
    fn the_fingerprint_covers_every_source_file() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let listed = include_str!("lib.rs");
        let mut missing = Vec::new();
        let entries = std::fs::read_dir(&source).expect("read src/");
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".rs") {
                continue;
            }
            if !listed.contains(&format!("include_bytes!(\"{name}\")")) {
                missing.push(name);
            }
        }
        assert!(
            missing.is_empty(),
            "SOURCE_FINGERPRINT does not cover {missing:?}: the compile gate would identify \
             the wrong rlib"
        );
    }
}
