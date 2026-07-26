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
//! #      consumed: Option<ConsumedReceipt<'_>>,
//! #      egress: &Egress<'_>, credential: &Credential, keys: PlanKeys,
//! #      ledger: &dyn SpentLedger)
//! #   -> Result<(), Box<dyn std::error::Error>> {
//! // 1. plan: profile re-validated, disclosure verified, provider bytes
//! //    built, and the context chain SEALED over exactly those bytes.
//! let plan = plan(&PlanInput {
//!     effect_id: "meff-1",
//!     execution_key: "exec-abc",       // byom's kernel-derived one-shot key
//!     subject_digest: subject,         // byom's authorized subject, echoed
//!     system: Some("Be brief."), prompt: "Say OK.",
//!     max_output_tokens: 256, classification_ref: "class-public",
//! }, binding, profile, disclosure, chain, keys)?;
//!
//! // 2. …the caller COMMITS the prepared effect, then byom consumes the
//! //    permit for `plan.execution_key()`, and the reply is attested
//! //    against the committed consumption row (ConsumedReceipt)…
//!
//! // 3. gate: the only way to obtain an ExecutionPermit.
//! let permit = authorize(consumed, &Expectation {
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
//! //    permit over — by value, exactly once, against a durable ledger:
//! let outcome = dispatch(&plan, permit, egress, credential, ledger,
//!                        Duration::from_secs(60));
//! # let _ = outcome; Ok(()) }
//! ```
//!
//! Plumbing worth knowing:
//!
//! - **The gate is a type *and* a durable row (D-R3-1).** [`dispatch`] needs
//!   an [`ExecutionPermit`]; the only constructor is [`authorize`], which
//!   itself needs a [`ConsumedReceipt`] — an attestation over the committed
//!   consumption record, minted under the daemon's own keyed secret. The
//!   permit has private fields, no `Clone` and no `Deserialize`, and
//!   `dispatch` takes it **by value**. Because a *value* is never enough on
//!   its own, the single use is also claimed in a durable [`SpentLedger`]
//!   before the socket opens: a second permit for the same consumption sends
//!   nothing. (R3-B01 found the earlier version of this claim false — the
//!   fields were public, the permit was `Clone` + serde, and `dispatch` only
//!   borrowed it, so one permit dispatched twice.)
//! - **The destination is bound at authorization.** The permit carries the
//!   provider binding's own origin and the one-origin egress policy derived
//!   from it, and `dispatch` dials *that* and refuses a plan that names
//!   anything else. [`CallPlan`] is immutable besides (R3-B02).
//! - **The wire is sealed.** `dispatch` takes an [`Egress`], not a
//!   `&dyn Transport`: the live [`HttpsTransport`] the daemon holds, or the
//!   recording double, which exists only under test configuration.
//! - **The credential is a type too.** [`Credential`] has no `Serialize`
//!   and a redacting `Debug`, so the ways a key usually escapes — a record
//!   serialized into an event, a `{:?}` in a problem detail — cannot leak
//!   it. Its one exit, `expose()`, is crate-private: only the transport's
//!   header writer can call it.
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

pub use attempt::{next, EffectEvent, EffectState, TransitionError};
pub use binding::{
    BindingError, CredentialRef, ModelProfile, ModelProviderBinding, ProfileError, ProviderKind,
    RequestLimits, Status,
};
pub use broker::{
    dispatch, external_idempotency_key, plan, BrokerError, CallPlan, Outcome, PlanInput, PlanKeys,
    DEFAULT_TIMEOUT,
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
    authorize, Claim, ConsumedReceipt, EpisodeFence, ExecutionConsumptionReceipt, ExecutionPermit,
    Expectation, PermitError, SpentLedger, BROKER_DRIVER_AUDIENCE, OWNER_PROTOCOL_BYOM,
    PHASE_PRE_EGRESS, RECEIPT_PROVENANCE_TAG,
};
pub use transport::{
    Egress, HttpsTransport, RawResponse, Transport, TransportError, PROFILE_HTTPS,
    PROFILE_RECORDING,
};
#[cfg(any(test, feature = "testing"))]
pub use transport::{RecordingTransport, SentRequest};
