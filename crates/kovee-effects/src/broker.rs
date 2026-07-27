//! The model broker's own logic: plan a call, then dispatch it — with the
//! permit gate between the two and nothing able to skip it.
//!
//! # The enforcement chain
//!
//! Everything below must hold before a byte leaves. Each line is a refusal.
//!
//! ```text
//!  1  the worker's attempt binding is current          (koveed, §15.2)
//!  2  BOTH fences are current                          (koveed, L21)
//!  3  binding + profile active, profile pins the exact
//!     binding revision/digest, limits satisfied        plan()
//!  4  DisclosureManifest complete, incl. training_use  plan()
//!  5  ProviderContextManifest chain built and SEALED
//!     over the exact provider-request bytes            plan()
//!  6  the Effect is COMMITTED prepared, under byom's
//!     stable execution key                             koveed
//!  7  byom's execution_permit_consume returns ONE
//!     ExecutionConsumptionReceipt (max_uses 1)         koveed
//!  8  the authority ADMITTED byom's reply and ATTESTED it,
//!     then authorize(): key, audience, subject,
//!     disclosure, Episode, both fences, incarnation,
//!     expiry, spent                       ConsumptionAuthority::authorize
//!  9  the permit carries THIS authority's keyed seal      dispatch()
//! 10  the plan's origin IS the origin the permit bound   dispatch()
//! 11  that origin is https and exactly allowlisted, by
//!     the policy the PERMIT carries                     dispatch()
//! 12  the bytes about to leave match the sealed digest   dispatch()
//! 13  the attempt is COMMITTED dispatching               koveed
//! 14  the one use is CLAIMED in the authority's durable
//!     ledger                                            dispatch()
//! 15  the resolved address is globally routable          transport
//! ```
//!
//! Only then does the credential get resolved and injected, inside the
//! transport, from a value the worker never had.
//!
//! What you write (the two halves, and the gate is not optional — you cannot
//! call [`dispatch`] without an [`ExecutionPermit`], you hand the permit
//! over rather than lending it, the destination comes from the permit, and
//! the spent ledger comes from the authority rather than from here):
//! ```no_run
//! # use kovee_effects::*;
//! # use std::time::Duration;
//! # fn f(plan: &CallPlan, permit: ExecutionPermit, egress: &Egress<'_>,
//! #      credential: &Credential, authority: &ConsumptionAuthority<'_>) {
//! let outcome = dispatch(plan, permit, egress, credential, authority,
//!                        Duration::from_secs(60));
//! match outcome.state {
//!     EffectState::Completed => { /* reply + usage */ }
//!     EffectState::Failed => { /* nothing was transmitted */ }
//!     EffectState::Ambiguous => { /* frozen; needs reconciliation */ }
//!     _ => unreachable!("dispatch always terminalizes"),
//! }
//! # }
//! ```
//!
//! The permit is consumed **by value**, so a second dispatch with the same
//! one is not a policy violation but a compile error:
//! ```compile_fail,E0382
//! # use kovee_effects::*;
//! # use std::time::Duration;
//! # fn f(plan: &CallPlan, permit: ExecutionPermit, egress: &Egress<'_>,
//! #      credential: &Credential, authority: &ConsumptionAuthority<'_>) {
//! let first = dispatch(plan, permit, egress, credential, authority, Duration::from_secs(60));
//! let second = dispatch(plan, permit, egress, credential, authority, Duration::from_secs(60));
//! # }
//! ```
//! and a ledger of one's own is not a thing `dispatch` accepts at all:
//! ```compile_fail,E0308
//! # use kovee_effects::*;
//! # use std::time::Duration;
//! # fn f(plan: &CallPlan, permit: ExecutionPermit, egress: &Egress<'_>,
//! #      credential: &Credential, ledger: &dyn SpentLedger) {
//! let outcome = dispatch(plan, permit, egress, credential, ledger, Duration::from_secs(60));
//! # }
//! ```

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use kovee_core::canonical::typed_byte_digest;
use kovee_core::family::DigestRef;

use crate::attempt::EffectState;
use crate::binding::{ModelProfile, ModelProviderBinding, ProfileError};
use crate::credential::Credential;
use crate::disclosure::DisclosureManifest;
use crate::driver::{driver_for, DriverError, ModelReply, ModelRequest, PreparedRequest, Usage};
use crate::egress::{check_origin, EgressError, Origin};
use crate::keying::{record_digest, RecordDigestKey};
use crate::manifest::{ManifestError, ProviderContextManifest};
use crate::permit::{Claim, ConsumptionAuthority, ExecutionPermit};
use crate::transport::Egress;

/// **Kovee's `$domain` for the host-effect BINDING fragment** — the preimage
/// of the `host_effect_digest` byom stores, compares on replay, and demands
/// again at `effect_outcome_admit`.
///
/// It is the converse of byom's `bpp-parent-budget-fragment-v0` (R3-L02): a
/// peer-owned digest the other side must verify travels as a frozen
/// `portable_public` fragment whose members that side holds, so the digest is
/// *derived*, not *asserted* (disposition D-R3-3). byom rebuilds this exact
/// preimage — the act facts from its OWN committed ActIntent, the two
/// Kovee-owned members from the request — and refuses a
/// `host_effect_digest` that does not re-derive from it.
///
/// The old preimage was Kovee's whole local effect projection, including its
/// keyed provider-context digest. byom held none of those bytes, so it could
/// only store whatever value it was handed.
pub const HOST_EFFECT_BINDING_TAG: &str = "kovee-host-effect-binding-v1";

/// The frozen member set of that fragment, in canonical order.
///
/// - `intent_ref`, `stable_execution_key`, `context_manifest_ref`,
///   `context_digest`, `disclosure_manifest_ref`, `disclosure_digest` are
///   byom's OWN committed act facts. They are never echoed as request members
///   (A8's converse); byom reads each from its committed ActIntent.
/// - `host_effect_ref` is Kovee's Effect identity, already a request member.
/// - `external_idempotency_key` and `final_provider_request_typed_byte_digest`
///   are Kovee's own, and travel as request members precisely so byom can
///   rebuild the preimage. They are not free: byom re-checks that the
///   idempotency key is exactly
///   `kovee-model-{stable_execution_key}-{byte_digest[..16]}`.
pub const HOST_EFFECT_BINDING_FIELDS: [&str; 9] = [
    "context_digest",
    "context_manifest_ref",
    "disclosure_digest",
    "disclosure_manifest_ref",
    "external_idempotency_key",
    "final_provider_request_typed_byte_digest",
    "host_effect_ref",
    "intent_ref",
    "stable_execution_key",
];
/// The typed-bytes domain of a provider response.
pub const PROVIDER_RESPONSE_DOMAIN: &str = "dev.kovee.provider-response-bytes.v1";

/// The default per-call wall-clock budget.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("model profile: {0}")]
    Profile(#[from] ProfileError),
    #[error("disclosure manifest: {0}")]
    Disclosure(#[from] crate::disclosure::DisclosureError),
    #[error("provider context manifest: {0}")]
    Manifest(#[from] ManifestError),
    #[error("provider driver: {0}")]
    Driver(#[from] DriverError),
    #[error("egress: {0}")]
    Egress(#[from] EgressError),
    #[error("the effect projection could not be canonicalized")]
    Uncanonical,
}

/// One planned model call: everything decided before authority is asked
/// for, and — now literally — nothing that can be changed after.
///
/// Every field is private and there is no public constructor: a plan exists
/// only as [`plan`] returns it, sealed in one step with its own
/// `host_effect_digest` over the whole projection. R3 changed `plan.origin`
/// after the permit was minted and reached the transport (R3-B02); that
/// assignment is now a compile error, and dispatch checks the destination
/// against the permit's bound origin regardless.
///
/// ```compile_fail,E0616
/// # use kovee_effects::{CallPlan, Origin};
/// # fn f(mut plan: CallPlan) {
/// plan.origin = Origin::https("exfil.example", 443);
/// # }
/// ```
#[derive(Debug)]
pub struct CallPlan {
    effect_id: String,
    execution_key: String,
    external_idempotency_key: String,
    subject_digest: DigestRef,
    host_effect_digest: DigestRef,
    /// The exact preimage of `host_effect_digest`: the frozen
    /// `portable_public` fragment byom rebuilds from its own committed act
    /// (R3-L01, D-R3-3).
    host_effect_binding: Value,
    disclosure: DisclosureManifest,
    context_manifest: ProviderContextManifest,
    origin: Origin,
    provider_kind: crate::binding::ProviderKind,
    model_selector: String,
    request: PreparedRequest,
    max_output_tokens: u64,
}

impl CallPlan {
    /// Kovee's local Effect id — the `host_effect_ref` byom binds.
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }
    /// byom's kernel-derived one-shot key. Kovee echoes it; it is the
    /// identity the receipt must name.
    pub fn execution_key(&self) -> &str {
        &self.execution_key
    }
    /// The stable external idempotency key: the same logical call always
    /// derives the same one, so a driver retry cannot duplicate the effect.
    pub fn external_idempotency_key(&self) -> &str {
        &self.external_idempotency_key
    }
    /// byom's authorized subject digest, echoed.
    pub fn subject_digest(&self) -> &DigestRef {
        &self.subject_digest
    }
    /// Kovee's own canonical digest over the local effect projection.
    pub fn host_effect_digest(&self) -> &DigestRef {
        &self.host_effect_digest
    }
    pub fn disclosure(&self) -> &DisclosureManifest {
        &self.disclosure
    }
    /// The sealed chain: its last link is the exact request bytes.
    pub fn context_manifest(&self) -> &ProviderContextManifest {
        &self.context_manifest
    }
    /// The destination, copied from the provider binding when the plan was
    /// sealed. Read-only, and never the last word: the permit's own bound
    /// origin is what dispatch dials.
    pub fn origin(&self) -> &Origin {
        &self.origin
    }
    pub fn provider_kind(&self) -> crate::binding::ProviderKind {
        self.provider_kind
    }
    pub fn model_selector(&self) -> &str {
        &self.model_selector
    }
    pub fn request(&self) -> &PreparedRequest {
        &self.request
    }
    pub fn max_output_tokens(&self) -> u64 {
        self.max_output_tokens
    }

    /// The frozen `portable_public` host-effect binding fragment — the exact
    /// preimage of [`host_effect_digest`](Self::host_effect_digest), which
    /// byom rebuilds from its own committed act (D-R3-3).
    ///
    /// It is published for audit and for the vector that pins the two sides
    /// together; the wire carries only the two Kovee-owned members byom does
    /// not hold, never byom's own committed digests (A8's converse).
    pub fn host_effect_binding(&self) -> &Value {
        &self.host_effect_binding
    }

    /// A plan identical to this one but dialing `origin` — **test-only**, and
    /// the point of it is that it must not help: it is how R3's own probe
    /// (change the destination after authorization) is reproduced against a
    /// type that no longer lets production code do it.
    #[cfg(any(test, feature = "testing"))]
    pub fn probe_with_origin(self, origin: Origin) -> CallPlan {
        CallPlan { origin, ..self }
    }

    /// A plan identical to this one but carrying `body` as the request bytes
    /// — **test-only**, and again the point is that it must not help: the
    /// sealed chain no longer covers those bytes, so dispatch refuses.
    #[cfg(any(test, feature = "testing"))]
    pub fn probe_with_request_body(self, body: Vec<u8>) -> CallPlan {
        let request = PreparedRequest {
            body,
            ..self.request
        };
        CallPlan { request, ..self }
    }
}

/// **The host-effect binding fragment (R3-L01, D-R3-3).**
///
/// Composed here from the parts so [`plan`] seals a `CallPlan` in ONE
/// construction, digest included. Every member is one byom either holds in its
/// committed ActIntent or is handed explicitly, so byom can build the
/// identical preimage and re-derive the digest instead of storing an
/// assertion. [`host_effect_binding_digest`] is the whole of what byom checks.
#[allow(clippy::too_many_arguments)]
pub fn host_effect_binding(
    host_effect_ref: &str,
    intent_ref: &str,
    stable_execution_key: &str,
    context_manifest_ref: &str,
    context_digest: &DigestRef,
    disclosure_manifest_ref: &str,
    disclosure_digest: &DigestRef,
    external_idempotency_key: &str,
    request_byte_digest: &str,
) -> Value {
    json!({
        "context_digest": context_digest,
        "context_manifest_ref": context_manifest_ref,
        "disclosure_digest": disclosure_digest,
        "disclosure_manifest_ref": disclosure_manifest_ref,
        "external_idempotency_key": external_idempotency_key,
        "final_provider_request_typed_byte_digest": request_byte_digest,
        "host_effect_ref": host_effect_ref,
        "intent_ref": intent_ref,
        "stable_execution_key": stable_execution_key,
    })
}

/// The `portable_public` digest of one such fragment. Unkeyed by
/// construction: a cross-boundary digest a counterparty must re-derive can
/// never be keyed (A8).
pub fn host_effect_binding_digest(fragment: &Value) -> Option<DigestRef> {
    record_digest(HOST_EFFECT_BINDING_TAG, fragment, RecordDigestKey::Portable)
}

/// What the caller asks the broker to plan.
#[derive(Debug, Clone, Copy)]
pub struct PlanInput<'a> {
    pub effect_id: &'a str,
    /// byom's `stable_execution_key` from the prepared `model_egress` act.
    pub execution_key: &'a str,
    /// byom's authorizing ActIntent — a member of the binding fragment byom
    /// rebuilds, so the effect digest names the act it was prepared for.
    pub act_intent_ref: &'a str,
    /// byom's authorized `subject_digest`, echoed. It binds the PERMIT (the
    /// receipt names byom's own committed value), and is deliberately not a
    /// member of the binding fragment: byom recomputes it, so a fragment
    /// carrying it would be an owner echo (A8's converse).
    pub subject_digest: &'a DigestRef,
    /// The HOST-owned ContextManifest pair the act's seats assented to, as
    /// byom committed it. Kovee holds it only as byom's value.
    pub context_manifest_ref: &'a str,
    pub context_manifest_digest: &'a DigestRef,
    pub system: Option<&'a str>,
    pub prompt: &'a str,
    pub max_output_tokens: u64,
    /// The classification of everything that leaves; the profile must allow
    /// it (§16.3 "validates … classification … immediately before each use").
    pub classification_ref: &'a str,
}

/// Plans one call: validates the profile against its binding revision,
/// checks classification and limits, builds the provider request bytes, and
/// seals the provider-context chain over exactly those bytes.
///
/// The disclosure manifest and the (unsealed) chain are inputs, because they
/// are what byom's act was prepared against — the plan may not re-derive
/// them, only seal and check.
pub fn plan(
    input: &PlanInput<'_>,
    binding: &ModelProviderBinding,
    profile: &ModelProfile,
    disclosure: DisclosureManifest,
    context_manifest: ProviderContextManifest,
    keys: PlanKeys<'_>,
) -> Result<CallPlan, BrokerError> {
    // 3. binding + profile, re-validated immediately before use.
    profile.check_against(binding)?;
    if !profile
        .allowed_classification_refs
        .iter()
        .any(|c| c == input.classification_ref)
    {
        return Err(BrokerError::Profile(
            ProfileError::ClassificationNotAllowed(input.classification_ref.to_owned()),
        ));
    }
    if !profile
        .allowed_regions
        .contains(&binding.provider_claims.region)
    {
        return Err(BrokerError::Profile(ProfileError::WidenedRegion));
    }
    let max_output_tokens = input.max_output_tokens;
    if max_output_tokens == 0 || max_output_tokens > profile.request_limits.output_tokens {
        return Err(BrokerError::Profile(ProfileError::OverLimit(
            "output_tokens",
        )));
    }
    // A crude but honest input bound: 1 token ≈ 4 bytes is the floor no
    // tokenizer beats, so this refuses only requests that certainly exceed.
    if (input.prompt.len() + input.system.map_or(0, str::len)) as u64 / 4
        > profile.request_limits.input_tokens
    {
        return Err(BrokerError::Profile(ProfileError::OverLimit(
            "input_tokens",
        )));
    }

    // 4. the disclosure manifest must still verify as authorized. Its digest
    //    is the CROSS-BOUNDARY one byom's act pinned, so the check needs no
    //    key and byom performs the identical one (A8).
    disclosure.verify()?;

    // 5. the exact provider request, then the chain sealed over its bytes.
    let driver = driver_for(binding.provider_kind);
    let request = driver.build(&ModelRequest {
        model: &profile.model_selector,
        system: input.system,
        prompt: input.prompt,
        max_output_tokens,
    })?;
    let context_manifest = context_manifest.seal(&request.body, keys.context)?;
    context_manifest.verify(keys.context)?;

    // The effect digest byom stores as `host_effect_digest`, compares on a
    // replay, and demands again at `effect_outcome_admit`: the
    // `portable_public` digest of the FROZEN BINDING FRAGMENT above (A8,
    // D-R3-3). It is derived BEFORE the plan exists, so the plan is sealed in
    // one construction and has no half-built state anyone could observe.
    let external_idempotency_key = external_idempotency_key(
        input.execution_key,
        &context_manifest.final_provider_request_typed_byte_digest,
    );
    let binding_fragment = host_effect_binding(
        input.effect_id,
        input.act_intent_ref,
        input.execution_key,
        input.context_manifest_ref,
        input.context_manifest_digest,
        &disclosure.disclosure_id,
        &disclosure.digest,
        &external_idempotency_key,
        &context_manifest.final_provider_request_typed_byte_digest,
    );
    let host_effect_digest =
        host_effect_binding_digest(&binding_fragment).ok_or(BrokerError::Uncanonical)?;
    Ok(CallPlan {
        effect_id: input.effect_id.to_owned(),
        execution_key: input.execution_key.to_owned(),
        external_idempotency_key,
        subject_digest: input.subject_digest.clone(),
        host_effect_digest,
        host_effect_binding: binding_fragment,
        disclosure,
        context_manifest,
        origin: binding.endpoint.clone(),
        provider_kind: binding.provider_kind,
        model_selector: profile.model_selector.clone(),
        request,
        max_output_tokens,
    })
}

/// The per-object digest key a plan needs.
///
/// Only the provider-context chain is keyed now: it is a purely LOCAL object
/// whose verifiability Kovee erases per object (D-R1-2). The disclosure
/// manifest and the local effect projection both cross the boundary — byom's
/// act pins them and byomd re-derives them — so both are unkeyed
/// `portable_public` and neither takes a secret at all (A8, D-R3-3).
#[derive(Debug, Clone, Copy)]
pub struct PlanKeys<'a> {
    pub context: RecordDigestKey<'a>,
}

/// The stable external idempotency key: byom's one-shot key plus the exact
/// bytes. A driver-level retry of the same call reuses it; a different
/// request is a different effect.
pub fn external_idempotency_key(execution_key: &str, request_digest: &str) -> String {
    format!("kovee-model-{execution_key}-{}", &request_digest[..16])
}

/// The terminal result of one dispatch.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub state: EffectState,
    pub reply: Option<ModelReply>,
    pub usage: Usage,
    /// The typed digest of the exact response bytes, when any arrived.
    pub response_digest: Option<String>,
    pub external_ref: Option<String>,
    /// The observation that justifies this classification (§16.1: a failed
    /// or ambiguous attempt "records the exact observations that justify
    /// that classification").
    pub observation: Option<String>,
    pub latency_ms: u64,
    pub transport_profile: &'static str,
}

impl Outcome {
    fn terminal(
        state: EffectState,
        observation: String,
        latency: Duration,
        transport_profile: &'static str,
    ) -> Outcome {
        Outcome {
            state,
            reply: None,
            usage: Usage::default(),
            response_digest: None,
            external_ref: None,
            observation: Some(observation),
            latency_ms: latency.as_millis().min(u64::MAX as u128) as u64,
            transport_profile,
        }
    }
}

/// Dispatches a planned call under an already-consumed permit.
///
/// Four things make this the gate rather than a convention:
///
/// - the permit is minted only by
///   [`ConsumptionAuthority::authorize`](crate::ConsumptionAuthority::authorize),
///   and is neither `Clone` nor `Deserialize`, so it cannot be forged or
///   copied;
/// - it is taken **by value**, so the caller cannot dispatch twice with it;
/// - it carries the minting authority's keyed **seal**, re-verified here
///   first of all — a permit some other authority minted is refused before
///   anything else is looked at (R3-B01);
/// - the one authorized use is then claimed in **that authority's own
///   durable ledger** before the socket opens. There is no ledger argument:
///   R3's confirmation dispatched a forged permit against a ledger it wrote
///   itself, and that call site no longer exists.
///
/// The destination is the permit's own bound origin, not a field of the plan:
/// a plan whose origin no longer matches what was authorized is refused
/// before any byte leaves (R3-B02).
///
/// This function always terminalizes. It never retries: an `ambiguous`
/// outcome is frozen for reconciliation.
pub fn dispatch(
    plan: &CallPlan,
    permit: ExecutionPermit,
    egress: &Egress<'_>,
    credential: &Credential,
    authority: &ConsumptionAuthority<'_>,
    timeout: Duration,
) -> Outcome {
    let started = Instant::now();
    let profile = egress.profile();

    // 8b. this authority minted this permit. A well-formed permit from
    //     anywhere else is not authority here, and the check is first
    //     because nothing after it means anything otherwise.
    if !authority.sealed(&permit) {
        return Outcome::terminal(
            EffectState::Failed,
            format!(
                "this permit was not sealed by the consumption authority {:?}: it was minted \
                 elsewhere and authorizes nothing here",
                authority.key_ref()
            ),
            started.elapsed(),
            profile,
        );
    }

    // The permit must still be for this exact effect. Cheap, and it closes
    // the gap between `authorize` and here.
    if permit.execution_key() != plan.execution_key {
        return Outcome::terminal(
            EffectState::Failed,
            format!(
                "the permit authorizes execution key {:?}, not {:?}",
                permit.execution_key(),
                plan.execution_key
            ),
            started.elapsed(),
            profile,
        );
    }
    if permit.disclosure_digest() != &plan.disclosure.digest {
        return Outcome::terminal(
            EffectState::Failed,
            "the permit authorizes another disclosure than this plan's".to_owned(),
            started.elapsed(),
            profile,
        );
    }

    // 9. the destination the PERMIT bound at authorization — the provider
    //    binding's own endpoint. The plan is checked against that, never the
    //    other way round, and it is the permit's origin that gets dialed.
    let origin = permit.bound_origin();
    if &plan.origin != origin {
        return Outcome::terminal(
            EffectState::Failed,
            format!(
                "the permit authorizes egress to {origin}, but this plan names {}",
                plan.origin
            ),
            started.elapsed(),
            profile,
        );
    }

    // 10. https, and exactly the allowlist the permit carries.
    if let Err(e) = check_origin(origin, permit.bound_egress_policy()) {
        return Outcome::terminal(
            EffectState::Failed,
            e.to_string(),
            started.elapsed(),
            profile,
        );
    }

    // 11. the bytes about to leave are the ones the chain sealed and the
    //     permit therefore authorized.
    if let Err(e) = plan.context_manifest.check_bytes(&plan.request.body) {
        return Outcome::terminal(
            EffectState::Failed,
            e.to_string(),
            started.elapsed(),
            profile,
        );
    }

    // 13. the one use, claimed durably BEFORE the socket opens, in the
    //     ledger the AUTHORITY owns. A permit value is not the authority;
    //     this row is.
    match authority.claim_single_use(&permit) {
        Ok(Claim::Claimed) => {}
        Ok(Claim::AlreadySpent) => {
            return Outcome::terminal(
                EffectState::Failed,
                format!(
                    "this one-shot permit's use is already spent (consumption {}); a new \
                     attempt needs a new byom act",
                    permit.consumption_ref()
                ),
                started.elapsed(),
                profile,
            );
        }
        Err(e) => {
            // A use that cannot be recorded is a use that does not happen.
            return Outcome::terminal(
                EffectState::Failed,
                format!("the permit's single use could not be claimed durably: {e}"),
                started.elapsed(),
                profile,
            );
        }
    }

    // 14. one exchange, credential injected inside the transport.
    let response = match egress
        .transport()
        .send(origin, &plan.request, credential, timeout)
    {
        Ok(response) => response,
        Err(e) => {
            // "No receipt observed" is not proof of failure (§16.1): a
            // failure from the first flush onward may still have been
            // received and billed, so it freezes as `ambiguous` rather than
            // being written off as `failed`.
            let state = if e.is_uncertain() {
                EffectState::Ambiguous
            } else {
                EffectState::Failed
            };
            return Outcome::terminal(state, e.to_string(), started.elapsed(), profile);
        }
    };
    let latency = started.elapsed();
    let response_digest =
        typed_byte_digest(PROVIDER_RESPONSE_DOMAIN, "application/json", &response.body);
    let driver = driver_for(plan.provider_kind);
    match driver.parse(response.status, &response.body) {
        Ok(reply) => Outcome {
            state: EffectState::Completed,
            usage: reply.usage,
            response_digest: Some(response_digest),
            external_ref: reply.external_ref.clone(),
            observation: None,
            latency_ms: latency.as_millis().min(u64::MAX as u128) as u64,
            transport_profile: profile,
            reply: Some(reply),
        },
        Err(e) => {
            // The provider answered, so the disclosure DID happen and the
            // call may have been billed — but the outcome is definite, so
            // this is `failed`, not `ambiguous`: a retry needs new authority
            // either way, and the response digest records what was observed.
            Outcome {
                state: EffectState::Failed,
                reply: None,
                usage: Usage::default(),
                response_digest: Some(response_digest),
                external_ref: None,
                observation: Some(e.to_string()),
                latency_ms: latency.as_millis().min(u64::MAX as u128) as u64,
                transport_profile: profile,
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::binding::{ProviderKind, RequestLimits, Status};
    use crate::disclosure::{DisclosureItem, ProviderClaims};
    use crate::manifest::{ByomSourceFields, Segment, SegmentKind};
    use crate::permit::{
        EpisodeFence, Expectation, MemorySpentLedger, SpentLedger, BROKER_DRIVER_AUDIENCE,
    };
    use crate::transport::RecordingTransport;

    fn d(b: u8) -> DigestRef {
        DigestRef::portable_public(format!("{b:02x}").repeat(32))
    }

    fn claims() -> ProviderClaims {
        ProviderClaims {
            region: "us".into(),
            retention: "30-days".into(),
            training_use: "prohibited".into(),
        }
    }

    fn binding() -> ModelProviderBinding {
        ModelProviderBinding::new(
            "mpb-1",
            "realm-personal",
            ProviderKind::Anthropic,
            ProviderKind::Anthropic.default_origin(),
            claims(),
            "env:ANTHROPIC_API_KEY",
            "terms-1",
        )
        .unwrap()
    }

    fn profile(binding: &ModelProviderBinding) -> ModelProfile {
        ModelProfile::new(
            "mp-1",
            binding,
            crate::driver::ANTHROPIC_MODEL,
            RequestLimits {
                input_tokens: 40_000,
                output_tokens: 1_024,
                calls: 1,
            },
        )
        .unwrap()
    }

    const SECRET: [u8; 32] = [7u8; 32];

    fn keys() -> PlanKeys<'static> {
        PlanKeys {
            context: RecordDigestKey::Object {
                key_ref: "kovee-provider-context-object:pcm-1",
                secret: &SECRET,
            },
        }
    }

    fn disclosure() -> DisclosureManifest {
        DisclosureManifest::model_egress(
            "disc-1",
            "realm-personal",
            Some("proj-1"),
            Some("space-1"),
            "model-profile:mp-1",
            "purpose-review",
            &["collaboration_item"],
            vec![DisclosureItem {
                ref_: "contrib-1".into(),
                revision: Some(1),
                digest: d(0xb1),
                size: 12,
            }],
            Vec::new(),
            claims(),
            "2027-01-15T08:00:00Z",
        )
        .unwrap()
    }

    fn chain(
        disclosure: &DisclosureManifest,
        b: &ModelProviderBinding,
        p: &ModelProfile,
    ) -> ProviderContextManifest {
        ProviderContextManifest::build(
            "pcm-1",
            "inv-1",
            "att-1",
            1,
            Some(ByomSourceFields::example()),
            vec![
                Segment::new(
                    SegmentKind::SystemInstruction,
                    "sys-1",
                    1,
                    d(1),
                    "class-public",
                ),
                Segment::new(
                    SegmentKind::CollaborationItem,
                    "contrib-1",
                    1,
                    d(2),
                    "class-public",
                ),
            ],
            (&b.model_provider_binding_id, b.revision, b.digest.clone()),
            (&p.model_profile_id, p.revision, p.digest.clone()),
            &p.adapter_version,
            &disclosure.disclosure_id,
            disclosure.digest.clone(),
            "authdep-1",
            d(0x44),
            "2027-01-15T08:00:00Z",
            keys().context,
        )
        .unwrap()
    }

    fn input<'a>(subject: &'a DigestRef) -> PlanInput<'a> {
        PlanInput {
            effect_id: "meff-1",
            execution_key: "exec-abc",
            act_intent_ref: "actint-1",
            subject_digest: subject,
            context_manifest_ref: "ctxman-1",
            context_manifest_digest: subject,
            system: Some("Be brief."),
            prompt: "Say OK.",
            max_output_tokens: 16,
            classification_ref: "class-public",
        }
    }

    fn planned() -> CallPlan {
        let b = binding();
        let p = profile(&b);
        let disc = disclosure();
        let chain = chain(&disc, &b, &p);
        let subject = d(0x03);
        plan(&input(&subject), &b, &p, disc, chain, keys()).unwrap()
    }

    const REPLY: &[u8] = br#"{"id":"msg_01","model":"claude-haiku-4-5-20251001",
        "stop_reason":"end_turn","content":[{"type":"text","text":"OK"}],
        "usage":{"input_tokens":12,"output_tokens":2}}"#;

    /// The daemon's authority over an in-memory ledger, as every test here
    /// needs one: `authorize` and `dispatch` must be the same authority, or
    /// the seal refuses.
    fn authority(ledger: &dyn SpentLedger) -> crate::permit::ConsumptionAuthority<'_> {
        crate::permit::fixture::authority(ledger)
    }

    /// The permit for this plan, minted the ONLY way one can be: byom's reply
    /// JSON → the authority's `admit` → its keyed attestation over the
    /// committed consumption → its `authorize`. There is no literal to write
    /// here any more, and no key to choose, which is the point of R3-B01.
    fn permit_for(authority: &ConsumptionAuthority<'_>, plan: &CallPlan) -> ExecutionPermit {
        gate(
            authority,
            plan,
            plan.execution_key(),
            &plan.disclosure().digest,
            plan.origin().clone(),
            crate::permit::fixture::CONSUMPTION,
        )
    }

    /// The same gate, with each bound value chooseable — so a test can hold a
    /// permit that authorizes another key, another disclosure, another
    /// destination or another consumption row, without ever writing a permit
    /// field.
    fn gate(
        authority: &ConsumptionAuthority<'_>,
        plan: &CallPlan,
        execution_key: &str,
        disclosure_digest: &DigestRef,
        bound_origin: Origin,
        consumption: &str,
    ) -> ExecutionPermit {
        use crate::permit::fixture;
        let fence = fixture::digest(0x05);
        let reply = fixture::reply(
            execution_key,
            plan.subject_digest(),
            disclosure_digest,
            &fence,
        );
        let receipt = authority.admit(&reply).unwrap();
        let consumed = authority.attest(&receipt, consumption).unwrap();
        authority
            .authorize(
                Some(consumed),
                &Expectation {
                    execution_key,
                    subject_digest: plan.subject_digest(),
                    disclosure_digest,
                    driver_audience: BROKER_DRIVER_AUDIENCE,
                    episode: Some(EpisodeFence {
                        episode_ref: "ep-1",
                        fence_digest: &fence,
                        byom_fence_epoch: 7,
                        kovee_invocation_fence: 1,
                    }),
                    endpoint_incarnation: "inst-1",
                    recovery_epoch: 0,
                    now: 1_800_000_000,
                    already_spent: false,
                    bound_origin: &bound_origin,
                },
            )
            .unwrap()
    }

    /// A ledger that fails rather than answering: a use that cannot be
    /// recorded is a use that does not happen.
    struct BrokenLedger;
    impl crate::sealed::LedgerSeal for BrokenLedger {}
    impl SpentLedger for BrokenLedger {
        fn claim_single_use(&self, _permit: &ExecutionPermit) -> Result<Claim, String> {
            Err("the consumption row is unwritable".to_owned())
        }
    }

    /// The daemon's ledger as koveed's really is: one conditional `UPDATE` on
    /// a row that a real byom consumption created. A permit naming no such
    /// row claims nothing — which is what makes the durable ledger, and not
    /// the permit value, the thing that authorizes egress.
    struct RowLedger {
        unspent: std::sync::Mutex<Vec<String>>,
        consulted: std::sync::atomic::AtomicUsize,
    }

    impl RowLedger {
        /// The daemon's table, holding exactly the consumptions byom really
        /// granted.
        fn holding(rows: &[&str]) -> RowLedger {
            RowLedger {
                unspent: std::sync::Mutex::new(rows.iter().map(|r| (*r).to_owned()).collect()),
                consulted: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn consulted(&self) -> usize {
            self.consulted.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl crate::sealed::LedgerSeal for RowLedger {}
    impl SpentLedger for RowLedger {
        fn claim_single_use(&self, permit: &ExecutionPermit) -> Result<Claim, String> {
            self.consulted
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut unspent = self.unspent.lock().map_err(|e| e.to_string())?;
            match unspent.iter().position(|r| r == permit.consumption_ref()) {
                Some(row) => {
                    unspent.remove(row);
                    Ok(Claim::Claimed)
                }
                None => Ok(Claim::AlreadySpent),
            }
        }
    }

    #[test]
    fn planning_seals_the_chain_over_the_exact_bytes() {
        let plan = planned();
        plan.context_manifest()
            .check_bytes(&plan.request().body)
            .unwrap();
        assert_eq!(plan.origin(), &ProviderKind::Anthropic.default_origin());
        assert_eq!(plan.model_selector(), crate::driver::ANTHROPIC_MODEL);
        // The idempotency key is stable and derived, not random.
        assert_eq!(
            plan.external_idempotency_key(),
            planned().external_idempotency_key()
        );
        assert!(plan
            .external_idempotency_key()
            .starts_with("kovee-model-exec-abc-"));
        // And the local effect digest binds every one of those facts — as the
        // CROSS-BOUNDARY fragment byom pins at consumption and demands again
        // at `effect_outcome_admit`, so unkeyed `portable_public` (A8).
        assert_eq!(plan.host_effect_digest().class, "portable_public");
        assert_eq!(plan.host_effect_digest().algorithm, "sha-256");
        assert!(plan.host_effect_digest().key_ref.is_none());
        assert_eq!(plan.host_effect_digest(), planned().host_effect_digest());
        // The plan is sealed in one construction: its digest covers the
        // BINDING FRAGMENT it reports, with no window where the two disagree,
        // and that fragment is exactly the frozen member set byom rebuilds.
        assert_eq!(
            host_effect_binding_digest(plan.host_effect_binding()).unwrap(),
            *plan.host_effect_digest()
        );
        let mut members: Vec<&str> = plan
            .host_effect_binding()
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        members.sort_unstable();
        let mut frozen = HOST_EFFECT_BINDING_FIELDS.to_vec();
        frozen.sort_unstable();
        assert_eq!(members, frozen);
    }

    #[test]
    fn a_dispatch_completes_and_meters() {
        let plan = planned();
        let transport = RecordingTransport::answering(REPLY);
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let permit = permit_for(&authority, &plan);
        let outcome = dispatch(
            &plan,
            permit,
            &Egress::recording(&transport),
            &Credential::new("sk-ant-secret"),
            &authority,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Completed);
        assert_eq!(outcome.reply.as_ref().unwrap().text, "OK");
        assert_eq!(outcome.usage.input_tokens, 12);
        assert_eq!(outcome.usage.output_tokens, 2);
        assert_eq!(outcome.external_ref.as_deref(), Some("msg_01"));
        assert_eq!(outcome.response_digest.as_ref().unwrap().len(), 64);
        assert_eq!(
            outcome.transport_profile,
            crate::transport::PROFILE_RECORDING
        );
        assert_eq!(transport.send_count(), 1);
        // The credential reached the wire and only the wire.
        let sent = transport.sent().pop().unwrap();
        assert_eq!(sent.header("x-api-key"), Some("sk-ant-secret"));
        assert_eq!(&sent.origin, plan.origin());
    }

    // R3's own probe (R3-B01): dispatch twice under one consumption. R3 held
    // ONE permit and dispatched twice, recording two sends. The permit is now
    // consumed by value, so the literal repeat is a compile error (see the
    // module doc); this is the strictly harder case — two permit VALUES for
    // the one receipt, which is what a caller could still contrive.
    #[test]
    fn a_second_dispatch_under_one_consumption_sends_nothing() {
        let plan = planned();
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let first = permit_for(&authority, &plan);
        let second = permit_for(&authority, &plan);
        assert_eq!(first.consumption_ref(), second.consumption_ref());
        let transport = RecordingTransport::answering(REPLY);
        let one = dispatch(
            &plan,
            first,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &authority,
            DEFAULT_TIMEOUT,
        );
        let two = dispatch(
            &plan,
            second,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &authority,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(one.state, EffectState::Completed);
        assert_eq!(
            two.state,
            EffectState::Failed,
            "a one-shot permit authorizes exactly one dispatch"
        );
        assert!(two
            .observation
            .as_deref()
            .unwrap_or_default()
            .contains("already spent"));
        assert_eq!(transport.send_count(), 1, "exactly one request left");
    }

    // R3's own probe (R3-B02): change the destination AFTER the permit exists.
    // Production code cannot do this at all now — `CallPlan.origin` is private
    // — so the probe uses the test-only rebuild, and the permit's own bound
    // origin refuses it anyway.
    #[test]
    fn an_origin_changed_after_authorization_sends_nothing() {
        let plan = planned();
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let permit = permit_for(&authority, &plan);
        let moved = planned().probe_with_origin(Origin::https("exfil.example", 443));
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &moved,
            permit,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &authority,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Failed);
        let observation = outcome.observation.unwrap_or_default();
        assert!(
            observation.contains("api.anthropic.com") && observation.contains("exfil.example"),
            "{observation}"
        );
        assert_eq!(transport.send_count(), 0, "not one byte left");
        // And the use was NOT claimed: a refused dispatch does not burn the
        // permit, so the real destination can still be served.
        assert_eq!(
            ledger
                .claim_single_use(&permit_for(&authority, &plan))
                .unwrap(),
            crate::permit::Claim::Claimed
        );
    }

    // R3's confirmation held a permit it minted itself. A permit is now
    // SEALED to the authority that minted it, so one made anywhere else —
    // however well formed, however opaque — buys nothing here.
    #[test]
    fn a_permit_sealed_by_another_authority_sends_nothing() {
        let plan = planned();
        let ledger = MemorySpentLedger::default();
        let daemon = authority(&ledger);
        // A second authority: another secret, and a ledger that forgets.
        let forgetful = MemorySpentLedger::default();
        let elsewhere = crate::permit::ConsumptionAuthority::new(
            "kovee-consumption-object:mine",
            [0xffu8; 32],
            &forgetful,
        );
        let theirs = permit_for(&elsewhere, &plan);
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            theirs,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &daemon,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Failed);
        assert!(
            outcome
                .observation
                .as_deref()
                .unwrap_or_default()
                .contains("was not sealed by the consumption authority"),
            "{:?}",
            outcome.observation
        );
        assert_eq!(transport.send_count(), 0, "not one byte left");
        // And the daemon's own ledger never saw the use at all.
        assert_eq!(
            ledger
                .claim_single_use(&permit_for(&daemon, &plan))
                .unwrap(),
            crate::permit::Claim::Claimed
        );
    }

    /// The seal is over the permit's own recorded projection, and `dispatch`
    /// is where that matters: a permit this authority really did mint, with
    /// one member rewritten afterwards, is refused **by the seal** — before
    /// the execution-key check that would otherwise have caught this one.
    ///
    /// Without this, "sealed" only ever meant "keyed by the same secret":
    /// R3's confirmation replaced both seal computations with an HMAC over a
    /// constant and every test here stayed green.
    #[test]
    fn a_permit_altered_after_it_was_sealed_sends_nothing() {
        let plan = planned();
        let ledger = MemorySpentLedger::default();
        let daemon = authority(&ledger);
        for member in ExecutionPermit::SEALED_MEMBERS {
            let mut permit = permit_for(&daemon, &plan);
            permit.tamper(member);
            let transport = RecordingTransport::answering(REPLY);
            let outcome = dispatch(
                &plan,
                permit,
                &Egress::recording(&transport),
                &Credential::new("k"),
                &daemon,
                DEFAULT_TIMEOUT,
            );
            assert_eq!(outcome.state, EffectState::Failed, "{member}");
            assert!(
                outcome
                    .observation
                    .as_deref()
                    .unwrap_or_default()
                    .contains("was not sealed by the consumption authority"),
                "{member} was rewritten after authorization and the seal did not \
                 notice: {:?}",
                outcome.observation
            );
            assert_eq!(transport.send_count(), 0, "{member}: not one byte left");
        }
    }

    /// R3-B01, the hard half: a permit from an authority of one's own, where
    /// "one's own" is as close to the daemon's as key material can get.
    ///
    /// The old adversary probe handed the forged permit to an authority with
    /// a *different* secret, so it only ever proved that two keys differ.
    /// This forger shares the daemon's `key_ref` and secret — the seal cannot
    /// tell them apart, and does not — and differs in what R3's confirmation
    /// actually chose: its own receipt, its own consumption row, and a ledger
    /// that forgets. It is the daemon's **durable ledger** that refuses it,
    /// because the row it names is not a consumption byom ever granted.
    #[test]
    fn a_permit_from_an_authority_of_ones_own_sends_nothing() {
        let plan = planned();
        // The daemon's table: exactly the one row a real byom consumption
        // created for this effect.
        let rows = RowLedger::holding(&[crate::permit::fixture::CONSUMPTION]);
        let daemon = authority(&rows);
        // The forger: the daemon's own key material, its own row, its own
        // ledger that always says "first use".
        let forgetful = MemorySpentLedger::default();
        let forger = authority(&forgetful);
        let forged = gate(
            &forger,
            &plan,
            plan.execution_key(),
            &plan.disclosure().digest,
            plan.origin().clone(),
            "eac-forged",
        );
        assert!(
            daemon.sealed(&forged),
            "the premise: identical key material seals identically, so the \
             refusal below is not a key mismatch"
        );

        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            forged,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &daemon,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Failed);
        assert!(
            outcome
                .observation
                .as_deref()
                .unwrap_or_default()
                .contains("already spent"),
            "the daemon's own row is what refuses it: {:?}",
            outcome.observation
        );
        assert_eq!(transport.send_count(), 0, "not one byte left");
        assert_eq!(
            rows.consulted(),
            1,
            "the DAEMON's ledger was consulted, not the forger's"
        );
        // The forger's permissive ledger was never asked: `dispatch` takes the
        // authority, and a ledger is not something a call site supplies.
        assert_eq!(
            forgetful
                .claim_single_use(&permit_for(&forger, &plan))
                .unwrap(),
            crate::permit::Claim::Claimed
        );
        // And the real row is untouched, so the lawful call still works.
        let lawful = permit_for(&daemon, &plan);
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            lawful,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &daemon,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Completed);
        assert_eq!(transport.send_count(), 1);
    }

    #[test]
    fn an_uncertain_transport_failure_is_ambiguous_not_failed() {
        let plan = planned();
        let transport = RecordingTransport::uncertain("connection reset after write");
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let permit = permit_for(&authority, &plan);
        let outcome = dispatch(
            &plan,
            permit,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &authority,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Ambiguous);
        assert!(outcome.state.retry_frozen());
        assert!(outcome
            .observation
            .as_deref()
            .unwrap()
            .contains("may have been transmitted"));
        // The use is spent: bytes may have left, so no second attempt on this
        // authority — the ledger says so even though nothing was confirmed.
        assert_eq!(
            ledger
                .claim_single_use(&permit_for(&authority, &plan))
                .unwrap(),
            crate::permit::Claim::AlreadySpent
        );
    }

    #[test]
    fn a_ledger_that_cannot_record_the_use_refuses_the_dispatch() {
        let plan = planned();
        let authority = authority(&BrokenLedger);
        let permit = permit_for(&authority, &plan);
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            permit,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &authority,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Failed);
        assert!(outcome
            .observation
            .as_deref()
            .unwrap_or_default()
            .contains("could not be claimed durably"));
        assert_eq!(transport.send_count(), 0);
    }

    #[test]
    fn a_permit_for_another_effect_stops_the_dispatch_before_egress() {
        let plan = planned();
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        // A permit minted for another execution key.
        let elsewhere = gate(
            &authority,
            &plan,
            "exec-someone-elses",
            &plan.disclosure().digest,
            plan.origin().clone(),
            crate::permit::fixture::CONSUMPTION,
        );
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            elsewhere,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &authority,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Failed);
        assert_eq!(transport.send_count(), 0, "no byte left");
        // And the same for a permit bound to another disclosure.
        let other_disclosure = gate(
            &authority,
            &plan,
            plan.execution_key(),
            &d(0xdd),
            plan.origin().clone(),
            crate::permit::fixture::CONSUMPTION,
        );
        let transport = RecordingTransport::answering(REPLY);
        assert_eq!(
            dispatch(
                &plan,
                other_disclosure,
                &Egress::recording(&transport),
                &Credential::new("k"),
                &authority,
                DEFAULT_TIMEOUT
            )
            .state,
            EffectState::Failed
        );
        assert_eq!(transport.send_count(), 0);
    }

    #[test]
    fn a_plaintext_origin_stops_the_dispatch_even_when_the_permit_bound_it() {
        let plaintext = Origin {
            scheme: "http".into(),
            host: "api.anthropic.com".into(),
            port: 80,
        };
        let plan = planned().probe_with_origin(plaintext.clone());
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let permit = gate(
            &authority,
            &plan,
            plan.execution_key(),
            &plan.disclosure().digest,
            plaintext,
            crate::permit::fixture::CONSUMPTION,
        );
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            permit,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &authority,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Failed);
        assert!(outcome.observation.as_deref().unwrap().contains("https"));
        assert_eq!(transport.send_count(), 0);
    }

    #[test]
    fn tampered_bytes_after_sealing_stop_the_dispatch() {
        // Something rewrote the request after the permit authorized its
        // digest. The last check before the socket catches it.
        let plan = planned()
            .probe_with_request_body(br#"{"model":"other","max_tokens":1,"messages":[]}"#.to_vec());
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let permit = permit_for(&authority, &plan);
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            permit,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &authority,
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Failed);
        assert!(outcome
            .observation
            .as_deref()
            .unwrap()
            .contains("does not match"));
        assert_eq!(transport.send_count(), 0);
    }

    #[test]
    fn a_provider_error_is_a_definite_failure_with_the_response_digest() {
        let plan = planned();
        let ledger = MemorySpentLedger::default();
        let authority = authority(&ledger);
        let permit = permit_for(&authority, &plan);
        let transport = RecordingTransport::responding(
            401,
            br#"{"error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
        );
        let outcome = dispatch(
            &plan,
            permit,
            &Egress::recording(&transport),
            &Credential::new("k"),
            &authority,
            DEFAULT_TIMEOUT,
        );
        // The provider answered definitely, so this is `failed`, not
        // `ambiguous` — and the response digest records what was observed.
        assert_eq!(outcome.state, EffectState::Failed);
        assert!(!outcome.state.retry_frozen());
        assert_eq!(outcome.response_digest.as_ref().unwrap().len(), 64);
        assert!(outcome.observation.as_deref().unwrap().contains("HTTP 401"));
        // The request DID leave: the disclosure happened.
        assert_eq!(transport.send_count(), 1);
    }

    #[test]
    fn a_disabled_binding_or_disallowed_classification_never_gets_planned() {
        let b = binding();
        let p = profile(&b);
        let subject = d(0x03);
        let disabled = b.clone().disabled().unwrap();
        assert!(matches!(
            plan(
                &input(&subject),
                &disabled,
                &p,
                disclosure(),
                chain(&disclosure(), &b, &p),
                keys()
            ),
            Err(BrokerError::Profile(ProfileError::BindingDisabled))
        ));
        let mut wrong_class = input(&subject);
        wrong_class.classification_ref = "class-secret";
        assert!(matches!(
            plan(
                &wrong_class,
                &b,
                &p,
                disclosure(),
                chain(&disclosure(), &b, &p),
                keys()
            ),
            Err(BrokerError::Profile(
                ProfileError::ClassificationNotAllowed(_)
            ))
        ));
        let mut disabled_profile = p.clone();
        disabled_profile.status = Status::Disabled;
        assert!(matches!(
            plan(
                &input(&subject),
                &b,
                &disabled_profile,
                disclosure(),
                chain(&disclosure(), &b, &p),
                keys()
            ),
            Err(BrokerError::Profile(ProfileError::ProfileDisabled))
        ));
    }

    #[test]
    fn a_request_over_the_profiles_limits_never_gets_planned() {
        let b = binding();
        let p = profile(&b);
        let subject = d(0x03);
        let mut over_output = input(&subject);
        over_output.max_output_tokens = 100_000;
        assert!(matches!(
            plan(
                &over_output,
                &b,
                &p,
                disclosure(),
                chain(&disclosure(), &b, &p),
                keys()
            ),
            Err(BrokerError::Profile(ProfileError::OverLimit(
                "output_tokens"
            )))
        ));
        let huge = "x".repeat(400_000);
        let mut over_input = input(&subject);
        over_input.prompt = &huge;
        assert!(matches!(
            plan(
                &over_input,
                &b,
                &p,
                disclosure(),
                chain(&disclosure(), &b, &p),
                keys()
            ),
            Err(BrokerError::Profile(ProfileError::OverLimit(
                "input_tokens"
            )))
        ));
    }

    #[test]
    fn a_tampered_disclosure_never_gets_planned() {
        let b = binding();
        let p = profile(&b);
        let subject = d(0x03);
        let mut tampered = disclosure();
        tampered.provider_claims.training_use = "permitted".into();
        assert!(matches!(
            plan(
                &input(&subject),
                &b,
                &p,
                tampered,
                chain(&disclosure(), &b, &p),
                keys()
            ),
            Err(BrokerError::Disclosure(_))
        ));
    }
}
