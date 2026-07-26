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
//!  8  authorize(): key, audience, subject, disclosure,
//!     Episode, both fences, incarnation, expiry, spent  permit::authorize
//!  9  origin is https and exactly allowlisted           dispatch()
//! 10  the bytes about to leave match the sealed digest   dispatch()
//! 11  the resolved address is globally routable          transport
//! 12  the attempt is COMMITTED dispatching               koveed
//! ```
//!
//! Only then does the credential get resolved and injected, inside the
//! transport, from a value the worker never had.
//!
//! What you write (the two halves, and the gate is not optional — you
//! cannot call [`dispatch`] without an [`ExecutionPermit`]):
//! ```no_run
//! # use kovee_effects::*;
//! # use std::time::Duration;
//! # fn f(plan: &CallPlan, permit: &ExecutionPermit, transport: &dyn Transport,
//! #      credential: &Credential) {
//! let outcome = dispatch(plan, permit, transport, credential, Duration::from_secs(60));
//! match outcome.state {
//!     EffectState::Completed => { /* reply + usage */ }
//!     EffectState::Failed => { /* nothing was transmitted */ }
//!     EffectState::Ambiguous => { /* frozen; needs reconciliation */ }
//!     _ => unreachable!("dispatch always terminalizes"),
//! }
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
use crate::permit::ExecutionPermit;
use crate::transport::{Transport, TransportError};

/// The byom type tag of Kovee's local effect projection — the preimage of
/// the `host_effect_digest` byom stores and compares on replay.
pub const EFFECT_TAG: &str = "kovee-model-effect-v1";
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
/// for, and nothing that can be changed after.
#[derive(Debug, Clone)]
pub struct CallPlan {
    /// Kovee's local Effect id — the `host_effect_ref` byom binds.
    pub effect_id: String,
    /// byom's kernel-derived one-shot key. Kovee echoes it; it is the
    /// identity the receipt must name.
    pub execution_key: String,
    /// The stable external idempotency key: the same logical call always
    /// derives the same one, so a driver retry cannot duplicate the effect.
    pub external_idempotency_key: String,
    /// byom's authorized subject digest, echoed.
    pub subject_digest: DigestRef,
    /// Kovee's own canonical digest over the local effect projection.
    pub host_effect_digest: DigestRef,
    pub disclosure: DisclosureManifest,
    /// The sealed chain: its last link is the exact bytes below.
    pub context_manifest: ProviderContextManifest,
    pub origin: Origin,
    pub provider_kind: crate::binding::ProviderKind,
    pub model_selector: String,
    pub request: PreparedRequest,
    pub max_output_tokens: u64,
}

impl CallPlan {
    /// The local effect projection whose digest byom stores.
    pub fn projection(&self) -> Value {
        json!({
            "effect_id": self.effect_id,
            "execution_key": self.execution_key,
            "external_idempotency_key": self.external_idempotency_key,
            "subject_digest": self.subject_digest,
            "disclosure_manifest_ref": self.disclosure.disclosure_id,
            "disclosure_digest": self.disclosure.digest,
            "provider_context_id": self.context_manifest.provider_context_id,
            "provider_context_digest": self.context_manifest.digest,
            "final_provider_request_typed_byte_digest":
                self.context_manifest.final_provider_request_typed_byte_digest,
        })
    }
}

/// What the caller asks the broker to plan.
#[derive(Debug, Clone, Copy)]
pub struct PlanInput<'a> {
    pub effect_id: &'a str,
    /// byom's `stable_execution_key` from the prepared `model_egress` act.
    pub execution_key: &'a str,
    /// byom's authorized `subject_digest`, echoed.
    pub subject_digest: &'a DigestRef,
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

    // 4. the disclosure manifest must still verify as authorized — under
    //    its own per-object key, so a tampered or re-keyed record fails.
    disclosure.verify(keys.disclosure)?;

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

    let mut planned = CallPlan {
        effect_id: input.effect_id.to_owned(),
        execution_key: input.execution_key.to_owned(),
        external_idempotency_key: external_idempotency_key(
            input.execution_key,
            &context_manifest.final_provider_request_typed_byte_digest,
        ),
        subject_digest: input.subject_digest.clone(),
        host_effect_digest: DigestRef::portable_public("0".repeat(64)),
        disclosure,
        context_manifest,
        origin: binding.endpoint.clone(),
        provider_kind: binding.provider_kind,
        model_selector: profile.model_selector.clone(),
        request,
        max_output_tokens,
    };
    // The local effect digest byom stores as `host_effect_digest` and
    // compares on a replay. Kovee's own object, so keyed per object.
    planned.host_effect_digest = record_digest(EFFECT_TAG, &planned.projection(), keys.effect)
        .ok_or(BrokerError::Uncanonical)?;
    Ok(planned)
}

/// The three per-object digest keys a plan needs. All `local_erasure_safe`
/// in production: each names a Kovee-owned object whose secret can be
/// destroyed independently (D-R1-2), and each is the class byom's runtime
/// schemas require for that field.
#[derive(Debug, Clone, Copy)]
pub struct PlanKeys<'a> {
    pub disclosure: RecordDigestKey<'a>,
    pub context: RecordDigestKey<'a>,
    pub effect: RecordDigestKey<'a>,
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
/// Taking `&ExecutionPermit` by value-reference is the gate: the permit is
/// minted only by [`crate::permit::authorize`], so there is no way to reach
/// this function without having passed every check in that gate.
///
/// This function always terminalizes. It never retries: an `ambiguous`
/// outcome is frozen for reconciliation.
pub fn dispatch(
    plan: &CallPlan,
    permit: &ExecutionPermit,
    transport: &dyn Transport,
    credential: &Credential,
    timeout: Duration,
) -> Outcome {
    let started = Instant::now();
    let profile = transport.profile();

    // The permit must still be for this exact effect. Cheap, and it closes
    // the gap between `authorize` and here.
    if permit.execution_key != plan.execution_key {
        return Outcome::terminal(
            EffectState::Failed,
            format!(
                "the permit authorizes execution key {:?}, not {:?}",
                permit.execution_key, plan.execution_key
            ),
            started.elapsed(),
            profile,
        );
    }
    if permit.disclosure_digest != plan.disclosure.digest {
        return Outcome::terminal(
            EffectState::Failed,
            "the permit authorizes another disclosure than this plan's".to_owned(),
            started.elapsed(),
            profile,
        );
    }

    // 9. the origin: https and exactly the binding's own allowlist.
    let policy = crate::egress::EgressPolicy::allowing([plan.origin.clone()]);
    if let Err(e) = check_origin(&plan.origin, &policy) {
        return Outcome::terminal(
            EffectState::Failed,
            e.to_string(),
            started.elapsed(),
            profile,
        );
    }

    // 10. the bytes about to leave are the ones the chain sealed and the
    //     permit therefore authorized.
    if let Err(e) = plan.context_manifest.check_bytes(&plan.request.body) {
        return Outcome::terminal(
            EffectState::Failed,
            e.to_string(),
            started.elapsed(),
            profile,
        );
    }

    // 11-13. one exchange, credential injected inside the transport.
    let response = match transport.send(&plan.origin, &plan.request, credential, timeout) {
        Ok(response) => response,
        Err(e @ TransportError::NotSent(_)) => {
            return Outcome::terminal(
                EffectState::Failed,
                e.to_string(),
                started.elapsed(),
                profile,
            );
        }
        Err(e @ TransportError::Uncertain(_)) => {
            // "No receipt observed" is not proof of failure (§16.1).
            return Outcome::terminal(
                EffectState::Ambiguous,
                e.to_string(),
                started.elapsed(),
                profile,
            );
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
    use crate::permit::{BROKER_DRIVER_AUDIENCE, OWNER_PROTOCOL_BYOM, PHASE_PRE_EGRESS};
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
            disclosure: RecordDigestKey::Object {
                key_ref: "kovee-disclosure-object:disc-1",
                secret: &SECRET,
            },
            context: RecordDigestKey::Object {
                key_ref: "kovee-provider-context-object:pcm-1",
                secret: &SECRET,
            },
            effect: RecordDigestKey::Object {
                key_ref: "kovee-model-effect-object:meff-1",
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
            keys().disclosure,
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
            subject_digest: subject,
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

    fn permit_for(plan: &CallPlan) -> ExecutionPermit {
        ExecutionPermit {
            owner_protocol: OWNER_PROTOCOL_BYOM.into(),
            phase: PHASE_PRE_EGRESS.into(),
            owner_endpoint_ref: "byom-endpoint-local".into(),
            owner_intent_ref: "actint-1".into(),
            owner_receipt_ref: "ecr-1".into(),
            owner_receipt_digest: Some(d(0x06)),
            mandate_use_ref: "muse-1".into(),
            execution_key: plan.execution_key.clone(),
            subject_digest: plan.subject_digest.clone(),
            disclosure_digest: plan.disclosure.digest.clone(),
            owner_unverified_digests: Vec::new(),
            driver_audience: BROKER_DRIVER_AUDIENCE.into(),
            episode_ref: Some("ep-1".into()),
            byom_fence_epoch: 7,
            kovee_invocation_fence: 1,
            budget_reservation_set_ref: "rset-1".into(),
            expires_at: "2027-01-15T09:00:00Z".into(),
            max_uses: 1,
        }
    }

    const REPLY: &[u8] = br#"{"id":"msg_01","model":"claude-haiku-4-5-20251001",
        "stop_reason":"end_turn","content":[{"type":"text","text":"OK"}],
        "usage":{"input_tokens":12,"output_tokens":2}}"#;

    #[test]
    fn planning_seals_the_chain_over_the_exact_bytes() {
        let plan = planned();
        plan.context_manifest
            .check_bytes(&plan.request.body)
            .unwrap();
        assert_eq!(plan.origin, ProviderKind::Anthropic.default_origin());
        assert_eq!(plan.model_selector, crate::driver::ANTHROPIC_MODEL);
        // The idempotency key is stable and derived, not random.
        assert_eq!(
            plan.external_idempotency_key,
            planned().external_idempotency_key
        );
        assert!(plan
            .external_idempotency_key
            .starts_with("kovee-model-exec-abc-"));
        // And the local effect digest binds every one of those facts — as
        // Kovee's own object, so keyed per object (the class byom's
        // `execution_permit_consume` requires for `host_effect_digest`).
        assert_eq!(plan.host_effect_digest.class, "local_erasure_safe");
        assert_eq!(
            plan.host_effect_digest.key_ref.as_deref(),
            Some("kovee-model-effect-object:meff-1")
        );
        assert_eq!(plan.host_effect_digest, planned().host_effect_digest);
    }

    #[test]
    fn a_dispatch_completes_and_meters() {
        let plan = planned();
        let permit = permit_for(&plan);
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            &permit,
            &transport,
            &Credential::new("sk-ant-secret"),
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
        assert_eq!(sent.origin, plan.origin);
    }

    #[test]
    fn an_uncertain_transport_failure_is_ambiguous_not_failed() {
        let plan = planned();
        let permit = permit_for(&plan);
        let transport = RecordingTransport::uncertain("connection reset after write");
        let outcome = dispatch(
            &plan,
            &permit,
            &transport,
            &Credential::new("k"),
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Ambiguous);
        assert!(outcome.state.retry_frozen());
        assert!(outcome
            .observation
            .as_deref()
            .unwrap()
            .contains("may have been transmitted"));
    }

    #[test]
    fn a_permit_for_another_effect_stops_the_dispatch_before_egress() {
        let plan = planned();
        let mut permit = permit_for(&plan);
        permit.execution_key = "exec-someone-elses".into();
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            &permit,
            &transport,
            &Credential::new("k"),
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Failed);
        assert_eq!(transport.send_count(), 0, "no byte left");
        // And the same for a permit bound to another disclosure.
        let mut permit = permit_for(&plan);
        permit.disclosure_digest = d(0xdd);
        let transport = RecordingTransport::answering(REPLY);
        assert_eq!(
            dispatch(
                &plan,
                &permit,
                &transport,
                &Credential::new("k"),
                DEFAULT_TIMEOUT
            )
            .state,
            EffectState::Failed
        );
        assert_eq!(transport.send_count(), 0);
    }

    #[test]
    fn a_non_allowlisted_or_plaintext_origin_stops_the_dispatch() {
        let mut plan = planned();
        plan.origin = Origin {
            scheme: "http".into(),
            host: "api.anthropic.com".into(),
            port: 80,
        };
        let permit = permit_for(&plan);
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            &permit,
            &transport,
            &Credential::new("k"),
            DEFAULT_TIMEOUT,
        );
        assert_eq!(outcome.state, EffectState::Failed);
        assert!(outcome.observation.as_deref().unwrap().contains("https"));
        assert_eq!(transport.send_count(), 0);
    }

    #[test]
    fn tampered_bytes_after_sealing_stop_the_dispatch() {
        let mut plan = planned();
        // Something rewrote the request after the permit authorized its
        // digest. The last check before the socket catches it.
        plan.request.body = br#"{"model":"other","max_tokens":1,"messages":[]}"#.to_vec();
        let permit = permit_for(&plan);
        let transport = RecordingTransport::answering(REPLY);
        let outcome = dispatch(
            &plan,
            &permit,
            &transport,
            &Credential::new("k"),
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
        let permit = permit_for(&plan);
        let transport = RecordingTransport::responding(
            401,
            br#"{"error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
        );
        let outcome = dispatch(
            &plan,
            &permit,
            &transport,
            &Credential::new("k"),
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
