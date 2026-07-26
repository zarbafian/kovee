//! The §16.3 revisioned broker records: `ModelProviderBinding` and
//! `ModelProfile`.
//!
//! The shape of the trust boundary, in one sentence: the **binding** owns
//! the endpoint, the account, the region, the transport, the provider
//! terms, and the credential *reference*; a **profile** selects one exact
//! binding revision and digest and may narrow it — never override the
//! endpoint, account, region, transport, or terms.
//!
//! `credential_secret_ref` is a *reference*. There is no field anywhere in
//! these records, in an event, or in a portable manifest that can hold key
//! material, and [`CredentialRef`] resolves only inside the broker
//! ([`crate::credential`]).
//!
//! What you write:
//! ```
//! use kovee_effects::{ModelProfile, ModelProviderBinding, ProviderKind, RequestLimits};
//! use kovee_effects::{Origin, ProviderClaims};
//! let binding = ModelProviderBinding::new(
//!     "mpb-anthropic-1", "realm-personal", ProviderKind::Anthropic,
//!     Origin::https("api.anthropic.com", 443),
//!     ProviderClaims { region: "us".into(), retention: "30-days".into(),
//!                      training_use: "prohibited".into() },
//!     "env:ANTHROPIC_API_KEY", "terms-anthropic-2025-01",
//! ).unwrap();
//! let profile = ModelProfile::new(
//!     "mp-anthropic-1", &binding, "claude-haiku-4-5-20251001",
//!     RequestLimits { input_tokens: 40_000, output_tokens: 2_048, calls: 1 },
//! ).unwrap();
//! assert_eq!(profile.provider_binding_digest, binding.digest);
//! // A profile cannot even name another endpoint: it has no such field.
//! assert!(serde_json::to_value(&profile).unwrap().get("endpoint").is_none());
//! ```

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use kovee_core::family::{tagged_canonical, DigestRef};

use crate::disclosure::ProviderClaims;
use crate::egress::{EgressPolicy, Origin};

pub const BINDING_TAG: &str = "kovee-model-provider-binding-v1";
pub const PROFILE_TAG: &str = "kovee-model-profile-v1";

/// The provider kinds this broker has a narrow driver for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Anthropic's Messages API (`POST /v1/messages`).
    Anthropic,
    /// OpenAI's chat-completions API (`POST /v1/chat/completions`).
    Openai,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::Anthropic => "anthropic",
            ProviderKind::Openai => "openai",
        }
    }

    #[allow(clippy::should_implement_trait)] // a fallible Option helper, not FromStr.
    pub fn from_str(s: &str) -> Option<ProviderKind> {
        Some(match s {
            "anthropic" => ProviderKind::Anthropic,
            "openai" => ProviderKind::Openai,
            _ => return None,
        })
    }

    /// The default public origin of this provider. It is a *default for the
    /// operator to record*, not a fallback the broker reaches for: egress
    /// dials the binding's own origin, which is also its allowlist.
    pub fn default_origin(self) -> Origin {
        match self {
            ProviderKind::Anthropic => Origin::https("api.anthropic.com", 443),
            ProviderKind::Openai => Origin::https("api.openai.com", 443),
        }
    }
}

/// `active | disabled` (§16.3). Disabling blocks new egress without
/// rewriting old receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,
    Disabled,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Active => "active",
            Status::Disabled => "disabled",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Status> {
        Some(match s {
            "active" => Status::Active,
            "disabled" => Status::Disabled,
            _ => return None,
        })
    }
}

/// A reference to the credential — never the credential. `env:NAME` reads
/// the daemon's own environment; `store:REF` reads the daemon's secret
/// table. Both resolve inside the broker and nowhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialRef {
    Env(String),
    Store(String),
}

impl CredentialRef {
    pub fn parse(text: &str) -> Option<CredentialRef> {
        if let Some(name) = text.strip_prefix("env:") {
            (!name.is_empty()).then(|| CredentialRef::Env(name.to_owned()))
        } else if let Some(reference) = text.strip_prefix("store:") {
            (!reference.is_empty()).then(|| CredentialRef::Store(reference.to_owned()))
        } else {
            None
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("the provider claims are incomplete: region, retention and training_use are required")]
    IncompleteClaims,
    #[error("the credential reference {0:?} is not an `env:NAME` or `store:REF` reference")]
    BadCredentialRef(String),
    #[error("model egress is https only; {0} is not")]
    NotHttps(String),
    #[error("model_selector is required: a profile names one exact model")]
    NoModel,
    #[error("request limits must be positive")]
    ZeroLimits,
    #[error("the record could not be canonicalized")]
    Uncanonical,
}

/// §16.3 `ModelProviderBinding`. The credential lives only here, as a ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProviderBinding {
    pub model_provider_binding_id: String,
    pub realm_id: String,
    pub revision: u64,
    pub provider_kind: ProviderKind,
    /// The one origin bytes may leave through. Also the allowlist: there
    /// is no second, wider list to fall back to.
    pub endpoint: Origin,
    pub allowed_regions: Vec<String>,
    pub provider_claims: ProviderClaims,
    pub transport_security_profile_ref: String,
    /// A secret-manager reference — never key material (§16.3).
    pub credential_secret_ref: String,
    pub provider_terms_digest: DigestRef,
    pub status: Status,
    pub digest: DigestRef,
}

impl ModelProviderBinding {
    pub fn new(
        model_provider_binding_id: &str,
        realm_id: &str,
        provider_kind: ProviderKind,
        endpoint: Origin,
        provider_claims: ProviderClaims,
        credential_secret_ref: &str,
        provider_terms_ref: &str,
    ) -> Result<ModelProviderBinding, BindingError> {
        if !provider_claims.is_complete() {
            return Err(BindingError::IncompleteClaims);
        }
        if CredentialRef::parse(credential_secret_ref).is_none() {
            return Err(BindingError::BadCredentialRef(
                credential_secret_ref.to_owned(),
            ));
        }
        if endpoint.scheme != "https" {
            return Err(BindingError::NotHttps(endpoint.to_string()));
        }
        let terms_digest = DigestRef::portable_public(kovee_core::family::sha256_hex(
            provider_terms_ref.as_bytes(),
        ));
        let mut binding = ModelProviderBinding {
            model_provider_binding_id: model_provider_binding_id.to_owned(),
            realm_id: realm_id.to_owned(),
            revision: 1,
            provider_kind,
            allowed_regions: vec![provider_claims.region.clone()],
            endpoint,
            provider_claims,
            transport_security_profile_ref: "kovee-tls13-ca-pinned-host-v1".to_owned(),
            credential_secret_ref: credential_secret_ref.to_owned(),
            provider_terms_digest: terms_digest,
            status: Status::Active,
            digest: DigestRef::portable_public("0".repeat(64)),
        };
        binding.digest = digest_of(BINDING_TAG, &binding.projection())?;
        Ok(binding)
    }

    /// This binding's egress policy: exactly its own origin.
    pub fn egress_policy(&self) -> EgressPolicy {
        EgressPolicy::allowing([self.endpoint.clone()])
    }

    pub fn credential_ref(&self) -> Option<CredentialRef> {
        CredentialRef::parse(&self.credential_secret_ref)
    }

    pub fn is_active(&self) -> bool {
        self.status == Status::Active
    }

    /// Disables the binding at a new revision. Old receipts keep naming the
    /// revision they used; only new egress is blocked.
    pub fn disabled(mut self) -> Result<ModelProviderBinding, BindingError> {
        self.status = Status::Disabled;
        self.revision += 1;
        self.digest = digest_of(BINDING_TAG, &self.projection())?;
        Ok(self)
    }

    pub fn projection(&self) -> Value {
        strip_digest(self)
    }
}

/// The per-call limits a profile enforces before egress (§16.3
/// `request_limits`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestLimits {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub calls: u64,
}

/// §16.3 `ModelProfile`. It selects an exact binding revision/digest and
/// carries no endpoint, account, transport, or terms member at all — so
/// "a profile cannot override the endpoint" is structural, not a rule
/// someone has to remember.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProfile {
    pub model_profile_id: String,
    pub realm_id: String,
    pub revision: u64,
    pub provider_binding_ref: String,
    pub provider_binding_revision: u64,
    pub provider_binding_digest: DigestRef,
    pub model_selector: String,
    pub allowed_classification_refs: Vec<String>,
    pub allowed_regions: Vec<String>,
    pub provider_claims: ProviderClaims,
    pub request_limits: RequestLimits,
    pub adapter_version: String,
    pub status: Status,
    pub digest: DigestRef,
}

impl ModelProfile {
    pub fn new(
        model_profile_id: &str,
        binding: &ModelProviderBinding,
        model_selector: &str,
        request_limits: RequestLimits,
    ) -> Result<ModelProfile, BindingError> {
        if model_selector.trim().is_empty() {
            return Err(BindingError::NoModel);
        }
        if request_limits.input_tokens == 0
            || request_limits.output_tokens == 0
            || request_limits.calls == 0
        {
            return Err(BindingError::ZeroLimits);
        }
        let mut profile = ModelProfile {
            model_profile_id: model_profile_id.to_owned(),
            realm_id: binding.realm_id.clone(),
            revision: 1,
            provider_binding_ref: binding.model_provider_binding_id.clone(),
            provider_binding_revision: binding.revision,
            provider_binding_digest: binding.digest.clone(),
            model_selector: model_selector.to_owned(),
            allowed_classification_refs: vec!["class-public".to_owned()],
            // A profile may NARROW the binding's regions, never widen them.
            allowed_regions: binding.allowed_regions.clone(),
            provider_claims: binding.provider_claims.clone(),
            request_limits,
            adapter_version: crate::driver::adapter_version(binding.provider_kind).to_owned(),
            status: Status::Active,
            digest: DigestRef::portable_public("0".repeat(64)),
        };
        profile.digest = digest_of(PROFILE_TAG, &profile.projection())?;
        Ok(profile)
    }

    /// Restricts this profile to `classifications` at a new revision.
    pub fn with_classifications(
        mut self,
        classifications: &[&str],
    ) -> Result<ModelProfile, BindingError> {
        self.allowed_classification_refs =
            classifications.iter().map(|c| (*c).to_owned()).collect();
        self.revision += 1;
        self.digest = digest_of(PROFILE_TAG, &self.projection())?;
        Ok(self)
    }

    pub fn is_active(&self) -> bool {
        self.status == Status::Active
    }

    /// Validates this profile against the binding revision it selected —
    /// re-run immediately before every use (§16.3). A binding that has been
    /// re-revised or disabled since fails here.
    pub fn check_against(&self, binding: &ModelProviderBinding) -> Result<(), ProfileError> {
        if !binding.is_active() {
            return Err(ProfileError::BindingDisabled);
        }
        if !self.is_active() {
            return Err(ProfileError::ProfileDisabled);
        }
        if self.provider_binding_ref != binding.model_provider_binding_id {
            return Err(ProfileError::WrongBinding);
        }
        if self.provider_binding_revision != binding.revision
            || self.provider_binding_digest != binding.digest
        {
            return Err(ProfileError::StaleBindingRevision);
        }
        // A profile narrows; it never widens.
        if self
            .allowed_regions
            .iter()
            .any(|r| !binding.allowed_regions.contains(r))
        {
            return Err(ProfileError::WidenedRegion);
        }
        if self.provider_claims != binding.provider_claims {
            return Err(ProfileError::RestatedClaims);
        }
        Ok(())
    }

    pub fn projection(&self) -> Value {
        strip_digest(self)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("the provider binding is disabled: no new egress leaves through it")]
    BindingDisabled,
    #[error("the model profile is disabled")]
    ProfileDisabled,
    #[error("the profile selects another provider binding")]
    WrongBinding,
    #[error("the provider binding was re-revised after this profile pinned it")]
    StaleBindingRevision,
    #[error("a profile may narrow the binding's regions, never widen them")]
    WidenedRegion,
    #[error("a profile may not restate the binding's provider claims")]
    RestatedClaims,
    #[error("the classification {0:?} is not allowed by this model profile")]
    ClassificationNotAllowed(String),
    #[error("the request exceeds the profile's {0} limit")]
    OverLimit(&'static str),
}

fn strip_digest<T: Serialize>(record: &T) -> Value {
    let mut value = serde_json::to_value(record).unwrap_or_else(|_| json!({}));
    if let Some(map) = value.as_object_mut() {
        map.remove("digest");
    }
    value
}

fn digest_of(tag: &str, projection: &Value) -> Result<DigestRef, BindingError> {
    let preimage = tagged_canonical(tag, projection).map_err(|_| BindingError::Uncanonical)?;
    Ok(DigestRef::portable_public(kovee_core::family::sha256_hex(
        &preimage,
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn claims() -> ProviderClaims {
        ProviderClaims {
            region: "us".to_owned(),
            retention: "30-days".to_owned(),
            training_use: "prohibited".to_owned(),
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
            "terms-anthropic-2025-01",
        )
        .unwrap()
    }

    fn limits() -> RequestLimits {
        RequestLimits {
            input_tokens: 40_000,
            output_tokens: 1_024,
            calls: 1,
        }
    }

    #[test]
    fn a_binding_carries_a_credential_reference_and_no_key_material() {
        let b = binding();
        assert_eq!(
            b.credential_ref(),
            Some(CredentialRef::Env("ANTHROPIC_API_KEY".to_owned()))
        );
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains("env:ANTHROPIC_API_KEY"));
        // A literal key can never be recorded as the reference.
        assert!(matches!(
            ModelProviderBinding::new(
                "mpb-2",
                "realm-personal",
                ProviderKind::Openai,
                ProviderKind::Openai.default_origin(),
                claims(),
                "sk-ant-not-a-reference",
                "terms",
            ),
            Err(BindingError::BadCredentialRef(_))
        ));
    }

    #[test]
    fn the_binding_endpoint_is_its_own_allowlist() {
        let b = binding();
        let policy = b.egress_policy();
        assert_eq!(policy.origin_allowlist, vec![b.endpoint.clone()]);
        crate::egress::check_origin(&b.endpoint, &policy).unwrap();
        assert!(crate::egress::check_origin(&Origin::https("evil.example", 443), &policy).is_err());
    }

    #[test]
    fn a_profile_pins_an_exact_binding_revision_and_cannot_widen_it() {
        let b = binding();
        let p = ModelProfile::new("mp-1", &b, "claude-haiku-4-5-20251001", limits()).unwrap();
        p.check_against(&b).unwrap();
        // The profile record has no endpoint/account/transport member at all.
        let value = serde_json::to_value(&p).unwrap();
        for absent in [
            "endpoint",
            "account_ref",
            "transport_security_profile_ref",
            "credential_secret_ref",
            "provider_terms_digest",
        ] {
            assert!(value.get(absent).is_none(), "{absent} must not be settable");
        }
        // A re-revised binding invalidates the pin.
        let disabled = b.clone().disabled().unwrap();
        assert_eq!(
            p.check_against(&disabled).unwrap_err(),
            ProfileError::BindingDisabled
        );
        let mut rerevised = b.clone();
        rerevised.revision = 2;
        assert_eq!(
            p.check_against(&rerevised).unwrap_err(),
            ProfileError::StaleBindingRevision
        );
        // And a widened region is refused.
        let mut widened = p.clone();
        widened.allowed_regions.push("cn".to_owned());
        assert_eq!(
            widened.check_against(&b).unwrap_err(),
            ProfileError::WidenedRegion
        );
        // A narrowed classification set is a new revision with a new digest.
        let narrowed = p.clone().with_classifications(&["class-internal"]).unwrap();
        assert_eq!(narrowed.revision, 2);
        assert_ne!(narrowed.digest, p.digest);
        narrowed.check_against(&b).unwrap();
    }

    #[test]
    fn incomplete_claims_and_zero_limits_are_refused() {
        let mut blank = claims();
        blank.training_use = String::new();
        assert_eq!(
            ModelProviderBinding::new(
                "mpb-3",
                "realm-personal",
                ProviderKind::Anthropic,
                ProviderKind::Anthropic.default_origin(),
                blank,
                "env:K",
                "terms",
            )
            .unwrap_err(),
            BindingError::IncompleteClaims
        );
        let b = binding();
        assert_eq!(
            ModelProfile::new("mp-4", &b, "", limits()).unwrap_err(),
            BindingError::NoModel
        );
        assert_eq!(
            ModelProfile::new(
                "mp-5",
                &b,
                "m",
                RequestLimits {
                    input_tokens: 0,
                    output_tokens: 1,
                    calls: 1
                }
            )
            .unwrap_err(),
            BindingError::ZeroLimits
        );
    }

    #[test]
    fn provider_kinds_and_statuses_round_trip() {
        for kind in [ProviderKind::Anthropic, ProviderKind::Openai] {
            assert_eq!(ProviderKind::from_str(kind.as_str()), Some(kind));
            assert_eq!(kind.default_origin().scheme, "https");
        }
        assert_eq!(ProviderKind::from_str("gemini"), None);
        for status in [Status::Active, Status::Disabled] {
            assert_eq!(Status::from_str(status.as_str()), Some(status));
        }
    }
}
