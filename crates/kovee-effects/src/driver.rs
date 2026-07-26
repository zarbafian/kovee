//! The narrow provider driver: one trait, two implementations, and nothing
//! in either of them that can widen what leaves.
//!
//! A driver does exactly three things:
//!
//! 1. **map in** — turn Kovee's [`ModelRequest`] into the provider's own
//!    request line, headers, and body ([`ModelDriver::build`]);
//! 2. **map out** — turn the provider's response body into
//!    [`ModelReply`] ([`ModelDriver::parse`]);
//! 3. **meter** — pull the token usage out of that body ([`Usage`]).
//!
//! What a driver never does: choose the destination (the binding's origin),
//! see the credential (the transport injects it from the
//! [`Credential`](crate::credential::Credential) the broker resolved), or
//! stream (`stream` is never set; a partial response has no digest).
//!
//! What you write:
//! ```
//! use kovee_effects::{ModelDriver, ModelRequest, ANTHROPIC, ANTHROPIC_MODEL};
//! let request = ModelRequest {
//!     model: ANTHROPIC_MODEL, system: Some("Be brief."),
//!     prompt: "Say OK.", max_output_tokens: 16,
//! };
//! let prepared = ANTHROPIC.build(&request).unwrap();
//! assert_eq!(prepared.method, "POST");
//! assert_eq!(prepared.path, "/v1/messages");
//! // max_tokens is mandatory on the Messages API, so it is always sent.
//! let body: serde_json::Value = serde_json::from_slice(&prepared.body).unwrap();
//! assert_eq!(body["max_tokens"], 16);
//! ```

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::binding::ProviderKind;

/// The current-generation model ids this broker defaults to. Pinned here as
/// named constants (never inline in call sites) and kept in step with
/// akson's `bench/serve.sh`, which pins the same two. An operator overrides
/// them per `ModelProfile.model_selector`; these are only the default a
/// seeded profile starts from.
pub const ANTHROPIC_MODEL: &str = "claude-haiku-4-5-20251001";
/// The OpenAI default, matching akson's bench pin.
pub const OPENAI_MODEL: &str = "gpt-4o-mini";

/// The Anthropic API version header value the Messages API requires.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The adapter version recorded in the `ProviderContextManifest`: which
/// exact mapping produced the bytes.
pub fn adapter_version(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::Anthropic => "kovee-anthropic-messages-v1/2023-06-01",
        ProviderKind::Openai => "kovee-openai-chat-completions-v1",
    }
}

/// What the worker asked for, after the broker has resolved the profile.
/// There is no destination, no credential, and no header map here — a
/// worker cannot express any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelRequest<'a> {
    pub model: &'a str,
    pub system: Option<&'a str>,
    pub prompt: &'a str,
    pub max_output_tokens: u64,
}

/// How the transport must authenticate to this provider. The value is
/// supplied by the transport, not by the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// `x-api-key: <credential>` (Anthropic).
    ApiKeyHeader,
    /// `authorization: Bearer <credential>` (OpenAI).
    Bearer,
}

impl AuthScheme {
    /// The header name the credential goes in, and the value prefix.
    pub fn header(self) -> (&'static str, &'static str) {
        match self {
            AuthScheme::ApiKeyHeader => ("x-api-key", ""),
            AuthScheme::Bearer => ("authorization", "Bearer "),
        }
    }
}

/// One provider request, fully determined except for the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRequest {
    pub method: &'static str,
    pub path: &'static str,
    pub auth: AuthScheme,
    /// Static headers (never a credential). `content-type`, `host`, and
    /// `content-length` are added by the transport.
    pub headers: Vec<(String, String)>,
    /// The exact bytes whose typed digest the provider-context manifest
    /// seals and the byom permit therefore authorizes.
    pub body: Vec<u8>,
}

/// Token usage, as the provider reported it (§16.3 step 6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }
}

/// The mapped-out reply the broker hands back to the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelReply {
    pub text: String,
    pub usage: Usage,
    /// The provider's own id for the response, when it gives one: the
    /// `external_ref` of the effect receipt.
    pub external_ref: Option<String>,
    /// The model the provider says actually answered (§16.3 "model revision
    /// where known").
    pub model: Option<String>,
    pub stop_reason: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DriverError {
    #[error("the request names no model")]
    NoModel,
    #[error("max_output_tokens must be positive")]
    NoOutputBudget,
    #[error("the provider request could not be serialized")]
    Unserializable,
    #[error("the provider returned HTTP {status}: {detail}")]
    ProviderStatus { status: u16, detail: String },
    #[error("the provider reply was not JSON: {0}")]
    NotJson(String),
    #[error("the provider reply carried no {0}")]
    Missing(&'static str),
}

/// One narrow provider driver (§16.3). Object-safe: the broker holds
/// `&'static dyn ModelDriver`.
pub trait ModelDriver: Send + Sync {
    fn kind(&self) -> ProviderKind;

    /// Builds the exact provider request. Deterministic: the same
    /// `ModelRequest` always produces the same bytes, which is what lets
    /// the manifest seal them before egress and re-check them after.
    fn build(&self, request: &ModelRequest<'_>) -> Result<PreparedRequest, DriverError>;

    /// Maps the provider's status + body to a reply, or to the typed error
    /// the effect receipt records.
    fn parse(&self, status: u16, body: &[u8]) -> Result<ModelReply, DriverError>;
}

/// The driver for a provider kind.
pub fn driver_for(kind: ProviderKind) -> &'static dyn ModelDriver {
    match kind {
        ProviderKind::Anthropic => &ANTHROPIC,
        ProviderKind::Openai => &OPENAI,
    }
}

fn check(request: &ModelRequest<'_>) -> Result<(), DriverError> {
    if request.model.trim().is_empty() {
        return Err(DriverError::NoModel);
    }
    if request.max_output_tokens == 0 {
        return Err(DriverError::NoOutputBudget);
    }
    Ok(())
}

/// Canonical JSON bytes, so the sealed digest is reproducible.
fn body_bytes(value: &Value) -> Result<Vec<u8>, DriverError> {
    kovee_core::canonical::jcs(value).map_err(|_| DriverError::Unserializable)
}

fn provider_error(status: u16, body: &[u8]) -> DriverError {
    // A provider error body may echo request content, so only its own
    // error message is surfaced — bounded, and never the whole body.
    let text = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/message")
                .or_else(|| v.pointer("/error/type"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "the provider gave no machine-readable error".to_owned());
    DriverError::ProviderStatus {
        status,
        detail: text.chars().take(256).collect(),
    }
}

// ------------------------------------------------------------- anthropic ----

/// The Anthropic Messages API driver.
pub struct AnthropicDriver;

/// The one Anthropic driver instance.
pub static ANTHROPIC: AnthropicDriver = AnthropicDriver;

impl ModelDriver for AnthropicDriver {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Anthropic
    }

    fn build(&self, request: &ModelRequest<'_>) -> Result<PreparedRequest, DriverError> {
        check(request)?;
        // The Messages API differs from chat-completions in three ways this
        // driver handles: the path is `/v1/messages`, `max_tokens` is
        // REQUIRED in the body, and the system prompt is a top-level member
        // rather than a message with `role: "system"`.
        let mut body = json!({
            "model": request.model,
            "max_tokens": request.max_output_tokens,
            "messages": [{"role": "user", "content": request.prompt}],
        });
        if let Some(system) = request.system {
            body["system"] = json!(system);
        }
        Ok(PreparedRequest {
            method: "POST",
            path: "/v1/messages",
            auth: AuthScheme::ApiKeyHeader,
            headers: vec![("anthropic-version".to_owned(), ANTHROPIC_VERSION.to_owned())],
            body: body_bytes(&body)?,
        })
    }

    fn parse(&self, status: u16, body: &[u8]) -> Result<ModelReply, DriverError> {
        if !(200..300).contains(&status) {
            return Err(provider_error(status, body));
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|e| DriverError::NotJson(e.to_string()))?;
        let text = value["content"]
            .as_array()
            .and_then(|blocks| {
                blocks
                    .iter()
                    .find(|b| b["type"] == "text")
                    .and_then(|b| b["text"].as_str())
            })
            .ok_or(DriverError::Missing("text content block"))?
            .to_owned();
        Ok(ModelReply {
            text,
            usage: Usage {
                input_tokens: value["usage"]["input_tokens"].as_u64().unwrap_or(0),
                output_tokens: value["usage"]["output_tokens"].as_u64().unwrap_or(0),
            },
            external_ref: value["id"].as_str().map(str::to_owned),
            model: value["model"].as_str().map(str::to_owned),
            stop_reason: value["stop_reason"].as_str().map(str::to_owned),
        })
    }
}

// ---------------------------------------------------------------- openai ----

/// The OpenAI chat-completions driver.
pub struct OpenaiDriver;

/// The one OpenAI driver instance.
pub static OPENAI: OpenaiDriver = OpenaiDriver;

impl ModelDriver for OpenaiDriver {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Openai
    }

    fn build(&self, request: &ModelRequest<'_>) -> Result<PreparedRequest, DriverError> {
        check(request)?;
        let mut messages = Vec::new();
        if let Some(system) = request.system {
            messages.push(json!({"role": "system", "content": system}));
        }
        messages.push(json!({"role": "user", "content": request.prompt}));
        let body = json!({
            "model": request.model,
            "messages": messages,
            "max_completion_tokens": request.max_output_tokens,
        });
        Ok(PreparedRequest {
            method: "POST",
            path: "/v1/chat/completions",
            auth: AuthScheme::Bearer,
            headers: Vec::new(),
            body: body_bytes(&body)?,
        })
    }

    fn parse(&self, status: u16, body: &[u8]) -> Result<ModelReply, DriverError> {
        if !(200..300).contains(&status) {
            return Err(provider_error(status, body));
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|e| DriverError::NotJson(e.to_string()))?;
        let text = value["choices"][0]["message"]["content"]
            .as_str()
            .ok_or(DriverError::Missing("choices[0].message.content"))?
            .to_owned();
        Ok(ModelReply {
            text,
            usage: Usage {
                input_tokens: value["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
                output_tokens: value["usage"]["completion_tokens"].as_u64().unwrap_or(0),
            },
            external_ref: value["id"].as_str().map(str::to_owned),
            model: value["model"].as_str().map(str::to_owned),
            stop_reason: value["choices"][0]["finish_reason"]
                .as_str()
                .map(str::to_owned),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn request<'a>(model: &'a str, system: Option<&'a str>) -> ModelRequest<'a> {
        ModelRequest {
            model,
            system,
            prompt: "Say OK.",
            max_output_tokens: 16,
        }
    }

    #[test]
    fn the_anthropic_request_is_a_messages_api_call_with_max_tokens() {
        let prepared = ANTHROPIC
            .build(&request(ANTHROPIC_MODEL, Some("Be brief.")))
            .unwrap();
        assert_eq!((prepared.method, prepared.path), ("POST", "/v1/messages"));
        assert_eq!(prepared.auth, AuthScheme::ApiKeyHeader);
        assert_eq!(
            prepared.headers,
            vec![("anthropic-version".to_owned(), "2023-06-01".to_owned())]
        );
        let body: Value = serde_json::from_slice(&prepared.body).unwrap();
        assert_eq!(body["model"], ANTHROPIC_MODEL);
        assert_eq!(body["max_tokens"], 16);
        assert_eq!(body["system"], "Be brief.");
        assert_eq!(body["messages"][0]["role"], "user");
        // No streaming: a partial response has no digest to bind.
        assert!(body.get("stream").is_none());
        // The bytes are canonical, so the sealed digest is reproducible.
        assert_eq!(
            prepared.body,
            ANTHROPIC
                .build(&request(ANTHROPIC_MODEL, Some("Be brief.")))
                .unwrap()
                .body
        );
    }

    #[test]
    fn the_openai_request_is_a_chat_completions_call() {
        let prepared = OPENAI
            .build(&request(OPENAI_MODEL, Some("Be brief.")))
            .unwrap();
        assert_eq!(
            (prepared.method, prepared.path),
            ("POST", "/v1/chat/completions")
        );
        assert_eq!(prepared.auth, AuthScheme::Bearer);
        let body: Value = serde_json::from_slice(&prepared.body).unwrap();
        assert_eq!(body["model"], OPENAI_MODEL);
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][1]["role"], "user");
        assert_eq!(body["max_completion_tokens"], 16);
        assert!(body.get("stream").is_none());
        // Without a system prompt there is exactly one message.
        let plain = OPENAI.build(&request(OPENAI_MODEL, None)).unwrap();
        let body: Value = serde_json::from_slice(&plain.body).unwrap();
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_prepared_request_carries_no_credential_and_no_destination() {
        for prepared in [
            ANTHROPIC.build(&request(ANTHROPIC_MODEL, None)).unwrap(),
            OPENAI.build(&request(OPENAI_MODEL, None)).unwrap(),
        ] {
            for (name, value) in &prepared.headers {
                assert!(
                    !name.eq_ignore_ascii_case("authorization")
                        && !name.eq_ignore_ascii_case("x-api-key"),
                    "a driver never sets a credential header: {name}={value}"
                );
            }
            // And the request names a PATH, never a host or a URL.
            assert!(prepared.path.starts_with('/'));
            assert!(!prepared.path.contains("://"));
        }
    }

    #[test]
    fn anthropic_replies_map_to_text_and_usage() {
        let body = br#"{"id":"msg_01","model":"claude-haiku-4-5-20251001",
            "stop_reason":"end_turn","content":[{"type":"text","text":"OK"}],
            "usage":{"input_tokens":12,"output_tokens":3}}"#;
        let reply = ANTHROPIC.parse(200, body).unwrap();
        assert_eq!(reply.text, "OK");
        assert_eq!(
            reply.usage,
            Usage {
                input_tokens: 12,
                output_tokens: 3
            }
        );
        assert_eq!(reply.usage.total(), 15);
        assert_eq!(reply.external_ref.as_deref(), Some("msg_01"));
        assert_eq!(reply.stop_reason.as_deref(), Some("end_turn"));
    }

    #[test]
    fn openai_replies_map_to_text_and_usage() {
        let body = br#"{"id":"chatcmpl-1","model":"gpt-4o-mini",
            "choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"OK"}}],
            "usage":{"prompt_tokens":9,"completion_tokens":2}}"#;
        let reply = OPENAI.parse(200, body).unwrap();
        assert_eq!(reply.text, "OK");
        assert_eq!(
            reply.usage,
            Usage {
                input_tokens: 9,
                output_tokens: 2
            }
        );
        assert_eq!(reply.external_ref.as_deref(), Some("chatcmpl-1"));
    }

    #[test]
    fn a_non_2xx_status_is_a_typed_error_with_a_bounded_detail() {
        let body = br#"{"error":{"type":"authentication_error","message":"invalid x-api-key"}}"#;
        let err = ANTHROPIC.parse(401, body).unwrap_err();
        assert_eq!(
            err,
            DriverError::ProviderStatus {
                status: 401,
                detail: "invalid x-api-key".to_owned()
            }
        );
        // A body with no machine-readable error still yields a typed error.
        assert!(matches!(
            OPENAI.parse(503, b"<html>gateway</html>").unwrap_err(),
            DriverError::ProviderStatus { status: 503, .. }
        ));
        // A long provider message is truncated, not echoed wholesale.
        let long = format!(r#"{{"error":{{"message":"{}"}}}}"#, "x".repeat(4096));
        let DriverError::ProviderStatus { detail, .. } =
            OPENAI.parse(400, long.as_bytes()).unwrap_err()
        else {
            panic!("expected a provider status error")
        };
        assert_eq!(detail.chars().count(), 256);
    }

    #[test]
    fn a_reply_without_content_is_an_error_not_an_empty_answer() {
        assert_eq!(
            ANTHROPIC
                .parse(200, br#"{"content":[{"type":"tool_use"}]}"#)
                .unwrap_err(),
            DriverError::Missing("text content block")
        );
        assert_eq!(
            OPENAI.parse(200, br#"{"choices":[]}"#).unwrap_err(),
            DriverError::Missing("choices[0].message.content")
        );
        assert!(matches!(
            OPENAI.parse(200, b"not json").unwrap_err(),
            DriverError::NotJson(_)
        ));
    }

    #[test]
    fn an_empty_model_or_zero_output_budget_is_refused() {
        assert_eq!(
            ANTHROPIC.build(&request("  ", None)).unwrap_err(),
            DriverError::NoModel
        );
        let mut zero = request(ANTHROPIC_MODEL, None);
        zero.max_output_tokens = 0;
        assert_eq!(
            ANTHROPIC.build(&zero).unwrap_err(),
            DriverError::NoOutputBudget
        );
    }

    #[test]
    fn driver_lookup_and_adapter_versions_are_per_kind() {
        assert_eq!(
            driver_for(ProviderKind::Anthropic).kind(),
            ProviderKind::Anthropic
        );
        assert_eq!(
            driver_for(ProviderKind::Openai).kind(),
            ProviderKind::Openai
        );
        assert_ne!(
            adapter_version(ProviderKind::Anthropic),
            adapter_version(ProviderKind::Openai)
        );
    }
}
