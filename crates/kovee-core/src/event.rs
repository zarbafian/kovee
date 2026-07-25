//! The §11.3 event envelope, mirroring `spec/schemas/kcp-event.schema.json`
//! and the `eventEnvelope` def of `events-read-result.schema.json`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ijson::SAFE_MAX;
use crate::limits;
use crate::problem::{Problem, ProblemKind};

/// Reverse-domain event types Kovee itself emits (the reserved
/// `dev.kovee.*` namespace, §11.3).
pub const EVENT_PROJECT_CREATED: &str = "dev.kovee.project.created.v1";
pub const EVENT_SPACE_CREATED: &str = "dev.kovee.space.created.v1";
pub const EVENT_CONTRIBUTION_APPENDED: &str = "dev.kovee.space.contribution-appended.v1";

/// One §11.3 event. Exactly one of `payload` / `payload_ref` is present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub event_id: String,
    pub installation_id: String,
    pub realm_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub project_id: Option<String>,
    pub stream_id: String,
    pub stream_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub project_sequence: Option<u64>,
    #[serde(rename = "type")]
    pub event_type: String,
    pub schema_ref: String,
    pub resource_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resource_revision: Option<u64>,
    pub actor_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub causation_ref: Option<String>,
    pub correlation_ref: String,
    pub occurred_at: String,
    pub classification_ref: String,
    pub payload_digest: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub payload_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ext: Option<serde_json::Map<String, Value>>,
}

fn invalid(detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::Invalid, "invalid event envelope").with_detail(detail)
}

impl EventEnvelope {
    /// Validates the lexical shapes the schema pins: identifiers, the
    /// event-type name, the timestamp (calendar-valid), the payload
    /// exclusivity rule, and safe sequences.
    pub fn validate(&self) -> Result<(), Problem> {
        for (name, value) in [
            ("event_id", &self.event_id),
            ("installation_id", &self.installation_id),
            ("realm_id", &self.realm_id),
            ("stream_id", &self.stream_id),
            ("schema_ref", &self.schema_ref),
            ("resource_ref", &self.resource_ref),
            ("actor_ref", &self.actor_ref),
            ("correlation_ref", &self.correlation_ref),
            ("classification_ref", &self.classification_ref),
        ] {
            if !limits::is_identifier(value) {
                return Err(invalid(format!("{name} is not an identifier")));
            }
        }
        for (name, value) in [
            ("project_id", &self.project_id),
            ("causation_ref", &self.causation_ref),
            ("payload_ref", &self.payload_ref),
        ] {
            if let Some(v) = value {
                if !limits::is_identifier(v) {
                    return Err(invalid(format!("{name} is not an identifier")));
                }
            }
        }
        if self.stream_sequence > SAFE_MAX
            || self.project_sequence.is_some_and(|s| s > SAFE_MAX)
            || self.resource_revision.is_some_and(|r| r > SAFE_MAX)
        {
            return Err(invalid("sequence outside the safe-integer range"));
        }
        if !limits::is_event_type(&self.event_type) {
            return Err(invalid("type is not a versioned reverse-domain name"));
        }
        if !limits::is_timestamp(&self.occurred_at) {
            return Err(invalid(
                "occurred_at is not a calendar-valid RFC 3339 date-time",
            ));
        }
        if !limits::is_digest_hex(&self.payload_digest) {
            return Err(invalid("payload_digest is not 64 lowercase hex"));
        }
        match (&self.payload, &self.payload_ref) {
            (Some(_), None) | (None, Some(_)) => {}
            _ => return Err(invalid("exactly one of payload / payload_ref is required")),
        }
        if let Some(ext) = &self.ext {
            for key in ext.keys() {
                if !limits::is_ext_namespace(key) {
                    return Err(invalid(format!(
                        "ext key {key:?} is not a reverse-domain namespace"
                    )));
                }
            }
        }
        Ok(())
    }
}
