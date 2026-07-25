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
pub const EVENT_RELATION_ASSERTED: &str = "dev.kovee.space.relation-asserted.v1";
pub const EVENT_FRONTIER_PINNED: &str = "dev.kovee.space.frontier-pinned.v1";
pub const EVENT_CONTEXT_ASSEMBLY_CREATED: &str = "dev.kovee.space.context-assembly-created.v1";
pub const EVENT_ARTIFACT_UPLOAD_BEGAN: &str = "dev.kovee.artifact.upload-began.v1";
pub const EVENT_ARTIFACT_UPLOAD_SEALING: &str = "dev.kovee.artifact.upload-sealing.v1";
pub const EVENT_ARTIFACT_UPLOAD_ABORTED: &str = "dev.kovee.artifact.upload-aborted.v1";
pub const EVENT_ARTIFACT_AVAILABLE: &str = "dev.kovee.artifact.available.v1";
pub const EVENT_ARTIFACT_REJECTED: &str = "dev.kovee.artifact.rejected.v1";
pub const EVENT_INVOCATION_CREATED: &str = "dev.kovee.invocation.created.v1";
pub const EVENT_INVOCATION_CLAIMED: &str = "dev.kovee.invocation.claimed.v1";
pub const EVENT_INVOCATION_SUCCEEDED: &str = "dev.kovee.invocation.succeeded.v1";
pub const EVENT_INVOCATION_CANCELED: &str = "dev.kovee.invocation.canceled.v1";
// Slice-3 lifecycle/disposition/registry event types.
pub const EVENT_PROJECT_UPDATED: &str = "dev.kovee.project.updated.v1";
pub const EVENT_PROJECT_POLICY_CHANGE_PREPARED: &str =
    "dev.kovee.project.policy-change-prepared.v1";
pub const EVENT_PROJECT_POLICY_CHANGE_CONFIRMED: &str =
    "dev.kovee.project.policy-change-confirmed.v1";
pub const EVENT_PROJECT_POLICY_CHANGE_CANCELED: &str =
    "dev.kovee.project.policy-change-canceled.v1";
pub const EVENT_SPACE_UPDATED: &str = "dev.kovee.space.updated.v1";
pub const EVENT_SPACE_FROZEN: &str = "dev.kovee.space.frozen.v1";
pub const EVENT_SPACE_REOPENED: &str = "dev.kovee.space.reopened.v1";
pub const EVENT_SPACE_ARCHIVED: &str = "dev.kovee.space.archived.v1";
pub const EVENT_SPACE_RESTRICTED: &str = "dev.kovee.space.restricted.v1";
pub const EVENT_SPACE_POLICY_NARROWED: &str = "dev.kovee.space.policy-narrowed.v1";
pub const EVENT_SPACE_WIDENING_PREPARED: &str = "dev.kovee.space.access-widening-prepared.v1";
pub const EVENT_SPACE_WIDENING_CONFIRMED: &str = "dev.kovee.space.access-widening-confirmed.v1";
pub const EVENT_SPACE_WIDENING_CANCELED: &str = "dev.kovee.space.access-widening-canceled.v1";
pub const EVENT_PARTICIPANT_ADDED: &str = "dev.kovee.space.participant-added.v1";
pub const EVENT_PARTICIPANT_ACTIVATED: &str = "dev.kovee.space.participant-activated.v1";
pub const EVENT_PARTICIPANT_UPDATED: &str = "dev.kovee.space.participant-updated.v1";
pub const EVENT_PARTICIPANT_REMOVED: &str = "dev.kovee.space.participant-removed.v1";
pub const EVENT_GRANT_CREATED: &str = "dev.kovee.space.access-grant-created.v1";
pub const EVENT_GRANT_REVOKED: &str = "dev.kovee.space.access-grant-revoked.v1";
pub const EVENT_CONTRIBUTION_WITHDRAWN: &str = "dev.kovee.space.contribution-withdrawn.v1";
pub const EVENT_CONTRIBUTION_SUPERSEDED: &str = "dev.kovee.space.contribution-superseded.v1";
pub const EVENT_CONTRIBUTION_REDACTED: &str = "dev.kovee.space.contribution-redacted.v1";
pub const EVENT_RELATION_RETRACTED: &str = "dev.kovee.space.relation-retracted.v1";
pub const EVENT_LENS_CREATED: &str = "dev.kovee.space.lens-created.v1";
pub const EVENT_LENS_UPDATED: &str = "dev.kovee.space.lens-updated.v1";
pub const EVENT_LENS_REVOKED: &str = "dev.kovee.space.lens-revoked.v1";
pub const EVENT_REACTION_SET: &str = "dev.kovee.space.reaction-set.v1";
pub const EVENT_ASSISTANT_CREATED: &str = "dev.kovee.assistant.created.v1";
pub const EVENT_ASSISTANT_REVISION_REGISTERED: &str = "dev.kovee.assistant.revision-registered.v1";
pub const EVENT_DEPLOYMENT_CREATED: &str = "dev.kovee.assistant.deployment-created.v1";
pub const EVENT_DEPLOYMENT_ACTIVATED: &str = "dev.kovee.assistant.deployment-activated.v1";
pub const EVENT_DEPLOYMENT_DRAINED: &str = "dev.kovee.assistant.deployment-drained.v1";
pub const EVENT_ALIAS_BOUND: &str = "dev.kovee.assistant.alias-bound.v1";
pub const EVENT_ALIAS_UPDATED: &str = "dev.kovee.assistant.alias-updated.v1";
pub const EVENT_ALIAS_REVOKED: &str = "dev.kovee.assistant.alias-revoked.v1";
/// The reserved Kovee event namespace (§11.3): application events may
/// never emit under it.
pub const RESERVED_EVENT_NAMESPACE: &str = "dev.kovee.";

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
