//! The §11.2 command envelope and command result, mirroring
//! `spec/schemas/kcp-command.schema.json` and
//! `kcp-command-result.schema.json` (the wire truth).
//!
//! Reads never carry `meta` (a closed shape with no meta member at all);
//! mutations require it. [`Shape`] selects which of the three schema
//! shapes — generic, `#/$defs/mutationCommand`, `#/$defs/readCommand` —
//! a value is validated against.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::limits;
use crate::problem::Problem;

pub type JsonMap = Map<String, Value>;

/// `Command.meta` (§11.2): closed shape, `request_id` and
/// `idempotency_key` required.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandMeta {
    pub request_id: String,
    pub idempotency_key: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expected_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub causation_event_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub traceparent: Option<String>,
}

/// Which envelope schema shape to validate against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// The top-level generic schema: `meta` optional, `realm_id` required.
    Generic,
    /// `#/$defs/mutationCommand`: `meta` required.
    Mutation,
    /// `#/$defs/readCommand`: no `meta` member exists.
    Read,
    /// The `hello` pre-auth framing: no `realm_id`/`project_id`/`meta`
    /// member exists (`spec/schemas/ops/hello-request.schema.json`).
    PreAuth,
}

/// A parsed but not yet operation-validated command envelope. Field
/// closure (`additionalProperties: false`) is enforced by serde;
/// [`RawCommand::validate`] enforces the lexical shapes and the
/// read/mutation meta rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCommand {
    pub version: String,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub meta: Option<CommandMeta>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub realm_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub project_id: Option<String>,
    pub args: JsonMap,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ext: Option<JsonMap>,
}

fn invalid(detail: impl Into<String>) -> Problem {
    Problem::new(
        crate::problem::ProblemKind::Invalid,
        "invalid command envelope",
    )
    .with_detail(detail)
}

impl RawCommand {
    /// Deserializes a strict-parsed value into the envelope shape.
    pub fn from_value(value: Value) -> Result<RawCommand, Problem> {
        serde_json::from_value(value).map_err(|e| invalid(e.to_string()))
    }

    /// Validates the envelope against `shape`, mirroring the schema's
    /// `$defs` constraints exactly.
    pub fn validate(&self, shape: Shape) -> Result<(), Problem> {
        if !limits::is_protocol_version(&self.version) {
            return Err(invalid("version is not major.minor"));
        }
        if !limits::is_operation_id(&self.op) {
            return Err(invalid("op is not an operation id"));
        }
        match shape {
            Shape::Generic | Shape::Mutation | Shape::Read => match &self.realm_id {
                Some(realm) if limits::is_identifier(realm) => {}
                Some(_) => return Err(invalid("realm_id is not an identifier")),
                None => return Err(invalid("realm_id is required")),
            },
            Shape::PreAuth => {
                if self.realm_id.is_some() || self.project_id.is_some() {
                    return Err(invalid("hello carries no realm_id or project_id"));
                }
            }
        }
        if let Some(project) = &self.project_id {
            if !limits::is_identifier(project) {
                return Err(invalid("project_id is not an identifier"));
            }
        }
        match (shape, &self.meta) {
            (Shape::Mutation, None) => {
                return Err(invalid("a state-changing operation requires meta (§11.2)"));
            }
            (Shape::Read | Shape::PreAuth, Some(_)) => {
                return Err(invalid(
                    "a read carries no meta member (§11.2 closed read shape)",
                ));
            }
            _ => {}
        }
        if let Some(meta) = &self.meta {
            if !limits::is_identifier(&meta.request_id) {
                return Err(invalid("meta.request_id is not an identifier"));
            }
            if !limits::is_identifier(&meta.idempotency_key) {
                return Err(invalid("meta.idempotency_key is not an identifier"));
            }
            if let Some(rev) = meta.expected_revision {
                if rev > crate::ijson::SAFE_MAX {
                    return Err(invalid("meta.expected_revision is not a safe integer"));
                }
            }
            if let Some(cause) = &meta.causation_event_ref {
                if !limits::is_identifier(cause) {
                    return Err(invalid("meta.causation_event_ref is not an identifier"));
                }
            }
            if let Some(tp) = &meta.traceparent {
                if !limits::is_traceparent(tp) {
                    return Err(invalid("meta.traceparent is not a traceparent"));
                }
            }
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

/// `CommandResult` (§11.2): `{outcome:"ok", result, revision?,
/// event_cursor?} | {outcome:"problem", problem}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "lowercase", deny_unknown_fields)]
pub enum CommandResult {
    Ok {
        result: Value,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        revision: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        event_cursor: Option<String>,
    },
    Problem {
        problem: Problem,
    },
}

impl CommandResult {
    pub fn problem(problem: Problem) -> CommandResult {
        CommandResult::Problem { problem }
    }
}
