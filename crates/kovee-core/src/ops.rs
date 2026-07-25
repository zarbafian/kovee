//! The K1 slice-1 operation surface: per-operation argument shapes
//! mirroring `spec/schemas/ops/<op>-request.schema.json`, plus the
//! registry-derived read/mutation meta rule and envelope field placement.
//!
//! The registry (`spec/registry.json`) fixes which operations exist and on
//! which surface; the per-op schemas fix the closed argument shapes. This
//! module implements both in Rust — no JSON-Schema engine — and the vector
//! round-trip test (`tests/k1_slice1_vectors.rs`) proves agreement with
//! the schema files for every `spec/vectors/ops/` case of these ops.

use serde::Deserialize;
use serde_json::Value;

use crate::envelope::{JsonMap, Shape};
use crate::ijson::SAFE_MAX;
use crate::limits;
use crate::problem::{Problem, ProblemKind};
use crate::records::ContributionPart;

/// Read or mutation, per the K0 registry family of each op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Read,
    Mutation,
}

/// Whether an envelope field may/must appear for an op (each request
/// schema closes its envelope, so a forbidden member fails).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldRule {
    Required,
    Optional,
    Forbidden,
}

/// One slice-1 operation's registry-derived envelope rules.
#[derive(Debug, Clone, Copy)]
pub struct OpSpec {
    pub name: &'static str,
    pub kind: OpKind,
    pub realm_id: FieldRule,
    pub project_id: FieldRule,
}

/// The slice-1 operation table. Every operation here has a registry row
/// (`spec/registry.json`) on the `external_client` surface; an operation
/// absent from the registry is not callable (§11.6.1) and dispatch answers
/// `unknown-op`.
pub const SLICE1_OPS: [OpSpec; 8] = [
    OpSpec {
        name: "hello",
        kind: OpKind::Read,
        realm_id: FieldRule::Forbidden,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "realm_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "project_create",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "space_create",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "contribution_append",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "contribution_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "events_read",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
];

pub fn op_spec(name: &str) -> Option<&'static OpSpec> {
    SLICE1_OPS.iter().find(|s| s.name == name)
}

impl OpSpec {
    /// The envelope [`Shape`] this op's request schema pins.
    pub fn shape(&self) -> Shape {
        if self.name == "hello" {
            return Shape::PreAuth;
        }
        match self.kind {
            OpKind::Read => Shape::Read,
            OpKind::Mutation => Shape::Mutation,
        }
    }

    /// Checks the envelope realm/project placement this op's closed
    /// request schema pins.
    pub fn check_placement(
        &self,
        realm_id: &Option<String>,
        project_id: &Option<String>,
    ) -> Result<(), Problem> {
        check_field(self.name, "realm_id", self.realm_id, realm_id.is_some())?;
        check_field(
            self.name,
            "project_id",
            self.project_id,
            project_id.is_some(),
        )
    }
}

fn check_field(op: &str, field: &str, rule: FieldRule, present: bool) -> Result<(), Problem> {
    match (rule, present) {
        (FieldRule::Required, false) => Err(invalid(format!("{op} requires {field}"))),
        (FieldRule::Forbidden, true) => Err(invalid(format!("{op} carries no {field} member"))),
        _ => Ok(()),
    }
}

fn invalid(detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::Invalid, "invalid operation arguments").with_detail(detail)
}

fn parse_args<T: for<'de> Deserialize<'de>>(args: &JsonMap) -> Result<T, Problem> {
    serde_json::from_value(Value::Object(args.clone())).map_err(|e| invalid(e.to_string()))
}

fn check_identifier(field: &str, value: &str) -> Result<(), Problem> {
    if limits::is_identifier(value) {
        Ok(())
    } else {
        Err(invalid(format!("{field} is not an identifier")))
    }
}

fn check_opt_identifier(field: &str, value: &Option<String>) -> Result<(), Problem> {
    match value {
        Some(v) => check_identifier(field, v),
        None => Ok(()),
    }
}

fn check_display(field: &str, value: &str) -> Result<(), Problem> {
    if limits::is_display_name(value) {
        Ok(())
    } else {
        Err(invalid(format!(
            "{field} is not a 1-256 scalar display name"
        )))
    }
}

fn check_safe(field: &str, value: u64) -> Result<(), Problem> {
    if value <= SAFE_MAX {
        Ok(())
    } else {
        Err(invalid(format!("{field} is not a safe integer")))
    }
}

// -------------------------------------------------------------- hello ----

/// §11.1 HelloRequest args, verbatim field list.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloArgs {
    pub supported_versions: Vec<String>,
    pub implementation: String,
    pub implementation_version: String,
    pub requested_features: Vec<String>,
}

impl HelloArgs {
    pub fn from_args(args: &JsonMap) -> Result<HelloArgs, Problem> {
        let parsed: HelloArgs = parse_args(args)?;
        if parsed.supported_versions.is_empty()
            || parsed.supported_versions.len() > limits::LIST_MAX_ITEMS
        {
            return Err(invalid("supported_versions must hold 1-256 items"));
        }
        if !all_unique(&parsed.supported_versions) {
            return Err(invalid("supported_versions items must be unique"));
        }
        for v in &parsed.supported_versions {
            if !limits::is_protocol_version(v) {
                return Err(invalid("supported_versions item is not major.minor"));
            }
        }
        check_display("implementation", &parsed.implementation)?;
        check_identifier("implementation_version", &parsed.implementation_version)?;
        if parsed.requested_features.len() > limits::LIST_MAX_ITEMS {
            return Err(invalid("requested_features holds more than 256 items"));
        }
        if !all_unique(&parsed.requested_features) {
            return Err(invalid("requested_features items must be unique"));
        }
        for f in &parsed.requested_features {
            if !limits::is_operation_id(f) {
                return Err(invalid("requested_features item is not a feature id"));
            }
        }
        Ok(parsed)
    }
}

fn all_unique(items: &[String]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    items.iter().all(|i| seen.insert(i))
}

// --------------------------------------------------------- realm_show ----

/// `realm_show` args: the closed empty object (the read target is the
/// envelope `realm_id`; gap note KG16).
pub fn realm_show_args(args: &JsonMap) -> Result<(), Problem> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(invalid("realm_show args is the closed empty object"))
    }
}

// ------------------------------------------------------ project_create ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCreateArgs {
    pub name: String,
    #[serde(default)]
    pub default_classification_ref: Option<String>,
    #[serde(default)]
    pub policy_set_ref: Option<String>,
}

impl ProjectCreateArgs {
    pub fn from_args(args: &JsonMap) -> Result<ProjectCreateArgs, Problem> {
        let parsed: ProjectCreateArgs = parse_args(args)?;
        check_display("name", &parsed.name)?;
        check_opt_identifier(
            "default_classification_ref",
            &parsed.default_classification_ref,
        )?;
        check_opt_identifier("policy_set_ref", &parsed.policy_set_ref)?;
        Ok(parsed)
    }
}

// -------------------------------------------------------- space_create ----

pub const SPACE_VISIBILITIES: [&str; 2] = ["project", "restricted"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceCreateArgs {
    pub title: String,
    pub visibility: String,
    #[serde(default)]
    pub purpose_contribution_ref: Option<String>,
    #[serde(default)]
    pub default_classification_ref: Option<String>,
    #[serde(default)]
    pub policy_set_ref: Option<String>,
}

impl SpaceCreateArgs {
    pub fn from_args(args: &JsonMap) -> Result<SpaceCreateArgs, Problem> {
        let parsed: SpaceCreateArgs = parse_args(args)?;
        check_display("title", &parsed.title)?;
        if !SPACE_VISIBILITIES.contains(&parsed.visibility.as_str()) {
            return Err(invalid("visibility is not in the closed §10.2 enum"));
        }
        check_opt_identifier("purpose_contribution_ref", &parsed.purpose_contribution_ref)?;
        check_opt_identifier(
            "default_classification_ref",
            &parsed.default_classification_ref,
        )?;
        check_opt_identifier("policy_set_ref", &parsed.policy_set_ref)?;
        Ok(parsed)
    }
}

// ---------------------------------------------------------- space_show ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceShowArgs {
    pub space_id: String,
}

impl SpaceShowArgs {
    pub fn from_args(args: &JsonMap) -> Result<SpaceShowArgs, Problem> {
        let parsed: SpaceShowArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        Ok(parsed)
    }
}

// -------------------------------------------------- contribution_append ----

/// Closed ContributionKind enum, verbatim §10.2.
pub const CONTRIBUTION_KINDS: [&str; 12] = [
    "utterance",
    "goal",
    "question",
    "claim",
    "observation",
    "evidence",
    "proposal",
    "critique",
    "synthesis",
    "result",
    "decision_reference",
    "system_notice",
];

/// Closed epistemic-posture enum, verbatim §10.2.
pub const EPISTEMIC_POSTURES: [&str; 5] =
    ["asserted", "tentative", "observed", "reported", "contested"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionAppendArgs {
    pub space_id: String,
    pub branch_id: String,
    pub expected_head_digest: String,
    pub kind: String,
    pub body_parts: Vec<ContributionPart>,
    #[serde(default)]
    pub schema_ref: Option<String>,
    #[serde(default)]
    pub subject_refs: Option<Vec<String>>,
    #[serde(default)]
    pub source_refs: Option<Vec<String>>,
    #[serde(default)]
    pub epistemic_posture: Option<String>,
    #[serde(default)]
    pub classification_ref: Option<String>,
    #[serde(default)]
    pub retention_policy_ref: Option<String>,
    /// Worker-surface binding (§15.2); schema-valid but refused on the
    /// external_client surface at dispatch (registry rule, gap note KG14).
    #[serde(default)]
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub fence_epoch: Option<u64>,
}

impl ContributionAppendArgs {
    pub fn from_args(args: &JsonMap) -> Result<ContributionAppendArgs, Problem> {
        let parsed: ContributionAppendArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        check_identifier("branch_id", &parsed.branch_id)?;
        if !limits::is_digest_hex(&parsed.expected_head_digest) {
            return Err(invalid("expected_head_digest is not 64 lowercase hex"));
        }
        if !CONTRIBUTION_KINDS.contains(&parsed.kind.as_str()) {
            return Err(invalid("kind is not in the closed ContributionKind enum"));
        }
        if parsed.body_parts.is_empty() || parsed.body_parts.len() > limits::LIST_MAX_ITEMS {
            return Err(invalid("body_parts must hold 1-256 items"));
        }
        for part in &parsed.body_parts {
            validate_part(part)?;
        }
        check_opt_identifier("schema_ref", &parsed.schema_ref)?;
        for (field, refs) in [
            ("subject_refs", &parsed.subject_refs),
            ("source_refs", &parsed.source_refs),
        ] {
            if let Some(items) = refs {
                if items.len() > limits::LIST_MAX_ITEMS {
                    return Err(invalid(format!("{field} holds more than 256 items")));
                }
                for item in items {
                    check_identifier(field, item)?;
                }
            }
        }
        if let Some(posture) = &parsed.epistemic_posture {
            if !EPISTEMIC_POSTURES.contains(&posture.as_str()) {
                return Err(invalid("epistemic_posture is not in the closed enum"));
            }
        }
        check_opt_identifier("classification_ref", &parsed.classification_ref)?;
        check_opt_identifier("retention_policy_ref", &parsed.retention_policy_ref)?;
        check_opt_identifier("attempt_id", &parsed.attempt_id)?;
        if let Some(fence) = parsed.fence_epoch {
            check_safe("fence_epoch", fence)?;
        }
        Ok(parsed)
    }
}

fn validate_part(part: &ContributionPart) -> Result<(), Problem> {
    match part {
        ContributionPart::Text {
            media_type,
            text,
            language,
        } => {
            if !limits::is_media_type(media_type) {
                return Err(invalid("media_type is not an RFC 6838 type/subtype"));
            }
            if text.chars().count() > limits::INLINE_TEXT_MAX_SCALARS {
                return Err(invalid("text exceeds the 64 KiB inline-content cap"));
            }
            if let Some(lang) = language {
                if !limits::is_language_tag(lang) {
                    return Err(invalid("language is not a BCP 47-shaped tag"));
                }
            }
        }
        ContributionPart::Data { schema_ref, .. } => {
            check_identifier("schema_ref", schema_ref)?;
        }
        ContributionPart::Artifact {
            artifact_ref,
            title,
        } => {
            check_identifier("artifact_ref", artifact_ref)?;
            if let Some(t) = title {
                check_display("title", t)?;
            }
        }
        ContributionPart::Reference {
            object_ref,
            object_revision,
            digest,
        } => {
            check_identifier("object_ref", object_ref)?;
            if let Some(rev) = object_revision {
                check_safe("object_revision", *rev)?;
            }
            if let Some(d) = digest {
                if !limits::is_digest_hex(d) {
                    return Err(invalid("digest is not 64 lowercase hex"));
                }
            }
        }
        ContributionPart::Mention {
            target_kind,
            target_ref,
            target_revision,
            display_text,
        } => {
            if !["principal", "assistant_alias"].contains(&target_kind.as_str()) {
                return Err(invalid("target_kind is not in the closed enum"));
            }
            check_identifier("target_ref", target_ref)?;
            check_safe("target_revision", *target_revision)?;
            check_display("display_text", display_text)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------- contribution_show ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionShowArgs {
    pub contribution_id: String,
}

impl ContributionShowArgs {
    pub fn from_args(args: &JsonMap) -> Result<ContributionShowArgs, Problem> {
        let parsed: ContributionShowArgs = parse_args(args)?;
        check_identifier("contribution_id", &parsed.contribution_id)?;
        Ok(parsed)
    }
}

// ---------------------------------------------------------- events_read ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsReadArgs {
    pub source: String,
    #[serde(default)]
    pub after_cursor: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub type_prefixes: Option<Vec<String>>,
    pub limit: u64,
}

impl EventsReadArgs {
    pub fn from_args(args: &JsonMap) -> Result<EventsReadArgs, Problem> {
        let parsed: EventsReadArgs = parse_args(args)?;
        check_identifier("source", &parsed.source)?;
        if let Some(cursor) = &parsed.after_cursor {
            if cursor.is_empty() || cursor.chars().count() > limits::CURSOR_MAX_CHARS {
                return Err(invalid("after_cursor must hold 1-4096 characters"));
            }
        }
        check_opt_identifier("project_id", &parsed.project_id)?;
        if let Some(prefixes) = &parsed.type_prefixes {
            if prefixes.len() > limits::LIST_MAX_ITEMS {
                return Err(invalid("type_prefixes holds more than 256 items"));
            }
            for p in prefixes {
                if !limits::is_event_type_prefix(p) {
                    return Err(invalid("type_prefixes item is not an event-type prefix"));
                }
            }
        }
        if parsed.limit < 1 || parsed.limit > limits::PAGE_MAX_LIMIT {
            return Err(invalid("limit must be 1-512"));
        }
        Ok(parsed)
    }
}

/// Validates an operation's args against its slice-1 schema mirror,
/// discarding the parse — the shared schema-conformance gate the vector
/// round-trip test drives directly.
pub fn validate_op_args(op: &str, args: &JsonMap) -> Result<(), Problem> {
    match op {
        "hello" => HelloArgs::from_args(args).map(drop),
        "realm_show" => realm_show_args(args),
        "project_create" => ProjectCreateArgs::from_args(args).map(drop),
        "space_create" => SpaceCreateArgs::from_args(args).map(drop),
        "space_show" => SpaceShowArgs::from_args(args).map(drop),
        "contribution_append" => ContributionAppendArgs::from_args(args).map(drop),
        "contribution_show" => ContributionShowArgs::from_args(args).map(drop),
        "events_read" => EventsReadArgs::from_args(args).map(drop),
        other => Err(Problem::new(
            ProblemKind::UnknownOp,
            format!("operation {other} is not in the slice-1 table"),
        )),
    }
}
