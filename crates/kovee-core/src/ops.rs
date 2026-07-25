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

/// The K1 operation table (slice 1 + slice 2). Every operation here has a
/// registry row (`spec/registry.json`); an operation absent from the
/// registry is not callable (§11.6.1) and dispatch answers `unknown-op`.
/// Surface acceptance (external_client vs worker) is enforced by the
/// daemon's per-socket dispatch tables, not here.
pub const K1_OPS: [OpSpec; 25] = [
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
    // ------------------------------------------------ slice-2 additions ----
    OpSpec {
        name: "relation_assert",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "contribution_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "frontier_pin",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "frontier_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "lens_read",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "context_assembly_create",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "context_assembly_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "events_wait",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "artifact_upload_begin",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "artifact_upload_credential",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "artifact_upload_finalize",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "artifact_upload_abort",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "artifact_upload_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "artifact_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "invocation_create",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "invocation_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
];

pub fn op_spec(name: &str) -> Option<&'static OpSpec> {
    K1_OPS.iter().find(|s| s.name == name)
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

// ------------------------------------------------------ relation_assert ----

/// Closed RelationKind enum, verbatim §10.2.
pub const RELATION_KINDS: [&str; 11] = [
    "addresses",
    "supports",
    "challenges",
    "refines",
    "qualifies",
    "supersedes",
    "depends_on",
    "derived_from",
    "produced_by",
    "quotes",
    "evaluates",
];

/// `objectRefTriple` args mirror.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefTripleArgs {
    pub object_ref: String,
    pub revision: u64,
    pub digest: String,
}

fn check_ref_triple(field: &str, triple: &RefTripleArgs) -> Result<(), Problem> {
    check_identifier(field, &triple.object_ref)?;
    check_safe(field, triple.revision)?;
    if !limits::is_digest_hex(&triple.digest) {
        return Err(invalid(format!("{field}.digest is not 64 lowercase hex")));
    }
    Ok(())
}

/// `relation_assert` args: the public/worker schema excludes
/// `relation_class` — an external caller cannot request, spoof, or
/// upgrade a structural relation (§10.2).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationAssertArgs {
    pub space_id: String,
    pub branch_id: String,
    pub expected_head_digest: String,
    pub kind: String,
    pub from_ref: RefTripleArgs,
    pub to_ref: RefTripleArgs,
    #[serde(default)]
    pub rationale_ref: Option<String>,
    #[serde(default)]
    pub schema_ref: Option<String>,
    /// Worker-surface binding (§15.2); refused on external_client.
    #[serde(default)]
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub fence_epoch: Option<u64>,
}

impl RelationAssertArgs {
    pub fn from_args(args: &JsonMap) -> Result<RelationAssertArgs, Problem> {
        let parsed: RelationAssertArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        check_identifier("branch_id", &parsed.branch_id)?;
        if !limits::is_digest_hex(&parsed.expected_head_digest) {
            return Err(invalid("expected_head_digest is not 64 lowercase hex"));
        }
        if !RELATION_KINDS.contains(&parsed.kind.as_str()) {
            return Err(invalid("kind is not in the closed RelationKind enum"));
        }
        check_ref_triple("from_ref", &parsed.from_ref)?;
        check_ref_triple("to_ref", &parsed.to_ref)?;
        check_opt_identifier("rationale_ref", &parsed.rationale_ref)?;
        check_opt_identifier("schema_ref", &parsed.schema_ref)?;
        check_opt_identifier("attempt_id", &parsed.attempt_id)?;
        if let Some(fence) = parsed.fence_epoch {
            check_safe("fence_epoch", fence)?;
        }
        Ok(parsed)
    }
}

// ----------------------------------------------------------- list reads ----

fn check_cursor(field: &str, value: &Option<String>) -> Result<(), Problem> {
    if let Some(cursor) = value {
        if cursor.is_empty() || cursor.chars().count() > limits::CURSOR_MAX_CHARS {
            return Err(invalid(format!("{field} must hold 1-4096 characters")));
        }
    }
    Ok(())
}

fn check_limit(limit: u64) -> Result<(), Problem> {
    if (1..=limits::PAGE_MAX_LIMIT).contains(&limit) {
        Ok(())
    } else {
        Err(invalid("limit must be 1-512"))
    }
}

/// `space_list` args (§11.5 pagination shape).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceListArgs {
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl SpaceListArgs {
    pub fn from_args(args: &JsonMap) -> Result<SpaceListArgs, Problem> {
        let parsed: SpaceListArgs = parse_args(args)?;
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

/// `contribution_list` args.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionListArgs {
    pub space_id: String,
    #[serde(default)]
    pub branch_id: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl ContributionListArgs {
    pub fn from_args(args: &JsonMap) -> Result<ContributionListArgs, Problem> {
        let parsed: ContributionListArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        check_opt_identifier("branch_id", &parsed.branch_id)?;
        if let Some(kind) = &parsed.kind {
            if !CONTRIBUTION_KINDS.contains(&kind.as_str()) {
                return Err(invalid("kind is not in the closed ContributionKind enum"));
            }
        }
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

/// `lens_read` args.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LensReadArgs {
    pub lens_id: String,
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl LensReadArgs {
    pub fn from_args(args: &JsonMap) -> Result<LensReadArgs, Problem> {
        let parsed: LensReadArgs = parse_args(args)?;
        check_identifier("lens_id", &parsed.lens_id)?;
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

// ------------------------------------------------------------ frontiers ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierPinArgs {
    pub space_id: String,
    pub branch_id: String,
}

impl FrontierPinArgs {
    pub fn from_args(args: &JsonMap) -> Result<FrontierPinArgs, Problem> {
        let parsed: FrontierPinArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        check_identifier("branch_id", &parsed.branch_id)?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierShowArgs {
    pub frontier_id: String,
}

impl FrontierShowArgs {
    pub fn from_args(args: &JsonMap) -> Result<FrontierShowArgs, Problem> {
        let parsed: FrontierShowArgs = parse_args(args)?;
        check_identifier("frontier_id", &parsed.frontier_id)?;
        Ok(parsed)
    }
}

// ----------------------------------------------------- context assembly ----

/// Free-text ceiling (schema `freeText`, gap note KG8).
const FREE_TEXT_MAX_SCALARS: usize = 4096;

fn check_free_text(field: &str, value: &str) -> Result<(), Problem> {
    if value.chars().count() > FREE_TEXT_MAX_SCALARS {
        return Err(invalid(format!("{field} exceeds the 4096-scalar cap")));
    }
    Ok(())
}

fn check_ref_list(field: &str, refs: &Option<Vec<String>>) -> Result<(), Problem> {
    if let Some(items) = refs {
        if items.len() > limits::LIST_MAX_ITEMS {
            return Err(invalid(format!("{field} holds more than 256 items")));
        }
        for item in items {
            check_identifier(field, item)?;
        }
    }
    Ok(())
}

/// `context_assembly_create` args (§10.8): K1 serves exactly the built-in
/// `explicit_refs_v1` selection policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAssemblyCreateArgs {
    pub space_id: String,
    pub branch_id: String,
    pub audience_ref: String,
    pub purpose: String,
    pub selection_policy_ref: String,
    #[serde(default)]
    pub required_refs: Option<Vec<String>>,
    #[serde(default)]
    pub trigger_refs: Option<Vec<String>>,
    #[serde(default)]
    pub recipe_ref: Option<String>,
    #[serde(default)]
    pub recipe_revision: Option<u64>,
    #[serde(default)]
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub fence_epoch: Option<u64>,
}

impl ContextAssemblyCreateArgs {
    pub fn from_args(args: &JsonMap) -> Result<ContextAssemblyCreateArgs, Problem> {
        let parsed: ContextAssemblyCreateArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        check_identifier("branch_id", &parsed.branch_id)?;
        check_identifier("audience_ref", &parsed.audience_ref)?;
        check_free_text("purpose", &parsed.purpose)?;
        check_identifier("selection_policy_ref", &parsed.selection_policy_ref)?;
        check_ref_list("required_refs", &parsed.required_refs)?;
        check_ref_list("trigger_refs", &parsed.trigger_refs)?;
        check_opt_identifier("recipe_ref", &parsed.recipe_ref)?;
        if let Some(rev) = parsed.recipe_revision {
            check_safe("recipe_revision", rev)?;
        }
        check_opt_identifier("attempt_id", &parsed.attempt_id)?;
        if let Some(fence) = parsed.fence_epoch {
            check_safe("fence_epoch", fence)?;
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAssemblyShowArgs {
    pub assembly_id: String,
}

impl ContextAssemblyShowArgs {
    pub fn from_args(args: &JsonMap) -> Result<ContextAssemblyShowArgs, Problem> {
        let parsed: ContextAssemblyShowArgs = parse_args(args)?;
        check_identifier("assembly_id", &parsed.assembly_id)?;
        Ok(parsed)
    }
}

// ----------------------------------------------------------- events_wait ----

/// `events_wait` args (§11.4 verbatim: source, after_cursor, filters?,
/// timeout_ms). `filters` narrows and never widens; a filter member this
/// implementation cannot honor fails closed rather than silently widening.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsWaitArgs {
    pub source: String,
    pub after_cursor: String,
    #[serde(default)]
    pub filters: Option<JsonMap>,
    pub timeout_ms: u64,
}

impl EventsWaitArgs {
    pub fn from_args(args: &JsonMap) -> Result<EventsWaitArgs, Problem> {
        let parsed: EventsWaitArgs = parse_args(args)?;
        check_identifier("source", &parsed.source)?;
        if parsed.after_cursor.is_empty()
            || parsed.after_cursor.chars().count() > limits::CURSOR_MAX_CHARS
        {
            return Err(invalid("after_cursor must hold 1-4096 characters"));
        }
        check_safe("timeout_ms", parsed.timeout_ms)?;
        Ok(parsed)
    }

    /// The one filter member this implementation honors.
    pub fn type_prefixes(&self) -> Result<Option<Vec<String>>, Problem> {
        let Some(filters) = &self.filters else {
            return Ok(None);
        };
        let mut prefixes = None;
        for (key, value) in filters {
            match key.as_str() {
                "type_prefixes" => {
                    let items: Vec<String> = serde_json::from_value(value.clone())
                        .map_err(|_| invalid("filters.type_prefixes must be a string array"))?;
                    if items.len() > limits::LIST_MAX_ITEMS {
                        return Err(invalid("filters.type_prefixes holds more than 256 items"));
                    }
                    for p in &items {
                        if !limits::is_event_type_prefix(p) {
                            return Err(invalid("filters.type_prefixes item is not a prefix"));
                        }
                    }
                    prefixes = Some(items);
                }
                other => {
                    return Err(invalid(format!(
                        "filter {other:?} is not honored by this implementation (narrow-only)"
                    )));
                }
            }
        }
        Ok(prefixes)
    }
}

// ------------------------------------------------------------- artifacts ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUploadBeginArgs {
    pub declared_raw_sha256: String,
    pub declared_size: u64,
    pub declared_media_type: String,
    #[serde(default)]
    pub classification_ref: Option<String>,
}

impl ArtifactUploadBeginArgs {
    pub fn from_args(args: &JsonMap) -> Result<ArtifactUploadBeginArgs, Problem> {
        let parsed: ArtifactUploadBeginArgs = parse_args(args)?;
        if !limits::is_digest_hex(&parsed.declared_raw_sha256) {
            return Err(invalid("declared_raw_sha256 is not 64 lowercase hex"));
        }
        check_safe("declared_size", parsed.declared_size)?;
        if !limits::is_media_type(&parsed.declared_media_type) {
            return Err(invalid("declared_media_type is not type/subtype"));
        }
        check_opt_identifier("classification_ref", &parsed.classification_ref)?;
        Ok(parsed)
    }
}

/// Shared `{upload_id}` args (`credential`/`finalize`/`show`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadIdArgs {
    pub upload_id: String,
}

impl UploadIdArgs {
    pub fn from_args(args: &JsonMap) -> Result<UploadIdArgs, Problem> {
        let parsed: UploadIdArgs = parse_args(args)?;
        check_identifier("upload_id", &parsed.upload_id)?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUploadAbortArgs {
    pub upload_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

impl ArtifactUploadAbortArgs {
    pub fn from_args(args: &JsonMap) -> Result<ArtifactUploadAbortArgs, Problem> {
        let parsed: ArtifactUploadAbortArgs = parse_args(args)?;
        check_identifier("upload_id", &parsed.upload_id)?;
        if let Some(reason) = &parsed.reason {
            check_free_text("reason", reason)?;
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactShowArgs {
    pub artifact_id: String,
}

impl ArtifactShowArgs {
    pub fn from_args(args: &JsonMap) -> Result<ArtifactShowArgs, Problem> {
        let parsed: ArtifactShowArgs = parse_args(args)?;
        check_identifier("artifact_id", &parsed.artifact_id)?;
        Ok(parsed)
    }
}

// ------------------------------------------------------------ invocation ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationCreateArgs {
    pub assistant_deployment_id: String,
    pub assistant_deployment_revision: u64,
    #[serde(default)]
    pub space_id: Option<String>,
    #[serde(default)]
    pub branch_id: Option<String>,
    #[serde(default)]
    pub context_assembly_ref: Option<String>,
    #[serde(default)]
    pub context_assembly_digest: Option<String>,
    #[serde(default)]
    pub budget_reservation_set_ref: Option<String>,
    #[serde(default)]
    pub disclosure_rules_digest: Option<String>,
    #[serde(default)]
    pub priority: Option<u64>,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub max_attempts: Option<u64>,
    pub deadline: String,
}

impl InvocationCreateArgs {
    pub fn from_args(args: &JsonMap) -> Result<InvocationCreateArgs, Problem> {
        let parsed: InvocationCreateArgs = parse_args(args)?;
        check_identifier("assistant_deployment_id", &parsed.assistant_deployment_id)?;
        check_safe(
            "assistant_deployment_revision",
            parsed.assistant_deployment_revision,
        )?;
        check_opt_identifier("space_id", &parsed.space_id)?;
        check_opt_identifier("branch_id", &parsed.branch_id)?;
        check_opt_identifier("context_assembly_ref", &parsed.context_assembly_ref)?;
        for (field, digest) in [
            ("context_assembly_digest", &parsed.context_assembly_digest),
            ("disclosure_rules_digest", &parsed.disclosure_rules_digest),
        ] {
            if let Some(d) = digest {
                if !limits::is_digest_hex(d) {
                    return Err(invalid(format!("{field} is not 64 lowercase hex")));
                }
            }
        }
        check_opt_identifier(
            "budget_reservation_set_ref",
            &parsed.budget_reservation_set_ref,
        )?;
        if let Some(p) = parsed.priority {
            check_safe("priority", p)?;
        }
        if let Some(nb) = &parsed.not_before {
            if !limits::is_timestamp(nb) {
                return Err(invalid("not_before is not an RFC 3339 date-time"));
            }
        }
        if let Some(m) = parsed.max_attempts {
            check_safe("max_attempts", m)?;
        }
        if !limits::is_timestamp(&parsed.deadline) {
            return Err(invalid("deadline is not an RFC 3339 date-time"));
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationShowArgs {
    pub invocation_id: String,
}

impl InvocationShowArgs {
    pub fn from_args(args: &JsonMap) -> Result<InvocationShowArgs, Problem> {
        let parsed: InvocationShowArgs = parse_args(args)?;
        check_identifier("invocation_id", &parsed.invocation_id)?;
        Ok(parsed)
    }
}

/// Validates an operation's args against its K1 schema mirror, discarding
/// the parse — the shared schema-conformance gate the vector round-trip
/// tests drive directly.
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
        "relation_assert" => RelationAssertArgs::from_args(args).map(drop),
        "space_list" => SpaceListArgs::from_args(args).map(drop),
        "contribution_list" => ContributionListArgs::from_args(args).map(drop),
        "frontier_pin" => FrontierPinArgs::from_args(args).map(drop),
        "frontier_show" => FrontierShowArgs::from_args(args).map(drop),
        "lens_read" => LensReadArgs::from_args(args).map(drop),
        "context_assembly_create" => ContextAssemblyCreateArgs::from_args(args).map(drop),
        "context_assembly_show" => ContextAssemblyShowArgs::from_args(args).map(drop),
        "events_wait" => EventsWaitArgs::from_args(args).map(drop),
        "artifact_upload_begin" => ArtifactUploadBeginArgs::from_args(args).map(drop),
        "artifact_upload_credential" | "artifact_upload_finalize" | "artifact_upload_show" => {
            UploadIdArgs::from_args(args).map(drop)
        }
        "artifact_upload_abort" => ArtifactUploadAbortArgs::from_args(args).map(drop),
        "artifact_show" => ArtifactShowArgs::from_args(args).map(drop),
        "invocation_create" => InvocationCreateArgs::from_args(args).map(drop),
        "invocation_show" => InvocationShowArgs::from_args(args).map(drop),
        other => Err(Problem::new(
            ProblemKind::UnknownOp,
            format!("operation {other} is not in the K1 table"),
        )),
    }
}
