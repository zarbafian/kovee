//! The K1 operation surface: per-operation argument shapes mirroring
//! `spec/schemas/ops/<op>-request.schema.json`, plus the registry-derived
//! read/mutation meta rule and envelope field placement.
//!
//! The registry (`spec/registry.json`) fixes which operations exist and on
//! which surface; the per-op schemas fix the closed argument shapes. This
//! module implements both in Rust — no JSON-Schema engine — and the vector
//! round-trip tests (`tests/k1_slice1_vectors.rs`, `tests/k1_vectors.rs`)
//! prove agreement with the schema files for every `spec/vectors/ops/`
//! case. Slice 3 closes the table: every distinct registry operation of
//! the three K1 bundles has a row here (parity is machine-checked against
//! `spec/registry.json` by `tests/k1_vectors.rs`).

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

/// One row per distinct registry operation. Every operation here has a
/// registry row (`spec/registry.json`); an operation absent from the
/// registry is not callable (§11.6.1) and dispatch answers `unknown-op`.
/// Surface acceptance (external_client vs worker vs operator — the
/// operator entries bind to the owner principal in the personal profile,
/// registry-README resolutions 5/6) is enforced by the daemon's
/// per-socket dispatch tables, not here.
///
/// The three K1 bundles close at 86 operations; K2 slice 1 adds the three
/// `governed_work_binding_v1` greenfield-binding operations (89) and slice
/// 2 the six formation/episode-binding ones (95). The bundle is still
/// INCOMPLETE — `collaboration_context_bundle_*` and `workspace_*` are
/// unbuilt — so `hello` does not advertise it (§11.6: bundles are atomic).
pub const KCP_OPS: [OpSpec; 95] = [
    OpSpec {
        name: "hello",
        kind: OpKind::Read,
        realm_id: FieldRule::Forbidden,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "protocol_info",
        kind: OpKind::Read,
        realm_id: FieldRule::Forbidden,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "diagnose",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
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
    // ------------------------------------------------ slice-3 additions ----
    OpSpec {
        name: "project_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "project_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "project_update_metadata",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "project_access_policy_change_prepare",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "project_access_policy_change_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "project_access_policy_change_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "project_access_policy_change_confirm",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "project_access_policy_change_cancel",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_update_metadata",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_freeze",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_reopen",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_archive",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_restrict",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_policy_narrow",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_access_widen_prepare",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_access_widen_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_access_widen_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_access_widen_confirm",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_access_widen_cancel",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_participant_add",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_participant_activate",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_participant_update",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_participant_remove",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_participant_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_access_grant_create",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_access_grant_revoke",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "space_access_grant_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "contribution_withdraw",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "contribution_supersede",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "contribution_redact",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "relation_retract",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "lens_create",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "lens_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "lens_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "lens_update",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "lens_revoke",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "reaction_set",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "event_payload",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "snapshot_read",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "disclosure_manifest_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "assistant_create",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "assistant_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "assistant_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "assistant_revision_register",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "assistant_revision_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "assistant_revision_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "deployment_create",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "deployment_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "deployment_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "deployment_activate",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "deployment_drain",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Optional,
    },
    OpSpec {
        name: "assistant_alias_bind",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "assistant_alias_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "assistant_alias_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "assistant_alias_update",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "assistant_alias_revoke",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "invocation_list",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "invocation_cancel",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    OpSpec {
        name: "application_event_emit",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Required,
    },
    // ------------------------- K2 slice 1: governed_work_binding_v1 ----
    // The greenfield-binding half (amendment A5 wire names). Realm-scoped
    // and project-free: a governed scope is named by its own selector,
    // never by the envelope's project placement.
    OpSpec {
        name: "governance_enable",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "governance_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "governance_disable",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    // ------------------------- K2 slice 2: governed_work_binding_v1 ----
    // The formation half (amendment A5 wire names for §11.6's
    // `mission_promotion_*` and `sage_turn_binding_show` rows). A
    // promotion is realm-scoped: the project, space, and branch it forms
    // over are read from the pinned frontier, never from the envelope, so
    // one command cannot name one project and pin another's frontier.
    OpSpec {
        name: "endeavor_promotion_prepare",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "endeavor_promotion_start",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "endeavor_promotion_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "endeavor_promotion_cancel",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "endeavor_promotion_reconcile",
        kind: OpKind::Mutation,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
    OpSpec {
        name: "byom_episode_binding_show",
        kind: OpKind::Read,
        realm_id: FieldRule::Required,
        project_id: FieldRule::Forbidden,
    },
];

pub fn op_spec(name: &str) -> Option<&'static OpSpec> {
    KCP_OPS.iter().find(|s| s.name == name)
}

impl OpSpec {
    /// The envelope [`Shape`] this op's request schema pins.
    pub fn shape(&self) -> Shape {
        if self.name == "hello" || self.name == "protocol_info" {
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

// ------------------------------------------------- slice-3 shared bits ----

/// `statusToken`: `^[a-z][a-z0-9_]{0,63}$` (gap note KG6 — bounded token,
/// no invented enum).
pub fn is_status_token(s: &str) -> bool {
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && s.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn check_status_token(field: &str, value: &str) -> Result<(), Problem> {
    if is_status_token(value) {
        Ok(())
    } else {
        Err(invalid(format!("{field} is not a bounded status token")))
    }
}

fn check_opt_status_token(field: &str, value: &Option<String>) -> Result<(), Problem> {
    match value {
        Some(v) => check_status_token(field, v),
        None => Ok(()),
    }
}

fn check_opt_timestamp(field: &str, value: &Option<String>) -> Result<(), Problem> {
    match value {
        Some(v) if limits::is_timestamp(v) => Ok(()),
        Some(_) => Err(invalid(format!("{field} is not an RFC 3339 date-time"))),
        None => Ok(()),
    }
}

fn check_object(field: &str, value: &Value) -> Result<(), Problem> {
    if value.is_object() {
        Ok(())
    } else {
        Err(invalid(format!("{field} must be a JSON object")))
    }
}

fn check_opt_object(field: &str, value: &Option<Value>) -> Result<(), Problem> {
    match value {
        Some(v) => check_object(field, v),
        None => Ok(()),
    }
}

fn check_id_list(field: &str, items: &[String], unique: bool) -> Result<(), Problem> {
    if items.len() > limits::LIST_MAX_ITEMS {
        return Err(invalid(format!("{field} holds more than 256 items")));
    }
    if unique && !all_unique(items) {
        return Err(invalid(format!("{field} items must be unique")));
    }
    for item in items {
        check_identifier(field, item)?;
    }
    Ok(())
}

/// The closed empty-args rule shared by `protocol_info`, `project_show`,
/// and `realm_show` (the read target travels in the envelope).
pub fn empty_args(op: &str, args: &JsonMap) -> Result<(), Problem> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(invalid(format!("{op} args is the closed empty object")))
    }
}

// ------------------------------------------------------------ diagnose ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnoseArgs {
    #[serde(default)]
    pub checks: Option<Vec<String>>,
}

impl DiagnoseArgs {
    pub fn from_args(args: &JsonMap) -> Result<DiagnoseArgs, Problem> {
        let parsed: DiagnoseArgs = parse_args(args)?;
        if let Some(checks) = &parsed.checks {
            check_id_list("checks", checks, true)?;
        }
        Ok(parsed)
    }
}

// ----------------------------------------------------- generic id reads ----

macro_rules! single_id_args {
    ($name:ident, $field:ident) => {
        #[derive(Debug, Clone, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub $field: String,
        }

        impl $name {
            pub fn from_args(args: &JsonMap) -> Result<$name, Problem> {
                let parsed: $name = parse_args(args)?;
                check_identifier(stringify!($field), &parsed.$field)?;
                Ok(parsed)
            }
        }
    };
}

single_id_args!(ChangeIdArgs, change_id);
single_id_args!(WideningIdArgs, widening_id);
single_id_args!(SpaceIdArgs, space_id);
single_id_args!(ParticipantIdArgs, participant_id);
single_id_args!(GrantRevokeArgs, space_access_id);
single_id_args!(LensIdArgs, lens_id);
single_id_args!(EventPayloadArgs, event_id);
single_id_args!(DisclosureManifestShowArgs, disclosure_id);
single_id_args!(AssistantShowArgs, definition_id);
single_id_args!(AssistantRevisionShowArgs, assistant_revision_id);
single_id_args!(DeploymentIdArgs, assistant_deployment_id);
single_id_args!(AliasIdArgs, alias_binding_id);

// -------------------------------------------------------- generic pages ----

/// The plain §11.5 page args `{ after?, limit, snapshot? }`
/// (`project_list`, `project_access_policy_change_list`,
/// `assistant_list`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageArgs {
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl PageArgs {
    pub fn from_args(args: &JsonMap) -> Result<PageArgs, Problem> {
        let parsed: PageArgs = parse_args(args)?;
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

/// A §11.5 page over one space's collection (`space_participant_list`,
/// `space_access_grant_list`, `lens_list`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacePageArgs {
    pub space_id: String,
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl SpacePageArgs {
    pub fn from_args(args: &JsonMap) -> Result<SpacePageArgs, Problem> {
        let parsed: SpacePageArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

/// `space_access_widen_list` args (`space_id` narrows, optionally).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidenListArgs {
    #[serde(default)]
    pub space_id: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl WidenListArgs {
    pub fn from_args(args: &JsonMap) -> Result<WidenListArgs, Problem> {
        let parsed: WidenListArgs = parse_args(args)?;
        check_opt_identifier("space_id", &parsed.space_id)?;
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

/// `assistant_revision_list` args.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantRevisionListArgs {
    #[serde(default)]
    pub definition_id: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl AssistantRevisionListArgs {
    pub fn from_args(args: &JsonMap) -> Result<AssistantRevisionListArgs, Problem> {
        let parsed: AssistantRevisionListArgs = parse_args(args)?;
        check_opt_identifier("definition_id", &parsed.definition_id)?;
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

/// `deployment_list` args.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentListArgs {
    #[serde(default)]
    pub assistant_revision_id: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl DeploymentListArgs {
    pub fn from_args(args: &JsonMap) -> Result<DeploymentListArgs, Problem> {
        let parsed: DeploymentListArgs = parse_args(args)?;
        check_opt_identifier("assistant_revision_id", &parsed.assistant_revision_id)?;
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

/// `assistant_alias_list` args.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasListArgs {
    #[serde(default)]
    pub assistant_deployment_id: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl AliasListArgs {
    pub fn from_args(args: &JsonMap) -> Result<AliasListArgs, Problem> {
        let parsed: AliasListArgs = parse_args(args)?;
        check_opt_identifier("assistant_deployment_id", &parsed.assistant_deployment_id)?;
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

/// Closed §10.6 invocation-state machine names.
pub const INVOCATION_STATES: [&str; 10] = [
    "queued",
    "claimed",
    "running",
    "waiting_commitment",
    "waiting_human",
    "waiting_resource",
    "succeeded",
    "failed",
    "canceled",
    "ambiguous",
];

/// `invocation_list` args.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationListArgs {
    #[serde(default)]
    pub assistant_deployment_id: Option<String>,
    #[serde(default)]
    pub space_id: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl InvocationListArgs {
    pub fn from_args(args: &JsonMap) -> Result<InvocationListArgs, Problem> {
        let parsed: InvocationListArgs = parse_args(args)?;
        check_opt_identifier("assistant_deployment_id", &parsed.assistant_deployment_id)?;
        check_opt_identifier("space_id", &parsed.space_id)?;
        if let Some(state) = &parsed.state {
            if !INVOCATION_STATES.contains(&state.as_str()) {
                return Err(invalid("state is not in the closed §10.6 enum"));
            }
        }
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

/// `snapshot_read` args (§11.5 page + the collection selector, KG28).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotReadArgs {
    pub source: String,
    #[serde(default)]
    pub after: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub snapshot: Option<String>,
}

impl SnapshotReadArgs {
    pub fn from_args(args: &JsonMap) -> Result<SnapshotReadArgs, Problem> {
        let parsed: SnapshotReadArgs = parse_args(args)?;
        check_identifier("source", &parsed.source)?;
        check_cursor("after", &parsed.after)?;
        check_limit(parsed.limit)?;
        check_cursor("snapshot", &parsed.snapshot)?;
        Ok(parsed)
    }
}

// -------------------------------------------------- project mutations ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUpdateMetadataArgs {
    pub name: String,
}

impl ProjectUpdateMetadataArgs {
    pub fn from_args(args: &JsonMap) -> Result<ProjectUpdateMetadataArgs, Problem> {
        let parsed: ProjectUpdateMetadataArgs = parse_args(args)?;
        check_display("name", &parsed.name)?;
        Ok(parsed)
    }
}

/// `project_access_policy_change_prepare` args: proposal deltas only —
/// prior values and digests are server-derived (KG5/KG17).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PapcPrepareArgs {
    #[serde(default)]
    pub proposed_policy_set_ref: Option<String>,
    #[serde(default)]
    pub proposed_default_classification_ref: Option<String>,
}

impl PapcPrepareArgs {
    pub fn from_args(args: &JsonMap) -> Result<PapcPrepareArgs, Problem> {
        let parsed: PapcPrepareArgs = parse_args(args)?;
        check_opt_identifier("proposed_policy_set_ref", &parsed.proposed_policy_set_ref)?;
        check_opt_identifier(
            "proposed_default_classification_ref",
            &parsed.proposed_default_classification_ref,
        )?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PapcConfirmArgs {
    pub change_id: String,
    pub decision_receipt_ref: String,
}

impl PapcConfirmArgs {
    pub fn from_args(args: &JsonMap) -> Result<PapcConfirmArgs, Problem> {
        let parsed: PapcConfirmArgs = parse_args(args)?;
        check_identifier("change_id", &parsed.change_id)?;
        check_identifier("decision_receipt_ref", &parsed.decision_receipt_ref)?;
        Ok(parsed)
    }
}

// ---------------------------------------------------- space lifecycle ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceUpdateMetadataArgs {
    pub space_id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub purpose_contribution_ref: Option<String>,
}

impl SpaceUpdateMetadataArgs {
    pub fn from_args(args: &JsonMap) -> Result<SpaceUpdateMetadataArgs, Problem> {
        let parsed: SpaceUpdateMetadataArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        if let Some(title) = &parsed.title {
            check_display("title", title)?;
        }
        check_opt_identifier("purpose_contribution_ref", &parsed.purpose_contribution_ref)?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacePolicyNarrowArgs {
    pub space_id: String,
    #[serde(default)]
    pub policy_set_ref: Option<String>,
    #[serde(default)]
    pub default_classification_ref: Option<String>,
}

impl SpacePolicyNarrowArgs {
    pub fn from_args(args: &JsonMap) -> Result<SpacePolicyNarrowArgs, Problem> {
        let parsed: SpacePolicyNarrowArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        check_opt_identifier("policy_set_ref", &parsed.policy_set_ref)?;
        check_opt_identifier(
            "default_classification_ref",
            &parsed.default_classification_ref,
        )?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidenPrepareArgs {
    pub space_id: String,
    #[serde(default)]
    pub proposed_visibility: Option<String>,
    #[serde(default)]
    pub proposed_policy_set_ref: Option<String>,
    #[serde(default)]
    pub proposed_default_classification_ref: Option<String>,
}

impl WidenPrepareArgs {
    pub fn from_args(args: &JsonMap) -> Result<WidenPrepareArgs, Problem> {
        let parsed: WidenPrepareArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        if let Some(visibility) = &parsed.proposed_visibility {
            if !SPACE_VISIBILITIES.contains(&visibility.as_str()) {
                return Err(invalid(
                    "proposed_visibility is not in the closed §10.2 enum",
                ));
            }
        }
        check_opt_identifier("proposed_policy_set_ref", &parsed.proposed_policy_set_ref)?;
        check_opt_identifier(
            "proposed_default_classification_ref",
            &parsed.proposed_default_classification_ref,
        )?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidenConfirmArgs {
    pub widening_id: String,
    pub decision_receipt_ref: String,
}

impl WidenConfirmArgs {
    pub fn from_args(args: &JsonMap) -> Result<WidenConfirmArgs, Problem> {
        let parsed: WidenConfirmArgs = parse_args(args)?;
        check_identifier("widening_id", &parsed.widening_id)?;
        check_identifier("decision_receipt_ref", &parsed.decision_receipt_ref)?;
        Ok(parsed)
    }
}

// -------------------------------------------------------- participants ----

/// Closed SpaceParticipant enums, verbatim §10.2.
pub const PARTICIPANT_KINDS: [&str; 4] = [
    "principal",
    "assistant_deployment",
    "service",
    "peer_projection",
];
pub const PARTICIPANT_ROLES: [&str; 3] = ["steward", "contributor", "observer"];
pub const PARTICIPANT_STATUSES: [&str; 4] = ["proposed", "active", "muted", "revoked"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantAddArgs {
    pub space_id: String,
    pub subject_ref: String,
    pub kind: String,
    pub role: String,
    #[serde(default)]
    pub subject_revision: Option<u64>,
}

impl ParticipantAddArgs {
    pub fn from_args(args: &JsonMap) -> Result<ParticipantAddArgs, Problem> {
        let parsed: ParticipantAddArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        check_identifier("subject_ref", &parsed.subject_ref)?;
        if !PARTICIPANT_KINDS.contains(&parsed.kind.as_str()) {
            return Err(invalid("kind is not in the closed SpaceParticipant enum"));
        }
        if !PARTICIPANT_ROLES.contains(&parsed.role.as_str()) {
            return Err(invalid("role is not in the closed SpaceParticipant enum"));
        }
        if let Some(rev) = parsed.subject_revision {
            check_safe("subject_revision", rev)?;
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantActivateArgs {
    pub participant_id: String,
    pub subject_digest: String,
}

impl ParticipantActivateArgs {
    pub fn from_args(args: &JsonMap) -> Result<ParticipantActivateArgs, Problem> {
        let parsed: ParticipantActivateArgs = parse_args(args)?;
        check_identifier("participant_id", &parsed.participant_id)?;
        if !limits::is_digest_hex(&parsed.subject_digest) {
            return Err(invalid("subject_digest is not 64 lowercase hex"));
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantUpdateArgs {
    pub participant_id: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

impl ParticipantUpdateArgs {
    pub fn from_args(args: &JsonMap) -> Result<ParticipantUpdateArgs, Problem> {
        let parsed: ParticipantUpdateArgs = parse_args(args)?;
        check_identifier("participant_id", &parsed.participant_id)?;
        if let Some(role) = &parsed.role {
            if !PARTICIPANT_ROLES.contains(&role.as_str()) {
                return Err(invalid("role is not in the closed SpaceParticipant enum"));
            }
        }
        if let Some(status) = &parsed.status {
            if !PARTICIPANT_STATUSES.contains(&status.as_str()) {
                return Err(invalid("status is not in the closed SpaceParticipant enum"));
            }
        }
        Ok(parsed)
    }
}

// -------------------------------------------------------------- grants ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantCreateArgs {
    pub space_id: String,
    pub subject_ref: String,
    pub allowed_actions: Vec<String>,
    #[serde(default)]
    pub classification_ceiling_ref: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl GrantCreateArgs {
    pub fn from_args(args: &JsonMap) -> Result<GrantCreateArgs, Problem> {
        let parsed: GrantCreateArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        check_identifier("subject_ref", &parsed.subject_ref)?;
        if parsed.allowed_actions.is_empty()
            || parsed.allowed_actions.len() > limits::LIST_MAX_ITEMS
        {
            return Err(invalid("allowed_actions must hold 1-256 items"));
        }
        for action in &parsed.allowed_actions {
            check_status_token("allowed_actions", action)?;
        }
        check_opt_identifier(
            "classification_ceiling_ref",
            &parsed.classification_ceiling_ref,
        )?;
        check_opt_timestamp("expires_at", &parsed.expires_at)?;
        Ok(parsed)
    }
}

// -------------------------------------------------------- dispositions ----

/// `contribution_withdraw` / `contribution_redact` args (§10.2
/// ContributionDisposition caller fields, KG22).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionDispositionArgs {
    pub contribution_ref: String,
    pub reason_class: String,
}

impl ContributionDispositionArgs {
    pub fn from_args(args: &JsonMap) -> Result<ContributionDispositionArgs, Problem> {
        let parsed: ContributionDispositionArgs = parse_args(args)?;
        check_identifier("contribution_ref", &parsed.contribution_ref)?;
        check_status_token("reason_class", &parsed.reason_class)?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionSupersedeArgs {
    pub contribution_ref: String,
    pub replacement_ref: String,
    pub reason_class: String,
}

impl ContributionSupersedeArgs {
    pub fn from_args(args: &JsonMap) -> Result<ContributionSupersedeArgs, Problem> {
        let parsed: ContributionSupersedeArgs = parse_args(args)?;
        check_identifier("contribution_ref", &parsed.contribution_ref)?;
        check_identifier("replacement_ref", &parsed.replacement_ref)?;
        check_status_token("reason_class", &parsed.reason_class)?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationRetractArgs {
    pub relation_ref: String,
    pub reason_class: String,
}

impl RelationRetractArgs {
    pub fn from_args(args: &JsonMap) -> Result<RelationRetractArgs, Problem> {
        let parsed: RelationRetractArgs = parse_args(args)?;
        check_identifier("relation_ref", &parsed.relation_ref)?;
        check_status_token("reason_class", &parsed.reason_class)?;
        Ok(parsed)
    }
}

// -------------------------------------------------------------- lenses ----

/// Closed SpaceLens.kind enum, verbatim §10.2.
pub const LENS_KINDS: [&str; 7] = [
    "stream",
    "workbench",
    "pulse",
    "branch_compare",
    "ensemble",
    "provenance",
    "custom",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LensCreateArgs {
    pub space_id: String,
    pub kind: String,
    pub query_ast: Value,
    pub sort_spec: Value,
    pub presentation_options: Value,
    pub visibility: String,
}

impl LensCreateArgs {
    pub fn from_args(args: &JsonMap) -> Result<LensCreateArgs, Problem> {
        let parsed: LensCreateArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        if !LENS_KINDS.contains(&parsed.kind.as_str()) {
            return Err(invalid("kind is not in the closed SpaceLens enum"));
        }
        check_object("query_ast", &parsed.query_ast)?;
        check_object("sort_spec", &parsed.sort_spec)?;
        check_object("presentation_options", &parsed.presentation_options)?;
        check_status_token("visibility", &parsed.visibility)?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LensUpdateArgs {
    pub lens_id: String,
    #[serde(default)]
    pub query_ast: Option<Value>,
    #[serde(default)]
    pub sort_spec: Option<Value>,
    #[serde(default)]
    pub presentation_options: Option<Value>,
    #[serde(default)]
    pub visibility: Option<String>,
}

impl LensUpdateArgs {
    pub fn from_args(args: &JsonMap) -> Result<LensUpdateArgs, Problem> {
        let parsed: LensUpdateArgs = parse_args(args)?;
        check_identifier("lens_id", &parsed.lens_id)?;
        check_opt_object("query_ast", &parsed.query_ast)?;
        check_opt_object("sort_spec", &parsed.sort_spec)?;
        check_opt_object("presentation_options", &parsed.presentation_options)?;
        check_opt_status_token("visibility", &parsed.visibility)?;
        Ok(parsed)
    }
}

// ------------------------------------------------------------ reactions ----

/// Closed Reaction.state enum, verbatim §10.2.
pub const REACTION_STATES: [&str; 2] = ["present", "removed"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionSetArgs {
    pub space_id: String,
    pub target_ref: String,
    pub target_revision: u64,
    pub target_digest: String,
    pub key: String,
    pub state: String,
}

impl ReactionSetArgs {
    pub fn from_args(args: &JsonMap) -> Result<ReactionSetArgs, Problem> {
        let parsed: ReactionSetArgs = parse_args(args)?;
        check_identifier("space_id", &parsed.space_id)?;
        check_identifier("target_ref", &parsed.target_ref)?;
        check_safe("target_revision", parsed.target_revision)?;
        if !limits::is_digest_hex(&parsed.target_digest) {
            return Err(invalid("target_digest is not 64 lowercase hex"));
        }
        check_status_token("key", &parsed.key)?;
        if !REACTION_STATES.contains(&parsed.state.as_str()) {
            return Err(invalid("state is not in the closed Reaction enum"));
        }
        Ok(parsed)
    }
}

// ----------------------------------------------------------- assistants ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantCreateArgs {
    pub name: String,
    pub description: String,
}

impl AssistantCreateArgs {
    pub fn from_args(args: &JsonMap) -> Result<AssistantCreateArgs, Problem> {
        let parsed: AssistantCreateArgs = parse_args(args)?;
        check_display("name", &parsed.name)?;
        check_free_text("description", &parsed.description)?;
        Ok(parsed)
    }
}

/// Closed §14.4 security-profile names and §15.3 concurrency policies.
pub const SECURITY_PROFILES: [&str; 3] = ["developer", "confined", "secure"];
pub const CONCURRENCY_POLICIES: [&str; 3] =
    ["serial-branch", "parallel-independent", "causal-keyed"];

/// `resource_limits {cpu, memory, disk, output_bytes}` verbatim §14.2
/// (units unpinned, gap note KG7).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub cpu: u64,
    pub memory: u64,
    pub disk: u64,
    pub output_bytes: u64,
}

/// The §14.2 assistant-revision manifest, typed per gap note KG7 — the
/// closed field list verbatim; open members (`runtime`, `network_policy`,
/// `attention_proposals[]`) carry no authority.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionManifest {
    pub schema_version: String,
    pub definition_id: String,
    pub version: String,
    pub entrypoint: String,
    pub package_digest: String,
    pub runtime: Value,
    pub supported_worker_protocols: Vec<String>,
    pub input_schema_ref: String,
    pub output_schema_ref: String,
    pub skills: Vec<String>,
    pub attention_proposals: Vec<Value>,
    pub requested_capabilities: Vec<String>,
    pub model_profiles: Vec<String>,
    pub tool_profiles: Vec<String>,
    pub network_policy: Value,
    pub resource_limits: ResourceLimits,
    pub default_timeout: u64,
    pub max_concurrency: u64,
    pub causal_concurrency_policy: String,
    pub checkpoint_support: bool,
    pub cancellation_support: bool,
    pub security_profiles: Vec<String>,
}

impl RevisionManifest {
    fn validate(&self) -> Result<(), Problem> {
        for (field, value) in [
            ("manifest.schema_version", &self.schema_version),
            ("manifest.definition_id", &self.definition_id),
            ("manifest.version", &self.version),
            ("manifest.entrypoint", &self.entrypoint),
            ("manifest.input_schema_ref", &self.input_schema_ref),
            ("manifest.output_schema_ref", &self.output_schema_ref),
        ] {
            check_identifier(field, value)?;
        }
        if !limits::is_digest_hex(&self.package_digest) {
            return Err(invalid("manifest.package_digest is not 64 lowercase hex"));
        }
        check_object("manifest.runtime", &self.runtime)?;
        check_object("manifest.network_policy", &self.network_policy)?;
        for (field, list) in [
            (
                "manifest.supported_worker_protocols",
                &self.supported_worker_protocols,
            ),
            ("manifest.skills", &self.skills),
            (
                "manifest.requested_capabilities",
                &self.requested_capabilities,
            ),
            ("manifest.model_profiles", &self.model_profiles),
            ("manifest.tool_profiles", &self.tool_profiles),
        ] {
            check_id_list(field, list, true)?;
        }
        if self.attention_proposals.len() > limits::LIST_MAX_ITEMS {
            return Err(invalid(
                "manifest.attention_proposals holds more than 256 items",
            ));
        }
        for proposal in &self.attention_proposals {
            check_object("manifest.attention_proposals", proposal)?;
        }
        for (field, value) in [
            ("manifest.resource_limits.cpu", self.resource_limits.cpu),
            (
                "manifest.resource_limits.memory",
                self.resource_limits.memory,
            ),
            ("manifest.resource_limits.disk", self.resource_limits.disk),
            (
                "manifest.resource_limits.output_bytes",
                self.resource_limits.output_bytes,
            ),
            ("manifest.default_timeout", self.default_timeout),
            ("manifest.max_concurrency", self.max_concurrency),
        ] {
            check_safe(field, value)?;
        }
        if !CONCURRENCY_POLICIES.contains(&self.causal_concurrency_policy.as_str()) {
            return Err(invalid(
                "manifest.causal_concurrency_policy is not in the closed §15.3 set",
            ));
        }
        if self.security_profiles.is_empty()
            || self.security_profiles.len() > 3
            || !all_unique(&self.security_profiles)
        {
            return Err(invalid(
                "manifest.security_profiles must hold 1-3 unique profiles",
            ));
        }
        for profile in &self.security_profiles {
            if !SECURITY_PROFILES.contains(&profile.as_str()) {
                return Err(invalid(
                    "manifest.security_profiles item is not a §14.4 profile",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantRevisionRegisterArgs {
    pub definition_id: String,
    pub version: String,
    pub manifest: RevisionManifest,
    pub package_artifact_ref: String,
    pub package_digest: String,
    pub config_schema_digest: String,
    pub sdk_protocol_range: String,
    #[serde(default)]
    pub signature_refs: Option<Vec<String>>,
}

impl AssistantRevisionRegisterArgs {
    pub fn from_args(args: &JsonMap) -> Result<AssistantRevisionRegisterArgs, Problem> {
        let parsed: AssistantRevisionRegisterArgs = parse_args(args)?;
        check_identifier("definition_id", &parsed.definition_id)?;
        check_identifier("version", &parsed.version)?;
        parsed.manifest.validate()?;
        check_identifier("package_artifact_ref", &parsed.package_artifact_ref)?;
        for (field, digest) in [
            ("package_digest", &parsed.package_digest),
            ("config_schema_digest", &parsed.config_schema_digest),
        ] {
            if !limits::is_digest_hex(digest) {
                return Err(invalid(format!("{field} is not 64 lowercase hex")));
            }
        }
        check_identifier("sdk_protocol_range", &parsed.sdk_protocol_range)?;
        if let Some(refs) = &parsed.signature_refs {
            check_id_list("signature_refs", refs, true)?;
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentCreateArgs {
    pub assistant_revision_id: String,
    pub config_ref: String,
    pub config_digest: String,
    pub secret_binding_set_ref: String,
    pub secret_binding_set_digest: String,
    pub policy_ref: String,
    pub pool_ref: String,
    pub security_profile: String,
    pub concurrency_policy: String,
    pub rollout_policy: Value,
}

impl DeploymentCreateArgs {
    pub fn from_args(args: &JsonMap) -> Result<DeploymentCreateArgs, Problem> {
        let parsed: DeploymentCreateArgs = parse_args(args)?;
        for (field, value) in [
            ("assistant_revision_id", &parsed.assistant_revision_id),
            ("config_ref", &parsed.config_ref),
            ("secret_binding_set_ref", &parsed.secret_binding_set_ref),
            ("policy_ref", &parsed.policy_ref),
            ("pool_ref", &parsed.pool_ref),
        ] {
            check_identifier(field, value)?;
        }
        for (field, digest) in [
            ("config_digest", &parsed.config_digest),
            (
                "secret_binding_set_digest",
                &parsed.secret_binding_set_digest,
            ),
        ] {
            if !limits::is_digest_hex(digest) {
                return Err(invalid(format!("{field} is not 64 lowercase hex")));
            }
        }
        if !SECURITY_PROFILES.contains(&parsed.security_profile.as_str()) {
            return Err(invalid("security_profile is not a §14.4 profile"));
        }
        if !CONCURRENCY_POLICIES.contains(&parsed.concurrency_policy.as_str()) {
            return Err(invalid("concurrency_policy is not in the closed §15.3 set"));
        }
        check_object("rollout_policy", &parsed.rollout_policy)?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasBindArgs {
    pub display_alias: String,
    pub assistant_deployment_id: String,
    pub deployment_revision: u64,
}

impl AliasBindArgs {
    pub fn from_args(args: &JsonMap) -> Result<AliasBindArgs, Problem> {
        let parsed: AliasBindArgs = parse_args(args)?;
        check_display("display_alias", &parsed.display_alias)?;
        check_identifier("assistant_deployment_id", &parsed.assistant_deployment_id)?;
        check_safe("deployment_revision", parsed.deployment_revision)?;
        Ok(parsed)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasUpdateArgs {
    pub alias_binding_id: String,
    pub assistant_deployment_id: String,
    pub deployment_revision: u64,
}

impl AliasUpdateArgs {
    pub fn from_args(args: &JsonMap) -> Result<AliasUpdateArgs, Problem> {
        let parsed: AliasUpdateArgs = parse_args(args)?;
        check_identifier("alias_binding_id", &parsed.alias_binding_id)?;
        check_identifier("assistant_deployment_id", &parsed.assistant_deployment_id)?;
        check_safe("deployment_revision", parsed.deployment_revision)?;
        Ok(parsed)
    }
}

// ---------------------------------------------------- invocation cancel ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationCancelArgs {
    pub invocation_id: String,
    #[serde(default)]
    pub cancellation_scope: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Worker-surface binding (§15.2); refused on external_client.
    #[serde(default)]
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub fence_epoch: Option<u64>,
}

impl InvocationCancelArgs {
    pub fn from_args(args: &JsonMap) -> Result<InvocationCancelArgs, Problem> {
        let parsed: InvocationCancelArgs = parse_args(args)?;
        check_identifier("invocation_id", &parsed.invocation_id)?;
        check_opt_status_token("cancellation_scope", &parsed.cancellation_scope)?;
        if let Some(reason) = &parsed.reason {
            check_free_text("reason", reason)?;
        }
        check_opt_identifier("attempt_id", &parsed.attempt_id)?;
        if let Some(fence) = parsed.fence_epoch {
            check_safe("fence_epoch", fence)?;
        }
        Ok(parsed)
    }
}

// ---------------------------------------------- application_event_emit ----

/// Registered application event payloads are capped at 64 KiB (§11.8).
pub const APP_EVENT_PAYLOAD_MAX_BYTES: usize = 65_536;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationEventEmitArgs {
    pub attempt_id: String,
    pub fence_epoch: u64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: Value,
}

impl ApplicationEventEmitArgs {
    pub fn from_args(args: &JsonMap) -> Result<ApplicationEventEmitArgs, Problem> {
        let parsed: ApplicationEventEmitArgs = parse_args(args)?;
        check_identifier("attempt_id", &parsed.attempt_id)?;
        check_safe("fence_epoch", parsed.fence_epoch)?;
        if !limits::is_event_type(&parsed.event_type) {
            return Err(invalid("type is not a versioned reverse-domain name"));
        }
        check_object("payload", &parsed.payload)?;
        let bytes = serde_json::to_vec(&parsed.payload)
            .map_err(|_| invalid("payload is not serializable"))?;
        if bytes.len() > APP_EVENT_PAYLOAD_MAX_BYTES {
            return Err(invalid("payload exceeds the §11.8 64 KiB cap"));
        }
        Ok(parsed)
    }
}

// ------------------------------- governed_work_binding_v1 (K2 slice 1) ----

/// `governance_enable` args (amendment A5 wire name). The Society
/// recovery epoch and the byomd endpoint incarnation are NOT arguments:
/// they are read from byomd's projection surface and server-recomputed,
/// so a caller cannot assert a governance fact it does not observe.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceEnableArgs {
    pub byom_endpoint_ref: String,
    pub society_ref: String,
    pub exact_scope_selector: String,
    pub allowed_project_and_space_selectors: Vec<String>,
    pub classification_binding_ref: String,
    /// Exact-CAS field: the `KoveeGovernanceOwnerBinding` revision this
    /// enable expects; `0` means "expected absent".
    pub expected_owner_revision: u64,
    /// The frozen row's "expected absent-or-identical
    /// `KoveeRealmByomBinding`": absent means absent, present means the
    /// retry of an existing binding.
    #[serde(default)]
    pub expected_binding_ref: Option<String>,
    /// The exact subject digest the confirming human saw. Optional in the
    /// personal profile (the UID-checked owner channel is the explicit
    /// confirmation); when present it must equal the server-recomputed
    /// digest exactly.
    #[serde(default)]
    pub confirmed_subject_digest: Option<String>,
}

impl GovernanceEnableArgs {
    pub fn from_args(args: &JsonMap) -> Result<GovernanceEnableArgs, Problem> {
        let parsed: GovernanceEnableArgs = parse_args(args)?;
        check_identifier("byom_endpoint_ref", &parsed.byom_endpoint_ref)?;
        check_identifier("society_ref", &parsed.society_ref)?;
        check_selector("exact_scope_selector", &parsed.exact_scope_selector)?;
        let selectors = &parsed.allowed_project_and_space_selectors;
        if selectors.is_empty() || selectors.len() > limits::LIST_MAX_ITEMS {
            return Err(invalid(
                "allowed_project_and_space_selectors must hold 1-256 items",
            ));
        }
        if !all_unique(selectors) {
            return Err(invalid(
                "allowed_project_and_space_selectors items must be unique",
            ));
        }
        for selector in selectors {
            check_selector("allowed_project_and_space_selectors item", selector)?;
        }
        check_identifier(
            "classification_binding_ref",
            &parsed.classification_binding_ref,
        )?;
        check_safe("expected_owner_revision", parsed.expected_owner_revision)?;
        check_opt_identifier("expected_binding_ref", &parsed.expected_binding_ref)?;
        check_opt_digest("confirmed_subject_digest", &parsed.confirmed_subject_digest)?;
        Ok(parsed)
    }
}

/// `governance_show` args: the whole realm's governance state, or one
/// binding narrowed by ref.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceShowArgs {
    #[serde(default)]
    pub binding_ref: Option<String>,
}

impl GovernanceShowArgs {
    pub fn from_args(args: &JsonMap) -> Result<GovernanceShowArgs, Problem> {
        let parsed: GovernanceShowArgs = parse_args(args)?;
        check_opt_identifier("binding_ref", &parsed.binding_ref)?;
        Ok(parsed)
    }
}

/// `governance_disable` args. The confirmed subject digest is REQUIRED —
/// `governance_disable` is always step-up (frozen authority row), and in
/// the personal profile the exact-digest confirmation is what stands in
/// for a second factor (labeled honestly, developer assurance).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceDisableArgs {
    pub binding_ref: String,
    pub expected_owner_revision: u64,
    pub confirmed_subject_digest: String,
}

impl GovernanceDisableArgs {
    pub fn from_args(args: &JsonMap) -> Result<GovernanceDisableArgs, Problem> {
        let parsed: GovernanceDisableArgs = parse_args(args)?;
        check_identifier("binding_ref", &parsed.binding_ref)?;
        check_safe("expected_owner_revision", parsed.expected_owner_revision)?;
        if !limits::is_digest_hex(&parsed.confirmed_subject_digest) {
            return Err(invalid("confirmed_subject_digest is not a digest hex"));
        }
        Ok(parsed)
    }
}

// ------------------------------------ K2 slice 2: endeavor promotion ----

/// `endeavor_promotion_prepare` args. Everything byom-facing is DERIVED —
/// the endpoint incarnation, the Society recovery epoch, the binding
/// quadruple, and the project/space/branch come from the active seam and
/// the pinned frontier, so a caller cannot name a stale fact and have it
/// believed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionPrepareArgs {
    pub byom_endpoint_ref: String,
    pub society_ref: String,
    /// An already pinned `SpaceFrontier` — the exact frontier this
    /// formation forms at.
    pub frontier_ref: String,
    /// A Kovee `ContextAssembly` taken AT that frontier.
    pub collaboration_context_bundle_ref: String,
    /// The admitted human byom Participant the principal acts for.
    pub bound_participant_ref: String,
    pub participant_binding_epoch: u64,
    /// The §16.3 uniqueness scope: one explicit human formation command.
    pub client_formation_key: String,
    pub endeavor_proposal_ref: String,
    /// The canonical EndeavorProposal subject body (shape owned by byom's
    /// B0.1 `endeavor_propose` subject; carried opaque here).
    pub endeavor_proposal: JsonMap,
    /// The principal's OWN explicit Position filling the sole computed
    /// formation seat. The operation cannot import an offline Position or
    /// fill another Participant's seat.
    pub source_principal_position: JsonMap,
}

impl PromotionPrepareArgs {
    pub fn from_args(args: &JsonMap) -> Result<PromotionPrepareArgs, Problem> {
        let parsed: PromotionPrepareArgs = parse_args(args)?;
        for (field, value) in [
            ("byom_endpoint_ref", &parsed.byom_endpoint_ref),
            ("society_ref", &parsed.society_ref),
            ("frontier_ref", &parsed.frontier_ref),
            (
                "collaboration_context_bundle_ref",
                &parsed.collaboration_context_bundle_ref,
            ),
            ("bound_participant_ref", &parsed.bound_participant_ref),
            ("client_formation_key", &parsed.client_formation_key),
            ("endeavor_proposal_ref", &parsed.endeavor_proposal_ref),
        ] {
            check_identifier(field, value)?;
        }
        check_safe(
            "participant_binding_epoch",
            parsed.participant_binding_epoch,
        )?;
        if parsed.endeavor_proposal.is_empty() {
            return Err(invalid("endeavor_proposal must be the proposal object"));
        }
        if parsed.source_principal_position.is_empty() {
            return Err(invalid(
                "source_principal_position must be the Position object",
            ));
        }
        Ok(parsed)
    }
}

/// `endeavor_promotion_start` args: which formation, and the FRESH
/// authentication observation this attempt proves. §16.3 requires a fresh
/// human authentication attempt per send, so the observation is required
/// and must differ from the previous attempt's.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionStartArgs {
    pub formation_id: String,
    pub authentication_observation_ref: String,
}

impl PromotionStartArgs {
    pub fn from_args(args: &JsonMap) -> Result<PromotionStartArgs, Problem> {
        let parsed: PromotionStartArgs = parse_args(args)?;
        check_identifier("formation_id", &parsed.formation_id)?;
        check_identifier(
            "authentication_observation_ref",
            &parsed.authentication_observation_ref,
        )?;
        Ok(parsed)
    }
}

/// `endeavor_promotion_show` args: one promotion, or the realm's whole
/// recorded set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionShowArgs {
    #[serde(default)]
    pub formation_id: Option<String>,
}

impl PromotionShowArgs {
    pub fn from_args(args: &JsonMap) -> Result<PromotionShowArgs, Problem> {
        let parsed: PromotionShowArgs = parse_args(args)?;
        check_opt_identifier("formation_id", &parsed.formation_id)?;
        Ok(parsed)
    }
}

/// `endeavor_promotion_cancel` args. Admissible ONLY before the first
/// send — the one pre-send release of the uniqueness slot.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionCancelArgs {
    pub formation_id: String,
    pub reason: String,
}

impl PromotionCancelArgs {
    pub fn from_args(args: &JsonMap) -> Result<PromotionCancelArgs, Problem> {
        let parsed: PromotionCancelArgs = parse_args(args)?;
        check_identifier("formation_id", &parsed.formation_id)?;
        check_display("reason", &parsed.reason)?;
        Ok(parsed)
    }
}

/// `endeavor_promotion_reconcile` args. The query is always run; the
/// terminalization is opt-in and needs the same source human freshly
/// authenticated (§16.3).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionReconcileArgs {
    pub formation_id: String,
    #[serde(default)]
    pub terminalize: bool,
    #[serde(default)]
    pub authentication_observation_ref: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

impl PromotionReconcileArgs {
    pub fn from_args(args: &JsonMap) -> Result<PromotionReconcileArgs, Problem> {
        let parsed: PromotionReconcileArgs = parse_args(args)?;
        check_identifier("formation_id", &parsed.formation_id)?;
        check_opt_identifier(
            "authentication_observation_ref",
            &parsed.authentication_observation_ref,
        )?;
        if let Some(reason) = &parsed.reason {
            check_display("reason", reason)?;
        }
        if parsed.terminalize && parsed.authentication_observation_ref.is_none() {
            return Err(invalid(
                "terminalize requires authentication_observation_ref: only the same source \
                 human, freshly authenticated, may deny future execution",
            ));
        }
        Ok(parsed)
    }
}

/// `byom_episode_binding_show` args: one binding by its stable key, one
/// Episode's bindings, or the realm's whole set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeBindingShowArgs {
    #[serde(default)]
    pub stable_binding_key: Option<String>,
    #[serde(default)]
    pub episode_ref: Option<String>,
}

impl EpisodeBindingShowArgs {
    pub fn from_args(args: &JsonMap) -> Result<EpisodeBindingShowArgs, Problem> {
        let parsed: EpisodeBindingShowArgs = parse_args(args)?;
        check_opt_identifier("stable_binding_key", &parsed.stable_binding_key)?;
        check_opt_identifier("episode_ref", &parsed.episode_ref)?;
        Ok(parsed)
    }
}

fn check_selector(field: &str, value: &str) -> Result<(), Problem> {
    if limits::is_selector(value) {
        Ok(())
    } else {
        Err(invalid(format!(
            "{field} is not a 1-256 visible-ASCII selector"
        )))
    }
}

fn check_opt_digest(field: &str, value: &Option<String>) -> Result<(), Problem> {
    match value {
        Some(v) if !limits::is_digest_hex(v) => {
            Err(invalid(format!("{field} is not a digest hex")))
        }
        _ => Ok(()),
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
        // ---------------------------------------------------- slice 3 ----
        "protocol_info" | "project_show" => empty_args(op, args),
        "diagnose" => DiagnoseArgs::from_args(args).map(drop),
        "project_list" | "project_access_policy_change_list" | "assistant_list" => {
            PageArgs::from_args(args).map(drop)
        }
        "project_update_metadata" => ProjectUpdateMetadataArgs::from_args(args).map(drop),
        "project_access_policy_change_prepare" => PapcPrepareArgs::from_args(args).map(drop),
        "project_access_policy_change_show" | "project_access_policy_change_cancel" => {
            ChangeIdArgs::from_args(args).map(drop)
        }
        "project_access_policy_change_confirm" => PapcConfirmArgs::from_args(args).map(drop),
        "space_update_metadata" => SpaceUpdateMetadataArgs::from_args(args).map(drop),
        "space_freeze" | "space_reopen" | "space_archive" | "space_restrict" => {
            SpaceIdArgs::from_args(args).map(drop)
        }
        "space_policy_narrow" => SpacePolicyNarrowArgs::from_args(args).map(drop),
        "space_access_widen_prepare" => WidenPrepareArgs::from_args(args).map(drop),
        "space_access_widen_show" | "space_access_widen_cancel" => {
            WideningIdArgs::from_args(args).map(drop)
        }
        "space_access_widen_list" => WidenListArgs::from_args(args).map(drop),
        "space_access_widen_confirm" => WidenConfirmArgs::from_args(args).map(drop),
        "space_participant_add" => ParticipantAddArgs::from_args(args).map(drop),
        "space_participant_activate" => ParticipantActivateArgs::from_args(args).map(drop),
        "space_participant_update" => ParticipantUpdateArgs::from_args(args).map(drop),
        "space_participant_remove" => ParticipantIdArgs::from_args(args).map(drop),
        "space_participant_list" | "space_access_grant_list" | "lens_list" => {
            SpacePageArgs::from_args(args).map(drop)
        }
        "space_access_grant_create" => GrantCreateArgs::from_args(args).map(drop),
        "space_access_grant_revoke" => GrantRevokeArgs::from_args(args).map(drop),
        "contribution_withdraw" | "contribution_redact" => {
            ContributionDispositionArgs::from_args(args).map(drop)
        }
        "contribution_supersede" => ContributionSupersedeArgs::from_args(args).map(drop),
        "relation_retract" => RelationRetractArgs::from_args(args).map(drop),
        "lens_create" => LensCreateArgs::from_args(args).map(drop),
        "lens_show" | "lens_revoke" => LensIdArgs::from_args(args).map(drop),
        "lens_update" => LensUpdateArgs::from_args(args).map(drop),
        "reaction_set" => ReactionSetArgs::from_args(args).map(drop),
        "event_payload" => EventPayloadArgs::from_args(args).map(drop),
        "snapshot_read" => SnapshotReadArgs::from_args(args).map(drop),
        "disclosure_manifest_show" => DisclosureManifestShowArgs::from_args(args).map(drop),
        "assistant_create" => AssistantCreateArgs::from_args(args).map(drop),
        "assistant_show" => AssistantShowArgs::from_args(args).map(drop),
        "assistant_revision_register" => AssistantRevisionRegisterArgs::from_args(args).map(drop),
        "assistant_revision_show" => AssistantRevisionShowArgs::from_args(args).map(drop),
        "assistant_revision_list" => AssistantRevisionListArgs::from_args(args).map(drop),
        "deployment_create" => DeploymentCreateArgs::from_args(args).map(drop),
        "deployment_show" | "deployment_activate" | "deployment_drain" => {
            DeploymentIdArgs::from_args(args).map(drop)
        }
        "deployment_list" => DeploymentListArgs::from_args(args).map(drop),
        "assistant_alias_bind" => AliasBindArgs::from_args(args).map(drop),
        "assistant_alias_show" | "assistant_alias_revoke" => AliasIdArgs::from_args(args).map(drop),
        "assistant_alias_list" => AliasListArgs::from_args(args).map(drop),
        "assistant_alias_update" => AliasUpdateArgs::from_args(args).map(drop),
        "invocation_list" => InvocationListArgs::from_args(args).map(drop),
        "invocation_cancel" => InvocationCancelArgs::from_args(args).map(drop),
        "application_event_emit" => ApplicationEventEmitArgs::from_args(args).map(drop),
        // ------------------------------------------- K2 slice 1 ----
        "governance_enable" => GovernanceEnableArgs::from_args(args).map(drop),
        "governance_show" => GovernanceShowArgs::from_args(args).map(drop),
        "governance_disable" => GovernanceDisableArgs::from_args(args).map(drop),
        "endeavor_promotion_prepare" => PromotionPrepareArgs::from_args(args).map(drop),
        "endeavor_promotion_start" => PromotionStartArgs::from_args(args).map(drop),
        "endeavor_promotion_show" => PromotionShowArgs::from_args(args).map(drop),
        "endeavor_promotion_cancel" => PromotionCancelArgs::from_args(args).map(drop),
        "endeavor_promotion_reconcile" => PromotionReconcileArgs::from_args(args).map(drop),
        "byom_episode_binding_show" => EpisodeBindingShowArgs::from_args(args).map(drop),
        other => Err(Problem::new(
            ProblemKind::UnknownOp,
            format!("operation {other} is not in the K1 table"),
        )),
    }
}
