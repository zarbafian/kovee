//! §10 record projections as they appear in the per-operation result
//! schemas (`spec/schemas/ops/*-result.schema.json`): the realm, project,
//! space, and contribution shapes plus the §11.1 hello result.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// §10.1 Realm projection (`realm-show-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Realm {
    pub realm_id: String,
    pub installation_id: String,
    pub revision: u64,
    pub name: String,
    pub status: String,
    pub home_region: String,
    pub auth_policy_ref: String,
    pub retention_policy_ref: String,
    pub encryption_key_ref: String,
    pub created_at: String,
}

/// §10.1 Project projection (`project-create-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub project_id: String,
    pub realm_id: String,
    pub revision: u64,
    pub name: String,
    pub status: String,
    pub default_classification_ref: String,
    pub policy_set_ref: String,
    pub created_by: String,
    pub created_at: String,
}

/// §10.2 Space projection (`space-create-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Space {
    pub space_id: String,
    pub realm_id: String,
    pub project_id: String,
    pub revision: u64,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub purpose_contribution_ref: Option<String>,
    pub visibility: String,
    pub status: String,
    pub main_branch_id: String,
    pub next_space_sequence: u64,
    pub default_classification_ref: String,
    pub policy_set_ref: String,
    pub created_by: String,
    pub created_at: String,
}

/// §10.2 ContributionPart union — five arms discriminated structurally by
/// their disjoint closed required member sets (no type tag exists in the
/// record model; gap note KG21). Deserialization is manual because each
/// arm is a closed object (`additionalProperties: false`) and serde's
/// untagged matching would silently ignore unknown members.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ContributionPart {
    Text {
        media_type: String,
        text: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        language: Option<String>,
    },
    Data {
        schema_ref: String,
        value: Value,
    },
    Artifact {
        artifact_ref: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        title: Option<String>,
    },
    Reference {
        object_ref: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        object_revision: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        digest: Option<String>,
    },
    Mention {
        target_kind: String,
        target_ref: String,
        target_revision: u64,
        display_text: String,
    },
}

impl<'de> Deserialize<'de> for ContributionPart {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let map = serde_json::Map::<String, Value>::deserialize(d)?;
        let has = |k: &str| map.contains_key(k);
        let keys_within = |allowed: &[&str]| map.keys().all(|k| allowed.contains(&k.as_str()));
        let take_str = |k: &str| -> Result<String, D::Error> {
            match map.get(k) {
                Some(Value::String(s)) => Ok(s.clone()),
                _ => Err(D::Error::custom(format!(
                    "part member {k} must be a string"
                ))),
            }
        };
        let take_opt_str = |k: &str| -> Result<Option<String>, D::Error> {
            match map.get(k) {
                None => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                _ => Err(D::Error::custom(format!(
                    "part member {k} must be a string"
                ))),
            }
        };
        let take_u64 = |k: &str| -> Result<u64, D::Error> {
            map.get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| D::Error::custom(format!("part member {k} must be an integer")))
        };
        if has("media_type") && has("text") && keys_within(&["media_type", "text", "language"]) {
            return Ok(ContributionPart::Text {
                media_type: take_str("media_type")?,
                text: take_str("text")?,
                language: take_opt_str("language")?,
            });
        }
        if has("schema_ref") && has("value") && keys_within(&["schema_ref", "value"]) {
            return Ok(ContributionPart::Data {
                schema_ref: take_str("schema_ref")?,
                value: map.get("value").cloned().unwrap_or(Value::Null),
            });
        }
        if has("artifact_ref") && keys_within(&["artifact_ref", "title"]) {
            return Ok(ContributionPart::Artifact {
                artifact_ref: take_str("artifact_ref")?,
                title: take_opt_str("title")?,
            });
        }
        if has("object_ref") && keys_within(&["object_ref", "object_revision", "digest"]) {
            let object_revision = match map.get("object_revision") {
                None => None,
                Some(v) => Some(v.as_u64().ok_or_else(|| {
                    D::Error::custom("part member object_revision must be an integer")
                })?),
            };
            return Ok(ContributionPart::Reference {
                object_ref: take_str("object_ref")?,
                object_revision,
                digest: take_opt_str("digest")?,
            });
        }
        if has("target_kind")
            && has("target_ref")
            && has("target_revision")
            && has("display_text")
            && keys_within(&[
                "target_kind",
                "target_ref",
                "target_revision",
                "display_text",
            ])
        {
            return Ok(ContributionPart::Mention {
                target_kind: take_str("target_kind")?,
                target_ref: take_str("target_ref")?,
                target_revision: take_u64("target_revision")?,
                display_text: take_str("display_text")?,
            });
        }
        Err(D::Error::custom(
            "body part matches no closed ContributionPart arm",
        ))
    }
}

/// §10.2 Contribution projection
/// (`contribution-append-result.schema.json`); `revision` is always 1 —
/// contributions are immutable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contribution {
    pub contribution_id: String,
    pub revision: u64,
    pub realm_id: String,
    pub project_id: String,
    pub space_id: String,
    pub origin_branch_id: String,
    pub origin_branch_sequence: u64,
    pub space_sequence: u64,
    pub author_actor_ref: String,
    pub kind: String,
    pub schema_ref: String,
    pub body_parts: Vec<ContributionPart>,
    pub subject_refs: Vec<String>,
    pub source_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub epistemic_posture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub invocation_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context_assembly_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub causation_ref: Option<String>,
    pub classification_ref: String,
    pub retention_policy_ref: String,
    pub content_digest: String,
    pub created_at: String,
}

/// §10.2 `objectRefTriple` (`relation-assert-request.schema.json`): an
/// exact pinned endpoint — object, revision, digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRefTriple {
    pub object_ref: String,
    pub revision: u64,
    pub digest: String,
}

/// §10.2 SpaceRelation projection (`relation-assert-result.schema.json`);
/// the public/worker surface always creates `semantic_assertion`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceRelation {
    pub relation_id: String,
    pub revision: u64,
    pub space_id: String,
    pub origin_branch_id: String,
    pub branch_sequence: u64,
    pub author_actor_ref: String,
    pub kind: String,
    pub from_ref: ObjectRefTriple,
    pub to_ref: ObjectRefTriple,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rationale_ref: Option<String>,
    pub relation_class: String,
    pub classification_ref: String,
    pub schema_ref: String,
    pub digest: String,
    pub created_at: String,
}

/// §10.2 SpaceFrontier projection (`frontier-pin-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceFrontier {
    pub frontier_id: String,
    pub revision: u64,
    pub space_id: String,
    pub branch_id: String,
    pub branch_sequence: u64,
    pub branch_head_digest: String,
    pub project_event_cursor: String,
    pub external_source_cursors: Vec<Value>,
    pub created_at: String,
    pub digest: String,
}

/// §10.8 ContextAssembly item (`context-assembly-create-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyItem {
    pub object_ref: String,
    pub revision: u64,
    pub digest: String,
    pub size: u64,
    pub classification_ref: String,
    pub role: String,
    pub order: u64,
    pub inclusion_reason: String,
}

/// §10.8 ContextAssembly relation entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyRelation {
    pub relation_ref: String,
    pub digest: String,
}

/// §10.8 ContextAssembly transformation entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyTransformation {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub instruction_ref: Option<String>,
    pub version: String,
    pub source_digest: String,
    pub result_digest: String,
}

/// §10.8 ContextAssembly omission entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyOmission {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub visible_candidate_ref: Option<String>,
    pub reason: String,
}

/// §10.8 ContextAssembly totals.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyTotals {
    pub items: u64,
    pub bytes: u64,
    pub estimated_tokens: u64,
}

/// §10.8 ContextAssembly projection
/// (`context-assembly-create-result.schema.json`): immutable evidence of
/// selection, never a bearer capability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAssembly {
    pub assembly_id: String,
    pub revision: u64,
    pub realm_id: String,
    pub project_id: String,
    pub space_id: String,
    pub branch_id: String,
    pub audience_ref: String,
    pub purpose: String,
    pub trigger_refs: Vec<String>,
    pub frontier_ref: String,
    pub frontier_digest: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub recipe_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub recipe_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub recipe_digest: Option<String>,
    pub selection_policy_ref: String,
    pub selection_policy_digest: String,
    pub items: Vec<AssemblyItem>,
    pub relations: Vec<AssemblyRelation>,
    pub transformations: Vec<AssemblyTransformation>,
    pub omissions: Vec<AssemblyOmission>,
    pub classification_join_ref: String,
    pub totals: AssemblyTotals,
    pub selection_policy_version: String,
    pub assembler_version: String,
    pub authorization_dependency_set_ref: String,
    pub authority_digest: String,
    pub created_at: String,
    pub digest: String,
}

/// §10.10 Artifact projection (`artifact-show-result.schema.json`).
/// Amendment A5: no retained plaintext hash over erasable content —
/// `raw_sha256` and `typed_byte_digest` stay absent; the content address
/// is a `local_erasure_safe` typed digest kept internally.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub artifact_id: String,
    pub realm_id: String,
    pub owner_ref: String,
    pub revision: u64,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub raw_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub typed_byte_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub media_type: Option<String>,
    pub classification_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sealed_storage_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sealed_storage_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verification_digest: Option<String>,
    pub encryption_key_ref: String,
    pub created_by: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub available_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub retention_until: Option<String>,
}

/// §10.10 ArtifactUpload projection
/// (`artifact-upload-finalize-result.schema.json` / `-show-result`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUpload {
    pub upload_id: String,
    pub artifact_id: String,
    pub realm_id: String,
    pub owner_ref: String,
    pub revision: u64,
    pub declared_raw_sha256: String,
    pub declared_size: u64,
    pub declared_media_type: String,
    pub classification_ref: String,
    pub staging_storage_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider_upload_ref: Option<String>,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sealed_storage_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub seal_observation_digest: Option<String>,
    pub authorization_dependency_set_ref: String,
    pub authority_digest: String,
    pub max_bytes: u64,
    pub expires_at: String,
    pub idempotency_key: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sealed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub terminal_at: Option<String>,
}

/// §10.6 Invocation projection (`invocation-create-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub invocation_id: String,
    pub realm_id: String,
    pub project_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub space_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub branch_id: Option<String>,
    pub assistant_deployment_id: String,
    pub assistant_deployment_revision: u64,
    pub assistant_revision_id: String,
    pub effective_config_ref: String,
    pub effective_config_digest: String,
    pub secret_binding_set_ref: String,
    pub secret_binding_set_digest: String,
    pub effective_policy_digest: String,
    pub effective_security_profile: String,
    pub rollout_decision_ref: String,
    pub trigger_ref: String,
    pub trigger_digest: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context_assembly_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context_assembly_digest: Option<String>,
    pub input_manifest_ref: String,
    pub input_digest: String,
    pub correlation_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub causation_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub commitment_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub work_realization_ref: Option<String>,
    pub state: String,
    pub revision: u64,
    pub priority: u64,
    pub not_before: String,
    pub deadline: String,
    pub max_attempts: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub budget_reservation_set_ref: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub terminal_at: Option<String>,
}

/// §11.1 HelloResult (`hello-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloResult {
    pub selected_version: String,
    pub implementation: String,
    pub implementation_version: String,
    pub features: Vec<String>,
    pub limits_digest: String,
    pub server_time: String,
    pub installation_id: String,
}

/// `protocol_info` result (KG2): HelloResult minus `selected_version`
/// plus `supported_versions` (`protocol-info-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolInfoResult {
    pub supported_versions: Vec<String>,
    pub implementation: String,
    pub implementation_version: String,
    pub features: Vec<String>,
    pub limits_digest: String,
    pub server_time: String,
    pub installation_id: String,
}

/// §10.2 SpaceParticipant projection
/// (`space-participant-add-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceParticipant {
    pub participant_id: String,
    pub space_id: String,
    pub subject_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subject_revision: Option<u64>,
    pub kind: String,
    pub role: String,
    pub authority_source_ref: String,
    pub status: String,
    pub revision: u64,
}

/// §10.2 SpaceAccessGrant projection
/// (`space-access-grant-create-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceAccessGrant {
    pub space_access_id: String,
    pub space_id: String,
    pub subject_ref: String,
    pub revision: u64,
    pub source_membership_or_policy_ref: String,
    pub allowed_actions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub classification_ceiling_ref: Option<String>,
    pub authorization_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<String>,
    pub status: String,
    pub granted_by_or_policy_use_ref: String,
    pub created_at: String,
}

/// §10.2 SpaceLens projection (`lens-show-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceLens {
    pub lens_id: String,
    pub space_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub owner_ref: Option<String>,
    pub revision: u64,
    pub kind: String,
    pub query_ast: Value,
    pub sort_spec: Value,
    pub presentation_options: Value,
    pub visibility: String,
    pub status: String,
    pub created_at: String,
}

/// §10.2 Reaction projection (`reaction-set-result.schema.json`): a
/// lightweight mutable presentation signal — never evidence, a vote,
/// acceptance, attention, or authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reaction {
    pub reaction_id: String,
    pub space_id: String,
    pub target_ref: String,
    pub target_revision: u64,
    pub target_digest: String,
    pub actor_ref: String,
    pub key: String,
    pub state: String,
    pub revision: u64,
    pub updated_at: String,
}

/// §10.2 ContributionDisposition projection
/// (`contribution-withdraw/supersede/redact-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionDisposition {
    pub disposition_id: String,
    pub contribution_ref: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub replacement_ref: Option<String>,
    pub reason_class: String,
    pub authorized_by_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub payload_removed_at: Option<String>,
    pub created_at: String,
}

/// §10.2 RelationDisposition projection
/// (`relation-retract-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationDisposition {
    pub disposition_id: String,
    pub relation_ref: String,
    pub kind: String,
    pub authorized_by_ref: String,
    pub reason_class: String,
    pub created_at: String,
}

/// §10.1 ProjectAccessPolicyChange projection
/// (`project-access-policy-change-prepare-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectAccessPolicyChange {
    pub change_id: String,
    pub project_id: String,
    pub expected_project_revision: u64,
    pub prior_policy_set_ref: String,
    pub proposed_policy_set_ref: String,
    pub prior_default_classification_ref: String,
    pub proposed_default_classification_ref: String,
    pub affected_space_frontier_refs: Vec<String>,
    pub affected_item_set_digest: String,
    pub effective_change: String,
    pub classification_join_ref: String,
    pub destination_audience_digest: String,
    pub subject_digest: String,
    pub prepared_by_principal: String,
    pub state: String,
    pub revision: u64,
    pub created_at: String,
}

/// §10.2 SpaceAccessWidening projection
/// (`space-access-widen-prepare-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceAccessWidening {
    pub widening_id: String,
    pub space_id: String,
    pub expected_space_revision: u64,
    pub prior_visibility: String,
    pub proposed_visibility: String,
    pub prior_policy_set_ref: String,
    pub proposed_policy_set_ref: String,
    pub prior_default_classification_ref: String,
    pub proposed_default_classification_ref: String,
    pub affected_frontier_refs: Vec<String>,
    pub affected_item_set_digest: String,
    pub classification_join_ref: String,
    pub destination_audience_digest: String,
    pub subject_digest: String,
    pub prepared_by_principal: String,
    pub state: String,
    pub revision: u64,
    pub created_at: String,
}

/// §10.5 AssistantDefinition projection
/// (`assistant-create-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantDefinition {
    pub definition_id: String,
    pub realm_id: String,
    pub owner_ref: String,
    pub revision: u64,
    pub name: String,
    pub description: String,
    pub status: String,
    pub created_at: String,
}

/// §10.5 AssistantRevision projection
/// (`assistant-revision-register-result.schema.json`); the manifest stays
/// a validated open object here (typed at admission by
/// [`crate::ops::RevisionManifest`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantRevision {
    pub assistant_revision_id: String,
    pub definition_id: String,
    pub version: String,
    pub manifest: Value,
    pub package_artifact_ref: String,
    pub package_digest: String,
    pub config_schema_digest: String,
    pub sdk_protocol_range: String,
    pub signature_refs: Vec<String>,
    pub created_by: String,
    pub created_at: String,
}

/// §10.5 AssistantDeployment projection
/// (`deployment-create-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantDeployment {
    pub assistant_deployment_id: String,
    pub assistant_revision_id: String,
    pub realm_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub project_id: Option<String>,
    pub revision: u64,
    pub config_ref: String,
    pub config_digest: String,
    pub secret_binding_set_ref: String,
    pub secret_binding_set_digest: String,
    pub policy_ref: String,
    pub pool_ref: String,
    pub security_profile: String,
    pub concurrency_policy: String,
    pub rollout_policy: Value,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub activated_at: Option<String>,
}

/// §10.5 AssistantAliasBinding projection
/// (`assistant-alias-bind-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantAliasBinding {
    pub alias_binding_id: String,
    pub realm_id: String,
    pub project_id: String,
    pub revision: u64,
    pub normalized_alias: String,
    pub display_alias: String,
    pub assistant_deployment_id: String,
    pub deployment_revision: u64,
    pub status: String,
    pub created_by: String,
    pub created_at: String,
}
