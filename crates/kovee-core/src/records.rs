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
