//! Parity check for the K0-frozen operation registry (`spec/registry.json`).
//!
//! The registry is the source of all later counts, so this test compares it
//! against an independently frozen exact `(bundle, operation, surface)` set
//! and closed field enums (R0 KREG-01/KREG-03): membership tests replaced
//! the old aggregate-count-only proof, under which any same-bundle rename
//! still passed. `EXPECTED` was generated once from the reviewed registry
//! and hand-verified against DESIGN.md §11.6/§11.6.1 (counts 3/65/22; four
//! dual-surface operations). Editing it is a deliberate registry revision.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::Path;

/// The frozen exact `(bundle, operation, surface)` set — one row per
/// expected (operation, surface) clause (K0 milestone sheet).
const EXPECTED: [(&str, &str, &str); 90] = [
    ("core_v1", "hello", "external_client"),
    ("core_v1", "protocol_info", "external_client"),
    ("core_v1", "diagnose", "operator"),
    ("shared_space_v1", "realm_show", "external_client"),
    ("shared_space_v1", "project_create", "external_client"),
    ("shared_space_v1", "project_show", "external_client"),
    ("shared_space_v1", "project_list", "external_client"),
    (
        "shared_space_v1",
        "project_update_metadata",
        "external_client",
    ),
    (
        "shared_space_v1",
        "project_access_policy_change_prepare",
        "external_client",
    ),
    (
        "shared_space_v1",
        "project_access_policy_change_show",
        "external_client",
    ),
    (
        "shared_space_v1",
        "project_access_policy_change_list",
        "external_client",
    ),
    (
        "shared_space_v1",
        "project_access_policy_change_confirm",
        "external_client",
    ),
    (
        "shared_space_v1",
        "project_access_policy_change_cancel",
        "external_client",
    ),
    ("shared_space_v1", "space_create", "external_client"),
    ("shared_space_v1", "space_show", "external_client"),
    ("shared_space_v1", "space_list", "external_client"),
    (
        "shared_space_v1",
        "space_update_metadata",
        "external_client",
    ),
    ("shared_space_v1", "space_freeze", "external_client"),
    ("shared_space_v1", "space_reopen", "external_client"),
    ("shared_space_v1", "space_archive", "external_client"),
    ("shared_space_v1", "space_restrict", "external_client"),
    ("shared_space_v1", "space_policy_narrow", "external_client"),
    (
        "shared_space_v1",
        "space_access_widen_prepare",
        "external_client",
    ),
    (
        "shared_space_v1",
        "space_access_widen_show",
        "external_client",
    ),
    (
        "shared_space_v1",
        "space_access_widen_list",
        "external_client",
    ),
    (
        "shared_space_v1",
        "space_access_widen_confirm",
        "external_client",
    ),
    (
        "shared_space_v1",
        "space_access_widen_cancel",
        "external_client",
    ),
    (
        "shared_space_v1",
        "space_participant_add",
        "external_client",
    ),
    ("shared_space_v1", "space_participant_activate", "operator"),
    (
        "shared_space_v1",
        "space_participant_update",
        "external_client",
    ),
    (
        "shared_space_v1",
        "space_participant_remove",
        "external_client",
    ),
    (
        "shared_space_v1",
        "space_participant_list",
        "external_client",
    ),
    ("shared_space_v1", "space_access_grant_create", "operator"),
    ("shared_space_v1", "space_access_grant_revoke", "operator"),
    (
        "shared_space_v1",
        "space_access_grant_list",
        "external_client",
    ),
    ("shared_space_v1", "contribution_append", "external_client"),
    ("shared_space_v1", "contribution_append", "worker"),
    ("shared_space_v1", "contribution_show", "external_client"),
    ("shared_space_v1", "contribution_list", "external_client"),
    (
        "shared_space_v1",
        "contribution_withdraw",
        "external_client",
    ),
    (
        "shared_space_v1",
        "contribution_supersede",
        "external_client",
    ),
    ("shared_space_v1", "contribution_redact", "external_client"),
    ("shared_space_v1", "relation_assert", "external_client"),
    ("shared_space_v1", "relation_assert", "worker"),
    ("shared_space_v1", "relation_retract", "external_client"),
    ("shared_space_v1", "frontier_pin", "external_client"),
    ("shared_space_v1", "frontier_show", "external_client"),
    ("shared_space_v1", "lens_create", "external_client"),
    ("shared_space_v1", "lens_show", "external_client"),
    ("shared_space_v1", "lens_list", "external_client"),
    ("shared_space_v1", "lens_update", "external_client"),
    ("shared_space_v1", "lens_revoke", "external_client"),
    ("shared_space_v1", "lens_read", "external_client"),
    (
        "shared_space_v1",
        "context_assembly_create",
        "external_client",
    ),
    ("shared_space_v1", "context_assembly_create", "worker"),
    (
        "shared_space_v1",
        "context_assembly_show",
        "external_client",
    ),
    ("shared_space_v1", "reaction_set", "external_client"),
    ("shared_space_v1", "events_read", "external_client"),
    ("shared_space_v1", "events_wait", "external_client"),
    ("shared_space_v1", "event_payload", "external_client"),
    ("shared_space_v1", "snapshot_read", "external_client"),
    (
        "shared_space_v1",
        "artifact_upload_begin",
        "external_client",
    ),
    ("shared_space_v1", "artifact_upload_show", "external_client"),
    (
        "shared_space_v1",
        "artifact_upload_credential",
        "external_client",
    ),
    (
        "shared_space_v1",
        "artifact_upload_finalize",
        "external_client",
    ),
    (
        "shared_space_v1",
        "artifact_upload_abort",
        "external_client",
    ),
    ("shared_space_v1", "artifact_show", "external_client"),
    (
        "shared_space_v1",
        "disclosure_manifest_show",
        "external_client",
    ),
    ("developer_assistant_v1", "assistant_create", "operator"),
    (
        "developer_assistant_v1",
        "assistant_show",
        "external_client",
    ),
    (
        "developer_assistant_v1",
        "assistant_list",
        "external_client",
    ),
    (
        "developer_assistant_v1",
        "assistant_revision_register",
        "operator",
    ),
    (
        "developer_assistant_v1",
        "assistant_revision_show",
        "external_client",
    ),
    (
        "developer_assistant_v1",
        "assistant_revision_list",
        "external_client",
    ),
    ("developer_assistant_v1", "deployment_create", "operator"),
    (
        "developer_assistant_v1",
        "deployment_show",
        "external_client",
    ),
    (
        "developer_assistant_v1",
        "deployment_list",
        "external_client",
    ),
    ("developer_assistant_v1", "deployment_activate", "operator"),
    ("developer_assistant_v1", "deployment_drain", "operator"),
    ("developer_assistant_v1", "assistant_alias_bind", "operator"),
    (
        "developer_assistant_v1",
        "assistant_alias_show",
        "external_client",
    ),
    (
        "developer_assistant_v1",
        "assistant_alias_list",
        "external_client",
    ),
    (
        "developer_assistant_v1",
        "assistant_alias_update",
        "operator",
    ),
    (
        "developer_assistant_v1",
        "assistant_alias_revoke",
        "operator",
    ),
    (
        "developer_assistant_v1",
        "invocation_create",
        "external_client",
    ),
    (
        "developer_assistant_v1",
        "invocation_show",
        "external_client",
    ),
    (
        "developer_assistant_v1",
        "invocation_list",
        "external_client",
    ),
    (
        "developer_assistant_v1",
        "invocation_cancel",
        "external_client",
    ),
    ("developer_assistant_v1", "invocation_cancel", "worker"),
    ("developer_assistant_v1", "application_event_emit", "worker"),
];

/// Per-bundle entry counts implied by `EXPECTED` (registry-README table).
const EXPECTED_COUNTS: [(&str, usize); 3] = [
    ("core_v1", 3),
    ("shared_space_v1", 65),
    ("developer_assistant_v1", 22),
];

/// The closed §9.2 dependency-kind enum, tokenized in §9.2 order
/// (spec/registry-README.md). Independent copy: the registry's own
/// `dependency_category_tokens` must match it exactly.
const DEPENDENCY_TOKENS: [&str; 21] = [
    "principal_status",
    "authentication_binding_security_epoch",
    "current_authentication_observation",
    "service_identity_capability",
    "installation_recovery_epoch",
    "realm_status_kill_epoch",
    "project_status_revision",
    "target_resource_revision",
    "membership",
    "space_access_participant_binding",
    "branch_status_frontier",
    "contribution_relation_endpoint_visibility",
    "lens_scope",
    "attention_revision_acceptance",
    "context_item_visibility",
    "commitment_terms_acceptance",
    "classification_retention_policy",
    "remaining_use_grant",
    "kovee_policy_set",
    "realm_authority_binding",
    "external_visibility_proof",
];

const SURFACES: [&str; 3] = ["external_client", "operator", "worker"];

const OFFLINE: [&str; 3] = ["no", "cached_draft_only", "queueable"];

/// Closed list of the exact actor-kind strings used by the 90 entries.
const ACTOR_KINDS: [&str; 15] = [
    "authenticated creator or authorized principal",
    "authenticated operator",
    "authenticated principal",
    "authenticated project owner principal only",
    "authenticated steward/owner principal",
    "authenticated steward/owner principal only",
    "connector service (only for its mapped resources)",
    "current attempt (own exact child invocation under an explicit parent capability)",
    "fenced worker (exact listed proposal operation in its capability)",
    "invocation attempt only",
    "mapped connector (only for contribution/reaction/upload operations granted to it)",
    "narrow policy service consuming an exact active standing-policy/contract receipt",
    "pre-auth channel",
    "principal",
    "principal only",
];

/// Closed list of the exact assurance values used by the 90 entries.
const ASSURANCES: [&str; 13] = [
    "current assurance required by policy",
    "current login",
    "current login (principal); workload identity (mapped connector)",
    "current login or workload identity",
    "current login; policy may require step-up",
    "current login; production test may require step-up",
    "current login; step-up for production activation",
    "current step-up observation at risk-required level",
    "none",
    "risk-required current step-up",
    "risk-required step-up",
    "worker capability",
    "workload identity plus invocation capability",
];

const CONNECTOR_ACTOR: &str =
    "mapped connector (only for contribution/reaction/upload operations granted to it)";
const CONNECTOR_SPLIT_ASSURANCE: &str =
    "current login (principal); workload identity (mapped connector)";

/// The eleven registry fields fixed at k0-2, plus per-entry provenance.
const REQUIRED_FIELDS: [&str; 11] = [
    "operation",
    "bundle",
    "surface",
    "allowed_actor_kinds",
    "action_scope",
    "dependency_categories",
    "constraints",
    "fence",
    "assurance",
    "offline",
    "source",
];

fn load_registry() -> Result<serde_json::Value, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("spec")
        .join("registry.json");
    let raw = std::fs::read_to_string(&path)?;
    // Valid JSON is the first assertion: a parse failure fails the test.
    Ok(serde_json::from_str(&raw)?)
}

fn entries(doc: &serde_json::Value) -> Result<&Vec<serde_json::Value>, Box<dyn Error>> {
    doc.get("entries")
        .and_then(|e| e.as_array())
        .ok_or_else(|| "registry.json has no `entries` array".into())
}

fn str_list(entry: &serde_json::Value, field: &str) -> Result<Vec<String>, Box<dyn Error>> {
    entry
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("`{field}` is not an array in {entry}"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("non-string item in `{field}` of {entry}").into())
        })
        .collect()
}

#[test]
fn every_entry_has_all_registry_fields() -> Result<(), Box<dyn Error>> {
    let doc = load_registry()?;
    for entry in entries(&doc)? {
        let obj = entry
            .as_object()
            .ok_or_else(|| format!("non-object entry: {entry}"))?;
        for field in REQUIRED_FIELDS {
            assert!(
                obj.contains_key(field),
                "entry {} is missing required field `{field}`",
                entry
            );
        }
        for list_field in ["allowed_actor_kinds", "action_scope"] {
            assert!(
                !str_list(entry, list_field)?.is_empty(),
                "entry {} has an empty `{list_field}`",
                entry["operation"]
            );
        }
        // `constraints` may be empty; `dependency_categories` may be empty
        // only for the pre-auth channel (hello, protocol_info), whose
        // §11.6.1 row names no authority input.
        let op = entry["operation"].as_str().unwrap_or_default();
        if str_list(entry, "dependency_categories")?.is_empty() {
            assert!(
                op == "hello" || op == "protocol_info",
                "entry {op} has empty dependency_categories but is not pre-auth"
            );
        }
    }
    Ok(())
}

#[test]
fn exact_bundle_operation_surface_set_matches_frozen_expectation() -> Result<(), Box<dyn Error>> {
    let doc = load_registry()?;
    let expected: BTreeSet<(&str, &str, &str)> = EXPECTED.iter().copied().collect();
    assert_eq!(
        expected.len(),
        EXPECTED.len(),
        "EXPECTED contains a duplicate"
    );

    let mut actual = BTreeSet::new();
    for entry in entries(&doc)? {
        let triple = (
            entry["bundle"].as_str().ok_or("bundle is not a string")?,
            entry["operation"]
                .as_str()
                .ok_or("operation is not a string")?,
            entry["surface"].as_str().ok_or("surface is not a string")?,
        );
        assert!(
            actual.insert(triple),
            "duplicate (bundle, operation, surface): {triple:?}"
        );
        assert!(
            expected.contains(&triple),
            "registry entry not in the frozen expected set: {triple:?}"
        );
    }
    for triple in &expected {
        assert!(
            actual.contains(triple),
            "frozen expected entry missing from the registry: {triple:?}"
        );
    }

    // The frozen counts derive from EXPECTED itself; print for eyeballing.
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (bundle, _, _) in EXPECTED {
        *counts.entry(bundle).or_default() += 1;
    }
    println!(
        "registry parity counts: {counts:?} (total {})",
        EXPECTED.len()
    );
    for (bundle, count) in EXPECTED_COUNTS {
        assert_eq!(counts.get(bundle), Some(&count), "bundle {bundle}");
    }
    let declared = doc
        .get("entry_counts")
        .and_then(|c| c.as_object())
        .ok_or("registry.json has no entry_counts")?;
    for (bundle, count) in EXPECTED_COUNTS {
        assert_eq!(
            declared.get(bundle).and_then(|v| v.as_u64()),
            Some(count as u64),
            "declared entry_counts for {bundle}"
        );
    }
    Ok(())
}

#[test]
fn field_values_come_from_closed_enums() -> Result<(), Box<dyn Error>> {
    let doc = load_registry()?;
    // The registry's own token list must equal the independent frozen copy.
    let registry_tokens = str_list(&doc, "dependency_category_tokens")?;
    assert_eq!(
        registry_tokens, DEPENDENCY_TOKENS,
        "registry dependency_category_tokens drifted from the frozen §9.2 enum"
    );
    let token_index: BTreeMap<&str, usize> = DEPENDENCY_TOKENS
        .iter()
        .enumerate()
        .map(|(i, t)| (*t, i))
        .collect();

    for entry in entries(&doc)? {
        let op = entry["operation"]
            .as_str()
            .ok_or("operation not a string")?;
        let surface = entry["surface"].as_str().ok_or("surface not a string")?;
        assert!(
            SURFACES.contains(&surface),
            "{op}: unknown surface `{surface}`"
        );
        let offline = entry["offline"].as_str().ok_or("offline not a string")?;
        assert!(
            OFFLINE.contains(&offline),
            "{op}: unknown offline value `{offline}`"
        );
        let assurance = entry["assurance"]
            .as_str()
            .ok_or("assurance not a string")?;
        assert!(
            ASSURANCES.contains(&assurance),
            "{op}/{surface}: assurance `{assurance}` is not in the closed list"
        );
        for actor in str_list(entry, "allowed_actor_kinds")? {
            assert!(
                ACTOR_KINDS.contains(&actor.as_str()),
                "{op}/{surface}: actor kind `{actor}` is not in the closed list"
            );
        }
        // Canonical §9.2 tokens only, §9.2 order, no duplicates (KREG-01).
        let deps = str_list(entry, "dependency_categories")?;
        let mut last = None;
        for token in &deps {
            let index = *token_index.get(token.as_str()).ok_or_else(|| {
                format!("{op}/{surface}: `{token}` is not a canonical §9.2 token")
            })?;
            if let Some(prev) = last {
                assert!(
                    index > prev,
                    "{op}/{surface}: dependency tokens out of §9.2 order or duplicated"
                );
            }
            last = Some(index);
        }
    }
    Ok(())
}

#[test]
fn connector_authority_split_holds_in_both_directions() -> Result<(), Box<dyn Error>> {
    // R0 KREG-02: connector-capable mutations carry the split assurance and
    // the connector's service-identity dependency; the split assurance never
    // appears without the connector actor; contribution_redact is
    // principal-only (connector redaction disallowed pending a design
    // amendment — spec/registry-README.md).
    let doc = load_registry()?;
    for entry in entries(&doc)? {
        let op = entry["operation"]
            .as_str()
            .ok_or("operation not a string")?;
        let surface = entry["surface"].as_str().ok_or("surface not a string")?;
        let actors = str_list(entry, "allowed_actor_kinds")?;
        let assurance = entry["assurance"]
            .as_str()
            .ok_or("assurance not a string")?;
        let has_connector = actors.iter().any(|a| a == CONNECTOR_ACTOR);
        let has_split = assurance == CONNECTOR_SPLIT_ASSURANCE;
        assert_eq!(
            has_connector, has_split,
            "{op}/{surface}: mapped-connector actor and split assurance must \
             appear together (actor: {has_connector}, assurance: {has_split})"
        );
        if has_connector {
            assert_eq!(
                surface, "external_client",
                "{op}: connector actor off external_client"
            );
            let deps = str_list(entry, "dependency_categories")?;
            assert!(
                deps.iter().any(|d| d == "service_identity_capability"),
                "{op}/{surface}: connector-capable mutation lacks service_identity_capability"
            );
        }
        if op == "contribution_redact" {
            assert!(
                !has_connector,
                "contribution_redact must not list the mapped connector (KREG-02 decision)"
            );
        }
    }
    Ok(())
}

#[test]
fn no_sage_era_operation_name_survives() -> Result<(), Box<dyn Error>> {
    // Amendment A5: no Sage-era wire name survives the K0 extraction.
    let doc = load_registry()?;
    for entry in entries(&doc)? {
        let operation = entry["operation"]
            .as_str()
            .ok_or("operation is not a string")?;
        for banned in ["sage", "mission"] {
            assert!(
                !operation.to_lowercase().contains(banned),
                "Sage-era operation name survives: `{operation}` contains `{banned}`"
            );
        }
    }
    Ok(())
}
