//! Structural parity check for the K0-frozen operation registry
//! (`spec/registry.json`): the registry is the source of all later counts,
//! so its shape is enforced here (K0 milestone sheet, "registry structural
//! check").

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::Path;

const BUNDLES: [&str; 3] = ["core_v1", "shared_space_v1", "developer_assistant_v1"];

/// The eight registry fields fixed at K0, plus per-entry provenance.
const REQUIRED_FIELDS: [&str; 9] = [
    "operation",
    "bundle",
    "surface",
    "allowed_actor_kinds",
    "dependency_categories",
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
        for list_field in ["allowed_actor_kinds", "dependency_categories"] {
            let list = obj
                .get(list_field)
                .and_then(|v| v.as_array())
                .ok_or_else(|| format!("`{list_field}` is not an array in {entry}"))?;
            assert!(
                !list.is_empty(),
                "entry {} has an empty `{list_field}`",
                entry
            );
        }
    }
    Ok(())
}

#[test]
fn no_duplicate_operation_surface_pair() -> Result<(), Box<dyn Error>> {
    let doc = load_registry()?;
    let mut seen = BTreeSet::new();
    for entry in entries(&doc)? {
        let operation = entry["operation"]
            .as_str()
            .ok_or("operation is not a string")?;
        let surface = entry["surface"].as_str().ok_or("surface is not a string")?;
        assert!(
            seen.insert((operation.to_owned(), surface.to_owned())),
            "duplicate (operation, surface) pair: ({operation}, {surface})"
        );
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

#[test]
fn every_bundle_is_one_of_the_three_k1_bundles() -> Result<(), Box<dyn Error>> {
    let doc = load_registry()?;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for entry in entries(&doc)? {
        let bundle = entry["bundle"].as_str().ok_or("bundle is not a string")?;
        assert!(
            BUNDLES.contains(&bundle),
            "entry {} names unknown bundle `{bundle}`",
            entry["operation"]
        );
        *counts.entry(bundle.to_owned()).or_default() += 1;
    }
    // K0-frozen counts (spec/registry-README.md): freezing is the point, so
    // any drift must be a deliberate registry revision, not an accident.
    assert_eq!(counts.get("core_v1"), Some(&3));
    assert_eq!(counts.get("shared_space_v1"), Some(&65));
    assert_eq!(counts.get("developer_assistant_v1"), Some(&22));
    Ok(())
}
