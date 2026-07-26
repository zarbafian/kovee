//! K1 vector round-trip (kovee §25.1): positive AND negative golden
//! vectors for every K1 slice-2 operation — wrong surface (forbidden
//! members such as `relation_class` or provider fields), wrong actor
//! shape, dependency invalidation, and replay negatives (unkeyed
//! mutations, meta on reads) — must all agree byte-for-byte with the
//! Rust schema mirrors, exactly as the slice-1 suite proves for the
//! first op set. The independent rederivers (`xcheck/run.py`,
//! `tscheck/check.mjs`) run over the same files in `run-checks.sh`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use kovee_core::envelope::RawCommand;
use kovee_core::ijson;
use kovee_core::ops;
use kovee_core::records::{Invocation, Space, SpaceRelation};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("spec")
        .join("vectors")
}

fn load(path: &Path) -> Value {
    let raw =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn vector_files() -> Vec<PathBuf> {
    let dir = vectors_dir().join("ops");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    files
}

/// The request-schema basenames of the FULL K1 op table (slice 3 closes
/// it): one `<op-with-dashes>-request` name per `ops::KCP_OPS` row.
fn k1_request_schemas() -> Vec<String> {
    ops::KCP_OPS
        .iter()
        .map(|spec| format!("{}-request", spec.name.replace('_', "-")))
        .collect()
}

fn accepts_op_request(value: &Value) -> bool {
    let text = serde_json::to_string(value).unwrap();
    let Ok(strict) = ijson::parse_strict(&text) else {
        return false;
    };
    let Ok(cmd) = RawCommand::from_value(strict) else {
        return false;
    };
    let Some(spec) = ops::op_spec(&cmd.op) else {
        return false;
    };
    cmd.validate(spec.shape()).is_ok()
        && spec.check_placement(&cmd.realm_id, &cmd.project_id).is_ok()
        && ops::validate_op_args(&cmd.op, &cmd.args).is_ok()
}

#[test]
fn k1_op_request_vectors_round_trip() {
    // EVERY K1 operation's request vectors — positives and the §25.1
    // negative classes — must agree with the Rust schema mirrors.
    let schemas = k1_request_schemas();
    let mut checked = 0;
    let mut negatives = 0;
    for path in vector_files() {
        let vector = load(&path);
        let Some(schema) = vector["input"]["schema"].as_str() else {
            continue;
        };
        if !schemas.iter().any(|s| s == schema) {
            continue;
        }
        let value = &vector["input"]["value"];
        let expected = vector["expected"]["valid"].as_bool().unwrap();
        let actual = accepts_op_request(value);
        assert_eq!(
            actual,
            expected,
            "{}: schema says valid={expected}, Rust says {actual}",
            path.display()
        );
        checked += 1;
        if !expected {
            negatives += 1;
        }
    }
    // 89 ops × 3 negatives (missing-required, wrong-surface-args,
    // replay) plus the positive requests.
    assert!(checked >= 292, "only {checked} op vectors found");
    assert!(negatives >= 264, "only {negatives} negatives found");
}

#[test]
fn every_k1_op_has_wrong_surface_replay_and_missing_required_negatives() {
    // §25.1 verbatim: every operation carries the four negative classes
    // where they are expressible. Prove file-level coverage per op.
    let dir = vectors_dir().join("ops");
    for schema in k1_request_schemas() {
        let base = schema.trim_end_matches("-request");
        for suffix in ["invalid-missing-required", "invalid-wrong-surface-args"] {
            let path = dir.join(format!("{base}-{suffix}.json"));
            assert!(path.exists(), "missing negative vector {}", path.display());
        }
        // Replay negatives: unkeyed mutation or meta-on-read.
        let unkeyed = dir.join(format!("{base}-invalid-replay-unkeyed.json"));
        let meta_on_read = dir.join(format!("{base}-invalid-replay-meta-on-read.json"));
        assert!(
            unkeyed.exists() || meta_on_read.exists(),
            "missing replay negative for {base}"
        );
    }
}

#[test]
fn ops_table_matches_the_frozen_registry_exactly() {
    // §11.6.1 parity, both directions: every distinct registry operation
    // has a K1 ops-table row, and every table row has a registry entry.
    // (Per-surface dispatch parity is proven end-to-end by the daemon's
    // `k1_bundles` suite.)
    let registry = load(
        &vectors_dir()
            .parent()
            .unwrap()
            .join("registry.json")
            .to_path_buf(),
    );
    let registry_ops: std::collections::BTreeSet<&str> = registry["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["operation"].as_str().unwrap())
        .collect();
    let table_ops: std::collections::BTreeSet<&str> =
        ops::KCP_OPS.iter().map(|spec| spec.name).collect();
    assert_eq!(
        registry_ops, table_ops,
        "the ops table and spec/registry.json must carry the same exact operation set"
    );
    assert_eq!(
        table_ops.len(),
        89,
        "86 K1 operations plus the 3 K2 slice-1 greenfield-binding ones"
    );
    // The bundles the registry pins: the three K1 bundles plus K2 slice
    // 1's governed_work_binding_v1 (the binding half only — its
    // formation operations arrive with slice 2).
    let bundles: Vec<&str> = registry["bundles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_str().unwrap())
        .collect();
    assert_eq!(
        bundles,
        vec![
            "core_v1",
            "shared_space_v1",
            "developer_assistant_v1",
            "governed_work_binding_v1"
        ]
    );
}

#[test]
fn worker_surface_vectors_accept_the_attempt_binding_shape() {
    // Dual-surface ops: the schema admits the §15.2 binding members;
    // surface acceptance is the daemon's dispatch decision, not shape.
    for name in [
        "relation-assert-valid-worker-request.json",
        "contribution-append-valid-worker-request.json",
        "context-assembly-create-valid-worker-request.json",
    ] {
        let vector = load(&vectors_dir().join("ops").join(name));
        assert!(
            vector["expected"]["valid"].as_bool().unwrap(),
            "{name}: worker vectors are positives"
        );
        assert!(
            accepts_op_request(&vector["input"]["value"]),
            "{name}: the Rust mirror must accept the worker shape"
        );
    }
}

#[test]
fn result_projections_deserialize_from_vectors() {
    // The daemon's own result types must accept the schema-valid result
    // fixtures (closed shapes: an unknown member fails).
    let invocation = load(
        &vectors_dir()
            .join("ops")
            .join("invocation-show-valid-result.json"),
    );
    let parsed: Invocation = serde_json::from_value(invocation["input"]["value"].clone()).unwrap();
    assert!(!parsed.invocation_id.is_empty());
    assert!(
        ["developer", "confined", "secure"].contains(&parsed.effective_security_profile.as_str())
    );

    let page = load(
        &vectors_dir()
            .join("ops")
            .join("space-list-valid-result-page.json"),
    );
    let items = page["input"]["value"]["items"].as_array().unwrap();
    assert!(!items.is_empty());
    for item in items {
        let space: Space = serde_json::from_value(item.clone()).unwrap();
        assert!(!space.space_id.is_empty());
    }
    for field in ["snapshot", "boundary_event_cursor"] {
        assert!(
            page["input"]["value"][field].is_string(),
            "§11.5 page shape requires {field}"
        );
    }

    let begin = load(
        &vectors_dir()
            .join("ops")
            .join("artifact-upload-begin-valid-result.json"),
    );
    let value = &begin["input"]["value"];
    for field in [
        "upload_id",
        "artifact_id",
        "state",
        "declared_raw_sha256",
        "max_bytes",
        "expires_at",
    ] {
        assert!(
            !value[field].is_null(),
            "begin result must carry {field} (and never a credential)"
        );
    }
    assert!(value.get("credential").is_none(), "§10.10: no credential");
}

#[test]
fn relation_kind_enum_is_closed_and_verbatim() {
    // The §10.2 closed relation enum, byte-for-byte with the schema.
    let schema_path = vectors_dir()
        .parent()
        .unwrap()
        .join("schemas")
        .join("ops")
        .join("relation-assert-request.schema.json");
    let schema = load(&schema_path);
    let schema_kinds: Vec<&str> = schema["$defs"]["relationKind"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(schema_kinds, ops::RELATION_KINDS.to_vec());
    // And a synthetic out-of-enum kind fails the mirror.
    let mut relation = load(
        &vectors_dir()
            .join("ops")
            .join("relation-assert-valid-worker-request.json"),
    )["input"]["value"]
        .clone();
    relation["args"]["kind"] = Value::String("trusts".into());
    assert!(!accepts_op_request(&relation), "unknown kind fails closed");
}

/// A synthetic SpaceRelation projection round-trips through the closed
/// Rust record (no relation result vector carries a full record, so the
/// shape is pinned here against the result schema's required set).
#[test]
fn space_relation_projection_is_closed() {
    let record = serde_json::json!({
        "relation_id": "rel-0001", "revision": 1, "space_id": "space-0001",
        "origin_branch_id": "branch-0001", "branch_sequence": 4,
        "author_actor_ref": "prin-0001", "kind": "supports",
        "from_ref": {"object_ref": "contrib-0011", "revision": 1,
                      "digest": "2e".repeat(32)},
        "to_ref": {"object_ref": "contrib-0007", "revision": 1,
                    "digest": "3d".repeat(32)},
        "relation_class": "semantic_assertion",
        "classification_ref": "class-default",
        "schema_ref": "schema:space-relation-v1",
        "digest": "4c".repeat(32),
        "created_at": "2026-07-26T00:00:00Z",
    });
    let parsed: SpaceRelation = serde_json::from_value(record.clone()).unwrap();
    assert_eq!(parsed.relation_class, "semantic_assertion");
    // Closed shape: an unknown member fails.
    let mut widened = record;
    widened["grants_access"] = Value::Bool(true);
    assert!(serde_json::from_value::<SpaceRelation>(widened).is_err());
}
