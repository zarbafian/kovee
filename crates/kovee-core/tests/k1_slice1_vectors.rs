//! K1 slice-1 vector round-trip: the K0 schemas in `spec/schemas/` are
//! the wire truth, the Rust in `kovee-core` enforces the same
//! constraints, and this test proves agreement over the golden vectors —
//! every schema-valid envelope command and slice-1 op request must pass
//! the Rust validation, every schema-invalid one must fail, the raw
//! acceptance commands must be rejected by strict I-JSON parsing, and
//! every digest derivation must reproduce the vectors' canonical bytes
//! and SHA-256 values byte-for-byte (parity with `xcheck`/`tscheck`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use kovee_core::canonical;
use kovee_core::envelope::{RawCommand, Shape};
use kovee_core::ijson;
use kovee_core::ops;
use kovee_core::records::{Contribution, HelloResult};
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

fn vector_files(family: &str) -> Vec<PathBuf> {
    let dir = vectors_dir().join(family);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    files
}

/// Full slice-1 acceptance of one command value: strict re-parse, envelope
/// shape, and the per-op argument schema mirror.
fn accepts_command(value: &Value, shape: Shape) -> bool {
    // Round-trip through the strict parser so the same acceptance path the
    // daemon runs is exercised (the vector file itself was parsed by
    // serde_json; schema-vector values contain no acceptance violations).
    let text = serde_json::to_string(value).unwrap();
    let Ok(strict) = ijson::parse_strict(&text) else {
        return false;
    };
    let Ok(cmd) = RawCommand::from_value(strict) else {
        return false;
    };
    cmd.validate(shape).is_ok()
}

#[test]
fn envelope_command_vectors_round_trip() {
    let mut checked = 0;
    for path in vector_files("envelope") {
        let vector = load(&path);
        if vector["input"]["schema"].as_str() != Some("kcp-command") {
            continue;
        }
        let shape = match vector["input"]["ref"].as_str() {
            Some("#/$defs/mutationCommand") => Shape::Mutation,
            Some("#/$defs/readCommand") => Shape::Read,
            None => Shape::Generic,
            Some(other) => panic!("{}: unknown ref {other}", path.display()),
        };
        let expected = vector["expected"]["valid"].as_bool().unwrap();
        let actual = accepts_command(&vector["input"]["value"], shape);
        assert_eq!(
            actual,
            expected,
            "{}: schema says valid={expected}, Rust says {actual}",
            path.display()
        );
        checked += 1;
    }
    assert!(checked >= 12, "only {checked} kcp-command vectors found");
}

#[test]
fn raw_acceptance_command_vectors_are_rejected() {
    let mut checked = 0;
    for path in vector_files("envelope") {
        let vector = load(&path);
        let name = vector["name"].as_str().unwrap_or_default();
        if !name.starts_with("envelope/command-") {
            continue;
        }
        let Some(raw) = vector["input"]["raw"].as_str() else {
            continue;
        };
        assert!(
            !vector["expected"]["valid"].as_bool().unwrap(),
            "{name}: raw command vectors are all invalid"
        );
        assert!(
            ijson::parse_strict(raw).is_err(),
            "{name}: strict I-JSON parse must reject this input"
        );
        checked += 1;
    }
    assert!(checked >= 3, "only {checked} raw command vectors found");
}

/// The request-schema basenames of the slice-1 op set.
const SLICE1_REQUEST_SCHEMAS: [&str; 8] = [
    "hello-request",
    "realm-show-request",
    "project-create-request",
    "space-create-request",
    "space-show-request",
    "contribution-append-request",
    "contribution-show-request",
    "events-read-request",
];

#[test]
fn slice1_op_request_vectors_round_trip() {
    let mut checked = 0;
    for path in vector_files("ops") {
        let vector = load(&path);
        let Some(schema) = vector["input"]["schema"].as_str() else {
            continue;
        };
        if !SLICE1_REQUEST_SCHEMAS.contains(&schema) {
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
    }
    // 8 ops × at least 3 negatives + the valid requests.
    assert!(checked >= 30, "only {checked} slice-1 op vectors found");
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
fn result_projections_deserialize_from_vectors() {
    // The daemon's own result types must accept the schema-valid result
    // fixtures (closed shapes: an unknown member fails).
    let contribution = load(
        &vectors_dir()
            .join("ops")
            .join("contribution-append-valid-result.json"),
    );
    let parsed: Contribution =
        serde_json::from_value(contribution["input"]["value"].clone()).unwrap();
    assert_eq!(parsed.revision, 1);
    assert_eq!(parsed.body_parts.len(), 2);

    let hello = load(
        &vectors_dir()
            .join("envelope")
            .join("hello-result-valid.json"),
    );
    let parsed: HelloResult = serde_json::from_value(hello["input"]["value"].clone()).unwrap();
    assert_eq!(parsed.selected_version, "0.1");
}

#[test]
fn digest_vectors_reproduce_byte_for_byte() {
    let mut derivations_checked = 0;
    for path in vector_files("envelope") {
        let vector = load(&path);
        let name = vector["name"].as_str().unwrap_or_default();
        if !name.starts_with("envelope/digest-") {
            continue;
        }
        let inputs = vector["input"]["derivations"].as_array().unwrap();
        let expected = vector["expected"]["results"].as_array().unwrap();
        assert_eq!(inputs.len(), expected.len(), "{name}: shape mismatch");
        let mut primaries = Vec::new();
        for (derivation, expect) in inputs.iter().zip(expected) {
            let (canonical_str, hex) = derive(derivation);
            if let Some(canon) = expect["canonical"].as_str() {
                assert_eq!(
                    canonical_str.as_deref(),
                    Some(canon),
                    "{name}: canonical bytes differ"
                );
            }
            let expected_hex = expect["sha256_hex"]
                .as_str()
                .or(expect["digest_hex"].as_str())
                .unwrap();
            assert_eq!(hex, expected_hex, "{name}: digest differs");
            primaries.push(hex);
            derivations_checked += 1;
        }
        match vector["expected"]["relation"].as_str() {
            Some("equal") => {
                assert!(
                    primaries.windows(2).all(|w| w[0] == w[1]),
                    "{name}: not equal"
                )
            }
            Some("distinct") => {
                let unique: std::collections::BTreeSet<_> = primaries.iter().collect();
                assert_eq!(unique.len(), primaries.len(), "{name}: not distinct");
            }
            _ => {}
        }
    }
    assert!(
        derivations_checked >= 10,
        "only {derivations_checked} digest derivations found"
    );
}

/// Mirrors `xcheck/run.py::derive_digest` exactly.
fn derive(d: &Value) -> (Option<String>, String) {
    match d["kind"].as_str().unwrap() {
        "dev.kovee.canonical-object-digest.v1" => {
            let (canonical_str, hex) = canonical::canonical_object_digest(
                d["object_kind"].as_str().unwrap(),
                d["schema_ref"].as_str().unwrap(),
                &d["projection"],
            )
            .unwrap();
            (Some(canonical_str), hex)
        }
        "kcp-command-idempotency" => {
            let projection = if let Some(p) = d.get("projection").filter(|p| !p.is_null()) {
                p.clone()
            } else {
                let raw = d["raw_command"].as_object().unwrap();
                let fields = d["projection_fields"].as_array().unwrap();
                let mut out = serde_json::Map::new();
                for f in fields {
                    let key = f.as_str().unwrap();
                    if let Some(v) = raw.get(key) {
                        out.insert(key.to_owned(), v.clone());
                    }
                }
                Value::Object(out)
            };
            let (canonical_str, hex) = canonical::canonical_object_digest(
                "kcp-command-idempotency",
                d["schema_ref"].as_str().unwrap(),
                &projection,
            )
            .unwrap();
            (Some(canonical_str), hex)
        }
        "dev.kovee.typed-bytes-digest.v1" => {
            let hex = canonical::typed_byte_digest(
                d["domain"].as_str().unwrap(),
                d["media_or_schema_ref"].as_str().unwrap(),
                d["bytes_utf8"].as_str().unwrap().as_bytes(),
            );
            (None, hex)
        }
        other => panic!("unknown derivation kind {other}"),
    }
}
