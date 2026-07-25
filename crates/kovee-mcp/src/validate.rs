//! A strict interpreter for exactly the JSON-Schema subset the C3a
//! tools document uses — kovee-core's validator approach (hand-written
//! checks, no JSON-Schema crate), but driven by the embedded document
//! instead of hand-copied shapes.
//!
//! Two entry points:
//! - [`check_supported`] walks a schema once at startup and refuses any
//!   keyword, `type`, or `pattern` this interpreter does not implement,
//!   so a document evolution can never be silently under-validated —
//!   the server fails to start instead;
//! - [`validate`] enforces the schema on every tool input before
//!   dispatch. Every document shape is closed
//!   (`additionalProperties: false`), so an envelope- or
//!   channel-derived member riding in on tool input (`realm_id`,
//!   `actor_ref`, `meta`, …) is refused as an unknown member.
//!
//! `pattern` literals are mapped verbatim to the matching
//! `kovee_core::limits` predicate — the same lexical checks the daemon
//! validates with. Three of those predicates (`is_media_type`,
//! `is_language_tag`, `is_event_type_prefix`) embed the same character
//! cap the document states as `maxLength` next to the pattern, so the
//! combined outcome is identical.

use kovee_core::limits;
use serde_json::{Map, Value};

type JsonMap = Map<String, Value>;

/// The schema keywords this interpreter implements — exactly the
/// constructs the C3a document uses.
const KEYWORDS: [&str; 17] = [
    "$defs",
    "$ref",
    "additionalProperties",
    "description",
    "enum",
    "items",
    "maxItems",
    "maxLength",
    "minItems",
    "minLength",
    "maximum",
    "minimum",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "type",
];

/// Maps a document `pattern` literal to the kovee-core lexical
/// predicate implementing it. An unmapped pattern is unsupported.
fn matcher_for(pattern: &str) -> Option<fn(&str) -> bool> {
    Some(match pattern {
        r"^[\x21-\x7e]{1,128}$" => limits::is_identifier,
        r"^[0-9a-f]{64}$" => limits::is_digest_hex,
        r"^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*$" => limits::is_language_tag,
        r"^[!#$%&'*+.^_`|~a-zA-Z0-9-]+/[!#$%&'*+.^_`|~a-zA-Z0-9-]+$" => limits::is_media_type,
        r"^[a-z][a-z0-9]*(\.[a-z0-9-]+)*$" => limits::is_event_type_prefix,
        _ => return None,
    })
}

fn defs_of(root: &Value) -> Result<Option<&JsonMap>, String> {
    match root.get("$defs") {
        None => Ok(None),
        Some(Value::Object(map)) => Ok(Some(map)),
        Some(_) => Err("$defs is not an object".to_owned()),
    }
}

fn resolve<'a>(reference: &Value, defs: Option<&'a JsonMap>) -> Result<&'a Value, String> {
    let Some(reference) = reference.as_str() else {
        return Err("$ref is not a string".to_owned());
    };
    let Some(name) = reference.strip_prefix("#/$defs/") else {
        return Err(format!("$ref {reference:?} is not a #/$defs/ reference"));
    };
    defs.and_then(|d| d.get(name))
        .ok_or_else(|| format!("$ref {reference:?} does not resolve"))
}

// ------------------------------------------------------ supportedness ----

/// Verifies at startup that `root` (a tool `input_schema` with its
/// `$defs`) uses only constructs this interpreter implements.
pub fn check_supported(root: &Value) -> Result<(), String> {
    let defs = defs_of(root)?;
    walk(root, defs, true)?;
    if let Some(defs_map) = defs {
        for schema in defs_map.values() {
            walk(schema, defs, false)?;
        }
    }
    Ok(())
}

fn walk(schema: &Value, defs: Option<&JsonMap>, is_root: bool) -> Result<(), String> {
    let Some(map) = schema.as_object() else {
        return Err("schema node is not an object".to_owned());
    };
    for (key, member) in map {
        if !KEYWORDS.contains(&key.as_str()) {
            return Err(format!("unsupported schema keyword {key:?}"));
        }
        match key.as_str() {
            "$defs" if !is_root => {
                return Err("$defs below the schema root".to_owned());
            }
            "$ref" => {
                resolve(member, defs)?;
            }
            "type" => match member.as_str() {
                Some("object" | "string" | "integer" | "array") => {}
                _ => return Err(format!("unsupported type {member}")),
            },
            "additionalProperties" if member != &Value::Bool(false) => {
                return Err("additionalProperties must be false".to_owned());
            }
            "pattern" => {
                let literal = member.as_str().unwrap_or("");
                if matcher_for(literal).is_none() {
                    return Err(format!("unsupported pattern {literal:?}"));
                }
            }
            "enum" if member.as_array().is_none_or(|a| a.is_empty()) => {
                return Err("enum is not a non-empty array".to_owned());
            }
            "required" => {
                let ok = member
                    .as_array()
                    .is_some_and(|a| a.iter().all(Value::is_string));
                if !ok {
                    return Err("required is not a string array".to_owned());
                }
            }
            "properties" => {
                let Some(props) = member.as_object() else {
                    return Err("properties is not an object".to_owned());
                };
                for sub in props.values() {
                    walk(sub, defs, false)?;
                }
            }
            "items" => walk(member, defs, false)?,
            "oneOf" => {
                let Some(arms) = member.as_array() else {
                    return Err("oneOf is not an array".to_owned());
                };
                for arm in arms {
                    walk(arm, defs, false)?;
                }
            }
            "minLength" | "maxLength" | "minItems" | "maxItems" if member.as_u64().is_none() => {
                return Err(format!("{key} is not a non-negative integer"));
            }
            "minimum" | "maximum" if member.as_i64().is_none() => {
                return Err(format!("{key} is not an integer"));
            }
            "description" if !member.is_string() => {
                return Err("description is not a string".to_owned());
            }
            _ => {}
        }
    }
    Ok(())
}

// --------------------------------------------------------- validation ----

/// Validates one tool input against its document schema.
pub fn validate(root: &Value, input: &Value) -> Result<(), String> {
    let defs = defs_of(root)?;
    node(root, defs, input, "input")
}

fn node(schema: &Value, defs: Option<&JsonMap>, value: &Value, path: &str) -> Result<(), String> {
    let Some(map) = schema.as_object() else {
        return Err(format!("{path}: schema node is not an object"));
    };
    if let Some(reference) = map.get("$ref") {
        return node(resolve(reference, defs)?, defs, value, path);
    }
    if let Some(arms) = map.get("oneOf").and_then(Value::as_array) {
        let hits = arms
            .iter()
            .filter(|arm| node(arm, defs, value, path).is_ok())
            .count();
        return if hits == 1 {
            Ok(())
        } else {
            Err(format!(
                "{path} matches {hits} of the {} oneOf arms (exactly one required)",
                arms.len()
            ))
        };
    }
    if let Some(allowed) = map.get("enum").and_then(Value::as_array) {
        if !allowed.iter().any(|candidate| candidate == value) {
            return Err(format!("{path} is not one of the closed enum values"));
        }
    }
    match map.get("type").and_then(Value::as_str) {
        None => Ok(()), // e.g. dataPart.value — any JSON
        Some("object") => check_object(map, defs, value, path),
        Some("string") => check_string(map, value, path),
        Some("integer") => check_integer(map, value, path),
        Some("array") => check_array(map, defs, value, path),
        Some(other) => Err(format!("{path}: unsupported schema type {other:?}")),
    }
}

fn check_object(
    schema: &JsonMap,
    defs: Option<&JsonMap>,
    value: &Value,
    path: &str,
) -> Result<(), String> {
    let Some(members) = value.as_object() else {
        return Err(format!("{path} is not an object"));
    };
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !members.contains_key(name) {
                return Err(format!("{path}.{name} is required"));
            }
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    let closed = schema.get("additionalProperties") == Some(&Value::Bool(false));
    for (name, member) in members {
        match properties.and_then(|p| p.get(name)) {
            Some(sub) => node(sub, defs, member, &format!("{path}.{name}"))?,
            None if closed => {
                return Err(format!(
                    "{path}.{name} is not a member of this closed shape"
                ));
            }
            None => {} // open object (e.g. events_wait filters)
        }
    }
    Ok(())
}

fn check_string(schema: &JsonMap, value: &Value, path: &str) -> Result<(), String> {
    let Some(s) = value.as_str() else {
        return Err(format!("{path} is not a string"));
    };
    let scalars = s.chars().count() as u64;
    if let Some(min) = schema.get("minLength").and_then(Value::as_u64) {
        if scalars < min {
            return Err(format!("{path} is shorter than {min} characters"));
        }
    }
    if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
        if scalars > max {
            return Err(format!("{path} is longer than {max} characters"));
        }
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        let Some(matches) = matcher_for(pattern) else {
            return Err(format!("{path}: unsupported pattern {pattern:?}"));
        };
        if !matches(s) {
            return Err(format!("{path} does not match {pattern:?}"));
        }
    }
    Ok(())
}

fn check_integer(schema: &JsonMap, value: &Value, path: &str) -> Result<(), String> {
    // serde_json keeps 1.0 as a float, so a non-integer representation
    // fails here — the I-JSON discipline of the daemon's own parser.
    let n: i128 = match (value.as_i64(), value.as_u64()) {
        (Some(i), _) => i128::from(i),
        (None, Some(u)) => i128::from(u),
        _ => return Err(format!("{path} is not an integer")),
    };
    if let Some(min) = schema.get("minimum").and_then(Value::as_i64) {
        if n < i128::from(min) {
            return Err(format!("{path} is less than {min}"));
        }
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_i64) {
        if n > i128::from(max) {
            return Err(format!("{path} is greater than {max}"));
        }
    }
    Ok(())
}

fn check_array(
    schema: &JsonMap,
    defs: Option<&JsonMap>,
    value: &Value,
    path: &str,
) -> Result<(), String> {
    let Some(items) = value.as_array() else {
        return Err(format!("{path} is not an array"));
    };
    let count = items.len() as u64;
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
        if count < min {
            return Err(format!("{path} holds fewer than {min} items"));
        }
    }
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
        if count > max {
            return Err(format!("{path} holds more than {max} items"));
        }
    }
    if let Some(item_schema) = schema.get("items") {
        for (index, item) in items.iter().enumerate() {
            node(item_schema, defs, item, &format!("{path}[{index}]"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::document;

    fn schema_of(tool: &str) -> Value {
        document::load()
            .unwrap()
            .tool(tool)
            .unwrap()
            .input_schema
            .clone()
    }

    #[test]
    fn every_document_schema_is_supported() {
        // document::load already runs check_supported per tool; assert
        // it directly too so a drift names the failing construct.
        for tool in document::load().unwrap().tools {
            check_supported(&tool.input_schema).unwrap_or_else(|e| panic!("{}: {e}", tool.name));
        }
    }

    #[test]
    fn closed_shapes_refuse_channel_derived_members() {
        let schema = schema_of("kovee_space_show");
        validate(&schema, &json!({"space_id": "space-1"})).unwrap();
        for injected in ["actor_ref", "realm_id", "project_id", "meta"] {
            let err =
                validate(&schema, &json!({"space_id": "space-1", injected: "x"})).unwrap_err();
            assert!(err.contains(injected), "{err}");
            assert!(err.contains("closed shape"), "{err}");
        }
    }

    #[test]
    fn required_pattern_and_bounds_are_enforced() {
        let schema = schema_of("kovee_contribution_list");
        let err = validate(&schema, &json!({"space_id": "space-1"})).unwrap_err();
        assert!(err.contains("limit is required"), "{err}");
        let err = validate(&schema, &json!({"space_id": "space-1", "limit": 513})).unwrap_err();
        assert!(err.contains("greater than 512"), "{err}");
        let err = validate(&schema, &json!({"space_id": "space-1", "limit": 0})).unwrap_err();
        assert!(err.contains("less than 1"), "{err}");
        let err = validate(&schema, &json!({"space_id": "spa ce", "limit": 5})).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
        let err = validate(&schema, &json!({"space_id": "space-1", "limit": 5.5})).unwrap_err();
        assert!(err.contains("not an integer"), "{err}");
        let err = validate(
            &schema,
            &json!({"space_id": "space-1", "limit": 5, "kind": "song"}),
        )
        .unwrap_err();
        assert!(err.contains("enum"), "{err}");
        validate(
            &schema,
            &json!({"space_id": "space-1", "limit": 5, "kind": "claim"}),
        )
        .unwrap();
    }

    #[test]
    fn one_of_discriminates_contribution_parts() {
        let schema = schema_of("kovee_contribution_append");
        let base = |parts: Value| {
            json!({
                "space_id": "space-1",
                "branch_id": "branch-1",
                "expected_head_digest": "a".repeat(64),
                "kind": "observation",
                "body_parts": parts,
            })
        };
        validate(
            &schema,
            &base(json!([{"media_type": "text/plain", "text": "hi"}])),
        )
        .unwrap();
        validate(&schema, &base(json!([{"artifact_ref": "art-1"}]))).unwrap();
        let err = validate(&schema, &base(json!([{}]))).unwrap_err();
        assert!(err.contains("oneOf"), "{err}");
        let err = validate(
            &schema,
            &base(json!([{"media_type": "text/plain", "text": "hi", "actor_ref": "x"}])),
        )
        .unwrap_err();
        assert!(err.contains("oneOf"), "{err}");
    }

    #[test]
    fn unknown_constructs_are_refused_at_startup() {
        let err = check_supported(&json!({"type": "string", "format": "uri"})).unwrap_err();
        assert!(err.contains("format"), "{err}");
        let err = check_supported(&json!({"type": "number"})).unwrap_err();
        assert!(err.contains("unsupported type"), "{err}");
        let err = check_supported(&json!({"type": "string", "pattern": "^x+$"})).unwrap_err();
        assert!(err.contains("unsupported pattern"), "{err}");
        let err =
            check_supported(&json!({"type": "object", "additionalProperties": true})).unwrap_err();
        assert!(err.contains("additionalProperties"), "{err}");
    }
}
