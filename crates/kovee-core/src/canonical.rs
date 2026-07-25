//! The §11.8 digest constructions: RFC 8785 JCS over the I-JSON value
//! space, `CanonicalObjectDigest`, `TypedByteDigest`, and the §11.2
//! idempotency request digest. Byte-for-byte parity with the independent
//! rederivers (`xcheck/run.py`, `tscheck/`) is proven by the digest
//! vectors in `spec/vectors/envelope/` (see `tests/k1_slice1_vectors.rs`).
//!
//! What you write:
//! ```
//! use kovee_core::canonical::canonical_object_digest;
//! let (canonical, hex) = canonical_object_digest(
//!     "kcp-decision-subject",
//!     "https://kovee.example/kcp/v0/kcp-command.schema.json#/$defs/args",
//!     &serde_json::json!({"branch": "main", "sequence": 42}),
//! ).unwrap();
//! assert!(canonical.starts_with("{\"$domain\":"));
//! assert_eq!(hex.len(), 64);
//! ```

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::envelope::RawCommand;
use crate::ijson::SAFE_MAX;

/// The `$domain` constant of `CanonicalObjectDigest` (§11.8).
pub const COD_DOMAIN: &str = "dev.kovee.canonical-object-digest.v1";
/// The frame constant of `TypedByteDigest` (§11.8).
pub const TBD_DOMAIN: &str = "dev.kovee.typed-bytes-digest.v1";

#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    #[error("unsafe integer in canonical input")]
    UnsafeInteger,
    #[error("non-finite number in canonical input")]
    NonFinite,
}

/// RFC 8785 JCS bytes: object keys sorted by UTF-16 code units, ES
/// minimal number form, the two-character escapes plus `\u00xx` for
/// remaining controls.
pub fn jcs(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    jcs_into(value, &mut out)?;
    Ok(out)
}

fn jcs_into(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > SAFE_MAX {
                    return Err(CanonicalError::UnsafeInteger);
                }
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                if u > SAFE_MAX {
                    return Err(CanonicalError::UnsafeInteger);
                }
                out.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(f) = n.as_f64() {
                out.extend_from_slice(es_number(f)?.as_bytes());
            } else {
                return Err(CanonicalError::NonFinite);
            }
        }
        Value::String(s) => jcs_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                jcs_into(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| {
                let ka: Vec<u16> = a.0.encode_utf16().collect();
                let kb: Vec<u16> = b.0.encode_utf16().collect();
                ka.cmp(&kb)
            });
            out.push(b'{');
            for (i, (key, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                jcs_string(key, out);
                out.push(b':');
                jcs_into(val, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn jcs_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// ECMAScript `Number::toString(10)` for a finite double (RFC 8785).
/// Rust's `{:e}` yields the shortest round-trip digits; this reformats
/// them under the ES fixed/exponent thresholds.
pub fn es_number(v: f64) -> Result<String, CanonicalError> {
    if !v.is_finite() {
        return Err(CanonicalError::NonFinite);
    }
    if v == 0.0 {
        return Ok("0".to_owned());
    }
    let sign = if v < 0.0 { "-" } else { "" };
    let sci = format!("{:e}", v.abs()); // e.g. "1.25e-8", "1e21"
    let (mant, exp_s) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exp: i64 = exp_s.parse().unwrap_or(0);
    let (ip, fp) = mant.split_once('.').unwrap_or((mant, ""));
    let digits: String = format!("{ip}{fp}");
    let stripped = digits.trim_start_matches('0');
    let s = stripped.trim_end_matches('0');
    let trailing = (stripped.len() - s.len()) as i64;
    let k = s.len() as i64;
    // n: position of the decimal point relative to the digit string.
    let n = k + trailing + exp - fp.len() as i64;
    let out = if k <= n && n <= 21 {
        format!("{s}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &s[..n as usize], &s[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{s}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let mant_out = if k > 1 {
            format!("{}.{}", &s[..1], &s[1..])
        } else {
            s.to_owned()
        };
        format!("{mant_out}e{}{}", if e >= 0 { "+" } else { "-" }, e.abs())
    };
    Ok(format!("{sign}{out}"))
}

/// `CanonicalObjectDigest(kind, schema_ref, projection)` (§11.8): the
/// canonical bytes and the SHA-256 hex over them.
pub fn canonical_object_digest(
    object_kind: &str,
    schema_ref: &str,
    projection: &Value,
) -> Result<(String, String), CanonicalError> {
    let obj = serde_json::json!({
        "$domain": COD_DOMAIN,
        "protocol_major": 0,
        "object_kind": object_kind,
        "schema_ref": schema_ref,
        "projection": projection,
    });
    let bytes = jcs(&obj)?;
    let hex = sha256_hex(&bytes);
    Ok((String::from_utf8_lossy(&bytes).into_owned(), hex))
}

fn frame(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// `TypedByteDigest(domain, media_or_schema_ref, bytes)` (§11.8).
pub fn typed_byte_digest(domain: &str, media_or_schema_ref: &str, data: &[u8]) -> String {
    let mut input = Vec::new();
    frame(TBD_DOMAIN.as_bytes(), &mut input);
    frame(domain.as_bytes(), &mut input);
    frame(b"0", &mut input);
    frame(media_or_schema_ref.as_bytes(), &mut input);
    frame(data, &mut input);
    sha256_hex(&input)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The `kcp-command` schema id — the `schema_ref` of the idempotency
/// request digest (§11.2; `spec/vectors/envelope/digest-command-…`).
pub const KCP_COMMAND_SCHEMA_REF: &str = "https://kovee.example/kcp/v0/kcp-command.schema.json";

/// The §11.2 idempotency request digest: `CanonicalObjectDigest` for kind
/// `kcp-command-idempotency` over `{version, authority_surface, op,
/// realm_id, project_id?, expected_revision?, args, ext}` — excluding
/// `request_id`, `traceparent`, transport headers, and causation
/// telemetry. Absent `ext` canonicalizes to `{}` (the projection lists
/// `ext` unmarked); absent optional members are omitted.
pub fn idempotency_request_digest(
    cmd: &RawCommand,
    authority_surface: &str,
) -> Result<String, CanonicalError> {
    let mut projection = serde_json::Map::new();
    projection.insert("version".into(), Value::String(cmd.version.clone()));
    projection.insert(
        "authority_surface".into(),
        Value::String(authority_surface.to_owned()),
    );
    projection.insert("op".into(), Value::String(cmd.op.clone()));
    if let Some(realm) = &cmd.realm_id {
        projection.insert("realm_id".into(), Value::String(realm.clone()));
    }
    if let Some(project) = &cmd.project_id {
        projection.insert("project_id".into(), Value::String(project.clone()));
    }
    if let Some(rev) = cmd.meta.as_ref().and_then(|m| m.expected_revision) {
        projection.insert("expected_revision".into(), Value::from(rev));
    }
    projection.insert("args".into(), Value::Object(cmd.args.clone()));
    projection.insert(
        "ext".into(),
        Value::Object(cmd.ext.clone().unwrap_or_default()),
    );
    let (_, hex) = canonical_object_digest(
        "kcp-command-idempotency",
        KCP_COMMAND_SCHEMA_REF,
        &Value::Object(projection),
    )?;
    Ok(hex)
}
