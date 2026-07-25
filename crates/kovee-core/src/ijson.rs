//! Strict I-JSON acceptance (design §11.8): duplicate keys, unsafe
//! integers, non-finite numbers, and unpaired surrogates are rejected.
//!
//! `serde_json` already rejects non-finite numbers and unpaired surrogates;
//! this parser adds the two checks it is lenient about — duplicate object
//! keys (serde_json silently keeps the last) and integers outside the
//! ±(2^53−1) I-JSON safe range — by building the value through a visitor
//! that sees every map entry and every number token.
//!
//! What you write:
//! ```
//! assert!(kovee_core::ijson::parse_strict(r#"{"a":1}"#).is_ok());
//! assert!(kovee_core::ijson::parse_strict(r#"{"a":1,"a":2}"#).is_err());
//! assert!(kovee_core::ijson::parse_strict("{\"n\":9007199254740992}").is_err());
//! ```

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// The largest I-JSON safe integer magnitude, 2^53 − 1 (§11.8).
pub const SAFE_MAX: u64 = 9_007_199_254_740_991;

#[derive(Debug, thiserror::Error)]
pub enum IjsonError {
    #[error("not strict I-JSON: {0}")]
    Reject(String),
}

struct Strict;

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a strict I-JSON value")
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        if v.unsigned_abs() > SAFE_MAX {
            return Err(E::custom("unsafe integer (outside ±(2^53-1))"));
        }
        Ok(Value::from(v))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        if v > SAFE_MAX {
            return Err(E::custom("unsafe integer (outside ±(2^53-1))"));
        }
        Ok(Value::from(v))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        if !v.is_finite() {
            return Err(E::custom("non-finite number"));
        }
        Ok(serde_json::Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(v) = seq.next_element_seed(Strict)? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(Strict)?;
            if out.insert(key.clone(), value).is_some() {
                return Err(A::Error::custom(format!("duplicate object key {key:?}")));
            }
        }
        Ok(Value::Object(out))
    }
}

/// Parses `text` as one strict I-JSON value with nothing but whitespace
/// after it. A UTF-8 BOM prefix is rejected (§11.8 strict UTF-8; the
/// acceptance family's `bom-prefix` case).
pub fn parse_strict(text: &str) -> Result<Value, IjsonError> {
    if text.starts_with('\u{feff}') {
        return Err(IjsonError::Reject("BOM prefix".to_owned()));
    }
    let mut de = serde_json::Deserializer::from_str(text);
    let value = Strict
        .deserialize(&mut de)
        .map_err(|e| IjsonError::Reject(e.to_string()))?;
    de.end().map_err(|e| IjsonError::Reject(e.to_string()))?;
    Ok(value)
}
