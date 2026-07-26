//! The Kovee-owned governed-scope selector grammar and its overlap rule.
//!
//! byom pins only the bounded opaque wire shape of a selector (≤256
//! visible-ASCII bytes); the grammar and the "no overlapping active owner
//! selectors" predicate (§16.6 item 1) are Kovee's to close, and this is
//! where they are closed.
//!
//! What you write:
//! ```
//! use kovee_byom::scope::{Selector, overlaps};
//! let all = Selector::parse("project:*").unwrap();
//! let one = Selector::parse("project:proj-1/space:sp-1").unwrap();
//! assert!(overlaps(&all, &one));      // the wildcard covers the exact scope
//! let other = Selector::parse("project:proj-2").unwrap();
//! assert!(!overlaps(&one, &other));   // disjoint projects never overlap
//! ```
//!
//! Plumbing: a selector is `realm` or a `/`-joined path of `kind:value`
//! segments in the fixed order `project` then `space`, where `value` is
//! an identifier or the wildcard `*`. Two selectors overlap when every
//! segment they share matches (wildcards match anything) — so a prefix
//! covers every extension of itself, which is exactly the containment
//! the owner-binding uniqueness rule needs.

use kovee_core::limits;

/// A parsed governed-scope selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    text: String,
    segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    kind: &'static str,
    value: Option<String>,
}

/// The fixed segment order. A selector names a prefix of it.
const SEGMENT_KINDS: [&str; 2] = ["project", "space"];

/// Selectors are at most 256 visible-ASCII bytes on the wire (byom's
/// `selector` def in the C2 host schemas).
pub const SELECTOR_MAX_BYTES: usize = 256;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectorError {
    #[error("selector is empty or longer than 256 visible-ASCII bytes")]
    Shape,
    #[error("selector segment {0} is not <kind>:<identifier|*>")]
    Segment(usize),
    #[error("selector segments must appear in the order project, space")]
    Order,
}

impl Selector {
    /// The whole realm — the widest scope; overlaps everything.
    pub fn realm() -> Selector {
        Selector {
            text: "realm".to_owned(),
            segments: Vec::new(),
        }
    }

    pub fn parse(text: &str) -> Result<Selector, SelectorError> {
        if text.is_empty()
            || text.len() > SELECTOR_MAX_BYTES
            || !text.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(SelectorError::Shape);
        }
        if text == "realm" {
            return Ok(Selector::realm());
        }
        let mut segments = Vec::new();
        for (index, raw) in text.split('/').enumerate() {
            let Some((kind, value)) = raw.split_once(':') else {
                return Err(SelectorError::Segment(index));
            };
            let Some(expected) = SEGMENT_KINDS.get(index) else {
                return Err(SelectorError::Order);
            };
            if kind != *expected {
                return Err(SelectorError::Order);
            }
            let value = match value {
                "*" => None,
                v if limits::is_identifier(v) && !v.contains(':') => Some(v.to_owned()),
                _ => return Err(SelectorError::Segment(index)),
            };
            segments.push(Segment {
                kind: expected,
                value,
            });
        }
        Ok(Selector {
            text: text.to_owned(),
            segments,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The canonical projection the exact-scope digest is taken over.
    pub fn projection(&self) -> serde_json::Value {
        serde_json::json!({
            "selector": self.text,
            "segments": self.segments.iter().map(|s| serde_json::json!({
                "kind": s.kind,
                "value": s.value,
            })).collect::<Vec<_>>(),
        })
    }
}

/// Whether two governed scopes overlap — the §16.6 item 1 predicate. Two
/// selectors overlap when neither disagrees on a segment both name; a
/// shorter selector therefore covers every extension of itself, and a
/// wildcard segment matches any value.
pub fn overlaps(a: &Selector, b: &Selector) -> bool {
    for (sa, sb) in a.segments.iter().zip(b.segments.iter()) {
        match (&sa.value, &sb.value) {
            (Some(va), Some(vb)) if va != vb => return false,
            _ => {}
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn s(text: &str) -> Selector {
        Selector::parse(text).unwrap()
    }

    #[test]
    fn the_realm_selector_overlaps_everything() {
        assert!(overlaps(
            &Selector::realm(),
            &s("project:proj-1/space:sp-1")
        ));
        assert!(overlaps(&s("project:proj-1"), &Selector::realm()));
    }

    #[test]
    fn wildcards_cover_exact_scopes_and_disjoint_ids_do_not_overlap() {
        assert!(overlaps(&s("project:*"), &s("project:proj-1")));
        assert!(overlaps(
            &s("project:proj-1"),
            &s("project:proj-1/space:sp-9")
        ));
        assert!(!overlaps(&s("project:proj-1"), &s("project:proj-2")));
        assert!(!overlaps(
            &s("project:proj-1/space:sp-1"),
            &s("project:proj-1/space:sp-2")
        ));
        // Same project, one wildcard space: still overlapping.
        assert!(overlaps(
            &s("project:proj-1/space:*"),
            &s("project:proj-1/space:sp-2")
        ));
    }

    #[test]
    fn overlap_is_symmetric_and_reflexive() {
        let pairs = [
            ("realm", "project:proj-1"),
            ("project:*", "project:proj-1/space:sp-1"),
            ("project:proj-1", "project:proj-2"),
        ];
        for (a, b) in pairs {
            assert_eq!(overlaps(&s(a), &s(b)), overlaps(&s(b), &s(a)), "{a} vs {b}");
        }
        for text in ["realm", "project:proj-1", "project:proj-1/space:sp-1"] {
            assert!(overlaps(&s(text), &s(text)));
        }
    }

    #[test]
    fn malformed_selectors_fail_closed() {
        assert_eq!(Selector::parse(""), Err(SelectorError::Shape));
        assert_eq!(Selector::parse(&"a".repeat(257)), Err(SelectorError::Shape));
        assert_eq!(Selector::parse("proj-1"), Err(SelectorError::Segment(0)));
        assert_eq!(Selector::parse("space:sp-1"), Err(SelectorError::Order));
        assert_eq!(
            Selector::parse("project:p/space:s/branch:b"),
            Err(SelectorError::Order)
        );
        assert_eq!(Selector::parse("project: "), Err(SelectorError::Shape));
    }
}
