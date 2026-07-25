//! §11.8 encoding limits and the closed lexical shapes the K0 op schemas
//! pin (identifier, display name, digest hex, traceparent, …). Each
//! predicate mirrors one `$defs` entry in `spec/schemas/`; the vector
//! round-trip test proves the mirror is faithful.

/// Request body cap: 256 KiB (§11.8), enforced at admission.
pub const REQUEST_MAX_BYTES: usize = 256 * 1024;
/// Reply cap: 1 MiB (§11.8).
pub const REPLY_MAX_BYTES: usize = 1024 * 1024;
/// A request contains at most 256 list items (§11.8).
pub const LIST_MAX_ITEMS: usize = 256;
/// Page/event read limit is at most 512 (§11.8).
pub const PAGE_MAX_LIMIT: u64 = 512;
/// Contribution inline content cap: 64 KiB of Unicode scalar values
/// (§11.8; schema `inlineText.maxLength`).
pub const INLINE_TEXT_MAX_SCALARS: usize = 65_536;
/// Opaque cursor / snapshot token ceiling (K0 extraction decision).
pub const CURSOR_MAX_CHARS: usize = 4096;

/// `identifier`: 1–128 visible-ASCII bytes (§11.8 + K0 extraction).
pub fn is_identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// `displayName`: 1–256 Unicode scalar values (§11.8).
pub fn is_display_name(s: &str) -> bool {
    let n = s.chars().count();
    (1..=256).contains(&n)
}

/// `digestHex`: exactly 64 lowercase hex characters.
pub fn is_digest_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `protocolVersion`: `major.minor`, no leading zeros (§11).
pub fn is_protocol_version(s: &str) -> bool {
    let Some((major, minor)) = s.split_once('.') else {
        return false;
    };
    is_plain_number(major) && is_plain_number(minor)
}

fn is_plain_number(s: &str) -> bool {
    match s.as_bytes() {
        [] => false,
        [b'0'] => true,
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

/// `operationId` / `featureId`: `^[a-z][a-z0-9_]{0,127}$`.
pub fn is_operation_id(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_lowercase() => {}
        _ => return false,
    }
    s.len() <= 128 && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// `traceparent`: `^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`.
pub fn is_traceparent(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 4
        && [2usize, 32, 16, 2]
            .iter()
            .zip(&parts)
            .all(|(len, p)| p.len() == *len && p.bytes().all(is_lower_hex))
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// `ext` property name: `^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$` (§11.9
/// reverse-domain namespace).
pub fn is_ext_namespace(s: &str) -> bool {
    let mut segments = s.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    let mut first_bytes = first.bytes();
    match first_bytes.next() {
        Some(b) if b.is_ascii_lowercase() => {}
        _ => return false,
    }
    if !first_bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return false;
    }
    let mut rest = 0;
    for seg in segments {
        rest += 1;
        if seg.is_empty()
            || !seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return false;
        }
    }
    rest >= 1
}

/// `mediaType`: RFC 6838 `type/subtype` token pair, ≤128 chars.
pub fn is_media_type(s: &str) -> bool {
    if s.len() > 128 {
        return false;
    }
    let Some((t, sub)) = s.split_once('/') else {
        return false;
    };
    is_mt_token(t) && is_mt_token(sub)
}

fn is_mt_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b))
}

/// `languageTag`: `^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*$`, ≤64 chars.
pub fn is_language_tag(s: &str) -> bool {
    if s.len() > 64 {
        return false;
    }
    let mut segments = s.split('-');
    let Some(first) = segments.next() else {
        return false;
    };
    if first.is_empty() || first.len() > 8 || !first.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    segments.all(|seg| {
        !seg.is_empty() && seg.len() <= 8 && seg.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// `eventType`: reverse-domain name ending in a major version, e.g.
/// `dev.kovee.space.contribution-appended.v1` (§11.3), ≤128 chars.
pub fn is_event_type(s: &str) -> bool {
    if s.len() > 128 {
        return false;
    }
    let segments: Vec<&str> = s.split('.').collect();
    if segments.len() < 3 {
        return false;
    }
    let Some((&version, body)) = segments.split_last() else {
        return false;
    };
    let Some((&first, middle)) = body.split_first() else {
        return false;
    };
    if !is_lower_alnum_head(first) {
        return false;
    }
    if !middle.iter().all(|seg| is_dashed_segment(seg)) || middle.is_empty() {
        return false;
    }
    let v = version.strip_prefix('v').unwrap_or("");
    matches!(v.as_bytes(), [b'1'..=b'9', rest @ ..] if rest.iter().all(u8::is_ascii_digit))
}

fn is_lower_alnum_head(s: &str) -> bool {
    let mut b = s.bytes();
    matches!(b.next(), Some(c) if c.is_ascii_lowercase())
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn is_dashed_segment(s: &str) -> bool {
    // `[a-z][a-z0-9]*(-[a-z0-9]+)*`
    let mut parts = s.split('-');
    let Some(first) = parts.next() else {
        return false;
    };
    is_lower_alnum_head(first)
        && parts.all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// `eventTypePrefix`: `^[a-z][a-z0-9]*(\.[a-z0-9-]+)*$`, ≤128 chars.
pub fn is_event_type_prefix(s: &str) -> bool {
    if s.len() > 128 {
        return false;
    }
    let mut segments = s.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    is_lower_alnum_head(first)
        && segments.all(|seg| {
            !seg.is_empty()
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// RFC 3339 `date-time` with semantic calendar validity (R0 KENV-05):
/// the schema pattern plus real month lengths and leap years.
pub fn is_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    if !(digit(0) && digit(1) && digit(2) && digit(3) && b[4] == b'-') {
        return false;
    }
    if !(digit(5) && digit(6) && b[7] == b'-' && digit(8) && digit(9) && b[10] == b'T') {
        return false;
    }
    if !(digit(11) && digit(12) && b[13] == b':' && digit(14) && digit(15) && b[16] == b':') {
        return false;
    }
    if !(digit(17) && digit(18)) {
        return false;
    }
    let num = |from: usize, to: usize| -> u32 { s[from..to].parse().unwrap_or(u32::MAX) };
    let (year, month, day) = (num(0, 4), num(5, 7), num(8, 10));
    let (hour, minute, second) = (num(11, 13), num(14, 16), num(17, 19));
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if leap {
                29
            } else {
                28
            }
        }
    };
    if day < 1 || day > days {
        return false;
    }
    // Fraction and offset.
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z') => i + 1 == b.len(),
        Some(b'+') | Some(b'-') => {
            if b.len() != i + 6 || b[i + 3] != b':' {
                return false;
            }
            let oh = num(i + 1, i + 3);
            let om = num(i + 4, i + 6);
            digit(i + 1) && digit(i + 2) && digit(i + 4) && digit(i + 5) && oh <= 23 && om <= 59
        }
        _ => false,
    }
}
