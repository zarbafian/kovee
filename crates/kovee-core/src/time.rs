//! RFC 3339 UTC timestamps from unix time — no chrono dependency; the
//! civil-from-days algorithm (Howard Hinnant's) over `SystemTime`.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current unix time in seconds (0 if the clock is before the epoch,
/// which only a broken clock reports).
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Formats unix seconds as an RFC 3339 UTC `date-time` (`…Z`), matching
/// the schema `timestamp` pattern.
pub fn rfc3339_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Parses an RFC 3339 UTC `date-time` back to unix seconds — the inverse
/// of [`rfc3339_utc`], and the reason it exists: an external record's
/// `expires_at` (a byom `ExecutionConsumptionReceipt`, say) has to be
/// compared against the clock before it is honored, and "unparseable"
/// must fail closed rather than read as "never expires".
///
/// Only the `Z` form is accepted, with an optional fractional part that is
/// truncated. An offset form, a bad calendar date, or an out-of-range field
/// returns `None`.
pub fn unix_from_rfc3339_utc(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    // The tail is either `Z` or `.<digits>Z`; an offset form is refused.
    let tail = text.get(19..)?;
    let tail = match tail.strip_prefix('.') {
        Some(rest) => {
            let digits = rest.trim_end_matches('Z');
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            &rest[digits.len()..]
        }
        None => tail,
    };
    if tail != "Z" {
        return None;
    }
    if !(1..=12).contains(&month) || day < 1 || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month as u32, day as u32)?;
    // A leap second (`:60`) is clamped to the minute's last representable
    // second rather than rejected.
    Some(days * 86_400 + hour * 3600 + minute * 60 + second.min(59))
}

/// Days since the unix epoch for a civil date, or `None` when the day is
/// out of range for the month (Howard Hinnant's algorithm, inverted).
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    let last = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => return None,
    };
    if d > last {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        // `date -u -d @1784161216` says 2026-07-16T00:20:16Z.
        assert_eq!(rfc3339_utc(1_784_161_216), "2026-07-16T00:20:16Z");
        assert!(crate::limits::is_timestamp(&rfc3339_utc(4_102_444_800)));
    }

    #[test]
    fn parsing_round_trips_the_formatter() {
        for t in [
            0,
            1_784_161_216,
            4_102_444_800,
            951_782_400, // 2000-02-29, a leap day
            1_709_164_800,
        ] {
            assert_eq!(
                unix_from_rfc3339_utc(&rfc3339_utc(t)),
                Some(t),
                "round trip {t}"
            );
        }
        // A fractional part is accepted and truncated.
        assert_eq!(
            unix_from_rfc3339_utc("2026-07-26T00:00:00.250Z"),
            Some(unix_from_rfc3339_utc("2026-07-26T00:00:00Z").unwrap())
        );
    }

    #[test]
    fn an_unparseable_timestamp_fails_closed() {
        for bad in [
            "",
            "2026-07-26",
            "2026-07-26T00:00:00",           // no zone
            "2026-07-26T00:00:00+02:00",     // offset form is refused
            "2026-13-01T00:00:00Z",          // month out of range
            "2026-02-30T00:00:00Z",          // day out of range for February
            "2025-02-29T00:00:00Z",          // not a leap year
            "2026-07-26T24:00:00Z",          // hour out of range
            "2026-07-26T00:60:00Z",          // minute out of range
            "20260726T000000Z",              // wrong separators
            "2026-07-26T00:00:00.Z",         // empty fraction
            "not-a-timestamp-at-all-really", // long enough, still nonsense
        ] {
            assert_eq!(unix_from_rfc3339_utc(bad), None, "{bad:?} must not parse");
        }
    }
}
