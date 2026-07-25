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
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        // `date -u -d @1784161216` says 2026-07-16T00:20:16Z.
        assert_eq!(rfc3339_utc(1_784_161_216), "2026-07-16T00:20:16Z");
        assert!(crate::limits::is_timestamp(&rfc3339_utc(4_102_444_800)));
    }
}
