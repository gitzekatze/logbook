//! Canonical event times (F-A08): UTC, exactly 6 decimal places, so the text
//! order is the time order.

/// Microseconds since 1970-01-01 of 9999-12-31T23:59:59.999999Z.
const LAST_MICROS: i64 = 253_402_300_799_999_999;

/// The canonical text for a time given in microseconds since 1970-01-01 UTC,
/// such as `2026-11-23T22:45:21.721966Z`. `None` before 1970 or after 9999.
pub fn utc_time(unix_micros: i64) -> Option<String> {
    if !(0..=LAST_MICROS).contains(&unix_micros) {
        return None;
    }
    let secs = unix_micros.div_euclid(1_000_000);
    let micros = unix_micros.rem_euclid(1_000_000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        s / 3600,
        s % 3600 / 60,
        s % 60
    ))
}

/// Whether `text` is a canonical time with a real calendar date and clock time.
pub fn is_canonical_time(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() != 27 {
        return false;
    }
    let shape = b.iter().enumerate().all(|(i, &c)| match i {
        4 | 7 => c == b'-',
        10 => c == b'T',
        13 | 16 => c == b':',
        19 => c == b'.',
        26 => c == b'Z',
        _ => c.is_ascii_digit(),
    });
    if !shape {
        return false;
    }
    let num = |from: usize, to: usize| {
        b[from..to]
            .iter()
            .fold(0u32, |n, &c| n * 10 + u32::from(c - b'0'))
    };
    let (year, month, day) = (num(0, 4), num(5, 7), num(8, 10));
    (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day)
        && num(11, 13) < 24
        && num(14, 16) < 60
        && num(17, 19) < 60
}

fn days_in_month(year: u32, month: u32) -> u32 {
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Year, month and day of a day number since 1970-01-01 (Howard Hinnant's
/// civil_from_days algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dates across four centuries, including leap days of every kind,
    /// against reference values (Python's datetime).
    #[test]
    fn utc_time_matches_reference_dates() {
        for (micros, want) in [
            (49_062_000_123, "1970-01-01T13:37:42.000123Z"),
            (946_647_462_000_123, "1999-12-31T13:37:42.000123Z"),
            (951_831_462_000_123, "2000-02-29T13:37:42.000123Z"),
            (951_917_862_000_123, "2000-03-01T13:37:42.000123Z"),
            (1_078_061_862_000_123, "2004-02-29T13:37:42.000123Z"),
            (1_677_677_862_000_123, "2023-03-01T13:37:42.000123Z"),
            (1_709_213_862_000_123, "2024-02-29T13:37:42.000123Z"),
            (4_107_505_062_000_123, "2100-02-28T13:37:42.000123Z"),
            (4_107_591_462_000_123, "2100-03-01T13:37:42.000123Z"),
            (13_574_612_262_000_123, "2400-02-29T13:37:42.000123Z"),
            (13_574_698_662_000_123, "2400-03-01T13:37:42.000123Z"),
            (253_402_263_462_000_123, "9999-12-31T13:37:42.000123Z"),
        ] {
            assert_eq!(utc_time(micros).as_deref(), Some(want));
            assert!(is_canonical_time(want), "{want}");
        }
    }

    /// The exact limits of every part: the last valid value passes, the
    /// first invalid one doesn't.
    #[test]
    fn canonical_time_limits() {
        for ok in [
            "2026-01-31T23:59:59.999999Z",
            "2024-02-29T00:00:00.000000Z",
            "2000-02-29T00:00:00.000000Z",
            "2026-04-30T00:00:00.000000Z",
            "2026-12-31T00:00:00.000000Z",
        ] {
            assert!(is_canonical_time(ok), "{ok} must pass");
        }
        for bad in [
            "2026-01-01T24:00:00.000000Z",
            "2026-01-01T23:60:00.000000Z",
            "2026-01-01T23:59:60.000000Z",
            "2026-04-31T00:00:00.000000Z",
            "2026-06-31T00:00:00.000000Z",
            "2026-09-31T00:00:00.000000Z",
            "2026-11-31T00:00:00.000000Z",
            "2026-01-32T00:00:00.000000Z",
            "2026-02-29T00:00:00.000000Z",
            "2100-02-29T00:00:00.000000Z",
            "2026-00-10T00:00:00.000000Z",
            "2026-01-00T00:00:00.000000Z",
        ] {
            assert!(!is_canonical_time(bad), "{bad} must fail");
        }
    }
}
