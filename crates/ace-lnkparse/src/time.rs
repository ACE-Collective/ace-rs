//! `parse_filetime` and `parse_dostime`: a FILETIME or a DOS date and time to an aware UTC
//! datetime, or `None` for zero or a value `datetime` refuses.

use crate::value::DateTime;

/// `datetime.fromtimestamp((filetime - 116444736000000000) / 10000000, tz=timezone.utc)`, or
/// `None` when the filetime is zero or the date is out of `datetime`'s range.
pub(crate) fn filetime(nanosec: i64) -> Option<DateTime> {
    if nanosec == 0 {
        return None;
    }
    let num = i128::from(nanosec) - 116_444_736_000_000_000;
    from_timestamp(int_div_to_f64(num, 10_000_000))
}

/// Python's `int / int`: the exact quotient rounded once to the nearest `f64`, ties to even.
fn int_div_to_f64(num: i128, den: u128) -> f64 {
    if num == 0 {
        return 0.0;
    }
    let n = num.unsigned_abs();
    // Scale so the quotient has well over 53 significant bits, then round it once.
    let scale = n.leading_zeros() - 1;
    let big = n << scale;
    let (q, r) = (big / den, big % den);
    let bits = 128 - q.leading_zeros();
    let shift = bits.saturating_sub(53);
    let mut mant = q >> shift;
    if shift > 0 {
        let rem = q & ((1u128 << shift) - 1);
        let half = 1u128 << (shift - 1);
        if rem > half || (rem == half && (r != 0 || mant & 1 == 1)) {
            mant += 1;
        }
    }
    // mant has at most 54 bits (2^53 after a carry), so it converts exactly.
    let exp = i64::from(shift) - i64::from(scale);
    #[allow(clippy::cast_precision_loss)]
    let v = mant as f64 * pow2(exp);
    if num < 0 { -v } else { v }
}

fn pow2(e: i64) -> f64 {
    // e stays well inside the normal range here.
    #[allow(clippy::cast_sign_loss)]
    f64::from_bits(((e + 1023) as u64) << 52)
}

fn round_half_even(x: f64) -> f64 {
    let r = x.round();
    if (x - r).abs() == 0.5 {
        2.0 * (x / 2.0).round()
    } else {
        r
    }
}

/// `datetime.fromtimestamp(t, tz=timezone.utc)`: CPython's `_PyTime_ObjectToTimeval` with
/// ROUND_HALF_EVEN, then `gmtime`, then the year check (1 to 9999).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn from_timestamp(t: f64) -> Option<DateTime> {
    let mut intpart = t.trunc();
    let mut frac = round_half_even((t - intpart) * 1e6);
    if frac >= 1e6 {
        frac -= 1e6;
        intpart += 1.0;
    } else if frac < 0.0 {
        frac += 1e6;
        intpart -= 1.0;
    }
    // |t| is below 1e12 here, so intpart fits an i64 exactly.
    let secs = intpart as i64;
    let us = frac as u32;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    if !(1..=9999).contains(&y) {
        return None;
    }
    Some(DateTime {
        year: y as u16,
        month: m,
        day: d,
        hour: (sod / 3600) as u8,
        minute: (sod / 60 % 60) as u8,
        second: (sod % 60) as u8,
        microsecond: us,
    })
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400) => 29,
        _ => 28,
    }
}

/// `parse_dostime`: `None` for zero or a date or time `datetime` refuses.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn dostime(dos: u32) -> Option<DateTime> {
    if dos == 0 {
        return None;
    }
    let year = ((dos & 0x0000_FE00) >> 9) + 1980;
    let month = (dos & 0x0000_01E0) >> 5;
    let day = dos & 0x0000_001F;
    let hour = (dos & 0xF800_0000) >> 27;
    let minute = (dos & 0x07E0_0000) >> 21;
    let second = ((dos & 0x001F_0000) >> 16) * 2;
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(DateTime {
        year: year as u16,
        month: month as u8,
        day: day as u8,
        hour: hour as u8,
        minute: minute as u8,
        second: second as u8,
        microsecond: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn division_is_correctly_rounded() {
        for (n, d) in [
            (1i128, 3u128),
            (-7, 2),
            (123_456_789_012_345_678, 10_000_000),
        ] {
            #[allow(clippy::cast_precision_loss)]
            let want = n as f64 / d as f64;
            assert_eq!(int_div_to_f64(n, d), want);
        }
        // Python 3.14: ((1 << 63) + 1234567) / 10**7 == 922337203685.6011
        let n = (1i128 << 63) + 1_234_567;
        assert_eq!(int_div_to_f64(n, 10_000_000), 922_337_203_685.601_1);
    }

    #[test]
    fn epoch_and_limits() {
        let d = filetime(116_444_736_000_000_000 + 10_000_005).unwrap();
        assert_eq!(d.ace3_format(), "1970-01-01T00:00:01.000001+0000");
        assert!(filetime(i64::MAX).is_none());
        assert_eq!(
            filetime(1).unwrap().ace3_format(),
            "1601-01-01T00:00:00.000000+0000"
        );
    }
}
