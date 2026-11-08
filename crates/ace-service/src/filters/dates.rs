//! ace3's date range values (`saq/util/relative_time.py`), which the date filters take:
//!
//! - `01-15-2026 08:00 - 01-22-2026 08:00`, two absolute endpoints in `MM-DD-YYYY HH:MM`;
//! - `-7d - now`, two relative endpoints, or one of each;
//! - `-7d`, short for `-7d - now`.
//!
//! A relative endpoint is `now`, an offset (`-7d`, `+1w`, `-8h30m`), an offset with a snap (`-1d@d`), or a
//! snap alone (`@d`, the same as `now@d`). Units are `s`, `m`, `h`, `d`, `w` and `y` (365 days), and a snap
//! is one of those or `mon`. A token is stored as written and resolved on every read, so a saved `-24h`
//! keeps meaning the last day.
//!
//! As in ace3: an offset is real time, so across a DST change `-1d` is 24 hours; a snap floors the wall
//! clock in the viewer's timezone, toward the past, and `@w` is the Sunday before; an absolute endpoint is
//! that wall clock in the viewer's timezone. Where a wall clock occurs twice, a snap keeps the occurrence the
//! time it snapped was in and an absolute endpoint takes the later one, as pytz's `localize` does by
//! default; one that doesn't occur, in a gap, is read an hour on.

use chrono::{DateTime, Datelike, Duration, LocalResult, NaiveDateTime, TimeZone, Timelike, Utc};
use chrono_tz::Tz;

/// The format of an absolute endpoint, ace3's `ABSOLUTE_DATE_FORMAT`.
const ABSOLUTE: &str = "%m-%d-%Y %H:%M";

/// The most digits one offset's number may have, so the sum can't overflow.
const MAX_DIGITS: usize = 9;

/// The window a value names at `now`, in UTC, as (start, end). A single token is bounded by now, in whichever
/// order puts the earlier first, so `+1d` is the next day.
pub(crate) fn window(
    value: &str,
    now: DateTime<Utc>,
    tz: Tz,
) -> Result<(DateTime<Utc>, DateTime<Utc>), String> {
    let parts: Vec<&str> = value.split(" - ").collect();
    match parts.as_slice() {
        [one] => {
            let resolved = endpoint(one, now, tz)?;
            Ok(if resolved <= now {
                (resolved, now)
            } else {
                (now, resolved)
            })
        }
        [start, end] => Ok((endpoint(start, now, tz)?, endpoint(end, now, tz)?)),
        _ => Err(format!(
            "{value:?} isn't '<start> - <end>' or a single relative time"
        )),
    }
}

fn endpoint(token: &str, now: DateTime<Utc>, tz: Tz) -> Result<DateTime<Utc>, String> {
    let token = token.trim();
    if let Some(relative) = Relative::parse(token) {
        return relative.resolve(now, tz);
    }
    let naive = NaiveDateTime::parse_from_str(token, ABSOLUTE).map_err(|_| {
        format!("{token:?} isn't a date as MM-DD-YYYY HH:MM or a relative time such as -7d")
    })?;
    local(tz, naive, None).ok_or_else(|| format!("{token:?} is out of range"))
}

/// A wall clock in `tz`: where it occurs twice, the occurrence with `offset` when one has it, else the later;
/// where it doesn't occur, an hour on.
fn local(
    tz: Tz,
    naive: NaiveDateTime,
    offset: Option<chrono::FixedOffset>,
) -> Option<DateTime<Utc>> {
    use chrono::Offset;
    match tz.from_local_datetime(&naive) {
        LocalResult::Single(time) => Some(time.with_timezone(&Utc)),
        LocalResult::Ambiguous(early, late) => {
            let kept = match offset {
                Some(offset) if early.offset().fix() == offset => early,
                _ => late,
            };
            Some(kept.with_timezone(&Utc))
        }
        LocalResult::None => tz
            .from_local_datetime(&(naive + Duration::hours(1)))
            .earliest()
            .map(|time| time.with_timezone(&Utc)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Snap {
    Second,
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

/// A relative endpoint: an offset in seconds, signed, and a snap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Relative {
    seconds: i64,
    snap: Option<Snap>,
}

impl Relative {
    /// The token as a relative time, or None for anything else, ace3's anchored pattern.
    fn parse(token: &str) -> Option<Self> {
        let token = token.to_ascii_lowercase();
        let (base, snap) = match token.split_once('@') {
            Some((base, snap)) => (base, Some(snap)),
            None => (token.as_str(), None),
        };
        let snap = match snap {
            None => None,
            Some("s") => Some(Snap::Second),
            Some("m") => Some(Snap::Minute),
            Some("h") => Some(Snap::Hour),
            Some("d") => Some(Snap::Day),
            Some("w") => Some(Snap::Week),
            Some("mon") => Some(Snap::Month),
            Some("y") => Some(Snap::Year),
            Some(_) => return None,
        };
        let seconds = match base {
            "" if snap.is_some() => 0,
            "now" => 0,
            _ => {
                let (sign, magnitude) = match base.as_bytes().first() {
                    Some(b'-') => (-1, &base[1..]),
                    Some(b'+') => (1, &base[1..]),
                    _ => return None,
                };
                sign * magnitude_seconds(magnitude)?
            }
        };
        Some(Relative { seconds, snap })
    }

    fn resolve(self, now: DateTime<Utc>, tz: Tz) -> Result<DateTime<Utc>, String> {
        let out_of_range = || "a relative time out of range".to_owned();
        let shifted = now
            .checked_add_signed(Duration::try_seconds(self.seconds).ok_or_else(out_of_range)?)
            .ok_or_else(out_of_range)?;
        let Some(snap) = self.snap else {
            return Ok(shifted);
        };
        let wall = shifted.with_timezone(&tz);
        let offset = {
            use chrono::Offset;
            wall.offset().fix()
        };
        let naive = wall.naive_local();
        let date = naive.date();
        let floor = match snap {
            Snap::Second => naive.with_nanosecond(0),
            Snap::Minute => naive.with_nanosecond(0).and_then(|t| t.with_second(0)),
            Snap::Hour => date.and_hms_opt(naive.hour(), 0, 0),
            Snap::Day => date.and_hms_opt(0, 0, 0),
            Snap::Week => {
                let back = i64::from(date.weekday().num_days_from_sunday());
                (date - Duration::days(back)).and_hms_opt(0, 0, 0)
            }
            Snap::Month => date.with_day(1).and_then(|d| d.and_hms_opt(0, 0, 0)),
            Snap::Year => date
                .with_day(1)
                .and_then(|d| d.with_month(1))
                .and_then(|d| d.and_hms_opt(0, 0, 0)),
        }
        .ok_or_else(out_of_range)?;
        local(tz, floor, Some(offset)).ok_or_else(out_of_range)
    }
}

/// `8h30m`, `1d 12h`: components of digits and a unit, with spaces between them allowed, in seconds.
fn magnitude_seconds(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let mut at = 0;
    let mut total: i64 = 0;
    let mut components = 0;
    while at < bytes.len() {
        if components > 0 {
            while at < bytes.len() && bytes[at] == b' ' {
                at += 1;
            }
        }
        let digits = bytes[at..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if digits == 0 || digits > MAX_DIGITS {
            return None;
        }
        let count: i64 = text[at..at + digits].parse().ok()?;
        at += digits;
        while at < bytes.len() && bytes[at] == b' ' {
            at += 1;
        }
        let unit = match bytes.get(at)? {
            b's' => 1,
            b'm' => 60,
            b'h' => 3600,
            b'd' => 86_400,
            b'w' => 604_800,
            b'y' => 365 * 86_400,
            _ => return None,
        };
        at += 1;
        total = total.checked_add(count.checked_mul(unit)?)?;
        components += 1;
    }
    (components > 0).then_some(total)
}
