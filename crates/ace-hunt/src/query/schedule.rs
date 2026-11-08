//! When a query hunt runs and what it searches: ace3's `Hunt.ready`, `next_execution_time`,
//! `suppressed` and the per-group suppression of `base_hunter.py`, `QueryHunt`'s `start_time`,
//! `end_time` and `execute` (`query_hunter.py`), and what `HuntManager.execute_threaded_hunt`
//! records after a run (`manager.py`).
//!
//! ace3 keeps a hunt's state as pickles under its data directory; here it's a [`State`], which the
//! hunter keeps in Postgres. Every function takes the time, so a run reads the clock once.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{HuntConfig, is_timedelta_string};

/// What ace3 persists about a hunt between runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub last_executed_time: Option<DateTime<Utc>>,
    /// The end of the last window searched, which a full coverage hunt starts its next one at.
    pub last_end_time: Option<DateTime<Utc>>,
    /// When an ungrouped hunt last alerted.
    pub last_alert_time: Option<DateTime<Utc>>,
    /// When each group of a grouped hunt with a suppression last alerted, by its suppression key.
    pub last_alert_times: BTreeMap<String, DateTime<Utc>>,
}

/// ace3's `create_timedelta`: `DD:HH:MM:SS`, read from the right.
pub fn timedelta(text: &str) -> Result<TimeDelta, String> {
    let parts: Vec<&str> = text.split(':').collect();
    let number = |part: &str| -> Result<i64, String> {
        part.trim()
            .parse::<i64>()
            .map_err(|_| format!("invalid literal for int() with base 10: {part:?}"))
    };
    let mut seconds = 0i64;
    for (part, unit) in parts.iter().rev().zip([1i64, 60, 3600, 86400]) {
        seconds = seconds.saturating_add(number(part)?.saturating_mul(unit));
    }
    TimeDelta::try_seconds(seconds).ok_or_else(|| format!("{text:?} is too long"))
}

/// Python's `str(timedelta)`: `0:10:00`, `1 day, 2:00:00`, `-1 day, 23:59:00`.
pub fn timedelta_str(delta: TimeDelta) -> String {
    let total = delta.num_seconds();
    let days = total.div_euclid(86400);
    let rest = total.rem_euclid(86400);
    let clock = format!("{}:{:02}:{:02}", rest / 3600, rest % 3600 / 60, rest % 60);
    match days {
        0 => clock,
        1 | -1 => format!("{days} day, {clock}"),
        _ => format!("{days} days, {clock}"),
    }
}

fn optional(text: Option<&str>) -> Option<TimeDelta> {
    text.filter(|t| !t.is_empty())
        .and_then(|t| timedelta(t).ok())
}

/// The frequency, when it's a timedelta rather than a cron schedule.
pub fn frequency(config: &HuntConfig) -> Option<TimeDelta> {
    if config.frequency.is_empty() || !is_timedelta_string(&config.frequency) {
        return None;
    }
    timedelta(config.frequency.trim_end_matches('\n')).ok()
}

pub fn suppression(config: &HuntConfig) -> Option<TimeDelta> {
    optional(config.suppression.as_deref())
}

/// `QueryHunt.time_range`: `time_ranges.TIMESPEC` when there is one, then `time_range`.
pub fn time_range(config: &HuntConfig) -> Option<TimeDelta> {
    if let Some(ranges) = &config.time_ranges
        && let Some((_, range)) = ranges.iter().find(|(name, _)| name == "TIMESPEC")
    {
        return range
            .duration_before
            .as_deref()
            .and_then(|t| timedelta(t).ok());
    }
    optional(config.time_range.as_deref())
}

/// Whether an ungrouped hunt is suppressed: it alerted less than `suppression` ago. A grouped
/// hunt is suppressed per group instead, so never as a whole.
pub fn suppressed(config: &HuntConfig, state: &State, now: DateTime<Utc>) -> bool {
    suppression_end(config, state, now).is_some()
}

pub fn suppression_end(
    config: &HuntConfig,
    state: &State,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if config.group_by.is_some() {
        return None;
    }
    let end = state.last_alert_time? + suppression(config)?;
    (now < end).then_some(end)
}

/// `Hunt.next_execution_time`.
pub fn next_execution_time(
    config: &HuntConfig,
    state: &State,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, String> {
    if let Some(end) = suppression_end(config, state, now) {
        return Ok(end);
    }
    if let Some(frequency) = frequency(config) {
        return Ok(match state.last_executed_time {
            None => now - frequency,
            Some(last) => last + frequency,
        });
    }
    if !config.frequency.is_empty() {
        let cron = croner::parser::CronParser::new()
            .parse(&config.frequency)
            .map_err(|e| format!("hunt {} has a bad cron schedule: {e}", config.name))?;
        let from = state.last_executed_time.unwrap_or(now);
        return cron
            .find_next_occurrence(&from, false)
            .map_err(|e| format!("hunt {} has a bad cron schedule: {e}", config.name));
    }
    Err(format!(
        "hunt {} has an invalid frequency or cron schedule",
        config.name
    ))
}

/// `QueryHunt.ready`: never run, or past its next execution time. ace3's manager checks
/// `suppressed` first, and skips a suppressed hunt before asking.
pub fn ready(config: &HuntConfig, state: &State, now: DateTime<Utc>) -> Result<bool, String> {
    if state.last_executed_time.is_none() {
        return Ok(true);
    }
    Ok(now >= next_execution_time(config, state, now)?)
}

/// What a run searches: the window it records as covered, and the window it queries, which is
/// that one moved back by `offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub target_start: DateTime<Utc>,
    pub target_end: DateTime<Utc>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// `QueryHunt.start_time`, `end_time` and `execute`'s offset.
pub fn window(config: &HuntConfig, state: &State, now: DateTime<Utc>) -> Result<Window, String> {
    let range =
        time_range(config).ok_or_else(|| format!("hunt {} has no time range", config.name))?;
    let max = optional(config.max_time_range.as_deref());
    let (start, end) = match (config.full_coverage, state.last_end_time) {
        (true, Some(last)) => {
            let normal_end = last + range;
            let end = if normal_end >= now {
                now
            } else {
                match max {
                    Some(max) if last + max < now => last + max,
                    _ => now,
                }
            };
            (last, end)
        }
        _ => (now - range, now),
    };
    let offset = optional(config.offset.as_deref()).unwrap_or_default();
    Ok(Window {
        target_start: start,
        target_end: end,
        start: start - offset,
        end: end - offset,
    })
}

/// Whether a group's alerts are suppressed: it alerted less than `suppression` ago.
pub fn group_suppressed(config: &HuntConfig, state: &State, key: &str, now: DateTime<Utc>) -> bool {
    group_suppression(config, state, key, now).is_some()
}

/// The window a group's suppression drops its alerts in, when `now` is in it: from when it last
/// alerted to `suppression` after.
pub fn group_suppression(
    config: &HuntConfig,
    state: &State,
    key: &str,
    now: DateTime<Utc>,
) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let suppression = suppression(config)?;
    let last = *state.last_alert_times.get(key)?;
    (now < last + suppression).then_some((last, last + suppression))
}

/// How a run ended, for [`record_run`].
pub enum Ran<'a> {
    /// The search returned rows, and these are the suppression keys of the submissions the run
    /// made, None for one that has none.
    Searched { submitted: &'a [Option<String>] },
    /// The search failed or was cancelled, so the window wasn't covered.
    Failed,
}

/// What ace3 records after a run: `execute`'s last end time when the search returned,
/// `execute_with_lock`'s last executed time, and the manager's alert times, pruning a grouped
/// hunt's expired ones.
pub fn record_run(
    config: &HuntConfig,
    state: &mut State,
    window: &Window,
    ran: &Ran<'_>,
    now: DateTime<Utc>,
) {
    state.last_executed_time = Some(now);
    let mut submitted: &[Option<String>] = &[];
    if let Ran::Searched { submitted: s } = ran {
        state.last_end_time = Some(window.target_end);
        submitted = s;
    }
    let suppression = suppression(config);
    if !submitted.is_empty() {
        if config.group_by.is_none() {
            state.last_alert_time = Some(now);
        } else if suppression.is_some() {
            for key in submitted.iter().flatten() {
                state.last_alert_times.insert(key.clone(), now);
            }
        }
    }
    if config.group_by.is_some() {
        match suppression {
            Some(suppression) => state
                .last_alert_times
                .retain(|_, last| now < *last + suppression),
            None => state.last_alert_times.clear(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timedeltas_read_and_print_as_python_s() {
        assert_eq!(timedelta("00:10:00"), Ok(TimeDelta::minutes(10)));
        assert_eq!(timedelta("30"), Ok(TimeDelta::seconds(30)));
        assert_eq!(timedelta("01:00:00:00"), Ok(TimeDelta::days(1)));
        assert!(timedelta("x").is_err());
        assert_eq!(timedelta_str(TimeDelta::minutes(10)), "0:10:00");
        assert_eq!(timedelta_str(TimeDelta::hours(26)), "1 day, 2:00:00");
        assert_eq!(timedelta_str(TimeDelta::days(3)), "3 days, 0:00:00");
        assert_eq!(timedelta_str(TimeDelta::minutes(-1)), "-1 day, 23:59:00");
    }
}
