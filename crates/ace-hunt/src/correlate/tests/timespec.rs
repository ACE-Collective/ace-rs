//! `test_timespec.py`: 7 cases.

use chrono::TimeDelta;

use crate::correlate::command::timespec;

/// TestParseTimespec.test_combined_units, four parameters.
#[test]
fn test_combined_units() {
    for (text, expected) in [
        ("8h30m30s", TimeDelta::seconds(8 * 3600 + 30 * 60 + 30)),
        ("1d12h", TimeDelta::hours(36)),
        ("1y2w3d", TimeDelta::days(365 + 14 + 3)),
        // days before years: the years add to the days already counted
        ("3d 1y", TimeDelta::days(3 + 365)),
    ] {
        assert_eq!(timespec(text), Ok(expected), "{text}");
    }
}

#[test]
fn test_whitespace_variants() {
    assert_eq!(timespec("  1h  30m  "), Ok(TimeDelta::minutes(90)));
}

#[test]
fn test_invalid_raises_value_error() {
    assert!(matches!(timespec("invalid"), Err(e) if e.starts_with("ValueError")));
}

#[test]
fn test_case_insensitive() {
    assert_eq!(timespec("1H30M"), Ok(TimeDelta::minutes(90)));
}
