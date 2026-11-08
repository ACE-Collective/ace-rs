//! A query string read as pairs, for the routes whose filters repeat `f`, which axum's `Query` can't take.

use std::str::FromStr;

use ace_service::filters::timezone;
use axum::extract::RawQuery;
use chrono::{DateTime, NaiveDateTime, Utc};
use chrono_tz::Tz;

use crate::error::ApiError;

/// A query's pairs, in order.
pub(crate) struct Params(Vec<(String, String)>);

impl Params {
    pub(crate) fn of(RawQuery(raw): RawQuery) -> Result<Self, ApiError> {
        let pairs = serde_urlencoded::from_str(raw.as_deref().unwrap_or(""))
            .map_err(|e| ApiError::bad_request(format!("the query isn't one: {e}")))?;
        Ok(Params(pairs))
    }

    /// A parameter given at most once.
    pub(crate) fn one(&self, name: &str) -> Result<Option<&str>, ApiError> {
        let mut found = self.0.iter().filter(|(key, _)| key == name);
        let first = found.next().map(|(_, value)| value.as_str());
        if found.next().is_some() {
            return Err(ApiError::bad_request(format!("{name} is given twice")));
        }
        Ok(first)
    }

    /// Every value of a repeated parameter.
    pub(crate) fn all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .collect()
    }

    pub(crate) fn parsed<T: FromStr>(&self, name: &str, what: &str) -> Result<Option<T>, ApiError> {
        self.one(name)?
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| ApiError::bad_request(format!("{name} is {what}, not {value:?}")))
            })
            .transpose()
    }

    /// `tz`, UTC when it's left out.
    pub(crate) fn tz(&self) -> Result<Tz, ApiError> {
        Ok(match self.one("tz")? {
            Some(name) => timezone(name)?,
            None => Tz::UTC,
        })
    }

    /// A time as RFC 3339, or with no offset as UTC, as ace3's `changed_since` takes one.
    pub(crate) fn time(&self, name: &str) -> Result<Option<DateTime<Utc>>, ApiError> {
        self.one(name)?
            .map(|value| {
                DateTime::parse_from_rfc3339(value)
                    .map(|time| time.with_timezone(&Utc))
                    .or_else(|_| NaiveDateTime::from_str(value).map(|naive| naive.and_utc()))
                    .map_err(|_| {
                        ApiError::bad_request(format!(
                            "{name} is a time such as 2026-11-07T12:00:00Z, not {value:?}"
                        ))
                    })
            })
            .transpose()
    }
}
