//! The alert list's Observable Pattern filter (PLAN.md decision 39): ace3's `saq/gui/observable_pattern.py`
//! and the pattern half of its `saq/gui/filter_query.py` (`c9114508`, `b525e575`).
//!
//! A pattern is an observable's value in which `*` matches anything. It must start or end with text, so
//! an index serves it: `observables_by_value_start`, on the first `INDEXED_CHARS` characters of the
//! value, when it starts with text (`https://evil.com/*`), and `observables_by_value_end`, on the last
//! ones reversed, when it starts with `*` and ends with text (`*.evil.com`). Both are migration 0081's. A
//! pattern with a wildcard at both ends (`*evil*`) has neither and would read every observable, so
//! `check_pattern` refuses it wherever a filter list comes in (`filters::check`). A `*` between two runs
//! of text (`evil.com*.net`) is a pattern that starts with text, as in ace3. `%`, `_` and `\` are
//! themselves: only `*` is a wildcard.
//!
//! A list reads it in two steps, as ace3's does. First each pattern's observables are looked up, the
//! distinct (type, value) pairs, at most `MAX_PATTERN_OBSERVABLES` and for at most
//! `PATTERN_LOOKUP_TIMEOUT`; then the list's query finds the alerts holding those pairs as the exact
//! Observable filter does, through `observables_one_per_value`. A pattern past either bound is refused,
//! never cut short, since a partial list of pairs would quietly leave alerts out: `ServiceError::
//! FilterRefused` with ace3's words. A refusal is remembered for `PATTERN_REFUSAL_TTL` in this process
//! (`Refusals`), because a pinned badge and an open list run their filters on every refresh, and a
//! lookup that ran to the time limit costs that much of the database each time. A pattern that was
//! looked up isn't remembered: a new observable can match it at any time.
//!
//! What differs from ace3: ace3's `observables` holds each (type, value) once and its 500 counts those
//! rows; here an observable is a row per alert, so the 500 counts distinct (type, value) pairs, which
//! is what ace3's rows are. The lookup's time covers reading every alert's copy of a matching value.
//! ace3 matches the value's stored bytes; here it is the stored text, so a suffix is reversed by
//! character rather than by byte, which is the same match.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::ServiceError;
use crate::filters::ANY_TYPE;

/// The wildcard: anything, including nothing.
pub const WILDCARD: char = '*';

/// ace3's `MAX_PATTERN_OBSERVABLES`: a pattern, or the patterns of one filter between them, matching
/// more distinct observables than this is refused. The list's query matches the pairs exactly, and its
/// cost grows with the alerts that hold them.
pub const MAX_PATTERN_OBSERVABLES: usize = 500;

/// ace3's `PATTERN_LOOKUP_TIMEOUT_MS`: how long one pattern's lookup may run, as Postgres's
/// `statement_timeout`. An anchored pattern is a range scan that takes milliseconds; this bounds one
/// that isn't selective, such as a pattern for a rare type that only a common type's values match.
pub const PATTERN_LOOKUP_TIMEOUT: &str = "1s";

/// ace3's `PATTERN_REFUSAL_TTL_SECONDS`: how long a refused pattern stays refused without a lookup.
pub const PATTERN_REFUSAL_TTL: Duration = Duration::from_secs(300);

/// How many characters of a value's start, and of its end, the two indexes hold (migration 0081),
/// ace3's `OBSERVABLE_VALUE_REV_LENGTH`. A longer run of text narrows the index's range by this many
/// characters and is checked against the whole value.
pub const INDEXED_CHARS: usize = 255;

/// Postgres's `query_canceled`, which a `statement_timeout` raises.
const QUERY_CANCELED: &str = "57014";

/// A pattern that starts with text: the index's range is the text's start, and the whole value is
/// checked. `$1` is the start's LIKE, `$2` the whole value's, `$3` the type or `''` for any, `$4` one
/// more than the bound. A plain statement, not a checked macro, so `tests/service.rs` explains this
/// exact text; its plan is the test's, `a_pattern_lookup_reads_its_index`.
pub const START_LOOKUP: &str = r#"SELECT DISTINCT o.type, o.value FROM analysis.observables o
WHERE left(o.value, 255) COLLATE "C" LIKE $1
  AND o.value LIKE $2
  AND ($3::text = '' OR o.type = $3::text)
LIMIT $4"#;

/// A pattern that starts with `*` and ends with text: the range is the end's text reversed. As
/// `START_LOOKUP`, with `$1` the reversed end's LIKE.
pub const END_LOOKUP: &str = r#"SELECT DISTINCT o.type, o.value FROM analysis.observables o
WHERE left(reverse(o.value), 255) COLLATE "C" LIKE $1
  AND o.value LIKE $2
  AND ($3::text = '' OR o.type = $3::text)
LIMIT $4"#;

/// The pattern without the whitespace around it, or ace3's reason why no index can serve it: it is
/// empty, only wildcards, or has a wildcard at both ends.
pub fn check_pattern(pattern: &str) -> Result<String, String> {
    let stripped = pattern.trim();
    if stripped.chars().all(|c| c == WILDCARD) {
        return Err(format!(
            "observable pattern {pattern:?} has no text to match"
        ));
    }
    if stripped.starts_with(WILDCARD) && stripped.ends_with(WILDCARD) {
        return Err(format!(
            "observable pattern {pattern:?} has a wildcard at both ends; it must start or end with text \
             (e.g. evil.com/* or *.evil.com)"
        ));
    }
    Ok(stripped.to_owned())
}

/// `text` for a LIKE whose escape is Postgres's default, the backslash: `\`, `%` and `_` stand for
/// themselves.
fn escape_like(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Which index a checked pattern reads, and the two LIKE patterns of its lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// True for `END_LOOKUP`, a pattern that starts with `*`.
    pub from_end: bool,
    /// The indexed expression's LIKE: the literal text at the anchored end, cut to `INDEXED_CHARS`
    /// (reversed for the end), escaped, then `%`.
    pub range: String,
    /// The whole value's LIKE: the literal text escaped, each `*` a `%`.
    pub whole: String,
}

/// The lookup of a pattern `check_pattern` let through.
pub fn lookup(pattern: &str) -> Lookup {
    let whole = pattern
        .split(WILDCARD)
        .map(escape_like)
        .collect::<Vec<_>>()
        .join("%");
    if pattern.starts_with(WILDCARD) {
        let end = pattern.rsplit(WILDCARD).next().unwrap_or_default();
        let reversed: String = end.chars().rev().take(INDEXED_CHARS).collect();
        Lookup {
            from_end: true,
            range: format!("{}%", escape_like(&reversed)),
            whole,
        }
    } else {
        let start = pattern.split(WILDCARD).next().unwrap_or_default();
        let start: String = start.chars().take(INDEXED_CHARS).collect();
        Lookup {
            from_end: false,
            range: format!("{}%", escape_like(&start)),
            whole,
        }
    }
}

/// ace3's `normalize_observable_pattern`: the pattern as its type would store it when that changes
/// nothing but its case, else as typed. A pattern is rarely a valid value of its type (`*.evil.com`
/// isn't a file's sha256), and then it is matched as typed; the match keeps case.
pub fn normalized(kind: &str, pattern: &str) -> String {
    if kind == ANY_TYPE {
        return pattern.to_owned();
    }
    match crate::observables::normalized(kind, pattern) {
        Ok((_, value)) if value.to_lowercase() == pattern.to_lowercase() => value,
        _ => pattern.to_owned(),
    }
}

/// The patterns refused for a bound, by (type, pattern), each with its reason and when that ends, for
/// this process: ace3's `_refused_patterns`.
#[derive(Debug, Default)]
pub(crate) struct Refusals {
    refused: Mutex<HashMap<(String, String), (String, Instant)>>,
}

impl Refusals {
    fn get(&self, key: &(String, String)) -> Option<String> {
        let refused = self.refused.lock().unwrap_or_else(|e| e.into_inner());
        refused
            .get(key)
            .filter(|(_, until)| *until > Instant::now())
            .map(|(reason, _)| reason.clone())
    }

    fn refuse(&self, key: (String, String), reason: String) -> ServiceError {
        let now = Instant::now();
        let mut refused = self.refused.lock().unwrap_or_else(|e| e.into_inner());
        refused.retain(|_, (_, until)| *until > now);
        refused.insert(key, (reason.clone(), now + PATTERN_REFUSAL_TTL));
        ServiceError::FilterRefused(reason)
    }
}

/// The distinct (type, value) pairs one filter's patterns match, as the list's two arrays, or
/// `FilterRefused`. `restore` is the statement that sets the transaction's own timeout back.
pub(crate) async fn matches(
    conn: &mut sqlx::PgConnection,
    refusals: &Refusals,
    patterns: &[(String, String)],
    restore: &'static str,
) -> Result<(Vec<String>, Vec<String>), ServiceError> {
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    for (kind, pattern) in patterns {
        found.extend(matched(conn, refusals, kind, pattern, restore).await?);
    }
    // each pattern is bounded, and so is their union, which is what the list's query matches
    if found.len() > MAX_PATTERN_OBSERVABLES {
        return Err(ServiceError::FilterRefused(format!(
            "these observable patterns match more than {MAX_PATTERN_OBSERVABLES} observables together; \
             make them more specific"
        )));
    }
    Ok(found.into_iter().unzip())
}

/// One pattern's pairs: ace3's `resolve_observable_pattern`.
async fn matched(
    conn: &mut sqlx::PgConnection,
    refusals: &Refusals,
    kind: &str,
    pattern: &str,
    restore: &'static str,
) -> Result<Vec<(String, String)>, ServiceError> {
    let pattern = normalized(
        kind,
        &check_pattern(pattern).map_err(ServiceError::FilterRefused)?,
    );
    let key = (kind.to_owned(), pattern.clone());
    if let Some(reason) = refusals.get(&key) {
        return Err(ServiceError::FilterRefused(reason));
    }
    let lookup = lookup(&pattern);
    let any = if kind == ANY_TYPE { "" } else { kind };
    let limit = i64::try_from(MAX_PATTERN_OBSERVABLES + 1).unwrap_or(i64::MAX);
    // the plan is made for these values, so the range is the pattern's own: a plan made once for
    // any value can't use either index
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "SET LOCAL plan_cache_mode = force_custom_plan; \
         SET LOCAL statement_timeout = '{PATTERN_LOOKUP_TIMEOUT}'"
    )))
    .execute(&mut *conn)
    .await?;
    let rows: Result<Vec<(String, String)>, sqlx::Error> = sqlx::query_as(if lookup.from_end {
        END_LOOKUP
    } else {
        START_LOOKUP
    })
    .bind(&lookup.range)
    .bind(&lookup.whole)
    .bind(any)
    .bind(limit)
    .fetch_all(&mut *conn)
    .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(error)
            if error
                .as_database_error()
                .and_then(|error| error.code())
                .is_some_and(|code| code == QUERY_CANCELED) =>
        {
            // the analyst is told why; this is for whoever tunes PATTERN_LOOKUP_TIMEOUT
            tracing::info!(
                observable_type = kind,
                observable_pattern = %pattern,
                "observable pattern lookup stopped at {PATTERN_LOOKUP_TIMEOUT}"
            );
            return Err(refusals.refuse(
                key,
                format!(
                    "observable pattern {kind}:{pattern} took too long to look up; make its text longer \
                     or pick a type"
                ),
            ));
        }
        Err(error) => return Err(error.into()),
    };
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "SET LOCAL plan_cache_mode = auto; {restore}"
    )))
    .execute(&mut *conn)
    .await?;
    if rows.len() > MAX_PATTERN_OBSERVABLES {
        return Err(refusals.refuse(
            key,
            format!(
                "observable pattern {kind}:{pattern} matches more than {MAX_PATTERN_OBSERVABLES} observables; \
                 make it more specific"
            ),
        ));
    }
    Ok(rows)
}
