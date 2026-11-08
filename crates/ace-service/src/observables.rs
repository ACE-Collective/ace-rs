//! An observable's prevalence across alerts (PLAN.md 5.5), ace3's `POST /api/v2/observables/lookup`: how
//! many alerts hold it, when it was first and last seen, their dispositions and the newest few. It needs
//! `observable:read`, as ace3's does.
//!
//! What differs from ace3:
//! - ace3 keeps one index of every observable it has seen, and normalizes a value by its type there. ace4
//!   looks in every alert's own observables, so a value matches as it's stored: a file's sha256 is
//!   lowercased, as `ace_results` writes it, and other values are matched exactly.
//! - ace3 counts only its default queue and leaves out `faqueue` alerts. ace4's roots have no queue or
//!   alert type yet, so every alert counts.
//! - ace3 lists the events each alert belongs to. Events come with 5.6's events router.
//! - Seen is when the root became an alert, where ace3's is when its alert row was inserted.
//!
//! `observable_types` is ace3's `GET /api/v2/observable-types/`, under the same permission: the types this
//! binary was built with (`ObservableKind::all`), a site's own among them (PLAN.md 2.31). ace3 reads its
//! YAML registry, which can change while it runs; ace4's list is fixed when the binary is built, so
//! there's nothing to reload or cache, and no database row adds a type, as in ace3.

use std::collections::BTreeMap;

use ace_results::{ObservableKind, Sha256};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::permission::OBSERVABLE_READ;
use crate::{Service, ServiceError};

/// ace3's limits.
pub const MAX_LOOKUP_PAIRS: usize = 1000;
pub const MAX_RECENT_ALERTS: u32 = 20;
pub const MAX_EXCLUDED_ALERTS: usize = 100;
/// The disposition counts' key for alerts nobody has dispositioned, as ace3 calls them.
pub const OPEN: &str = "OPEN";

/// What to look up: (type, value) pairs, and which alerts count.
#[derive(Debug, Clone, Default)]
pub struct Lookup {
    pub pairs: Vec<(String, String)>,
    /// How many of the newest alerts to list for each pair.
    pub recent: u32,
    /// Alerts to leave out, such as the caller's own.
    pub exclude: Vec<Uuid>,
    /// Only alerts that became alerts at or after this.
    pub since: Option<DateTime<Utc>>,
}

/// One pair's prevalence, at the pair's index in the request.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Prevalence {
    pub index: usize,
    pub kind: String,
    /// The value as it was matched, or None when the pair was refused.
    pub value: Option<String>,
    /// Why the pair couldn't be looked up, such as a type that doesn't exist.
    pub error: Option<String>,
    pub alerts: i64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    /// Alerts by disposition, `OPEN` for none, adding up to `alerts`.
    pub dispositions: BTreeMap<String, i64>,
    pub recent: Vec<RecentAlert>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecentAlert {
    pub id: Uuid,
    pub disposition: Option<String>,
    pub alerted_at: DateTime<Utc>,
}

/// The value a pair is matched as, or why it can't be.
pub(crate) fn normalized(kind: &str, value: &str) -> Result<(ObservableKind, String), String> {
    let kind: ObservableKind = kind.parse().map_err(|e| format!("{e}"))?;
    if value.is_empty() {
        return Err("an empty value".to_owned());
    }
    let value = if kind == ObservableKind::File {
        value
            .to_ascii_lowercase()
            .parse::<Sha256>()
            .map_err(|e| format!("a file is looked up by its sha256: {e}"))?
            .to_hex()
    } else {
        value.to_owned()
    };
    Ok((kind, value))
}

impl Service {
    /// This binary's observable types, in name order, deprecated ones included, as ace3 lists them.
    pub async fn observable_types(
        &self,
        actor: &crate::Actor,
    ) -> Result<&'static [ObservableKind], ServiceError> {
        self.gate
            .read(actor, "observable_types", &OBSERVABLE_READ, &|_tx| {
                Box::pin(async { Ok(ObservableKind::all()) })
            })
            .await
    }

    pub async fn lookup_observables(
        &self,
        actor: &crate::Actor,
        lookup: &Lookup,
    ) -> Result<Vec<Prevalence>, ServiceError> {
        if lookup.pairs.is_empty() || lookup.pairs.len() > MAX_LOOKUP_PAIRS {
            return Err(ServiceError::InvalidRequest(format!(
                "a lookup has 1 to {MAX_LOOKUP_PAIRS} pairs"
            )));
        }
        if lookup.recent > MAX_RECENT_ALERTS {
            return Err(ServiceError::InvalidRequest(format!(
                "a lookup lists at most {MAX_RECENT_ALERTS} recent alerts"
            )));
        }
        if lookup.exclude.len() > MAX_EXCLUDED_ALERTS {
            return Err(ServiceError::InvalidRequest(format!(
                "a lookup leaves out at most {MAX_EXCLUDED_ALERTS} alerts"
            )));
        }
        let mut results: Vec<Prevalence> = Vec::with_capacity(lookup.pairs.len());
        let (mut kinds, mut values, mut indexes) = (Vec::new(), Vec::new(), Vec::new());
        for (index, (kind, value)) in lookup.pairs.iter().enumerate() {
            let mut result = Prevalence {
                index,
                kind: kind.clone(),
                ..Prevalence::default()
            };
            match normalized(kind, value) {
                Ok((kind, value)) => {
                    result.kind = kind.as_str().to_owned();
                    result.value = Some(value.clone());
                    kinds.push(kind.as_str().to_owned());
                    values.push(value);
                    indexes.push(i64::try_from(index).unwrap_or(i64::MAX));
                }
                Err(why) => result.error = Some(why),
            }
            results.push(result);
        }
        let (kinds, values, indexes) = (&kinds, &values, &indexes);
        let recent = i64::from(lookup.recent);
        let (exclude, since) = (&lookup.exclude, lookup.since);
        let (counts, newest) = self
            .gate
            .read(actor, "lookup_observables", &OBSERVABLE_READ, &|tx| {
                Box::pin(async move {
                    let counts = sqlx::query!(
                        r#"SELECT w.n AS "n!", r.disposition, count(*) AS "alerts!",
                                  min(r.alerted_at) AS "first_seen!", max(r.alerted_at) AS "last_seen!"
                           FROM unnest($1::text[], $2::text[], $3::bigint[]) AS w(type, value, n)
                           JOIN analysis.observables o
                             ON o.type = w.type AND o.value_hash = analysis.value_hash(w.value)
                            AND o.value = w.value
                           JOIN analysis.roots r ON r.id = o.root_id
                           WHERE r.alerted_at IS NOT NULL AND r.id <> ALL ($4::uuid[])
                             AND ($5::timestamptz IS NULL OR r.alerted_at >= $5)
                           GROUP BY w.n, r.disposition"#,
                        kinds,
                        values,
                        indexes,
                        exclude,
                        since,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let newest = if recent == 0 {
                        Vec::new()
                    } else {
                        sqlx::query!(
                            r#"SELECT n AS "n!", id AS "id!", disposition, alerted_at AS "alerted_at!"
                               FROM (SELECT w.n, r.id, r.disposition, r.alerted_at,
                                            row_number() OVER (PARTITION BY w.n
                                                ORDER BY r.alerted_at DESC, r.id DESC) AS rank
                                     FROM unnest($1::text[], $2::text[], $3::bigint[]) AS w(type, value, n)
                                     JOIN analysis.observables o
                                       ON o.type = w.type AND o.value_hash = analysis.value_hash(w.value)
                                      AND o.value = w.value
                                     JOIN analysis.roots r ON r.id = o.root_id
                                     WHERE r.alerted_at IS NOT NULL AND r.id <> ALL ($4::uuid[])
                                       AND ($5::timestamptz IS NULL OR r.alerted_at >= $5)) ranked
                               WHERE rank <= $6
                               ORDER BY n, rank"#,
                            kinds,
                            values,
                            indexes,
                            exclude,
                            since,
                            recent,
                        )
                        .fetch_all(tx.conn())
                        .await?
                        .into_iter()
                        .map(|row| {
                            (
                                row.n,
                                RecentAlert {
                                    id: row.id,
                                    disposition: row.disposition,
                                    alerted_at: row.alerted_at,
                                },
                            )
                        })
                        .collect()
                    };
                    let counts: Vec<_> = counts
                        .into_iter()
                        .map(|row| {
                            (
                                row.n,
                                row.disposition,
                                row.alerts,
                                row.first_seen,
                                row.last_seen,
                            )
                        })
                        .collect();
                    Ok((counts, newest))
                })
            })
            .await?;
        let len = results.len();
        let at = move |n: i64| usize::try_from(n).ok().filter(|n| *n < len);
        for (n, disposition, alerts, first, last) in counts {
            let Some(i) = at(n) else { continue };
            let result = &mut results[i];
            result.alerts += alerts;
            result.first_seen = Some(result.first_seen.map_or(first, |seen| seen.min(first)));
            result.last_seen = Some(result.last_seen.map_or(last, |seen| seen.max(last)));
            *result
                .dispositions
                .entry(disposition.unwrap_or_else(|| OPEN.to_owned()))
                .or_default() += alerts;
        }
        for (n, alert) in newest {
            if let Some(i) = at(n) {
                results[i].recent.push(alert);
            }
        }
        Ok(results)
    }
}
