//! The archive's weekly partitions, as ace3's `ace partitions maintain` keeps its email archive's
//! (`ace3/saq/database/partitions.py`, `ace3/docs/DATABASE_PARTITIONS.md`), which the scheduler's
//! `email_archive_partitions` task runs daily.
//!
//! `archive`, ace3's `archived_messages`, has a partition an ISO week, `<table>_pYYYYwWW`, and a
//! default partition under them, `<table>_p_catchall`. For each table, maintenance:
//!
//! 1. drops each week every row of which is past the table's retention, which is a catalog change,
//!    not a delete;
//! 2. makes the weeks from the oldest still kept to `WEEKS_AHEAD` weeks ahead, so rows land in their
//!    week and never in the catchall.
//!
//! As ace3's rule has it, the catchall must stay empty: Postgres moves a new week's rows out of the
//! default partition when it makes the week, under a lock on the table. So a week the catchall holds
//! rows of isn't made, and the run says so and fails, as ace3's exits 1 when a table needs attention.
//! Every statement runs with a 5-second `lock_timeout`, so one that would wait behind a long
//! transaction gives up and the next run tries again.

use chrono::{DateTime, Datelike, Duration as ChronoDuration, NaiveDateTime, Utc};
use serde::Serialize;

use super::{ArchiveConfig, iso_week_start, week_of};
use crate::db::{Db, DbError};

/// How many weeks past this one are made ahead, as ace3's.
pub const WEEKS_AHEAD: i64 = 4;

/// The partitioned tables.
pub const TABLES: [&str; 1] = ["archive"];

/// What one run did to one table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TableMaintenance {
    pub table: String,
    pub dropped: Vec<String>,
    pub created: Vec<String>,
    /// What needs attention: a catchall holding rows, or a table busy past the lock timeout.
    pub problems: Vec<String>,
}

impl TableMaintenance {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// A week's partition name: its ISO year and week.
pub fn partition_name(table: &str, week_start: NaiveDateTime) -> String {
    let iso = week_start.date().iso_week();
    format!("{table}_p{}w{:02}", iso.year(), iso.week())
}

/// The week a partition name is, or None for the catchall and anything else.
fn week_of_name(table: &str, name: &str) -> Option<NaiveDateTime> {
    let rest = name.strip_prefix(table)?.strip_prefix("_p")?;
    let (year, week) = rest.split_once('w')?;
    iso_week_start(year.parse().ok()?, week.parse().ok()?)
}

/// Drops the weeks past retention and makes the ones to come, for each table, at `now`. With
/// `dry_run`, says what it would do and changes nothing.
pub async fn maintain(
    db: &Db,
    config: &ArchiveConfig,
    now: DateTime<Utc>,
    dry_run: bool,
) -> Result<Vec<TableMaintenance>, DbError> {
    let mut done = Vec::new();
    for table in TABLES {
        done.push(
            maintain_table(db, table, config.retention_days, now.naive_utc(), dry_run).await?,
        );
    }
    Ok(done)
}

async fn maintain_table(
    db: &Db,
    table: &str,
    retention_days: u32,
    now: NaiveDateTime,
    dry_run: bool,
) -> Result<TableMaintenance, DbError> {
    let mut done = TableMaintenance {
        table: format!("email_archive.{table}"),
        ..Default::default()
    };
    let existing: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i
         JOIN pg_class c ON c.oid = i.inhrelid
         WHERE i.inhparent = to_regclass($1)
         ORDER BY c.relname",
    )
    .bind(format!("email_archive.{table}"))
    .fetch_all(db.pool())
    .await?;
    let cutoff = now - ChronoDuration::days(i64::from(retention_days));

    for name in &existing {
        let Some(start) = week_of_name(table, name) else {
            continue;
        };
        let end = start + ChronoDuration::days(7);
        if end > cutoff {
            continue;
        }
        if !dry_run {
            let statement = format!("DROP TABLE email_archive.{name}");
            if let Err(problem) = ddl(db, statement).await? {
                done.problems.push(format!("{name}: {problem}"));
                continue;
            }
        }
        done.dropped.push(name.clone());
    }

    let (mut week, _) = week_of(cutoff);
    let (this_week, _) = week_of(now);
    let last = this_week + ChronoDuration::weeks(WEEKS_AHEAD);
    while week <= last {
        let name = partition_name(table, week);
        let end = week + ChronoDuration::days(7);
        if end > cutoff && !existing.contains(&name) {
            // the names are the constant tables', not input
            let held: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT EXISTS (SELECT 1 FROM email_archive.{table}_p_catchall
                                WHERE insert_date >= $1 AND insert_date < $2)"
            )))
            .bind(week)
            .bind(end)
            .fetch_one(db.pool())
            .await?;
            if held {
                done.problems.push(format!(
                    "{table}_p_catchall holds rows of the week {name} would hold, so it isn't made: \
                     move them into a week's partition by hand"
                ));
            } else if dry_run {
                done.created.push(name);
            } else {
                let statement = format!(
                    "CREATE TABLE email_archive.{name} PARTITION OF email_archive.{table} \
                     FOR VALUES FROM ('{week}') TO ('{end}')"
                );
                match ddl(db, statement).await? {
                    Ok(()) => done.created.push(name),
                    Err(problem) => done.problems.push(format!("{name}: {problem}")),
                }
            }
        }
        week = end;
    }
    Ok(done)
}

/// Runs one DDL statement with a short lock timeout. A timeout, or a statement Postgres refuses, is
/// a problem to report, not an error of the run. Its names are a constant table's and a partition
/// name made from one and a date, never input.
async fn ddl(db: &Db, statement: String) -> Result<Result<(), String>, DbError> {
    let mut tx = db.begin().await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(tx.conn())
        .await?;
    match sqlx::query(sqlx::AssertSqlSafe(statement))
        .execute(tx.conn())
        .await
    {
        Ok(_) => {
            tx.commit().await?;
            Ok(Ok(()))
        }
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("55P03") => {
            Ok(Err("table busy, will try again next run".to_owned()))
        }
        Err(sqlx::Error::Database(e)) => Ok(Err(e.message().to_owned())),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_week_is_named_by_its_iso_year_and_week() {
        let monday = iso_week_start(2026, 1).expect("a week");
        assert_eq!(monday.to_string(), "2025-12-29 00:00:00");
        assert_eq!(partition_name("archive", monday), "archive_p2026w01");
        assert_eq!(week_of_name("archive", "archive_p2026w01"), Some(monday));
        assert_eq!(week_of_name("archive", "archive_p_catchall"), None);
        assert_eq!(week_of_name("archive", "archive_index_p2026w01"), None);
    }
}
