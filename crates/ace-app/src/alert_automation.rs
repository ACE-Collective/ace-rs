//! `ace alert-automation`: what alert automation's rules did (PLAN.md 7.22), ace3's
//! `saq/cli/commands/alert_automation.py`. `list` prints the most recent runs, newest first, as a table
//! or with `--json` as JSON; `report --rule NAME` compares the rule's dry runs with how each alert was
//! dispositioned since, which is how a dry run is read before a rule is put in enforce.
//!
//! They read Postgres through the service (`ace_service`'s `alert_automation_report`) as the scheduler's
//! component `scheduler:alert_automation`, which holds `alert_automation:run`, so they run where `ace
//! serve` does, with `ACE_RS_DATABASE_URL`. The output is ace3's, column for column. What differs: a
//! `--since` is a UTC date or date and time as ace3's, also taken with a `Z` or an offset; `--limit` is 1
//! to `ace_service::MAX_LISTED_RUNS`; the JSON names the alert `alert_uuid` and the time `insert_date`,
//! as ace3's, from ace-rs's `root_id` and `created_at`.

use std::fmt::Write as _;
use std::process::ExitCode;

use ace_core::db::{Db, DbConfig};
use ace_sdk::alert_automation::Mode;
use ace_service::{Actor, AutomationRun, Component, DryRunReport, RunsQuery, Service};
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use clap::{Subcommand, ValueEnum};
use serde_json::json;

#[derive(Subcommand)]
pub enum AlertAutomationCommand {
    /// List alert automation runs, newest first.
    List {
        /// Only runs of this rule.
        #[arg(long)]
        rule: Option<String>,
        /// Only runs in this mode.
        #[arg(long, value_enum)]
        mode: Option<RunMode>,
        /// Only runs recorded at or after this UTC date (YYYY-MM-DD[THH:MM:SS]).
        #[arg(long, value_parser = since)]
        since: Option<DateTime<Utc>>,
        /// Most runs to list.
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Compare a rule's dry-run decisions with how analysts dispositioned the alerts.
    Report {
        /// The rule to report on.
        #[arg(long)]
        rule: String,
        /// Only dry runs recorded at or after this UTC date (YYYY-MM-DD[THH:MM:SS]).
        #[arg(long, value_parser = since)]
        since: Option<DateTime<Utc>>,
    },
}

/// A rule's mode, as `--mode` takes it.
#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum RunMode {
    DryRun,
    Enforce,
}

/// ace3's `_since`: a date, or a date and time, in UTC; an RFC 3339 time with its offset too.
fn since(text: &str) -> Result<DateTime<Utc>, String> {
    if let Ok(at) = DateTime::parse_from_rfc3339(text) {
        return Ok(at.with_timezone(&Utc));
    }
    if let Ok(at) = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S") {
        return Ok(at.and_utc());
    }
    if let Ok(at) = NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S") {
        return Ok(at.and_utc());
    }
    NaiveDate::parse_from_str(text, "%Y-%m-%d")
        .map(|day| day.and_hms_opt(0, 0, 0).expect("midnight").and_utc())
        .map_err(|_| format!("{text:?} isn't a date: use YYYY-MM-DD[THH:MM:SS], in UTC"))
}

/// The component the commands read as: the sweep's own, which holds `alert_automation:run`.
fn actor() -> Result<Actor> {
    Ok(Actor::Internal {
        id: Component::new("scheduler:alert_automation").map_err(anyhow::Error::msg)?,
    })
}

/// What `list` prints.
pub async fn list(service: &Service, query: &RunsQuery, as_json: bool) -> Result<String> {
    let runs = service.alert_automation_runs(&actor()?, query).await?;
    if as_json {
        let runs: Vec<_> = runs.iter().map(run_json).collect();
        return Ok(format!("{}\n", serde_json::to_string_pretty(&runs)?));
    }
    if runs.is_empty() {
        return Ok("no alert automation runs\n".to_owned());
    }
    let mut out = format!(
        "{:<19}  {:<24} {:<8} {:<8} {:<36}  ACTIONS\n",
        "INSERTED", "RULE", "MODE", "STATUS", "ALERT"
    );
    for run in &runs {
        let actions = run
            .actions
            .iter()
            .map(|action| {
                let status = serde_json::to_value(action.status).unwrap_or_default();
                format!("{}={}", action.kind, status.as_str().unwrap_or_default())
            })
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            out,
            "{:<19}  {:<24} {:<8} {:<8} {:<36}  {actions}",
            run.created_at.format("%Y-%m-%d %H:%M:%S"),
            run.rule,
            run.mode,
            run.status,
            run.alert.to_string(),
        )?;
    }
    Ok(out)
}

fn run_json(run: &AutomationRun) -> serde_json::Value {
    json!({
        "id": run.id,
        "rule": run.rule,
        "alert_uuid": run.alert,
        "mode": run.mode,
        "status": run.status,
        "insert_date": run.created_at,
        "evidence": run.evidence,
        "actions": run.actions,
    })
}

/// What `report` prints.
pub async fn report(service: &Service, rule: &str, since: Option<DateTime<Utc>>) -> Result<String> {
    let report = service
        .alert_automation_report(&actor()?, rule, since)
        .await?;
    Ok(report_text(&report))
}

fn report_text(report: &DryRunReport) -> String {
    let mut out = format!("rule {}: {} dry runs\n", report.rule, report.runs);
    for (label, count) in [
        ("analysts dispositioned the same way: ", report.same),
        (
            "analysts dispositioned differently:  ",
            u64::try_from(report.different.len()).unwrap_or(u64::MAX),
        ),
        ("still open:                          ", report.still_open),
        ("dispositioned by ACE:                ", report.automated),
        ("alert deleted:                       ", report.missing),
        ("no disposition decided:              ", report.undecided),
    ] {
        out.push_str(&format!("  {label}{count}\n"));
    }
    if !report.different.is_empty() {
        out.push('\n');
        out.push_str(&format!("{:<36}  {:<20} ANALYST\n", "ALERT", "DRY RUN"));
        for (alert, decided, actual) in &report.different {
            out.push_str(&format!(
                "{:<36}  {decided:<20} {actual}\n",
                alert.to_string()
            ));
        }
    }
    out
}

pub fn run(command: AlertAutomationCommand) -> Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async {
        let db = Db::connect(&DbConfig::from_env("ace")?)
            .await
            .context("connecting to Postgres")?;
        // it reads the runs table alone, so the service needs no modules
        let service = Service::new(
            db,
            ace_core::orchestrator::Orchestrator::new(
                ace_core::eligibility::Catalog::new(vec![]),
                ace_core::modes::Modes::ace3(),
            ),
        );
        let out = match command {
            AlertAutomationCommand::List {
                rule,
                mode,
                since,
                limit,
                json,
            } => {
                let query = RunsQuery {
                    rule,
                    mode: mode.map(|mode| match mode {
                        RunMode::DryRun => Mode::DryRun,
                        RunMode::Enforce => Mode::Enforce,
                    }),
                    since,
                    limit,
                };
                list(&service, &query, json).await?
            }
            AlertAutomationCommand::Report { rule, since } => {
                report(&service, &rule, since).await?
            }
        };
        print!("{out}");
        Ok(ExitCode::SUCCESS)
    })
}

#[cfg(test)]
mod tests {
    //! ace3 `c55f15a2`'s `tests/saq/alert_automation/test_cli.py` (4), each by its name. The runs are
    //! rows as the sweep writes them (`ace_service`'s alert automation tests check the sweep writes them
    //! so), set up directly so each case has the alerts ace3's has.
    use super::*;
    use ace_core::testing::TestDb;
    use serde_json::Value;
    use uuid::Uuid;

    const RULE: &str = "confirmed_removal";

    fn service(db: &Db) -> Service {
        Service::new(
            db.clone(),
            ace_core::orchestrator::Orchestrator::new(
                ace_core::eligibility::Catalog::new(vec![]),
                ace_core::modes::Modes::ace3(),
            ),
        )
    }

    /// An alert, with its disposition and who set it: a user, or one of ACE's components.
    async fn alert(db: &Db, disposition: Option<(&str, bool)>) -> Uuid {
        let root = ace_core::tree::NewRoot::new("correlation");
        let mut tx = db.begin().await.expect("begins");
        ace_core::tree::create_root(&mut tx, &root)
            .await
            .expect("creates");
        tx.commit().await.expect("commits");
        sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
            .bind(root.id)
            .execute(db.pool())
            .await
            .expect("an alert");
        if let Some((disposition, by_ace)) = disposition {
            let by = if by_ace {
                json!({"kind": "internal", "id": "scheduler:alert_automation"})
            } else {
                json!({"kind": "user", "id": Uuid::from_u128(7), "name": "analyst"})
            };
            sqlx::query(
                "UPDATE analysis.roots SET disposition = $2, dispositioned_at = now(),
                                           dispositioned_by = $3
                 WHERE id = $1",
            )
            .bind(root.id)
            .bind(disposition)
            .bind(by)
            .execute(db.pool())
            .await
            .expect("dispositions");
        }
        root.id
    }

    fn done(kind: &str, detail: Value) -> Value {
        json!({"type": kind, "status": "done", "attempts": 1, "detail": detail, "reason": null})
    }

    /// ace3's `ACTIONS` as a run records them: the disposition DELIVERY, then the removal.
    fn delivered() -> Value {
        json!([
            done(
                "disposition",
                json!({"disposition": "DELIVERY", "comment": "confirmed"})
            ),
            done("remediate", json!({"queued": []})),
        ])
    }

    async fn run_of(db: &Db, root: Uuid, mode: &str, actions: Value) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO analysis.alert_automation_runs (rule_name, root_id, mode, status, evidence,
                                                        actions)
             VALUES ($1, $2, $3, 'done', '{\"probe\": \"made_up_probe\", \"confirmations\": []}', $4)
             RETURNING id",
        )
        .bind(RULE)
        .bind(root)
        .bind(mode)
        .bind(actions)
        .fetch_one(db.pool())
        .await
        .expect("a run")
    }

    #[tokio::test]
    async fn test_report_compares_the_dry_run_with_what_analysts_did() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let same = alert(db, Some(("DELIVERY", false))).await;
        let different = alert(db, Some(("FALSE_POSITIVE", false))).await;
        let still_open = alert(db, None).await;
        let automated = alert(db, Some(("DELIVERY", true))).await;
        for root in [same, different, still_open, automated] {
            run_of(db, root, "dry_run", delivered()).await;
        }
        // an alert that's gone: the run outlives it, since its root has no foreign key
        run_of(db, Uuid::nil(), "dry_run", delivered()).await;
        // an enforce run and another rule's aren't counted
        run_of(db, still_open, "enforce", delivered()).await;

        let out = report(&service(db), RULE, None).await.expect("reports");

        assert!(out.contains(&format!("rule {RULE}: 5 dry runs")), "{out}");
        for line in [
            "analysts dispositioned the same way: 1",
            "analysts dispositioned differently:  1",
            "still open:                          1",
            "dispositioned by ACE:                1",
            "alert deleted:                       1",
        ] {
            assert!(out.contains(line), "{line}: {out}");
        }
        assert!(
            out.contains(&format!("{different}  {:<20} FALSE_POSITIVE", "DELIVERY")),
            "{out}"
        );
        assert!(!out.contains(&same.to_string()), "{out}");
    }

    #[tokio::test]
    async fn test_report_counts_a_dry_run_that_decided_no_disposition() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let root = alert(db, None).await;
        run_of(
            db,
            root,
            "dry_run",
            json!([done("remediate", json!({"queued": []}))]),
        )
        .await;

        let out = report(&service(db), RULE, None).await.expect("reports");

        assert!(out.contains(&format!("rule {RULE}: 1 dry runs")), "{out}");
        assert!(
            out.contains("no disposition decided:              1"),
            "{out}"
        );
    }

    #[tokio::test]
    async fn test_report_counts_only_dry_runs_since_the_date() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let root = alert(db, None).await;
        run_of(db, root, "dry_run", delivered()).await;

        let later = since("2999-01-01").expect("a date");
        let out = report(&service(db), RULE, Some(later))
            .await
            .expect("reports");

        assert!(out.contains(&format!("rule {RULE}: 0 dry runs")), "{out}");
    }

    #[tokio::test]
    async fn test_list_shows_the_runs() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let dry = alert(db, None).await;
        run_of(db, dry, "dry_run", delivered()).await;
        let enforced = alert(db, Some(("DELIVERY", true))).await;
        run_of(db, enforced, "enforce", delivered()).await;
        let service = service(db);

        let dry_only = RunsQuery {
            mode: Some(Mode::DryRun),
            ..RunsQuery::default()
        };
        let listed: Value =
            serde_json::from_str(&list(&service, &dry_only, true).await.expect("lists"))
                .expect("JSON");
        let listed = listed.as_array().expect("a list");
        assert_eq!(
            listed
                .iter()
                .map(|run| (
                    run["alert_uuid"].as_str().unwrap_or_default().to_owned(),
                    run["mode"].clone(),
                    run["status"].clone()
                ))
                .collect::<Vec<_>>(),
            [(dry.to_string(), json!("dry_run"), json!("done"))]
        );
        assert_eq!(
            listed[0]["actions"]
                .as_array()
                .expect("actions")
                .iter()
                .map(|action| action["type"].clone())
                .collect::<Vec<_>>(),
            [json!("disposition"), json!("remediate")]
        );

        let of_rule = RunsQuery {
            rule: Some(RULE.to_owned()),
            ..RunsQuery::default()
        };
        let out = list(&service, &of_rule, false).await.expect("lists");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0].split_whitespace().take(5).collect::<Vec<_>>(),
            ["INSERTED", "RULE", "MODE", "STATUS", "ALERT"]
        );
        assert_eq!(
            lines[1..]
                .iter()
                .map(|line| line.split_whitespace().nth(3).unwrap_or_default())
                .collect::<Vec<_>>(),
            ["enforce", "dry_run"]
        );
        assert!(
            lines[1].ends_with("disposition=done, remediate=done"),
            "{out}"
        );

        let none = RunsQuery {
            rule: Some("no_such_rule".to_owned()),
            ..RunsQuery::default()
        };
        assert_eq!(
            list(&service, &none, false).await.expect("lists"),
            "no alert automation runs\n"
        );
    }

    /// Besides ace3's: a limit outside its bounds and a date that isn't one are refused, and the command
    /// reads only as the sweep's component, which holds `alert_automation:run`.
    #[tokio::test]
    async fn a_list_outside_its_bounds_or_a_date_that_isnt_one_is_refused() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = service(db);
        for limit in [0, ace_service::MAX_LISTED_RUNS + 1] {
            let query = RunsQuery {
                limit,
                ..RunsQuery::default()
            };
            assert!(list(&service, &query, false).await.is_err(), "{limit}");
        }
        assert!(since("yesterday").is_err());
        assert_eq!(
            since("2026-05-01T10:00:00").expect("a time"),
            since("2026-05-01T10:00:00Z").expect("a time")
        );
        let analyst = Actor::User {
            id: ace_service::UserId(Uuid::from_u128(7)),
            name: "analyst".to_owned(),
        };
        assert!(matches!(
            service
                .alert_automation_runs(&analyst, &RunsQuery::default())
                .await,
            Err(ace_service::ServiceError::PermissionDenied { .. })
        ));
    }
}
