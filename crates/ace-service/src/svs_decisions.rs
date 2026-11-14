//! What has been decided about a test's signatures (PLAN.md 7.10 batch 5, part 5b): ace3's
//! `saq/svs/expectations.py` and the reads of `aceapi_v2/svs/expectations` and `ignores`.
//!
//! - An **expectation** is a signature a run of the test on one platform should fire (`expected`), or one
//!   that fires there but isn't what the test is about (`rejected`, and not proposed again). A run is
//!   judged by its own platform's decisions only. Anything else a run fires is a candidate in that run's
//!   result. Removing a decision makes the signature a candidate again the next time it fires.
//! - An **ignore** marks a signature as launcher noise, for one test on every platform (`svs:run_manage`)
//!   or for every test (`svs:admin`). An ignored signature is never a candidate and never missing.
//! - A test's **settings** hold an observation window that replaces the computed one, and whether a run of
//!   it holds its hosts for its whole attribution window.
//!
//! Every change of an expectation or an ignore marks the affected runs' results stale in its own
//! transaction (`svs_results`), so the timers recompute them, and each write has an audit row. A write may
//! carry a precondition (`ace_core::svs::results::Precondition`): one that no longer holds is
//! `StaleWrite` and changes nothing.
//!
//! What differs from ace3's:
//! - Who decided is the actor, whatever it is, where ace3 stores a user id and so refuses a key that
//!   belongs to nobody: every key here has an identity of its own to record.
//! - A signature is named as a detection names it (`analysis.detections.signature_uuid`): up to 36 of
//!   A-Z, a-z, 0-9, `_` and `-`, the shape of a rule's `uuid` meta, where ace3 takes only a uuid. A rule
//!   whose meta isn't a uuid can fire too.
//! - A changed-since page holds back rows changed in the last few seconds (`Service::with_feed_settle`),
//!   as ace3's does, so a pull resumed from its last `updated_at` never misses a row whose transaction
//!   committed late.

use ace_core::svs::catalog::platform_slugs;
use ace_core::svs::results::Precondition;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgConnection;
use sqlx::types::Json;
use uuid::Uuid;

use crate::alerts::{RecordedActor, page_limit};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{SVS_ADMIN, SVS_RUN_MANAGE, SVS_RUN_READ};
use crate::svs_results::{StaleRuns, mark_stale_where};
use crate::{Actor, Service, ServiceError};

/// The most decisions one page holds.
pub const MAX_DECISIONS_PAGE: u32 = 1000;
/// The longest reason a decision keeps, as ace3's request has it.
pub const MAX_DECISION_REASON: usize = 4096;

/// A decision about a signature for a test: ace3's `ExpectationState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectationState {
    /// A run of the test should fire it.
    Expected,
    /// It fires, but it isn't what the test is about; never proposed again.
    Rejected,
}

impl ExpectationState {
    pub fn as_str(self) -> &'static str {
        match self {
            ExpectationState::Expected => "expected",
            ExpectationState::Rejected => "rejected",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "expected" => Some(ExpectationState::Expected),
            "rejected" => Some(ExpectationState::Rejected),
            _ => None,
        }
    }
}

/// A decision about a signature for a test on one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    pub test_guid: Uuid,
    /// The platform the decision is about: only the test's runs on it are judged by it.
    pub platform: String,
    pub signature_uuid: String,
    pub state: ExpectationState,
    /// The signature's family and name as last known.
    pub signature_family: Option<String>,
    pub signature_name: Option<String>,
    pub reason: Option<String>,
    /// The run whose result the decision was made from.
    pub decided_from_run: Option<Uuid>,
    pub decided_by: Option<RecordedActor>,
    pub decided_at: DateTime<Utc>,
    /// The `changed_since` key, and what an `If-Match` names.
    pub updated_at: DateTime<Utc>,
}

/// Which expectations to list.
#[derive(Debug, Clone, Default)]
pub struct ExpectationQuery {
    /// Only this test's, by its guid.
    pub test: Option<String>,
    pub platform: Option<String>,
    pub signature: Option<String>,
    /// Only `expected` or only `rejected`.
    pub state: Option<String>,
    /// Only decisions made or changed at or after this; the rows then come in (updated_at, id) order.
    pub changed_since: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectationPage {
    pub expectations: Vec<Expectation>,
    pub next_cursor: Option<String>,
}

/// A signature ignored during a test's runs, or every test's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ignore {
    /// The test, for a test's ignore; None for a global one.
    pub test_guid: Option<Uuid>,
    pub signature_uuid: String,
    pub signature_family: Option<String>,
    pub signature_name: Option<String>,
    pub reason: Option<String>,
    pub created_by: Option<RecordedActor>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Ignore {
    /// `global` or `test`: ace3's `IgnoreScope`.
    pub fn scope(&self) -> &'static str {
        if self.test_guid.is_some() {
            "test"
        } else {
            "global"
        }
    }
}

/// Which ignores to list.
#[derive(Debug, Clone, Default)]
pub struct IgnoreQuery {
    /// Only `global` or only `test` ignores.
    pub scope: Option<String>,
    /// The ignores that apply to this test: its own and the global ones.
    pub test: Option<String>,
    pub signature: Option<String>,
    pub changed_since: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnorePage {
    pub ignores: Vec<Ignore>,
    pub next_cursor: Option<String>,
}

/// A test's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestSettings {
    pub test_guid: Uuid,
    /// None for the computed window.
    pub observation_minutes: Option<i32>,
    pub holds_host: bool,
    pub set_by: Option<RecordedActor>,
    pub updated_at: DateTime<Utc>,
}

/// Where a page of decisions left off: by id, or by (updated_at, id) for a changed-since pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FeedCursor {
    /// `id` or `updated_at`: the order the page was read in.
    pub(crate) o: String,
    pub(crate) at: Option<DateTime<Utc>>,
    pub(crate) id: i64,
}

impl FeedCursor {
    pub(crate) fn encode(changed: bool, at: DateTime<Utc>, id: i64) -> String {
        let cursor = FeedCursor {
            o: if changed { "updated_at" } else { "id" }.to_owned(),
            at: changed.then_some(at),
            id,
        };
        hex::encode(serde_json::to_vec(&cursor).unwrap_or_default())
    }

    /// The cursor of a page read in the order this request reads in, or `InvalidRequest`: a cursor from
    /// a listing with `changed_since` doesn't page one without, nor the other way.
    pub(crate) fn decode(text: &str, changed: bool) -> Result<FeedCursor, ServiceError> {
        let cursor: FeedCursor = hex::decode(text)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| ServiceError::InvalidRequest(format!("{text:?} isn't a cursor")))?;
        let order = if changed { "updated_at" } else { "id" };
        if cursor.o != order || cursor.at.is_some() != changed {
            return Err(ServiceError::InvalidRequest(format!(
                "this cursor pages a listing ordered by {}, not {order}: pass the same changed_since \
                 (or none) as the request that returned it",
                cursor.o
            )));
        }
        Ok(cursor)
    }
}

fn unknown_test(guid: &str) -> ServiceError {
    ServiceError::NotFound(format!("test {guid} not found"))
}

fn invalid(message: impl Into<String>) -> ServiceError {
    ServiceError::InvalidRequest(message.into())
}

/// A signature as a detection names it: a rule's `uuid` meta (the module's docs).
pub(crate) fn signature_uuid(value: &str) -> Result<String, ServiceError> {
    let value = value.trim();
    let shaped = !value.is_empty()
        && value.len() <= 36
        && value.starts_with(|c: char| c.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !shaped {
        return Err(invalid(format!("{value:?} is not a signature uuid")));
    }
    // a uuid is compared as the catalog and the detections write it, lower case
    Ok(match Uuid::parse_str(value) {
        Ok(uuid) => uuid.to_string(),
        Err(_) => value.to_owned(),
    })
}

fn reason_of(reason: Option<&str>) -> Result<Option<&str>, ServiceError> {
    match reason {
        Some(reason) if reason.chars().count() > MAX_DECISION_REASON => Err(invalid(format!(
            "a reason is at most {MAX_DECISION_REASON} characters"
        ))),
        other => Ok(other),
    }
}

struct TestRow {
    guid: Uuid,
    platforms: Vec<String>,
}

/// The catalog test, removed or not: a decision outlives its test's place in the repository.
async fn catalog_test(conn: &mut PgConnection, guid: &str) -> Result<TestRow, ServiceError> {
    let parsed = Uuid::parse_str(guid.trim()).map_err(|_| unknown_test(guid))?;
    sqlx::query_as!(
        TestRow,
        "SELECT guid, platforms FROM svs.catalog_tests WHERE guid = $1",
        parsed,
    )
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| unknown_test(guid))
}

/// The platform, which has to be one of the test's: ace3's `_platform`.
fn platform_of(test: &TestRow, platform: Option<&str>) -> Result<String, ServiceError> {
    let platform = platform.unwrap_or_default().trim().to_lowercase();
    let platforms = platform_slugs(&test.platforms);
    if !platforms.contains(&platform) {
        let known = if platforms.is_empty() {
            "it supports none".to_owned()
        } else {
            platforms.join(", ")
        };
        return Err(invalid(format!(
            "platform {platform:?} is not one of test {}'s ({known})",
            test.guid
        )));
    }
    Ok(platform)
}

/// The signature's family and name as the latest run result that has it says (the run's own, when
/// given), or its family as an attributed detection recorded it: ace3's `_last_known`.
async fn last_known(
    conn: &mut PgConnection,
    signature: &str,
    run: Option<i64>,
) -> Result<(Option<String>, Option<String>), ServiceError> {
    if let Some(run) = run
        && let Some(row) = sqlx::query!(
            "SELECT signature_family, signature_name FROM svs.run_results
             WHERE signature_uuid = $1 AND run_id = $2",
            signature,
            run,
        )
        .fetch_optional(&mut *conn)
        .await?
    {
        return Ok((row.signature_family, row.signature_name));
    }
    if let Some(row) = sqlx::query!(
        "SELECT signature_family, signature_name FROM svs.run_results
         WHERE signature_uuid = $1 ORDER BY updated_at DESC, id DESC LIMIT 1",
        signature,
    )
    .fetch_optional(&mut *conn)
    .await?
    {
        return Ok((row.signature_family, row.signature_name));
    }
    let family = sqlx::query_scalar!(
        r#"SELECT d.signature_family AS "family!" FROM analysis.detections d
           WHERE d.signature_uuid = $1 AND d.signature_family IS NOT NULL
             AND EXISTS (SELECT FROM svs.attributions a WHERE a.detection_id = d.id)
           LIMIT 1"#,
        signature,
    )
    .fetch_optional(conn)
    .await?;
    Ok((family, None))
}

struct ExpectationRow {
    id: i64,
    test_guid: Uuid,
    platform: String,
    signature_uuid: String,
    state: String,
    signature_family: Option<String>,
    signature_name: Option<String>,
    reason: Option<String>,
    decided_from_run: Option<Uuid>,
    decided_by: Value,
    decided_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl ExpectationRow {
    fn into_expectation(self) -> Result<Expectation, ServiceError> {
        Ok(Expectation {
            test_guid: self.test_guid,
            platform: self.platform,
            signature_uuid: self.signature_uuid,
            state: ExpectationState::parse(&self.state).ok_or_else(|| {
                ServiceError::from(ace_core::DbError::Decode(
                    "a stored expectation state".to_owned(),
                ))
            })?,
            signature_family: self.signature_family,
            signature_name: self.signature_name,
            reason: self.reason,
            decided_from_run: self.decided_from_run,
            decided_by: RecordedActor::from_row(Some(self.decided_by))?,
            decided_at: self.decided_at,
            updated_at: self.updated_at,
        })
    }
}

async fn expectation_row(
    conn: &mut PgConnection,
    test: Uuid,
    platform: &str,
    signature: &str,
    lock: bool,
) -> Result<Option<Expectation>, ServiceError> {
    if lock {
        sqlx::query_scalar!(
            "SELECT id FROM svs.expectations
             WHERE test_guid = $1 AND platform = $2 AND signature_uuid = $3 FOR UPDATE",
            test,
            platform,
            signature,
        )
        .fetch_optional(&mut *conn)
        .await?;
    }
    sqlx::query_as!(
        ExpectationRow,
        r#"SELECT e.id, e.test_guid, e.platform, e.signature_uuid, e.state, e.signature_family,
                  e.signature_name, e.reason, r.uuid AS "decided_from_run?",
                  e.decided_by AS "decided_by!: Value", e.decided_at, e.updated_at
           FROM svs.expectations e
           LEFT JOIN svs.runs r ON r.id = e.decided_from_run_id
           WHERE e.test_guid = $1 AND e.platform = $2 AND e.signature_uuid = $3"#,
        test,
        platform,
        signature,
    )
    .fetch_optional(conn)
    .await?
    .map(ExpectationRow::into_expectation)
    .transpose()
}

struct IgnoreRow {
    id: i64,
    test_guid: Option<Uuid>,
    signature_uuid: String,
    signature_family: Option<String>,
    signature_name: Option<String>,
    reason: Option<String>,
    created_by: Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl IgnoreRow {
    fn into_ignore(self) -> Result<Ignore, ServiceError> {
        Ok(Ignore {
            test_guid: self.test_guid,
            signature_uuid: self.signature_uuid,
            signature_family: self.signature_family,
            signature_name: self.signature_name,
            reason: self.reason,
            created_by: RecordedActor::from_row(Some(self.created_by))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

async fn ignore_row(
    conn: &mut PgConnection,
    test: Option<Uuid>,
    signature: &str,
    lock: bool,
) -> Result<Option<Ignore>, ServiceError> {
    if lock {
        sqlx::query_scalar!(
            "SELECT id FROM svs.ignores
             WHERE test_guid IS NOT DISTINCT FROM $1 AND signature_uuid = $2 FOR UPDATE",
            test,
            signature,
        )
        .fetch_optional(&mut *conn)
        .await?;
    }
    sqlx::query_as!(
        IgnoreRow,
        r#"SELECT id, test_guid, signature_uuid, signature_family, signature_name, reason,
                  created_by AS "created_by!: Value", created_at, updated_at
           FROM svs.ignores WHERE test_guid IS NOT DISTINCT FROM $1 AND signature_uuid = $2"#,
        test,
        signature,
    )
    .fetch_optional(conn)
    .await?
    .map(IgnoreRow::into_ignore)
    .transpose()
}

async fn settings_row(
    conn: &mut PgConnection,
    test: Uuid,
) -> Result<Option<TestSettings>, ServiceError> {
    let Some(row) = sqlx::query!(
        r#"SELECT test_guid, observation_minutes, holds_host, set_by AS "set_by: Value", updated_at
           FROM svs.test_settings WHERE test_guid = $1"#,
        test,
    )
    .fetch_optional(conn)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(TestSettings {
        test_guid: row.test_guid,
        observation_minutes: row.observation_minutes,
        holds_host: row.holds_host,
        set_by: RecordedActor::from_row(row.set_by)?,
        updated_at: row.updated_at,
    }))
}

/// What a decision's audit row keeps.
#[derive(Serialize)]
struct ExpectationRecord<'a> {
    state: ExpectationState,
    reason: Option<&'a str>,
    signature_family: Option<&'a str>,
    signature_name: Option<&'a str>,
    decided_from_run: Option<Uuid>,
}

impl Recorded for ExpectationRecord<'_> {}

impl<'a> ExpectationRecord<'a> {
    fn of(expectation: &'a Expectation) -> Self {
        ExpectationRecord {
            state: expectation.state,
            reason: expectation.reason.as_deref(),
            signature_family: expectation.signature_family.as_deref(),
            signature_name: expectation.signature_name.as_deref(),
            decided_from_run: expectation.decided_from_run,
        }
    }
}

#[derive(Serialize)]
struct IgnoreRecord<'a> {
    scope: &'static str,
    reason: Option<&'a str>,
    signature_family: Option<&'a str>,
    signature_name: Option<&'a str>,
}

impl Recorded for IgnoreRecord<'_> {}

impl<'a> IgnoreRecord<'a> {
    fn of(ignore: &'a Ignore) -> Self {
        IgnoreRecord {
            scope: ignore.scope(),
            reason: ignore.reason.as_deref(),
            signature_family: ignore.signature_family.as_deref(),
            signature_name: ignore.signature_name.as_deref(),
        }
    }
}

#[derive(Serialize)]
struct SettingsRecord {
    observation_minutes: Option<i32>,
    holds_host: bool,
}

impl Recorded for SettingsRecord {}

impl SettingsRecord {
    fn of(settings: &TestSettings) -> Self {
        SettingsRecord {
            observation_minutes: settings.observation_minutes,
            holds_host: settings.holds_host,
        }
    }
}

fn expectation_target(test: Uuid, platform: &str, signature: &str) -> Target {
    Target::svs_expectation(&format!("{test}/{platform}/{signature}"))
}

fn ignore_target(test: Option<Uuid>, signature: &str) -> Target {
    Target::svs_ignore(&match test {
        Some(test) => format!("{test}/{signature}"),
        None => format!("global/{signature}"),
    })
}

fn stale(why: String) -> ServiceError {
    ServiceError::StaleWrite(why)
}

/// How many expectations `query` matches, counting up to `cap`, for an export's bound.
pub(crate) async fn expectation_count(
    conn: &mut PgConnection,
    query: &ExpectationQuery,
    settle: f64,
    cap: i64,
) -> Result<i64, ServiceError> {
    if let Some(state) = &query.state
        && ExpectationState::parse(state).is_none()
    {
        return Err(invalid("state must be one of expected, rejected"));
    }
    let test = query
        .test
        .as_deref()
        .map(|test| Uuid::parse_str(test.trim()).unwrap_or(Uuid::nil()));
    Ok(sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM (
               SELECT FROM svs.expectations e
               WHERE ($1::uuid IS NULL OR e.test_guid = $1)
                 AND ($2::text IS NULL OR e.platform = $2)
                 AND ($3::text IS NULL OR e.signature_uuid = $3)
                 AND ($4::text IS NULL OR e.state = $4)
                 AND ($5::timestamptz IS NULL
                      OR (e.updated_at >= $5 AND e.updated_at < now() - make_interval(secs => $6)))
               LIMIT $7) x"#,
        test,
        query.platform.as_ref().map(|p| p.trim().to_lowercase()),
        query.signature.as_ref().map(|s| s.trim().to_owned()),
        query.state,
        query.changed_since,
        settle,
        cap,
    )
    .fetch_one(conn)
    .await?)
}

/// How many ignores `query` matches, counting up to `cap`, for an export's bound.
pub(crate) async fn ignore_count(
    conn: &mut PgConnection,
    query: &IgnoreQuery,
    settle: f64,
    cap: i64,
) -> Result<i64, ServiceError> {
    if let Some(scope) = &query.scope
        && !matches!(scope.as_str(), "global" | "test")
    {
        return Err(invalid("scope must be one of global, test"));
    }
    let test = query
        .test
        .as_deref()
        .map(|test| Uuid::parse_str(test.trim()).unwrap_or(Uuid::nil()));
    Ok(sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM (
               SELECT FROM svs.ignores i
               WHERE ($1::text IS NULL OR (i.test_guid IS NULL) = ($1 = 'global'))
                 AND ($2::uuid IS NULL OR i.test_guid IS NULL OR i.test_guid = $2)
                 AND ($3::text IS NULL OR i.signature_uuid = $3)
                 AND ($4::timestamptz IS NULL
                      OR (i.updated_at >= $4 AND i.updated_at < now() - make_interval(secs => $5)))
               LIMIT $6) x"#,
        query.scope,
        test,
        query.signature.as_ref().map(|s| s.trim().to_owned()),
        query.changed_since,
        settle,
        cap,
    )
    .fetch_one(conn)
    .await?)
}

impl Service {
    /// The service with how long a changed-since page holds a row back after it changed, 5 seconds unless
    /// set: ace3's `CHANGED_SINCE_SETTLE_SECONDS`.
    pub fn with_feed_settle(mut self, settle: chrono::TimeDelta) -> Self {
        self.feed_settle = settle;
        self
    }

    /// How long a changed-since page holds a row back.
    pub(crate) fn feed_settle_seconds(&self) -> f64 {
        self.feed_settle.num_milliseconds() as f64 / 1000.0
    }

    /// Decides a signature for a test on a platform, `expected` or `rejected`: ace3's `set_expectation`.
    /// With `run`, a run of the test, the decision was made from that run's result, it's about the run's
    /// platform, and the run's event log records it; without one, `platform` names one of the test's.
    /// It needs `svs:run_manage`. An unknown test is `NotFound`; a signature, state, platform or run that
    /// can't be used `InvalidRequest`; a precondition that no longer holds `StaleWrite`.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_svs_expectation(
        &self,
        actor: &Actor,
        test_guid: &str,
        platform: Option<&str>,
        signature: &str,
        state: &str,
        reason: Option<&str>,
        run: Option<Uuid>,
        precondition: Precondition,
        now: DateTime<Utc>,
    ) -> Result<Expectation, ServiceError> {
        let reason = reason_of(reason)?;
        self.gate
            .write(actor, "set_svs_expectation", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    let conn = tx.conn();
                    let test = catalog_test(conn, test_guid).await?;
                    let signature = signature_uuid(signature)?;
                    let state = ExpectationState::parse(state)
                        .ok_or_else(|| invalid("state must be one of expected, rejected"))?;
                    let mut platform = platform.map(str::to_owned);
                    let mut from_run = None;
                    if let Some(run) = run {
                        let found = sqlx::query!(
                            "SELECT id, test_guid, platform FROM svs.runs WHERE uuid = $1",
                            run,
                        )
                        .fetch_optional(&mut *conn)
                        .await?
                        .filter(|found| found.test_guid == test.guid)
                        .ok_or_else(|| {
                            invalid(format!("run {run} is not a run of test {}", test.guid))
                        })?;
                        if let Some(asked) = &platform
                            && asked.trim().to_lowercase() != found.platform
                        {
                            return Err(invalid(format!(
                                "run {run} is on {}, not {asked}",
                                found.platform
                            )));
                        }
                        platform = Some(found.platform);
                        from_run = Some(found.id);
                    }
                    let platform = platform_of(&test, platform.as_deref())?;
                    let (family, name) = last_known(conn, &signature, from_run).await?;
                    let what = format!(
                        "the decision about {} on {platform}",
                        name.as_deref().unwrap_or(&signature)
                    );
                    let before =
                        expectation_row(conn, test.guid, &platform, &signature, true).await?;
                    if let Some(why) =
                        precondition.refuses(before.as_ref().map(|row| row.updated_at), &what)
                    {
                        return Err(stale(why));
                    }
                    let written = sqlx::query!(
                        "INSERT INTO svs.expectations AS e
                             (test_guid, platform, signature_uuid, state, signature_family,
                              signature_name, reason, decided_from_run_id, decided_by, decided_at)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
                         ON CONFLICT ON CONSTRAINT expectations_are_unique DO UPDATE
                         SET state = EXCLUDED.state, signature_family = EXCLUDED.signature_family,
                             signature_name = EXCLUDED.signature_name, reason = EXCLUDED.reason,
                             decided_from_run_id = EXCLUDED.decided_from_run_id,
                             decided_by = EXCLUDED.decided_by, decided_at = EXCLUDED.decided_at
                         WHERE $11",
                        test.guid,
                        platform,
                        signature,
                        state.as_str(),
                        family,
                        name,
                        reason,
                        from_run,
                        Json(actor) as _,
                        now,
                        // a row someone else added since this looked is refused, not replaced, when
                        // the client said it saw none
                        !matches!(precondition, Precondition::Absent),
                    )
                    .execute(&mut *conn)
                    .await?
                    .rows_affected();
                    if written != 1 {
                        return Err(stale(format!(
                            "{what} was decided by someone else since you loaded it"
                        )));
                    }
                    if let Some(from_run) = from_run {
                        crate::svs_runs::add_event(
                            conn,
                            from_run,
                            "candidate_decision",
                            actor,
                            None,
                            None,
                            Some(json!({
                                "signature_uuid": signature, "platform": platform,
                                "state": state.as_str(), "reason": reason,
                            })),
                            now,
                        )
                        .await?;
                    }
                    mark_stale_where(conn, &StaleRuns::TestOnPlatform(test.guid, &platform))
                        .await?;
                    let after = expectation_row(conn, test.guid, &platform, &signature, false)
                        .await?
                        .ok_or_else(|| unknown_test(test_guid))?;
                    let target = expectation_target(test.guid, &platform, &signature);
                    let change = match &before {
                        Some(before) => Change::updated(
                            target,
                            &ExpectationRecord::of(before),
                            &ExpectationRecord::of(&after),
                        )?,
                        None => Change::added(target, &ExpectationRecord::of(&after))?,
                    };
                    Ok(Audited::changed(after, change))
                })
            })
            .await
    }

    /// Removes a decision: the signature is a candidate again the next time a run on the platform fires
    /// it. ace3's `remove_expectation`. It needs `svs:run_manage`. An unknown test, or no such decision,
    /// is `NotFound`.
    pub async fn remove_svs_expectation(
        &self,
        actor: &Actor,
        test_guid: &str,
        platform: &str,
        signature: &str,
    ) -> Result<(), ServiceError> {
        self.gate
            .write(actor, "remove_svs_expectation", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    let conn = tx.conn();
                    let test = catalog_test(conn, test_guid).await?;
                    let platform = platform.trim().to_lowercase();
                    let signature = signature_uuid(signature)?;
                    let before = expectation_row(conn, test.guid, &platform, &signature, true)
                        .await?
                        .ok_or_else(|| {
                            ServiceError::NotFound(format!(
                                "no decision about signature {signature} for test {} on {platform}",
                                test.guid
                            ))
                        })?;
                    sqlx::query!(
                        "DELETE FROM svs.expectations
                         WHERE test_guid = $1 AND platform = $2 AND signature_uuid = $3",
                        test.guid,
                        platform,
                        signature,
                    )
                    .execute(&mut *conn)
                    .await?;
                    mark_stale_where(conn, &StaleRuns::TestOnPlatform(test.guid, &platform))
                        .await?;
                    let change = Change::removed(
                        expectation_target(test.guid, &platform, &signature),
                        &ExpectationRecord::of(&before),
                    )?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }

    /// One decision: ace3's `get_expectation`. It needs `svs:run_read`; none is `NotFound`.
    pub async fn svs_expectation(
        &self,
        actor: &Actor,
        test_guid: &str,
        platform: &str,
        signature: &str,
    ) -> Result<Expectation, ServiceError> {
        self.gate
            .read(actor, "svs_expectation", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let missing = || {
                        ServiceError::NotFound(format!(
                            "no decision about signature {signature} for test {test_guid} on {platform}"
                        ))
                    };
                    let test = Uuid::parse_str(test_guid.trim()).map_err(|_| missing())?;
                    let signature = signature_uuid(signature)?;
                    expectation_row(
                        tx.conn(),
                        test,
                        &platform.trim().to_lowercase(),
                        &signature,
                        false,
                    )
                    .await?
                    .ok_or_else(missing)
                })
            })
            .await
    }

    /// A page of every test's decisions, by id, or with `changed_since` in (updated_at, id) order of
    /// settled rows. It needs `svs:run_read`. A state that isn't one, or a cursor of another listing, is
    /// `InvalidRequest`.
    pub async fn svs_expectations(
        &self,
        actor: &Actor,
        query: &ExpectationQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<ExpectationPage, ServiceError> {
        let limit = page_limit(limit, MAX_DECISIONS_PAGE)?;
        let changed = query.changed_since.is_some();
        let after = &cursor
            .map(|cursor| FeedCursor::decode(cursor, changed))
            .transpose()?;
        if let Some(state) = &query.state
            && ExpectationState::parse(state).is_none()
        {
            return Err(invalid("state must be one of expected, rejected"));
        }
        // a guid that isn't one matches nothing
        let test = query
            .test
            .as_deref()
            .map(|test| Uuid::parse_str(test.trim()).unwrap_or(Uuid::nil()));
        let platform = query.platform.as_ref().map(|p| p.trim().to_lowercase());
        let signature = query.signature.as_ref().map(|s| s.trim().to_owned());
        let (platform, signature, state) = (&platform, &signature, &query.state);
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_expectations", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = sqlx::query_as!(
                        ExpectationRow,
                        r#"SELECT e.id, e.test_guid, e.platform, e.signature_uuid, e.state,
                                  e.signature_family, e.signature_name, e.reason,
                                  r.uuid AS "decided_from_run?", e.decided_by AS "decided_by!: Value",
                                  e.decided_at, e.updated_at
                           FROM svs.expectations e
                           LEFT JOIN svs.runs r ON r.id = e.decided_from_run_id
                           WHERE ($1::uuid IS NULL OR e.test_guid = $1)
                             AND ($2::text IS NULL OR e.platform = $2)
                             AND ($3::text IS NULL OR e.signature_uuid = $3)
                             AND ($4::text IS NULL OR e.state = $4)
                             AND ($5::timestamptz IS NULL
                                  OR (e.updated_at >= $5
                                      AND e.updated_at < now() - make_interval(secs => $9)))
                             AND ($6::bigint IS NULL
                                  OR CASE WHEN $8 THEN (e.updated_at, e.id) > ($7::timestamptz, $6)
                                          ELSE e.id > $6 END)
                           ORDER BY CASE WHEN $8 THEN e.updated_at END, e.id
                           LIMIT $10"#,
                        test,
                        platform.as_deref(),
                        signature.as_deref(),
                        state.as_deref(),
                        changed_since,
                        after.as_ref().map(|c| c.id),
                        after.as_ref().and_then(|c| c.at),
                        changed,
                        settle,
                        limit + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last()
                            .map(|last| FeedCursor::encode(changed, last.updated_at, last.id))
                    } else {
                        None
                    };
                    Ok(ExpectationPage {
                        expectations: rows
                            .into_iter()
                            .map(ExpectationRow::into_expectation)
                            .collect::<Result<_, _>>()?,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// Ignores a signature during the test's runs, or every test's when `test_guid` is None: ace3's
    /// `set_ignore`. Setting it again replaces its reason. A test's needs `svs:run_manage` and a global
    /// one `svs:admin`. An unknown test is `NotFound`; a signature that isn't one `InvalidRequest`; a
    /// precondition that no longer holds `StaleWrite`.
    pub async fn set_svs_ignore(
        &self,
        actor: &Actor,
        signature: &str,
        test_guid: Option<&str>,
        reason: Option<&str>,
        precondition: Precondition,
        now: DateTime<Utc>,
    ) -> Result<Ignore, ServiceError> {
        let reason = reason_of(reason)?;
        let permission = if test_guid.is_some() {
            &SVS_RUN_MANAGE
        } else {
            &SVS_ADMIN
        };
        self.gate
            .write(actor, "set_svs_ignore", permission, &|tx| {
                Box::pin(async move {
                    let conn = tx.conn();
                    let test = match test_guid {
                        Some(guid) => Some(catalog_test(conn, guid).await?.guid),
                        None => None,
                    };
                    let signature = signature_uuid(signature)?;
                    let (family, name) = last_known(conn, &signature, None).await?;
                    let what = format!(
                        "the ignore of {} {}",
                        name.as_deref().unwrap_or(&signature),
                        if test.is_some() {
                            "for this test"
                        } else {
                            "for every test"
                        }
                    );
                    let before = ignore_row(conn, test, &signature, true).await?;
                    if let Some(why) =
                        precondition.refuses(before.as_ref().map(|row| row.updated_at), &what)
                    {
                        return Err(stale(why));
                    }
                    let replace = async |conn: &mut PgConnection| {
                        Ok::<u64, ServiceError>(
                            sqlx::query!(
                                "UPDATE svs.ignores SET reason = $3
                                 WHERE test_guid IS NOT DISTINCT FROM $1 AND signature_uuid = $2",
                                test,
                                signature,
                                reason,
                            )
                            .execute(conn)
                            .await?
                            .rows_affected(),
                        )
                    };
                    let mut written = match &before {
                        Some(_) => replace(&mut *conn).await?,
                        None => sqlx::query!(
                            "INSERT INTO svs.ignores
                                 (test_guid, signature_uuid, signature_family, signature_name, reason,
                                  created_by, created_at)
                             VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
                             ON CONFLICT DO NOTHING",
                            test,
                            signature,
                            family,
                            name,
                            reason,
                            Json(actor) as _,
                            now,
                        )
                        .execute(&mut *conn)
                        .await?
                        .rows_affected(),
                    };
                    // two people adding it at once: the second, with no precondition, replaces the
                    // first's reason, as setting it again does; one that saw no row is refused
                    if written == 0 && matches!(precondition, Precondition::None) {
                        written = replace(&mut *conn).await?;
                    }
                    if written != 1 {
                        return Err(stale(format!(
                            "{what} was decided by someone else since you loaded it"
                        )));
                    }
                    mark_stale_where(
                        conn,
                        &match test {
                            Some(test) => StaleRuns::Test(test),
                            None => StaleRuns::Every,
                        },
                    )
                    .await?;
                    let after = ignore_row(conn, test, &signature, false)
                        .await?
                        .ok_or_else(|| ServiceError::NotFound(what.clone()))?;
                    let target = ignore_target(test, &signature);
                    let change = match &before {
                        Some(before) => Change::updated(
                            target,
                            &IgnoreRecord::of(before),
                            &IgnoreRecord::of(&after),
                        )?,
                        None => Change::added(target, &IgnoreRecord::of(&after))?,
                    };
                    Ok(Audited::changed(after, change))
                })
            })
            .await
    }

    /// Stops ignoring a signature: ace3's `remove_ignore`. A test's needs `svs:run_manage` and a global
    /// one `svs:admin`. An unknown test, or a signature that isn't ignored there, is `NotFound`.
    pub async fn remove_svs_ignore(
        &self,
        actor: &Actor,
        signature: &str,
        test_guid: Option<&str>,
    ) -> Result<(), ServiceError> {
        let permission = if test_guid.is_some() {
            &SVS_RUN_MANAGE
        } else {
            &SVS_ADMIN
        };
        self.gate
            .write(actor, "remove_svs_ignore", permission, &|tx| {
                Box::pin(async move {
                    let conn = tx.conn();
                    let test = match test_guid {
                        Some(guid) => Some(catalog_test(conn, guid).await?.guid),
                        None => None,
                    };
                    let signature = signature_uuid(signature)?;
                    let before =
                        ignore_row(conn, test, &signature, true)
                            .await?
                            .ok_or_else(|| {
                                ServiceError::NotFound(format!(
                                    "signature {signature} is not ignored {}",
                                    match test {
                                        Some(test) => format!("for test {test}"),
                                        None => "globally".to_owned(),
                                    }
                                ))
                            })?;
                    sqlx::query!(
                        "DELETE FROM svs.ignores
                         WHERE test_guid IS NOT DISTINCT FROM $1 AND signature_uuid = $2",
                        test,
                        signature,
                    )
                    .execute(&mut *conn)
                    .await?;
                    mark_stale_where(
                        conn,
                        &match test {
                            Some(test) => StaleRuns::Test(test),
                            None => StaleRuns::Every,
                        },
                    )
                    .await?;
                    let change = Change::removed(
                        ignore_target(test, &signature),
                        &IgnoreRecord::of(&before),
                    )?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }

    /// One ignore: a test's, or the global one when `test_guid` is None. It needs `svs:run_read`; none is
    /// `NotFound`.
    pub async fn svs_ignore(
        &self,
        actor: &Actor,
        signature: &str,
        test_guid: Option<&str>,
    ) -> Result<Ignore, ServiceError> {
        self.gate
            .read(actor, "svs_ignore", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let missing =
                        || ServiceError::NotFound(format!("signature {signature} is not ignored"));
                    let test = match test_guid {
                        Some(guid) => Some(Uuid::parse_str(guid.trim()).map_err(|_| missing())?),
                        None => None,
                    };
                    let signature = signature_uuid(signature)?;
                    ignore_row(tx.conn(), test, &signature, false)
                        .await?
                        .ok_or_else(missing)
                })
            })
            .await
    }

    /// A page of the ignores, by id, or with `changed_since` in (updated_at, id) order of settled rows;
    /// `test` also finds the global ones, which apply to it. A removed ignore is gone, not listed. It
    /// needs `svs:run_read`. A scope that isn't one, or a cursor of another listing, is `InvalidRequest`.
    pub async fn svs_ignores(
        &self,
        actor: &Actor,
        query: &IgnoreQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<IgnorePage, ServiceError> {
        let limit = page_limit(limit, MAX_DECISIONS_PAGE)?;
        let changed = query.changed_since.is_some();
        let after = &cursor
            .map(|cursor| FeedCursor::decode(cursor, changed))
            .transpose()?;
        if let Some(scope) = &query.scope
            && !matches!(scope.as_str(), "global" | "test")
        {
            return Err(invalid("scope must be one of global, test"));
        }
        let test = query
            .test
            .as_deref()
            .map(|test| Uuid::parse_str(test.trim()).unwrap_or(Uuid::nil()));
        let signature = query.signature.as_ref().map(|s| s.trim().to_owned());
        let (signature, scope) = (&signature, &query.scope);
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_ignores", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = sqlx::query_as!(
                        IgnoreRow,
                        r#"SELECT i.id, i.test_guid, i.signature_uuid, i.signature_family,
                                  i.signature_name, i.reason, i.created_by AS "created_by!: Value",
                                  i.created_at, i.updated_at
                           FROM svs.ignores i
                           WHERE ($1::text IS NULL OR (i.test_guid IS NULL) = ($1 = 'global'))
                             AND ($2::uuid IS NULL OR i.test_guid IS NULL OR i.test_guid = $2)
                             AND ($3::text IS NULL OR i.signature_uuid = $3)
                             AND ($4::timestamptz IS NULL
                                  OR (i.updated_at >= $4
                                      AND i.updated_at < now() - make_interval(secs => $8)))
                             AND ($5::bigint IS NULL
                                  OR CASE WHEN $7 THEN (i.updated_at, i.id) > ($6::timestamptz, $5)
                                          ELSE i.id > $5 END)
                           ORDER BY CASE WHEN $7 THEN i.updated_at END, i.id
                           LIMIT $9"#,
                        scope.as_deref(),
                        test,
                        signature.as_deref(),
                        changed_since,
                        after.as_ref().map(|c| c.id),
                        after.as_ref().and_then(|c| c.at),
                        changed,
                        settle,
                        limit + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last()
                            .map(|last| FeedCursor::encode(changed, last.updated_at, last.id))
                    } else {
                        None
                    };
                    Ok(IgnorePage {
                        ignores: rows
                            .into_iter()
                            .map(IgnoreRow::into_ignore)
                            .collect::<Result<_, _>>()?,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// The most minutes a test's observation window may be set to: the overlay's
    /// `svs.runs.observation_window.ceiling_hours`.
    pub fn max_svs_observation_minutes(&self) -> i64 {
        self.runs.windows.ceiling.num_minutes()
    }

    /// The test's settings, None when it has none: ace3's `get_test_settings`. It needs `svs:run_read`;
    /// an unknown test is `NotFound`.
    pub async fn svs_test_settings(
        &self,
        actor: &Actor,
        test_guid: &str,
    ) -> Result<Option<TestSettings>, ServiceError> {
        self.gate
            .read(actor, "svs_test_settings", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let test = catalog_test(tx.conn(), test_guid).await?;
                    settings_row(tx.conn(), test.guid).await
                })
            })
            .await
    }

    /// Sets the settings of the test's runs registered from now on, replacing what was set: an
    /// observation window used as it is, with no slack and no floor, up to the configured ceiling (None
    /// for the computed one), and whether a run holds its hosts for its whole attribution window. ace3's
    /// `set_test_settings`. It needs `svs:run_manage`. An unknown test is `NotFound`, and minutes out of
    /// range `InvalidRequest`. Setting what is set already writes nothing.
    pub async fn set_svs_test_settings(
        &self,
        actor: &Actor,
        test_guid: &str,
        observation_minutes: Option<i32>,
        holds_host: bool,
    ) -> Result<TestSettings, ServiceError> {
        let ceiling = self.max_svs_observation_minutes();
        if let Some(minutes) = observation_minutes
            && !(1..=ceiling).contains(&i64::from(minutes))
        {
            return Err(invalid(format!(
                "observation_minutes must be from 1 to {ceiling} \
                 (svs.runs.observation_window.ceiling_hours)"
            )));
        }
        self.gate
            .write(actor, "set_svs_test_settings", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    let conn = tx.conn();
                    let test = catalog_test(conn, test_guid).await?;
                    sqlx::query_scalar!(
                        "SELECT id FROM svs.test_settings WHERE test_guid = $1 FOR UPDATE",
                        test.guid,
                    )
                    .fetch_optional(&mut *conn)
                    .await?;
                    let before = settings_row(conn, test.guid).await?;
                    if let Some(before) = &before
                        && before.observation_minutes == observation_minutes
                        && before.holds_host == holds_host
                    {
                        return Ok(Audited::unchanged(before.clone()));
                    }
                    sqlx::query!(
                        "INSERT INTO svs.test_settings
                             (test_guid, observation_minutes, holds_host, set_by)
                         VALUES ($1, $2, $3, $4::jsonb)
                         ON CONFLICT (test_guid) DO UPDATE
                         SET observation_minutes = EXCLUDED.observation_minutes,
                             holds_host = EXCLUDED.holds_host, set_by = EXCLUDED.set_by",
                        test.guid,
                        observation_minutes,
                        holds_host,
                        Json(actor) as _,
                    )
                    .execute(&mut *conn)
                    .await?;
                    let after = settings_row(conn, test.guid)
                        .await?
                        .ok_or_else(|| unknown_test(test_guid))?;
                    let target = Target::svs_test_settings(test.guid);
                    let change = match &before {
                        Some(before) => Change::updated(
                            target,
                            &SettingsRecord::of(before),
                            &SettingsRecord::of(&after),
                        )?,
                        None => Change::added(target, &SettingsRecord::of(&after))?,
                    };
                    Ok(Audited::changed(after, change))
                })
            })
            .await
    }

    /// Back to the computed window, and runs that hold their hosts only for their observation window:
    /// ace3's `remove_test_settings`. It needs `svs:run_manage`. An unknown test, or one with no
    /// settings, is `NotFound`.
    pub async fn remove_svs_test_settings(
        &self,
        actor: &Actor,
        test_guid: &str,
    ) -> Result<(), ServiceError> {
        self.gate
            .write(actor, "remove_svs_test_settings", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    let conn = tx.conn();
                    let test = catalog_test(conn, test_guid).await?;
                    sqlx::query_scalar!(
                        "SELECT id FROM svs.test_settings WHERE test_guid = $1 FOR UPDATE",
                        test.guid,
                    )
                    .fetch_optional(&mut *conn)
                    .await?;
                    let before = settings_row(conn, test.guid).await?.ok_or_else(|| {
                        ServiceError::NotFound(format!("test {} has no settings", test.guid))
                    })?;
                    sqlx::query!(
                        "DELETE FROM svs.test_settings WHERE test_guid = $1",
                        test.guid
                    )
                    .execute(&mut *conn)
                    .await?;
                    let change = Change::removed(
                        Target::svs_test_settings(test.guid),
                        &SettingsRecord::of(&before),
                    )?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }
}
