//! Reading alerts (PLAN.md 5.5): the alert list, one alert, its observables with what modules found, and
//! a file's download. An alert is a root a detection turned into one (`analysis.roots.alerted_at`). Each
//! read needs `alert:read`, as ace3's routes do, and an actor without it learns nothing, not even whether
//! the alert exists. A read writes no audit row, except a download, which ace3 audits and so does this.
//!
//! Lists are pages in a fixed order with a cursor, so a client paging through while alerts arrive sees
//! each one once: the alert list in the order its query asks, and an alert's observables by when each was
//! added. A page's size is bounded here, so the GUI's list (5.10) shares the bound.
//!
//! The alert list (5.10) takes the alert screen's filters (`crate::filters`) and one of ace3's sort orders:
//! when each became an alert, its title, or its disposition, either way, each with the alert's id to break
//! a tie, so the order is total and a cursor is stable. A cursor names the last alert a page held, and for
//! the disposition order the disposition it had then, since that can change while a client pages: an
//! alert dispositioned meanwhile is then where its new disposition puts it, and may be seen twice or not
//! at all, as in any keyset. When it became an alert and its title don't change. The page says how many
//! alerts the filters match in all, as ace3's list does.
//!
//! The list is one static query: each filter is a fixed condition that a NULL parameter turns off, so every
//! value is a bound parameter and the SQL is checked against the schema when it's built. A text filter is
//! `ILIKE` over a bounded value, and the query has `LIST_TIMEOUT` to run, past which it's refused as a
//! filter to narrow.

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::filters::{FilterEntry, FilterScreen, Resolved, split};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::ALERT_READ;
use crate::{Service, ServiceError};

/// The most alerts one page holds, as ace3's listing.
pub const MAX_ALERTS_PAGE: u32 = 1000;
/// The most observables one page holds. Each carries its results, which are larger than an alert row.
pub const MAX_OBSERVABLES_PAGE: u32 = 500;

/// An actor as a row recorded it: its identity and the name it had then.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RecordedActor {
    pub kind: String,
    pub id: String,
    pub name: Option<String>,
}

impl RecordedActor {
    pub(crate) fn from_row(value: Option<Value>) -> Result<Option<Self>, ServiceError> {
        value
            .map(|value| {
                serde_json::from_value(value).map_err(|e| {
                    ServiceError::from(ace_core::DbError::Decode(format!("a stored actor: {e}")))
                })
            })
            .transpose()
    }
}

/// Where an alert's analysis is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisState {
    /// Tasks are queued or running for its current pass.
    Running,
    /// Its current pass completed.
    Complete,
    /// Its analysis was cancelled and hasn't started again.
    Cancelled,
}

impl AnalysisState {
    /// From a root's pass, the pass that completed last, and whether it was cancelled.
    pub(crate) fn of(pass: i32, completed_pass: i32, cancelled: bool) -> Self {
        if cancelled {
            AnalysisState::Cancelled
        } else if pass > 0 && completed_pass == pass {
            AnalysisState::Complete
        } else {
            AnalysisState::Running
        }
    }
}

/// One alert's row.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertSummary {
    pub id: Uuid,
    /// The submission's description, as the sender wrote it.
    pub title: String,
    pub analysis_mode: String,
    pub event_time: Option<DateTime<Utc>>,
    pub event_time_source: String,
    pub created_at: DateTime<Utc>,
    pub alerted_at: DateTime<Utc>,
    pub disposition: Option<String>,
    pub dispositioned_at: Option<DateTime<Utc>>,
    pub dispositioned_by: Option<RecordedActor>,
    pub submitted_by: Option<RecordedActor>,
    pub analysis: AnalysisState,
}

/// One page of the alert list, the cursor for the next, None on the last, and how many alerts the filters
/// match in all.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertPage {
    pub alerts: Vec<AlertSummary>,
    pub next: Option<String>,
    pub total: i64,
}

/// How long the alert list's query may run. A filter that takes longer is refused, to be narrowed.
pub const LIST_TIMEOUT: &str = "10s";

/// The alert list's orders, ace3's sort filters that ace4's alerts have fields for. ace3's owner and queue
/// orders come with those fields (`FilterScreen::left_out`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AlertSort {
    /// When each became an alert, ace3's `Alert Date`, its default.
    #[default]
    AlertDate,
    /// Its title, ace3's `Description`, by its bytes.
    Description,
    /// Its disposition, `OPEN` for none, ace3's `Disposition`.
    Disposition,
}

impl AlertSort {
    pub const ALL: &'static [AlertSort] = &[
        AlertSort::AlertDate,
        AlertSort::Description,
        AlertSort::Disposition,
    ];

    /// Its name in a request.
    pub fn as_str(self) -> &'static str {
        match self {
            AlertSort::AlertDate => "alert_date",
            AlertSort::Description => "description",
            AlertSort::Disposition => "disposition",
        }
    }

    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|sort| sort.as_str() == name)
    }
}

/// What the alert list shows: the alert screen's filters, resolved in `tz`, in an order.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertQuery {
    pub filters: Vec<FilterEntry>,
    pub sort: AlertSort,
    pub descending: bool,
    /// Where a date filter's wall clock is, the viewer's timezone.
    pub tz: Tz,
}

impl Default for AlertQuery {
    /// Every alert, newest first, as ace3's list starts.
    fn default() -> Self {
        AlertQuery {
            filters: Vec::new(),
            sort: AlertSort::AlertDate,
            descending: true,
            tz: Tz::UTC,
        }
    }
}

/// Where a page of the alert list ends: the order it's in, its last alert, and for the disposition order
/// the disposition that alert had. As text it's `<sort>.<asc|desc>.<uuid>[.<disposition>]`, and a bare
/// uuid is the default order's, 5.5's cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AlertCursor {
    sort: AlertSort,
    descending: bool,
    id: Uuid,
    key: Option<String>,
}

impl AlertCursor {
    fn encode(&self) -> String {
        let dir = if self.descending { "desc" } else { "asc" };
        match &self.key {
            Some(key) => format!("{}.{dir}.{}.{key}", self.sort.as_str(), self.id),
            None => format!("{}.{dir}.{}", self.sort.as_str(), self.id),
        }
    }

    fn decode(text: &str, query: &AlertQuery) -> Result<Self, ServiceError> {
        let bad = || ServiceError::InvalidRequest(format!("{text:?} isn't a cursor of this list"));
        let cursor = if let Ok(id) = text.parse::<Uuid>() {
            AlertCursor {
                sort: AlertSort::AlertDate,
                descending: true,
                id,
                key: None,
            }
        } else {
            let mut parts = text.splitn(4, '.');
            let sort = parts.next().and_then(AlertSort::named).ok_or_else(bad)?;
            let descending = match parts.next() {
                Some("desc") => true,
                Some("asc") => false,
                _ => return Err(bad()),
            };
            let id = parts
                .next()
                .and_then(|id| id.parse().ok())
                .ok_or_else(bad)?;
            let key = parts.next().map(str::to_owned);
            let keyed = sort == AlertSort::Disposition;
            let shaped = key.as_deref().is_some_and(|key| {
                key.len() <= 64
                    && !key.is_empty()
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            });
            if keyed != shaped || (!keyed && key.is_some()) {
                return Err(bad());
            }
            AlertCursor {
                sort,
                descending,
                id,
                key,
            }
        };
        if cursor.sort != query.sort || cursor.descending != query.descending {
            return Err(ServiceError::InvalidRequest(format!(
                "the cursor {text:?} pages another order: ask for the order of the request that gave it"
            )));
        }
        Ok(cursor)
    }
}

/// An alert, with how much it holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub summary: AlertSummary,
    pub observables: i64,
    pub files: i64,
    pub detections: i64,
}

/// A path a file observable has in the alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertFile {
    pub path: String,
    pub yara_meta: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relationship {
    pub kind: String,
    pub target_type: String,
    pub target_value: String,
}

/// What one module found about an observable.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleResult {
    /// The result's id in this alert, which the tree's additions name.
    pub id: i64,
    pub module: String,
    pub analysis_type: String,
    pub schema_version: i32,
    pub summary: Option<String>,
    pub tags: Vec<String>,
    pub details: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertDetection {
    pub description: String,
    pub details: Option<Value>,
    /// The module whose result raised it, or None for one a submission or the core added.
    pub module: Option<String>,
}

/// An observable of an alert and everything recorded about it.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertObservable {
    pub id: i64,
    pub kind: String,
    pub value: String,
    pub time: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub directives: Vec<String>,
    pub exclude_modules: Vec<String>,
    /// The observable an analyst should look at instead, as (type, value).
    pub redirection: Option<(String, String)>,
    /// The label a module gave it in place of its type's name, such as `Source IP`, or None.
    pub display_type: Option<String>,
    /// What an observable modifier rule shows in place of its value, or None (PLAN.md 7.6).
    pub display_value: Option<String>,
    /// An observable modifier rule's `ignore` took it out of the tree, so the alert view doesn't draw it,
    /// as ace3's `Observable.ignored`.
    pub ignored: bool,
    /// A file's paths, the one it's analyzed under first (PLAN.md decision 15).
    pub files: Vec<AlertFile>,
    pub relationships: Vec<Relationship>,
    pub results: Vec<ModuleResult>,
    pub detections: Vec<AlertDetection>,
}

impl AlertObservable {
    /// What the alert view calls its type, as ace3's `Observable.display_type`: the label a module gave
    /// it, else its type's default label, either followed by the type's name in parentheses, else the
    /// type's name alone. So the Splunk module's `src_ip` reads `Source IP (ip)`.
    pub fn display_label(&self) -> String {
        let default = self
            .kind
            .parse::<ace_results::ObservableKind>()
            .ok()
            .and_then(|kind| kind.default_display_type());
        match self.display_type.as_deref().or(default) {
            Some(label) => format!("{label} ({})", self.kind),
            None => self.kind.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObservablePage {
    pub observables: Vec<AlertObservable>,
    pub next: Option<i64>,
}

/// A file an actor was let download: its bytes are the bucket's object with this hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDownload {
    pub sha256: String,
    pub path: String,
}

/// A download's audit row: what was read.
#[derive(Serialize)]
struct FileRead<'a> {
    sha256: &'a str,
    path: &'a str,
}

impl Recorded for FileRead<'_> {}

/// The columns of a root that `AlertSummary` reads.
struct AlertRow {
    id: Uuid,
    description: String,
    analysis_mode: String,
    event_time: Option<DateTime<Utc>>,
    event_time_source: String,
    created_at: DateTime<Utc>,
    alerted_at: DateTime<Utc>,
    disposition: Option<String>,
    dispositioned_at: Option<DateTime<Utc>>,
    dispositioned_by: Option<Value>,
    submitted_by: Option<Value>,
    pass: i32,
    completed_pass: i32,
    cancelled: bool,
}

impl AlertRow {
    fn summary(self) -> Result<AlertSummary, ServiceError> {
        let analysis = AnalysisState::of(self.pass, self.completed_pass, self.cancelled);
        Ok(AlertSummary {
            id: self.id,
            title: self.description,
            analysis_mode: self.analysis_mode,
            event_time: self.event_time,
            event_time_source: self.event_time_source,
            created_at: self.created_at,
            alerted_at: self.alerted_at,
            disposition: self.disposition,
            dispositioned_at: self.dispositioned_at,
            dispositioned_by: RecordedActor::from_row(self.dispositioned_by)?,
            submitted_by: RecordedActor::from_row(self.submitted_by)?,
            analysis,
        })
    }
}

pub(crate) fn page_limit(limit: Option<u32>, max: u32) -> Result<i64, ServiceError> {
    match limit {
        None => Ok(i64::from(max.min(100))),
        Some(limit) if (1..=max).contains(&limit) => Ok(i64::from(limit)),
        Some(limit) => Err(ServiceError::InvalidRequest(format!(
            "a page holds 1 to {max}, not {limit}"
        ))),
    }
}

/// `LIST_TIMEOUT` for the rest of a read's transaction.
pub(crate) const SET_LIST_TIMEOUT: &str = "SET LOCAL statement_timeout = '10s'";

/// A query cancelled by its timeout as a filter to narrow; anything else as it is.
pub(crate) fn timed_out(error: sqlx::Error) -> ServiceError {
    let cancelled = error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| code == "57014");
    if cancelled {
        ServiceError::InvalidRequest(format!(
            "the list took longer than {LIST_TIMEOUT} to read: narrow its filters"
        ))
    } else {
        error.into()
    }
}

pub(crate) fn no_alert(id: Uuid) -> ServiceError {
    ServiceError::NotFound(format!("no alert {id}"))
}

impl Service {
    /// A page of the alerts `query` matches, in its order, of up to `limit` (100 when None, at most
    /// `MAX_ALERTS_PAGE`), after the cursor `after`, a page's `next`. A cursor of another order, or one that
    /// names no alert, is `InvalidRequest`, and so is a filter the alert screen can't take
    /// (`filters::check`) or one that runs past `LIST_TIMEOUT`.
    pub async fn alerts(
        &self,
        actor: &crate::Actor,
        query: &AlertQuery,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> Result<AlertPage, ServiceError> {
        let limit = page_limit(limit, MAX_ALERTS_PAGE)?;
        let after = after
            .map(|after| AlertCursor::decode(after, query))
            .transpose()?;
        let page = self.alert_page(actor, query, limit, after.as_ref()).await?;
        if page.alerts.is_empty() && after.is_some() {
            // past the end, the page has no row to carry the total, so the first page counts
            let first = self.alert_page(actor, query, 1, None).await?;
            return Ok(AlertPage {
                total: first.total,
                ..page
            });
        }
        Ok(page)
    }

    async fn alert_page(
        &self,
        actor: &crate::Actor,
        query: &AlertQuery,
        limit: i64,
        after: Option<&AlertCursor>,
    ) -> Result<AlertPage, ServiceError> {
        let f = Resolved::new(FilterScreen::Alerts, &query.filters, Utc::now(), query.tz)?;
        let window = |slug, inverted| f.windows(slug, inverted).map(split);
        let ((a1, a2), (a3, a4)) = (window("alert_date", false)?, window("alert_date", true)?);
        let ((e1, e2), (e3, e4)) = (window("event_date", false)?, window("event_date", true)?);
        let ((d1, d2), (d3, d4)) = (
            window("disposition_date", false)?,
            window("disposition_date", true)?,
        );
        let ((o1, o2), (o3, o4)) = (split(f.observables(false)), split(f.observables(true)));
        let ((s1, s2), (s3, s4)) = (
            split(f.signatures("detection_point", false)),
            split(f.signatures("detection_point", true)),
        );
        let (described, not_described) = (
            f.patterns("description", false, false),
            f.patterns("description", true, false),
        );
        let (disposition, not_disposition) =
            (f.names("disposition", false), f.names("disposition", true));
        let (by, by_none) = f.names_or_none("disposition_by", false);
        let (not_by, not_by_none) = f.names_or_none("disposition_by", true);
        let (tagged, not_tagged) = (
            f.patterns("tag", false, true),
            f.patterns("tag", true, true),
        );
        let (analysis, not_analysis) = (f.names("analysis", false), f.names("analysis", true));
        let (unconfirmed, not_unconfirmed) = (
            f.names("unconfirmed_detections", false),
            f.names("unconfirmed_detections", true),
        );
        let (tp, fp) = self.disposition_classes().lists();
        let verdicts = (&unconfirmed, &not_unconfirmed, &tp, &fp);
        let sort = query.sort;
        let descending = query.descending;
        let after_id = after.map(|cursor| cursor.id);
        let after_key = after.and_then(|cursor| cursor.key.clone());
        let params = (
            (a1, a2, a3, a4),
            (e1, e2, e3, e4),
            (d1, d2, d3, d4),
            (o1, o2, o3, o4),
            (s1, s2, s3, s4),
        );
        let params = &params;
        let texts = (
            &described,
            &not_described,
            &disposition,
            &not_disposition,
            &by,
            &not_by,
            &tagged,
            &not_tagged,
            &analysis,
            &not_analysis,
        );
        let after_key = &after_key;
        self.gate
            .read(actor, "alerts", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let (
                        (a1, a2, a3, a4),
                        (e1, e2, e3, e4),
                        (d1, d2, d3, d4),
                        (o1, o2, o3, o4),
                        (s1, s2, s3, s4),
                    ) = params;
                    let (described, not_described, disposition, not_disposition, by, not_by, tagged, not_tagged, analysis, not_analysis) = texts;
                    let (unconfirmed, not_unconfirmed, tp, fp) = verdicts;
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    if let Some(after) = after_id {
                        let known = sqlx::query_scalar!(
                            r#"SELECT EXISTS (SELECT FROM analysis.roots
                                              WHERE id = $1 AND alerted_at IS NOT NULL) AS "known!""#,
                            after,
                        )
                        .fetch_one(tx.conn())
                        .await?;
                        if !known {
                            return Err(ServiceError::InvalidRequest(format!(
                                "the cursor names no alert {after}"
                            )));
                        }
                    }
                    let rows = sqlx::query!(
                        r#"WITH matched AS (
                             SELECT r.id, r.alerted_at,
                                    (CASE $1::text WHEN 'description' THEN r.description
                                                   WHEN 'disposition' THEN COALESCE(r.disposition, 'OPEN')
                                     END) COLLATE "C" AS k,
                                    count(*) OVER () AS total
                             FROM analysis.roots r
                             WHERE r.alerted_at IS NOT NULL
                               -- Alert Date, Event Date and Disposition Date: any of the windows, or none
                               AND ($6::timestamptz[] IS NULL OR EXISTS (
                                     SELECT FROM unnest($6::timestamptz[], $7::timestamptz[]) w(s, e)
                                     WHERE r.alerted_at BETWEEN w.s AND w.e))
                               AND ($8::timestamptz[] IS NULL OR NOT EXISTS (
                                     SELECT FROM unnest($8::timestamptz[], $9::timestamptz[]) w(s, e)
                                     WHERE r.alerted_at BETWEEN w.s AND w.e))
                               AND ($10::timestamptz[] IS NULL OR EXISTS (
                                     SELECT FROM unnest($10::timestamptz[], $11::timestamptz[]) w(s, e)
                                     WHERE r.event_time BETWEEN w.s AND w.e))
                               AND ($12::timestamptz[] IS NULL OR NOT EXISTS (
                                     SELECT FROM unnest($12::timestamptz[], $13::timestamptz[]) w(s, e)
                                     WHERE r.event_time BETWEEN w.s AND w.e))
                               AND ($14::timestamptz[] IS NULL OR EXISTS (
                                     SELECT FROM unnest($14::timestamptz[], $15::timestamptz[]) w(s, e)
                                     WHERE r.dispositioned_at BETWEEN w.s AND w.e))
                               AND ($16::timestamptz[] IS NULL OR NOT EXISTS (
                                     SELECT FROM unnest($16::timestamptz[], $17::timestamptz[]) w(s, e)
                                     WHERE r.dispositioned_at BETWEEN w.s AND w.e))
                               -- Description: contains any, case-insensitive
                               AND ($18::text[] IS NULL OR r.description ILIKE ANY ($18::text[]))
                               AND ($19::text[] IS NULL OR NOT r.description ILIKE ANY ($19::text[]))
                               -- Disposition, with OPEN for none
                               AND ($20::text[] IS NULL
                                    OR COALESCE(r.disposition, 'OPEN') = ANY ($20::text[]))
                               AND ($21::text[] IS NULL
                                    OR NOT COALESCE(r.disposition, 'OPEN') = ANY ($21::text[]))
                               -- Disposition By: the name the row recorded, or None for no disposition
                               AND ($22::text[] IS NULL
                                    OR (r.dispositioned_by ->> 'name') = ANY ($22::text[])
                                    OR ($23::boolean AND r.dispositioned_by IS NULL))
                               AND ($24::text[] IS NULL OR NOT COALESCE(
                                    (r.dispositioned_by ->> 'name') = ANY ($24::text[])
                                    OR ($25::boolean AND r.dispositioned_by IS NULL), false))
                               -- Observable: a (type, value) the alert holds, '' for any type
                               AND ($26::text[] IS NULL OR EXISTS (
                                     SELECT FROM analysis.observables o
                                     JOIN unnest($26::text[], $27::text[]) p(t, v)
                                       ON (p.t = '' OR o.type = p.t)
                                      AND o.value_hash = analysis.value_hash(p.v) AND o.value = p.v
                                     WHERE o.root_id = r.id))
                               AND ($28::text[] IS NULL OR NOT EXISTS (
                                     SELECT FROM analysis.observables o
                                     JOIN unnest($28::text[], $29::text[]) p(t, v)
                                       ON (p.t = '' OR o.type = p.t)
                                      AND o.value_hash = analysis.value_hash(p.v) AND o.value = p.v
                                     WHERE o.root_id = r.id))
                               -- Tag: on any of its observables or results, * matching anything
                               AND ($30::text[] IS NULL
                                    OR EXISTS (SELECT FROM analysis.observables o, unnest(o.tags) t(tag)
                                               WHERE o.root_id = r.id AND t.tag ILIKE ANY ($30::text[]))
                                    OR EXISTS (SELECT FROM analysis.results x, unnest(x.tags) t(tag)
                                               WHERE x.root_id = r.id AND t.tag ILIKE ANY ($30::text[])))
                               AND ($31::text[] IS NULL OR NOT (
                                    EXISTS (SELECT FROM analysis.observables o, unnest(o.tags) t(tag)
                                            WHERE o.root_id = r.id AND t.tag ILIKE ANY ($31::text[]))
                                    OR EXISTS (SELECT FROM analysis.results x, unnest(x.tags) t(tag)
                                               WHERE x.root_id = r.id AND t.tag ILIKE ANY ($31::text[]))))
                               -- Analysis: a result of one of the modules
                               AND ($32::text[] IS NULL OR EXISTS (
                                     SELECT FROM analysis.results x
                                     WHERE x.root_id = r.id AND x.module = ANY ($32::text[])))
                               AND ($33::text[] IS NULL OR NOT EXISTS (
                                     SELECT FROM analysis.results x
                                     WHERE x.root_id = r.id AND x.module = ANY ($33::text[])))
                               -- Detection Point: a detection by the signature, '' for any version
                               AND ($34::text[] IS NULL OR EXISTS (
                                     SELECT FROM analysis.detections d
                                     JOIN unnest($34::text[], $35::text[]) g(u, v)
                                       ON lower(d.signature_uuid) = g.u
                                      AND (g.v = '' OR d.signature_version = g.v)
                                     WHERE d.root_id = r.id))
                               AND ($36::text[] IS NULL OR NOT EXISTS (
                                     SELECT FROM analysis.detections d
                                     JOIN unnest($36::text[], $37::text[]) g(u, v)
                                       ON lower(d.signature_uuid) = g.u
                                      AND (g.v = '' OR d.signature_version = g.v)
                                     WHERE d.root_id = r.id))
                               -- Unconfirmed Detections: an inherited TP of several signatures' (7.14)
                               AND ($38::text[] IS NULL
                                    OR ('True' = ANY ($38::text[]) AND EXISTS (
                                     SELECT FROM analysis.detections d
                                     LEFT JOIN analysis.detection_verdicts v ON v.detection_id = d.id
                                     WHERE d.root_id = r.id
                                       AND analysis.detection_verdict_source(
                                             r.disposition, $40, $41, v.verdict,
                                             EXISTS (SELECT FROM analysis.detections x
                                                     WHERE x.root_id = d.root_id
                                                       AND x.signature_uuid IS DISTINCT FROM d.signature_uuid))
                                           = 'inherited_multi'))
                                    OR ('False' = ANY ($38::text[]) AND NOT EXISTS (
                                     SELECT FROM analysis.detections d
                                     LEFT JOIN analysis.detection_verdicts v ON v.detection_id = d.id
                                     WHERE d.root_id = r.id
                                       AND analysis.detection_verdict_source(
                                             r.disposition, $40, $41, v.verdict,
                                             EXISTS (SELECT FROM analysis.detections x
                                                     WHERE x.root_id = d.root_id
                                                       AND x.signature_uuid IS DISTINCT FROM d.signature_uuid))
                                           = 'inherited_multi')))
                               AND ($39::text[] IS NULL OR NOT (
                                    ('True' = ANY ($39::text[]) AND EXISTS (
                                     SELECT FROM analysis.detections d
                                     LEFT JOIN analysis.detection_verdicts v ON v.detection_id = d.id
                                     WHERE d.root_id = r.id
                                       AND analysis.detection_verdict_source(
                                             r.disposition, $40, $41, v.verdict,
                                             EXISTS (SELECT FROM analysis.detections x
                                                     WHERE x.root_id = d.root_id
                                                       AND x.signature_uuid IS DISTINCT FROM d.signature_uuid))
                                           = 'inherited_multi'))
                                    OR ('False' = ANY ($39::text[]) AND NOT EXISTS (
                                     SELECT FROM analysis.detections d
                                     LEFT JOIN analysis.detection_verdicts v ON v.detection_id = d.id
                                     WHERE d.root_id = r.id
                                       AND analysis.detection_verdict_source(
                                             r.disposition, $40, $41, v.verdict,
                                             EXISTS (SELECT FROM analysis.detections x
                                                     WHERE x.root_id = d.root_id
                                                       AND x.signature_uuid IS DISTINCT FROM d.signature_uuid))
                                           = 'inherited_multi'))))
                           )
                           SELECT r.id, r.description, r.analysis_mode, r.event_time,
                                  r.event_time_source::text AS "event_time_source!",
                                  r.created_at, r.alerted_at AS "alerted_at!", r.disposition,
                                  r.dispositioned_at,
                                  r.dispositioned_by AS "dispositioned_by: Value",
                                  r.submitted_by AS "submitted_by: Value",
                                  r.pass, r.completed_pass,
                                  r.cancelled_at IS NOT NULL AS "cancelled!",
                                  m.k AS "key?", m.total AS "total!"
                           FROM matched m JOIN analysis.roots r ON r.id = m.id
                           WHERE $3::uuid IS NULL OR CASE
                             WHEN $1 = 'alert_date' AND $2::boolean THEN (m.alerted_at, m.id) <
                               (SELECT a.alerted_at, a.id FROM analysis.roots a WHERE a.id = $3)
                             WHEN $1 = 'alert_date' THEN (m.alerted_at, m.id) >
                               (SELECT a.alerted_at, a.id FROM analysis.roots a WHERE a.id = $3)
                             WHEN $2 THEN (m.k, m.id) < (COALESCE($4::text,
                               (SELECT a.description FROM analysis.roots a WHERE a.id = $3)) COLLATE "C", $3)
                             ELSE (m.k, m.id) > (COALESCE($4::text,
                               (SELECT a.description FROM analysis.roots a WHERE a.id = $3)) COLLATE "C", $3)
                           END
                           ORDER BY
                             CASE WHEN $1 = 'alert_date' AND $2 THEN m.alerted_at END DESC,
                             CASE WHEN $1 = 'alert_date' AND NOT $2 THEN m.alerted_at END ASC,
                             CASE WHEN $1 <> 'alert_date' AND $2 THEN m.k END DESC,
                             CASE WHEN $1 <> 'alert_date' AND NOT $2 THEN m.k END ASC,
                             CASE WHEN $2 THEN m.id END DESC,
                             CASE WHEN NOT $2 THEN m.id END ASC
                           LIMIT $5"#,
                        sort.as_str(),
                        descending,
                        after_id,
                        after_key.as_deref(),
                        limit + 1,
                        a1.as_deref(),
                        a2.as_deref(),
                        a3.as_deref(),
                        a4.as_deref(),
                        e1.as_deref(),
                        e2.as_deref(),
                        e3.as_deref(),
                        e4.as_deref(),
                        d1.as_deref(),
                        d2.as_deref(),
                        d3.as_deref(),
                        d4.as_deref(),
                        described.as_deref(),
                        not_described.as_deref(),
                        disposition.as_deref(),
                        not_disposition.as_deref(),
                        by.as_deref(),
                        by_none,
                        not_by.as_deref(),
                        not_by_none,
                        o1.as_deref(),
                        o2.as_deref(),
                        o3.as_deref(),
                        o4.as_deref(),
                        tagged.as_deref(),
                        not_tagged.as_deref(),
                        analysis.as_deref(),
                        not_analysis.as_deref(),
                        s1.as_deref(),
                        s2.as_deref(),
                        s3.as_deref(),
                        s4.as_deref(),
                        unconfirmed.as_deref(),
                        not_unconfirmed.as_deref(),
                        tp,
                        fp,
                    )
                    .fetch_all(tx.conn())
                    .await
                    .map_err(timed_out)?;
                    let total = rows.first().map_or(0, |row| row.total);
                    let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
                    let mut alerts = Vec::with_capacity(rows.len());
                    let mut last_key = None;
                    for row in rows.into_iter().take(usize::try_from(limit).unwrap_or(usize::MAX)) {
                        last_key = row.key;
                        alerts.push(
                            AlertRow {
                                id: row.id,
                                description: row.description,
                                analysis_mode: row.analysis_mode,
                                event_time: row.event_time,
                                event_time_source: row.event_time_source,
                                created_at: row.created_at,
                                alerted_at: row.alerted_at,
                                disposition: row.disposition,
                                dispositioned_at: row.dispositioned_at,
                                dispositioned_by: row.dispositioned_by,
                                submitted_by: row.submitted_by,
                                pass: row.pass,
                                completed_pass: row.completed_pass,
                                cancelled: row.cancelled,
                            }
                            .summary()?,
                        );
                    }
                    let next = match alerts.last() {
                        Some(last) if more => Some(
                            AlertCursor {
                                sort,
                                descending,
                                id: last.id,
                                key: (sort == AlertSort::Disposition).then(|| last_key.unwrap_or_default()),
                            }
                            .encode(),
                        ),
                        _ => None,
                    };
                    Ok(AlertPage {
                        alerts,
                        next,
                        total,
                    })
                })
            })
            .await
    }

    /// One alert, with how many observables, files and detections it has.
    pub async fn alert(&self, actor: &crate::Actor, id: Uuid) -> Result<Alert, ServiceError> {
        self.gate
            .read(actor, "alert", &ALERT_READ, &|tx| {
                Box::pin(async move { alert_in(tx, id).await })
            })
            .await
    }

    /// A page of an alert's observables in the order they were added, each with its files, relationships,
    /// results and detections, of up to `limit` (100 when None, at most `MAX_OBSERVABLES_PAGE`) after the
    /// observable `after` names.
    pub async fn alert_observables(
        &self,
        actor: &crate::Actor,
        id: Uuid,
        limit: Option<u32>,
        after: Option<i64>,
    ) -> Result<ObservablePage, ServiceError> {
        let limit = page_limit(limit, MAX_OBSERVABLES_PAGE)?;
        self.gate
            .read(actor, "alert_observables", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let alert = sqlx::query_scalar!(
                        "SELECT alerted_at IS NOT NULL FROM analysis.roots WHERE id = $1",
                        id,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .flatten();
                    if alert != Some(true) {
                        return Err(no_alert(id));
                    }
                    let (observables, more) = observables_in(tx, id, after, limit).await?;
                    let next = if more {
                        observables.last().map(|observable| observable.id)
                    } else {
                        None
                    };
                    Ok(ObservablePage { observables, next })
                })
            })
            .await
    }

    /// Lets an actor download a file observable of an alert, and records that they did, as ace3's
    /// download routes log it. It needs `alert:read`. The caller fetches the bytes by the hash: the row
    /// says the file was asked for, and is written whether or not the bytes then arrive.
    pub async fn download_file(
        &self,
        actor: &crate::Actor,
        id: Uuid,
        observable: i64,
    ) -> Result<FileDownload, ServiceError> {
        self.gate
            .write(actor, "download_file", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let found = sqlx::query!(
                        r#"SELECT o.type, o.value, r.alerted_at IS NOT NULL AS "alert!",
                                  (SELECT f.path FROM analysis.files f
                                   WHERE f.root_id = o.root_id AND f.observable_id = o.id
                                   ORDER BY f.analyzed DESC, f.depth, f.path COLLATE "C"
                                   LIMIT 1) AS path
                           FROM analysis.observables o
                           JOIN analysis.roots r ON r.id = o.root_id
                           WHERE o.root_id = $1 AND o.id = $2"#,
                        id,
                        observable,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let Some(found) = found.filter(|found| found.alert) else {
                        return Err(ServiceError::NotFound(format!(
                            "no observable {observable} in alert {id}"
                        )));
                    };
                    let Some(path) = found.path.filter(|_| found.r#type == "file") else {
                        return Err(ServiceError::InvalidRequest(format!(
                            "observable {observable} isn't a file"
                        )));
                    };
                    let change = Change::read(
                        Target::observable(id, observable),
                        &FileRead {
                            sha256: &found.value,
                            path: &path,
                        },
                    )?;
                    Ok(Audited::changed(
                        FileDownload {
                            sha256: found.value,
                            path,
                        },
                        change,
                    ))
                })
            })
            .await
    }
}

/// One alert and its counts, in a read's transaction.
pub(crate) async fn alert_in(
    tx: &mut ace_core::db::Tx<'_>,
    id: Uuid,
) -> Result<Alert, ServiceError> {
    let row = sqlx::query_as!(
        AlertRow,
        r#"SELECT r.id, r.description, r.analysis_mode, r.event_time,
                  r.event_time_source::text AS "event_time_source!",
                  r.created_at, r.alerted_at AS "alerted_at!", r.disposition,
                  r.dispositioned_at,
                  r.dispositioned_by AS "dispositioned_by: Value",
                  r.submitted_by AS "submitted_by: Value",
                  r.pass, r.completed_pass,
                  r.cancelled_at IS NOT NULL AS "cancelled!"
           FROM analysis.roots r
           WHERE r.id = $1 AND r.alerted_at IS NOT NULL"#,
        id,
    )
    .fetch_optional(tx.conn())
    .await?
    .ok_or_else(|| no_alert(id))?;
    let counts = sqlx::query!(
        r#"SELECT
             (SELECT count(*) FROM analysis.observables WHERE root_id = $1) AS "observables!",
             (SELECT count(*) FROM analysis.files WHERE root_id = $1) AS "files!",
             (SELECT count(*) FROM analysis.detections WHERE root_id = $1) AS "detections!""#,
        id,
    )
    .fetch_one(tx.conn())
    .await?;
    Ok(Alert {
        summary: row.summary()?,
        observables: counts.observables,
        files: counts.files,
        detections: counts.detections,
    })
}

/// Up to `limit` of an alert's observables after `after`, in the order they were added, each with its
/// files, relationships, results and detections, and whether there are more.
pub(crate) async fn observables_in(
    tx: &mut ace_core::db::Tx<'_>,
    id: Uuid,
    after: Option<i64>,
    limit: i64,
) -> Result<(Vec<AlertObservable>, bool), ServiceError> {
    let mut rows = sqlx::query!(
        "SELECT id, type, value, time, tags, directives, exclude_modules,
                redirection_type, redirection_value, display_type, display_value, ignored
         FROM analysis.observables
         WHERE root_id = $1 AND id > $2
         ORDER BY id LIMIT $3",
        id,
        after.unwrap_or(0),
        limit + 1,
    )
    .fetch_all(tx.conn())
    .await?;
    let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let ids: Vec<i64> = rows.iter().map(|row| row.id).collect();
    let mut observables: Vec<AlertObservable> = rows
        .into_iter()
        .map(|row| AlertObservable {
            id: row.id,
            kind: row.r#type,
            value: row.value,
            time: row.time,
            tags: row.tags,
            directives: row.directives,
            exclude_modules: row.exclude_modules,
            redirection: row.redirection_type.zip(row.redirection_value),
            display_type: row.display_type,
            display_value: row.display_value,
            ignored: row.ignored,
            files: Vec::new(),
            relationships: Vec::new(),
            results: Vec::new(),
            detections: Vec::new(),
        })
        .collect();
    let at = |observable: i64| ids.binary_search(&observable).ok();

    for row in sqlx::query!(
        r#"SELECT observable_id, path, yara_meta FROM analysis.files
           WHERE root_id = $1 AND observable_id = ANY($2)
           ORDER BY observable_id, analyzed DESC, depth, path COLLATE "C""#,
        id,
        &ids,
    )
    .fetch_all(tx.conn())
    .await?
    {
        if let Some(i) = at(row.observable_id) {
            observables[i].files.push(AlertFile {
                path: row.path,
                yara_meta: row.yara_meta,
            });
        }
    }
    for row in sqlx::query!(
        "SELECT observable_id, kind, target_type, target_value
         FROM analysis.relationships
         WHERE root_id = $1 AND observable_id = ANY($2)
         ORDER BY observable_id, kind, target_type, target_value",
        id,
        &ids,
    )
    .fetch_all(tx.conn())
    .await?
    {
        if let Some(i) = at(row.observable_id) {
            observables[i].relationships.push(Relationship {
                kind: row.kind,
                target_type: row.target_type,
                target_value: row.target_value,
            });
        }
    }
    for row in sqlx::query!(
        "SELECT id, observable_id, module, analysis_type, schema_version, summary, tags,
                details, created_at
         FROM analysis.results
         WHERE root_id = $1 AND observable_id = ANY($2)
         ORDER BY observable_id, module",
        id,
        &ids,
    )
    .fetch_all(tx.conn())
    .await?
    {
        if let Some(i) = at(row.observable_id) {
            observables[i].results.push(ModuleResult {
                id: row.id,
                module: row.module,
                analysis_type: row.analysis_type,
                schema_version: row.schema_version,
                summary: row.summary,
                tags: row.tags,
                details: row.details,
                created_at: row.created_at,
            });
        }
    }
    for row in sqlx::query!(
        r#"SELECT d.observable_id, d.description, d.details,
                  r.module AS "module?"
           FROM analysis.detections d
           LEFT JOIN analysis.results r ON r.id = d.result_id
           WHERE d.root_id = $1 AND d.observable_id = ANY($2)
           ORDER BY d.id"#,
        id,
        &ids,
    )
    .fetch_all(tx.conn())
    .await?
    {
        if let Some(i) = row.observable_id.and_then(at) {
            observables[i].detections.push(AlertDetection {
                description: row.description,
                details: row.details,
                module: row.module,
            });
        }
    }
    Ok((observables, more))
}
