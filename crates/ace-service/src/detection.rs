//! The observables ACE detects wherever they appear (PLAN.md 7.6), ace3's `aceapi_v2/detection`
//! service and its `observable_detections` table, for 5.6's `detection` router and 5.11's
//! `admin/detection.html`.
//!
//! A detection is an entry on 5.14's `observable_detection` list, which the `observable_detection`
//! module reads on each leased task (`ace_sdk::Module::LISTS`): an exact, case-sensitive value of one
//! observable type, with an optional expiry, and ace3's detection context as the entry's note. So a
//! detection added here applies to the next task that checks an observable, with no restart and no
//! export: ace3 copies its table to Redis every minute (`ace observables export`) and its module reads
//! the copy. The list is the binary's: a build whose modules don't read it has no detections, and every
//! function here answers 404.
//!
//! Reading needs `detection:read`, and adding, removing and setting an expiry need `detection:write`,
//! ace3's names. A write goes through the `lists` service's own steps (`lists::add_entry` and the rest),
//! so it's checked, raises the lists' version and has the same audit row as a list write, under this
//! service's action names.
//!
//! As in ace3:
//! - A listing is ordered by type, value and id, filtered by a search of the value, a type and whether
//!   the detection is active (no expiry, or one still to come), expired, or either, and paged with 25,
//!   50, 100 or 200 a page (50 otherwise), its page clamped to the pages there are. A search with a `*`
//!   in it is a pattern, each `*` any run of characters and nothing else added, so `*.ru` anchors; any
//!   other is found anywhere in the value. Either ignores case, and `%`, `_` and `\` are themselves.
//! - A new detection takes the type's default lifetime unless it says otherwise, and an explicit none
//!   never expires: ace3's `observable_expiration_default` (90 days) and `observable_expiration_mappings`
//!   (`sha256` and `md5` never), a type taking its nearest listed ancestor's. Its context defaults to
//!   `manually added by <name>`.
//! - A second detection of the same type and value is a conflict. A detection's comments are the
//!   observable's (`observable_comments`), oldest first, shown read-only.
//!
//! The detections are also YARA rules of the ruleset the core builds (PLAN.md 7.16,
//! `ace_core::rulesets`, ace3's `saq/observables/export/yara.py`), so one matches a file's content too.
//! `detection_export` says what the current ruleset holds of them and which were left out, which ace3
//! only logs.
//!
//! What differs:
//! - ace3 runs a value through its observable class, which normalizes some types. ace-rs's observables
//!   have no normalization: a `file` value is trimmed, lowercased and has to be a sha256, as ace3's is,
//!   and any other value is stored as given, up to 4096 bytes, the list's limit. ace3 checks the type
//!   against its registry; here it's one this binary has.
//! - ace3's `batch_id` has no column on a list entry, and nothing in ace-rs sends one. Its `fa_hits` and
//!   `observable_id` come from its index of every observable, which ace-rs doesn't have.
//! - ace3 sets any expiry. Here, as on every list, a new expiry has to be in the future: a detection is
//!   turned off by removing it, which ace3's page offers too.
//! - A list holds at most 1000 entries (`ace_sdk::lists::MAX_ENTRIES`), where ace3's table has no limit.
//! - ace3 orders values by its column's case-insensitive collation; here they're in the database's.

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sqlx::PgConnection;

use ace_results::ObservableKind;
use ace_sdk::lists::{ListSpec, MatchKind};

use crate::actor::Actor;
use crate::alerts::RecordedActor;
use crate::gate::Audited;
use crate::lists::{
    ListEntry, NewListEntry, add_entry, delete_entry, edit_entry, entry_row, now, spec,
};
use crate::observable_comments::{CommentRow, ObservableComment};
use crate::observables::normalized;
use crate::permission::{DETECTION_READ, DETECTION_WRITE};
use crate::{Service, ServiceError};

/// The list the detections are, which the `observable_detection` module reads.
pub const DETECTION_LIST: &str = "observable_detection";
/// The page sizes a listing takes, ace3's `PAGE_SIZE_CHOICES`.
pub const DETECTION_PAGE_SIZES: [i64; 4] = [25, 50, 100, 200];
/// The page size of a listing that asks for none of those.
pub const DEFAULT_DETECTION_PAGE_SIZE: i64 = 50;
/// A new detection's lifetime unless its type's says otherwise: ace3's
/// `observable_expiration_default`.
pub const DEFAULT_DETECTION_LIFETIME_DAYS: i64 = 90;
/// The types whose detections never expire unless one says otherwise, with their descendants: ace3's
/// `observable_expiration_mappings`, since a hash names the same content forever.
pub const NEVER_EXPIRING_TYPES: [&str; 2] = ["sha256", "md5"];

/// Which detections a listing has, by expiry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DetectionStatus {
    /// No expiry, or one still to come.
    #[default]
    Active,
    Expired,
    All,
}

impl DetectionStatus {
    pub const ALL: [DetectionStatus; 3] = [
        DetectionStatus::Active,
        DetectionStatus::Expired,
        DetectionStatus::All,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DetectionStatus::Active => "active",
            DetectionStatus::Expired => "expired",
            DetectionStatus::All => "all",
        }
    }

    pub fn parse(text: &str) -> Option<DetectionStatus> {
        DetectionStatus::ALL
            .into_iter()
            .find(|status| status.as_str() == text)
    }
}

/// What a listing asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionFilter {
    /// Part of the value, or a pattern with `*`.
    pub search: Option<String>,
    pub observable_type: Option<String>,
    pub status: DetectionStatus,
    /// 1-based, clamped to the pages there are.
    pub page: i64,
    /// One of `DETECTION_PAGE_SIZES`, else `DEFAULT_DETECTION_PAGE_SIZE`.
    pub page_size: i64,
}

impl Default for DetectionFilter {
    fn default() -> Self {
        DetectionFilter {
            search: None,
            observable_type: None,
            status: DetectionStatus::Active,
            page: 1,
            page_size: DEFAULT_DETECTION_PAGE_SIZE,
        }
    }
}

/// `page_size` if a listing takes it, else the default: ace3's `clamp_page_size`.
pub fn clamp_detection_page_size(page_size: i64) -> i64 {
    if DETECTION_PAGE_SIZES.contains(&page_size) {
        page_size
    } else {
        DEFAULT_DETECTION_PAGE_SIZE
    }
}

/// An observable ACE detects.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    /// The list entry's id.
    pub id: i64,
    pub observable_type: String,
    pub value: String,
    pub expires_at: Option<DateTime<Utc>>,
    /// Its expiry passed.
    pub expired: bool,
    /// Why it's there: ace3's detection context.
    pub context: String,
    pub created_by: RecordedActor,
    pub created_at: DateTime<Utc>,
    pub modified_by: RecordedActor,
    pub modified_at: DateTime<Utc>,
    /// The observable's comments, oldest first. Empty where a function doesn't read them.
    pub comments: Vec<ObservableComment>,
}

impl Detection {
    fn of(entry: ListEntry, now: DateTime<Utc>) -> Detection {
        Detection {
            id: entry.id,
            observable_type: entry.observable_type.unwrap_or_default(),
            value: entry.value,
            expired: entry.expires_at.is_some_and(|expires| expires <= now),
            expires_at: entry.expires_at,
            context: entry.note,
            created_by: entry.created_by,
            created_at: entry.created_at,
            modified_by: entry.updated_by,
            modified_at: entry.updated_at,
            comments: Vec::new(),
        }
    }
}

/// One page of detections, and what a pager needs.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionPage {
    pub items: Vec<Detection>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
    pub total_pages: i64,
}

impl DetectionPage {
    /// The 1-based place of the page's first detection, 0 when it has none.
    pub fn first_index(&self) -> i64 {
        if self.items.is_empty() {
            0
        } else {
            (self.page - 1) * self.page_size + 1
        }
    }

    pub fn last_index(&self) -> i64 {
        (self.page - 1) * self.page_size + self.items.len() as i64
    }

    pub fn has_prev(&self) -> bool {
        self.page > 1
    }

    pub fn has_next(&self) -> bool {
        self.page < self.total_pages
    }
}

/// The types for a listing's filter and a new detection's form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionTypes {
    /// The types that have a detection, in name order.
    pub present: Vec<String>,
    /// Every type this binary has that isn't deprecated, in name order.
    pub all: Vec<String>,
}

/// When a new detection expires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DetectionExpiry {
    /// Its type's default lifetime.
    #[default]
    Default,
    Never,
    At(DateTime<Utc>),
}

/// A detection to add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDetection {
    pub observable_type: String,
    pub value: String,
    pub expires: DetectionExpiry,
    /// Why; `manually added by <name>` when None.
    pub context: Option<String>,
}

/// The default expiry of a new detection of `kind`, from `now`.
pub fn default_detection_expiry(kind: ObservableKind, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let never = std::iter::once(kind)
        .chain(kind.ancestors())
        .any(|k| NEVER_EXPIRING_TYPES.contains(&k.as_str()));
    (!never).then(|| now + Duration::days(DEFAULT_DETECTION_LIFETIME_DAYS))
}

/// The name an actor goes by, for a detection's default context.
fn actor_name(actor: &Actor) -> String {
    match actor {
        Actor::User { name, .. } | Actor::ApiKey { name, .. } => name.clone(),
        Actor::Internal { id } => id.as_str().to_owned(),
    }
}

/// The type and value a detection of `kind` and `value` is stored as, or why it can't be one.
pub fn detection_identity(
    kind: &str,
    value: &str,
) -> Result<(ObservableKind, String), ServiceError> {
    let parsed: ObservableKind = kind
        .parse()
        .map_err(|_| ServiceError::InvalidRequest(format!("no observable type {kind:?}")))?;
    let value = if parsed == ObservableKind::File {
        value.trim()
    } else {
        value
    };
    normalized(parsed.as_str(), value)
        .map_err(|why| ServiceError::InvalidRequest(format!("not a {parsed} value: {why}")))
}

/// The list as this binary has it, or a 404.
fn detection_list(catalog: &ace_core::eligibility::Catalog) -> Result<ListSpec, ServiceError> {
    spec(catalog, DETECTION_LIST)
}

fn no_detection(id: i64) -> ServiceError {
    ServiceError::NotFound(format!("no detection {id}"))
}

/// The search's ILIKE pattern: ace3's `_search_pattern`.
pub fn detection_search_pattern(search: &str) -> String {
    let escaped = search
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    if search.contains('*') {
        escaped.replace('*', "%")
    } else {
        format!("%{escaped}%")
    }
}

struct DetectionRow {
    id: i64,
    observable_type: Option<String>,
    value: String,
    note: String,
    expires_at: Option<DateTime<Utc>>,
    created_by: Value,
    created_at: DateTime<Utc>,
    updated_by: Value,
    updated_at: DateTime<Utc>,
}

impl DetectionRow {
    fn into_detection(self, now: DateTime<Utc>) -> Result<Detection, ServiceError> {
        let actor = |value| {
            RecordedActor::from_row(Some(value))?
                .ok_or_else(|| ServiceError::from(ace_core::DbError::Decode("no actor".to_owned())))
        };
        Ok(Detection {
            id: self.id,
            observable_type: self.observable_type.unwrap_or_default(),
            value: self.value,
            expired: self.expires_at.is_some_and(|expires| expires <= now),
            expires_at: self.expires_at,
            context: self.note,
            created_by: actor(self.created_by)?,
            created_at: self.created_at,
            modified_by: actor(self.updated_by)?,
            modified_at: self.updated_at,
            comments: Vec::new(),
        })
    }
}

/// The comments on each detection's observable, oldest first, read in one query.
async fn add_comments(
    conn: &mut PgConnection,
    detections: &mut [Detection],
) -> Result<(), ServiceError> {
    if detections.is_empty() {
        return Ok(());
    }
    let kinds: Vec<String> = detections
        .iter()
        .map(|d| d.observable_type.clone())
        .collect();
    let values: Vec<String> = detections.iter().map(|d| d.value.clone()).collect();
    let rows = sqlx::query_as!(
        CommentRow,
        r#"SELECT c.id, c.type AS kind, c.value, c.author_id, u.username::text AS "username!",
                  u.display_name, c.created_by AS "created_by!: Value", c.comment, c.created_at,
                  c.edited_at
           FROM analysis.observable_comments c JOIN service.users u ON u.id = c.author_id
           WHERE (c.type, c.value_hash, c.value) IN (
               SELECT k, analysis.value_hash(v), v FROM unnest($1::text[], $2::text[]) AS w(k, v))
           ORDER BY c.created_at, c.id"#,
        &kinds,
        &values,
    )
    .fetch_all(conn)
    .await?;
    for row in rows {
        let comment = row.into_comment()?;
        for detection in detections.iter_mut() {
            if detection.observable_type == comment.kind && detection.value == comment.value {
                detection.comments.push(comment.clone());
            }
        }
    }
    Ok(())
}

/// The ruleset the YARA export of the detections is in: the latest the core built.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionExportRuleset {
    /// The serialized ruleset's sha256.
    pub key: String,
    pub commit: String,
    pub built_at: DateTime<Utc>,
}

/// One exported type's rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionExportType {
    pub observable_type: String,
    /// How many detections its rule holds, and how many strings they are.
    pub detections: i64,
    pub strings: i64,
}

/// A detection the export left out. The error is the compiler's or the export's, and may quote the
/// value: text to show, never markup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionExportSkipped {
    pub id: i64,
    /// The type it would have been exported under.
    pub observable_type: String,
    /// The detection's value as it is now; None when it's gone since the build.
    pub value: Option<String>,
    pub error: String,
}

/// What the current ruleset holds of the detections as YARA rules (PLAN.md 7.16).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DetectionExport {
    /// None when no ruleset has been built: the core builds none without a signatures repository.
    pub ruleset: Option<DetectionExportRuleset>,
    /// The detections in the ruleset's rules.
    pub exported: i64,
    pub types: Vec<DetectionExportType>,
    pub skipped: Vec<DetectionExportSkipped>,
    /// Why nothing was exported, when the generated files didn't load together.
    pub error: Option<String>,
}

impl Service {
    /// What the current ruleset holds of the detections as YARA rules: each exported type, and each
    /// detection left out with why (PLAN.md 7.16, `ace_core::rulesets`). A detection added since the
    /// ruleset was built is in neither until the next build, a minute away at most. It needs
    /// `detection:read`.
    pub async fn detection_export(&self, actor: &Actor) -> Result<DetectionExport, ServiceError> {
        let components = self.orchestrator.catalog();
        let catalog = &*components;
        self.gate
            .read(actor, "detection_export", &DETECTION_READ, &|tx| {
                Box::pin(async move {
                    let spec = detection_list(catalog)?;
                    let Some(ruleset) = ace_core::rulesets::current_with(tx.conn()).await? else {
                        return Ok(DetectionExport::default());
                    };
                    let report = ruleset.detection_export.unwrap_or_default();
                    let ids: Vec<i64> = report.skipped.iter().map(|s| s.id).collect();
                    let values: std::collections::BTreeMap<i64, String> = sqlx::query!(
                        "SELECT id, value FROM lists.entries WHERE list = $1 AND id = ANY($2)",
                        spec.name,
                        &ids,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|row| (row.id, row.value))
                    .collect();
                    Ok(DetectionExport {
                        ruleset: Some(DetectionExportRuleset {
                            key: ruleset.key.to_hex(),
                            commit: ruleset.commit,
                            built_at: ruleset.built_at,
                        }),
                        exported: report.exported() as i64,
                        types: report
                            .types
                            .into_iter()
                            .map(|t| DetectionExportType {
                                observable_type: t.export_type,
                                detections: t.detections as i64,
                                strings: t.strings as i64,
                            })
                            .collect(),
                        skipped: report
                            .skipped
                            .into_iter()
                            .map(|s| DetectionExportSkipped {
                                value: values.get(&s.id).cloned(),
                                id: s.id,
                                observable_type: s.export_type,
                                error: s.error,
                            })
                            .collect(),
                        error: report.error,
                    })
                })
            })
            .await
    }

    /// A page of the detections, with their comments. It needs `detection:read`.
    pub async fn detections(
        &self,
        actor: &Actor,
        filter: &DetectionFilter,
    ) -> Result<DetectionPage, ServiceError> {
        let components = self.orchestrator.catalog();
        let catalog = &*components;
        self.gate
            .read(actor, "detections", &DETECTION_READ, &|tx| {
                Box::pin(async move {
                    let spec = detection_list(catalog)?;
                    let now = now(tx.conn()).await?;
                    let search = filter
                        .search
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .map(detection_search_pattern);
                    let kind = filter.observable_type.as_deref().filter(|s| !s.is_empty());
                    let status = filter.status.as_str();
                    let page_size = clamp_detection_page_size(filter.page_size);
                    let total = sqlx::query_scalar!(
                        r#"SELECT count(*) AS "count!" FROM lists.entries
                           WHERE list = $1
                             AND ($2::text IS NULL OR observable_type = $2)
                             AND ($3::text IS NULL OR value ILIKE $3 ESCAPE '\')
                             AND CASE $4::text
                                   WHEN 'active' THEN expires_at IS NULL OR expires_at > $5
                                   WHEN 'expired' THEN expires_at <= $5
                                   ELSE true END"#,
                        spec.name,
                        kind,
                        search,
                        status,
                        now,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let total_pages = ((total + page_size - 1) / page_size).max(1);
                    let page = filter.page.clamp(1, total_pages);
                    let mut items = sqlx::query_as!(
                        DetectionRow,
                        r#"SELECT id, observable_type, value, note, expires_at,
                                  created_by AS "created_by!: Value", created_at,
                                  updated_by AS "updated_by!: Value", updated_at
                           FROM lists.entries
                           WHERE list = $1
                             AND ($2::text IS NULL OR observable_type = $2)
                             AND ($3::text IS NULL OR value ILIKE $3 ESCAPE '\')
                             AND CASE $4::text
                                   WHEN 'active' THEN expires_at IS NULL OR expires_at > $5
                                   WHEN 'expired' THEN expires_at <= $5
                                   ELSE true END
                           ORDER BY observable_type, value, id
                           LIMIT $6 OFFSET $7"#,
                        spec.name,
                        kind,
                        search,
                        status,
                        now,
                        page_size,
                        (page - 1) * page_size,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|row| row.into_detection(now))
                    .collect::<Result<Vec<_>, _>>()?;
                    add_comments(tx.conn(), &mut items).await?;
                    Ok(DetectionPage {
                        items,
                        total,
                        page,
                        page_size,
                        total_pages,
                    })
                })
            })
            .await
    }

    /// The types that have a detection, and every type a new one can be of. It needs
    /// `detection:read`.
    pub async fn detection_types(&self, actor: &Actor) -> Result<DetectionTypes, ServiceError> {
        let components = self.orchestrator.catalog();
        let catalog = &*components;
        self.gate
            .read(actor, "detection_types", &DETECTION_READ, &|tx| {
                Box::pin(async move {
                    let spec = detection_list(catalog)?;
                    let present = sqlx::query_scalar!(
                        r#"SELECT DISTINCT observable_type AS "observable_type!" FROM lists.entries
                           WHERE list = $1 AND observable_type IS NOT NULL
                           ORDER BY 1"#,
                        spec.name,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let mut all: Vec<String> = ObservableKind::all()
                        .iter()
                        .filter(|kind| !kind.is_deprecated())
                        .map(|kind| kind.as_str().to_owned())
                        .collect();
                    all.sort();
                    Ok(DetectionTypes { present, all })
                })
            })
            .await
    }

    /// Adds a detection. It needs `detection:write`, applies to the next task that checks an
    /// observable, and is audited as a list entry's addition.
    pub async fn create_detection(
        &self,
        actor: &Actor,
        detection: &NewDetection,
    ) -> Result<Detection, ServiceError> {
        let components = self.orchestrator.catalog();
        let catalog = &*components;
        self.gate
            .write(actor, "create_detection", &DETECTION_WRITE, &|tx| {
                Box::pin(async move {
                    let spec = detection_list(catalog)?;
                    let (kind, value) =
                        detection_identity(&detection.observable_type, &detection.value)?;
                    let now = now(tx.conn()).await?;
                    let existing = sqlx::query_scalar!(
                        "SELECT id FROM lists.entries
                         WHERE list = $1 AND observable_type = $2 AND value = $3",
                        spec.name,
                        kind.as_str(),
                        value,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    if existing.is_some() {
                        return Err(ServiceError::Conflict(format!(
                            "a detection already exists for {kind} {value}"
                        )));
                    }
                    let entry = NewListEntry {
                        kind: MatchKind::Exact,
                        value,
                        ignore_case: false,
                        observable_type: Some(kind.as_str().to_owned()),
                        note: detection
                            .context
                            .clone()
                            .unwrap_or_else(|| format!("manually added by {}", actor_name(actor))),
                        expires_at: match detection.expires {
                            DetectionExpiry::Default => default_detection_expiry(kind, now),
                            DetectionExpiry::Never => None,
                            DetectionExpiry::At(at) => Some(at),
                        },
                    };
                    let (added, change) = add_entry(tx.conn(), actor, &spec, &entry).await?;
                    Ok(Audited::changed(Detection::of(added, now), change))
                })
            })
            .await
    }

    /// Removes a detection, which is how one is turned off, and returns it as it was. It needs
    /// `detection:write`, and its audit row keeps the whole entry.
    pub async fn delete_detection(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<Detection, ServiceError> {
        let components = self.orchestrator.catalog();
        let catalog = &*components;
        self.gate
            .write(actor, "delete_detection", &DETECTION_WRITE, &|tx| {
                Box::pin(async move {
                    let spec = detection_list(catalog)?;
                    let now = now(tx.conn()).await?;
                    let (removed, change) =
                        delete_entry(tx.conn(), &spec, id)
                            .await
                            .map_err(|e| match e {
                                ServiceError::NotFound(_) => no_detection(id),
                                e => e,
                            })?;
                    Ok(Audited::changed(Detection::of(removed, now), change))
                })
            })
            .await
    }

    /// Sets when a detection expires; None never. It needs `detection:write`. Setting what it has
    /// changes nothing and has no audit row.
    pub async fn set_detection_expiration(
        &self,
        actor: &Actor,
        id: i64,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Detection, ServiceError> {
        let components = self.orchestrator.catalog();
        let catalog = &*components;
        self.gate
            .write(actor, "set_detection_expiration", &DETECTION_WRITE, &|tx| {
                Box::pin(async move {
                    let spec = detection_list(catalog)?;
                    let now = now(tx.conn()).await?;
                    let (entry, change) = edit_entry(tx.conn(), actor, &spec, id, &|before| {
                        Ok(NewListEntry {
                            expires_at,
                            ..before.clone()
                        })
                    })
                    .await
                    .map_err(|e| match e {
                        ServiceError::NotFound(_) => no_detection(id),
                        e => e,
                    })?;
                    let mut detection = Detection::of(entry, now);
                    add_comments(tx.conn(), std::slice::from_mut(&mut detection)).await?;
                    Ok(match change {
                        Some(change) => Audited::changed(detection, change),
                        None => Audited::unchanged(detection),
                    })
                })
            })
            .await
    }

    /// One detection, with its comments, for a page that shows it after a write. It needs
    /// `detection:read`.
    pub async fn detection(&self, actor: &Actor, id: i64) -> Result<Detection, ServiceError> {
        let components = self.orchestrator.catalog();
        let catalog = &*components;
        self.gate
            .read(actor, "detection", &DETECTION_READ, &|tx| {
                Box::pin(async move {
                    let spec = detection_list(catalog)?;
                    let now = now(tx.conn()).await?;
                    let entry = entry_row(tx.conn(), spec.name, id)
                        .await
                        .map_err(|e| match e {
                            ServiceError::NotFound(_) => no_detection(id),
                            e => e,
                        })?;
                    let mut detection = Detection::of(entry, now);
                    add_comments(tx.conn(), std::slice::from_mut(&mut detection)).await?;
                    Ok(detection)
                })
            })
            .await
    }
}
