//! YARA QA (PLAN.md 2.27), for 5.6's `yara_qa` router: the rules in QA mode, what they matched, the files,
//! and purges.
//!
//! A rule whose `modifiers` hold `qa` is tried on live traffic without alerting. The core's recorder keeps
//! one row of `yara.qa_matches` per (rule uuid, rule version, file) for 30 days after the file last
//! matched, and holds the file in the bucket's `alert_files` pool for as long (`ace_core::yara_qa`). The
//! rules in QA mode now come from the current ruleset's row (2.25), which lists them whether or not they
//! ever matched, as ace3's rule inventory does. A rule shows up here when it's in QA mode in that ruleset
//! or has matches recorded.
//!
//! Permissions are ace3's: `signature:read` for the rules, the matches and a match's record,
//! `signature:download` for anything holding a matched file, which is live malware, and
//! `signature:qa_purge` to purge. A download goes through `Gate::write` with a row of what was read, as
//! ace3 logs one. A purge is a write: it deletes the matches and releases only their own holds on their
//! files in one transaction with its audit row, so a file a root or another match still holds stays
//! (`ace_core::yara_qa::purge_in`).
//!
//! A row past its expiry isn't listed or served: its hold has lapsed, and the bucket's GC may have taken
//! the file. It still counts towards `match_count`, and a purge removes it.
//!
//! Everything here that came from a rule or a file is data: a rule's name, uuid, meta and tags are what
//! its author wrote, a match's record holds bytes of the file, and a file's path is what the alert's sender
//! named it. Nothing reads it, and the adapters return it as strings.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use ace_core::bucket::ALERT_FILES;
use ace_core::db::Tx;
use ace_core::rulesets::{self, QaRule};
use ace_core::yara_qa::{self, MAX_PURGE, PurgeTarget, QaError};
use ace_results::types::yara::ScanResult;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{SIGNATURE_DOWNLOAD, SIGNATURE_QA_PURGE, SIGNATURE_READ};
use crate::{Service, ServiceError};

/// The most rules or matches one page holds, as ace3's.
pub const MAX_QA_PAGE: u32 = 500;
/// A page's size when none is asked for, as ace3's.
const DEFAULT_QA_PAGE: u32 = 50;
/// The most files one download holds, ace3's `yara_qa.max_bulk_download_files`.
pub const MAX_QA_DOWNLOAD_FILES: usize = 500;
/// The most bytes of files one download holds, ace3's `yara_qa.max_bulk_download_bytes`.
pub const MAX_QA_DOWNLOAD_BYTES: i64 = 1 << 30;
/// The most versions one purge names, as ace3's.
pub const MAX_PURGE_VERSIONS: usize = 1000;
/// The most characters of a purge's reason, as ace3's.
pub const MAX_PURGE_REASON: usize = 1024;

/// Whether a rule is in QA mode in the current ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QaStatus {
    /// It is.
    Qa,
    /// It has matches recorded, and no rule in QA mode in the current ruleset has its uuid: it left QA
    /// mode or the repository. ace3 tells those two apart; the manifest records only QA rules.
    NotQa,
}

impl QaStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            QaStatus::Qa => "qa",
            QaStatus::NotQa => "not_qa",
        }
    }
}

/// How a list of rules is ordered, as ace3's: by name, by when it last matched, or by its matches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum QaSort {
    #[default]
    Name,
    LastMatch,
    MatchCount,
}

/// Which rules to list. Every filter that's set must match.
#[derive(Debug, Clone, Default)]
pub struct QaRuleFilter {
    /// A substring of the rule's name, uuid, namespace or file, in any case.
    pub q: Option<String>,
    pub status: Option<QaStatus>,
    /// Only rules that have matched (true) or haven't (false).
    pub has_matches: Option<bool>,
    pub sort: QaSort,
    pub descending: bool,
}

/// The ruleset the list of QA rules came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QaRuleset {
    /// Its key, the sha256 of its bytes.
    pub key: String,
    pub commit: String,
    pub built_at: DateTime<Utc>,
    /// False for a ruleset built before its QA rules were recorded: the builder fills them in on its next
    /// run, and until then a rule that never matched is missing from the list.
    pub qa_rules_recorded: bool,
}

/// What was recorded for one version of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QaVersion {
    /// The commit of the rule's repository, or `unknown`.
    pub signature_version: String,
    /// The rule's name and namespace when it last matched under this version.
    pub rule: String,
    pub namespace: String,
    /// Every match under this version.
    pub match_count: i64,
    /// The files kept under this version, which haven't expired.
    pub stored_count: i64,
    pub first_match_at: DateTime<Utc>,
    pub last_match_at: DateTime<Utc>,
}

/// A rule in QA mode now, or one with matches recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QaRuleSummary {
    pub signature_uuid: String,
    /// Its name in the current ruleset, or when it last matched.
    pub name: String,
    pub status: QaStatus,
    /// Its `enabled` meta in the current ruleset; None when it's not a QA rule there.
    pub enabled: Option<bool>,
    /// Its namespace in the current ruleset, or when it last matched.
    pub namespace: Option<String>,
    /// Its file in the current ruleset, relative to the signature directory.
    pub path: Option<String>,
    pub tags: Vec<String>,
    pub match_count: i64,
    pub stored_count: i64,
    pub version_count: usize,
    pub first_match_at: Option<DateTime<Utc>>,
    pub last_match_at: Option<DateTime<Utc>>,
}

/// A page of rules, and how many match the filters across pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QaRulePage {
    pub rules: Vec<QaRuleSummary>,
    pub total: usize,
    /// None when no ruleset has been built, and then only rules with matches are listed.
    pub ruleset: Option<QaRuleset>,
}

/// One rule, with its counts per version, most recently matched first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QaRuleDetail {
    pub rule: QaRuleSummary,
    pub versions: Vec<QaVersion>,
    pub ruleset: Option<QaRuleset>,
}

/// One kept file of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QaMatch {
    pub id: i64,
    pub signature_uuid: String,
    pub signature_version: String,
    pub rule: String,
    pub namespace: String,
    /// The key of the ruleset the rule came from, when the scan used one the core built.
    pub ruleset: Option<String>,
    pub sha256: String,
    /// The file's path in the alert when it last matched.
    pub file_path: String,
    /// The file's size, or None when the bucket no longer has it.
    pub file_size: Option<i64>,
    /// The root it was found in when it last matched, which may be gone, and whether it's an alert.
    pub root: Uuid,
    pub alerted: bool,
    pub observable_id: i64,
    /// How many times this file matched this version of the rule.
    pub hit_count: i32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// When it's let go unless it matches again.
    pub expires_at: DateTime<Utc>,
}

/// A page of a rule's matches, newest first, and the cursor for the next, None on the last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QaMatchPage {
    pub matches: Vec<QaMatch>,
    pub next: Option<i64>,
}

/// How often one of a rule's strings matched, and where first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QaStringSummary {
    pub identifier: String,
    pub count: usize,
    pub first_offset: u64,
}

/// A match's record in short: the rule as it matched and, per string, how often and where first. The
/// whole record is `qa_match_record`'s.
#[derive(Debug, Clone, PartialEq)]
pub struct QaMatchSummary {
    pub meta: Map<String, Value>,
    pub tags: Vec<String>,
    pub commit: Option<String>,
    pub strings: Vec<QaStringSummary>,
}

/// One match, with its record in short, or None when the record isn't one the scanner writes.
#[derive(Debug, Clone, PartialEq)]
pub struct QaMatchDetail {
    pub qa_match: QaMatch,
    pub summary: Option<QaMatchSummary>,
}

/// A match to download: what's recorded and its whole record. The caller fetches the file from the
/// bucket's `alert_files` pool by its hash.
#[derive(Debug, Clone, PartialEq)]
pub struct QaDownload {
    pub qa_match: QaMatch,
    pub record: Value,
}

/// What a purge removes from one rule: every match of some versions, or some matches. Exactly one of the
/// two.
#[derive(Debug, Clone, Default)]
pub struct QaPurge {
    pub versions: Option<Vec<String>>,
    pub match_ids: Option<Vec<i64>>,
    /// Why, for the audit row: at most 1024 characters.
    pub reason: Option<String>,
}

/// What a purge did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QaPurged {
    /// The matches removed, by id. Their files go at the bucket's GC once nothing else holds them.
    pub purged: Vec<i64>,
    /// Matches of the target past the `MAX_PURGE` this purge removed, which purging again removes.
    pub remaining: i64,
}

fn page_limit(limit: Option<u32>) -> Result<i64, ServiceError> {
    match limit.unwrap_or(DEFAULT_QA_PAGE) {
        limit @ 1..=MAX_QA_PAGE => Ok(i64::from(limit)),
        limit => Err(ServiceError::InvalidRequest(format!(
            "a page holds 1 to {MAX_QA_PAGE}, not {limit}"
        ))),
    }
}

fn no_match(id: i64) -> ServiceError {
    ServiceError::NotFound(format!("no kept YARA QA match {id}"))
}

impl From<QaError> for ServiceError {
    fn from(error: QaError) -> Self {
        match error {
            QaError::Bucket(e) => ServiceError::Bucket(e),
            QaError::Db(e) => ServiceError::from(e),
            QaError::Queue(e) => ServiceError::Orchestrator(e.into()),
            // a row that breaks its own table's rules
            QaError::Invalid(why) => ServiceError::from(ace_core::db::DbError::Decode(why)),
        }
    }
}

/// The current ruleset and its QA rules, empty when it has none recorded.
async fn current_ruleset(
    tx: &mut Tx<'_>,
) -> Result<(Option<QaRuleset>, Vec<QaRule>), ServiceError> {
    let Some(row) = rulesets::current_with(tx.conn()).await? else {
        return Ok((None, Vec::new()));
    };
    let ruleset = QaRuleset {
        key: row.key.to_hex(),
        commit: row.commit,
        built_at: row.built_at,
        qa_rules_recorded: row.qa_rules.is_some(),
    };
    Ok((Some(ruleset), row.qa_rules.unwrap_or_default()))
}

/// Each rule's versions, by uuid, most recently matched first; one rule's when `only` is set.
async fn versions(
    tx: &mut Tx<'_>,
    only: Option<&str>,
) -> Result<BTreeMap<String, Vec<QaVersion>>, ServiceError> {
    let rows = sqlx::query!(
        r#"SELECT signature_uuid, signature_version,
                  (array_agg(rule ORDER BY last_seen DESC, id DESC))[1] AS "rule!",
                  (array_agg(namespace ORDER BY last_seen DESC, id DESC))[1] AS "namespace!",
                  sum(hit_count)::bigint AS "match_count!",
                  count(*) FILTER (WHERE expires_at > now()) AS "stored_count!",
                  min(first_seen) AS "first_match_at!", max(last_seen) AS "last_match_at!"
           FROM yara.qa_matches
           WHERE $1::text IS NULL OR signature_uuid = $1
           GROUP BY signature_uuid, signature_version"#,
        only,
    )
    .fetch_all(tx.conn())
    .await?;
    let mut by_uuid: BTreeMap<String, Vec<QaVersion>> = BTreeMap::new();
    for row in rows {
        by_uuid
            .entry(row.signature_uuid)
            .or_default()
            .push(QaVersion {
                signature_version: row.signature_version,
                rule: row.rule,
                namespace: row.namespace,
                match_count: row.match_count,
                stored_count: row.stored_count,
                first_match_at: row.first_match_at,
                last_match_at: row.last_match_at,
            });
    }
    for versions in by_uuid.values_mut() {
        versions.sort_by(|a, b| {
            (b.last_match_at, &b.signature_version).cmp(&(a.last_match_at, &a.signature_version))
        });
    }
    Ok(by_uuid)
}

/// One summary per uuid that's a QA rule in `qa_rules` or has versions, as ace3's `merge`. A uuid two QA
/// rules share takes the first's name, and a QA rule without a uuid isn't listed: nothing it matches is
/// kept.
fn merge(
    qa_rules: &[QaRule],
    mut versions: BTreeMap<String, Vec<QaVersion>>,
) -> Vec<(QaRuleSummary, Vec<QaVersion>)> {
    let mut merged: BTreeMap<String, QaRuleSummary> = BTreeMap::new();
    for rule in qa_rules {
        let Some(uuid) = rule.uuid.as_ref() else {
            continue;
        };
        merged.entry(uuid.clone()).or_insert_with(|| QaRuleSummary {
            signature_uuid: uuid.clone(),
            name: rule.name.clone(),
            status: QaStatus::Qa,
            enabled: Some(rule.enabled),
            namespace: Some(rule.namespace.clone()),
            path: Some(rule.path.clone()),
            tags: rule.tags.clone(),
            match_count: 0,
            stored_count: 0,
            version_count: 0,
            first_match_at: None,
            last_match_at: None,
        });
    }
    for (uuid, versions) in &versions {
        let latest = &versions[0];
        let summary = merged.entry(uuid.clone()).or_insert_with(|| QaRuleSummary {
            signature_uuid: uuid.clone(),
            name: latest.rule.clone(),
            status: QaStatus::NotQa,
            enabled: None,
            namespace: Some(latest.namespace.clone()),
            path: None,
            tags: Vec::new(),
            match_count: 0,
            stored_count: 0,
            version_count: 0,
            first_match_at: None,
            last_match_at: None,
        });
        summary.match_count = versions.iter().map(|v| v.match_count).sum();
        summary.stored_count = versions.iter().map(|v| v.stored_count).sum();
        summary.version_count = versions.len();
        summary.first_match_at = versions.iter().map(|v| v.first_match_at).min();
        summary.last_match_at = Some(latest.last_match_at);
    }
    merged
        .into_values()
        .map(|summary| {
            let versions = versions.remove(&summary.signature_uuid).unwrap_or_default();
            (summary, versions)
        })
        .collect()
}

/// `filter`'s rules in its order, as ace3's `filter_and_sort`.
fn filter_and_sort(mut rules: Vec<QaRuleSummary>, filter: &QaRuleFilter) -> Vec<QaRuleSummary> {
    if let Some(needle) = filter.q.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        let needle = needle.to_lowercase();
        let has =
            |text: Option<&str>| text.is_some_and(|text| text.to_lowercase().contains(&needle));
        rules.retain(|rule| {
            has(Some(&rule.name))
                || has(Some(&rule.signature_uuid))
                || has(rule.namespace.as_deref())
                || has(rule.path.as_deref())
        });
    }
    if let Some(status) = filter.status {
        rules.retain(|rule| rule.status == status);
    }
    if let Some(has_matches) = filter.has_matches {
        rules.retain(|rule| (rule.match_count > 0) == has_matches);
    }
    let by_name = |a: &QaRuleSummary, b: &QaRuleSummary| {
        (a.name.to_lowercase(), &a.signature_uuid).cmp(&(b.name.to_lowercase(), &b.signature_uuid))
    };
    rules.sort_by(|a, b| {
        let order = match filter.sort {
            QaSort::Name => Ordering::Equal,
            QaSort::LastMatch => a.last_match_at.cmp(&b.last_match_at),
            QaSort::MatchCount => a.match_count.cmp(&b.match_count),
        };
        order.then_with(|| by_name(a, b))
    });
    if filter.descending {
        rules.reverse();
    }
    rules
}

/// A kept match as it reads, with its file's size and its root's state.
struct MatchRow {
    id: i64,
    signature_uuid: String,
    signature_version: String,
    rule: String,
    namespace: String,
    ruleset: Option<String>,
    sha256: String,
    file_path: String,
    file_size: Option<i64>,
    root_id: Uuid,
    alerted: bool,
    observable_id: i64,
    hit_count: i32,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    record: Value,
}

impl MatchRow {
    fn qa_match(&self) -> QaMatch {
        QaMatch {
            id: self.id,
            signature_uuid: self.signature_uuid.clone(),
            signature_version: self.signature_version.clone(),
            rule: self.rule.clone(),
            namespace: self.namespace.clone(),
            ruleset: self.ruleset.clone(),
            sha256: self.sha256.clone(),
            file_path: self.file_path.clone(),
            file_size: self.file_size,
            root: self.root_id,
            alerted: self.alerted,
            observable_id: self.observable_id,
            hit_count: self.hit_count,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            expires_at: self.expires_at,
        }
    }
}

/// Kept matches, newest first: one rule's, of one version when `version` is set, these when `ids` is set,
/// before the id `before`, up to `limit`; or the one `id` names.
#[allow(clippy::too_many_arguments)]
async fn match_rows(
    tx: &mut Tx<'_>,
    id: Option<i64>,
    signature_uuid: Option<&str>,
    version: Option<&str>,
    ids: Option<&[i64]>,
    before: Option<i64>,
    limit: i64,
    ascending: bool,
) -> Result<Vec<MatchRow>, ServiceError> {
    Ok(sqlx::query_as!(
        MatchRow,
        r#"SELECT q.id, q.signature_uuid, q.signature_version, q.rule, q.namespace, q.ruleset,
                  q.sha256, q.file_path, s.size AS "file_size?", q.root_id,
                  coalesce(r.alerted_at IS NOT NULL, false) AS "alerted!", q.observable_id,
                  q.hit_count, q.first_seen, q.last_seen, q.expires_at, q.match AS record
           FROM yara.qa_matches q
           LEFT JOIN store.objects s
             ON s.pool = $8 AND s.sha256 = q.sha256 AND s.state = 'present'
           LEFT JOIN analysis.roots r ON r.id = q.root_id
           WHERE q.expires_at > now()
             AND ($1::bigint IS NULL OR q.id = $1)
             AND ($2::text IS NULL OR q.signature_uuid = $2)
             AND ($3::text IS NULL OR q.signature_version = $3)
             AND ($4::bigint[] IS NULL OR q.id = ANY($4))
             AND ($5::bigint IS NULL OR q.id < $5)
           ORDER BY CASE WHEN $7 THEN q.id END, q.id DESC
           LIMIT $6"#,
        id,
        signature_uuid,
        version,
        ids,
        before,
        limit,
        ascending,
        ALERT_FILES,
    )
    .fetch_all(tx.conn())
    .await?)
}

async fn one_match(tx: &mut Tx<'_>, id: i64) -> Result<MatchRow, ServiceError> {
    match_rows(tx, Some(id), None, None, None, None, 1, false)
        .await?
        .pop()
        .ok_or_else(|| no_match(id))
}

/// A record in short, or None when it isn't one the scanner writes.
fn summarize(record: &Value) -> Option<QaMatchSummary> {
    let scan: ScanResult = serde_json::from_value(record.clone()).ok()?;
    let mut strings: Vec<QaStringSummary> = Vec::new();
    for (offset, identifier, _) in &scan.strings {
        match strings.iter_mut().find(|s| s.identifier == *identifier) {
            Some(seen) => {
                seen.count += 1;
                seen.first_offset = seen.first_offset.min(*offset);
            }
            None => strings.push(QaStringSummary {
                identifier: identifier.clone(),
                count: 1,
                first_offset: *offset,
            }),
        }
    }
    Some(QaMatchSummary {
        meta: scan.meta,
        tags: scan.tags,
        commit: scan.commit,
        strings,
    })
}

/// A download's audit row for one match.
#[derive(Serialize)]
struct QaMatchRead<'a> {
    signature_uuid: &'a str,
    signature_version: &'a str,
    sha256: &'a str,
}

impl Recorded for QaMatchRead<'_> {}

#[derive(Serialize)]
struct QaFileRead<'a> {
    id: i64,
    sha256: &'a str,
}

/// A download's audit row for a rule's matches.
#[derive(Serialize)]
struct QaMatchesRead<'a> {
    version: Option<&'a str>,
    matches: Vec<QaFileRead<'a>>,
}

impl Recorded for QaMatchesRead<'_> {}

#[derive(Serialize)]
struct PurgedMatch<'a> {
    id: i64,
    signature_version: &'a str,
    sha256: &'a str,
    root: Uuid,
}

/// A purge's audit row: what it removed.
#[derive(Serialize)]
struct PurgedMatches<'a> {
    matches: Vec<PurgedMatch<'a>>,
}

impl Recorded for PurgedMatches<'_> {}

/// A purge's audit row: what was asked, and why.
#[derive(Serialize)]
struct PurgeRequest<'a> {
    versions: Option<&'a [String]>,
    match_ids: Option<&'a [i64]>,
    reason: Option<&'a str>,
    remaining: i64,
}

impl Recorded for PurgeRequest<'_> {}

/// Refuses a purge before it runs, so a refused one has no row.
fn check_purge(purge: &QaPurge) -> Result<PurgeTarget<'_>, ServiceError> {
    if purge
        .reason
        .as_ref()
        .is_some_and(|reason| reason.chars().count() > MAX_PURGE_REASON)
    {
        return Err(ServiceError::InvalidRequest(format!(
            "a reason is at most {MAX_PURGE_REASON} characters"
        )));
    }
    match (&purge.versions, &purge.match_ids) {
        (Some(versions), None) if versions.is_empty() || versions.len() > MAX_PURGE_VERSIONS => {
            Err(ServiceError::InvalidRequest(format!(
                "give 1 to {MAX_PURGE_VERSIONS} versions"
            )))
        }
        (Some(versions), None) => Ok(PurgeTarget::Versions(versions)),
        (None, Some(ids)) if ids.is_empty() || ids.len() > MAX_PURGE => {
            Err(ServiceError::InvalidRequest(format!(
                "give 1 to {MAX_PURGE} match ids, or purge by version"
            )))
        }
        (None, Some(ids)) => Ok(PurgeTarget::Matches(ids)),
        _ => Err(ServiceError::InvalidRequest(
            "give versions or match_ids, not both".to_owned(),
        )),
    }
}

impl Service {
    /// A page of the rules in QA mode in the current ruleset and the rules with matches recorded, as
    /// ace3 lists them: filtered and ordered by `filter`, `limit` of them (50 when None, at most
    /// `MAX_QA_PAGE`) after the first `offset`. The list is built whole from the ruleset's row and one
    /// count per rule version, so an offset into it costs nothing more.
    pub async fn qa_rules(
        &self,
        actor: &crate::Actor,
        filter: &QaRuleFilter,
        limit: Option<u32>,
        offset: u32,
    ) -> Result<QaRulePage, ServiceError> {
        let limit = usize::try_from(page_limit(limit)?).unwrap_or(usize::MAX);
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        self.gate
            .read(actor, "qa_rules", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let (ruleset, qa_rules) = current_ruleset(tx).await?;
                    let versions = versions(tx, None).await?;
                    let rules = merge(&qa_rules, versions)
                        .into_iter()
                        .map(|(summary, _)| summary)
                        .collect();
                    let rules = filter_and_sort(rules, filter);
                    Ok(QaRulePage {
                        total: rules.len(),
                        rules: rules.into_iter().skip(offset).take(limit).collect(),
                        ruleset,
                    })
                })
            })
            .await
    }

    /// One rule in QA mode or with matches recorded, with its counts per version.
    pub async fn qa_rule(
        &self,
        actor: &crate::Actor,
        signature_uuid: &str,
    ) -> Result<QaRuleDetail, ServiceError> {
        self.gate
            .read(actor, "qa_rule", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let (ruleset, qa_rules) = current_ruleset(tx).await?;
                    let versions = versions(tx, Some(signature_uuid)).await?;
                    let (rule, versions) = merge(&qa_rules, versions)
                        .into_iter()
                        .find(|(rule, _)| rule.signature_uuid == signature_uuid)
                        .ok_or_else(|| {
                            ServiceError::NotFound(
                                "no rule in QA mode and no QA matches with that uuid".to_owned(),
                            )
                        })?;
                    Ok(QaRuleDetail {
                        rule,
                        versions,
                        ruleset,
                    })
                })
            })
            .await
    }

    /// A page of a rule's kept matches, newest first, of one version when `version` is set: up to
    /// `limit` (50 when None, at most `MAX_QA_PAGE`) before the match `after` names.
    pub async fn qa_matches(
        &self,
        actor: &crate::Actor,
        signature_uuid: &str,
        version: Option<&str>,
        limit: Option<u32>,
        after: Option<i64>,
    ) -> Result<QaMatchPage, ServiceError> {
        let limit = page_limit(limit)?;
        self.gate
            .read(actor, "qa_matches", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let mut matches: Vec<QaMatch> = match_rows(
                        tx,
                        None,
                        Some(signature_uuid),
                        version,
                        None,
                        after,
                        limit + 1,
                        false,
                    )
                    .await?
                    .iter()
                    .map(MatchRow::qa_match)
                    .collect();
                    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
                    let more = matches.len() > limit;
                    matches.truncate(limit);
                    let next = if more {
                        matches.last().map(|m| m.id)
                    } else {
                        None
                    };
                    Ok(QaMatchPage { matches, next })
                })
            })
            .await
    }

    /// One kept match, with its record in short.
    pub async fn qa_match(
        &self,
        actor: &crate::Actor,
        id: i64,
    ) -> Result<QaMatchDetail, ServiceError> {
        self.gate
            .read(actor, "qa_match", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let row = one_match(tx, id).await?;
                    Ok(QaMatchDetail {
                        qa_match: row.qa_match(),
                        summary: summarize(&row.record),
                    })
                })
            })
            .await
    }

    /// A kept match's whole record as the YARA module wrote it, never cut short. It holds bytes of the
    /// file, as ace3's does, and ace3 serves it under `signature:read` without a log line.
    pub async fn qa_match_record(
        &self,
        actor: &crate::Actor,
        id: i64,
    ) -> Result<Value, ServiceError> {
        self.gate
            .read(actor, "qa_match_record", &SIGNATURE_READ, &|tx| {
                Box::pin(async move { Ok(one_match(tx, id).await?.record) })
            })
            .await
    }

    /// Lets an actor download a kept match's file and record, and records that they did, as ace3 logs it.
    /// It needs `signature:download`.
    pub async fn download_qa_match(
        &self,
        actor: &crate::Actor,
        id: i64,
    ) -> Result<QaDownload, ServiceError> {
        self.gate
            .write(actor, "download_qa_match", &SIGNATURE_DOWNLOAD, &|tx| {
                Box::pin(async move {
                    let row = one_match(tx, id).await?;
                    let change = Change::read(
                        Target::qa_match(id),
                        &QaMatchRead {
                            signature_uuid: &row.signature_uuid,
                            signature_version: &row.signature_version,
                            sha256: &row.sha256,
                        },
                    )?;
                    let download = QaDownload {
                        qa_match: row.qa_match(),
                        record: row.record,
                    };
                    Ok(Audited::changed(download, change))
                })
            })
            .await
    }

    /// Lets an actor download a rule's kept matches, of one version when `version` is set, or those
    /// `match_ids` names, each of which has to be one of the rule's, and records that they did. At most
    /// `MAX_QA_DOWNLOAD_FILES` files and `MAX_QA_DOWNLOAD_BYTES` bytes, as ace3's limits; past either it's
    /// `TooLarge`. It needs `signature:download`.
    pub async fn download_qa_matches(
        &self,
        actor: &crate::Actor,
        signature_uuid: &str,
        version: Option<&str>,
        match_ids: &[i64],
    ) -> Result<Vec<QaDownload>, ServiceError> {
        if match_ids.len() > MAX_QA_DOWNLOAD_FILES {
            return Err(ServiceError::TooLarge(format!(
                "more than {MAX_QA_DOWNLOAD_FILES} files; narrow the download by version or match_id"
            )));
        }
        let ids = (!match_ids.is_empty()).then_some(match_ids);
        let limit = i64::try_from(MAX_QA_DOWNLOAD_FILES + 1).unwrap_or(i64::MAX);
        self.gate
            .write(actor, "download_qa_matches", &SIGNATURE_DOWNLOAD, &|tx| {
                Box::pin(async move {
                    let rows = match_rows(
                        tx,
                        None,
                        Some(signature_uuid),
                        version,
                        ids,
                        None,
                        limit,
                        true,
                    )
                    .await?;
                    if let Some(ids) = ids {
                        let mut missing: Vec<i64> = ids
                            .iter()
                            .copied()
                            .filter(|id| !rows.iter().any(|row| row.id == *id))
                            .collect();
                        missing.sort_unstable();
                        missing.dedup();
                        if !missing.is_empty() {
                            return Err(ServiceError::NotFound(format!(
                                "no kept matches of this rule with ids {missing:?}"
                            )));
                        }
                    }
                    if rows.is_empty() {
                        return Err(ServiceError::NotFound("no kept matches to download".to_owned()));
                    }
                    if rows.len() > MAX_QA_DOWNLOAD_FILES {
                        return Err(ServiceError::TooLarge(format!(
                            "more than {MAX_QA_DOWNLOAD_FILES} files; narrow the download by version or match_id"
                        )));
                    }
                    let bytes: i64 = rows.iter().filter_map(|row| row.file_size).sum();
                    if bytes > MAX_QA_DOWNLOAD_BYTES {
                        return Err(ServiceError::TooLarge(format!(
                            "{bytes} bytes is more than {MAX_QA_DOWNLOAD_BYTES}; narrow the download by version or match_id"
                        )));
                    }
                    let change = Change::read(
                        Target::qa_rule(signature_uuid),
                        &QaMatchesRead {
                            version,
                            matches: rows
                                .iter()
                                .map(|row| QaFileRead {
                                    id: row.id,
                                    sha256: &row.sha256,
                                })
                                .collect(),
                        },
                    )?;
                    let downloads = rows
                        .into_iter()
                        .map(|row| QaDownload {
                            qa_match: row.qa_match(),
                            record: row.record,
                        })
                        .collect();
                    Ok(Audited::changed(downloads, change))
                })
            })
            .await
    }

    /// Purges a rule's matches: every match of some versions, or some matches, up to `MAX_PURGE` of them,
    /// expired or not. Each one's own hold on its file goes with it, in the same transaction as the audit
    /// row, which lists each match removed and the request with its reason; a file a root or another match
    /// still holds stays. A purge that finds nothing has no row. It needs `signature:qa_purge`.
    pub async fn purge_qa_matches(
        &self,
        actor: &crate::Actor,
        signature_uuid: &str,
        purge: &QaPurge,
    ) -> Result<QaPurged, ServiceError> {
        let target = check_purge(purge)?;
        self.gate
            .write(actor, "purge_qa_matches", &SIGNATURE_QA_PURGE, &|tx| {
                Box::pin(async move {
                    let (purged, remaining) = yara_qa::purge_in(tx, signature_uuid, target).await?;
                    let result = QaPurged {
                        purged: purged.iter().map(|p| p.id).collect(),
                        remaining,
                    };
                    if purged.is_empty() {
                        return Ok(Audited::unchanged(result));
                    }
                    let change = Change::removed(
                        Target::qa_rule(signature_uuid),
                        &PurgedMatches {
                            matches: purged
                                .iter()
                                .map(|p| PurgedMatch {
                                    id: p.id,
                                    signature_version: &p.signature_version,
                                    sha256: &p.sha256,
                                    root: p.root_id,
                                })
                                .collect(),
                        },
                    )?
                    .details(&PurgeRequest {
                        versions: purge.versions.as_deref(),
                        match_ids: purge.match_ids.as_deref(),
                        reason: purge.reason.as_deref(),
                        remaining,
                    })?;
                    Ok(Audited::changed(result, change))
                })
            })
            .await
    }

    /// ace3's daily `ace yara-qa prune` (PLAN.md 6.7): removes the matches past their expiry, 30 days
    /// after the file last matched, with their holds on the files, in batches of `MAX_PURGE`, each batch
    /// a transaction with its audit row listing the matches it removed. It stops at a batch that comes
    /// back short. Expired matches are already not listed or served, so this only frees the rows and
    /// lets the bucket's GC take a file nothing else holds. The scheduler's `yara_qa_prune` task calls
    /// it as the component `scheduler:yara_qa_prune`, which migration 0036 grants `signature:qa_purge`,
    /// the purge's own permission; ace3's prune runs under none.
    pub async fn prune_qa_matches(&self, actor: &crate::Actor) -> Result<QaPruned, ServiceError> {
        let mut pruned = QaPruned::default();
        loop {
            let removed = self
                .gate
                .write(actor, "prune_qa_matches", &SIGNATURE_QA_PURGE, &|tx| {
                    Box::pin(async move {
                        let removed = yara_qa::prune_expired_in(tx).await?;
                        let count = removed.len();
                        if removed.is_empty() {
                            return Ok(Audited::unchanged(count));
                        }
                        let change = Change::removed(
                            Target::expired_qa_matches(),
                            &PurgedMatches {
                                matches: removed
                                    .iter()
                                    .map(|p| PurgedMatch {
                                        id: p.id,
                                        signature_version: &p.signature_version,
                                        sha256: &p.sha256,
                                        root: p.root_id,
                                    })
                                    .collect(),
                            },
                        )?;
                        Ok(Audited::changed(count, change))
                    })
                })
                .await?;
            pruned.removed += removed as u64;
            if removed > 0 {
                pruned.batches += 1;
            }
            if removed < MAX_PURGE {
                return Ok(pruned);
            }
        }
    }
}

/// What a prune of expired QA matches removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct QaPruned {
    pub removed: u64,
    /// Transactions that removed matches, each with its audit row.
    pub batches: u64,
}
