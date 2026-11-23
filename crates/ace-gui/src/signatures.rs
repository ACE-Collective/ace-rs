//! The signatures area (PLAN.md 5.11's `signatures` area): ace3's `app/signatures/` views and
//! `app/templates/signatures/`, the hub and YARA QA, over 5.6's `yara_qa` service.
//!
//! `signature:read` gates the whole area, as ace3's blueprint-level `require_signatures_area_access`
//! does: every route here checks it first, and a page or a write then needs its own permission, which the
//! service checks: `signature:download` for a file and `signature:qa_purge` for a purge. A user without
//! `signature:read` gets 403, and a visitor who isn't signed in goes to the login. The base layout links
//! to `/signatures` for whoever holds `signature:read`, as ace3's navigation does.
//!
//! ace3's YARA QA page is a shell that `signatures_yara_qa.js` fills from `/api/v2/signatures/yara-qa`.
//! Here the server draws each page, every control is a link or a form, and ace3's script's parts are
//! these:
//! - `signatures.signatures_hub` (`hub.html`): `GET /signatures`, a tile for each page the viewer may
//!   open: Samples (`svs_samples`, 7.10 batch 2), YARA QA and Validations (`svs_validations`, batch 3).
//! - `signatures.yara_qa` (`yara_qa.html`): `GET /signatures/yara-qa`, the rules in QA mode and the rules
//!   with matches kept (`Service::qa_rules`), with ace3's filters as a `GET` form, its search, status,
//!   matches, sort, descending and page size, and its pages as Previous and Next links. ace3's status
//!   `missing` (removed) isn't one: ace-rs's ruleset records only its QA rules, so a rule that left QA mode
//!   and one that left the repository are both `not_qa` (5.6). The warning for rules that couldn't be
//!   read is the ruleset's: none built, or built before its QA rules were recorded.
//! - A rule's row, which ace3's script expands in place, is its own page, `GET
//!   /signatures/yara-qa/rules/{uuid}` (`qa_rule`, `qa_matches`): its versions, each a link that shows its
//!   files, and its kept files, 25 a page, newest first, with First and Next links, since the service's
//!   cursor goes one way. The version loaded now is the current ruleset's commit, where ace3 also has a
//!   rule's content hash, which ace-rs doesn't record.
//! - ace3's match modal is `GET /signatures/yara-qa/matches/{id}` (`qa_match`): the rule as it matched,
//!   each string's count and first offset, and its meta as JSON, with a link to the whole record.
//! - Downloads are links to the API's audited downloads, which take the session cookie
//!   (`/api/yara-qa/v1/...`): a file, a version's or a rule's files. Download selected is the rule page's
//!   form, sent to `GET /signatures/yara-qa/rules/{uuid}/download`, which sends the browser to the API's
//!   download with those ids, so the download and its audit row are the API's.
//! - A purge is destructive, so it's two steps where ace3's script has a `window.confirm`: Purge selected,
//!   Purge this version and Purge older versions each go to `GET /signatures/yara-qa/rules/{uuid}/purge`,
//!   which lists what will go and asks for a reason; its form posts to the same path, a `SignedIn` post
//!   that has passed 5.7's same-origin check, through `Service::purge_qa_matches`, which checks
//!   `signature:qa_purge` and writes the audit row with the reason. The answer says how many went, and
//!   offers to purge again when more than one purge's 500 were asked for.
//!
//! Everything a rule or a file brings is text: a rule's name, uuid, namespace, file, tags, meta and
//! version, a string's identifier, and a file's path. askama escapes it, and a uuid or a version in a link
//! is percent-encoded, so a link is always a path on this site.
//!
//! Left out: ace3's copy-the-uuid button and its select-all box, which need a script; its alert link's
//! `?direct=`, which is `/alerts/{id}` here; and its note that a file is on another node, since ace-rs's
//! files are in one bucket. ace3's folder holds four more pages: `samples.html` and `sample_detail.html`,
//! with `_samples_page.html`, are `svs_samples` (7.10 batch 2); `validations.html` and
//! `validation_detail.html`, with `_validations_page.html`, are `svs_validations` (batch 3). The hub
//! links to the SVS guides (`help`, batch 9).

use ace_service::{
    MAX_QA_DOWNLOAD_FILES, QaMatch, QaMatchDetail, QaPurge, QaRuleDetail, QaRuleFilter, QaRulePage,
    QaRuleSummary, QaRuleset, QaSort, QaStatus, QaVersion, SIGNATURE_DOWNLOAD, SIGNATURE_QA_PURGE,
    SIGNATURE_READ, ServiceError,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};

use crate::Gui;
use crate::actions::encode;
use crate::admin::Module;
use crate::list::{all, one, pairs};
use crate::session::{Failure, SignedIn, render, see_other};
use crate::templates::Layout;

/// A rule's kept files on one page, as ace3's `QA_MATCH_PAGE_SIZE`.
pub const MATCHES_PER_PAGE: u32 = 25;
/// The page sizes the list offers, as ace3's.
pub const PAGE_SIZES: [u32; 3] = [25, 50, 100];
/// The most matches one purge removes, `ace_core::yara_qa::MAX_PURGE`, which the service checks.
const MAX_PURGE: usize = 500;
/// The most characters of a purge's reason, which the service checks.
pub const MAX_REASON: usize = ace_service::MAX_PURGE_REASON;
/// The largest purge form: 1000 versions of a commit each, or 500 ids, and a reason of 1024 characters
/// percent-encoded.
pub const MAX_PURGE_FORM_BYTES: usize = 128 << 10;

/// ace3's `SIGNATURE_MODULES`: the samples (7.10 batch 2), YARA QA and the validations (batch 3).
const SAMPLES: Module = Module {
    href: "/signatures/samples",
    title: "Samples",
    description: "Files YARA rules matched on alerts graded TP or FP, their labels, retirements and deletions.",
};

const VALIDATIONS: Module = Module {
    href: "/signatures/validations",
    title: "Validations",
    description: "Reports on YARA rule changes, replayed against every graded sample: regressions, new false positives and what else a change does.",
};

const YARA_QA: Module = Module {
    href: "/signatures/yara-qa",
    title: "Yara QA Results",
    description: "Browse YARA rules running in QA mode, how often they match, and download the files they matched.",
};

/// `/signatures`.
#[derive(Debug, Template)]
#[template(path = "signatures/hub.html")]
pub struct HubPage {
    pub layout: Layout,
    pub modules: Vec<Module>,
}

// ---- what the pages show ----

/// A time as the pages show it.
fn when(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// A size as ace3's `qa_size` shows it.
pub fn size(bytes: i64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    let units = ["KB", "MB", "GB"];
    loop {
        value /= 1024.0;
        if value < 1024.0 || unit == units.len() - 1 {
            break;
        }
        unit += 1;
    }
    format!("{value:.1} {}", units[unit])
}

/// A commit cut to 10 characters, as ace3's `qa_short_version`; anything else as it is.
pub fn short_version(version: &str) -> String {
    let hex = version
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if hex && (version.len() == 40 || version.len() == 64) {
        version[..10].to_owned()
    } else {
        version.to_owned()
    }
}

/// A rule's page, by its uuid.
pub fn rule_href(uuid: &str) -> String {
    format!("/signatures/yara-qa/rules/{}", encode(uuid))
}

/// A query string of these pairs.
fn query(pairs: &[(&str, String)]) -> String {
    serde_urlencoded::to_string(pairs).expect("pairs of text encode")
}

/// A path and its query, or the path alone when the query is empty.
fn with_query(path: &str, pairs: &[(&str, String)]) -> String {
    if pairs.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", query(pairs))
    }
}

/// A rule, as a row of the list and the head of its page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRow {
    pub href: String,
    pub uuid: String,
    pub name: String,
    pub namespace: String,
    pub path: String,
    pub tags: Vec<String>,
    /// `QA` or `not QA`.
    pub status: &'static str,
    pub in_qa: bool,
    /// `yes`, `no`, or empty when it isn't a QA rule in the current ruleset.
    pub enabled: &'static str,
    pub match_count: i64,
    pub stored_count: i64,
    pub version_count: usize,
    pub first_match: String,
    /// When it last matched, or `never`.
    pub last_match: String,
}

pub fn rule_row(rule: &QaRuleSummary) -> RuleRow {
    RuleRow {
        href: rule_href(&rule.signature_uuid),
        uuid: rule.signature_uuid.clone(),
        name: rule.name.clone(),
        namespace: rule.namespace.clone().unwrap_or_default(),
        path: rule.path.clone().unwrap_or_default(),
        tags: rule.tags.clone(),
        status: match rule.status {
            QaStatus::Qa => "QA",
            QaStatus::NotQa => "not QA",
        },
        in_qa: rule.status == QaStatus::Qa,
        enabled: match rule.enabled {
            Some(true) => "yes",
            Some(false) => "no",
            None => "",
        },
        match_count: rule.match_count,
        stored_count: rule.stored_count,
        version_count: rule.version_count,
        first_match: rule.first_match_at.map(when).unwrap_or_default(),
        last_match: rule
            .last_match_at
            .map(when)
            .unwrap_or_else(|| "never".to_owned()),
    }
}

/// What the page says about the ruleset the list comes from, when a rule may be missing from it.
fn ruleset_warning(ruleset: Option<&QaRuleset>) -> Option<String> {
    match ruleset {
        None => {
            Some("No ruleset has been built yet, so only rules with matches are listed.".to_owned())
        }
        Some(ruleset) if !ruleset.qa_rules_recorded => Some(format!(
            "The current ruleset (commit {}) was built before its QA rules were recorded, so rules \
             that have never matched may be missing until it's built again.",
            short_version(&ruleset.commit)
        )),
        Some(_) => None,
    }
}

/// The list's filters, as the form shows them and its links carry them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListForm {
    pub q: String,
    /// `qa`, `not_qa`, or empty for all.
    pub status: String,
    /// `true`, `false`, or empty for any.
    pub has_matches: String,
    /// `name`, `last_match` or `match_count`.
    pub sort: String,
    pub descending: bool,
    pub limit: u32,
    pub offset: u32,
}

impl Default for ListForm {
    /// ace3's defaults: the rules in QA mode, by name, 50 a page.
    fn default() -> Self {
        ListForm {
            q: String::new(),
            status: "qa".to_owned(),
            has_matches: String::new(),
            sort: "name".to_owned(),
            descending: false,
            limit: 50,
            offset: 0,
        }
    }
}

impl ListForm {
    /// The filters a query string gives, or why it isn't one.
    pub fn parse(text: &str) -> Result<ListForm, String> {
        let form = pairs(text.as_bytes());
        let mut list = ListForm::default();
        if let Some(q) = one(&form, "q") {
            list.q = q.to_owned();
        }
        if let Some(status) = one(&form, "status") {
            if !["qa", "not_qa", ""].contains(&status) {
                return Err(format!(
                    "{status:?} isn't a status: qa, not_qa, or empty for all"
                ));
            }
            list.status = status.to_owned();
        }
        if let Some(has) = one(&form, "has_matches") {
            if !["true", "false", ""].contains(&has) {
                return Err("has_matches is true, false, or empty for any".to_owned());
            }
            list.has_matches = has.to_owned();
        }
        match one(&form, "sort") {
            None | Some("") => {}
            Some(sort @ ("name" | "last_match" | "match_count")) => list.sort = sort.to_owned(),
            Some(sort) => {
                return Err(format!(
                    "{sort:?} isn't a sort: name, last_match or match_count"
                ));
            }
        }
        list.descending = matches!(one(&form, "descending"), Some("true" | "on"));
        if let Some(limit) = one(&form, "limit").filter(|limit| !limit.is_empty()) {
            list.limit = limit
                .parse()
                .map_err(|_| format!("{limit:?} isn't a page size"))?;
        }
        if let Some(offset) = one(&form, "offset").filter(|offset| !offset.is_empty()) {
            list.offset = offset
                .parse()
                .map_err(|_| format!("{offset:?} isn't an offset"))?;
        }
        Ok(list)
    }

    /// The service's filter.
    pub fn filter(&self) -> QaRuleFilter {
        QaRuleFilter {
            q: Some(self.q.clone()).filter(|q| !q.trim().is_empty()),
            status: match self.status.as_str() {
                "qa" => Some(QaStatus::Qa),
                "not_qa" => Some(QaStatus::NotQa),
                _ => None,
            },
            has_matches: match self.has_matches.as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            sort: match self.sort.as_str() {
                "last_match" => QaSort::LastMatch,
                "match_count" => QaSort::MatchCount,
                _ => QaSort::Name,
            },
            descending: self.descending,
        }
    }

    /// The list at another offset.
    fn at(&self, offset: u32) -> String {
        with_query(
            "/signatures/yara-qa",
            &[
                ("q", self.q.clone()),
                ("status", self.status.clone()),
                ("has_matches", self.has_matches.clone()),
                ("sort", self.sort.clone()),
                ("descending", self.descending.to_string()),
                ("limit", self.limit.to_string()),
                ("offset", offset.to_string()),
            ],
        )
    }
}

/// `/signatures/yara-qa`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListView {
    pub form: ListForm,
    pub page_sizes: &'static [u32],
    pub rows: Vec<RuleRow>,
    pub total: usize,
    /// The first and last shown, counting from 1, or 0 and 0 for none.
    pub first_shown: usize,
    pub last_shown: usize,
    pub previous: Option<String>,
    pub next: Option<String>,
    pub warning: Option<String>,
}

/// The list as it draws for a page of rules.
pub fn list_view(form: ListForm, page: &QaRulePage) -> ListView {
    let shown = page.rules.len();
    let offset = usize::try_from(form.offset).unwrap_or(usize::MAX);
    let last_shown = offset.saturating_add(shown);
    let previous = (form.offset > 0).then(|| form.at(form.offset.saturating_sub(form.limit)));
    let next = (last_shown < page.total).then(|| {
        form.at(form
            .offset
            .saturating_add(u32::try_from(shown).unwrap_or(u32::MAX)))
    });
    ListView {
        page_sizes: &PAGE_SIZES,
        rows: page.rules.iter().map(rule_row).collect(),
        total: page.total,
        first_shown: if shown == 0 { 0 } else { offset + 1 },
        last_shown: if shown == 0 { 0 } else { last_shown },
        previous,
        next,
        warning: ruleset_warning(page.ruleset.as_ref()),
        form,
    }
}

#[derive(Debug, Template)]
#[template(path = "signatures/yara_qa.html")]
pub struct YaraQaPage {
    pub layout: Layout,
    pub view: ListView,
}

/// One version of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRow {
    pub version: String,
    pub short: String,
    pub rule: String,
    pub namespace: String,
    pub match_count: i64,
    pub stored_count: i64,
    pub first_match: String,
    pub last_match: String,
    /// The version the current ruleset loads.
    pub current: bool,
    /// The rule's page showing this version's files.
    pub href: String,
    pub selected: bool,
}

fn version_row(
    uuid: &str,
    version: &QaVersion,
    current: Option<&str>,
    selected: Option<&str>,
) -> VersionRow {
    VersionRow {
        version: version.signature_version.clone(),
        short: short_version(&version.signature_version),
        rule: version.rule.clone(),
        namespace: version.namespace.clone(),
        match_count: version.match_count,
        stored_count: version.stored_count,
        first_match: when(version.first_match_at),
        last_match: when(version.last_match_at),
        current: current == Some(version.signature_version.as_str()),
        href: with_query(
            &rule_href(uuid),
            &[("version", version.signature_version.clone())],
        ),
        selected: selected == Some(version.signature_version.as_str()),
    }
}

/// One kept file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchRow {
    pub id: i64,
    /// Its own page.
    pub href: String,
    pub file_path: String,
    pub sha256: String,
    pub short_sha256: String,
    /// Its size, or `gone` when the bucket no longer has it.
    pub size: String,
    pub version: String,
    pub short_version: String,
    pub hit_count: i32,
    pub first_seen: String,
    pub last_seen: String,
    pub expires: String,
    /// The alert it was found in, when its root is one.
    pub alert: Option<String>,
    /// The API's download of it, for a viewer who holds `signature:download`.
    pub download: Option<String>,
}

pub fn match_row(qa_match: &QaMatch, can_download: bool) -> MatchRow {
    MatchRow {
        id: qa_match.id,
        href: format!("/signatures/yara-qa/matches/{}", qa_match.id),
        file_path: qa_match.file_path.clone(),
        sha256: qa_match.sha256.clone(),
        short_sha256: format!("{}…", qa_match.sha256.get(..16).unwrap_or(&qa_match.sha256)),
        size: qa_match
            .file_size
            .map(size)
            .unwrap_or_else(|| "gone".to_owned()),
        version: qa_match.signature_version.clone(),
        short_version: short_version(&qa_match.signature_version),
        hit_count: qa_match.hit_count,
        first_seen: when(qa_match.first_seen),
        last_seen: when(qa_match.last_seen),
        expires: when(qa_match.expires_at),
        alert: qa_match
            .alerted
            .then(|| format!("/alerts/{}", qa_match.root)),
        download: can_download.then(|| format!("/api/yara-qa/v1/matches/{}/download", qa_match.id)),
    }
}

/// The version the current ruleset loads, when the rule is a QA rule in it.
fn current_version(detail: &QaRuleDetail) -> Option<&str> {
    match (&detail.ruleset, detail.rule.status) {
        (Some(ruleset), QaStatus::Qa) => Some(ruleset.commit.as_str()),
        _ => None,
    }
}

/// A purge's confirm page for these versions or these matches.
fn purge_href(uuid: &str, versions: &[String], ids: &[i64]) -> String {
    let mut pairs: Vec<(&str, String)> = versions
        .iter()
        .map(|version| ("version", version.clone()))
        .collect();
    pairs.extend(ids.iter().map(|id| ("match_id", id.to_string())));
    with_query(&format!("{}/purge", rule_href(uuid)), &pairs)
}

/// A rule's page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleView {
    pub rule: RuleRow,
    pub versions: Vec<VersionRow>,
    /// The version whose files are shown, or None for every version's.
    pub version: Option<String>,
    pub matches: Vec<MatchRow>,
    /// The first page of files, when this isn't it.
    pub first: Option<String>,
    pub next: Option<String>,
    /// What the current ruleset loads, in words.
    pub loaded_now: Option<String>,
    pub warning: Option<String>,
    pub can_download: bool,
    pub can_purge: bool,
    /// The API's download of the files shown: every version's, or this version's.
    pub download_all: Option<String>,
    /// Where the files' form sends a selection to download.
    pub download_selected: String,
    /// The purge's confirm page, which the files' form sends a selection to.
    pub purge_selected: String,
    /// The confirm page for this version's files.
    pub purge_version: Option<String>,
    /// The confirm page for every version but the one loaded now, and how many versions and files.
    pub purge_older: Option<(String, usize, i64)>,
}

impl RuleView {
    /// Whether the files have boxes to tick.
    pub fn selectable(&self) -> bool {
        self.can_download || self.can_purge
    }

    /// Where the files' form goes by default: the purge's confirm, or the download when the viewer can't
    /// purge. Download selected names its own.
    pub fn form_action(&self) -> &str {
        if self.can_purge {
            &self.purge_selected
        } else {
            &self.download_selected
        }
    }
}

/// A rule's page, for its detail and a page of its files.
pub fn rule_view(
    detail: &QaRuleDetail,
    version: Option<&str>,
    after: Option<i64>,
    matches: &ace_service::QaMatchPage,
    can_download: bool,
    can_purge: bool,
) -> RuleView {
    let uuid = detail.rule.signature_uuid.as_str();
    let href = rule_href(uuid);
    let current = current_version(detail);
    let version_pairs: Vec<(&str, String)> = version
        .map(|version| vec![("version", version.to_owned())])
        .unwrap_or_default();
    let older: Vec<&QaVersion> = detail
        .versions
        .iter()
        .filter(|v| v.stored_count > 0 && Some(v.signature_version.as_str()) != current)
        .collect();
    let next = matches.next.map(|next| {
        let mut pairs = version_pairs.clone();
        pairs.push(("after", next.to_string()));
        with_query(&href, &pairs)
    });
    RuleView {
        rule: rule_row(&detail.rule),
        versions: detail
            .versions
            .iter()
            .map(|v| version_row(uuid, v, current, version))
            .collect(),
        version: version.map(str::to_owned),
        matches: matches
            .matches
            .iter()
            .map(|m| match_row(m, can_download))
            .collect(),
        first: after.map(|_| with_query(&href, &version_pairs)),
        next,
        loaded_now: detail.ruleset.as_ref().map(|ruleset| match current {
            Some(_) => format!(
                "Loaded now: commit {}, in the ruleset built {}.",
                short_version(&ruleset.commit),
                when(ruleset.built_at)
            ),
            None => format!(
                "The current ruleset (commit {}, built {}) doesn't load it in QA mode.",
                short_version(&ruleset.commit),
                when(ruleset.built_at)
            ),
        }),
        warning: ruleset_warning(detail.ruleset.as_ref()),
        can_download,
        can_purge,
        download_all: (can_download && detail.rule.stored_count > 0).then(|| {
            with_query(
                &format!("/api/yara-qa/v1/rules/{}/download", encode(uuid)),
                &version_pairs,
            )
        }),
        download_selected: format!("{href}/download"),
        purge_selected: format!("{href}/purge"),
        purge_version: version
            .filter(|_| can_purge)
            .map(|version| purge_href(uuid, &[version.to_owned()], &[])),
        purge_older: (can_purge && !older.is_empty()).then(|| {
            let versions: Vec<String> = older.iter().map(|v| v.signature_version.clone()).collect();
            (
                purge_href(uuid, &versions, &[]),
                older.len(),
                older.iter().map(|v| v.stored_count).sum(),
            )
        }),
    }
}

#[derive(Debug, Template)]
#[template(path = "signatures/rule.html")]
pub struct RulePage {
    pub layout: Layout,
    pub view: RuleView,
}

/// How often one string matched, and where first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringRow {
    pub identifier: String,
    pub count: usize,
    /// In hex, as ace3 shows it.
    pub first_offset: String,
}

/// A match's page, ace3's match modal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchView {
    pub row: MatchRow,
    pub uuid: String,
    pub rule_href: String,
    pub rule: String,
    pub namespace: String,
    pub ruleset: String,
    pub root: String,
    /// The record in short, or None when it isn't one the YARA module writes.
    pub summary: Option<SummaryView>,
    /// The API's whole record.
    pub record: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryView {
    pub tags: String,
    pub commit: String,
    pub strings: Vec<StringRow>,
    pub string_matches: usize,
    /// The rule's meta as JSON.
    pub meta: String,
}

pub fn match_view(detail: &QaMatchDetail, can_download: bool) -> MatchView {
    let qa_match = &detail.qa_match;
    MatchView {
        row: match_row(qa_match, can_download),
        uuid: qa_match.signature_uuid.clone(),
        rule_href: rule_href(&qa_match.signature_uuid),
        rule: qa_match.rule.clone(),
        namespace: qa_match.namespace.clone(),
        ruleset: qa_match.ruleset.clone().unwrap_or_default(),
        root: qa_match.root.to_string(),
        summary: detail.summary.as_ref().map(|summary| SummaryView {
            tags: summary.tags.join(", "),
            commit: summary.commit.clone().unwrap_or_default(),
            string_matches: summary.strings.iter().map(|s| s.count).sum(),
            strings: summary
                .strings
                .iter()
                .map(|s| StringRow {
                    identifier: s.identifier.clone(),
                    count: s.count,
                    first_offset: format!("0x{:x}", s.first_offset),
                })
                .collect(),
            meta: serde_json::to_string_pretty(&summary.meta).unwrap_or_default(),
        }),
        record: format!("/api/yara-qa/v1/matches/{}/record", qa_match.id),
    }
}

#[derive(Debug, Template)]
#[template(path = "signatures/match.html")]
pub struct MatchPage {
    pub layout: Layout,
    pub view: MatchView,
}

/// What a purge will remove, to confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeView {
    pub rule: String,
    pub rule_href: String,
    /// Where the form posts.
    pub action: String,
    /// The versions whose every record goes, or none for a purge of matches.
    pub versions: Vec<VersionRow>,
    /// The matches that go, or none for a purge of versions.
    pub matches: Vec<MatchRow>,
    /// The kept files that go.
    pub files: i64,
    pub reason: String,
    pub max_reason: usize,
    /// Why the last post was refused, or None for a first look.
    pub problem: Option<String>,
}

#[derive(Debug, Template)]
#[template(path = "signatures/confirm_purge.html")]
pub struct ConfirmPurgePage {
    pub layout: Layout,
    pub view: PurgeView,
}

/// What a purge did.
#[derive(Debug, Template)]
#[template(path = "signatures/purged.html")]
pub struct PurgedPage {
    pub layout: Layout,
    /// The rule's uuid.
    pub uuid: String,
    pub rule_href: String,
    pub purged: usize,
    pub remaining: i64,
    /// The confirm page again, when matches are left past the 500 one purge removes.
    pub again: Option<String>,
}

// ---- the gate and the answers every handler shares ----

/// Whether the viewer may enter the area, or the answer saying they may not.
async fn enter(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Result<(), Failure> {
    match gui.service.allowed(&viewer.actor, &SIGNATURE_READ).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Failure::new(
            StatusCode::FORBIDDEN,
            "The signatures area needs signature:read. Ask an administrator.",
            parts,
        )),
        Err(error) => Err(Failure::from_service(error, parts)),
    }
}

fn bad_request(message: impl Into<String>, parts: &Parts) -> Response {
    Failure::new(StatusCode::BAD_REQUEST, message, parts).into_response()
}

fn failed(error: ServiceError, parts: &Parts) -> Response {
    Failure::from_service(error, parts).into_response()
}

fn uuid_of(uuid: Result<Path<String>, PathRejection>) -> Option<String> {
    uuid.ok().map(|Path(uuid)| uuid)
}

/// The versions and match ids a form or a query names, or why they aren't.
fn targets(form: &[(String, String)]) -> Result<(Vec<String>, Vec<i64>), String> {
    let versions = all(form, "version");
    let ids = all(form, "match_id")
        .iter()
        .map(|id| id.trim().parse::<i64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "A match id is a number.".to_owned())?;
    Ok((versions, ids))
}

// ---- the pages ----

/// `GET /signatures`: the hub.
pub(crate) async fn hub(State(gui): State<Gui>, viewer: SignedIn, parts: Parts) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    render(&HubPage {
        layout: viewer.layout,
        // every page here needs only the area's signature:read
        modules: vec![SAMPLES, YARA_QA, VALIDATIONS],
    })
}

/// `GET /signatures/yara-qa`: the rules.
pub(crate) async fn yara_qa(State(gui): State<Gui>, viewer: SignedIn, parts: Parts) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = match ListForm::parse(parts.uri.query().unwrap_or("")) {
        Ok(form) => form,
        Err(problem) => return bad_request(problem, &parts),
    };
    match gui
        .service
        .qa_rules(&viewer.actor, &form.filter(), Some(form.limit), form.offset)
        .await
    {
        Ok(page) => render(&YaraQaPage {
            layout: viewer.layout,
            view: list_view(form, &page),
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /signatures/yara-qa/rules/{uuid}`: a rule, its versions and a page of its files.
pub(crate) async fn rule_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    uuid: Result<Path<String>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(uuid) = uuid_of(uuid) else {
        return bad_request("A rule's uuid is text.", &parts);
    };
    let form = pairs(parts.uri.query().unwrap_or("").as_bytes());
    let version = one(&form, "version").filter(|version| !version.is_empty());
    let after = match one(&form, "after").filter(|after| !after.is_empty()) {
        None => None,
        Some(after) => match after.parse::<i64>() {
            Ok(after) => Some(after),
            Err(_) => return bad_request("after is a match's id.", &parts),
        },
    };
    let actor = &viewer.actor;
    let read = async {
        let detail = gui.service.qa_rule(actor, &uuid).await?;
        let matches = gui
            .service
            .qa_matches(actor, &uuid, version, Some(MATCHES_PER_PAGE), after)
            .await?;
        let can_download = gui.service.allowed(actor, &SIGNATURE_DOWNLOAD).await?;
        let can_purge = gui.service.allowed(actor, &SIGNATURE_QA_PURGE).await?;
        Ok::<_, ServiceError>(rule_view(
            &detail,
            version,
            after,
            &matches,
            can_download,
            can_purge,
        ))
    };
    match read.await {
        Ok(view) => render(&RulePage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /signatures/yara-qa/matches/{id}`: one kept file and its record in short.
pub(crate) async fn match_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<i64>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Ok(Path(id)) = id else {
        return bad_request("A match's id is a number.", &parts);
    };
    let actor = &viewer.actor;
    let read = async {
        let detail = gui.service.qa_match(actor, id).await?;
        let can_download = gui.service.allowed(actor, &SIGNATURE_DOWNLOAD).await?;
        Ok::<_, ServiceError>(match_view(&detail, can_download))
    };
    match read.await {
        Ok(view) => render(&MatchPage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /signatures/yara-qa/rules/{uuid}/download`: the files ticked on the rule's page, sent on to the
/// API's download of them, which checks `signature:download` and writes the audit row.
pub(crate) async fn download_selected(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    uuid: Result<Path<String>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(uuid) = uuid_of(uuid) else {
        return bad_request("A rule's uuid is text.", &parts);
    };
    let form = pairs(parts.uri.query().unwrap_or("").as_bytes());
    let ids = match targets(&form) {
        Ok((_, ids)) => ids,
        Err(problem) => return bad_request(problem, &parts),
    };
    if ids.is_empty() {
        return bad_request("Tick the files to download.", &parts);
    }
    if ids.len() > MAX_QA_DOWNLOAD_FILES {
        return Failure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("A download holds at most {MAX_QA_DOWNLOAD_FILES} files."),
            &parts,
        )
        .into_response();
    }
    let ids: Vec<String> = ids.iter().map(i64::to_string).collect();
    see_other(
        &with_query(
            &format!("/api/yara-qa/v1/rules/{}/download", encode(&uuid)),
            &[("match_ids", ids.join(","))],
        ),
        None,
    )
}

/// What a purge of `versions` or `ids` removes from the rule, read to confirm.
async fn purge_view(
    gui: &Gui,
    viewer: &SignedIn,
    uuid: &str,
    versions: &[String],
    ids: &[i64],
    reason: String,
) -> Result<PurgeView, ServiceError> {
    let actor = &viewer.actor;
    let detail = gui.service.qa_rule(actor, uuid).await?;
    let can_download = gui.service.allowed(actor, &SIGNATURE_DOWNLOAD).await?;
    let current = current_version(&detail);
    let mut version_rows = Vec::new();
    for version in versions {
        let found = detail
            .versions
            .iter()
            .find(|v| &v.signature_version == version)
            .ok_or_else(|| {
                ServiceError::NotFound(format!("this rule has no matches under version {version}"))
            })?;
        version_rows.push(version_row(uuid, found, current, None));
    }
    let mut matches = Vec::new();
    for id in ids {
        let found = gui.service.qa_match(actor, *id).await?;
        if found.qa_match.signature_uuid != uuid {
            return Err(ServiceError::NotFound(format!(
                "no kept match {id} of this rule"
            )));
        }
        matches.push(match_row(&found.qa_match, can_download));
    }
    let files = if versions.is_empty() {
        i64::try_from(matches.len()).unwrap_or(i64::MAX)
    } else {
        version_rows.iter().map(|v| v.stored_count).sum()
    };
    let rule_href = rule_href(uuid);
    Ok(PurgeView {
        rule: detail.rule.name,
        action: format!("{rule_href}/purge"),
        rule_href,
        versions: version_rows,
        matches,
        files,
        reason,
        max_reason: MAX_REASON,
        problem: None,
    })
}

/// Checks a purge's targets before anything is read: versions or matches, not both, and not too many.
fn check_targets(versions: &[String], ids: &[i64]) -> Result<(), String> {
    match (versions.is_empty(), ids.is_empty()) {
        (true, true) => Err("Choose the files or the versions to purge.".to_owned()),
        (false, false) => Err("A purge is of versions or of files, not both.".to_owned()),
        _ if ids.len() > MAX_PURGE => Err(format!(
            "One purge removes at most {MAX_PURGE} files; choose fewer, or purge by version."
        )),
        _ if versions.len() > ace_service::MAX_PURGE_VERSIONS => Err(format!(
            "One purge names at most {} versions.",
            ace_service::MAX_PURGE_VERSIONS
        )),
        _ => Ok(()),
    }
}

/// `GET /signatures/yara-qa/rules/{uuid}/purge`: what a purge will remove, and its form.
pub(crate) async fn confirm_purge(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    uuid: Result<Path<String>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(uuid) = uuid_of(uuid) else {
        return bad_request("A rule's uuid is text.", &parts);
    };
    // Only someone who could purge is asked to confirm one.
    match gui
        .service
        .allowed(&viewer.actor, &SIGNATURE_QA_PURGE)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Failure::new(
                StatusCode::FORBIDDEN,
                "Purging needs signature:qa_purge.",
                &parts,
            )
            .into_response();
        }
        Err(error) => return failed(error, &parts),
    }
    let form = pairs(parts.uri.query().unwrap_or("").as_bytes());
    let (versions, ids) = match targets(&form) {
        Ok(targets) => targets,
        Err(problem) => return bad_request(problem, &parts),
    };
    if let Err(problem) = check_targets(&versions, &ids) {
        return bad_request(problem, &parts);
    }
    match purge_view(&gui, &viewer, &uuid, &versions, &ids, String::new()).await {
        Ok(view) => render(&ConfirmPurgePage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /signatures/yara-qa/rules/{uuid}/purge`: the purge, through `Service::purge_qa_matches`.
pub(crate) async fn purge(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    uuid: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(uuid) = uuid_of(uuid) else {
        return bad_request("A rule's uuid is text.", &parts);
    };
    let form = pairs(&body);
    let (versions, ids) = match targets(&form) {
        Ok(targets) => targets,
        Err(problem) => return bad_request(problem, &parts),
    };
    if let Err(problem) = check_targets(&versions, &ids) {
        return bad_request(problem, &parts);
    }
    let reason = one(&form, "reason").unwrap_or("").trim().to_owned();
    let request = QaPurge {
        versions: (!versions.is_empty()).then(|| versions.clone()),
        match_ids: (!ids.is_empty()).then(|| ids.clone()),
        reason: (!reason.is_empty()).then(|| reason.clone()),
    };
    match gui
        .service
        .purge_qa_matches(&viewer.actor, &uuid, &request)
        .await
    {
        Ok(purged) => render(&PurgedPage {
            layout: viewer.layout,
            uuid: uuid.clone(),
            rule_href: rule_href(&uuid),
            purged: purged.purged.len(),
            remaining: purged.remaining,
            again: (purged.remaining > 0).then(|| purge_href(&uuid, &versions, &ids)),
        }),
        // a reason too long draws the form again with what was typed
        Err(ServiceError::InvalidRequest(problem)) => {
            match purge_view(&gui, &viewer, &uuid, &versions, &ids, reason).await {
                Ok(mut view) => {
                    view.problem = Some(problem);
                    let mut response = render(&ConfirmPurgePage {
                        layout: viewer.layout,
                        view,
                    });
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    response
                }
                Err(error) => failed(error, &parts),
            }
        }
        Err(error) => failed(error, &parts),
    }
}
