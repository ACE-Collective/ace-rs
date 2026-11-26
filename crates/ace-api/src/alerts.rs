//! `/api/alerts/v1`: the alert list with its filters, sorts and exports, one alert, its observables, its
//! relationship graph, a file's download, the disposition, the owner and a comment's edit, and the site's
//! dispositions.
//!
//! `PUT /api/alerts/v1/owner` is ace3's `PUT /api/v2/alerts/owner` (PLAN.md 7.17): take, assign or
//! unassign alerts, leaving alone those another analyst owns unless `take_owned` confirms taking them.
//! ace3's `owner_id` and `alert_uuids` are `owner` and `alerts` here, ids are uuids, and `skipped` says
//! each owner's id beside their name, since a confirmation names the id. An alert's owner is on the alert
//! itself (`owner`, `owner_name`, `owned_at`), where ace3's page polls `GET /alerts/{uuid}/meta` for it.
//! `PUT .../disposition` takes `take_from`, the same confirmation for one alert, which ace3's API has no
//! route for: its GUI's forms carry it.
//!
//! `GET /api/alerts/v1/directives` and `POST .../alerts/{id}/observables/{observable}/directives` are the
//! directives an analyst may add to an observable and their adding (PLAN.md decision 31). ace3 adds them
//! through its GUI's Add Observable form and `POST /api/v2/alerts/observables` (several alerts at once),
//! and one at a time through its observable actions (`.../observables/{uuid}/render` and the like); here
//! one route takes any of the binary's list for one observable, under `observable:write` as ace3's
//! observable actions are.
//!
//! `POST /api/alerts/v1/commonalities` is ace3's `POST /api/v2/alerts/commonalities` (PLAN.md 7.23):
//! a page's alerts grouped by the observable values they share. ace3's `alert_uuids` are `alerts` here,
//! as in the owner's route, and a request outside its bounds is 400 where ace3's is 422.
//!
//! An alert's comments (PLAN.md 5.15) are on it, `comments`, in the list, its exports (one line each in
//! the CSV's `comments`, as ace3's) and `GET .../alerts/{id}`, as ace3's list rows carry them, and
//! `PATCH .../alerts/{id}/comments/{comment}` is ace3's edit of one, by its author. ace3's API has no
//! route that adds or deletes one: its GUI does both, and so does this one's. `PUT .../disposition` takes
//! the comment ace3's GUI sends with a disposition.
//!
//! `GET /api/alerts/v1/dispositions` has no ace3 route: ace3's clients read `dispositions:` from its
//! config. It's the site's set in order with each disposition's metadata (the owner's decision of
//! 2026-11-14), under `alert:read`.

use std::io::{Seek, SeekFrom};

use ace_core::bucket::ALERT_FILES;
use ace_results::Sha256;
use ace_service::filters::{FilterScreen, decode};
use ace_service::{
    Actor, AlertDetection, AlertFile, AlertGraph, AlertObservable, AlertQuery, AlertSort,
    AlertSummary, AnalysisState, GraphEdge, GraphNode, ModuleResult, RecordedActor, Relationship,
};
use axum::Json;
use axum::body::Body;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, Format, time_cell};
use crate::observable_comments::{AuthorBody, EditCommentRequest};
use crate::params::Params;

/// The password of a download's zip, as ace3's. It's there so that a scanner on the analyst's machine
/// leaves the file alone, not to keep it secret.
pub(crate) const ZIP_PASSWORD: &str = "infected";

/// A download's bytes, as the document shows them.
#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
#[allow(dead_code)]
pub(crate) struct ZipBody(Vec<u8>);

/// Who did something, as the row recorded them then.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ActorBody {
    /// `user`, `api_key` or `internal`.
    kind: String,
    id: String,
    /// The user's or key's name at the time. An internal component's id is its name.
    name: Option<String>,
}

impl ActorBody {
    /// Its name, or its id when it has none, as a cell of an export.
    pub(crate) fn shown(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.id.clone())
    }
}

impl From<RecordedActor> for ActorBody {
    fn from(actor: RecordedActor) -> Self {
        ActorBody {
            kind: actor.kind,
            id: actor.id,
            name: actor.name,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AnalysisBody {
    /// Tasks are queued or running.
    Running,
    /// The current pass completed.
    Complete,
    /// Analysis was cancelled and hasn't started again.
    Cancelled,
}

/// An alert: a root that a detection made worth an analyst's time.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertBody {
    id: Uuid,
    /// The submission's description, as its sender wrote it. Show it as text.
    pub(crate) title: String,
    analysis_mode: String,
    event_time: Option<DateTime<Utc>>,
    /// `event`, `query_time`, `now` or `unset`: where `event_time` came from.
    event_time_source: String,
    created_at: DateTime<Utc>,
    /// When a detection made the root an alert.
    alerted_at: DateTime<Utc>,
    pub(crate) disposition: Option<String>,
    dispositioned_at: Option<DateTime<Utc>>,
    dispositioned_by: Option<ActorBody>,
    submitted_by: Option<ActorBody>,
    analysis: AnalysisBody,
    /// The queue it's in. Show it as text.
    pub(crate) queue: String,
    /// The tags the core gave it: SVS's `svs_test`, `svs:marker_mismatch` and `svs:maintenance`.
    tags: Vec<String>,
    /// What SVS makes of it: `test` (every detection attributed to a test run, one by a marker), `test?`
    /// (every detection, by context alone), `partial` (some) or `mismatch` (a marker that doesn't agree
    /// with its run); null when SVS never touched it.
    pub(crate) svs_status: Option<String>,
    /// The test runs it's attributed to, oldest first: `GET /api/svs/v1/runs/{run_id}`.
    svs_runs: Vec<Uuid>,
    /// The analyst who took it; null when nobody owns it. What a confirmation to take it names.
    owner: Option<Uuid>,
    /// What the owner is called: their display name, or their username. Show it as text.
    pub(crate) owner_name: Option<String>,
    /// When they took it.
    owned_at: Option<DateTime<Utc>>,
    /// Its comments (PLAN.md 5.15), its latest 100 oldest first. Not given by the AI API, which reads
    /// none, as ace3's AI export has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) comments: Option<Vec<AlertCommentBody>>,
}

/// A comment on an alert, ace3's `AlertCommentRead`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertCommentBody {
    id: i64,
    alert: Uuid,
    /// The user it's by, as they're called now; null for one ACE itself wrote, which `created_by` names.
    author: Option<AuthorBody>,
    /// What a page calls the author: their display name, else their username, else `ACE`. Show it as
    /// text.
    author_name: String,
    /// The actor that wrote it: the author, one of their keys, or one of ACE's components.
    created_by: ActorBody,
    /// The text, with LF line breaks. Show it as text.
    comment: String,
    created_at: DateTime<Utc>,
    /// When the text last changed; null if it never has.
    edited_at: Option<DateTime<Utc>>,
}

impl From<ace_service::AlertComment> for AlertCommentBody {
    fn from(comment: ace_service::AlertComment) -> Self {
        AlertCommentBody {
            author_name: comment.author_name(),
            id: comment.id,
            alert: comment.alert,
            author: comment.author.map(AuthorBody::from),
            created_by: comment.created_by.into(),
            comment: comment.comment,
            created_at: comment.created_at,
            edited_at: comment.edited_at,
        }
    }
}

impl From<AlertSummary> for AlertBody {
    fn from(alert: AlertSummary) -> Self {
        let (svs_status, svs_runs) = match alert.svs {
            Some(svs) => (Some(svs.status.as_str().to_owned()), svs.runs),
            None => (None, Vec::new()),
        };
        let (owner, owner_name) = match alert.owner {
            Some(owner) => (Some(owner.id.0), Some(owner.name)),
            None => (None, None),
        };
        AlertBody {
            owner,
            owner_name,
            owned_at: alert.owned_at,
            comments: alert
                .comments
                .map(|comments| comments.into_iter().map(AlertCommentBody::from).collect()),
            tags: alert.tags,
            svs_status,
            svs_runs,
            id: alert.id,
            title: alert.title,
            analysis_mode: alert.analysis_mode,
            event_time: alert.event_time,
            event_time_source: alert.event_time_source,
            created_at: alert.created_at,
            alerted_at: alert.alerted_at,
            disposition: alert.disposition,
            dispositioned_at: alert.dispositioned_at,
            dispositioned_by: alert.dispositioned_by.map(ActorBody::from),
            submitted_by: alert.submitted_by.map(ActorBody::from),
            analysis: match alert.analysis {
                AnalysisState::Running => AnalysisBody::Running,
                AnalysisState::Complete => AnalysisBody::Complete,
                AnalysisState::Cancelled => AnalysisBody::Cancelled,
            },
            queue: alert.queue,
        }
    }
}

impl ExportRow for AlertBody {
    const HEADER: &'static [&'static str] = &[
        "id",
        "title",
        "analysis_mode",
        "event_time",
        "event_time_source",
        "created_at",
        "alerted_at",
        "disposition",
        "dispositioned_at",
        "dispositioned_by",
        "submitted_by",
        "analysis",
        "queue",
        "tags",
        "svs_status",
        "svs_runs",
        "owner",
        "owned_at",
        "comments",
    ];

    fn cells(&self) -> Vec<String> {
        let actor = |actor: &Option<ActorBody>| {
            actor
                .as_ref()
                .map(|actor| actor.name.clone().unwrap_or_else(|| actor.id.clone()))
                .unwrap_or_default()
        };
        vec![
            self.id.to_string(),
            self.title.clone(),
            self.analysis_mode.clone(),
            time_cell(self.event_time),
            self.event_time_source.clone(),
            time_cell(Some(self.created_at)),
            time_cell(Some(self.alerted_at)),
            self.disposition.clone().unwrap_or_default(),
            time_cell(self.dispositioned_at),
            actor(&self.dispositioned_by),
            actor(&self.submitted_by),
            match self.analysis {
                AnalysisBody::Running => "running",
                AnalysisBody::Complete => "complete",
                AnalysisBody::Cancelled => "cancelled",
            }
            .to_owned(),
            self.queue.clone(),
            self.tags.join(" "),
            self.svs_status.clone().unwrap_or_default(),
            self.svs_runs
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            self.owner_name.clone().unwrap_or_default(),
            time_cell(self.owned_at),
            // ace3's: each comment's text on its own line, oldest first
            self.comments
                .iter()
                .flatten()
                .map(|comment| comment.comment.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        ]
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertPageBody {
    alerts: Vec<AlertBody>,
    /// Pass as `after` for the next page, with the same filters and order; null on the last.
    next: Option<String>,
    /// How many alerts the filters match in all.
    total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertDetailBody {
    alert: AlertBody,
    observables: i64,
    files: i64,
    detections: i64,
    /// The alert's own links out of ACE, such as those its hunt rendered: ace3's root
    /// `pivot_links`.
    pivot_links: Vec<PivotLinkBody>,
}

impl From<ace_service::Alert> for AlertDetailBody {
    fn from(alert: ace_service::Alert) -> Self {
        AlertDetailBody {
            alert: alert.summary.into(),
            observables: alert.observables,
            files: alert.files,
            detections: alert.detections,
            pivot_links: alert.pivot_links.into_iter().map(Into::into).collect(),
        }
    }
}

/// The alert list's parameters, which its exports share but for `limit` and `after`. The handler reads
/// them from the query itself, since `f` repeats.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct AlertsQuery {
    /// A filter in the share-link encoding, `[!]<slug>:<value>,<value>`, with the alert screen's slugs
    /// (`GET /api/filters/v1/screens/alerts`); repeat it for more. Filters are ANDed, the values of one
    /// ORed, and `!` inverts one.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// `alert_date`, the default, `description`, `disposition`, `queue` or `owner`.
    sort: Option<String>,
    /// `desc`, the default, or `asc`.
    dir: Option<String>,
    /// The IANA timezone relative date filters (`-7d`, `@d`) resolve in; UTC when left out.
    tz: Option<String>,
    /// How many alerts, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<String>,
}

/// The export's parameters: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct AlertExportQuery {
    /// A filter, as the list takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// `alert_date`, the default, `description`, `disposition`, `queue` or `owner`.
    sort: Option<String>,
    /// `desc`, the default, or `asc`.
    dir: Option<String>,
    /// The IANA timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
}

/// The list's query from its parameters.
fn alert_query(params: &Params) -> Result<AlertQuery, ApiError> {
    let (filters, _) = decode(FilterScreen::Alerts, &params.all("f"), true)?;
    let sort = match params.one("sort")? {
        None => AlertSort::default(),
        Some(name) => AlertSort::named(name).ok_or_else(|| {
            ApiError::bad_request(format!(
                "sort is alert_date, description, disposition, queue or owner, not {name:?}"
            ))
        })?,
    };
    let descending = match params.one("dir")? {
        None | Some("desc") => true,
        Some("asc") => false,
        Some(other) => {
            return Err(ApiError::bad_request(format!(
                "dir is asc or desc, not {other:?}"
            )));
        }
    };
    Ok(AlertQuery {
        filters,
        sort,
        descending,
        tz: params.tz()?,
    })
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ObservablesQuery {
    /// How many observables, 1 to 500; 100 when left out.
    pub(crate) limit: Option<u32>,
    /// The `next` of the previous page.
    pub(crate) after: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FileBody {
    /// The file's path in the alert, such as `email.rfc822.parts/invoice.zip`.
    path: String,
    yara_meta: Vec<String>,
    /// What the module that wrote it made it under this path, such as `email.attachment`, or null.
    /// Its `type=` tag is among `yara_meta`.
    role: Option<String>,
}

/// What a file's bytes are, as the type step found them, with ace3's names for the checks.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FileTypeBody {
    /// libmagic's description, as `file -b -L` prints it.
    description: String,
    /// libmagic's mime type.
    mime: String,
    is_ole_file: bool,
    is_rtf_file: bool,
    /// `%PDF-` in the first kilobyte. ace3's `is_pdf_file` is this unless the name ends in
    /// `.pdfparser`.
    has_pdf_marker: bool,
    is_pe_file: bool,
    is_zip_file: bool,
    is_jar_file: bool,
    is_x509: bool,
    is_lnk_file: bool,
    is_email_file: bool,
    /// ace3's `is_pcap_file`: a pcap magic number, or a pcapng section header with its byte-order
    /// magic.
    is_pcap_file: bool,
    /// OneNote's header GUID in the first 16 bytes.
    has_onenote_header: bool,
    /// `CAFEBABE` at the start: a Java class file.
    is_java_class_file: bool,
    /// `<?xml` in the first kilobyte.
    has_xml_marker: bool,
    /// The EPS binary header or `%!PS-Adobe-` at the start.
    is_eps_file: bool,
    /// `#@~^` at the start: a script encoded by Microsoft's script encoder.
    is_encoded_script: bool,
    /// A HAR's start in the first 4096 bytes: whitespace, `{`, `"log"` and `:`.
    has_har_header: bool,
    /// Pillow would open it as an image, by its first kilobyte.
    is_image: bool,
    /// Whether it parses as JavaScript with a keyword in it; null when the type step didn't check,
    /// which it does only where the mime type or the name says JavaScript.
    javascript: Option<bool>,
}

impl From<ace_results::types::file_type::TypeFacts> for FileTypeBody {
    fn from(facts: ace_results::types::file_type::TypeFacts) -> Self {
        FileTypeBody {
            description: facts.description,
            mime: facts.mime,
            is_ole_file: facts.is_ole_file,
            is_rtf_file: facts.is_rtf_file,
            has_pdf_marker: facts.has_pdf_marker,
            is_pe_file: facts.is_pe_file,
            is_zip_file: facts.is_zip_file,
            is_jar_file: facts.is_jar_file,
            is_x509: facts.is_x509,
            is_lnk_file: facts.is_lnk_file,
            is_email_file: facts.is_email_file,
            is_pcap_file: facts.is_pcap_file,
            has_onenote_header: facts.has_onenote_header,
            is_java_class_file: facts.is_java_class_file,
            has_xml_marker: facts.has_xml_marker,
            is_eps_file: facts.is_eps_file,
            is_encoded_script: facts.is_encoded_script,
            has_har_header: facts.has_har_header,
            is_image: facts.is_image,
            javascript: facts.javascript,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RelationshipBody {
    kind: String,
    target_type: String,
    target_value: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ResultBody {
    module: String,
    analysis_type: String,
    schema_version: i32,
    summary: Option<String>,
    /// Why the module said it failed, or null when it didn't. A failed result keeps what the
    /// module had before it failed, as a partial result.
    error: Option<String>,
    tags: Vec<String>,
    /// The result's details, as the analysis type's JSON Schema (`ace schema export`) says.
    details: Value,
    created_at: DateTime<Utc>,
    /// True for a result the analysis cache wrote in place of the module's task, from a result the
    /// module made earlier, in this alert or another: ace3's `from_cache_hit`.
    from_cache_hit: bool,
    /// For a result from the cache, when the task that made it ended: ace3's `cached_at`. Null
    /// otherwise.
    cached_at: Option<DateTime<Utc>>,
    /// The result's links out of ACE, ace3's `pivot_links`, in order.
    pivot_links: Vec<PivotLinkBody>,
}

/// A link out of ACE: ace3's `PivotLink` (PLAN.md decision 32 part (b)). The URL is always
/// `https://`; the icon, when there is one, is served at `/icons/{icon}` by the GUI.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PivotLinkBody {
    url: String,
    text: String,
    /// The name of an icon the binary registers, or null for a link with none.
    icon: Option<String>,
}

impl From<ace_results::PivotLink> for PivotLinkBody {
    fn from(link: ace_results::PivotLink) -> Self {
        PivotLinkBody {
            url: link.url,
            text: link.text,
            icon: link.icon,
        }
    }
}

/// A module whose task on the observable failed and left no result: it crashed, was stopped at
/// its deadline or returned an error. A module that ran to its end and says it failed has a
/// result instead, with its `error`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FailedModuleBody {
    module: String,
    /// The task's error, or null when it recorded none.
    error: Option<String>,
    /// The failed task's id, which `/api/crashes/v1/crashes/{id}` reads with `crash:read`.
    task: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DetectionBody {
    description: String,
    details: Option<Value>,
    /// The module whose result raised it.
    module: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RedirectionBody {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

/// An observable of an alert and everything recorded about it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ObservableBody {
    /// The observable's id in this alert, for `after` and for its file.
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    /// A file's value is its sha256.
    value: String,
    time: Option<DateTime<Utc>>,
    tags: Vec<String>,
    directives: Vec<String>,
    exclude_modules: Vec<String>,
    /// The observable an analyst should look at instead.
    redirection: Option<RedirectionBody>,
    /// The label a module gave it in place of its type's name, such as `Source IP`, or null.
    display_type: Option<String>,
    files: Vec<FileBody>,
    /// A file's type: what the type step found in its bytes (PLAN.md decision 25). ace3 showed this
    /// as file_type's result, which ace-rs doesn't store. Absent for an observable that isn't a file,
    /// for a file whose type step hasn't ended or failed, and from the AI investigation API.
    #[serde(skip_serializing_if = "Option::is_none")]
    file_type: Option<FileTypeBody>,
    relationships: Vec<RelationshipBody>,
    results: Vec<ResultBody>,
    /// The modules whose tasks on it failed without a result. Absent from the AI investigation
    /// API's observables, which can't read the task queue.
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_modules: Option<Vec<FailedModuleBody>>,
    detections: Vec<DetectionBody>,
}

impl From<AlertObservable> for ObservableBody {
    fn from(observable: AlertObservable) -> Self {
        ObservableBody {
            id: observable.id,
            kind: observable.kind,
            value: observable.value,
            time: observable.time,
            tags: observable.tags,
            directives: observable.directives,
            exclude_modules: observable.exclude_modules,
            redirection: observable
                .redirection
                .map(|(kind, value)| RedirectionBody { kind, value }),
            display_type: observable.display_type,
            files: observable
                .files
                .into_iter()
                .map(
                    |AlertFile {
                         path,
                         yara_meta,
                         role,
                     }| FileBody {
                        path,
                        yara_meta,
                        role,
                    },
                )
                .collect(),
            file_type: observable.file_type.map(FileTypeBody::from),
            relationships: observable
                .relationships
                .into_iter()
                .map(
                    |Relationship {
                         kind,
                         target_type,
                         target_value,
                     }| RelationshipBody {
                        kind,
                        target_type,
                        target_value,
                    },
                )
                .collect(),
            results: observable
                .results
                .into_iter()
                .map(|result: ModuleResult| ResultBody {
                    module: result.module,
                    analysis_type: result.analysis_type,
                    schema_version: result.schema_version,
                    summary: result.summary,
                    error: result.error,
                    tags: result.tags,
                    details: result.details,
                    created_at: result.created_at,
                    from_cache_hit: result.cached_at.is_some(),
                    cached_at: result.cached_at,
                    pivot_links: result.pivot_links.into_iter().map(Into::into).collect(),
                })
                .collect(),
            failed_modules: observable.failed.map(|failed| {
                failed
                    .into_iter()
                    .map(|failed| FailedModuleBody {
                        module: failed.module,
                        error: failed.error,
                        task: failed.task,
                    })
                    .collect()
            }),
            detections: observable
                .detections
                .into_iter()
                .map(
                    |AlertDetection {
                         description,
                         details,
                         module,
                     }| DetectionBody {
                        description,
                        details,
                        module,
                    },
                )
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ObservablePageBody {
    observables: Vec<ObservableBody>,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

impl From<ace_service::ObservablePage> for ObservablePageBody {
    fn from(page: ace_service::ObservablePage) -> Self {
        ObservablePageBody {
            observables: page
                .observables
                .into_iter()
                .map(ObservableBody::from)
                .collect(),
            next: page.next,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispositionRequest {
    /// One of the site's dispositions, such as `FALSE_POSITIVE`. The set is the site overlay's
    /// `dispositions` over ace3's, so it's a string here, not an enum; `GET /api/filters/v1/screens/alerts`
    /// lists it as the `Disposition` filter's options. An analyst's must be one an analyst may choose.
    disposition: String,
    /// The analyst the caller agrees to take the alert from: its `owner`, as the caller last read it. An
    /// alert another analyst owns is changed only with it, and the caller then owns the alert.
    #[serde(default)]
    take_from: Option<Uuid>,
    /// A comment added to the alert with the disposition, ace3's `user_comment`, by the caller's user;
    /// one that's only whitespace is none.
    #[serde(default)]
    comment: Option<String>,
}

/// An owner that's required and may be null, so leaving it out never quietly unassigns.
fn required_owner<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Uuid>, D::Error> {
    Option::<Uuid>::deserialize(deserializer)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerRequest {
    /// The alerts, 1 to 500. One that names no alert is left out of the answer.
    alerts: Vec<Uuid>,
    /// The user who gets the alerts: the caller's own id takes them, another user's assigns them, and
    /// null unassigns them. It has to be there.
    #[serde(deserialize_with = "required_owner")]
    #[schema(required = true)]
    owner: Option<Uuid>,
    /// Per alert, the analyst the caller agrees to take it from: its `owner`, as the caller last read it.
    /// An alert another analyst owns is changed only when it's named here with that analyst; otherwise it's
    /// left alone and listed in `skipped`.
    #[serde(default)]
    take_owned: std::collections::BTreeMap<Uuid, Uuid>,
}

/// The analyst an alert was left with.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SkippedOwnerBody {
    /// Their id, which `take_owned` names to take the alert from them.
    owner: Uuid,
    /// What they're called. Show it as text.
    name: String,
}

/// What a change of owner did.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct OwnerChangeBody {
    /// The alerts that now have the owner asked for, in the order asked for.
    applied: Vec<Uuid>,
    /// The alerts left alone, each with the analyst who owns it.
    skipped: std::collections::BTreeMap<Uuid, SkippedOwnerBody>,
    /// What to tell a person when alerts were skipped, such as `took ownership of 1 alerts; left 1 alert
    /// owned by Jane alone`; null otherwise.
    message: Option<String>,
}

/// Sets the owner of the alerts: the caller takes them when `owner` is their own id, assigns them to
/// someone else otherwise, and unassigns them when it's null. An alert another analyst owns is left alone
/// unless `take_owned` confirms taking it from them; one whose owner's account is disabled changes hands
/// with no confirmation. The caller is a user, or an API key that belongs to one. Each alert that changes
/// has an audit row.
#[utoipa::path(
    put,
    path = "/api/alerts/v1/owner",
    tag = "alerts",
    request_body = OwnerRequest,
    responses(
        (status = 200, description = "The alerts that changed and those left alone", body = OwnerChangeBody),
        (status = 400, description = "No alerts or more than 500, a new owner who doesn't exist or is disabled, a caller that isn't a user, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write, or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn owner(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<OwnerRequest>, JsonRejection>,
) -> Result<Json<OwnerChangeBody>, ApiError> {
    let Json(body) = body?;
    let confirmed = body
        .take_owned
        .into_iter()
        .map(|(alert, owner)| (alert, ace_service::UserId(owner)))
        .collect();
    let changed = web
        .service
        .change_alert_owner(
            &actor,
            &body.alerts,
            body.owner.map(ace_service::UserId),
            &confirmed,
        )
        .await?;
    Ok(Json(OwnerChangeBody {
        applied: changed.applied,
        skipped: changed
            .skipped
            .into_iter()
            .map(|skipped| {
                (
                    skipped.alert,
                    SkippedOwnerBody {
                        owner: skipped.owner.0,
                        name: skipped.name,
                    },
                )
            })
            .collect(),
        message: changed.message,
    }))
}

/// What the disposition did to the alert's analysis.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DispositionedBody {
    /// Queued and delayed tasks it cancelled.
    cancelled: usize,
    /// Running tasks it asked to stop.
    stopped: usize,
    /// The dispositioned mode's tasks it queued.
    queued: usize,
}

/// The alerts the filters match, newest first or in the order asked, a page at a time, with how many
/// match in all. Follow `next` until it's null, with the same filters and order: each order breaks ties by
/// the alert's id, so an alert that arrives meanwhile never shifts a later page.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts",
    tag = "alerts",
    params(AlertsQuery),
    responses(
        (status = 200, description = "A page of alerts", body = AlertPageBody),
        (status = 400, description = "A filter, order, timezone or limit that isn't one, a cursor of another order or that names no alert, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<AlertPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = alert_query(&params)?;
    let limit = params.parsed("limit", "a number from 1 to 1000")?;
    let page = web
        .service
        .alerts(&actor, &query, limit, params.one("after")?)
        .await?;
    Ok(Json(AlertPageBody {
        alerts: page.alerts.into_iter().map(AlertBody::from).collect(),
        next: page.next,
        total: page.total,
    }))
}

async fn export_alerts(
    format: Format,
    actor: Actor,
    web: Web,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let (service, max) = (web.service, web.config.max_export_rows);
    let params = Params::of(raw)?;
    let query = alert_query(&params)?;
    let first = service
        .alerts(&actor, &query, Some(EXPORT_PAGE), None)
        .await?;
    let total = first.total;
    let first = (
        first.alerts.into_iter().map(AlertBody::from).collect(),
        first.next,
    );
    export::respond(
        format,
        "alerts",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .alerts(&actor, &query, Some(EXPORT_PAGE), Some(&cursor))
                    .await?;
                Ok((
                    page.alerts.into_iter().map(AlertBody::from).collect(),
                    page.next,
                ))
            }
        },
    )
}

/// Every alert the list's filters match, in its order, as CSV: a header line, then a row per alert, with a
/// cell that a spreadsheet would read as a formula behind a `'`. A failure part-way ends the file there.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/export/csv",
    tag = "alerts",
    params(AlertExportQuery),
    responses(
        (status = 200, description = "The alerts", content_type = "text/csv", body = String),
        (status = 400, description = "A filter, order or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 413, description = "More alerts than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_csv(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_alerts(Format::Csv, actor, web, raw).await
}

/// Every alert the list's filters match, in its order, as NDJSON: an alert as the list gives it on each
/// line. A failure part-way ends it with an `{"error": ...}` line.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/export/ndjson",
    tag = "alerts",
    params(AlertExportQuery),
    responses(
        (status = 200, description = "The alerts", content_type = "application/x-ndjson", body = String),
        (status = 400, description = "A filter, order or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 413, description = "More alerts than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_ndjson(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_alerts(Format::Ndjson, actor, web, raw).await
}

/// One alert, with how many observables, files and detections it holds.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id")),
    responses(
        (status = 200, description = "The alert", body = AlertDetailBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<AlertDetailBody>, ApiError> {
    let Path(id) = id?;
    let alert = web.service.alert(&actor, id).await?;
    Ok(Json(alert.into()))
}

/// An alert's observables in the order they were added, each with its files, relationships, results
/// and detections, a page at a time.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}/observables",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id"), ObservablesQuery),
    responses(
        (status = 200, description = "A page of observables", body = ObservablePageBody),
        (status = 400, description = "A limit out of range, or an id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
    )
)]
pub(crate) async fn observables(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    query: Result<Query<ObservablesQuery>, QueryRejection>,
) -> Result<Json<ObservablePageBody>, ApiError> {
    let (Path(id), Query(query)) = (id?, query?);
    let page = web
        .service
        .alert_observables(&actor, id, query.limit, query.after)
        .await?;
    Ok(Json(page.into()))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GraphNodeKindBody {
    Alert,
    Observable,
    Result,
    Tag,
}

/// A node of the graph.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct GraphNodeBody {
    /// `alert`, `o<id>`, `r<id>` or `t<n>`, unique in the graph, which its edges name.
    id: String,
    kind: GraphNodeKindBody,
    /// The alert's title, an observable's type and value, a result's module or a tag, at most 80
    /// characters. It's the alert's text: show it as text.
    label: String,
    /// An observable's id in the alert, as `/observables` gives it.
    observable: Option<i64>,
    /// A result's id in the alert.
    result: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GraphEdgeKindBody {
    /// The alert to an observable its submission added.
    Observed,
    /// An observable to a result of it.
    Analyzed,
    /// A result to an observable it added.
    Added,
    /// An observable or result to its tag.
    Tagged,
    /// An observable to the observable a relationship of it names.
    Related,
}

/// An edge of the graph, between two of its nodes.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct GraphEdgeBody {
    from: String,
    to: String,
    kind: GraphEdgeKindBody,
    /// A `related` edge's relationship, such as `extracted_from`.
    relationship: Option<String>,
}

/// An alert's relationship graph.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct GraphBody {
    alert: Uuid,
    nodes: Vec<GraphNodeBody>,
    edges: Vec<GraphEdgeBody>,
    /// Whether the graph was cut short: it holds at most 1000 nodes and 2000 edges, nearest the alert
    /// first, from a tree of at most 5000 observables.
    truncated: bool,
    /// What was left out, when anything was.
    note: Option<String>,
}

impl From<AlertGraph> for GraphBody {
    fn from(graph: AlertGraph) -> Self {
        use ace_service::{GraphEdgeKind, GraphNodeKind};
        GraphBody {
            alert: graph.alert,
            nodes: graph
                .nodes
                .into_iter()
                .map(|node: GraphNode| GraphNodeBody {
                    id: node.id,
                    kind: match node.kind {
                        GraphNodeKind::Alert => GraphNodeKindBody::Alert,
                        GraphNodeKind::Observable => GraphNodeKindBody::Observable,
                        GraphNodeKind::Result => GraphNodeKindBody::Result,
                        GraphNodeKind::Tag => GraphNodeKindBody::Tag,
                    },
                    label: node.label,
                    observable: node.observable,
                    result: node.result,
                })
                .collect(),
            edges: graph
                .edges
                .into_iter()
                .map(|edge: GraphEdge| GraphEdgeBody {
                    from: edge.from,
                    to: edge.to,
                    kind: match edge.kind {
                        GraphEdgeKind::Observed => GraphEdgeKindBody::Observed,
                        GraphEdgeKind::Analyzed => GraphEdgeKindBody::Analyzed,
                        GraphEdgeKind::Added => GraphEdgeKindBody::Added,
                        GraphEdgeKind::Tagged => GraphEdgeKindBody::Tagged,
                        GraphEdgeKind::Related => GraphEdgeKindBody::Related,
                    },
                    relationship: edge.relationship,
                })
                .collect(),
            truncated: graph.truncated,
            note: graph.note,
        }
    }
}

/// An alert's relationship graph, which the GUI's graph page draws: a node for the alert, each
/// observable, each result and each tag, and an edge for each observable the submission or a result
/// added, each result of an observable, each tag and each relationship between two of the alert's
/// observables. It's read from one snapshot of the alert's tree, and bounded, saying so when it was cut.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}/graph",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id")),
    responses(
        (status = 200, description = "The graph", body = GraphBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
    )
)]
pub(crate) async fn graph(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<GraphBody>, ApiError> {
    let Path(id) = id?;
    Ok(Json(web.service.alert_graph(&actor, id).await?.into()))
}

/// A file observable's bytes, as a zip encrypted with AES-256 and the password `infected`, as ace3's
/// downloads are, holding the file under its name in the alert. The download is in the audit record.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}/observables/{observable}/file",
    tag = "alerts",
    params(
        ("id" = Uuid, Path, description = "The alert's id"),
        ("observable" = i64, Path, description = "The file observable's id in the alert"),
    ),
    responses(
        (status = 200, description = "The zip", content_type = "application/zip", body = ZipBody),
        (status = 400, description = "An observable that isn't a file, or an id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert or observable", body = ErrorBody),
    )
)]
pub(crate) async fn file(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    ids: Result<Path<(Uuid, i64)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((id, observable)) = ids?;
    let download = web.service.download_file(&actor, id, observable).await?;
    let sha256: Sha256 = download.sha256.parse().map_err(ApiError::internal)?;
    let cached = web
        .bucket
        .get(ALERT_FILES, &sha256)
        .await
        .map_err(ApiError::internal)?;
    let name = download
        .path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("file")
        .to_owned();
    zipped_file(cached.file, cached.size, name, &sha256.to_string()).await
}

/// A file from the bucket as a zip encrypted with AES-256 and the password `infected`, holding it
/// as `name`, downloaded as `<download>.zip`.
pub(crate) async fn zipped_file(
    mut source: std::fs::File,
    size: u64,
    name: String,
    download: &str,
) -> Result<Response, ApiError> {
    let zipped = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        let out = tempfile::tempfile()?;
        let mut zip = zip::ZipWriter::new(out);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .large_file(size >= u64::from(u32::MAX))
            .with_aes_encryption(zip::AesMode::Aes256, ZIP_PASSWORD);
        zip.start_file(name, options)
            .map_err(std::io::Error::other)?;
        std::io::copy(&mut source, &mut zip)?;
        let mut out = zip.finish().map_err(std::io::Error::other)?;
        out.seek(SeekFrom::Start(0))?;
        Ok(out)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
    zip_download(zipped, download)
}

/// A finished zip, read from its start, as the answer: downloaded as `<download>.zip`.
pub(crate) fn zip_download(zipped: std::fs::File, download: &str) -> Result<Response, ApiError> {
    let length = zipped.metadata().map_err(ApiError::internal)?.len();
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(
        tokio::fs::File::from_std(zipped),
    ));
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/zip".to_owned()),
            (header::CONTENT_LENGTH, length.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{download}.zip\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        body,
    )
        .into_response())
}

/// One of the site's dispositions.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DispositionBody {
    name: String,
    /// An event's disposition is its alerts' highest ranked. OPEN is 0.
    rank: i32,
    /// The badge's class: a class token of letters, digits, `-` and `_`, such as Bootstrap's `danger`.
    css: String,
    /// Whether choosing it offers Save to Event.
    show_save_to_event: bool,
    /// False when only ACE sets it: `PUT .../disposition` refuses it from an analyst or an API key, and
    /// refuses a change to an alert that has it.
    analyst_selectable: bool,
    /// What it says about an alert's detections: `tp`, `fp`, or null for an unclassified one.
    #[schema(value_type = Option<String>)]
    class: Option<&'static str>,
}

/// The site's dispositions.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DispositionsBody {
    /// In the site's order: ace3's, then the site's own.
    dispositions: Vec<DispositionBody>,
}

/// The site's dispositions in order, each with its rank, badge class, whether it offers Save to Event,
/// whether an analyst may choose it, and its class in the detection verdicts. An alert may still carry a
/// disposition that isn't listed, one the site has since dropped from its configuration.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/dispositions",
    tag = "alerts",
    responses(
        (status = 200, description = "The site's dispositions", body = DispositionsBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
    )
)]
pub(crate) async fn dispositions(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<DispositionsBody>, ApiError> {
    let set = web.service.disposition_list(&actor).await?;
    Ok(Json(DispositionsBody {
        dispositions: set
            .all()
            .iter()
            .map(|disposition| DispositionBody {
                name: disposition.name.clone(),
                rank: disposition.rank,
                css: disposition.css.clone(),
                show_save_to_event: disposition.show_save_to_event,
                analyst_selectable: disposition.analyst_selectable,
                class: set.class(&disposition.name).map(|class| match class {
                    ace_service::DispositionClass::Tp => "tp",
                    ace_service::DispositionClass::Fp => "fp",
                }),
            })
            .collect(),
    }))
}

/// Records an analyst's verdict on the alert. Its analysis is cancelled and it moves to the
/// dispositioned mode. A later disposition replaces the earlier one and who made it. A root that no
/// detection made an alert can be dispositioned too, as the service allows. The disposition is one of
/// the site's, and one only ACE sets is refused, as is a change to an alert that has one. `comment` is
/// added to the alert with it, by the caller's user. The caller, a user or a key of one, becomes the
/// owner of an alert nobody owns. An alert another analyst owns is left
/// alone, unless `take_from` names that analyst or their account is disabled, and is then the caller's.
#[utoipa::path(
    put,
    path = "/api/alerts/v1/alerts/{id}/disposition",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id")),
    request_body = DispositionRequest,
    responses(
        (status = 200, description = "The disposition is recorded", body = DispositionedBody),
        (status = 400, description = "Not one of the site's dispositions, one only ACE sets, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write, sent a comment without being a person or a person's key, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such root", body = ErrorBody),
        (status = 409, description = "The alert's disposition is one only ACE sets, which an analyst can't change, or another analyst owns the alert and `take_from` doesn't name them", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn disposition(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<DispositionRequest>, JsonRejection>,
) -> Result<Json<DispositionedBody>, ApiError> {
    let (Path(id), Json(body)) = (id?, body?);
    let done = web
        .service
        .disposition(
            &actor,
            id,
            &body.disposition,
            body.take_from.map(ace_service::UserId),
            body.comment.as_deref(),
        )
        .await?;
    Ok(Json(DispositionedBody {
        cancelled: done.cancelled.cancelled.len(),
        stopped: done.cancelled.signalled.len(),
        queued: done.queued.len(),
    }))
}

/// Edits the text of a comment on the alert, ace3's `PATCH /api/v2/alerts/{uuid}/comments/{id}`. Only
/// the comment's author may (403). Text whose line breaks and ends are all that differ from what's stored
/// is no change: the comment isn't marked edited.
#[utoipa::path(
    patch,
    path = "/api/alerts/v1/alerts/{id}/comments/{comment}",
    tag = "alerts",
    params(
        ("id" = Uuid, Path, description = "The alert's id"),
        ("comment" = i64, Path, description = "The comment's id"),
    ),
    request_body = EditCommentRequest,
    responses(
        (status = 200, description = "The comment as it is now", body = AlertCommentBody),
        (status = 400, description = "An id that isn't one, a comment that's empty or too long, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write, isn't the comment's author, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such comment on this alert", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn edit_comment(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(Uuid, i64)>, PathRejection>,
    body: Result<Json<EditCommentRequest>, JsonRejection>,
) -> Result<Json<AlertCommentBody>, ApiError> {
    let Path((id, comment)) = path?;
    let Json(body) = body?;
    let edited = web
        .service
        .edit_alert_comment(&actor, id, comment, &body.comment)
        .await?;
    Ok(Json(AlertCommentBody::from(edited)))
}

/// A directive an analyst may add, and what it asks for.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DirectiveBody {
    name: String,
    description: String,
}

/// The directives an analyst may add to an observable, in name order.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DirectivesBody {
    directives: Vec<DirectiveBody>,
}

/// The directives an analyst may add to an observable (PLAN.md decision 31): those of ace3's
/// `GUI_DIRECTIVES` an ace-rs module reads and the site's, in name order, with ace3's descriptions. ace3's `GET /api/v2/common/valid_directives` lists
/// every directive under `system:read`; this lists the ones an analyst may add, under `alert:read`.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/directives",
    tag = "alerts",
    responses(
        (status = 200, description = "The directives an analyst may add", body = DirectivesBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
    )
)]
pub(crate) async fn directives(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<DirectivesBody>, ApiError> {
    let list = web.service.directive_list(&actor).await?;
    Ok(Json(DirectivesBody {
        directives: list
            .iter()
            .map(|directive| DirectiveBody {
                name: directive.name.to_owned(),
                description: directive.description.to_owned(),
            })
            .collect(),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddDirectivesRequest {
    /// One or more of `GET /api/alerts/v1/directives`' names.
    directives: Vec<String>,
}

/// What adding directives did.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DirectivesAddedBody {
    /// The directives the observable didn't have, in the order asked for.
    added: Vec<String>,
    /// The observable's directives now.
    directives: Vec<String>,
    /// How many tasks the alert queued, anew or again.
    queued: usize,
}

/// Adds directives to an observable of the alert and analyzes the alert again in correlation mode, as
/// ace3's Add Observable form and its observable actions do (PLAN.md decision 31): a module that requires
/// one of them is queued, and what a disposition cancelled runs again. A directive the observable has is
/// left as it is, and the alert is analyzed again all the same. An alert whose disposition only ACE sets is
/// refused. There's no way to remove a directive, as in ace3.
#[utoipa::path(
    post,
    path = "/api/alerts/v1/alerts/{id}/observables/{observable}/directives",
    tag = "alerts",
    params(
        ("id" = Uuid, Path, description = "The alert's id"),
        ("observable" = i64, Path, description = "The observable's id in the alert"),
    ),
    request_body = AddDirectivesRequest,
    responses(
        (status = 200, description = "The directives are on the observable, and the alert is analyzed again", body = DirectivesAddedBody),
        (status = 400, description = "No directive, one an analyst may not add, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold observable:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such alert, or no such observable in it", body = ErrorBody),
        (status = 409, description = "The alert's disposition is one only ACE sets, so it isn't analyzed again", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn add_directives(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(Uuid, i64)>, PathRejection>,
    body: Result<Json<AddDirectivesRequest>, JsonRejection>,
) -> Result<Json<DirectivesAddedBody>, ApiError> {
    let (Path((id, observable)), Json(body)) = (path?, body?);
    let done = web
        .service
        .add_directives(&actor, id, observable, &body.directives)
        .await?;
    Ok(Json(DirectivesAddedBody {
        added: done.added,
        directives: done.directives,
        queued: done.queued,
    }))
}

/// Which alerts to compare.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommonalitiesRequest {
    /// 1 to 500 alerts, in the order the page lists them.
    #[schema(min_items = 1, max_items = 500)]
    alerts: Vec<Uuid>,
    /// Up to 100 observables, each `type:value`, to leave out of the grouping.
    #[serde(default)]
    #[schema(max_items = 100)]
    ignore: Vec<String>,
}

/// A group of alerts that potentially relate.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CommonalityGroupBody {
    /// The group's alerts, the most strongly linked first.
    alerts: Vec<Uuid>,
    /// 0 to 1: how much the group's alerts have in common, from its size and how many observable values
    /// its pairs of alerts share.
    intensity: f64,
    /// How many observable values every alert of the group has.
    shared: usize,
    /// The most observable values any alert of the group has.
    total: usize,
    /// Every pair of the group's alerts shares at least 90% of the values of the one with more.
    near_identical: bool,
}

/// One observable value two or more of the alerts have. They may have it under more than one type (an
/// address as both the sender and the return path): `types` lists them, most useful first, and `type`
/// is the first.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CommonalityObservableBody {
    #[serde(rename = "type")]
    kind: String,
    types: Vec<String>,
    value: String,
    /// The requested alerts that have it.
    alerts: Vec<Uuid>,
    /// The index in `groups` of the first group with an alert that has it.
    group: usize,
    /// The indexes of every group with an alert that has it; more than one means it links groups.
    groups: Vec<usize>,
}

/// The requested alerts grouped by the observable values they share. Alerts sharing two or more are
/// grouped together; alerts sharing only one are grouped only with alerts no stronger group took.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CommonalitiesBody {
    groups: Vec<CommonalityGroupBody>,
    /// Every observable value two or more of the alerts have, ordered by group and, within one, most
    /// useful first: values that link groups, then by type (the overlay's
    /// `gui.commonalities_priority_types`), then by how many of the group's alerts have it.
    observables: Vec<CommonalityObservableBody>,
    /// Each alert sharing anything -> how many other requested alerts share at least one value with it.
    related: std::collections::BTreeMap<Uuid, usize>,
    /// How many of the requested alerts share nothing with any other.
    unrelated: usize,
    /// Each type in `observables` -> the types it extends, nearest first (`email_from` ->
    /// `[email_address]`), so a type without a color of its own can take its parent's.
    type_ancestors: std::collections::BTreeMap<String, Vec<String>>,
}

impl From<ace_service::commonalities::Commonalities> for CommonalitiesBody {
    fn from(found: ace_service::commonalities::Commonalities) -> Self {
        CommonalitiesBody {
            groups: found
                .groups
                .into_iter()
                .map(|group| CommonalityGroupBody {
                    alerts: group.alerts,
                    intensity: group.intensity,
                    shared: group.shared,
                    total: group.total,
                    near_identical: group.near_identical,
                })
                .collect(),
            observables: found
                .observables
                .into_iter()
                .map(|o| CommonalityObservableBody {
                    kind: o.kind,
                    types: o.kinds,
                    value: o.value,
                    alerts: o.alerts,
                    group: o.group,
                    groups: o.groups,
                })
                .collect(),
            related: found.related,
            unrelated: found.unrelated,
            type_ancestors: found.type_ancestors,
        }
    }
}

/// Groups the alerts by the observable values they share, so an analyst sees which alerts on a page
/// are potentially the same activity (the alert list's Commonalities panel). An id that isn't an alert
/// is left out. A POST because the list of alerts can be long; nothing is changed.
#[utoipa::path(
    post,
    path = "/api/alerts/v1/commonalities",
    tag = "alerts",
    request_body = CommonalitiesRequest,
    responses(
        (status = 200, description = "The alerts' groups and the values they share", body = CommonalitiesBody),
        (status = 400, description = "No alerts or more than 500, more than 100 to ignore, queries that ran past their 10 s, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read, or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn commonalities(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<CommonalitiesRequest>, JsonRejection>,
) -> Result<Json<CommonalitiesBody>, ApiError> {
    let Json(body) = body?;
    let found = web
        .service
        .alert_commonalities(&actor, &body.alerts, &body.ignore)
        .await?;
    Ok(Json(found.into()))
}
