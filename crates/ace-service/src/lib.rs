//! The service layer: the writes people and ACE's own components make, each carrying who made it.
//!
//! `Actor` is the one value for who is acting (PLAN.md 5.1, ace3 #1089). Every function here that
//! writes takes `&Actor` as its first argument, with no default and no `Option`, so a caller can't
//! forget it. The type lives below the adapters, so nothing has to import an API crate to name it
//! (ace3 #953).
//!
//! `ace-service` depends on `ace-core`, and the core doesn't know about actors. A write here opens
//! the transaction, calls the core's functions with it, and records the actor in the same
//! transaction. So what records an analyst's decision lives here, and the core keeps what the
//! decision does to the queue.
//!
//! Every write also names the permission it needs. `gate` holds the database, so a function here
//! can only write through `Gate::write`, which refuses an actor without that permission before the
//! write looks at anything. `gate`'s docs say who holds what, and `permission`'s say what a name is.
//!
//! `auth` turns a GUI session or an API key into an `Actor`, or refuses it, and an adapter calls it before
//! anything else. It also holds the first admin and the writes on users and keys.
//!
//! Every write says what it changed too, because `Gate::write`'s body has to return `Audited`. The
//! gate writes the row in the write's transaction (`gate::audit`). To add a write: call `Gate::write`
//! once, with the function's own name as its action, and add the function to
//! `every_write_function_has_an_audit_test` and `every_write_fails_when_its_audit_fails` in
//! `tests/service.rs`, which read this crate's source and fail until both cover it.
//!
//! Reads go through `Gate::read`, which checks a permission the same way and writes no row: `alerts` and
//! `observables`. A read ace3 audits, such as a file's download, goes through `Gate::write` with a row
//! that says what was read. A row records the request's source address when an adapter gives one
//! (`source`). Nothing reads `service.audit` yet. ace3's reader is Splunk searching log lines, and
//! `Gate::write`'s log line keeps that search working.
//!
//! `users` reads users, groups and keys, and changes profiles, groups and keys' scopes, for 5.6's `users`
//! router. `permission::CATALOG` is ace3's catalog of the names ACE checks. Not here from ace3: a 403
//! saying which half of a key's check refused.
//!
//! `crashes` reads failed tasks for 5.6's `crashes` router, and audits their download as a read.
//!
//! `commands` starts and cancels the commands analysts run from the GUI (5.12), ace3's `cli` router, and
//! reads them with their output. A pool runs each, contained, until its deadline.
//!
//! `detection` keeps the observables ACE detects wherever they appear, entries of 5.14's
//! `observable_detection` list, for 5.6's `detection` router and 5.11's admin page (7.6).
//!
//! `detection_points` lists every alert's detections for 5.6's `detection_points` router, each with its
//! verdict, and `detection_verdicts` writes the verdicts (7.14), which SVS reads for its labels.
//!
//! `yara_qa` reads the rules in QA mode and what they matched for 5.6's `yara_qa` router, audits a download
//! of the files as a read, and purges matches as a write.
//!
//! `observable_comments` keeps analysts' comments on an observable by its type and value, across alerts,
//! for 5.6's `observable_comments` router, and reads an alert's for 5.8's alert view.
//!
//! `events` reads events, adds alerts to them, sets their status, edits them, takes alerts out and tags
//! them, and keeps the threat types and malware's threats, for 5.11's events area and ace3's `events`,
//! `threat_types` and `threats` routers.
//!
//! `alert_view` reads an alert's whole tree for 5.8's alert view, and watches an alert for results landing
//! on it, so an open page can show them. `alert_graph` turns that tree into 5.13's relationship graph.
//!
//! `directives` adds the directives an analyst asks for to an observable of an alert and analyzes it
//! again (PLAN.md decision 31), from the list the binary registers, ace3's `GUI_DIRECTIVES` and a site's.
//!
//! `preferences` keeps a user's GUI preferences, ace3's `user_preferences` router, for 5.7's GUI and its
//! routes under `/api/users/v1/me/preferences`.
//!
//! `lists` keeps the analyst-edited lists (5.14), such as the observables enabled for detection, which the lease
//! API adds to the tasks of the modules that read them.
//!
//! `maintenance` holds the bucket's scheduled maintenance (PLAN.md 6.7): GC, the orphan sweep and the
//! verify, each under its own permission, which only the scheduler's components hold. `yara_qa` holds the
//! prune of expired QA matches.
//!
//! `remediation` queues, stops, retries, restores and deletes remediations, finds the remediation targets
//! of alerts and observables, and sums up an alert's remediation coverage, and `file_collections` lists,
//! stops, retries, deletes and prunes file collections (7.9), each an action of `ace_core::actions`, which
//! network pools run from the queue.
//!
//! `svs` is SVS's service side (7.10): the test hosts, under `svs:admin` to change and `svs:run_read` to
//! read, and an alert's SVS status, read with the alert. Its model is `ace_core::svs`. `svs_catalog` is the
//! Atomic Red Team test catalog (batch 4): its tests and repositories under `svs:run_read`, and its
//! refresh under `svs:catalog_refresh`. `svs_runs` is a test run's life (batch 5): registration and a
//! launcher's calls under `svs:run_register`, the timers under `svs:run_timers`, refused registrations
//! and the test hosts' maintenance windows. `svs_results` is a run's result (batch 5): what fired against
//! what its test is expected to fire, computed as the run ends and whenever it's stale. `svs_decisions`
//! is what's decided about a test's signatures: its expectations, ignores and settings, under
//! `svs:run_manage` (a global ignore under `svs:admin`), each with a precondition for a write made from a
//! page. `svs_run_reads` is the runs screen: the runs with ace3's filters, their batches, the event and
//! result feeds, a run's result, history and comments. `svs_test_state` reads a catalog test's state and
//! run history (batch 8), which the catalog's list carries. `svs_coverage` is ATT&CK coverage per
//! technique and platform: its refresh under `svs:coverage_refresh`, its daily snapshot under
//! `svs:coverage_snapshot`, and its reads under `svs:run_read`. `svs_worklist` is the declared-vs-measured
//! worklist, read under `svs:run_read` and resolved under `svs:run_manage`.
//!
//! `routing` is alert routing (7.13), ace3's `saq/alert_routing/`: the routers that decide which queue an
//! alert belongs in, run by `ace serve`'s routing worker when an alert's pass completes, and the audited move
//! between queues.
//!
//! `alert_automation` is ace3's alert automation (7.22): the overlay's rules, which the scheduler's
//! `alert_automation` sweeps under `alert_automation:run`, each disposing an alert, queueing its removals or
//! recording a comment when its trigger, a probe's confirmed remediation check, fires.
//!
//! `filters` is the filter model of a list screen (5.10), ace3's filter language and share links, which the
//! alert list (`alerts`) and the detection points (`detection_points`) take, and `saved_filters` keeps an
//! analyst's saved filters, ace3's `saved_filters` router.
//!
//! Writes outside this crate today:
//! - `Orchestrator::set_mode` and `queue::cancel_root` have no caller outside the core's own flows
//!   and tests. Each gets a function here when a route for it appears (5.5, 5.6).
//! - The lease API, `Orchestrator::land_result`, the reaper, the ruleset builder, the QA recorder and
//!   the scheduler's own rows (`ace_core::scheduler`) stay out for good. They are the engine's own writes, not requests: a pool authenticates with
//!   its token, and a task's row names its `lease_owner`. So do a GUI command's claim, reports and end
//!   (5.12), which its pool makes; its start and cancel are here.

mod actor;
pub mod ai;
mod alert_automation;
mod alert_graph;
mod alert_view;
mod alert_work;
mod alerts;
mod auth;
mod collection;
mod commands;
mod crashes;
mod detection;
mod detection_points;
mod detection_verdicts;
mod directives;
mod dispositions;
mod email_archive;
mod events;
mod exports;
mod file_collections;
pub mod filters;
mod gate;
mod hunts;
mod lists;
mod maintenance;
mod monitoring;
mod observable_comments;
mod observables;
mod ownership;
mod permission;
mod preferences;
mod remediation;
mod remediation_timeline;
pub mod routing;
mod saved_filters;
pub mod search;
mod source;
mod submit;
mod svs;
pub mod svs_association;
mod svs_catalog;
mod svs_coverage;
mod svs_decisions;
mod svs_results;
mod svs_review;
mod svs_run_reads;
mod svs_runs;
mod svs_samples;
mod svs_test_state;
mod svs_validations;
mod svs_worklist;
mod users;
mod yara_qa;

use ace_core::bucket::BucketError;
use ace_core::db::{Db, DbError, Retryable};
use ace_core::orchestrator::{Dispositioned, Orchestrator, OrchestratorError};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::types::Json;
use uuid::Uuid;

use gate::{Audited, Change, Gate, Recorded, TITLE_LIMIT, Target};

pub use ace_core::submit::SubmittedFile;
pub use ace_core::svs::catalog::{
    RefreshResult as CatalogRefresh, RepositoryStatus as CatalogRepository,
    Skipped as CatalogSkipped,
};
pub use ace_core::svs::coverage::{
    CoverageState as SvsCoverageState, CoverageStatus as SvsCoverageStatus,
    RefreshState as SvsCoverageRefreshState,
};
pub use ace_core::svs::hosts::HostFields;
pub use ace_core::svs::results::{Precondition, ResultRow, ResultStatus};
pub use ace_core::svs::runs::{
    HostHolder, ObservationSource, Registration, RunsConfig, TargetSpec,
};
pub use ace_core::svs::samples::{
    CaptureState, Label as SampleLabel, MissingReason, Strength as VoteStrength,
    Votes as SampleVotes,
};
pub use ace_core::svs::test_state::{PlatformHistory, TestHistory, TestState};
pub use ace_core::svs::validations::ValidationState;
pub use ace_core::svs::worklist::{WorklistKind, WorklistResolution, WorklistStatus};
pub use ace_core::svs::{AttributionConfidence, RunState, SvsStatus};
pub use ace_core::tree::DEFAULT_QUEUE;
pub use ace_sdk::actions::{ActionKind, RemediationAction};
pub use ace_sdk::directives::{Directive, DirectiveList};
pub use ace_sdk::lists::MatchKind;
pub use actor::{Actor, ApiKeyId, Component, InvalidComponent, UserId};
pub use alert_automation::{
    ActionRecord, ActionStatus, AlertAutomation, AutomationSweep, Confirmation, Detail, Evidence,
    Rule as AutomationRule, RunStatus,
};
pub use alert_graph::{
    AlertGraph, GraphEdge, GraphEdgeKind, GraphNode, GraphNodeKind, MAX_GRAPH_EDGES,
    MAX_GRAPH_NODES, MAX_LABEL_CHARS, graph_of,
};
pub use alert_view::{Addition, AlertTree, AlertWatch, MAX_TREE_OBSERVABLES, RESULTS_CHANNEL};
pub use alert_work::{AlertWork, MAX_SLOWEST, MAX_WORK_ROWS, ModuleTime, WorkTask};
pub use alerts::{
    Alert, AlertDetection, AlertFile, AlertObservable, AlertPage, AlertQuery, AlertSort,
    AlertSummary, AnalysisState, FailedModule, FileDownload, FileHead, LIST_TIMEOUT,
    MAX_ALERTS_PAGE, MAX_OBSERVABLES_PAGE, ModuleResult, ObservablePage, RecordedActor,
    Relationship,
};
pub use auth::{
    InvalidUsername, IssuedToken, MAX_PASSWORD_BYTES, MIN_PASSWORD_CHARS, NewApiKey, NewSession,
    Password, RequestParts, SESSION_LIFETIME_SECONDS, SessionCookie, Transport, Username,
};
pub use collection::{Collected, DEFAULT_KEY_LIFETIME};
pub use commands::{
    CommandDetail, CommandPage, CommandRun, CommandState, DEFAULT_COMMAND_TIMEOUT_SECONDS,
    MAX_COMMAND_CHARS, MAX_COMMAND_TIMEOUT_SECONDS, MAX_COMMAND_WORDS, MAX_COMMANDS_PAGE,
    parse_command,
};
pub use crashes::{Crash, CrashDetail, CrashFilter, CrashInput, CrashPage, MAX_CRASHES_PAGE};
pub use detection::{
    DEFAULT_DETECTION_LIFETIME_DAYS, DEFAULT_DETECTION_PAGE_SIZE, DETECTION_LIST,
    DETECTION_PAGE_SIZES, Detection, DetectionExpiry, DetectionExport, DetectionExportRuleset,
    DetectionExportSkipped, DetectionExportType, DetectionFilter, DetectionPage, DetectionStatus,
    DetectionTypes, NEVER_EXPIRING_TYPES, NewDetection, clamp_detection_page_size,
    default_detection_expiry, detection_identity, detection_search_pattern,
};
pub use detection_points::{
    DetectionPoint, DetectionPointFilter, DetectionPointPage, MAX_DETECTIONS_PAGE,
};
pub use detection_verdicts::{
    BatchRules, DispositionClass, DispositionClasses, MAX_VERDICT_TARGETS, SkipCause,
    SkippedDetection, Verdict, VerdictBatch, VerdictSource, effective_verdict,
};
pub use directives::DirectivesAdded;
pub use dispositions::{
    BADGE_STYLES, DEFAULT_BADGE, Disposition, Dispositions, MAX_BADGE_CLASS_CHARS,
    MAX_DISPOSITION_CHARS, MAX_RANK, is_badge_class, is_disposition_name,
};
pub use email_archive::{
    ArchiveDownload, ArchiveLookup, ArchivedEmail, EmailCopy, MAX_DOWNLOAD_BYTES,
    MAX_DOWNLOAD_FILES,
};
pub use events::{
    AddedToEvent, CLOSED_EVENTS_PAGE, CLOSED_STATUS, CampaignChoice, Event, EventAlert,
    EventChoice, EventChoices, EventEdit, EventEditChoices, EventListPage, EventMalware,
    EventOwner, EventOwnerChoice, EventPage, EventRef, EventTimes, EventValue,
    MAX_CATALOG_NAME_CHARS, MAX_EDIT_MALWARE, MAX_EVENT_ALERTS, MAX_EVENT_CHOICES,
    MAX_EVENT_COMMENT_CHARS, MAX_EVENT_NAME_CHARS, MAX_EVENT_TAG_CHARS, MAX_EVENT_TAGS,
    MAX_EVENTS_PAGE, MAX_EXPORT_EVENTS, MAX_NEW_MALWARE_THREATS, MAX_THREAT_TYPE_CHARS,
    MalwareChoice, NewEvent, RemovedAlerts, Threat, ThreatType,
};
pub use exports::{ExportOutcome, ExportRecord, MAX_EXPORT_STATE_BYTES};
pub use file_collections::{
    CollectedDownload, CollectionAsk, CollectionRequested, CollectionsPruned, FileCollection,
    FileCollectionPage, MAX_COLLECTION_ALERTS, PAST_LIMIT_RETRY_SECONDS,
};
pub use filters::events::{
    EventFilters, EventOwnerFilter, EventQuery, EventSort, MAX_EVENT_FILTER_IDS,
    MAX_EVENT_FILTER_VALUES,
};
pub use filters::{FilterEntry, FilterScreen, FilterValue};
pub use gate::Holder;
pub use hunts::{
    DEDUP_KEY_LIFETIME, GroupSuppressed, HuntRow, HuntRun, HuntState, HuntSubmission,
    HuntValidation, LoadedHuntRow, MAX_SUPPRESSIONS_PAGE, RunRecorded, SUPPRESSION_RETENTION,
    Suppression, SuppressionPage, SuppressionReason,
};
pub use lists::{ListEntry, ListSummary, ListView, NewListEntry};
pub use maintenance::{PoolGc, PoolOrphans, PoolVerify, RootsCleaned};
pub use monitoring::{
    MAX_MONITOR_RECORDS_READ, MonitorCheck, MonitorRecord, MonitorReport, MonitoringState,
    ScheduledRun, ScheduledTask,
};
pub use observable_comments::{CommentAuthor, MAX_COMMENT_CHARS, ObservableComment};
pub use observables::{
    Lookup, MAX_EXCLUDED_ALERTS, MAX_LOOKUP_PAIRS, MAX_RECENT_ALERTS, OPEN, Prevalence, RecentAlert,
};
pub use ownership::{
    AlertOwner, MAX_OWNER_ALERTS, MAX_OWNER_CHOICES, OwnerChange, OwnerChoice, OwnershipCheck,
    SkippedAlert, check_alert_ownership, confirmed_takes, describe_frozen, describe_skipped,
};
pub use permission::{
    ADMIN_READ, AI_ALERT, AI_BACKENDS, AI_EVENT, AI_EXPORT, AI_SEARCH, ALERT_AUTOMATION_RUN,
    ALERT_CREATE, ALERT_QUEUE, ALERT_READ, ALERT_WRITE, ANALYSIS_CACHE_MAINTAIN, ANALYSIS_CLEANUP,
    BUCKET_GC, BUCKET_VERIFY, CATALOG, CLI_EXECUTE, CRASH_READ, CatalogEntry, DETECTION_READ,
    DETECTION_WRITE, EMAIL_ARCHIVE_MAINTAIN, EMAIL_READ, EVENT_READ, EVENT_WRITE, EXPORT_RECORD,
    Effect, FILE_COLLECTION_CREATE, FILE_COLLECTION_PRUNE, FILE_COLLECTION_READ,
    FILE_COLLECTION_WRITE, HUNT_READ, HUNT_WRITE, InvalidPermission, LIST_READ, LIST_WRITE,
    MONITORING_READ, MONITORING_REPORT, NRD_REFRESH, OBSERVABLE_READ, OBSERVABLE_WRITE,
    PermissionName, PermissionPattern, REMEDIATION_READ, REMEDIATION_WRITE, SEARCH_INDEX,
    SIGNATURE_DOWNLOAD, SIGNATURE_QA_PURGE, SIGNATURE_READ, SVS_ADMIN, SVS_COVERAGE_REFRESH,
    SVS_COVERAGE_SNAPSHOT, SVS_RUN_MANAGE, SVS_RUN_READ, SVS_RUN_REGISTER, SVS_RUN_TIMERS,
    SVS_VALIDATE, SVS_VALIDATION_PRUNE, USER_READ, USER_SELF, USER_WRITE,
};
pub use preferences::{
    AlertSectionsPreference, MANAGE_COLUMNS, MAX_ALERT_SECTIONS, ManageColumn,
    ManageColumnsPreference, Preference, PreferenceKey, PreferenceValue, Theme, ThemePreference,
    is_section_id,
};
pub use remediation::{
    ACE_SOURCE, ActionAttempt, ActionQuery, ActionSummary, COVERAGE_TYPE, Coverage, CoverageCheck,
    CoverageRemediation, CoverageState, MAX_ACTIONS_PAGE, MAX_HISTORY, MAX_TARGET_ALERTS,
    MAX_TARGETS, Remediation, RemediationPage, RemediationTarget, TOOLTIP_TARGET_LIMIT,
    TargetCoverage, TargetKey, assemble_coverage, journal_explains,
};
pub use remediation_timeline::{
    MAX_TIMELINE_EVENTS, MAX_TIMELINE_TRIES, RemediationTimeline, TimelineCheck, TimelineDelivery,
    TimelineEvent, TimelineInput, TimelineRemediation, TimelineTry, assemble_timeline,
    format_duration, upper_first,
};
pub use saved_filters::{
    MAX_SAVED_FILTER_DESCRIPTION_CHARS, MAX_SAVED_FILTER_NAME_CHARS, MAX_SAVED_FILTERS,
    NewSavedFilter, SavedFilter, SavedFilterChange,
};
pub use search::{
    IndexError, Indexed, LaneResult, Scoped, SearchConfig, SearchHit, SearchIndex, SearchLane,
    SearchRequest, SearchResponse, SearchResult, SimilarRequest, Tier,
};
pub use source::with_source_ip;
pub use submit::{ManualAlert, ManualAlerts, ManualObservable, ManualValue};
pub use svs::{
    AlertSvsStatus, AlertSvsView, MAX_TEST_HOSTS_PAGE, MarkerMismatch, RunRef, TestHost,
    TestHostPage,
};
pub use svs_association::{AlertRelease, Association, AssociationResult, MarkerRouter};
pub use svs_catalog::{
    CatalogTest, CatalogTestDetail, CatalogTestPage, CatalogTestQuery, MAX_CATALOG_TESTS_PAGE,
};
pub use svs_coverage::{
    CoverageHistoryCounts, CoverageHistoryPage, CoverageHistoryQuery, CoveragePage, CoverageQuery,
    CoverageRefresh, CoverageRow, CoverageSnapshot, CoverageSnapshotRow, CoverageSummary,
    CoverageTestRow, HistoryGroup, MAX_COVERAGE_PAGE, MAX_HISTORY_PERIODS, ManualSignature,
    MeasuredSignature, PeriodCounts, PlatformCounts, RemovedTest, TechniqueCoverage,
};
pub use svs_decisions::{
    Expectation, ExpectationPage, ExpectationQuery, ExpectationState, Ignore, IgnorePage,
    IgnoreQuery, MAX_DECISION_REASON, MAX_DECISIONS_PAGE, TestSettings,
};
pub use svs_results::ComputedResult;
pub use svs_review::{
    BulkResult, CLOSE_REASON_BY_PERSON, MAX_BULK_RUNS, MAX_RUN_REASON_CHARS, ReviewBlockers,
    ReviewOutcome, Reviewed,
};
pub use svs_run_reads::{
    HistoryRun, MAX_RUN_COMMENT_CHARS, MAX_RUN_HISTORY, MAX_RUNS_PAGE, RunAlert, RunAlertDetection,
    RunAlertPage, RunAttribution, RunAttributionPage, RunBatch, RunBatchPage, RunComment,
    RunEventFeedPage, RunEventRow, RunHistory, RunPage, RunQuery, RunResult, RunResultPage,
    RunResults, RunRow, RunSummary, SVS_NEEDS_ATTENTION_CAP, SignatureHistory, SuppressionShare,
    SvsFeed,
};
pub use svs_runs::{
    MAX_MAINTENANCE_PAGE, MAX_RUN_EVENTS_PAGE, MaintenanceWindow, REFUSAL_ALERT_TYPE, REFUSAL_TOOL,
    RegistrationDecision, Run, RunDetail, RunEvent, RunTarget, RunValidation, TimerResult,
    ValidatedTarget,
};
pub use svs_samples::{
    DownloadCapture, DownloadFile, LabelChange, MAX_DELETIONS_PAGE, MAX_SAMPLE_DOWNLOAD_BYTES,
    MAX_SAMPLE_DOWNLOAD_FILES, MAX_SAMPLE_REASON, MAX_SAMPLES_PAGE, MissingCount,
    NO_DETECTION_LEFT, Retirement, Sample, SampleCapture, SampleDeletion, SampleDetail,
    SampleDetection, SampleDownload, SamplePage, SampleQuery, SampleSort, SkippedSampleDetection,
};
pub use svs_validations::{
    CompileProblem, MAX_VALIDATIONS_PAGE, ResultSelection, RuleCount, Validation, ValidationAsk,
    ValidationDetail, ValidationPage, ValidationQuery, ValidationResult, ValidationResultPage,
    ValidationStatus, ValidationsPruned, listed_categories, new_fp_categories,
    regression_categories, validation_report_path,
};
pub use svs_worklist::{
    BulkResolution, MAX_BULK_ROWS, MAX_WORKLIST_PAGE, MeasuredTechnique, MeasuredTest,
    SignatureWorklist, WorklistPage, WorklistQuery, WorklistRefresh, WorklistRow,
};
pub use users::{ApiKey, Grant, Group, MAX_KEY_SCOPE, Profile, User, UserDetail};
pub use yara_qa::{
    MAX_PURGE_REASON, MAX_PURGE_VERSIONS, MAX_QA_DOWNLOAD_BYTES, MAX_QA_DOWNLOAD_FILES,
    MAX_QA_PAGE, QaDownload, QaMatch, QaMatchDetail, QaMatchPage, QaMatchSummary, QaPruned,
    QaPurge, QaPurged, QaRuleDetail, QaRuleFilter, QaRulePage, QaRuleSummary, QaRuleset, QaSort,
    QaStatus, QaStringSummary, QaVersion,
};

/// A group's id. Groups hold users, and their rows apply to their members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(pub Uuid);

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),
    #[error("{actor} doesn't hold {permission}")]
    PermissionDenied {
        actor: String,
        permission: PermissionName,
    },
    /// A stored row that breaks the rules of a permission, which migration 0020 should prevent.
    #[error(transparent)]
    InvalidPermission(#[from] InvalidPermission),
    /// A change that couldn't be encoded for its audit row, which fails the write.
    #[error("recording the audit row: {0}")]
    AuditEncoding(#[from] serde_json::Error),
    /// No actor: an unknown user, a wrong password or a disabled user at a login, or a credential that
    /// is wrong, revoked or expired. It says nothing more, on purpose, and an adapter shouldn't either.
    #[error("not authenticated")]
    NotAuthenticated,
    /// A session's request that another site's page could have made (`RequestParts::same_origin`).
    #[error("this request came from another site")]
    CrossSiteRequest,
    #[error("that username is taken")]
    UsernameTaken,
    #[error("that group name is taken")]
    GroupNameTaken,
    /// The user has a saved filter with this name on the screen already.
    #[error("a saved filter named {0:?} exists already")]
    FilterNameTaken(String),
    #[error("no user {0}")]
    NoUser(Uuid),
    /// A disposition of an alert another analyst owns, which the caller didn't confirm taking from them
    /// (PLAN.md 7.17, `ownership`): the alert was left alone. `owner` is who a confirmation names.
    #[error(
        "alert {alert} is owned by {name}, so it was left alone: confirm taking it from them to change it"
    )]
    AlertOwned {
        alert: Uuid,
        owner: Uuid,
        name: String,
    },
    #[error("a user exists already, so a first user needs forcing")]
    UsersExist,
    #[error("a user can't disable themselves: another user with user:write has to")]
    CantDisableYourself,
    /// A change to grants or groups that would leave the actor without `user:write`, which only another
    /// holder of it could then give back. Nothing was written.
    #[error(
        "that would take user:write from you, and only another user with user:write could give it back"
    )]
    CantDropYourOwnUserWrite,
    #[error(
        "a password has to be at least {MIN_PASSWORD_CHARS} characters and at most {MAX_PASSWORD_BYTES} bytes"
    )]
    WeakPassword,
    #[error("an API key's name is 1 to 255 characters with no control characters")]
    InvalidKeyName,
    /// Hashing failed, or there was no randomness to do it with. It holds no password.
    #[error("hashing a credential: {0}")]
    Hashing(String),
    /// A request the service can't take as it is, such as a submission naming a mode that doesn't exist
    /// or a page that's too large. Nothing was written.
    #[error("{0}")]
    InvalidRequest(String),
    /// A filter list that is well formed but can't be run as it stands: an Observable Pattern that matches
    /// more observables than the filter's bound, or whose lookup ran past its time (PLAN.md decision 39,
    /// `filters::patterns`). It is the analyst's to narrow. Nothing was listed, since a list without the
    /// filter would show more than was asked for.
    #[error("{0}")]
    FilterRefused(String),
    /// What a request names isn't there, or isn't what it says, such as a root that isn't an alert.
    #[error("{0}")]
    NotFound(String),
    /// What a request names was there and is gone for good, such as a collected file the bucket no
    /// longer holds: HTTP's 410.
    #[error("{0}")]
    Gone(String),
    /// A request for more than a limit allows at once, such as a download of too many files. Nothing was
    /// written.
    #[error("{0}")]
    TooLarge(String),
    /// A refusal that isn't about a permission the actor holds, such as changing another user's
    /// comment. Nothing was written.
    #[error("{0}")]
    Forbidden(String),
    /// A write that would clash with what's there, such as a name that's taken or a row something still
    /// uses. Nothing was written.
    #[error("{0}")]
    Conflict(String),
    /// A write made from a row that someone else has changed, added or removed since the client read it
    /// (`ace_core::svs::results::Precondition`): HTTP's 412. Nothing was written.
    #[error("{0}")]
    StaleWrite(String),
    #[error(transparent)]
    Bucket(#[from] BucketError),
    /// What the request needs isn't set up on this node, such as the email archive's key, or failed
    /// in a way only an operator can fix. Its message says which.
    #[error("{0}")]
    Unconfigured(String),
    /// A limit refused the request (PLAN.md 7.15, `ai`): HTTP's 429, with how long to wait.
    #[error("{detail}")]
    RateLimited {
        detail: String,
        retry_after_seconds: u64,
    },
    /// The request can't be served for now and may be tried again, such as when the AI API's rate
    /// limiter can't be reached: HTTP's 503.
    #[error("{0}")]
    Unavailable(String),
    /// A data source the request was sent on to failed, ran out of time or throttled it (PLAN.md
    /// 7.15): HTTP's 502, 504 or 429. The reason is the source's own, and holds no credential.
    #[error("{reason}")]
    Upstream { status: u16, reason: String },
}

impl From<DbError> for ServiceError {
    fn from(error: DbError) -> Self {
        ServiceError::Orchestrator(OrchestratorError::Db(error))
    }
}

impl From<sqlx::Error> for ServiceError {
    fn from(error: sqlx::Error) -> Self {
        ServiceError::Orchestrator(OrchestratorError::from(error))
    }
}

impl Retryable for ServiceError {
    fn is_retryable(&self) -> bool {
        match self {
            ServiceError::Orchestrator(e) => e.is_retryable(),
            ServiceError::Bucket(BucketError::Db(e)) => e.is_retryable(),
            ServiceError::Bucket(_)
            | ServiceError::Unconfigured(_)
            | ServiceError::RateLimited { .. }
            | ServiceError::Unavailable(_)
            | ServiceError::Upstream { .. }
            | ServiceError::InvalidRequest(_)
            | ServiceError::FilterRefused(_)
            | ServiceError::NotFound(_)
            | ServiceError::Gone(_)
            | ServiceError::TooLarge(_)
            | ServiceError::Forbidden(_)
            | ServiceError::Conflict(_)
            | ServiceError::StaleWrite(_)
            | ServiceError::PermissionDenied { .. }
            | ServiceError::InvalidPermission(_)
            | ServiceError::AuditEncoding(_)
            | ServiceError::NotAuthenticated
            | ServiceError::CrossSiteRequest
            | ServiceError::UsernameTaken
            | ServiceError::GroupNameTaken
            | ServiceError::FilterNameTaken(_)
            | ServiceError::NoUser(_)
            | ServiceError::AlertOwned { .. }
            | ServiceError::UsersExist
            | ServiceError::CantDisableYourself
            | ServiceError::CantDropYourOwnUserWrite
            | ServiceError::WeakPassword
            | ServiceError::InvalidKeyName
            | ServiceError::Hashing(_) => false,
        }
    }
}

/// A disposition's audit row, before and after: what it replaced and what it did to the analysis.
#[derive(Serialize)]
struct DispositionState {
    disposition: Option<String>,
    dispositioned_by: Option<Value>,
    analysis_mode: String,
    /// The alert's owner, when it has one (PLAN.md 7.17): an analyst's disposition takes an alert nobody
    /// owns.
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<Uuid>,
}

impl Recorded for DispositionState {}

/// What's needed to read a disposition's audit row after its alert is deleted. ace3 records these
/// and the alert's type, tool, queue, company and owner, which ace-rs's roots don't have yet.
#[derive(Serialize)]
struct RootSnapshot {
    title: String,
    event_time: Option<DateTime<Utc>>,
    root_created_at: DateTime<Utc>,
    /// Why, when ACE made the disposition for SVS: ace3 adds it to the alert as a comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    /// The analyst the alert was taken from, when the disposition took it (PLAN.md 7.17).
    #[serde(skip_serializing_if = "Option::is_none")]
    taken_from: Option<Uuid>,
}

impl Recorded for RootSnapshot {}

/// A permission row's audit: the row, and for a removed one who made it, since nothing else keeps that.
#[derive(Serialize)]
struct PermissionRecord<'a> {
    major: &'a str,
    minor: &'a str,
    effect: Effect,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_by: Option<Value>,
}

impl Recorded for PermissionRecord<'_> {}

/// The service layer over one database. The adapters hold one of these.
#[derive(Debug, Clone)]
pub struct Service {
    gate: Gate,
    orchestrator: Orchestrator,
    passwords: auth::Passwords,
    /// The result listener, which the alert view's watches share.
    feed: std::sync::Arc<alert_view::Feed>,
    /// The action handlers the binary has (PLAN.md 7.9): what remediates and collects, and what it
    /// acts on.
    actions: ace_core::actions::ActionCatalog,
    /// The site's dispositions and how each classifies (PLAN.md 7.14), `dispositions`' docs.
    dispositions: std::sync::Arc<dispositions::Dispositions>,
    /// The run page's link to the site's log search, the overlay's `svs.log_search_url` (PLAN.md 7.10).
    log_search: Option<std::sync::Arc<ace_core::svs::log_search::LogSearchTemplate>>,
    /// The bucket, for an adapter whose writes reach it with no bucket of its own, such as the GUI's
    /// deletion of an SVS sample (PLAN.md 7.10). `ace serve` sets it.
    bucket: Option<ace_core::bucket::Bucket>,
    /// YARA validation's settings, the overlay's `svs.yara` (PLAN.md 7.10 batch 3): its repositories and its
    /// retention. None configured by default.
    validation: std::sync::Arc<ace_core::svs::yara::ValidationConfig>,
    /// The Atomic Red Team catalog's settings, the overlay's `svs.catalog` (PLAN.md 7.10 batch 4): its
    /// repositories and what a refresh may read. None configured by default.
    catalog: std::sync::Arc<ace_core::svs::catalog::CatalogConfig>,
    /// The alert routers (PLAN.md 7.13), `routing`'s docs: the built-in one unless the binary adds others.
    routers: routing::Routers,
    /// What a launcher may register and how long a run's windows last, the overlay's `svs.runs` (PLAN.md
    /// 7.10 batch 5). ace3's defaults unless the binary sets others.
    runs: std::sync::Arc<ace_core::svs::runs::RunsConfig>,
    /// How long a changed-since page holds a row back after it changed (PLAN.md 7.10 batch 5):
    /// `svs_decisions`' docs.
    feed_settle: chrono::TimeDelta,
    /// The ATT&CK release coverage is computed against, the overlay's `svs.attack_release` (PLAN.md 7.10
    /// batch 8). None is ace3's default release, which every build has.
    attack: Option<std::sync::Arc<ace_core::svs::attack::AttackCatalog>>,
    /// The search index (PLAN.md 7.11), `search`'s docs. None unless the binary sets one, and then a
    /// search runs its exact lane and its listings only.
    search: Option<std::sync::Arc<dyn search::SearchIndex>>,
    /// Search's settings, ace3's defaults unless the binary sets others.
    search_config: std::sync::Arc<search::SearchConfig>,
    /// The AI investigation API (PLAN.md 7.15), `ai`'s docs. None unless the binary turns it on, and
    /// then its routes say it's off.
    ai: Option<std::sync::Arc<ai::AiSurface>>,
    /// The directives an analyst may add to an observable (PLAN.md decision 31), `directives`' docs:
    /// those of ace3's `GUI_DIRECTIVES` an ace-rs module reads, unless the binary adds a site's.
    directives: std::sync::Arc<ace_sdk::directives::DirectiveList>,
    /// The Observable Patterns refused for a bound, remembered for a while (`filters::patterns`).
    pattern_refusals: std::sync::Arc<filters::patterns::Refusals>,
    /// The overlay's alert automation rules (PLAN.md 7.22), `alert_automation`'s docs. None by default.
    automation: std::sync::Arc<alert_automation::AlertAutomation>,
}

impl Service {
    pub fn new(db: Db, orchestrator: Orchestrator) -> Self {
        Service {
            gate: Gate::new(db),
            orchestrator,
            passwords: auth::Passwords::new(),
            feed: std::sync::Arc::default(),
            actions: ace_core::actions::ActionCatalog::default(),
            dispositions: std::sync::Arc::default(),
            log_search: None,
            bucket: None,
            validation: std::sync::Arc::default(),
            catalog: std::sync::Arc::default(),
            routers: routing::Routers::builtin(),
            runs: std::sync::Arc::default(),
            feed_settle: chrono::TimeDelta::seconds(5),
            attack: None,
            search: None,
            search_config: std::sync::Arc::default(),
            ai: None,
            directives: std::sync::Arc::default(),
            pattern_refusals: std::sync::Arc::default(),
            automation: std::sync::Arc::default(),
        }
    }

    /// The service with YARA validation's settings (PLAN.md 7.10 batch 3).
    pub fn with_validation(mut self, config: ace_core::svs::yara::ValidationConfig) -> Self {
        self.validation = std::sync::Arc::new(config);
        self
    }

    /// YARA validation's settings.
    pub fn validation_config(&self) -> std::sync::Arc<ace_core::svs::yara::ValidationConfig> {
        self.validation.clone()
    }

    /// The service with the site's dispositions (PLAN.md 7.14), `Dispositions::ace3` unless the binary sets
    /// others.
    pub fn with_dispositions(mut self, dispositions: Dispositions) -> Self {
        self.dispositions = std::sync::Arc::new(dispositions);
        self
    }

    /// The site's dispositions.
    pub fn dispositions(&self) -> &Dispositions {
        &self.dispositions
    }

    /// The service with the overlay's `svs.log_search_url`, checked (PLAN.md 7.10).
    /// The service with the node's bucket, which `bucket` hands to an adapter that has none.
    pub fn with_bucket(mut self, bucket: ace_core::bucket::Bucket) -> Self {
        self.bucket = Some(bucket);
        self
    }

    /// The node's bucket, when `ace serve` gave the service one.
    pub fn bucket(&self) -> Option<&ace_core::bucket::Bucket> {
        self.bucket.as_ref()
    }

    pub fn with_log_search(
        mut self,
        template: Option<ace_core::svs::log_search::LogSearchTemplate>,
    ) -> Self {
        self.log_search = template.map(std::sync::Arc::new);
        self
    }

    /// The template of a run's link to the site's log search, None when the site set none.
    pub fn log_search(&self) -> Option<&ace_core::svs::log_search::LogSearchTemplate> {
        self.log_search.as_deref()
    }

    /// The service with the binary's action handlers (PLAN.md 7.9), which a remediation names and
    /// whose observable types make an alert's remediation targets.
    pub fn with_actions(mut self, actions: ace_core::actions::ActionCatalog) -> Self {
        self.actions = actions;
        self
    }

    /// The binary's action handlers.
    pub fn actions(&self) -> &ace_core::actions::ActionCatalog {
        &self.actions
    }

    /// Whether the actor holds a permission, for an adapter deciding what to show. A write doesn't
    /// need this: `Gate::write` checks for itself.
    pub async fn allowed(
        &self,
        actor: &Actor,
        permission: &PermissionName,
    ) -> Result<bool, ServiceError> {
        self.gate.allowed(actor, permission).await
    }

    /// Records a disposition of an alert and who made it. Its analysis is cancelled and it moves
    /// to dispositioned mode, all in one transaction. A later disposition replaces the earlier one
    /// and its actor, as in ace3, where an analyst, an API key and SVS's maintenance timers all
    /// call `set_dispositions`. It needs `alert:write`, as ace3's route does, and an actor without
    /// it learns nothing about the alert. A disposition is one of the site's (`Dispositions`); anything
    /// else is `InvalidRequest`. From an analyst, anyone but ACE's own components, it must be
    /// `analyst_selectable` (`InvalidRequest` otherwise), and an alert whose disposition isn't can't be
    /// changed (`Conflict`), as ace3's `set_disposition` and `is_frozen_disposition` have it.
    ///
    /// Ownership (PLAN.md 7.17, `ownership`'s docs): an analyst's disposition makes them the owner of an
    /// alert nobody owns. An alert another analyst owns is left alone (`AlertOwned`, which names them),
    /// unless `take_from` is that analyst, the caller's confirmation that they take it, or the owner's
    /// account is disabled; the caller then becomes its owner. The frozen check comes first, so a frozen
    /// alert is never taken.
    pub async fn disposition(
        &self,
        actor: &Actor,
        root: Uuid,
        disposition: &str,
        take_from: Option<UserId>,
    ) -> Result<Dispositioned, ServiceError> {
        if !is_disposition_name(disposition) {
            return Err(ServiceError::InvalidRequest(
                "a disposition is up to 64 uppercase ASCII letters, digits and _, starting with a letter"
                    .to_owned(),
            ));
        }
        let analyst = dispositions::is_analyst(actor);
        match self.dispositions.get(disposition) {
            None => {
                return Err(ServiceError::InvalidRequest(format!(
                    "{disposition} isn't one of this site's dispositions: {}",
                    self.dispositions.selectable().join(", ")
                )));
            }
            Some(configured) if analyst && !configured.analyst_selectable => {
                return Err(ServiceError::InvalidRequest(format!(
                    "only ACE sets the disposition {disposition}"
                )));
            }
            Some(_) => {}
        }
        self.gate
            .write(actor, "disposition", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    let (dispositioned, change) = self
                        .disposition_in(tx, root, disposition, actor, None, take_from)
                        .await?;
                    Ok(Audited::changed(dispositioned, change))
                })
            })
            .await
    }

    /// A disposition's writes, in its caller's transaction: the one writer of an alert's disposition,
    /// which `disposition` and SVS (closing a run's and a maintenance window's alerts, and giving a
    /// disassociated alert back, `svs_association`) share. `by` is who the alert's row names: the actor, or
    /// the component that acts for them. From an analyst it refuses a frozen alert (`Conflict`). `comment`
    /// says why, in the audit row, where ace3 adds a comment to the alert. An analyst's disposition
    /// checks and takes ownership (`disposition`'s docs), `take_from` being who they confirmed taking the
    /// alert from; a component's does neither, and its callers pick alerts nobody owns. Returns what the
    /// analysis did and the audit row's change, which the caller's write records.
    pub(crate) async fn disposition_in(
        &self,
        tx: &mut ace_core::db::Tx<'_>,
        root: Uuid,
        disposition: &str,
        by: &Actor,
        comment: Option<&str>,
        take_from: Option<UserId>,
    ) -> Result<(Dispositioned, Change), ServiceError> {
        // Locks first, so `before` is what this write replaces. The title is capped here,
        // not by the column: it's whatever the alert's sender wrote.
        let found = sqlx::query!(
            r#"SELECT disposition, dispositioned_by AS "dispositioned_by: Value",
                      analysis_mode, event_time, created_at, owner_id,
                      left(description, $2) AS "title!"
               FROM analysis.roots WHERE id = $1 FOR UPDATE"#,
            root,
            TITLE_LIMIT,
        )
        .fetch_optional(tx.conn())
        .await?
        .ok_or(OrchestratorError::NoRoot(root))?;
        if dispositions::is_analyst(by) && self.dispositions.is_frozen(found.disposition.as_deref())
        {
            return Err(ServiceError::Conflict(format!(
                "the alert's disposition {} is set only by ACE, so an analyst can't change it",
                found.disposition.as_deref().unwrap_or_default()
            )));
        }
        // the frozen check came first, as in ace3: a frozen alert is left alone whoever owns it
        let analyst = dispositions::is_analyst(by);
        let user = routing::acting_user(by);
        let claim = if analyst {
            let owner = ownership::locked_owner(tx.conn(), root, false)
                .await?
                .flatten();
            ownership::claim(owner, user, take_from)
        } else {
            ownership::Claim::Keep
        };
        let taken_from = match &claim {
            ownership::Claim::Refused(owner) => {
                return Err(ServiceError::AlertOwned {
                    alert: root,
                    owner: owner.id.0,
                    name: owner.name.clone(),
                });
            }
            ownership::Claim::TakeFrom(owner) => Some(owner.clone()),
            ownership::Claim::Keep | ownership::Claim::Take => None,
        };
        let dispositioned = self.orchestrator.stop_for_disposition(tx, root).await?;
        let owner_after = match claim {
            ownership::Claim::Take | ownership::Claim::TakeFrom(_) => {
                // a user who is gone can't own it: the alert is then nobody's
                sqlx::query_scalar!(
                    "UPDATE analysis.roots r
                     SET owner_id = u.id, owned_at = CASE WHEN u.id IS NULL THEN NULL ELSE now() END
                     FROM (SELECT (SELECT id FROM service.users WHERE id = $2) AS id) u
                     WHERE r.id = $1
                     RETURNING r.owner_id",
                    root,
                    user.map(|user| user.0),
                )
                .fetch_one(tx.conn())
                .await?
            }
            _ => found.owner_id,
        };
        if let Some(from) = &taken_from {
            tracing::info!(
                alert_uuid = %root, alert_owner = from.username,
                new_owner = owner_after.map(|owner| owner.to_string()), changed_by = %by,
                "alert ownership taken"
            );
        }
        let mode = sqlx::query_scalar!(
            "UPDATE analysis.roots
             SET disposition = $2, dispositioned_at = now(), dispositioned_by = $3::jsonb
             WHERE id = $1
             RETURNING analysis_mode",
            root,
            disposition,
            Json(by) as _,
        )
        .fetch_one(tx.conn())
        .await?;
        let change = Change::updated(
            Target::root(root),
            &DispositionState {
                disposition: found.disposition,
                dispositioned_by: found.dispositioned_by,
                analysis_mode: found.analysis_mode,
                owner: found.owner_id,
            },
            &DispositionState {
                disposition: Some(disposition.to_owned()),
                dispositioned_by: Some(serde_json::to_value(by)?),
                analysis_mode: mode,
                owner: owner_after,
            },
        )?
        .details(&RootSnapshot {
            title: found.title,
            event_time: found.event_time,
            root_created_at: found.created_at,
            comment: comment.map(str::to_owned),
            taken_from: taken_from.map(|owner| owner.id.0),
        })?;
        Ok((dispositioned, change))
    }

    /// Adds a row giving a holder an effect on a pattern, as ace3's `add_user_permission`,
    /// `add_group_permission` and API key scopes do. It needs `user:write`. Adding a row that exists,
    /// in any case, changes nothing and returns false. The row records who made it. A deny that takes
    /// `user:write` from the actor is `ServiceError::CantDropYourOwnUserWrite` (`users::keeps_user_write`).
    pub async fn grant(
        &self,
        actor: &Actor,
        holder: &Holder,
        pattern: &PermissionPattern,
        effect: Effect,
    ) -> Result<bool, ServiceError> {
        let (user, group, api_key, component) = holder.columns();
        if permission::covered_by(pattern).next().is_none() {
            // ace3 warns about a likely typo and grants it anyway, since a site may know better
            tracing::warn!(%actor, %pattern, "a grant covers no permission ACE checks");
        }
        self.gate
            .write(actor, "grant", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    let added = sqlx::query!(
                        "INSERT INTO service.permissions
                             (user_id, group_id, api_key_id, component, major, minor, effect, created_by)
                         VALUES ($1, $2, $3, $4, $5::text, $6::text, $7, $8::jsonb)
                         ON CONFLICT ON CONSTRAINT permissions_are_unique DO NOTHING",
                        user,
                        group,
                        api_key,
                        component,
                        pattern.major(),
                        pattern.minor(),
                        effect as Effect,
                        Json(actor) as _,
                    )
                    .execute(tx.conn())
                    .await
                    .map_err(|error| {
                        let missing = error
                            .as_database_error()
                            .is_some_and(|error| error.is_foreign_key_violation());
                        if missing {
                            ServiceError::NotFound(format!("no {}", Target::holder(holder)))
                        } else {
                            error.into()
                        }
                    })?;
                    if added.rows_affected() == 0 {
                        return Ok(Audited::unchanged(false));
                    }
                    // only a deny can, but the check is one query
                    users::keeps_user_write(tx.conn(), actor).await?;
                    let change = Change::added(
                        Target::holder(holder),
                        &PermissionRecord {
                            major: pattern.major(),
                            minor: pattern.minor(),
                            effect,
                            created_by: None,
                        },
                    )?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
    }

    /// Removes the row `grant` would add, as ace3's `delete_user_permission` and
    /// `delete_group_permission` do. It needs `user:write`. Returns false when there's no such row. Revoking
    /// the actor's own `user:write` is `ServiceError::CantDropYourOwnUserWrite`, which ace3 allows.
    pub async fn revoke(
        &self,
        actor: &Actor,
        holder: &Holder,
        pattern: &PermissionPattern,
        effect: Effect,
    ) -> Result<bool, ServiceError> {
        let (user, group, api_key, component) = holder.columns();
        self.gate
            .write(actor, "revoke", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    let removed = sqlx::query_scalar!(
                        r#"DELETE FROM service.permissions
                           WHERE user_id IS NOT DISTINCT FROM $1
                             AND group_id IS NOT DISTINCT FROM $2
                             AND api_key_id IS NOT DISTINCT FROM $3
                             AND component IS NOT DISTINCT FROM $4
                             AND major = $5::text AND minor = $6::text AND effect = $7
                           RETURNING created_by AS "created_by!: Value""#,
                        user,
                        group,
                        api_key,
                        component,
                        pattern.major(),
                        pattern.minor(),
                        effect as Effect,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let Some(created_by) = removed else {
                        return Ok(Audited::unchanged(false));
                    };
                    users::keeps_user_write(tx.conn(), actor).await?;
                    let change = Change::removed(
                        Target::holder(holder),
                        &PermissionRecord {
                            major: pattern.major(),
                            minor: pattern.minor(),
                            effect,
                            created_by: Some(created_by),
                        },
                    )?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
    }
}
