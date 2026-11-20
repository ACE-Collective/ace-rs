//! The module traits: a sync one for parsers and an async one for lookups.
//!
//! A parser reads hostile files in a contained process of its own, so it is plain blocking code
//! that polls `TaskContext::is_cancelled`. A lookup waits on the network inside a shared async
//! pool, many tasks at a time, and selects on `TaskContext::cancelled`.

use std::future::Future;
use std::time::Duration;

use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::Instrument;

use crate::context::TaskContext;
use crate::lists::ListSpec;
use crate::manifest::Resources;
use crate::reads::Read;
use crate::tree::TreeFiles;
use crate::writes::Write;

/// A module's settings: the block a site's config overlay gives it. Missing settings fall back
/// to `Default`. Derive `Deserialize` with `#[serde(deny_unknown_fields)]`; the loader refuses
/// unknown keys either way.
pub trait Settings: DeserializeOwned + JsonSchema + Default + Send + Sync + 'static {}

impl<T: DeserializeOwned + JsonSchema + Default + Send + Sync + 'static> Settings for T {}

/// What every module has, whichever way it runs. `Manifest::parser` and `Manifest::lookup`
/// collect these constants into the module's manifest.
pub trait Module: Sized + Send + Sync + 'static {
    /// The module's name, as configured and as named in a result's `exclude_modules`.
    const NAME: &'static str;
    /// The observable types the module takes. Types that extend these are taken too.
    const INPUTS: &'static [ObservableKind];
    /// Modules whose results this one needs before it runs.
    const DEPENDS_ON: &'static [&'static str] = &[];
    /// Directives that keep the module off an observable, such as `no_scan` for YARA. The core
    /// doesn't queue the module for an observable that has one, and a run on an observable
    /// that gained one after its task was queued is skipped. `exclude_all` keeps every module
    /// off.
    const SKIP_DIRECTIVES: &'static [&'static str] = &[];
    /// Directives an observable must have for the module to run on it, as ace3's
    /// `required_directives`, such as `original_email` for the email logger. The core doesn't queue
    /// the module for an observable without every one.
    const REQUIRED_DIRECTIVES: &'static [&'static str] = &[];
    /// Directives an observable of one type must have for the module to run on it, as ace3's
    /// phishkit module needs `crawl` on a URL and nothing of the kind on a file
    /// (`custom_requirement`). The core doesn't queue the module for such an observable without
    /// them, and queues it once a result adds the last one.
    const REQUIRED_DIRECTIVES_BY_KIND: &'static [(ObservableKind, &'static [&'static str])] = &[];
    /// The names of the secrets the module reads. The task context gives it these and no others.
    const SECRETS: &'static [&'static str] = &[];
    /// The shared connections the module takes (`crate::connections`), each in a slot of its own
    /// name, which its overlay section binds to a connection with `connections:`. The connection's
    /// settings are its settings block's key of the slot's name, so `Settings` has a field of the
    /// connection type's settings there, which the overlay can't set any other way; its secrets are
    /// `TaskContext::connection_secret`'s. Only a lookup takes one: a parser reaches no service.
    const CONNECTIONS: &'static [crate::connections::ConnectionSlot] = &[];
    const RESOURCES: Resources = Resources::DEFAULT;
    /// True for a module that does nothing until a site configures it, such as the Splunk
    /// module, which needs its query: it runs only as the site overlay's named instances
    /// (PLAN.md 2.23), never as itself on its defaults.
    const INSTANCES_ONLY: bool = false;
    /// False for a module ace3 ships disabled, such as the LDAP lookup, which a site turns on by
    /// giving it a section in the overlay, empty or not, as ace3's site config sets `enabled: true`.
    /// Without one it doesn't run.
    const ENABLED_BY_DEFAULT: bool = true;
    /// True for a module that reads the body parts of the email that carried its observable, as
    /// ace3's modules for encrypted attachments do. The core adds it to the module's tasks, which read it
    /// with `TaskContext::carrying_email`, or says an email in the root isn't parsed yet, and a
    /// module that needs to know then delays itself.
    const READS_CARRYING_EMAIL: bool = false;
    /// True for a module that runs once everything else in its root has finished, as ace3's
    /// `execute_final_analysis`, and reads the YARA rules that matched its observable or anything
    /// below it. The core holds its tasks back until then and adds those rules to them. Of the others
    /// that run last, it waits only for those on a file below its observable, which can add to what's
    /// below, so one that runs last on a file mustn't wait itself for one above it.
    const RUNS_LAST: bool = false;
    /// For a module that runs last: the observable types whose values below its observable it
    /// reads, as ace3's `recurse_tree` finds them, such as the email logger's URLs. The core adds
    /// them to its tasks, which read them with `TaskContext::observables_below`.
    const READS_BELOW: &'static [ObservableKind] = &[];
    /// True for a module that reads which modules' results added its observable, as ace3's
    /// `iterate_all_references` finds the analyses that hold one. The core adds their names to its
    /// tasks, which read them with `TaskContext::added_by`. A result that lands after the task is
    /// leased isn't among them, so such a module usually runs last too.
    const READS_ADDED_BY: bool = false;
    /// True for a module that reads its root's event time, as ace3's modules read
    /// `get_root().event_time`, such as a search over a window around the alert. The core adds it
    /// to the module's tasks, with where it came from, which the module reads with
    /// `TaskContext::event_time`. A result that depends on it isn't a function of the observable, so
    /// the analysis cache refuses a module that reads it (`crate::cache::refusal`).
    const READS_EVENT_TIME: bool = false;
    /// The most results of the module's analysis type a root holds before the core stops queuing
    /// the module there, ace3's `automation_limit`: a module that may fan out, such as a lookup
    /// per recipient of a mass mail, stops at it. All the module's instances count together, as
    /// ace3 counts a root's analyses of one type. An observable with the directive
    /// `ignore_automation_limits` isn't held to it (`crate::limits`). None, the default, has no
    /// limit; a site's overlay sets one with `automation_limit` beside `settings`, over this.
    const AUTOMATION_LIMIT: Option<u32> = None;
    /// True for a module that reads the tags of the observables its observable is related to, as
    /// ace3's modules read the tags of the file one was `extracted_from`. The core adds them to its
    /// tasks, which read them with `TaskContext::related_tags`, as they are when it's leased.
    const READS_RELATED_TAGS: bool = false;
    /// True for a module that walks its root's tree, as ace3's modules walk the `RootAnalysis`
    /// (`recurse_tree`, `search_down`, `wait_for_analysis`): the core adds the tree as it is when the
    /// task is leased, its observables, the results on each, what each added and the tasks still to
    /// finish, which the module reads with `TaskContext::tree` (`crate::tree`).
    const READS_TREE: bool = false;
    /// For a module that reads its root's tree: the files in it whose bytes it reads too, which the
    /// pool downloads before the task runs (`TaskContext::tree_file`).
    const READS_TREE_FILES: Option<TreeFiles> = None;
    /// For a module that reads its root's tree: the modules whose results' details it reads there
    /// (`TreeResult::details`), such as the JavaScript deobfuscator the DOM snapshots that
    /// `html_js_extraction` and `har_extraction` keep in theirs.
    const READS_TREE_DETAILS: &'static [&'static str] = &[];
    /// What a module that walks the tree may add to observables in its root other than the one it
    /// analyzed (`ResultEnvelope::others`), as ace3's lure module adds `crawl` to the URL it picks.
    /// A parser's result comes from hostile input, so the core refuses a result whose `others` add
    /// anything this doesn't name, and any `others` at all from a module that declares nothing.
    const ADDS_TO_OTHERS: Option<OtherAdditionsAllowed> = None;
    /// True for a module that changes its root's description and details, as ace3's mailbox module
    /// does (`ResultEnvelope::root`). The core refuses a result that changes them from any other.
    const SETS_ROOT: bool = false;
    /// True for a module that adds files another module's result stored for the root without
    /// adding them (`ResultEnvelope::stored`), as ace3's pcap_files adds the objects pcap_analyzer
    /// carved. Such a module depends on the one that stores them, and adds each by its sha256 and
    /// size with no upload; the core takes such a file only from a module that declares this, and
    /// only when the root holds it.
    const ADDS_STORED_FILES: bool = false;
    /// True for a lookup that adds files it fetched, such as an email it downloads from a mailbox
    /// (PLAN.md decision 28). Its pool's containment then lets it connect to the bucket's port, so it
    /// can upload them to the core's presigned URLs; a network pool none of whose modules declares it
    /// can't reach the bucket, and the core gives no upload URL to, and takes no uploaded file from,
    /// a lookup that doesn't declare it. Only a lookup may declare it: a parser's files are its
    /// supervisor's to upload.
    const ADDS_FETCHED_FILES: bool = false;
    /// The analyst-edited lists the module reads (PLAN.md 5.14), such as `observable_detection`'s
    /// observables enabled for detection. The core adds each to the module's tasks as it is when the task is leased, and
    /// the module reads it with `TaskContext::list`. The lists a binary knows are its modules'.
    const LISTS: &'static [ListSpec] = &[];
    /// The reads of ACE's own data the module makes (PLAN.md 7.2), with `TaskContext::read`. Only
    /// a lookup may declare one: `Manifest::parser` refuses a parser that does.
    const READS: &'static [Read] = &[];
    /// The writes to ACE's own data the module makes (PLAN.md 7.2), with `TaskContext::write`.
    /// They land with the task's end, in its transaction. Only a lookup may declare one.
    const WRITES: &'static [Write] = &[];
    /// The programs the module runs (PLAN.md 7.3), by the names its pool's image maps to programs
    /// (`crate::tools::ToolSpec`), with `TaskContext::run_tool`. Only a parser may declare one, and
    /// only a pool whose image has each runs it.
    const TOOLS: &'static [&'static str] = &[];
    /// The scanner images the module sends its observable through (PLAN.md 7.7), by the names of
    /// their specs (`crate::scanners::ScannerSpec`), with `Delay::with_scan`. Only a parser may
    /// declare one: the scanner's output is hostile, and its next run reads it.
    const SCANNERS: &'static [&'static str] = &[];
    /// False for a module whose tasks end with writes and never a result, as ace3's email logger,
    /// which creates no analysis. Its type needs no view.
    const STORES_RESULTS: bool = true;
    /// Whether the module's results are kept across roots and reused in place of a task, as ace3's
    /// `cache_ttl` opts a module into its analysis result cache (PLAN.md decision 26,
    /// `crate::cache`), with its time to live and what besides its input its result depends on.
    /// A module whose task reads what the key doesn't hold can't opt in: every binary refuses it
    /// when it reads its overlay (`Manifest::cache_refusal`).
    const CACHE: Option<crate::cache::Cache> = None;

    /// The analysis type the module writes.
    type Output: AnalysisType;
    type Settings: Settings;

    /// Builds the module once per process, before any task, such as loading a ruleset. A failure
    /// here is a setup failure, not a failed task.
    fn init(settings: &Self::Settings) -> Result<Self, ModuleError>;

    /// What the module takes, from its settings: the checks it makes before it does anything, over
    /// facts the core holds, as data (`crate::takes`, PLAN.md decision 23). The core doesn't queue a
    /// task these decline, and the pool checks them again before `analyze`, which therefore
    /// doesn't repeat them. The default takes everything the inputs, modes and directives allow.
    /// It runs where the module's settings are checked, in the core and in the pool, on the
    /// overlay's settings and nothing else.
    fn takes(settings: &Self::Settings) -> crate::takes::Takes {
        let _ = settings;
        crate::takes::Takes::everything()
    }
}

/// What a module may add to other observables in its root (`Module::ADDS_TO_OTHERS`): these tags and
/// directives, and detections only when `detections` is true. Never `yara_meta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtherAdditionsAllowed {
    pub tags: &'static [&'static str],
    pub directives: &'static [&'static str],
    pub detections: bool,
}

impl OtherAdditionsAllowed {
    /// Why `additions` aren't allowed, or None when they are.
    pub fn refusal(&self, additions: &ace_results::ObservableAdditions) -> Option<String> {
        if let Some(tag) = additions
            .tags
            .iter()
            .find(|t| !self.tags.contains(&t.as_str()))
        {
            return Some(format!("the tag {tag:?}"));
        }
        if let Some(d) = additions
            .directives
            .iter()
            .find(|d| !self.directives.contains(&d.as_str()))
        {
            return Some(format!("the directive {d:?}"));
        }
        if !additions.detections.is_empty() && !self.detections {
            return Some("a detection".to_owned());
        }
        if !additions.yara_meta.is_empty() {
            return Some("a yara_meta tag".to_owned());
        }
        None
    }
}

/// A module that parses files: sync, one task per contained process.
pub trait Parser: Module {
    fn analyze(
        &self,
        ctx: &TaskContext<Self::Settings>,
    ) -> Result<Outcome<Self::Output>, ModuleError>;
}

/// A module that looks something up over the network: async, many tasks per pool process.
pub trait Lookup: Module {
    /// The TCP ports the module connects to.
    const TCP_PORTS: &'static [u16];

    fn analyze(
        &self,
        ctx: &TaskContext<Self::Settings>,
    ) -> impl Future<Output = Result<Outcome<Self::Output>, ModuleError>> + Send;
}

/// How a task ended, when it didn't fail.
// A task returns one Outcome and it's moved once or twice, so the size of the result variant
// costs nothing worth a Box at every module's return.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome<D> {
    /// The result, which the core checks against its schema and stores. A module that ran to its
    /// end and failed (a tool that exited with an error, a lookup that couldn't answer, a file
    /// that didn't read) still returns its result here, marked with why
    /// (`ResultEnvelope::with_error`, ace3's `Analysis.error`): the alert shows it with an
    /// `error` badge, and what the module had before it failed is kept. An `Err(ModuleError)` is
    /// for a task that couldn't run to its end.
    Done(ResultEnvelope<D>),
    /// Run the task again later, as ace3's `delay_analysis`.
    Delay(Delay),
    /// The module had nothing to say about this observable, such as an archive module given a
    /// file that isn't an archive. No result is stored.
    Skipped(String),
}

/// A request to run the task again after `run_after`, the counterpart of ace3's
/// `delay_analysis` (`saq/modules/base_module.py:685`).
#[derive(Debug, Clone, PartialEq)]
pub struct Delay {
    pub run_after: Duration,
    /// How long after the first delay the task may keep asking for more. Past it, the task fails
    /// with `DelayTimedOut`. A module that wants a result on timeout, such as a query that "timed
    /// out", checks the elapsed time itself first, as ace3's API analyzers do.
    pub timeout: Duration,
    /// What the next run needs, such as a search id. `TaskContext::delay_state` reads it back.
    pub state: serde_json::Value,
    /// A scan to run meanwhile (PLAN.md 7.7): the core queues it and runs the task again when it
    /// ends, or after `run_after`, whichever comes first, and the next run reads it with
    /// `TaskContext::scan`.
    pub scan: Option<crate::scanners::ScanRequest>,
}

impl Delay {
    pub fn new(run_after: Duration, timeout: Duration) -> Self {
        Delay {
            run_after,
            timeout,
            state: serde_json::Value::Null,
            scan: None,
        }
    }

    /// Runs `scan` while the task waits, as ace3's modules wait on a Celery task.
    pub fn with_scan(mut self, scan: crate::scanners::ScanRequest) -> Self {
        self.scan = Some(scan);
        self
    }

    pub fn with_state<T: Serialize>(mut self, state: &T) -> Result<Self, ModuleError> {
        self.state = serde_json::to_value(state)
            .map_err(|e| ModuleError::other(format!("delay state doesn't serialize: {e}")))?;
        Ok(self)
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Why a task failed: it couldn't run to its end, so it has no result, its row in the queue is
/// `failed` with this as its error (PLAN.md 2.19), and the alert lists the module under its
/// observable. ace3 keeps the same in `root.analysis_failures`. This is not a module saying its
/// analysis failed, which is a result with an error (`Outcome::Done`): return this for what the
/// module can't answer for (its peer is down, its secret is missing, its own bug), and that for
/// what the input or a tool did.
#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    /// The task was cancelled.
    #[error("cancelled")]
    Cancelled,
    /// A peer the module depends on couldn't be reached. The task can be tried again later.
    #[error("peer unavailable: {0}")]
    Unavailable(#[source] BoxError),
    #[error("secret {0:?} isn't declared in the module's SECRETS")]
    UndeclaredSecret(String),
    #[error("secret {0:?} isn't set")]
    MissingSecret(String),
    #[error("the delay timed out {0:?} after the first delay")]
    DelayTimedOut(Duration),
    #[error("{0}")]
    Other(#[source] BoxError),
}

impl ModuleError {
    pub fn other(error: impl Into<BoxError>) -> Self {
        ModuleError::Other(error.into())
    }
}

impl From<std::io::Error> for ModuleError {
    fn from(error: std::io::Error) -> Self {
        ModuleError::Other(error.into())
    }
}

impl From<crate::files::FileOutputError> for ModuleError {
    fn from(error: crate::files::FileOutputError) -> Self {
        ModuleError::Other(error.into())
    }
}

/// The span a task runs in. Every log line inside it carries the root's uuid, the observable,
/// the module and, when the task came from the queue, its id.
pub fn task_span<S>(module: &'static str, ctx: &TaskContext<S>) -> tracing::Span {
    tracing::info_span!(
        "task",
        root = %ctx.root(),
        observable = %ctx.observable(),
        module = %module,
        task = ctx.task_id(),
    )
}

/// The directive that keeps every module off an observable, as ace3's `exclude_all`.
pub const EXCLUDE_ALL: &str = "exclude_all";

/// The directive that lifts every module's automation limit for an observable
/// (`Module::AUTOMATION_LIMIT`), as ace3's `ignore_automation_limits`, which an analyst adds to
/// force an analysis.
pub const IGNORE_AUTOMATION_LIMITS: &str = "ignore_automation_limits";

/// The first of the observable's directives that keeps module `M` off it.
fn skipping_directive<M: Module, S>(ctx: &TaskContext<S>) -> Option<&str> {
    ctx.observable()
        .directives
        .iter()
        .map(String::as_str)
        .find(|d| *d == EXCLUDE_ALL || M::SKIP_DIRECTIVES.contains(d))
}

/// Why module `M`'s declaration (`Module::takes`) declines the task, from the facts the task
/// carries: the same check the core made before it queued the task, made again on the facts as they
/// are now.
pub fn declined<M: Module>(ctx: &TaskContext<M::Settings>) -> Option<String> {
    let takes = M::takes(ctx.settings());
    if takes.is_everything() {
        return None;
    }
    let results = ctx.dependency_details();
    takes.check(&ctx.facts(results)).err().map(str::to_owned)
}

/// Runs a parser on one task, inside the task's span.
pub fn run_parser<M: Parser>(
    module: &M,
    ctx: &TaskContext<M::Settings>,
) -> Result<Outcome<M::Output>, ModuleError> {
    let span = task_span(M::NAME, ctx);
    let _entered = span.enter();
    ctx.check_cancelled()?;
    if let Some(directive) = skipping_directive::<M, _>(ctx) {
        return Ok(Outcome::Skipped(format!("directive {directive}")));
    }
    if let Some(why) = declined::<M>(ctx) {
        return Ok(Outcome::Skipped(why));
    }
    let outcome = module.analyze(ctx)?;
    check_delay(ctx, outcome)
}

/// Runs a lookup on one task, inside the task's span. Cancelling the task's token ends it at the
/// module's next await, even if the module never checks the token itself.
pub async fn run_lookup<M: Lookup>(
    module: &M,
    ctx: &TaskContext<M::Settings>,
) -> Result<Outcome<M::Output>, ModuleError> {
    async {
        ctx.check_cancelled()?;
        if let Some(directive) = skipping_directive::<M, _>(ctx) {
            return Ok(Outcome::Skipped(format!("directive {directive}")));
        }
        if let Some(why) = declined::<M>(ctx) {
            return Ok(Outcome::Skipped(why));
        }
        let outcome = tokio::select! {
            biased;
            () = ctx.cancelled() => return Err(ModuleError::Cancelled),
            outcome = module.analyze(ctx) => outcome?,
        };
        check_delay(ctx, outcome)
    }
    .instrument(task_span(M::NAME, ctx))
    .await
}

/// Refuses a delay asked for after the timeout of the first one.
fn check_delay<S, D>(ctx: &TaskContext<S>, outcome: Outcome<D>) -> Result<Outcome<D>, ModuleError> {
    if let (Outcome::Delay(delay), Some(delayed)) = (&outcome, ctx.delayed()) {
        let waited = (ctx.now() - delayed.first_delayed_at)
            .to_std()
            .unwrap_or_default();
        if waited >= delay.timeout {
            return Err(ModuleError::DelayTimedOut(delay.timeout));
        }
    }
    Ok(outcome)
}
