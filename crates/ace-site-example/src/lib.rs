//! An example site, built the way a site repository builds its binaries (PLAN.md 2.31, 2.32):
//! the open-source pools, one module of the site's own in the network pool and one in the parser
//! pool, and one observable type of its own, which those modules' results add.
//!
//! The ticket file parser stands in for a site's parser of its own: it lists the tickets a file
//! names. It runs as the open-source parsers do, one contained task process per task, which
//! builds it and no other module of the pool from the settings the site's overlay gave it
//! (`ace_pool::task_process`). Its `init` refuses an empty prefix, which stops the site's parser
//! pool when it starts and not a task later.
//!
//! The ticket lookup stands in for a site's lookup in its own ticket system. For an fqdn it adds
//! an `example_ticket` observable; for a ticket it records the ticket and adds nothing. A ticket
//! the system doesn't know is a lookup that failed: its result says so with
//! `ResultEnvelope::with_error`, as any module's does (ace3's `Analysis.error`), which the alert
//! view shows as an `error` badge with the reason. Its results
//! have a view of the site's own, its analysis template (5.9), and a ticket has an observable action
//! of the site's own that opens it, both named by the binary's list.
//!
//! Its hunts' `type: executable` command for `hunts/scripts/field_values.py` runs ace4's example
//! script command type (`ace_hunt::correlate::scripts::example`, PLAN.md decision 16), registered
//! with `App::hunt_script` as a site registers the types of its own hunt scripts.
//!
//! It adds a directive an analyst may add to an observable, `example_ticket_history`, which the alert
//! page's Add Directive and the JSON API offer beside ace3's (PLAN.md decision 31).
//!
//! Its alert summary is the site's own too: an alert whose type is `example - ticket`, or starts with
//! it, has its ticket queue and ticket at the top of its page (`ExampleTicketSummary`), where ace3 has
//! a template per alert type.
//!
//! The ticket lookup reaches its ticket system through a shared connection (`ace_sdk::connections`)
//! of the site's type `example_ticket_system`: the system's URL and timeout, and its API token as the
//! secret in the role `token`. The overlay names the connection once in `connections:` and binds it to
//! the lookup's slot `tickets`, as every component of a site that talks to the same system would, so
//! the URL and the token aren't repeated in each one's settings. The lookup gets the connection's
//! settings as its settings' `tickets`, and a real one would read the token with
//! `TaskContext::connection_secret("tickets", "token")`; a cached result's key would hold the URL,
//! which changes what the lookup finds, and not the timeout.
//!
//! The ticket lookup joins ace3's `correlation` module group, so it runs in every mode that runs the
//! group (`analysis`, `cli` and `correlation`). The ticket file parser joins the `correlation` mode
//! alone (`App::module_in_mode`, ace3's `analysis_mode_correlation: enabled_modules:`), as a site's
//! module that only makes sense on an alert does: it runs on an alert's files and not on a file
//! submitted for analysis.
//!
//! Its list is ace4's own, `ace::app()`, with its modules added to two of its pools
//! (`App::add_to_parser_pool`, `App::add_to_lookup_pool`), so it has every open-source module, hunt
//! type and script command type without repeating them.
//!
//! Its collector (PLAN.md 6.1), `example`, stands in for a site's collector over a source of its own:
//! `ace collect example` takes each `*.ticket` file in its `directory` setting as an item keyed by the
//! file's name, submits it as a ticket alert with its `tags` setting as the root's tags, and deletes the
//! file once the core has it (a new root or a duplicate of one), as the journal collector deletes an
//! queue message. It asks first whether the name already made a root (`Submitter::submitted`), and
//! deletes such a file without reading it, as a feed's collector skips an article it submitted before
//! it fetches it. A file the core refuses moves to `rejected/`; one it couldn't take stays for the next
//! pass. It declares one secret,
//! `example_collector_token`, and needs it set, as a real source's credentials would be.
//!
//! Its hunts search its ticket system (PLAN.md decision 40, [`hunt`]): a hunt type of its own,
//! `example_tickets`, with the search `ace hunter` runs its hunts with, and a correlation query source
//! type of the same name, both through the ticket system's shared connection. Its ticket summary is
//! also the template `example/ticket.html`, which a hunt names in `alert_template` to have it whatever
//! its alert's type.
//!
//! Its alert router type (PLAN.md 7.13) is ace3's example integration's (`integrations.example`'s
//! `ExampleTagRouter`): an overlay entry of type `example_tag` sends a new alert carrying one tag to one
//! queue, and does nothing to any other, so the type changes nothing until an entry and that tag appear.
//!
//! Its alert action (PLAN.md decision 55), `ticket_open`, puts "Open in Ticket System" beside the alert
//! page's own links, to the ticket system's page for the alert under the overlay's
//! `alert_actions.ticket_open.settings.ticket_url`; with no section it's off.

use ace_app::App;
use ace_gui::{AlertSummary, AnalysisView, ObservableAction, SummaryInput};
use ace_results::{
    AnalysisType, FileRole, NewObservable, ObservableKind, ObservableType, ResultEnvelope,
};
use ace_sdk::takes::{Case, Condition, Match, Takes, Text};
use ace_sdk::{Lookup, Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The site's observable type: a ticket in its ticket system.
pub const TICKET: ObservableKind = ObservableKind::define(&ObservableType {
    name: "example_ticket",
    parent: None,
    deprecated: false,
    default_display_type: Some("Ticket"),
    description: Some("a ticket in the example site's ticket system"),
});

/// Every observable type the site adds.
pub const OBSERVABLE_TYPES: &[ObservableKind] = &[TICKET];

/// The site's file role: an export from its ticket system, which a site module would give a file it
/// fetched, so a YARA rule can scan it by `type=example.ticket_export` (PLAN.md decision 25).
pub const TICKET_EXPORT: FileRole = FileRole::define("example.ticket_export");

/// Every file role the site adds.
pub const FILE_ROLES: &[FileRole] = &[TICKET_EXPORT];

/// The site's directive, which an analyst may add to an observable from the alert page's menu or the
/// JSON API, beside ace3's (PLAN.md decision 31), as site_ace registers `locate_file`. A module of the site's
/// that requires it (`Module::REQUIRED_DIRECTIVES`) runs on an observable only once someone adds it.
pub const TICKET_HISTORY: ace_sdk::directives::Directive = ace_sdk::directives::Directive::new(
    "example_ticket_history",
    "look up every ticket that ever named this in the example site's ticket system",
);

/// Every directive the site adds.
pub const DIRECTIVES: &[ace_sdk::directives::Directive] = &[TICKET_HISTORY];

/// The site's binaries' list: ace4's, with the site's own added.
pub fn app() -> App {
    ace::app()
        .observable_types(OBSERVABLE_TYPES)
        .file_roles(FILE_ROLES)
        .directives(DIRECTIVES)
        .add_to_parser_pool("parsers", |pool| pool.module::<TicketFile>())
        .add_to_lookup_pool("lookups", |pool| pool.module::<TicketLookup>())
        .collector(EXAMPLE_COLLECTOR, |setup| {
            Ok(std::sync::Arc::new(DirectoryCollector::new(setup)?))
        })
        .module_in_group("correlation", TicketLookup::NAME)
        .module_in_mode("correlation", TicketFile::NAME)
        .analysis_view::<TicketAnalysis>()
        .analysis_view::<TicketFileAnalysis>()
        .observable_action(OPEN_TICKET)
        .alert_action(TICKET_ACTION, ticket_action)
        .alert_summary::<ExampleTicketSummary>()
        // the same summary, for an alert whose hunt names it in `alert_template`
        .alert_template::<ExampleTicketSummary>(TICKET_TEMPLATE)
        .hunt_type(hunt::TicketHunts)
        .hunt_search(hunt::TICKET_HUNTS, hunt::SLOTS, hunt::build_search)
        .query_source_type(hunt::TICKET_HUNTS, hunt::SLOTS, hunt::build_source)
        .alert_router_type(EXAMPLE_TAG_ROUTER, |settings| {
            Ok(std::sync::Arc::new(ExampleTagRouter::new(settings)?))
        })
        .hunt_script(
            ace_hunt::correlate::scripts::example::SUFFIX,
            ace_hunt::correlate::scripts::example::NAME,
            |_, settings| ace_hunt::correlate::scripts::example::build(settings),
        )
}

/// The ticket summary's template name, which a hunt's `alert_template` names (PLAN.md decision 40).
pub const TICKET_TEMPLATE: &str = "example/ticket.html";

pub mod hunt;

/// The example alert router's type name, which an overlay's `alert_routers:` entry names.
pub const EXAMPLE_TAG_ROUTER: &str = "example_tag";

/// Routes an alert tagged `tag` to `queue` when it's first routed, ace3's example `ExampleTagRouter`. It only
/// reads the alert and returns a decision; it never changes the tree, and doesn't fail.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExampleTagRouter {
    pub tag: String,
    pub queue: String,
}

impl ExampleTagRouter {
    /// The router an overlay entry's settings make, which must name its `tag` and `queue` and nothing else.
    pub fn new(settings: &serde_json::Value) -> Result<ExampleTagRouter, String> {
        let router: ExampleTagRouter = ace_service::routing::settings(settings)?;
        ace_service::routing::Queue::new(router.queue.as_str())?;
        Ok(router)
    }
}

impl ace_service::routing::Router for ExampleTagRouter {
    fn route<'a>(
        &'a self,
        alert: &'a ace_service::routing::Alert,
        stage: ace_service::routing::Stage,
        _: &'a mut ace_service::routing::Tx<'_>,
    ) -> ace_service::routing::RouteFuture<'a> {
        Box::pin(async move {
            if stage != ace_service::routing::Stage::Alerted || !alert.has_tag(&self.tag) {
                return Ok(None);
            }
            ace_service::routing::Decision::new(self.queue.as_str(), format!("tagged {}", self.tag))
                .map(Some)
        })
    }
}

/// An observable action of the site's own (PLAN.md 5.9): a ticket opens in the site's ticket system.
pub const OPEN_TICKET: ObservableAction =
    ObservableAction::new("example_open_ticket", "Open Ticket", |target| {
        (target.kind == TICKET.as_str()).then(|| {
            format!(
                "https://tickets.example.com/ticket/{}",
                ace_gui::actions::encode(target.value)
            )
        })
    });

/// The site's alert action (PLAN.md decision 55): "Open in Ticket System", a link to the ticket
/// system's page for the alert, under the `ticket_url` of its overlay section `alert_actions.ticket_open`,
/// which may be `http://` to this machine, as a desktop tool's is. With no section it's off.
pub const TICKET_ACTION: &str = "ticket_open";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketActionSettings {
    ticket_url: String,
}

/// Builds the site's alert action from its settings (`TICKET_ACTION`).
pub fn ticket_action(
    settings: Option<&serde_json::Value>,
) -> Result<Option<ace_gui::AlertAction>, String> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let settings: TicketActionSettings =
        serde_json::from_value(settings.clone()).map_err(|e| format!("its settings: {e}"))?;
    let base = settings.ticket_url.trim_end_matches('/').to_owned();
    Ok(Some(
        ace_gui::AlertAction::new(
            TICKET_ACTION,
            "Open in Ticket System",
            ace_service::ALERT_READ,
            move |target| Some(format!("{base}/alerts/{}", target.alert)),
        )
        .with_title("This alert's page in the ticket system"),
    ))
}

/// The alert type the site's summary draws: what the site's own submitter would name.
pub const TICKET_ALERT_TYPE: &str = "example - ticket";

/// The site's summary of a ticket alert, at the top of the alert's page: the ticket system's queue
/// from what the submitter said, and the alert's first ticket.
pub struct ExampleTicketSummary;

/// How a ticket alert's summary shows.
#[derive(askama::Template)]
#[template(path = "ticket_summary.html")]
pub struct TicketSummaryView<'a> {
    pub queue: &'a str,
    pub ticket: Option<&'a str>,
}

impl AlertSummary for ExampleTicketSummary {
    const ALERT_TYPE: &'static str = TICKET_ALERT_TYPE;
    type View<'a> = TicketSummaryView<'a>;

    fn view<'a>(alert: &SummaryInput<'a>) -> Option<TicketSummaryView<'a>> {
        // an alert that names no ticket queue has the page's default summary
        let queue = alert.origin["details"]["ticket_queue"].as_str()?;
        let ticket = alert
            .tree
            .observables
            .iter()
            .find(|observable| observable.kind == TICKET.as_str())
            .map(|observable| observable.value.as_str());
        Some(TicketSummaryView { queue, ticket })
    }
}

pub struct TicketLookup;

/// What the ticket lookup found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TicketAnalysis {
    pub tickets: Vec<String>,
}

impl AnalysisType for TicketAnalysis {
    const NAME: &'static str = "example_ticket_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = TicketLookup::NAME;
}

/// How a ticket lookup's result shows on its page.
#[derive(askama::Template)]
#[template(path = "ticket_analysis.html")]
pub struct TicketView<'a> {
    pub analysis: &'a TicketAnalysis,
}

impl AnalysisView for TicketAnalysis {
    type View<'a> = TicketView<'a>;

    fn view(&self) -> TicketView<'_> {
        TicketView { analysis: self }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TicketSettings {
    /// What a ticket's name starts with.
    pub prefix: String,
    /// The ticket system, from the connection the overlay binds to the slot `tickets`.
    pub tickets: TicketSystemSettings,
}

impl Default for TicketSettings {
    fn default() -> Self {
        TicketSettings {
            prefix: "TICKET-".to_owned(),
            tickets: TicketSystemSettings::default(),
        }
    }
}

/// The site's connection type: its ticket system, which the overlay names once in `connections:`.
pub struct TicketSystem;

/// A ticket system connection's settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TicketSystemSettings {
    /// Where the system's API is.
    pub url: String,
    /// How long a request to it may take.
    pub request_timeout_seconds: u64,
    /// A proxy the lookup reaches the system through, such as `http://proxy.example.com:3128`. Its
    /// port joins the ports of the pool that runs the lookup (`ConnectionType::tcp_ports`, PLAN.md
    /// decision 35), so a site's proxy may be on any port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
}

impl Default for TicketSystemSettings {
    fn default() -> Self {
        TicketSystemSettings {
            url: "https://tickets.example.com".to_owned(),
            request_timeout_seconds: 30,
            proxy: None,
        }
    }
}

impl ace_sdk::ConnectionType for TicketSystem {
    const NAME: &'static str = "example_ticket_system";
    const SECRETS: &'static [&'static str] = &["token"];
    type Settings = TicketSystemSettings;

    /// Which system is asked changes what is found; how long a request may take doesn't.
    fn identity(settings: &TicketSystemSettings) -> serde_json::Value {
        serde_json::json!({"url": settings.url})
    }

    /// The proxy's port, when it names one, beside the lookup's own.
    fn tcp_ports(settings: &TicketSystemSettings) -> Vec<u16> {
        settings
            .proxy
            .as_deref()
            .and_then(|url| url.trim_end_matches('/').rsplit(':').next())
            .and_then(|port| port.parse().ok())
            .into_iter()
            .collect()
    }
}

/// The ticket lookup's one slot: the ticket system.
pub const TICKETS: ace_sdk::ConnectionSlot = ace_sdk::ConnectionSlot::of::<TicketSystem>("tickets");

impl Module for TicketLookup {
    const NAME: &'static str = "example_ticket_lookup";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn, TICKET];
    const CONNECTIONS: &'static [ace_sdk::ConnectionSlot] = &[TICKETS];
    type Output = TicketAnalysis;
    type Settings = TicketSettings;

    fn init(_: &TicketSettings) -> Result<Self, ModuleError> {
        Ok(TicketLookup)
    }
}

impl Lookup for TicketLookup {
    // a real lookup would connect to its ticket system
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<TicketSettings>,
    ) -> Result<Outcome<TicketAnalysis>, ModuleError> {
        let observable = ctx.observable();
        if observable.kind == TICKET {
            // The lookup ran to its end and failed: a result with its reason, not a failed task.
            // An `Err(ModuleError)` here would be a task that didn't finish, which leaves no
            // result and is tried again only when it says its peer was unavailable.
            if !observable.value.starts_with(&ctx.settings().prefix) {
                let unknown = format!(
                    "the ticket system has no ticket {}: its tickets start with {}",
                    observable.value,
                    ctx.settings().prefix
                );
                return Ok(Outcome::Done(
                    ResultEnvelope::new(TicketAnalysis {
                        tickets: Vec::new(),
                    })
                    .with_error(unknown),
                ));
            }
            return Ok(Outcome::Done(ResultEnvelope::new(TicketAnalysis {
                tickets: vec![observable.value.clone()],
            })));
        }
        let ticket = format!("{}{}", ctx.settings().prefix, observable.value);
        let result = ResultEnvelope::new(TicketAnalysis {
            tickets: vec![ticket.clone()],
        })
        .with_summary(format!("1 ticket for {}", observable.value))
        .with_observable(NewObservable::new(TICKET, ticket));
        Ok(Outcome::Done(result))
    }
}

/// The site's parser: the tickets a file names.
pub struct TicketFile;

/// What the ticket file parser found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TicketFileAnalysis {
    pub tickets: Vec<String>,
}

impl AnalysisType for TicketFileAnalysis {
    const NAME: &'static str = "example_ticket_file_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = TicketFile::NAME;
}

/// How a ticket file's result shows on its page.
#[derive(askama::Template)]
#[template(path = "ticket_file_analysis.html")]
pub struct TicketFileView<'a> {
    pub analysis: &'a TicketFileAnalysis,
}

impl AnalysisView for TicketFileAnalysis {
    type View<'a> = TicketFileView<'a>;

    fn view(&self) -> TicketFileView<'_> {
        TicketFileView { analysis: self }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TicketFileSettings {
    /// What a ticket's name starts with, before its number.
    pub prefix: String,
    /// Extensions, such as `.bin`, of files the module never reads: its declaration of what it
    /// takes (`Module::takes`) is built from these, so the core queues no task for such a file.
    pub skip_extensions: Vec<String>,
}

impl Default for TicketFileSettings {
    fn default() -> Self {
        TicketFileSettings {
            prefix: "TICKET-".to_owned(),
            skip_extensions: Vec::new(),
        }
    }
}

/// How much of a file the parser reads.
const TICKET_FILE_BYTES: u64 = 1024 * 1024;

impl Module for TicketFile {
    const NAME: &'static str = "example_ticket_file";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = TicketFileAnalysis;
    type Settings = TicketFileSettings;

    fn init(settings: &TicketFileSettings) -> Result<Self, ModuleError> {
        // every position of a file would start a ticket
        if settings.prefix.is_empty() {
            return Err(ModuleError::other("prefix must not be empty"));
        }
        Ok(TicketFile)
    }

    /// What it takes, as a site's module declares it (PLAN.md decision 23): a file with bytes, and
    /// not one of the extensions the settings skip, compared lowered. The core queues no task for
    /// anything else, and the pool checks it again before `analyze`, which therefore doesn't.
    fn takes(settings: &TicketFileSettings) -> Takes {
        Takes::everything()
            .and(Condition::not_empty(), "an empty file")
            .and(
                Condition::Extension(Text::new(
                    Match::OneOf(settings.skip_extensions.clone()),
                    Case::Lower,
                ))
                .negated(),
                "its extension is one the settings skip",
            )
    }
}

impl Parser for TicketFile {
    fn analyze(
        &self,
        ctx: &TaskContext<TicketFileSettings>,
    ) -> Result<Outcome<TicketFileAnalysis>, ModuleError> {
        use std::io::Read;
        let file = ctx.input_file()?;
        let mut bytes = Vec::new();
        std::fs::File::open(&file.local_path)?
            .take(TICKET_FILE_BYTES)
            .read_to_end(&mut bytes)?;
        let text = String::from_utf8_lossy(&bytes);
        let prefix = ctx.settings().prefix.as_str();
        let mut tickets: Vec<String> = Vec::new();
        for (at, _) in text.match_indices(prefix) {
            let number: String = text[at + prefix.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            let ticket = format!("{prefix}{number}");
            if !number.is_empty() && !tickets.contains(&ticket) {
                tickets.push(ticket);
            }
        }
        if tickets.is_empty() {
            return Ok(Outcome::Skipped("the file names no ticket".to_owned()));
        }
        let mut result = ResultEnvelope::new(TicketFileAnalysis {
            tickets: tickets.clone(),
        })
        .with_summary(format!("{} tickets named", tickets.len()));
        for ticket in tickets {
            result = result.with_observable(NewObservable::new(TICKET, ticket));
        }
        Ok(Outcome::Done(result))
    }
}

/// The example collector (the crate's docs).
pub const EXAMPLE_COLLECTOR: ace_app::collector::CollectorSpec =
    ace_app::collector::CollectorSpec::new("example").secrets(&[EXAMPLE_COLLECTOR_TOKEN]);

/// The secret the example collector reads, as a real one reads its source's credentials.
pub const EXAMPLE_COLLECTOR_TOKEN: &str = "example_collector_token";

/// The example collector's settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryCollectorSettings {
    /// Where its `*.ticket` files arrive.
    pub directory: std::path::PathBuf,
    /// The analysis mode its roots run in.
    #[serde(default = "default_collector_mode")]
    pub analysis_mode: String,
    /// The ticket system's queue, which the ticket alert's summary shows.
    #[serde(default = "default_ticket_queue")]
    pub ticket_queue: String,
    /// The tags each root gets (`Origin::tags`).
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_collector_mode() -> String {
    "analysis".to_owned()
}

fn default_ticket_queue() -> String {
    "triage".to_owned()
}

/// A collector over a directory (the crate's docs).
pub struct DirectoryCollector {
    settings: DirectoryCollectorSettings,
}

impl DirectoryCollector {
    pub fn new(setup: &ace_app::collector::CollectorSetup) -> Result<DirectoryCollector, String> {
        let settings: DirectoryCollectorSettings = serde_json::from_value(
            setup
                .settings
                .clone()
                .ok_or("the example collector needs settings with its directory")?,
        )
        .map_err(|e| format!("the example collector's settings: {e}"))?;
        if setup.secrets.get(EXAMPLE_COLLECTOR_TOKEN).is_none() {
            return Err(format!(
                "the example collector needs {EXAMPLE_COLLECTOR_TOKEN}"
            ));
        }
        Ok(DirectoryCollector { settings })
    }

    /// The files waiting, oldest name first; dot files, such as Finder's `.DS_Store`, aren't items.
    fn waiting(&self) -> Result<Vec<std::path::PathBuf>, String> {
        let entries = std::fs::read_dir(&self.settings.directory)
            .map_err(|e| format!("{}: {e}", self.settings.directory.display()))?;
        let mut files: Vec<std::path::PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path.extension().is_some_and(|e| e == "ticket")
                    && !path
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            })
            .collect();
        files.sort();
        Ok(files)
    }

    async fn item(
        &self,
        submitter: &ace_app::collector::Submitter,
        path: &std::path::Path,
        name: &str,
    ) -> Result<ace_app::collector::Item, String> {
        use ace_app::collector::{Item, Origin, Submission, SubmittedFile};
        let spooled = submitter
            .spool_file(path)
            .await
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Item {
            key: Some(name.to_owned()),
            submission: Submission {
                description: format!("Example ticket file {name}"),
                analysis_mode: Some(self.settings.analysis_mode.clone()),
                event_time: None,
                observables: Vec::new(),
                file_yara_meta: Default::default(),
            },
            origin: Origin {
                details: Some(serde_json::json!({
                    "alert_type": TICKET_ALERT_TYPE,
                    "tool": "example collector",
                    "details": {"ticket_queue": self.settings.ticket_queue},
                })),
                tags: self.settings.tags.clone(),
                ..Origin::default()
            },
            files: vec![SubmittedFile {
                path: ace_results::AlertPath::new(name).map_err(|e| e.to_string())?,
                spooled,
            }],
        })
    }
}

impl ace_app::collector::Collector for DirectoryCollector {
    fn collect<'a>(
        &'a self,
        submitter: &'a ace_app::collector::Submitter,
    ) -> ace_app::collector::PassFuture<'a> {
        use ace_app::collector::{NotSubmitted, Pass};
        Box::pin(async move {
            for path in self.waiting()? {
                if submitter.stopping() {
                    break;
                }
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                // the core has it already: forget it without reading it
                match submitter.submitted(&name).await {
                    Ok(Some(root)) => {
                        tracing::info!(%root, file = %name, "already submitted; not read again");
                        std::fs::remove_file(&path)
                            .map_err(|e| format!("{}: {e}", path.display()))?;
                        continue;
                    }
                    Ok(None) => {}
                    // the submission decides, as it would without the question
                    Err(e) => {
                        tracing::warn!(file = %name, "couldn't ask whether it was submitted: {e:#}")
                    }
                }
                // a file that went or can't be read ends the pass; the next one tries again
                let item = self.item(submitter, &path, &name).await?;
                match submitter.submit(&item).await {
                    // the core has it: the source can forget it
                    Ok(_) => std::fs::remove_file(&path)
                        .map_err(|e| format!("{}: {e}", path.display()))?,
                    Err(NotSubmitted::Refused(_)) => {
                        let rejected = self.settings.directory.join("rejected");
                        std::fs::create_dir_all(&rejected)
                            .and_then(|()| std::fs::rename(&path, rejected.join(&name)))
                            .map_err(|e| format!("{}: {e}", path.display()))?;
                    }
                    // it stays where it is, for the next pass
                    Err(NotSubmitted::GivenBack(_)) => break,
                }
            }
            Ok(Pass::Drained)
        })
    }
}
