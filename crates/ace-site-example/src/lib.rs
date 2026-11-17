//! An example site, built the way a site repository builds its binaries (PLAN.md 2.31, 2.32):
//! the open-source pools, one module of the site's own in the network pool, and one observable
//! type of its own, which that module's results add.
//!
//! The ticket lookup stands in for a site's lookup in its own ticket system. For an fqdn it adds
//! an `example_ticket` observable; for a ticket it records the ticket and adds nothing. A ticket
//! the system doesn't know is a lookup that failed: its result says so with
//! `ResultEnvelope::with_error`, as any module's does (ace3's `Analysis.error`), which the alert
//! view shows as an `error` badge with the reason. Its results
//! have a view of the site's own, its analysis template (5.9), and a ticket has an observable action
//! of the site's own that opens it, both named by the binary's list.
//!
//! Its alert summary is the site's own too: an alert whose type is `example - ticket`, or starts with
//! it, has its ticket queue and ticket at the top of its page (`ExampleTicketSummary`), where ace3 has
//! a template per alert type.
//!
//! Its alert router type (PLAN.md 7.13) is ace3's example integration's (`integrations.example`'s
//! `ExampleTagRouter`): an overlay entry of type `example_tag` sends a new alert carrying one tag to one
//! queue, and does nothing to any other, so the type changes nothing until an entry and that tag appear.

use ace_app::App;
use ace_gui::{AlertSummary, AnalysisView, ObservableAction, SummaryInput};
use ace_results::{AnalysisType, NewObservable, ObservableKind, ObservableType, ResultEnvelope};
use ace_sdk::{Lookup, Module, ModuleError, Outcome, TaskContext};
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

/// The site's binaries' list.
pub fn app() -> App {
    App::new()
        .observable_types(OBSERVABLE_TYPES)
        .parser_pool(ace::parser_pool())
        .lookup_pool(ace::lookup_pool().module::<TicketLookup>())
        .module_in_group("correlation", TicketLookup::NAME)
        .analysis_view::<TicketAnalysis>()
        .observable_action(OPEN_TICKET)
        .alert_summary::<ExampleTicketSummary>()
        .alert_router_type(EXAMPLE_TAG_ROUTER, |settings| {
            Ok(std::sync::Arc::new(ExampleTagRouter::new(settings)?))
        })
}

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
}

impl Default for TicketSettings {
    fn default() -> Self {
        TicketSettings {
            prefix: "TICKET-".to_owned(),
        }
    }
}

impl Module for TicketLookup {
    const NAME: &'static str = "example_ticket_lookup";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn, TICKET];
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
