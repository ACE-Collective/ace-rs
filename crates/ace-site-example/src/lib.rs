//! An example site, built the way a site repository builds its binaries (PLAN.md 2.31, 2.32):
//! the open-source pools, one module of the site's own in the network pool, and one observable
//! type of its own, which that module's results add.
//!
//! The ticket lookup stands in for a site's lookup in its own ticket system. For an fqdn it adds
//! an `example_ticket` observable; for a ticket it records the ticket and adds nothing.

use ace_app::App;
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
        .python_pool(ace::python_pool())
        .module_in_group("correlation", TicketLookup::NAME)
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
