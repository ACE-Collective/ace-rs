# 0005: A site's hunt types, query sources and named alert summaries

Status: designed and built on 2026-11-21 as PLAN.md decision 40, for the site port's batch C2 (LogScale) and later D3 (MailFilter). It follows the extension points ace4 already has: `App::hunt_type` for a hunt type's validation, `App::command_type_with_connections` and the overlay's shared connections for a correlation command type, and `App::alert_summary` for the alert page's summary. *What the owner decides* lists the two choices it left open, which the owner made on 2026-11-22: a search past its timeout fails the run, and Splunk's instances became shared connections (PLAN.md decision 41), which changes *Splunk on the same path* below.

## The problem

the site port's inventory (`docs/modules.md`, *Missing extension points*) names four gaps that stop a site's hunts from running in ace4:

2. A hunt type adds only its validation (`App::hunt_type`). `ace hunter` runs a hunt only when its `type` is `splunk`, and skips any other, saying it "waits for its client". There is no way for a site to say how its hunts' query runs.
3. A correlation's query sources are a closed enum with one variant, Splunk (`ace_app::hunter::QuerySourceConfig`). A site can't add one.
4. Credentials: since `v0.7.8-g2` a command type takes the shared connections its overlay entry binds, and `ace hunter` resolves their secrets. Nothing gives a hunt type's query or a query source a connection.
9. ace3 picks an alert's template by the hunt's `alert_template` before it looks at the alert's type (`saq/gui/alert.py`, `GUIAlertPresenter.template_path`). ace4 keeps `alert_template` in the submission's `extensions` and picks a summary by type only.

Splunk, ace4's own hunt type, is special-cased throughout `ace_app::hunter`: its instances, its search, its event time, its source. The design puts Splunk on the same path a site's type takes, so there is one.

## The design

### A hunt type's search

A new trait in `ace-hunt`, `ace_hunt::search::HuntSearch`, is the running half of a hunt type, beside `HuntType`, the loading half:

```rust
pub trait HuntSearch: Send + Sync {
    /// The check of a hunt the type's class makes when the hunter loads it (Splunk: the instance it names).
    fn on_load(&self, config: &HuntConfig) -> Result<(), HuntError> { Ok(()) }
    /// Runs the hunt's query over the window: the rows, and what ran.
    fn search<'a>(&'a self, hunt: &'a Hunt, home: &'a Path, window: &'a Window,
                  limits: SearchLimits, stop: Stop) -> BoxFuture<'a, Searched>;
    /// ace3's `extract_event_timestamp` for one row.
    fn event_time(&self, row: &JsonMap<String, Json>, now: DateTime<Utc>) -> Option<DateTime<Utc>>;
}
```

`Searched` holds what ran (the query as the type formats it, the link to it in the vendor's console, a search id, the `tool_instance`) and the rows or the error. `SearchLimits` is the hunter's poll interval and the hunt's `query_timeout`; `Stop` is a future that ends when the hunter stops, which a search must end on. This is ace3's `QueryHunt` contract (`execute_query`, `extract_event_timestamp`, `formatted_query`, `search_link`, `tool_instance`) without ace3's mutable hunt object.

A binary adds one with `App::hunt_search(kind, slots, build)`, for the hunt type `kind` that `App::hunt_type` added. `slots` are the shared connections it takes, as a command type's are; `build` makes the search from a `SearchSetup` (below) or says why it can't. A search for a type the binary hasn't is refused when `ace` starts (`App::check_overlay`). A type with no search loads its hunts, and `ace hunter` skips them, saying the binary has no search for the type.

`ace hunter`'s tick no longer knows Splunk: it finds the hunt type's search, asks it for the rows, and hands its event time, query, link and `tool_instance` to `ace_hunt::query::process`, as it handed Splunk's.

### A query source

`ace_hunt::correlate::source::QuerySource` is unchanged. A binary adds a query source *type* with `App::query_source_type(kind, slots, build)`, as ace3's `hunter.correlation.query_sources` entry names a class. An instance is an entry of the overlay's `query_sources:`, named as a correlation's `source:` names it, with its type, settings and connections:

```yaml
query_sources:
  logscale:
    type: logscale
    settings: {repository: search-all, use_index_time: false}
    connections: {endpoint_vendor: endpoint}
```

When the overlay has no `query_sources:` key the hunter has ace3's default, `splunk` on the `default` instance. A source that fails to build is logged and left out, and a query naming it fails its step, as in ace3.

### Splunk on the same path

Every `App` has the types `splunk` for both, as every `App` has the AI backend type `splunk` (`ai::builtin_types`), and a site's type of that name takes its place. *Since decision 41 (2026-11-22), Splunk's instances are the overlay's connections of type `splunk`: the search takes every one by its name, a source binds one to its slot `splunk`, and the hunter configuration's `splunk:` is gone. What follows is the design as first built.* Splunk's instances stay where they are, in the hunter configuration's `splunk:`, which is ace3's global `splunk_config_<name>` sections, read by both Splunk types and, in `ai_api`, by the Splunk AI backend. Their secrets keep ace3's names (`splunk_<instance>_password`, `splunk_<instance>_token`). So Splunk's search and source are built from the hunter's Splunk instances rather than from connections, and that is the only Splunk-specific thing left in the hunter: where its types' builder finds the instances. The tick, the source registry and the trait objects are the same for every type.

### Credentials

A search or a source takes shared connections (`ace_sdk::connections`), and nothing else. The overlay binds them:

- a hunt type's search in `hunt_types.<kind>.connections`, with its settings in `hunt_types.<kind>.settings`;
- a query source in `query_sources.<name>.connections`.

`SearchSetup` is what a builder is given: the entry's name, its settings, and its connections (each with its secrets when the process holds them). `ace hunter` resolves the secrets of the connections that `hunt_types:`, `query_sources:` and `command_types:` bind, and of the Splunk instances, and no others (PLAN.md 2.24). Every `ace` command checks the bindings against the slots when it reads the overlay (`App::check_overlay`), as it checks a command type's, and a connection that only a search or a source binds counts as one a component of the binary takes.

So a site's `endpoint_vendor` connection is held by the lookups pool (its Endpoint modules) and by `ace hunter` (the LogScale search and source). The AI backend's read-only client is a second connection of the same type, bound only by its `ai_api.backends` entry, so only `ace serve-ai` holds it.

### What `ace serve` gets

`ace serve` validates hunts (the `hunt` router, PLAN.md 6.4) but never searches. It builds the query sources with their settings and none of their secrets, as it builds the command types, and wraps each so that running a query is refused ("a query runs only in ace hunter; send its saved results"): a validation run then has each source's default time field and format and its display of the window in the trace, and nothing in `ace serve` can reach a data source. It builds no hunt type search. Splunk's sources need the hunter's instances, which `ace serve` hasn't, so in `ace serve` they fail to build and are left out, as now. *Since decision 41, `ace serve` builds them too, from their instances' connections without secrets.*

### An alert summary chosen by name

`App::alert_template::<T: AlertSummary>(name)` adds a summary under a template name, such as ace3's `endpoint_vendor/logscale.html`. The alert page's choice becomes ace3's: the submission's `extensions.alert_template` first, when a summary has that name, then the alert's type as now, then the default. A name with no summary falls through to the type, where ace3 would fail to render the page; that is logged. The open-source hunt summary is registered under ace3's own name too, `analysis/custom/hunter_splunk.html`, which two of the signatures' hunts name.

The summaries live in the binary, as askama templates, as the owner's direction of 2026-11-15 has it for summaries by type ("a site/integration can register its own through `App`"). ace3's Manual Analysis list of selectable templates (`custom_alerts.selectable_templates`) has no counterpart, since ace4 has no Manual Analysis page; when it has one, it offers the named summaries.

## What it changes

- `ace_app::hunter`: `QuerySourceConfig` and the hunter configuration's `query_sources` go (the overlay's `query_sources:` replaces them); `Tick::search` becomes `Option<ace_hunt::search::Ran>`; the tick's Splunk code moves into the Splunk search (`hunter::splunk`).
- `ace_sdk::overlay`: two sections, `hunt_types:` and `query_sources:`.
- `ace_gui::analysis::summary`: named summaries.
- `ace-site-example`: a hunt type with a search, `example_tickets`, over its ticket system's connection, and a query source type, `example_tickets`, each tested against a recorded ticket system; a named summary.
- site_port: LogScale's search, source, AI backend and two summaries (batch C2).

## What the owner decides

1. **A search's timeout.** (Decided 2026-11-22: a search past its timeout fails the run.) a site's LogScale search returns the rows it has when its timeout passes, which is none until the search is done, and ace3's hunter then records the window as searched, so a slow search silently skips a window. ace4's Splunk search fails the run instead, and the window is searched again on the next tick. Recommendation: LogScale fails too, as built; its AI backend already turns the same case into a 504.
2. **Splunk's instances.** (Decided 2026-11-22: they become shared connections of type `splunk`, PLAN.md decision 41.) They stay in the hunter configuration, so `ace serve` can't build the Splunk query sources for validation and the Splunk AI backend repeats an instance's settings. Recommendation: leave them for now; if the owner wants one place for every credential, they become shared connections of a type `splunk`, which needs a binding per instance name, not per fixed slot.
