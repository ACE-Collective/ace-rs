//! The site overlay: the small YAML file a site writes over its modules' manifests (PLAN.md
//! 2.23).
//!
//! ```yaml
//! modules:
//!   rdap_analyzer:
//!     settings:
//!       request_timeout_seconds: 10
//!   splunk_api:
//!     instances:
//!       proxy_domain_lookup:
//!         inputs: [fqdn]
//!         settings:
//!           query: index=proxy hostname="<O_VALUE>"
//! secrets:
//!   splunk_password: env:ACE4_SPLUNK_PASSWORD
//!   resolver_token: file:/run/secrets/resolver_token
//! ```
//!
//! Every level refuses keys it doesn't know, settings blocks included (ace3 #858). A module with
//! no section runs on its manifest's defaults (ace3 #1044). A section for a module this build
//! doesn't have logs a warning and is skipped, so removing a module never stops startup (ace3
//! #901, #916).
//!
//! `scheduler:` sets the schedule, timeout or `enabled` of the core's scheduled tasks (PLAN.md 6.7),
//! by task name, each key refused when unknown. A task this build doesn't have logs a warning and is
//! skipped, as a removed module is.
//!
//! `nrd:` lists the feeds of the newly registered domains list (PLAN.md 7.4), as ace3's `nrd:`
//! section does, for the scheduler's `nrd_refresh` task.
//!
//! `hooks:` holds the settings of `configuration_defined_tagging` and `observable_modifier`, which the
//! core runs over the whole tree (PLAN.md 7.6, `crate::hooks`).
//!
//! `actions:` holds the settings of the remediators, remediation probes and file collectors a network
//! pool hosts (PLAN.md 7.9, `crate::actions`), by `<kind>/<name>`, such as `remediation/office365_email`.
//! A pool gives each handler its own entry's `settings`, and the secrets its spec declares.
//!
//! `dispositions:` and `disposition_classification:` are ace3's sections of those names (PLAN.md 7.14,
//! `ace_service`'s `Dispositions`). `dispositions` is the set of alert dispositions, each with ace3's `rank`
//! (an event takes its alerts' highest), `css` (its badge's class), `show_save_to_event` (the disposition
//! offers Save to Event) and `analyst_selectable` (false for one only ACE sets).
//! `disposition_classification` maps a disposition to `tp` or `fp`. Each entry is merged over ace3's own, as
//! ace3 merges a site's config over its `saq.default.yaml`, so a site names only what it changes, and a new
//! disposition is a new entry with at least `rank` and `css`. A disposition can't be removed, as in ace3,
//! whose merge only adds and replaces; one a site retires is set `analyst_selectable: false`. `ace serve`
//! checks both when it starts; a pool doesn't read them.
//!
//! `svs:` is ace3's section of that name, holding the keys of SVS that are ported (PLAN.md 7.10): so far
//! `log_search_url`, which `ace serve` checks when it starts, `yara`, YARA validation's (batch 3), with
//! the keys of ace3's `service_svs` section that its workers read, and batch 4's `attack_release`, `catalog`
//! (the Atomic Red Team repositories whose tests runs may be registered for) and the keys of `runs` that
//! a run's windows read. Every process that reads the overlay refuses a `yara` whose lease its heartbeat
//! can't keep, as every ace3 process refuses that `service_svs`, and a `catalog` or `runs` whose values
//! can't be used.
//!
//! `alert_routers:` is ace3's section of that name (PLAN.md 7.13, `ace_service::routing`): each router, by its
//! name, with its `type`, `priority` and `settings`. `ace serve` builds and checks them when it starts.
//!
//! `ai_api:` turns on the AI investigation API (PLAN.md 7.15, `ace_service::ai`), which is off without
//! it, and names its query backends: ace3's `ai_api:` and `ai_query_backend_<name>:` sections. Each
//! backend has a `type` the binary has, its `limits`, the `secrets` it is given and its `settings`.
//! `ace serve` builds and checks them when it starts; a pool doesn't read them.
//!
//! `observable_exclusions:` is ace3's section of that name (`crate::exclusions`): the observables no
//! module analyzes, each a `<type>:<value>` by name, merged over ace3's defaults by name, a name set to
//! null dropping one of ace3's. The core reads it, as `Exclusions::from_section`, where it decides
//! what to queue; a pool doesn't.
//!
//! `analysis_cache:` is ace3's section of that name (PLAN.md decision 26, `crate::cache`): `enabled`, the
//! switch for the whole cache, and `retention_days`, how long a day's kept results stay. A module's
//! section, or an instance's, sets its time to live in seconds with `cache_ttl` beside its `settings`,
//! as ace3's module sections do, 0 keeping none; a module that doesn't opt in (`Module::CACHE`) refuses
//! any other value, and every binary refuses a cacheable module whose task reads what its key doesn't
//! hold (`Manifest::cache_refusal`). The core reads the switch; a pool doesn't.
//!
//! A module's section, or an instance's, sets ace3's `automation_limit` beside its `settings`: the
//! most results of the module's analysis type a root holds before the core stops queuing the module
//! there (`Module::AUTOMATION_LIMIT`, which it replaces). Like `cache_ttl` it isn't a setting, so it
//! isn't in a cached result's key, as ace3's config hash leaves it out.
//!
//! A module's section, or an instance's, sets ace3's `enabled` (PLAN.md decision 33). `enabled: false`
//! turns off a module that is on by default, or one instance: no component is made of it, so no pool
//! builds it, the core queues no task for it, and a module that depends on it finds its dependency met,
//! as ace3's engine treats a dependency on a module it didn't load (`build_and_validate_dependency_graph`)
//! and as decision 30 treats a dependency the binary hasn't. `enabled: true`, like a section with
//! nothing in it, turns on a module that is off by default. Left out, a section changes nothing about
//! whether the module runs.
//!
//! `collectors:` holds each collector's section (PLAN.md 6.1, `ace_app::collector`), by its name: its
//! `settings`, which its builder is given as a module's are, how long a key it submitted holds
//! (`key_lifetime_seconds`), how long it waits between passes that found nothing (`poll_seconds`), how
//! many times it tries a submission the core couldn't take (`submit_attempts`), and how long a stop
//! waits for its pass (`stop_seconds`). `ace collect <name>` reads its own section and secrets and no
//! other collector's.
//!
//! `connections:` holds the shared connections (`crate::connections`): each a named connection of a
//! type an integration declares, with its settings and the secrets of `secrets:` it uses, which a
//! module's, an instance's, an action handler's, a collector's or an AI backend's section, or a
//! command type's entry in `command_types:`, binds to one of its slots with `connections:`. Every
//! name a `connections:` binds must be a connection here, and every secret a connection names a
//! secret in `secrets:`; the connection's type is checked by what reads it.
//!
//! `secrets:` says where each secret comes from, by the name modules declare in
//! `Module::SECRETS`: `env:<VARIABLE>` or `file:<path>`, as ace3's `env:` references. Nothing
//! is read when the overlay loads; a pool reads only the ones its modules declare (PLAN.md 2.24,
//! ace3 #1009).
//!
//! A module that ace3 ships disabled (`Module::ENABLED_BY_DEFAULT` false) runs only when the overlay
//! has a section for it, empty or not.
//!
//! A module with `instances` runs once per instance and not as itself, as each of ace3's
//! `analysis_module_*` sections is one run of its class. An instance's name is its key: the
//! name its tasks and results carry in the queue and the tree, and the name modes and groups
//! list. It may narrow the module's inputs, and join module groups with `groups`.

use std::collections::BTreeMap;

use ace_results::ObservableKind;
use serde::Deserialize;
use serde_json::Value;

use crate::connections::{Binding, ConnectionKind, ConnectionSlot};
use crate::manifest::{Manifest, SettingsError};
use crate::takes::Takes;

/// A site's overlay, as its YAML file says it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Overlay {
    /// Sections by module name.
    pub modules: BTreeMap<String, ModuleSection>,
    /// Where each secret comes from, by name.
    pub secrets: BTreeMap<String, SecretSource>,
    /// The core's scheduled tasks (PLAN.md 6.7), by task name. `ace serve` reads it; a pool doesn't.
    pub scheduler: BTreeMap<String, ScheduledTaskSection>,
    /// The feeds of the newly registered domains list (PLAN.md 7.4), ace3's `nrd:` section, which
    /// `ace serve`'s `nrd_refresh` task reads.
    pub nrd: NrdSection,
    /// The settings of the modules the core runs as hooks (PLAN.md 7.6), `ace_sdk::hooks`. `ace serve`
    /// reads it; a pool doesn't.
    pub hooks: crate::hooks::HooksSection,
    /// The settings of the action handlers (PLAN.md 7.9), by `<kind>/<name>`.
    pub actions: BTreeMap<String, ActionSection>,
    /// ace3's `disposition_classification:`, each entry over ace3's own (PLAN.md 7.14). `ace serve` reads
    /// it; a pool doesn't.
    pub disposition_classification: BTreeMap<String, DispositionClass>,
    /// ace3's `dispositions:`, by disposition, each entry over ace3's own (PLAN.md 7.14). `ace serve` reads
    /// it; a pool doesn't.
    pub dispositions: BTreeMap<String, DispositionSection>,
    /// The names in `dispositions` in the order the file writes them, which is where a site's own
    /// disposition goes in the menus, after ace3's, as ace3's merge appends it. `from_yaml` sets it.
    #[serde(skip)]
    pub disposition_order: Vec<String>,
    /// ace3's `svs:` section, as far as SVS is ported (PLAN.md 7.10). `ace serve` reads it; a pool doesn't.
    pub svs: SvsSection,
    /// ace3's `alert_routers:` (PLAN.md 7.13), by router name: the routers of the types the binary has
    /// that decide which queue an alert belongs in. `ace serve` reads it; a pool doesn't.
    pub alert_routers: BTreeMap<String, AlertRouterSection>,
    /// The YARA export of the observables enabled for detection (PLAN.md 7.16): ace3's `yara_export:`,
    /// `yara_export_string_modifiers:` and `yara_export_string_boundaries:`. `ace serve` reads it; a pool
    /// doesn't.
    pub yara_export: YaraExportSection,
    /// The AI investigation API (PLAN.md 7.15): ace3's `ai_api:` and `ai_query_backend_<name>:`
    /// sections. Off unless `enabled`. `ace serve` reads it; a pool doesn't.
    pub ai_api: AiApiSection,
    /// ace3's `observable_exclusions:`, each `<type>:<value>` by name over ace3's own, null dropping one
    /// (`crate::exclusions`): the observables no module analyzes. `from_yaml` checks every spec reads.
    /// The core reads it; a pool doesn't.
    pub observable_exclusions: BTreeMap<String, Option<String>>,
    /// ace3's `analysis_cache:` (PLAN.md decision 26, `crate::cache`): the switch for the whole cache
    /// and how long its rows' days are kept. Each module's time to live is its section's `cache_ttl`.
    /// The core reads it; a pool doesn't.
    pub analysis_cache: AnalysisCacheSection,
    /// The collectors' sections (PLAN.md 6.1), by collector name. `ace collect <name>` reads its own;
    /// nothing else does.
    pub collectors: BTreeMap<String, CollectorSection>,
    /// The shared connections (`crate::connections`), by name.
    pub connections: BTreeMap<String, crate::connections::ConnectionSection>,
    /// The correlation command types' entries, by type name: the connections each binds. `ace
    /// hunter` and `ace serve` read them; a pool doesn't.
    pub command_types: BTreeMap<String, CommandTypeSection>,
}

/// What the overlay says about one correlation command type (`ace_app::App::command_type_with`).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CommandTypeSection {
    /// The type's slots, each bound to a connection (`crate::connections`).
    pub connections: BTreeMap<String, String>,
}

/// What the overlay says about one collector (PLAN.md 6.1). Each field left out keeps its default,
/// which `ace_app::collector` gives.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CollectorSection {
    /// What the collector's builder is given, as a module's settings are.
    pub settings: Option<Value>,
    /// How long a key the collector submitted keeps an item with the same key from being submitted
    /// again, ace3's `persistence_unmodified_expiration_seconds`.
    pub key_lifetime_seconds: Option<u64>,
    /// How long the collector waits after a pass that had nothing more, ace3's
    /// `collection_frequency`.
    pub poll_seconds: Option<u64>,
    /// How many times one item's submission is tried while the core can't take it, before the item is
    /// given back to its source.
    pub submit_attempts: Option<u32>,
    /// How long a stop waits for the pass under way to end, after which what it holds goes back to its
    /// source uncommitted.
    pub stop_seconds: Option<u64>,
    /// The collector's slots, each bound to a connection (`crate::connections`).
    pub connections: BTreeMap<String, String>,
}

/// The analysis cache's settings (`Overlay::analysis_cache`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AnalysisCacheSection {
    /// ace3's `enabled`: false turns the whole cache off, so the core neither looks a result up nor
    /// keeps one, whatever each module's `cache_ttl` says. A pool reads the overlay either way, and
    /// refuses a module that can't be cached with its `cache_ttl` set.
    pub enabled: bool,
    /// ace3's `partition_retention_days`: a day's rows are dropped this many days after it ends. It
    /// must be longer than every module's time to live, which the core checks when it starts.
    pub retention_days: u32,
}

impl Default for AnalysisCacheSection {
    /// ace3's `saq.default.yaml`.
    fn default() -> Self {
        AnalysisCacheSection {
            enabled: true,
            retention_days: 35,
        }
    }
}

/// The AI investigation API's settings (PLAN.md 7.15, `ace_service::ai`): read-only routes an AI agent's
/// own key calls. ace3's `ai_api:` section, with its `ai_query_backend_<name>:` sections as `backends`.
///
/// What differs from ace3's: `enabled` turns the whole API on, where ace3 runs it as a service of its
/// own that a site starts or doesn't; a backend's `type` names a backend type the binary was built with
/// (`App::ai_backend_type`) where ace3 names a Python module and class; and a backend names the
/// secrets it is given, from `secrets:`, and gets no other. `ace serve` checks the section when it
/// starts, and one it can't use stops it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AiApiSection {
    /// Whether the API answers at all. False by default: its routes then say it's off.
    pub enabled: bool,
    /// Serve requests without limits when the limiter's store can't be reached. False by default,
    /// which refuses them: the limits protect a data source's quota.
    pub rate_limit_fail_open: bool,
    /// The search routes' limits: only the concurrency, the two rates and `max_query_timeout` are used.
    pub search_limits: AiLimitsSection,
    /// The export route's limits, the same four.
    pub export_limits: AiLimitsSection,
    /// The query backends, by name. A backend's name is its route, `/api/ai/v1/query/<name>`, and its
    /// permission, `ai:<name>`.
    pub backends: BTreeMap<String, AiBackendSection>,
}

/// ace3's `AIQueryBackendLimits`. A key left out keeps ace3's default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AiLimitsSection {
    /// The most queries running at once, across every node. ace3's default is 2.
    pub max_concurrency: Option<u32>,
    /// 10 by default; 60 for the export.
    pub requests_per_minute: Option<u32>,
    /// 120 by default; 1200 for the export.
    pub hourly_budget: Option<u32>,
    /// The row limit when a request names none: 1000.
    pub default_limit: Option<u32>,
    /// The largest row limit a request may name: 5000.
    pub max_limit: Option<u32>,
    /// The widest window a query may cover, as `DD:HH:MM:SS`: `90:00:00:00`.
    pub max_window: Option<String>,
    /// The timeout when a request names none, in seconds: 300.
    pub default_query_timeout: Option<u32>,
    /// The largest timeout a request may name, in seconds: 600.
    pub max_query_timeout: Option<u32>,
}

/// One of ace3's `ai_query_backend_<name>:` sections.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiBackendSection {
    /// The backend type, as the binary names it: `splunk`, or ace3's testing backends `fake` and
    /// `fake_unwindowed`, which answer canned rows.
    #[serde(rename = "type")]
    pub kind: String,
    /// Whether the API serves it. False by default, as in ace3.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub limits: AiLimitsSection,
    /// The secrets the backend is given, each a name in `secrets:`. It gets no other.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// What the type's builder takes; null when left out.
    #[serde(default)]
    pub settings: Option<Value>,
    /// The type's slots, each bound to a connection (`crate::connections`), whose secrets it is
    /// given too.
    #[serde(default)]
    pub connections: BTreeMap<String, String>,
}

/// ace3's `yara_export:` section, with its two neighbours `yara_export_string_modifiers:` and
/// `yara_export_string_boundaries:` as `string_modifiers` and `string_boundaries`, and its template
/// directory as `templates`. A key left out keeps ace3's default (`ace_yara::export::ExportConfig`).
/// `ace serve` checks the section when it starts, and one it can't use stops it.
///
/// What differs from ace3's: there is no `max_strings_per_rule`, a libyara setting yara-x doesn't have
/// (a list's 1,000 entries bound the rule). `templates` holds each template's text by type, over the
/// ones ace3 ships, where ace3's `export_template_dir` names a directory. `string_modifiers` and
/// `string_boundaries` replace ace3's maps whole when given, so a site can drop an entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct YaraExportSection {
    /// False builds rulesets without the detections' rules. ace3 turns the export off by disabling its
    /// `observable_export_yara` target.
    pub enabled: Option<bool>,
    /// The observable types to export. An entry also covers every type that extends it.
    pub export_list: Option<Vec<String>>,
    /// The fewest characters a value has to be exported.
    pub export_minimum_length: Option<u32>,
    /// The string modifiers by type; `default` is every other type's.
    pub string_modifiers: Option<BTreeMap<String, String>>,
    /// The boundary family by type: `hostname`, `email_address`, `ipv4`, `ipv6`, `hex`, or `ip`.
    pub string_boundaries: Option<BTreeMap<String, String>>,
    /// A rule template by type, or `default`, each replacing or adding to ace3's.
    pub templates: BTreeMap<String, String>,
}

/// One of ace3's `alert_routers:` entries (PLAN.md 7.13): a router of a type the binary has, which a site
/// names, places in the order and configures. Its name is its key, which every move it makes records.
///
/// What differs from ace3's: `type` names a router type the binary was built with (`App::alert_router_type`)
/// where ace3 names a Python module and class, and `settings` is ace3's `kwargs`. `ace serve` checks every
/// entry when it starts, and an entry it can't build stops it, as the rest of the overlay does, where ace3
/// logs the entry and loads the others (`ace_service::routing`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertRouterSection {
    /// The router type, as the binary names it.
    #[serde(rename = "type")]
    pub kind: String,
    /// Routers run lowest first, and the first to decide wins. The built-in `detection_queue` is 500.
    pub priority: i32,
    /// What the type's builder takes, ace3's `kwargs`; null when left out.
    #[serde(default)]
    pub settings: Option<Value>,
}

/// ace3's `svs:` section. Each batch of 7.10 adds the keys its part reads; one this build doesn't have is
/// refused, as ace3's schema refuses an unknown key.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SvsSection {
    /// A link to the site's log search for one run, shown on the run's page; ACE never queries it.
    /// `{run_uuid}`, `{marker}`, `{test_guid}`, `{earliest}` and `{latest}` (epoch seconds: the run's start,
    /// and the end of its attribution window or now) are replaced, URL-encoded. `ace serve` checks it when
    /// it starts (`ace_core::svs::log_search`).
    pub log_search_url: Option<String>,
    /// YARA validation (batch 3): ace3's `svs.yara`, with `service_svs`'s keys.
    pub yara: SvsYaraSection,
    /// The ATT&CK release coverage uses for technique and tactic names, sub-technique parents, platforms
    /// and revoked techniques (batch 4): ace3's `svs.attack_release`, `v20.0` by default. It names an
    /// extract built into the binary (`ace_core::svs::attack`); `ace serve` refuses one it doesn't have.
    pub attack_release: String,
    /// The Atomic Red Team test catalog (batch 4): ace3's `svs.catalog`.
    pub catalog: SvsCatalogSection,
    /// Test runs: the keys of ace3's `svs.runs` that a run's windows read (batch 4). Batch 5 adds the rest.
    pub runs: SvsRunsSection,
    // ace3's `svs.coverage` has one key, `refresh_interval_seconds` (120): how often `service_svs`
    // recomputes coverage. Here that is the schedule of the scheduler's `svs_coverage_refresh`, every two
    // minutes by default (`scheduler:` in this file, batch 8), so there is no `coverage` section.
}

impl Default for SvsSection {
    fn default() -> Self {
        SvsSection {
            log_search_url: None,
            yara: SvsYaraSection::default(),
            attack_release: "v20.0".to_owned(),
            catalog: SvsCatalogSection::default(),
            runs: SvsRunsSection::default(),
        }
    }
}

impl SvsSection {
    /// Refuses values SVS can't run with, saying which key. Every process that reads the overlay checks it.
    pub fn check(&self) -> Result<(), (String, String)> {
        self.yara
            .check()
            .map_err(|message| ("svs.yara".to_owned(), message))?;
        if !is_attack_release_name(&self.attack_release) {
            return Err((
                "svs.attack_release".to_owned(),
                format!(
                    "{:?} is not an ATT&CK release name (for example v20.0)",
                    self.attack_release
                ),
            ));
        }
        self.catalog
            .check()
            .map_err(|message| ("svs.catalog".to_owned(), message))?;
        self.runs
            .check()
            .map_err(|message| ("svs.runs".to_owned(), message))
    }
}

/// How an ATT&CK release is named: `v20.0`, ace3's `RELEASE_RE` (`^v\d+\.\d+$`, ASCII digits).
pub fn is_attack_release_name(value: &str) -> bool {
    let Some((major, minor)) = value.strip_prefix('v').and_then(|v| v.split_once('.')) else {
        return false;
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    digits(major) && digits(minor)
}

/// ace3's `svs.catalog` (PLAN.md 7.10 batch 4): the Atomic Red Team repositories whose
/// `atomics/T*/T*.yaml` make up the test catalog (`ace_core::svs::catalog`).
///
/// What differs from ace3's:
/// - A repository is named here with its URL and branch, as `svs.yara`'s are, where ace3 names a
///   `git_repo_*` section whose checkout `service_git` keeps: ace4 has no such sections. The catalog reads a
///   commit from SVS's own mirror of the repository, never a working tree.
/// - ace3's `refresh_interval_seconds` is the schedule of the scheduler's `svs_catalog_refresh`
///   (`scheduler:` in this file), every five minutes by default as ace3's 300 seconds.
/// - What one refresh reads is bounded (`max_files`, `max_file_bytes`, `max_total_bytes`, `max_tests`),
///   where ace3 bounds only a file's size.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SvsCatalogSection {
    /// The catalog's repositories, by the name a test's `repository` gives.
    pub repositories: BTreeMap<String, SvsCatalogRepository>,
    /// How long fetching a repository into its mirror may take (the first fetch clones it), and reading a
    /// commit's atomic files from it.
    pub fetch_timeout_seconds: u64,
    /// Where SVS keeps its own bare clone of each catalog repository. The system's temporary directory by
    /// default.
    pub mirror_dir: Option<std::path::PathBuf>,
    /// The most atomic files (`atomics/T*/T*.yaml`) one commit may hold. A commit with more fails its
    /// refresh, and the catalog keeps the tests of the commit it last read.
    pub max_files: u64,
    /// The largest atomic file read, in bytes: ace3's 10 MiB. A larger one is skipped and counted.
    pub max_file_bytes: u64,
    /// The most bytes of atomic files one refresh reads; more fails the refresh.
    pub max_total_bytes: u64,
    /// The most tests one commit may define; more fails the refresh.
    pub max_tests: u64,
}

impl Default for SvsCatalogSection {
    fn default() -> Self {
        SvsCatalogSection {
            repositories: BTreeMap::new(),
            fetch_timeout_seconds: 600,
            mirror_dir: None,
            max_files: 10_000,
            max_file_bytes: 10 << 20,
            max_total_bytes: 256 << 20,
            max_tests: 100_000,
        }
    }
}

/// One Atomic Red Team repository the catalog reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvsCatalogRepository {
    /// What the mirror fetches: a URL or a path git can fetch from. A credential in it is never shown.
    pub url: String,
    /// The branch whose newest commit the catalog reflects.
    pub branch: String,
    /// The SSH private key the mirror fetches with: the name of a secret in the overlay's `secrets:`, as
    /// `svs.yara`'s repositories name theirs. None by default.
    #[serde(default)]
    pub ssh_key: Option<String>,
}

impl SvsCatalogSection {
    /// Refuses values the refresh can't run with.
    pub fn check(&self) -> Result<(), String> {
        for (key, value) in [
            ("fetch_timeout_seconds", self.fetch_timeout_seconds),
            ("max_files", self.max_files),
            ("max_file_bytes", self.max_file_bytes),
            ("max_total_bytes", self.max_total_bytes),
            ("max_tests", self.max_tests),
        ] {
            if value == 0 {
                return Err(format!("{key} must be at least 1"));
            }
        }
        if let Some(dir) = &self.mirror_dir
            && !dir.is_absolute()
        {
            return Err(format!(
                "mirror_dir ({}) must be an absolute path",
                dir.display()
            ));
        }
        for (name, repository) in &self.repositories {
            check_repository(
                name,
                &repository.url,
                &repository.branch,
                &repository.ssh_key,
            )?;
        }
        Ok(())
    }
}

/// ace3's `svs.runs` (PLAN.md 7.10 batches 4 and 5): what a launcher may register and how long a run's
/// windows last (`ace_core::svs::windows`, `ace_core::svs::runs`). ace3's `timer_interval_seconds` has no
/// key: the run timers are the scheduler's `svs_run_timers`, whose schedule the overlay's `scheduler:`
/// section sets.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SvsRunsSection {
    /// A run whose launcher hasn't called start this long after registering it goes to error and is closed.
    pub start_timeout_minutes: u32,
    /// How long a started run waits for its alerts before it ends.
    pub observation_window: SvsObservationWindow,
    /// How much longer than the observation window alerts are still attributed to the run, as late.
    pub attribution_extra_hours: u32,
    /// The largest `extra` a registration may carry, as JSON.
    pub max_extra_bytes: u32,
    /// The most targets one run may have.
    pub max_targets: u32,
    /// The longest maintenance window a launcher may open on a test host.
    pub max_maintenance_minutes: u32,
}

impl Default for SvsRunsSection {
    fn default() -> Self {
        SvsRunsSection {
            start_timeout_minutes: 30,
            observation_window: SvsObservationWindow::default(),
            attribution_extra_hours: 24,
            max_extra_bytes: 16384,
            max_targets: 16,
            max_maintenance_minutes: 240,
        }
    }
}

/// ace3's `svs.runs.observation_window`: the worst-case latency of the signatures a run expects, plus
/// slack, within a floor and a ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SvsObservationWindow {
    /// Added to the worst-case latency of the slowest expected signature.
    pub slack_minutes: u32,
    /// The shortest observation window.
    pub floor_minutes: u32,
    /// The longest observation window.
    pub ceiling_hours: u32,
}

impl Default for SvsObservationWindow {
    fn default() -> Self {
        SvsObservationWindow {
            slack_minutes: 30,
            floor_minutes: 60,
            ceiling_hours: 72,
        }
    }
}

impl SvsRunsSection {
    /// Refuses a floor or ceiling of 0 and a floor above the ceiling, as ace3's schema does.
    pub fn check(&self) -> Result<(), String> {
        for (key, value) in [
            ("start_timeout_minutes", self.start_timeout_minutes),
            ("max_targets", self.max_targets),
            ("max_maintenance_minutes", self.max_maintenance_minutes),
        ] {
            if value == 0 {
                return Err(format!("{key} must be at least 1"));
            }
        }
        let window = &self.observation_window;
        if window.floor_minutes == 0 {
            return Err("observation_window.floor_minutes must be at least 1".to_owned());
        }
        if window.ceiling_hours == 0 {
            return Err("observation_window.ceiling_hours must be at least 1".to_owned());
        }
        if u64::from(window.floor_minutes) > u64::from(window.ceiling_hours) * 60 {
            return Err(format!(
                "observation_window.floor_minutes ({}) must not exceed ceiling_hours ({}) in minutes",
                window.floor_minutes, window.ceiling_hours
            ));
        }
        Ok(())
    }
}

/// What every repository SVS fetches is checked for: its name, URL, branch and `ssh_key`.
fn check_repository(
    name: &str,
    url: &str,
    branch: &str,
    ssh_key: &Option<String>,
) -> Result<(), String> {
    let name_ok = !name.is_empty()
        && name.len() <= 256
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && !name.starts_with('.');
    if !name_ok {
        return Err(format!(
            "repository name {name:?} must be letters, digits, '_', '-' and '.', not starting with '.'"
        ));
    }
    if url.trim().is_empty() {
        return Err(format!("repository {name}: url is empty"));
    }
    if branch.is_empty() || branch.starts_with('-') || branch.contains("..") {
        return Err(format!(
            "repository {name}: branch {branch:?} isn't a branch name"
        ));
    }
    if ssh_key.as_deref() == Some("") {
        return Err(format!("repository {name}: ssh_key is empty"));
    }
    Ok(())
}

/// ace3's `svs.yara` (YARA validation, PLAN.md 7.10 batch 3), with the keys of its `service_svs` section that
/// the validation workers read. Both commits of a repository compile the way the YARA pool's ruleset build
/// loads rules and scan every stored sample, in a contained process.
///
/// What differs from ace3's:
/// - A repository is named here with its URL, branch and signature directory, where ace3 names a
///   `git_repo_*` section and finds the directory from `service_yara.signature_dir`: ace4 has no such
///   sections, and its ruleset build reads one directory of a repository (PLAN.md 2.25).
/// - `file_timeout_seconds` is ace3's `service_yara.default_timeout`, and the work and mirror directories are
///   absolute, as ace4 has no `DATA_DIR`.
/// - The corpus is bounded (`max_corpus_files`, `max_corpus_bytes`) and so is the scan's memory
///   (`scan_memory_mb`), where ace3 bounds neither.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SvsYaraSection {
    /// The repositories whose commits may be validated, by the name a request gives.
    pub repositories: BTreeMap<String, SvsRepository>,
    /// How long compiling and scanning one commit's rules over the whole corpus may take.
    pub scan_timeout_seconds: u64,
    /// How many validations run at once.
    pub max_concurrent_validations: u32,
    /// How long fetching a repository into its mirror may take (the first fetch clones it), and exporting a
    /// commit from it.
    pub fetch_timeout_seconds: u64,
    /// The largest export of one commit, in bytes; unset for no limit.
    pub max_archive_bytes: Option<u64>,
    /// The most files and directories in the export of one commit; unset for no limit.
    pub max_archive_members: Option<u64>,
    /// The most distinct files a validation replays. A corpus with more fails the validation, rather than
    /// leaving samples out of a report that would then read as complete.
    pub max_corpus_files: u64,
    /// The most bytes of files a validation copies out of the bucket, with the same rule.
    pub max_corpus_bytes: u64,
    /// The address space the contained scan may map, in MiB.
    pub scan_memory_mb: u64,
    /// How long one scan of one file may take when the scan runs in this process: ace3's
    /// `service_yara.default_timeout`. A contained scan has no per-file timeout (`ace_yara::replay`).
    pub file_timeout_seconds: u64,
    /// Where SVS keeps its own bare clone of each repository. The system's temporary directory by default.
    pub mirror_dir: Option<std::path::PathBuf>,
    /// Where each validation gets its private working directory: both commits' rules and a plaintext copy of
    /// every sample, deleted when the validation ends. It must have no `.` in its path, which would change
    /// the extension YARA sees for a file without one.
    pub work_dir: Option<std::path::PathBuf>,
    /// How long a finished validation and its report are kept; the scheduler's `svs_validations_prune`
    /// removes older ones.
    pub retention_days: u32,
    /// How many validations one prune transaction removes, with their results.
    pub prune_batch_size: u32,
    /// ace3's `service_svs.poll_interval_seconds`: how long an idle worker waits before it looks again.
    pub poll_interval_seconds: f64,
    /// ace3's `service_svs.heartbeat_interval_seconds`: how often a worker renews its lease.
    pub heartbeat_interval_seconds: u64,
    /// ace3's `service_svs.lease_seconds`: how long a lease lasts without a heartbeat.
    pub lease_seconds: u64,
    /// ace3's `service_svs.max_attempts`: how many times a validation is claimed before one whose worker
    /// stopped heartbeating is failed.
    pub max_attempts: u32,
}

impl Default for SvsYaraSection {
    fn default() -> Self {
        SvsYaraSection {
            repositories: BTreeMap::new(),
            scan_timeout_seconds: 1800,
            max_concurrent_validations: 1,
            fetch_timeout_seconds: 600,
            max_archive_bytes: None,
            max_archive_members: None,
            max_corpus_files: 100_000,
            max_corpus_bytes: 16 << 30,
            scan_memory_mb: 4096,
            file_timeout_seconds: 10,
            mirror_dir: None,
            work_dir: None,
            retention_days: 90,
            prune_batch_size: 100,
            poll_interval_seconds: 5.0,
            heartbeat_interval_seconds: 30,
            lease_seconds: 300,
            max_attempts: 3,
        }
    }
}

/// One repository YARA validation may fetch.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvsRepository {
    /// What the mirror fetches: a URL or a path git can fetch from. An error never shows it.
    pub url: String,
    /// The branch the repository's rules are merged into, fetched with every validation.
    pub branch: String,
    /// The signature directory, relative to the repository's top: each directory in it is a namespace, as
    /// the ruleset build loads it. `yara` by default, as the core's `ACE4_SIGNATURES_DIR`.
    #[serde(default = "default_signature_dir")]
    pub signature_dir: String,
    /// The SSH private key the mirror fetches with, ace3's `git_repo_*` section's `ssh_key_path`: the name
    /// of a secret in the overlay's `secrets:`, whose value is the key's text. None by default: git then
    /// runs with `ace serve`'s environment. `ace_core::svs::yara::repository` says how git is given it.
    #[serde(default)]
    pub ssh_key: Option<String>,
}

fn default_signature_dir() -> String {
    "yara".to_owned()
}

impl SvsYaraSection {
    /// Refuses values the workers can't run with. Every process that reads the overlay checks it.
    pub fn check(&self) -> Result<(), String> {
        let positive = [
            ("scan_timeout_seconds", self.scan_timeout_seconds),
            ("fetch_timeout_seconds", self.fetch_timeout_seconds),
            ("max_corpus_files", self.max_corpus_files),
            ("max_corpus_bytes", self.max_corpus_bytes),
            ("scan_memory_mb", self.scan_memory_mb),
            ("file_timeout_seconds", self.file_timeout_seconds),
            (
                "heartbeat_interval_seconds",
                self.heartbeat_interval_seconds,
            ),
            ("lease_seconds", self.lease_seconds),
            (
                "max_concurrent_validations",
                u64::from(self.max_concurrent_validations),
            ),
            ("retention_days", u64::from(self.retention_days)),
            ("max_attempts", u64::from(self.max_attempts)),
        ];
        for (key, value) in positive {
            if value == 0 {
                return Err(format!("{key} must be at least 1"));
            }
        }
        for (key, value) in [
            ("max_archive_bytes", self.max_archive_bytes),
            ("max_archive_members", self.max_archive_members),
        ] {
            if value == Some(0) {
                return Err(format!("{key} must be at least 1, or unset for no limit"));
            }
        }
        if !(1..=1000).contains(&self.prune_batch_size) {
            return Err("prune_batch_size must be between 1 and 1000".to_owned());
        }
        if !(self.poll_interval_seconds.is_finite() && self.poll_interval_seconds > 0.0) {
            return Err("poll_interval_seconds must be above 0".to_owned());
        }
        if self.heartbeat_interval_seconds.saturating_mul(3) > self.lease_seconds {
            return Err(format!(
                "heartbeat_interval_seconds ({}) times 3 must not exceed lease_seconds ({}): one late \
                 heartbeat must not lose the lease",
                self.heartbeat_interval_seconds, self.lease_seconds
            ));
        }
        for (name, repository) in &self.repositories {
            check_repository(
                name,
                &repository.url,
                &repository.branch,
                &repository.ssh_key,
            )?;
            let dir = std::path::Path::new(&repository.signature_dir);
            if dir.is_absolute()
                || dir
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(format!(
                    "repository {name}: signature_dir must be relative to the repository's top"
                ));
            }
        }
        Ok(())
    }
}

/// What a disposition says about an alert's detections, ace3's `tp` and `fp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DispositionClass {
    /// They found malicious activity.
    Tp,
    /// They didn't.
    Fp,
}

/// ace3's `disposition_classification:` from its `saq.default.yaml`, the default a site's overlay is
/// merged over: `ace_service`'s `Dispositions`, and the core's SVS reads before `ace serve` hands it the
/// site's.
pub const ACE3_DISPOSITION_CLASSES: &[(&str, DispositionClass)] = &[
    ("FALSE_POSITIVE", DispositionClass::Fp),
    ("GRAYWARE", DispositionClass::Tp),
    ("POLICY_VIOLATION", DispositionClass::Tp),
    ("RECONNAISSANCE", DispositionClass::Tp),
    ("WEAPONIZATION", DispositionClass::Tp),
    ("DELIVERY", DispositionClass::Tp),
    ("EXPLOITATION", DispositionClass::Tp),
    ("INSTALLATION", DispositionClass::Tp),
    ("COMMAND_AND_CONTROL", DispositionClass::Tp),
    ("EXFIL", DispositionClass::Tp),
    ("DAMAGE", DispositionClass::Tp),
    ("SIMULATED", DispositionClass::Tp),
];

/// What the overlay says about one disposition, ace3's `DispositionConfig`. A key left out keeps what the
/// disposition has; a new disposition needs `rank` and `css`, as ace3's schema requires them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DispositionSection {
    /// An event's disposition is its alerts' highest ranked.
    pub rank: Option<i64>,
    /// Its badge's class, any class token, as ace3's is any text. The stylesheet colours Bootstrap's
    /// `primary`, `secondary`, `success`, `danger`, `warning`, `info`, `light` and `dark`.
    pub css: Option<String>,
    /// Whether choosing it offers Save to Event.
    pub show_save_to_event: Option<bool>,
    /// False when only ACE sets the disposition: an analyst can't choose it, or change an alert that has
    /// it, and only ACE grades its alerts' detections.
    pub analyst_selectable: Option<bool>,
}

/// What the overlay says about one action handler.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ActionSection {
    /// What the handler's builder is given, as a module's settings are.
    pub settings: Option<Value>,
    /// The handler's slots, each bound to a connection (`crate::connections`).
    pub connections: BTreeMap<String, String>,
}

/// ace3's `nrd:` section: the feeds the `nrd_refresh` task builds the newly registered domains list
/// from. ace3's `enabled` kill switch is the task's own `scheduler.nrd_refresh.enabled`, and its
/// `database_path` is Postgres.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NrdSection {
    /// The fewest hours between two rebuilds. Once they've passed, each run asks each feed with
    /// HEAD whether it changed, and rebuilds only when one did.
    pub check_interval_hours: u64,
    /// The feeds, in order. None is no list.
    pub url_lists: Vec<NrdList>,
    /// A PEM file of CA certificates to trust besides the platform's. Certificates are always
    /// verified.
    pub ca_certificates: Option<std::path::PathBuf>,
}

impl Default for NrdSection {
    fn default() -> Self {
        NrdSection {
            check_interval_hours: 24,
            url_lists: Vec::new(),
            ca_certificates: None,
        }
    }
}

/// One feed: a text file of domains, one a line, and the URLs to try when its own fails.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NrdList {
    pub url: String,
    #[serde(default)]
    pub backups: Vec<String>,
}

/// What the overlay says about one of the core's scheduled tasks. Each field left out keeps the
/// task's default; `ace_app`'s scheduler lists the tasks and their defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScheduledTaskSection {
    /// A five-field cron expression, in UTC, as ace3's `etc/cron.yaml` schedules its cadences.
    pub schedule: Option<String>,
    /// How long a run may take before it's stopped.
    pub timeout_seconds: Option<u64>,
    /// False stops the task running.
    pub enabled: Option<bool>,
}

/// Where a secret's value comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum SecretSource {
    /// `env:<VARIABLE>`: an environment variable of the process.
    Env(String),
    /// `file:<path>`: a file's contents without its trailing newline, such as a Compose secret
    /// in `/run/secrets`.
    File(std::path::PathBuf),
}

impl TryFrom<String> for SecretSource {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        match text.split_once(':') {
            Some(("env", name)) if !name.is_empty() => Ok(SecretSource::Env(name.to_owned())),
            Some(("file", path)) if !path.is_empty() => Ok(SecretSource::File(path.into())),
            _ => Err(format!(
                "{text:?} is neither env:<VARIABLE> nor file:<path>"
            )),
        }
    }
}

impl std::fmt::Display for SecretSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretSource::Env(name) => write!(f, "env:{name}"),
            SecretSource::File(path) => write!(f, "file:{}", path.display()),
        }
    }
}

/// What the overlay says about one module.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ModuleSection {
    /// The module's settings block, when it runs as itself.
    pub settings: Option<Value>,
    /// Named instances, each a run of the module with its own inputs and settings.
    pub instances: BTreeMap<String, InstanceSection>,
    /// How long, in seconds, the module's results are kept in the analysis cache (ace3's
    /// `cache_ttl`), for the module and each of its instances that doesn't say: 0 keeps none. A
    /// module that can't be cached (`Module::CACHE`) refuses any but 0. Without it, a cacheable
    /// module keeps its results for its own time to live (`Cache::ttl`).
    pub cache_ttl: Option<u64>,
    /// The most results of the module's analysis type a root holds before the core stops queuing
    /// it there (ace3's `automation_limit`, `Module::AUTOMATION_LIMIT`), for the module and each
    /// of its instances that doesn't say. Without it, the module's own.
    pub automation_limit: Option<u32>,
    /// The module's slots (`Module::CONNECTIONS`), each bound to a connection
    /// (`crate::connections`), for the module and each of its instances.
    pub connections: BTreeMap<String, String>,
    /// ace3's `enabled`: false turns the module and every instance of it off, whatever
    /// `Module::ENABLED_BY_DEFAULT` says. Left out, or true, the section turns it on.
    pub enabled: Option<bool>,
}

/// One named instance of a module.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct InstanceSection {
    /// The observable types the instance takes, each one the module takes. None takes the
    /// module's own.
    pub inputs: Option<Vec<ObservableKind>>,
    pub settings: Option<Value>,
    /// The module groups the instance joins, as a site's config adds a section to ace3's
    /// `module_group_*` lists, so the analysis modes that run a group run it. An instance named as
    /// one of ace3's modules is in that module's groups already.
    pub groups: Vec<String>,
    /// The instance's own `cache_ttl`, over its module's (`ModuleSection::cache_ttl`).
    pub cache_ttl: Option<u64>,
    /// The instance's own `automation_limit`, over its module's
    /// (`ModuleSection::automation_limit`).
    pub automation_limit: Option<u32>,
    /// The instance's own bindings, each over its module's for that slot
    /// (`ModuleSection::connections`).
    pub connections: BTreeMap<String, String>,
    /// ace3's `enabled` for this instance: false turns it off.
    pub enabled: Option<bool>,
}

/// An overlay that doesn't load.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OverlayError {
    #[error("the overlay doesn't parse at {path}: {message}")]
    Parse { path: String, message: String },
    #[error("the overlay's {path}: {source}")]
    Settings {
        path: String,
        #[source]
        source: SettingsError,
    },
    #[error("the overlay's instance {instance} of {module} takes {kind}, which {module} doesn't")]
    Input {
        module: String,
        instance: String,
        kind: ObservableKind,
    },
    #[error(
        "the overlay's instance {instance} of {module} has a module's or another instance's name"
    )]
    DuplicateKey { module: String, instance: String },
    #[error("the overlay names instance {0:?}; a name is lowercase letters, digits and _")]
    BadName(String),
    #[error("the overlay's {path}: {source}")]
    Declaration {
        path: String,
        #[source]
        source: crate::manifest::DeclarationError,
    },
    #[error("the overlay {path} can't be read: {message}")]
    Read { path: String, message: String },
    #[error("the overlay's {path}: {message}")]
    Cache { path: String, message: String },
    #[error("the overlay's {path}: {message}")]
    Connection { path: String, message: String },
}

/// What the core queues and a pool runs: a module as itself, or one named instance of it.
#[derive(Debug, Clone)]
pub struct Component {
    /// The name in the queue and the tree: the module's name, or the instance's.
    pub key: String,
    pub manifest: Manifest,
    /// The observable types it takes: the manifest's, or the instance's narrower list.
    pub inputs: Vec<ObservableKind>,
    /// Its settings block. None runs on the settings type's defaults.
    pub settings: Option<Value>,
    /// The module groups an instance joins (`InstanceSection::groups`).
    pub groups: Vec<String>,
    /// What it takes on its settings (`Module::takes`, `crate::takes`).
    pub takes: Takes,
    /// How long its results are kept in the analysis cache (`Module::CACHE`, `cache_ttl`), or None
    /// when they aren't.
    pub cache_ttl: Option<std::time::Duration>,
    /// ace3's `automation_limit` for it: the overlay's, or else its module's
    /// (`Module::AUTOMATION_LIMIT`). None has no limit.
    pub automation_limit: Option<u32>,
    /// Its slots bound to the overlay's connections (`crate::connections`), whose settings are in
    /// `settings` under each slot's name.
    pub connections: Vec<Binding>,
}

impl Component {
    /// The module as itself, on its defaults. A declaration that can't be used
    /// (`Manifest::declaration`) takes everything here; `Overlay::components`, which every
    /// binary's catalog and pools come from, refuses it.
    pub fn of(manifest: Manifest) -> Component {
        Component {
            key: manifest.name.to_owned(),
            manifest,
            inputs: manifest.inputs.to_vec(),
            settings: None,
            groups: Vec::new(),
            takes: manifest.declaration(None).unwrap_or_default(),
            cache_ttl: manifest
                .cache
                .map(|cache| cache.ttl)
                .filter(|ttl| !ttl.is_zero()),
            automation_limit: manifest.automation_limit,
            connections: Vec::new(),
        }
    }

    /// The component on a settings block, with its declaration checked.
    fn with_settings(
        manifest: Manifest,
        key: String,
        settings: Option<Value>,
        path: String,
    ) -> Result<Component, OverlayError> {
        let takes = manifest
            .declaration(settings.as_ref())
            .map_err(|source| OverlayError::Declaration { path, source })?;
        Ok(Component {
            key,
            manifest,
            inputs: manifest.inputs.to_vec(),
            settings,
            groups: Vec::new(),
            takes,
            cache_ttl: manifest
                .cache
                .map(|cache| cache.ttl)
                .filter(|ttl| !ttl.is_zero()),
            automation_limit: manifest.automation_limit,
            connections: Vec::new(),
        })
    }

    /// The component with the overlay's `cache_ttl` for it, refused when the module can't be cached
    /// with it: it doesn't opt in, or its task reads what the key doesn't hold
    /// (`Manifest::cache_refusal`).
    fn with_cache_ttl(mut self, ttl: Option<u64>, path: String) -> Result<Component, OverlayError> {
        let refuse = |message: String| OverlayError::Cache {
            path: path.clone(),
            message,
        };
        match (ttl, self.manifest.cache) {
            (Some(0), _) => self.cache_ttl = None,
            (Some(_), None) => {
                return Err(refuse(format!(
                    "{} doesn't opt into the analysis cache (Module::CACHE), so its cache_ttl is 0 \
                     or nothing",
                    self.manifest.name
                )));
            }
            (Some(seconds), Some(_)) => {
                self.cache_ttl = Some(std::time::Duration::from_secs(seconds));
            }
            // a module ace3 can cache but doesn't by default keeps none until the overlay says
            (None, cache) => {
                self.cache_ttl = cache.map(|cache| cache.ttl).filter(|ttl| !ttl.is_zero());
            }
        }
        if self.cache_ttl.is_some()
            && let Some(why) = self.manifest.cache_refusal()
        {
            return Err(refuse(why));
        }
        Ok(self)
    }

    /// The component with the overlay's `automation_limit` for it, if it gives one.
    fn with_automation_limit(mut self, limit: Option<u32>) -> Component {
        if limit.is_some() {
            self.automation_limit = limit;
        }
        self
    }

    /// True when it takes observables of `kind`, directly or through a parent type.
    pub fn accepts(&self, kind: ObservableKind) -> bool {
        self.inputs.iter().any(|&input| kind.is_subtype_of(input))
    }

    /// Its own settings block, without its connections' settings: what of its settings a cached
    /// result's key holds, beside each connection's identity (`crate::cache::KeyParts`).
    pub fn own_settings(&self) -> Option<Value> {
        if self.connections.is_empty() {
            return self.settings.clone();
        }
        let mut block = self.settings.clone()?;
        if let Some(object) = block.as_object_mut() {
            for binding in &self.connections {
                object.remove(&binding.slot);
            }
            if object.is_empty() {
                return None;
            }
        }
        Some(block)
    }

    /// Each bound slot's connection type and identity, by slot, for a cached result's key.
    pub fn connection_identities(&self) -> BTreeMap<String, Value> {
        self.connections
            .iter()
            .map(|binding| {
                (
                    binding.slot.clone(),
                    serde_json::json!({"type": binding.kind, "identity": binding.identity}),
                )
            })
            .collect()
    }

    /// The instance's name, when this is a named instance.
    pub fn instance(&self) -> Option<&str> {
        (self.key != self.manifest.name).then_some(self.key.as_str())
    }
}

impl Overlay {
    /// Parses an overlay. An empty file is an overlay with no sections. A key written twice in one
    /// mapping is refused, where reading straight into JSON would keep the last silently.
    pub fn from_yaml(text: &str) -> Result<Overlay, OverlayError> {
        let parse_error = |path: String, message: String| OverlayError::Parse { path, message };
        let yaml = serde_norway::from_str::<serde_norway::Value>(text)
            .map_err(|e| parse_error(String::new(), e.to_string()))?;
        // JSON's map forgets the order, so the dispositions' is read here
        let disposition_order = yaml
            .get("dispositions")
            .and_then(serde_norway::Value::as_mapping)
            .map(|mapping| {
                mapping
                    .keys()
                    .filter_map(|key| key.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let value: Value =
            serde_norway::from_str(text).map_err(|e| parse_error(String::new(), e.to_string()))?;
        if value.is_null() {
            return Ok(Overlay::default());
        }
        let mut overlay: Overlay = serde_path_to_error::deserialize(value).map_err(|e| {
            let path = e.path().to_string();
            parse_error(path, e.into_inner().to_string())
        })?;
        overlay.disposition_order = disposition_order;
        crate::exclusions::Exclusions::from_section(&overlay.observable_exclusions)
            .map_err(|(path, message)| parse_error(path, message))?;
        overlay
            .svs
            .check()
            .map_err(|(path, message)| parse_error(path, message))?;
        // a repository's ssh_key is a secret's name, and a name with no source is a mistake in this file
        let yara = overlay
            .svs
            .yara
            .repositories
            .iter()
            .map(|(name, r)| ("yara", name, &r.ssh_key));
        let catalog = overlay
            .svs
            .catalog
            .repositories
            .iter()
            .map(|(name, r)| ("catalog", name, &r.ssh_key));
        // and so is a backend's secret
        for (name, backend) in &overlay.ai_api.backends {
            if let Some(secret) = backend
                .secrets
                .iter()
                .find(|secret| !overlay.secrets.contains_key(*secret))
            {
                return Err(parse_error(
                    format!("ai_api.backends.{name}.secrets"),
                    format!("{secret:?} isn't a secret in secrets:"),
                ));
            }
        }
        for (section, name, ssh_key) in yara.chain(catalog) {
            if let Some(secret) = ssh_key
                && !overlay.secrets.contains_key(secret)
            {
                return Err(parse_error(
                    format!("svs.{section}.repositories.{name}.ssh_key"),
                    format!("{secret:?} isn't a secret in secrets:"),
                ));
            }
        }
        overlay.check_connection_names()?;
        Ok(overlay)
    }

    /// Refuses a connection with a bad name or a secret `secrets:` hasn't, and a `connections:` that
    /// binds a slot to a connection there isn't. What a connection's type is and whether a slot is
    /// one its component has are checked by what reads them (`bind`, `check_connections`).
    fn check_connection_names(&self) -> Result<(), OverlayError> {
        let refuse = |path: String, message: String| OverlayError::Connection { path, message };
        for (name, connection) in &self.connections {
            if !crate::connections::is_connection_name(name) {
                return Err(refuse(
                    format!("connections.{name}"),
                    "a connection's name is lowercase letters, digits and _".to_owned(),
                ));
            }
            for (role, secret) in &connection.secrets {
                if !self.secrets.contains_key(secret) {
                    return Err(refuse(
                        format!("connections.{name}.secrets.{role}"),
                        format!("{secret:?} isn't a secret in secrets:"),
                    ));
                }
            }
        }
        let mut uses: Vec<(String, &BTreeMap<String, String>)> = Vec::new();
        for (module, section) in &self.modules {
            uses.push((
                format!("modules.{module}.connections"),
                &section.connections,
            ));
            for (instance, entry) in &section.instances {
                uses.push((
                    format!("modules.{module}.instances.{instance}.connections"),
                    &entry.connections,
                ));
            }
        }
        for (entry, section) in &self.actions {
            uses.push((format!("actions.{entry}.connections"), &section.connections));
        }
        for (name, section) in &self.collectors {
            uses.push((
                format!("collectors.{name}.connections"),
                &section.connections,
            ));
        }
        for (name, section) in &self.ai_api.backends {
            uses.push((
                format!("ai_api.backends.{name}.connections"),
                &section.connections,
            ));
        }
        for (name, section) in &self.command_types {
            uses.push((
                format!("command_types.{name}.connections"),
                &section.connections,
            ));
        }
        for (path, bindings) in uses {
            for (slot, connection) in bindings {
                if !self.connections.contains_key(connection) {
                    return Err(refuse(
                        format!("{path}.{slot}"),
                        format!("{connection:?} isn't a connection in connections:"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The bindings of a component's `connections:` (`uses`, at `path`) to its `slots`, each
    /// checked: a slot the component has, bound to a connection of the slot's type whose settings
    /// and secrets that type takes.
    pub fn bind(
        &self,
        path: &str,
        slots: &[ConnectionSlot],
        uses: &BTreeMap<String, String>,
    ) -> Result<Vec<Binding>, OverlayError> {
        let refuse = |path: String, message: String| OverlayError::Connection { path, message };
        let mut bindings = Vec::new();
        for (slot_name, name) in uses {
            let Some(slot) = slots.iter().find(|slot| slot.name == slot_name) else {
                let names: Vec<&str> = slots.iter().map(|slot| slot.name).collect();
                return Err(refuse(
                    format!("{path}.{slot_name}"),
                    if names.is_empty() {
                        "this takes no connection".to_owned()
                    } else {
                        format!("this has no slot {slot_name:?}; its slots are {names:?}")
                    },
                ));
            };
            let Some(section) = self.connections.get(name) else {
                return Err(refuse(
                    format!("{path}.{slot_name}"),
                    format!("{name:?} isn't a connection in connections:"),
                ));
            };
            let identity = crate::connections::check_section(name, section, &slot.kind).map_err(
                |(at, message)| refuse(at, format!("{message} (bound at {path}.{slot_name})")),
            )?;
            bindings.push(Binding {
                slot: slot.name.to_owned(),
                connection: name.clone(),
                kind: slot.kind.name,
                settings: section.settings.clone(),
                identity,
                secrets: section.secrets.clone(),
            });
        }
        Ok(bindings)
    }

    /// Checks every connection against its type among `kinds`, the types the binary's components
    /// take: a connection of a type none of them takes, or whose settings or secrets its type
    /// refuses, is an error. `ace` checks this before any command runs.
    pub fn check_connections(&self, kinds: &[ConnectionKind]) -> Result<(), OverlayError> {
        for (name, section) in &self.connections {
            let Some(kind) = kinds.iter().find(|kind| kind.name == section.kind) else {
                let mut names: Vec<&str> = kinds.iter().map(|kind| kind.name).collect();
                names.sort_unstable();
                names.dedup();
                return Err(OverlayError::Connection {
                    path: format!("connections.{name}.type"),
                    message: format!(
                        "no component of this binary takes a connection of type {:?} (the types are {names:?})",
                        section.kind
                    ),
                });
            };
            crate::connections::check_section(name, section, kind)
                .map_err(|(path, message)| OverlayError::Connection { path, message })?;
        }
        Ok(())
    }

    /// The sections `text` writes, by name, each as it is written. For a process that has to know
    /// what its overlay holds beyond what it reads of it: `ace serve-ai` takes an overlay with its own
    /// sections and no other (PLAN.md 7.15). An empty file has none.
    pub fn sections(text: &str) -> Result<BTreeMap<String, Value>, OverlayError> {
        let value: Value = serde_norway::from_str(text).map_err(|e| OverlayError::Parse {
            path: String::new(),
            message: e.to_string(),
        })?;
        match value {
            Value::Null => Ok(BTreeMap::new()),
            Value::Object(sections) => Ok(sections.into_iter().collect()),
            _ => Err(OverlayError::Parse {
                path: String::new(),
                message: "the overlay isn't a mapping of sections".to_owned(),
            }),
        }
    }

    /// Reads and parses the overlay at `path`.
    pub fn read(path: &std::path::Path) -> Result<Overlay, OverlayError> {
        let text = std::fs::read_to_string(path).map_err(|e| OverlayError::Read {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        Overlay::from_yaml(&text)
    }

    /// The overlay without the sections of modules not in `manifests`. A pool's binary links
    /// only its own modules, so it reads the site's overlay through this: the other pools'
    /// sections aren't removed modules, and the core, which knows every module, warns about the
    /// ones that are.
    pub fn for_pool(&self, manifests: &[Manifest]) -> Overlay {
        Overlay {
            modules: self
                .modules
                .iter()
                .filter(|(name, _)| manifests.iter().any(|m| m.name == name.as_str()))
                .map(|(name, section)| (name.clone(), section.clone()))
                .collect(),
            secrets: self.secrets.clone(),
            scheduler: BTreeMap::new(),
            nrd: NrdSection::default(),
            hooks: crate::hooks::HooksSection::default(),
            actions: self.actions.clone(),
            disposition_classification: BTreeMap::new(),
            dispositions: BTreeMap::new(),
            disposition_order: Vec::new(),
            svs: SvsSection::default(),
            alert_routers: BTreeMap::new(),
            yara_export: YaraExportSection::default(),
            // a pool serves no API, and reads no backend's secret
            ai_api: AiApiSection::default(),
            // the core decides what is queued
            observable_exclusions: BTreeMap::new(),
            // the core looks results up and keeps them
            analysis_cache: AnalysisCacheSection::default(),
            // a collector is a process of the `ace` binary, never a pool's
            collectors: BTreeMap::new(),
            // what its modules and handlers bind is checked when it builds them
            connections: self.connections.clone(),
            // the hunter and `ace serve` build the command types
            command_types: BTreeMap::new(),
        }
    }

    /// The components the overlay makes of `manifests`, the modules this build has, with each
    /// settings block checked against its module's settings type. A section for a module not in
    /// `manifests` logs a warning and is skipped.
    pub fn components(&self, manifests: &[Manifest]) -> Result<Vec<Component>, OverlayError> {
        for name in self.modules.keys() {
            if !manifests.iter().any(|m| m.name == name) {
                tracing::warn!(
                    module = %name,
                    "the overlay has a section for a module this build doesn't have; skipping it"
                );
            }
        }
        let mut components = Vec::new();
        for &manifest in manifests {
            let section = self.modules.get(manifest.name);
            if manifest.instances_only && section.is_none_or(|s| s.instances.is_empty()) {
                if section.is_some_and(|s| s.settings.is_some()) {
                    return Err(OverlayError::Parse {
                        path: format!("modules.{}.settings", manifest.name),
                        message: "this module runs only as named instances, each with its own \
                                  settings"
                            .into(),
                    });
                }
                tracing::info!(
                    module = manifest.name,
                    "the overlay names no instance of this module, so it doesn't run"
                );
                continue;
            }
            if section.is_some_and(|s| s.enabled == Some(false)) {
                tracing::info!(
                    module = manifest.name,
                    "the overlay turns this module off (enabled: false), so it doesn't run"
                );
                continue;
            }
            let Some(section) = section else {
                if manifest.enabled_by_default && !manifest.connections.is_empty() {
                    tracing::warn!(
                        module = manifest.name,
                        "the overlay binds none of this module's connections, so it runs without them"
                    );
                }
                if manifest.enabled_by_default {
                    components.push(
                        Component::with_settings(
                            manifest,
                            manifest.name.to_owned(),
                            None,
                            format!("modules.{}", manifest.name),
                        )?
                        .with_cache_ttl(None, format!("modules.{}", manifest.name))?,
                    );
                } else {
                    tracing::info!(
                        module = manifest.name,
                        "this module is off unless the overlay has a section for it, and it has none"
                    );
                }
                continue;
            };
            let check = |path: String, block: Option<&Value>| {
                manifest
                    .check_settings(block)
                    .map_err(|source| OverlayError::Settings { path, source })
            };
            if section.instances.is_empty() {
                let path = format!("modules.{}.settings", manifest.name);
                let bindings = self.bind(
                    &format!("modules.{}.connections", manifest.name),
                    manifest.connections,
                    &section.connections,
                )?;
                let settings = with_connections(
                    &path,
                    section.settings.clone(),
                    manifest.connections,
                    &bindings,
                )?;
                check(path.clone(), settings.as_ref())?;
                components.push(
                    Component {
                        connections: bindings,
                        ..Component::with_settings(
                            manifest,
                            manifest.name.to_owned(),
                            settings,
                            path,
                        )?
                    }
                    .with_cache_ttl(
                        section.cache_ttl,
                        format!("modules.{}.cache_ttl", manifest.name),
                    )?
                    .with_automation_limit(section.automation_limit),
                );
                continue;
            }
            if section.settings.is_some() {
                return Err(OverlayError::Parse {
                    path: format!("modules.{}.settings", manifest.name),
                    message: "a module with instances takes its settings in each instance".into(),
                });
            }
            for (name, instance) in &section.instances {
                if instance.enabled == Some(false) {
                    tracing::info!(
                        module = manifest.name,
                        instance = %name,
                        "the overlay turns this instance off (enabled: false), so it doesn't run"
                    );
                    continue;
                }
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                {
                    return Err(OverlayError::BadName(name.clone()));
                }
                let path = format!("modules.{}.instances.{name}.settings", manifest.name);
                let mut uses = section.connections.clone();
                uses.extend(instance.connections.clone());
                let bindings = self.bind(
                    &format!("modules.{}.instances.{name}.connections", manifest.name),
                    manifest.connections,
                    &uses,
                )?;
                let settings = with_connections(
                    &path,
                    instance.settings.clone(),
                    manifest.connections,
                    &bindings,
                )?;
                check(path.clone(), settings.as_ref())?;
                let inputs = match &instance.inputs {
                    None => manifest.inputs.to_vec(),
                    Some(inputs) => {
                        if let Some(&kind) = inputs.iter().find(|&&k| !manifest.accepts(k)) {
                            return Err(OverlayError::Input {
                                module: manifest.name.to_owned(),
                                instance: name.clone(),
                                kind,
                            });
                        }
                        inputs.clone()
                    }
                };
                components.push(
                    Component {
                        inputs,
                        groups: instance.groups.clone(),
                        connections: bindings,
                        ..Component::with_settings(manifest, name.clone(), settings, path)?
                    }
                    .with_cache_ttl(
                        instance.cache_ttl.or(section.cache_ttl),
                        format!("modules.{}.instances.{name}.cache_ttl", manifest.name),
                    )?
                    .with_automation_limit(instance.automation_limit.or(section.automation_limit)),
                );
            }
        }
        // an instance named like a module, or like another module's instance, would share its
        // tasks and results
        let mut seen = std::collections::BTreeSet::new();
        for component in &components {
            let clashes_with_module =
                component.instance().is_some() && manifests.iter().any(|m| m.name == component.key);
            if clashes_with_module || !seen.insert(component.key.as_str()) {
                return Err(OverlayError::DuplicateKey {
                    module: component.manifest.name.to_owned(),
                    instance: component.key.clone(),
                });
            }
        }
        Ok(components)
    }
}

/// A module's own settings block with each binding's settings under its slot's key. Its own block
/// sets no slot's key, bound or not: a slot's settings come only from a connection.
fn with_connections(
    path: &str,
    block: Option<Value>,
    slots: &[ConnectionSlot],
    bindings: &[Binding],
) -> Result<Option<Value>, OverlayError> {
    if let Some(Value::Object(object)) = &block
        && let Some(slot) = slots.iter().find(|slot| object.contains_key(slot.name))
    {
        return Err(OverlayError::Connection {
            path: format!("{path}.{}", slot.name),
            message: format!(
                "the settings of the slot {} come from the connection its connections: binds, not \
                 from the module's settings",
                slot.name
            ),
        });
    }
    if bindings.is_empty() {
        return Ok(block);
    }
    let mut block = match block {
        None | Some(Value::Null) => serde_json::Map::new(),
        Some(Value::Object(object)) => object,
        Some(_) => {
            return Err(OverlayError::Connection {
                path: path.to_owned(),
                message: "a module that takes a connection has a mapping of settings".to_owned(),
            });
        }
    };
    for binding in bindings {
        block.insert(
            binding.slot.clone(),
            binding
                .settings
                .clone()
                .filter(|settings| !settings.is_null())
                .unwrap_or_else(|| Value::Object(serde_json::Map::new())),
        );
    }
    Ok(Some(Value::Object(block)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::example::{LineCounter, Resolver};
    use std::sync::{Arc, Mutex};

    const LINE_COUNTER: Manifest = Manifest::parser::<LineCounter>();
    const RESOLVER: Manifest = Manifest::lookup::<Resolver>();

    fn manifests() -> Vec<Manifest> {
        vec![LINE_COUNTER, RESOLVER]
    }

    fn components(yaml: &str) -> Result<Vec<Component>, OverlayError> {
        Overlay::from_yaml(yaml)?.components(&manifests())
    }

    fn keys(components: &[Component]) -> Vec<&str> {
        components.iter().map(|c| c.key.as_str()).collect()
    }

    /// A cacheable module keeps its results for its own time to live unless its section's `cache_ttl`
    /// says another, or 0 for none; a module that doesn't opt in refuses one; and one whose task reads
    /// what the key doesn't hold is refused whatever its section says, but when it is 0 (PLAN.md
    /// decision 26).
    #[test]
    fn automation_limit_is_the_module_s_unless_the_overlay_says_otherwise() {
        let mut limited = LINE_COUNTER;
        limited.automation_limit = Some(15);
        let limits = |yaml: &str| -> Vec<Option<u32>> {
            Overlay::from_yaml(yaml)
                .expect("parses")
                .components(&[limited, RESOLVER])
                .expect("loads")
                .iter()
                .map(|c| c.automation_limit)
                .collect()
        };
        assert_eq!(limits(""), [Some(15), None]);
        assert_eq!(
            limits(
                "modules: {example_line_counter: {automation_limit: 5}, example_resolver: {automation_limit: 1}}"
            ),
            [Some(5), Some(1)]
        );
        // an instance takes its module's unless it says its own
        assert_eq!(
            limits(
                "modules: {example_line_counter: {automation_limit: 5, instances: {a: {}, b: {automation_limit: 2}}}}"
            ),
            [Some(5), Some(2), None]
        );
        // it's no setting, so a cached result's key doesn't hold it
        let component =
            &Overlay::from_yaml("modules: {example_line_counter: {automation_limit: 5}}")
                .expect("parses")
                .components(&[limited])
                .expect("loads")[0];
        assert_eq!(component.settings, None);
    }

    #[test]
    fn cache_ttl_is_the_module_s_unless_the_overlay_says_otherwise() {
        use crate::cache::Cache;
        use std::time::Duration;
        let mut cached = LINE_COUNTER;
        cached.cache = Some(Cache::new(1, Duration::from_secs(600)));
        let ttl = |yaml: &str, manifests: &[Manifest]| -> Result<Vec<Option<u64>>, OverlayError> {
            Ok(Overlay::from_yaml(yaml)?
                .components(manifests)?
                .iter()
                .map(|c| c.cache_ttl.map(|t| t.as_secs()))
                .collect())
        };
        let both = [cached, RESOLVER];
        assert_eq!(ttl("", &both), Ok(vec![Some(600), None]));
        assert_eq!(
            ttl("modules: {example_line_counter: {cache_ttl: 60}}", &both),
            Ok(vec![Some(60), None])
        );
        assert_eq!(
            ttl("modules: {example_line_counter: {cache_ttl: 0}}", &both),
            Ok(vec![None, None])
        );
        // an instance takes its module's unless it says its own
        assert_eq!(
            ttl(
                "modules: {example_line_counter: {cache_ttl: 60, instances: {a: {}, b: {cache_ttl: 5}}}}",
                &both
            ),
            Ok(vec![Some(60), Some(5), None])
        );
        let refused = ttl("modules: {example_resolver: {cache_ttl: 60}}", &both).unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("doesn't opt into the analysis cache"),
            "{refused}"
        );
        assert_eq!(
            ttl("modules: {example_resolver: {cache_ttl: 0}}", &both),
            Ok(vec![Some(600), None])
        );
        // a cacheable module that walks its tree can't be cached, unless the overlay keeps none
        let mut walks = cached;
        walks.reads_tree = true;
        let refused = ttl("", &[walks]).unwrap_err();
        assert!(refused.to_string().contains("READS_TREE"), "{refused}");
        assert_eq!(
            ttl("modules: {example_line_counter: {cache_ttl: 0}}", &[walks]),
            Ok(vec![None])
        );
        // a module ace3 can cache but doesn't by default keeps nothing until its section says
        let mut off = cached;
        off.cache = Some(Cache::new(1, Duration::ZERO));
        assert_eq!(ttl("", &[off]), Ok(vec![None]));
        assert_eq!(
            ttl("modules: {example_line_counter: {cache_ttl: 90}}", &[off]),
            Ok(vec![Some(90)])
        );
        // the switch and the retention, ace3's defaults
        let overlay = Overlay::from_yaml("analysis_cache: {enabled: false}").expect("loads");
        assert!(!overlay.analysis_cache.enabled);
        assert_eq!(overlay.analysis_cache.retention_days, 35);
        assert!(Overlay::from_yaml("analysis_cache: {enable: false}").is_err());
    }

    /// A collector's section (PLAN.md 6.1): its settings and its four numbers, each key refused when
    /// unknown.
    #[test]
    fn a_collector_s_section_reads() {
        let overlay = Overlay::from_yaml(
            "collectors: {journal: {settings: {queue: q}, key_lifetime_seconds: 60, poll_seconds: 2, \
             submit_attempts: 3, stop_seconds: 10}}",
        )
        .expect("loads");
        assert_eq!(
            overlay.collectors["journal"],
            CollectorSection {
                settings: Some(serde_json::json!({"queue": "q"})),
                key_lifetime_seconds: Some(60),
                poll_seconds: Some(2),
                submit_attempts: Some(3),
                stop_seconds: Some(10),
                connections: BTreeMap::new(),
            }
        );
        assert!(Overlay::from_yaml("collectors: {journal: {poll: 2}}").is_err());
    }

    #[test]
    fn an_unknown_key_fails_at_every_level() {
        let cases = [
            ("modul: {}", "modul", "unknown field `modul`"),
            (
                "modules: {example_resolver: {setings: {}}}",
                "modules.example_resolver.setings",
                "unknown field `setings`",
            ),
            (
                "modules: {example_resolver: {instances: {a: {input: [fqdn]}}}}",
                "modules.example_resolver.instances.a.input",
                "unknown field `input`",
            ),
        ];
        for (yaml, path, message) in cases {
            let err = components(yaml).unwrap_err();
            println!("{err}");
            match err {
                OverlayError::Parse {
                    path: got,
                    message: said,
                } => {
                    assert_eq!(got, path, "{yaml}");
                    assert!(said.starts_with(message), "{yaml}: {said}");
                }
                other => panic!("{yaml}: {other}"),
            }
        }
        // inside a settings block, the module's settings type refuses it
        let err =
            components("modules: {example_line_counter: {settings: {max_byte: 3}}}").unwrap_err();
        println!("{err}");
        assert_eq!(
            err,
            OverlayError::Settings {
                path: "modules.example_line_counter.settings".to_owned(),
                source: SettingsError::UnknownKey {
                    path: "max_byte".to_owned()
                },
            }
        );
        let err = components(
            "modules: {example_resolver: {instances: {a: {settings: {delays: 1, delay: 2}}}}}",
        )
        .unwrap_err();
        assert!(
            matches!(&err, OverlayError::Settings { path, source: SettingsError::UnknownKey { path: key } }
                if path == "modules.example_resolver.instances.a.settings" && key == "delay"),
            "{err}"
        );
    }

    /// The disposition sections parse as ace3 writes them, and refuse a key or class they don't know, and
    /// a disposition named twice, which could otherwise be both TP and FP.
    #[test]
    fn the_disposition_sections_refuse_what_they_dont_know() {
        let overlay = Overlay::from_yaml(
            "disposition_classification: {REVIEWED: fp, SIMULATED: tp}\n\
             dispositions: {SIMULATED: {analyst_selectable: true}, DELIVERY: {}}",
        )
        .expect("parses");
        assert_eq!(
            overlay.disposition_classification,
            BTreeMap::from([
                ("REVIEWED".to_owned(), DispositionClass::Fp),
                ("SIMULATED".to_owned(), DispositionClass::Tp),
            ])
        );
        assert_eq!(
            overlay.dispositions["SIMULATED"].analyst_selectable,
            Some(true)
        );
        assert_eq!(overlay.dispositions["DELIVERY"].analyst_selectable, None);
        // the file's order, which JSON's map would lose
        let overlay = Overlay::from_yaml(
            "dispositions:\n  ZULU: {rank: 1, css: info}\n  ALPHA: {rank: 2, css: dark}\n  OPEN: {}\n",
        )
        .expect("parses");
        assert_eq!(overlay.disposition_order, ["ZULU", "ALPHA", "OPEN"]);
        assert_eq!(overlay.dispositions["ZULU"].rank, Some(1));
        assert_eq!(overlay.dispositions["ALPHA"].css.as_deref(), Some("dark"));
        for (yaml, path, message) in [
            (
                "disposition_classification: {REVIEWED: benign}",
                "disposition_classification.REVIEWED",
                "unknown variant `benign`",
            ),
            (
                "dispositions: {SIMULATED: {colour: info}}",
                "dispositions.SIMULATED.colour",
                "unknown field `colour`",
            ),
            (
                "dispositions: {DELIVERY: null}",
                "dispositions.DELIVERY",
                "invalid type: null",
            ),
            (
                "dispositions: {DELIVERY: {rank: high}}",
                "dispositions.DELIVERY.rank",
                "invalid type",
            ),
            (
                "disposition_classifications: {REVIEWED: fp}",
                "disposition_classifications",
                "unknown field",
            ),
            (
                "disposition_classification:\n  REVIEWED: tp\n  REVIEWED: fp\n",
                "",
                "duplicate entry with key \"REVIEWED\"",
            ),
            (
                "modules:\n  example_resolver: {}\n  example_resolver: {settings: {}}\n",
                "",
                "duplicate entry with key \"example_resolver\"",
            ),
        ] {
            match Overlay::from_yaml(yaml) {
                Err(OverlayError::Parse {
                    path: got,
                    message: said,
                }) => {
                    assert_eq!(got, path, "{yaml}: {said}");
                    assert!(said.contains(message), "{yaml}: {said}");
                }
                other => panic!("{yaml}: {other:?}"),
            }
        }
    }

    /// ace3's `observable_exclusions:`: entries by name over ace3's, null dropping one, and a spec that
    /// isn't `<type>:<value>` refused when the file loads.
    #[test]
    fn observable_exclusions_merge_over_ace3_s_and_refuse_a_bad_spec() {
        let overlay = Overlay::from_yaml(
            "observable_exclusions:\n  exclude_google: null\n  mine: \"fqdn:example.com\"\n",
        )
        .expect("parses");
        let exclusions =
            crate::exclusions::Exclusions::from_section(&overlay.observable_exclusions)
                .expect("reads");
        assert!(exclusions.excludes("fqdn", "example.com"));
        assert!(exclusions.excludes("fqdn", "youtube.com"));
        assert!(!exclusions.excludes("fqdn", "google.com"));
        assert!(overlay.for_pool(&[]).observable_exclusions.is_empty());
        match Overlay::from_yaml("observable_exclusions: {mine: example.com}") {
            Err(OverlayError::Parse { path, message }) => {
                assert_eq!(path, "observable_exclusions.mine");
                assert!(message.contains("<type>:<value>"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_module_with_no_section_runs_on_its_defaults() {
        for yaml in ["", "# nothing yet\n", "modules: {}"] {
            let components = components(yaml).expect("loads");
            assert_eq!(
                keys(&components),
                ["example_line_counter", "example_resolver"]
            );
            assert!(components.iter().all(|c| c.settings.is_none()));
            assert!(components.iter().all(|c| c.instance().is_none()));
            assert_eq!(components[1].inputs, RESOLVER.inputs);
        }
        // a section for one module leaves the other on its defaults
        let components = components("modules: {example_line_counter: {settings: {max_bytes: 5}}}")
            .expect("loads");
        assert_eq!(
            components[0].settings,
            Some(serde_json::json!({"max_bytes": 5}))
        );
        assert_eq!(components[1].settings, None);
    }

    /// Collects what tracing writes, for the warning tests.
    #[derive(Clone, Default)]
    struct Logs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Logs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_removed_module_logs_a_warning_and_the_rest_loads() {
        let logs = Logs::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let loaded = tracing::subscriber::with_default(subscriber, || {
            components(
                "modules:\n  pdf_parser_v1: {settings: {anything: 1}}\n  example_line_counter: {settings: {max_bytes: 5}}\n",
            )
        })
        .expect("startup continues");
        let logs = String::from_utf8(logs.0.lock().expect("lock").clone()).expect("text");
        println!("{logs}");
        assert_eq!(keys(&loaded), ["example_line_counter", "example_resolver"]);
        assert!(logs.contains("WARN"), "{logs}");
        assert!(logs.contains("module=pdf_parser_v1"), "{logs}");
        assert!(logs.contains("doesn't have"), "{logs}");
    }

    /// A module that needs a site's settings to do anything, as the Splunk module needs its
    /// query, runs only as named instances: with none, it isn't a component at all.
    #[test]
    fn an_instances_only_module_runs_only_as_its_instances() {
        let mut resolver = RESOLVER;
        resolver.instances_only = true;
        let manifests = [LINE_COUNTER, resolver];
        let of = |yaml: &str| Overlay::from_yaml(yaml).and_then(|o| o.components(&manifests));
        assert_eq!(keys(&of("").expect("loads")), ["example_line_counter"]);
        assert_eq!(
            keys(&of("modules: {example_resolver: {instances: {a: {}}}}").expect("loads")),
            ["example_line_counter", "a"]
        );
        let err = of("modules: {example_resolver: {settings: {delays: 1}}}").unwrap_err();
        assert!(err.to_string().contains("only as named instances"), "{err}");
    }

    /// ace3's `enabled: false` (PLAN.md decision 33) turns off a module that is on by default, with
    /// its settings and bindings unread, and one instance of a module; `enabled: true` turns on one
    /// that is off by default, as an empty section does.
    #[test]
    fn enabled_false_turns_a_module_or_an_instance_off() {
        let mut resolver = RESOLVER;
        resolver.enabled_by_default = false;
        let manifests = [LINE_COUNTER, resolver];
        let of = |yaml: &str| Overlay::from_yaml(yaml).and_then(|o| o.components(&manifests));
        assert!(
            keys(
                &of("modules: {example_line_counter: {enabled: false, settings: {nope: 1}}}")
                    .expect("loads")
            )
            .is_empty(),
            "off, its settings aren't checked"
        );
        assert_eq!(
            keys(&of("modules: {example_line_counter: {enabled: true}}").expect("loads")),
            ["example_line_counter"]
        );
        assert_eq!(
            keys(&of("modules: {example_resolver: {enabled: true}}").expect("loads")),
            ["example_line_counter", "example_resolver"]
        );
        assert_eq!(
            keys(&of("modules: {example_resolver: {enabled: false}}").expect("loads")),
            ["example_line_counter"]
        );
        assert!(of("modules: {example_line_counter: {enabled: maybe}}").is_err());
        let instances = of(
            "modules: {example_line_counter: {instances: {a: {}, b: {enabled: false, settings: {nope: 1}}}}}",
        )
        .expect("loads");
        assert_eq!(instances.len(), 1, "{:?}", keys(&instances));
        assert!(
            of("modules: {example_line_counter: {enabled: false, instances: {a: {}}}}")
                .expect("loads")
                .is_empty(),
            "a module turned off takes its instances with it"
        );
    }

    /// A module ace3 ships disabled runs only when the overlay has a section for it, empty or not,
    /// as an ace3 site turns one on with `enabled: true`.
    #[test]
    fn a_module_off_by_default_runs_only_with_a_section() {
        let mut resolver = RESOLVER;
        resolver.enabled_by_default = false;
        let manifests = [LINE_COUNTER, resolver];
        let of = |yaml: &str| Overlay::from_yaml(yaml).and_then(|o| o.components(&manifests));
        assert_eq!(keys(&of("").expect("loads")), ["example_line_counter"]);
        assert_eq!(
            keys(&of("modules: {example_resolver: {}}").expect("loads")),
            ["example_line_counter", "example_resolver"]
        );
        let set = of("modules: {example_resolver: {settings: {delays: 1}}}").expect("loads");
        assert_eq!(set[1].settings, Some(serde_json::json!({"delays": 1})));
    }

    /// An instance can join module groups, as a site's config lists a section in ace3's groups.
    #[test]
    fn an_instance_carries_the_groups_it_joins() {
        let components = components(
            "modules:\n  example_resolver:\n    instances:\n      proxy:\n        groups: [correlation]\n      plain: {}\n",
        )
        .expect("loads");
        let groups: Vec<(&str, Vec<String>)> = components
            .iter()
            .map(|c| (c.key.as_str(), c.groups.clone()))
            .collect();
        assert_eq!(
            groups,
            [
                ("example_line_counter", vec![]),
                ("plain", vec![]),
                ("proxy", vec!["correlation".to_owned()])
            ]
        );
    }

    #[test]
    fn instances_are_components_with_their_own_inputs_and_settings() {
        let components = components(
            "modules:\n  example_resolver:\n    instances:\n      dkim_domains:\n        inputs: [email_dkim_signing_domain]\n        settings: {delays: 1}\n      all_domains: {}\n",
        )
        .expect("loads");
        assert_eq!(
            keys(&components),
            ["example_line_counter", "all_domains", "dkim_domains"]
        );
        let dkim = &components[2];
        assert_eq!(dkim.instance(), Some("dkim_domains"));
        assert_eq!(dkim.manifest.name, "example_resolver");
        assert!(dkim.accepts(ObservableKind::EmailDkimSigningDomain));
        assert!(!dkim.accepts(ObservableKind::Fqdn));
        assert_eq!(dkim.settings, Some(serde_json::json!({"delays": 1})));
        assert!(components[1].accepts(ObservableKind::Fqdn));

        // an instance can't take what its module doesn't, or reuse a key
        let err = super::tests::components(
            "modules: {example_resolver: {instances: {a: {inputs: [file]}}}}",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                OverlayError::Input { kind, .. } if kind == ObservableKind::File
            ),
            "{err}"
        );
        let err = super::tests::components(
            "modules: {example_resolver: {instances: {example_line_counter: {}}}}",
        )
        .unwrap_err();
        assert!(matches!(err, OverlayError::DuplicateKey { .. }), "{err}");
        let err =
            super::tests::components("modules: {example_resolver: {instances: {Bad-Name: {}}}}")
                .unwrap_err();
        assert!(matches!(err, OverlayError::BadName(_)), "{err}");
    }

    /// Batch 4's keys of `svs:` (PLAN.md 7.10): the defaults are ace3's, an unknown key is refused as ace3's
    /// schema refuses one, and so are values the catalog and a run's windows can't use.
    #[test]
    fn the_svs_catalog_and_runs_keys_are_checked() {
        let svs = Overlay::from_yaml("").expect("parses").svs;
        assert_eq!(svs.attack_release, "v20.0");
        assert!(svs.catalog.repositories.is_empty());
        assert_eq!(
            (
                svs.catalog.max_files,
                svs.catalog.max_file_bytes,
                svs.catalog.max_total_bytes,
                svs.catalog.max_tests,
                svs.catalog.fetch_timeout_seconds
            ),
            (10_000, 10 << 20, 256 << 20, 100_000, 600)
        );
        let window = &svs.runs.observation_window;
        assert_eq!(
            (
                window.slack_minutes,
                window.floor_minutes,
                window.ceiling_hours,
                svs.runs.attribution_extra_hours
            ),
            (30, 60, 72, 24)
        );
        assert_eq!(
            (
                svs.runs.start_timeout_minutes,
                svs.runs.max_extra_bytes,
                svs.runs.max_targets,
                svs.runs.max_maintenance_minutes
            ),
            (30, 16384, 16, 240)
        );
        let overlay = Overlay::from_yaml(
            "secrets: {art_key: env:ART_KEY}\n\
             svs: {attack_release: v21.1, catalog: {repositories: {\n\
               art: {url: 'https://forge.example/art.git', branch: master, ssh_key: art_key}}},\n\
               runs: {observation_window: {floor_minutes: 5, slack_minutes: 0}, max_targets: 4,\n\
                      max_extra_bytes: 0, start_timeout_minutes: 10, max_maintenance_minutes: 60}}\n",
        )
        .expect("parses");
        assert_eq!(
            (
                overlay.svs.runs.max_targets,
                overlay.svs.runs.max_extra_bytes
            ),
            (4, 0)
        );
        assert_eq!(overlay.svs.attack_release, "v21.1");
        assert_eq!(overlay.svs.catalog.repositories["art"].branch, "master");
        assert_eq!(overlay.svs.runs.observation_window.floor_minutes, 5);
        for (yaml, at, said) in [
            (
                "svs: {attack_release: ../v20.0}",
                "svs.attack_release",
                "is not an ATT&CK release name",
            ),
            (
                "svs: {attack_release: v20}",
                "svs.attack_release",
                "is not an ATT&CK release name",
            ),
            (
                "svs: {catalog: {refresh_interval_seconds: 300}}",
                "svs.catalog",
                "unknown field",
            ),
            (
                "svs: {catalog: {max_files: 0}}",
                "svs.catalog",
                "max_files must be at least 1",
            ),
            (
                "svs: {catalog: {mirror_dir: relative/dir}}",
                "svs.catalog",
                "must be an absolute path",
            ),
            (
                "svs: {catalog: {repositories: {'.hidden': {url: /x, branch: main}}}}",
                "svs.catalog",
                "repository name",
            ),
            (
                "svs: {catalog: {repositories: {r: {url: /x, branch: '-x'}}}}",
                "svs.catalog",
                "isn't a branch name",
            ),
            (
                "svs: {catalog: {repositories: {r: {url: /x, branch: main, ssh_key: art_key}}}}",
                "svs.catalog.repositories.r.ssh_key",
                "\"art_key\" isn't a secret in secrets:",
            ),
            (
                "svs: {runs: {observation_window: {floor_minutes: 0}}}",
                "svs.runs",
                "floor_minutes must be at least 1",
            ),
            (
                "svs: {runs: {observation_window: {floor_minutes: 121, ceiling_hours: 2}}}",
                "svs.runs",
                "must not exceed ceiling_hours",
            ),
            // batch 5's keys, each at least 1
            (
                "svs: {runs: {max_targets: 0}}",
                "svs.runs",
                "max_targets must be at least 1",
            ),
            (
                "svs: {runs: {start_timeout_minutes: 0}}",
                "svs.runs",
                "start_timeout_minutes must be at least 1",
            ),
            (
                "svs: {runs: {max_maintenance_minutes: 0}}",
                "svs.runs",
                "max_maintenance_minutes must be at least 1",
            ),
            // ace3's key the scheduler's own section replaces
            (
                "svs: {runs: {timer_interval_seconds: 30}}",
                "svs.runs",
                "unknown field",
            ),
            // test_config.py's `test_coverage_defaults`: ace3's `svs.coverage` holds only
            // `refresh_interval_seconds` (120), which is the schedule of the scheduler's
            // `svs_coverage_refresh`, every two minutes (`scheduler:` in this file), so the section
            // has no key and is refused, as ace3 refuses an unknown key of it
            (
                "svs: {coverage: {refresh_interval_seconds: 120}}",
                "svs",
                "unknown field `coverage`",
            ),
            (
                "svs: {coverage: {nope: 1}}",
                "svs",
                "unknown field `coverage`",
            ),
        ] {
            let err = Overlay::from_yaml(yaml).expect_err(yaml);
            assert!(
                matches!(&err, OverlayError::Parse { path, message } if path.starts_with(at) && message.contains(said)),
                "{yaml}: {err:?}"
            );
        }
        assert!(is_attack_release_name("v20.0") && is_attack_release_name("v1.10"));
        for bad in [
            "20.0", "v20", "v.1", "v1.", "v1.0.0", "v1.x", "V1.0", "v1.0\n",
        ] {
            assert!(!is_attack_release_name(bad), "{bad:?}");
        }
    }

    /// A repository's `ssh_key` is the name of a secret this file gives a source for (PLAN.md 7.10).
    #[test]
    fn a_repository_names_its_ssh_key_secret() {
        let overlay = Overlay::from_yaml(
            "secrets: {rules_key: file:/run/secrets/rules_key}\n\
             svs: {yara: {repositories: {\n\
               keyed: {url: 'ssh://git@forge.example/rules.git', branch: main, ssh_key: rules_key},\n\
               plain: {url: /x, branch: main}}}}\n",
        )
        .expect("parses");
        let repositories = &overlay.svs.yara.repositories;
        assert_eq!(repositories["keyed"].ssh_key.as_deref(), Some("rules_key"));
        assert_eq!(repositories["plain"].ssh_key, None);
        // a name with no source, an empty one, and a key's text where its name goes
        for (yaml, at, said) in [
            (
                "svs: {yara: {repositories: {r: {url: /x, branch: main, ssh_key: rules_key}}}}",
                "svs.yara.repositories.r.ssh_key",
                "\"rules_key\" isn't a secret in secrets:",
            ),
            (
                "secrets: {other: env:OTHER}\n\
                 svs: {yara: {repositories: {r: {url: /x, branch: main, ssh_key: rules_key}}}}",
                "svs.yara.repositories.r.ssh_key",
                "\"rules_key\" isn't a secret in secrets:",
            ),
            (
                "svs: {yara: {repositories: {r: {url: /x, branch: main, ssh_key: ''}}}}",
                "svs.yara",
                "repository r: ssh_key is empty",
            ),
        ] {
            let err = Overlay::from_yaml(yaml).expect_err(yaml);
            assert!(
                matches!(&err, OverlayError::Parse { path, message } if path == at && message.contains(said)),
                "{yaml}: {err:?}"
            );
        }
    }

    #[test]
    fn secrets_name_their_sources() {
        let overlay = Overlay::from_yaml(
            "secrets:\n  resolver_token: env:ACE4_RESOLVER_TOKEN\n  other: file:/run/secrets/other\n",
        )
        .expect("loads");
        assert_eq!(
            overlay.secrets["resolver_token"],
            SecretSource::Env("ACE4_RESOLVER_TOKEN".to_owned())
        );
        assert_eq!(
            overlay.secrets["other"],
            SecretSource::File("/run/secrets/other".into())
        );
        let err = Overlay::from_yaml("secrets: {resolver_token: ACE4_RESOLVER_TOKEN}").unwrap_err();
        println!("{err}");
        assert!(
            matches!(&err, OverlayError::Parse { path, .. } if path == "secrets.resolver_token"),
            "{err}"
        );
    }
    /// PLAN.md 7.15: the `ai_api` section, off by default, and what it refuses.
    #[test]
    fn the_ai_api_section_is_off_unless_it_says_otherwise() {
        let overlay = Overlay::from_yaml("modules: {}").expect("parses");
        assert_eq!(overlay.ai_api, AiApiSection::default());
        assert!(!overlay.ai_api.enabled && overlay.ai_api.backends.is_empty());

        let overlay = Overlay::from_yaml(
            "secrets: {token: 'env:AI_TOKEN'}\n\
             ai_api:\n  enabled: true\n  rate_limit_fail_open: true\n  \
             search_limits: {requests_per_minute: 20}\n  backends:\n    \
             splunk:\n      type: splunk\n      enabled: true\n      secrets: [token]\n      \
             limits: {max_concurrency: 4, max_window: '180:00:00:00'}\n      \
             settings: {splunk: {host: h, timezone: GMT}}\n    \
             off: {type: fake}\n",
        )
        .expect("parses");
        let section = &overlay.ai_api;
        assert!(section.enabled && section.rate_limit_fail_open);
        assert_eq!(section.search_limits.requests_per_minute, Some(20));
        assert_eq!(section.export_limits, AiLimitsSection::default());
        let splunk = &section.backends["splunk"];
        assert_eq!((splunk.kind.as_str(), splunk.enabled), ("splunk", true));
        assert_eq!(splunk.secrets, ["token"]);
        assert_eq!(splunk.limits.max_concurrency, Some(4));
        assert_eq!(splunk.limits.max_window.as_deref(), Some("180:00:00:00"));
        assert!(splunk.settings.is_some());
        // a backend is off until its entry says enabled, as in ace3
        assert!(!section.backends["off"].enabled);
        // a pool's view of the overlay holds none of it
        assert_eq!(overlay.for_pool(&[]).ai_api, AiApiSection::default());

        for (text, path) in [
            ("ai_api: {enable: true}", "ai_api"),
            (
                "ai_api: {backends: {b: {enabled: true}}}",
                "ai_api.backends.b",
            ),
            (
                "ai_api: {backends: {b: {type: fake, limit: 1}}}",
                "ai_api.backends.b",
            ),
            (
                "ai_api: {search_limits: {per_minute: 1}}",
                "ai_api.search_limits",
            ),
            // a secret has to have a source in secrets:
            (
                "ai_api: {backends: {b: {type: fake, secrets: [nowhere]}}}",
                "ai_api.backends.b.secrets",
            ),
        ] {
            let error = Overlay::from_yaml(text).expect_err(text).to_string();
            assert!(error.contains(path), "{text}: {error}");
        }
    }
}
