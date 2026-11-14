//! The core's hooks (PLAN.md 7.6): ace3's `observable_modifier` and `configuration_defined_tagging`, which
//! read and change the whole tree, so they run in the core, beside the tree, rather than on a pool. And
//! SVS's hook (PLAN.md 7.10 batch 6), ace3's `svs_alert_tagger`, below.
//!
//! # When they run
//!
//! ace3 runs both inside its analysis loop (`saq/engine/executor.py`). The modifier's `pre` rules run as
//! each observable is taken off the work stack, before the modules after it (its priority is 1), and
//! again whenever the observable comes back; its `post` rules run in final analysis, once the stack is
//! empty and nothing is delayed, on every observable, and when that adds work the loop goes back to
//! normal analysis and comes to final analysis again. `configuration_defined_tagging` runs in post
//! analysis, after final analysis, once per pass. A detection then makes the root an alert, and the
//! correlation pass that follows runs all of it again.
//!
//! Here:
//! - `pre` rules run where a result lands and where a submission starts (`Orchestrator::land_result`,
//!   `Orchestrator::start`), in that transaction, over the observables it added or changed, before
//!   eligibility queues anything for them, so an `exclude_analysis`, `limit_analysis` or `ignore` keeps
//!   modules off as ace3's does.
//! - The rest run in the core's hooks task (`HOOKS_MODULE`). Each landing and each mode change in a mode
//!   that runs a hook sets the root's `hooks_due`, and when the root's last task ends with it set,
//!   `queue::check_completion` queues the hooks task, on the root's first observable, instead of ending
//!   the pass. The core's hooks worker (`run_worker`, in `ace serve`) runs it in one transaction: the
//!   `post` rules over every observable; if any matched, what they did is written, eligibility runs over
//!   what they touched, `hooks_due` is set again, and the task comes back once that work is done, as
//!   ace3 returns to final analysis; once a run matches nothing, `configuration_defined_tagging` adds its
//!   detections to the root. Then the pass ends, or, when a detection made the root an alert, the
//!   correlation pass starts, whose end runs the hooks again.
//!
//! # The SVS hook
//!
//! ace3's `svs_alert_tagger` runs in post analysis in correlation mode and tags the alert, and its marker
//! router judges the same alert again, twice, to write its attributions. Here one judgment does both
//! (`crate::svs::attribution::judge`, the owner's decision of 2026-11-14): once the modifier's `post` rules
//! match nothing and the tagging has added its detections, the hooks task judges the root's SVS context
//! once, in the modes that list `svs_alert_tagger`, and writes what follows from that one judgment in the
//! task's transaction: the attributions of its detections to test runs (`svs.attributions`, with each
//! change in its run's event log), the `svs_test`, `svs:marker_mismatch` and `svs:maintenance` tags on
//! the root (`analysis.roots.tags`), a root detection for each marker that doesn't agree with its run, and
//! its maintenance record (`svs.maintenance_alerts`). A mismatch detection can't change the mode: the hook
//! judges alerts only. What it did is the run's `Ran::svs`, and each write is logged.
//!
//! It is bounded as its module says: while no run is registered or inside its attribution window and no
//! maintenance window was open lately, it is one query; otherwise it reads only the rows that hold
//! marker-shaped text, a capped number of each, judges a capped number of markers, an event has a capped
//! number of hosts, and it considers only the runs and windows on those hosts whose windows overlap the
//! event, a capped number of each.
//!
//! A rule matches an observable once, ever: each match is kept in the observable's
//! `observable_modifier` result, as ace3 keeps it in its analysis, and isn't evaluated there again, so
//! the hooks' reruns end. A root detection is added once per tag.
//!
//! # What they write
//!
//! Everything a hook does is in the tree, as a module's result is, and goes in the hook's transaction:
//! - a rule's match is the observable's `observable_modifier` result (`observable_modifier_analysis`,
//!   ace3's `ObservableModifierAnalysis`: `matched_rules`, each with its name, uuid and
//!   `actions_applied`, and ace3's summary), which adds a `signature_id` observable per rule uuid;
//! - its actions: tags, directives, `exclude_modules`, `limit_modules`, `display_type` and
//!   `display_value` on the observable; detections on it, raised by that result, with the rule's uuid as
//!   their signature; `reset_analysis` queues a task again that ended with no result; `ignore` sets the
//!   observable's `ignored`, or the `ignored` of the additions of the parent results it names;
//! - `configuration_defined_tagging`'s detections are on the root (`analysis.detections.observable_id`
//!   NULL), with ace3's `alertable_tag` signature;
//! - the SVS hook's writes, above.
//!
//! The hooks task is a row of `queue.tasks`, so each run is recorded with its end, and one that fails
//! keeps its error, as a module's does. None of this is an analyst's write, so no audit row is written,
//! as none is for a module's result; each match is logged with its rule.
//!
//! # Bounds
//!
//! The rules are an analyst's, compiled when the core starts (`rules::Rules::compile`): at most
//! `rules::MAX_RULES`, with `rules::MAX_PATTERNS` patterns, each at most `rules::MAX_PATTERN_BYTES` long
//! and compiled by the `regex` crate, which doesn't backtrack, within `rules::REGEX_SIZE_LIMIT` alone and
//! `rules::ALL_PATTERNS_LIMIT` together. What they read is hostile: a root's tree is read up to
//! `ace_sdk::tree`'s `MAX_TREE_OBSERVABLES` observables and `MAX_TREE_RESULTS` results, the details only of
//! the modules a `details_match` names, and one evaluation stops after `rules::STEP_BUDGET` steps. A `pre`
//! evaluation over its budget changes nothing and logs why; a hooks run over it fails its task.
//!
//! # What differs from ace3
//!
//! - The rules are the overlay's `hooks:` section (`ace_sdk::hooks`), read when the core starts. ace3
//!   watches its rules file and reloads it live; here a change takes a restart. A rule ace3 logs and
//!   skips (no uuid, an unknown phase or scope, a pattern that doesn't compile) stops startup, as the
//!   rest of the overlay does, and so does an unknown observable type or `observable_match` attribute,
//!   which ace3 would let match nothing.
//! - A module is named by its key (`rdap_analyzer`) where ace3 names a Python path, a tree condition's
//!   `analysis_type` and `reset_analysis` an Analysis class's, `exclude_analysis` an analyzer's.
//! - Patterns are the `regex` crate's, so one that needs backtracking, such as a look-around or a
//!   backreference, doesn't compile.
//! - A details value a `details_match` tests is a string as itself and anything else as Python's
//!   `str()` writes it (`rules::py_str`), from the stored JSON, so a value ace3 held as a Python object
//!   other than JSON's reads as its JSON form would.
//! - A file has a path per place it's in, where ace3 has an observable per path: a `file_name` matches
//!   when any of its names does, and its `display_value` reads its analyzed path.
//! - A rule's detections' signature version is `unknown`, as ace3's is without its optional `git_dir`.
//! - `pre` rules run over what a landing touched, and over what their own matches add up to
//!   `PRE_ROUNDS` times, where ace3 runs them each time an observable comes back to its stack, also
//!   after a tag or directive lands; a later landing that touches the observable runs them again. A
//!   mode change doesn't run them, where ace3 runs its modules again in the new mode; the `post` rules
//!   run at the end of that pass.
//! - ace3 leaves final analysis after each match and puts every observable back on its stack, so a
//!   rule set with many matches costs a pass over the tree each; here a run evaluates every observable
//!   once, and runs again only when something matched.
//! - ace3's per-rule cost log lines (`execute_post_analysis`) aren't written; each match is logged.
//! - A cancelled root, one whitelisted or dispositioned, runs no hook. ace3's whitelisting stops its
//!   loop before final analysis but still runs post analysis, so `configuration_defined_tagging` can add
//!   a root detection there, which can't make that root an alert anyway.

pub mod rules;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use ace_results::ObservableKind;
use ace_sdk::hooks::{HooksSection, Phase};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::{Db, DbError, Isolation, Retryable, Tx};
use crate::modes::Modes;
use crate::orchestrator::{Orchestrator, OrchestratorError};
use crate::queue::{self, QueueError, Task, TaskId, TaskState, Wakeups, Worker};
use crate::tree::ObservableId;
use rules::{Budget, Node, Rules, Tree};

/// ace3's observable modifier's module name, which the modes' groups list.
pub const OBSERVABLE_MODIFIER: &str = "observable_modifier";
/// ace3's configuration-defined tagging's module name.
pub const CONFIGURATION_DEFINED_TAGGING: &str = "configuration_defined_tagging";
/// The module key of the hooks task. No pool runs it; the core's hooks worker does.
pub const HOOKS_MODULE: &str = "core_hooks";
/// The analysis type of the modifier's results, ace3's `ObservableModifierAnalysis`.
pub const MODIFIER_ANALYSIS: &str = "observable_modifier_analysis";
/// ace3's `ALERTABLE_TAG` signature (`saq/signatures/builtin.py`), on a tag's root detection.
pub const ALERTABLE_TAG_SIGNATURE: &str = "14564014-a223-440a-914f-03a1f322e1bf";
/// The levels of ace3's `tags:` section that make a detection.
const ALERTABLE_LEVELS: [&str; 3] = ["alert", "critical", "warning"];
/// How many times `pre` rules run over what their own matches added, in one landing.
const PRE_ROUNDS: usize = 3;

/// ace3's SVS tagger's module name: the SVS hook runs in the modes that list it.
pub const SVS_ALERT_TAGGER: &str = crate::svs::attribution::SVS_ALERT_TAGGER;

/// The hooks the overlay turns on, compiled.
#[derive(Debug, Clone, Default)]
pub struct Hooks {
    modifier: Option<Arc<Rules>>,
    /// The tags whose level makes a detection, when `configuration_defined_tagging` is on.
    alertable: Option<Arc<BTreeSet<String>>>,
    /// The SVS hook, when the binary runs it (`with_svs`).
    svs: Option<crate::svs::attribution::HookConfig>,
}

impl Hooks {
    /// No hooks, as a binary with no overlay section has.
    pub fn none() -> Hooks {
        Hooks::default()
    }

    /// The hooks the overlay's section turns on: the modifier when it has an enabled rule, and the
    /// tagging when it has a section, as ace3 ships it disabled.
    pub fn from_section(section: &HooksSection) -> Result<Hooks, rules::RuleError> {
        let modifier = match &section.observable_modifier {
            Some(s) => Some(Rules::compile(s)?).filter(|r| !r.is_empty()),
            None => None,
        };
        let alertable = section.configuration_defined_tagging.as_ref().map(|s| {
            s.tags
                .iter()
                .filter(|(_, level)| ALERTABLE_LEVELS.contains(&level.as_str()))
                .map(|(tag, _)| tag.clone())
                .collect::<BTreeSet<_>>()
        });
        Ok(Hooks {
            modifier: modifier.map(Arc::new),
            alertable: alertable.map(Arc::new),
            svs: None,
        })
    }

    /// These hooks with the SVS hook, `svs_alert_tagger` (the module docs), which `ace serve` runs.
    pub fn with_svs(mut self, config: crate::svs::attribution::HookConfig) -> Hooks {
        self.svs = Some(config);
        self
    }

    /// The names of the hooks that are on, for the comparison to count as ported.
    pub fn names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.alertable.is_some() {
            names.push(CONFIGURATION_DEFINED_TAGGING);
        }
        if self.modifier.is_some() {
            names.push(OBSERVABLE_MODIFIER);
        }
        if self.svs.is_some() {
            names.push(SVS_ALERT_TAGGER);
        }
        names
    }

    pub fn rules(&self) -> Option<&Rules> {
        self.modifier.as_deref()
    }

    fn modifier_in(&self, modes: &Modes, mode: &str) -> Option<&Rules> {
        self.modifier
            .as_deref()
            .filter(|_| modes.modules_in(mode).contains(OBSERVABLE_MODIFIER))
    }

    fn tagging_in(&self, modes: &Modes, mode: &str) -> Option<&BTreeSet<String>> {
        self.alertable.as_deref().filter(|_| {
            modes
                .modules_in(mode)
                .contains(CONFIGURATION_DEFINED_TAGGING)
        })
    }

    fn svs_in(&self, modes: &Modes, mode: &str) -> Option<&crate::svs::attribution::HookConfig> {
        self.svs
            .as_ref()
            .filter(|_| modes.modules_in(mode).contains(SVS_ALERT_TAGGER))
    }

    /// Whether a hook runs at the end of a pass in `mode`.
    pub fn run_in(&self, modes: &Modes, mode: &str) -> bool {
        self.modifier_in(modes, mode)
            .is_some_and(|r| r.has_phase(Phase::Post))
            || self.tagging_in(modes, mode).is_some()
            || self.svs_in(modes, mode).is_some()
    }
}

/// What the hooks wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Effects {
    /// The observables whose eligibility may have changed: those a rule changed and those it added.
    pub touched: Vec<ObservableId>,
    /// Whether a detection was added.
    pub detected: bool,
    /// Whether any rule matched.
    pub matched: bool,
    /// Tasks queued again by `reset_analysis`.
    pub requeued: Vec<TaskId>,
}

impl Effects {
    fn extend(&mut self, other: Effects) {
        self.touched.extend(other.touched);
        self.detected |= other.detected;
        self.matched |= other.matched;
        self.requeued.extend(other.requeued);
    }
}

/// Marks the root's hooks due, when a hook runs at the end of a pass in `mode`.
pub(crate) async fn mark_due(
    tx: &mut Tx<'_>,
    hooks: &Hooks,
    modes: &Modes,
    root: Uuid,
    mode: &str,
) -> Result<(), DbError> {
    if hooks.run_in(modes, mode) {
        sqlx::query!(
            "UPDATE analysis.roots SET hooks_due = true WHERE id = $1",
            root
        )
        .execute(tx.conn())
        .await?;
    }
    Ok(())
}

/// Runs the `pre` rules over `observables`, and over what their matches add, and writes what matched.
/// An evaluation over its budget writes nothing and logs why, since a landing mustn't fail on it.
pub(crate) async fn pre(
    tx: &mut Tx<'_>,
    hooks: &Hooks,
    modes: &Modes,
    root: Uuid,
    mode: &str,
    observables: &[ObservableId],
) -> Result<Effects, DbError> {
    let Some(rules) = hooks
        .modifier_in(modes, mode)
        .filter(|r| r.has_phase(Phase::Pre))
    else {
        return Ok(Effects::default());
    };
    let mut effects = Effects::default();
    let mut next: Vec<ObservableId> = observables.to_vec();
    for _ in 0..PRE_ROUNDS {
        if next.is_empty() {
            break;
        }
        let mut tree = load(tx, root, rules).await?;
        let index: HashMap<i64, usize> = tree
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.id, i))
            .collect();
        let mut budget = Budget::new(rules::STEP_BUDGET);
        let mut matches = Vec::new();
        let mut seen = BTreeSet::new();
        for id in &next {
            let Some(&node) = index.get(&id.0) else {
                continue;
            };
            if !seen.insert(node) || tree.nodes[node].ignored {
                continue;
            }
            match rules.evaluate(&mut tree, node, Phase::Pre, &mut budget) {
                Ok(found) => matches.extend(found),
                Err(over) => {
                    tracing::error!(%root, "{over}; its pre rules change nothing in this landing");
                    return Ok(effects);
                }
            }
        }
        let round = write(tx, root, rules, &tree, &matches).await?;
        next = round
            .touched
            .iter()
            .filter(|id| !observables.contains(id) && !effects.touched.contains(id))
            .copied()
            .collect();
        effects.extend(round);
    }
    Ok(effects)
}

/// Loads the root's tree as the rules read it, with the details of the modules they read.
async fn load(tx: &mut Tx<'_>, root: Uuid, rules: &Rules) -> Result<Tree, DbError> {
    use ace_sdk::tree::{MAX_TREE_OBSERVABLES, MAX_TREE_RESULTS};

    let head = sqlx::query!(
        r#"SELECT origin ->> 'alert_type' AS alert_type, origin ->> 'queue' AS queue,
                  CASE WHEN jsonb_typeof(origin -> 'tags') = 'array'
                       THEN ARRAY(SELECT jsonb_array_elements_text(origin -> 'tags')) END AS tags,
                  tags AS core_tags
           FROM analysis.roots WHERE id = $1"#,
        root,
    )
    .fetch_optional(tx.conn())
    .await?;
    let mut tree = Tree::default();
    if let Some(head) = head {
        tree.alert_type = head.alert_type;
        tree.queue = head.queue;
        // the submitter's tags, then the core's own (`analysis.roots.tags`)
        tree.root_tags = head.tags.unwrap_or_default();
        for tag in head.core_tags {
            if !tree.root_tags.contains(&tag) {
                tree.root_tags.push(tag);
            }
        }
    }
    let limit = MAX_TREE_OBSERVABLES as i64 + 1;
    let rows = sqlx::query!(
        r#"SELECT id AS "id: ObservableId", type AS kind, value, tags, directives, display_type,
                  display_value, ignored
           FROM analysis.observables WHERE root_id = $1 ORDER BY id LIMIT $2"#,
        root,
        limit,
    )
    .fetch_all(tx.conn())
    .await?;
    if rows.len() > MAX_TREE_OBSERVABLES {
        tracing::warn!(%root, "the root has more than {MAX_TREE_OBSERVABLES} observables; the hooks read the first");
    }
    let mut index: HashMap<i64, usize> = HashMap::new();
    for row in rows.into_iter().take(MAX_TREE_OBSERVABLES) {
        let kind: ObservableKind = row
            .kind
            .parse()
            .map_err(|e| DbError::Decode(format!("observable {}: {e}", row.id.0)))?;
        index.insert(row.id.0, tree.nodes.len());
        tree.nodes.push(Node {
            id: row.id.0,
            kind,
            value: row.value,
            tags: row.tags,
            directives: row.directives,
            yara_meta: Vec::new(),
            paths: Vec::new(),
            display_type: row.display_type,
            display_value: row.display_value,
            no_analysis: Vec::new(),
            results: Vec::new(),
            parents: Vec::new(),
            matched: Vec::new(),
            ignored: row.ignored,
        });
    }
    for row in sqlx::query!(
        r#"SELECT observable_id AS "id: ObservableId", path, yara_meta FROM analysis.files
           WHERE root_id = $1 ORDER BY observable_id, analyzed DESC, depth, path COLLATE "C""#,
        root,
    )
    .fetch_all(tx.conn())
    .await?
    {
        if let Some(&i) = index.get(&row.id.0) {
            let node = &mut tree.nodes[i];
            node.paths.push(row.path);
            for tag in row.yara_meta {
                if !node.yara_meta.contains(&tag) {
                    node.yara_meta.push(tag);
                }
            }
        }
    }
    let details_of: Vec<String> = rules
        .details_of()
        .iter()
        .cloned()
        .chain([OBSERVABLE_MODIFIER.to_owned()])
        .collect();
    let every = rules.details_of().contains("");
    let limit = MAX_TREE_RESULTS as i64 + 1;
    let rows = sqlx::query!(
        r#"SELECT id, observable_id AS "observable_id: ObservableId", module,
                  CASE WHEN $3 OR module = ANY($4) THEN details END AS details
           FROM analysis.results WHERE root_id = $1 ORDER BY id LIMIT $2"#,
        root,
        limit,
        every,
        &details_of,
    )
    .fetch_all(tx.conn())
    .await?;
    if rows.len() > MAX_TREE_RESULTS {
        tracing::warn!(%root, "the root has more than {MAX_TREE_RESULTS} results; the hooks read the first");
    }
    let mut result_index: HashMap<i64, usize> = HashMap::new();
    for row in rows.into_iter().take(MAX_TREE_RESULTS) {
        let Some(&observable) = index.get(&row.observable_id.0) else {
            continue;
        };
        if row.module == OBSERVABLE_MODIFIER
            && let Some(details) = &row.details
        {
            tree.nodes[observable].matched = rules::matched_rules(details);
        }
        result_index.insert(row.id, tree.results.len());
        tree.nodes[observable].results.push(tree.results.len());
        tree.results.push(rules::Analysis {
            id: row.id,
            observable,
            module: row.module,
            added: Vec::new(),
            details: row.details,
        });
    }
    for row in sqlx::query!(
        r#"SELECT id, result_id, observable_id FROM analysis.result_additions
           WHERE root_id = $1 AND NOT ignored ORDER BY id"#,
        root,
    )
    .fetch_all(tx.conn())
    .await?
    {
        let (Some(&result), Some(&node)) = (
            result_index.get(&row.result_id),
            index.get(&row.observable_id),
        ) else {
            continue;
        };
        tree.results[result].added.push((node, row.id));
        tree.nodes[node].parents.push((result, row.id));
    }
    for row in sqlx::query!(
        r#"SELECT t.observable_id AS "id: ObservableId", t.module FROM queue.tasks t
           WHERE t.root_id = $1 AND t.state = 'done'
             AND NOT EXISTS (SELECT 1 FROM analysis.results r
                             WHERE r.root_id = t.root_id AND r.observable_id = t.observable_id
                               AND r.module = t.module)
           ORDER BY t.id"#,
        root,
    )
    .fetch_all(tx.conn())
    .await?
    {
        if let Some(&i) = index.get(&row.id.0) {
            tree.nodes[i].no_analysis.push(row.module);
        }
    }
    Ok(tree)
}

/// Writes what the matches did: each matched observable's result, its `signature_id` observables, its
/// detections and the changes to it.
async fn write(
    tx: &mut Tx<'_>,
    root: Uuid,
    rules: &Rules,
    tree: &Tree,
    matches: &[rules::Matched],
) -> Result<Effects, DbError> {
    let mut effects = Effects::default();
    let mut by_node: BTreeMap<usize, Vec<&rules::Matched>> = BTreeMap::new();
    for m in matches {
        by_node.entry(m.node).or_default().push(m);
    }
    for (node, matched) in by_node {
        effects.matched = true;
        let n = &tree.nodes[node];
        let observable = ObservableId(n.id);
        let summary = rules::summary(&n.matched);
        let result = sqlx::query_scalar!(
            r#"INSERT INTO analysis.results
                   (root_id, observable_id, module, analysis_type, schema_version, details, summary)
               VALUES ($1, $2, $3, $4, 1, $5, $6)
               ON CONFLICT (root_id, observable_id, module) DO UPDATE
                   SET details = EXCLUDED.details, summary = EXCLUDED.summary
               RETURNING id AS "id: crate::tree::ResultId""#,
            root,
            observable as ObservableId,
            OBSERVABLE_MODIFIER,
            MODIFIER_ANALYSIS,
            json!({"matched_rules": n.matched}),
            summary,
        )
        .fetch_one(tx.conn())
        .await?;
        let depth = crate::tree::depth(tx.conn(), root, observable)
            .await?
            .saturating_add(1);
        let mut tags = Vec::new();
        let mut directives = Vec::new();
        let mut exclude = Vec::new();
        let mut limit = Vec::new();
        let mut reset = Vec::new();
        let mut removed = Vec::new();
        let mut ignored = false;
        for m in matched {
            let rule = &rules.rules()[m.rule];
            let a = &rule.actions;
            tags.extend(a.add_tags.iter().cloned());
            directives.extend(a.add_directives.iter().cloned());
            if a.ignore && rule.phase == Phase::Pre {
                directives.push(ace_sdk::EXCLUDE_ALL.to_owned());
            }
            exclude.extend(a.exclude_analysis.iter().cloned());
            limit.extend(a.limit_analysis.iter().cloned());
            if let Some(Value::Array(modules)) = m.applied.get("reset_analysis") {
                reset.extend(modules.iter().filter_map(Value::as_str).map(str::to_owned));
            }
            removed.extend(m.removed_from.iter().copied());
            ignored |= m.ignored;
            for description in &a.add_detection_points {
                effects.detected = true;
                sqlx::query!(
                    "INSERT INTO analysis.detections
                         (root_id, observable_id, result_id, description, signature_uuid,
                          signature_version, signature_family)
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    root,
                    observable as ObservableId,
                    result as crate::tree::ResultId,
                    description,
                    rule.uuid,
                    rules::SIGNATURE_VERSION,
                    rules::SIGNATURE_FAMILY,
                )
                .execute(tx.conn())
                .await?;
            }
            // ace3 adds one per uuid not added before; the observable is unique by value anyway
            let added = crate::tree::upsert_observable_at(
                tx,
                root,
                &ace_results::NewObservable::new(ObservableKind::SignatureId, rule.uuid.clone()),
                depth,
            )
            .await?;
            crate::tree::add_result_addition(tx, root, result, added.id, None).await?;
            effects.touched.push(added.id);
        }
        sqlx::query!(
            "UPDATE analysis.observables
             SET tags = analysis.merged(tags, $3), directives = analysis.merged(directives, $4),
                 exclude_modules = analysis.merged(exclude_modules, $5),
                 limit_modules = analysis.merged(limit_modules, $6),
                 display_type = $7, display_value = $8, ignored = ignored OR $9
             WHERE root_id = $1 AND id = $2",
            root,
            observable as ObservableId,
            &tags,
            &directives,
            &exclude,
            &limit,
            n.display_type,
            n.display_value,
            ignored,
        )
        .execute(tx.conn())
        .await?;
        if !removed.is_empty() {
            sqlx::query!(
                "UPDATE analysis.result_additions SET ignored = true WHERE root_id = $1 AND id = ANY($2)",
                root,
                &removed,
            )
            .execute(tx.conn())
            .await?;
        }
        if !reset.is_empty() {
            effects
                .requeued
                .extend(queue::requeue_without_result(tx, root, observable, &reset).await?);
        }
        effects.touched.push(observable);
    }
    Ok(effects)
}

/// `configuration_defined_tagging`: a detection on the root for each tag configured as alertable that
/// anything in the root has, the root's own tags, its observables' and its results', once per tag.
async fn tag_detections(
    tx: &mut Tx<'_>,
    root: Uuid,
    alertable: &BTreeSet<String>,
) -> Result<bool, DbError> {
    if alertable.is_empty() {
        return Ok(false);
    }
    let alertable: Vec<String> = alertable.iter().cloned().collect();
    let added = sqlx::query_scalar!(
        r#"WITH present AS (
               SELECT t FROM analysis.observables o, unnest(o.tags) t WHERE o.root_id = $1
               UNION SELECT t FROM analysis.results r, unnest(r.tags) t WHERE r.root_id = $1
               UNION SELECT jsonb_array_elements_text(origin -> 'tags') FROM analysis.roots
                     WHERE id = $1 AND jsonb_typeof(origin -> 'tags') = 'array'
               UNION SELECT t FROM analysis.roots x, unnest(x.tags) t WHERE x.id = $1),
           wanted AS (
               SELECT DISTINCT 'tag ' || p.t || ' is configured to be alertable' AS description
               FROM present p WHERE p.t = ANY($2))
           INSERT INTO analysis.detections (root_id, observable_id, description, signature_uuid)
           SELECT $1, NULL, w.description, $3 FROM wanted w
           WHERE NOT EXISTS (SELECT 1 FROM analysis.detections d
                             WHERE d.root_id = $1 AND d.observable_id IS NULL
                               AND d.description = w.description)
           ORDER BY w.description
           RETURNING id"#,
        root,
        &alertable,
        ALERTABLE_TAG_SIGNATURE,
    )
    .fetch_all(tx.conn())
    .await?;
    Ok(!added.is_empty())
}

#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),
    #[error(transparent)]
    Queue(#[from] QueueError),
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    OverBudget(#[from] rules::OverBudget),
}

impl From<sqlx::Error> for HookError {
    fn from(error: sqlx::Error) -> Self {
        HookError::Db(DbError::Sqlx(error))
    }
}

impl Retryable for HookError {
    fn is_retryable(&self) -> bool {
        match self {
            HookError::Orchestrator(e) => e.is_retryable(),
            HookError::Queue(e) => e.is_retryable(),
            HookError::Db(e) => e.is_retryable(),
            HookError::OverBudget(_) => false,
        }
    }
}

/// What a hooks run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ran {
    pub effects: Effects,
    /// Tasks the run queued: eligibility over what it touched, or the correlation mode's.
    pub queued: Vec<TaskId>,
    /// The mode the root changed to, when a detection made it an alert.
    pub mode_changed_to: Option<String>,
    /// What the SVS hook made of the root, when it judged it.
    pub svs: Option<crate::svs::attribution::Judged>,
}

impl Orchestrator {
    /// Runs a claimed hooks task and ends it, in one transaction (the module docs).
    pub async fn run_hooks(&self, worker: &Worker, task: &Task) -> Result<Ran, HookError> {
        worker
            .db()
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move { self.run_hooks_in(tx, worker, task).await })
            })
            .await
    }

    async fn run_hooks_in(
        &self,
        tx: &mut Tx<'_>,
        worker: &Worker,
        task: &Task,
    ) -> Result<Ran, HookError> {
        let root = worker.finish_in(tx, task.id, TaskState::Done, None).await?;
        let state = sqlx::query!(
            "UPDATE analysis.roots SET hooks_due = false WHERE id = $1
             RETURNING analysis_mode, cancelled_at IS NOT NULL AS \"cancelled!\"",
            root,
        )
        .fetch_one(tx.conn())
        .await?;
        let mut ran = Ran::default();
        if state.cancelled {
            queue::check_completion(tx, root).await?;
            return Ok(ran);
        }
        let mode = state.analysis_mode;
        if let Some(rules) = self.hooks().modifier_in(self.modes(), &mode) {
            let mut tree = load(tx, root, rules).await?;
            let mut budget = Budget::new(rules::STEP_BUDGET);
            let mut matches = Vec::new();
            for node in 0..tree.nodes.len() {
                if tree.nodes[node].ignored {
                    continue;
                }
                matches.extend(rules.evaluate(&mut tree, node, Phase::Post, &mut budget)?);
            }
            ran.effects = write(tx, root, rules, &tree, &matches).await?;
        }
        if ran.effects.matched {
            // what the rules did may make more work, or other rules match: the hooks run again
            sqlx::query!(
                "UPDATE analysis.roots SET hooks_due = true WHERE id = $1",
                root
            )
            .execute(tx.conn())
            .await?;
        } else {
            if let Some(alertable) = self.hooks().tagging_in(self.modes(), &mode) {
                ran.effects.detected |= tag_detections(tx, root, alertable).await?;
            }
            // last, so its one judgment sees every detection the pass made
            if let Some(config) = self.hooks().svs_in(self.modes(), &mode) {
                ran.svs =
                    crate::svs::attribution::judge(tx.conn(), root, config, chrono::Utc::now())
                        .await?;
                ran.effects.detected |= ran.svs.as_ref().is_some_and(|judged| judged.detected);
            }
        }
        let touched = ran.effects.touched.clone();
        let (queued, changed) = self
            .after_hooks(tx, root, &mode, &touched, ran.effects.detected)
            .await?;
        ran.queued = queued;
        ran.mode_changed_to = changed;
        queue::check_completion(tx, root).await?;
        Ok(ran)
    }
}

/// The core's hooks worker: claims hooks tasks as `worker`, waking on the queue's notifications with
/// `fallback` as the longest wait, and runs each, until `stop` fires. A run that fails fails its task
/// with why.
pub async fn run_worker(
    orchestrator: Orchestrator,
    worker: Worker,
    fallback: Duration,
    stop: CancellationToken,
) {
    let mut wakeups = None;
    loop {
        if wakeups.is_none() {
            match tokio::time::timeout(fallback, Wakeups::listen(worker.db())).await {
                Ok(Ok(listening)) => wakeups = Some(listening),
                Ok(Err(e)) => tracing::warn!("the hooks worker can't listen for tasks: {e}"),
                Err(_) => tracing::warn!("the hooks worker's listener didn't connect in time"),
            }
        }
        let next = match wakeups.as_mut() {
            Some(wakeups) => tokio::select! {
                () = stop.cancelled() => return,
                next = worker.next_task(wakeups, fallback) => next.map(|(task, _)| Some(task)),
            },
            None => tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(fallback) => worker.claim().await,
            },
        };
        let task = match next {
            Ok(Some(task)) => task,
            Ok(None) => continue,
            Err(e) => {
                tracing::error!("the hooks worker couldn't claim a task: {e}");
                wakeups = None;
                tokio::time::sleep(fallback).await;
                continue;
            }
        };
        if let Err(e) = orchestrator.run_hooks(&worker, &task).await {
            tracing::error!(task = %task.id, root = %task.root, "the hooks failed: {e}");
            if let Err(e) = worker.fail(task.id, &e.to_string()).await {
                tracing::error!(task = %task.id, "failing the hooks task failed: {e}");
            }
        }
    }
}

/// The hooks worker: one per core process, named for the host and process.
pub fn hooks_worker(db: Db) -> Worker {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "core".to_owned());
    Worker::new(
        db,
        format!("core/{host}/{}/hooks", std::process::id()),
        vec![HOOKS_MODULE.to_owned()],
        Duration::from_secs(60),
    )
}
