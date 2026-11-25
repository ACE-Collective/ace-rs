//! `observable_modifier`'s rules, compiled and evaluated over a snapshot of a root's tree (`Tree`), as
//! ace3's `saq/modules/util/observable_modifier.py` evaluates them over its `RootAnalysis`.
//!
//! Evaluating is pure: it reads the snapshot and changes it as each matched rule's actions would, so a
//! later rule sees what an earlier one did, as in ace3, and returns what matched. The caller writes that
//! to the tree (`super::apply`). Every walk and every pattern test spends from a `Budget`, so a rule set
//! over a large, hostile tree stops at a known cost rather than running on.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use ace_results::ObservableKind;
use ace_sdk::hooks::{ModifierRule, Phase, Scope};
use serde_json::{Map, Value, json};

/// The most rules the overlay may hold, as many as one analyst-edited list (PLAN.md 5.14).
pub const MAX_RULES: usize = 1000;
/// The most patterns all the rules together may hold.
pub const MAX_PATTERNS: usize = 1024;
/// The longest pattern, in bytes, as a list's (5.14).
pub const MAX_PATTERN_BYTES: usize = 1024;
/// What the parts of one pattern that `fancy-regex` hands to the `regex` crate may compile to, as a
/// list's `size_limit`.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// What those parts' lazy DFA may cache.
pub const REGEX_DFA_LIMIT: usize = 128 << 10;
/// The most backtracking steps one test of one pattern may take, `fancy-regex`'s default. Past it the
/// test gives up and counts as not matching (`Pattern::test`).
pub const BACKTRACK_LIMIT: usize = 1_000_000;
/// The most segments a `details_match` path may have.
pub const MAX_PATH_SEGMENTS: usize = 32;
/// The steps one evaluation over one tree may take: a result or an observable visited in a walk, a
/// pattern tested, a value looked up. Past it the evaluation stops (`OverBudget`).
pub const STEP_BUDGET: u64 = 20_000_000;

/// The signature family of an observable modifier rule's detections, ace3's
/// `SignatureType.OBSERVABLE_MODIFIER`.
pub const SIGNATURE_FAMILY: &str = "observable_modifier";
/// The signature version of a rule that didn't come from a repository's commit, ace3's
/// `SIGNATURE_VERSION_UNKNOWN`. ace3 reads a commit only when its optional `git_dir` is set; the overlay
/// has no commit.
pub const SIGNATURE_VERSION: &str = "unknown";

/// A rule that doesn't compile, with where, which the rules skip.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {message}")]
pub struct RuleError {
    /// Where the rule is (`hooks.observable_modifier.rules[2]`, or the file and its index) and the key
    /// at fault.
    pub path: String,
    /// The rule's name and uuid, as far as they read.
    pub rule: String,
    pub message: String,
}

/// A pattern as Python's `re` writes it, compiled by `fancy-regex`, which hands the parts that need no
/// backtracking to the `regex` crate and backtracks only for look-around and backreferences.
#[derive(Debug, Clone)]
pub struct Pattern {
    regex: fancy_regex::Regex,
}

impl Pattern {
    /// Whether the pattern matches anywhere in `text`. A test past `BACKTRACK_LIMIT` counts as not
    /// matching, logged, where ace3's `re` would run on.
    fn test(&self, text: &str) -> bool {
        match self.regex.is_match(text) {
            Ok(matched) => matched,
            Err(e) => {
                tracing::warn!(
                    pattern = self.regex.as_str(),
                    "an observable modifier pattern gave up, so it counts as not matching: {e}"
                );
                false
            }
        }
    }
}

/// An error at `path`; `Rules::and` names the rule.
fn error(path: String, message: String) -> RuleError {
    RuleError {
        path,
        rule: String::new(),
        message,
    }
}

/// An evaluation spent its whole budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the observable modifier's rules took more than {STEP_BUDGET} steps over this tree")]
pub struct OverBudget;

/// What an evaluation may still spend.
#[derive(Debug)]
pub struct Budget {
    left: u64,
}

impl Budget {
    pub fn new(steps: u64) -> Budget {
        Budget { left: steps }
    }

    fn spend(&mut self, steps: u64) -> Result<(), OverBudget> {
        self.left = self.left.checked_sub(steps).ok_or(OverBudget)?;
        Ok(())
    }

    pub fn left(&self) -> u64 {
        self.left
    }
}

/// The compiled rules.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    rules: Vec<Rule>,
    /// The modules whose details a `details_match` reads, so a snapshot loads only those.
    details_of: BTreeSet<String>,
    /// Every pattern's text, for `MAX_PATTERNS` across the overlay's rules and a file's.
    sources: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub uuid: String,
    pub enabled: bool,
    pub phase: Phase,
    conditions: Conditions,
    pub actions: ace_sdk::hooks::RuleActions,
    /// The tree conditions scoped to the parent, which `ignore` reads.
    parent_modules: Vec<String>,
    has_parent_scope: bool,
}

#[derive(Debug, Clone, Default)]
struct Conditions {
    alert_tags: Vec<String>,
    alert_type: Option<String>,
    queue: Option<String>,
    observable_types: Vec<ObservableKind>,
    value_pattern: Option<Pattern>,
    file_name_pattern: Option<Pattern>,
    display_type_pattern: Option<Pattern>,
    display_value_pattern: Option<Pattern>,
    has_tags: Vec<String>,
    has_directives: Vec<String>,
    has_yara_meta_tags: Vec<String>,
    tree_conditions: Vec<TreeCondition>,
}

/// An observable's attribute a tree condition's `observable_match` reads, as ace3 reads it with
/// `getattr` and tests `str()` of it: those of ace3's `Observable` an ace-rs observable has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attribute {
    Type,
    Value,
    FileName,
    DisplayType,
    DisplayValue,
    /// A list, as Python's `str()` writes one: `['a', 'b']`.
    Tags,
    Directives,
    /// `True` or `False`.
    Ignored,
    /// `limited_analysis` and `excluded_analysis`: the modules' keys, as a list.
    LimitedAnalysis,
    ExcludedAnalysis,
    /// Python's `str()` of the observable's time, `2026-11-24 14:28:25+00:00`. An observable with no
    /// time matches nothing, as ace3's `getattr` gives None.
    Time,
}

impl Attribute {
    const NAMES: &[(&str, Attribute)] = &[
        ("type", Attribute::Type),
        ("value", Attribute::Value),
        ("file_name", Attribute::FileName),
        ("display_type", Attribute::DisplayType),
        ("display_value", Attribute::DisplayValue),
        ("tags", Attribute::Tags),
        ("directives", Attribute::Directives),
        ("ignored", Attribute::Ignored),
        ("limited_analysis", Attribute::LimitedAnalysis),
        ("excluded_analysis", Attribute::ExcludedAnalysis),
        ("time", Attribute::Time),
    ];

    fn named(name: &str) -> Option<Attribute> {
        Attribute::NAMES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|&(_, a)| a)
    }
}

#[derive(Debug, Clone)]
struct TreeCondition {
    analysis_type: String,
    scope: Scope,
    details_match: Vec<(Vec<String>, Pattern)>,
    observable_match: Vec<(Attribute, Pattern)>,
    produces: Option<(ObservableKind, Option<Pattern>)>,
    negate: bool,
    match_count: Option<u32>,
}

struct Compiler {
    sources: Vec<String>,
}

impl Compiler {
    fn pattern(&mut self, path: String, source: &str) -> Result<Pattern, RuleError> {
        if self.sources.len() >= MAX_PATTERNS {
            return Err(error(
                path,
                format!("the rules hold more than {MAX_PATTERNS} patterns"),
            ));
        }
        if source.len() > MAX_PATTERN_BYTES {
            return Err(error(
                path,
                format!("a pattern is at most {MAX_PATTERN_BYTES} bytes"),
            ));
        }
        let regex = fancy_regex::RegexBuilder::new(source)
            .backtrack_limit(BACKTRACK_LIMIT)
            .delegate_size_limit(REGEX_SIZE_LIMIT)
            .delegate_dfa_size_limit(REGEX_DFA_LIMIT)
            .build()
            .map_err(|e| error(path, format!("the pattern doesn't compile: {e}")))?;
        self.sources.push(source.to_owned());
        Ok(Pattern { regex })
    }

    fn optional(
        &mut self,
        path: String,
        source: Option<&str>,
    ) -> Result<Option<Pattern>, RuleError> {
        // ace3 skips an empty pattern, as it skips one that isn't there
        match source.filter(|s| !s.is_empty()) {
            Some(source) => self.pattern(path, source).map(Some),
            None => Ok(None),
        }
    }
}

fn kind(path: String, name: &str) -> Result<ObservableKind, RuleError> {
    name.parse()
        .map_err(|_| error(path, format!("{name:?} isn't an observable type")))
}

impl Rules {
    /// Compiles rules, each as `ModifierSection::parsed` read it, from `source` (where they are, for the
    /// errors' paths). A rule that doesn't read or compile is skipped with why, as ace3 logs and skips
    /// it, and so is a rule whose uuid another has, and every rule past `MAX_RULES`.
    pub fn compile(
        source: &str,
        parsed: &[Result<ModifierRule, String>],
    ) -> (Rules, Vec<RuleError>) {
        Rules::default().and(source, parsed)
    }

    /// These rules followed by `parsed`'s, compiled as `compile` compiles them: a uuid one of these
    /// has is taken there too, and the bounds count both.
    pub fn and(
        mut self,
        source: &str,
        parsed: &[Result<ModifierRule, String>],
    ) -> (Rules, Vec<RuleError>) {
        let mut compiler = Compiler {
            sources: std::mem::take(&mut self.sources),
        };
        let mut uuids: BTreeSet<String> = self.rules.iter().map(|r| r.uuid.clone()).collect();
        let mut refused = Vec::new();
        for (i, rule) in parsed.iter().enumerate() {
            let at = |field: &str| {
                if field.is_empty() {
                    format!("{source}[{i}]")
                } else {
                    format!("{source}[{i}].{field}")
                }
            };
            let rule = match rule {
                Ok(rule) => rule,
                Err(why) => {
                    refused.push(error(at(""), why.clone()));
                    continue;
                }
            };
            let named = |mut e: RuleError| {
                e.rule = format!("{:?} ({})", rule.name, rule.uuid);
                e
            };
            if self.rules.len() >= MAX_RULES {
                refused.push(named(error(
                    at(""),
                    format!("past the first {MAX_RULES} rules"),
                )));
                continue;
            }
            if rule.uuid.trim().is_empty() {
                refused.push(named(error(at("uuid"), "a rule needs a uuid".to_owned())));
                continue;
            }
            if uuids.contains(&rule.uuid) {
                refused.push(named(error(
                    at("uuid"),
                    format!("another rule has the uuid {}", rule.uuid),
                )));
                continue;
            }
            // a rule's patterns count toward the bound only when the whole rule compiles
            let before = compiler.sources.len();
            match compile_rule(rule, &mut compiler, &at) {
                Ok(compiled) => {
                    uuids.insert(rule.uuid.clone());
                    for tc in &compiled.conditions.tree_conditions {
                        if !tc.details_match.is_empty() {
                            // an empty name is any module's details, so the snapshot loads them all
                            self.details_of.insert(tc.analysis_type.clone());
                        }
                    }
                    self.rules.push(compiled);
                }
                Err(e) => {
                    compiler.sources.truncate(before);
                    refused.push(named(e));
                }
            }
        }
        self.sources = compiler.sources;
        (self, refused)
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules.iter().all(|r| !r.enabled)
    }

    /// Whether an enabled rule runs in `phase`.
    pub fn has_phase(&self, phase: Phase) -> bool {
        self.rules.iter().any(|r| r.enabled && r.phase == phase)
    }

    /// The modules whose details the rules read; an empty name means every module's.
    pub fn details_of(&self) -> &BTreeSet<String> {
        &self.details_of
    }
}

fn compile_rule(
    rule: &ModifierRule,
    compiler: &mut Compiler,
    at: &dyn Fn(&str) -> String,
) -> Result<Rule, RuleError> {
    let c = &rule.conditions;
    let observable_types = c
        .observable_types
        .iter()
        .enumerate()
        .map(|(j, t)| kind(at(&format!("conditions.observable_types[{j}]")), t))
        .collect::<Result<Vec<_>, _>>()?;
    let mut tree_conditions = Vec::new();
    for (j, tc) in c.tree_conditions.iter().enumerate() {
        let at = |field: &str| at(&format!("conditions.tree_conditions[{j}].{field}"));
        let mut details_match = Vec::new();
        for (path, pattern) in &tc.details_match {
            let segments: Vec<String> = path.split('.').map(str::to_owned).collect();
            if segments.len() > MAX_PATH_SEGMENTS {
                return Err(error(
                    at("details_match"),
                    format!("a path has at most {MAX_PATH_SEGMENTS} segments"),
                ));
            }
            details_match.push((
                segments,
                compiler.pattern(at(&format!("details_match.{path}")), pattern)?,
            ));
        }
        let mut observable_match = Vec::new();
        for (name, pattern) in &tc.observable_match {
            // ace3's `getattr` of an attribute its observable lacks gives None, which matches nothing;
            // such a rule can never match, so it's skipped, and the log says why
            let Some(attribute) = Attribute::named(name) else {
                let names: Vec<&str> = Attribute::NAMES.iter().map(|&(n, _)| n).collect();
                return Err(error(
                    at(&format!("observable_match.{name}")),
                    format!("an observable_match reads {}", names.join(", ")),
                ));
            };
            observable_match.push((
                attribute,
                compiler.pattern(at(&format!("observable_match.{name}")), pattern)?,
            ));
        }
        let produces = match &tc.produces_observable {
            Some(p) => Some((
                kind(at("produces_observable.type"), &p.kind)?,
                compiler.optional(at("produces_observable.value"), p.value.as_deref())?,
            )),
            None => None,
        };
        tree_conditions.push(TreeCondition {
            analysis_type: tc.analysis_type.clone(),
            scope: tc.scope,
            details_match,
            observable_match,
            produces,
            negate: tc.negate,
            match_count: tc.match_count,
        });
    }
    let conditions = Conditions {
        alert_tags: c.alert_tags.clone(),
        alert_type: c.alert_type.clone(),
        queue: c.queue.clone(),
        observable_types,
        value_pattern: compiler
            .optional(at("conditions.value_pattern"), c.value_pattern.as_deref())?,
        file_name_pattern: compiler.optional(
            at("conditions.file_name_pattern"),
            c.file_name_pattern.as_deref(),
        )?,
        display_type_pattern: compiler.optional(
            at("conditions.display_type_pattern"),
            c.display_type_pattern.as_deref(),
        )?,
        display_value_pattern: compiler.optional(
            at("conditions.display_value_pattern"),
            c.display_value_pattern.as_deref(),
        )?,
        has_tags: c.has_tags.clone(),
        has_directives: c.has_directives.clone(),
        has_yara_meta_tags: c.has_yara_meta_tags.clone(),
        tree_conditions,
    };
    let parent_modules = conditions
        .tree_conditions
        .iter()
        .filter(|tc| tc.scope == Scope::Parent)
        .map(|tc| tc.analysis_type.clone())
        .collect();
    let has_parent_scope = conditions
        .tree_conditions
        .iter()
        .any(|tc| tc.scope == Scope::Parent);
    Ok(Rule {
        name: rule.name.clone(),
        uuid: rule.uuid.clone(),
        enabled: rule.enabled,
        phase: rule.phase,
        conditions,
        actions: rule.actions.clone(),
        parent_modules,
        has_parent_scope,
    })
}

/// A root's tree as the rules read it, and as their actions change it while they're evaluated.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    pub alert_type: Option<String>,
    pub queue: Option<String>,
    /// The root's own tags, as its submitter gave them.
    pub root_tags: Vec<String>,
    pub nodes: Vec<Node>,
    pub results: Vec<Analysis>,
}

/// An observable of the tree.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: i64,
    pub kind: ObservableKind,
    pub value: String,
    pub tags: Vec<String>,
    pub directives: Vec<String>,
    /// A file's `yara_meta` tags, of every path it has.
    pub yara_meta: Vec<String>,
    /// A file's paths, the one it's analyzed under first.
    pub paths: Vec<String>,
    pub display_type: Option<String>,
    pub display_value: Option<String>,
    /// Its time as Python's `str()` writes it (`py_time`), when it has one.
    pub time: Option<String>,
    /// The modules it's limited to and excluded from, ace3's `limited_analysis` and
    /// `excluded_analysis`.
    pub limit_modules: Vec<String>,
    pub exclude_modules: Vec<String>,
    /// The modules whose task on it ended with no result, ace3's "no analysis" sentinel.
    pub no_analysis: Vec<String>,
    /// The results on it.
    pub results: Vec<usize>,
    /// The results that added it and still hold it, by result and addition row.
    pub parents: Vec<(usize, i64)>,
    /// What rules have matched it before, ace3's `matched_rules`.
    pub matched: Vec<Value>,
    pub ignored: bool,
}

impl Node {
    fn file_names(&self) -> impl Iterator<Item = &str> {
        self.paths
            .iter()
            .map(|p| p.rsplit('/').next().unwrap_or(p))
            .filter(|_| self.kind == ObservableKind::File)
    }

    /// ace3's `Observable.display_type`: the label, else the type's default label, with the type in
    /// parentheses, else the type.
    fn display_type_text(&self) -> String {
        match self
            .display_type
            .as_deref()
            .or(self.kind.default_display_type())
        {
            Some(label) => format!("{label} ({})", self.kind.as_str()),
            None => self.kind.as_str().to_owned(),
        }
    }

    /// ace3's `Observable.display_value`: a file shows its path in place of its sha256.
    fn display_value_text(&self) -> String {
        let shown = if self.kind == ObservableKind::File {
            self.paths
                .first()
                .cloned()
                .unwrap_or_else(|| self.value.clone())
        } else {
            self.value.clone()
        };
        match &self.display_value {
            Some(label) => format!("{label} ({shown})"),
            None => shown,
        }
    }

    fn matched_uuids(&self) -> BTreeSet<String> {
        self.matched
            .iter()
            .filter_map(|m| m.get("uuid").and_then(Value::as_str).map(str::to_owned))
            .collect()
    }
}

/// A result of the tree.
#[derive(Debug, Clone)]
pub struct Analysis {
    pub id: i64,
    pub observable: usize,
    pub module: String,
    /// The observables it added and still holds, by node and addition row.
    pub added: Vec<(usize, i64)>,
    /// Its details, when a rule reads them.
    pub details: Option<Value>,
}

/// A rule that matched an observable.
#[derive(Debug, Clone, PartialEq)]
pub struct Matched {
    pub node: usize,
    pub rule: usize,
    /// What its actions did, ace3's `actions_applied`.
    pub applied: Map<String, Value>,
    /// The addition rows its `ignore` took the observable out of.
    pub removed_from: Vec<i64>,
    /// Whether its `ignore` took the observable out of the tree.
    pub ignored: bool,
}

impl Rules {
    /// Evaluates the rules of `phase` against the observable `node`, applying each match's actions to
    /// the tree, and returns the matches in order. A rule that matched the observable before, in either
    /// phase, isn't evaluated again, as in ace3.
    pub fn evaluate(
        &self,
        tree: &mut Tree,
        node: usize,
        phase: Phase,
        budget: &mut Budget,
    ) -> Result<Vec<Matched>, OverBudget> {
        let mut emitted = tree.nodes[node].matched_uuids();
        let mut matches = Vec::new();
        let mut ignores = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.enabled || rule.phase != phase || emitted.contains(&rule.uuid) {
                continue;
            }
            budget.spend(1)?;
            if !rule.conditions.evaluate(tree, node, budget)? {
                continue;
            }
            let applied = apply(&rule.actions, &mut tree.nodes[node]);
            emitted.insert(rule.uuid.clone());
            tracing::info!(rule = %rule.name, observable = tree.nodes[node].id, ?phase, "an observable modifier rule matched");
            let mut matched = Matched {
                node,
                rule: index,
                applied,
                removed_from: Vec::new(),
                ignored: false,
            };
            tree.nodes[node].matched.push(json!({
                "name": rule.name,
                "uuid": rule.uuid,
                "actions_applied": matched.applied,
            }));
            if rule.actions.ignore {
                if phase == Phase::Pre {
                    // ace3's pre phase also keeps everything else off the observable
                    add_unique(&mut tree.nodes[node].directives, ace_sdk::EXCLUDE_ALL);
                    let (removed, ignored) = ignore(rule, tree, node);
                    matched.removed_from = removed;
                    matched.ignored = ignored;
                } else {
                    ignores.push(matches.len());
                }
            }
            matches.push(matched);
        }
        // ace3's post phase takes the observable out once every rule has been evaluated
        for i in ignores {
            let (removed, ignored) = ignore(&self.rules[matches[i].rule], tree, node);
            matches[i].removed_from = removed;
            matches[i].ignored = ignored;
        }
        Ok(matches)
    }
}

/// ace3's `RuleActions.apply`: changes the observable and says what changed, in ace3's order.
fn apply(actions: &ace_sdk::hooks::RuleActions, node: &mut Node) -> Map<String, Value> {
    let mut applied = Map::new();
    if !actions.reset_analysis.is_empty() {
        let mut reset = Vec::new();
        for module in &actions.reset_analysis {
            if let Some(at) = node.no_analysis.iter().position(|m| m == module) {
                node.no_analysis.remove(at);
                reset.push(module.clone());
            }
        }
        if !reset.is_empty() {
            applied.insert("reset_analysis".to_owned(), json!(reset));
        }
    }
    if !actions.add_directives.is_empty() {
        for d in &actions.add_directives {
            add_unique(&mut node.directives, d);
        }
        applied.insert("add_directives".to_owned(), json!(actions.add_directives));
    }
    if !actions.add_tags.is_empty() {
        for t in &actions.add_tags {
            add_unique(&mut node.tags, t);
        }
        applied.insert("add_tags".to_owned(), json!(actions.add_tags));
    }
    if !actions.add_detection_points.is_empty() {
        applied.insert(
            "add_detection_points".to_owned(),
            json!(actions.add_detection_points),
        );
    }
    if !actions.exclude_analysis.is_empty() {
        for m in &actions.exclude_analysis {
            add_unique(&mut node.exclude_modules, m);
        }
        applied.insert(
            "exclude_analysis".to_owned(),
            json!(actions.exclude_analysis),
        );
    }
    if !actions.limit_analysis.is_empty() {
        for m in &actions.limit_analysis {
            add_unique(&mut node.limit_modules, m);
        }
        applied.insert("limit_analysis".to_owned(), json!(actions.limit_analysis));
    }
    if let Some(display_type) = &actions.set_display_type {
        node.display_type = Some(display_type.clone());
        applied.insert("set_display_type".to_owned(), json!(display_type));
    }
    if let Some(display_value) = &actions.set_display_value {
        node.display_value = Some(display_value.clone());
        applied.insert("set_display_value".to_owned(), json!(display_value));
    }
    if actions.ignore {
        applied.insert("ignore".to_owned(), json!(true));
    }
    applied
}

fn add_unique(items: &mut Vec<String>, item: &str) {
    if !items.iter().any(|i| i == item) {
        items.push(item.to_owned());
    }
}

/// ace3's `_apply_ignore`: with tree conditions scoped to the parent, the observable leaves the results
/// of those conditions' modules that added it, and the tree once no result holds it; without, it leaves
/// the tree. Returns the addition rows it left and whether it left the tree.
fn ignore(rule: &Rule, tree: &mut Tree, node: usize) -> (Vec<i64>, bool) {
    if !rule.has_parent_scope {
        tree.nodes[node].ignored = true;
        return (Vec::new(), true);
    }
    let mut removed = Vec::new();
    let mut parents = tree.nodes[node].parents.clone();
    for module in &rule.parent_modules {
        parents.retain(|&(result, addition)| {
            if !module.is_empty() && tree.results[result].module == *module {
                removed.push((result, addition));
                false
            } else {
                true
            }
        });
    }
    for &(result, addition) in &removed {
        tree.results[result].added.retain(|&(_, a)| a != addition);
    }
    tree.nodes[node].parents = parents;
    let ignored = tree.nodes[node].parents.is_empty();
    if ignored {
        tree.nodes[node].ignored = true;
    }
    (removed.into_iter().map(|(_, a)| a).collect(), ignored)
}

impl Conditions {
    /// ace3's `RuleConditions.evaluate`, in its order: the cheap checks first, the tree last.
    fn evaluate(&self, tree: &Tree, node: usize, budget: &mut Budget) -> Result<bool, OverBudget> {
        let n = &tree.nodes[node];
        if !self.observable_types.is_empty()
            && !self
                .observable_types
                .iter()
                .any(|&t| n.kind.is_subtype_of(t))
        {
            return Ok(false);
        }
        if !self
            .alert_tags
            .iter()
            .all(|t| tree.root_tags.iter().any(|r| r == t))
        {
            return Ok(false);
        }
        if self.alert_type.is_some() && tree.alert_type != self.alert_type {
            return Ok(false);
        }
        if self.queue.is_some() && tree.queue != self.queue {
            return Ok(false);
        }
        if !self.has_tags.iter().all(|t| n.tags.contains(t)) {
            return Ok(false);
        }
        if !self.has_directives.iter().all(|d| n.directives.contains(d)) {
            return Ok(false);
        }
        if !self
            .has_yara_meta_tags
            .iter()
            .all(|t| n.yara_meta.contains(t))
        {
            return Ok(false);
        }
        if let Some(pattern) = &self.value_pattern {
            budget.spend(1)?;
            if !pattern.test(&n.value) {
                return Ok(false);
            }
        }
        if let Some(pattern) = &self.file_name_pattern {
            let mut any = false;
            for name in n.file_names() {
                budget.spend(1)?;
                if pattern.test(name) {
                    any = true;
                    break;
                }
            }
            if !any {
                return Ok(false);
            }
        }
        if let Some(pattern) = &self.display_type_pattern {
            budget.spend(1)?;
            if !pattern.test(&n.display_type_text()) {
                return Ok(false);
            }
        }
        if let Some(pattern) = &self.display_value_pattern {
            budget.spend(1)?;
            if !pattern.test(&n.display_value_text()) {
                return Ok(false);
            }
        }
        for tc in &self.tree_conditions {
            if !tc.evaluate(tree, node, budget)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl TreeCondition {
    fn evaluate(&self, tree: &Tree, node: usize, budget: &mut Budget) -> Result<bool, OverBudget> {
        let found = self.inner(tree, node, budget)?;
        Ok(found != self.negate)
    }

    fn counted(&self, matches: u32) -> bool {
        match self.match_count {
            Some(count) => matches == count,
            None => matches > 0,
        }
    }

    fn inner(&self, tree: &Tree, node: usize, budget: &mut Budget) -> Result<bool, OverBudget> {
        // no result of the module anywhere: no walk can find one
        if !self.analysis_type.is_empty() {
            budget.spend(tree.results.len() as u64)?;
            if !tree.results.iter().any(|r| r.module == self.analysis_type) {
                return Ok(self.match_count == Some(0));
            }
        }
        // ace3 looks at descendant observables themselves, analyzed or not, for this one shape
        if self.scope == Scope::Descendants
            && !self.observable_match.is_empty()
            && self.analysis_type.is_empty()
            && self.details_match.is_empty()
        {
            let mut matches = 0;
            for other in descendant_nodes(tree, node, budget)? {
                if !self.check_observable(tree, other, budget)? {
                    continue;
                }
                matches += 1;
                if self.match_count.is_none() {
                    return Ok(true);
                }
            }
            return Ok(self.counted(matches));
        }
        let candidates: Vec<usize> = match self.scope {
            Scope::Ancestors => ancestors(tree, node, budget)?,
            Scope::Descendants => descendants(tree, node, budget)?,
            Scope::Parent => tree.nodes[node].parents.iter().map(|&(r, _)| r).collect(),
            Scope::Siblings => siblings(tree, node, budget)?,
            Scope::This => tree.nodes[node].results.clone(),
            Scope::Global => (0..tree.results.len()).collect(),
        };
        let mut matches = 0;
        for result in candidates {
            budget.spend(1)?;
            let r = &tree.results[result];
            if !self.analysis_type.is_empty() && r.module != self.analysis_type {
                continue;
            }
            if !self.details_match.is_empty() && !self.check_details(r.details.as_ref(), budget)? {
                continue;
            }
            if !self.observable_match.is_empty()
                && !self.check_observable(tree, r.observable, budget)?
            {
                continue;
            }
            if let Some((kind, value)) = &self.produces {
                let mut any = false;
                for &(added, _) in &r.added {
                    budget.spend(1)?;
                    let a = &tree.nodes[added];
                    if !a.kind.is_subtype_of(*kind) {
                        continue;
                    }
                    if let Some(value) = value
                        && !value.test(&a.value)
                    {
                        continue;
                    }
                    any = true;
                    break;
                }
                if !any {
                    continue;
                }
            }
            matches += 1;
            if self.match_count.is_none() {
                return Ok(true);
            }
        }
        Ok(self.counted(matches))
    }

    /// ace3's `_check_observable`: every attribute matches. A file has a name per path, and any of
    /// them matching is enough.
    fn check_observable(
        &self,
        tree: &Tree,
        node: usize,
        budget: &mut Budget,
    ) -> Result<bool, OverBudget> {
        let n = &tree.nodes[node];
        for (attribute, pattern) in &self.observable_match {
            let values: Vec<String> = match attribute {
                Attribute::Type => vec![n.kind.as_str().to_owned()],
                Attribute::Value => vec![n.value.clone()],
                Attribute::FileName => n.file_names().map(str::to_owned).collect(),
                Attribute::DisplayType => vec![n.display_type_text()],
                Attribute::DisplayValue => vec![n.display_value_text()],
                Attribute::Tags => vec![py_list(&n.tags)],
                Attribute::Directives => vec![py_list(&n.directives)],
                Attribute::Ignored => vec![if n.ignored { "True" } else { "False" }.to_owned()],
                Attribute::LimitedAnalysis => vec![py_list(&n.limit_modules)],
                Attribute::ExcludedAnalysis => vec![py_list(&n.exclude_modules)],
                Attribute::Time => n.time.iter().cloned().collect(),
            };
            let mut any = false;
            for value in &values {
                budget.spend(1)?;
                if pattern.test(value) {
                    any = true;
                    break;
                }
            }
            if !any {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// ace3's `_check_details`: each path's value, or any of the values it fans out to through lists,
    /// matches its pattern as Python's `str()` writes it. Empty details match nothing.
    fn check_details(
        &self,
        details: Option<&Value>,
        budget: &mut Budget,
    ) -> Result<bool, OverBudget> {
        let Some(details) = details.filter(|d| truthy(d)) else {
            return Ok(false);
        };
        for (path, pattern) in &self.details_match {
            let Some(values) = nested_values(details, path, budget)? else {
                return Ok(false);
            };
            let mut any = false;
            for value in values {
                budget.spend(1)?;
                if pattern.test(&py_str(value)) {
                    any = true;
                    break;
                }
            }
            if !any {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Python's truth of a details value: an empty dict or list, and null, are false.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Object(o) => !o.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}

/// ace3's `get_nested_value`: the path walked through dicts, applied to each element of a list it meets
/// (only to elements that are dicts), dropping nulls. None when nothing resolves.
fn nested_values<'v>(
    data: &'v Value,
    path: &[String],
    budget: &mut Budget,
) -> Result<Option<Vec<&'v Value>>, OverBudget> {
    let mut candidates = vec![data];
    let mut fanned_out = false;
    for key in path {
        let mut next = Vec::new();
        for c in candidates {
            budget.spend(1)?;
            match c {
                Value::Array(items) => {
                    fanned_out = true;
                    for item in items {
                        budget.spend(1)?;
                        if let Some(v) = item.as_object().and_then(|o| o.get(key))
                            && !v.is_null()
                        {
                            next.push(v);
                        }
                    }
                }
                Value::Object(o) => {
                    if let Some(v) = o.get(key)
                        && !v.is_null()
                    {
                        next.push(v);
                    }
                }
                _ => {}
            }
        }
        if next.is_empty() {
            return Ok(None);
        }
        candidates = next;
    }
    // ace3 tests each element of a list it reached through a list, and a value reached through dicts
    // only as itself, list or not
    if !fanned_out
        && candidates.len() == 1
        && let Value::Array(items) = candidates[0]
    {
        return Ok(Some(items.iter().collect()));
    }
    Ok(Some(candidates))
}

/// Python's `str()` of a list of strings: `['a', 'b']`.
fn py_list(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|i| ace_pycompat::repr::repr(i)).collect();
    format!("[{}]", parts.join(", "))
}

/// Python's `str()` of a timezone-aware `datetime`: `2026-11-24 14:28:25+00:00`, with the microseconds
/// when there are any.
pub fn py_time(time: chrono::DateTime<chrono::Utc>) -> String {
    use chrono::Timelike;
    if time.nanosecond() / 1000 == 0 {
        time.format("%Y-%m-%d %H:%M:%S+00:00").to_string()
    } else {
        time.format("%Y-%m-%d %H:%M:%S%.6f+00:00").to_string()
    }
}

/// Python's `str()` of a JSON value: a string as itself, `True`, an int's digits, a float's repr, and a
/// list or dict as Python's repr of it.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        _ => py_repr(value),
    }
}

fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => i.to_string(),
            (_, Some(u), _) => u.to_string(),
            (_, _, Some(f)) => ace_pycompat::json::float_repr(f),
            _ => n.to_string(),
        },
        Value::String(s) => ace_pycompat::repr::repr(s),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(o) => {
            let parts: Vec<String> = o
                .iter()
                .map(|(k, v)| format!("{}: {}", ace_pycompat::repr::repr(k), py_repr(v)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

/// The results above the observable: those that added it, those that added theirs, and so on.
fn ancestors(tree: &Tree, node: usize, budget: &mut Budget) -> Result<Vec<usize>, OverBudget> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut stack: Vec<usize> = tree.nodes[node].parents.iter().map(|&(r, _)| r).collect();
    while let Some(result) = stack.pop() {
        budget.spend(1)?;
        if !seen.insert(result) {
            continue;
        }
        out.push(result);
        stack.extend(
            tree.nodes[tree.results[result].observable]
                .parents
                .iter()
                .map(|&(r, _)| r),
        );
    }
    Ok(out)
}

/// The results below the observable: those on what its results added, and so on. Its own results
/// aren't among them.
fn descendants(tree: &Tree, node: usize, budget: &mut Budget) -> Result<Vec<usize>, OverBudget> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut stack = Vec::new();
    for &own in &tree.nodes[node].results {
        for &(child, _) in &tree.results[own].added {
            stack.extend(tree.nodes[child].results.iter().copied());
        }
    }
    while let Some(result) = stack.pop() {
        budget.spend(1)?;
        if !seen.insert(result) {
            continue;
        }
        out.push(result);
        for &(child, _) in &tree.results[result].added {
            stack.extend(tree.nodes[child].results.iter().copied());
        }
    }
    Ok(out)
}

/// The observables below the observable.
fn descendant_nodes(
    tree: &Tree,
    node: usize,
    budget: &mut Budget,
) -> Result<Vec<usize>, OverBudget> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut stack = Vec::new();
    for &own in &tree.nodes[node].results {
        stack.extend(tree.results[own].added.iter().map(|&(n, _)| n));
    }
    while let Some(other) = stack.pop() {
        budget.spend(1)?;
        if !seen.insert(other) {
            continue;
        }
        out.push(other);
        for &result in &tree.nodes[other].results {
            stack.extend(tree.results[result].added.iter().map(|&(n, _)| n));
        }
    }
    Ok(out)
}

/// Every result on the observables whose results added this one, those results included.
fn siblings(tree: &Tree, node: usize, budget: &mut Budget) -> Result<Vec<usize>, OverBudget> {
    let mut seen_nodes = HashSet::new();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for &(parent, _) in &tree.nodes[node].parents {
        let parent_node = tree.results[parent].observable;
        if !seen_nodes.insert(parent_node) {
            continue;
        }
        for &result in &tree.nodes[parent_node].results {
            budget.spend(1)?;
            if seen.insert(result) {
                out.push(result);
            }
        }
    }
    Ok(out)
}

/// The matched rules of an observable modifier result's details, ace3's `matched_rules`.
pub fn matched_rules(details: &Value) -> Vec<Value> {
    details
        .get("matched_rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// ace3's summary: "Applied 2 rule(s): a, b".
pub fn summary(matched: &[Value]) -> Option<String> {
    if matched.is_empty() {
        return None;
    }
    let names: Vec<&str> = matched
        .iter()
        .map(|m| m.get("name").and_then(Value::as_str).unwrap_or(""))
        .collect();
    Some(format!(
        "Applied {} rule(s): {}",
        matched.len(),
        names.join(", ")
    ))
}

/// The modules each enabled rule's `limit_analysis` names, by rule, for `ace serve` to warn about one the
/// binary hasn't (PLAN.md decision 59): a file such a rule limits isn't analyzed by anything.
pub fn limited_to(rules: &Rules) -> BTreeMap<&str, BTreeSet<&str>> {
    let mut named: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for rule in rules.rules.iter().filter(|r| r.enabled) {
        if !rule.actions.limit_analysis.is_empty() {
            named
                .entry(rule.name.as_str())
                .or_default()
                .extend(rule.actions.limit_analysis.iter().map(String::as_str));
        }
    }
    named
}

/// The modules each rule names in an action, by rule, for the core to warn about one it doesn't know.
pub fn named_modules(rules: &Rules) -> BTreeMap<&str, BTreeSet<&str>> {
    let mut named: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for rule in &rules.rules {
        let a = &rule.actions;
        let modules = a
            .exclude_analysis
            .iter()
            .chain(&a.limit_analysis)
            .chain(&a.reset_analysis)
            .map(String::as_str)
            .chain(
                rule.conditions
                    .tree_conditions
                    .iter()
                    .map(|tc| tc.analysis_type.as_str())
                    .filter(|m| !m.is_empty()),
            );
        named.entry(rule.name.as_str()).or_default().extend(modules);
    }
    named
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(yaml: &str) -> Rules {
        let section: ace_sdk::hooks::ModifierSection =
            serde_json::from_value(serde_yaml_like(yaml)).expect("a rules section");
        let (rules, refused) = Rules::compile("rules", &section.parsed());
        assert!(refused.is_empty(), "{refused:?}");
        rules
    }

    fn serde_yaml_like(yaml: &str) -> Value {
        // the overlay's own parser, through a section that holds nothing else
        let text = format!("modules:\n  x:\n    settings:\n{}", indent(yaml, 6));
        let overlay = ace_sdk::Overlay::from_yaml(&text).expect("parses");
        overlay.modules["x"].settings.clone().expect("settings")
    }

    fn indent(text: &str, by: usize) -> String {
        text.lines()
            .map(|l| format!("{}{l}\n", " ".repeat(by)))
            .collect()
    }

    fn node(id: i64, kind: ObservableKind, value: &str) -> Node {
        Node {
            id,
            kind,
            value: value.to_owned(),
            tags: Vec::new(),
            directives: Vec::new(),
            yara_meta: Vec::new(),
            paths: Vec::new(),
            display_type: None,
            display_value: None,
            time: None,
            limit_modules: Vec::new(),
            exclude_modules: Vec::new(),
            no_analysis: Vec::new(),
            results: Vec::new(),
            parents: Vec::new(),
            matched: Vec::new(),
            ignored: false,
        }
    }

    /// email file 0 -> email_analyzer result 0 -> url 1 -> crawl result 1 -> file 2 (page.html)
    /// -> file_type result 2; file 0 -> file_type result 3.
    fn tree() -> Tree {
        let mut tree = Tree::default();
        let mut email = node(1, ObservableKind::File, "e");
        email.paths = vec!["email.rfc822".to_owned()];
        let url = node(2, ObservableKind::Url, "http://x.example/a");
        let mut page = node(3, ObservableKind::File, "p");
        page.paths = vec!["dir/page.html".to_owned()];
        tree.nodes = vec![email, url, page];
        let result = |id, observable, module: &str, details: Value| Analysis {
            id,
            observable,
            module: module.to_owned(),
            added: Vec::new(),
            details: Some(details),
        };
        tree.results = vec![
            result(
                10,
                0,
                "email_analyzer",
                json!({"email": {"from": "soc@third.example"}}),
            ),
            result(
                11,
                1,
                "crawl",
                json!({"hits": [{"rule": "a"}, {"rule": "b"}, 3]}),
            ),
            result(12, 2, "file_type", json!({"mime": "text/html"})),
            result(13, 0, "file_type", json!({"mime": "message/rfc822"})),
        ];
        let link = |tree: &mut Tree, result: usize, node: usize, row: i64| {
            tree.results[result].added.push((node, row));
            tree.nodes[node].parents.push((result, row));
        };
        link(&mut tree, 0, 1, 100);
        link(&mut tree, 1, 2, 101);
        for (i, r) in tree.results.clone().iter().enumerate() {
            tree.nodes[r.observable].results.push(i);
        }
        tree
    }

    fn matches(rules: &Rules, tree: &mut Tree, node: usize) -> Vec<String> {
        let mut budget = Budget::new(STEP_BUDGET);
        rules
            .evaluate(tree, node, Phase::Post, &mut budget)
            .expect("in budget")
            .into_iter()
            .map(|m| rules.rules()[m.rule].name.clone())
            .collect()
    }

    #[test]
    fn each_scope_finds_what_ace3_s_walk_finds() {
        let rules = rules(
            r#"
rules:
  - {name: ancestors, uuid: a1, conditions: {tree_conditions: [{analysis_type: email_analyzer, details_match: {email.from: '@third\.example$'}}]}}
  - {name: parent, uuid: a2, conditions: {tree_conditions: [{analysis_type: crawl, scope: parent}]}}
  - {name: siblings, uuid: a3, conditions: {tree_conditions: [{analysis_type: file_type, scope: siblings, details_match: {mime: rfc822}}]}}
  - {name: self, uuid: a4, conditions: {tree_conditions: [{analysis_type: file_type, scope: self, details_match: {mime: html}}]}}
  - {name: descendants, uuid: a5, conditions: {tree_conditions: [{analysis_type: file_type, scope: descendants}]}}
  - {name: descendant files, uuid: a6, conditions: {tree_conditions: [{scope: descendants, observable_match: {file_name: '\.html$'}}]}}
  - {name: global count, uuid: a7, conditions: {tree_conditions: [{analysis_type: file_type, scope: global, match_count: 2}]}}
  - {name: none of a module, uuid: a8, conditions: {tree_conditions: [{analysis_type: sandbox, match_count: 0}]}}
  - {name: negated, uuid: a9, conditions: {tree_conditions: [{analysis_type: crawl, scope: self, negate: true}]}}
  - {name: fans out, uuid: b1, conditions: {tree_conditions: [{analysis_type: crawl, scope: self, details_match: {hits.rule: '^b$'}}]}}
  - {name: produces, uuid: b2, conditions: {tree_conditions: [{scope: self, produces_observable: {type: file, value: '^p$'}}]}}
"#,
        );
        let mut t = tree();
        // the page: below the email and the crawl
        assert_eq!(
            matches(&rules, &mut t, 2),
            [
                "ancestors",
                "parent",
                "self",
                "global count",
                "none of a module",
                "negated"
            ]
        );
        let mut t = tree();
        // the url: its parent's file is the email, whose file_type says rfc822
        assert_eq!(
            matches(&rules, &mut t, 1),
            [
                "ancestors",
                "siblings",
                "descendants",
                "descendant files",
                "global count",
                "none of a module",
                "fans out",
                "produces"
            ]
        );
    }

    #[test]
    fn actions_change_the_tree_for_the_rules_after_them_and_a_match_isn_t_repeated() {
        let rules = rules(
            r#"
rules:
  - {name: tag, uuid: t1, conditions: {observable_types: [url]}, actions: {add_tags: [seen], set_display_type: Link, reset_analysis: [crawl, other]}}
  - {name: needs the tag, uuid: t2, conditions: {has_tags: [seen], display_type_pattern: '^Link \(url\)$'}, actions: {add_directives: [crawl]}}
  - {name: off, uuid: t3, enabled: false}
  - {name: pre, uuid: t4, phase: pre}
"#,
        );
        let mut t = tree();
        t.nodes[1].no_analysis.push("crawl".to_owned());
        let mut budget = Budget::new(STEP_BUDGET);
        let found = rules
            .evaluate(&mut t, 1, Phase::Post, &mut budget)
            .expect("in budget");
        assert_eq!(found.len(), 2);
        assert_eq!(
            Value::Object(found[0].applied.clone()),
            json!({"reset_analysis": ["crawl"], "add_tags": ["seen"], "set_display_type": "Link"})
        );
        assert_eq!(t.nodes[1].directives, ["crawl"]);
        assert_eq!(t.nodes[1].matched.len(), 2);
        assert!(
            rules
                .evaluate(&mut t, 1, Phase::Post, &mut budget)
                .expect("in budget")
                .is_empty(),
            "matched once, ever"
        );
        assert_eq!(
            summary(&t.nodes[1].matched).as_deref(),
            Some("Applied 2 rule(s): tag, needs the tag")
        );
    }

    #[test]
    fn ignore_takes_an_observable_from_the_parents_a_rule_names() {
        let rules = rules(
            r#"
rules:
  - {name: from crawl, uuid: i1, conditions: {tree_conditions: [{analysis_type: crawl, scope: parent}]}, actions: {ignore: true}}
  - {name: everywhere, uuid: i2, conditions: {observable_types: [url]}, actions: {ignore: true}}
"#,
        );
        let mut t = tree();
        // a second parent keeps the page in the tree
        t.results[3].added.push((2, 102));
        t.nodes[2].parents.push((3, 102));
        let mut budget = Budget::new(STEP_BUDGET);
        let found = rules
            .evaluate(&mut t, 2, Phase::Post, &mut budget)
            .expect("in budget");
        assert_eq!(found[0].removed_from, [101]);
        assert!(!found[0].ignored && !t.nodes[2].ignored);
        assert!(t.results[1].added.is_empty());
        let found = rules
            .evaluate(&mut t, 1, Phase::Pre, &mut budget)
            .expect("in budget");
        assert!(found.is_empty(), "both are post rules");
        let found = rules
            .evaluate(&mut t, 1, Phase::Post, &mut budget)
            .expect("in budget");
        assert!(found[0].ignored && t.nodes[1].ignored);
    }

    #[test]
    fn details_read_as_python_s_str_writes_them() {
        assert_eq!(py_str(&json!("a")), "a");
        assert_eq!(py_str(&json!(true)), "True");
        assert_eq!(py_str(&json!(3)), "3");
        assert_eq!(py_str(&json!(1.5)), "1.5");
        assert_eq!(
            py_str(&json!({"a": [1, "b", null, false]})),
            "{'a': [1, 'b', None, False]}"
        );
        let rules = rules(
            r#"
rules:
  - {name: dict, uuid: d1, conditions: {tree_conditions: [{analysis_type: email_analyzer, scope: global, details_match: {email: "^\\{'from': 'soc@"}}]}}
"#,
        );
        let mut t = tree();
        assert_eq!(matches(&rules, &mut t, 0), ["dict"]);
    }

    #[test]
    fn an_evaluation_stops_at_its_budget() {
        // a chain of 50,000 results, each adding the next observable, and a rule that walks it
        let rules = rules(
            r#"
rules:
  - {name: deep, uuid: x1, conditions: {tree_conditions: [{analysis_type: nothing_has_this, scope: ancestors, negate: true}, {analysis_type: m, scope: ancestors, match_count: 7}]}}
"#,
        );
        let mut t = Tree::default();
        let n = 50_000;
        for i in 0..n {
            t.nodes
                .push(node(i, ObservableKind::Fqdn, &format!("h{i}")));
            t.results.push(Analysis {
                id: i,
                observable: i as usize,
                module: "m".to_owned(),
                added: Vec::new(),
                details: None,
            });
            t.nodes[i as usize].results.push(i as usize);
            if i > 0 {
                t.results[(i - 1) as usize].added.push(((i) as usize, i));
                t.nodes[i as usize].parents.push(((i - 1) as usize, i));
            }
        }
        let mut budget = Budget::new(1_000_000);
        let mut over = false;
        for node in 0..n as usize {
            if rules
                .evaluate(&mut t, node, Phase::Post, &mut budget)
                .is_err()
            {
                over = true;
                break;
            }
        }
        assert!(over, "a quadratic walk spends the budget and stops");
    }

    /// Python's `re` patterns compile as ace3's do: look-around and backreferences included (the
    /// owner's decision of 2026-11-24, `fancy-regex`).
    #[test]
    fn look_around_and_backreferences_compile_and_match_as_python_s() {
        let rules = rules(
            r#"
rules:
  - {name: ahead, uuid: l1, conditions: {value_pattern: '\.example/(?=[a-z]{1}$)(?=[a-z]*[a-z])[a-z]{1}(?=[/?#]|$)'}}
  - {name: not google, uuid: l2, conditions: {value_pattern: '(?i)^(?!https?://accounts\.google\.com/).*x\.example'}}
  - {name: twice, uuid: l3, conditions: {value_pattern: '(\w)\1'}}
"#,
        );
        let mut t = tree();
        // `tt` in http is a letter twice
        assert_eq!(matches(&rules, &mut t, 1), ["ahead", "not google", "twice"]);
        let mut t = tree();
        t.nodes[1].value = "https://accounts.google.com/x.example/aa".to_owned();
        assert_eq!(matches(&rules, &mut t, 1), ["twice"]);
    }

    /// ace3 tests `str()` of whatever `getattr` gives: a list as Python writes one, a bool as `True`,
    /// a time as a `datetime`'s.
    #[test]
    fn observable_match_reads_what_ace3_s_getattr_reads() {
        let rules = rules(
            r#"
rules:
  - {name: tags, uuid: o1, conditions: {tree_conditions: [{scope: global, observable_match: {type: url, tags: new_sender}}]}}
  - {name: directives, uuid: o2, conditions: {tree_conditions: [{scope: global, observable_match: {directives: "^\\['crawl'\\]$"}}]}}
  - {name: ignored, uuid: o3, conditions: {tree_conditions: [{scope: global, observable_match: {type: url, ignored: '^False$'}}]}}
  - {name: limited, uuid: o4, conditions: {tree_conditions: [{scope: global, observable_match: {limited_analysis: "'crawl'"}}]}}
  - {name: excluded, uuid: o5, conditions: {tree_conditions: [{scope: global, observable_match: {excluded_analysis: '^\[\]$'}}]}}
  - {name: time, uuid: o6, conditions: {tree_conditions: [{scope: global, observable_match: {time: '^2026-11-24 14:28:25\+00:00$'}}]}}
  - {name: no time, uuid: o7, conditions: {tree_conditions: [{scope: global, observable_match: {type: file, time: '.*'}}]}}
"#,
        );
        let mut t = tree();
        let url = &mut t.nodes[1];
        url.tags = vec!["x".to_owned(), "new_sender".to_owned()];
        url.directives = vec!["crawl".to_owned()];
        url.limit_modules = vec!["crawl".to_owned()];
        url.time = Some(py_time("2026-11-24T14:28:25Z".parse().expect("a time")));
        // the email file's results, global: the url is the one observable a result is on with these
        assert_eq!(
            matches(&rules, &mut t, 0),
            [
                "tags",
                "directives",
                "ignored",
                "limited",
                "excluded",
                "time"
            ]
        );
        assert_eq!(
            py_time("2026-11-24T14:28:25.5Z".parse().expect("a time")),
            "2026-11-24 14:28:25.500000+00:00"
        );
    }

    /// A test past the backtracking bound gives up and counts as not matching, where Python's `re`
    /// would run on, and the rest of the rules still run.
    #[test]
    fn a_pattern_past_its_backtracking_bound_counts_as_not_matching() {
        let rules = rules(
            r#"
rules:
  - {name: explodes, uuid: b1, conditions: {value_pattern: '^(a|b|ab)*(?>c)'}}
  - {name: after it, uuid: b2, conditions: {observable_types: [url]}}
"#,
        );
        let mut t = tree();
        // the alternatives split the run every way before the `d` refuses each, past the bound
        let text = format!("{}dc", "ab".repeat(28));
        t.nodes[1].value = text.clone();
        assert_eq!(matches(&rules, &mut t, 1), ["after it"]);
        // it gave up, rather than finding no match
        let mut compiler = Compiler {
            sources: Vec::new(),
        };
        let pattern = compiler
            .pattern("p".to_owned(), r"^(a|b|ab)*(?>c)")
            .expect("compiles");
        assert!(pattern.regex.is_match(&text).is_err(), "past the bound");
        assert!(!pattern.test(&text));
    }

    /// A rule ace3 would log and skip is skipped with why, and the rules around it compile (the
    /// owner's decision of 2026-11-24).
    #[test]
    fn a_rule_that_doesn_t_compile_is_skipped_and_the_others_kept() {
        let section: ace_sdk::hooks::ModifierSection = serde_json::from_value(serde_yaml_like(
            r#"
rules:
  - {name: first, uuid: k1}
  - {name: no uuid}
  - {name: bad pattern, uuid: k2, conditions: {value_pattern: '('}}
  - {name: unknown type, uuid: k3, conditions: {observable_types: [nope]}}
  - {name: unknown key, uuid: k4, actions: {explode: true}}
  - {name: again, uuid: k1}
  - {name: last, uuid: k5, conditions: {value_pattern: '(?=x)'}}
"#,
        ))
        .expect("a section: each rule is read on its own");
        let (rules, refused) = Rules::compile("rules", &section.parsed());
        let kept: Vec<&str> = rules.rules().iter().map(|r| r.name.as_str()).collect();
        assert_eq!(kept, ["first", "last"]);
        let why: Vec<String> = refused
            .iter()
            .map(|e| format!("{e} [{}]", e.rule))
            .collect();
        assert_eq!(why.len(), 5, "{why:#?}");
        assert!(
            why[0].starts_with("rules[1]: missing field `uuid`"),
            "{why:#?}"
        );
        assert!(
            why[1].starts_with("rules[2].conditions.value_pattern: the pattern doesn't compile")
        );
        assert!(why[1].ends_with("[\"bad pattern\" (k2)]"));
        assert!(why[2].contains("\"nope\" isn't an observable type"));
        assert!(why[3].contains("explode"));
        assert!(why[4].starts_with("rules[5].uuid: another rule has the uuid k1"));
        // the overlay's rules come first, and a file's uuid can't take one of theirs
        let (both, refused) = rules.and("file.yaml", &section.parsed()[..1]);
        assert_eq!(both.rules().len(), 2);
        assert_eq!(refused[0].path, "file.yaml[0].uuid");
    }
}
