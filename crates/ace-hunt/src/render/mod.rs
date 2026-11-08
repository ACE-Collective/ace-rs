//! A hunt's templates rendered as ace3 renders them (PLAN.md 6.3).
//!
//! ace3 renders a hunt's name, tags, pivot links, playbook URL, dedup key, summary details and
//! observable mappings with Jinja2 3.1 against an event (`saq/query/summary_detail_rendering.py`
//! and `template_rendering.py`): a `SandboxedEnvironment` with Jinja2's defaults (no autoescape,
//! no trimming, the one trailing newline dropped, no extensions) and one filter of ace3's own,
//! `fromjson`, either with the default Undefined (permissive) or with StrictUndefined. Its entry
//! points are [`Renderer::jinja`] (`render_jinja_template`), [`Renderer::event`]
//! (`render_event_template`, which nests the event's dotted keys first) and
//! [`Renderer::events_multi`] (`render_event_templates_multi`, which renders once per item of
//! each list the templates read); the hunter's own uses of them are the methods after those.
//!
//! The engine is minijinja, with the template's tree rewritten so it behaves as Python does
//! ([`rewrite`]): values are Python's ([`py`]), with their operators ([`ops`]), methods
//! ([`methods`]), Jinja2's filters and tests ([`filters`]), and printing as `str()`. Globals are
//! Jinja2's `range` (capped at 100,000 items, as the sandbox caps it), `dict`, `namespace`,
//! `cycler` and `joiner` ([`globals`]); `lipsum`, which makes random text, isn't here, and a
//! template calling it fails as an undefined call does. ace3's Jinja has no loader, so `{% include %}`, `{% import %}`
//! and `{% extends %}` fail in both; minijinja also refuses `{% block %}`, which no hunt uses.
//!
//! ace3's renders have no bounds. Here each is bounded ([`Limits`]): minijinja's fuel counts the
//! instructions a render runs, a macro nests at most 82 deep (Python lets ace3's reach about 190), a render writes at most 1 MiB and
//! builds no string longer, a list or dict holds at most 100,000 items, and one multi render is at
//! most 1,000 combinations of its lists' items. A render past a bound fails as a template error
//! does, which is how ace3 treats any exception.

pub mod compare;
pub mod event;
pub mod filters;
pub mod globals;
pub mod json;
pub mod methods;
pub mod ops;
pub mod py;
pub mod rewrite;

use std::sync::Arc;

use minijinja::machinery::{self, CodeGenerator};
use minijinja::value::{Enumerator, Object, ObjectRepr, Value};
use minijinja::{AutoEscape, Environment, Error, ErrorKind, UndefinedBehavior};

use crate::model::SummaryDetail;
use crate::value::{Map, Value as Loaded};
use py::{Kind, PyDict, kind};
use rewrite::Segment;

/// The bounds on one render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// minijinja's fuel: about one unit per instruction run.
    pub fuel: u64,
    /// The bytes a render writes, and the longest string it builds.
    pub output_bytes: usize,
    /// The items a list or dict a render builds holds.
    pub items: usize,
    /// minijinja's recursion limit, which macro calls, loops and blocks count against. 500 is its
    /// most without the stacker feature, and lets a macro call itself 82 deep, where ace3's Python
    /// gets to about 190 before its RecursionError; no hunt template recurses.
    pub recursion: usize,
    /// The renders one multi render makes, one per combination of its lists' items.
    pub combinations: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            fuel: 5_000_000,
            output_bytes: 1 << 20,
            items: 100_000,
            recursion: 500,
            combinations: 1_000,
        }
    }
}

/// What rendering a template gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rendered {
    Text(String),
    /// Under StrictUndefined, the template read something the event doesn't have: ace3's
    /// `UndefinedError`, which its callers take as a missing field.
    Undefined(String),
    /// The template didn't parse or raised: ace3 logs it and gets `None`.
    Failed(String),
}

impl Rendered {
    pub fn text(&self) -> Option<&str> {
        match self {
            Rendered::Text(t) => Some(t),
            _ => None,
        }
    }
}

/// An UndefinedError out of a multi render, which ends it, as ace3's propagates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undefined(pub String);

/// The bounds of the render running on this thread, and what it has written.
pub mod budget {
    use std::cell::Cell;

    use minijinja::{Error, ErrorKind};

    use super::Limits;

    thread_local! {
        static STATE: Cell<(Limits, usize)> = Cell::new((Limits::default(), 0));
    }

    fn limit(what: &str) -> Error {
        Error::new(
            ErrorKind::InvalidOperation,
            format!("ace4 limit: the render's {what} is past its bound"),
        )
    }

    /// A string of `len` bytes being built.
    pub fn string(len: usize) -> Result<(), Error> {
        if len > STATE.with(Cell::get).0.output_bytes {
            return Err(limit("string"));
        }
        Ok(())
    }

    /// A list or dict of `n` items being built.
    pub fn items(n: usize) -> Result<(), Error> {
        if n > STATE.with(Cell::get).0.items {
            return Err(limit("list"));
        }
        Ok(())
    }

    /// `n` more bytes written.
    pub fn emit(n: usize) -> Result<(), Error> {
        STATE.with(|s| {
            let (limits, written) = s.get();
            let written = written.saturating_add(n);
            s.set((limits, written));
            if written > limits.output_bytes {
                Err(limit("output"))
            } else {
                Ok(())
            }
        })
    }

    /// Starts counting a render, until the guard drops.
    pub fn start(limits: Limits) -> Guard {
        let previous = STATE.with(|s| s.replace((limits, 0)));
        Guard(previous)
    }

    pub struct Guard((Limits, usize));

    impl Drop for Guard {
        fn drop(&mut self) {
            STATE.with(|s| s.set(self.0));
        }
    }
}

/// Which arms of a template's `{% if %}`s and inline ifs its renders take, for the comparison to
/// say how much of each template its events reach. Off unless [`coverage::begin`] turns it on.
pub mod coverage {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeSet;

    thread_local! {
        static ON: Cell<bool> = const { Cell::new(false) };
        static ARMS: RefCell<BTreeSet<u32>> = const { RefCell::new(BTreeSet::new()) };
        static TAKEN: RefCell<BTreeSet<u32>> = const { RefCell::new(BTreeSet::new()) };
    }

    /// Starts counting the renders of one template on this thread.
    pub fn begin() {
        ON.with(|on| on.set(true));
        ARMS.with(|a| a.borrow_mut().clear());
        TAKEN.with(|t| t.borrow_mut().clear());
    }

    /// Stops, giving how many arms the renders since [`begin`] took, of how many.
    pub fn end() -> (usize, usize) {
        ON.with(|on| on.set(false));
        let arms = ARMS.with(|a| a.borrow().clone());
        let taken = TAKEN.with(|t| t.borrow().intersection(&arms).count());
        (taken, arms.len())
    }

    pub(super) fn on() -> bool {
        ON.with(Cell::get)
    }

    pub(super) fn declare(id: u32) {
        ARMS.with(|a| a.borrow_mut().insert(id));
    }

    pub(super) fn taken(id: u32) {
        TAKEN.with(|t| t.borrow_mut().insert(id));
    }
}

/// The context a template renders in: the event's keys, and nothing named as the rewritten
/// tree's functions are, which no template can name.
#[derive(Debug)]
struct Root(Arc<PyDict>);

impl Object for Root {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Map
    }
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        if key.as_str().is_some_and(|k| k.starts_with('%')) {
            return None;
        }
        self.0.lookup(key).ok().flatten()
    }
    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Values(self.0.entries().into_iter().map(|(k, _)| k).collect())
    }
}

fn environment(strict: bool, limits: &Limits) -> Environment<'static> {
    let mut env = Environment::empty();
    env.set_undefined_behavior(if strict {
        UndefinedBehavior::Strict
    } else {
        UndefinedBehavior::Lenient
    });
    env.set_fuel(Some(limits.fuel));
    env.set_recursion_limit(limits.recursion);
    for &(name, f) in filters::filters() {
        env.add_filter(name, f);
    }
    for &(name, f) in filters::tests() {
        env.add_test(name, f);
    }
    env.add_function("range", ops::range);
    env.add_function("dict", ops::dict_global);
    env.add_function("namespace", minijinja::functions::namespace);
    env.add_function("cycler", globals::cycler);
    env.add_function("joiner", globals::joiner);
    env.add_function("%add", ops::add);
    env.add_function("%sub", ops::sub);
    env.add_function("%mul", ops::mul);
    env.add_function("%div", ops::div);
    env.add_function("%floordiv", ops::floordiv);
    env.add_function("%mod", ops::rem);
    env.add_function("%pow", ops::pow);
    env.add_function("%neg", ops::neg);
    env.add_function("%concat", ops::concat);
    env.add_function("%compare", ops::compare_chain);
    env.add_function("%getattr", ops::getattr);
    env.add_function("%getitem", ops::getitem);
    env.add_function("%slice", ops::slice);
    env.add_function("%iter", ops::iter_check);
    env.add_function("%cover", |id: u32| {
        coverage::taken(id);
        String::new()
    });
    env.add_function("%covered", |id: u32, v: Value| {
        coverage::taken(id);
        v
    });
    env.add_function("%list", ops::list);
    env.add_function("%tuple", ops::tuple);
    env.add_function("%dict", ops::dict);
    env.add_function("%lenient_undefined", || {
        Value::from_object(py::LenientUndefined)
    });
    env.set_unknown_method_callback(methods::call_method);
    env.set_formatter(|out, state, value| {
        let text = match kind(value) {
            Kind::Undefined => {
                ops::check_strict(state, value)?;
                return Ok(());
            }
            Kind::Str(s) => s.to_owned(),
            _ => py::str_of(value),
        };
        // `{% autoescape true %}` escapes what isn't marked safe
        let text = if matches!(state.auto_escape(), AutoEscape::Html) && !value.is_safe() {
            filters::html_escape(&text)
        } else {
            text
        };
        budget::emit(text.len())?;
        out.write_str(&text)
            .map_err(|_| Error::new(ErrorKind::WriteFailure, "the output can't be written"))
    });
    env
}

/// Renders ace3's hunt templates.
pub struct Renderer {
    permissive: Environment<'static>,
    strict: Environment<'static>,
    limits: Limits,
}

impl Default for Renderer {
    fn default() -> Renderer {
        Renderer::new(Limits::default())
    }
}

/// Jinja2's lexer turns `\r\n` and `\r` into `\n` in a template's text and strings.
fn normalize_newlines(template: &str) -> String {
    template.replace("\r\n", "\n").replace('\r', "\n")
}

/// A template parsed as Jinja2 parses it, or the syntax error.
/// The paths ace3 finds in a template (`_extract_paths`), or its syntax error.
pub fn paths(template: &str) -> Result<Vec<Vec<Segment>>, String> {
    let source = normalize_newlines(template);
    let ast =
        machinery::parse(&source, "<template>", Default::default()).map_err(|e| e.to_string())?;
    Ok(rewrite::paths(&ast))
}

impl Renderer {
    pub fn new(limits: Limits) -> Renderer {
        Renderer {
            permissive: environment(false, &limits),
            strict: environment(true, &limits),
            limits,
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    fn render(&self, template: &str, root: &Value, strict: bool) -> Rendered {
        let env = if strict {
            &self.strict
        } else {
            &self.permissive
        };
        let source = normalize_newlines(template);
        let ast = match machinery::parse(&source, "<template>", Default::default()) {
            Ok(ast) => ast,
            Err(e) => return Rendered::Failed(format!("TemplateSyntaxError: {e}")),
        };
        let filter_names: Vec<&str> = filters::filters().iter().map(|(n, _)| *n).collect();
        let test_names: Vec<&str> = filters::tests().iter().map(|(n, _)| *n).collect();
        let check = rewrite::Check {
            filters: &|n| filter_names.contains(&n),
            tests: &|n| test_names.contains(&n),
            cover: coverage::on(),
        };
        let ast = match rewrite::rebuild(&ast, &check) {
            Ok(ast) => ast,
            Err(e) => return Rendered::Failed(format!("TemplateSyntaxError: {e}")),
        };
        let mut generator = CodeGenerator::new("<template>", &source);
        generator.compile_stmt(&ast);
        let (instructions, blocks) = generator.finish();
        let _guard = budget::start(self.limits);
        let mut text = String::new();
        let mut out = machinery::make_string_output(&mut text);
        let result = machinery::eval(
            env,
            &instructions,
            root.clone(),
            &blocks,
            &mut out,
            AutoEscape::None,
        );
        match result {
            Ok(_) => Rendered::Text(text),
            Err(e) => match e.kind() {
                ErrorKind::UndefinedError
                | ErrorKind::UnknownMethod
                | ErrorKind::UnknownFunction
                    if strict =>
                {
                    Rendered::Undefined(e.to_string())
                }
                _ => Rendered::Failed(e.to_string()),
            },
        }
    }

    fn root(context: &Map) -> Value {
        match kind(&py::to_template(&Loaded::Map(context.clone()))) {
            Kind::Dict(d) => Value::from_object(Root(d)),
            _ => Value::from(()),
        }
    }

    /// `render_jinja_template(template, context, strict)`.
    pub fn jinja(&self, template: &str, context: &Map, strict: bool) -> Rendered {
        self.render(template, &Self::root(context), strict)
    }

    /// `render_event_template(template, event, strict)`: the event's dotted keys nested first.
    pub fn event(&self, template: &str, event: &Map, strict: bool) -> Rendered {
        self.jinja(template, &event::expand_dotted_keys(event), strict)
    }

    /// `render_event_template_multi(template, event, strict)`.
    pub fn event_multi(
        &self,
        template: &str,
        event: &Map,
        strict: bool,
    ) -> Result<Vec<String>, Undefined> {
        Ok(self
            .events_multi(&[template], event, strict)?
            .into_iter()
            .map(|mut row| row.remove(0))
            .collect())
    }

    /// `render_event_templates_multi(templates, event, strict)`: each list a template's path
    /// resolves to is an axis, the same path in two templates one axis, and the templates render
    /// once per combination of the axes' items, in `itertools.product`'s order, each against its
    /// own copy of the event with each axis's path set to its item. An empty list gives no rows;
    /// a render that fails drops its row.
    pub fn events_multi(
        &self,
        templates: &[&str],
        event: &Map,
        strict: bool,
    ) -> Result<Vec<Vec<String>>, Undefined> {
        let flat = event::expand_dotted_keys(event);
        let mut all_paths: Vec<Vec<Segment>> = Vec::new();
        for template in templates {
            match paths(template) {
                Ok(paths) => {
                    for path in paths {
                        if !all_paths.contains(&path) {
                            all_paths.push(path);
                        }
                    }
                }
                Err(_) => return Ok(Vec::new()),
            }
        }
        let mut axes: Vec<(Vec<Segment>, Vec<Loaded>)> = Vec::new();
        for path in all_paths {
            if let Some(Loaded::Seq(items)) = event::resolve(&flat, &path) {
                if items.is_empty() {
                    return Ok(Vec::new());
                }
                axes.push((path, items.clone()));
            }
        }
        let row = |scoped: &Map| -> Result<Option<Vec<String>>, Undefined> {
            // the templates of a row share one context, as ace3's do
            let root = Self::root(scoped);
            let mut row = Vec::with_capacity(templates.len());
            for template in templates {
                match self.render(template, &root, strict) {
                    Rendered::Text(t) => row.push(t),
                    Rendered::Undefined(e) => return Err(Undefined(e)),
                    Rendered::Failed(_) => return Ok(None),
                }
            }
            Ok(Some(row))
        };
        if axes.is_empty() {
            return Ok(row(&flat)?.into_iter().collect());
        }
        let total = axes
            .iter()
            .try_fold(1usize, |n, (_, items)| n.checked_mul(items.len()));
        if total.is_none_or(|n| n > self.limits.combinations) {
            return Ok(Vec::new());
        }
        let mut results = Vec::new();
        let mut index = vec![0usize; axes.len()];
        'combos: loop {
            let mut scoped = flat.clone();
            for ((path, items), &i) in axes.iter().zip(&index) {
                event::set(&mut scoped, path, items[i].clone());
            }
            if let Some(r) = row(&scoped)? {
                results.push(r);
            }
            // the last axis turns fastest, as itertools.product's does
            for k in (0..axes.len()).rev() {
                index[k] += 1;
                if index[k] < axes[k].1.len() {
                    continue 'combos;
                }
                index[k] = 0;
            }
            break;
        }
        Ok(results)
    }

    /// The hunt's name for an alert (`QueryHunt._render_name`): as written when it has no `{{`
    /// or `{%`, rendered permissively, and as written again when that fails.
    pub fn name(&self, name: &str, event: &Map) -> String {
        if !name.contains("{{") && !name.contains("{%") {
            return name.to_owned();
        }
        match self.jinja(name, event, false) {
            Rendered::Text(t) => t,
            _ => name.to_owned(),
        }
    }

    /// `_interpolate_strict` (`saq/query/extraction.py`): an observable mapping's value, file
    /// name, tags and directives, where a missing field gives nothing.
    pub fn interpolate_strict(&self, template: &str, event: &Map) -> Vec<String> {
        self.event_multi(template, event, true).unwrap_or_default()
    }

    /// `render_sd_content`: a summary detail's content for one event, or `None` to skip it.
    /// Strict unless the detail lists its required fields; the `jinja` format renders the event
    /// as it is, the others with its dotted keys nested.
    pub fn summary_content(&self, detail: &SummaryDetail, event: &Map) -> Option<String> {
        let strict = detail.required_fields.is_none();
        let r = if detail.format == "jinja" {
            self.jinja(&detail.content, event, strict)
        } else {
            self.event(&detail.content, event, strict)
        };
        r.text().map(str::to_owned)
    }

    /// `render_sd_header`: `(false, None)` to skip the event, else the header if there is one.
    pub fn summary_header(&self, detail: &SummaryDetail, event: &Map) -> (bool, Option<String>) {
        let Some(header) = &detail.header else {
            return (true, None);
        };
        let strict = detail.required_fields.is_none();
        let r = if detail.format == "jinja" {
            self.jinja(header, event, strict)
        } else {
            self.event(header, event, strict)
        };
        match r {
            Rendered::Text(t) => (true, Some(t)),
            _ => (false, None),
        }
    }

    /// A grouped `jinja` summary detail's content, rendered once with `{"events": events}`, or
    /// `None` to skip it: a missing field under strict, a failure, or nothing but whitespace.
    pub fn grouped_summary_content(
        &self,
        detail: &SummaryDetail,
        events: &[Map],
    ) -> Option<String> {
        let mut context = Map::new();
        context.insert(
            Loaded::Str("events".to_owned()),
            Loaded::Seq(events.iter().cloned().map(Loaded::Map).collect()),
        );
        match self.jinja(&detail.content, &context, detail.required_fields.is_none()) {
            Rendered::Text(t) if !t.trim_matches(methods::is_space).is_empty() => Some(t),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(pairs: &[(&str, Loaded)]) -> Map {
        let mut m = Map::new();
        for (k, v) in pairs {
            m.insert(Loaded::str(k), v.clone());
        }
        m
    }

    fn failed(r: &Rendered, why: &str) -> bool {
        matches!(r, Rendered::Failed(e) if e.contains(why))
    }

    #[test]
    fn a_render_that_loops_runs_out_of_fuel() {
        let r = Renderer::default();
        let out = r.jinja(
            "{% for i in range(100000) %}{% for j in range(100000) %}{% endfor %}{% endfor %}",
            &Map::new(),
            false,
        );
        assert!(failed(&out, "fuel"), "{out:?}");
        // a loop the signatures could plausibly need still fits
        let out = r.jinja(
            "{% for i in range(100000) %}{% endfor %}done",
            &Map::new(),
            false,
        );
        assert_eq!(out, Rendered::Text("done".to_owned()));
    }

    #[test]
    fn a_render_writes_at_most_its_output_bound() {
        let r = Renderer::default();
        let out = r.jinja(
            "{% for i in range(2000) %}{{ 'x' * 1000 }}{% endfor %}",
            &Map::new(),
            false,
        );
        assert!(failed(&out, "output"), "{out:?}");
        // literal text counts too
        let big = format!(
            "{{% for i in range(2000) %}}{}{{% endfor %}}",
            "y".repeat(1000)
        );
        assert!(failed(&r.jinja(&big, &Map::new(), false), "output"));
        // and output inside a captured block
        let set = "{% set s %}{% for i in range(2000) %}{{ 'x' * 1000 }}{% endfor %}{% endset %}x";
        assert!(failed(&r.jinja(set, &Map::new(), false), "output"));
    }

    #[test]
    fn a_render_builds_no_string_or_list_past_its_bounds() {
        let r = Renderer::default();
        for template in [
            "{{ ('x' * 2000000)|length }}",
            "{% set ns = namespace(s='ab') %}{% for i in range(30) %}{% set ns.s = ns.s ~ ns.s %}{% endfor %}x",
            "{% set ns = namespace(s='ab') %}{% for i in range(30) %}{% set ns.s = ns.s + ns.s %}{% endfor %}x",
            "{{ ['x'] * 200000 }}",
            "{% set l = [] %}{% for i in range(100000) %}{% set _ = l.append(i) %}{% set _ = l.append(i) %}{% endfor %}x",
            "{{ ('ab' * 400000)|replace('a', 'aaaa') }}",
        ] {
            let out = r.jinja(template, &Map::new(), false);
            assert!(failed(&out, "ace4 limit"), "{template}: {out:?}");
        }
    }

    #[test]
    fn macros_nest_only_so_deep() {
        let r = Renderer::default();
        let out = r.jinja(
            "{% macro rec(n) %}{{ rec(n + 1) }}{% endmacro %}{{ rec(0) }}",
            &Map::new(),
            false,
        );
        assert!(matches!(out, Rendered::Failed(_)), "{out:?}");
        let out = r.jinja(
            "{% macro down(n) %}{% if n %}{{ down(n - 1) }}{% else %}bottom{% endif %}{% endmacro %}{{ down(82) }}",
            &Map::new(),
            false,
        );
        assert_eq!(out, Rendered::Text("bottom".to_owned()));
    }

    #[test]
    fn a_multi_render_makes_at_most_its_bound_of_combinations() {
        let r = Renderer::default();
        let items = |n: usize| Loaded::Seq((0..n).map(|i| Loaded::Int(i as i128)).collect());
        let small = event(&[("a", items(10)), ("b", items(100))]);
        assert_eq!(
            r.event_multi("{{ a }}-{{ b }}", &small, true)
                .unwrap()
                .len(),
            1000
        );
        let large = event(&[("a", items(11)), ("b", items(100))]);
        assert_eq!(
            r.event_multi("{{ a }}-{{ b }}", &large, true),
            Ok(Vec::new())
        );
    }

    #[test]
    fn the_paths_are_ace3s_in_its_order() {
        use rewrite::Segment::{Index, Name};
        let n = |s: &str| Name(s.to_owned());
        assert_eq!(
            paths("{{ a.b }}{{ a }}{{ c[0].d }}{{ e['f'] }}{{ g[h] }}{{ x if y else z }}").unwrap(),
            vec![
                vec![n("c"), Index(0), n("d")],
                vec![n("a"), n("b")],
                vec![n("e"), n("f")],
                vec![n("g")],
                vec![n("h")],
                vec![n("y")],
                vec![n("x")],
                vec![n("z")],
            ]
        );
        // a for loop's filter comes after its body, as Jinja2's For declares it
        assert_eq!(
            paths("{% for i in items if keep %}{{ i.v }}{% endfor %}").unwrap(),
            vec![vec![n("i"), n("v")], vec![n("items")], vec![n("keep")]]
        );
    }
}
