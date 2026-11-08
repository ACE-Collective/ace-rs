//! A condition's expression evaluated against an event (`expressions.py`): Jinja, `equals`,
//! `glob` (Python's `fnmatch`) or `regex` (`re.search`) on a property, and `and`, `or` and `not`
//! over sub-expressions, with the trace of each.
//!
//! A Jinja expression is true when it renders to something other than blank, `false`, `0` or
//! `none` in any case, and false when it fails to render, which its trace records. The other
//! failures end the whole correlation, as the exception does in ace3: a sub-expression that isn't a
//! string or a valid expression, an unknown type, and a pattern that doesn't compile. A pattern is
//! compiled by the `regex` crate, which reads Python's syntax for what the signatures use but has
//! no lookaround or backreferences, within 1 MiB.

use std::cell::RefCell;
use std::collections::HashMap;

use regex::{Regex, RegexBuilder};
use serde_json::Value as Json;

use super::Expression;
use super::engine::EngineError;
use super::trace::ExpressionTrace;
use crate::query::extract::{py_str, to_loaded};
use crate::render::methods::is_space;
use crate::render::{Rendered, Renderer};
use crate::value::{Map, Value};

/// The event an expression is evaluated against, and the stream it's in.
#[derive(Clone, Copy)]
pub struct Scope<'a> {
    pub event: &'a Map,
    pub events: &'a [Map],
}

/// `build_jinja_context(event, events)`: `_events` and `_event`, and nothing else, so no template
/// reaches configuration or a credential. `_events` is only built for a template that names it,
/// since a template can only reach it by its name.
pub fn context(template: &str, scope: Scope<'_>) -> Map {
    let mut m = Map::new();
    if template.contains("_events") {
        m.insert(
            Value::str("_events"),
            Value::Seq(scope.events.iter().cloned().map(Value::Map).collect()),
        );
    }
    m.insert(Value::str("_event"), Value::Map(scope.event.clone()));
    m
}

/// A template rendered in a correlation's context, as ace3's `_jinja_env.from_string(t).render`:
/// its text, or why it failed.
pub fn render(renderer: &Renderer, template: &str, scope: Scope<'_>) -> Result<String, String> {
    match renderer.jinja(template, &context(template, scope), false) {
        Rendered::Text(t) => Ok(t),
        Rendered::Undefined(e) | Rendered::Failed(e) => Err(e),
    }
}

/// Whether a rendered Jinja expression is true.
pub fn truthy(rendered: &str) -> bool {
    let stripped = rendered.trim_matches(is_space);
    !stripped.is_empty() && !["false", "0", "none", ""].contains(&stripped.to_lowercase().as_str())
}

/// What evaluates expressions, with the patterns it has compiled.
pub struct Evaluator<'a> {
    pub renderer: &'a Renderer,
    patterns: RefCell<HashMap<(String, bool), Regex>>,
}

const PATTERN_BYTES: usize = 1 << 20;

impl<'a> Evaluator<'a> {
    pub fn new(renderer: &'a Renderer) -> Evaluator<'a> {
        Evaluator {
            renderer,
            patterns: RefCell::new(HashMap::new()),
        }
    }

    /// `evaluate_expression`.
    pub fn evaluate(&self, expr: &Expression, scope: Scope<'_>) -> Result<bool, EngineError> {
        match expr.kind.as_str() {
            "jinja" => Ok(match render(self.renderer, &py_str(&expr.value), scope) {
                Ok(t) => truthy(&t),
                Err(_) => false,
            }),
            "equals" | "glob" | "regex" => self.compare(expr, scope),
            "and" => {
                for sub in items(&expr.value) {
                    if !self.evaluate(&sub_expression(sub)?, scope)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            "or" => {
                for sub in items(&expr.value) {
                    if self.evaluate(&sub_expression(sub)?, scope)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            "not" => Ok(!self.evaluate(&sub_expression(&expr.value)?, scope)?),
            other => Err(unknown(other)),
        }
    }

    fn compare(&self, expr: &Expression, scope: Scope<'_>) -> Result<bool, EngineError> {
        let Some(value) = property_value(expr, scope.event) else {
            return Ok(false);
        };
        let wanted = normalized_value(expr);
        Ok(match expr.kind.as_str() {
            "equals" => value == wanted,
            "glob" => self
                .pattern(&fnmatch_translate(&wanted), false)?
                .is_match(&value),
            _ => self
                .pattern(&py_str(&expr.value), !expr.case_sensitive)?
                .is_match(&value),
        })
    }

    fn pattern(&self, pattern: &str, ignore_case: bool) -> Result<Regex, EngineError> {
        let key = (pattern.to_owned(), ignore_case);
        if let Some(r) = self.patterns.borrow().get(&key) {
            return Ok(r.clone());
        }
        let compiled = RegexBuilder::new(pattern)
            .case_insensitive(ignore_case)
            .size_limit(PATTERN_BYTES)
            .dfa_size_limit(PATTERN_BYTES)
            .build()
            .map_err(|e| EngineError::Raised(format!("re.error: {e}")))?;
        self.patterns.borrow_mut().insert(key, compiled.clone());
        Ok(compiled)
    }

    /// `evaluate_expression_traced`.
    pub fn evaluate_traced(
        &self,
        expr: &Expression,
        scope: Scope<'_>,
    ) -> Result<(bool, ExpressionTrace), EngineError> {
        match expr.kind.as_str() {
            "jinja" => Ok(match render(self.renderer, &py_str(&expr.value), scope) {
                Ok(rendered) => {
                    let result = truthy(&rendered);
                    let mut trace = ExpressionTrace::new("jinja", result);
                    trace.rendered_value = Some(rendered);
                    (result, trace)
                }
                Err(e) => {
                    let mut trace = ExpressionTrace::new("jinja", false);
                    trace.error = Some(e);
                    (false, trace)
                }
            }),
            "equals" | "glob" | "regex" => {
                let value = property_value(expr, scope.event);
                let compare = normalized_value(expr);
                let result = self.evaluate(expr, scope)?;
                let mut trace = ExpressionTrace::new(&expr.kind, result);
                trace.property_name = expr.property.clone();
                trace.property_value = value;
                trace.compare_value = Some(compare);
                Ok((result, trace))
            }
            "and" | "or" => {
                let stop_on = expr.kind == "or";
                let mut subs = Vec::new();
                let mut result = !stop_on;
                for sub in items(&expr.value) {
                    let (r, t) = self.evaluate_traced(&sub_expression(sub)?, scope)?;
                    subs.push(t);
                    if r == stop_on {
                        result = stop_on;
                        break;
                    }
                }
                let mut trace = ExpressionTrace::new(&expr.kind, result);
                trace.sub_expressions = Some(subs);
                Ok((result, trace))
            }
            "not" => {
                let (r, t) = self.evaluate_traced(&sub_expression(&expr.value)?, scope)?;
                let mut trace = ExpressionTrace::new("not", !r);
                trace.sub_expressions = Some(vec![t]);
                Ok((!r, trace))
            }
            other => Err(unknown(other)),
        }
    }
}

fn unknown(kind: &str) -> EngineError {
    EngineError::Raised(format!(
        "ValueError: unknown expression type: {}",
        crate::value::py_repr(kind)
    ))
}

fn items(value: &Json) -> &[Json] {
    match value {
        Json::Array(items) => items,
        _ => &[],
    }
}

/// `_parse_sub_expression`: a string is a Jinja expression, a mapping an expression.
fn sub_expression(value: &Json) -> Result<Expression, EngineError> {
    match value {
        Json::String(s) => Ok(Expression {
            kind: "jinja".to_owned(),
            value: Json::String(s.clone()),
            property: None,
            case_sensitive: true,
        }),
        Json::Object(_) => Expression::from_value(&to_loaded(value))
            .map_err(|e| EngineError::Raised(format!("ValidationError: {e}"))),
        other => Err(EngineError::Raised(format!(
            "ValueError: invalid sub-expression: {}",
            crate::query::extract::py_repr_json(other)
        ))),
    }
}

/// `_get_property_value`: the property's `str()`, lowered unless case-sensitive; None when the
/// event lacks it or it's None.
pub fn property_value(expr: &Expression, event: &Map) -> Option<String> {
    let value = event.get(expr.property.as_deref()?)?;
    if matches!(value, Value::Null) {
        return None;
    }
    let text = crate::render::py::str_of(&crate::render::py::to_template(value));
    Some(if expr.case_sensitive {
        text
    } else {
        text.to_lowercase()
    })
}

/// `_normalize_expr_value`.
pub fn normalized_value(expr: &Expression) -> String {
    let text = py_str(&expr.value);
    if expr.case_sensitive {
        text
    } else {
        text.to_lowercase()
    }
}

/// `fnmatch.translate(pattern)`: `*` any run, `?` any one character, `[...]` a set (`[!...]`
/// its complement), anything else itself, anchored at both ends, `.` matching a newline.
pub fn fnmatch_translate(pattern: &str) -> String {
    let p: Vec<char> = pattern.chars().collect();
    // fnmatch matches from the start, as `re.match` does
    let mut out = String::from("\\A(?s:");
    let mut i = 0;
    let mut last_star = false;
    while i < p.len() {
        let c = p[i];
        i += 1;
        match c {
            '*' => {
                if !last_star {
                    out.push_str(".*");
                }
                last_star = true;
                continue;
            }
            '?' => out.push('.'),
            '[' => {
                let mut j = i;
                if j < p.len() && p[j] == '!' {
                    j += 1;
                }
                if j < p.len() && p[j] == ']' {
                    j += 1;
                }
                while j < p.len() && p[j] != ']' {
                    j += 1;
                }
                if j >= p.len() {
                    out.push_str("\\[");
                } else {
                    let stuff: Vec<char> = p[i..j].to_vec();
                    i = j + 1;
                    out.push_str(&set(&stuff));
                }
            }
            c => out.push_str(&regex::escape(&c.to_string())),
        }
        last_star = false;
    }
    out.push_str(")\\z");
    out
}

/// A `[...]` set's text as a Rust class: `!` first negates it, `a-z` is a range (a reversed one
/// matches nothing, as Python drops it), and every other character is itself.
fn set(stuff: &[char]) -> String {
    if stuff.is_empty() {
        // an empty set never matches
        return "[^\\s\\S]".to_owned();
    }
    if stuff == ['!'] {
        return ".".to_owned();
    }
    let (negated, body) = if stuff[0] == '!' {
        (true, &stuff[1..])
    } else {
        (false, stuff)
    };
    let escape = |c: char| -> String {
        if c.is_alphanumeric() {
            c.to_string()
        } else {
            format!("\\x{{{:x}}}", c as u32)
        }
    };
    let mut class = String::new();
    let mut k = 0;
    while k < body.len() {
        if k + 2 < body.len() && body[k + 1] == '-' {
            let (lo, hi) = (body[k], body[k + 2]);
            if lo <= hi {
                class.push_str(&format!("{}-{}", escape(lo), escape(hi)));
            }
            k += 3;
        } else {
            class.push_str(&escape(body[k]));
            k += 1;
        }
    }
    if class.is_empty() {
        return if negated {
            ".".to_owned()
        } else {
            "[^\\s\\S]".to_owned()
        };
    }
    format!("[{}{class}]", if negated { "^" } else { "" })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, text: &str) -> bool {
        Regex::new(&fnmatch_translate(pattern))
            .expect("compiles")
            .is_match(text)
    }

    #[test]
    fn globs_match_as_fnmatch_does() {
        assert!(matches("admin*", "admin_user"));
        assert!(!matches("user*", "admin_user"));
        assert!(matches("*.internal.corp", "web1.internal.corp"));
        assert!(!matches("*.internal.corp", "web1.internal.corp.evil"));
        assert!(matches("a?c", "abc"));
        assert!(matches("[a-c]x", "bx"));
        assert!(!matches("[!a-c]x", "bx"));
        assert!(matches("[!a-c]x", "dx"));
        assert!(matches("[", "["));
        assert!(matches("a[]]b", "a]b"));
        assert!(matches("*\n*", "a\nb"));
        assert!(!matches("[z-a]", "m"));
        assert!(matches("a.b", "a.b"));
        assert!(!matches("a.b", "axb"));
    }
}
