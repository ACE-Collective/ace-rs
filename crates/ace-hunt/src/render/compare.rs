//! 6.3's comparison with ace3: the calls tools/ace3/hunts/render_templates.py makes, made with
//! ace-rs, in the same shape, so `normal::diff` can diff the two.
//!
//! A call names one of ace3's rendering functions (render_templates.py lists them), and a result
//! is the text, `null` for ace3's `None`, `{"undefined": true}` for an UndefinedError that escaped,
//! or a multi render's list.

use serde_json::{Map as JsonMap, Value as Json, json};

use super::{Rendered, Renderer, Undefined};
use crate::HuntConfig;
use crate::model::SummaryDetail;
use crate::value::{Map, Value};

fn rendered(r: Rendered) -> Json {
    match r {
        Rendered::Text(t) => Json::String(t),
        Rendered::Undefined(_) => json!({"undefined": true}),
        Rendered::Failed(_) => Json::Null,
    }
}

fn multi<T: Into<Json>>(r: Result<Vec<T>, Undefined>) -> Json {
    match r {
        Ok(items) => Json::Array(items.into_iter().map(Into::into).collect()),
        Err(_) => json!({"undefined": true}),
    }
}

/// One render, as render_templates.py's `render` makes it.
pub fn render_call(
    renderer: &Renderer,
    call: &str,
    templates: &[String],
    event: &Map,
    events: &[Map],
    detail: Option<&SummaryDetail>,
) -> Json {
    let strict = call.ends_with("_strict");
    let base = call.strip_suffix("_strict").unwrap_or(call);
    let first = templates.first().map(String::as_str).unwrap_or("");
    match base {
        "jinja" => rendered(renderer.jinja(first, event, strict)),
        "event" => rendered(renderer.event(first, event, strict)),
        "multi" => multi(renderer.event_multi(first, event, strict)),
        "rows" => {
            let refs: Vec<&str> = templates.iter().map(String::as_str).collect();
            multi(renderer.events_multi(&refs, event, strict))
        }
        "grouped" => {
            let mut context = Map::new();
            context.insert(
                Value::str("events"),
                Value::Seq(events.iter().cloned().map(Value::Map).collect()),
            );
            rendered(renderer.jinja(first, &context, strict))
        }
        "name" => Json::String(renderer.name(first, event)),
        "interpolate" => Json::Array(
            renderer
                .interpolate_strict(first, event)
                .into_iter()
                .map(Json::String)
                .collect(),
        ),
        "sd_content" => detail
            .and_then(|d| renderer.summary_content(d, event))
            .map_or(Json::Null, Json::String),
        "sd_header" => match detail {
            Some(d) => {
                let (ok, header) = renderer.summary_header(d, event);
                json!({"ok": ok, "header": header})
            }
            None => Json::Null,
        },
        "sd_grouped" => detail
            .and_then(|d| renderer.grouped_summary_content(d, events))
            .map_or(Json::Null, Json::String),
        other => Json::String(format!("no call {other}")),
    }
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Seq(items)) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_owned))
            .collect(),
        Some(Value::Str(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn maps(v: Option<&Value>) -> Vec<Map> {
    match v {
        Some(Value::Seq(items)) => items.iter().filter_map(|i| i.as_map().cloned()).collect(),
        _ => Vec::new(),
    }
}

/// A summary detail as a case or an entry gives it: content, header, format, required fields.
pub fn detail_of(spec: &Map, template: &str) -> SummaryDetail {
    let text = |k: &str| spec.get(k).and_then(Value::as_str).map(str::to_owned);
    SummaryDetail {
        content: text("content").unwrap_or_else(|| template.to_owned()),
        header: match spec.get("header") {
            Some(Value::Str(s)) => Some(s.clone()),
            Some(_) => None,
            None => Some(template.to_owned()),
        },
        format: text("format").unwrap_or_else(|| "md".to_owned()),
        limit: 10,
        grouped: false,
        dedup_fields: None,
        required_fields: match spec.get("required_fields") {
            Some(Value::Seq(_)) => Some(strings(spec.get("required_fields"))),
            _ => None,
        },
    }
}

/// The cases of templates/cases.yaml rendered with ace-rs, in render_templates.py's shape: each
/// case's `path` and `renders`.
pub fn cases(renderer: &Renderer, cases: &Value) -> Json {
    let mut out = Vec::new();
    let Value::Seq(cases) = cases else {
        return json!({"hunts": []});
    };
    for case in cases {
        let Some(case) = case.as_map() else { continue };
        let templates = strings(case.get("templates"));
        let mut events = maps(case.get("events"));
        if case.get("events").is_none() {
            events.push(Map::new());
        }
        let sd_spec = case
            .get("sd")
            .and_then(Value::as_map)
            .cloned()
            .unwrap_or_default();
        let mut renders = JsonMap::new();
        for call in strings(case.get("calls")) {
            if call == "shared" {
                // ace-rs renders each template against its own copy of the event
                for (e, event) in events.iter().enumerate() {
                    let first = templates.first().cloned().unwrap_or_default();
                    let second = templates.get(1).cloned().unwrap_or_default();
                    renders.insert(
                        format!("all {call} {e}"),
                        json!([
                            rendered(renderer.event(&first, event, false)),
                            rendered(renderer.jinja(&second, event, false)),
                        ]),
                    );
                }
                continue;
            }
            if call.starts_with("rows") {
                for (e, event) in events.iter().enumerate() {
                    renders.insert(
                        format!("all {call} {e}"),
                        render_call(renderer, &call, &templates, event, &events, None),
                    );
                }
                continue;
            }
            if call.starts_with("grouped") {
                for (t, template) in templates.iter().enumerate() {
                    renders.insert(
                        format!("{t} {call}"),
                        render_call(
                            renderer,
                            &call,
                            std::slice::from_ref(template),
                            &Map::new(),
                            &events,
                            None,
                        ),
                    );
                }
                continue;
            }
            for (t, template) in templates.iter().enumerate() {
                let detail = call
                    .starts_with("sd_")
                    .then(|| detail_of(&sd_spec, template));
                if call == "sd_grouped" {
                    renders.insert(
                        format!("{t} {call}"),
                        render_call(
                            renderer,
                            &call,
                            std::slice::from_ref(template),
                            &Map::new(),
                            &events,
                            detail.as_ref(),
                        ),
                    );
                    continue;
                }
                for (e, event) in events.iter().enumerate() {
                    renders.insert(
                        format!("{t} {call} {e}"),
                        render_call(
                            renderer,
                            &call,
                            std::slice::from_ref(template),
                            event,
                            &events,
                            detail.as_ref(),
                        ),
                    );
                }
            }
        }
        out.push(json!({
            "path": case.get("name").and_then(Value::as_str).unwrap_or(""),
            "renders": renders,
        }));
    }
    json!({"hunts": out})
}

/// A reference file reduced to each entry's `path` and `renders`, for diffing with [`cases`].
pub fn reduce_cases(reference: &Json) -> Json {
    let hunts: Vec<Json> = reference["hunts"]
        .as_array()
        .map(|hunts| {
            hunts
                .iter()
                .map(|h| json!({"path": h["path"], "renders": h["renders"]}))
                .collect()
        })
        .unwrap_or_default();
    json!({"hunts": hunts})
}

/// Each template of a hunt where ace3's hunter renders it, keyed as render_templates.py keys
/// them, with the text: pivot links' url and text together, and an observable type only when
/// it's a template.
pub fn hunt_templates(config: &HuntConfig) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for (at, text) in config.templates() {
        if let Some(rest) = at.strip_prefix("pivot_links/") {
            let (i, field) = rest.split_once('/').unwrap_or((rest, ""));
            let key = format!("pivot_links/{i}");
            if field == "url"
                && let Some(text_field) = config
                    .pivot_links
                    .get(i.parse::<usize>().unwrap_or(usize::MAX))
                    .and_then(|l| l.get("text"))
                    .and_then(Json::as_str)
            {
                out.push((key, vec![text.to_owned(), text_field.to_owned()]));
            }
            continue;
        }
        if at.starts_with("observable_mapping/") && at.ends_with("/type") && !text.contains("{{") {
            continue;
        }
        out.push((at, vec![text.to_owned()]));
    }
    out
}

/// The summary detail `summary_details/N/...` names.
pub fn detail_at<'a>(config: &'a HuntConfig, at: &str) -> Option<&'a SummaryDetail> {
    let rest = at.strip_prefix("summary_details/")?;
    let i: usize = rest.split('/').next()?.parse().ok()?;
    config.summary_details.get(i)
}

/// The call ace3's hunter renders the template at `at` with (render_templates.py's
/// `hunt_templates`).
pub fn hunter_call(config: &HuntConfig, at: &str) -> &'static str {
    if at == "name" {
        return "name";
    }
    if at == "playbook_url" || at == "dedup_key" || at.ends_with("/type") {
        return "event_strict";
    }
    if at.starts_with("tags/") {
        return "multi_strict";
    }
    if at.starts_with("pivot_links/") {
        return "rows_strict";
    }
    if let Some(detail) = detail_at(config, at) {
        return if at.ends_with("/header") {
            "sd_header"
        } else if detail.grouped && detail.format == "jinja" {
            "sd_grouped"
        } else {
            "sd_content"
        };
    }
    "interpolate"
}

fn loaded_strings(v: Option<&Value>) -> Json {
    Json::Array(strings(v).into_iter().map(Json::String).collect())
}

/// How many arms of a hunt's templates' ifs its events reach: `(taken, arms, templates with an
/// arm none reaches)`, each template's renders counted together, a pivot link's two templates
/// each on its own.
pub fn coverage(
    renderer: &Renderer,
    config: &HuntConfig,
    reference: Option<&Map>,
) -> (usize, usize, usize) {
    let empty = Map::new();
    let events = reference
        .and_then(|r| r.get("events"))
        .and_then(Value::as_map)
        .unwrap_or(&empty);
    let second = events
        .get("second")
        .and_then(Value::as_map)
        .cloned()
        .unwrap_or_default();
    let (mut taken, mut arms, mut partial) = (0, 0, 0);
    for (at, texts) in hunt_templates(config) {
        let call = hunter_call(config, &at);
        for text in &texts {
            super::coverage::begin();
            for (_, event) in events.iter() {
                let Some(event) = event.as_map() else {
                    continue;
                };
                let group = [event.clone(), second.clone()];
                let call = if call.starts_with("rows") {
                    "multi_strict"
                } else {
                    call
                };
                render_call(
                    renderer,
                    call,
                    std::slice::from_ref(text),
                    event,
                    &group,
                    detail_at(config, &at),
                );
            }
            let (t, a) = super::coverage::end();
            taken += t;
            arms += a;
            partial += usize::from(t < a);
        }
    }
    (taken, arms, partial)
}

/// One hunt of the signatures: ace3's renders reduced to each key's call, templates and result,
/// and ace-rs's of the same key, rendering the hunt as ace-rs loaded it against the events ace3 used.
pub fn signature_hunt(
    renderer: &Renderer,
    path: &str,
    config: Option<&HuntConfig>,
    reference: Option<&Map>,
) -> (Json, Json) {
    let empty = Map::new();
    let events = reference
        .and_then(|r| r.get("events"))
        .and_then(Value::as_map)
        .unwrap_or(&empty);
    let ref_templates = reference
        .and_then(|r| r.get("templates"))
        .and_then(Value::as_map)
        .unwrap_or(&empty);
    let ref_renders = reference
        .and_then(|r| r.get("renders"))
        .and_then(Value::as_map)
        .unwrap_or(&empty);
    let mut theirs = JsonMap::new();
    for (key, result) in ref_renders.iter() {
        let key = key.as_str().unwrap_or("");
        let at = key.rsplit_once(' ').map_or(key, |(at, _)| at);
        let spec = ref_templates.get(at).and_then(Value::as_map);
        theirs.insert(
            key.to_owned(),
            json!({
                "call": spec.and_then(|s| s.get("call")).map_or(Json::Null, Value::to_json),
                "templates": loaded_strings(spec.and_then(|s| s.get("templates"))),
                "result": result.to_json(),
            }),
        );
    }
    let mut ours = JsonMap::new();
    if let Some(config) = config {
        let second = events
            .get("second")
            .and_then(Value::as_map)
            .cloned()
            .unwrap_or_default();
        for (at, texts) in hunt_templates(config) {
            let call = hunter_call(config, &at);
            for (variant, event) in events.iter() {
                let (Some(variant), Some(event)) = (variant.as_str(), event.as_map()) else {
                    continue;
                };
                let group = [event.clone(), second.clone()];
                let result = render_call(
                    renderer,
                    call,
                    &texts,
                    event,
                    &group,
                    detail_at(config, &at),
                );
                ours.insert(
                    format!("{at} {variant}"),
                    json!({"call": call, "templates": texts, "result": result}),
                );
            }
        }
    }
    (
        json!({"path": path, "renders": Json::Object(ours)}),
        json!({"path": path, "renders": Json::Object(theirs)}),
    )
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::normal::{classify, diff, parse_rows};

    fn hunts_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/hunts")
    }

    /// The Done check's half that runs anywhere: the templates written for the comparison, each
    /// filter, test, global and edge among them, render as ace3's Jinja rendered them, but where
    /// differences.md says why not. tools/ace3/hunts/compare-templates runs the signatures.
    #[test]
    fn the_template_cases_render_as_they_do_in_ace3() {
        let dir = hunts_dir();
        let text = std::fs::read_to_string(dir.join("templates/cases.yaml")).unwrap();
        let cases_yaml = crate::yaml::load(
            &text,
            "cases.yaml",
            &mut crate::yaml::Budget::new(crate::yaml::Limits::default()),
        )
        .unwrap();
        let reference: Json = serde_json::from_slice(
            &std::fs::read(dir.join("reference/templates-cases.json")).unwrap(),
        )
        .unwrap();
        let reference = reduce_cases(&reference);
        let ours = cases(&Renderer::default(), &cases_yaml);
        let rows = parse_rows(
            &std::fs::read_to_string(dir.join("differences.md")).unwrap(),
            "templates-cases",
        );
        let report = classify(diff(&reference, &ours), &rows);
        let unexplained: Vec<String> = report.unexplained.iter().map(ToString::to_string).collect();
        assert!(
            unexplained.is_empty(),
            "{} unexplained:\n{}",
            unexplained.len(),
            unexplained.join("\n")
        );
        assert!(
            report.unused.is_empty(),
            "rows that match nothing in the cases: {:?}",
            report.unused
        );
    }
}
