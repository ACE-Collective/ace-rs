//! An API search's pivot links, ace3's `pivot_links` on a `BaseAPIAnalyzer`
//! (`BaseAPIAnalyzer.process_pivot_links` and `process_overflow_pivot_link`,
//! `saq/modules/api_analysis.py`; `PivotLinkConfig`, `saq/query/config.py`), PLAN.md decisions 52
//! and 53.
//!
//! Each entry's `url` and `text` are Jinja templates rendered against each row, as ace3 renders
//! them with `render_event_templates_multi` (strict): one link per combination of the list values
//! the templates read, a row missing a field skipped, an empty url or text skipped. Links are kept
//! once each by url, icon and text, in row order; with `limit`, the first `limit` are kept, and when
//! more qualified and `overflow` is set, one more link renders against the first row with
//! `overflow_count` (how many weren't kept), with the entry's icon unless the overflow names its
//! own. A link goes beside the result, or, with `target: root` (ace3's default), on the alert's
//! summary (`RootChanges::pivot_links`).
//!
//! Where it differs from ace3: a link must be a plain `https://` URL with a label
//! (`PivotLink::refusal`), so one that isn't is dropped, with a warning, before the limit counts it,
//! where ace3 keeps it; an icon is the name of one the binary registers
//! (`ace_app::App::pivot_link_icon`), where ace3 also takes a `data:` URL, and a settings block that
//! names anything else fails to load; `overflow` without `limit` fails to load, where ace3 logs it
//! and never shows it; and a link another result already put on the alert still counts toward this
//! search's limit, since the module doesn't read the alert's links (ace3 skips it before counting).
//! The renders are bounded, as the hunter's are (`ace_hunt::render::Limits`).

use ace_hunt::render::{Rendered, Renderer};
use ace_hunt::value::{Map as Loaded, Value as LoadedValue};
use ace_results::{MAX_PIVOT_LINKS, PivotLink, is_icon_name};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value};

/// One of ace3's `pivot_links` entries.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PivotLinkSetting {
    /// A Jinja template of the link's URL, rendered against each row.
    pub url: String,
    /// A Jinja template of what the link says.
    pub text: String,
    /// A registered icon's name (`ace_app::App::pivot_link_icon`).
    #[serde(default)]
    pub icon: Option<String>,
    /// Where the links go: `root`, the alert's summary, as ace3's default, or `analysis`, beside
    /// the result.
    #[serde(default)]
    pub target: PivotTarget,
    /// The most links the entry adds; none for no limit.
    #[serde(default)]
    pub limit: Option<u32>,
    /// One link added when `limit` kept fewer than qualified.
    #[serde(default)]
    pub overflow: Option<OverflowSetting>,
}

/// Where an entry's links go.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PivotTarget {
    #[default]
    Root,
    Analysis,
}

/// ace3's `PivotLinkOverflowConfig`: templates rendered against the first row with
/// `overflow_count` set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverflowSetting {
    pub url: String,
    pub text: String,
    /// Its own icon; the entry's when none.
    #[serde(default)]
    pub icon: Option<String>,
}

/// Why `entries` can't be used: an icon that isn't a name, `overflow` without `limit`, or a
/// template that doesn't compile.
pub fn check(entries: &[PivotLinkSetting], renderer: &Renderer) -> Result<(), String> {
    for (i, entry) in entries.iter().enumerate() {
        let icons = [entry.icon.as_deref()]
            .into_iter()
            .chain([entry.overflow.as_ref().and_then(|o| o.icon.as_deref())]);
        for icon in icons.flatten() {
            if !is_icon_name(icon) {
                return Err(format!(
                    "pivot_links[{i}]: {icon:?} isn't an icon's name; an icon is the name of one \
                     the binary registers (App::pivot_link_icon)"
                ));
            }
        }
        if entry.overflow.is_some() && entry.limit.is_none() {
            return Err(format!(
                "pivot_links[{i}] has overflow without limit, so its overflow link would never show"
            ));
        }
        let templates = [&entry.url, &entry.text]
            .into_iter()
            .chain(entry.overflow.iter().flat_map(|o| [&o.url, &o.text]));
        for template in templates {
            renderer
                .check(template)
                .map_err(|e| format!("pivot_links[{i}]: {template:?}: {e}"))?;
        }
    }
    Ok(())
}

/// The links a search's rows give, beside its result and on its root, in that order of entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Links {
    pub analysis: Vec<PivotLink>,
    pub root: Vec<PivotLink>,
}

/// `process_pivot_links` over `rows`. `name` names the search in a warning about a refused link.
pub fn render(
    entries: &[PivotLinkSetting],
    rows: &[Map<String, Value>],
    renderer: &Renderer,
    name: &str,
) -> Links {
    let mut links = Links::default();
    if entries.is_empty() || rows.is_empty() {
        return links;
    }
    let loaded: Vec<Loaded> = rows.iter().map(load).collect();
    for entry in entries {
        let target = match entry.target {
            PivotTarget::Root => &mut links.root,
            PivotTarget::Analysis => &mut links.analysis,
        };
        let mut candidates: Vec<PivotLink> = Vec::new();
        for row in &loaded {
            let Ok(rendered) = renderer.events_multi(&[&entry.url, &entry.text], row, true) else {
                // ace3's UndefinedError: the row lacks a field the templates read
                continue;
            };
            for mut pair in rendered {
                let text = pair.pop().unwrap_or_default();
                let url = pair.pop().unwrap_or_default();
                if url.is_empty() || text.is_empty() {
                    continue;
                }
                let link = PivotLink {
                    url,
                    text,
                    icon: entry.icon.clone(),
                };
                if !usable(&link, name) || target.contains(&link) || candidates.contains(&link) {
                    continue;
                }
                candidates.push(link);
            }
        }
        let shown = entry.limit.map_or(candidates.len(), |limit| {
            (limit as usize).min(candidates.len())
        });
        let hidden = candidates.len() - shown;
        target.extend(candidates.into_iter().take(shown));
        if let (Some(overflow), true) = (&entry.overflow, hidden > 0)
            && let Some(link) = overflow_link(entry, overflow, &loaded[0], hidden, renderer)
            && usable(&link, name)
            && !target.contains(&link)
        {
            target.push(link);
        }
    }
    for (place, list) in [("analysis", &mut links.analysis), ("root", &mut links.root)] {
        if list.len() > MAX_PIVOT_LINKS {
            tracing::warn!(
                search = name,
                place,
                "{} pivot links; the {} past {MAX_PIVOT_LINKS} are dropped",
                list.len(),
                list.len() - MAX_PIVOT_LINKS
            );
            list.truncate(MAX_PIVOT_LINKS);
        }
    }
    links
}

/// `process_overflow_pivot_link`: the templates against the first row with `overflow_count` over
/// it, as ace3's `{**event, "overflow_count": n}`.
fn overflow_link(
    entry: &PivotLinkSetting,
    overflow: &OverflowSetting,
    first: &Loaded,
    hidden: usize,
    renderer: &Renderer,
) -> Option<PivotLink> {
    let mut context = first.clone();
    context.insert(
        LoadedValue::Str("overflow_count".to_owned()),
        LoadedValue::Int(hidden as i128),
    );
    let text_of = |template: &str| match renderer.event(template, &context, true) {
        Rendered::Text(text) if !text.is_empty() => Some(text),
        _ => None,
    };
    Some(PivotLink {
        url: text_of(&overflow.url)?,
        text: text_of(&overflow.text)?,
        icon: overflow.icon.clone().or_else(|| entry.icon.clone()),
    })
}

/// Whether ACE can show the link; one it can't is dropped with a warning that doesn't quote the URL,
/// which may carry a row's value.
fn usable(link: &PivotLink, name: &str) -> bool {
    match link.refusal() {
        None => true,
        Some(_) => {
            tracing::warn!(
                search = name,
                "a pivot link isn't a plain https:// URL with a label of at most 1,024 characters, \
                 and is dropped"
            );
            false
        }
    }
}

/// A row as Python's `json.loads` gives it, for the templates.
fn load(row: &Map<String, Value>) -> Loaded {
    match ace_hunt::query::extract::to_loaded(&Value::Object(row.clone())) {
        LoadedValue::Map(map) => map,
        _ => Loaded::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entries(value: Value) -> Vec<PivotLinkSetting> {
        serde_json::from_value(value).expect("pivot links")
    }

    fn rows(value: Value) -> Vec<Map<String, Value>> {
        serde_json::from_value(value).expect("rows")
    }

    fn texts(links: &[PivotLink]) -> Vec<String> {
        links
            .iter()
            .map(|l| format!("{} {} {:?}", l.url, l.text, l.icon))
            .collect()
    }

    #[test]
    fn links_render_per_row_once_each_up_to_the_limit_with_one_overflow() {
        let renderer = Renderer::default();
        let entries = entries(json!([{
            "url": "{{ link }}",
            "text": "Ticket {{ ticket }} ({{ description | truncate(12) }})",
            "icon": "servicenow",
            "limit": 2,
            "overflow": {"url": "{{ search_link }}", "text": "More ({{ overflow_count }} more)"},
        }, {
            "url": "https://portal.example/{{ ticket }}",
            "text": "{{ ticket }}",
            "target": "analysis",
        }]));
        check(&entries, &renderer).expect("usable");
        let rows = rows(json!([
            {"ticket": "T1", "link": "https://tickets.example/T1", "description": "printer on fire again",
             "search_link": "https://tickets.example/search?q=a"},
            {"ticket": "T1", "link": "https://tickets.example/T1", "description": "printer on fire again"},
            {"ticket": "T2", "link": "http://tickets.example/T2", "description": "plain"},
            {"ticket": "T3", "link": "https://tickets.example/T3", "description": "three"},
            {"ticket": "T4", "description": "no link"},
            {"ticket": "T5", "link": "https://tickets.example/T5", "description": "five"},
        ]));
        let links = render(&entries, &rows, &renderer, "example");
        assert_eq!(
            texts(&links.root),
            [
                "https://tickets.example/T1 Ticket T1 (printer...) Some(\"servicenow\")",
                // the http:// link is dropped before the limit, and T1 once
                "https://tickets.example/T3 Ticket T3 (three) Some(\"servicenow\")",
                "https://tickets.example/search?q=a More (1 more) Some(\"servicenow\")",
            ]
        );
        assert_eq!(
            texts(&links.analysis),
            [
                "https://portal.example/T1 T1 None",
                "https://portal.example/T2 T2 None",
                "https://portal.example/T3 T3 None",
                "https://portal.example/T4 T4 None",
                "https://portal.example/T5 T5 None",
            ]
        );
    }

    #[test]
    fn a_list_field_gives_a_link_per_value_and_no_overflow_within_the_limit() {
        let renderer = Renderer::default();
        let entries = entries(json!([{
            "url": "https://hosts.example/{{ host }}",
            "text": "{{ host }}",
            "limit": 5,
            "overflow": {"url": "https://hosts.example/", "text": "{{ overflow_count }} more", "icon": "other"},
        }]));
        let rows = rows(json!([{"host": ["a", "b"]}, {"host": []}, {"host": "c"}]));
        let links = render(&entries, &rows, &renderer, "example");
        assert_eq!(
            texts(&links.root),
            [
                "https://hosts.example/a a None",
                "https://hosts.example/b b None",
                "https://hosts.example/c c None",
            ]
        );
        // past the limit, the overflow's own icon
        let entries = entries_with_limit(1);
        let links = render(&entries, &rows, &renderer, "example");
        assert_eq!(
            texts(&links.root),
            [
                "https://hosts.example/a a None",
                "https://hosts.example/ 2 more Some(\"other\")",
            ]
        );
    }

    fn entries_with_limit(limit: u32) -> Vec<PivotLinkSetting> {
        entries(json!([{
            "url": "https://hosts.example/{{ host }}",
            "text": "{{ host }}",
            "limit": limit,
            "overflow": {"url": "https://hosts.example/", "text": "{{ overflow_count }} more", "icon": "other"},
        }]))
    }

    #[test]
    fn a_bad_icon_an_overflow_without_a_limit_and_a_bad_template_are_refused() {
        let renderer = Renderer::default();
        let data_url =
            entries(json!([{"url": "{{ a }}", "text": "x", "icon": "data:image/png;base64,AA=="}]));
        assert!(
            check(&data_url, &renderer)
                .expect_err("refused")
                .contains("App::pivot_link_icon")
        );
        let no_limit = entries(json!([{"url": "{{ a }}", "text": "x",
                                        "overflow": {"url": "{{ a }}", "text": "y"}}]));
        assert!(
            check(&no_limit, &renderer)
                .expect_err("refused")
                .contains("without limit")
        );
        let bad = entries(json!([{"url": "{{ a ", "text": "x"}]));
        assert!(check(&bad, &renderer).is_err());
        assert!(
            serde_json::from_value::<Vec<PivotLinkSetting>>(json!([{"url": "a", "text": "b",
                                                                   "target": "event"}]))
            .is_err()
        );
    }

    #[test]
    fn links_past_the_bound_are_dropped() {
        let renderer = Renderer::default();
        let entries = entries(
            json!([{"url": "https://x.example/{{ n }}", "text": "{{ n }}",
                                      "target": "analysis"}]),
        );
        let rows: Vec<Map<String, Value>> = (0..=MAX_PIVOT_LINKS)
            .map(|n| json!({"n": n}).as_object().cloned().expect("a row"))
            .collect();
        let links = render(&entries, &rows, &renderer, "example");
        assert_eq!(links.analysis.len(), MAX_PIVOT_LINKS);
    }
}
