//! The normal form of a root's tree (PLAN.md 3.1): a JSON form both ace4 and ace3 can write, so
//! the same sample can be compared across the two systems. `ace root normal-form` writes it for
//! ace4, and `tools/ace3/` will write it for ace3 (3.2).
//!
//! ```text
//! {
//!   "form": 1,
//!   "observables": {
//!     "<type>:<value>": {                       a file's value is its sha256
//!       "tags": {"phish": true},
//!       "directives": {"sandbox": true},
//!       "excluded_analysis": {"archive": true},  module names
//!       "relationships": {"extracted_from file:<sha256>": true},
//!       "detections": {"<description>": [details, ...]},
//!       "time": "2026-11-01T12:00:00Z",          when the data gave it one
//!       "redirection": "file:<sha256>",          when it has one
//!       "paths": {"a.zip": {"type=email.attachment": true}},   a file's paths and yara_meta
//!       "results": {
//!         "<module>": {
//!           "summary": "...",
//!           "tags": {"single_file_zip": true},
//!           "details": {...}                     as the module wrote them, keys sorted
//!         }
//!       }
//!     }
//!   }
//! }
//! ```
//!
//! Sets are objects whose keys are the members, so a diff by JSON pointer names the member, and
//! the text sorts every object's keys, so one tree always gives the same bytes. `ace-testkit`'s
//! form for one module's reference dump is built the same way.
//!
//! The form leaves out what says when or where a run happened: row ids, the root's id, creation
//! times, the root's event time and analysis mode, task state and attempts. An observable's
//! `time` stays, because it comes from the data, such as a row of a Splunk result. Detections on
//! a result and on the observable it analyzed both sit on that observable, because that's how
//! the core stores them. Of a detection the form keeps its description and details. The
//! signature fields name a ruleset commit, which is a fact about the run.
//!
//! Some fields of a result are about the run too. `RUN_FIELDS` lists them, and the form leaves
//! them out.

use std::collections::BTreeMap;

use ace_results::sort_json_keys;
use chrono::SecondsFormat;
use serde_json::{Map, Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::DbError;
use crate::tree::ObservableId;

/// The version of this form, which `ace compare` checks both sides for.
pub const FORM: u64 = 1;

/// Fields of a result that describe the run rather than the sample, as (analysis type, path).
/// A `*` segment is every array item. Each is a clock reading, something derived from one, or an
/// id another run wouldn't get. `tests/e2e/run` fails when two runs of one email differ by a field
/// that isn't here.
const RUN_FIELDS: &[(&str, &str)] = &[
    ("email_analysis", "/details/email/log_entry/date"),
    // how old the domain is today, in the details and in the summary built from them
    ("rdap_analysis", "/summary"),
    ("rdap_analysis", "/details/age_created_in_days"),
    ("rdap_analysis", "/details/age_last_updated_in_days"),
    ("rdap_analysis", "/details/datetime_of_analysis"),
    // when the hit was found
    ("nrd_analysis", "/details/matched_at"),
    ("splunk_api_analysis", "/details/end_time"),
    ("splunk_api_analysis", "/details/query_start"),
    ("splunk_api_analysis", "/details/running_start_time"),
    ("splunk_api_analysis", "/details/search_id"),
    ("splunk_api_analysis", "/details/start_time"),
    ("yara_scan_results", "/details/scan_results/*/commit"),
    ("yara_scan_results", "/details/scan_results/*/ruleset"),
];

fn set<'a>(items: impl IntoIterator<Item = &'a String>) -> Value {
    Value::Object(
        items
            .into_iter()
            .map(|i| (i.clone(), json!(true)))
            .collect(),
    )
}

/// The tree of `root` in the normal form, or None when there is no such root.
pub async fn normal_form(pool: &PgPool, root: Uuid) -> Result<Option<Value>, DbError> {
    let exists = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!" FROM analysis.roots WHERE id = $1"#,
        root
    )
    .fetch_optional(pool)
    .await?;
    if exists.is_none() {
        return Ok(None);
    }

    let mut paths: BTreeMap<ObservableId, Map<String, Value>> = BTreeMap::new();
    for row in sqlx::query!(
        r#"SELECT observable_id AS "id: ObservableId", path, yara_meta FROM analysis.files
           WHERE root_id = $1"#,
        root,
    )
    .fetch_all(pool)
    .await?
    {
        paths
            .entry(row.id)
            .or_default()
            .insert(row.path, set(&row.yara_meta));
    }

    let mut relationships: BTreeMap<ObservableId, Vec<String>> = BTreeMap::new();
    for row in sqlx::query!(
        r#"SELECT observable_id AS "id: ObservableId", kind, target_type, target_value
           FROM analysis.relationships WHERE root_id = $1"#,
        root,
    )
    .fetch_all(pool)
    .await?
    {
        relationships.entry(row.id).or_default().push(format!(
            "{} {}:{}",
            row.kind, row.target_type, row.target_value
        ));
    }

    let mut detections: BTreeMap<ObservableId, BTreeMap<String, Vec<Value>>> = BTreeMap::new();
    for row in sqlx::query!(
        r#"SELECT observable_id AS "id: ObservableId", description, details
           FROM analysis.detections WHERE root_id = $1"#,
        root,
    )
    .fetch_all(pool)
    .await?
    {
        detections
            .entry(row.id)
            .or_default()
            .entry(row.description)
            .or_default()
            .push(sort_json_keys(row.details.unwrap_or(Value::Null)));
    }

    let mut results: BTreeMap<ObservableId, Map<String, Value>> = BTreeMap::new();
    for row in sqlx::query!(
        r#"SELECT observable_id AS "id: ObservableId", module, analysis_type, details, summary, tags
           FROM analysis.results WHERE root_id = $1"#,
        root,
    )
    .fetch_all(pool)
    .await?
    {
        let mut result =
            json!({"summary": row.summary, "tags": set(&row.tags), "details": row.details});
        remove_run_fields(&row.analysis_type, &mut result);
        results
            .entry(row.id)
            .or_default()
            .insert(row.module, result);
    }

    let mut observables = Map::new();
    for row in sqlx::query!(
        r#"SELECT id AS "id: ObservableId", type AS kind, value, time, tags, directives,
                  exclude_modules, redirection_type, redirection_value
           FROM analysis.observables WHERE root_id = $1"#,
        root,
    )
    .fetch_all(pool)
    .await?
    {
        // details of equal detections sort too, so their order doesn't depend on the rows'
        let mut on_observable = detections.remove(&row.id).unwrap_or_default();
        for details in on_observable.values_mut() {
            details.sort_by_cached_key(Value::to_string);
        }
        let mut normal = json!({
            "tags": set(&row.tags),
            "directives": set(&row.directives),
            "excluded_analysis": set(&row.exclude_modules),
            "relationships": set(&relationships.remove(&row.id).unwrap_or_default()),
            "detections": on_observable,
            "results": results.remove(&row.id).unwrap_or_default(),
        });
        if let Some(time) = row.time {
            normal["time"] = json!(time.to_rfc3339_opts(SecondsFormat::AutoSi, true));
        }
        if let (Some(kind), Some(value)) = (row.redirection_type, row.redirection_value) {
            normal["redirection"] = json!(format!("{kind}:{value}"));
        }
        if let Some(paths) = paths.remove(&row.id) {
            normal["paths"] = Value::Object(paths);
        }
        observables.insert(format!("{}:{}", row.kind, row.value), normal);
    }
    Ok(Some(json!({"form": FORM, "observables": observables})))
}

/// The form as text: keys sorted at every level, two-space indents, a final newline. Python's
/// `json.dumps(form, indent=2, sort_keys=True, ensure_ascii=False)` gives the same text.
pub fn to_text(form: &Value) -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string_pretty(&sort_json_keys(form.clone()))?;
    text.push('\n');
    Ok(text)
}

fn remove_run_fields(analysis_type: &str, result: &mut Value) {
    for (_, path) in RUN_FIELDS.iter().filter(|(t, _)| *t == analysis_type) {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        remove_at(result, &segments);
    }
}

fn remove_at(value: &mut Value, segments: &[&str]) {
    match (value, segments) {
        (Value::Object(map), [key]) => {
            map.remove(*key);
        }
        (Value::Object(map), [key, rest @ ..]) => {
            if let Some(value) = map.get_mut(*key) {
                remove_at(value, rest);
            }
        }
        (Value::Array(items), ["*", rest @ ..]) => {
            items.iter_mut().for_each(|item| remove_at(item, rest));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_fields_go_and_the_sample_s_stay() {
        let mut yara = json!({
            "summary": "matched",
            "details": {"scan_results": [
                {"rule": "a", "commit": "c1", "ruleset": "r1"},
                {"rule": "b", "commit": "c1", "ruleset": "r1"},
            ]},
        });
        remove_run_fields("yara_scan_results", &mut yara);
        assert_eq!(
            yara,
            json!({
                "summary": "matched",
                "details": {"scan_results": [{"rule": "a"}, {"rule": "b"}]},
            })
        );

        let mut rdap =
            json!({"summary": "84 days", "details": {"age_created_in_days": "1", "x": 1}});
        remove_run_fields("rdap_analysis", &mut rdap);
        assert_eq!(rdap, json!({"details": {"x": 1}}));

        // another type's field of the same name is the module's own
        let mut other = json!({"details": {"start_time": "t"}});
        remove_run_fields("archive_analysis", &mut other);
        assert_eq!(other, json!({"details": {"start_time": "t"}}));
    }
}
