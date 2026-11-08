//! The hunt model: what a hunt file's `rule` and `commands` validate into.
//!
//! These are ace3's pydantic models, field for field: `HuntConfig` (`saq/collectors/hunter/
//! base_hunter.py`) with `BaseQueryConfig` and `SummaryDetailConfig` (`saq/query/config.py`) and
//! `QueryHuntConfig` (`query_hunter.py`) as one [`HuntConfig`], since every hunt type ace3 runs is a
//! query hunt; `ObservableMapping` (`saq/observables/mapping.py`) and `IconConfiguration`
//! (`saq/gui/icon.py`); and the correlation schema in [`crate::correlate`]. A hunt type's own
//! fields, such as Splunk's `splunk_config`, are its [`HuntConfig::settings`] ([`crate::types`]).
//!
//! Every model refuses keys it doesn't know, as each of ace3's does (`extra: forbid`). Each is
//! serialized as pydantic's `model_dump(mode="json", by_alias=True)` writes it, every field
//! present with its default, which is the normal form 6.2's comparison diffs.
//!
//! Strings that are Jinja templates (a hunt's name, tags, summary details, pivot links, an
//! observable mapping's type and value, `dedup_key`) are kept as written: 6.3 renders them.

use serde::Serialize;
use serde_json::{Map as JsonMap, Value as Json};

use crate::HuntError;
use crate::correlate::Correlate;
use crate::types::HuntType;
use crate::validate::{
    Errors, Loc, Obj, V, boolean, dict, list, one_of, opt_integer, opt_string, opt_string_list,
    push, raw_dict, string, string_list, value_error,
};
use crate::value::Value;

/// ace3's global defaults for query hunts (`query_hunter` in `etc/saq.default.yaml`), which a hunt
/// that leaves them out takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDefaults {
    pub max_result_count: Option<i128>,
    pub query_timeout: Option<String>,
}

impl Default for QueryDefaults {
    fn default() -> QueryDefaults {
        QueryDefaults {
            max_result_count: Some(100),
            query_timeout: Some("00:30:00".to_owned()),
        }
    }
}

/// A hunt's `rule`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HuntConfig {
    pub query: Option<String>,
    pub query_path: Option<String>,
    pub observable_mapping: Vec<ObservableMapping>,
    pub max_result_count: Option<i128>,
    /// Patterns, matched against a whole value, that no mapping makes an observable of. ace3
    /// compiles them at load and logs one that doesn't compile without failing the hunt; 6.4
    /// compiles them where they're used.
    pub ignored_values: Vec<String>,
    pub summary_details: Vec<SummaryDetail>,
    pub query_prefix: Option<String>,
    pub query_suffix: Option<String>,
    /// Each link as written: ace3's hunt model types these as plain dicts, so it checks nothing
    /// in them at load.
    pub pivot_links: Vec<JsonMap<String, Json>>,
    #[serde(serialize_with = "named_map")]
    pub time_ranges: Option<Vec<(String, TimeRange)>>,
    pub uuid: String,
    pub name: String,
    /// The hunt type, `type` in the file.
    #[serde(rename = "type")]
    pub kind: String,
    pub enabled: bool,
    pub instance_types: Vec<String>,
    pub author: Vec<String>,
    pub description: String,
    pub alert_type: String,
    pub analysis_mode: String,
    /// `HH:MM:SS` (with up to four parts) or a cron expression.
    pub frequency: String,
    pub queue: String,
    pub suppression: Option<String>,
    pub playbook_url: Option<String>,
    pub tags: Vec<String>,
    pub icon_configuration: Option<IconConfiguration>,
    pub alert_template: Option<String>,
    pub time_range: Option<String>,
    pub max_time_range: Option<String>,
    pub full_coverage: bool,
    pub use_index_time: bool,
    pub offset: Option<String>,
    pub group_by: Option<String>,
    pub description_field: Option<String>,
    /// The query file, `search` in the file, read at load (relative to the loader's home).
    #[serde(rename = "search")]
    pub query_file_path: Option<String>,
    pub query_timeout: Option<String>,
    pub auto_append: String,
    pub dedup_key: Option<String>,
    pub correlate: Option<Correlate>,
    /// The hunt type's own fields, as its [`HuntType`] validated them.
    #[serde(flatten)]
    pub settings: JsonMap<String, Json>,
}

fn named_map<S: serde::Serializer, T: Serialize>(
    value: &Option<Vec<(String, T)>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    match value {
        None => serializer.serialize_none(),
        Some(pairs) => {
            let mut map = serializer.serialize_map(Some(pairs.len()))?;
            for (k, v) in pairs {
                map.serialize_entry(k, v)?;
            }
            map.end()
        }
    }
}

/// One of `time_ranges`: what a `<TIMESPEC_NAME>` token in the query spans.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimeRange {
    pub duration_before: Option<String>,
    pub duration_after: Option<String>,
}

/// One of `observable_mapping`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ObservableMapping {
    pub field: Option<String>,
    /// The fields, `[field]` when only `field` was given.
    pub fields: Vec<String>,
    /// The observable type, or a Jinja template that renders to one.
    #[serde(rename = "type")]
    pub kind: String,
    pub tags: Vec<String>,
    pub directives: Vec<String>,
    pub time: bool,
    pub ignored_values: Vec<String>,
    pub display_type: Option<String>,
    pub display_value: Option<String>,
    /// `all` or `any`.
    pub fields_mode: String,
    pub field_lookup_type: Option<String>,
    pub value: Option<String>,
    pub file_name: Option<String>,
    /// `base64` or `ascii_hex`.
    pub file_decoder: Option<String>,
    pub volatile: bool,
    pub relationships: Vec<RelationshipMapping>,
    pub limit: Option<i128>,
    pub fallback_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RelationshipMapping {
    #[serde(rename = "type")]
    pub kind: String,
    pub target: RelationshipTarget,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RelationshipTarget {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

/// One of `summary_details`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SummaryDetail {
    pub content: String,
    pub header: Option<String>,
    /// `md`, `pre`, `txt` or `jinja`; ace3 logs any other and takes `md`.
    pub format: String,
    pub limit: i128,
    pub grouped: bool,
    pub dedup_fields: Option<Vec<String>>,
    pub required_fields: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IconConfiguration {
    pub blueprint_file_location: Option<BlueprintFileLocation>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BlueprintFileLocation {
    pub name: String,
    pub path: String,
}

/// Turns a field's validation into one that takes `Optional[...]`.
pub fn optional<T>(
    f: impl FnOnce(&Value, &[Loc], &mut Errors) -> V<T>,
) -> impl FnOnce(&Value, &[Loc], &mut Errors) -> V<Option<T>> {
    move |v, loc, errs| match v {
        Value::Null => Ok(Some(None)),
        other => Ok(f(other, loc, errs)?.map(Some)),
    }
}

/// Collects the fields of a model, `None` if any failed.
macro_rules! all {
    ($($field:ident),+ $(,)?) => {
        (|| Some(($($field?,)+)))()
    };
}
pub(crate) use all;

static TIMEDELTA: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    // Python's `$` also matches before a final newline; `\d` is any Unicode digit in both
    regex::Regex::new(r"^(\d+:)?(\d+:)?(\d+:)?\d+\n?$").expect("a valid pattern")
});

/// `HH:MM:SS` with up to four parts, as ace3's `is_timedelta_string`.
pub fn is_timedelta_string(value: &str) -> bool {
    TIMEDELTA.is_match(value)
}

/// `HuntConfig.validate_frequency`: a timedelta string or a cron expression croniter takes.
fn check_frequency(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("frequency must not be empty");
    }
    if is_timedelta_string(value) {
        return Ok(());
    }
    match croner::parser::CronParser::new().parse(value) {
        Ok(_) => Ok(()),
        Err(_) => Err("frequency must be a timedelta string or a valid cron expression"),
    }
}

impl HuntConfig {
    /// Validates a hunt's `rule` as `kind`'s config class does.
    pub fn validate(
        v: &Value,
        kind: &dyn HuntType,
        defaults: &QueryDefaults,
        errs: &mut Errors,
    ) -> V<HuntConfig> {
        let loc: Vec<Loc> = Vec::new();
        let Some(mut o) = Obj::new(v, &loc, kind.model(), errs) else {
            return Ok(None);
        };
        let query = o.default(errs, "query", None, opt_string)?;
        let query_path = o.default(errs, "query_path", None, opt_string)?;
        let observable_mapping = o.default(errs, "observable_mapping", Vec::new(), |v, l, e| {
            list(v, l, e, ObservableMapping::validate)
        })?;
        let max_result_count = o.default(
            errs,
            "max_result_count",
            defaults.max_result_count,
            opt_integer,
        )?;
        let ignored_values = o.default(errs, "ignored_values", Vec::new(), string_list)?;
        let summary_details = o.default(errs, "summary_details", Vec::new(), |v, l, e| {
            list(v, l, e, SummaryDetail::validate)
        })?;
        let query_prefix = o.default(errs, "query_prefix", None, opt_string)?;
        let query_suffix = o.default(errs, "query_suffix", None, opt_string)?;
        let pivot_links = o.default(errs, "pivot_links", Vec::new(), |v, l, e| {
            list(v, l, e, raw_dict)
        })?;
        let time_ranges = o.default(errs, "time_ranges", None, validate_time_ranges)?;
        let uuid = o.required(errs, "uuid", string)?;
        let name = o.required(errs, "name", string)?;
        let kind_name = o.required(errs, "type", string)?;
        let enabled = o.required(errs, "enabled", boolean)?;
        let instance_types = o.default(errs, "instance_types", Vec::new(), string_list)?;
        let author = o.default(errs, "author", Vec::new(), |v, l, e| match v {
            // normalize_author, a before validator
            Value::Null => Ok(Some(Vec::new())),
            Value::Str(s) => Ok(Some(vec![s.clone()])),
            other => string_list(other, l, e),
        })?;
        let description = o.required(errs, "description", string)?;
        let alert_type = o.required(errs, "alert_type", string)?;
        let analysis_mode = o.default(errs, "analysis_mode", "correlation".to_owned(), string)?;
        let frequency = o.required(errs, "frequency", |v, l, e| {
            let Some(s) = string(v, l, e)? else {
                return Ok(None);
            };
            match check_frequency(&s) {
                Ok(()) => Ok(Some(s)),
                Err(message) => {
                    value_error(e, l, message);
                    Ok(None)
                }
            }
        })?;
        let queue = o.default(errs, "queue", "default".to_owned(), string)?;
        let suppression = o.default(errs, "suppression", None, opt_string)?;
        let playbook_url = o.default(errs, "playbook_url", None, opt_string)?;
        let tags = o.default(errs, "tags", Vec::new(), string_list)?;
        let icon_configuration = o.default(
            errs,
            "icon_configuration",
            None,
            optional(IconConfiguration::validate),
        )?;
        let alert_template = o.default(errs, "alert_template", None, opt_string)?;
        let time_range = o.default(errs, "time_range", None, opt_string)?;
        let max_time_range = o.default(errs, "max_time_range", None, opt_string)?;
        let full_coverage = o.required(errs, "full_coverage", boolean)?;
        let use_index_time = o.required(errs, "use_index_time", boolean)?;
        let offset = o.default(errs, "offset", None, opt_string)?;
        let group_by = o.default(errs, "group_by", None, opt_string)?;
        let description_field = o.default(errs, "description_field", None, opt_string)?;
        let query_file_path = o.default(errs, "search", None, opt_string)?;
        let query_timeout = o.default(
            errs,
            "query_timeout",
            defaults.query_timeout.clone(),
            opt_string,
        )?;
        let auto_append = o.default(errs, "auto_append", kind.auto_append().to_owned(), string)?;
        let dedup_key = o.default(errs, "dedup_key", None, opt_string)?;
        let correlate = o.default(errs, "correlate", None, optional(Correlate::validate))?;
        let settings = kind.settings(&mut o, errs)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        let Some((
            query,
            query_path,
            observable_mapping,
            max_result_count,
            ignored_values,
            summary_details,
            query_prefix,
            query_suffix,
            pivot_links,
            time_ranges,
            uuid,
            name,
            kind_name,
            enabled,
            instance_types,
            author,
            description,
            alert_type,
            analysis_mode,
            frequency,
            queue,
            suppression,
            playbook_url,
            tags,
            icon_configuration,
            alert_template,
            time_range,
            max_time_range,
            full_coverage,
            use_index_time,
            offset,
            group_by,
            description_field,
            query_file_path,
            query_timeout,
            auto_append,
            dedup_key,
            correlate,
            settings,
        )) = all!(
            query,
            query_path,
            observable_mapping,
            max_result_count,
            ignored_values,
            summary_details,
            query_prefix,
            query_suffix,
            pivot_links,
            time_ranges,
            uuid,
            name,
            kind_name,
            enabled,
            instance_types,
            author,
            description,
            alert_type,
            analysis_mode,
            frequency,
            queue,
            suppression,
            playbook_url,
            tags,
            icon_configuration,
            alert_template,
            time_range,
            max_time_range,
            full_coverage,
            use_index_time,
            offset,
            group_by,
            description_field,
            query_file_path,
            query_timeout,
            auto_append,
            dedup_key,
            correlate,
            settings,
        )
        else {
            return Ok(None);
        };
        let config = HuntConfig {
            query,
            query_path,
            observable_mapping,
            max_result_count,
            ignored_values,
            summary_details,
            query_prefix,
            query_suffix,
            pivot_links,
            time_ranges,
            uuid,
            name,
            kind: kind_name,
            enabled,
            instance_types,
            author,
            description,
            alert_type,
            analysis_mode,
            frequency,
            queue,
            suppression,
            playbook_url,
            tags,
            icon_configuration,
            alert_template,
            time_range,
            max_time_range,
            full_coverage,
            use_index_time,
            offset,
            group_by,
            description_field,
            query_file_path,
            query_timeout,
            auto_append,
            dedup_key,
            correlate,
            settings,
        };
        // QueryHuntConfig.validate_time_range_source, then the type's own
        if let Err(message) = config
            .check_time_range_source()
            .and_then(|()| kind.check(&config))
        {
            value_error(errs, &loc, &message);
            return Ok(None);
        }
        Ok(Some(config))
    }

    /// Every string of the hunt that ace3 renders as a Jinja template against an event, with
    /// where it is: what 6.3 renders. The query's own tokens (`<TIMESPEC>`, `<include:...>`)
    /// aren't Jinja and aren't here.
    pub fn templates(&self) -> Vec<(String, &str)> {
        let mut out: Vec<(String, &str)> = vec![("name".to_owned(), self.name.as_str())];
        fn add<'a>(out: &mut Vec<(String, &'a str)>, at: String, text: Option<&'a str>) {
            if let Some(text) = text {
                out.push((at, text));
            }
        }
        add(
            &mut out,
            "playbook_url".to_owned(),
            self.playbook_url.as_deref(),
        );
        add(&mut out, "dedup_key".to_owned(), self.dedup_key.as_deref());
        for (i, tag) in self.tags.iter().enumerate() {
            add(&mut out, format!("tags/{i}"), Some(tag));
        }
        for (i, link) in self.pivot_links.iter().enumerate() {
            for field in ["url", "text"] {
                add(
                    &mut out,
                    format!("pivot_links/{i}/{field}"),
                    link.get(field).and_then(Json::as_str),
                );
            }
        }
        for (i, detail) in self.summary_details.iter().enumerate() {
            add(
                &mut out,
                format!("summary_details/{i}/content"),
                Some(&detail.content),
            );
            add(
                &mut out,
                format!("summary_details/{i}/header"),
                detail.header.as_deref(),
            );
        }
        for (i, mapping) in self.observable_mapping.iter().enumerate() {
            let at = |field: &str| format!("observable_mapping/{i}/{field}");
            add(&mut out, at("type"), Some(&mapping.kind));
            add(&mut out, at("value"), mapping.value.as_deref());
            add(&mut out, at("file_name"), mapping.file_name.as_deref());
            for (j, tag) in mapping.tags.iter().enumerate() {
                add(&mut out, at(&format!("tags/{j}")), Some(tag));
            }
            for (j, directive) in mapping.directives.iter().enumerate() {
                add(&mut out, at(&format!("directives/{j}")), Some(directive));
            }
            for (j, relationship) in mapping.relationships.iter().enumerate() {
                add(
                    &mut out,
                    at(&format!("relationships/{j}/target/value")),
                    Some(&relationship.target.value),
                );
            }
        }
        out
    }

    fn check_time_range_source(&self) -> Result<(), String> {
        let timespec = self.time_ranges.as_ref().is_some_and(|ranges| {
            ranges
                .iter()
                .any(|(name, range)| name == "TIMESPEC" && range.duration_before.is_some())
        });
        if self.time_range.is_none() && !timespec {
            return Err(
                "Either 'time_range' or 'time_ranges' with a TIMESPEC entry must be specified"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// `time_ranges`: its `normalize_time_ranges` before validator, which takes a string as the
/// lookback alone, then `dict[str, TimeRangeConfig]`.
fn validate_time_ranges(
    v: &Value,
    loc: &[Loc],
    errs: &mut Errors,
) -> V<Option<Vec<(String, TimeRange)>>> {
    let map = match v {
        Value::Null => return Ok(Some(None)),
        Value::Map(map) => map,
        other => {
            return Err(HuntError::python(
                "AttributeError",
                format!("'{}' object has no attribute 'items'", other.type_name()),
            ));
        }
    };
    let mut normalized = crate::value::Map::new();
    for (k, item) in map.iter() {
        let item = match item {
            Value::Str(s) => {
                let mut range = crate::value::Map::new();
                range.insert(Value::str("duration_before"), Value::Str(s.clone()));
                range.insert(Value::str("duration_after"), Value::Null);
                Value::Map(range)
            }
            other => other.clone(),
        };
        normalized.insert(k.clone(), item);
    }
    Ok(dict(&Value::Map(normalized), loc, errs, TimeRange::validate)?.map(Some))
}

impl TimeRange {
    fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<TimeRange> {
        let Some(mut o) = Obj::new(v, loc, "TimeRangeConfig", errs) else {
            return Ok(None);
        };
        let duration_before = o.default(errs, "duration_before", None, opt_string)?;
        let duration_after = o.default(errs, "duration_after", None, opt_string)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        Ok(
            all!(duration_before, duration_after).map(|(duration_before, duration_after)| {
                TimeRange {
                    duration_before,
                    duration_after,
                }
            }),
        )
    }
}

impl ObservableMapping {
    pub fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<ObservableMapping> {
        let Some(mut o) = Obj::new(v, loc, "ObservableMapping", errs) else {
            return Ok(None);
        };
        let field = o.default(errs, "field", None, opt_string)?;
        let fields = o.default(errs, "fields", Vec::new(), string_list)?;
        let kind = o.required(errs, "type", string)?;
        let tags = o.default(errs, "tags", Vec::new(), string_list)?;
        let directives = o.default(errs, "directives", Vec::new(), string_list)?;
        let time = o.default(errs, "time", false, boolean)?;
        let ignored_values = o.default(errs, "ignored_values", Vec::new(), string_list)?;
        let display_type = o.default(errs, "display_type", None, opt_string)?;
        let display_value = o.default(errs, "display_value", None, opt_string)?;
        let fields_mode = o.default(errs, "fields_mode", "all".to_owned(), |v, l, e| {
            one_of(v, l, e, &["any", "all"])
        })?;
        let field_lookup_type = o.default(
            errs,
            "field_lookup_type",
            Some("key".to_owned()),
            opt_string,
        )?;
        let value = o.default(errs, "value", None, opt_string)?;
        let file_name = o.default(errs, "file_name", None, opt_string)?;
        let file_decoder = o.default(
            errs,
            "file_decoder",
            None,
            optional(|v, l, e| one_of(v, l, e, &["base64", "ascii_hex"])),
        )?;
        let volatile = o.default(errs, "volatile", false, boolean)?;
        let relationships = o.default(errs, "relationships", Vec::new(), |v, l, e| {
            list(v, l, e, RelationshipMapping::validate)
        })?;
        let limit = o.default(errs, "limit", None, |v, l, e| {
            let Some(limit) = opt_integer(v, l, e)? else {
                return Ok(None);
            };
            if limit.is_some_and(|n| n < 1) {
                push(
                    e,
                    l,
                    "greater_than_equal",
                    "Input should be greater than or equal to 1",
                );
                return Ok(None);
            }
            Ok(Some(limit))
        })?;
        let fallback_type = o.default(errs, "fallback_type", None, opt_string)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        let Some((
            field,
            fields,
            kind,
            tags,
            directives,
            time,
            ignored_values,
            display_type,
            display_value,
            fields_mode,
            field_lookup_type,
            value,
            file_name,
            file_decoder,
            volatile,
            relationships,
            limit,
            fallback_type,
        )) = all!(
            field,
            fields,
            kind,
            tags,
            directives,
            time,
            ignored_values,
            display_type,
            display_value,
            fields_mode,
            field_lookup_type,
            value,
            file_name,
            file_decoder,
            volatile,
            relationships,
            limit,
            fallback_type,
        )
        else {
            return Ok(None);
        };
        let mut mapping = ObservableMapping {
            field,
            fields,
            kind,
            tags,
            directives,
            time,
            ignored_values,
            display_type,
            display_value,
            fields_mode,
            field_lookup_type,
            value,
            file_name,
            file_decoder,
            volatile,
            relationships,
            limit,
            fallback_type,
        };
        if let Err(message) = mapping.check() {
            value_error(errs, loc, message);
            return Ok(None);
        }
        Ok(Some(mapping))
    }

    /// The mapping's after validators, in ace3's order.
    fn check(&mut self) -> Result<(), &'static str> {
        let field_given = self.field.as_deref().is_some_and(|f| !f.is_empty());
        if !field_given && self.fields.is_empty() {
            return Err("Either 'field' or 'fields' must be specified in observable mapping");
        }
        if field_given
            && self.fields.is_empty()
            && let Some(field) = &self.field
        {
            self.fields = vec![field.clone()];
        }
        if self.fields_mode == "any" && self.value.is_some() {
            return Err("fields_mode='any' cannot be used with a custom 'value' template");
        }
        if self.kind == "file" && self.display_value.is_some() {
            return Err("display_value is not supported for file type observables (type=file)");
        }
        if self.kind.contains("{{") {
            if self.file_name.is_some() || self.file_decoder.is_some() {
                return Err(
                    "file_name/file_decoder cannot be used with a Jinja-templated 'type' (file observables require a static 'file' type)",
                );
            }
        } else if self.fallback_type.is_some() {
            return Err("fallback_type is only valid when 'type' is a Jinja template");
        }
        if let Some(fallback) = &self.fallback_type {
            if fallback.contains("{{") {
                return Err("fallback_type must be a static observable type, not a template");
            }
            if fallback == "file" {
                return Err(
                    "fallback_type cannot be 'file' (file observables require file_name handling)",
                );
            }
        }
        Ok(())
    }
}

impl RelationshipMapping {
    fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<RelationshipMapping> {
        let Some(mut o) = Obj::new(v, loc, "RelationshipMapping", errs) else {
            return Ok(None);
        };
        let kind = o.required(errs, "type", string)?;
        let target = o.required(errs, "target", |v, l, e| {
            let Some(mut t) = Obj::new(v, l, "RelationshipMappingTarget", e) else {
                return Ok(None);
            };
            let kind = t.required(e, "type", string)?;
            let value = t.required(e, "value", string)?;
            if !t.finish(e) {
                return Ok(None);
            }
            Ok(all!(kind, value).map(|(kind, value)| RelationshipTarget { kind, value }))
        })?;
        if !o.finish(errs) {
            return Ok(None);
        }
        Ok(all!(kind, target).map(|(kind, target)| RelationshipMapping { kind, target }))
    }
}

impl SummaryDetail {
    fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<SummaryDetail> {
        let Some(mut o) = Obj::new(v, loc, "SummaryDetailConfig", errs) else {
            return Ok(None);
        };
        let content = o.required(errs, "content", string)?;
        let header = o.default(errs, "header", None, opt_string)?;
        let format = o.default(errs, "format", "md".to_owned(), |v, l, e| {
            // validate_format logs a format it doesn't know, and takes markdown
            Ok(string(v, l, e)?.map(|f| {
                if ["md", "pre", "txt", "jinja"].contains(&f.as_str()) {
                    f
                } else {
                    "md".to_owned()
                }
            }))
        })?;
        let limit = o.default(errs, "limit", 100, crate::validate::integer)?;
        let grouped = o.default(errs, "grouped", false, boolean)?;
        let dedup_fields = o.default(errs, "dedup_fields", None, opt_string_list)?;
        let required_fields = o.default(errs, "required_fields", None, opt_string_list)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        Ok(all!(
            content,
            header,
            format,
            limit,
            grouped,
            dedup_fields,
            required_fields
        )
        .map(
            |(content, header, format, limit, grouped, dedup_fields, required_fields)| {
                SummaryDetail {
                    content,
                    header,
                    format,
                    limit,
                    grouped,
                    dedup_fields,
                    required_fields,
                }
            },
        ))
    }
}

impl IconConfiguration {
    fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<IconConfiguration> {
        let Some(mut o) = Obj::new(v, loc, "IconConfiguration", errs) else {
            return Ok(None);
        };
        let blueprint_file_location = o.default(
            errs,
            "blueprint_file_location",
            None,
            optional(|v, l, e| {
                let Some(mut b) = Obj::new(v, l, "BlueprintFileLocation", e) else {
                    return Ok(None);
                };
                let name = b.required(e, "name", string)?;
                let path = b.required(e, "path", string)?;
                if !b.finish(e) {
                    return Ok(None);
                }
                Ok(all!(name, path).map(|(name, path)| BlueprintFileLocation { name, path }))
            }),
        )?;
        let url = o.default(errs, "url", None, opt_string)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        Ok(
            all!(blueprint_file_location, url).map(|(blueprint_file_location, url)| {
                IconConfiguration {
                    blueprint_file_location,
                    url,
                }
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timedelta_strings_match_ace3s_pattern() {
        for ok in ["00:15:00", "01:00:00:00", "5", "1:2", "00:00:10\n"] {
            assert!(is_timedelta_string(ok), "{ok}");
        }
        for bad in ["", "1:2:3:4:5", "a", "1::2", "*/5 * * * *", " 1"] {
            assert!(!is_timedelta_string(bad), "{bad}");
        }
    }

    #[test]
    fn a_hunts_templates_are_listed_with_where_they_are() {
        let rule = crate::yaml::load(
            "uuid: u\nname: '{{ user }} signed in'\ntype: splunk\nenabled: true\ndescription: d\n\
             alert_type: a\nfrequency: '00:01:00'\ntime_range: '00:01:00'\nfull_coverage: true\n\
             use_index_time: true\ntags: ['{{ tag }}']\nobservable_mapping:\n  - field: f\n    \
             type: '{{ kind }}'\n    fallback_type: fqdn\n",
            "rule.yaml",
            &mut crate::yaml::Budget::new(crate::yaml::Limits::default()),
        )
        .unwrap();
        let config = HuntConfig::validate(
            &rule,
            &crate::types::Splunk::default(),
            &QueryDefaults::default(),
            &mut Vec::new(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            config.templates(),
            [
                ("name".to_owned(), "{{ user }} signed in"),
                ("tags/0".to_owned(), "{{ tag }}"),
                ("observable_mapping/0/type".to_owned(), "{{ kind }}"),
            ]
        );
    }

    #[test]
    fn frequencies_are_timedeltas_or_cron() {
        assert!(check_frequency("*/5 * * * *").is_ok());
        assert!(check_frequency("@hourly").is_ok());
        assert!(check_frequency("every day").is_err());
        assert_eq!(check_frequency(""), Err("frequency must not be empty"));
    }
}
