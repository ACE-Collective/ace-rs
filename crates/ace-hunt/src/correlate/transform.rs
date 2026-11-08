//! What a transform does with its command's output (`transforms.py`): an event transform sets a
//! property, the output read as its `property_type`; a stream transform replaces the stream with the
//! output's JSON lines (`mutate`) or merges them into it by time (`merge`).

use std::cmp::Ordering;

use super::engine::EngineError;
use super::time::{Time, parse_time_value, py_float};
use super::{MergeTimeSpec, Transform};
use crate::render::json::loads;
use crate::render::methods::is_space;
use crate::value::{Map, Value};

/// What a transform made.
#[derive(Debug, Clone)]
pub enum Applied {
    /// An event transform set its property on the event.
    Event,
    /// A stream transform's new stream, and for a merge how many incoming events it dropped for a
    /// missing or unreadable time.
    Stream {
        events: Vec<Map>,
        merge_dropped: Option<usize>,
    },
}

/// Why a transform failed: a step error, or an output that ends the correlation.
#[derive(Debug, Clone)]
pub enum TransformError {
    Step(String),
    Run(EngineError),
}

impl From<String> for TransformError {
    fn from(s: String) -> TransformError {
        TransformError::Step(s)
    }
}

/// `apply_transform`.
pub fn apply(
    transform: &Transform,
    output: &str,
    event: &mut Map,
    events: &[Map],
) -> Result<Applied, TransformError> {
    if transform.kind == "event" {
        if transform.method != "property" {
            return Err(TransformError::Step(format!(
                "ValueError: invalid event transform method: {}",
                transform.method
            )));
        }
        let value = property_value(output, &transform.property_type)?;
        let name = transform.property_name.clone().unwrap_or_default();
        event.insert(Value::Str(name), value);
        return Ok(Applied::Event);
    }
    match transform.method.as_str() {
        "mutate" => Ok(Applied::Stream {
            events: json_lines(output)?
                .into_iter()
                .map(stream_event)
                .collect::<Result<_, _>>()?,
            merge_dropped: None,
        }),
        "merge" => {
            let spec = transform.merge_time_spec.as_ref().ok_or_else(|| {
                TransformError::Step("'merge_time_spec' is required for merge method".to_owned())
            })?;
            let (events, dropped) = merge(output, events, spec)?;
            Ok(Applied::Stream {
                events,
                merge_dropped: Some(dropped),
            })
        }
        other => Err(TransformError::Step(format!(
            "ValueError: invalid stream transform method: {other}"
        ))),
    }
}

/// A stream event must be a JSON object: ace3 takes any JSON value into its stream and then fails
/// on the first step or extraction that reads one as a dict, which ends its run; ace4 ends it here.
fn stream_event(value: Value) -> Result<Map, TransformError> {
    match value {
        Value::Map(m) => Ok(m),
        other => Err(TransformError::Run(EngineError::Raised(format!(
            "AttributeError: a stream event is a {}, not a dict",
            other.type_name()
        )))),
    }
}

/// The output's non-blank lines, each read as JSON.
fn json_lines(output: &str) -> Result<Vec<Value>, String> {
    output
        .trim_matches(is_space)
        .lines()
        .map(|l| l.trim_matches(is_space))
        .filter(|l| !l.is_empty())
        .map(|l| loads(l).map_err(|e| format!("JSONDecodeError: {}", e.0)))
        .collect()
}

/// `_parse_property_value`.
pub fn property_value(output: &str, property_type: &str) -> Result<Value, String> {
    let stripped = output.trim_matches(is_space);
    match property_type {
        "list" => Ok(Value::Seq(json_lines(output)?)),
        "dict" => loads(output).map_err(|e| format!("JSONDecodeError: {}", e.0)),
        "int" => py_int(stripped).map(Value::Int).ok_or_else(|| {
            format!(
                "ValueError: invalid literal for int() with base 10: {}",
                crate::value::py_repr(stripped)
            )
        }),
        "float" => py_float(&Value::Str(stripped.to_owned())).map(Value::Float),
        "bool" => Ok(Value::Bool(
            ["true", "1", "yes"].contains(&stripped.to_lowercase().as_str()),
        )),
        _ => Ok(Value::Str(stripped.to_owned())),
    }
}

/// Python's `int(text)` in base 10: a sign, digits and `_` between them.
fn py_int(text: &str) -> Option<i128> {
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    let n: i128 = digits.replace('_', "").parse().ok()?;
    Some(if negative { -n } else { n })
}

/// `_apply_merge`: the incoming events with a readable time interleaved with the existing ones by
/// time, an existing event first on a tie, after the existing events that have no time.
fn merge(
    output: &str,
    existing: &[Map],
    spec: &MergeTimeSpec,
) -> Result<(Vec<Map>, usize), TransformError> {
    let mut dropped = 0;
    let mut incoming: Vec<Map> = Vec::new();
    for value in json_lines(output)? {
        let event = stream_event(value)?;
        if !event.contains(&spec.r_field) {
            dropped += 1;
            continue;
        }
        incoming.push(event);
    }
    let mut timeless: Vec<Map> = Vec::new();
    let mut timed: Vec<(Time, u8, Map)> = Vec::new();
    for e in existing {
        let ts = e
            .get(&spec.l_field)
            .and_then(|v| parse_time_value(v, Some(&spec.l_format)).ok());
        match ts {
            Some(ts) => timed.push((ts, 0, e.clone())),
            None => timeless.push(e.clone()),
        }
    }
    for e in incoming {
        let ts = e
            .get(&spec.r_field)
            .map(|v| parse_time_value(v, Some(&spec.r_format)));
        match ts {
            Some(Ok(ts)) => timed.push((ts, 1, e)),
            _ => dropped += 1,
        }
    }
    let aware = timed.iter().any(|(t, _, _)| matches!(t, Time::Aware(_)));
    let naive = timed.iter().any(|(t, _, _)| matches!(t, Time::Naive(_)));
    if aware && naive {
        return Err(TransformError::Step(
            "TypeError: can't compare offset-naive and offset-aware datetimes".to_owned(),
        ));
    }
    timed.sort_by(|a, b| {
        a.0.py_cmp(&b.0)
            .unwrap_or(Ordering::Equal)
            .then(a.1.cmp(&b.1))
    });
    timeless.extend(timed.into_iter().map(|(_, _, e)| e));
    Ok((timeless, dropped))
}
