//! `test_transforms.py`: 11 cases.

use serde_json::{Value as Json, json};

use super::{ev, evs, js, v};
use crate::correlate::Transform;
use crate::correlate::transform::{Applied, apply};
use crate::value::Map;

fn transform(json: Json) -> Transform {
    let mut json = json;
    json["command"] = json!({"type": "defined", "name": "test"});
    Transform::from_value(&v(json)).expect("a valid transform")
}

fn property(property_type: &str, name: &str, output: &str, event: &mut Map) {
    let t = transform(json!({
        "type": "event", "method": "property", "property_name": name, "property_type": property_type,
    }));
    let events = vec![event.clone()];
    assert!(matches!(
        apply(&t, output, event, &events),
        Ok(Applied::Event)
    ));
}

#[test]
fn test_str_type() {
    let mut event = ev(json!({"field1": "value1"}));
    property("str", "result", "hello world\n", &mut event);
    assert_eq!(js(&event)["result"], json!("hello world"));
}

#[test]
fn test_int_type() {
    let mut event = ev(json!({}));
    property("int", "count", "42\n", &mut event);
    assert_eq!(js(&event)["count"], json!(42));
}

#[test]
#[allow(clippy::approx_constant)] // ace3's value
fn test_float_type() {
    let mut event = ev(json!({}));
    property("float", "score", "3.14\n", &mut event);
    let score = js(&event)["score"].as_f64().expect("a float");
    assert!((score - 3.14).abs() < 1e-9);
}

#[test]
fn test_bool_type() {
    let mut event = ev(json!({}));
    property("bool", "active", "true\n", &mut event);
    assert_eq!(js(&event)["active"], json!(true));
    property("bool", "active", "false\n", &mut event);
    assert_eq!(js(&event)["active"], json!(false));
}

#[test]
fn test_list_type() {
    let mut event = ev(json!({}));
    property("list", "items", "{\"a\": 1}\n{\"b\": 2}\n", &mut event);
    assert_eq!(js(&event)["items"], json!([{"a": 1}, {"b": 2}]));
}

#[test]
fn test_dict_type() {
    let mut event = ev(json!({}));
    property("dict", "data", "{\"key\": \"value\"}", &mut event);
    assert_eq!(js(&event)["data"], json!({"key": "value"}));
}

#[test]
fn test_replaces_stream() {
    let t = transform(json!({"type": "stream", "method": "mutate"}));
    let old = evs(json!([{"old": 1}, {"old": 2}, {"old": 3}]));
    let mut first = old[0].clone();
    let Ok(Applied::Stream {
        events,
        merge_dropped,
    }) = apply(&t, "{\"new\": 1}\n{\"new\": 2}\n", &mut first, &old)
    else {
        panic!("a stream");
    };
    assert_eq!(
        events.iter().map(js).collect::<Vec<_>>(),
        [json!({"new": 1}), json!({"new": 2})]
    );
    // mutate doesn't drop events by timestamp
    assert_eq!(merge_dropped, None);
}

fn merge(existing: Json, output: &str) -> (Vec<Json>, Option<usize>) {
    let t = transform(json!({
        "type": "stream", "method": "merge",
        "merge_time_spec": {"l_field": "time", "l_format": "epoch", "r_field": "time", "r_format": "epoch"},
    }));
    let existing = evs(existing);
    let mut first = existing[0].clone();
    match apply(&t, output, &mut first, &existing) {
        Ok(Applied::Stream {
            events,
            merge_dropped,
        }) => (events.iter().map(js).collect(), merge_dropped),
        _ => panic!("a stream"),
    }
}

fn sources(events: &[Json]) -> Vec<&str> {
    events
        .iter()
        .map(|e| e["src"].as_str().unwrap_or(""))
        .collect()
}

#[test]
fn test_merge_by_time() {
    let (merged, dropped) = merge(
        json!([{"time": "1000", "src": "existing1"}, {"time": "3000", "src": "existing2"}]),
        "{\"time\": \"2000\", \"src\": \"new1\"}\n",
    );
    assert_eq!(sources(&merged), ["existing1", "new1", "existing2"]);
    assert_eq!(dropped, Some(0));
}

#[test]
fn test_merge_same_timestamp_existing_first() {
    let (merged, _) = merge(
        json!([{"time": "1000", "src": "existing"}]),
        "{\"time\": \"1000\", \"src\": \"new\"}\n",
    );
    assert_eq!(sources(&merged), ["existing", "new"]);
}

#[test]
fn test_merge_drops_missing_timestamps() {
    let (merged, dropped) = merge(
        json!([{"time": "1000", "src": "existing"}]),
        "{\"src\": \"no_time\"}\n{\"time\": \"2000\", \"src\": \"with_time\"}\n",
    );
    let s = sources(&merged);
    assert!(!s.contains(&"no_time"));
    assert!(s.contains(&"with_time"));
    // the dropped count is surfaced so the trace can show it
    assert_eq!(dropped, Some(1));
}

#[test]
fn test_merge_drops_unparseable_timestamps() {
    let (merged, dropped) = merge(
        json!([{"time": "1000", "src": "existing"}]),
        "{\"time\": \"not-a-timestamp\", \"src\": \"bad_time\"}\n{\"time\": \"2000\", \"src\": \"with_time\"}\n",
    );
    let s = sources(&merged);
    assert!(!s.contains(&"bad_time"));
    assert!(s.contains(&"with_time"));
    assert_eq!(dropped, Some(1));
}
