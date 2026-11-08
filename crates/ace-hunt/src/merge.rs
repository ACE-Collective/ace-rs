//! ace3's `deep_merge` (`saq/collectors/hunter/loader.py`): how a file's values combine with what
//! it includes.
//!
//! A key the base doesn't have is added. Two mappings merge key by key. Two lists combine: an
//! observable mapping (a mapping with `type` and `field` or `fields`) replaces the base's entry
//! with the same type and fields where it stands, and any other item is appended unless an equal
//! one is already there. Anything else replaces the base's value.

use crate::HuntError;
use crate::value::{Map, Value, py_eq};

/// `_get_observable_mapping_identity`: its type and the set of its fields, or None for an item
/// that isn't an observable mapping.
fn identity(item: &Value) -> Result<Option<(Value, Vec<Value>)>, HuntError> {
    let Value::Map(map) = item else {
        return Ok(None);
    };
    let Some(kind) = map.get("type") else {
        return Ok(None);
    };
    let fields = match map.get("fields").filter(|f| f.truthy()) {
        Some(fields) => fields.clone(),
        None => match map.get("field").filter(|f| f.truthy()) {
            Some(field) => Value::Seq(vec![field.clone()]),
            None => return Ok(None),
        },
    };
    let unhashable =
        |v: &Value| HuntError::python("TypeError", format!("unhashable type: '{}'", v.type_name()));
    if matches!(kind, Value::Seq(_) | Value::Map(_)) {
        return Err(unhashable(kind));
    }
    let mut set: Vec<Value> = Vec::new();
    for field in fields
        .py_iter()
        .map_err(|m| HuntError::python("TypeError", m))?
    {
        if matches!(field, Value::Seq(_) | Value::Map(_)) {
            return Err(unhashable(&field));
        }
        if !set.iter().any(|f| py_eq(f, &field)) {
            set.push(field);
        }
    }
    Ok(Some((kind.clone(), set)))
}

fn same_identity(a: &(Value, Vec<Value>), b: &(Value, Vec<Value>)) -> bool {
    py_eq(&a.0, &b.0)
        && a.1.len() == b.1.len()
        && a.1.iter().all(|x| b.1.iter().any(|y| py_eq(x, y)))
}

/// Merges `over` into `base`.
pub fn deep_merge(base: &Map, over: &Map) -> Result<Map, HuntError> {
    let mut result = base.clone();
    for (k, value) in over.iter() {
        let merged = match (result.get_value(k), value) {
            (None, _) => value.clone(),
            (Some(Value::Map(b)), Value::Map(o)) => Value::Map(deep_merge(b, o)?),
            (Some(Value::Seq(b)), Value::Seq(o)) => {
                let mut list = b.clone();
                // the identities of the base's items; a later equal identity takes the index
                let mut identities: Vec<((Value, Vec<Value>), usize)> = Vec::new();
                for (i, existing) in list.iter().enumerate() {
                    if let Some(id) = identity(existing)? {
                        match identities
                            .iter_mut()
                            .find(|(other, _)| same_identity(other, &id))
                        {
                            Some(entry) => entry.1 = i,
                            None => identities.push((id, i)),
                        }
                    }
                }
                for item in o {
                    let found = match identity(item)? {
                        Some(id) => identities
                            .iter()
                            .find(|(other, _)| same_identity(other, &id))
                            .map(|(_, i)| *i),
                        None => None,
                    };
                    match found {
                        Some(i) => list[i] = item.clone(),
                        None if !list.iter().any(|x| py_eq(x, item)) => list.push(item.clone()),
                        None => {}
                    }
                }
                Value::Seq(list)
            }
            (Some(_), _) => value.clone(),
        };
        result.insert(k.clone(), merged);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml::{Budget, Limits, load};

    fn yaml(text: &str) -> Map {
        match load(text, "test.yaml", &mut Budget::new(Limits::default())).unwrap() {
            Value::Map(m) => m,
            other => panic!("{other:?}"),
        }
    }

    fn merged(base: &str, over: &str) -> serde_json::Value {
        Value::Map(deep_merge(&yaml(base), &yaml(over)).unwrap()).to_json()
    }

    #[test]
    fn values_dicts_and_lists_merge_as_ace3s() {
        assert_eq!(
            merged(
                "a: 1\nb: {x: 1, y: 2}\nc: [1, 2]\nd: [1]",
                "a: 2\nb: {y: 3}\nc: [2, 3]\nd: {k: v}\ne: 5"
            ),
            serde_json::json!({"a": 2, "b": {"x": 1, "y": 3}, "c": [1, 2, 3], "d": {"k": "v"}, "e": 5})
        );
    }

    #[test]
    fn an_observable_mapping_replaces_the_one_with_its_type_and_fields() {
        let out = merged(
            "m: [{field: a, type: ip, tags: [x]}, {fields: [b, c], type: user}, {field: d, type: url}]",
            "m: [{fields: [a], type: ip, tags: [y]}, {fields: [c, b], type: user, directives: [z]}, {field: d, type: fqdn}]",
        );
        assert_eq!(
            out["m"],
            serde_json::json!([
                {"fields": ["a"], "type": "ip", "tags": ["y"]},
                {"fields": ["c", "b"], "type": "user", "directives": ["z"]},
                {"field": "d", "type": "url"},
                {"field": "d", "type": "fqdn"},
            ])
        );
    }

    #[test]
    fn list_items_compare_as_python_does() {
        assert_eq!(
            merged("l: [1, a]", "l: [true, 1.0, a, b]")["l"],
            serde_json::json!([1, "a", "b"])
        );
    }
}
