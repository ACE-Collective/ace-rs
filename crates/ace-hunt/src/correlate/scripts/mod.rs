//! The script command types (PLAN.md decision 16): what each of the 7 Python scripts the
//! signatures' hunts run under `hunts/scripts/` computes, in Rust, with the network of [`Net`].
//! Each reads its arguments as the script's `argparse` parser does ([`argparse`]), takes its input
//! as the script does, and writes what the script prints: JSON as Python's `json.dumps` writes it,
//! with the script's keys in the script's order.
//!
//! Only each script's logic is here, never detection content (decision 16). A list a script holds
//! is logic when it is how the script reads its input or decides what it reports, such as a
//! provider's id format, the role mailboxes it probes or the score's thresholds, and content when
//! it is a tuned lexicon or a site's own value. Content comes from the signatures checkout at run
//! time, as the files a command stages (`removed_hunt_two.json`, `proxy_ip_ranges.json`), or
//! from the hunter's configuration (`removed_hunt_three`'s settings). Each module says which of its
//! lists is which.
//!
//! [`SCRIPTS`] is each script's path, as the hunts' predefined commands give it, and its type's
//! name: an executable command whose path ends with that path runs the type ([`super::script`]).

pub mod argparse;
pub mod signature_name_12;
pub mod removed_hunt_one;
pub mod dns_lookup;
pub mod signature_name_11;
pub mod ip;
pub mod is_proxy_ip;
pub mod removed_hunt_three;
pub mod signature_name_13;

#[cfg(test)]
pub(crate) mod cases;

use std::sync::Arc;

use super::net::Net;
use super::pyjson;
use super::script::{Script, ScriptExit};
use crate::value::{Map, Value, py_repr};

/// Each script's path under a signatures checkout and its type's name.
pub const SCRIPTS: [(&str, &str); 7] = [
    ("hunts/scripts/signature_name_12.py", "signature_name_12"),
    ("hunts/scripts/removed_hunt_one.py", "removed_hunt_one"),
    ("hunts/scripts/dns_lookup.py", "dns_lookup"),
    ("hunts/scripts/signature_name_11.py", "signature_name_11"),
    ("hunts/scripts/is_proxy_ip.py", "is_proxy_ip"),
    ("hunts/scripts/removed_hunt_three.py", "removed_hunt_three"),
    ("hunts/scripts/signature_name_13.py", "signature_name_13"),
];

/// Builds the type named `name` (one of [`SCRIPTS`]) over `net`, with its settings from the
/// hunter's configuration (`Value::Null` for none), or why it can't be built.
pub fn build(
    name: &str,
    net: &Net,
    settings: &serde_json::Value,
) -> Result<Arc<dyn Script>, String> {
    let no_settings = |name: &str| -> Result<(), String> {
        match settings {
            serde_json::Value::Null => Ok(()),
            serde_json::Value::Object(m) if m.is_empty() => Ok(()),
            _ => Err(format!("{name} takes no settings")),
        }
    };
    Ok(match name {
        "signature_name_12" => {
            no_settings(name)?;
            Arc::new(signature_name_12::BeaconScore)
        }
        "removed_hunt_one" => {
            no_settings(name)?;
            Arc::new(removed_hunt_one::CertOwnership { net: net.clone() })
        }
        "dns_lookup" => {
            no_settings(name)?;
            Arc::new(dns_lookup::DnsLookup { net: net.clone() })
        }
        "signature_name_11" => {
            no_settings(name)?;
            Arc::new(signature_name_11::DomainOwnership { net: net.clone() })
        }
        "is_proxy_ip" => {
            no_settings(name)?;
            Arc::new(is_proxy_ip::IsproxyIp)
        }
        "removed_hunt_three" => {
            if settings.is_null() {
                return Err(format!(
                    "{name} needs its settings in the hunter's configuration: scripts.{name}.home_tenant, the site's tenant"
                ));
            }
            let settings: removed_hunt_three::Settings =
                serde_json::from_value(settings.clone())
                    .map_err(|e| format!("{name}'s settings: {e}"))?;
            Arc::new(removed_hunt_three::M365TenantEnrich {
                net: net.clone(),
                settings,
            })
        }
        "signature_name_13" => {
            no_settings(name)?;
            Arc::new(signature_name_13::RdapLookup { net: net.clone() })
        }
        other => return Err(format!("no script command type is named {other}")),
    })
}

/// `print(json.dumps(value))`.
pub fn print_json(value: &Value) -> String {
    let mut out = pyjson::dumps(value, false);
    out.push('\n');
    out
}

/// A string value.
pub fn s(text: impl Into<String>) -> Value {
    Value::Str(text.into())
}

/// A list of strings.
pub fn strings<I: IntoIterator<Item = S>, S: Into<String>>(items: I) -> Value {
    Value::Seq(items.into_iter().map(|i| Value::Str(i.into())).collect())
}

/// Sets `key` in `map`, keeping its place if it's there, as `d[key] = value` does.
pub fn set(map: &mut Map, key: &str, value: Value) {
    map.insert(Value::Str(key.to_owned()), value);
}

/// A dict from pairs, in order.
pub fn dict<const N: usize>(pairs: [(&str, Value); N]) -> Map {
    let mut map = Map::new();
    for (k, v) in pairs {
        set(&mut map, k, v);
    }
    map
}

/// `str.strip()`, by Python's whitespace.
pub fn strip(text: &str) -> &str {
    text.trim_matches(crate::render::methods::is_space)
}

/// Python's `str()` of a loaded value.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::Str(s) => s.clone(),
        other => py_repr_value(other),
    }
}

/// Python's `repr()` of a loaded value.
pub fn py_repr_value(value: &Value) -> String {
    match value {
        Value::Str(s) | Value::Date(s) | Value::DateTime(s) => py_repr(s),
        Value::Seq(items) => format!(
            "[{}]",
            items
                .iter()
                .map(py_repr_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Map(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| format!("{}: {}", py_repr_value(k), py_repr_value(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => other.key_text(),
    }
}

/// `json.loads` of text, as a loaded value.
pub fn loads(text: &str) -> Result<Value, ace_pycompat::PyErr> {
    ace_pycompat::json::loads(text).map(|v| from_pycompat(&v))
}

/// `json.loads` of bytes, which reads UTF-8, UTF-16 or UTF-32 as Python detects it.
pub fn loads_bytes(bytes: &[u8]) -> Result<Value, ace_pycompat::PyErr> {
    ace_pycompat::json::loads_bytes(bytes).map(|v| from_pycompat(&v))
}

fn from_pycompat(value: &ace_pycompat::json::Value) -> Value {
    use ace_pycompat::json::Value as P;
    match value {
        P::Null => Value::Null,
        P::Bool(b) => Value::Bool(*b),
        P::Int(text) => text
            .parse::<i128>()
            .map(Value::Int)
            .unwrap_or_else(|_| Value::Float(text.parse().unwrap_or(f64::INFINITY))),
        P::Float(f) => Value::Float(*f),
        P::Str(s) => Value::Str(s.as_str().to_owned()),
        P::Array(items) => Value::Seq(items.iter().map(from_pycompat).collect()),
        P::Object(members) => {
            let mut map = Map::new();
            for (k, v) in members {
                map.insert(Value::Str(k.as_str().to_owned()), from_pycompat(v));
            }
            Value::Map(map)
        }
    }
}

/// An uncaught exception's exit, `Traceback ...` and its last line.
pub fn raised(kind: &str, message: &str) -> ScriptExit {
    ScriptExit::raised(kind, message)
}

/// `AttributeError: '<type>' object has no attribute '<name>'`.
pub fn no_attribute(value: &Value, name: &str) -> ScriptExit {
    raised(
        "AttributeError",
        &format!("'{}' object has no attribute '{name}'", value.type_name()),
    )
}

/// `value == number` in Python, for a JSON value.
pub fn equals_int(value: &Value, number: i128) -> bool {
    match value {
        Value::Bool(b) => i128::from(*b) == number,
        Value::Int(i) => *i == number,
        Value::Float(f) => *f == number as f64,
        _ => false,
    }
}
