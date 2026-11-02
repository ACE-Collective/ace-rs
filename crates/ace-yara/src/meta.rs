//! A rule's meta block, as yara-python hands it to ace3.

use serde::ser::{Serialize, SerializeMap, Serializer};
use yara_x::MetaValue as XMetaValue;

/// One meta value: a string, an integer, a float or a boolean. It serializes as the bare
/// value, as ace3's JSON writes it.
#[derive(Debug, Clone, PartialEq)]
pub enum MetaValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl Serialize for MetaValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            MetaValue::Str(s) => serializer.serialize_str(s),
            MetaValue::Int(i) => serializer.serialize_i64(*i),
            MetaValue::Float(f) => serializer.serialize_f64(*f),
            MetaValue::Bool(b) => serializer.serialize_bool(*b),
        }
    }
}

/// Serializes as an object, in the dict's order.
impl Serialize for Meta {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// A meta string as yara-python returns it. libyara keeps the string as a C string, so it ends
/// at the first NUL, and yara-python decodes it as UTF-8 with invalid bytes dropped.
fn python_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes[..end]
        .utf8_chunks()
        .map(|chunk| chunk.valid())
        .collect()
}

/// A rule's meta, keyed the way yara-python's `rule.meta` dict is: when a key repeats, the
/// last value wins and the key keeps the position of its first appearance.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Meta(Vec<(String, MetaValue)>);

impl Meta {
    /// Builds the dict from (key, value) pairs in source order.
    pub fn from_pairs<K: Into<String>>(pairs: impl IntoIterator<Item = (K, MetaValue)>) -> Self {
        let mut meta = Meta::default();
        for (key, value) in pairs {
            let key = key.into();
            match meta.0.iter_mut().find(|(k, _)| *k == key) {
                Some(entry) => entry.1 = value,
                None => meta.0.push((key, value)),
            }
        }
        meta
    }

    /// yara-x returns any string with an escape sequence in it as bytes, valid UTF-8 or not, so
    /// both kinds become the string yara-python would return.
    pub(crate) fn from_yara_x(metadata: yara_x::Metadata<'_, '_>) -> Self {
        Self::from_pairs(metadata.map(|(key, value)| {
            let value = match value {
                XMetaValue::Integer(i) => MetaValue::Int(i),
                XMetaValue::Float(f) => MetaValue::Float(f),
                XMetaValue::Bool(b) => MetaValue::Bool(b),
                XMetaValue::String(s) => MetaValue::Str(python_string(s.as_bytes())),
                XMetaValue::Bytes(b) => MetaValue::Str(python_string(b)),
            };
            (key, value)
        }))
    }

    pub fn get(&self, key: &str) -> Option<&MetaValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &MetaValue)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeated_key_keeps_its_first_position_and_its_last_value() {
        let meta = Meta::from_pairs([
            ("k", MetaValue::Str("first".into())),
            ("n", MetaValue::Int(5)),
            ("k", MetaValue::Str("second".into())),
        ]);
        let pairs: Vec<_> = meta.iter().collect();
        assert_eq!(
            pairs,
            [
                ("k", &MetaValue::Str("second".into())),
                ("n", &MetaValue::Int(5))
            ]
        );
    }

    #[test]
    fn strings_with_escapes_read_as_yara_python_reads_them() {
        // yara-python 4.5.4 in ace3's dev container reads this meta as
        // {'e': 'AB', 'f': 'a\\b', 'g': '', 'plain': 'x', 're': 're:.*\\.doc$', 'n': -2}.
        let rules = yara_x::compile(
            r#"rule a { meta: e = "\x41\xff\x42" f = "a\\b" g = "\x00x" plain = "x"
               re = "re:.*\\.doc$" n = -2 condition: true }"#,
        )
        .unwrap();
        let rule = rules.iter().next().unwrap();
        let meta = Meta::from_yara_x(rule.metadata());
        let str_of = |key| match meta.get(key) {
            Some(MetaValue::Str(s)) => s.clone(),
            other => panic!("{key}: {other:?}"),
        };
        assert_eq!(str_of("e"), "AB");
        assert_eq!(str_of("f"), r"a\b");
        assert_eq!(str_of("g"), "");
        assert_eq!(str_of("plain"), "x");
        assert_eq!(str_of("re"), r"re:.*\.doc$");
        assert_eq!(meta.get("n"), Some(&MetaValue::Int(-2)));
    }
}
