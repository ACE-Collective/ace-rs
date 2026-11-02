//! A rule's meta block, as yara-python hands it to ace3.

use yara_x::MetaValue as XMetaValue;

/// One meta value. YARA meta values are strings, integers, floats or booleans; yara-x
/// returns a string with an escape that isn't valid UTF-8 as bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum MetaValue {
    Str(String),
    Bytes(Vec<u8>),
    Int(i64),
    Float(f64),
    Bool(bool),
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

    pub(crate) fn from_yara_x(metadata: yara_x::Metadata<'_, '_>) -> Self {
        Self::from_pairs(metadata.map(|(key, value)| {
            let value = match value {
                XMetaValue::Integer(i) => MetaValue::Int(i),
                XMetaValue::Float(f) => MetaValue::Float(f),
                XMetaValue::Bool(b) => MetaValue::Bool(b),
                XMetaValue::String(s) => MetaValue::Str(s.to_string()),
                XMetaValue::Bytes(b) => MetaValue::Bytes(b.to_vec()),
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
}
