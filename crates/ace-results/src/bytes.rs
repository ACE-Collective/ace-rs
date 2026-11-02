//! Byte strings in results.
//!
//! ace3 stores details as JSON and turns bytes into text on the way, so bytes that aren't UTF-8
//! come back changed (ace3 #999). Here a byte string stays bytes: in JSON it is an object with one
//! key, `{"base64": "..."}`, holding standard base64 with padding. It never goes through a text
//! codec, and a plain JSON string is not accepted in its place.

use std::borrow::Cow;
use std::fmt;
use std::ops::Deref;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};

/// The key of the tagged form.
pub const BYTES_TAG: &str = "base64";

/// A byte string that serializes as `{"base64": "..."}`.
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Bytes(bytes.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Bytes(bytes)
    }
}

impl From<&[u8]> for Bytes {
    fn from(bytes: &[u8]) -> Self {
        Bytes(bytes.to_vec())
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes(b\"{}\")", self.0.escape_ascii())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tagged = serializer.serialize_struct("Bytes", 1)?;
        tagged.serialize_field(BYTES_TAG, &STANDARD.encode(&self.0))?;
        tagged.end()
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Tagged {
            base64: String,
        }

        let tagged = Tagged::deserialize(deserializer)?;
        STANDARD
            .decode(tagged.base64.as_bytes())
            .map(Bytes)
            .map_err(|e| de::Error::custom(format_args!("invalid base64 in a byte string: {e}")))
    }
}

impl JsonSchema for Bytes {
    fn schema_name() -> Cow<'static, str> {
        "Bytes".into()
    }

    fn schema_id() -> Cow<'static, str> {
        "ace_results::Bytes".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A byte string, as standard base64 with padding.",
            "type": "object",
            "properties": {
                BYTES_TAG: {
                    "type": "string",
                    "contentEncoding": "base64",
                    "pattern": "^[A-Za-z0-9+/]*={0,2}$",
                },
            },
            "required": [BYTES_TAG],
            "additionalProperties": false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn non_utf8_round_trips_unchanged() {
        let original = Bytes::new(vec![0xff, 0xfe, 0x00, 0x80, b'a', 0xc3, 0x28]);
        assert!(
            std::str::from_utf8(&original).is_err(),
            "the test bytes must not be UTF-8"
        );

        let text = serde_json::to_string(&original).expect("bytes serialize");
        assert_eq!(text, r#"{"base64":"//4AgGHDKA=="}"#);

        let back: Bytes = serde_json::from_str(&text).expect("bytes deserialize");
        assert_eq!(back, original);
    }

    #[test]
    fn every_byte_value_round_trips() {
        let original = Bytes::new((0..=255u8).collect::<Vec<_>>());
        let back: Bytes =
            serde_json::from_value(serde_json::to_value(&original).expect("serializes"))
                .expect("deserializes");
        assert_eq!(back, original);
    }

    #[test]
    fn plain_strings_are_not_bytes() {
        assert!(serde_json::from_value::<Bytes>(json!("abc")).is_err());
        assert!(serde_json::from_value::<Bytes>(json!({"base64": "not base64!"})).is_err());
        assert!(serde_json::from_value::<Bytes>(json!({"base64": "", "extra": 1})).is_err());
        assert!(serde_json::from_value::<Bytes>(json!([1, 2, 3])).is_err());
    }
}
