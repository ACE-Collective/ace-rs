//! Checking a result in JSON against its type's schema.
//!
//! The core checks every result before it writes it, whether a Rust or a Python module wrote it.
//! An error names the path of each field that failed, as a JSON pointer such as
//! `/details/attachment_count`. A field the schema doesn't declare is named by its own path.

use std::fmt;

use jsonschema::error::ValidationErrorKind;
use serde_json::Value;

use crate::envelope::AnalysisType;
use crate::registry::result_schema;

/// Messages longer than this are cut, because a failed check prints the value it failed on, and
/// details can hold a whole email body.
const MAX_MESSAGE_LEN: usize = 300;

/// A compiled result schema.
#[derive(Debug)]
pub struct ResultValidator {
    validator: jsonschema::Validator,
}

impl ResultValidator {
    pub fn new(schema: &schemars::Schema) -> Result<Self, InvalidSchema> {
        jsonschema::validator_for(schema.as_value())
            .map(|validator| ResultValidator { validator })
            .map_err(|e| InvalidSchema(e.to_string()))
    }

    /// The validator for results of `T`.
    pub fn of<T: AnalysisType>() -> Result<Self, InvalidSchema> {
        ResultValidator::new(&result_schema::<T>())
    }

    pub fn validate(&self, result: &Value) -> Result<(), InvalidResult> {
        let mut fields = Vec::new();
        for error in self.validator.iter_errors(result) {
            let path = error.instance_path().as_str();
            match error.kind() {
                ValidationErrorKind::AdditionalProperties { unexpected } => {
                    fields.extend(unexpected.iter().map(|name| FieldError {
                        path: format!("{path}/{}", escape_pointer(name)),
                        message: "unknown field".to_owned(),
                    }));
                }
                _ => fields.push(FieldError {
                    path: path.to_owned(),
                    message: truncate(error.to_string()),
                }),
            }
        }
        if fields.is_empty() {
            Ok(())
        } else {
            Err(InvalidResult::Fields(fields))
        }
    }
}

/// One field that failed its schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    /// The field's JSON pointer; empty for the result as a whole.
    pub path: String,
    pub message: String,
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        write!(f, "{path}: {}", self.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidResult {
    #[error("the result has no analysis_type or schema_version")]
    Untyped,
    #[error("unknown analysis type {name} version {version}")]
    UnknownType { name: String, version: u64 },
    #[error("the schema of {name} version {version} doesn't compile: {error}")]
    BadSchema {
        name: &'static str,
        version: u32,
        error: String,
    },
    #[error("invalid result: {}", join(.0))]
    Fields(Vec<FieldError>),
}

impl InvalidResult {
    /// The fields that failed, if the result named a known type.
    pub fn fields(&self) -> &[FieldError] {
        match self {
            InvalidResult::Fields(fields) => fields,
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid result schema: {0}")]
pub struct InvalidSchema(String);

fn join(fields: &[FieldError]) -> String {
    fields
        .iter()
        .map(FieldError::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// A property name as one JSON pointer segment (RFC 6901).
fn escape_pointer(name: &str) -> String {
    name.replace('~', "~0").replace('/', "~1")
}

fn truncate(mut message: String) -> String {
    if message.len() > MAX_MESSAGE_LEN {
        let mut end = MAX_MESSAGE_LEN;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push_str("...");
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_segments_are_escaped() {
        assert_eq!(escape_pointer("a/b~c"), "a~1b~0c");
    }

    #[test]
    fn long_messages_are_cut_on_a_char_boundary() {
        let message = truncate("é".repeat(400));
        assert!(message.ends_with("..."));
        assert!(message.len() <= MAX_MESSAGE_LEN + 3);
    }
}
