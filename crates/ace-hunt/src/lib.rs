//! Hunts: the model, and loading them from a signatures checkout as ace3's hunter does (PLAN.md
//! 6.2).
//!
//! A hunt is a YAML file in a hunt type's rule directory, such as `hunts/splunk/` in the
//! signatures repository. [`manager::load_hunts`] loads every hunt of a type, each to a [`Hunt`] or
//! the [`HuntError`] ace3 gives it: [`loader`] reads a file with its includes as ace3's
//! `saq/collectors/hunter/loader.py` does, [`yaml`] parses it as PyYAML's SafeLoader does, within
//! bounds, and [`model`] and [`correlate`] validate it as ace3's pydantic models do, error for
//! error. [`types`] holds the hunt types. [`normal`] is the comparison with ace3's loader.
//! [`render`] renders a hunt's templates as ace3's Jinja does (6.3). [`query`] turns a query hunt's
//! rows into the submissions ace3's hunter makes and says when the hunt runs and over what window,
//! and [`splunk`] builds a Splunk hunt's search (6.4). [`search`] is how a hunt type's query runs
//! (decision 40). [`correlate`] also runs a hunt's correlation
//! over its rows (6.6).
//!
//! This crate depends on nothing else in the workspace, so whatever runs hunts (6.4's hunter, 6.7's
//! scheduler), checks them (6.8's `ace signatures check`) or serves them (6.4's `hunt` router) can
//! use it without the core or the database. Sending a search, keeping a hunt's state and submitting
//! are the hunter's (`ace_app::hunter`).

pub mod correlate;
pub mod loader;
pub mod manager;
pub mod merge;
pub mod model;
pub mod normal;
pub mod paths;
pub mod query;
pub mod render;
pub mod search;
pub mod splunk;
pub mod types;
pub mod validate;
pub mod value;
pub mod yaml;

pub use loader::{Hunt, LoadOptions, load_hunt};
pub use manager::{LoadedHunt, hunt_files, load_hunts};
pub use model::HuntConfig;
pub use types::HuntType;
pub use validate::LineError;

/// Why a hunt didn't load.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum HuntError {
    /// What ace3 raises as a Python exception other than a validation error: its class, such as
    /// `FileNotFoundError` or `ScannerError`, and its text, which can differ from ace3's in its
    /// wording (tools/ace3/hunts/differences.md).
    #[error("{class}: {message}")]
    Python { class: String, message: String },
    /// A pydantic ValidationError: the model, such as `SplunkHuntConfig`, and each error.
    #[error("{} validation errors for {title}: {}", errors.len(), describe(errors))]
    Validation {
        title: String,
        errors: Vec<LineError>,
    },
    /// One of ace4's bounds on what a hunt file may make it build, which ace3 doesn't have.
    #[error("{0}")]
    Limit(String),
}

impl HuntError {
    pub fn python(class: &str, message: impl Into<String>) -> HuntError {
        HuntError::Python {
            class: class.to_owned(),
            message: message.into(),
        }
    }
}

fn describe(errors: &[LineError]) -> String {
    errors
        .iter()
        .map(|e| {
            let loc: Vec<String> = e
                .loc
                .iter()
                .map(|l| match l.to_json() {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                })
                .collect();
            format!("{}: {}", loc.join("."), e.msg)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

impl From<yaml::YamlError> for HuntError {
    fn from(error: yaml::YamlError) -> HuntError {
        match error.class {
            Some(class) => HuntError::python(class, error.message),
            None => HuntError::Limit(error.message),
        }
    }
}
