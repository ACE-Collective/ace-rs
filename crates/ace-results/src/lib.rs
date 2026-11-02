//! The contract between ace4's core and its analysis modules: observable kinds, result types, the
//! analysis type registry and the types' JSON Schemas.
//!
//! The API, the GUI and the search indexer depend on this crate and on no `ace-mod-*` crate, so
//! reading an alert never loads analyzer code. `ace-layering` enforces that.

pub mod bytes;
pub mod envelope;
pub mod file;
pub mod observable;
pub mod registry;

pub use bytes::Bytes;
pub use envelope::{AnalysisType, EnvelopeError, NewObservable, ResultEnvelope};
pub use file::{
    AlertPath, InvalidAlertPath, InvalidSha256, InvalidYaraMeta, NewFile, Sha256, YaraMeta,
};
pub use observable::{ObservableKind, UnknownObservableKind};
pub use registry::{AnalysisTypeInfo, BUILTIN, Registry, RegistryError, result_schema};
