//! The contract between ace4's core and its analysis modules: observable kinds, result types, the
//! analysis type registry and the types' JSON Schemas.
//!
//! The API, the GUI and the search indexer depend on this crate and on no `ace-mod-*` crate, so
//! reading an alert never loads analyzer code. `ace-layering` enforces that.

pub mod bytes;
pub mod envelope;
pub mod file;
pub mod links;
pub mod observable;
pub mod registry;
pub mod types;
pub mod validate;

pub use bytes::Bytes;
pub use envelope::{
    AnalysisType, EnvelopeError, NewObservable, ObservableAdditions, ResultEnvelope,
};
pub use file::{
    AlertPath, InvalidAlertPath, InvalidSha256, InvalidYaraMeta, NewFile, Sha256, YaraMeta,
};
pub use links::{Detection, ObservableRef, Relationship, RelationshipKind};
pub use observable::{
    ObservableKind, ObservableType, TypeListError, UnknownObservableKind, install_types, type_list,
};
pub use registry::{AnalysisTypeInfo, Registry, RegistryError, result_schema, sort_json_keys};
pub use validate::{FieldError, InvalidResult, InvalidSchema, ResultValidator};
