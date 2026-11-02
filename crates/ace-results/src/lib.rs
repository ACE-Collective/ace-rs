//! The contract between ace4's core and its analysis modules: observable kinds and result types.
//!
//! The API, the GUI and the search indexer depend on this crate and on no `ace-mod-*` crate, so
//! reading an alert never loads analyzer code. `ace-layering` enforces that.

pub mod observable;

pub use observable::{ObservableKind, UnknownObservableKind};
