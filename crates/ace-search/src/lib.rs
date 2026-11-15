//! The search indexer (PLAN.md 7.11): ace3's `saq/search/` index, in Postgres.
//!
//! `ace_service::search` is the read path: the query language, the lanes' fusion, the tiers and the
//! filters. This crate is what it reads: an alert's text as documents (`documents`), cut into chunks
//! by the embedding model's tokenizer (`chunking`), each chunk with its embedding (`model`) and its
//! terms (`sparse`), kept in `search.chunks` and searched there (`pg`). `PgIndex` is the
//! `ace_service::search::SearchIndex` that `ace serve` gives the service, and its `index_next` is the
//! indexer's work: one due alert at a time, bounded by `documents::Bounds`.
//!
//! The split keeps the model out of every crate but this one and the binary: the service, the API and
//! the GUI ask a trait object. `ace-layering` keeps this crate off the `ace-mod-*` crates, so indexing
//! an alert never loads an analyzer: a result's text is read from its stored details by its analysis
//! type's name.
//!
//! Nothing an alert holds leaves the process to be embedded. The model's files are pinned by hash
//! (`model`), and `vendor/README.md` says where they come from and under what licence.
//!
//! `qdrant` is ace3's index behind the same trait, built only for this crate's tests, which run ace3's
//! retrieval regression (`tests/saq/search/test_retrieval.py`) against both. What they measured, and
//! what it says about Qdrant, is `docs/decisions/0002-search-index.md`.
//!
//! # ace3's tests
//!
//! `src/tests.rs`' docs map each case of `ace3/tests/saq/search/` to its test here or in
//! `ace-service`'s, `ace-api`'s and `ace-gui`'s, and say which have no counterpart and why.

pub mod chunking;
pub mod chunks;
pub mod documents;
pub mod model;
pub mod pg;
#[cfg(feature = "qdrant")]
pub mod qdrant;
pub mod sparse;

pub use documents::{Bounds, Document};
pub use model::Model;
pub use pg::PgIndex;

#[cfg(test)]
mod tests;
