//! The pool runtime.
//!
//! For now it holds containment (PLAN.md 2.18): what a parser's task process applies to itself
//! before the module runs. The async pool (2.16) and the task supervisor (2.17) come later and
//! call it.

pub mod containment;

pub use containment::{Contained, ContainmentError, SandboxProfile, contain};
