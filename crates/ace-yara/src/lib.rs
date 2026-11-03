//! ACE's YARA scanner layers on yara-x.
//!
//! ace3 puts two layers above libyara (DESIGN.md, *The YARA scanner*). The first is the
//! team's yara_scanner_v2 library: it loads a signature directory one namespace per
//! subdirectory, leaves out rule files that don't compile, sets default externals and
//! filters matches on meta directives. The second is ACE's own reading of a rule's meta:
//! `enabled`, the uuid and `modifiers`. This crate ports both onto yara-x, so the YARA pool,
//! SVS validation and `ace yara scan` filter matches the same way.

pub mod filter;
pub mod load;
pub mod meta;
pub mod mime;
pub mod replay;
pub mod rule_meta;
pub mod ruleset;
pub mod scan;

pub use load::{
    EXTERNALS, FileOutcome, FileReport, LoadError, LoadOptions, Loaded, Namespace, RuleInfo,
    Ruleset, compile, discover, load_dir,
};
pub use meta::{Meta, MetaValue};

/// The yara-x version this crate builds with. A ruleset serialized by one version loads only in
/// the same version.
pub const YARA_X_VERSION: &str = yara_x::VERSION;
pub use rule_meta::DetectionBlocker;
pub use scan::{Match, PatternMatch, RuleTime, ScanError, ScanOutcome, ScanRequest, Scanner};
