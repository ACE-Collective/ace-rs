//! The tagging and detection modules (PLAN.md 7.6), ports of ace3's `saq/modules/tag.py` and
//! `saq/modules/observable_detection.py`:
//!
//! - `observable_detection` ([`ObservableDetection`]), a lookup: an observable on the
//!   `observable_detection` list (5.14), which analysts edit through the `detection` router and the
//!   admin page, gets a detection point and a `detect_<type>` tag. ace3 reads a Redis copy of its
//!   `observable_detections` table that `ace observables export` keeps; here the list comes on the
//!   lease.
//! - `user_defined_tagging` ([`UserDefinedTagging`]), a lookup: the tags mapped to an observable in
//!   ACE's database, through the core's `observable-tags` read (7.2).
//! - `site_tagger` ([`SiteTagger`]), a parser: the tags of each row of a site's tag CSV that matches
//!   an observable, by value, glob, regex, CIDR or subdomain.
//!
//! `configuration_defined_tagging` and `observable_modifier`, ace3's other two in this family, are on
//! the core's pool (`docs/modules.md`): they aren't here.

pub mod detection;
pub mod site;
pub mod user;

pub use detection::ObservableDetection;
pub use site::SiteTagger;
pub use user::UserDefinedTagging;
