//! ace3's two modules that find URLs and indicators in text: `url_extraction` and
//! `ioc_extraction` (PLAN.md 7.5 batch 1), on `ace-urlfinder`, the port of urlfinderlib they use.

pub mod ioc_extraction;
/// Python `re` patterns on fancy-regex, which 7.5 batch 8's link module compiles its settings' with too.
pub mod pyre;
pub mod url_extraction;

pub use ioc_extraction::IocExtraction;
pub use url_extraction::UrlExtraction;
