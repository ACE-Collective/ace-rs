//! ace3's file identity modules (PLAN.md 7.5 batch 2): `file_type`, which most file modules read,
//! and the modules that identify a file further: its hashes, a shortcut's and a certificate's
//! contents, an RTF file's stray NULs, and an image's likeness to the analysts' images; and its
//! fuzzy hash's matches with known files' (`ssdeep`, PLAN.md 7.5 batch 10).

pub mod binary;
pub mod checks;
pub mod dhash;
pub mod file_type;
pub mod hash;
pub mod javascript;
pub mod libmagic;
pub mod lnk;
pub mod pillow;
pub mod ssdeep;
pub mod x509;

pub use binary::BinaryFileAnalyzer;
pub use dhash::DHashImageAnalyzer;
pub use file_type::FileType;
pub use hash::FileHashAnalyzer;
pub use lnk::LnkParseAnalyzer;
pub use ssdeep::SsdeepAnalyzer;
pub use x509::X509Analyzer;
