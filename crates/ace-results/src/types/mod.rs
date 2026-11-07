//! The analysis types of the ported modules. Each module writes one, and its manifest names it,
//! so a binary's registry lists the types of the modules it links.

pub mod archive;
pub mod email;
pub mod msoffice;
pub mod olevba;
pub mod rdap;
pub mod rtf;
pub mod splunk;
pub mod yara;
