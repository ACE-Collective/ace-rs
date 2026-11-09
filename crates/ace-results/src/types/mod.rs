//! The analysis types of the ported modules. Each module writes one, and its manifest names it,
//! so a binary's registry lists the types of the modules it links.

pub mod archive;
pub mod brocess;
pub mod dns;
pub mod email;
pub mod ioc_extraction;
pub mod msoffice;
pub mod nrd;
pub mod olevba;
pub mod pcode;
pub mod pdf;
pub mod rdap;
pub mod rtf;
pub mod snort;
pub mod splunk;
pub mod url_extraction;
pub mod user;
pub mod xlm;
pub mod yara;
