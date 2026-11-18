//! ace3's modules that read an observable's value and add what's in it (PLAN.md 7.5 batch 3):
//! `command_line_analyzer`, `file_path_analysis`, `file_location_analysis`, `network_identifier`,
//! `parse_url`, `idna_analyzer`, `email_address_fqdn_analyzer` and `protected_url_analyzer`, all on
//! the parser pool, with `protected_url_one_drive` on the lookup pool for the 1drv.ms links
//! `protected_url_analyzer` follows in ace3. `apex_domain_analyzer`, ace3's since `d7436a48`, is on
//! the parser pool too. URLs and domains are read with `ace-urlfinder`'s port of
//! urlfinderlib and `ace-pycompat`'s Python, as ace3 reads them.

pub mod apex;
pub mod command_line;
pub mod email_address;
pub mod file_path;
mod iptools;
pub mod network;
pub mod observable;
pub mod protected;
pub mod py;
pub mod urls;

pub use apex::ApexDomainAnalyzer;
pub use command_line::CommandLineAnalyzer;
pub use email_address::EmailAddressFqdnAnalyzer;
pub use file_path::{FileLocationAnalyzer, FilePathAnalyzer};
pub use network::NetworkIdentifier;
pub use protected::{OneDriveUrlAnalyzer, ProtectedUrlAnalyzer};
pub use urls::{IdnaAnalyzer, ParseUrlAnalyzer};
