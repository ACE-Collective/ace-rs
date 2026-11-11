//! PLAN.md 7.5 batch 13: ace3's packet capture modules (`saq/modules/file_analysis/pcap.py`, ace3's
//! docs/PCAP_ANALYSIS.md), each a port of ace3's:
//!
//! - `pcap_analyzer` (`analyzer`): capinfos and two tshark runs, in the sandbox runner, over a pcap
//!   or pcapng (by its magic), into the capture's index, with its hosts as observables and the
//!   objects and certificates it carves stored for the root (`ResultEnvelope::stored`).
//! - `pcap_dns`, `pcap_tls`, `pcap_http` and `pcap_files` (`category`): one category of that index
//!   each as observables, the carved files among them, which they add with no upload
//!   (`Module::ADDS_STORED_FILES`). ace3 configures these as four instances of one class.
//! - `pcap_tls_decryption` (`decryption`): once the rest of the alert is done, tshark again with
//!   every TLS key log in the alert, adding what the decrypted traffic shows.
//! - `tls_keylog` (`keylog`): a TLS key log, by its content.
//!
//! # Where key material goes
//!
//! A key log is a file of the alert, held in the bucket's `alert_files` pool by its root, as ace3
//! keeps it in the root's storage directory; tls_keylog tags it `tls_keylog`. pcap_tls_decryption
//! reads the files so tagged (`Module::READS_TREE_FILES`), which its pool downloads into its task's
//! directory, keeps only the lines that are key log lines, as ace3 does, and writes them to the
//! task's scratch directory, where tshark, in the runner, reads them (`-o tls.keylog_file:`). The
//! task's directory goes when the task ends, as ace3's sandbox working directory does. Nothing logs
//! a line: the results hold each key log's sha256, name and label counts, the sessions' client
//! randoms (in the clear in every capture) and counts, as ace3's do. A pcapng's own Decryption
//! Secrets Blocks stay in the capture: pcap_analyzer reads their headers and keeps the client
//! randoms they key, never the secrets.
//!
//! # tshark
//!
//! tshark 4.4.19, ace3's, reads a file with `-n` and nothing else: no capture, no extcap, no name
//! resolution. In the runner it starts threads and no process; were it to run dumpcap or an extcap
//! helper, the runner would kill it (`ace_pool`'s containment tests). Its home and personal
//! configuration directory are a path that doesn't exist (`ace_sdk::tools::SANDBOX_TOOLS`), so it
//! loads no personal preferences or plugins, Lua among them, that a file could put in its working
//! directory. Its limits are ace3's: 120 s a run, 64 MiB of each output, 4 GiB of address space,
//! 256 MiB a file.
//!
//! # What isn't ace3's
//!
//! - The categories' share of each type's 50 observables follows the order ace3's trees run them
//!   in, http, files, dns, tls (a set's order in ace3, so not fixed there). A category works out
//!   what the ones before it added from the same index rather than read their results (`budget`).
//! - ace3's tls_keylog applies a key log that arrives after a capture's decryption finished, which
//!   happens in ace3 when an analyst adds one to an alert; that changes the capture's decryption
//!   analysis, a result on another observable. ace4 has no way to add a file to an analyzed alert,
//!   and its decryption runs once everything else is done, key logs included, so the port
//!   recognizes and tags key logs and leaves `applied_to` and `skipped` empty.
//! - Observables aren't volatile and have no sort order, which ace4 doesn't have.

pub mod analyzer;
pub mod budget;
pub mod category;
pub mod decryption;
pub mod index;
pub mod keylog;
pub mod tshark;

#[cfg(test)]
mod reference;

use std::fs::File;
use std::io::Read;
use std::path::Path;

pub use analyzer::PcapAnalyzer;
pub use category::{PcapDns, PcapFiles, PcapHttp, PcapTls};
pub use decryption::PcapTlsDecryptor;
pub use keylog::TlsKeylogAnalyzer;

/// ace3's `pcap` section's defaults.
pub mod config {
    use std::time::Duration;

    /// One tshark run's timeout (`tshark_timeout`).
    pub const TSHARK_TIMEOUT: Duration = Duration::from_secs(120);
    /// capinfos' (`CAPINFOS_TIMEOUT_SECONDS`).
    pub const CAPINFOS_TIMEOUT: Duration = Duration::from_secs(30);
    /// The work around a run (`RUN_MARGIN_SECONDS`).
    pub const RUN_MARGIN: Duration = Duration::from_secs(30);
    /// The largest capture dissected (`max_file_size`).
    pub const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;
    /// The largest file read as a key log (`max_keylog_size`).
    pub const MAX_KEYLOG_SIZE: u64 = 10 * 1024 * 1024;
    /// Rows kept in each table (`max_table_rows`).
    pub const MAX_TABLE_ROWS: usize = 500;
    /// Packets read for DNS, TLS, HTTP, DHCP and NBNS (`max_field_packets`).
    pub const MAX_FIELD_PACKETS: u64 = 50_000;
    /// Files carved from one capture, objects and certificates (`max_extracted_files`).
    pub const MAX_EXTRACTED_FILES: usize = 100;
    /// Observables of one type one capture adds across its pcap results
    /// (`max_observables_per_type`).
    pub const MAX_OBSERVABLES_PER_TYPE: u64 = 50;
    /// Names never added as fqdn observables (`excluded_fqdn_suffixes`).
    pub const EXCLUDED_FQDN_SUFFIXES: &[&str] = &[".arpa", ".local"];

    /// The most one tshark run can take with the work around it (`_run_seconds`).
    pub fn run_seconds() -> Duration {
        TSHARK_TIMEOUT + RUN_MARGIN
    }
}

// libpcap (both byte orders, micro- and nanosecond timestamps) and the pcapng section header block
const PCAP_MAGIC_BYTES: [&[u8; 4]; 4] = [
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
];
/// A pcapng section header block's type.
pub const PCAPNG_SECTION_HEADER: &[u8; 4] = b"\x0a\x0d\x0d\x0a";
/// Its byte-order magics: little-endian, then big-endian.
pub const PCAPNG_BYTE_ORDER_MAGICS: [&[u8; 4]; 2] = [b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"];

/// ace3's `is_pcap_file`: the file starts with a pcap or pcapng magic number, whatever its name.
pub fn is_pcap_file(path: &Path) -> bool {
    let mut header = Vec::new();
    let Ok(file) = File::open(path) else {
        // a file that can't be read is not a capture anyone can dissect
        return false;
    };
    if file.take(12).read_to_end(&mut header).is_err() {
        return false;
    }
    if header.len() >= 4 && PCAP_MAGIC_BYTES.iter().any(|m| &header[..4] == *m) {
        return true;
    }
    // the pcapng block type alone is just LF CR CR LF, which text can start with
    header.len() >= 12
        && &header[..4] == PCAPNG_SECTION_HEADER
        && PCAPNG_BYTE_ORDER_MAGICS
            .iter()
            .any(|m| &header[8..12] == *m)
}

/// `saq.util.strings.format_item_list_for_summary`.
pub fn item_list(items: &[String], max_items: usize) -> String {
    let mut result = items[..items.len().min(max_items)].join(", ");
    if items.len() > max_items {
        result.push_str(&format!(" + {} more", items.len() - max_items));
    }
    result
}

/// `_format_counts`: `<count> <type>` by type, joined by commas.
pub fn format_counts(counts: &ace_results::types::pcap::Counts) -> String {
    counts
        .iter()
        .map(|(kind, count)| format!("{count} {kind}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The sha256 of bytes, as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The sha256 of a file's bytes, as lowercase hex.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// The directory of an alert path, with its trailing `/`, or nothing at the alert's top.
pub fn alert_dir(path: &str) -> &str {
    path.rfind('/').map_or("", |i| &path[..=i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capture_is_known_by_its_magic() {
        let dir = tempfile::tempdir().unwrap();
        let file = |name: &str, bytes: &[u8]| {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            is_pcap_file(&path)
        };
        assert!(file("a", b"\xd4\xc3\xb2\xa1rest"));
        assert!(file("b", b"\x4d\x3c\xb2\xa1"));
        assert!(file(
            "c",
            b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a"
        ));
        // the block type alone is text's LF CR CR LF
        assert!(!file("d", b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00text"));
        assert!(!file("e", b"\xd4\xc3"));
        assert!(!is_pcap_file(&dir.path().join("missing")));
    }

    #[test]
    fn summaries_list_their_items_as_ace3_does() {
        let items: Vec<String> = (0..5).map(|i| i.to_string()).collect();
        assert_eq!(item_list(&items, 3), "0, 1, 2 + 2 more");
        assert_eq!(item_list(&items[..2], 3), "0, 1");
        assert_eq!(alert_dir("a/b/c.pcap"), "a/b/");
        assert_eq!(alert_dir("c.pcap"), "");
    }
}
