//! TLS key logs (NSS's SSLKEYLOGFILE format) and a pcapng's Decryption Secrets Blocks, as ace3's
//! pcap.py reads them, and the tls_keylog module (`TlsKeylogAnalyzer`).
//!
//! A key log's lines are TLS secrets. They're read here only to count their labels and to collect
//! the lines tshark is given; nothing here logs or stores one.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use ace_pycompat::pystr;
use ace_results::types::pcap::{Counts, TlsKeylogAnalysis};
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use regex::Regex;

use crate::config::MAX_KEYLOG_SIZE;
use crate::{PCAPNG_BYTE_ORDER_MAGICS, PCAPNG_SECTION_HEADER, format_counts};

/// The tag a key log gets.
pub const TAG_TLS_KEYLOG: &str = "tls_keylog";

/// The NSS key log format's labels.
const KEYLOG_LABELS: [&str; 9] = [
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EARLY_EXPORTER_SECRET",
    "EXPORTER_SECRET",
    "RSA",
];
const KEYLOG_SNIFF_BYTES: usize = 4096;
const KEYLOG_SNIFF_LINES: usize = 5;

/// `RE_KEYLOG_LINE`: a label, then two runs of hex digits, each after one space.
static KEYLOG_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        "^({}) ([0-9a-fA-F]+) ([0-9a-fA-F]+)$",
        KEYLOG_LABELS.join("|")
    ))
    .expect("the pattern compiles")
});

/// What a key log holds: its labels' counts, the sessions it keys by client random, and its key
/// log lines, stripped.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KeylogContents {
    pub label_counts: Counts,
    pub client_randoms: BTreeSet<String>,
    pub lines: Vec<String>,
}

/// `is_keylog_file`: the first lines of the file, comments and blank lines aside, up to five, are
/// all key log lines, and there is one.
pub fn is_keylog_file(path: &Path) -> bool {
    let mut head = Vec::new();
    let Ok(file) = File::open(path) else {
        // a file that cannot be read is not a key log anyone can use
        return false;
    };
    if file
        .take(KEYLOG_SNIFF_BYTES as u64)
        .read_to_end(&mut head)
        .is_err()
    {
        return false;
    }
    let Ok(text) = pystr::decode_ascii(&head) else {
        return false;
    };
    let mut lines = pystr::splitlines(text);
    // the last line of a full read may be cut in the middle
    if head.len() == KEYLOG_SNIFF_BYTES && !lines.is_empty() {
        lines.pop();
    }
    let mut checked = 0;
    for line in lines {
        let line = pystr::strip(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !KEYLOG_LINE.is_match(line) {
            return false;
        }
        checked += 1;
        if checked >= KEYLOG_SNIFF_LINES {
            break;
        }
    }
    checked > 0
}

/// `parse_keylog_lines`: every key log line. Anything else is dropped, so what reaches tshark is
/// only key material.
pub fn parse_keylog_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> KeylogContents {
    let mut contents = KeylogContents::default();
    for line in lines {
        let line = pystr::strip(line);
        let Some(m) = KEYLOG_LINE.captures(line) else {
            continue;
        };
        *contents.label_counts.entry(m[1].to_owned()).or_default() += 1;
        // an RSA line is keyed by the encrypted pre-master secret, not the client random
        if &m[1] != "RSA" {
            contents.client_randoms.insert(m[2].to_ascii_lowercase());
        }
        contents.lines.push(line.to_owned());
    }
    contents
}

/// `read_keylog`: the file as ace3 reads it, as ASCII ignoring any other byte, in lines as Python's
/// text mode splits them (at `\r\n`, `\r` and `\n`).
pub fn read_keylog(path: &Path) -> std::io::Result<KeylogContents> {
    let bytes = std::fs::read(path)?;
    let text: String = bytes
        .iter()
        .filter(|b| b.is_ascii())
        .map(|&b| b as char)
        .collect();
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    Ok(parse_keylog_lines(normalized.split_inclusive('\n')))
}

// pcapng's Decryption Secrets Block, and its secrets' types
const PCAPNG_DECRYPTION_SECRETS_BLOCK: u32 = 0x0000_000A;
const PCAPNG_SECRETS_TYPES: [(u32, &str); 6] = [
    (0x544C_534B, "TLS"),
    (0x5353_484B, "SSH"),
    (0x5747_4B4C, "WireGuard"),
    (0x5A4E_574B, "ZigBee NWK"),
    (0x5A41_5053, "ZigBee APS"),
    (0x5541_4B4C, "OPC UA"),
];
/// The most block headers read: each costs ace3 about a microsecond, and the secrets come before
/// the packets they decrypt.
const EMBEDDED_SECRETS_MAX_BLOCKS: u64 = 1_000_000;
const EMBEDDED_SECRETS_STOP_CHECK_BLOCKS: u64 = 10_000;

/// A pcapng's Decryption Secrets Blocks: how many of each kind, the TLS secrets' labels and the
/// sessions they key. Never the secrets.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EmbeddedSecrets {
    pub types: Counts,
    pub label_counts: Counts,
    pub client_randoms: BTreeSet<String>,
}

/// The name ace3 gives a secrets type.
pub fn secrets_type_name(first_word: u32) -> String {
    PCAPNG_SECRETS_TYPES
        .iter()
        .find(|(id, _)| *id == first_word)
        .map_or_else(
            || format!("0x{first_word:08x}"),
            |(_, name)| (*name).to_owned(),
        )
}

/// `read_embedded_secrets`: only block headers are read, the rest skipped by seeking, at most a
/// million of them, and only up to `max_tls_bytes` of TLS secrets are parsed. None when there are
/// none, or the file isn't a pcapng. Cancelled when `stopping` says so.
pub fn read_embedded_secrets(
    path: &Path,
    max_tls_bytes: u64,
    stopping: impl Fn() -> bool,
) -> Result<Option<EmbeddedSecrets>, ModuleError> {
    let mut file = File::open(path)?;
    let mut first = [0u8; 4];
    if read_up_to(&mut file, &mut first)? < 4 || &first != PCAPNG_SECTION_HEADER {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut little = true;
    let mut types: Counts = BTreeMap::new();
    let mut tls_lines: Vec<String> = Vec::new();
    let mut tls_bytes = 0u64;
    let mut blocks = 0u64;
    loop {
        blocks += 1;
        if blocks > EMBEDDED_SECRETS_MAX_BLOCKS {
            tracing::info!(
                path = %path.display(),
                "stopped looking for decryption secrets after {EMBEDDED_SECRETS_MAX_BLOCKS} blocks"
            );
            break;
        }
        if blocks.is_multiple_of(EMBEDDED_SECRETS_STOP_CHECK_BLOCKS) && stopping() {
            return Err(ModuleError::Cancelled);
        }
        let block_start = file.stream_position()?;
        let mut header = [0u8; 12];
        if read_up_to(&mut file, &mut header)? < 12 {
            break;
        }
        if &header[..4] == PCAPNG_SECTION_HEADER {
            // every section declares its own byte order
            if !PCAPNG_BYTE_ORDER_MAGICS
                .iter()
                .any(|m| header[8..12] == m[..])
            {
                break;
            }
            little = header[8..12] == PCAPNG_BYTE_ORDER_MAGICS[0][..];
        }
        let word = |at: usize, bytes: &[u8]| {
            let b: [u8; 4] = bytes[at..at + 4].try_into().expect("four bytes");
            if little {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let (block_type, length, first_word) =
            (word(0, &header), word(4, &header), word(8, &header));
        // a damaged block ends the scan: tshark has already read what it could of the file
        if length < 12 || length % 4 != 0 {
            break;
        }
        if block_type == PCAPNG_DECRYPTION_SECRETS_BLOCK && length >= 20 {
            let mut raw_length = [0u8; 4];
            // the file ends inside the block
            if read_up_to(&mut file, &mut raw_length)? < 4 {
                break;
            }
            let secrets_length = word(0, &raw_length);
            let name = secrets_type_name(first_word);
            *types.entry(name.clone()).or_default() += 1;
            if name == "TLS"
                && u64::from(secrets_length) <= u64::from(length) - 20
                && tls_bytes + u64::from(secrets_length) <= max_tls_bytes
            {
                let mut secrets = Vec::new();
                (&mut file)
                    .take(u64::from(secrets_length))
                    .read_to_end(&mut secrets)?;
                // decode("ascii", errors="ignore")
                let text: String = secrets
                    .iter()
                    .filter(|b| b.is_ascii())
                    .map(|&b| b as char)
                    .collect();
                tls_lines.extend(pystr::splitlines(&text).into_iter().map(str::to_owned));
                tls_bytes += u64::from(secrets_length);
            }
        }
        file.seek(SeekFrom::Start(block_start + u64::from(length)))?;
    }
    if types.is_empty() {
        return Ok(None);
    }
    let contents = parse_keylog_lines(tls_lines.iter().map(String::as_str));
    Ok(Some(EmbeddedSecrets {
        types,
        label_counts: contents.label_counts,
        client_randoms: contents.client_randoms,
    }))
}

/// Reads until `buf` is full or the file ends, and says how much it read, as Python's `read(n)`.
fn read_up_to(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut read = 0;
    while read < buf.len() {
        match file.read(&mut buf[read..])? {
            0 => break,
            n => read += n,
        }
    }
    Ok(read)
}

/// The tls_keylog module.
pub struct TlsKeylogAnalyzer;

impl Module for TlsKeylogAnalyzer {
    const NAME: &'static str = "tls_keylog";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        memory_mb: 512,
        cpu_seconds: 60,
    };
    type Output = TlsKeylogAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(TlsKeylogAnalyzer)
    }
}

impl Parser for TlsKeylogAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<TlsKeylogAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let path = &file.local_path;
        if !path.is_file() || file.size > MAX_KEYLOG_SIZE || !is_keylog_file(path) {
            return Ok(Outcome::Skipped("not a TLS key log".to_owned()));
        }
        let contents = read_keylog(path)?;
        let mut result = ResultEnvelope::new(TlsKeylogAnalysis {
            label_counts: contents.label_counts,
            client_randoms: contents.client_randoms.len() as u64,
            applied_to: Vec::new(),
            skipped: Vec::new(),
        });
        result.analyzed.add_tag(TAG_TLS_KEYLOG);
        // ace3 applies a key log that arrives after a capture's decryption finished; ace-rs's
        // decryption runs once everything else in the alert is done, this module among them
        // (the crate's docs)
        result.summary = Some(keylog_summary(&result.details));
        Ok(Outcome::Done(result))
    }
}

/// `TlsKeylogAnalysis.generate_summary`.
fn keylog_summary(details: &TlsKeylogAnalysis) -> String {
    let secrets: u64 = details.label_counts.values().sum();
    let mut summary = format!(
        "TLS Key Log: {secrets} secrets for {} TLS sessions ({})",
        details.client_randoms,
        format_counts(&details.label_counts)
    );
    if !details.applied_to.is_empty() {
        summary.push_str(&format!(", applied to {} pcaps", details.applied_to.len()));
    }
    if !details.skipped.is_empty() {
        summary.push_str(&format!(
            ", not applied to {} pcaps (out of time)",
            details.skipped.len()
        ));
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn a_key_log_is_known_by_its_first_lines() {
        let dir = tempfile::tempdir().unwrap();
        let line = format!("CLIENT_RANDOM {} {}", "ab".repeat(32), "cd".repeat(48));
        assert!(is_keylog_file(&file(
            dir.path(),
            "a",
            format!("# c\n\n{line}\n").as_bytes()
        )));
        assert!(!is_keylog_file(&file(
            dir.path(),
            "b",
            b"# only a comment\n"
        )));
        assert!(!is_keylog_file(&file(
            dir.path(),
            "c",
            format!("{line}\nnot one\n").as_bytes()
        )));
        // five lines decide; a bad sixth isn't read
        let five = format!("{line}\n").repeat(5) + "not one\n";
        assert!(is_keylog_file(&file(dir.path(), "d", five.as_bytes())));
        assert!(!is_keylog_file(&file(dir.path(), "e", "\u{e9}".as_bytes())));
        // a full sniff drops its last line, which may be cut
        let full = format!("{line}\n").repeat(40);
        assert!(is_keylog_file(&file(
            dir.path(),
            "f",
            &full.as_bytes()[..5000]
        )));
    }

    #[test]
    fn lines_are_counted_by_label_and_rsa_keys_no_session() {
        let contents = parse_keylog_lines([
            "CLIENT_RANDOM AB01 cd\n",
            "  RSA aa bb ",
            "EXPORTER_SECRET ab01 ef",
            "junk",
        ]);
        assert_eq!(contents.label_counts["CLIENT_RANDOM"], 1);
        assert_eq!(contents.label_counts["RSA"], 1);
        assert_eq!(contents.client_randoms.iter().collect::<Vec<_>>(), ["ab01"]);
        assert_eq!(
            contents.lines,
            [
                "CLIENT_RANDOM AB01 cd",
                "RSA aa bb",
                "EXPORTER_SECRET ab01 ef"
            ]
        );
    }

    #[test]
    fn embedded_secrets_are_counted_and_never_kept() {
        let samples = ace_testkit::samples_dir().join("ace3/pcap");
        let secrets = read_embedded_secrets(
            &samples.join("http_tls_dsb.pcapng"),
            MAX_KEYLOG_SIZE,
            || false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(secrets.types["TLS"], 1);
        assert_eq!(secrets.client_randoms.len(), 2);
        assert!(
            read_embedded_secrets(&samples.join("http_tls.pcapng"), MAX_KEYLOG_SIZE, || false)
                .unwrap()
                .is_none()
        );
        assert!(
            read_embedded_secrets(&samples.join("network.pcap"), MAX_KEYLOG_SIZE, || false)
                .unwrap()
                .is_none()
        );
    }
}
