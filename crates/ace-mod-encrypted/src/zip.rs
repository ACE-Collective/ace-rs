//! ace3's `ZipEncryptionAnalyzer` (`saq/modules/email/encryption/zip.py`): a zip with an encrypted
//! entry, the password John finds among the email's candidates, and what 7z extracts with it.
//!
//! zip2john gives John one of two kinds of hash, and John's check is followed here:
//!
//! - an entry with WinZip's AES is a hash of its own, which John cracks when the password's verifier
//!   matches and the HMAC of the entry's data does. Each is cracked on its own, and ace3 takes the
//!   password of the last one John cracked, in the archive's order, so the last entry that any
//!   candidate opens decides. With one AES entry or more, John
//!   loads only those, since zip2john prints them first.
//! - otherwise up to eight ZipCrypto entries, the smallest, make one hash: John wants each one's check
//!   byte and the smallest one's data, decrypted, inflated and its CRC right.
//!
//! The zip crate does both checks. 7z's extraction is `ace_mod_archive::formats::extract`, which
//! writes what 7z writes, an empty file for an entry the password doesn't open among them.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::time::{Duration, Instant};

use ace_mod_archive::extracted_name;
use ace_mod_archive::formats::{self, Format};
use ace_results::types::encrypted::ZipEncryptionAnalysis;
use ace_results::{AnalysisType, NewFile, ObservableKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use zip::extra_fields::ExtraField;

use crate::{
    ArchiveSettings, Carried, DIRECTIVE_EXTRACT_URLS, MAX_OUTPUT_BYTES, as_john_shows, carried,
    cracking_deadline, decrypted_detection, summarize,
};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<ZipEncryptionAnalyzer>();

const DISPLAY_NAME: &str = "Zip Encryption Analysis";
/// zip2john's `MAX_PKZ_FILES`.
const MAX_PKZ_FILES: usize = 8;

/// ace3's `ZipEncryptionAnalyzer`.
pub struct ZipEncryptionAnalyzer;

impl Module for ZipEncryptionAnalyzer {
    const NAME: &'static str = ZipEncryptionAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const READS_CARRYING_EMAIL: bool = true;
    // ace3's global 60 s, in which John has ten threads. 5,000 candidates against an AES entry take
    // under 10 s of one thread here (docs/measurements/encrypted.md); more entries take more, and the
    // candidates stop before this.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(120),
        cpu_seconds: 120,
        memory_mb: 2048,
    };
    type Output = ZipEncryptionAnalysis;
    type Settings = ArchiveSettings;

    fn init(_: &ArchiveSettings) -> Result<Self, ModuleError> {
        Ok(ZipEncryptionAnalyzer)
    }
}

/// What John would be given to crack: the entries zip2john hashes.
#[derive(Debug, PartialEq, Eq)]
pub enum Hashes {
    /// The AES entries, by index, in the archive's order.
    Aes(Vec<usize>),
    /// The ZipCrypto entries, by index, the smallest first: John decrypts the first in full.
    ZipCrypto(Vec<usize>),
}

/// `zipfile.ZipFile(path)` and whether any entry's flag bits say it's encrypted. None for what
/// Python's zipfile wouldn't open.
fn encrypted_zip(path: &Path) -> Option<zip::ZipArchive<BufReader<File>>> {
    let mut archive = zip::ZipArchive::new(BufReader::new(File::open(path).ok()?)).ok()?;
    let encrypted =
        (0..archive.len()).any(|i| archive.by_index_raw(i).is_ok_and(|e| e.encrypted()));
    encrypted.then_some(archive)
}

/// The entries zip2john would hash, or ace3's error when it prints nothing, or more than ace3 reads
/// from a tool: each hash holds an entry's data in hex, an AES entry's whole, ZipCrypto's smallest.
pub fn hashes<R: Read + io::Seek>(archive: &mut zip::ZipArchive<R>) -> Result<Hashes, String> {
    let mut aes = Vec::new();
    let mut output = 0u64;
    // (compressed size, index), for the legacy entries zip2john takes
    let mut legacy: Vec<(u64, usize)> = Vec::new();
    for index in 0..archive.len() {
        let Ok(entry) = archive.by_index_raw(index) else {
            continue;
        };
        if !entry.encrypted() {
            continue;
        }
        let is_aes = entry
            .extra_data_fields()
            .any(|field| matches!(field, ExtraField::AeXEncryption(_)));
        if is_aes {
            aes.push(index);
            output += 2 * entry.compressed_size() + 200;
            continue;
        }
        // process_legacy: PKZIP 1.0, 2.0 or 4.5's version, stored or deflated, and 4 bytes or more
        let method = entry.compression();
        if matches!(entry.version_needed(), 10 | 20 | 45)
            && matches!(
                method,
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
            && entry.size() >= 4
        {
            legacy.push((entry.compressed_size(), index));
        }
    }
    // handle_file_entry keeps the smallest, an earlier one first among equals
    legacy.sort_by_key(|(size, _)| *size);
    legacy.truncate(MAX_PKZ_FILES);
    // print_and_cleanup prints them after any AES entry's line, the smallest whole
    if let Some(((smallest, _), others)) = legacy.split_first() {
        output += 2 * smallest
            + others
                .iter()
                .map(|(size, _)| 2 * size.min(&36))
                .sum::<u64>()
            + 200;
    }
    if output > MAX_OUTPUT_BYTES {
        return Err("zip2john did not finish".to_owned());
    }
    if !aes.is_empty() {
        return Ok(Hashes::Aes(aes));
    }
    if legacy.is_empty() {
        return Err(
            "zip2john failed: no entry is AES, or ZipCrypto stored or deflated with 4 bytes or more"
                .to_owned(),
        );
    }
    Ok(Hashes::ZipCrypto(
        legacy.into_iter().map(|(_, index)| index).collect(),
    ))
}

/// Whether the password opens the entry, with its data's check: the CRC for ZipCrypto, the HMAC for
/// AES, read to the end.
fn opens<R: Read + io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    index: usize,
    password: &[u8],
) -> bool {
    let Ok(mut entry) = archive.by_index_decrypt(index, password) else {
        return false;
    };
    io::copy(&mut entry, &mut io::sink()).is_ok()
}

/// Whether the password passes the check byte of a ZipCrypto entry, or the verifier of an AES one.
fn checks<R: Read + io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    index: usize,
    password: &[u8],
) -> bool {
    archive.by_index_decrypt(index, password).is_ok()
}

/// The password ace3 would read from John's answer, or None: the candidates in order, until
/// `deadline`.
pub fn crack<R: Read + io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    hashes: &Hashes,
    candidates: &[String],
    deadline: Instant,
) -> Option<String> {
    match hashes {
        Hashes::ZipCrypto(entries) => {
            let (&smallest, others) = entries.split_first()?;
            for candidate in candidates {
                if Instant::now() >= deadline {
                    return None;
                }
                let password = candidate.as_bytes();
                if others.iter().all(|&i| checks(archive, i, password))
                    && opens(archive, smallest, password)
                {
                    return Some(candidate.clone());
                }
            }
            None
        }
        Hashes::Aes(entries) => {
            // crack_password keeps the last line of John's --show that names the file, which is the
            // last entry John cracked, so the entries are tried from the last: the first that opens
            // gives the answer, and when they share a password one entry's work is all of it
            for &index in entries.iter().rev() {
                for candidate in candidates {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    if opens(archive, index, candidate.as_bytes()) {
                        return Some(candidate.clone());
                    }
                }
            }
            None
        }
    }
}

fn summary(details: &ZipEncryptionAnalysis, error: Option<&str>) -> String {
    summarize(
        DISPLAY_NAME,
        error,
        details.password.as_deref(),
        details.email,
        details.email_body.as_deref(),
        &details.word_list,
    )
}

/// 7z's `x -y -p<password> -o<file>.decrypted`: every file, where 7z writes it, and the last line
/// 7z writes to stderr when a member doesn't extract, which makes it exit 2: `ERROR: Wrong password
/// : <member>` for one the password doesn't open, in archive order. For any other failure the
/// line has the library's words for it in 7z's place.
pub(crate) fn extract_all(
    ctx: &TaskContext<ArchiveSettings>,
    format: Format,
    path: &Path,
    base: &str,
    password: &str,
) -> Result<(Vec<NewFile>, Option<String>), ModuleError> {
    let entries = formats::list(format, path, password).map_err(ModuleError::other)?;
    let mut by_path: BTreeMap<String, usize> = BTreeMap::new();
    for entry in entries.iter().filter(|e| !e.is_dir) {
        if let Some(name) = extracted_name(Format::Zip, &entry.name) {
            // a later entry of the same name replaces an earlier one, as 7z -y and unrar -y do
            by_path.insert(format!("{base}/{name}"), entry.index);
        }
    }
    let wanted: Vec<usize> = by_path.values().copied().collect();
    let mut written: BTreeMap<usize, NewFile> = BTreeMap::new();
    let mut failure: Option<ModuleError> = None;
    let mut not_extracted: BTreeMap<usize, String> = BTreeMap::new();
    formats::extract(
        format,
        path,
        password,
        &wanted,
        &mut |index, reader| {
            if ctx.is_cancelled() {
                return Err(io::Error::other("cancelled"));
            }
            let Some((path, _)) = by_path.iter().find(|(_, i)| **i == index) else {
                return Ok(());
            };
            match ctx.write_file_from(path, reader, None) {
                Ok(file) => {
                    written.insert(index, file);
                    Ok(())
                }
                Err(e) => {
                    let message = e.to_string();
                    failure.get_or_insert(ModuleError::from(e));
                    Err(io::Error::other(message))
                }
            }
        },
        &mut |index, error| {
            tracing::warn!(index, %error, "an entry didn't extract");
            not_extracted.insert(index, error);
        },
    )
    .map_err(ModuleError::other)?;
    ctx.check_cancelled()?;
    if let Some(failure) = failure {
        return Err(failure);
    }
    let last_error = not_extracted.iter().next_back().map(|(index, error)| {
        let name = entries
            .iter()
            .find(|entry| entry.index == *index)
            .map_or("", |entry| entry.name.as_str());
        format!("ERROR: {error} : {name}")
    });
    Ok((written.into_values().collect(), last_error))
}

impl Parser for ZipEncryptionAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<ArchiveSettings>,
    ) -> Result<Outcome<ZipEncryptionAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let Some(mut archive) = encrypted_zip(&file.local_path) else {
            return Ok(Outcome::Skipped("not an encrypted zip".to_owned()));
        };
        if let Some(delay) = ace_mod_msoffice::wait_for_emails(ctx) {
            return Ok(Outcome::Delay(delay));
        }
        let mut details = ZipEncryptionAnalysis::default();
        // `error` is why nothing was extracted, or not everything: ace3's `Analysis.error`
        let done = |details: ZipEncryptionAnalysis, files: Vec<NewFile>, error: Option<String>| {
            let mut result = ResultEnvelope::new(details);
            result.summary = Some(summary(&result.details, error.as_deref()));
            result.error = error.filter(|e| !e.trim().is_empty());
            result.analyzed.tags.push("encrypted_zip".to_owned());
            result.files = files;
            Ok(Outcome::Done(result))
        };
        let hashes = match hashes(&mut archive) {
            Ok(hashes) => hashes,
            Err(error) => return done(details, Vec::new(), Some(error)),
        };
        // zip.py's wordlist_from_email (1998ca56): an email with no text is still an email
        match carried(ctx)? {
            Carried::Absent => {}
            Carried::NoBody => details.email = true,
            Carried::Raised(message) => {
                tracing::warn!("building the wordlist raised: {message}");
                // zip.py's except Exception around the wordlist (its 41d44392), before it assigns
                // anything the wordlist gave
                let error = format!("unable to build the password wordlist: {message}");
                return done(details, Vec::new(), Some(error));
            }
            Carried::Body { text, words } => {
                details.email = true;
                details.email_body = Some(text);
                if !words.is_empty() {
                    let found = crack(&mut archive, &hashes, &words, cracking_deadline(ctx));
                    details.password = found.map(|p| as_john_shows(&p).to_owned());
                }
                details.word_list = words;
            }
        }
        drop(archive);
        // none of the candidates was the password: the summary says so, and since ace3's 1998ca56
        // it isn't an error
        let Some(password) = details.password.clone().filter(|p| !p.is_empty()) else {
            return done(details, Vec::new(), None);
        };
        let base = format!("{}.decrypted", file.path.as_str());
        let (mut files, last_error) =
            extract_all(ctx, Format::Zip, &file.local_path, &base, &password)?;
        for file in &mut files {
            file.detections.push(decrypted_detection());
            file.add_directive(DIRECTIVE_EXTRACT_URLS);
        }
        // 7z exits 1 for a warning and 2 when a member didn't extract; what it extracted before
        // is still added. ace3's reason is `tool_failure_reason`: the status and 7z's last line
        let error = last_error.map(|line| format!("7z exited with status 2: {line}"));
        done(details, files, error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> zip::ZipArchive<BufReader<File>> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/ace3/dumps/fixtures/encrypted/zip")
            .join(name);
        encrypted_zip(&path).expect("an encrypted zip")
    }

    fn words(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn the_hashes_are_zip2johns() {
        assert_eq!(
            hashes(&mut fixture("aes256.zip")),
            Ok(Hashes::Aes(vec![0, 1]))
        );
        assert!(matches!(
            hashes(&mut fixture("zipcrypto.zip")),
            Ok(Hashes::ZipCrypto(_))
        ));
        // the plain entry isn't one
        assert_eq!(
            hashes(&mut fixture("mixed.zip")),
            Ok(Hashes::ZipCrypto(vec![0]))
        );
    }

    #[test]
    fn the_password_is_the_candidate_that_opens_it() {
        for (name, password) in [
            ("zipcrypto.zip", "Secr3tPw"),
            ("aes256.zip", "Aes256Pw"),
            ("aes128.zip", "Aes128Pw"),
            ("stored.zip", "St0red99"),
        ] {
            let mut archive = fixture(name);
            let hashes = hashes(&mut archive).expect("hashes");
            let candidates = words(&["wrong", "Wr0ngOne", password, "after"]);
            assert_eq!(
                crack(&mut archive, &hashes, &candidates, later()).as_deref(),
                Some(password),
                "{name}"
            );
            assert_eq!(
                crack(&mut archive, &hashes, &words(&["nope"]), later()),
                None
            );
        }
    }

    #[test]
    fn of_two_aes_entries_the_later_ones_password_is_kept() {
        let mut archive = fixture("two_passwords.zip");
        let hashes = hashes(&mut archive).expect("hashes");
        let candidates = words(&["SecondPw2", "FirstPw1"]);
        assert_eq!(
            crack(&mut archive, &hashes, &candidates, later()).as_deref(),
            Some("SecondPw2")
        );
    }

    #[test]
    fn nothing_is_tried_past_the_deadline() {
        let mut archive = fixture("zipcrypto.zip");
        let hashes = hashes(&mut archive).expect("hashes");
        assert_eq!(
            crack(&mut archive, &hashes, &words(&["Secr3tPw"]), Instant::now()),
            None
        );
    }
}
