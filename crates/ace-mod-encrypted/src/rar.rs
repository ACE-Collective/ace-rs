//! ace3's `RarEncryptionAnalyzer` (`saq/modules/email/encryption/rar.py`): a RAR that needs a
//! password, the one John finds among the email's candidates, and what unrar extracts with it.
//!
//! rar2john gives John one hash, and John's check is followed here, with libunrar:
//!
//! - headers encrypted (`rar -hp`), RAR4 or RAR5: the archive's own headers, which libunrar can't
//!   read with the wrong password;
//! - RAR5, files encrypted: the first encrypted file's password check value, which libunrar compares
//!   before it reads the file. John looks no further, so a candidate that passes it and then fails the
//!   file's CRC is still John's;
//! - RAR4, files encrypted: no check value, so the file rar2john picks, by its rule on the headers'
//!   sizes (`rar4_best`), is decrypted and unpacked and its CRC checked. rar2john writes that file's
//!   data into the hash, and ace3 stops a tool past 64 MiB of output, so a file of more than about
//!   32 MiB is ace3's `rar2john did not finish`.
//!
//! ace3 then runs `unrar x`, and adds nothing unless every file extracts.

use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use ace_mod_archive::extracted_name;
use ace_mod_archive::formats::Format;
use ace_results::types::encrypted::RarEncryptionAnalysis;
use ace_results::{AnalysisType, NewFile, ObservableKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use unrar::error::Code;

use crate::{
    ArchiveSettings, Carried, DIRECTIVE_EXTRACT_URLS, MAX_OUTPUT_BYTES, as_john_shows, carried,
    cracking_deadline, decrypted_detection, summarize,
};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<RarEncryptionAnalyzer>();

const DISPLAY_NAME: &str = "Rar Encryption Analysis";

/// ace3's `RarEncryptionAnalyzer`.
pub struct RarEncryptionAnalyzer;

impl Module for RarEncryptionAnalyzer {
    const NAME: &'static str = RarEncryptionAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const READS_CARRYING_EMAIL: bool = true;
    // ace3's global 60 s, in which John has ten threads. A RAR's key derivation is the dearest of the
    // three formats: 5,000 candidates take most of this on one thread (docs/measurements/encrypted.md),
    // and the candidates stop before it.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(300),
        cpu_seconds: 300,
        memory_mb: 2048,
    };
    type Output = RarEncryptionAnalysis;
    type Settings = ArchiveSettings;

    fn init(_: &ArchiveSettings) -> Result<Self, ModuleError> {
        Ok(RarEncryptionAnalyzer)
    }
}

/// What rar2john would hash, and so what a candidate is checked on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hash {
    /// The archive's headers are encrypted.
    Headers,
    /// The file at this index in the archive's order, RAR5's or RAR4's.
    File { index: usize, rar5: bool },
}

/// rarfile's `needs_password()`, and what rar2john would hash: None for what isn't a RAR or needs no
/// password; an error for one rar2john gives no hash for, as ace3 words it.
pub fn hash(path: &Path) -> Option<Result<Hash, String>> {
    let archive = unrar::Archive::new(path).open_for_listing().ok()?;
    if archive.has_encrypted_headers() {
        return Some(Ok(Hash::Headers));
    }
    let rar5 = is_rar5(path);
    let mut first_encrypted = None;
    let mut needs_password = false;
    let mut cursor = archive;
    let mut index = 0;
    loop {
        let Ok(Some(header)) = cursor.read_header() else {
            break;
        };
        let entry = header.entry();
        if entry.is_encrypted() {
            needs_password = true;
            if entry.is_file() && first_encrypted.is_none() {
                first_encrypted = Some(index);
            }
        }
        index += 1;
        let Ok(next) = header.skip() else {
            break;
        };
        cursor = next;
    }
    if !needs_password {
        return None;
    }
    let no_hash = || "rar2john failed: no encrypted file it hashes".to_owned();
    if rar5 {
        // rar2john hashes the first encrypted file's check value and stops
        return Some(
            first_encrypted
                .map(|index| Hash::File { index, rar5 })
                .ok_or_else(no_hash),
        );
    }
    let best = std::fs::read(path).ok().and_then(|data| rar4_best(&data));
    Some(match best {
        None => Err(no_hash()),
        // the line holds the file's packed data in hex
        Some(best) if 2 * best.pack + 200 > MAX_OUTPUT_BYTES => {
            Err("rar2john did not finish".to_owned())
        }
        Some(best) => Ok(Hash::File {
            index: best.index,
            rar5,
        }),
    })
}

/// A RAR4 file header, as rar2john reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rar4File {
    /// Its place among the archive's file headers, which is libunrar's order.
    pub index: usize,
    pub pack: u64,
    pub unp: u64,
    pub method: u8,
}

/// The file rar2john hashes in a RAR4 whose headers aren't encrypted: of the encrypted files that
/// aren't solid or directories, with RAR 2.9's encryption or later, the one its rule prefers, the
/// smallest packed with enough unpacked bytes to tell a wrong password.
pub(crate) fn rar4_best(data: &[u8]) -> Option<Rar4File> {
    let u16_at = |at: usize| -> Option<u64> {
        Some(u64::from(u16::from_le_bytes(
            data.get(at..at + 2)?.try_into().ok()?,
        )))
    };
    let u32_at = |at: usize| -> Option<u64> {
        Some(u64::from(u32::from_le_bytes(
            data.get(at..at + 4)?.try_into().ok()?,
        )))
    };
    let mut at = data.windows(7).position(|w| w == b"Rar!\x1a\x07\x00")?;
    let mut index = 0;
    let mut best: Option<Rar4File> = None;
    while at + 7 <= data.len() {
        let kind = *data.get(at + 2)?;
        let flags = u16_at(at + 3)?;
        let size = u16_at(at + 5)?;
        if size < 7 {
            break;
        }
        let mut next = at as u64 + size;
        if kind == 0x74 {
            let mut pack = u32_at(at + 7)?;
            let mut unp = u32_at(at + 11)?;
            if flags & 0x100 != 0 {
                pack += u32_at(at + 32)? << 32;
                unp += u32_at(at + 36)? << 32;
            }
            next += pack;
            let version = *data.get(at + 24)?;
            let method = *data.get(at + 25)?;
            let usable =
                flags & 0x10 == 0 && (flags & 0xe0) >> 5 != 7 && flags & 0x04 != 0 && version >= 29;
            if usable {
                let enough = |file_method: u8| if file_method > 0x30 { 4 } else { 1 };
                let better_already = best.is_some_and(|b| {
                    ((b.pack < pack && b.unp >= enough(b.method))
                        || (b.unp > unp && unp < enough(method)))
                        || (b.pack == pack
                            && ((b.unp > unp && unp < 8) || (b.unp <= unp && b.unp >= 8)))
                });
                if !better_already {
                    best = Some(Rar4File {
                        index,
                        pack,
                        unp,
                        method,
                    });
                }
            }
            index += 1;
        } else if kind == 0x7b {
            break;
        } else if flags & 0x8000 != 0 {
            next += u32_at(at + 7)?;
        }
        at = usize::try_from(next).ok()?;
    }
    best
}

/// RAR5's signature, at the start or after a self-extractor in the first megabyte, where libunrar
/// looks for one.
fn is_rar5(path: &Path) -> bool {
    let mut head = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(1 << 20).read_to_end(&mut head))
        .is_ok_and(|_| head.windows(8).any(|w| w == b"Rar!\x1a\x07\x01\x00"))
}

/// Whether John would take this candidate.
fn opens(path: &Path, hash: &Hash, password: &str) -> bool {
    let Ok(archive) = unrar::Archive::with_password(path, password).open_for_processing() else {
        return false;
    };
    match hash {
        Hash::Headers => matches!(archive.read_header(), Ok(Some(_))),
        Hash::File { index, rar5 } => {
            let mut cursor = archive;
            let mut at = 0;
            loop {
                let Ok(Some(header)) = cursor.read_header() else {
                    return false;
                };
                if at == *index {
                    return match header.test() {
                        Ok(_) => true,
                        // the check value passed, and the data's CRC didn't
                        Err(e) => *rar5 && e.code == Code::BadData,
                    };
                }
                let Ok(next) = header.skip() else {
                    return false;
                };
                cursor = next;
                at += 1;
            }
        }
    }
}

/// The candidate John would find, in order, until `deadline`.
pub fn crack(path: &Path, hash: &Hash, candidates: &[String], deadline: Instant) -> Option<String> {
    for candidate in candidates {
        if Instant::now() >= deadline {
            return None;
        }
        if opens(path, hash, candidate) {
            return Some(candidate.clone());
        }
    }
    None
}

/// `unrar x -y -kb`: every file, where unrar writes it, or None when one doesn't extract, for which
/// unrar exits with an error and ace3 adds nothing.
fn extract_all(
    ctx: &TaskContext<ArchiveSettings>,
    path: &Path,
    base: &str,
    password: &str,
) -> Result<Option<Vec<NewFile>>, ModuleError> {
    let Ok(mut cursor) = unrar::Archive::with_password(path, password).open_for_processing() else {
        return Ok(None);
    };
    let mut by_path: std::collections::BTreeMap<String, NewFile> = Default::default();
    loop {
        ctx.check_cancelled()?;
        let header = match cursor.read_header() {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "unrar stopped");
                return Ok(None);
            }
        };
        let entry = header.entry();
        let name = extracted_name(Format::Zip, &entry.filename.to_string_lossy());
        if !entry.is_file() || name.is_none() {
            cursor = match header.skip() {
                Ok(next) => next,
                Err(_) => return Ok(None),
            };
            continue;
        }
        let (bytes, next) = match header.read() {
            Ok(read) => read,
            Err(e) => {
                tracing::warn!(error = %e, "an entry didn't extract");
                return Ok(None);
            }
        };
        let target = format!("{base}/{}", name.unwrap_or_default());
        let file = ctx.write_file(&target, &bytes, None)?;
        by_path.insert(target, file);
        cursor = next;
    }
    Ok(Some(by_path.into_values().collect()))
}

fn summary(details: &RarEncryptionAnalysis, error: Option<&str>) -> String {
    summarize(
        DISPLAY_NAME,
        error,
        details.password.as_deref(),
        details.email,
        details.email_body.as_deref(),
        &details.word_list,
    )
}

impl Parser for RarEncryptionAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<ArchiveSettings>,
    ) -> Result<Outcome<RarEncryptionAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let Some(hash) = hash(&file.local_path) else {
            return Ok(Outcome::Skipped(
                "not a RAR that needs a password".to_owned(),
            ));
        };
        if let Some(delay) = ace_mod_msoffice::wait_for_emails(ctx) {
            return Ok(Outcome::Delay(delay));
        }
        let mut details = RarEncryptionAnalysis::default();
        // `error` is why nothing was extracted: ace3's `Analysis.error`
        let done = |details: RarEncryptionAnalysis, files: Vec<NewFile>, error: Option<String>| {
            let mut result = ResultEnvelope::new(details);
            result.summary = Some(summary(&result.details, error.as_deref()));
            result.error = error.filter(|e| !e.trim().is_empty());
            result.analyzed.tags.push("encrypted_rar".to_owned());
            result.files = files;
            Ok(Outcome::Done(result))
        };
        let hash = match hash {
            Ok(hash) => hash,
            Err(error) => return done(details, Vec::new(), Some(error)),
        };
        // rar.py's wordlist_from_email (1998ca56): an email with no text is still an email
        match carried(ctx)? {
            Carried::Absent => {}
            Carried::NoBody => details.email = true,
            Carried::Raised(message) => {
                tracing::warn!("building the wordlist raised: {message}");
                // rar.py's except Exception around the wordlist (its 41d44392), before it assigns
                // anything the wordlist gave
                let error = format!("unable to build the password wordlist: {message}");
                return done(details, Vec::new(), Some(error));
            }
            Carried::Body { text, words } => {
                details.email = true;
                details.email_body = Some(text);
                if !words.is_empty() {
                    let found = crack(&file.local_path, &hash, &words, cracking_deadline(ctx));
                    details.password = found.map(|p| as_john_shows(&p).to_owned());
                }
                details.word_list = words;
            }
        }
        // none of the candidates was the password: the summary says so, and since ace3's 1998ca56
        // it isn't an error
        let Some(password) = details.password.clone().filter(|p| !p.is_empty()) else {
            return done(details, Vec::new(), None);
        };
        let base = format!("{}.decrypted", file.path.as_str());
        let Some(mut files) = extract_all(ctx, &file.local_path, &base, &password)? else {
            // ace3's is `unrar exited with status <n>: <the last line unrar wrote>`, which the
            // library this links doesn't write
            let error = "unrar could not extract the archive".to_owned();
            return done(details, Vec::new(), Some(error));
        };
        for file in &mut files {
            file.detections.push(decrypted_detection());
            file.add_directive(DIRECTIVE_EXTRACT_URLS);
        }
        done(details, files, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/ace3/dumps/fixtures/encrypted/rar")
            .join(name)
    }

    #[test]
    fn each_kind_of_rar_cracks_with_its_password_and_no_other() {
        for (name, password) in [
            ("rar4.rar", "Rar4Pass"),
            ("rar4_headers.rar", "Rar4Head"),
            ("rar4_stored.rar", "Rar4Stor"),
            ("rar5.rar", "Rar5Pass"),
            ("rar5_headers.rar", "Rar5Head"),
            ("rar5_solid.rar", "Rar5Sold"),
        ] {
            let path = fixture(name);
            let hash = hash(&path).expect("a RAR").expect("a hash");
            let later = Instant::now() + Duration::from_secs(60);
            let candidates = ["Wr0ngOne".to_owned(), password.to_owned()];
            assert_eq!(
                crack(&path, &hash, &candidates, later).as_deref(),
                Some(password),
                "{name}"
            );
            assert_eq!(crack(&path, &hash, &candidates[..1], later), None, "{name}");
        }
    }

    #[test]
    fn rar2john_picks_a_rar4s_smallest_packed_file() {
        // invoice.txt packs to 80 bytes and docs/notes.txt to 64
        let data = std::fs::read(fixture("rar4.rar")).expect("the fixture");
        let best = rar4_best(&data).expect("a file");
        assert_eq!((best.index, best.pack, best.unp), (1, 64, 70));
        // the headers say nothing when they're encrypted
        let data = std::fs::read(fixture("rar4_headers.rar")).expect("the fixture");
        assert_eq!(rar4_best(&data), None);
    }

    #[test]
    fn a_rar_with_no_password_isnt_one() {
        let path = ace_testkit::samples_dir().join("ace3/archive/test.r07");
        assert_eq!(hash(&path), None);
    }
}
