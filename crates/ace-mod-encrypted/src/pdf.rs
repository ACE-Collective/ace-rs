//! ace3's `PDFEncryptionAnalyzer` (`saq/modules/email/encryption/pdf.py`): a PDF pikepdf can't open
//! without a user password, the one John finds among the email's candidates, and a decrypted copy.
//!
//! John's PDF format checks a candidate as the user password only (`pdf_fmt_plug.c`), with the
//! standard security handler's algorithms for revisions 2 to 6, which `john_user_password` follows. So
//! a body that gives the owner password, which libqpdf would open the file with, cracks nothing in
//! ace3, and nothing here. The parameters are those pdf2john.pl hands John: the trailer's first `/ID`
//! and `/Encrypt`'s `/O`, `/U`, `/P`, `/R`, `/Length` (40 when it's missing) and `/EncryptMetadata`.
//!
//! The copy is pikepdf's `save()` with its defaults, through libqpdf, but for the second `/ID`, which
//! pikepdf makes from the clock and this from the content (`Document::save_as_pikepdf_saves`).

use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::time::{Duration, Instant};

use ace_mod_pdf::qpdf::{Document, Locked};
use ace_results::types::encrypted::PdfEncryptionAnalysis;
use ace_results::{AnalysisType, NewFile, ObservableKind, ResultEnvelope, YaraMeta};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use aes::Aes128;
use cipher::common::array::Array;
use cipher::{BlockModeEncrypt, KeyIvInit, StreamCipher};
use md5::{Digest, Md5};
use rc4::{KeyInit, Rc4};
use sha2::{Sha256, Sha384, Sha512};

use crate::{Carried, PdfSettings, carried, cracking_deadline, decrypted_detection, summarize};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<PdfEncryptionAnalyzer>();

const DISPLAY_NAME: &str = "PDF Encryption Analysis";
/// The standard security handler's padding.
const PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];
/// John's `PLAINTEXT_LENGTH` for its PDF format: a longer candidate is cut to it.
const PLAINTEXT_LENGTH: usize = 32;

/// ace3's `PDFEncryptionAnalyzer`.
pub struct PdfEncryptionAnalyzer;

impl Module for PdfEncryptionAnalyzer {
    const NAME: &'static str = PdfEncryptionAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const READS_CARRYING_EMAIL: bool = true;
    // ace3's global 60 s. 5,000 candidates against revision 6, the dearest, take a few seconds here
    // (docs/measurements/encrypted.md); writing the copy is libqpdf's work on the whole file.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(120),
        cpu_seconds: 120,
        memory_mb: 2048,
    };
    type Output = PdfEncryptionAnalysis;
    type Settings = PdfSettings;

    fn init(_: &PdfSettings) -> Result<Self, ModuleError> {
        Ok(PdfEncryptionAnalyzer)
    }
}

/// The parameters of John's hash, as pdf2john.pl writes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash {
    r: i64,
    /// The key's length in bits: `/Length`, or 40.
    length: i64,
    p: i64,
    o: Vec<u8>,
    u: Vec<u8>,
    encrypt_metadata: bool,
    id: Vec<u8>,
}

impl Hash {
    /// What pdf2john.pl makes of the parameters, or the complaint it prints instead.
    pub fn of(locked: &Locked) -> Result<Hash, String> {
        let Some(r) = locked.r else {
            return Err("Standard security handler missing revision".to_owned());
        };
        let (Some(o), Some(u), Some(p)) = (&locked.o, &locked.u, locked.p) else {
            return Err("Incomplete Encrypt specification".to_owned());
        };
        if p == 0 || o.is_empty() || u.is_empty() {
            return Err("Incomplete Encrypt specification".to_owned());
        }
        let v = locked.v.unwrap_or_default();
        if !matches!(v, 1 | 2 | 4 | 5) {
            return Err(format!("Encryption version {v} not currently supported"));
        }
        Ok(Hash {
            r,
            length: locked.length.filter(|l| *l != 0).unwrap_or(40),
            p,
            o: o.clone(),
            u: u.clone(),
            encrypt_metadata: v < 4 || locked.encrypt_metadata != Some(false),
            id: locked.id.clone(),
        })
    }
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn rc4(key: &[u8], data: &mut [u8]) {
    if let Ok(mut cipher) = Rc4::new_from_slice(key) {
        cipher.apply_keystream(data);
    }
}

/// `pdf_compute_encryption_key`: algorithm 2 for revisions 2 to 4.
fn rc4_key(hash: &Hash, password: &[u8]) -> Vec<u8> {
    let n = usize::try_from(hash.length / 8).unwrap_or(0).min(16);
    let password = &password[..password.len().min(32)];
    let mut o = hash.o.clone();
    o.resize(32, 0);
    let p = (hash.p as u32).to_le_bytes();
    let no_metadata: &[u8] = if hash.r >= 4 && !hash.encrypt_metadata {
        &[0xFF; 4]
    } else {
        &[]
    };
    let mut key = md5(&[
        password,
        &PADDING[..32 - password.len()],
        &o,
        &p,
        &hash.id,
        no_metadata,
    ]);
    if hash.r >= 3 {
        for _ in 0..50 {
            key = md5(&[&key[..n]]);
        }
    }
    key[..n].to_vec()
}

/// Algorithm 2.B, revision 6's hash, without the owner key, as John has it.
fn hardened_hash(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut block: Vec<u8> = Sha256::new()
        .chain_update(password)
        .chain_update(salt)
        .finalize()
        .to_vec();
    let mut round = 0usize;
    loop {
        let mut unit = Vec::with_capacity(password.len() + block.len());
        unit.extend_from_slice(password);
        unit.extend_from_slice(&block);
        let mut data = unit.repeat(64);
        let Ok(mut encryptor) =
            cbc::Encryptor::<Aes128>::new_from_slices(&block[..16], &block[16..32])
        else {
            return [0; 32];
        };
        let (blocks, _) = Array::slice_as_chunks_mut(&mut data);
        encryptor.encrypt_blocks(blocks);
        let sum: u32 = data[..16].iter().map(|b| u32::from(*b)).sum();
        block = match sum % 3 {
            0 => Sha256::digest(&data).to_vec(),
            1 => Sha384::digest(&data).to_vec(),
            _ => Sha512::digest(&data).to_vec(),
        };
        round += 1;
        let last = u32::from(*data.last().unwrap_or(&0));
        if round >= 64 && (round as u32) >= last + 32 {
            break;
        }
    }
    let mut out = [0; 32];
    out.copy_from_slice(&block[..32]);
    out
}

/// Whether John's PDF format takes `password` as the user password.
pub fn john_user_password(hash: &Hash, password: &[u8]) -> bool {
    let password = &password[..password.len().min(PLAINTEXT_LENGTH)];
    match hash.r {
        2 => {
            let mut out = PADDING;
            rc4(&rc4_key(hash, password), &mut out);
            hash.u.len() >= 32 && out[..] == hash.u[..32]
        }
        3 | 4 => {
            let key = rc4_key(hash, password);
            let mut out = md5(&[&PADDING, &hash.id]);
            rc4(&key, &mut out);
            for x in 1..=19u8 {
                let round: Vec<u8> = key.iter().map(|b| b ^ x).collect();
                rc4(&round, &mut out);
            }
            hash.u.len() >= 16 && out[..] == hash.u[..16]
        }
        5 => {
            let Some(salt) = hash.u.get(32..40) else {
                return false;
            };
            let out: [u8; 32] = Sha256::new()
                .chain_update(&password[..password.len().min(127)])
                .chain_update(salt)
                .finalize()
                .into();
            out[..] == hash.u[..32]
        }
        6 => {
            let Some(salt) = hash.u.get(32..40) else {
                return false;
            };
            hardened_hash(password, salt)[..] == hash.u[..32]
        }
        _ => false,
    }
}

/// The candidate John would find, in order, until `deadline`.
pub fn crack(hash: &Hash, candidates: &[String], deadline: Instant) -> Option<String> {
    for candidate in candidates {
        if Instant::now() >= deadline {
            return None;
        }
        if john_user_password(hash, candidate.as_bytes()) {
            return Some(candidate.clone());
        }
    }
    None
}

/// `is_pdf_file`: `%PDF-` in the first 1,024 bytes, and not pdf_analyzer's dump.
fn is_pdf_file(path: &std::path::Path, alert_path: &str) -> bool {
    if alert_path.ends_with(".pdfparser") {
        return false;
    }
    let mut head = Vec::new();
    File::open(path)
        .and_then(|f| f.take(1024).read_to_end(&mut head))
        .is_ok_and(|_| head.windows(5).any(|w| w == b"%PDF-"))
}

fn summary(details: &PdfEncryptionAnalysis, error: Option<&str>) -> String {
    summarize(
        DISPLAY_NAME,
        error,
        details.password.as_deref(),
        details.email,
        details.email_body.as_deref(),
        &details.word_list,
    )
}

impl PdfEncryptionAnalyzer {
    /// The decrypted copy, or the message of the exception ace3 would raise.
    fn decrypt(
        ctx: &TaskContext<PdfSettings>,
        password: &str,
    ) -> Result<Result<NewFile, String>, ModuleError> {
        let file = ctx.input_file()?;
        let Ok(password) = CString::new(password) else {
            return Ok(Err("embedded null byte".to_owned()));
        };
        let copy = match Document::open_with_password(&file.local_path, &password)
            .and_then(|document| document.save_as_pikepdf_saves())
        {
            Ok(copy) => copy,
            Err(raised) => return Ok(Err(raised.message)),
        };
        // create_output_file: the file's name, at the top of the alert
        let mut record = ctx.write_file(
            &format!("{}.decrypted", file.name()),
            &copy,
            &[YaraMeta::new("type", "document.pdf").map_err(ModuleError::other)?],
        )?;
        record.tags.push("decrypted_pdf".to_owned());
        record.detections.push(decrypted_detection());
        Ok(Ok(record))
    }
}

impl Parser for PdfEncryptionAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<PdfSettings>,
    ) -> Result<Outcome<PdfEncryptionAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if !is_pdf_file(&file.local_path, file.path.as_str()) {
            return Ok(Outcome::Skipped("not a PDF".to_owned()));
        }
        let locked = match Document::locked(&file.local_path) {
            Ok(Some(locked)) => locked,
            Ok(None) => return Ok(Outcome::Skipped("opens without a password".to_owned())),
            Err(raised) => return Ok(Outcome::Skipped(format!("pikepdf can't open it: {raised}"))),
        };
        if let Some(delay) = ace_mod_msoffice::wait_for_emails(ctx) {
            return Ok(Outcome::Delay(delay));
        }
        let mut details = PdfEncryptionAnalysis::default();
        // why no copy was written: ace3's `Analysis.error`
        let mut failure: Option<String> = None;
        let mut files = Vec::new();
        match carried(ctx)? {
            Carried::Absent => {}
            Carried::NoBody => details.email = true,
            Carried::Raised(message) => {
                // pdf.py's except Exception: the error, and the engine logs the exception
                failure = Some(format!("decryption failed: {message}"));
            }
            Carried::Body { text, words } => {
                details.email = true;
                details.email_body = Some(text);
                details.word_list = words.clone();
                if !words.is_empty() {
                    match Hash::of(&locked) {
                        Err(complaint) => {
                            failure = Some(format!("pdf2john.pl failed: {complaint}\n"));
                        }
                        Ok(hash) => {
                            details.password = crack(&hash, &words, cracking_deadline(ctx));
                            // none of the candidates was the password: the summary says so,
                            // and since ace3's 1998ca56 it isn't an error
                            if let Some(password) = &details.password {
                                match Self::decrypt(ctx, password)? {
                                    Ok(record) => files.push(record),
                                    Err(message) => {
                                        failure = Some(format!("decryption failed: {message}"));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let mut result = ResultEnvelope::new(details);
        result.summary = Some(summary(&result.details, failure.as_deref()));
        result.error = failure.filter(|e| !e.trim().is_empty());
        result.analyzed.tags.push("encrypted_pdf".to_owned());
        result.files = files;
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/ace3/dumps/fixtures/encrypted/pdf")
            .join(name)
    }

    fn hash_of(name: &str) -> Hash {
        let locked = Document::locked(&fixture(name))
            .expect("reads")
            .expect("locked");
        Hash::of(&locked).expect("a hash")
    }

    #[test]
    fn only_the_user_password_is_johns() {
        for (name, user, owner, r) in [
            ("rc4_40.pdf", "Rc4Forty", "OwnerPw1", 2),
            ("rc4_128.pdf", "Rc4User1", "OwnerPw2", 3),
            ("aes_128.pdf", "AesUser1", "OwnerPw3", 4),
            ("aes_256.pdf", "Aes256Us", "OwnerPw4", 6),
        ] {
            let hash = hash_of(name);
            assert_eq!(hash.r, r, "{name}");
            assert!(john_user_password(&hash, user.as_bytes()), "{name}");
            assert!(!john_user_password(&hash, owner.as_bytes()), "{name}");
            assert!(!john_user_password(&hash, b"Wr0ngOne"), "{name}");
            // and libqpdf opens it with either
            for password in [user, owner] {
                let password = CString::new(password).expect("no NUL");
                assert!(Document::open_with_password(&fixture(name), &password).is_ok());
            }
        }
    }

    #[test]
    fn a_file_with_an_owner_password_only_isnt_locked() {
        assert!(
            Document::locked(&fixture("owner_only.pdf"))
                .expect("reads")
                .is_none()
        );
    }
}
