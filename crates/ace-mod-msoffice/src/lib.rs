//! ace3's `MSOfficeEncryptionAnalyzer` (`saq/modules/email/encryption/msoffice.py`), with `generate_wordlist`
//! and `wordlist_from_email` (`saq/cracking.py`), on a port of msoffcrypto-tool and html2text (PLAN.md 4.11).
//!
//! ace3 extracts a hash with office2john.py and cracks it with John the Ripper. A task process can't
//! start a process, so this tries the same passwords itself. PLAN.md 7.3 decides John's future. Three
//! things follow from that:
//!
//! - John has no format for XOR obfuscation or for Agile with a hash or a cipher it doesn't know, so
//!   office2john.py's complaint about them is kept as the error, and nothing is tried. msoffcrypto's
//!   doc97 verifies nothing for XOR, so a password can't be tried on one anyway.
//! - msoffcrypto's check of a password fails on Office 2010's Agile with SHA-1, and John's doesn't, so
//!   passwords are checked as John does (`OfficeFile::try_password`) and the file decrypted as ace3 does.
//! - ace3 reads John's answer up to a ':', so a password with one is cut short and the file isn't
//!   decrypted there. Here it is. No sample has one.

pub mod html2text;
pub mod htmlparser;
pub use ace_mod_oletools::msoffcrypto::{method, office};

use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ace_mod_oletools::py::is_space;
use ace_results::FileRole;
use ace_results::types::msoffice::MsofficeEncryptionAnalysis;
use ace_results::{AnalysisType, Detection, ObservableKind, ResultEnvelope};
use ace_sdk::takes::{Condition, Takes, TypeFact};
use ace_sdk::{
    CarryingEmail, Delay, EmailBodyPart, Manifest, Module, ModuleError, Outcome, Parser, Resources,
    TaskContext,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::method::{OUT_OF_TIME, Stop};
use crate::office::OfficeFile;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<MsofficeEncryption>();

const DISPLAY_NAME: &str = "MSOffice Encryption Analysis";
/// ace3's built-in `EMAIL_ENCRYPTED_DECRYPTED` signature.
const SIGNATURE_UUID: &str = "ef715326-081e-4ece-97ba-02817b5a28cd";
/// See <https://isc.sans.edu/diary/rss/23774> and
/// <https://twitter.com/BouncyHat/status/1308897932389896192>.
const DEFAULT_PASSWORDS: [&str; 2] = ["VelvetSweatshop", "/01Hannes Ruescher/01"];
/// The Python frames at ace3's call, which olefile's recursion limit counts: the library diff's are
/// close enough for what's a crafted directory's depth either way.
const DEPTH: usize = 4;
/// What's left for the rest of a task when it stops trying passwords: reading the file, decrypting it
/// and writing it.
const AFTER_CRACKING: Duration = Duration::from_secs(5);
/// How long a task that's found an encrypted file first waits for the root's emails to be parsed.
const EMAILS_PENDING_DELAY: Duration = Duration::from_secs(1);

/// ace3's `MSOfficeEncryptionAnalyzer`.
pub struct MsofficeEncryption;

/// ace3's settings of the module. Its `john_bin_path` is gone: a task process can't start one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct MsofficeEncryptionSettings {
    /// The shortest password to try.
    pub range_low: usize,
    /// The longest password to try.
    pub range_high: usize,
    /// How much of the email's body to look at.
    pub byte_limit: usize,
    /// The most passwords to try from the email.
    pub list_limit: usize,
}

impl Default for MsofficeEncryptionSettings {
    fn default() -> Self {
        MsofficeEncryptionSettings {
            range_low: 4,
            range_high: 11,
            byte_limit: 1024,
            list_limit: 5000,
        }
    }
}

impl Module for MsofficeEncryption {
    const NAME: &'static str = MsofficeEncryptionAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const READS_CARRYING_EMAIL: bool = true;
    // docs/measurements/msoffice.md. ace3's John has its global 60 s and ten threads. A task process has
    // one thread: 5,000 Office 2013 passwords take 44 s of it on arm64 with SHA-512 instructions, and
    // should take about 105 s on amd64 without them, which isn't measured. This covers the list on both.
    // Whatever a file's spin count asks for, the module stops before this and says it couldn't crack it.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(150),
        cpu_seconds: 150,
        memory_mb: 2048,
    };
    type Output = MsofficeEncryptionAnalysis;
    type Settings = MsofficeEncryptionSettings;

    fn init(_: &MsofficeEncryptionSettings) -> Result<Self, ModuleError> {
        Ok(MsofficeEncryption)
    }

    fn takes(_: &MsofficeEncryptionSettings) -> Takes {
        // msoffcrypto's OfficeFile opens a zip as plain OOXML, never encrypted, since an encrypted
        // Office file is always an OLE container; only an OLE file can get past analyze's
        // is_encrypted. From the file's type (PLAN.md decision 25).
        Takes::everything().and(Condition::type_fact(TypeFact::IsOleFile), "not an OLE file")
    }
}

/// `open(path, errors="ignore").read()`, on ace3's nodes where the text mode is UTF-8: undecodable
/// bytes dropped and line ends made `\n`.
pub fn read_text(data: &[u8]) -> String {
    let mut text = String::with_capacity(data.len());
    for chunk in data.utf8_chunks() {
        text.push_str(chunk.valid());
    }
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// Python's `string.punctuation`.
const PUNCTUATION: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// ace3's `generate_wordlist` since `1998ca56`, in its order: the text cut at `byte_limit`
/// characters and split at whitespace, then every word as written and without the punctuation
/// around it, then every substring of a word, shortest first, each once and only if its length is
/// in range, until `list_limit` are listed. A candidate is added before the limit is checked, as
/// ace3's `_add` does.
pub fn generate_wordlist(
    text: &str,
    range_low: usize,
    range_high: usize,
    byte_limit: usize,
    list_limit: usize,
) -> Vec<String> {
    let data: String = text.chars().take(byte_limit).collect();
    let words: Vec<Vec<char>> = data
        .split(is_space)
        .filter(|word| !word.is_empty())
        .map(|word| word.chars().collect())
        .collect();
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    // whether the list is full
    let mut add = |candidate: &[char]| -> bool {
        if (range_low..=range_high).contains(&candidate.len()) {
            let candidate: String = candidate.iter().collect();
            if seen.insert(candidate.clone()) {
                candidates.push(candidate);
            }
        }
        candidates.len() >= list_limit
    };
    for word in &words {
        let text: String = word.iter().collect();
        let stripped: Vec<char> = ace_pycompat::pystr::strip_chars(&text, PUNCTUATION)
            .chars()
            .collect();
        if add(word) || add(&stripped) {
            return candidates;
        }
    }
    for size in range_low..=range_high {
        for word in &words {
            if size > word.len() {
                continue;
            }
            for start in 0..=word.len() - size {
                if add(&word[start..start + size]) {
                    return candidates;
                }
            }
        }
    }
    candidates
}

/// How ace3 cuts candidate passwords from an email's body: `generate_wordlist`'s range of lengths and
/// its limits, which each module that cracks with them has as settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WordlistLimits {
    pub range_low: usize,
    pub range_high: usize,
    pub byte_limit: usize,
    pub list_limit: usize,
}

/// The text of an email's body parts and the candidates in it.
pub type BodyWords = (String, Vec<String>);

/// ace3's `wordlist_from_email` past its finding the email, since `1998ca56`: every body part read
/// as text, an HTML part through html2text, stripped and cut at `byte_limit` characters, each text
/// once, in the email's order; then the texts joined by a blank line, and the words in them. None
/// when no part has any text, ace3's `email_body` None. html2text's exception is what ace3's
/// caller catches.
pub fn words_from_parts(
    parts: &[EmailBodyPart],
    limits: WordlistLimits,
) -> Result<Result<Option<BodyWords>, ace_mod_oletools::py::PyErr>, std::io::Error> {
    let mut texts: Vec<String> = Vec::new();
    for part in parts {
        let mut content = read_text(&fs::read(&part.path)?);
        if part.html {
            content = match html2text::html2text(&content) {
                Ok(text) => text,
                Err(error) => return Ok(Err(error)),
            };
        }
        let text: String = ace_pycompat::pystr::strip(&content)
            .chars()
            .take(limits.byte_limit)
            .collect();
        // the HTML part is often the text part again
        if !text.is_empty() && !texts.contains(&text) {
            texts.push(text);
        }
    }
    if texts.is_empty() {
        return Ok(Ok(None));
    }
    let body = texts.join("\n\n");
    let words = generate_wordlist(
        &body,
        limits.range_low,
        limits.range_high,
        body.chars().count(),
        limits.list_limit,
    );
    Ok(Ok(Some((body, words))))
}

/// The password that opens the file, or None when none does. One that breaks the reading of the file
/// stops it, as John refusing the hash would, and so does `stop`.
pub fn crack<'a>(
    office: &mut OfficeFile,
    passwords: impl Iterator<Item = &'a str>,
    stop: Stop,
) -> Option<String> {
    for password in passwords {
        match office.try_password(password, stop) {
            Ok(()) => return Some(password.to_owned()),
            Err(error) if error.kind == "InvalidKeyError" => {}
            Err(error) => {
                if error.kind != OUT_OF_TIME {
                    tracing::info!("msoffcrypto's reading stopped: {}", error.message);
                }
                return None;
            }
        }
    }
    None
}

/// The delay of a task whose file may have come in an email that isn't parsed yet, longer each time:
/// None when the task knows its carrying email, or that none carried it. An outer email adds a nested
/// email's attachments too, before the nested one has been parsed, and that's the email whose body has
/// the password. ace3 analyzes the attachment once per path, and ace-rs once, so a module that reads the
/// body waits for the root's emails, once it knows its file is one it cracks.
pub fn wait_for_emails<S>(ctx: &TaskContext<S>) -> Option<Delay> {
    if !matches!(ctx.carrying_email(), CarryingEmail::Pending) {
        return None;
    }
    let delays = ctx.delayed().map_or(0, |delayed| delayed.delays);
    let after = EMAILS_PENDING_DELAY.saturating_mul(2u32.saturating_pow(delays.min(5)));
    // the emails' own tasks end, whatever happens to them, so this needs no limit
    Some(Delay::new(after, Duration::MAX))
}

fn summarize(details: &MsofficeEncryptionAnalysis, error: Option<&str>) -> String {
    if let Some(error) = error {
        return format!("{DISPLAY_NAME}: {error}");
    }
    if let Some(password) = &details.password {
        return format!("{DISPLAY_NAME}: password {password}");
    }
    if !details.email {
        return format!("{DISPLAY_NAME}: no associated email detected");
    }
    if details.email_body.as_deref().is_none_or(str::is_empty) {
        return format!("{DISPLAY_NAME}: email body cannot be determined");
    }
    if details.word_list.is_empty() {
        return format!("{DISPLAY_NAME}: word list could not be created from email");
    }
    format!("{DISPLAY_NAME}: password not available")
}

/// What ace3's `except Exception` records of an encrypted document whose cracking or decryption
/// raised (since its `41d44392`): `decryption failed: {str(e) or type(e).__name__}`.
fn decryption_failed(kind: &str, message: &str) -> String {
    format!(
        "decryption failed: {}",
        if message.is_empty() { kind } else { message }
    )
}

impl MsofficeEncryption {
    /// Fills in the details and returns the decrypted file, if it got that far, or sets `failure` to
    /// why it didn't (ace3's `Analysis.error`). A Python exception past here is ace3's `except
    /// Exception`, which logs, records that decryption failed and keeps what the result has.
    fn decrypt(
        ctx: &TaskContext<MsofficeEncryptionSettings>,
        office: &mut OfficeFile,
        details: &mut MsofficeEncryptionAnalysis,
        failure: &mut Option<String>,
    ) -> Result<Option<ace_results::NewFile>, ModuleError> {
        let file = ctx.input_file()?;
        details
            .word_list
            .extend(DEFAULT_PASSWORDS.iter().map(|word| (*word).to_owned()));
        let stop = Stop(Some(
            Instant::now() + ctx.time_left().saturating_sub(AFTER_CRACKING),
        ));
        let mut words = Vec::new();
        match ctx.carrying_email() {
            CarryingEmail::Pending | CarryingEmail::Absent => {}
            CarryingEmail::NoBody => details.email = true,
            CarryingEmail::Parts(parts) => {
                let settings = ctx.settings();
                let limits = WordlistLimits {
                    range_low: settings.range_low,
                    range_high: settings.range_high,
                    byte_limit: settings.byte_limit,
                    list_limit: settings.list_limit,
                };
                match words_from_parts(parts, limits)? {
                    Ok(found) => {
                        details.email = true;
                        if let Some((text, found)) = found {
                            details.email_body = Some(text);
                            words = found;
                        }
                    }
                    Err(error) => {
                        tracing::warn!("reading the email's body raised: {}", error.message);
                        *failure = Some(decryption_failed(&error.kind, &error.message));
                        return Ok(None);
                    }
                }
            }
        }
        details.word_list.extend(words.iter().cloned());
        details.password = crack(
            office,
            DEFAULT_PASSWORDS
                .iter()
                .copied()
                .chain(words.iter().map(String::as_str)),
            stop,
        );
        // none of the candidates was the password: the summary says so, and since ace3's
        // `1998ca56` it isn't an error
        if details.password.is_none() {
            return Ok(None);
        }
        let plain = match office.decrypt() {
            Ok(plain) => plain,
            Err(error) => {
                // a file that broke the port, or one too large for it. It keeps its password
                tracing::warn!("decryption raised {}: {}", error.kind, error.message);
                *failure = Some(decryption_failed(&error.kind, &error.message));
                return Ok(None);
            }
        };
        let mut record = ctx.write_file(
            &format!("{}.decrypted", file.path),
            &plain,
            FileRole::DOCUMENT_OFFICE,
        )?;
        record.tags.push("decrypted_msoffice".to_owned());
        record.detections.push(Detection {
            signature_uuid: Some(SIGNATURE_UUID.to_owned()),
            ..Detection::new("Was able to decrypt based on contents of email.")
        });
        Ok(Some(record))
    }
}

impl Parser for MsofficeEncryption {
    fn analyze(
        &self,
        ctx: &TaskContext<MsofficeEncryptionSettings>,
    ) -> Result<Outcome<MsofficeEncryptionAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = Arc::new(fs::read(&file.local_path)?);
        let Ok(mut office) = OfficeFile::open(data, DEPTH) else {
            return Ok(Outcome::Skipped("msoffcrypto can't read it".to_owned()));
        };
        match office.is_encrypted() {
            Ok(true) => {}
            Ok(false) => return Ok(Outcome::Skipped("not encrypted".to_owned())),
            // ace3's "Unsupported encryption method" makes a result, but only is_encrypted's own
            // exceptions get here, and msoffcrypto 6.0.0 raises no such thing from it
            Err(_) => {
                return Ok(Outcome::Skipped(
                    "msoffcrypto can't tell if it's encrypted".to_owned(),
                ));
            }
        }
        let mut details = MsofficeEncryptionAnalysis::default();
        let mut decrypted = None;
        // why the file wasn't decrypted: ace3's `Analysis.error`
        let mut failure: Option<String> = None;
        if let Some(complaint) = office.john_complaint(file.path.as_str()) {
            failure = Some(format!("office2john.py failed: {complaint}"));
        } else {
            // An outer email adds a nested email's attachments too, before the nested one has been
            // parsed, and that's the email whose body has the password. ace3 analyzes the attachment
            // once per path, and ace-rs once, so it waits for the root's emails. This is only for a file
            // that's encrypted: every file gets here, and the rest are done above.
            if let Some(delay) = wait_for_emails(ctx) {
                return Ok(Outcome::Delay(delay));
            }
            decrypted = Self::decrypt(ctx, &mut office, &mut details, &mut failure)?;
        }
        let mut result = ResultEnvelope::new(details);
        result.summary = Some(summarize(&result.details, failure.as_deref()));
        result.error = failure.filter(|e| !e.trim().is_empty());
        result.analyzed.tags.push("encrypted_msoffice".to_owned());
        if let Some(record) = decrypted {
            result.files.push(record);
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use ace_testkit::Harness;

    use super::*;

    const NO_EMAIL: &str = "ace-rs/office/encrypted_no_email.docx";

    fn harness() -> Harness<MsofficeEncryption> {
        Harness::new().expect("a harness")
    }

    /// The type step's OLE fact, which is all the declaration reads.
    fn typed(_: &str, local: &Path) -> Option<ace_results::types::file_type::TypeFacts> {
        let data = std::fs::read(local).ok()?;
        Some(ace_results::types::file_type::TypeFacts {
            is_ole_file: ace_mod_oletools::ole::has_magic(&data),
            ..Default::default()
        })
    }

    #[test]
    fn only_an_ole_file_is_taken() {
        let harness = harness().with_typer(typed);
        let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples");
        // a plain OOXML zip is never encrypted
        let docx = harness
            .file("doc.docx", samples.join("ace3/office/doc.docx"), &[])
            .expect("a file");
        assert!(matches!(
            harness.run_parser(docx).expect("runs"),
            Outcome::Skipped(why) if why == "not an OLE file"
        ));
        // an encrypted OOXML document is an OLE container, and is taken
        let encrypted = harness
            .file(
                "encrypted_agile.docx",
                samples.join("ace-rs/office/encrypted_agile.docx"),
                &[],
            )
            .expect("a file");
        assert!(!matches!(
            harness.run_parser(encrypted).expect("runs"),
            Outcome::Skipped(why) if why == "not an OLE file"
        ));
    }

    /// An email with these body parts, each its bytes and whether it is HTML.
    fn email_with(dir: &Path, parts: &[(&[u8], bool)]) -> CarryingEmail {
        CarryingEmail::Parts(
            parts
                .iter()
                .enumerate()
                .map(|(index, (text, html))| {
                    let path: PathBuf = dir.join(format!("email_body.{index}"));
                    fs::write(&path, text).expect("written");
                    EmailBodyPart { path, html: *html }
                })
                .collect(),
        )
    }

    /// An email with one plain text part.
    fn body_file(dir: &Path, text: &[u8]) -> CarryingEmail {
        email_with(dir, &[(text, false)])
    }

    fn done(
        outcome: Outcome<MsofficeEncryptionAnalysis>,
    ) -> ResultEnvelope<MsofficeEncryptionAnalysis> {
        match outcome {
            Outcome::Done(result) => result,
            other => panic!("not done: {other:?}"),
        }
    }

    fn run(
        harness: Harness<MsofficeEncryption>,
        sample: &str,
    ) -> Outcome<MsofficeEncryptionAnalysis> {
        let input = harness.sample(sample).expect("a sample");
        harness.run_parser(input).expect("runs")
    }

    #[test]
    fn a_password_in_the_body_decrypts_the_file_and_it_goes_on_with_ace3s_names() {
        let dir = tempfile::tempdir().expect("a directory");
        for (sample, password, body) in [
            (
                "ace-rs/office/encrypted_agile.docx",
                "Secr3tPw",
                &b"The password is Secr3tPw\n"[..],
            ),
            (
                "ace-rs/office/encrypted_standard.docx",
                "St4ndard",
                b"The password is St4ndard\n",
            ),
            (
                "ace-rs/office/encrypted_rc4.doc",
                "R4Binary1",
                b"The password is R4Binary1\n",
            ),
            (
                "ace-rs/office/encrypted_cryptoapi.doc",
                "CryptoAp1",
                b"The password is CryptoAp1\n",
            ),
            (
                "ace-rs/office/encrypted_rc4.xls",
                "R4Binary1",
                b"The password is R4Binary1\n",
            ),
            (
                "ace-rs/office/encrypted_cryptoapi.ppt",
                "CryptoAp1",
                b"The password is CryptoAp1\n",
            ),
        ] {
            let harness = harness().carrying_email(body_file(dir.path(), body));
            let input = harness.sample(sample).expect("a sample");
            let outcome = harness.run_parser(input).expect("runs");
            if sample == "ace-rs/office/encrypted_agile.docx" {
                // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
                ace_testkit::check_view_fixture("msoffice_encrypted_agile_docx", &outcome);
            }
            let result = done(outcome);
            assert_eq!(
                result.details.password.as_deref(),
                Some(password),
                "{sample}"
            );
            assert_eq!(result.analyzed.tags, ["encrypted_msoffice"]);
            let file = &result.files[0];
            assert!(file.path.as_str().ends_with(".decrypted"), "{sample}");
            assert_eq!(file.tags, ["decrypted_msoffice"]);
            assert_eq!(file.yara_meta[0].to_string(), "type=document.office");
            assert_eq!(
                file.detections[0].signature_uuid.as_deref(),
                Some(SIGNATURE_UUID)
            );
            assert!(harness.read_output(file).expect("stored").len() > 100);
        }
    }

    #[test]
    fn office_2010s_sha1_opens_as_john_opens_it_and_the_library_doesnt() {
        let dir = tempfile::tempdir().expect("a directory");
        let harness =
            harness().carrying_email(body_file(dir.path(), b"The password is Secr3tPw\n"));
        let input = harness
            .sample("ace-rs/office/encrypted_agile_sha1.docx")
            .expect("a sample");
        let result = done(harness.run_parser(input).expect("runs"));
        assert_eq!(result.details.password.as_deref(), Some("Secr3tPw"));
        assert_eq!(result.files.len(), 1);
    }

    #[test]
    fn a_hash_john_doesnt_know_isnt_tried() {
        let dir = tempfile::tempdir().expect("a directory");
        let harness =
            harness().carrying_email(body_file(dir.path(), b"The password is Secr3tPw\n"));
        let input = harness
            .sample("ace-rs/office/encrypted_agile_sha256.docx")
            .expect("a sample");
        let result = done(harness.run_parser(input).expect("runs"));
        assert_eq!(
            result.error.as_deref(),
            Some(
                "office2john.py failed: encrypted_agile_sha256.docx uses un-supported hashing \
                 algorithm SHA256, please file a bug! \n"
            )
        );
        assert!(result.details.word_list.is_empty());
    }

    #[test]
    fn a_default_password_needs_no_email() {
        let result = done(run(harness(), "ace-rs/office/encrypted_velvet.docx"));
        assert_eq!(result.details.password.as_deref(), Some("VelvetSweatshop"));
        assert!(!result.details.email);
        assert_eq!(result.files.len(), 1);
    }

    #[test]
    fn a_password_the_body_doesnt_hold_is_a_result_with_no_file() {
        let dir = tempfile::tempdir().expect("a directory");
        let harness = harness().carrying_email(body_file(dir.path(), b"The password is wrong\n"));
        let input = harness.sample(NO_EMAIL).expect("a sample");
        let result = done(harness.run_parser(input).expect("runs"));
        // not an error since ace3's 1998ca56: the summary says so
        assert_eq!(result.error, None);
        assert_eq!(
            result.summary.as_deref(),
            Some("MSOffice Encryption Analysis: password not available")
        );
        assert_eq!(result.details.password, None);
        assert!(result.files.is_empty());
        assert_eq!(
            result.details.email_body.as_deref(),
            Some("The password is wrong")
        );
    }

    #[test]
    fn what_the_email_gives_it() {
        let result = done(run(harness(), NO_EMAIL));
        assert!(!result.details.email);
        assert_eq!(result.details.email_body, None);
        assert_eq!(result.details.word_list, DEFAULT_PASSWORDS);
        let result = done(run(
            harness().carrying_email(CarryingEmail::NoBody),
            NO_EMAIL,
        ));
        assert!(result.details.email);
        assert_eq!(result.details.email_body, None);
    }

    #[test]
    fn a_body_html2text_raises_on_keeps_what_the_result_has_and_says_decryption_failed() {
        let dir = tempfile::tempdir().expect("a directory");
        let harness = harness().carrying_email(email_with(
            dir.path(),
            &[(b"plain text", false), (b"before &#1a after\n", true)],
        ));
        let input = harness.sample(NO_EMAIL).expect("a sample");
        let result = done(harness.run_parser(input).expect("runs"));
        assert!(!result.details.email);
        assert_eq!(result.details.word_list, DEFAULT_PASSWORDS);
        // ace3's `except Exception`, since its 41d44392: the exception's own text
        assert_eq!(
            result.error.as_deref(),
            Some("decryption failed: invalid literal for int() with base 10: '1a after\\n'")
        );
        assert_eq!(
            result.summary.as_deref(),
            Some(
                "MSOffice Encryption Analysis: decryption failed: invalid literal for int() with \
                 base 10: '1a after\\n'"
            )
        );
    }

    #[test]
    fn a_password_that_opens_a_package_thats_no_zip_is_kept_with_no_file() {
        let dir = tempfile::tempdir().expect("a directory");
        let harness =
            harness().carrying_email(body_file(dir.path(), b"The password is Secr3tPw\n"));
        let input = harness
            .sample("ace-rs/office/encrypted_not_zip.docx")
            .expect("a sample");
        let result = done(harness.run_parser(input).expect("runs"));
        assert_eq!(result.details.password.as_deref(), Some("Secr3tPw"));
        assert!(result.files.is_empty());
        // msoffcrypto's exception, which ace3 records since its 41d44392
        assert_eq!(
            result.error.as_deref(),
            Some("decryption failed: The file could not be decrypted with this password")
        );
    }

    #[test]
    fn what_cant_be_read_or_isnt_encrypted_is_skipped_without_waiting_for_an_email() {
        for sample in [
            "ace3/office/doc.docx",
            "ace3/office/doc.doc",
            "ace-rs/office/encrypted_extensible.docx",
            "ace-rs/office/msoffcrypto_plain.ppt",
            "ace-rs/office/msoffcrypto_plain.xls",
            "ace-rs/office/ole_short.doc",
        ] {
            let outcome = run(harness().carrying_email(CarryingEmail::Pending), sample);
            assert!(
                matches!(outcome, Outcome::Skipped(_)),
                "{sample}: {outcome:?}"
            );
        }
    }

    #[test]
    fn an_encrypted_file_waits_while_an_email_is_pending_longer_each_time() {
        let harness = harness().carrying_email(CarryingEmail::Pending);
        let input = harness.sample(NO_EMAIL).expect("a sample");
        let Outcome::Delay(delay) = harness.run_parser(input.clone()).expect("runs") else {
            panic!("no delay");
        };
        assert_eq!(delay.run_after, Duration::from_secs(1));
        let delayed = harness.after_delay(&delay, 3, Duration::from_secs(60));
        let Outcome::Delay(delay) = harness.rerun_parser(input, delayed).expect("runs") else {
            panic!("no delay");
        };
        assert_eq!(delay.run_after, Duration::from_secs(8));
    }

    #[test]
    fn john_has_no_format_for_xor_so_nothing_is_tried_and_no_email_is_needed() {
        for (sample, verifier) in [
            (
                "ace-rs/office/encrypted_xor.doc",
                "Password Verifier : b'78563412'",
            ),
            (
                "ace-rs/office/encrypted_xor.xls",
                "key : b'cdab', hash : b'3412'",
            ),
        ] {
            let result = done(run(
                harness().carrying_email(CarryingEmail::Pending),
                sample,
            ));
            let name = Path::new(sample)
                .file_name()
                .and_then(|n| n.to_str())
                .expect("a name");
            assert_eq!(
                result.error,
                Some(format!(
                    "office2john.py failed: {name} : XOR obfuscation detected, {verifier}\n"
                ))
            );
            assert!(result.details.word_list.is_empty());
        }
    }

    /// The same file with a spin count of 2^31-1, taking the digits' room from the indentation
    /// before them, so the stream keeps its size.
    fn with_huge_spin(data: &[u8]) -> Vec<u8> {
        let from = b"    <p:encryptedKey spinCount=\"100000\"";
        let to = b"<p:encryptedKey spinCount=\"2147483647\"";
        assert_eq!(from.len(), to.len());
        let at = data
            .windows(from.len())
            .position(|w| w == from)
            .expect("the attribute");
        let mut out = data.to_vec();
        out[at..at + to.len()].copy_from_slice(to);
        out
    }

    #[test]
    fn a_spin_count_past_the_time_stops_with_the_result_ace3_gets() {
        let dir = tempfile::tempdir().expect("a directory");
        let data = fs::read(ace_testkit::samples_dir().join(NO_EMAIL)).expect("a sample");
        let path = dir.path().join("huge_spin.docx");
        fs::write(&path, with_huge_spin(&data)).expect("written");
        let body = body_file(dir.path(), b"The password is Secr3tPw\n");
        let harness = harness()
            .carrying_email(body)
            .timeout(AFTER_CRACKING + Duration::from_millis(200));
        let input = harness
            .file("huge_spin.docx", &path, &[])
            .expect("an input");
        let started = Instant::now();
        let result = done(harness.run_parser(input).expect("runs"));
        // a loaded machine stretches this, but nothing near one spin count's minutes
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(result.error, None);
        assert!(
            result
                .details
                .word_list
                .iter()
                .any(|word| word == "Secr3tPw")
        );
    }

    #[test]
    fn a_wordlist_is_ace3s_words_then_their_substrings() {
        // every word, as written and without its punctuation, then each word's substrings,
        // shortest first, across the words in turn
        assert_eq!(
            generate_wordlist("ab cdef\n(ghij),", 4, 5, 1024, 5000),
            [
                "cdef", "ghij", "(ghi", "hij)", "ij),", "(ghij", "ghij)", "hij),"
            ]
        );
        // a whole word comes before a long word's substrings, so the limit drops those first
        assert_eq!(
            generate_wordlist("abcdefgh Secr3tPw", 4, 8, 1024, 3),
            ["abcdefgh", "Secr3tPw", "abcd"]
        );
        assert_eq!(generate_wordlist("abcdefgh", 4, 5, 4, 5000), ["abcd"]);
        assert!(generate_wordlist("", 4, 5, 1024, 5000).is_empty());
        // the candidate is added before the limit is checked, as ace3's `_add` does
        assert_eq!(generate_wordlist("abcd efgh", 4, 4, 1024, 0), ["abcd"]);
    }

    #[test]
    fn the_candidates_come_from_every_body_part_once() {
        let dir = tempfile::tempdir().expect("a directory");
        let limits = WordlistLimits {
            range_low: 4,
            range_high: 8,
            byte_limit: 12,
            list_limit: 5000,
        };
        let CarryingEmail::Parts(parts) = email_with(
            dir.path(),
            &[
                (b"  Use Secr3tPw  \n", false),
                (b"<p>Use Secr3tPw</p>", true),
                (b"a gateway banner that is long", true),
            ],
        ) else {
            panic!("parts");
        };
        let (body, words) = words_from_parts(&parts, limits)
            .expect("reads")
            .expect("html2text")
            .expect("text");
        // the HTML part repeats the text one, and each part is cut at byte_limit
        assert_eq!(body, "Use Secr3tPw\n\na gateway ba");
        assert_eq!(words[..3], ["Secr3tPw", "gateway", "Secr"]);
        let CarryingEmail::Parts(blank) = email_with(dir.path(), &[(b" \n ", false)]) else {
            panic!("parts");
        };
        assert_eq!(
            words_from_parts(&blank, limits)
                .expect("reads")
                .expect("html2text"),
            None
        );
    }

    #[test]
    fn text_mode_drops_bad_bytes_and_makes_line_ends_newlines() {
        assert_eq!(read_text(b"a\r\nb\rc\xffd\xef\xbf\xbd"), "a\nb\ncd\u{fffd}");
    }
}
