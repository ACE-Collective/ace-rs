//! The second half of `analyze_rfc822`: each body part and attachment as a file, then the
//! headers file and the combined file (`saq/modules/email/rfc822.py`, `ATTACHMENT PARSING` and
//! after).
//!
//! The files keep ace3's names and `yara_meta` tags, because YARA rules match on both: an
//! unnamed part is `<email>.unknown_<type>_<subtype>_<NNN><ext>`, a nested message
//! `<email>.email.rfc822`, and every part is tagged `type=email.attachment`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use ace_results::FileRole;
use ace_results::NewFile;
use ace_results::types::email::{BODY_PART_CONTENT_TYPES, EmailPart, ExtractionError, PartRole};
use ace_sdk::{FileOutputError, InputFile};
use sha2::{Digest, Sha256};

use crate::mime::Node;
use crate::naming::OutputNames;
use crate::py::{self, decode_rfc2822, py_strip};

pub const DIRECTIVE_EXTRACT_URLS: &str = "extract_urls";
pub const DIRECTIVE_PREVIEW: &str = "preview";
pub const DIRECTIVE_RENDER: &str = "render";
pub const TAG_EMAIL_PARSE_INCOMPLETE: &str = "email_parse_incomplete";

/// ace3's mime type to extension table: `mimetypes.guess_extension` in ace3's image, written by
/// `tools/ace3/dumps/mime_extensions.py`.
static EXTENSIONS: LazyLock<BTreeMap<&'static str, &'static str>> = LazyLock::new(|| {
    include_str!("extensions.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect()
});

/// `mimetypes.guess_extension(content_type) or ''`.
fn guess_extension(content_type: &str) -> &'static str {
    EXTENSIONS
        .get(content_type.to_lowercase().as_str())
        .copied()
        .unwrap_or("")
}

/// An extracted part, as the log entry records it.
pub struct Attachment {
    pub size: u64,
    pub content_type: String,
    /// The file's path inside the alert.
    pub path: String,
    pub sha256: String,
    /// The bytes, for the combined file.
    pub bytes: Vec<u8>,
}

/// Writes files for the module, the way the task context's `write_file` does.
pub trait Writer {
    fn write(&self, path: &str, bytes: &[u8], role: FileRole) -> Result<NewFile, FileOutputError>;
}

/// What extracting the parts produced.
#[derive(Default)]
pub struct Extracted {
    pub files: Vec<NewFile>,
    pub attachments: Vec<Attachment>,
    pub errors: Vec<ExtractionError>,
    /// Each part's file, content type and role, ace3's `details["parts"]` (5474fd6b).
    pub parts: Vec<EmailPart>,
}

/// Extracts the parts of `target` (`__recursive_parser`).
pub struct Extractor<'w> {
    pub input: &'w InputFile,
    pub writer: &'w dyn Writer,
    /// The original message's id in a journal report, which isn't extracted as a file.
    pub target_message_id: Option<String>,
    pub names: OutputNames,
    /// (maintype, subtype) -> how many unnamed parts of that type were stored.
    unnamed: BTreeMap<(String, String), usize>,
    pub out: Extracted,
}

impl<'w> Extractor<'w> {
    pub fn new(
        input: &'w InputFile,
        writer: &'w dyn Writer,
        target_message_id: Option<String>,
    ) -> Self {
        Extractor {
            input,
            writer,
            target_message_id,
            names: OutputNames::new(input.path.as_str()),
            unnamed: BTreeMap::new(),
            out: Extracted::default(),
        }
    }

    /// `_unnamed_part_name`: numbered per type, so the first part of a type ends `_000`.
    fn unnamed_part_name(&mut self, node: &Node<'_>, ext: &str) -> String {
        let (main, sub) = node
            .content_type
            .split_once('/')
            .map(|(m, s)| (m.to_owned(), s.to_owned()))
            .unwrap_or_default();
        let index = self.unnamed.entry((main.clone(), sub.clone())).or_insert(0);
        let name = format!(
            "{}.unknown_{main}_{sub}_{:03}{ext}",
            self.input.path, *index
        );
        *index += 1;
        name
    }

    /// `_recursive_parser`: a part that fails is recorded and the rest carry on.
    pub fn extract(&mut self, node: &Node<'_>) {
        if let Err(error) = self.extract_part(node) {
            tracing::error!(
                content_type = %node.content_type,
                %error,
                "extracting a part of an email failed"
            );
            self.out.errors.push(ExtractionError {
                content_type: Some(node.content_type.clone()),
                filename: node.headers.filename(),
                exception: format!("{}: {error}", error.kind()),
            });
        }
    }

    fn extract_part(&mut self, node: &Node<'_>) -> Result<(), PartError> {
        let is_message = node.content_type == "message/rfc822";
        if !is_message && !node.children.is_empty() {
            for child in &node.children {
                self.extract(child);
            }
            return Ok(());
        }

        let unknown_ext = guess_extension(&node.content_type);
        let mut file_name: Option<String> = None;
        if is_message {
            // the original message of a journal report isn't extracted, only what's inside it
            if let Some(wanted) = &self.target_message_id {
                for inner in &node.children {
                    if inner
                        .headers
                        .get("message-id")
                        .is_some_and(|id| py_strip(&decode_rfc2822(&id)) == wanted)
                    {
                        self.extract(inner);
                        return Ok(());
                    }
                }
            }
            file_name = Some(format!("{}.email.rfc822", self.input.path));
        }
        let named = match file_name.or_else(|| node.headers.filename()) {
            Some(name) if !name.is_empty() => {
                let decoded = py::make_header_str(&name).unwrap_or_else(|| {
                    tracing::warn!(name = %name, "unable to fully decode an attachment name");
                    name.clone()
                });
                Some(decoded.replace(['\r', '\n'], "")).filter(|name| !name.is_empty())
            }
            _ => None,
        };
        // a body part is an unnamed text or html part; anything else is an attachment
        let unnamed = named.is_none();
        let file_name = match named {
            Some(name) => name,
            None => self.unnamed_part_name(node, unknown_ext),
        };

        let payload: Vec<u8> = if is_message {
            // ace3 writes Python's re-serialization of the inner message (as_bytes); ace4 writes
            // the message as it appears in the email
            match node.children.first() {
                Some(inner) => inner.part.raw().to_vec(),
                None => return Ok(()),
            }
        } else {
            node.decoded_body().into_owned()
        };

        let path = self.names.output_file(&file_name);
        let mut file = self
            .writer
            .write(&path, &payload, FileRole::EMAIL_ATTACHMENT)
            .map_err(PartError::Write)?;
        file.add_directive(DIRECTIVE_EXTRACT_URLS);
        // only a part that declares text/plain, or declares nothing, is previewed: a malformed
        // Content-Type that Python reads as text/plain is rendered
        let declared_plain_text = match node.headers.get("content-type") {
            None => true,
            Some(value) => {
                let raw_type = value.to_str();
                let raw_type = raw_type.split(';').next().unwrap_or_default();
                node.content_type == "text/plain"
                    && py_strip(raw_type).to_lowercase() == "text/plain"
            }
        };
        file.add_directive(if declared_plain_text {
            DIRECTIVE_PREVIEW
        } else {
            DIRECTIVE_RENDER
        });

        let body = unnamed && BODY_PART_CONTENT_TYPES.contains(&node.content_type.as_str());
        self.out.parts.push(EmailPart {
            path: file.path.to_string(),
            content_type: node.content_type.clone(),
            role: if body {
                PartRole::Body
            } else {
                PartRole::Attachment
            },
        });
        self.out.attachments.push(Attachment {
            size: payload.len() as u64,
            content_type: node.content_type.clone(),
            path: file.path.to_string(),
            sha256: hex(&Sha256::digest(&payload)),
            bytes: payload,
        });
        self.out.files.push(file);

        if is_message {
            for inner in &node.children {
                self.extract(inner);
            }
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Why a part couldn't be extracted.
#[derive(Debug, thiserror::Error)]
pub enum PartError {
    #[error("{0}")]
    Write(FileOutputError),
}

impl PartError {
    fn kind(&self) -> &'static str {
        match self {
            PartError::Write(_) => "FileOutputError",
        }
    }
}
