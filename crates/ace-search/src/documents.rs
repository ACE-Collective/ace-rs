//! An alert as the few documents worth indexing: ace3's `saq/search/documents.py` and
//! `extractors.py`.
//!
//! | kind | key | text |
//! |---|---|---|
//! | `alert` | `header` | the description, and what the submitter said of the alert type, the tool and the instructions |
//! | `detection` | `detections` | every distinct detection description |
//! | `analysis` | the result's id | one for each result that holds text, by its analysis type |
//! | `comment` | the comment's id | one for each of the alert's comments (PLAN.md 5.15), titled by its author |
//!
//! Nothing is made for the observables: an identifier is found exactly by the lexical lane, and a
//! sentence encoder can't tell `1.2.3.4` from `1.2.3.5`.
//!
//! **A result's text** is read from its stored details by its analysis type's name, never through a
//! module's crate (`ace-layering` keeps this crate off them): an email's headers and body, a command
//! line and its paths, a QR code's text, a macro's source, an encrypted attachment's email body, RDAP's
//! registration, and the text files OCR, `pdftotext`, the XML text extractor and the JavaScript
//! deobfuscator wrote, read from the bucket up to `Bounds::max_document_bytes`.
//!
//! **Bounds.** ace3 bounds a document's bytes and chunks; an alert's documents are also bounded here
//! (`Bounds`), so one alert's indexing is a known amount of work. What is past a bound is counted and
//! left out.
//!
//! # What differs from ace3
//!
//! - ace-rs's modules attach no `llm_context_documents`, so nothing makes a `context` document. The
//!   index keeps the kind for when they come.
//! - A root has no alert type, tool, instructions or summary details of its own. The header reads the
//!   first three from what its submitter recorded (`analysis.roots.origin`), when it's there.
//! - An email's HTML body becomes text by dropping its tags, scripts and styles, where ace3 runs
//!   `html2text`, which also writes Markdown marks for links and emphasis.
//! - RDAP here keeps no WHOIS text. The document is the registration's fields: the domain, registrar,
//!   name servers, contacts' emails, network and country.
//! - Details over the byte bound are skipped by their stored size, which is their compressed size.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use ace_core::bucket::{ALERT_FILES, Bucket};
use ace_core::db::{Db, DbError, Isolation};
use ace_results::Sha256;
use ace_results::types::email::EmailAnalysis;
use serde_json::Value;
use uuid::Uuid;

/// The alert header's key.
pub const ALERT_HEADER_KEY: &str = "header";
/// The detections document's key.
pub const DETECTIONS_KEY: &str = "detections";
/// The largest file read from the bucket for its text. A larger one is left out: reading the start of
/// it would bring the whole object to this node first.
const MAX_TEXT_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// What one alert's indexing may read and write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounds {
    /// A document's tokens per chunk: ace3's `chunk_tokens`.
    pub chunk_tokens: usize,
    /// The tokens a chunk shares with the one before: ace3's `chunk_overlap`.
    pub chunk_overlap: usize,
    /// ace3's `max_chunks_per_document`.
    pub max_chunks_per_document: usize,
    /// ace3's `max_document_bytes`: the most of a file or a document that's read.
    pub max_document_bytes: usize,
    /// The most documents one alert has.
    pub max_documents: usize,
    /// The most chunks one alert has.
    pub max_chunks: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds {
            chunk_tokens: 200,
            chunk_overlap: 32,
            max_chunks_per_document: 16,
            max_document_bytes: 262_144,
            max_documents: 64,
            max_chunks: 256,
        }
    }
}

/// One piece of text about an alert: ace3's `SearchDocument`. `kind` and `key` name it within its
/// alert and stay the same when the alert is indexed again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub kind: &'static str,
    pub key: String,
    pub text: String,
    pub title: Option<String>,
    /// Whether the title says something and is embedded with the first chunk (an email's subject), or
    /// is a label for display only ("command line").
    pub embed_title: bool,
    pub result_id: Option<i64>,
    pub observable_id: Option<i64>,
}

impl Document {
    /// A comment on the alert (PLAN.md 5.15), titled by who wrote it: ace3's comment document.
    pub fn comment(key: &str, author: Option<&str>, text: &str) -> Option<Document> {
        let text = normalize_text(text);
        (!text.is_empty()).then(|| Document {
            kind: "comment",
            key: key.to_owned(),
            text,
            title: author.map(str::to_owned),
            embed_title: true,
            result_id: None,
            observable_id: None,
        })
    }
}

/// What an alert's documents are, or why it has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    pub documents: Vec<Document>,
    /// Documents past `Bounds::max_documents`.
    pub left_out: usize,
    /// Why nothing was read: no such root, or not an alert.
    pub skipped: Option<String>,
}

/// Runs of spaces and blank lines as one, each line trimmed: ace3's `normalize_text`.
pub fn normalize_text(text: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let mut out = String::with_capacity(line.len());
        let mut space = false;
        for c in line.chars() {
            if matches!(c, ' ' | '\t' | '\r' | '\u{c}' | '\u{b}') {
                space = true;
            } else {
                if space && !out.is_empty() {
                    out.push(' ');
                }
                space = false;
                out.push(c);
            }
        }
        // a blank line, or one of only spaces, is dropped
        if !out.is_empty() {
            lines.push(out);
        }
    }
    lines.join("\n")
}

fn truncated(text: String, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// An HTML body's text: no tags, no scripts or styles, the common entities decoded.
pub fn html_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(open) = rest.find('<') {
        out.push_str(&rest[..open]);
        let tag = &rest[open..];
        let lower = tag.chars().take(8).collect::<String>().to_ascii_lowercase();
        let skip_to = if lower.starts_with("<script") {
            Some("</script")
        } else if lower.starts_with("<style") {
            Some("</style")
        } else if lower.starts_with("<!--") {
            Some("-->")
        } else {
            None
        };
        let after = match skip_to {
            Some(close) => match tag.to_ascii_lowercase().find(close) {
                Some(at) => &tag[at..],
                None => "",
            },
            None => tag,
        };
        // a tag ends a word and, for a block, a line
        out.push('\n');
        rest = match after.find('>') {
            Some(end) => &after[end + 1..],
            None => "",
        };
    }
    out.push_str(rest);
    for (entity, text) in [
        ("&nbsp;", " "),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
        ("&apos;", "'"),
        ("&amp;", "&"),
    ] {
        out = out.replace(entity, text);
    }
    out
}

/// The text without the `//` comment banner the deobfuscator writes first: ace3's
/// `strip_leading_comments`.
pub fn strip_leading_comments(text: &str) -> String {
    text.lines()
        .skip_while(|line| line.trim().is_empty() || line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn listing(value: &Value) -> Option<String> {
    match value {
        Value::Array(items) => {
            let items: Vec<String> = items
                .iter()
                .filter_map(|item| match item {
                    Value::String(text) if !text.is_empty() => Some(text.clone()),
                    Value::Null | Value::String(_) => None,
                    other => Some(other.to_string()),
                })
                .collect();
            (!items.is_empty()).then(|| items.join(", "))
        }
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        _ => None,
    }
}

/// A result's row, with the observable it's on.
struct ResultRow {
    id: i64,
    observable_id: i64,
    analysis_type: String,
    details: Value,
    observable_value: String,
}

/// A file a result added.
#[derive(Debug, Clone)]
struct Added {
    sha256: String,
    path: String,
    yara_meta: Vec<String>,
}

impl Added {
    fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

/// A piece of text a result holds: its title, whether the title is only a label, and the text or the
/// added file it's in.
enum Piece {
    Text(Option<String>, bool, String),
    /// (label, whether it's only a label, the file's place among the result's added files, whether its
    /// leading comments go)
    File(Option<String>, bool, usize, bool),
    /// An email: its title, its header block, and its body's file and whether that is HTML.
    Email(Option<String>, String, Option<(usize, bool)>),
}

/// The analysis types that hold text, in ace3's `extractors.py`.
pub const EXTRACTED_TYPES: &[&str] = &[
    "email_analysis",
    "command_line_analysis",
    "qr_code_analysis",
    "olevba_analysis",
    "rdap_analysis",
    "zip_encryption_analysis",
    "rar_encryption_analysis",
    "pdf_encryption_analysis",
    "msoffice_encryption_analysis",
    "xml_plain_text_analysis",
    "ocr_analysis",
    "pdf_text_analysis",
    "javascript_deobfuscation_analysis",
];

fn email_headers(email: &Value) -> String {
    let mut lines = Vec::new();
    for (label, key) in [
        ("From", "from"),
        ("To", "to"),
        ("Cc", "cc"),
        ("Reply-To", "reply_to"),
        ("Message-ID", "message-id"),
    ] {
        if let Some(value) = email.get(key).and_then(listing) {
            lines.push(format!("{label}: {value}"));
        }
    }
    let subject = ["decoded_subject", "subject"].iter().find_map(|key| {
        email
            .get(*key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    });
    if let Some(subject) = subject {
        lines.push(format!("Subject: {subject}"));
    }
    // what else of the raw headers an analyst searches by
    for header in email
        .get("headers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(name), Some(value)) = (
            header.get(0).and_then(Value::as_str),
            header.get(1).and_then(Value::as_str),
        ) else {
            continue;
        };
        if ["date", "return-path", "sender"].contains(&name.to_lowercase().as_str())
            && !value.is_empty()
        {
            lines.push(format!("{name}: {value}"));
        }
    }
    lines.join("\n")
}

fn pieces(row: &ResultRow, added: &[Added]) -> Vec<Piece> {
    let details = &row.details;
    let text_of = |key: &str| {
        details
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    let label = |label: &str, text: Option<String>| {
        text.map(|text| Piece::Text(Some(label.to_owned()), true, text))
            .into_iter()
            .collect::<Vec<_>>()
    };
    let file = |label: &str, at: Option<usize>, strip: bool| {
        at.map(|at| Piece::File(Some(label.to_owned()), true, at, strip))
            .into_iter()
            .collect::<Vec<_>>()
    };
    match row.analysis_type.as_str() {
        "email_analysis" => {
            let Some(email) = details.get("email").filter(|email| email.is_object()) else {
                return Vec::new();
            };
            let title = ["decoded_subject", "subject"]
                .iter()
                .find_map(|key| {
                    email
                        .get(*key)
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                })
                .map(str::to_owned);
            // the parts the result records say which file is the body and whether it's HTML; a
            // result made before it recorded them is read by its files' names
            let parts: Option<Vec<ace_results::types::email::EmailPart>> = details
                .get("parts")
                .filter(|parts| !parts.is_null())
                .and_then(|parts| serde_json::from_value(parts.clone()).ok());
            let paths: Vec<&str> = added.iter().map(|a| a.path.as_str()).collect();
            let body = EmailAnalysis::body_in(parts.as_deref(), &paths).map(|at| {
                let html = EmailAnalysis::body_parts_in(parts.as_deref(), &paths)
                    .into_iter()
                    .any(|(index, html)| index == at && html);
                (at, html)
            });
            vec![Piece::Email(title, email_headers(email), body)]
        }
        "command_line_analysis" => {
            let mut lines = Vec::new();
            if !row.observable_value.is_empty() {
                lines.push(row.observable_value.clone());
            }
            lines.extend(
                details
                    .get("file_paths")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .filter(|path| !path.is_empty())
                    .map(str::to_owned),
            );
            label(
                "command line",
                (!lines.is_empty()).then(|| lines.join("\n")),
            )
        }
        "qr_code_analysis" => label("QR code", text_of("extracted_text")),
        "olevba_analysis" => {
            let code = details
                .get("macros")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|m| m.get("vba_code").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n");
            label("VBA macro", (!code.trim().is_empty()).then_some(code))
        }
        "rdap_analysis" => {
            let lines: Vec<String> = [
                ("Domain", "domain_name"),
                ("Registrar", "registrar"),
                ("Name servers", "name_servers"),
                ("Emails", "emails"),
                ("Network", "network_name"),
                ("Country", "country"),
            ]
            .iter()
            .filter_map(|(name, key)| {
                details
                    .get(*key)
                    .and_then(listing)
                    .map(|value| format!("{name}: {value}"))
            })
            .collect();
            label("whois", (!lines.is_empty()).then(|| lines.join("\n")))
        }
        "zip_encryption_analysis"
        | "rar_encryption_analysis"
        | "pdf_encryption_analysis"
        | "msoffice_encryption_analysis" => label("email body", text_of("email_body")),
        "xml_plain_text_analysis" => {
            let target = text_of("xml_plain_text");
            file(
                "document text",
                added
                    .iter()
                    .position(|f| target.as_deref().is_none_or(|target| f.path == target)),
                false,
            )
        }
        "ocr_analysis" => file(
            "OCR text",
            added.iter().position(|f| {
                f.yara_meta
                    .iter()
                    .any(|tag| tag == "type=document.text.ocr")
            }),
            false,
        ),
        "pdf_text_analysis" => {
            let target = text_of("output_path");
            file(
                "PDF text",
                added.iter().position(|f| {
                    target
                        .as_deref()
                        .is_none_or(|target| f.sha256 == target || f.path == target)
                }),
                false,
            )
        }
        "javascript_deobfuscation_analysis" => file(
            "deobfuscated script",
            added
                .iter()
                .position(|f| f.name().starts_with("deobfuscated-")),
            true,
        ),
        _ => Vec::new(),
    }
}

/// The start of a file's text, up to `max_bytes`, with what isn't UTF-8 dropped; empty when the file
/// can't be read. ace3's `read_text_file`.
async fn file_text(bucket: Option<&Bucket>, sha256: &str, max_bytes: usize) -> String {
    let (Some(bucket), Ok(sha256)) = (bucket, sha256.parse::<Sha256>()) else {
        return String::new();
    };
    let read = async {
        let Some(object) = bucket
            .object(ALERT_FILES, &sha256)
            .await
            .map_err(|error| error.to_string())?
        else {
            return Ok(Vec::new());
        };
        if object.size > MAX_TEXT_FILE_BYTES {
            tracing::debug!(%sha256, size = object.size, "not reading a file this large for its text");
            return Ok(Vec::new());
        }
        let cached = bucket
            .get(ALERT_FILES, &sha256)
            .await
            .map_err(|error| error.to_string())?;
        let limit = max_bytes as u64;
        tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            cached
                .file
                .take(limit)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
    };
    let bytes: Result<Vec<u8>, String> = read.await;
    match bytes {
        Ok(bytes) => String::from_utf8_lossy(&bytes).replace('\u{fffd}', ""),
        Err(error) => {
            tracing::debug!(%sha256, "a file's text couldn't be read: {error}");
            String::new()
        }
    }
}

/// Every document of the alert `root`, in a stable order: its header, its comments, its detections,
/// then its results' in the order they were written. ace3's `extract_documents`.
pub async fn extract(
    db: &Db,
    bucket: Option<&Bucket>,
    root: Uuid,
    bounds: &Bounds,
) -> Result<Extracted, DbError> {
    let max_details = i32::try_from(bounds.max_document_bytes).unwrap_or(i32::MAX);
    let max_results = i64::try_from(bounds.max_documents).unwrap_or(i64::MAX) * 4;
    let read = db
        .transaction(Isolation::RepeatableRead, |tx| {
            Box::pin(async move {
                let Some(alert) = sqlx::query!(
                    r#"SELECT description, origin AS "origin: Value",
                              alerted_at IS NOT NULL AS "alert!"
                       FROM analysis.roots WHERE id = $1"#,
                    root,
                )
                .fetch_optional(tx.conn())
                .await?
                else {
                    return Ok::<_, DbError>(None);
                };
                if !alert.alert {
                    return Ok(None);
                }
                let detections = sqlx::query_scalar!(
                    "SELECT description FROM analysis.detections
                     WHERE root_id = $1 ORDER BY id LIMIT 1000",
                    root,
                )
                .fetch_all(tx.conn())
                .await?;
                // its comments (PLAN.md 5.15), each by who wrote it as a page shows them: ACE's own
                // are by `ACE`, which ace3 writes as its automation user
                let comments = sqlx::query!(
                    r#"SELECT c.id, c.comment,
                              COALESCE(u.display_name, u.username::text, 'ACE') AS "author!"
                       FROM analysis.alert_comments c LEFT JOIN service.users u ON u.id = c.author_id
                       WHERE c.root_id = $1 ORDER BY c.created_at, c.id LIMIT 1000"#,
                    root,
                )
                .fetch_all(tx.conn())
                .await?
                .into_iter()
                .filter_map(|row| Document::comment(&row.id.to_string(), Some(&row.author), &row.comment))
                .collect::<Vec<_>>();
                let results = sqlx::query!(
                    r#"SELECT x.id, x.observable_id, x.analysis_type, x.details AS "details: Value",
                              o.value
                       FROM analysis.results x
                       JOIN analysis.observables o
                         ON o.root_id = x.root_id AND o.id = x.observable_id
                       WHERE x.root_id = $1 AND x.analysis_type = ANY ($2)
                         AND pg_column_size(x.details) <= $3
                       ORDER BY x.id LIMIT $4"#,
                    root,
                    EXTRACTED_TYPES as &[&str],
                    max_details,
                    max_results,
                )
                .fetch_all(tx.conn())
                .await?;
                let ids: Vec<i64> = results.iter().map(|row| row.id).collect();
                let added = sqlx::query!(
                    r#"SELECT a.result_id, o.value, COALESCE(a.path, '') AS "path!",
                              COALESCE(f.yara_meta, '{}') AS "yara_meta!"
                       FROM analysis.result_additions a
                       JOIN analysis.observables o
                         ON o.root_id = a.root_id AND o.id = a.observable_id AND o.type = 'file'
                       LEFT JOIN analysis.files f
                         ON f.root_id = a.root_id AND f.observable_id = a.observable_id
                        AND f.path = a.path
                       WHERE a.root_id = $1 AND a.result_id = ANY ($2)
                       ORDER BY a.id LIMIT 10000"#,
                    root,
                    &ids,
                )
                .fetch_all(tx.conn())
                .await?;
                let mut files: BTreeMap<i64, Vec<Added>> = BTreeMap::new();
                for row in added {
                    files.entry(row.result_id).or_default().push(Added {
                        sha256: row.value,
                        path: row.path,
                        yara_meta: row.yara_meta,
                    });
                }
                let results: Vec<(ResultRow, Vec<Added>)> = results
                    .into_iter()
                    .map(|row| {
                        let added = files.remove(&row.id).unwrap_or_default();
                        (
                            ResultRow {
                                id: row.id,
                                observable_id: row.observable_id,
                                analysis_type: row.analysis_type,
                                details: row.details,
                                observable_value: row.value,
                            },
                            added,
                        )
                    })
                    .collect();
                Ok(Some((alert.description, alert.origin, comments, detections, results)))
            })
        })
        .await?;
    let Some((description, origin, comments, detections, results)) = read else {
        return Ok(Extracted {
            documents: Vec::new(),
            left_out: 0,
            skipped: Some("alert not found".to_owned()),
        });
    };

    let mut documents: Vec<Document> = Vec::new();
    // the header leads with the description, which isn't repeated as an embedded title
    let mut lines = vec![description.clone()];
    for (name, key) in [
        ("alert type", "alert_type"),
        ("tool", "tool"),
        ("instructions", "instructions"),
    ] {
        if let Some(value) = origin
            .as_ref()
            .and_then(|origin| origin.get(key))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            lines.push(format!("{name}: {value}"));
        }
    }
    let header = normalize_text(&lines.join("\n"));
    if !header.is_empty() {
        documents.push(Document {
            kind: "alert",
            key: ALERT_HEADER_KEY.to_owned(),
            text: header,
            title: (!description.is_empty()).then_some(description),
            embed_title: false,
            result_id: None,
            observable_id: None,
        });
    }
    documents.extend(comments);
    let mut seen = BTreeSet::new();
    let described: Vec<String> = detections
        .iter()
        .map(|description| normalize_text(description))
        .filter(|description| !description.is_empty() && seen.insert(description.clone()))
        .collect();
    if !described.is_empty() {
        documents.push(Document {
            kind: "detection",
            key: DETECTIONS_KEY.to_owned(),
            text: described.join("\n"),
            title: Some("detections".to_owned()),
            embed_title: false,
            result_id: None,
            observable_id: None,
        });
    }
    let mut left_out = 0;
    for (row, added) in &results {
        for (index, piece) in pieces(row, added).into_iter().enumerate() {
            if documents.len() >= bounds.max_documents {
                left_out += 1;
                continue;
            }
            let max = bounds.max_document_bytes;
            let (title, label, text) = match piece {
                Piece::Text(title, label, text) => (title, label, text),
                Piece::File(title, label, at, strip) => {
                    let text = file_text(bucket, &added[at].sha256, max).await;
                    let text = if strip {
                        strip_leading_comments(&text)
                    } else {
                        text
                    };
                    (title, label, text)
                }
                Piece::Email(title, headers, body) => {
                    let body = match body {
                        Some((at, html)) => {
                            let text = file_text(bucket, &added[at].sha256, max).await;
                            if html { html_text(&text) } else { text }
                        }
                        None => String::new(),
                    };
                    let text = [headers, body]
                        .into_iter()
                        .filter(|part| !part.trim().is_empty())
                        .collect::<Vec<_>>()
                        .join("\n");
                    (title, false, text)
                }
            };
            let text = truncated(normalize_text(&text), max);
            if text.is_empty() {
                continue;
            }
            documents.push(Document {
                kind: "analysis",
                key: if index == 0 {
                    row.id.to_string()
                } else {
                    format!("{}:{index}", row.id)
                },
                text,
                title: title
                    .map(|title| normalize_text(&title))
                    .filter(|title| !title.is_empty()),
                embed_title: !label,
                result_id: Some(row.id),
                observable_id: Some(row.observable_id),
            });
        }
    }
    // two documents with one kind and key would be one row: the first is kept
    let mut seen = BTreeSet::new();
    documents.retain(|document| seen.insert((document.kind, document.key.clone())));
    Ok(Extracted {
        documents,
        left_out,
        skipped: None,
    })
}
