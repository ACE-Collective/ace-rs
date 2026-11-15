//! A document split into overlapping chunks sized in the model's tokens: ace3's
//! `saq/search/chunking.py`.
//!
//! The model reads at most 256 tokens of a text and drops the rest without a word, so a document is
//! cut before it's embedded, at the bounds the model's own tokenizer gives. A chunk is a slice of the
//! document, never tokens put back together, so the snippet a result shows is what was written.

/// One chunk of a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub index: usize,
    pub text: String,
    pub token_count: usize,
}

/// `text` as at most `max_chunks` chunks of `chunk_tokens` tokens, each sharing `overlap` tokens with
/// the one before: ace3's `chunk_text`. `offsets` are the (start, end) bytes of the text's tokens once
/// it's trimmed (`trimmed`, then `Model::token_offsets`). `title`, when given, goes before the first
/// chunk only. `chunk_tokens` of 0 or an overlap that isn't smaller are refused.
pub fn chunk_text(
    text: &str,
    offsets: &[(usize, usize)],
    chunk_tokens: usize,
    overlap: usize,
    max_chunks: usize,
    title: Option<&str>,
) -> Result<Vec<Chunk>, String> {
    if chunk_tokens < 1 {
        return Err("chunk_tokens must be positive".to_owned());
    }
    if overlap >= chunk_tokens {
        return Err("overlap must be smaller than chunk_tokens".to_owned());
    }
    if text.is_empty() || offsets.is_empty() || max_chunks == 0 {
        return Ok(Vec::new());
    }
    let stride = chunk_tokens - overlap;
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < offsets.len() {
        let end = (start + chunk_tokens).min(offsets.len());
        let body = text
            .get(offsets[start].0..offsets[end - 1].1)
            .ok_or_else(|| "a token's bounds aren't in the text".to_owned())?;
        let body = match title {
            Some(title) if chunks.is_empty() && !title.is_empty() => format!("{title}\n{body}"),
            _ => body.to_owned(),
        };
        chunks.push(Chunk {
            index: chunks.len(),
            text: body,
            token_count: end - start,
        });
        if end >= offsets.len() || chunks.len() >= max_chunks {
            break;
        }
        start += stride;
    }
    Ok(chunks)
}

/// The text as `chunk_text` reads it: ace3 strips it first.
pub fn trimmed(text: &str) -> &str {
    text.trim()
}
