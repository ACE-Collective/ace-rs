//! An alert's documents cut into chunks, each with its embedding and its terms: ace3's
//! `build_points`. It runs on a blocking thread, since the model does.

use crate::chunking::{chunk_text, trimmed};
use crate::documents::{Bounds, Document};
use crate::model::{Model, ModelError, max_chunk_tokens};
use crate::sparse;

/// One chunk, ready to write: ace3's point.
#[derive(Debug, Clone, PartialEq)]
pub struct Embedded {
    pub kind: &'static str,
    pub key: String,
    pub chunk: i32,
    pub title: Option<String>,
    /// The chunk as it was embedded.
    pub text: String,
    pub result_id: Option<i64>,
    pub observable_id: Option<i64>,
    pub embedding: Vec<f32>,
    /// The text's terms as a `tsvector`'s text (`sparse::tsvector_text`).
    pub terms: String,
    /// The same terms as ace3's sparse vector: each id with its saturated count.
    pub sparse: Vec<(u32, f64)>,
}

/// Cuts and embeds `documents`, in their order, and says how many chunks were past `bounds` and left
/// out. A document the bounds can't cut is an error.
pub fn embed(
    model: &Model,
    documents: &[Document],
    bounds: &Bounds,
) -> Result<(Vec<Embedded>, usize), ModelError> {
    let chunk_tokens = max_chunk_tokens(bounds.chunk_tokens);
    let overlap = bounds.chunk_overlap.min(chunk_tokens - 1);
    let mut entries: Vec<(&Document, usize, String)> = Vec::new();
    let mut left_out = 0;
    for document in documents {
        let text = trimmed(&document.text);
        let offsets = model.token_offsets(text)?;
        let title = document.title.as_deref().filter(|_| document.embed_title);
        let chunks = chunk_text(
            text,
            &offsets,
            chunk_tokens,
            overlap,
            bounds.max_chunks_per_document,
            title,
        )
        .map_err(ModelError::Model)?;
        for chunk in chunks {
            if entries.len() >= bounds.max_chunks {
                left_out += 1;
            } else {
                entries.push((document, chunk.index, chunk.text));
            }
        }
    }
    let texts: Vec<String> = entries.iter().map(|(_, _, text)| text.clone()).collect();
    let vectors = model.encode(&texts)?;
    let embedded = entries
        .into_iter()
        .zip(vectors)
        .map(|((document, index, text), embedding)| Embedded {
            kind: document.kind,
            key: document.key.clone(),
            chunk: i32::try_from(index).unwrap_or(i32::MAX),
            title: document.title.clone(),
            terms: sparse::tsvector_text(&text),
            sparse: sparse::term_weights(&text),
            text,
            result_id: document.result_id,
            observable_id: document.observable_id,
            embedding,
        })
        .collect();
    Ok((embedded, left_out))
}
