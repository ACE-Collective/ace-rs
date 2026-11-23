//! The embedding model: ace3's `saq/search/model.py`.
//!
//! The model is `sentence-transformers/all-MiniLM-L6-v2`, ace3's `search.embedding_model` default: a
//! six-layer BERT whose token vectors are averaged and normalized into 384 numbers. It runs here, in this
//! process, on the CPU: nothing an alert holds is sent anywhere to be embedded.
//!
//! **Where it comes from.** Three files of the model's repository on Hugging Face at one commit
//! ([`MODEL_REVISION`]): `model.safetensors`, `tokenizer.json` and `config.json`. The images download
//! them when they are built (`docker/ace-rs/Dockerfile`'s and `docker/dev/Dockerfile`'s `search-model`
//! stage) and `ACE_RS_SEARCH_MODEL` names their directory. [`Model::load`] reads nothing else, downloads
//! nothing, and refuses a file whose SHA-256 isn't the one pinned in [`MODEL_FILES`], so a model that
//! was swapped or cut short never embeds anything. ace3 downloads the model when its indexer first
//! starts; ace-rs's processes never fetch it.
//!
//! **What runs it.** `bert` below is the model's forward pass written out: the embeddings, six layers of
//! attention and feed-forward, each over `matrixmultiply`'s matrix product, read from the safetensors
//! file by Hugging Face's `safetensors`. It isn't Hugging Face's `candle`, which was the first choice:
//! candle 0.11's matrix kernels don't build for arm64 Linux unless every crate in the workspace is
//! compiled for the FP16 extension, which would tie every ace-rs binary to CPUs that have it. The model
//! is small and fixed, and the test below holds the pass to ace3's own vectors.
//!
//! **What matches ace3.** The weights are the same file sentence-transformers downloads. The tokenizer
//! is the model's own, read by Hugging Face's `tokenizers`, the library under ace3's. A text is cut at
//! the model's 256 tokens (`sentence_bert_config.json`'s `max_seq_length`, which the tokenizer file's
//! own 128 isn't), the token vectors are averaged under the attention mask and the result is
//! normalized, as its `1_Pooling` and `2_Normalize` modules do. `tests::the_model_embeds_as_ace3_s_does`
//! checks vectors against ones ace3's own model made.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use safetensors::{Dtype, SafeTensors};
use sha2::{Digest, Sha256};
use tokenizers::{Tokenizer, TruncationParams};

mod bert;

/// The model's name, ace3's `search.embedding_model`.
pub const MODEL_NAME: &str = "all-MiniLM-L6-v2";
/// Its repository on Hugging Face, the one source its files are fetched from.
pub const MODEL_REPOSITORY: &str = "sentence-transformers/all-MiniLM-L6-v2";
/// The commit of that repository the files are read at.
pub const MODEL_REVISION: &str = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41";
/// The files [`Model::load`] reads, each with its SHA-256.
pub const MODEL_FILES: [(&str, &str); 3] = [
    (
        "model.safetensors",
        "53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db",
    ),
    (
        "tokenizer.json",
        "be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037",
    ),
    (
        "config.json",
        "953f9c0d463486b10a6871cc2fd59f223b2c70184f49815e7efbcab5d8908b41",
    ),
];
/// The numbers in one embedding.
pub const DIMENSIONS: usize = 384;
/// The most tokens the model reads of one text, its two special tokens included: the model's
/// `max_seq_length`.
pub const MAX_SEQUENCE_TOKENS: usize = 256;
/// The variable that names the model's directory.
pub const MODEL_VAR: &str = "ACE_RS_SEARCH_MODEL";

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("reading the embedding model's {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "the embedding model's {path} isn't the pinned file: its SHA-256 is {found}, not {pinned}"
    )]
    Hash {
        path: PathBuf,
        found: String,
        pinned: &'static str,
    },
    #[error("the embedding model: {0}")]
    Model(String),
}

pub(crate) fn model_error(error: impl std::fmt::Display) -> ModelError {
    ModelError::Model(error.to_string())
}

/// The loaded model. It's shared by every task of its process, and a call that embeds blocks its
/// thread, so async callers go through `spawn_blocking`.
pub struct Model {
    /// Cuts a text as the model reads it, with its special tokens.
    encoder: Tokenizer,
    /// Tokenizes a whole text with no special tokens, for a chunk's bounds.
    chunker: Tokenizer,
    bert: bert::Bert,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(MODEL_NAME)
    }
}

impl Model {
    /// The model in `dir`, once each of its files matches its pinned hash.
    pub fn load(dir: &Path) -> Result<Arc<Model>, ModelError> {
        let mut files = Vec::with_capacity(MODEL_FILES.len());
        for (name, pinned) in MODEL_FILES {
            let path = dir.join(name);
            let bytes = std::fs::read(&path).map_err(|source| ModelError::Read {
                path: path.clone(),
                source,
            })?;
            let found = hex::encode(Sha256::digest(&bytes));
            if found != pinned {
                return Err(ModelError::Hash {
                    path,
                    found,
                    pinned,
                });
            }
            files.push(bytes);
        }
        let [weights, tokenizer, config] = <[Vec<u8>; 3]>::try_from(files)
            .map_err(|_| ModelError::Model("three files".to_owned()))?;
        let config: bert::Config = serde_json::from_slice(&config).map_err(model_error)?;
        let tensors = SafeTensors::deserialize(&weights).map_err(model_error)?;
        let bert = bert::Bert::load(&config, &|name: &str| {
            let view = tensors.tensor(name).map_err(model_error)?;
            if view.dtype() != Dtype::F32 {
                return Err(ModelError::Model(format!("{name} isn't 32-bit floats")));
            }
            let values = view
                .data()
                .as_chunks::<4>()
                .0
                .iter()
                .map(|bytes| f32::from_le_bytes(*bytes))
                .collect();
            Ok((view.shape().to_vec(), values))
        })?;
        if bert.hidden() != DIMENSIONS || bert.max_positions() < MAX_SEQUENCE_TOKENS {
            return Err(ModelError::Model(format!(
                "the model has {} dimensions and {} positions, not {DIMENSIONS} and at least {MAX_SEQUENCE_TOKENS}",
                bert.hidden(),
                bert.max_positions()
            )));
        }
        let mut chunker = Tokenizer::from_bytes(&tokenizer).map_err(model_error)?;
        chunker.with_padding(None);
        chunker.with_truncation(None).map_err(model_error)?;
        // each text is embedded alone, so nothing is padded and no token is masked
        let mut encoder = chunker.clone();
        encoder
            .with_truncation(Some(TruncationParams {
                max_length: MAX_SEQUENCE_TOKENS,
                ..TruncationParams::default()
            }))
            .map_err(model_error)?;
        Ok(Arc::new(Model {
            encoder,
            chunker,
            bert,
        }))
    }

    /// The model `ACE_RS_SEARCH_MODEL` names, or None when it's unset or empty.
    pub fn from_env() -> Result<Option<Arc<Model>>, ModelError> {
        match std::env::var(MODEL_VAR) {
            Ok(dir) if !dir.is_empty() => Model::load(Path::new(&dir)).map(Some),
            _ => Ok(None),
        }
    }

    /// The (start, end) bytes of each of `text`'s tokens, ace3's `token_offsets`: no special tokens and
    /// no cut, and a token with no text left out.
    pub fn token_offsets(&self, text: &str) -> Result<Vec<(usize, usize)>, ModelError> {
        let encoding = self.chunker.encode(text, false).map_err(model_error)?;
        Ok(encoding
            .get_offsets()
            .iter()
            .copied()
            .filter(|(start, end)| end > start)
            .collect())
    }

    /// Each text's embedding, normalized, in the texts' order: ace3's `encode_documents`.
    pub fn encode(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, ModelError> {
        texts.iter().map(|text| self.encode_one(text)).collect()
    }

    /// One text's embedding: ace3's `encode_query`, whose prefix is empty for this model. The mean of
    /// its tokens' vectors, at unit length.
    pub fn encode_one(&self, text: &str) -> Result<Vec<f32>, ModelError> {
        let encoding = self.encoder.encode(text, true).map_err(model_error)?;
        let tokens = self
            .bert
            .forward(encoding.get_ids(), encoding.get_type_ids())?;
        let hidden = self.bert.hidden();
        let count = tokens.len() / hidden;
        let mut mean = vec![0f32; hidden];
        for token in tokens.chunks_exact(hidden) {
            for (sum, value) in mean.iter_mut().zip(token) {
                *sum += value;
            }
        }
        let count = (count as f32).max(1e-9);
        for value in &mut mean {
            *value /= count;
        }
        let norm = mean
            .iter()
            .map(|value| value * value)
            .sum::<f32>()
            .sqrt()
            .max(1e-12);
        for value in &mut mean {
            *value /= norm;
        }
        Ok(mean)
    }
}

/// The most tokens a chunk may hold so the model reads all of it: ace3's `max_chunk_tokens`, the
/// configured size or the model's limit less its two special tokens, whichever is smaller.
pub fn max_chunk_tokens(configured: usize) -> usize {
    configured.clamp(1, MAX_SEQUENCE_TOKENS - 2)
}
