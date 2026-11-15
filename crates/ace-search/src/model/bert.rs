//! BERT's forward pass, as `transformers`' `BertModel` computes it when it isn't training: the
//! embeddings, then each layer's self-attention and feed-forward, each followed by a residual and a
//! layer normalization. One text at a time, so there is no padding and no mask.
//!
//! The numbers are the model file's 32-bit floats, and the matrix products are `matrixmultiply`'s. A
//! linear layer's weight is stored as (outputs, inputs), so `x W^T` reads it with its strides swapped
//! and nothing is copied.

use serde::Deserialize;

use super::ModelError;

/// What `config.json` says of the model's shape.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Config {
    hidden_size: usize,
    num_hidden_layers: usize,
    num_attention_heads: usize,
    intermediate_size: usize,
    max_position_embeddings: usize,
    type_vocab_size: usize,
    vocab_size: usize,
    layer_norm_eps: f64,
    hidden_act: String,
    #[serde(default)]
    position_embedding_type: Option<String>,
}

/// A linear layer: `weight` is (outputs, inputs), row by row.
struct Linear {
    weight: Vec<f32>,
    bias: Vec<f32>,
    inputs: usize,
    outputs: usize,
}

impl Linear {
    /// `x`, `rows` rows of `inputs`, through the layer: `rows` rows of `outputs`.
    fn apply(&self, x: &[f32], rows: usize) -> Vec<f32> {
        let mut out = Vec::with_capacity(rows * self.outputs);
        for _ in 0..rows {
            out.extend_from_slice(&self.bias);
        }
        // SAFETY: `x` is rows x inputs and `out` rows x outputs, each row-major with the strides given;
        // the weight is read as inputs x outputs through strides (1, inputs), which stay inside its
        // outputs x inputs values. `load` checked every length.
        unsafe {
            matrixmultiply::sgemm(
                rows,
                self.inputs,
                self.outputs,
                1.0,
                x.as_ptr(),
                self.inputs as isize,
                1,
                self.weight.as_ptr(),
                1,
                self.inputs as isize,
                1.0,
                out.as_mut_ptr(),
                self.outputs as isize,
                1,
            );
        }
        out
    }
}

struct LayerNorm {
    weight: Vec<f32>,
    bias: Vec<f32>,
    eps: f32,
}

impl LayerNorm {
    fn apply(&self, x: &mut [f32]) {
        let width = self.weight.len();
        for row in x.chunks_exact_mut(width) {
            let mean = row.iter().sum::<f32>() / width as f32;
            let variance = row
                .iter()
                .map(|value| (value - mean) * (value - mean))
                .sum::<f32>()
                / width as f32;
            let scale = 1.0 / (variance + self.eps).sqrt();
            for ((value, weight), bias) in row.iter_mut().zip(&self.weight).zip(&self.bias) {
                *value = (*value - mean) * scale * weight + bias;
            }
        }
    }
}

struct Layer {
    query: Linear,
    key: Linear,
    value: Linear,
    attention_output: Linear,
    attention_norm: LayerNorm,
    intermediate: Linear,
    output: Linear,
    output_norm: LayerNorm,
}

pub(crate) struct Bert {
    hidden: usize,
    heads: usize,
    max_positions: usize,
    vocabulary: usize,
    types: usize,
    words: Vec<f32>,
    positions: Vec<f32>,
    token_types: Vec<f32>,
    embedding_norm: LayerNorm,
    layers: Vec<Layer>,
}

/// A tensor by name: its shape and values.
pub(crate) type Tensors<'a> = &'a dyn Fn(&str) -> Result<(Vec<usize>, Vec<f32>), ModelError>;

fn shaped(tensors: Tensors<'_>, name: &str, shape: &[usize]) -> Result<Vec<f32>, ModelError> {
    let (found, values) = tensors(name)?;
    if found != shape || values.len() != shape.iter().product::<usize>() {
        return Err(ModelError::Model(format!(
            "{name} has the shape {found:?}, not {shape:?}"
        )));
    }
    Ok(values)
}

fn linear(
    tensors: Tensors<'_>,
    name: &str,
    inputs: usize,
    outputs: usize,
) -> Result<Linear, ModelError> {
    Ok(Linear {
        weight: shaped(tensors, &format!("{name}.weight"), &[outputs, inputs])?,
        bias: shaped(tensors, &format!("{name}.bias"), &[outputs])?,
        inputs,
        outputs,
    })
}

fn layer_norm(
    tensors: Tensors<'_>,
    name: &str,
    width: usize,
    eps: f64,
) -> Result<LayerNorm, ModelError> {
    Ok(LayerNorm {
        weight: shaped(tensors, &format!("{name}.weight"), &[width])?,
        bias: shaped(tensors, &format!("{name}.bias"), &[width])?,
        eps: eps as f32,
    })
}

impl Bert {
    pub(crate) fn load(config: &Config, tensors: Tensors<'_>) -> Result<Bert, ModelError> {
        let refuse = |what: String| Err(ModelError::Model(what));
        if config.hidden_act != "gelu" {
            return refuse(format!("the activation {:?} isn't gelu", config.hidden_act));
        }
        if config
            .position_embedding_type
            .as_deref()
            .is_some_and(|kind| kind != "absolute")
        {
            return refuse("the position embeddings aren't absolute".to_owned());
        }
        let hidden = config.hidden_size;
        let heads = config.num_attention_heads;
        if hidden == 0 || heads == 0 || !hidden.is_multiple_of(heads) {
            return refuse(format!(
                "{hidden} dimensions don't split into {heads} heads"
            ));
        }
        let mut layers = Vec::with_capacity(config.num_hidden_layers);
        for n in 0..config.num_hidden_layers {
            let at = |part: &str| format!("encoder.layer.{n}.{part}");
            layers.push(Layer {
                query: linear(tensors, &at("attention.self.query"), hidden, hidden)?,
                key: linear(tensors, &at("attention.self.key"), hidden, hidden)?,
                value: linear(tensors, &at("attention.self.value"), hidden, hidden)?,
                attention_output: linear(tensors, &at("attention.output.dense"), hidden, hidden)?,
                attention_norm: layer_norm(
                    tensors,
                    &at("attention.output.LayerNorm"),
                    hidden,
                    config.layer_norm_eps,
                )?,
                intermediate: linear(
                    tensors,
                    &at("intermediate.dense"),
                    hidden,
                    config.intermediate_size,
                )?,
                output: linear(
                    tensors,
                    &at("output.dense"),
                    config.intermediate_size,
                    hidden,
                )?,
                output_norm: layer_norm(
                    tensors,
                    &at("output.LayerNorm"),
                    hidden,
                    config.layer_norm_eps,
                )?,
            });
        }
        Ok(Bert {
            hidden,
            heads,
            max_positions: config.max_position_embeddings,
            vocabulary: config.vocab_size,
            types: config.type_vocab_size,
            words: shaped(
                tensors,
                "embeddings.word_embeddings.weight",
                &[config.vocab_size, hidden],
            )?,
            positions: shaped(
                tensors,
                "embeddings.position_embeddings.weight",
                &[config.max_position_embeddings, hidden],
            )?,
            token_types: shaped(
                tensors,
                "embeddings.token_type_embeddings.weight",
                &[config.type_vocab_size, hidden],
            )?,
            embedding_norm: layer_norm(
                tensors,
                "embeddings.LayerNorm",
                hidden,
                config.layer_norm_eps,
            )?,
            layers,
        })
    }

    pub(crate) fn hidden(&self) -> usize {
        self.hidden
    }

    pub(crate) fn max_positions(&self) -> usize {
        self.max_positions
    }

    /// The last layer's vector for each token: `ids.len()` rows of `hidden`.
    pub(crate) fn forward(&self, ids: &[u32], types: &[u32]) -> Result<Vec<f32>, ModelError> {
        let length = ids.len();
        if length == 0 || length > self.max_positions || types.len() != length {
            return Err(ModelError::Model(format!(
                "{length} tokens: the model reads 1 to {}",
                self.max_positions
            )));
        }
        let hidden = self.hidden;
        let mut x = Vec::with_capacity(length * hidden);
        for (position, (id, kind)) in ids.iter().zip(types).enumerate() {
            let (id, kind) = (*id as usize, *kind as usize);
            if id >= self.vocabulary || kind >= self.types {
                return Err(ModelError::Model(format!(
                    "the token {id} of type {kind} isn't the model's"
                )));
            }
            let word = &self.words[id * hidden..(id + 1) * hidden];
            let place = &self.positions[position * hidden..(position + 1) * hidden];
            let kind = &self.token_types[kind * hidden..(kind + 1) * hidden];
            x.extend(
                word.iter()
                    .zip(place)
                    .zip(kind)
                    .map(|((word, place), kind)| word + place + kind),
            );
        }
        self.embedding_norm.apply(&mut x);
        for layer in &self.layers {
            let attended = self.attend(layer, &x, length);
            let mut out = layer.attention_output.apply(&attended, length);
            for (out, x) in out.iter_mut().zip(&x) {
                *out += x;
            }
            layer.attention_norm.apply(&mut out);
            let mut inner = layer.intermediate.apply(&out, length);
            for value in &mut inner {
                *value = gelu(*value);
            }
            let mut next = layer.output.apply(&inner, length);
            for (next, out) in next.iter_mut().zip(&out) {
                *next += out;
            }
            layer.output_norm.apply(&mut next);
            x = next;
        }
        Ok(x)
    }

    /// Self-attention: each head's softmax of `q k^T / sqrt(d)` over its values, the heads side by
    /// side again.
    fn attend(&self, layer: &Layer, x: &[f32], length: usize) -> Vec<f32> {
        let hidden = self.hidden;
        let width = hidden / self.heads;
        let query = layer.query.apply(x, length);
        let key = layer.key.apply(x, length);
        let value = layer.value.apply(x, length);
        let scale = 1.0 / (width as f32).sqrt();
        let mut out = vec![0f32; length * hidden];
        let mut scores = vec![0f32; length * length];
        for head in 0..self.heads {
            let offset = head * width;
            // SAFETY: each matrix is the head's `width` columns of a length x hidden row-major buffer,
            // read with the row stride `hidden` from `offset`; `scores` is length x length and `out`'s
            // slice starts at the same offset with the same strides. All stay inside their buffers.
            unsafe {
                // scores = scale * Q K^T: K^T is K with its strides swapped
                matrixmultiply::sgemm(
                    length,
                    width,
                    length,
                    scale,
                    query.as_ptr().add(offset),
                    hidden as isize,
                    1,
                    key.as_ptr().add(offset),
                    1,
                    hidden as isize,
                    0.0,
                    scores.as_mut_ptr(),
                    length as isize,
                    1,
                );
            }
            for row in scores.chunks_exact_mut(length) {
                let highest = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
                let mut total = 0f32;
                for score in row.iter_mut() {
                    *score = (*score - highest).exp();
                    total += *score;
                }
                for score in row.iter_mut() {
                    *score /= total;
                }
            }
            // SAFETY: as above.
            unsafe {
                matrixmultiply::sgemm(
                    length,
                    length,
                    width,
                    1.0,
                    scores.as_ptr(),
                    length as isize,
                    1,
                    value.as_ptr().add(offset),
                    hidden as isize,
                    1,
                    0.0,
                    out.as_mut_ptr().add(offset),
                    hidden as isize,
                    1,
                );
            }
        }
        out
    }
}

/// GELU as `transformers` computes it: `x / 2 * (1 + erf(x / sqrt(2)))`.
fn gelu(x: f32) -> f32 {
    0.5 * x * (1.0 + libm::erff(x * std::f32::consts::FRAC_1_SQRT_2))
}
