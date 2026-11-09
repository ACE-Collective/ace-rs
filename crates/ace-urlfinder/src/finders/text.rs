//! `urlfinderlib/finders/text.py`: `TextUrlFinder`, which every other finder hands its
//! candidates to.

use std::collections::BTreeSet;

use rustc_hash::FxHashSet;

use crate::helpers;
use crate::py::{self, PyResult};
use crate::tokenizer::{Tokenizer, replace_with_spaces, split_on_space};
use crate::url::UrlList;

const SPLIT_CHARACTERS: [char; 17] = [
    '<', '>', '`', '[', ']', '{', '}', '"', '\'', '(', ')', '\u{2018}', '\u{2019}', '\u{201c}',
    '\u{201d}', '\u{ab}', '\u{bb}',
];

/// `_has_internal_whitespace`.
fn has_internal_whitespace(token: &str) -> bool {
    py::has_space(py::strip(token))
}

/// `TextUrlFinder(blob).find_urls(strict=True, domain_as_url=...)`.
pub fn find_urls(blob: &[u8], domain_as_url: bool) -> PyResult<BTreeSet<String>> {
    let blob = helpers::unescape_ascii(blob);
    let tok = Tokenizer::new(&blob);
    let replaced = replace_with_spaces(&tok.text, &SPLIT_CHARACTERS);

    let mut delimited: Vec<&str> = Vec::new();
    delimited.extend(tok.between_open_and_close("<", ">"));
    delimited.extend(tok.between_sequence("`"));
    delimited.extend(tok.between_open_and_close("[", "]"));
    delimited.extend(tok.between_open_and_close("{", "}"));
    delimited.extend(tok.between_sequence("\""));
    delimited.extend(tok.between_open_and_close("(", ")"));
    delimited.extend(tok.between_single_quotes());
    let free_text = tok
        .line_tokens()
        .chain(tok.sentences())
        .filter(|token| !has_internal_whitespace(token));

    let split = split_on_space(&replaced);

    let mut tokens: FxHashSet<&str> = FxHashSet::default();
    let wanted = |token: &str| {
        if token.contains('.') && token.contains('/') {
            return true;
        }
        domain_as_url && py::validators_domain(token)
    };
    for token in delimited.into_iter().chain(free_text).chain(split) {
        if !tokens.contains(token) && wanted(token) {
            tokens.insert(token);
        }
    }

    let mut valid = UrlList::new();
    for token in tokens {
        // display text<actual URL>, which stands for two URLs, not one
        if token.contains('<') && token.ends_with('>') {
            continue;
        }
        valid.append(&helpers::fix_possible_url(token, domain_as_url))?;
    }
    valid.distinct_values()
}
