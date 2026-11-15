//! A text's terms: ace3's `saq/search/sparse.py`.
//!
//! A text becomes a bag of terms in which every identifier an analyst might search for (a URL, an email
//! address, a hash, an address, a domain, a path) is kept whole and also split into its parts, so
//! `bob@example.com` matches the address and `example.com` still matches the domain. Plain words join
//! them, less a short list of stopwords. A term's id is ace3's, the first four bytes of its BLAKE2b
//! hash, so no vocabulary is kept anywhere. Documents and queries go through the same function.
//!
//! ace3 hands the ids and weights to Qdrant as a sparse vector, and Qdrant applies the inverse document
//! frequency. Here the ids are the lexemes of a Postgres `tsvector` (`tsvector_text`), each id as eight
//! hex digits and each occurrence a position, and `crate::pg` weights each term by how rare it is.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use blake2::Blake2b;
use blake2::digest::Digest;
use blake2::digest::consts::U4;
use regex::Regex;

/// The longest first, so a URL wins over the domain and the address inside it.
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)(?P<url>[a-z][a-z0-9+.-]*://[^\s<>"']+)"#,
        r"|(?P<email>[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})",
        r"|(?P<hash>\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b)",
        r"|(?P<ipv4>\b(?:\d{1,3}\.){3}\d{1,3}\b)",
        r#"|(?P<winpath>\b[a-z]:\\(?:[^\\\s<>"|?*]+\\)*[^\\\s<>"|?*]*)"#,
        r"|(?P<fqdn>\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b)",
        r#"|(?P<posixpath>(?:/[^/\s<>"'|?*]+){2,}/?)"#,
    ))
    .expect("a valid pattern")
});
static WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new("(?i)[a-z0-9]+").expect("a pattern"));
static NOT_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("(?i)[^a-z0-9]+").expect("a pattern"));

/// The shortest part or word kept.
pub const MIN_TOKEN_LENGTH: usize = 2;
/// How fast a term's weight stops growing with its count: ace3's `TF_SATURATION_K`.
pub const TF_SATURATION_K: f64 = 1.2;
/// The most distinct terms a query is searched by: its first, in the order they appear. A document's
/// are bounded by its chunk's size.
pub const MAX_QUERY_TERMS: usize = 64;
/// The most positions a term gets in a `tsvector`: its count, up to this.
const MAX_POSITIONS: usize = 32;

/// Plain words that say nothing alone. An identifier is never filtered.
const STOPWORDS: &str = "a an and are as at be been but by for from has have he her his i if in into is it its of on or our \
she so than that the their them then there these they this to too was we were what when where which \
who will with would you your yes no not do does did done can could should may might must shall \
am us me my mine yours ours them him hers am s t re ve ll d m \
http https www com net org html htm php";

fn is_stopword(word: &str) -> bool {
    STOPWORDS.split_ascii_whitespace().any(|stop| stop == word)
}

/// Every identifier-shaped part of `text`, lowercased, in the order they appear.
pub fn identifiers(text: &str) -> Vec<String> {
    IDENTIFIER
        .find_iter(text)
        .map(|found| {
            found
                .as_str()
                .to_lowercase()
                .trim_end_matches(['.', ',', ';', ':', ')'])
                .to_owned()
        })
        .collect()
}

/// The text's terms: its identifiers whole, their parts, and its plain words.
pub fn lexical_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for identifier in identifiers(text) {
        let parts: Vec<String> = NOT_WORD
            .split(&identifier)
            .filter(|part| part.chars().count() >= MIN_TOKEN_LENGTH)
            .map(str::to_lowercase)
            .collect();
        tokens.push(identifier);
        tokens.extend(parts);
    }
    tokens.extend(
        WORD.find_iter(text)
            .map(|word| word.as_str().to_lowercase())
            .filter(|word| word.chars().count() >= MIN_TOKEN_LENGTH && !is_stopword(word)),
    );
    tokens
}

/// A term's id: the first four bytes of its BLAKE2b hash, big-endian, as ace3's `token_index`.
pub fn token_index(token: &str) -> u32 {
    let digest: [u8; 4] = Blake2b::<U4>::digest(token.as_bytes()).into();
    u32::from_be_bytes(digest)
}

/// How many times each term id is in `text`. Two terms with one id count together, as in ace3.
pub fn term_counts(text: &str) -> BTreeMap<u32, usize> {
    let mut counts = BTreeMap::new();
    for token in lexical_tokens(text) {
        *counts.entry(token_index(&token)).or_insert(0) += 1;
    }
    counts
}

/// ace3's `term_weights`: each term id's count, saturated so a term said a hundred times doesn't own the
/// document. In id order, as ace3's sparse vector.
pub fn term_weights(text: &str) -> Vec<(u32, f64)> {
    term_counts(text)
        .into_iter()
        .map(|(index, count)| {
            let tf = count as f64;
            (index, tf / (tf + TF_SATURATION_K))
        })
        .collect()
}

/// A term id as a `tsvector` lexeme: eight hex digits.
pub fn lexeme(index: u32) -> String {
    format!("{index:08x}")
}

/// The text's terms as a `tsvector`'s text: each id a lexeme, with one position for each time it's
/// there, up to `MAX_POSITIONS`. Postgres's rank of a term grows with its positions and levels off, as
/// ace3's saturated count does. The lexemes are hex and the positions numbers, so the text has nothing
/// to quote.
pub fn tsvector_text(text: &str) -> String {
    let mut out = String::new();
    let mut position = 0;
    for (index, count) in term_counts(text) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push('\'');
        out.push_str(&lexeme(index));
        out.push_str("':");
        for n in 0..count.min(MAX_POSITIONS) {
            position += 1;
            if n > 0 {
                out.push(',');
            }
            out.push_str(&position.to_string());
        }
    }
    out
}

/// A query's terms: each distinct id with its saturated count, the first `MAX_QUERY_TERMS` in the order
/// they first appear.
pub fn query_terms(text: &str) -> Vec<(u32, f64)> {
    let mut order = Vec::new();
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    for token in lexical_tokens(text) {
        let index = token_index(&token);
        let count = counts.entry(index).or_insert(0);
        if *count == 0 {
            order.push(index);
        }
        *count += 1;
    }
    order
        .into_iter()
        .take(MAX_QUERY_TERMS)
        .map(|index| {
            let tf = counts[&index] as f64;
            (index, tf / (tf + TF_SATURATION_K))
        })
        .collect()
}
