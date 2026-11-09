//! `urlfinderlib/tokenizer/tokenizer.py`: `UTF8Tokenizer`, over byte offsets of the decoded text.
//! A token is a slice of the text, as Python's are, so the open sequence's first character is
//! skipped by its length in bytes.

use crate::py;

pub struct Tokenizer<'b> {
    pub blob: &'b [u8],
    pub text: String,
}

impl<'b> Tokenizer<'b> {
    pub fn new(blob: &'b [u8]) -> Tokenizer<'b> {
        Tokenizer {
            blob,
            text: py::decode_utf8_ignore(blob).into_owned(),
        }
    }

    /// `get_line_tokens`: `[^\n\r]+`.
    pub fn line_tokens(&self) -> impl Iterator<Item = &str> {
        self.text
            .split(['\n', '\r'])
            .filter(|token| !token.is_empty())
    }

    /// `get_ascii_strings(length)`: runs of printable ASCII in the bytes.
    pub fn ascii_strings(&self, length: usize) -> Vec<&'b str> {
        let mut strings = Vec::new();
        let blob = self.blob;
        let mut i = 0;
        while i < blob.len() {
            if (0x20..=0x7e).contains(&blob[i]) {
                let start = i;
                while i < blob.len() && (0x20..=0x7e).contains(&blob[i]) {
                    i += 1;
                }
                if i - start >= length {
                    strings.push(std::str::from_utf8(&blob[start..i]).unwrap_or(""));
                }
            } else {
                i += 1;
            }
        }
        strings
    }

    /// `get_sentences`.
    pub fn sentences(&self) -> Vec<&str> {
        let s = self.text.as_str();
        let mut sentences = Vec::new();
        let mut pos = 0;
        let mut chars = s.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            if !matches!(c, '.' | '!' | '?') {
                continue;
            }
            let Some(&(j, next)) = chars.peek() else {
                break;
            };
            if !py::is_space(next) {
                continue;
            }
            chars.next();
            let end = i;
            let start = match s[pos..end].rfind('\n') {
                Some(newline) => pos + newline + 1,
                None => pos,
            };
            sentences.push(&s[start..end]);
            pos = j + next.len_utf8();
        }
        sentences
    }

    /// `_get_indices_of_sequence`: where `sequence` starts, without overlaps.
    fn indices(&self, sequence: &str) -> Vec<usize> {
        if sequence.len() == 1 {
            let byte = sequence.as_bytes()[0];
            return memchr::memchr_iter(byte, self.text.as_bytes()).collect();
        }
        self.text.match_indices(sequence).map(|(i, _)| i).collect()
    }

    /// `get_tokens_between_open_and_close_sequence(open, close, strict=True)`: from each open
    /// sequence, one character on, to the first close sequence after it.
    pub fn between_open_and_close(&self, open: &str, close: &str) -> Vec<&str> {
        let opens = self.indices(open);
        let closes = self.indices(close);
        let skip = open.chars().next().map_or(0, char::len_utf8);
        let mut tokens = Vec::with_capacity(opens.len());
        for o in opens {
            let first = closes.partition_point(|&c| c <= o);
            if let Some(&c) = closes.get(first) {
                let start = o + skip;
                tokens.push(if start <= c { &self.text[start..c] } else { "" });
            }
        }
        tokens
    }

    /// `get_tokens_between_sequence`: between each two in a row, empty ones left out.
    pub fn between_sequence(&self, sequence: &str) -> Vec<&str> {
        let indices = self.indices(sequence);
        let skip = sequence.chars().next().map_or(0, char::len_utf8);
        indices
            .windows(2)
            .map(|w| &self.text[(w[0] + skip).min(w[1])..w[1]])
            .filter(|token| !token.is_empty())
            .collect()
    }

    /// `get_tokens_between_single_quotes`.
    pub fn between_single_quotes(&self) -> Vec<&str> {
        let mut tokens = self.between_sequence("'");
        tokens.extend(self.between_sequence("\u{2018}"));
        tokens.extend(self.between_sequence("\u{2019}"));
        tokens
    }
}

/// `[^\s]+` runs of a text.
pub fn split_on_space(text: &str) -> impl Iterator<Item = &str> {
    text.split(py::is_space).filter(|token| !token.is_empty())
}

/// `_get_new_tokenizer_with_replaced_characters(...)`'s text: each of the characters replaced
/// by a space.
pub fn replace_with_spaces(text: &str, characters: &[char]) -> String {
    text.chars()
        .map(|c| if characters.contains(&c) { ' ' } else { c })
        .collect()
}
