//! The rules of a rule file as its source has them, each with the hash of its own text: what ace3's
//! signature inventory reads with plyara (`saq/signatures/loaders/yara.py`'s `parse_rule_file`), which SVS
//! validation uses to say which rules a change added, removed or changed (PLAN.md 7.10 batch 3).
//!
//! The file is parsed, not compiled, so a file that doesn't compile still has its rules here, as in ace3. A
//! rule's text is the whole lines from the one it starts on to the one it ends on, as plyara's
//! `start_line` and `stop_line` slice it, and its hash is the sha256 of that text (ace3's `content_hash`).
//! Its uuid is its `uuid` meta, trimmed; a rule without one isn't tracked by ace3's inventory, and is
//! listed here with none so a caller can say it can't be tested.
//!
//! ace3 parses with plyara and ace4 with yara-x's own parser. They agree on well-formed rules; on a file
//! neither can make sense of, each finds what it can. A file that isn't UTF-8 has no rules here: yara-x's
//! parser needs text, and ace4's loader leaves such a file out (`crate::load`). Nor has a file past
//! `crate::guard`'s bounds, which the loader leaves out too: yara-x's parser would overflow its stack on it.

use sha2::{Digest, Sha256};
use yara_x_parser::Parser;
use yara_x_parser::ast::MetaValue;
use yara_x_parser::cst::SyntaxKind;

/// One rule as its source declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRule {
    pub name: String,
    /// Its `uuid` meta, trimmed, when it has one that isn't empty.
    pub uuid: Option<String>,
    pub private: bool,
    /// The sha256 of the rule's text: the whole lines it spans.
    pub content_hash: String,
}

/// The rules declared in `source`, in the order they appear.
pub fn rules(source: &[u8]) -> Vec<SourceRule> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    // yara-x's parser overflows its stack past these bounds; the loader leaves such a file out
    if crate::guard::check(source).is_err() {
        return Vec::new();
    }
    let Ok(cst) = Parser::new(source).try_into_cst() else {
        return Vec::new();
    };
    let spans: Vec<std::ops::Range<usize>> = cst
        .root()
        .children()
        .filter(|node| node.kind() == SyntaxKind::RULE_DECL)
        .map(|node| node.span().range())
        .collect();

    let ast = yara_x_parser::ast::AST::from(Parser::new(source));
    let declared: Vec<_> = ast.rules().collect();
    // Both trees come from one parse of the same text, so they list the same rules in the same order.
    if declared.len() != spans.len() {
        return Vec::new();
    }

    declared
        .into_iter()
        .zip(spans)
        .map(|(rule, span)| {
            let uuid = rule.meta.iter().flatten().rev().find_map(|meta| {
                (meta.identifier.name == "uuid").then(|| match &meta.value {
                    MetaValue::String((value, _)) => value.trim().to_owned(),
                    MetaValue::Bytes((value, _)) => {
                        String::from_utf8_lossy(value).trim().to_owned()
                    }
                    MetaValue::Integer((value, _)) => value.to_string(),
                    MetaValue::Float((value, _)) => value.to_string(),
                    MetaValue::Bool((value, _)) => value.to_string(),
                })
            });
            SourceRule {
                name: rule.identifier.name.to_owned(),
                uuid: uuid.filter(|u| !u.is_empty()),
                private: rule.flags.contains(yara_x_parser::ast::RuleFlags::Private),
                content_hash: hex(&Sha256::digest(whole_lines(text, span).as_bytes())),
            }
        })
        .collect()
}

/// The whole lines of `text` that `span` touches, each with its line ending.
fn whole_lines(text: &str, span: std::ops::Range<usize>) -> &str {
    let start = text[..span.start].rfind('\n').map_or(0, |i| i + 1);
    let last = span.end.max(span.start + 1).min(text.len()) - 1;
    let end = text[last..].find('\n').map_or(text.len(), |i| last + i + 1);
    &text[start..end]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_rule_has_its_own_lines_and_hash() {
        let source = b"import \"pe\"\n\nrule one {\n    meta:\n        uuid = \" u-1 \"\n    condition:\n        true\n}\nprivate rule two { condition: false }\nrule three { meta: other = 1 condition: false }\n";
        let found = rules(source);
        assert_eq!(
            found
                .iter()
                .map(|r| (r.name.as_str(), r.uuid.as_deref(), r.private))
                .collect::<Vec<_>>(),
            [
                ("one", Some("u-1"), false),
                ("two", None, true),
                ("three", None, false)
            ]
        );
        let one =
            "rule one {\n    meta:\n        uuid = \" u-1 \"\n    condition:\n        true\n}\n";
        assert_eq!(found[0].content_hash, hex(&Sha256::digest(one.as_bytes())));

        // the same rule moved within its file keeps its hash; a change to it doesn't
        let moved = b"rule three { meta: other = 1 condition: false }\nrule one {\n    meta:\n        uuid = \" u-1 \"\n    condition:\n        true\n}\n";
        assert_eq!(rules(moved)[1].content_hash, found[0].content_hash);
        let changed =
            b"rule one {\n    meta:\n        uuid = \" u-1 \"\n    condition:\n        false\n}\n";
        assert_ne!(rules(changed)[0].content_hash, found[0].content_hash);
    }

    #[test]
    fn a_file_that_does_not_compile_still_has_its_rules() {
        let found = rules(b"rule broken { meta: uuid = \"u-b\" condition: nope }\n");
        assert_eq!(found[0].uuid.as_deref(), Some("u-b"));
        assert!(rules(b"rule caf\xe9 { condition: false }\n").is_empty());
    }
}
