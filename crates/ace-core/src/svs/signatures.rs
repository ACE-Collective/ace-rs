//! What a run's result says about each signature, and the ATT&CK techniques signatures claim (PLAN.md 7.10
//! batch 4): ace3's `saq/svs/signatures.py`.
//!
//! A run's result names each signature with its family and the content hash of the rule itself, from
//! wherever ACE knows the signature: the built-in signatures, the hunts, or the YARA rules. A signature
//! none of them knows (a deleted rule) keeps what the caller already had of it.
//!
//! Signatures claim techniques through their `mitre:` tags: a hunt's tags, and a YARA rule's tags, which
//! include its `mitre_attack` meta.
//!
//! What differs from ace3's: ace3 reads the built-ins and the YARA rules from its signature inventory
//! (`saq/signatures/`), which ace4 doesn't have, so both functions take what's known of each family from
//! their caller. Batch 5's results give [`describe_signatures`] the built-ins and the ruleset's rules, and
//! batch 8's coverage gives [`signature_techniques`] the rules' tags; the hunts are
//! `super::windows`'s. The rules and their order of precedence are ace3's.

use std::collections::{BTreeMap, BTreeSet};

use super::attack::normalize_technique_id;
use super::windows::HuntInfo;

pub const MITRE_TAG_PREFIX: &str = "mitre:";

/// The families a signature is known by: ace3's `SignatureType` values.
pub const FAMILY_BUILTIN: &str = "builtin";
pub const FAMILY_HUNT: &str = "hunt";
pub const FAMILY_YARA: &str = "yara";

/// What ACE currently knows of a signature: ace3's `SignatureInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInfo {
    pub uuid: String,
    pub name: Option<String>,
    pub family: Option<String>,
    /// The rule's own content hash.
    pub content_hash: Option<String>,
}

/// The `mitre:` tags of one signature: ace3's `SignatureTags`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureTags {
    pub uuid: String,
    pub family: String,
    pub name: Option<String>,
    /// Its tags count toward coverage: the signature is enabled, and a YARA rule isn't in QA mode.
    pub counts: bool,
    /// The technique ids its tags name (`T1059.001`), as written but upper-cased, not yet resolved against
    /// the ATT&CK release; sorted.
    pub declared: Vec<String>,
    /// The `mitre:` tags that aren't technique ids: templated ones (`{{ technique }}`), tactics, typos;
    /// sorted.
    pub ignored: Vec<String>,
}

/// A built-in signature or a YARA rule, as its caller knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownSignature {
    pub uuid: String,
    pub name: String,
    pub content_hash: String,
    pub tags: Vec<String>,
    /// Whether its tags count toward coverage: enabled, and not in QA mode.
    pub counts: bool,
}

/// `(declared technique ids, ignored mitre: tags)` of a signature's tags, each sorted: ace3's
/// `_parse_mitre_tags`.
pub fn parse_mitre_tags<'a>(tags: impl IntoIterator<Item = &'a str>) -> (Vec<String>, Vec<String>) {
    let (mut declared, mut ignored) = (BTreeSet::new(), BTreeSet::new());
    for tag in tags {
        if !tag.to_lowercase().starts_with(MITRE_TAG_PREFIX) {
            continue;
        }
        let value: String = tag.chars().skip(MITRE_TAG_PREFIX.len()).collect();
        match normalize_technique_id(&value) {
            Some(technique) => declared.insert(technique),
            None => ignored.insert(tag.to_owned()),
        };
    }
    (
        declared.into_iter().collect(),
        ignored.into_iter().collect(),
    )
}

/// The `mitre:` tags of every hunt and YARA rule that has any, by signature uuid; a uuid both use is the
/// hunt's. ace3's `signature_techniques`.
pub fn signature_techniques(
    hunts: &BTreeMap<String, HuntInfo>,
    yara: &[KnownSignature],
) -> BTreeMap<String, SignatureTags> {
    let mut result = BTreeMap::new();
    for (uuid, hunt) in hunts {
        let (declared, ignored) = parse_mitre_tags(hunt.tags.iter().map(String::as_str));
        if !declared.is_empty() || !ignored.is_empty() {
            result.insert(
                uuid.clone(),
                SignatureTags {
                    uuid: uuid.clone(),
                    family: FAMILY_HUNT.to_owned(),
                    name: Some(hunt.name.clone()),
                    counts: hunt.enabled,
                    declared,
                    ignored,
                },
            );
        }
    }
    for rule in yara {
        if result.contains_key(&rule.uuid) {
            continue;
        }
        let (declared, ignored) = parse_mitre_tags(rule.tags.iter().map(String::as_str));
        if !declared.is_empty() || !ignored.is_empty() {
            result.insert(
                rule.uuid.clone(),
                SignatureTags {
                    uuid: rule.uuid.clone(),
                    family: FAMILY_YARA.to_owned(),
                    name: Some(rule.name.clone()),
                    counts: rule.counts,
                    declared,
                    ignored,
                },
            );
        }
    }
    result
}

/// What ACE currently knows of each of `uuids`; one it doesn't know is left out. A uuid is a built-in's
/// first, then a hunt's, then a YARA rule's. ace3's `describe_signatures`.
pub fn describe_signatures<'a>(
    uuids: impl IntoIterator<Item = &'a str>,
    builtins: &[KnownSignature],
    hunts: &BTreeMap<String, HuntInfo>,
    yara: &[KnownSignature],
) -> BTreeMap<String, SignatureInfo> {
    let info = |uuid: &str, name: &str, family: &str, content_hash: &str| SignatureInfo {
        uuid: uuid.to_owned(),
        name: Some(name.to_owned()),
        family: Some(family.to_owned()),
        content_hash: Some(content_hash.to_owned()),
    };
    let mut result = BTreeMap::new();
    for uuid in uuids.into_iter().collect::<BTreeSet<&str>>() {
        let known = if let Some(s) = builtins.iter().find(|s| s.uuid == uuid) {
            Some(info(uuid, &s.name, FAMILY_BUILTIN, &s.content_hash))
        } else if let Some(hunt) = hunts.get(uuid) {
            Some(info(uuid, &hunt.name, FAMILY_HUNT, &hunt.content_hash))
        } else {
            yara.iter()
                .find(|s| s.uuid == uuid)
                .map(|s| info(uuid, &s.name, FAMILY_YARA, &s.content_hash))
        };
        if let Some(known) = known {
            result.insert(uuid.to_owned(), known);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hunt(uuid: &str, enabled: bool, tags: &[&str]) -> (String, HuntInfo) {
        (
            uuid.to_owned(),
            HuntInfo {
                uuid: uuid.to_owned(),
                name: format!("hunt {uuid}"),
                enabled,
                latency: None,
                suppression: None,
                per_group: false,
                content_hash: format!("hash of hunt {uuid}"),
                tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            },
        )
    }

    fn known(uuid: &str, counts: bool, tags: &[&str]) -> KnownSignature {
        KnownSignature {
            uuid: uuid.to_owned(),
            name: format!("rule {uuid}"),
            content_hash: format!("hash of rule {uuid}"),
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            counts,
        }
    }

    /// A `mitre:` tag that names a technique is declared, upper-cased; one that doesn't (a tactic, a
    /// template, a typo) is ignored and kept as written; any other tag is nothing.
    #[test]
    fn mitre_tags_are_technique_ids_or_ignored() {
        let (declared, ignored) = parse_mitre_tags([
            "mitre:T1059.001",
            "MITRE:t1547",
            "mitre: T1003 ",
            "mitre:T1059.001",
            "phishing",
            "mitre:TA0002",
            "mitre:{{ technique }}",
            "mitre:T105",
            "attack:T1059",
        ]);
        assert_eq!(declared, ["T1003", "T1059.001", "T1547"]);
        assert_eq!(
            ignored,
            ["mitre:T105", "mitre:TA0002", "mitre:{{ technique }}"]
        );
    }

    /// Every hunt and YARA rule with a `mitre:` tag, by uuid: a uuid both use is the hunt's, a signature
    /// with none is left out, and a disabled hunt or a rule in QA mode is there but doesn't count.
    #[test]
    fn signature_techniques_are_the_hunts_then_the_rules() {
        let hunts = BTreeMap::from([
            hunt("h1", true, &["mitre:T1059.001", "phishing"]),
            hunt("h2", false, &["mitre:TA0002"]),
            hunt("h3", true, &["phishing"]),
            hunt("shared", true, &["mitre:T1003"]),
        ]);
        let yara = [
            known("y1", true, &["mitre:T1547"]),
            known("y2", false, &["mitre:T1548"]),
            known("y3", true, &[]),
            known("shared", true, &["mitre:T1105"]),
        ];
        let techniques = signature_techniques(&hunts, &yara);
        assert_eq!(
            techniques.keys().map(String::as_str).collect::<Vec<_>>(),
            ["h1", "h2", "shared", "y1", "y2"]
        );
        let h1 = &techniques["h1"];
        assert_eq!(
            (
                h1.family.as_str(),
                h1.name.as_deref(),
                h1.counts,
                &h1.declared[..]
            ),
            ("hunt", Some("hunt h1"), true, &["T1059.001".to_owned()][..])
        );
        assert_eq!(
            (techniques["h2"].counts, &techniques["h2"].ignored[..]),
            (false, &["mitre:TA0002".to_owned()][..])
        );
        assert_eq!(techniques["shared"].family, "hunt");
        assert_eq!(techniques["shared"].declared, ["T1003"]);
        assert_eq!(
            (techniques["y1"].family.as_str(), techniques["y1"].counts),
            ("yara", true)
        );
        assert!(!techniques["y2"].counts);
    }

    /// A signature is a built-in's first, then a hunt's, then a YARA rule's, and one nothing knows is left
    /// out.
    #[test]
    fn signatures_are_described_from_where_they_are_known() {
        let hunts = BTreeMap::from([hunt("h1", true, &[]), hunt("both", true, &[])]);
        let builtins = [known("b1", true, &[]), known("both", true, &[])];
        let yara = [known("y1", true, &[]), known("h1", true, &[])];
        let described = describe_signatures(
            ["b1", "h1", "y1", "both", "gone", "h1"],
            &builtins,
            &hunts,
            &yara,
        );
        let family = |uuid: &str| described[uuid].family.as_deref();
        assert_eq!(
            described.keys().map(String::as_str).collect::<Vec<_>>(),
            ["b1", "both", "h1", "y1"]
        );
        assert_eq!(
            (family("b1"), family("both"), family("h1"), family("y1")),
            (Some("builtin"), Some("builtin"), Some("hunt"), Some("yara"))
        );
        assert_eq!(
            described["h1"].content_hash.as_deref(),
            Some("hash of hunt h1")
        );
        assert_eq!(described["y1"].name.as_deref(), Some("rule y1"));
        assert!(describe_signatures([], &builtins, &hunts, &yara).is_empty());
    }
}
