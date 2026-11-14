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
//! their caller. A run's result (batch 5) gives [`describe_signatures`] the built-ins, which are ace3's
//! table ([`BUILTINS`]), and the YARA rules of the ruleset the pools scan with
//! (`yara.rulesets.signatures`, which the ruleset builder records); batch 8's coverage gives
//! [`signature_techniques`] the same rules' tags; the hunts are `super::windows`'s. The rules and their
//! order of precedence are ace3's.

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

/// ACE's built-in signatures, the identities of its own detection logic: ace3's `BUILTIN_SIGNATURES`
/// (`saq/signatures/builtin.py`), each its name, uuid and description. A module that raises one names its
/// uuid itself; this table is what a run's result reads to name it.
pub const BUILTINS: &[(&str, &str, &str)] = &[
    (
        "generic",
        "87fe1a4a-0e60-4e3b-b712-da9d3db12fa7",
        "ACE detection with no specific signature",
    ),
    (
        "alertable_tag",
        "14564014-a223-440a-914f-03a1f322e1bf",
        "tag configured as alertable",
    ),
    (
        "correlated_tag_match",
        "6bf55f83-9ec0-4b64-88b4-63b237e010c4",
        "correlated tag match",
    ),
    (
        "observable_flagged_for_detection",
        "97a0bcb8-1bde-4cf0-8fa2-72d6343c6458",
        "observable flagged for detection",
    ),
    (
        "archive_single_dangerous_file",
        "de4bfc85-d827-4e60-a7e3-211b60ad61c8",
        "archive holds a single exe/script/shortcut/JNLP/OneNote",
    ),
    (
        "rtf_extracted_suspect_file",
        "cb9764d5-049b-4b7e-bf40-cf7e9c618058",
        "RTF-extracted file suspect ext/mime/type",
    ),
    (
        "ole_extracted_suspect_file",
        "827c5aab-9fa2-45d9-8c5e-a13cd1be9812",
        "OLE attachment suspect type/ext/javascript",
    ),
    (
        "vbs_hex_encoded_content",
        "e46a6485-7ccd-4cba-8196-7540c5e7a1b9",
        "VBS large hex strings / high hex %",
    ),
    (
        "office_external_oleobject",
        "6ee4fb89-87d9-4cf0-85ec-52f7760b9a1d",
        "Office links external OLE object",
    ),
    (
        "xlm_macro_url",
        "3e719b5d-8063-4cd7-a72b-3d1cc8ead39c",
        "URL inside an Excel 4.0 macro",
    ),
    (
        "email_encrypted_attachment_decrypted",
        "ef715326-081e-4ece-97ba-02817b5a28cd",
        "decrypted email attachment (office/rar/zip)",
    ),
    (
        "email_macro_new_sender",
        "26fb96a4-6e20-48df-b826-a9c4a25b1965",
        "macro from a new sender",
    ),
    (
        "email_suspect_url_new_sender",
        "11b42a94-e21a-4cd0-bdb6-8f278d20611d",
        "suspect URL from a new sender",
    ),
    (
        "cve_2021_30657_dmg_script",
        "3ba358a3-b7ab-4475-a10a-f2a8070b455d",
        "CVE-2021-30657 DMG script",
    ),
    (
        "url_clicker",
        "a764126b-443d-4991-a554-72d86125382d",
        "user clicked a URL / visited a flagged domain (clicker detection)",
    ),
    (
        "dhash_image_match",
        "10d1e320-3b07-45f1-9bcf-078044643b7e",
        "image dhash match",
    ),
    (
        "svs_registration_refused",
        super::REGISTRATION_REFUSED_SIGNATURE,
        "SVS test run registered against a host that is not a test host",
    ),
    (
        "svs_marker_mismatch",
        super::MARKER_MISMATCH_SIGNATURE,
        "SVS test run marker that does not match its run",
    ),
    (
        "yara_rule_match",
        "3557435e-da7f-4b1b-a5dd-655107839530",
        "YARA rule match with no uuid meta",
    ),
    (
        "legacy",
        "3c649355-160e-405c-ad91-6916ab539849",
        "detection point predating signature attribution",
    ),
];

/// The built-ins as [`describe_signatures`] takes them, each with ace3's content hash of a built-in: the
/// sha256 of its name, uuid and description, one a line (`saq/signatures/loaders/builtin.py`).
pub fn builtin_signatures() -> Vec<KnownSignature> {
    use sha2::{Digest, Sha256};
    BUILTINS
        .iter()
        .map(|(name, uuid, description)| KnownSignature {
            uuid: (*uuid).to_owned(),
            name: (*name).to_owned(),
            content_hash: hex::encode(Sha256::digest(
                format!("{name}\n{uuid}\n{description}").as_bytes(),
            )),
            tags: Vec::new(),
            counts: true,
        })
        .collect()
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

    /// The built-ins are ace3's twenty, each uuid once, with ace3's hash of a built-in.
    #[test]
    fn the_built_ins_are_ace3_s() {
        let builtins = builtin_signatures();
        assert_eq!(builtins.len(), 20);
        let uuids: BTreeSet<&str> = builtins.iter().map(|s| s.uuid.as_str()).collect();
        assert_eq!(uuids.len(), 20);
        let generic = builtins
            .iter()
            .find(|s| s.name == "generic")
            .expect("generic");
        // sha256("generic\n87fe1a4a-0e60-4e3b-b712-da9d3db12fa7\nACE detection with no specific signature")
        assert_eq!(generic.uuid, crate::svs::results::GENERIC_SIGNATURE);
        assert_eq!(
            generic.content_hash,
            "eaf82dc1ba6749316046f3167f39865ccba488586cf85370ccca031848c8664c"
        );
        for uuid in crate::svs::results::untracked_signatures() {
            assert!(uuids.contains(uuid.as_str()), "{uuid} is a built-in");
        }
        let described =
            describe_signatures([generic.uuid.as_str()], &builtins, &BTreeMap::new(), &[]);
        assert_eq!(
            described[&generic.uuid].family.as_deref(),
            Some(FAMILY_BUILTIN)
        );
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
