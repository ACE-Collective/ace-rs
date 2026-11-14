//! Building the ATT&CK extract SVS reads: ace3's `bin/update-attack-catalog`.
//!
//! A developer runs `ace svs attack extract` when ACE adds support for a release and commits the file it
//! writes, `crates/ace-core/data/attack/<release>.json`, with its line in `VENDORED`. It reads the release's
//! enterprise STIX bundle (2.0 or 2.1) from MITRE's attack-stix-data repository and keeps only what SVS
//! uses: technique ids and names, sub-technique to parent, tactics, platforms, deprecated techniques and the
//! revoked ones with their successors. With an earlier extract it also lists the techniques whose name
//! changed since, which is informational: a rename keeps the technique's id, so nothing is remapped.
//!
//! What differs from ace3's: its script downloads the bundle unless given `--input`; this one only reads a
//! file, so no part of ACE fetches ATT&CK, and the developer downloads [`source_url`] first.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// The version of the extract's layout (`super::FORMAT` refuses any other).
pub const FORMAT: u64 = super::FORMAT;

const DOMAIN: &str = "enterprise-attack";
const KILL_CHAIN: &str = "mitre-attack";

/// The platform slugs SVS uses, in display order, with the name ATT&CK gives each today.
pub const PLATFORMS: &[(&str, &str)] = &[
    ("windows", "Windows"),
    ("linux", "Linux"),
    ("macos", "macOS"),
    ("esxi", "ESXi"),
    ("iaas", "IaaS"),
    ("containers", "Containers"),
    ("saas", "SaaS"),
    ("office-suite", "Office Suite"),
    ("identity-provider", "Identity Provider"),
    ("network-devices", "Network Devices"),
    ("pre", "PRE"),
];

/// Every other platform name a release has used, to its slug. A name in neither table stops the build: a
/// new platform has to be given a slug, never dropped.
const OLD_PLATFORM_NAMES: &[(&str, &str)] = &[
    ("Office 365", "office-suite"),
    ("Google Workspace", "office-suite"),
    ("Azure AD", "identity-provider"),
    ("Network", "network-devices"),
    ("AWS", "iaas"),
    ("GCP", "iaas"),
    ("Azure", "iaas"),
];

/// What a build made: the extract, and what it warned about.
#[derive(Debug, Clone, PartialEq)]
pub struct Built {
    pub extract: Value,
    pub warnings: Vec<String>,
}

/// The release as the extract names it (`v20.0`), from `v20.0`, `20.0`, `v20` or `20`.
pub fn parse_release(value: &str) -> Result<String, String> {
    let bad = || format!("{value:?} is not an ATT&CK release (for example v20.0)");
    let text = value.trim();
    let text = text.strip_prefix('v').unwrap_or(text);
    let (major, minor) = text.split_once('.').unwrap_or((text, "0"));
    let number = |part: &str| -> Option<u64> {
        (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse().ok())
            .flatten()
    };
    match (number(major), number(minor)) {
        (Some(major), Some(minor)) => Ok(format!("v{major}.{minor}")),
        _ => Err(bad()),
    }
}

/// Where MITRE publishes the enterprise bundle of `release` (as `parse_release` gives it).
pub fn source_url(release: &str) -> String {
    format!(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/\
         enterprise-attack-{}.json",
        release.strip_prefix('v').unwrap_or(release)
    )
}

fn text<'a>(object: &'a Value, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

/// Python's truth of a JSON value.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

fn list<'a>(object: &'a Value, key: &str) -> &'a [Value] {
    object
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn external_id(object: &Value) -> Option<&str> {
    list(object, "external_references")
        .iter()
        .find(|reference| {
            text(reference, "source_name") == Some("mitre-attack")
                && text(reference, "external_id").is_some_and(|id| !id.is_empty())
        })
        .and_then(|reference| text(reference, "external_id"))
}

fn is_technique_id(id: &str) -> bool {
    super::normalize_technique_id(id).as_deref() == Some(id)
}

fn platform_slugs(technique_id: &str, names: &[Value]) -> Result<Vec<&'static str>, String> {
    let mut slugs = BTreeSet::new();
    for name in names {
        let name = name.as_str().unwrap_or_default();
        let slug = PLATFORMS
            .iter()
            .find(|(_, current)| *current == name)
            .map(|(slug, _)| *slug)
            .or_else(|| {
                OLD_PLATFORM_NAMES
                    .iter()
                    .find(|(old, _)| *old == name)
                    .map(|(_, slug)| *slug)
            })
            .ok_or_else(|| {
                format!(
                    "{technique_id} names platform {name:?}, which has no slug; add it to PLATFORMS or \
                     OLD_PLATFORM_NAMES"
                )
            })?;
        slugs.insert(slug);
    }
    Ok(PLATFORMS
        .iter()
        .map(|(slug, _)| *slug)
        .filter(|slug| slugs.contains(slug))
        .collect())
}

fn check_release(
    objects: &[Value],
    release: &str,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    for object in objects {
        if text(object, "type") == Some("x-mitre-collection")
            && let Some(version) = text(object, "x_mitre_version").filter(|v| !v.is_empty())
        {
            if format!("v{version}") != release {
                return Err(format!(
                    "the bundle is ATT&CK {} {version}, not {release}",
                    text(object, "name").unwrap_or("None")
                ));
            }
            return Ok(());
        }
    }
    warnings.push(format!(
        "the bundle doesn't say which release it is; trusting that it is {release}"
    ));
    Ok(())
}

struct TacticRow {
    id: String,
    shortname: String,
    name: String,
}

/// The tactics in the matrix's order.
fn tactics(objects: &[Value]) -> Result<Vec<TacticRow>, String> {
    let mut by_stix_id: BTreeMap<&str, TacticRow> = BTreeMap::new();
    for object in objects {
        if text(object, "type") != Some("x-mitre-tactic")
            || truthy(object.get("revoked"))
            || truthy(object.get("x_mitre_deprecated"))
        {
            continue;
        }
        let name = text(object, "name").unwrap_or_default();
        let id = external_id(object).ok_or_else(|| format!("tactic {name:?} has no ATT&CK id"))?;
        let (Some(stix_id), Some(shortname)) =
            (text(object, "id"), text(object, "x_mitre_shortname"))
        else {
            return Err(format!("tactic {name:?} has no id or shortname"));
        };
        by_stix_id.insert(
            stix_id,
            TacticRow {
                id: id.to_owned(),
                shortname: shortname.to_owned(),
                name: name.to_owned(),
            },
        );
    }
    let mut order: Vec<&str> = Vec::new();
    for object in objects {
        if text(object, "type") == Some("x-mitre-matrix") && !truthy(object.get("revoked")) {
            for reference in list(object, "tactic_refs").iter().filter_map(Value::as_str) {
                if by_stix_id.contains_key(reference) && !order.contains(&reference) {
                    order.push(reference);
                }
            }
        }
    }
    // a tactic no matrix lists still counts, after the ones it does
    let mut unlisted: Vec<&str> = by_stix_id
        .keys()
        .copied()
        .filter(|reference| !order.contains(reference))
        .collect();
    unlisted.sort_by(|a, b| by_stix_id[a].id.cmp(&by_stix_id[b].id));
    order.extend(unlisted);
    Ok(order
        .into_iter()
        .filter_map(|reference| by_stix_id.remove(reference))
        .collect())
}

/// The current technique a revoked one ends up at, following revocations of revocations.
fn successor(
    technique_id: &str,
    stix_id: &str,
    revoked_by: &BTreeMap<&str, &str>,
    stix_to_id: &BTreeMap<&str, &str>,
    techniques: &BTreeMap<String, Value>,
    warnings: &mut Vec<String>,
) -> Result<Option<String>, String> {
    let mut seen = vec![technique_id.to_owned()];
    let mut current = stix_id;
    loop {
        let last = seen.last().cloned().unwrap_or_default();
        let Some(target) = revoked_by.get(current) else {
            warnings.push(format!(
                "{last} is revoked without a successor; {technique_id} is left out of the revoked map"
            ));
            return Ok(None);
        };
        let Some(target_id) = stix_to_id.get(target) else {
            warnings.push(format!(
                "{last} is revoked by {target}, which is not a technique in the bundle; {technique_id} \
                 is left out of the revoked map"
            ));
            return Ok(None);
        };
        if seen.iter().any(|id| id == target_id) {
            seen.push((*target_id).to_owned());
            return Err(format!("revocations form a cycle: {}", seen.join(" -> ")));
        }
        if techniques.contains_key(*target_id) {
            return Ok(Some((*target_id).to_owned()));
        }
        seen.push((*target_id).to_owned());
        current = target;
    }
}

/// The extract of one enterprise STIX bundle: ace3's `build`. `release` is `parse_release`'s, `source` what
/// the extract records as where the bundle came from, and `previous` an earlier extract, to list renames.
pub fn build(
    bundle: &[u8],
    release: &str,
    source: &str,
    previous: Option<&Value>,
) -> Result<Built, String> {
    let parsed: Value =
        serde_json::from_slice(bundle).map_err(|e| format!("not a STIX bundle: {e}"))?;
    let objects = parsed
        .get("objects")
        .and_then(Value::as_array)
        .ok_or("not a STIX bundle: it has no objects")?;
    let mut warnings = Vec::new();

    check_release(objects, release, &mut warnings)?;
    let tactics = tactics(objects)?;
    let tactic_ids: BTreeMap<&str, &str> = tactics
        .iter()
        .map(|t| (t.shortname.as_str(), t.id.as_str()))
        .collect();
    let tactic_order: BTreeMap<&str, usize> = tactics
        .iter()
        .enumerate()
        .map(|(index, t)| (t.id.as_str(), index))
        .collect();

    let patterns: Vec<&Value> = objects
        .iter()
        .filter(|object| {
            text(object, "type") == Some("attack-pattern")
                && match object.get("x_mitre_domains") {
                    None => true,
                    Some(domains) => domains
                        .as_array()
                        .is_some_and(|d| d.iter().any(|v| v.as_str() == Some(DOMAIN))),
                }
        })
        .collect();
    let mut stix_to_id: BTreeMap<&str, &str> = BTreeMap::new();
    for object in &patterns {
        let stix_id = text(object, "id").unwrap_or_default();
        match external_id(object).filter(|id| is_technique_id(id)) {
            Some(technique_id) => {
                stix_to_id.insert(stix_id, technique_id);
            }
            None => warnings.push(format!(
                "skipped attack-pattern {stix_id} ({:?}): no technique id",
                text(object, "name").unwrap_or("None")
            )),
        }
    }

    let mut parent_refs: BTreeMap<&str, &str> = BTreeMap::new();
    let mut revoked_by: BTreeMap<&str, &str> = BTreeMap::new();
    for object in objects {
        if text(object, "type") != Some("relationship") || truthy(object.get("revoked")) {
            continue;
        }
        let (Some(from), Some(to)) = (text(object, "source_ref"), text(object, "target_ref"))
        else {
            continue;
        };
        match text(object, "relationship_type") {
            Some("subtechnique-of") => {
                parent_refs.insert(from, to);
            }
            Some("revoked-by") => {
                revoked_by.insert(from, to);
            }
            _ => {}
        }
    }

    let mut techniques: BTreeMap<String, Value> = BTreeMap::new();
    let mut revoked_refs: BTreeMap<&str, &str> = BTreeMap::new();
    for object in &patterns {
        let stix_id = text(object, "id").unwrap_or_default();
        let Some(technique_id) = stix_to_id.get(stix_id).copied() else {
            continue;
        };
        if truthy(object.get("revoked")) {
            revoked_refs.insert(technique_id, stix_id);
            continue;
        }
        if techniques.contains_key(technique_id) {
            return Err(format!("{technique_id} appears twice in the bundle"));
        }
        let mut phases: Vec<&str> = Vec::new();
        for phase in list(object, "kill_chain_phases") {
            if text(phase, "kill_chain_name") != Some(KILL_CHAIN) {
                continue;
            }
            let name = text(phase, "phase_name").unwrap_or_default();
            let id = tactic_ids.get(name).ok_or_else(|| {
                format!("{technique_id} names tactic {name:?}, which the bundle doesn't have")
            })?;
            if !phases.contains(id) {
                phases.push(id);
            }
        }
        phases.sort_by_key(|id| tactic_order[id]);
        let parent = parent_refs
            .get(stix_id)
            .and_then(|parent| stix_to_id.get(parent))
            .copied()
            // a sub-technique the bundle doesn't relate to its parent: the id says which it is
            .or_else(|| super::syntactic_parent(technique_id));
        techniques.insert(
            technique_id.to_owned(),
            json!({
                "name": text(object, "name").ok_or_else(|| format!("{technique_id} has no name"))?,
                "parent": parent,
                "tactics": phases,
                "platforms": platform_slugs(technique_id, list(object, "x_mitre_platforms"))?,
                "deprecated": truthy(object.get("x_mitre_deprecated")),
            }),
        );
    }

    for (technique_id, technique) in &techniques {
        if let Some(parent) = text(technique, "parent")
            && !techniques.contains_key(parent)
        {
            warnings.push(format!(
                "{technique_id}'s parent {parent} is not in the bundle"
            ));
        }
    }

    let mut revoked = Map::new();
    for (technique_id, stix_id) in &revoked_refs {
        if techniques.contains_key(*technique_id) {
            warnings.push(format!(
                "{technique_id} is both revoked and current; the current technique wins"
            ));
            continue;
        }
        if let Some(successor) = successor(
            technique_id,
            stix_id,
            &revoked_by,
            &stix_to_id,
            &techniques,
            &mut warnings,
        )? {
            revoked.insert((*technique_id).to_owned(), Value::String(successor));
        }
    }

    let mut renamed = Map::new();
    if let Some(previous) = previous {
        let before = previous
            .get("techniques")
            .and_then(Value::as_object)
            .ok_or("the previous extract has no techniques")?;
        let previous_release =
            text(previous, "release").ok_or("the previous extract has no release")?;
        for (technique_id, technique) in &techniques {
            if let Some(was) = before.get(technique_id).and_then(|t| text(t, "name"))
                && Some(was) != text(technique, "name")
            {
                renamed.insert(
                    technique_id.clone(),
                    json!({"from": was, "previous_release": previous_release}),
                );
            }
        }
    }

    let used: BTreeSet<&str> = techniques
        .values()
        .flat_map(|t| list(t, "platforms").iter().filter_map(Value::as_str))
        .collect();
    let extract = json!({
        "format": FORMAT,
        "release": release,
        "domain": DOMAIN,
        "source": {"url": source, "sha256": hex::encode(Sha256::digest(bundle))},
        "platforms": PLATFORMS
            .iter()
            .filter(|(slug, _)| used.contains(slug))
            .map(|(slug, name)| json!({"slug": slug, "name": name}))
            .collect::<Vec<_>>(),
        "tactics": tactics
            .iter()
            .map(|t| json!({"id": t.id, "shortname": t.shortname, "name": t.name}))
            .collect::<Vec<_>>(),
        "techniques": techniques,
        "revoked": revoked,
        "renamed": renamed,
    });
    Ok(Built { extract, warnings })
}

fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.clone(), sorted(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// The extract's file: ace3's `json.dumps(extract, indent=1, sort_keys=True, ensure_ascii=False)` and a
/// line break, so a release's file is the same whichever of the two built it.
pub fn render(extract: &Value) -> String {
    use serde::Serialize;
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, formatter);
    sorted(extract)
        .serialize(&mut serializer)
        .expect("a JSON value serializes");
    let mut text = String::from_utf8(out).expect("serde_json writes UTF-8");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(stix: &str, id: &str, name: &str, extra: Value) -> Value {
        let mut object = json!({
            "type": "attack-pattern", "id": stix, "name": name,
            "external_references": [{"source_name": "mitre-attack", "external_id": id}],
            "x_mitre_domains": ["enterprise-attack"],
            "x_mitre_platforms": ["Windows"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        });
        for (key, value) in extra.as_object().expect("an object") {
            object[key] = value.clone();
        }
        object
    }

    fn tactic(stix: &str, id: &str, shortname: &str, name: &str) -> Value {
        json!({"type": "x-mitre-tactic", "id": stix, "name": name, "x_mitre_shortname": shortname,
               "external_references": [{"source_name": "mitre-attack", "external_id": id}]})
    }

    fn relationship(kind: &str, from: &str, to: &str) -> Value {
        json!({"type": "relationship", "relationship_type": kind, "source_ref": from, "target_ref": to})
    }

    fn bundle(extra: Vec<Value>) -> Vec<u8> {
        let mut objects = vec![
            json!({"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "99.0"}),
            tactic("tactic--exec", "TA0002", "execution", "Execution"),
            tactic("tactic--pers", "TA0003", "persistence", "Persistence"),
            tactic("tactic--old", "TA0099", "old", "Old"),
            json!({"type": "x-mitre-matrix", "tactic_refs": ["tactic--pers", "tactic--exec"]}),
            pattern(
                "ap--1059",
                "T1059",
                "Command and Scripting Interpreter",
                json!({"x_mitre_platforms": ["macOS", "Windows", "Azure AD"]}),
            ),
            pattern("ap--1059-001", "T1059.001", "PowerShell", json!({})),
            // no relationship to its parent: the id names it
            pattern(
                "ap--1059-002",
                "T1059.002",
                "AppleScript",
                json!({"x_mitre_platforms": ["macOS"]}),
            ),
            pattern(
                "ap--1547",
                "T1547",
                "Autostart",
                json!({"kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                {"kill_chain_name": "other", "phase_name": "nothing"},
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"}]}),
            ),
            pattern(
                "ap--1099",
                "T1099",
                "Old Technique",
                json!({"x_mitre_deprecated": true}),
            ),
            // revoked twice over: T1086 became T1064, which became T1059.001
            pattern(
                "ap--1086",
                "T1086",
                "PowerShell (old)",
                json!({"revoked": true}),
            ),
            pattern("ap--1064", "T1064", "Scripting", json!({"revoked": true})),
            // revoked with no successor: left out, with a warning
            pattern("ap--1200", "T1200", "Gone", json!({"revoked": true})),
            // another domain's, and one with no technique id
            pattern(
                "ap--mobile",
                "T1400",
                "Mobile",
                json!({"x_mitre_domains": ["mobile-attack"]}),
            ),
            pattern("ap--none", "CAPEC-1", "Not ATT&CK", json!({})),
            relationship("subtechnique-of", "ap--1059-001", "ap--1059"),
            relationship("revoked-by", "ap--1086", "ap--1064"),
            relationship("revoked-by", "ap--1064", "ap--1059-001"),
        ];
        objects.extend(extra);
        json!({"type": "bundle", "objects": objects})
            .to_string()
            .into_bytes()
    }

    /// The builder keeps what SVS uses, in ace3's layout: tactics in the matrix's order with an unlisted one
    /// last, platforms in display order under their slugs, parents from the relationship or the id,
    /// deprecated techniques kept, revocations followed to a current technique, and renames against an
    /// earlier extract. What it reads is what `AttackCatalog::load` takes.
    #[test]
    fn an_extract_is_built_from_a_bundle() {
        let previous = json!({"release": "v98.0", "techniques": {
            "T1059": {"name": "Scripting"}, "T1547": {"name": "Autostart"}}});
        let bytes = bundle(vec![]);
        let built = build(&bytes, "v99.0", "test", Some(&previous)).expect("builds");
        let extract = &built.extract;
        assert_eq!(extract["format"], 1);
        assert_eq!(extract["release"], "v99.0");
        assert_eq!(extract["domain"], "enterprise-attack");
        assert_eq!(
            extract["source"],
            json!({"url": "test", "sha256": hex::encode(Sha256::digest(&bytes))})
        );
        assert_eq!(
            extract["platforms"],
            json!([{"slug": "windows", "name": "Windows"}, {"slug": "macos", "name": "macOS"},
                   {"slug": "identity-provider", "name": "Identity Provider"}])
        );
        let ids: Vec<&str> = extract["tactics"]
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(|t| t["id"].as_str())
            .collect();
        assert_eq!(ids, ["TA0003", "TA0002", "TA0099"]);
        assert_eq!(
            extract["techniques"]["T1059"],
            json!({"name": "Command and Scripting Interpreter", "parent": null, "tactics": ["TA0002"],
                   "platforms": ["windows", "macos", "identity-provider"], "deprecated": false})
        );
        assert_eq!(extract["techniques"]["T1059.001"]["parent"], "T1059");
        assert_eq!(extract["techniques"]["T1059.002"]["parent"], "T1059");
        assert_eq!(
            extract["techniques"]["T1547"]["tactics"],
            json!(["TA0003", "TA0002"])
        );
        assert_eq!(extract["techniques"]["T1099"]["deprecated"], true);
        assert!(extract["techniques"].get("T1400").is_none());
        assert_eq!(
            extract["revoked"],
            json!({"T1086": "T1059.001", "T1064": "T1059.001"})
        );
        assert_eq!(
            extract["renamed"],
            json!({"T1059": {"from": "Scripting", "previous_release": "v98.0"}})
        );
        assert!(
            built
                .warnings
                .iter()
                .any(|w| w.contains("T1200 is revoked without a successor")),
            "{:?}",
            built.warnings
        );
        assert!(
            built
                .warnings
                .iter()
                .any(|w| w.contains("skipped attack-pattern ap--none")),
            "{:?}",
            built.warnings
        );

        let rendered = render(extract);
        let catalog = super::super::AttackCatalog::load(&rendered, "v99.0.json").expect("loads");
        assert_eq!(catalog.children_of("T1059"), ["T1059.001", "T1059.002"]);
        assert_eq!(
            catalog
                .resolve("T1086")
                .expect("an id")
                .revoked_from
                .as_deref(),
            Some("T1086")
        );
        // ace3's file layout: one space of indent, keys sorted, a final line break
        assert!(
            rendered.starts_with("{\n \"domain\": \"enterprise-attack\",\n \"format\": 1,\n"),
            "{rendered}"
        );
        assert!(rendered.ends_with("}\n"));
    }

    /// What stops a build: a bundle of another release, a platform with no slug, a tactic the bundle
    /// doesn't have, a technique twice, a revocation cycle, and something that isn't a bundle.
    #[test]
    fn a_build_refuses_what_it_cannot_place() {
        let fails = |extra: Vec<Value>, release: &str| {
            build(&bundle(extra), release, "test", None).expect_err("refused")
        };
        assert!(
            fails(vec![], "v98.0")
                .contains("the bundle is ATT&CK Enterprise ATT&CK 99.0, not v98.0")
        );
        let error = fails(
            vec![pattern(
                "ap--x",
                "T1700",
                "X",
                json!({"x_mitre_platforms": ["Mainframe"]}),
            )],
            "v99.0",
        );
        assert!(
            error.contains("T1700 names platform \"Mainframe\", which has no slug"),
            "{error}"
        );
        let error = fails(
            vec![pattern(
                "ap--x",
                "T1700",
                "X",
                json!({"kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "stealth"}]}),
            )],
            "v99.0",
        );
        assert!(error.contains("T1700 names tactic \"stealth\""), "{error}");
        let error = fails(
            vec![pattern("ap--again", "T1547", "Again", json!({}))],
            "v99.0",
        );
        assert!(error.contains("T1547 appears twice"), "{error}");
        let error = fails(
            vec![
                pattern("ap--a", "T1701", "A", json!({"revoked": true})),
                pattern("ap--b", "T1702", "B", json!({"revoked": true})),
                relationship("revoked-by", "ap--a", "ap--b"),
                relationship("revoked-by", "ap--b", "ap--a"),
            ],
            "v99.0",
        );
        assert!(
            error.contains("revocations form a cycle: T1701 -> T1702 -> T1701"),
            "{error}"
        );
        assert!(
            build(b"[1]", "v99.0", "test", None)
                .expect_err("no objects")
                .contains("not a STIX bundle")
        );
        // a bundle that doesn't say its release is trusted, with a warning
        let unnamed =
            json!({"objects": [tactic("tactic--exec", "TA0002", "execution", "Execution")]});
        let built = build(unnamed.to_string().as_bytes(), "v99.0", "test", None).expect("builds");
        assert!(built.warnings[0].contains("doesn't say which release it is"));
    }

    #[test]
    fn releases_are_named_one_way() {
        for (given, named) in [
            ("v20.0", "v20.0"),
            ("20.0", "v20.0"),
            ("v20", "v20.0"),
            (" 20 ", "v20.0"),
            ("v020.01", "v20.1"),
        ] {
            assert_eq!(parse_release(given).as_deref(), Ok(named), "{given:?}");
        }
        for bad in ["", "v", "twenty", "v20.0.1", "v20.x", "../v20.0"] {
            assert!(parse_release(bad).is_err(), "{bad:?}");
        }
        assert!(source_url("v20.0").ends_with("/enterprise-attack/enterprise-attack-20.0.json"));
    }

    /// A trial against MITRE's own bundle, for whoever vendors a release: `ACE4_ATTACK_BUNDLE` is the
    /// enterprise STIX bundle, `ACE4_ATTACK_RELEASE` its release, and `ACE4_ATTACK_EXPECTED` the extract
    /// ace3's `bin/update-attack-catalog` wrote from the same file. The two builders give the same bytes.
    #[test]
    #[ignore = "needs ACE4_ATTACK_BUNDLE, ACE4_ATTACK_RELEASE and ACE4_ATTACK_EXPECTED"]
    fn a_real_bundle_builds_as_ace3_s_script_does() {
        let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name}"));
        let bundle = std::fs::read(env("ACE4_ATTACK_BUNDLE")).expect("reads the bundle");
        let expected = std::fs::read_to_string(env("ACE4_ATTACK_EXPECTED")).expect("reads ace3's");
        let release = parse_release(&env("ACE4_ATTACK_RELEASE")).expect("a release");
        let started = std::time::Instant::now();
        let built = build(&bundle, &release, &source_url(&release), None).expect("builds");
        println!(
            "{} bytes of bundle in {:?}: {} techniques, {} tactics, {} revoked, {} warnings",
            bundle.len(),
            started.elapsed(),
            built.extract["techniques"]
                .as_object()
                .map_or(0, |o| o.len()),
            built.extract["tactics"].as_array().map_or(0, Vec::len),
            built.extract["revoked"].as_object().map_or(0, |o| o.len()),
            built.warnings.len()
        );
        for warning in &built.warnings {
            println!("warning: {warning}");
        }
        assert!(
            render(&built.extract) == expected,
            "the extract differs from ace3's"
        );
    }

    /// The vendored extract is in the layout `render` writes: reading it and writing it again gives the
    /// same bytes, so a release rebuilt here differs from ace3's file only where the bundle does.
    #[test]
    fn the_vendored_extract_is_in_the_rendered_layout() {
        for (name, text) in super::super::VENDORED {
            let value: Value = serde_json::from_str(text).expect("JSON");
            assert!(render(&value) == *text, "{name} isn't as render writes it");
        }
    }
}
