//! The ATT&CK release SVS coverage is computed against (PLAN.md 7.10 batch 4): ace3's `saq/svs/attack.py`
//! and `attack_files.py`, and the extract builder of its `bin/update-attack-catalog` ([`extract`]).
//!
//! ACE never fetches ATT&CK. Each supported release is a compact extract built into the binary from
//! `crates/ace-core/data/attack/<release>.json`, and the overlay's `svs.attack_release` names the one in
//! use. It gives the names of techniques and tactics, each sub-technique's parent, each technique's tactics
//! and platforms, and where a revoked technique went. The directory's `NOTICE` carries MITRE's terms.
//!
//! Technique ids from anywhere else (an atomic's `attack_technique`, a signature's `mitre:` tag) go through
//! [`AttackCatalog::resolve`]: a revoked id becomes its successor, and an id the release doesn't have is kept
//! as it is, as unknown.
//!
//! What differs from ace3's: ace3 reads the extract from `etc/attack/` beside its code when its config
//! loads; here the extracts are compiled in, so a release is vendored by adding its file and its line in
//! [`VENDORED`]. The overlay checks the release's name (`ace_sdk::is_attack_release_name`), and `ace serve`
//! refuses one that isn't vendored when it starts ([`vendored`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock, Mutex};

use regex::Regex;
use serde::{Deserialize, Serialize};

pub mod extract;

/// The layout of the extract this module reads (`extract::FORMAT` writes it).
pub const FORMAT: u64 = 1;

/// The release `svs.attack_release` names by default: ace3's.
pub const DEFAULT_RELEASE: &str = "v20.0";

/// The releases built into this binary, each with its extract's text.
pub const VENDORED: &[(&str, &str)] = &[("v20.0", include_str!("../../data/attack/v20.0.json"))];

// Python's `\d` is any Unicode decimal digit, and so is this one.
static TECHNIQUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^T\d{4}(\.\d{3})?$").expect("a valid pattern"));

/// Atomic Red Team's platform names that ATT&CK calls something else; any `iaas:<provider>` is `iaas`.
const ART_PLATFORM_ALIASES: &[(&str, &str)] = &[
    ("azure-ad", "identity-provider"),
    ("office-365", "office-suite"),
    ("google-workspace", "office-suite"),
];

/// Python's `str.strip()`: its whitespace is Unicode's and the four separators U+001C to U+001F.
fn strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// The extract of `release`: ace3's `release_path`, and its config's check that the file is there. The error
/// is ace3's, for a name that isn't a release's and for a release this binary doesn't have.
pub fn vendored(release: &str) -> Result<&'static str, String> {
    if !ace_sdk::is_attack_release_name(release) {
        return Err(format!(
            "{release:?} is not an ATT&CK release name (for example v20.0)"
        ));
    }
    VENDORED
        .iter()
        .find(|(name, _)| *name == release)
        .map(|(_, text)| *text)
        .ok_or_else(|| {
            format!(
                "svs.attack_release {release}: this build has no extract of it ({}); \
                 `ace svs attack extract {release}` builds one to vendor",
                VENDORED
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

/// Whether a technique of the release still counts: ace3's `TechniqueStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechniqueStatus {
    Active,
    Deprecated,
    /// Not in the release: a custom atomic's technique, a typo, or a release newer than the one pinned.
    Unknown,
}

impl TechniqueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TechniqueStatus::Active => "active",
            TechniqueStatus::Deprecated => "deprecated",
            TechniqueStatus::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tactic {
    /// `TA0002`.
    pub id: String,
    /// `execution`.
    pub shortname: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub parent: Option<String>,
    /// Its tactics' ids, in the matrix's order.
    pub tactics: Vec<String>,
    /// Its platforms' slugs, in display order.
    pub platforms: Vec<String>,
    pub deprecated: bool,
}

impl Technique {
    pub fn status(&self) -> TechniqueStatus {
        if self.deprecated {
            TechniqueStatus::Deprecated
        } else {
            TechniqueStatus::Active
        }
    }
}

/// What a technique id means in the release: the technique it counts as, and whether it was revoked to get
/// there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub technique: String,
    pub status: TechniqueStatus,
    pub revoked_from: Option<String>,
}

/// A technique's earlier name, from an extract built with `--previous`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Renamed {
    pub from: String,
    pub previous_release: String,
}

/// `T1059.001` from `t1059.001` or ` T1059.001 `; None for anything that isn't a technique id (a tactic, a
/// template, free text).
pub fn normalize_technique_id(value: &str) -> Option<String> {
    let value = strip(value).to_uppercase();
    TECHNIQUE.is_match(&value).then_some(value)
}

/// The parent a sub-technique id names (`T1059` for `T1059.001`), whatever the release says.
pub fn syntactic_parent(technique_id: &str) -> Option<&str> {
    technique_id.split_once('.').map(|(parent, _)| parent)
}

/// The platform slug for one of a test's `supported_platforms` (Atomic Red Team's names).
pub fn normalize_platform(name: &str) -> String {
    let name = strip(name).to_lowercase();
    if name.starts_with("iaas:") {
        return "iaas".to_owned();
    }
    ART_PLATFORM_ALIASES
        .iter()
        .find(|(art, _)| *art == name)
        .map_or(name, |(_, slug)| (*slug).to_owned())
}

/// One release's extract: ace3's `AttackCatalog`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackCatalog {
    pub release: String,
    /// Each platform's slug and ATT&CK's name for it, in display order.
    pub platforms: Vec<(String, String)>,
    /// The tactics in the matrix's order.
    pub tactics: Vec<Tactic>,
    pub techniques: BTreeMap<String, Technique>,
    /// A revoked technique's id and the technique of the release it became.
    pub revoked: BTreeMap<String, String>,
    pub renamed: BTreeMap<String, Renamed>,
    children: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct ExtractFile {
    release: String,
    platforms: Vec<ExtractPlatform>,
    tactics: Vec<ExtractTactic>,
    techniques: BTreeMap<String, ExtractTechnique>,
    revoked: BTreeMap<String, String>,
    renamed: BTreeMap<String, Renamed>,
}

#[derive(Deserialize)]
struct ExtractPlatform {
    slug: String,
    name: String,
}

#[derive(Deserialize)]
struct ExtractTactic {
    id: String,
    shortname: String,
    name: String,
}

#[derive(Deserialize)]
struct ExtractTechnique {
    name: String,
    parent: Option<String>,
    tactics: Vec<String>,
    platforms: Vec<String>,
    deprecated: bool,
}

impl AttackCatalog {
    /// The catalog an extract's text holds: ace3's `load_attack_catalog`. `name` is the extract's, for the
    /// error. An extract in another format is refused.
    pub fn load(text: &str, name: &str) -> Result<AttackCatalog, String> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("{name} isn't JSON: {e}"))?;
        let format = value.get("format");
        if format.and_then(serde_json::Value::as_u64) != Some(FORMAT) {
            let found = format.map_or("None".to_owned(), |f| f.to_string());
            return Err(format!(
                "{name} is in format {found}, not {FORMAT}; rebuild it with `ace svs attack extract`"
            ));
        }
        let file: ExtractFile = serde_json::from_value(value)
            .map_err(|e| format!("{name} isn't an ATT&CK extract: {e}"))?;
        let techniques: BTreeMap<String, Technique> = file
            .techniques
            .into_iter()
            .map(|(id, t)| {
                let technique = Technique {
                    id: id.clone(),
                    name: t.name,
                    parent: t.parent,
                    tactics: t.tactics,
                    platforms: t.platforms,
                    deprecated: t.deprecated,
                };
                (id, technique)
            })
            .collect();
        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        // the map is by id, so each parent's children come out sorted
        for technique in techniques.values() {
            if let Some(parent) = &technique.parent {
                children
                    .entry(parent.clone())
                    .or_default()
                    .push(technique.id.clone());
            }
        }
        Ok(AttackCatalog {
            release: file.release,
            platforms: file
                .platforms
                .into_iter()
                .map(|p| (p.slug, p.name))
                .collect(),
            tactics: file
                .tactics
                .into_iter()
                .map(|t| Tactic {
                    id: t.id,
                    shortname: t.shortname,
                    name: t.name,
                })
                .collect(),
            techniques,
            revoked: file.revoked,
            renamed: file.renamed,
            children,
        })
    }

    pub fn technique(&self, technique_id: &str) -> Option<&Technique> {
        self.techniques.get(technique_id)
    }

    /// What `technique_id` means in the release, or an error for something that isn't a technique id.
    pub fn resolve(&self, technique_id: &str) -> Result<Resolution, String> {
        let normalized = normalize_technique_id(technique_id)
            .ok_or_else(|| format!("{technique_id:?} is not an ATT&CK technique id"))?;
        let successor = self.revoked.get(&normalized);
        let effective = successor.unwrap_or(&normalized).clone();
        let status = self
            .techniques
            .get(&effective)
            .map_or(TechniqueStatus::Unknown, Technique::status);
        Ok(Resolution {
            technique: effective,
            status,
            revoked_from: successor.is_some().then_some(normalized),
        })
    }

    /// A technique's parent as the release has it, or as the id's syntax names it for one the release
    /// doesn't have.
    pub fn parent_of<'a>(&'a self, technique_id: &'a str) -> Option<&'a str> {
        match self.techniques.get(technique_id) {
            Some(technique) => technique.parent.as_deref(),
            None => syntactic_parent(technique_id),
        }
    }

    /// The release's sub-techniques of a technique, deprecated ones included, sorted.
    pub fn children_of(&self, technique_id: &str) -> &[String] {
        self.children.get(technique_id).map_or(&[], Vec::as_slice)
    }

    /// A tactic by its id (`TA0002`) or its shortname (`execution`), in any case.
    pub fn tactic(&self, value: &str) -> Option<&Tactic> {
        let value = strip(value);
        let (upper, lower) = (value.to_uppercase(), value.to_lowercase());
        // ace3 looks the upper-cased value up among ids and shortnames both, then the lower-cased one
        let find = |text: &str| {
            self.tactics
                .iter()
                .find(|t| t.id == text)
                .or_else(|| self.tactics.iter().find(|t| t.shortname == text))
        };
        find(&upper).or_else(|| find(&lower))
    }

    /// The techniques in any of the tactics `tactic_ids`.
    pub fn techniques_in<'a>(
        &self,
        tactic_ids: impl IntoIterator<Item = &'a str>,
    ) -> BTreeSet<String> {
        let wanted: BTreeSet<&str> = tactic_ids.into_iter().collect();
        self.techniques
            .values()
            .filter(|t| t.tactics.iter().any(|id| wanted.contains(id.as_str())))
            .map(|t| t.id.clone())
            .collect()
    }

    /// ATT&CK's name for a platform slug, or the slug for one the release doesn't use.
    pub fn platform_name<'a>(&'a self, slug: &'a str) -> &'a str {
        self.platforms
            .iter()
            .find(|(s, _)| s == slug)
            .map_or(slug, |(_, name)| name.as_str())
    }
}

static LOADED: LazyLock<Mutex<BTreeMap<String, Arc<AttackCatalog>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// The catalog of a vendored release, read once per process: ace3's `get_attack_catalog`.
pub fn attack_catalog(release: &str) -> Result<Arc<AttackCatalog>, String> {
    let mut loaded = LOADED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(catalog) = loaded.get(release) {
        return Ok(catalog.clone());
    }
    let text = vendored(release)?;
    let catalog = Arc::new(AttackCatalog::load(text, &format!("{release}.json"))?);
    loaded.insert(release.to_owned(), catalog.clone());
    Ok(catalog)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// ace3's `tests/saq/svs/conftest.py` `ATTACK_EXTRACT`: a small release its tests read.
    pub(crate) fn extract_fixture() -> serde_json::Value {
        crate::testing::attack_extract()
    }

    fn catalog() -> AttackCatalog {
        AttackCatalog::load(&extract_fixture().to_string(), "v99.0.json").expect("loads")
    }

    /// test_attack.py's `test_normalize_technique_id`.
    #[test]
    fn normalize_technique_ids() {
        assert_eq!(
            normalize_technique_id(" t1059.001 ").as_deref(),
            Some("T1059.001")
        );
        assert_eq!(normalize_technique_id("T1059").as_deref(), Some("T1059"));
        for value in [
            "TA0002",
            "{{ technique }}",
            "T105",
            "T1059.1",
            "mitre:T1059",
            "",
        ] {
            assert_eq!(normalize_technique_id(value), None, "{value:?}");
        }
    }

    /// test_attack.py's `test_syntactic_parent`.
    #[test]
    fn syntactic_parents() {
        assert_eq!(syntactic_parent("T1059.001"), Some("T1059"));
        assert_eq!(syntactic_parent("T1059"), None);
    }

    /// test_attack.py's `test_normalize_platform`.
    #[test]
    fn normalize_platforms() {
        for (name, slug) in [
            ("windows", "windows"),
            (" macOS ", "macos"),
            ("iaas:aws", "iaas"),
            ("iaas:gcp", "iaas"),
            ("azure-ad", "identity-provider"),
            ("office-365", "office-suite"),
            ("google-workspace", "office-suite"),
            ("containers", "containers"),
        ] {
            assert_eq!(normalize_platform(name), slug, "{name:?}");
        }
    }

    /// test_attack.py's `test_the_catalog`.
    #[test]
    fn the_catalog() {
        let catalog = catalog();
        assert_eq!(catalog.release, "v99.0");
        let slugs: Vec<&str> = catalog.platforms.iter().map(|(s, _)| s.as_str()).collect();
        assert_eq!(slugs, ["windows", "macos"]);
        assert_eq!(catalog.platform_name("macos"), "macOS");
        assert_eq!(catalog.platform_name("esxi"), "esxi");
        let tactics: Vec<&str> = catalog.tactics.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(tactics, ["TA0003", "TA0002"]);

        let technique = catalog.technique("T1547").expect("in the release");
        assert_eq!(technique.name, "Boot or Logon Autostart Execution");
        assert_eq!(technique.tactics, ["TA0003", "TA0002"]);
        assert_eq!(technique.platforms, ["windows"]);
        assert_eq!(technique.status(), TechniqueStatus::Active);
        assert_eq!(
            catalog.technique("T1099").expect("in the release").status(),
            TechniqueStatus::Deprecated
        );
        assert_eq!(catalog.technique("T9999"), None);
        assert_eq!(catalog.renamed["T1059"].from, "Scripting");
    }

    /// test_attack.py's `test_resolve`.
    #[test]
    fn resolve() {
        let catalog = catalog();
        let resolution = |technique: &str, status, revoked_from: Option<&str>| Resolution {
            technique: technique.to_owned(),
            status,
            revoked_from: revoked_from.map(str::to_owned),
        };
        assert_eq!(
            catalog.resolve("T1059"),
            Ok(resolution("T1059", TechniqueStatus::Active, None))
        );
        assert_eq!(
            catalog.resolve("t1086"),
            Ok(resolution(
                "T1059.001",
                TechniqueStatus::Active,
                Some("T1086")
            ))
        );
        assert_eq!(
            catalog.resolve("T1150"),
            Ok(resolution(
                "T1099",
                TechniqueStatus::Deprecated,
                Some("T1150")
            ))
        );
        assert_eq!(
            catalog.resolve("T1234.005"),
            Ok(resolution("T1234.005", TechniqueStatus::Unknown, None))
        );
        let error = catalog.resolve("TA0002").expect_err("a tactic");
        assert!(error.contains("is not an ATT&CK technique id"), "{error}");
    }

    /// test_attack.py's `test_parents_and_children`.
    #[test]
    fn parents_and_children() {
        let catalog = catalog();
        assert_eq!(catalog.parent_of("T1059.001"), Some("T1059"));
        assert_eq!(catalog.parent_of("T1059"), None);
        // an id the release doesn't have: its syntax names the parent
        assert_eq!(catalog.parent_of("T1234.005"), Some("T1234"));
        assert_eq!(catalog.children_of("T1059"), ["T1059.001", "T1059.002"]);
        assert!(catalog.children_of("T1547").is_empty());
    }

    /// test_attack.py's `test_tactics`.
    #[test]
    fn tactics() {
        let catalog = catalog();
        assert_eq!(
            catalog.tactic("TA0002").map(|t| t.shortname.as_str()),
            Some("execution")
        );
        assert_eq!(
            catalog.tactic("ta0002").map(|t| t.id.as_str()),
            Some("TA0002")
        );
        assert_eq!(
            catalog.tactic("Persistence").map(|t| t.id.as_str()),
            Some("TA0003")
        );
        assert_eq!(catalog.tactic("stealth"), None);
        let set = |ids: &[&str]| {
            ids.iter()
                .map(|id| (*id).to_owned())
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(catalog.techniques_in(["TA0003"]), set(&["T1547"]));
        assert_eq!(
            catalog.techniques_in(["TA0002"]),
            set(&["T1059", "T1059.001", "T1059.002", "T1547"])
        );
    }

    /// test_attack.py's `test_another_format_is_refused`.
    #[test]
    fn another_format_is_refused() {
        let mut extract = extract_fixture();
        extract["format"] = json!(2);
        let error = AttackCatalog::load(&extract.to_string(), "v99.0.json").expect_err("format 2");
        assert!(
            error.contains("v99.0.json is in format 2, not 1; rebuild it with"),
            "{error}"
        );
        extract.as_object_mut().expect("an object").remove("format");
        let error = AttackCatalog::load(&extract.to_string(), "v99.0.json").expect_err("no format");
        assert!(error.contains("is in format None, not 1"), "{error}");
    }

    /// test_attack.py's `test_the_vendored_release`: the default release is built in, read once, and
    /// consistent: every revoked id leads to a technique of the release, and every parent is one.
    #[test]
    fn the_vendored_release() {
        let release = ace_sdk::SvsSection::default().attack_release;
        assert!(vendored(&release).is_ok());
        let catalog = attack_catalog(&release).expect("vendored");
        assert_eq!(catalog.release, release);
        assert!(Arc::ptr_eq(
            &catalog,
            &attack_catalog(&release).expect("vendored")
        ));
        let powershell = catalog.technique("T1059.001").expect("in the release");
        assert_eq!(powershell.parent.as_deref(), Some("T1059"));
        assert!(powershell.platforms.iter().any(|p| p == "windows"));
        assert_eq!(
            catalog.tactic("execution").map(|t| t.id.as_str()),
            Some("TA0002")
        );
        assert!(
            catalog
                .revoked
                .values()
                .all(|successor| catalog.techniques.contains_key(successor))
        );
        assert!(
            catalog
                .techniques
                .values()
                .filter_map(|t| t.parent.as_ref())
                .all(|parent| catalog.techniques.contains_key(parent))
        );
        let known = [
            "windows",
            "linux",
            "macos",
            "esxi",
            "iaas",
            "containers",
            "saas",
            "office-suite",
            "identity-provider",
            "network-devices",
            "pre",
        ];
        assert!(
            catalog
                .platforms
                .iter()
                .all(|(slug, _)| known.contains(&slug.as_str()))
        );
        // each vendored extract names the release its file is named for
        for (name, text) in VENDORED {
            let catalog = AttackCatalog::load(text, name).expect("loads");
            assert_eq!(&catalog.release, name);
        }
    }

    /// test_attack.py's `test_attack_release_must_be_vendored`: the default is vendored, a name that isn't
    /// a release's is refused (it could otherwise name another file), and so is a release this build
    /// doesn't have. ace3's last step, a release that becomes valid once its file is there, is `VENDORED`
    /// gaining a line, which `the_vendored_release` covers for every line it has.
    #[test]
    fn the_attack_release_must_be_vendored() {
        assert_eq!(ace_sdk::SvsSection::default().attack_release, "v20.0");
        let error = vendored("../v20.0").expect_err("not a release name");
        assert!(error.contains("is not an ATT&CK release name"), "{error}");
        let error = attack_catalog("v1.0").expect_err("not vendored");
        assert!(
            error.contains("svs.attack_release v1.0: this build has no extract of it")
                && error.contains("`ace svs attack extract v1.0` builds one"),
            "{error}"
        );
        // the overlay refuses the first before any process looks for the file
        let error = ace_sdk::Overlay::from_yaml("svs: {attack_release: ../v20.0}")
            .expect_err("not a release name");
        assert!(
            error.to_string().contains("is not an ATT&CK release name"),
            "{error}"
        );
    }
}
