//! A module's results kept across roots (PLAN.md decision 26, docs/decisions/0004): ace3's analysis
//! result cache (`saq/analysis/cache.py`, `docs/ANALYSIS_CACHING.md`).
//!
//! A module opts in with `Module::CACHE`. The core then looks its result up before it would queue
//! the module's task on an observable, and when a result is kept for the same key and hasn't
//! expired, writes that result as the module's, through the same code as a task's end, and queues
//! no task. A task's end keeps its result when it may be kept (`ace_core::cache`).
//!
//! **What a cached result may depend on.** Only on what its key holds: the observable's type and
//! value (a file's value is its sha256, so its bytes and the type the core found in them), the
//! module's name, instance, `Cache::version` and analysis type, its settings block, and its
//! *extended version* (`Cache`'s `lists`, `tools`, `files`, `libraries` and `reads`, ace3's
//! `extended_version`). Whatever else its task can read makes a result from one root wrong in
//! another, so `Manifest::cache_refusal` refuses a cacheable module that reads it: its dependencies'
//! results, its tree, the modules that added its observable, its carrying email, the tags of its
//! related observables, what is below it or the rules that matched there, ACE's own data, or a list
//! its key doesn't hold. Every binary refuses such a module when it reads its overlay, so no pool
//! starts with one (`Overlay::components`), and every manifest is checked on its defaults in the
//! tests.
//!
//! A parser's lease also carries its file's path, `yara_meta` and role, which no declaration names.
//! A cacheable module's result may not depend on its `yara_meta` or role, and may depend on its path
//! only through the paths it names the files it adds at, which it declares as a function of the path
//! it analyzed (`CachePaths::Named`). The core checks what it can of that when it keeps a result:
//! each file must be at one of those paths, or nothing is kept. What a module's declaration
//! (`Module::takes`) reads is no part of the key: the core applies it before it looks anything up,
//! on the new root's facts, as ace3's executor checks a module's requirements before its cache.
//!
//! **What is never kept**, as ace3: a result with `error` set, a task that failed, timed out or was
//! cancelled, or that delayed (only its final run's result is), a result that adds to anything but
//! its own observable and the ones it adds (`others`, `redirected`, `root`, `stored`), one with
//! writes to ACE's data, and one larger than `MAX_COMPRESSED_BYTES` compressed. A module that has
//! nothing to say returns `Outcome::Skipped`, which stores nothing and so is never kept: a module
//! keeps a negative answer, as ace3's OCR and QR code modules keep a clean scan, by returning a
//! result that says so.
//!
//! **How to opt in.** Set `Module::CACHE` to a `Cache`: `Cache::new(version, ttl)` for a module whose
//! result follows from its observable and settings alone, such as a lookup of a value; then name in it
//! every list it reads (`lists`), every program it runs (`tools`, each with `version_args` in its
//! pool's `ToolSpec`), every file of its image its result depends on (`files`, such as a dictionary),
//! the libraries linked into it whose versions matter (`libraries`), and the reads whose answers the
//! core can key (`reads`, from `KEYED_READS`). A module that adds files names them with a function of
//! the path it read and gives the same function as `CachePaths::Named`. Raise `version` whenever a
//! change to the module would answer differently for the same input. Make sure a failure the next
//! alert should retry is a result with `error` or `Outcome::Skipped`, and a clean answer worth keeping
//! is a result. A time to live of zero makes the module cacheable but kept only once a site's overlay
//! gives it a `cache_ttl`. `ace`'s test `every_cacheable_module_reads_only_what_its_key_holds` checks
//! each opt-in with `Manifest::cache_refusal`.
//!
//! **What can't be keyed.** Anything the core can't make before the task is queued: another module's
//! result, the tree around the observable, an external service's state (a lookup's answer is kept for
//! its time to live, which bounds how stale it is, as in ace3), or the time (a result that says how
//! old something is keeps the age it had when it was kept). A module whose result depends on these
//! beyond what a time to live can bound shouldn't opt in.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::lists::ListSpec;
use crate::manifest::{Manifest, ModuleKind};
use crate::reads::Read;

/// The version of the key's format, hashed into every key, as ace3's `CACHE_KEY_FORMAT`. Changing
/// how a key is made changes this, and every row kept under the old format is then never found
/// again and goes with its day's partition.
pub const KEY_FORMAT: &str = "ace4-analysis-cache-key-v1";

/// The most a kept result may be, compressed: ace3's `max_compressed_bytes`, 1 MiB.
pub const MAX_COMPRESSED_BYTES: usize = 1024 * 1024;

/// A module's opt-in to the cache.
#[derive(Debug, Clone, Copy)]
pub struct Cache {
    /// Raised whenever the module's code gives another result for the same input, as ace3's module
    /// `version`. ace4's own version isn't in the key, as ace3's isn't: a change to a module that
    /// changes what it finds raises this.
    pub version: u32,
    /// How long a result is kept, unless the overlay says otherwise (`cache_ttl`). ace3's
    /// `cache_ttl` in `saq.default.yaml`. Zero keeps none unless the overlay sets one, for a module
    /// ace3 can cache but doesn't by default.
    pub ttl: Duration,
    /// How the paths of the files the module adds follow from the path of the one it analyzed.
    pub paths: CachePaths,
    /// The analyst-edited lists it reads (`Module::LISTS`) whose entries are in its key, which must
    /// be all of them: what each holds when the key is made, the entries that haven't expired.
    pub lists: &'static [ListSpec],
    /// The programs it runs (`Module::TOOLS`) whose versions are in its key, each as the pool's
    /// image has it (`crate::tools::ToolSpec::version_args`), which must be all of them. The pool
    /// reads them when it starts and sends them with each result.
    pub tools: &'static [&'static str],
    /// Files of the pool's image its result depends on, such as a dictionary, by path: each one's
    /// sha256 is in its key, read by the pool when it starts.
    pub files: &'static [&'static str],
    /// The libraries linked into the module whose versions are in its key, such as OpenCV: what
    /// this returns, called by the pool when it starts.
    pub libraries: fn() -> Vec<(&'static str, String)>,
    /// The reads of ACE's own data it makes (`Module::READS`) whose answers are in its key, which
    /// must be all of them, and each one `KEYED_READS` names: the core makes the read's answer for
    /// the observable when it makes the key, as the task would get it.
    pub reads: &'static [Read],
}

/// The reads whose answer the core can put in a key: those that answer for the task's own
/// observable alone, from what the core holds. `newly-registered` is whether the fqdn or url, or a
/// parent of it, is in the newly registered domains list: ace3 keys `nrd_analyzer` on its database
/// file's version, which changes with any domain; the answer itself changes only when this
/// observable's does.
pub const KEYED_READS: &[Read] = &[<crate::reads::NewlyRegistered as crate::reads::ReadKind>::READ];

impl Cache {
    /// An opt-in with nothing in its extended version, for a module whose result depends on its
    /// input and settings alone.
    pub const fn new(version: u32, ttl: Duration) -> Cache {
        Cache {
            version,
            ttl,
            paths: CachePaths::Unread,
            lists: &[],
            tools: &[],
            files: &[],
            libraries: no_libraries,
            reads: &[],
        }
    }
}

fn no_libraries() -> Vec<(&'static str, String)> {
    Vec::new()
}

/// How a cacheable module's result depends on its input file's path.
#[derive(Debug, Clone, Copy)]
pub enum CachePaths {
    /// Not at all, and it adds no file, or adds files at paths that don't follow from it.
    Unread,
    /// Only through the paths of the files it adds: every file it adds is at one of the paths this
    /// returns for the path it analyzed. A kept result names each file by its place in that list,
    /// and a hit puts it at the same place in the list for the new root's path. The module names its
    /// files with the same function.
    Named(fn(&str) -> Vec<String>),
}

/// Why a module can't be cached, or None when it can: what its task reads that its key doesn't
/// hold (`Manifest::cache_refusal`).
pub fn refusal(manifest: &Manifest) -> Option<String> {
    let cache = manifest.cache.as_ref()?;
    let reads = [
        (
            !manifest.depends_on.is_empty(),
            "its dependencies' results (DEPENDS_ON)",
        ),
        (manifest.reads_tree, "its root's tree (READS_TREE)"),
        (
            manifest.reads_added_by,
            "which modules added its observable (READS_ADDED_BY)",
        ),
        (
            manifest.reads_carrying_email,
            "the email that carried it (READS_CARRYING_EMAIL)",
        ),
        (
            manifest.reads_related_tags,
            "its related observables' tags (READS_RELATED_TAGS)",
        ),
        (
            manifest.runs_last,
            "the rules that matched below it (RUNS_LAST)",
        ),
        (
            !manifest.reads_below.is_empty(),
            "the observables below it (READS_BELOW)",
        ),
        (
            manifest
                .reads
                .iter()
                .any(|read| !cache.reads.contains(read) || !KEYED_READS.contains(read)),
            "ACE's own data (READS) its key doesn't hold (Cache::reads, KEYED_READS)",
        ),
        (
            !manifest.writes.is_empty(),
            "writes to ACE's own data (WRITES), which a hit doesn't make",
        ),
        (
            manifest.adds_to_others.is_some(),
            "additions to other observables (ADDS_TO_OTHERS)",
        ),
        (manifest.sets_root, "changes to its root (SETS_ROOT)"),
        (
            manifest.adds_stored_files,
            "files another result stored in its root (ADDS_STORED_FILES)",
        ),
        (
            !manifest.scanners.is_empty(),
            "a scanner's output (SCANNERS)",
        ),
        (
            !manifest.stores_results,
            "no result to keep (STORES_RESULTS)",
        ),
    ];
    if let Some((_, what)) = reads.iter().find(|(reads, _)| *reads) {
        return Some(format!(
            "{} is cacheable but reads {what}, which its key doesn't hold",
            manifest.name
        ));
    }
    if let Some(list) = manifest
        .lists
        .iter()
        .find(|list| !cache.lists.iter().any(|keyed| keyed.name == list.name))
    {
        return Some(format!(
            "{} is cacheable but reads the list {}, which its key doesn't hold (Cache::lists)",
            manifest.name, list.name
        ));
    }
    if let Some(tool) = manifest
        .tools
        .iter()
        .find(|tool| !cache.tools.contains(tool))
    {
        return Some(format!(
            "{} is cacheable but runs {tool}, whose version its key doesn't hold (Cache::tools)",
            manifest.name
        ));
    }
    if manifest.kind == ModuleKind::Lookup
        && (!cache.tools.is_empty()
            || !cache.files.is_empty()
            || matches!(cache.paths, CachePaths::Named(_)))
    {
        return Some(format!(
            "{} is a cacheable lookup, which runs no tool, reads no file of an image and adds no file \
             named after its input",
            manifest.name
        ));
    }
    None
}

/// What a key is made of besides the observable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyParts<'a> {
    /// The module's name (`Module::NAME`).
    pub module: &'a str,
    /// The component's key: the module's name, or its instance's.
    pub instance: &'a str,
    /// `Cache::version`.
    pub version: u32,
    /// The analysis type it writes, and its schema version.
    pub output: (&'a str, u32),
    /// The component's settings block. Its time to live isn't in it (`cache_ttl` is beside it in
    /// the overlay), so changing that keeps what was kept.
    pub settings: Option<&'a Value>,
    /// The extended version: each list's, tool's, file's, library's and read's, by `list:<name>`,
    /// `tool:<name>`, `file:<path>`, `library:<name>` and `read:<name>`.
    pub extended: &'a BTreeMap<String, String>,
    /// Each bound slot's connection type and identity, by slot (`Component::connection_identities`,
    /// `crate::connections`): what of a shared connection changes what the module finds, such as a
    /// tenant, and not a timeout. `settings` is then the module's own block, without the
    /// connections' settings. A module with no connection hashes nothing here, so its key is what it
    /// was before connections existed.
    pub connections: &'a BTreeMap<String, Value>,
}

/// The key: a sha256 over each part as `label:length:bytes`, so no two sets of parts run together,
/// as ace3's v2 key is made.
pub fn key(kind: &str, value: &str, parts: &KeyParts<'_>) -> [u8; 32] {
    let mut hash = Sha256::new();
    let mut update = |label: &str, value: &[u8]| {
        hash.update(format!("{label}:{}:", value.len()).as_bytes());
        hash.update(value);
    };
    update("format", KEY_FORMAT.as_bytes());
    update("type", kind.as_bytes());
    update("value", value.as_bytes());
    update("module", parts.module.as_bytes());
    update("instance", parts.instance.as_bytes());
    update("version", parts.version.to_string().as_bytes());
    update("output", parts.output.0.as_bytes());
    update("schema_version", parts.output.1.to_string().as_bytes());
    let settings = match parts.settings {
        None | Some(Value::Null) => "none".to_owned(),
        Some(block) => canonical(block),
    };
    update("settings", &Sha256::digest(settings.as_bytes()));
    for (name, version) in parts.extended {
        update(&format!("ext:{name}"), version.as_bytes());
    }
    for (slot, identity) in parts.connections {
        update(
            &format!("connection:{slot}"),
            &Sha256::digest(canonical(identity).as_bytes()),
        );
    }
    hash.finalize().into()
}

/// A JSON value with every object's keys in byte order, so two blocks that say the same hash the
/// same whatever order the overlay wrote them in.
pub fn canonical(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                Value::Object(
                    keys.into_iter()
                        .map(|key| (key.clone(), sorted(&map[key])))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    sorted(value).to_string()
}

/// A tool's version as its `--version` (or the like) prints it: the first line that isn't empty,
/// of stdout, or of stderr when stdout has none, as ace3's `probe_binary_version` reads it.
pub fn version_line(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let first = |bytes: &[u8]| {
        String::from_utf8_lossy(bytes)
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_owned)
    };
    first(stdout).or_else(|| first(stderr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    static NO_CONNECTIONS: std::sync::LazyLock<BTreeMap<String, Value>> =
        std::sync::LazyLock::new(BTreeMap::new);

    fn parts<'a>(
        extended: &'a BTreeMap<String, String>,
        settings: Option<&'a Value>,
    ) -> KeyParts<'a> {
        KeyParts {
            module: "qrcode",
            instance: "qrcode",
            version: 1,
            output: ("qrcode", 1),
            settings,
            extended,
            connections: &NO_CONNECTIONS,
        }
    }

    /// A connection's identity is in the key, by slot; a module with none keys as it did before
    /// connections (the same bytes are hashed).
    #[test]
    fn a_connection_s_identity_is_in_the_key() {
        let none = BTreeMap::new();
        let base = key("fqdn", "a.example", &parts(&none, None));
        let tenant = |id: &str| {
            BTreeMap::from([(
                "mail_api".to_owned(),
                json!({"type": "mail_api", "identity": {"tenant_id": id}}),
            )])
        };
        let (one, two) = (tenant("one"), tenant("two"));
        let with = |connections| KeyParts {
            connections,
            ..parts(&none, None)
        };
        assert_ne!(base, key("fqdn", "a.example", &with(&one)));
        assert_ne!(
            key("fqdn", "a.example", &with(&one)),
            key("fqdn", "a.example", &with(&two))
        );
        assert_eq!(
            key("fqdn", "a.example", &with(&one)),
            key("fqdn", "a.example", &with(&tenant("one")))
        );
        let mut hasher = Sha256::new();
        for (label, value) in [
            ("format", KEY_FORMAT.as_bytes()),
            ("type", b"fqdn".as_slice()),
            ("value", b"a.example".as_slice()),
            ("module", b"qrcode".as_slice()),
            ("instance", b"qrcode".as_slice()),
            ("version", b"1".as_slice()),
            ("output", b"qrcode".as_slice()),
            ("schema_version", b"1".as_slice()),
        ] {
            hasher.update(format!("{label}:{}:", value.len()).as_bytes());
            hasher.update(value);
        }
        let settings = Sha256::digest(b"none");
        hasher.update(format!("settings:{}:", settings.len()).as_bytes());
        hasher.update(settings);
        let before: [u8; 32] = hasher.finalize().into();
        assert_eq!(base, before);
    }

    #[test]
    fn every_part_is_in_the_key() {
        let none = BTreeMap::new();
        let base = key("file", "ab", &parts(&none, None));
        assert_eq!(base, key("file", "ab", &parts(&none, None)));
        assert_ne!(base, key("url", "ab", &parts(&none, None)));
        assert_ne!(base, key("file", "abc", &parts(&none, None)));
        let block = json!({"timeout": 30});
        assert_ne!(base, key("file", "ab", &parts(&none, Some(&block))));
        let mut tool = BTreeMap::new();
        tool.insert("tool:zbarimg".to_owned(), "0.23.93".to_owned());
        assert_ne!(base, key("file", "ab", &parts(&tool, None)));
        let mut other = parts(&none, None);
        other.instance = "qrcode_two";
        assert_ne!(base, key("file", "ab", &other));
        let mut other = parts(&none, None);
        other.version = 2;
        assert_ne!(base, key("file", "ab", &other));
        let mut other = parts(&none, None);
        other.output.1 = 2;
        assert_ne!(base, key("file", "ab", &other));
    }

    #[test]
    fn parts_never_run_together() {
        // v1 of ace3's key hashed {"tool_a": "1.0"} and {"tool_b": "1.0"} alike
        let mut a = BTreeMap::new();
        a.insert("tool:a".to_owned(), "1.0".to_owned());
        let mut b = BTreeMap::new();
        b.insert("tool:b".to_owned(), "1.0".to_owned());
        assert_ne!(
            key("file", "x", &parts(&a, None)),
            key("file", "x", &parts(&b, None))
        );
        assert_ne!(
            key("ab", "c", &parts(&a, None)),
            key("a", "bc", &parts(&a, None))
        );
    }

    #[test]
    fn a_settings_block_hashes_the_same_in_any_order() {
        let none = BTreeMap::new();
        let one: Value = serde_json::from_str(r#"{"a": 1, "b": {"y": 2, "x": 3}}"#).expect("json");
        let two: Value = serde_json::from_str(r#"{"b": {"x": 3, "y": 2}, "a": 1}"#).expect("json");
        assert_eq!(canonical(&one), canonical(&two));
        assert_eq!(
            key("file", "x", &parts(&none, Some(&one))),
            key("file", "x", &parts(&none, Some(&two)))
        );
        // no block and a null one are the defaults
        assert_eq!(
            key("file", "x", &parts(&none, None)),
            key("file", "x", &parts(&none, Some(&Value::Null)))
        );
    }

    /// A cacheable module may read only what its key holds: each read its task can make that the key
    /// doesn't, a list or a tool the key leaves out, or a lookup keyed on what only a parser has, is
    /// refused, with what it reads.
    #[test]
    fn a_cacheable_module_reads_only_what_its_key_holds() {
        use crate::example::{LineCounter, Resolver};
        let parser = Manifest::parser::<LineCounter>();
        let lookup = Manifest::lookup::<Resolver>();
        assert_eq!(
            refusal(&parser),
            None,
            "not cacheable, so nothing to refuse"
        );
        let mut cached = parser;
        cached.cache = Some(Cache::new(1, Duration::from_secs(60)));
        assert_eq!(refusal(&cached), None);
        let refused = |change: &dyn Fn(&mut Manifest)| {
            let mut m = cached;
            change(&mut m);
            refusal(&m).expect("refused")
        };
        assert!(refused(&|m| m.depends_on = &["file_type"]).contains("DEPENDS_ON"));
        assert!(refused(&|m| m.reads_tree = true).contains("READS_TREE"));
        assert!(refused(&|m| m.reads_added_by = true).contains("READS_ADDED_BY"));
        assert!(refused(&|m| m.reads_carrying_email = true).contains("READS_CARRYING_EMAIL"));
        assert!(refused(&|m| m.reads_related_tags = true).contains("READS_RELATED_TAGS"));
        assert!(refused(&|m| m.runs_last = true).contains("RUNS_LAST"));
        assert!(refused(&|m| m.sets_root = true).contains("SETS_ROOT"));
        assert!(refused(&|m| m.adds_stored_files = true).contains("ADDS_STORED_FILES"));
        assert!(refused(&|m| m.stores_results = false).contains("STORES_RESULTS"));
        const LIST: ListSpec = ListSpec {
            name: "a_list",
            description: "",
            typed: false,
        };
        assert!(refused(&|m| m.lists = &[LIST]).contains("a_list"));
        assert!(refused(&|m| m.tools = &["tesseract"]).contains("tesseract"));
        // a read is keyed only when the module says so and the core can make its answer
        const NEWLY: Read = <crate::reads::NewlyRegistered as crate::reads::ReadKind>::READ;
        const SNORT: Read = <crate::reads::SnortSignature as crate::reads::ReadKind>::READ;
        assert!(refused(&|m| m.reads = &[NEWLY]).contains("READS"));
        let mut reads = cached;
        reads.reads = &[NEWLY];
        reads.cache = Some(Cache {
            reads: &[NEWLY],
            ..Cache::new(1, Duration::from_secs(60))
        });
        assert_eq!(refusal(&reads), None);
        reads.reads = &[SNORT];
        reads.cache = Some(Cache {
            reads: &[SNORT],
            ..Cache::new(1, Duration::from_secs(60))
        });
        assert!(refusal(&reads).expect("refused").contains("KEYED_READS"));
        // what the key holds is no refusal
        let mut keyed = cached;
        keyed.lists = &[LIST];
        keyed.tools = &["tesseract"];
        keyed.cache = Some(Cache {
            lists: &[LIST],
            tools: &["tesseract"],
            ..Cache::new(1, Duration::from_secs(60))
        });
        assert_eq!(refusal(&keyed), None);
        // a lookup keyed on a tool, which it can't run
        let mut lookup = lookup;
        lookup.cache = Some(Cache {
            tools: &["tesseract"],
            ..Cache::new(1, Duration::from_secs(60))
        });
        assert!(
            refusal(&lookup)
                .expect("refused")
                .contains("cacheable lookup")
        );
    }

    #[test]
    fn a_version_is_the_first_line_that_says_something() {
        assert_eq!(
            version_line(b"\n  tesseract 5.5.0\n leptonica-1.84.1\n", b""),
            Some("tesseract 5.5.0".to_owned())
        );
        assert_eq!(
            version_line(b"", b"pdfinfo version 25.03.0\nCopyright"),
            Some("pdfinfo version 25.03.0".to_owned())
        );
        assert_eq!(version_line(b" \n", b""), None);
    }
}
