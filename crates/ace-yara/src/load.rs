//! Loading a signature directory the way `YaraScanner.compile_and_load_rules` in
//! yara_scanner_v2 3.0.0 does.
//!
//! - Each subdirectory of the signature directory is a namespace, holding the files directly
//!   in it whose names end in `.yar` or `.yara`, ignoring case.
//! - Each file compiles alone first. A file that fails is logged at ERROR with its path and
//!   left out, with every rule in it.
//! - The files that are left then compile together. If they don't, nothing loads, as in ace3,
//!   where the yara service keeps its previous generation.
//!
//! Two deliberate differences:
//!
//! - Every `re:` item in a rule's filter directives compiles with the regex crate while the
//!   file compiles alone, and a file with one that doesn't is left out like a file YARA
//!   rejects. ace3 compiles them with Python's `re` at scan time, where a bad pattern fails
//!   the scan, and only when the directives before it let the match through.
//! - ace3 reads a rule file before its `try`, so a file that isn't UTF-8 fails the whole load
//!   there. Here it is one more file that is left out.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use yara_x::{Compiler, SourceCode};

use crate::filter::RuleFilter;
use crate::meta::Meta;

/// The external variables yara_scanner_v2 defines for every rule (`DEFAULT_YARA_EXTERNALS`),
/// all strings and empty until a scan sets them. `filetype` is reserved and stays empty.
pub const EXTERNALS: [&str; 4] = ["filename", "filepath", "extension", "filetype"];

/// One namespace: its name, its directory and the rule files in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    pub name: String,
    pub dir: PathBuf,
    pub files: Vec<PathBuf>,
}

/// Lists a signature directory's namespaces the way `YaraScanner(signature_dir=...)` does,
/// sorted so that two listings of the same tree are the same. Files directly in the signature
/// directory and subdirectories of a namespace are not read.
pub fn discover(signature_dir: &Path) -> io::Result<Vec<Namespace>> {
    let mut namespaces = Vec::new();
    for entry in std::fs::read_dir(signature_dir)? {
        let dir = entry?.path();
        if !dir.is_dir() {
            continue;
        }

        let mut files = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase());
            if name.is_some_and(|n| n.ends_with(".yar") || n.ends_with(".yara")) {
                files.push(path);
            }
        }
        files.sort();

        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        namespaces.push(Namespace { name, dir, files });
    }
    namespaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(namespaces)
}

#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    /// Rule names whose matches are dropped, as yara_scanner_v2's blacklist does.
    pub blacklist: BTreeSet<String>,
}

/// A rule as compiled.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleInfo {
    pub namespace: String,
    pub name: String,
    pub meta: Meta,
    pub tags: Vec<String>,
    pub private: bool,
    pub global: bool,
}

/// What became of one rule file.
#[derive(Debug, Clone, PartialEq)]
pub struct FileReport {
    pub namespace: String,
    pub path: PathBuf,
    pub outcome: FileOutcome,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileOutcome {
    /// The file compiled alone and its rules are in the ruleset.
    Included { rules: Vec<RuleInfo> },
    /// The file was left out, with every rule in it.
    LeftOut { error: String },
}

impl FileReport {
    pub fn is_included(&self) -> bool {
        matches!(self.outcome, FileOutcome::Included { .. })
    }
}

/// Compiled rules, with the blacklist and each rule's filter directives, compiled once.
pub struct Ruleset {
    pub(crate) rules: yara_x::Rules,
    pub(crate) blacklist: BTreeSet<String>,
    /// Keyed by (namespace, rule name).
    pub(crate) filters: HashMap<(String, String), RuleFilter>,
}

impl Ruleset {
    pub fn rules(&self) -> &yara_x::Rules {
        &self.rules
    }

    pub fn is_blacklisted(&self, rule: &str) -> bool {
        self.blacklist.contains(rule)
    }

    /// The rule's filter directives. Every rule in the ruleset has an entry.
    pub fn filter(&self, namespace: &str, rule: &str) -> Option<&RuleFilter> {
        self.filters.get(&(namespace.to_string(), rule.to_string()))
    }
}

/// A loaded signature directory: the ruleset, what became of each file, and the compiler's
/// warnings for the files that were included.
pub struct Loaded {
    pub ruleset: Ruleset,
    pub files: Vec<FileReport>,
    pub warnings: Vec<String>,
}

impl Loaded {
    pub fn left_out(&self) -> impl Iterator<Item = &FileReport> {
        self.files.iter().filter(|f| !f.is_included())
    }

    pub fn rules(&self) -> impl Iterator<Item = &RuleInfo> {
        self.files.iter().flat_map(|f| match &f.outcome {
            FileOutcome::Included { rules } => rules.as_slice(),
            FileOutcome::LeftOut { .. } => &[],
        })
    }
}

#[derive(Debug)]
pub enum LoadError {
    /// The signature directory couldn't be listed.
    Discover { dir: PathBuf, error: io::Error },
    /// Every file compiled alone, but not together, so nothing loads. Two files in one
    /// namespace that define the same rule name do this.
    Combined { path: PathBuf, error: String },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Discover { dir, error } => {
                write!(
                    f,
                    "unable to list signature directory {}: {error}",
                    dir.display()
                )
            }
            LoadError::Combined { path, error } => write!(
                f,
                "the rule files compile alone but not together, at {}: {error}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// Loads every namespace in a signature directory.
pub fn load_dir(signature_dir: &Path, options: &LoadOptions) -> Result<Loaded, LoadError> {
    let namespaces = discover(signature_dir).map_err(|error| LoadError::Discover {
        dir: signature_dir.to_path_buf(),
        error,
    })?;
    compile(&namespaces, options)
}

/// Compiles the given namespaces: each file alone, then the files that compiled together.
pub fn compile(namespaces: &[Namespace], options: &LoadOptions) -> Result<Loaded, LoadError> {
    let mut files = Vec::new();
    let mut filters = HashMap::new();
    // Each namespace with the (path, source) of each file that compiled alone.
    type Sources = Vec<(PathBuf, Vec<u8>)>;
    let mut survivors: Vec<(&Namespace, Sources)> = Vec::new();

    for namespace in namespaces {
        let mut sources = Vec::new();
        for path in &namespace.files {
            let outcome = match compile_file(namespace, path) {
                Ok(file) => {
                    sources.push((path.clone(), file.source));
                    for (rule, filter) in file.rules.iter().zip(file.filters) {
                        filters.insert((rule.namespace.clone(), rule.name.clone()), filter);
                    }
                    FileOutcome::Included { rules: file.rules }
                }
                Err(error) => {
                    tracing::error!(
                        namespace = %namespace.name,
                        path = %path.display(),
                        "unable to compile {}, leaving it out: {error}",
                        path.display()
                    );
                    FileOutcome::LeftOut { error }
                }
            };
            files.push(FileReport {
                namespace: namespace.name.clone(),
                path: path.clone(),
                outcome,
            });
        }
        survivors.push((namespace, sources));
    }

    let mut compiler = new_compiler();
    for (namespace, sources) in &survivors {
        compiler.new_namespace(&namespace.name);
        compiler.add_include_dir(&namespace.dir);
        for (path, source) in sources {
            if let Err(error) = compiler.add_source(source_code(namespace, path, source)) {
                return Err(LoadError::Combined {
                    path: path.clone(),
                    error: error.to_string(),
                });
            }
        }
    }

    let rules = compiler.build();
    let warnings = rules.warnings().iter().map(|w| w.to_string()).collect();
    Ok(Loaded {
        ruleset: Ruleset {
            rules,
            blacklist: options.blacklist.clone(),
            filters,
        },
        files,
        warnings,
    })
}

pub(crate) fn new_compiler<'a>() -> Compiler<'a> {
    let mut compiler = Compiler::new();
    for name in EXTERNALS {
        // The names are valid identifiers and defined once, so this can't fail.
        compiler
            .define_global(name, "")
            .expect("the default externals are valid identifiers defined once");
    }
    compiler
}

/// The source, named `<namespace>/<file name>` in yara-x's errors and warnings, so they read
/// the same wherever the checkout is.
fn source_code<'a>(namespace: &Namespace, path: &Path, source: &'a [u8]) -> SourceCode<'a> {
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    SourceCode::from(source).with_origin(format!("{}/{file_name}", namespace.name))
}

/// A file that compiled alone: its source, and its rules each with its filter.
struct CompiledFile {
    source: Vec<u8>,
    rules: Vec<RuleInfo>,
    filters: Vec<RuleFilter>,
}

/// Compiles one file alone, as yara_scanner_v2 does before compiling the files together, and
/// compiles each rule's filter directives. Returns why the file is left out if either fails.
fn compile_file(namespace: &Namespace, path: &Path) -> Result<CompiledFile, String> {
    let source = std::fs::read(path).map_err(|e| format!("unable to read the file: {e}"))?;

    let mut compiler = new_compiler();
    compiler.new_namespace(&namespace.name);
    compiler.add_include_dir(&namespace.dir);
    compiler
        .add_source(source_code(namespace, path, &source))
        .map_err(|e| e.to_string())?;

    let mut rules = Vec::new();
    let mut filters = Vec::new();
    for rule in compiler.build().iter() {
        let info = RuleInfo {
            namespace: namespace.name.clone(),
            name: rule.identifier().to_string(),
            meta: Meta::from_yara_x(rule.metadata()),
            tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
            private: rule.is_private(),
            global: rule.is_global(),
        };
        let filter =
            RuleFilter::from_meta(&info.meta).map_err(|e| format!("rule {}: {e}", info.name))?;
        rules.push(info);
        filters.push(filter);
    }
    Ok(CompiledFile {
        source,
        rules,
        filters,
    })
}
