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
//! Four deliberate differences:
//!
//! - A rule file, and every file it includes, is a regular file inside the signature directory,
//!   reached through no symbolic link, and yara-x opens no file: `crate::include` reads them and puts
//!   an included file's text in place. ace3 follows a link and lets an include reach any file its
//!   process can read. A file that breaks the rule is left out like a file YARA rejects.
//! - A file is held to `crate::guard`'s bounds before yara-x reads it, and one past them is left out
//!   like a file YARA rejects: yara-x overflows its stack on it, which would abort the process.
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
use crate::include::{Boundary, Resolved};
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
    /// The exported detections' types and values by id, from the export's index rule
    /// (`crate::export`, PLAN.md 7.16).
    pub(crate) detections: std::collections::BTreeMap<i64, (String, String)>,
}

impl Ruleset {
    /// Wraps compiled rules, compiling each rule's filter directives. Fails on a `re:` item
    /// the regex crate can't compile, which `compile` has already left out.
    pub fn new(rules: yara_x::Rules, options: &LoadOptions) -> Result<Ruleset, String> {
        let mut filters = HashMap::new();
        let mut detections = std::collections::BTreeMap::new();
        for rule in rules.iter() {
            let meta = Meta::from_yara_x(rule.metadata());
            if rule.namespace() == crate::export::NAMESPACE
                && rule.identifier() == crate::export::INDEX_RULE
            {
                detections = crate::export::read_index(&meta);
            }
            let filter = RuleFilter::from_meta(&meta)
                .map_err(|e| format!("rule {}: {e}", rule.identifier()))?;
            filters.insert(
                (rule.namespace().to_string(), rule.identifier().to_string()),
                filter,
            );
        }
        Ok(Ruleset {
            rules,
            blacklist: options.blacklist.clone(),
            filters,
            detections,
        })
    }

    /// The type and value of the detection a matched `$obsd_` string names (`export::string_id`),
    /// when the ruleset's export holds it: what ace3's scanner reads from the detection's row.
    pub fn detection(&self, id: i64) -> Option<(&str, &str)> {
        self.detections
            .get(&id)
            .map(|(observable_type, value)| (observable_type.as_str(), value.as_str()))
    }

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
    pub warnings: Vec<CompileWarning>,
}

/// One of yara-x's warnings, such as `deprecated_field` for `pe.number_of_signatures`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileWarning {
    /// yara-x's code for it, such as `slow_pattern`.
    pub code: String,
    /// The source it's about, `<namespace>/<file name>` as [`compile`] names each file, or None
    /// when yara-x gives none.
    pub origin: Option<String>,
    /// The whole report, as yara-x writes it, with the lines it's about.
    pub text: String,
}

impl CompileWarning {
    fn of(warning: &yara_x::warnings::Warning) -> CompileWarning {
        CompileWarning {
            code: warning.code().to_owned(),
            origin: warning
                .labels()
                .find_map(|label| label.origin().map(str::to_owned)),
            text: warning.to_string(),
        }
    }
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
    /// namespace that define the same rule name do this. `files` is what became of each file
    /// when it compiled alone, when `compile` compiled them so.
    Combined {
        path: PathBuf,
        error: String,
        files: Vec<FileReport>,
    },
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
            LoadError::Combined { path, error, .. } => write!(
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
    let mut survivors: Vec<(&Namespace, Sources)> = Vec::new();

    for namespace in namespaces {
        let mut sources = Vec::new();
        for path in &namespace.files {
            let outcome = match compile_file(namespace, path) {
                Ok((source, rules)) => {
                    sources.push((path.clone(), source));
                    FileOutcome::Included { rules }
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

    let (ruleset, warnings) = match compile_sources(&survivors, options) {
        Ok(compiled) => compiled,
        Err(LoadError::Combined { path, error, .. }) => {
            return Err(LoadError::Combined { path, error, files });
        }
        Err(e) => return Err(e),
    };
    Ok(Loaded {
        ruleset,
        files,
        warnings,
    })
}

/// Compiles the files of the given namespaces together, without compiling each alone first:
/// for files `compile` has already let through, such as one namespace's at a time. Returns
/// the ruleset and the compiler's warnings.
pub fn compile_together(
    namespaces: &[Namespace],
    options: &LoadOptions,
) -> Result<(Ruleset, Vec<CompileWarning>), LoadError> {
    let mut survivors = Vec::new();
    for namespace in namespaces {
        let mut sources = Vec::new();
        for path in &namespace.files {
            let resolved = resolve(namespace, path).map_err(|error| LoadError::Combined {
                path: path.clone(),
                error,
                files: Vec::new(),
            })?;
            sources.push((path.clone(), resolved));
        }
        survivors.push((namespace, sources));
    }
    compile_sources(&survivors, options)
}

/// Each file's path and what yara-x is given of it: its text with its includes in place.
type Sources = Vec<(PathBuf, Resolved)>;

fn compile_sources(
    survivors: &[(&Namespace, Sources)],
    options: &LoadOptions,
) -> Result<(Ruleset, Vec<CompileWarning>), LoadError> {
    let mut compiler = new_compiler();
    for (namespace, sources) in survivors {
        compiler.new_namespace(&namespace.name);
        for (path, resolved) in sources {
            if let Err(error) = compiler.add_source(source_code(namespace, path, &resolved.source))
            {
                return Err(LoadError::Combined {
                    path: path.clone(),
                    error: with_note(error.to_string(), resolved),
                    files: Vec::new(),
                });
            }
        }
    }

    let rules = compiler.build();
    let warnings = rules.warnings().iter().map(CompileWarning::of).collect();
    // Every rule's filter compiled when its file compiled alone.
    let ruleset = Ruleset::new(rules, options).map_err(|error| LoadError::Combined {
        path: PathBuf::new(),
        error,
        files: Vec::new(),
    })?;
    Ok((ruleset, warnings))
}

/// A compiler with the default externals, which opens no file: an `include` is an error to it.
/// `crate::include` puts an included file's text in place before a source reaches it.
pub(crate) fn new_compiler<'a>() -> Compiler<'a> {
    let mut compiler = Compiler::new();
    compiler.enable_includes(false);
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

/// What yara-x is given of a namespace's rule file: its text, read inside the signature directory
/// through no symbolic link, with the files it includes in place, held to `crate::guard`'s bounds
/// (`crate::include`). Past the bounds yara-x overflows its stack, which would abort the process and
/// not just fail the file.
fn resolve(namespace: &Namespace, path: &Path) -> Result<Resolved, String> {
    Boundary::of_namespace(&namespace.dir)
        .load(&namespace.dir, path)
        .map_err(|refusal| refusal.to_string())
}

/// A rule file's own bytes, as the loader reads them: inside the signature directory, through no
/// symbolic link.
pub fn read_rule_file(namespace_dir: &Path, path: &Path) -> Result<Vec<u8>, String> {
    Boundary::of_namespace(namespace_dir)
        .read_rule_file(path)
        .map_err(|refusal| refusal.to_string())
}

/// yara-x's report, with which lines are an included file's when the file has includes.
fn with_note(report: String, resolved: &Resolved) -> String {
    match resolved.note() {
        Some(note) => format!("{report}\n{note}"),
        None => report,
    }
}

/// Compiles one file alone, as yara_scanner_v2 does before compiling the files together, and
/// compiles each rule's filter directives. Returns what yara-x was given and the file's rules, or why
/// it is left out if either fails.
fn compile_file(namespace: &Namespace, path: &Path) -> Result<(Resolved, Vec<RuleInfo>), String> {
    let resolved = resolve(namespace, path)?;

    let mut compiler = new_compiler();
    compiler.new_namespace(&namespace.name);
    compiler
        .add_source(source_code(namespace, path, &resolved.source))
        .map_err(|e| with_note(e.to_string(), &resolved))?;

    let mut rules = Vec::new();
    for rule in compiler.build().iter() {
        let info = RuleInfo {
            namespace: namespace.name.clone(),
            name: rule.identifier().to_string(),
            meta: Meta::from_yara_x(rule.metadata()),
            tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
            private: rule.is_private(),
            global: rule.is_global(),
        };
        RuleFilter::from_meta(&info.meta).map_err(|e| format!("rule {}: {e}", info.name))?;
        rules.push(info);
    }
    Ok((resolved, rules))
}
