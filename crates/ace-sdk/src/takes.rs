//! What a module takes: the checks a module makes before it does anything, declared as data over
//! facts the core already holds (PLAN.md decision 23).
//!
//! Most tasks used to end with nothing stored: a module was started on an observable only to
//! find that the file wasn't named `.dmg`, that `file_type` didn't call it an email, or that no
//! module it reads the outputs of had added it (`docs/measurements/task-start.md`). A module now
//! states those checks in `Module::takes`, built from its settings. The statement is data, not
//! code, so the core can evaluate it without running a module's code on what an attacker chose:
//!
//! - the core evaluates it with `Takes::check` before it queues a task, and doesn't queue one the
//!   module would decline (`ace_core::eligibility`), and evaluates it again whenever one of the
//!   facts it reads changes, as eligibility already reruns;
//! - the pool evaluates it again on the leased task, before `analyze`
//!   (`crate::module::run_parser`, `crate::module::run_lookup`), so a task queued before a fact
//!   changed, or queued under the core's audit setting, declines the same way. The module's body
//!   doesn't repeat the checks: there is one statement of what it takes.
//!
//! A module that declares nothing takes everything its inputs, modes and directives allow, as
//! before.
//!
//! **The facts.** Only what the core holds when it decides, and what a leased task carries: the
//! observable's own type, its directives and relationships and whether it redirects; where each
//! directive came from (`Condition::DirectiveFrom`, PLAN.md decision 44); which
//! modules' results added it, and whether it came with its root's submission (`Condition::AtRoot`);
//! the root's analysis mode; a file's analysis path (its name, its
//! extension, the whole path), its size, its role and its `yara_meta` tags; a file's type, what the
//! type step found in its bytes (`TypeFacts`, PLAN.md decision 25: libmagic's description and mime
//! type and file_type's checks, as `Condition::Type` and `Condition::Mime`); and the details of the
//! observable's results from the modules it depends on (needs the module in `Module::DEPENDS_ON`).
//! `Manifest::declaration` refuses one that names a fact its module's lease wouldn't carry, so the
//! pool can always check what the core checked.
//!
//! **Reads that only decide.** Which modules added the observable, whether it came with the
//! submission, where its directives came from and the root's mode are *gating* facts: the lease carries the ones a declaration
//! reads in a part of its own (`wire::Gate`), which the pool checks the declaration on and
//! `analyze` never sees. `analyze` sees which modules added the observable only with
//! `Module::READS_ADDED_BY` and the mode only in its tree (`Module::READS_TREE`), whatever the
//! declaration reads: `TaskContext` drops what its module doesn't declare it reads. A dependency's
//! result is one too when only the declaration reads it (`Module::READS_DEPENDENCIES` false, as
//! the RDAP module reads the apex module's): the lease carries it, and `analyze` doesn't see it.
//! Since the core
//! checks a declaration before it looks a result up in the analysis cache, a fact only a
//! declaration reads can't change a result, so it doesn't keep a module out of the cache
//! (`crate::cache::refusal`), as ace3's `custom_requirement` gates its cache lookup. Nothing here reads a file's bytes: the type step
//! read them, contained, before any other task on the file was queued, and a check the type doesn't
//! state stays in `analyze`.
//!
//! **A fact only the core holds.** How the files a hash names came into the root, up the tree
//! (`Condition::HashesOnlyFilesFrom`, `FileOrigins`, PLAN.md decision 69), is the one fact a
//! lease doesn't carry: it is the walk over the tree that would keep a module that made it in
//! `analyze` out of the cache (`Module::READS_TREE`). The core loads it where a declaration reads
//! it (`Reads::file_origins`) and declines on it; on the leased task it is unknown
//! (`Facts::origins` is None), so the condition holds there, as a type condition does on a file
//! whose type is unknown.
//!
//! **A file whose type is unknown.** A file's type step can fail (a crash, its deadline), and the
//! file's other tasks are queued anyway. A condition on its type is then unknown, and a rule whose
//! condition is unknown holds (`Condition::value`): the module runs on the file, as it did when the
//! check was its own, and its own parse decides. So a failed type step never keeps a module off a
//! file it would have run on; it can only start modules that would have declined it.
//!
//! **Exactness.** A rule says what the module's own check said, never a looser or tighter guess:
//! the same subject, the same comparison, the same case rule. Each `Case` names the function a
//! module used. A rule that is false where the module would have gone on loses a detection; the
//! core's audit setting (`ACE_RS_TAKES_AUDIT`, `ace_core::takes`) is how that is looked for.
//!
//! **Writing one.** Move the checks from the top of `analyze` into `Module::takes`, in the order
//! `analyze` made them, each as a rule with the reason `analyze` gave, and delete them from
//! `analyze`. Only a check that ends the task with `Outcome::Skipped` whatever comes after it can
//! move: one that delays, fails or writes something stays. A check of the bytes moves when a fact
//! of the file's type states it exactly: `TypeFact` names each with the function that computes it
//! (`ace_mod_files::checks`, libmagic's description), and a check that is that function on the
//! same bytes, or that function and the file's name as ace3's `is_pdf_file` and
//! `is_office_document` are, is `Condition::Type`. Besides file_type's own checks the type holds the
//! first-byte tests of modules that declare on them: `IsPcapFile` (ace3's `is_pcap_file`),
//! `HasOnenoteHeader` (the bytes' half of `is_onenote_file`, whose `.one` half is
//! `Condition::Name`), `IsJavaClassFile`, `HasXmlMarker` (`<?xml` in the first KiB),
//! `IsEpsFile`, `IsEncodedScript` (`#@~^`), `HasHarHeader` and `IsImage` (Pillow's `Image.open`, the ocr
//! and qrcode modules' test). Each is the module's own test, not
//! libmagic's answer, whose rules differ at the edges (a byte-order mark before `<?xml`, pcapng's
//! byte order). A module whose test of the first bytes is none of these adds one: a field of
//! `TypeFacts`, its column in `store.file_types` with a migration, the test in
//! `ace_mod_files::checks` called by the type step, and a `TypeFact`; the type step then makes it on
//! every file it types, so it must be cheap. One that needs a parse of its own (a format's structure)
//! stays in `analyze`. A file's role, what the module that wrote it made it, is `Condition::Role`.
//! Part of a check can move when the part declines on its own, as the email module's "file_type
//! calls it an email or it has `original_email`", or `binary_file_analyzer`'s RTF fact, `\rt` or
//! `{\rt`, for its `{\rt`. The core types a file only where something reads its type, so a
//! declaration that reads it (`Reads::file_type`) is what makes a file be typed in a mode without
//! file_type. A rule that reads a dependency's result needs the dependency in `DEPENDS_ON`; a
//! lookup's rules can read a file's path but not its size, type, role or `yara_meta`, which only a
//! parser's lease carries, and a lookup's that reads its input file (`Module::READS_INPUT_FILE`). A pool refuses to start with a declaration that breaks these, and
//! `ace_app::App::modules_with_unusable_declarations` lists them for a binary's test.
//!
//! ```text
//! fn takes(settings: &MySettings) -> Takes {
//!     Takes::everything()
//!         .and(Condition::not_empty(), "an empty file")
//!         .and(Condition::Name(Text::ends_with(".dmg", Case::Lower)), "not named .dmg")
//!         .and(Condition::at_most(settings.maximum_size), "too large")
//! }
//! ```
//!
//! **Checking one.** Run the stack with `ACE_RS_TAKES_AUDIT=1` in the core's environment over
//! traffic the module sees, `tests/e2e/run` with its comparison among it. The core then queues every
//! task as if nothing were declared and marks the ones a declaration declines; the pool still checks
//! the declaration, so a marked task ends skipped. Any marked task that stored a result or failed is
//! logged at ERROR under `ace_takes` as it ends and listed by `ace_core::takes::audit_report`;
//! `tests/e2e/run` fails on one. An empty report over enough traffic is what lets the setting go.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ace_pycompat::fnmatch::fnmatch;
use ace_pycompat::pystr;
use ace_results::types::file_type::{self, TypeFacts};
use ace_results::{FileRole, ObservableKind, Relationship, RelationshipKind, YaraMeta};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::directives::{DirectiveSource, SourcedDirective};

/// What a module takes: rules that must all hold, each with the reason it gives when it doesn't.
/// No rules takes everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Takes {
    pub rules: Vec<Rule>,
}

/// One check: the module goes on only `when` this holds, and otherwise declines with `otherwise`,
/// the reason its body gave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub when: Condition,
    pub otherwise: String,
}

/// A condition over the facts. A condition on a file's facts is false for an observable that
/// isn't a file, and one on a dependency's result is false when there is no such result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    /// Every one holds; true when empty.
    All(Vec<Condition>),
    /// At least one holds; false when empty.
    Any(Vec<Condition>),
    Not(Box<Condition>),
    /// The observable's own type is one of these. A type that extends one isn't, as when a module
    /// compares the type's name.
    Kind(Vec<ObservableKind>),
    /// The observable's type is one of these or extends one (`ObservableKind::is_subtype_of`), as
    /// when a module asks ace3's type hierarchy.
    Extends(Vec<ObservableKind>),
    /// The observable has this directive.
    Directive(String),
    /// The observable has this directive from one of these sources (PLAN.md decision 44), as a
    /// module that uploads a file to a vendor takes `upload_to_scanner` only from an analyst. Its other
    /// sources don't count, nor does a directive added before ACE recorded where directives came
    /// from.
    DirectiveFrom {
        directive: String,
        sources: Vec<DirectiveSource>,
    },
    /// The observable has a relationship of this kind.
    Relationship(RelationshipKind),
    /// The observable redirects to another (`redirection`).
    Redirected,
    /// A result of this module added the observable.
    AddedBy(String),
    /// A result of a module other than these added the observable: it isn't only theirs.
    AddedByOtherThan(Vec<String>),
    /// The observable came with its root's submission, as ace3's root analysis holds it among its
    /// own observables (`root.observables`), whatever results also added it later.
    AtRoot,
    /// The root's analysis mode is this one.
    Mode(String),
    /// The file's name: the last part of its analysis path.
    Name(Text),
    /// The file's analysis path, as the module sees it.
    Path(Text),
    /// The file's extension as Python's `os.path.splitext` gives it for the name: from its last
    /// dot that isn't a leading one, with the dot; empty when there is none.
    Extension(Text),
    /// The file's mime type: libmagic's, as the type step found it (`TypeFacts::mime`). Unknown
    /// when the file's type is.
    Mime(Text),
    /// A fact of the file's type, what its bytes are (`TypeFacts`, PLAN.md decision 25). Unknown
    /// when the type step failed.
    Type(TypeFact),
    /// The file's role under its analysis path is one of these: what its producer made it, such
    /// as `email.attachment` (`FileRole`). False for a file no producer gave a role.
    Role(Vec<FileRole>),
    /// The file has this `yara_meta` tag.
    YaraMeta {
        name: String,
        value: String,
    },
    /// The file's size in bytes is in this range, both ends included.
    Size {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<u64>,
    },
    /// The observable has a result from `module`, one the module depends on.
    HasResult(String),
    /// A top-level field of that result's details passes `test`. False without the result or the
    /// field.
    Result {
        module: String,
        field: String,
        test: Field,
    },
    /// The observable names at least one file through its `is_hash_of` relationships, and every
    /// file it names came only from `module`'s results (PLAN.md decision 69), as a site's
    /// hash lookup skips hashes of content its crawler module fetched. A file came only from
    /// `module` when every result that added it ([`Origin`]) is
    ///
    /// - a result of `module` that added it at a path (`analysis.result_additions.path`) none of
    ///   `except` matches, or
    /// - a result of another module on a file that itself came only from `module`, and so on up
    ///   the tree.
    ///
    /// A file that came with the root's submission, that no result added, that a result added
    /// with no path, or that the walk reaches a second time (a cycle, or two ways up to one
    /// file) didn't: each errs toward the module running. The walk starts afresh for each file
    /// the observable names.
    ///
    /// Its value needs the root's tree, which only the core reads (`Facts::origins`), so it is
    /// unknown on a leased task and holds there: only the core declines on it. Under the core's
    /// audit setting the pool therefore runs a task the core marked on it, and the audit reports
    /// that task if it stores a result.
    ///
    /// `except` is usually `Match::Glob`s, Python's `fnmatch`, whose `*` crosses `/`: a pattern
    /// such as `crawl/*/script.js` also matches a `script.js` deeper down, which then counts as
    /// not from `module`, so the error is again toward running.
    HashesOnlyFilesFrom {
        module: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        except: Vec<Text>,
    },
}

/// How the files a declaration's observable names came into its root, for
/// `Condition::HashesOnlyFilesFrom`: each file by its sha256, with every way it came in. The core
/// loads it for the files the observables it decides on name through `is_hash_of`, and for every
/// file a result that added one of those is on, up the tree (`ace_core::takes::held`). A leased
/// task doesn't carry it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileOrigins {
    pub files: BTreeMap<String, Vec<Origin>>,
}

/// One way a file came into its root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    /// With the root's submission (`Condition::AtRoot`).
    Submission,
    /// A result of `module` added it, at `path`. `on_file` is the sha256 of the file the result
    /// is on, or None when the result is on an observable that isn't a file.
    Result {
        module: String,
        path: Option<String>,
        on_file: Option<String>,
    },
}

impl FileOrigins {
    /// Whether `file` came only from `module`'s results, at paths none of `except` matches
    /// (`Condition::HashesOnlyFilesFrom`). `seen` holds the files this walk has reached.
    fn only_from(
        &self,
        file: &str,
        module: &str,
        except: &[Text],
        seen: &mut BTreeSet<String>,
    ) -> bool {
        // a second visit is a cycle or a second way up: it errs toward running
        if !seen.insert(file.to_owned()) {
            return false;
        }
        let origins = self.files.get(file).map(Vec::as_slice).unwrap_or_default();
        !origins.is_empty()
            && origins.iter().all(|origin| match origin {
                Origin::Submission => false,
                Origin::Result {
                    module: adder,
                    path,
                    ..
                } if adder == module => path
                    .as_deref()
                    .is_some_and(|path| !except.iter().any(|text| text.matches(path))),
                Origin::Result { on_file, .. } => on_file
                    .as_deref()
                    .is_some_and(|parent| self.only_from(parent, module, except, seen)),
            })
    }
}

/// A fact of a file's type, as `TypeFacts` holds it or as ace3's `file_type` computed it from the
/// facts and the file's name. Each is the function the modules called on the bytes, so a rule on
/// one says exactly what the module's own check said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TypeFact {
    /// libmagic's description passes the test.
    Description(Text),
    /// The OLE compound file signature at the start (`checks::is_ole_file`).
    IsOleFile,
    /// `\rt` or `{\rt` at the start (`checks::is_rtf_file`).
    IsRtfFile,
    /// `%PDF-` in the first 1024 bytes, whatever the name.
    HasPdfMarker,
    /// ace3's `is_pdf_file`: the marker, for a name not ending in `.pdfparser`.
    IsPdfFile,
    /// `MZ` at the start (`checks::is_pe_file`).
    IsPeFile,
    /// Python's `zipfile` lists at least one name.
    IsZipFile,
    /// A zip with `META-INF/MANIFEST.MF`.
    IsJarFile,
    /// A certificate cryptography loads.
    IsX509,
    /// The Windows shortcut header at the start (`checks::is_lnk_file`).
    IsLnkFile,
    /// ace3's `is_email_file`, or the mime type `message/rfc822`.
    IsEmailFile,
    /// ace3's `is_office_document`: an Office extension on the name, an Office format in the
    /// description, or an OLE or RTF file.
    IsOfficeDocument,
    /// What ace3's file_type tags `script.javascript`: the mime type or the name says JavaScript and
    /// node parses it with a keyword in it.
    IsJavascript,
    /// ace3's `is_pcap_file`: a pcap magic number, or a pcapng section header with its byte-order
    /// magic (`checks::is_pcap_file`).
    IsPcapFile,
    /// OneNote's header GUID in the first 16 bytes, the bytes' part of ace3's `is_onenote_file`
    /// (`checks::has_onenote_header`); its other part, a `.one` name, is `Condition::Name`.
    HasOnenoteHeader,
    /// `CAFEBABE` at the start, ace3's `is_java_class_file` (`checks::is_java_class_file`).
    IsJavaClassFile,
    /// `<?xml` in the first 1024 bytes (`checks::has_xml_marker`).
    HasXmlMarker,
    /// The EPS binary header or `%!PS-Adobe-` at the start, ace3's `_is_eps`
    /// (`checks::is_eps_file`).
    IsEpsFile,
    /// `#@~^` at the start (`checks::is_encoded_script`).
    IsEncodedScript,
    /// ace3's `is_har_header` on the first 4096 bytes (`checks::has_har_header`).
    HasHarHeader,
    /// Pillow would open it, by its first 1024 bytes: the test ace3's ocr and qrcode modules make
    /// before anything else (`ace_mod_files::pillow`).
    IsImage,
}

impl TypeFact {
    /// Its value for a file at `path` with these facts.
    pub fn of(&self, facts: &TypeFacts, path: &str) -> bool {
        match self {
            TypeFact::Description(text) => text.matches(&facts.description),
            TypeFact::IsOleFile => facts.is_ole_file,
            TypeFact::IsRtfFile => facts.is_rtf_file,
            TypeFact::HasPdfMarker => facts.has_pdf_marker,
            TypeFact::IsPdfFile => file_type::is_pdf_file(path, facts.has_pdf_marker),
            TypeFact::IsPeFile => facts.is_pe_file,
            TypeFact::IsZipFile => facts.is_zip_file,
            TypeFact::IsJarFile => facts.is_jar_file,
            TypeFact::IsX509 => facts.is_x509,
            TypeFact::IsLnkFile => facts.is_lnk_file,
            TypeFact::IsEmailFile => facts.is_email_file,
            TypeFact::IsOfficeDocument => facts.is_office_document(path),
            TypeFact::IsJavascript => facts.is_javascript(path),
            TypeFact::IsPcapFile => facts.is_pcap_file,
            TypeFact::HasOnenoteHeader => facts.has_onenote_header,
            TypeFact::IsJavaClassFile => facts.is_java_class_file,
            TypeFact::HasXmlMarker => facts.has_xml_marker,
            TypeFact::IsEpsFile => facts.is_eps_file,
            TypeFact::IsEncodedScript => facts.is_encoded_script,
            TypeFact::HasHarHeader => facts.has_har_header,
            TypeFact::IsImage => facts.is_image,
        }
    }
}

/// What a field of a dependency's result must be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Field {
    /// The boolean `true`.
    True,
    /// A string that passes the test.
    Text(Text),
}

/// A test on a string, after the case rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Text {
    pub test: Match,
    #[serde(default)]
    pub case: Case,
}

/// How a string is compared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Match {
    Equals(String),
    StartsWith(String),
    EndsWith(String),
    Contains(String),
    /// Equal to one of these.
    OneOf(Vec<String>),
    /// Python's `fnmatch.fnmatch` on POSIX, case-sensitive, of `prefix` and the string together.
    Glob {
        pattern: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        prefix: String,
    },
    /// Not empty.
    NotEmpty,
}

/// The case rule a module's comparison used. The pattern is compared as written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Case {
    /// Byte for byte.
    #[default]
    Exact,
    /// ASCII letters in either case, as `str::eq_ignore_ascii_case`.
    Ascii,
    /// The string lowered as Python's `str.lower` lowers it (`ace_pycompat::pystr::lower`). Rust's
    /// `str::to_lowercase` lowers to the same ASCII characters: the only characters either lowers
    /// to ASCII are ASCII letters, `U+212A` (Kelvin) and `U+0130` (to `i` and a combining dot), the
    /// same in both, so with a pattern in ASCII the two compare alike.
    Lower,
}

/// The facts a declaration is checked against, as the core holds them when it queues a task and as
/// a leased task carries them.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    pub kind: ObservableKind,
    pub directives: &'a [String],
    /// Where each of its directives came from, one entry for each directive and source; read only
    /// by `Condition::DirectiveFrom`.
    pub directive_sources: &'a [SourcedDirective],
    pub relationships: &'a [Relationship],
    pub redirected: bool,
    /// The modules whose results added the observable; read only by `Condition::AddedBy` and
    /// `Condition::AddedByOtherThan`.
    pub added_by: &'a [String],
    /// The observable came with its root's submission (`Condition::AtRoot`).
    pub at_root: bool,
    pub mode: Option<&'a str>,
    pub file: Option<FileFacts<'a>>,
    /// The details of the observable's results from the modules the module depends on, by module.
    pub results: &'a BTreeMap<String, Value>,
    /// How the files it names through `is_hash_of` came into the root; read only by
    /// `Condition::HashesOnlyFilesFrom`. None where it isn't known, as on a leased task, which
    /// makes that condition unknown.
    pub origins: Option<&'a FileOrigins>,
}

/// A file observable's facts.
#[derive(Debug, Clone, Copy)]
pub struct FileFacts<'a> {
    /// The path it is analyzed under (PLAN.md decision 15).
    pub path: &'a str,
    /// Its size, its type, its role and its `yara_meta` tags: what a parser's lease carries with
    /// the bytes, and a lookup's that reads its input file (`Module::READS_INPUT_FILE`). Another
    /// lookup's lease carries the path alone, so these are None for it, and
    /// `Manifest::declaration` refuses its rule that reads them.
    pub size: Option<u64>,
    /// What its bytes are, as the type step found them; None when its type is unknown.
    pub facts: Option<&'a TypeFacts>,
    pub role: Option<FileRole>,
    pub yara_meta: Option<&'a [YaraMeta]>,
}

/// What a declaration reads that a lease carries only for some modules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reads {
    pub added_by: bool,
    /// Where the observable's directives came from (`Condition::DirectiveFrom`).
    pub directive_sources: bool,
    /// Whether the observable came with its root's submission (`Condition::AtRoot`).
    pub at_root: bool,
    pub mode: bool,
    /// A file's size, mime type or `yara_meta`, which only a parser's lease carries.
    pub file_record: bool,
    /// A file's type (`Condition::Type`, `Condition::Mime`): the core types a file only where
    /// something reads its type (`ace_core::type_step`).
    pub file_type: bool,
    /// The modules whose results it reads.
    pub results: Vec<String>,
    /// How the files it names came into the root (`Condition::HashesOnlyFilesFrom`), which only
    /// the core reads.
    pub file_origins: bool,
}

impl Takes {
    /// Takes everything the core's other rules allow: a module that declares nothing.
    pub fn everything() -> Takes {
        Takes::default()
    }

    /// These rules and one more, checked after them.
    pub fn and(mut self, when: Condition, otherwise: impl Into<String>) -> Takes {
        self.rules.push(Rule {
            when,
            otherwise: otherwise.into(),
        });
        self
    }

    /// True when it declares nothing.
    pub fn is_everything(&self) -> bool {
        self.rules.is_empty()
    }

    /// Ok when the module takes an observable with these facts, else the reason of the first rule
    /// that doesn't hold.
    pub fn check(&self, facts: &Facts<'_>) -> Result<(), &str> {
        match self.rules.iter().find(|rule| !rule.when.holds(facts)) {
            Some(rule) => Err(&rule.otherwise),
            None => Ok(()),
        }
    }

    /// What it reads that a lease carries only on request.
    pub fn reads(&self) -> Reads {
        let mut reads = Reads::default();
        for rule in &self.rules {
            rule.when.collect_reads(&mut reads);
        }
        reads.results.sort();
        reads.results.dedup();
        reads
    }

    /// The declaration as JSON, for a module's description.
    pub fn describe(&self) -> Value {
        serde_json::to_value(&self.rules).unwrap_or(Value::Null)
    }
}

impl Condition {
    /// Holds when this doesn't.
    pub fn negated(self) -> Condition {
        Condition::Not(Box::new(self))
    }

    pub fn directive(name: &str) -> Condition {
        Condition::Directive(name.to_owned())
    }

    /// The observable has the directive `name` from one of `sources`.
    pub fn directive_from(name: &str, sources: &[DirectiveSource]) -> Condition {
        Condition::DirectiveFrom {
            directive: name.to_owned(),
            sources: sources.to_vec(),
        }
    }

    pub fn added_by(module: &str) -> Condition {
        Condition::AddedBy(module.to_owned())
    }

    /// A result of a module other than `modules` added the observable.
    pub fn added_by_other_than(modules: &[&str]) -> Condition {
        Condition::AddedByOtherThan(modules.iter().map(|m| (*m).to_owned()).collect())
    }

    pub fn yara_meta(name: &str, value: &str) -> Condition {
        Condition::YaraMeta {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    /// The file isn't empty.
    pub fn type_fact(fact: TypeFact) -> Condition {
        Condition::Type(fact)
    }

    pub fn role(role: FileRole) -> Condition {
        Condition::Role(vec![role])
    }

    pub fn not_empty() -> Condition {
        Condition::Size {
            min: Some(1),
            max: None,
        }
    }

    /// The file is at most `max` bytes.
    pub fn at_most(max: u64) -> Condition {
        Condition::Size {
            min: None,
            max: Some(max),
        }
    }

    /// The dependency's boolean field is true.
    pub fn result_true(module: &str, field: &str) -> Condition {
        Condition::Result {
            module: module.to_owned(),
            field: field.to_owned(),
            test: Field::True,
        }
    }

    /// The dependency's string field passes `text`.
    pub fn result_text(module: &str, field: &str, text: Text) -> Condition {
        Condition::Result {
            module: module.to_owned(),
            field: field.to_owned(),
            test: Field::Text(text),
        }
    }

    /// Whether it holds for these facts. A condition whose value is unknown, one on the type of a
    /// file whose type step failed, holds, so a failure never keeps a module off a file
    /// (`Condition::value`).
    pub fn holds(&self, facts: &Facts<'_>) -> bool {
        self.value(facts) != Some(false)
    }

    /// Its value for these facts, or None when it reads a file's type and that is unknown, or how
    /// files came into the root where that isn't known (`Facts::origins`). `All`,
    /// `Any` and `Not` follow: all known and true, one true, or the negation, with an unknown part
    /// unknown unless the rest decides it.
    pub fn value(&self, facts: &Facts<'_>) -> Option<bool> {
        match self {
            Condition::All(all) => {
                let mut unknown = false;
                for c in all {
                    match c.value(facts) {
                        Some(false) => return Some(false),
                        None => unknown = true,
                        Some(true) => {}
                    }
                }
                (!unknown).then_some(true)
            }
            Condition::Any(any) => {
                let mut unknown = false;
                for c in any {
                    match c.value(facts) {
                        Some(true) => return Some(true),
                        None => unknown = true,
                        Some(false) => {}
                    }
                }
                (!unknown).then_some(false)
            }
            Condition::Not(inner) => inner.value(facts).map(|v| !v),
            Condition::Mime(text) => type_value(facts, |t, _| text.matches(&t.mime)),
            Condition::Type(fact) => type_value(facts, |t, path| fact.of(t, path)),
            Condition::HashesOnlyFilesFrom { module, except } => {
                let files: Vec<&str> = facts
                    .relationships
                    .iter()
                    .filter(|r| {
                        r.kind == RelationshipKind::IsHashOf
                            && r.target.kind == ObservableKind::File
                    })
                    .map(|r| r.target.value.as_str())
                    .collect();
                if files.is_empty() {
                    return Some(false);
                }
                let origins = facts.origins?;
                Some(
                    files
                        .iter()
                        .all(|file| origins.only_from(file, module, except, &mut BTreeSet::new())),
                )
            }
            other => Some(other.known(facts)),
        }
    }

    /// The value of a condition that reads nothing that can be unknown.
    fn known(&self, facts: &Facts<'_>) -> bool {
        match self {
            Condition::Kind(kinds) => kinds.contains(&facts.kind),
            Condition::Extends(kinds) => kinds.iter().any(|k| facts.kind.is_subtype_of(*k)),
            Condition::Directive(name) => facts.directives.iter().any(|d| d == name),
            Condition::DirectiveFrom { directive, sources } => facts
                .directive_sources
                .iter()
                .any(|d| d.directive == *directive && sources.contains(&d.source)),
            Condition::Relationship(kind) => facts.relationships.iter().any(|r| r.kind == *kind),
            Condition::Redirected => facts.redirected,
            Condition::AddedBy(module) => facts.added_by.iter().any(|m| m == module),
            Condition::AddedByOtherThan(modules) => {
                facts.added_by.iter().any(|m| !modules.contains(m))
            }
            Condition::AtRoot => facts.at_root,
            Condition::Mode(mode) => facts.mode == Some(mode.as_str()),
            Condition::Name(text) => facts.file.is_some_and(|f| text.matches(name(f.path))),
            Condition::Path(text) => facts.file.is_some_and(|f| text.matches(f.path)),
            Condition::Extension(text) => facts
                .file
                .is_some_and(|f| text.matches(splitext(name(f.path)).1)),
            Condition::Role(roles) => facts
                .file
                .is_some_and(|f| f.role.is_some_and(|role| roles.contains(&role))),
            Condition::YaraMeta { name, value } => facts.file.is_some_and(|f| {
                f.yara_meta
                    .unwrap_or_default()
                    .iter()
                    .any(|m| m.name() == name && m.value() == value)
            }),
            Condition::Size { min, max } => facts.file.and_then(|f| f.size).is_some_and(|size| {
                min.is_none_or(|min| size >= min) && max.is_none_or(|max| size <= max)
            }),
            Condition::HasResult(module) => facts.results.contains_key(module),
            Condition::Result {
                module,
                field,
                test,
            } => facts
                .results
                .get(module)
                .and_then(|details| details.get(field))
                .is_some_and(|value| match (test, value) {
                    (Field::True, Value::Bool(b)) => *b,
                    (Field::Text(text), Value::String(s)) => text.matches(s),
                    _ => false,
                }),
            Condition::All(_)
            | Condition::Any(_)
            | Condition::Not(_)
            | Condition::Mime(_)
            | Condition::Type(_)
            | Condition::HashesOnlyFilesFrom { .. } => self.value(facts) == Some(true),
        }
    }

    fn collect_reads(&self, reads: &mut Reads) {
        match self {
            Condition::All(all) | Condition::Any(all) => {
                all.iter().for_each(|c| c.collect_reads(reads));
            }
            Condition::Not(inner) => inner.collect_reads(reads),
            Condition::AddedBy(_) | Condition::AddedByOtherThan(_) => reads.added_by = true,
            Condition::AtRoot => reads.at_root = true,
            Condition::DirectiveFrom { .. } => reads.directive_sources = true,
            Condition::Mode(_) => reads.mode = true,
            Condition::Mime(_) | Condition::Type(_) => {
                reads.file_record = true;
                reads.file_type = true;
            }
            Condition::Role(_) | Condition::YaraMeta { .. } | Condition::Size { .. } => {
                reads.file_record = true;
            }
            Condition::HasResult(module) | Condition::Result { module, .. } => {
                reads.results.push(module.clone());
            }
            Condition::HashesOnlyFilesFrom { .. } => reads.file_origins = true,
            _ => {}
        }
    }
}

impl Text {
    pub fn new(test: Match, case: Case) -> Text {
        Text { test, case }
    }

    pub fn exact(test: Match) -> Text {
        Text::new(test, Case::Exact)
    }

    pub fn ends_with(suffix: &str, case: Case) -> Text {
        Text::new(Match::EndsWith(suffix.to_owned()), case)
    }

    pub fn equals(value: &str) -> Text {
        Text::exact(Match::Equals(value.to_owned()))
    }

    pub fn contains(value: &str) -> Text {
        Text::exact(Match::Contains(value.to_owned()))
    }

    /// Whether `subject` passes.
    pub fn matches(&self, subject: &str) -> bool {
        match self.case {
            Case::Exact => self.test.matches(subject, |a, b| a == b),
            Case::Ascii => self.test.matches(subject, |a, b| a.eq_ignore_ascii_case(b)),
            Case::Lower => self.test.matches(&pystr::lower(subject), |a, b| a == b),
        }
    }
}

impl Match {
    fn matches(&self, subject: &str, same: impl Fn(&str, &str) -> bool) -> bool {
        let suffix = |suffix: &str| {
            subject.len() >= suffix.len()
                && subject.is_char_boundary(subject.len() - suffix.len())
                && same(&subject[subject.len() - suffix.len()..], suffix)
        };
        match self {
            Match::Equals(value) => same(subject, value),
            Match::StartsWith(value) => {
                subject.len() >= value.len()
                    && subject.is_char_boundary(value.len())
                    && same(&subject[..value.len()], value)
            }
            Match::EndsWith(value) => suffix(value),
            Match::Contains(value) => {
                if value.is_empty() {
                    return true;
                }
                subject.char_indices().any(|(at, _)| {
                    subject.len() - at >= value.len()
                        && subject.is_char_boundary(at + value.len())
                        && same(&subject[at..at + value.len()], value)
                })
            }
            Match::OneOf(values) => values.iter().any(|v| same(subject, v)),
            Match::Glob { pattern, prefix } => fnmatch(&format!("{prefix}{subject}"), pattern),
            Match::NotEmpty => !subject.is_empty(),
        }
    }
}

impl fmt::Display for Takes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.describe())
    }
}

/// A condition on a file's type: false for an observable that isn't a file, unknown for a file
/// whose type is.
fn type_value(facts: &Facts<'_>, of: impl Fn(&TypeFacts, &str) -> bool) -> Option<bool> {
    match facts.file {
        Some(file) => file.facts.map(|t| of(t, file.path)),
        None => Some(false),
    }
}

/// The last part of a path.
fn name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `os.path.splitext(name)`: the name and its last extension, with its dot; a leading dot isn't
/// one.
pub fn splitext(name: &str) -> (&str, &str) {
    let start = name.len() - name.trim_start_matches('.').len();
    match name[start..].rfind('.') {
        Some(dot) => name.split_at(start + dot),
        None => (name, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn file_facts<'a>(
        path: &'a str,
        size: u64,
        results: &'a BTreeMap<String, Value>,
        yara_meta: &'a [YaraMeta],
    ) -> Facts<'a> {
        Facts {
            kind: ObservableKind::File,
            directives: &[],
            directive_sources: &[],
            relationships: &[],
            redirected: false,
            added_by: &[],
            at_root: false,
            mode: None,
            file: Some(FileFacts {
                path,
                size: Some(size),
                facts: None,
                role: None,
                yara_meta: Some(yara_meta),
            }),
            results,
            origins: None,
        }
    }

    #[test]
    fn the_first_rule_that_fails_gives_the_reason() {
        let takes = Takes::everything()
            .and(Condition::not_empty(), "an empty file")
            .and(
                Condition::Name(Text::ends_with(".dmg", Case::Lower)),
                "not named .dmg",
            );
        let none = BTreeMap::new();
        assert_eq!(takes.check(&file_facts("a/b.DMG", 1, &none, &[])), Ok(()));
        assert_eq!(
            takes.check(&file_facts("a/b.dmg", 0, &none, &[])),
            Err("an empty file")
        );
        assert_eq!(
            takes.check(&file_facts("a.dmg/b", 3, &none, &[])),
            Err("not named .dmg")
        );
        assert!(
            Takes::everything()
                .check(&file_facts("x", 0, &none, &[]))
                .is_ok()
        );
    }

    #[test]
    fn each_case_rule_lowers_as_its_function_does() {
        let lower = Text::ends_with(".dmg", Case::Lower);
        let ascii = Text::ends_with(".dmg", Case::Ascii);
        let exact = Text::ends_with(".dmg", Case::Exact);
        for subject in ["x.dmg", "x.DMG", "x.Dmg"] {
            assert!(
                lower.matches(subject) && ascii.matches(subject),
                "{subject}"
            );
        }
        assert!(exact.matches("x.dmg") && !exact.matches("x.DMG"));
        // the Kelvin sign lowers to an ASCII k in Python and in Rust, and isn't one in ASCII
        let k = Text::ends_with(".k", Case::Lower);
        assert!(k.matches("x.\u{212a}"));
        assert_eq!("x.\u{212a}".to_lowercase(), pystr::lower("x.\u{212a}"));
        assert!(!Text::ends_with(".k", Case::Ascii).matches("x.\u{212a}"));
        // a suffix that starts inside a character never matches
        assert!(!Text::ends_with("\u{80}", Case::Exact).matches("\u{100}"));
        assert!(Text::contains("rfc822").matches("message/rfc822"));
        let image = Text::new(Match::StartsWith("image/".to_owned()), Case::Lower);
        assert!(image.matches("IMAGE/png") && !image.matches("x-image/png"));
        assert!(!Text::new(Match::StartsWith("\u{80}".to_owned()), Case::Exact).matches("\u{100}"));
        assert!(!Text::contains("rfc822").matches("message/rfc82"));
        assert!(
            Text::exact(Match::Glob {
                pattern: "*.pcap".to_owned(),
                prefix: "/opt/ace/data/root/".to_owned()
            })
            .matches("a/b.pcap")
        );
    }

    #[test]
    fn a_file_condition_is_false_for_an_observable_that_isnt_a_file() {
        let none = BTreeMap::new();
        let facts = Facts {
            kind: ObservableKind::Fqdn,
            directives: &[],
            directive_sources: &[],
            relationships: &[],
            redirected: false,
            added_by: &[],
            at_root: false,
            mode: None,
            file: None,
            results: &none,
            origins: None,
        };
        for condition in [
            Condition::not_empty(),
            Condition::Name(Text::exact(Match::NotEmpty)),
            Condition::Path(Text::exact(Match::NotEmpty)),
            Condition::Extension(Text::exact(Match::Equals(String::new()))),
            Condition::Mime(Text::exact(Match::NotEmpty)),
            Condition::yara_meta("type", "x"),
        ] {
            assert!(!condition.holds(&facts), "{condition:?}");
            assert!(condition.clone().negated().holds(&facts), "{condition:?}");
        }
    }

    #[test]
    fn a_result_condition_reads_a_field_of_the_dependency() {
        let results = BTreeMap::from([(
            "file_type".to_owned(),
            json!({"mime": "message/rfc822", "is_x509": true, "is_zip_file": false}),
        )]);
        let facts = file_facts("a", 1, &results, &[]);
        assert!(Condition::result_true("file_type", "is_x509").holds(&facts));
        assert!(!Condition::result_true("file_type", "is_zip_file").holds(&facts));
        assert!(!Condition::result_true("file_type", "missing").holds(&facts));
        assert!(!Condition::result_true("other", "is_x509").holds(&facts));
        assert!(
            Condition::result_text("file_type", "mime", Text::equals("message/rfc822"))
                .holds(&facts)
        );
        // a string field isn't true, and a boolean doesn't match text
        assert!(!Condition::result_true("file_type", "mime").holds(&facts));
        assert!(
            !Condition::result_text("file_type", "is_x509", Text::exact(Match::NotEmpty))
                .holds(&facts)
        );
        assert!(Condition::HasResult("file_type".to_owned()).holds(&facts));
    }

    #[test]
    fn a_type_condition_reads_the_facts_and_holds_when_the_type_is_unknown() {
        let none = BTreeMap::new();
        let pdf = TypeFacts {
            description: "PDF document, version 1.4".to_owned(),
            mime: "application/pdf".to_owned(),
            has_pdf_marker: true,
            ..TypeFacts::default()
        };
        let mut facts = file_facts("a/b.pdf", 3, &none, &[]);
        let is_pdf = Condition::type_fact(TypeFact::IsPdfFile);
        let is_pe = Condition::type_fact(TypeFact::IsPeFile);
        let mime = Condition::Mime(Text::equals("application/pdf"));
        // unknown: every type condition holds, negated or not, alone or among others
        for c in [&is_pdf, &is_pe, &mime] {
            assert_eq!(c.value(&facts), None);
            assert!(
                c.holds(&facts) && c.clone().negated().holds(&facts),
                "{c:?}"
            );
        }
        assert!(Condition::All(vec![is_pe.clone(), Condition::not_empty()]).holds(&facts));
        // ...unless a known part decides it
        assert!(!Condition::All(vec![is_pe.clone(), Condition::at_most(1)]).holds(&facts));
        assert!(Condition::Any(vec![is_pe.clone(), Condition::not_empty()]).holds(&facts));
        if let Some(file) = facts.file.as_mut() {
            file.facts = Some(&pdf);
        }
        assert!(is_pdf.holds(&facts) && mime.holds(&facts) && !is_pe.holds(&facts));
        assert!(
            Condition::type_fact(TypeFact::Description(Text::new(
                Match::Contains("pdf".to_owned()),
                Case::Lower
            )))
            .holds(&facts)
        );
        // is_pdf_file reads the name
        let parsed = FileFacts {
            path: "a/b.pdfparser",
            ..facts.file.expect("a file")
        };
        let parsed = Facts {
            file: Some(parsed),
            ..facts
        };
        assert!(!is_pdf.holds(&parsed));
        assert!(Condition::type_fact(TypeFact::HasPdfMarker).holds(&parsed));
        // a type condition on something that isn't a file is false, as other file conditions are
        let fqdn = Facts {
            kind: ObservableKind::Fqdn,
            file: None,
            ..facts
        };
        assert!(!is_pdf.holds(&fqdn) && is_pdf.clone().negated().holds(&fqdn));
        let reads = Takes::everything().and(is_pe, "not a PE").reads();
        assert!(reads.file_record && reads.file_type);
        let reads = Takes::everything()
            .and(Condition::not_empty(), "an empty file")
            .reads();
        assert!(reads.file_record && !reads.file_type);
    }

    #[test]
    fn a_role_condition_reads_the_path_s_role() {
        let none = BTreeMap::new();
        let mut facts = file_facts("a/b", 1, &none, &[]);
        let attachment = Condition::role(FileRole::EMAIL_ATTACHMENT);
        assert!(!attachment.holds(&facts));
        if let Some(file) = facts.file.as_mut() {
            file.role = Some(FileRole::EMAIL_ATTACHMENT);
        }
        assert!(attachment.holds(&facts));
        assert!(!Condition::role(FileRole::EMAIL).holds(&facts));
        let back: Condition =
            serde_json::from_value(serde_json::to_value(&attachment).expect("writes"))
                .expect("reads");
        assert_eq!(back, attachment);
    }

    /// Where an observable came from: with its root's submission, from which modules' results, and
    /// a type that extends another.
    #[test]
    fn lineage_and_type_conditions_read_their_facts() {
        let none = BTreeMap::new();
        let added = ["device_lookup".to_owned()];
        let mut facts = Facts {
            kind: ObservableKind::EmailFrom,
            directives: &[],
            directive_sources: &[],
            relationships: &[],
            redirected: false,
            added_by: &added,
            at_root: false,
            mode: None,
            file: None,
            results: &none,
            origins: None,
        };
        let others = Condition::added_by_other_than(&["device_lookup"]);
        assert!(!Condition::AtRoot.holds(&facts));
        assert!(!others.holds(&facts));
        assert!(Condition::added_by("device_lookup").holds(&facts));
        let both = ["device_lookup".to_owned(), "email_analyzer".to_owned()];
        facts.added_by = &both;
        assert!(others.holds(&facts));
        facts.at_root = true;
        assert!(Condition::AtRoot.holds(&facts));
        // a subtype extends its parent, and isn't its parent's own type
        assert!(Condition::Extends(vec![ObservableKind::EmailAddress]).holds(&facts));
        assert!(!Condition::Kind(vec![ObservableKind::EmailAddress]).holds(&facts));
        let reads = Takes::everything()
            .and(Condition::AtRoot, "x")
            .and(others, "y")
            .reads();
        assert!(reads.at_root && reads.added_by && !reads.mode);
        let back: Condition =
            serde_json::from_value(serde_json::to_value(Condition::AtRoot).expect("writes"))
                .expect("reads");
        assert_eq!(back, Condition::AtRoot);
    }

    /// A directive's source, which a declaration reads alone: the same directive from a hunt
    /// doesn't hold where it must be an analyst's.
    #[test]
    fn a_directive_from_holds_only_for_the_sources_it_names() {
        let none = BTreeMap::new();
        let directives = ["upload_to_scanner".to_owned()];
        let hunt = [SourcedDirective::new(
            "upload_to_scanner",
            DirectiveSource::Hunt,
        )];
        let mut facts = Facts {
            kind: ObservableKind::File,
            directives: &directives,
            directive_sources: &hunt,
            relationships: &[],
            redirected: false,
            added_by: &[],
            at_root: true,
            mode: None,
            file: None,
            results: &none,
            origins: None,
        };
        let analyst = Condition::directive_from("upload_to_scanner", &[DirectiveSource::Analyst]);
        assert!(Condition::directive("upload_to_scanner").holds(&facts));
        assert!(!analyst.holds(&facts));
        assert!(
            Condition::directive_from(
                "upload_to_scanner",
                &[DirectiveSource::Hunt, DirectiveSource::Analyst]
            )
            .holds(&facts)
        );
        let both = [
            SourcedDirective::new("upload_to_scanner", DirectiveSource::Hunt),
            SourcedDirective::new("upload_to_scanner", DirectiveSource::Analyst),
        ];
        facts.directive_sources = &both;
        assert!(analyst.holds(&facts));
        // another directive of the analyst's isn't this one
        let other = [SourcedDirective::new("crawl", DirectiveSource::Analyst)];
        facts.directive_sources = &other;
        assert!(!analyst.holds(&facts));
        // a directive with no recorded source, as one added before sources were recorded
        facts.directive_sources = &[];
        assert!(!analyst.holds(&facts) && analyst.clone().negated().holds(&facts));
        let reads = Takes::everything()
            .and(analyst.clone(), "not asked by an analyst")
            .reads();
        assert!(reads.directive_sources && !reads.added_by && !reads.file_record);
        let back: Condition =
            serde_json::from_value(serde_json::to_value(&analyst).expect("writes")).expect("reads");
        assert_eq!(back, analyst);
        assert_eq!(
            serde_json::to_value(&analyst).expect("writes"),
            json!({"directive_from": {"directive": "upload_to_scanner", "sources": ["analyst"]}})
        );
    }

    /// A hash whose files came only from the crawler, at paths it doesn't except, directly or as
    /// something extracted from such a file; unknown without the origins, as on a lease.
    #[test]
    fn hashes_only_files_from_walks_up_the_files_origins() {
        let none = BTreeMap::new();
        let crawled = Condition::HashesOnlyFilesFrom {
            module: "crawler".to_owned(),
            except: vec![
                Text::exact(Match::Glob {
                    pattern: "crawl/*/downloads/*".to_owned(),
                    prefix: String::new(),
                }),
                Text::exact(Match::Glob {
                    pattern: "crawl/*/script.js".to_owned(),
                    prefix: String::new(),
                }),
            ],
        };
        let by = |module: &str, path: Option<&str>, on_file: Option<&str>| Origin::Result {
            module: module.to_owned(),
            path: path.map(str::to_owned),
            on_file: on_file.map(str::to_owned),
        };
        let origins = FileOrigins {
            files: BTreeMap::from([
                (
                    "page".to_owned(),
                    vec![by("crawler", Some("crawl/j/dom.html"), None)],
                ),
                (
                    "payload".to_owned(),
                    vec![by("crawler", Some("crawl/j/downloads/x.zip"), None)],
                ),
                (
                    "script".to_owned(),
                    vec![by("crawler", Some("crawl/j/script.js"), None)],
                ),
                // fnmatch's * crosses /, so a deeper script.js is a payload too
                (
                    "deep".to_owned(),
                    vec![by("crawler", Some("crawl/j/a/script.js"), None)],
                ),
                ("pathless".to_owned(), vec![by("crawler", None, None)]),
                (
                    "inner".to_owned(),
                    vec![by("unpacker", Some("dom.html.extracted/i"), Some("page"))],
                ),
                (
                    "unpacked".to_owned(),
                    vec![by("unpacker", Some("x.zip.extracted/i"), Some("payload"))],
                ),
                (
                    "both".to_owned(),
                    vec![
                        by("crawler", Some("crawl/j/b.html"), None),
                        by("mailer", Some("attachment"), Some("email")),
                    ],
                ),
                ("email".to_owned(), vec![Origin::Submission]),
                (
                    "submitted".to_owned(),
                    vec![
                        by("crawler", Some("crawl/j/s.html"), None),
                        Origin::Submission,
                    ],
                ),
                (
                    "from_url".to_owned(),
                    vec![by("downloader", Some("d/x.html"), None)],
                ),
                // a cycle: each was added by a result on the other, and one by the crawler too
                (
                    "loop_a".to_owned(),
                    vec![
                        by("crawler", Some("crawl/j/l.html"), None),
                        by("unpacker", Some("b/a"), Some("loop_b")),
                    ],
                ),
                (
                    "loop_b".to_owned(),
                    vec![by("unpacker", Some("a/b"), Some("loop_a"))],
                ),
            ]),
        };
        let hash_of = |files: &[&str]| -> Vec<Relationship> {
            files
                .iter()
                .map(|f| {
                    Relationship::new(
                        RelationshipKind::IsHashOf,
                        ace_results::ObservableRef::new(ObservableKind::File, *f),
                    )
                })
                .collect()
        };
        let value = |files: &[&str], origins: Option<&FileOrigins>| {
            let relationships = hash_of(files);
            let facts = Facts {
                kind: ObservableKind::Sha256,
                directives: &[],
                directive_sources: &[],
                relationships: &relationships,
                redirected: false,
                added_by: &[],
                at_root: false,
                mode: None,
                file: None,
                results: &none,
                origins,
            };
            crawled.value(&facts)
        };
        let known = Some(&origins);
        assert_eq!(value(&["page"], known), Some(true));
        assert_eq!(value(&["inner"], known), Some(true));
        assert_eq!(value(&["page", "inner"], known), Some(true));
        for not in [
            &["payload"][..],
            &["script"],
            &["deep"],
            &["pathless"],
            &["unpacked"],
            &["both"],
            &["email"],
            &["submitted"],
            &["from_url"],
            &["loop_a"],
            &["loop_b"],
            &["unknown_file"],
            &["page", "payload"],
            &[],
        ] {
            assert_eq!(value(not, known), Some(false), "{not:?}");
        }
        // unknown on a lease, so it holds negated or not; a hash naming no file is still known
        assert_eq!(value(&["page"], None), None);
        assert_eq!(value(&[], None), Some(false));
        let relationships = hash_of(&["page"]);
        let lease = Facts {
            kind: ObservableKind::Sha256,
            directives: &[],
            directive_sources: &[],
            relationships: &relationships,
            redirected: false,
            added_by: &[],
            at_root: false,
            mode: None,
            file: None,
            results: &none,
            origins: None,
        };
        assert!(crawled.holds(&lease) && crawled.clone().negated().holds(&lease));
        // a relationship of another kind, or to something that isn't a file, names no file
        let other = vec![
            Relationship::new(
                RelationshipKind::ExtractedFrom,
                ace_results::ObservableRef::new(ObservableKind::File, "page"),
            ),
            Relationship::new(
                RelationshipKind::IsHashOf,
                ace_results::ObservableRef::new(ObservableKind::Url, "page"),
            ),
        ];
        let facts = Facts {
            relationships: &other,
            origins: known,
            ..lease
        };
        assert_eq!(crawled.value(&facts), Some(false));
        let reads = Takes::everything()
            .and(crawled.clone().negated(), "crawled")
            .reads();
        assert!(reads.file_origins && !reads.added_by && !reads.file_record);
        let back: Condition =
            serde_json::from_value(serde_json::to_value(&crawled).expect("writes")).expect("reads");
        assert_eq!(back, crawled);
    }

    #[test]
    fn the_extension_is_python_s() {
        assert_eq!(splitext("a.tar.gz"), ("a.tar", ".gz"));
        assert_eq!(splitext(".bashrc"), (".bashrc", ""));
        assert_eq!(splitext("..x.doc"), ("..x", ".doc"));
        assert_eq!(splitext("noext"), ("noext", ""));
        let none = BTreeMap::new();
        let doc = Condition::Extension(Text::exact(Match::OneOf(vec![".doc".to_owned()])));
        assert!(doc.holds(&file_facts("dir.x/a.doc", 1, &none, &[])));
        assert!(!doc.holds(&file_facts("a.doc/b", 1, &none, &[])));
    }

    #[test]
    fn a_declaration_says_what_it_reads_and_round_trips() {
        let takes = Takes::everything()
            .and(Condition::added_by("officeparser3"), "not an output")
            .and(
                Condition::Any(vec![
                    Condition::Mode("correlation".to_owned()),
                    Condition::result_true("file_type", "is_x509"),
                ]),
                "x",
            );
        assert_eq!(
            takes.reads(),
            Reads {
                added_by: true,
                directive_sources: false,
                at_root: false,
                mode: true,
                file_record: false,
                file_type: false,
                results: vec!["file_type".to_owned()],
                file_origins: false,
            }
        );
        let back: Takes =
            serde_json::from_value(json!({"rules": takes.describe()})).expect("reads");
        assert_eq!(back, takes);
        let meta = ["type=email.attachment".parse::<YaraMeta>().expect("valid")];
        assert!(
            Condition::yara_meta("type", "email.attachment").holds(&file_facts(
                "a",
                1,
                &BTreeMap::new(),
                &meta
            ))
        );
    }
}
