//! `file_type`: the type step (PLAN.md decision 25, docs/decisions/0003). It is ace3's
//! `FileTypeAnalyzer` (`saq/modules/file_analysis/file_type.py`) made every file's first task: the
//! core queues it on each new file before any other task on that file, and keeps what it finds,
//! the file's type, once per sha256 (`TypeFacts`), not as a result in the tree.
//!
//! It finds libmagic's description and mime type of the file, as `file -b -L` and
//! `file -b --mime-type -L` print them, and the checks of `is_file_type.py` that read only the
//! bytes. ace3's result, its tags and its `yara_meta` types are built from those facts and the
//! file's path (`FileTypeAnalysis::from_facts`, `TypeFacts::view`), since two of its checks read
//! the name too.
//!
//! Where ace4 departs:
//!
//! - libmagic runs in the task, on the database ace3's `file` reads (`libmagic.rs`); ace3 starts
//!   `file` twice. `is_javascript_file` parses with oxc where ace3 starts node (`javascript.rs`).
//! - ace3 also stamps the mime type on the file observable and works out an image's preview size
//!   for its alert page. ace4 keeps the mime type among the file's type, and its page doesn't scale
//!   previews.

use std::fs;
use std::time::Duration;

use ace_results::types::file_type::{FileTypeAnalysis, TypeFacts, asks_about_javascript};
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope, YaraMeta};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};

use crate::checks;
use crate::javascript;
use crate::libmagic::{self, Answer, Magic};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<FileType>();

/// Whether file_type gives a file at `path`, with these bytes and its mime type, the `yara_meta`
/// type `script.javascript`: the mime type or the name says JavaScript, and node would parse it.
pub fn tags_javascript(path: &str, mime: &str, data: &[u8]) -> bool {
    asks_about_javascript(path, mime) && javascript::is_javascript_file(path, data)
}

/// The module, with libmagic's database read before containment, which can't open it.
pub struct FileType {
    database: Result<Vec<u8>, String>,
}

impl Module for FileType {
    const NAME: &'static str = TypeFacts::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    // ace3 gives the module no limits of its own, and `file` and node none either.
    // docs/measurements/javascript-check.md has what a crafted file costs.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(300),
        memory_mb: 2048,
        cpu_seconds: 300,
    };
    type Output = TypeFacts;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(FileType {
            database: fs::read(libmagic::DATABASE).map_err(|e| e.to_string()),
        })
    }
}

/// What the bytes are, given libmagic's answers. `path` is the name the file is typed under,
/// which decides only whether the JavaScript check runs, as ace3 gates node on the name or the
/// mime type; the facts don't depend on it otherwise.
pub fn facts_of(path: &str, data: &[u8], description: String, mime: String) -> TypeFacts {
    let (is_zip_file, is_jar_file) = match checks::zip_names(data) {
        Some(names) => {
            let zip = !names.is_empty();
            (
                zip,
                zip && names.iter().any(|n| n == "META-INF/MANIFEST.MF"),
            )
        }
        None => (false, false),
    };
    let javascript = asks_about_javascript(path, &mime).then(|| javascript::javascript_bytes(data));
    TypeFacts {
        is_ole_file: checks::is_ole_file(data),
        is_rtf_file: checks::is_rtf_file(data),
        has_pdf_marker: checks::has_pdf_marker(data),
        is_pe_file: checks::is_pe_file(data),
        is_zip_file,
        is_jar_file,
        is_x509: crate::x509::is_x509(data),
        is_lnk_file: checks::is_lnk_file(data),
        is_email_file: checks::is_email_file(data) || mime == "message/rfc822",
        javascript,
        description,
        mime,
    }
}

/// ace3's result for a file at `path` with these facts, with the tags and `yara_meta` types it
/// gave the file: what the comparison's normal form and the reference tests rebuild.
pub fn as_ace3(facts: &TypeFacts, path: &str) -> ResultEnvelope<FileTypeAnalysis> {
    let analysis = FileTypeAnalysis::from_facts(facts, path);
    let summary = analysis.summary();
    let mut result = ResultEnvelope::new(analysis).with_summary(summary);
    let (tags, types) = facts.view(path);
    for tag in tags {
        result.analyzed.add_tag(tag);
    }
    for kind in types {
        result
            .analyzed
            .add_yara_meta(YaraMeta::new("type", kind).expect("a type is a valid tag"));
    }
    result
}

/// The type step's answer for the file at `local`, typed under `alert_path`, outside containment:
/// for a test harness (`ace_testkit::Harness::with_typer`), which has no core to run the step. None
/// when libmagic's database or the file doesn't read.
pub fn type_of(alert_path: &str, local: &std::path::Path) -> Option<TypeFacts> {
    let database = fs::read(libmagic::DATABASE).ok()?;
    let describe = |answer| {
        Magic::load(&database, answer)
            .ok()
            .map(|magic| ace_pycompat::pystr::strip(&magic.file(local)).to_owned())
    };
    let (description, mime) = (describe(Answer::Description)?, describe(Answer::MimeType)?);
    let data = fs::read(local).ok()?;
    Some(facts_of(alert_path, &data, description, mime))
}

impl Parser for FileType {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<TypeFacts>, ModuleError> {
        let file = ctx.input_file()?;
        let database = self
            .database
            .as_ref()
            .map_err(|e| ModuleError::other(format!("{}: {e}", libmagic::DATABASE)))?;
        let describe = |answer| -> Result<String, ModuleError> {
            let magic = Magic::load(database, answer).map_err(ModuleError::other)?;
            Ok(ace_pycompat::pystr::strip(&magic.file(&file.local_path)).to_owned())
        };
        let description = describe(Answer::Description)?;
        let mime = describe(Answer::MimeType)?;
        ctx.check_cancelled()?;
        let data = fs::read(&file.local_path)?;
        let facts = facts_of(file.path.as_str(), &data, description, mime);
        // the summary of ace3's result, for the task's log; the core keeps only the facts
        let summary = FileTypeAnalysis::from_facts(&facts, file.path.as_str()).summary();
        Ok(Outcome::Done(
            ResultEnvelope::new(facts).with_summary(summary),
        ))
    }
}
