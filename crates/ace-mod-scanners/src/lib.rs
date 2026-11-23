//! PLAN.md 7.7's modules: ports of ace3's clients of its two scanner services, which send a file or a
//! URL through a scanner image and add what comes back. `javascript_deobfuscation` runs a script in
//! js-deobfuscator's node sandbox with no network, and `phishkit_analyzer` loads a URL or renders a
//! file in phishkit's Chrome.
//!
//! The services keep their code: the images are ace3's (`docker/scanners/build`). What changes is how
//! a module reaches them. ace3's modules send a Celery task to a manager container, which runs the
//! scanner through the host's Docker socket and parses some of its output; here the module's first run
//! delays its task with a scan (`ace_sdk::scanners`), the scanner pool runs it, and the module's next
//! run reads the output archive, contained, which ace3's managers did with the Docker socket in hand.
//! What the managers added to the output (`std.out`, `std.err`, `exit.code`, the deobfuscator's
//! `report.json` and phishkit's `proxy.json`) the modules make here from the scan, as the managers
//! did.
//!
//! Both run on the parser pool, and both read the root's tree: the deobfuscator for the DOM snapshot
//! of the document a script ran in, which `html_js_extraction` and `har_extraction` keep in their
//! results, and phishkit for the root's analysis mode, since it renders files only in correlation
//! mode.

pub mod js;
pub mod mimetypes;
pub mod phishkit;

use std::cmp::Ordering;
use std::io::Read;
use std::path::Path;

use ace_results::NewFile;
use ace_sdk::scanners::{OUTPUT_ARCHIVE, STDERR, STDOUT};
use ace_sdk::{ModuleError, TaskContext};

pub use js::JavaScriptDeobfuscationAnalyzer;
pub use phishkit::PhishkitAnalyzer;

/// The most files a module keeps from one scan's output directory. ace3 keeps every one, up to its
/// root's limit of observables, which ace-rs's core doesn't have.
pub const MAX_FILES: usize = 1000;
/// The most of a log stream, and of a file a module reads into memory, that's read.
pub const MAX_TEXT_BYTES: u64 = 64 << 20;

/// A file the scanner left in its output directory, stored in the task's file store under a
/// placeholder path the module replaces with the one it adds it under.
#[derive(Debug, Clone)]
pub struct OutputFile {
    /// Its path under the output directory, such as `downloads/x.zip`.
    pub path: String,
    pub file: NewFile,
    /// Its bytes, for a file the module asked to read.
    pub bytes: Option<Vec<u8>>,
}

impl OutputFile {
    /// Its name: the last part of its path.
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

/// What a scan brought back.
#[derive(Debug, Clone, Default)]
pub struct ScanOutput {
    /// The output directory's regular files, in the order Python's `os.walk` gives them top-down:
    /// a directory's files before its subdirectories', each sorted by name.
    pub files: Vec<OutputFile>,
    /// Files past `MAX_FILES`, left out.
    pub left_out: usize,
    /// What the scanner wrote to stdout and stderr.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ScanOutput {
    /// The first file at `path` under the output directory.
    pub fn at(&self, path: &str) -> Option<&OutputFile> {
        self.files.iter().find(|f| f.path == path)
    }
}

/// Reads a scan's output archive (`ace_sdk::scanners::OUTPUT_ARCHIVE`, `STDOUT`, `STDERR`), storing
/// each regular file of the output directory in the task's file store and keeping the bytes of
/// those `read` names, by their path under the directory. Anything else in Docker's tar, such as a
/// link, a device or a name with `..`, is left out.
pub fn read_output<S>(
    ctx: &TaskContext<S>,
    archive: &Path,
    read: &dyn Fn(&str) -> bool,
) -> Result<ScanOutput, ModuleError> {
    let mut output = ScanOutput::default();
    let mut outer = tar::Archive::new(std::fs::File::open(archive)?);
    for entry in outer.entries()? {
        ctx.check_cancelled()?;
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().into_owned();
        match name.as_str() {
            OUTPUT_ARCHIVE => read_directory(ctx, &mut entry, read, &mut output)?,
            STDOUT => output.stdout = demux(&read_limited(&mut entry)?),
            STDERR => output.stderr = demux(&read_limited(&mut entry)?),
            _ => {}
        }
    }
    output.files.sort_by(|a, b| walk_order(&a.path, &b.path));
    Ok(output)
}

fn read_directory<S>(
    ctx: &TaskContext<S>,
    tar: &mut dyn Read,
    read: &dyn Fn(&str) -> bool,
    output: &mut ScanOutput,
) -> Result<(), ModuleError> {
    let mut inner = tar::Archive::new(tar);
    for entry in inner.entries()? {
        ctx.check_cancelled()?;
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let raw = entry.path_bytes().into_owned();
        let Some(path) = under_directory(&raw) else {
            continue;
        };
        if output.files.len() >= MAX_FILES {
            output.left_out += 1;
            continue;
        }
        let placeholder = format!("scan/{}", output.files.len());
        let (file, bytes) = if read(&path) {
            let bytes = read_limited(&mut entry)?;
            (ctx.write_file(&placeholder, &bytes, None)?, Some(bytes))
        } else {
            (ctx.write_file_from(&placeholder, &mut entry, None)?, None)
        };
        output.files.push(OutputFile { path, file, bytes });
    }
    Ok(())
}

/// A path in Docker's tar of a directory, `<directory>/<path>`, as its path under the directory:
/// UTF-8 parts with no `.`, `..` or empty one. None for anything else, or the directory itself.
fn under_directory(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut parts = text.trim_end_matches('/').split('/');
    parts.next()?;
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty()
        || rest
            .iter()
            .any(|p| p.is_empty() || *p == "." || *p == ".." || p.contains('\0'))
    {
        return None;
    }
    Some(rest.join("/"))
}

/// Python's `os.walk` top-down order over two paths in one tree: at the first part they differ in,
/// a file in that directory comes before anything in a subdirectory, and otherwise names sort.
fn walk_order(a: &str, b: &str) -> Ordering {
    let (a, b): (Vec<&str>, Vec<&str>) = (a.split('/').collect(), b.split('/').collect());
    for i in 0..a.len().min(b.len()) {
        if a[i] == b[i] {
            continue;
        }
        let (a_file, b_file) = (i + 1 == a.len(), i + 1 == b.len());
        return match (a_file, b_file) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => a[i].cmp(b[i]),
        };
    }
    a.len().cmp(&b.len())
}

/// Reads up to `MAX_TEXT_BYTES`.
fn read_limited(reader: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(MAX_TEXT_BYTES).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// One log stream as Docker frames it, without its frames: each piece has an 8-byte header, the
/// stream, three zeros and its big-endian length. A cut last frame gives what it holds.
pub fn demux(framed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(framed.len());
    let mut rest = framed;
    while rest.len() >= 8 {
        let len = u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
        let body = &rest[8..];
        let take = len.min(body.len());
        out.extend_from_slice(&body[..take]);
        rest = &body[take..];
    }
    out
}

/// Text as Python reads a pipe or a file in text mode, `errors="replace"` or not: UTF-8 with U+FFFD
/// for what doesn't decode, and `\r\n` and `\r` read as `\n`.
pub fn text(bytes: &[u8]) -> String {
    universal_newlines(&String::from_utf8_lossy(bytes))
}

/// Text as Python reads a file with `errors="ignore"`: what doesn't decode is dropped.
pub fn text_ignoring(bytes: &[u8]) -> String {
    universal_newlines(&ace_pycompat::pystr::decode_utf8_ignore(bytes))
}

/// `\r\n` and `\r` as `\n`, as Python's text mode reads them.
pub fn universal_newlines(text: &str) -> String {
    if !text.contains('\r') {
        return text.to_owned();
    }
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// `json.loads(text)`, as JSON: Python's parser accepts what serde_json wouldn't, such as `NaN`,
/// which reads as null here, and an int past 64 bits, which reads as a float.
pub fn json_loads(text: &str) -> Option<serde_json::Value> {
    ace_pycompat::json::loads(text).ok().map(|v| to_json(&v))
}

fn to_json(value: &ace_pycompat::json::Value) -> serde_json::Value {
    use ace_pycompat::json::Value as Py;
    use serde_json::Value;
    match value {
        Py::Null => Value::Null,
        Py::Bool(b) => Value::Bool(*b),
        Py::Int(digits) => digits
            .parse::<i64>()
            .map(Value::from)
            .or_else(|_| digits.parse::<u64>().map(Value::from))
            .unwrap_or_else(|_| {
                digits
                    .parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(Value::Null, Value::Number)
            }),
        Py::Float(f) => serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number),
        Py::Str(s) => Value::String(s.as_str().to_owned()),
        Py::Array(items) => Value::Array(items.iter().map(to_json).collect()),
        Py::Object(members) => Value::Object(
            members
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), to_json(v)))
                .collect(),
        ),
    }
}

/// `os.path.dirname`: everything before the last `/`, or nothing.
pub fn dirname(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// `os.path.join(dir, name)` for a relative `dir`.
pub fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// ace3's `format_item_list_for_summary`: the first 20 items, and how many more.
pub fn format_item_list_for_summary(items: &[String]) -> String {
    const MAX: usize = 20;
    let shown = items
        .iter()
        .take(MAX)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > MAX {
        format!("{shown} + {} more", items.len() - MAX)
    } else {
        shown
    }
}

/// A scan's job id: a UUID, as ace3's Celery task ids are, made from the module and the observable,
/// so that a task's runs agree on it, and the same file or URL gets the same paths in any root.
/// ace3's is random, so its scanner's output differs from run to run where it names the job.
pub fn job_id<S>(ctx: &TaskContext<S>, module: &str) -> String {
    let observable = ctx.observable();
    job_id_of(module, observable.kind, &observable.value)
}

/// `job_id` for an observable of `kind` and `value`: it follows from them and the module alone.
pub fn job_id_of(module: &str, kind: ace_results::ObservableKind, value: &str) -> String {
    let name = format!("ace4/{module}/{kind}/{value}");
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, name.as_bytes()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_lose_their_frames() {
        let mut framed = vec![1, 0, 0, 0, 0, 0, 0, 3];
        framed.extend_from_slice(b"abc");
        framed.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 9]);
        framed.extend_from_slice(b"de");
        assert_eq!(demux(&framed), b"abcde");
        assert_eq!(demux(&[1, 0]), b"");
    }

    #[test]
    fn paths_come_out_from_under_the_directory_in_walk_order() {
        assert_eq!(
            under_directory(b"output/a/b.txt").as_deref(),
            Some("a/b.txt")
        );
        assert_eq!(under_directory(b"output/"), None);
        assert_eq!(under_directory(b"output/../x"), None);
        assert_eq!(under_directory(b"output/a//x"), None);
        let mut paths = vec!["z.txt", "b/a.txt", "a.txt", "b/c/d", "b/z"];
        paths.sort_by(|a, b| walk_order(a, b));
        assert_eq!(paths, ["a.txt", "z.txt", "b/a.txt", "b/z", "b/c/d"]);
    }

    #[test]
    fn text_reads_as_python_reads_it() {
        assert_eq!(text(b"a\r\nb\rc\xff"), "a\nb\nc\u{fffd}");
        assert_eq!(text_ignoring(b"a\xffb"), "ab");
        assert_eq!(dirname("a/b/c.js"), "a/b");
        assert_eq!(dirname("c.js"), "");
        let items: Vec<String> = (0..22).map(|i| i.to_string()).collect();
        assert!(format_item_list_for_summary(&items).ends_with("19 + 2 more"));
    }
}
