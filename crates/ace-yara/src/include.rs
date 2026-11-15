//! What a rule file may read: itself and the files it includes, inside its signature directory, and
//! nothing else. yara-x opens no file at all.
//!
//! **Why.** yara-x resolves `include "path"` by joining the path to a directory and reading whatever
//! is there: `../` walks out, an absolute path replaces the directory, and a symbolic link is
//! followed. A file that isn't YARA fails with a syntax error that quotes its first line. So a rule
//! author who can push to the signatures repository could have the process that compiles the rules
//! read a file of its own, such as `/proc/self/environ`, and find a line of it in the build's report
//! or the core's log. A rule file that was itself a symbolic link was read the same way.
//!
//! **The rule.** A namespace is a directory of a signature directory. A rule file, and every file it
//! includes, is a regular file inside that signature directory, reached without passing through a
//! symbolic link:
//!
//! - A relative include is looked for in the directory of the file that holds it, and then in the
//!   namespace's own directory, as yara-x looked. `../other/common.yar` reaches another namespace
//!   of the same signature directory, as it does in ace3, whose loader joins the path to the
//!   namespace's directory.
//! - A path that leaves the signature directory is refused before anything is opened, by its text
//!   alone, so the refusal doesn't say whether a file is there.
//! - An absolute path is refused, wherever it points.
//! - A symbolic link is refused, as the path's last part or on the way to it, whatever it points to:
//!   the ruleset build exports a commit's regular files only, so a link could only ever work where
//!   the rules aren't built.
//! - A path holding a backslash or a NUL is refused: yara-x would unescape it, and no rule needs one.
//!
//! The signature directory is the boundary because it is all the ruleset build has of a commit
//! (`crate::ruleset::build_commit`): an include that reached further would compile in a checkout and
//! fail in the build. ace3 lets an include reach anywhere and SVS warns when one leaves the
//! repository, since "it resolves differently in production"; here it is refused everywhere.
//!
//! **How.** Before yara-x sees a source, [`Boundary::resolve`] replaces each `include` statement with
//! the text of the file it names, and theirs, and the compiler has includes turned off
//! (`crate::load::new_compiler`). So the rule is enforced before yara-x could open anything, and a
//! statement this missed is an error from yara-x (`include statements not allowed`), never a read.
//! Checking the paths and leaving yara-x to read them was the other way: one statement the two read
//! differently would then have been a file opened unchecked.
//!
//! Each file is opened one directory at a time from the signature directory, with `O_NOFOLLOW`, so
//! what was checked is what is read.
//!
//! An included file has to parse on its own, which makes putting its text in place the same as
//! including it: it can't leave a comment or a rule open over what follows. It is held to
//! `crate::guard`'s bounds before it is parsed, and the whole text again afterwards. Includes nest
//! at most [`MAX_INCLUDE_DEPTH`] deep, a file includes at most [`MAX_INCLUDED_FILES`] in all, of at
//! most [`MAX_INCLUDED_BYTES`] together, and a file that includes itself is refused.
//!
//! What it costs: yara-x's errors and warnings count lines in the text with the included files in
//! place, so [`Resolved::note`] says which lines are which file's.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::guard;

/// How deep includes may nest.
pub const MAX_INCLUDE_DEPTH: usize = 8;
/// How many files one rule file may include in all, counting a file each time it is included.
pub const MAX_INCLUDED_FILES: usize = 64;
/// The most bytes one rule file's included files hold together.
pub const MAX_INCLUDED_BYTES: usize = 8 << 20;

/// Why a file can't be read, or an include can't be followed. No reason holds a byte of any file,
/// and none says anything of a path outside the signature directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// The path isn't plain: it is empty, isn't UTF-8, or holds a backslash or a NUL.
    NotPlain,
    Absolute,
    /// By its text alone, the path leaves the signature directory.
    Outside,
    /// The path is a symbolic link, or passes through one.
    Symlink,
    NotFound,
    /// It is there, and isn't a regular file.
    NotAFile,
    /// It can't be opened, for the reason the system gave.
    Unreadable(String),
    /// It is already being included: a file that includes itself, directly or not.
    Circular,
    /// It isn't UTF-8.
    NotText,
    /// Past one of `crate::guard`'s bounds.
    Bounds(String),
    /// It doesn't parse on its own; the line of the first error.
    Syntax {
        line: usize,
    },
}

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Why::NotPlain => write!(
                f,
                "the path isn't plain text: it is empty, or holds a backslash, a NUL or bytes \
                 that aren't UTF-8"
            ),
            Why::Absolute => write!(
                f,
                "an absolute path: an include is relative, and stays inside the signature directory"
            ),
            Why::Outside => write!(f, "the path leaves the signature directory"),
            Why::Symlink => write!(f, "it is a symbolic link, or is reached through one"),
            Why::NotFound => write!(f, "no such file inside the signature directory"),
            Why::NotAFile => write!(f, "it isn't a regular file"),
            Why::Unreadable(error) => write!(f, "it can't be read: {error}"),
            Why::Circular => write!(f, "it is already being included: the includes are circular"),
            Why::NotText => write!(f, "it isn't UTF-8 text"),
            Why::Bounds(reason) => write!(f, "{reason}"),
            Why::Syntax { line } => write!(
                f,
                "it doesn't parse on its own (the first error is at its line {line}): an included \
                 file has to be whole"
            ),
        }
    }
}

/// Why a rule file is left out before yara-x sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The rule file itself can't be read.
    File(Why),
    /// The rule file is past one of `crate::guard`'s bounds.
    Bounds(guard::Refusal),
    /// One of its includes, or of a file it includes: the path as written and the line it is on in
    /// the file that holds it.
    Include {
        include: String,
        line: usize,
        why: Why,
    },
    Depth,
    Count,
    Size,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::File(why) => write!(f, "the rule file: {why}"),
            Refusal::Bounds(refusal) => write!(f, "{refusal}"),
            Refusal::Include { include, line, why } => {
                write!(f, "the include {include:?} at line {line}: {why}")
            }
            Refusal::Depth => write!(f, "includes nest more than {MAX_INCLUDE_DEPTH} files deep"),
            Refusal::Count => write!(
                f,
                "the file includes more than {MAX_INCLUDED_FILES} files in all"
            ),
            Refusal::Size => write!(
                f,
                "the files it includes hold more than {MAX_INCLUDED_BYTES} bytes together"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// One include of a rule file itself, and the lines its text takes in [`Resolved::source`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inlined {
    /// The path as the rule file writes it.
    pub include: String,
    pub first_line: usize,
    pub last_line: usize,
}

/// A rule file as yara-x is given it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The file's text, with each include replaced by the text of the file it names.
    pub source: Vec<u8>,
    /// The file's own includes, in order. Empty when it has none, and `source` is then the file.
    pub inlined: Vec<Inlined>,
}

impl Resolved {
    /// Which lines of what yara-x compiled are an included file's, for an error or a warning that
    /// names a line; None for a file with no include.
    pub fn note(&self) -> Option<String> {
        if self.inlined.is_empty() {
            return None;
        }
        let lines: Vec<String> = self
            .inlined
            .iter()
            .map(|inlined| {
                format!(
                    "lines {} to {} are {:?}",
                    inlined.first_line, inlined.last_line, inlined.include
                )
            })
            .collect();
        Some(format!(
            "note: the file's includes are compiled in place, so line numbers count their lines: {}",
            lines.join(", ")
        ))
    }
}

/// A signature directory: what its namespaces' rule files, and their includes, may read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Boundary {
    root: PathBuf,
}

/// A path inside the boundary, as the names from the signature directory down.
type Inside = Vec<OsString>;

impl Boundary {
    /// The boundary of the namespace whose directory is `namespace_dir`: the directory that holds
    /// it. A namespace directory with no parent is its own boundary.
    pub fn of_namespace(namespace_dir: &Path) -> Boundary {
        let root = match namespace_dir.parent() {
            Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
            Some(parent) if namespace_dir.file_name().is_some() => parent.to_path_buf(),
            _ => namespace_dir.to_path_buf(),
        };
        Boundary { root }
    }

    /// The signature directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `path` as names below the signature directory, when its text stays inside it.
    fn inside(&self, path: &Path) -> Result<Inside, Why> {
        let relative = match path.strip_prefix(&self.root) {
            Ok(relative) => relative,
            // a namespace directory with no parent: `a/x.yar` under the boundary `.`
            Err(_) if self.root == Path::new(".") && path.is_relative() => path,
            Err(_) => return Err(Why::Outside),
        };
        step(Vec::new(), relative)
    }

    /// Reads the regular file at `inside`, opening each directory from the signature directory down
    /// and following no symbolic link. At most `limit` bytes, when there is one.
    fn open(&self, inside: &[OsString], limit: Option<usize>) -> Result<Vec<u8>, Why> {
        let Some((name, directories)) = inside.split_last() else {
            return Err(Why::NotAFile);
        };
        let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let mut dir = rustix::fs::open(&self.root, directory, Mode::empty())
            .map_err(|errno| unreadable(None, OsStr::new(""), errno))?;
        for part in directories {
            dir = rustix::fs::openat(
                &dir,
                part.as_os_str(),
                directory | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|errno| unreadable(Some(&dir), part, errno))?;
        }
        // not blocking, so a FIFO of the name doesn't hold the open
        let file = rustix::fs::openat(
            &dir,
            name.as_os_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|errno| unreadable(Some(&dir), name, errno))?;
        let stat = rustix::fs::fstat(&file).map_err(|errno| Why::Unreadable(errno.to_string()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(Why::NotAFile);
        }
        let mut bytes = Vec::new();
        let mut file = std::fs::File::from(file);
        match limit {
            Some(limit) => {
                // one past the limit, so a file over it is seen to be
                let mut limited = file.take(limit as u64 + 1);
                limited
                    .read_to_end(&mut bytes)
                    .map_err(|error| Why::Unreadable(error.kind().to_string()))?;
            }
            None => {
                file.read_to_end(&mut bytes)
                    .map_err(|error| Why::Unreadable(error.kind().to_string()))?;
            }
        }
        Ok(bytes)
    }

    /// Reads a namespace's rule file: a regular file inside the signature directory, reached through
    /// no symbolic link.
    pub fn read_rule_file(&self, path: &Path) -> Result<Vec<u8>, Refusal> {
        let inside = self.inside(path).map_err(Refusal::File)?;
        self.open(&inside, None).map_err(Refusal::File)
    }

    /// Reads the rule file at `path`, of the namespace whose directory is `namespace_dir`, and
    /// resolves its includes: what yara-x is given in its place.
    pub fn load(&self, namespace_dir: &Path, path: &Path) -> Result<Resolved, Refusal> {
        let source = self.read_rule_file(path)?;
        self.resolve(namespace_dir, path, &source)
    }

    /// `source`, the text of the rule file at `path`, with its includes resolved, held to
    /// `crate::guard`'s bounds.
    pub fn resolve(
        &self,
        namespace_dir: &Path,
        path: &Path,
        source: &[u8],
    ) -> Result<Resolved, Refusal> {
        let sites = guard::includes(source).map_err(Refusal::Bounds)?;
        if !sites.iter().any(|site| site.top_level) {
            return Ok(Resolved {
                source: source.to_vec(),
                inlined: Vec::new(),
            });
        }
        let mut own = self.inside(path).map_err(Refusal::File)?;
        let namespace = self.inside(namespace_dir).map_err(Refusal::File)?;
        let mut walk = Walk {
            boundary: self,
            namespace,
            stack: vec![own.clone()],
            files: 0,
            bytes: 0,
        };
        own.pop();
        let mut inlined = Vec::new();
        let resolved = walk.inline(source, &sites, &own, 0, Some(&mut inlined))?;
        // every file passed alone; this is the text yara-x compiles
        guard::check(&resolved).map_err(Refusal::Bounds)?;
        Ok(Resolved {
            source: resolved,
            inlined,
        })
    }
}

/// `path` applied to the names `from`, by its text alone: `..` takes one away, and taking one from
/// none leaves the signature directory.
fn step(mut from: Inside, path: &Path) -> Result<Inside, Why> {
    for component in path.components() {
        match component {
            Component::Normal(name) => from.push(name.to_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                if from.pop().is_none() {
                    return Err(Why::Outside);
                }
            }
            Component::RootDir | Component::Prefix(_) => return Err(Why::Absolute),
        }
    }
    Ok(from)
}

/// Why `name` in `dir` didn't open. A symbolic link is told from what isn't there or isn't a
/// directory by looking at the name itself, never at what it points to.
fn unreadable(dir: Option<&rustix::fd::OwnedFd>, name: &OsStr, errno: Errno) -> Why {
    if let Some(dir) = dir
        && let Ok(stat) = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
    {
        return match FileType::from_raw_mode(stat.st_mode) {
            FileType::Symlink => Why::Symlink,
            FileType::RegularFile | FileType::Directory if errno == Errno::NOTDIR => Why::NotFound,
            FileType::RegularFile | FileType::Directory => Why::Unreadable(errno.to_string()),
            _ => Why::NotAFile,
        };
    }
    match errno {
        Errno::NOENT | Errno::NOTDIR => Why::NotFound,
        Errno::LOOP => Why::Symlink,
        other => Why::Unreadable(other.to_string()),
    }
}

/// The include's path as text, when it is plain.
fn plain(path: &[u8]) -> Result<&str, Why> {
    let text = std::str::from_utf8(path).map_err(|_| Why::NotPlain)?;
    if text.is_empty() || text.contains(['\\', '\0']) {
        return Err(Why::NotPlain);
    }
    Ok(text)
}

fn newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
}

/// One rule file's includes as they are followed.
struct Walk<'a> {
    boundary: &'a Boundary,
    /// The namespace's directory, where an include is looked for second.
    namespace: Inside,
    /// The files being included now, the rule file first.
    stack: Vec<Inside>,
    files: usize,
    bytes: usize,
}

impl Walk<'_> {
    /// `source` with each top-level include of `sites` replaced. `dir` is the directory of the file
    /// `source` is. `inlined` collects the rule file's own includes with their lines.
    fn inline(
        &mut self,
        source: &[u8],
        sites: &[guard::IncludeSite],
        dir: &Inside,
        depth: usize,
        mut inlined: Option<&mut Vec<Inlined>>,
    ) -> Result<Vec<u8>, Refusal> {
        let mut out = Vec::with_capacity(source.len());
        let mut cursor = 0;
        for site in sites.iter().filter(|site| site.top_level) {
            if depth == MAX_INCLUDE_DEPTH {
                return Err(Refusal::Depth);
            }
            let written = String::from_utf8_lossy(&site.path).into_owned();
            let refused = |why: Why| Refusal::Include {
                include: written.clone(),
                line: site.line,
                why,
            };
            let name = plain(&site.path).map_err(refused)?;
            let (found, bytes) = self.find(name, dir).map_err(refused)?;
            if self.stack.contains(&found) {
                return Err(refused(Why::Circular));
            }
            self.files += 1;
            if self.files > MAX_INCLUDED_FILES {
                return Err(Refusal::Count);
            }
            self.bytes += bytes.len();
            if self.bytes > MAX_INCLUDED_BYTES {
                return Err(Refusal::Size);
            }
            // the bounds first: yara-x's parser overflows its stack past them
            let inner_sites = guard::includes(&bytes)
                .map_err(|refusal| refused(Why::Bounds(refusal.to_string())))?;
            if std::str::from_utf8(&bytes).is_err() {
                return Err(refused(Why::NotText));
            }
            let parsed = yara_x_parser::ast::AST::from(yara_x_parser::Parser::new(&bytes));
            if let Some(error) = parsed.errors().first() {
                let at = match error {
                    yara_x_parser::ast::Error::SyntaxError { span, .. }
                    | yara_x_parser::ast::Error::InvalidInteger { span, .. }
                    | yara_x_parser::ast::Error::InvalidFloat { span, .. }
                    | yara_x_parser::ast::Error::InvalidRegexpModifier { span, .. }
                    | yara_x_parser::ast::Error::InvalidEscapeSequence { span, .. }
                    | yara_x_parser::ast::Error::InvalidUTF8(span)
                    | yara_x_parser::ast::Error::UnexpectedEscapeSequence(span) => span.start(),
                };
                let line = 1 + newlines(&bytes[..at.min(bytes.len())]);
                return Err(refused(Why::Syntax { line }));
            }
            drop(parsed);

            let mut inner_dir = found.clone();
            inner_dir.pop();
            self.stack.push(found);
            let inner = self.inline(&bytes, &inner_sites, &inner_dir, depth + 1, None)?;
            self.stack.pop();

            out.extend_from_slice(&source[cursor..site.span.start]);
            let first_line = 1 + newlines(&out);
            out.extend_from_slice(&inner);
            // a file whose last line is a `//` comment must not take what follows into it
            if !inner.ends_with(b"\n") {
                out.push(b'\n');
            }
            if let Some(inlined) = inlined.as_deref_mut() {
                inlined.push(Inlined {
                    include: written,
                    first_line,
                    last_line: newlines(&out).max(first_line),
                });
            }
            cursor = site.span.end;
        }
        out.extend_from_slice(&source[cursor..]);
        Ok(out)
    }

    /// The file an include names: in the including file's directory, then in the namespace's. A path
    /// whose text leaves the signature directory is refused before anything is opened.
    fn find(&self, name: &str, dir: &Inside) -> Result<(Inside, Vec<u8>), Why> {
        let named = Path::new(name);
        let mut candidates = vec![step(dir.clone(), named)?];
        if *dir != self.namespace {
            candidates.push(step(self.namespace.clone(), named)?);
        }
        let limit = MAX_INCLUDED_BYTES.saturating_sub(self.bytes);
        for candidate in candidates {
            match self.boundary.open(&candidate, Some(limit)) {
                Ok(bytes) => return Ok((candidate, bytes)),
                Err(Why::NotFound) => {}
                Err(why) => return Err(why),
            }
        }
        Err(Why::NotFound)
    }
}

#[cfg(test)]
mod tests;
