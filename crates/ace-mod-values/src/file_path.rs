//! `file_path_analysis` and `file_location_analysis`: ace3's `FilePathAnalyzer` and
//! `FileLocationAnalyzer` (`saq/modules/file_path.py`).
//!
//! A path with a `/` or `\` in it gives its file name, and a `<drive>:\Users\<name>\...` path its
//! user. A `host@path` location gives its host and its path.

use ace_results::types::values::{FileLocationAnalysis, FilePathAnalysis};
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

use crate::observable;

/// The two modules' manifests.
pub const FILE_PATH_MANIFEST: Manifest = Manifest::parser::<FilePathAnalyzer>();
pub const FILE_LOCATION_MANIFEST: Manifest = Manifest::parser::<FileLocationAnalyzer>();

pub struct FilePathAnalyzer;

impl Module for FilePathAnalyzer {
    const NAME: &'static str = FilePathAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::FilePath];
    type Output = FilePathAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(FilePathAnalyzer)
    }
}

/// `FILE_NAME_REGEX`, `^.*[/\\]([^/\\]+)$`: what follows the last separator, which has to be on
/// the first line, since `.` stops at a newline. The name may hold newlines.
pub fn file_name(path: &str) -> Option<String> {
    let sep = path.rfind(['/', '\\'])?;
    let name = &path[sep + 1..];
    (!name.is_empty() && !path[..sep].contains('\n')).then(|| name.to_owned())
}

/// `USER_REGEX`, `[a-z]:\\users\\([^\\]+)\\` without case, matched at the start.
pub fn user_name(path: &str) -> Option<String> {
    let mut chars = path.char_indices();
    let (_, drive) = chars.next()?;
    if !drive.is_ascii_alphabetic()
        && !matches!(drive, '\u{130}' | '\u{131}' | '\u{17f}' | '\u{212a}')
    {
        return None;
    }
    let rest = &path[drive.len_utf8()..];
    let rest = rest.strip_prefix(":\\")?;
    // "users" under re.IGNORECASE, which also folds the Kelvin sign and the long s
    let mut word = rest.chars();
    let mut taken = 0;
    for expected in "users".chars() {
        let c = word.next()?;
        let folded = match c {
            '\u{17f}' => 's',
            other => other.to_ascii_lowercase(),
        };
        if folded != expected {
            return None;
        }
        taken += c.len_utf8();
    }
    let rest = rest[taken..].strip_prefix('\\')?;
    let end = rest.find('\\')?;
    (end > 0).then(|| rest[..end].to_owned())
}

impl Parser for FilePathAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<FilePathAnalysis>, ModuleError> {
        let value = ctx.observable().value.as_str();
        // a path needs a separator, or it's only a file name
        if !value.contains(['\\', '/']) {
            return Ok(Outcome::Skipped("no path separator".to_owned()));
        }
        let mut result = ResultEnvelope::new(FilePathAnalysis::default());
        if let Some(name) = file_name(value) {
            result
                .observables
                .extend(observable::new(ObservableKind::FileName, &name));
            result.details.file_name = Some(name);
        }
        if let Some(user) = user_name(value) {
            result
                .observables
                .extend(observable::new(ObservableKind::User, &user));
            result.details.user_name = Some(user);
        }
        let details = &result.details;
        result.summary = (details.file_name.is_some() || details.user_name.is_some()).then(|| {
            let mut text = "File Path Analysis:".to_owned();
            if let Some(name) = details.file_name.as_ref().filter(|n| !n.is_empty()) {
                text.push_str(&format!(" file name {name}"));
            }
            if let Some(user) = details.user_name.as_ref().filter(|n| !n.is_empty()) {
                text.push_str(&format!(" user name {user}"));
            }
            text
        });
        Ok(Outcome::Done(result))
    }
}

pub struct FileLocationAnalyzer;

impl Module for FileLocationAnalyzer {
    const NAME: &'static str = FileLocationAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::FileLocation];
    type Output = FileLocationAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(FileLocationAnalyzer)
    }
}

impl Parser for FileLocationAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<FileLocationAnalysis>, ModuleError> {
        let value = ctx.observable().value.as_str();
        // ace3's FileLocationObservable refuses a value without a host and a path, so every one it
        // analyzes has them
        let Some((hostname, file_path)) = value.split_once('@') else {
            return Ok(Outcome::Skipped(
                "no @ between a host and a path".to_owned(),
            ));
        };
        let mut result = ResultEnvelope::new(FileLocationAnalysis {
            hostname: Some(hostname.to_owned()),
            file_path: Some(file_path.to_owned()),
        });
        result
            .observables
            .extend(observable::new(ObservableKind::Hostname, hostname));
        result
            .observables
            .extend(observable::new(ObservableKind::FilePath, file_path));
        result.summary = (!hostname.is_empty() || !file_path.is_empty())
            .then(|| format!("File Location Analysis: hostname {hostname} file path {file_path}"));
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_users() {
        assert_eq!(file_name(r"C:\a\b.exe").as_deref(), Some("b.exe"));
        assert_eq!(file_name("a/b/").as_deref(), None);
        assert_eq!(file_name("a/b\n").as_deref(), Some("b\n"));
        assert_eq!(file_name("a\nb/c").as_deref(), None);
        assert_eq!(
            user_name(r"c:\USERS\Bob Smith\Desktop\").as_deref(),
            Some("Bob Smith")
        );
        assert_eq!(user_name(r"C:\Users\carol"), None);
        assert_eq!(user_name("C:/Users/dan/file.txt"), None);
        assert_eq!(user_name(r"C:\Users\\x"), None);
    }
}
