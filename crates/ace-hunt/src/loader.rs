//! Loading one hunt file: ace3's `saq/collectors/hunter/loader.py`.
//!
//! A hunt file is YAML with a `rule`, optionally `include:`, a list of files whose values it
//! builds on, and `commands:`, the predefined commands its correlation can name. Each include is
//! read first, in order, each merged over the ones before it ([`crate::merge`]), and the file
//! itself last, so the file wins. An include's path is relative to the file that names it. A
//! file already read for the hunt is skipped, recognized as ace3 recognizes it, by the text of
//! its path; so a loop of includes that names each file the same way ends, and one file
//! included under two spellings is read twice. Before merging, a command's `path` and `files`
//! are made absolute against the file that names them.
//!
//! ace3 loops forever on a loop whose path grows each time round, such as `a` including
//! `../dir/a`, until the path is too long to open. ace-rs stops at the first file that is already
//! being read further up the chain of includes, and fails the hunt there.
//!
//! The rest is what ace3 does with what loaded: `rule` validates as the hunt type's model, each of
//! `commands` as a predefined command, and the query file named by `search` is read.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::HuntError;
use crate::correlate::PredefinedCommand;
use crate::merge::deep_merge;
use crate::model::{HuntConfig, QueryDefaults};
use crate::paths::{abspath, dirname, is_under, isabs, join, normpath, realpath};
use crate::types::HuntType;
use crate::value::{Map, Value, py_repr};
use crate::yaml::{self, Budget, Limits};

/// How hunts load.
#[derive(Debug, Clone)]
pub struct LoadOptions {
    /// What a query hunt that leaves them out takes.
    pub defaults: QueryDefaults,
    pub limits: Limits,
    /// What a relative `search` path is relative to, ace3's SAQ_HOME.
    pub home: PathBuf,
}

impl Default for LoadOptions {
    fn default() -> LoadOptions {
        LoadOptions {
            defaults: QueryDefaults::default(),
            limits: Limits::default(),
            home: PathBuf::from("/"),
        }
    }
}

/// A loaded hunt.
#[derive(Debug, Clone, PartialEq)]
pub struct Hunt {
    /// The hunt's file.
    pub path: PathBuf,
    pub config: HuntConfig,
    /// The predefined commands from the hunt's file and its includes.
    pub commands: Vec<PredefinedCommand>,
    /// Every file read for it, the hunt's own included, by the path it was read under, sorted.
    /// A change to any of them is a change to the hunt.
    pub files: Vec<String>,
    /// The text of the query file `search` names, if it names one.
    pub query_file: Option<String>,
}

/// Reads a file as Python's `open(path).read()` does, within the size bound.
fn read_text(path: &str, budget: &mut Budget) -> Result<String, HuntError> {
    budget.files += 1;
    if budget.files > budget.limits.max_files {
        return Err(HuntError::Limit(format!(
            "more than {} files read for one hunt",
            budget.limits.max_files
        )));
    }
    let metadata = std::fs::metadata(path).map_err(|e| os_error(&e, path))?;
    if metadata.is_dir() {
        return Err(HuntError::python(
            "IsADirectoryError",
            format!("[Errno 21] Is a directory: {}", py_repr(path)),
        ));
    }
    if metadata.len() > budget.limits.max_file_bytes {
        return Err(HuntError::Limit(format!(
            "{path} is {} bytes, more than {}",
            metadata.len(),
            budget.limits.max_file_bytes
        )));
    }
    let bytes = std::fs::read(path).map_err(|e| os_error(&e, path))?;
    String::from_utf8(bytes).map_err(|e| {
        let error = e.utf8_error();
        let at = error.valid_up_to();
        let byte = e.as_bytes()[at];
        let reason = match error.error_len() {
            None => "unexpected end of data",
            Some(_) if (0x80..0xc0).contains(&byte) || byte >= 0xf8 => "invalid start byte",
            Some(_) => "invalid continuation byte",
        };
        HuntError::python(
            "UnicodeDecodeError",
            format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {at}: {reason}"),
        )
    })
}

/// An I/O error as Python raises it: the OSError subclass for its errno, and its text.
pub(crate) fn os_error(error: &io::Error, path: &str) -> HuntError {
    let errno = error.raw_os_error().unwrap_or(0);
    let class = match errno {
        2 => "FileNotFoundError",
        13 | 1 => "PermissionError",
        20 => "NotADirectoryError",
        21 => "IsADirectoryError",
        _ => "OSError",
    };
    let text = error.to_string();
    let strerror = text.split(" (os error").next().unwrap_or(&text).to_owned();
    HuntError::python(
        class,
        format!("[Errno {errno}] {strerror}: {}", py_repr(path)),
    )
}

fn attribute_error(v: &Value, attribute: &str) -> HuntError {
    HuntError::python(
        "AttributeError",
        format!("'{}' object has no attribute '{attribute}'", v.type_name()),
    )
}

/// `name in v`, as Python evaluates it for whatever `v` is.
fn contains(v: &Value, name: &str) -> Result<bool, HuntError> {
    match v {
        Value::Map(map) => Ok(map.contains(name)),
        Value::Seq(items) => Ok(items.iter().any(|i| i.as_str() == Some(name))),
        Value::Str(s) => Ok(s.contains(name)),
        other => Err(HuntError::python(
            "TypeError",
            format!("argument of type '{}' is not iterable", other.type_name()),
        )),
    }
}

fn path_type_error(v: &Value) -> HuntError {
    HuntError::python(
        "TypeError",
        format!(
            "expected str, bytes or os.PathLike object, not {}",
            v.type_name()
        ),
    )
}

fn iterate(v: &Value) -> Result<Vec<Value>, HuntError> {
    v.py_iter().map_err(|m| HuntError::python("TypeError", m))
}

/// Makes a command's relative `path` and `files` absolute against `dir`.
fn resolve_command(cmd: &mut Value, dir: &str, only_executable: bool) -> Result<(), HuntError> {
    let Value::Map(map) = cmd else {
        return Err(attribute_error(cmd, "get"));
    };
    let executable =
        !only_executable || map.get("type").and_then(Value::as_str) == Some("executable");
    if executable && let Some(path) = map.get_mut("path").filter(|p| p.truthy()) {
        match path {
            Value::Str(s) if !isabs(s) => *s = normpath(&join(dir, s)),
            Value::Str(_) => {}
            other => return Err(path_type_error(other)),
        }
    }
    let Some(files) = map.get_mut("files") else {
        return Ok(());
    };
    if !files.truthy() {
        return Ok(());
    }
    for (i, file) in iterate(files)?.into_iter().enumerate() {
        let Value::Str(f) = &file else {
            return Err(path_type_error(&file));
        };
        if isabs(f) {
            continue;
        }
        let resolved = Value::Str(normpath(&join(dir, f)));
        match files {
            Value::Seq(items) => items[i] = resolved,
            Value::Map(m) => m.insert(Value::Int(i as i128), resolved),
            Value::Str(_) => {
                return Err(HuntError::python(
                    "TypeError",
                    "'str' object does not support item assignment",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The items `for item in v` visits, mutably for a list's, as copies for a dict's keys or a
/// string's characters, which Python would visit as new objects too.
fn for_each_item(
    v: &mut Value,
    f: impl FnMut(&mut Value) -> Result<(), HuntError>,
) -> Result<(), HuntError> {
    match v {
        Value::Seq(items) => items.iter_mut().try_for_each(f),
        other => iterate(other)?.iter_mut().try_for_each(f),
    }
}

/// `_resolve_file_paths_in_dict`.
fn resolve_file_paths(loaded: &mut Value, dir: &str) -> Result<(), HuntError> {
    let Value::Map(map) = loaded else {
        return Err(attribute_error(loaded, "get"));
    };
    if let Some(commands) = map.get_mut("commands") {
        for_each_item(commands, |cmd| resolve_command(cmd, dir, false))?;
    }
    let Some(rule) = map.get_mut("rule") else {
        return Ok(());
    };
    let Value::Map(rule) = rule else {
        return Err(attribute_error(rule, "get"));
    };
    let Some(correlate) = rule.get_mut("correlate") else {
        return Ok(());
    };
    if !correlate.truthy() {
        return Ok(());
    }
    let Value::Map(correlate) = correlate else {
        return Err(attribute_error(correlate, "get"));
    };
    match correlate.get_mut("logic") {
        Some(logic) => resolve_steps(logic, dir),
        None => Ok(()),
    }
}

/// `_resolve_command_paths_in_steps`.
fn resolve_steps(steps: &mut Value, dir: &str) -> Result<(), HuntError> {
    for_each_item(steps, |step| {
        if contains(step, "transform")? {
            let transform = match step {
                Value::Map(map) => map.get_mut("transform"),
                Value::Str(_) => {
                    return Err(HuntError::python(
                        "TypeError",
                        "string indices must be integers, not 'str'",
                    ));
                }
                _ => {
                    return Err(HuntError::python(
                        "TypeError",
                        "list indices must be integers or slices, not str",
                    ));
                }
            };
            if let Some(Value::Map(transform)) = transform
                && let Some(cmd) = transform.get_mut("command")
            {
                resolve_command(cmd, dir, true)?;
            }
        }
        if contains(step, "when")? {
            let Value::Map(map) = step else {
                return Err(attribute_error(step, "get"));
            };
            for branch in ["execute", "else"] {
                if let Some(steps) = map.get_mut(branch) {
                    resolve_steps(steps, dir)?;
                }
            }
        }
        Ok(())
    })
}

/// What one hunt has read so far.
struct Reading<'a> {
    history: BTreeSet<String>,
    /// The files being read, outermost first, by their real paths.
    chain: Vec<PathBuf>,
    root: Option<&'a Path>,
    budget: Budget,
}

/// `_load_and_merge_yaml`.
fn load_and_merge(path: &str, reading: &mut Reading<'_>) -> Result<Map, HuntError> {
    if let Some(root) = reading.root
        && !is_under(path, root)
    {
        return Err(HuntError::python(
            "HuntFileOutsideRootError",
            format!("hunt file {path} is outside {}", root.display()),
        ));
    }
    let text = read_text(path, &mut reading.budget)?;
    let real = realpath(path);
    if reading.chain.contains(&real) {
        return Err(HuntError::Limit(format!(
            "{path} includes itself, through a path that names it another way each time"
        )));
    }
    let mut loaded = yaml::load(&text, path, &mut reading.budget)?;
    let cwd = std::env::current_dir()
        .map_or_else(|_| "/".to_owned(), |d| d.to_string_lossy().into_owned());
    let dir = dirname(&abspath(path, &cwd)).to_owned();
    resolve_file_paths(&mut loaded, &dir)?;
    let Value::Map(mut loaded) = loaded else {
        // resolve_file_paths has already raised for anything but a dict
        return Err(attribute_error(&loaded, "get"));
    };

    let mut result = Map::new();
    if let Some(includes) = loaded.get("include").cloned() {
        let Value::Seq(includes) = includes else {
            return Err(HuntError::python(
                "ValueError",
                format!("include directives must be a list of strings in {path}"),
            ));
        };
        reading.chain.push(real);
        for include in &includes {
            let Value::Str(include) = include else {
                return Err(path_type_error(include));
            };
            let include = if isabs(include) {
                include.clone()
            } else {
                join(dirname(path), include)
            };
            if reading.history.contains(&include) {
                continue;
            }
            reading.history.insert(include.clone());
            let included = load_and_merge(&include, reading)?;
            result = deep_merge(&result, &included)?;
        }
        reading.chain.pop();
        loaded.remove("include");
    }
    deep_merge(&result, &loaded)
}

/// `load_merged_yaml`: a hunt file merged with its includes, unvalidated, and the files read.
/// With `root`, every file must lie under it, and one outside it is refused before it's opened.
pub fn load_merged(
    path: &str,
    root: Option<&Path>,
    limits: Limits,
) -> Result<(Map, Vec<String>), HuntError> {
    let mut reading = Reading {
        history: BTreeSet::from([path.to_owned()]),
        chain: Vec::new(),
        root,
        budget: Budget::new(limits),
    };
    let merged = load_and_merge(path, &mut reading)?;
    Ok((merged, reading.history.into_iter().collect()))
}

/// Reads a query file as `load_query_from_file` does: relative to `home`.
fn read_query_file(path: &str, options: &LoadOptions) -> Result<String, HuntError> {
    let path = if isabs(path) {
        path.to_owned()
    } else {
        join(&options.home.to_string_lossy(), path)
    };
    read_text(&path, &mut Budget::new(options.limits))
}

/// Loads one hunt file as `kind`'s hunt class does when ace3's HuntManager loads it.
pub fn load_hunt(
    path: &Path,
    kind: &dyn HuntType,
    options: &LoadOptions,
) -> Result<Hunt, HuntError> {
    let path_text = path.to_string_lossy().into_owned();
    let (merged, files) = load_merged(&path_text, None, options.limits)?;
    let rule = merged
        .get("rule")
        .ok_or_else(|| HuntError::python("KeyError", "'rule'"))?;
    let mut errs = Vec::new();
    let Some(config) = HuntConfig::validate(rule, kind, &options.defaults, &mut errs)? else {
        return Err(HuntError::Validation {
            title: kind.model().to_owned(),
            errors: errs,
        });
    };
    let mut commands = Vec::new();
    if let Some(list) = merged.get("commands") {
        for item in iterate(list)? {
            let mut errs = Vec::new();
            match PredefinedCommand::validate(&item, &[], &mut errs)? {
                Some(command) => commands.push(command),
                None => {
                    return Err(HuntError::Validation {
                        title: "PredefinedCommandConfig".to_owned(),
                        errors: errs,
                    });
                }
            }
        }
    }
    let query_file = match config.query_file_path.as_deref() {
        Some(file) if !file.is_empty() => Some(read_query_file(file, options)?),
        _ => None,
    };
    kind.on_load(&config)?;
    Ok(Hunt {
        path: path.to_owned(),
        config,
        commands,
        files,
        query_file,
    })
}

/// `<include:path>` in query text, which SplunkHunt expands when it runs.
static QUERY_INCLUDE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<include:([^>]+)>").expect("a valid pattern"));

/// `find_hunt_files_outside`: every file the hunt at `path` would read that lies outside `root`,
/// described, without opening any of them. ace3's validation API runs this on a hunt an analyst
/// submits, which 6.4's `hunt` router brings. `cwd` is what a query include's relative path is
/// relative to, the hunter's working directory.
pub fn files_outside(
    path: &str,
    root: &Path,
    options: &LoadOptions,
    cwd: &str,
) -> Result<Vec<String>, HuntError> {
    let merged = match load_merged(path, Some(root), options.limits) {
        Ok((merged, _)) => merged,
        Err(HuntError::Python { class, message }) if class == "HuntFileOutsideRootError" => {
            return Ok(vec![message]);
        }
        Err(other) => return Err(other),
    };
    let mut problems: Vec<String> = Vec::new();
    let inside = |file: &str, what: &str, problems: &mut Vec<String>| {
        if is_under(file, root) {
            return true;
        }
        let problem = format!("{what} {file} is outside the submitted hunt");
        if !problems.contains(&problem) {
            problems.push(problem);
        }
        false
    };
    let empty = Value::Map(Map::new());
    let rule = merged
        .get("rule")
        .filter(|r| r.as_map().is_some())
        .unwrap_or(&empty);
    let mut texts = Vec::new();
    strings_in(rule, &mut texts);
    for field in ["search", "query_file_path"] {
        let Some(Value::Str(file)) = rule.as_map().and_then(|r| r.get(field)) else {
            continue;
        };
        let query_path = if isabs(file) {
            file.clone()
        } else {
            join(&options.home.to_string_lossy(), file)
        };
        if inside(&query_path, "query file", &mut problems) && Path::new(&query_path).is_file() {
            texts.push(read_lossy(&query_path, options)?);
        }
    }
    let mut seen = BTreeSet::new();
    while let Some(text) = texts.pop() {
        for capture in QUERY_INCLUDE.captures_iter(&text) {
            let include = abspath(&capture[1], cwd);
            if !seen.insert(include.clone()) {
                continue;
            }
            if inside(&include, "query include", &mut problems) && Path::new(&include).is_file() {
                texts.push(read_lossy(&include, options)?);
            }
        }
    }
    let mut commands: Vec<Value> = merged
        .get("commands")
        .and_then(|c| match c {
            Value::Seq(items) => Some(items.clone()),
            _ => None,
        })
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.as_map().is_some())
        .collect();
    let mut steps: Vec<Value> = rule
        .as_map()
        .and_then(|r| r.get("correlate"))
        .and_then(Value::as_map)
        .and_then(|c| c.get("logic"))
        .and_then(|l| match l {
            Value::Seq(items) => Some(items.clone()),
            _ => None,
        })
        .unwrap_or_default();
    while let Some(step) = steps.pop() {
        let Value::Map(step) = step else {
            continue;
        };
        if let Some(Value::Map(transform)) = step.get("transform")
            && let Some(command @ Value::Map(_)) = transform.get("command")
        {
            commands.push(command.clone());
        }
        if step.contains("when") {
            for branch in ["execute", "else"] {
                if let Some(Value::Seq(items)) = step.get(branch) {
                    steps.extend(items.iter().cloned());
                }
            }
        }
    }
    for command in &commands {
        let Some(command) = command.as_map() else {
            continue;
        };
        if command.get("type").and_then(Value::as_str) == Some("executable")
            && let Some(Value::Str(file)) = command.get("path")
        {
            inside(file, "executable", &mut problems);
        }
        if let Some(Value::Seq(files)) = command.get("files") {
            for file in files {
                if let Value::Str(file) = file {
                    inside(file, "file", &mut problems);
                }
            }
        }
    }
    Ok(problems)
}

fn read_lossy(path: &str, options: &LoadOptions) -> Result<String, HuntError> {
    let metadata = std::fs::metadata(path).map_err(|e| os_error(&e, path))?;
    if metadata.len() > options.limits.max_file_bytes {
        return Err(HuntError::Limit(format!(
            "{path} is larger than {} bytes",
            options.limits.max_file_bytes
        )));
    }
    let bytes = std::fs::read(path).map_err(|e| os_error(&e, path))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn strings_in(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Str(s) => out.push(s.clone()),
        Value::Map(map) => map.iter().for_each(|(_, x)| strings_in(x, out)),
        Value::Seq(items) => items.iter().for_each(|x| strings_in(x, out)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    //! ace3's `tests/saq/collectors/hunter/test_loader.py`, where tools/ace3/hunts/cases doesn't
    //! already cover a case through the comparison.

    use super::*;
    use crate::types::Splunk;

    struct Package {
        _dir: tempfile::TempDir,
        package: PathBuf,
        outside: PathBuf,
    }

    impl Package {
        fn new() -> Package {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            let package = base.join("package");
            std::fs::create_dir_all(package.join("hunts")).unwrap();
            let outside = base.join("elsewhere/secret.yaml");
            std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
            std::fs::write(&outside, "rule:\n  name: not part of the hunt\n").unwrap();
            Package {
                _dir: dir,
                package,
                outside,
            }
        }

        fn write(&self, name: &str, text: &str) -> String {
            let path = self.package.join("hunts").join(name);
            std::fs::write(&path, text).unwrap();
            path.to_string_lossy().into_owned()
        }

        fn outside(&self, path: &str) -> Vec<String> {
            files_outside(path, &self.package, &LoadOptions::default(), "/").unwrap()
        }
    }

    #[test]
    fn a_hunt_that_stays_inside_passes() {
        let p = Package::new();
        let hunts = p.package.join("hunts");
        p.write("base.include.yaml", "rule:\n  tags: [base]\n");
        p.write(
            "query.spl",
            &format!("index=x <include:{}>\n", hunts.join("ips.txt").display()),
        );
        p.write("ips.txt", "1.1.1.1\n");
        p.write("enrich.py", "print('hi')\n");
        let path = p.write(
            "hunt.yaml",
            &format!(
                "include:\n  - base.include.yaml\nrule:\n  name: inside\n  search: {}\n  correlate:\n    logic:\n      - transform:\n          command:\n            type: executable\n            path: enrich.py\n            files: [ips.txt]\n",
                hunts.join("query.spl").display()
            ),
        );
        assert_eq!(p.outside(&path), Vec::<String>::new());
    }

    #[test]
    fn an_include_outside_is_reported_and_not_opened() {
        let p = Package::new();
        for include in [
            p.outside.to_string_lossy().into_owned(),
            "../../elsewhere/secret.yaml".to_owned(),
        ] {
            let path = p.write(
                "hunt.yaml",
                &format!("include:\n  - {include}\nrule:\n  name: x\n"),
            );
            let problems = p.outside(&path);
            assert_eq!(problems.len(), 1, "{problems:?}");
            assert!(problems[0].contains("secret.yaml") && problems[0].contains("outside"));
        }
        let path = p.write(
            "hunt.yaml",
            &format!("include:\n  - {}\nrule:\n  name: x\n", p.outside.display()),
        );
        let error = load_merged(&path, Some(&p.package), Limits::default()).unwrap_err();
        assert!(
            matches!(&error, HuntError::Python { class, .. } if class == "HuntFileOutsideRootError"),
            "{error:?}"
        );
        // without a root the include loads, as it does for a signatures repository
        let (merged, _) = load_merged(&path, None, Limits::default()).unwrap();
        assert_eq!(
            merged
                .get("rule")
                .and_then(Value::as_map)
                .and_then(|r| r.get("name"))
                .and_then(Value::as_str),
            Some("x")
        );
        // and a hunt outside the root is itself reported
        assert!(!p.outside(&p.outside.to_string_lossy()).is_empty());
    }

    #[test]
    fn query_files_and_their_includes_outside_are_reported() {
        let p = Package::new();
        let outside = p.outside.display().to_string();
        let path = p.write(
            "hunt.yaml",
            &format!("rule:\n  name: x\n  search: {outside}\n"),
        );
        assert_eq!(
            p.outside(&path),
            [format!(
                "query file {outside} is outside the submitted hunt"
            )]
        );
        let path = p.write(
            "hunt.yaml",
            &format!("rule:\n  name: x\n  query: 'index=x <include:{outside}>'\n"),
        );
        assert_eq!(
            p.outside(&path),
            [format!(
                "query include {outside} is outside the submitted hunt"
            )]
        );
        let inner = p.write("inner.txt", &format!("<include:{outside}>\n"));
        let query = p.write("query.spl", &format!("index=x <include:{inner}>\n"));
        let path = p.write(
            "hunt.yaml",
            &format!("rule:\n  name: x\n  search: {query}\n"),
        );
        assert_eq!(
            p.outside(&path),
            [format!(
                "query include {outside} is outside the submitted hunt"
            )]
        );
    }

    #[test]
    fn executables_and_their_files_outside_are_reported() {
        let p = Package::new();
        let outside = p.outside.display().to_string();
        let path = p.write(
            "hunt.yaml",
            &format!(
                "commands:\n  - name: lookup\n    type: executable\n    path: /usr/bin/env\nrule:\n  name: x\n  correlate:\n    logic:\n      - when: \"true\"\n        execute:\n          - transform:\n              command:\n                type: executable\n                path: script.py\n                files: [{outside}]\n"
            ),
        );
        assert_eq!(
            p.outside(&path),
            [
                "executable /usr/bin/env is outside the submitted hunt".to_owned(),
                format!("file {outside} is outside the submitted hunt"),
            ]
        );
    }

    #[test]
    fn a_file_too_large_and_too_many_includes_are_refused() {
        let p = Package::new();
        let limits = Limits {
            max_file_bytes: 64,
            ..Limits::default()
        };
        let path = p.write("big.yaml", &format!("rule:\n  name: {}\n", "x".repeat(100)));
        assert!(matches!(
            load_merged(&path, None, limits),
            Err(HuntError::Limit(_))
        ));

        // each file includes the next by a new spelling, and the chain never loops
        for i in 0..300 {
            p.write(
                &format!("chain{i}.include.yaml"),
                &format!("include:\n  - chain{}.include.yaml\n", i + 1),
            );
        }
        let path = p.write(
            "chain.yaml",
            "include:\n  - chain0.include.yaml\nrule: {}\n",
        );
        let error = load_merged(&path, None, Limits::default()).unwrap_err();
        assert!(
            matches!(&error, HuntError::Limit(m) if m.contains("files")),
            "{error:?}"
        );
    }

    #[test]
    fn a_query_file_is_read_from_home() {
        let p = Package::new();
        p.write("q.spl", "index=from_file\n");
        let path = p.write(
            "hunt.yaml",
            "rule:\n  uuid: u\n  name: n\n  type: splunk\n  enabled: true\n  description: d\n  alert_type: a\n  frequency: '00:01:00'\n  time_range: '00:01:00'\n  full_coverage: true\n  use_index_time: true\n  search: hunts/q.spl\n",
        );
        let options = LoadOptions {
            home: p.package.clone(),
            ..LoadOptions::default()
        };
        let hunt = load_hunt(Path::new(&path), &Splunk::default(), &options).unwrap();
        assert_eq!(hunt.query_file.as_deref(), Some("index=from_file\n"));
        let missing = load_hunt(
            Path::new(&path),
            &Splunk::default(),
            &LoadOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(&missing, HuntError::Python { class, message } if class == "FileNotFoundError" && message.contains("hunts/q.spl")),
            "{missing:?}"
        );
    }
}
