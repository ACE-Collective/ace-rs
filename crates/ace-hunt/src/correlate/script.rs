//! `type: executable` (PLAN.md decision 16): ace4 runs no hunt script. Each script the signatures'
//! hunts run is a built-in *script command type*, Rust that computes what the script computes,
//! registered with the script's path ([`CommandTypes::register_script`], as `ace_app::App::hunt_script`
//! does for the binary). An executable command whose path is a registered script's runs that type
//! with what ace3 would have handed the script: the rendered arguments as its argv, the event or
//! the stream on stdin, the command's rendered `env:`, and its `files:`, which it reads by the names
//! the script would see beside itself. An executable that isn't a registered script fails its step,
//! so its event alerts, as before; a hunt naming one still loads and validates.
//!
//! The rest is ace3's `_execute_executable`: the arguments and `env:` render with `_event` and
//! `_events` only, the cache key is the path, the rendered arguments and the rendered `env:`, a
//! stream transform's input is its events as JSON lines and an event transform's is the event when
//! `stdin: true`, a non-zero exit fails the step with the exit code and stderr, and stdout and
//! stderr are scrubbed of the run's secrets. The script's `files:` must be files, as ace3's staging
//! requires (`stage_executable`), and the script's own path too; a script type reads nothing else.
//! A type keeps to the command's `timeout` itself, each network call bounded by what's left of it,
//! and one that ends past it fails as ace3's runner's kill does.
//!
//! What the types don't get, and needn't: ace3's runner, its Landlock rules, its rlimits and its
//! environment allowlist, since nothing is executed. A script type sees no environment but the
//! command's own `env:`.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{NaiveDate, TimeDelta};
use serde_json::{Map as JsonMap, Value as Json};

use super::Command;
use super::cache::{get_cached, set_cached};
use super::command::{Call, timespec};
use super::engine::Engine;
use super::expr::render;
use super::pyjson::dumps_map;
use super::trace::sanitize;

/// The most of one staged file a script type reads.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// What a script type is handed, as ace3 handed the script.
pub struct ScriptCall<'a> {
    /// The rendered `args`, the script's `sys.argv[1:]`.
    pub argv: &'a [String],
    pub stdin: Option<&'a str>,
    /// The command's rendered `env:`, the only environment a script type sees.
    pub env: &'a [(String, String)],
    pub files: &'a Staged,
    /// When the command's `timeout` runs out.
    pub deadline: Instant,
    /// `datetime.date.today()`, from the run's clock.
    pub today: NaiveDate,
}

impl ScriptCall<'_> {
    /// What's left of the command's time, at most `cap`: the bound for one network call.
    pub fn bound(&self, cap: Duration) -> Duration {
        self.deadline
            .saturating_duration_since(Instant::now())
            .min(cap)
    }

    pub fn timed_out(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

/// A script that didn't exit 0: its exit code and what it wrote to stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptExit {
    pub code: i32,
    pub stderr: String,
}

impl ScriptExit {
    /// An uncaught Python exception's exit: code 1 and the exception's last line.
    pub fn raised(kind: &str, message: &str) -> ScriptExit {
        let last = if message.is_empty() {
            kind.to_owned()
        } else {
            format!("{kind}: {message}")
        };
        ScriptExit {
            code: 1,
            stderr: format!("Traceback (most recent call last):\n{last}\n"),
        }
    }
}

/// A script command type: what one of the hunts' scripts computes. One instance serves every hunt.
pub trait Script: Send + Sync {
    /// The script's stdout, or how it exited when that isn't 0.
    fn run(&self, call: &ScriptCall<'_>) -> Result<String, ScriptExit>;
}

/// A command's script and its `files:` as the script would see them: each by its path relative to
/// the directory they share, as ace3's runner copies them into the script's working directory.
#[derive(Debug, Clone, Default)]
pub struct Staged {
    /// The script's own directory, relative to the working directory.
    script_dir: PathBuf,
    files: BTreeMap<PathBuf, PathBuf>,
}

impl Staged {
    /// `stage_executable`: each source must be a file, followed through symlinks, inside one of
    /// `roots` (the hunt repositories) when there are any.
    pub fn stage(path: &str, files: &[String], roots: &[PathBuf]) -> Result<Staged, String> {
        let roots: Vec<PathBuf> = roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(r).ok())
            .collect();
        let mut real = Vec::new();
        for source in std::iter::once(path).chain(files.iter().map(String::as_str)) {
            let resolved = std::fs::canonicalize(source).unwrap_or_else(|_| PathBuf::from(source));
            if !roots.is_empty() && !roots.iter().any(|r| resolved.starts_with(r)) {
                return Err(format!(
                    "RuntimeError: {source} is outside the hunt repositories; an executable and its files must live in a hunt rule directory's repository"
                ));
            }
            if !resolved.is_file() {
                return Err(format!("RuntimeError: {source} is not a file"));
            }
            real.push(resolved);
        }
        let base = common_dir(&real);
        let relative = |p: &Path| {
            p.strip_prefix(&base)
                .map(Path::to_path_buf)
                .unwrap_or_default()
        };
        let script_dir = relative(&real[0])
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let files = real.iter().map(|p| (relative(p), p.clone())).collect();
        Ok(Staged { script_dir, files })
    }

    /// Files a test hands a script type directly: each name beside the script.
    pub fn from_files(files: impl IntoIterator<Item = (String, PathBuf)>) -> Staged {
        Staged {
            script_dir: PathBuf::new(),
            files: files
                .into_iter()
                .map(|(name, path)| (PathBuf::from(name), path))
                .collect(),
        }
    }

    /// `Path(__file__).parent / name`, read: None when nothing staged is there, as a missing file.
    pub fn read_beside_script(&self, name: &str) -> Option<Result<Vec<u8>, String>> {
        self.read(&normalize(&self.script_dir.join(name)))
    }

    /// A path the script was given, read as it would open it from its working directory: a
    /// relative path among the staged files, and nothing absolute, since a script type reads only
    /// what the command stages.
    pub fn read_argument(&self, path: &str) -> Option<Result<Vec<u8>, String>> {
        if Path::new(path).is_absolute() {
            return None;
        }
        self.read(&normalize(Path::new(path)))
    }

    fn read(&self, relative: &Path) -> Option<Result<Vec<u8>, String>> {
        let real = self.files.get(relative)?;
        Some(read_bounded(real))
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(format!("larger than {MAX_FILE_BYTES} bytes"));
    }
    Ok(bytes)
}

/// `os.path.commonpath` of the files' directories.
fn common_dir(paths: &[PathBuf]) -> PathBuf {
    let dirs: Vec<&Path> = paths.iter().filter_map(|p| p.parent()).collect();
    let Some(first) = dirs.first() else {
        return PathBuf::new();
    };
    let mut common: Vec<Component<'_>> = first.components().collect();
    for dir in &dirs[1..] {
        let shared = common
            .iter()
            .zip(dir.components())
            .take_while(|(a, b)| **a == *b)
            .count();
        common.truncate(shared);
    }
    common.iter().collect()
}

/// `os.path.normpath` of a relative path.
fn normalize(path: &Path) -> PathBuf {
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(p) => parts.push(p),
            // above the working directory: nothing staged is there
            Component::ParentDir if parts.pop().is_none() => return PathBuf::from(".."),
            _ => {}
        }
    }
    parts.iter().collect()
}

/// A script type, or why it failed to build.
pub type Built = Result<Arc<dyn Script>, String>;

/// A registered type, by the components of its path, with its name.
#[derive(Clone)]
struct Entry {
    suffix: Vec<String>,
    name: String,
    handler: Built,
}

/// The script types, each by the path its hunts give, matched on the path's last components.
#[derive(Clone, Default)]
pub struct Scripts {
    entries: Vec<Entry>,
    roots: Vec<PathBuf>,
}

impl Scripts {
    /// Registers `handler` as `name` for every executable whose path ends with `suffix`, such as
    /// `hunts/scripts/dns_lookup.py`; one already registered for that suffix is replaced.
    pub fn register(&mut self, suffix: &str, name: &str, handler: Arc<dyn Script>) {
        self.add(suffix, name, Ok(handler));
    }

    /// A type that failed to build: the hunts that run its script fail per step with `error`.
    pub fn failed(&mut self, suffix: &str, name: &str, error: &str) {
        self.add(suffix, name, Err(error.to_owned()));
    }

    fn add(&mut self, suffix: &str, name: &str, handler: Built) {
        let suffix = components(suffix);
        self.entries.retain(|e| e.suffix != suffix);
        self.entries.push(Entry {
            suffix,
            name: name.to_owned(),
            handler,
        });
    }

    /// The type for an executable's path, as its name and the type or why it failed to build.
    pub fn find(&self, path: &str) -> Option<(&str, &Built)> {
        let parts = components(path);
        self.entries
            .iter()
            .filter(|e| !e.suffix.is_empty() && parts.ends_with(&e.suffix))
            .max_by_key(|e| e.suffix.len())
            .map(|e| (e.name.as_str(), &e.handler))
    }

    /// The hunt repositories a script and its `files:` must be inside, ace3's
    /// `get_hunt_source_roots`; none checks nothing.
    pub fn set_roots(&mut self, roots: Vec<PathBuf>) {
        self.roots = roots;
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Each registered suffix and the type's name.
    pub fn names(&self) -> Vec<(String, &str)> {
        self.entries
            .iter()
            .map(|e| (e.suffix.join("/"), e.name.as_str()))
            .collect()
    }
}

fn components(path: &str) -> Vec<String> {
    normalize_abs(path)
        .split('/')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `os.path.normpath` as text.
fn normalize_abs(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    parts.join("/")
}

/// The step error for an executable that isn't a registered script.
pub fn no_script_type(path: &str) -> String {
    format!(
        "RuntimeError: executable {path} isn't a script command type here: ace4 runs no hunt script, and its script command types run in ace hunter (PLAN.md decision 16)"
    )
}

/// `str(timedelta)`.
pub fn timedelta_str(delta: TimeDelta) -> String {
    let total = delta.num_seconds();
    let micros = delta.subsec_nanos() / 1000;
    let days = total.div_euclid(86_400);
    let rest = total.rem_euclid(86_400);
    let clock = format!("{}:{:02}:{:02}", rest / 3600, (rest / 60) % 60, rest % 60);
    let clock = if micros != 0 {
        format!("{clock}.{micros:06}")
    } else {
        clock
    };
    match days {
        0 => clock,
        1 | -1 => format!("{days} day, {clock}"),
        _ => format!("{days} days, {clock}"),
    }
}

impl Engine<'_> {
    /// `_execute_executable`, with the registered script type in place of the script.
    pub(super) fn execute_executable(
        &mut self,
        command: &Command,
        call: Call<'_>,
    ) -> Result<String, String> {
        let timeout = timespec(&command.timeout)?;
        let mut argv = Vec::new();
        for arg in command.args.iter().flatten() {
            argv.push(render(self.rt.renderer, arg, call.scope)?);
        }
        let mut env: Vec<(String, String)> = Vec::new();
        for (key, value) in command.env.iter().flatten() {
            let rendered = render(self.rt.renderer, value, call.scope)?;
            match env.iter_mut().find(|(k, _)| k == key) {
                Some(entry) => entry.1 = rendered,
                None => env.push((key.clone(), rendered)),
            }
        }
        let path = command.path.clone().unwrap_or_default();
        let mut cache_args = JsonMap::new();
        cache_args.insert("type".to_owned(), Json::from("executable"));
        cache_args.insert("path".to_owned(), Json::from(path.clone()));
        cache_args.insert(
            "args".to_owned(),
            Json::Array(argv.iter().cloned().map(Json::from).collect()),
        );
        cache_args.insert(
            "env".to_owned(),
            if env.is_empty() {
                Json::Null
            } else {
                Json::Object(
                    env.iter()
                        .map(|(k, v)| (k.clone(), Json::from(v.clone())))
                        .collect(),
                )
            },
        );
        let cache = command.cache.as_deref().filter(|c| !c.is_empty());
        if cache.is_some()
            && let Some(cached) =
                get_cached(self.rt.cache, &cache_args, self.rt.secrets, &mut self.logs)
        {
            return Ok(cached);
        }
        let stdin = if call.transform_type == "stream" {
            Some(
                call.scope
                    .events
                    .iter()
                    .map(|e| dumps_map(e, false))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
        } else if command.stdin == Some(true) {
            Some(dumps_map(call.scope.event, false))
        } else {
            None
        };
        let script = match self.rt.command_types.scripts().find(&path) {
            None => return Err(no_script_type(&path)),
            Some((name, Err(error))) => {
                return Err(format!(
                    "ValueError: script command type {} failed to load: {error}",
                    crate::value::py_repr(name)
                ));
            }
            Some((_, Ok(script))) => script.clone(),
        };
        let staged = Staged::stage(
            &path,
            command.files.as_deref().unwrap_or_default(),
            self.rt.command_types.scripts().roots(),
        )?;
        let budget = timeout.to_std().unwrap_or(Duration::ZERO);
        let started = Instant::now();
        let deadline = started.checked_add(budget).unwrap_or(started);
        let today = (self.rt.clock)().date_naive();
        let result = script.run(&ScriptCall {
            argv: &argv,
            stdin: stdin.as_deref(),
            env: &env,
            files: &staged,
            deadline,
            today,
        });
        if Instant::now() > deadline {
            return Err(format!(
                "RuntimeError: command timed out after {}",
                timedelta_str(timeout)
            ));
        }
        let stdout = match result {
            Ok(stdout) => stdout,
            Err(exit) => {
                return Err(sanitize(
                    &format!(
                        "RuntimeError: command exited with code {}: {}",
                        exit.code, exit.stderr
                    ),
                    self.rt.secrets,
                ));
            }
        };
        let stdout = sanitize(&stdout, self.rt.secrets);
        if let Some(cache) = cache {
            let ttl = timespec(cache)?.num_seconds();
            set_cached(
                self.rt.cache,
                &cache_args,
                &stdout,
                ttl,
                self.rt.secrets,
                &mut self.logs,
            );
        }
        Ok(stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_script_is_found_by_the_end_of_its_path() {
        struct Echo;
        impl Script for Echo {
            fn run(&self, _: &ScriptCall<'_>) -> Result<String, ScriptExit> {
                Ok(String::new())
            }
        }
        let mut scripts = Scripts::default();
        scripts.register("hunts/scripts/dns_lookup.py", "dns_lookup", Arc::new(Echo));
        assert_eq!(
            scripts
                .find("/opt/signatures/hunts/commands/../scripts/dns_lookup.py")
                .map(|(n, _)| n),
            Some("dns_lookup")
        );
        assert!(
            scripts
                .find("/opt/signatures/other/dns_lookup.py")
                .is_none()
        );
        assert!(
            scripts
                .find("/opt/x/hunts/scripts/dns_lookup.py.bak")
                .is_none()
        );
        assert!(scripts.find("").is_none());
    }

    #[test]
    fn timedeltas_read_as_python_writes_them() {
        assert_eq!(timedelta_str(TimeDelta::seconds(1)), "0:00:01");
        assert_eq!(timedelta_str(TimeDelta::seconds(300)), "0:05:00");
        assert_eq!(
            timedelta_str(TimeDelta::seconds(86_400 + 61)),
            "1 day, 0:01:01"
        );
        assert_eq!(timedelta_str(TimeDelta::days(3)), "3 days, 0:00:00");
    }

    #[test]
    fn staged_files_are_read_beside_the_script() {
        let dir = tempfile::tempdir().expect("a directory");
        let scripts = dir.path().join("hunts/scripts");
        std::fs::create_dir_all(&scripts).expect("made");
        std::fs::write(scripts.join("s.py"), "").expect("written");
        std::fs::write(scripts.join("data.json"), "{}").expect("written");
        std::fs::write(scripts.join("other.json"), "{}").expect("written");
        let path = scripts.join("s.py").to_string_lossy().into_owned();
        let data = scripts.join("data.json").to_string_lossy().into_owned();
        let staged = Staged::stage(&path, &[data], &[]).expect("staged");
        assert_eq!(
            staged.read_beside_script("data.json"),
            Some(Ok(b"{}".to_vec()))
        );
        // a file the command doesn't stage isn't there for the script
        assert!(staged.read_beside_script("other.json").is_none());
        assert!(staged.read_argument("/etc/passwd").is_none());
        assert!(staged.read_argument("data.json").is_some());
        let missing = scripts.join("missing.json").to_string_lossy().into_owned();
        assert_eq!(
            Staged::stage(&path, std::slice::from_ref(&missing), &[]).map(|_| ()),
            Err(format!("RuntimeError: {missing} is not a file"))
        );
    }
}
