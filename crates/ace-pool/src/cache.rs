//! The pool's half of the analysis cache (PLAN.md decision 26, `ace_sdk::cache`): what in the
//! pool's image a cacheable module's result depends on, read once when the pool starts and sent
//! with each of that module's results (`TaskEnd::Done::probes`), so the core keeps the result under
//! the versions that made it, as ace3's `extended_version` probes its node's tools
//! (`saq/modules/tool_version.py`).
//!
//! A tool's version is the first line its version arguments print (`ToolSpec::version_args`), run as
//! a plain child process with an empty environment and nothing to read: the program is the image's
//! own and is given no input, which is why it needn't be contained as a task's runs are. A file's is
//! the sha256 of its bytes, and a library's what the module's `Cache::libraries` says. A module whose
//! probes don't all answer gets none, and the core then keeps none of its results.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ace_sdk::cache::{Cache, version_line};
use ace_sdk::tools::ToolSpec;
use ace_sdk::wire::TaskEnd;
use sha2::{Digest, Sha256};

use crate::modules::Modules;

/// How long a tool may take to print its version.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Each cacheable component's probes, by its key.
pub type Probes = BTreeMap<String, BTreeMap<String, String>>;

/// The probes of every cacheable module the pool runs. One that doesn't answer is left out, with a
/// warning: its results then aren't kept.
pub fn probe_modules(modules: &Modules, tools: &[ToolSpec]) -> Probes {
    let mut probes = Probes::new();
    for (key, manifest) in modules.components() {
        let Some(cache) = manifest.cache else {
            continue;
        };
        match probe(&cache, tools) {
            Ok(found) => {
                tracing::info!(module = key, ?found, "the analysis cache's versions");
                probes.insert(key.to_owned(), found);
            }
            Err(why) => tracing::warn!(
                module = key,
                "the module's results won't be kept in the analysis cache: {why}"
            ),
        }
    }
    probes
}

/// What `cache` says its results depend on in this image.
pub fn probe(cache: &Cache, tools: &[ToolSpec]) -> Result<BTreeMap<String, String>, String> {
    let mut found = BTreeMap::new();
    for name in cache.tools {
        let spec = tools
            .iter()
            .find(|spec| spec.name == *name)
            .ok_or_else(|| format!("the pool doesn't carry {name}"))?;
        if spec.version_args.is_empty() {
            return Err(format!("{name} has no version_args"));
        }
        found.insert(format!("tool:{name}"), tool_version(spec)?);
    }
    for path in cache.files {
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        found.insert(format!("file:{path}"), hex(&Sha256::digest(&bytes)));
    }
    for (name, version) in (cache.libraries)() {
        found.insert(format!("library:{name}"), version);
    }
    Ok(found)
}

/// Adds the module's probes to a result's end, for a module that has them.
pub fn attach(end: &mut TaskEnd, module: &str, probes: &Probes) {
    if let (TaskEnd::Done { probes: sent, .. }, Some(found)) = (end, probes.get(module)) {
        sent.clone_from(found);
    }
}

fn tool_version(spec: &ToolSpec) -> Result<String, String> {
    let mut child = Command::new(spec.program)
        .args(spec.args)
        .args(spec.version_args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", spec.program))?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if started.elapsed() > PROBE_TIMEOUT {
            child.kill().ok();
            child.wait().ok();
            return Err(format!("{} didn't print its version in time", spec.name));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    if let Some(mut out) = child.stdout.take() {
        out.read_to_end(&mut stdout).map_err(|e| e.to_string())?;
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_end(&mut stderr).map_err(|e| e.to_string())?;
    }
    let first = version_line(&stdout, &stderr);
    if !status.success() {
        // what a tool prints when it rejects its version arguments is its complaint, not a version
        return Err(format!(
            "{} exited with {status}: {}",
            spec.name,
            first.as_deref().unwrap_or("")
        ));
    }
    first.ok_or_else(|| format!("{} printed no version", spec.name))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn libraries() -> Vec<(&'static str, String)> {
        vec![("opencv", "4.12.0".to_owned())]
    }

    #[test]
    fn a_tool_s_version_is_what_it_prints_first() {
        let spec = ToolSpec {
            version_args: &["-c", "echo; echo 'sh 1.2'; echo more"],
            ..ace_sdk::tools::SANDBOX_TOOLS[0]
        };
        let spec = ToolSpec {
            name: "sh",
            program: "/bin/sh",
            interpreter: None,
            args: &[],
            ..spec
        };
        let cache = Cache {
            tools: &["sh"],
            files: &["/etc/hostname"],
            libraries,
            ..Cache::new(1, Duration::from_secs(60))
        };
        let found = probe(&cache, &[spec]).expect("probes");
        assert_eq!(found["tool:sh"], "sh 1.2");
        assert_eq!(found["file:/etc/hostname"].len(), 64);
        assert_eq!(found["library:opencv"], "4.12.0");
        // a tool the pool doesn't carry, or a file it hasn't, leaves the module with none
        let missing = Cache {
            tools: &["tesseract"],
            ..Cache::new(1, Duration::from_secs(60))
        };
        assert!(probe(&missing, &[spec]).is_err());
        let missing = Cache {
            files: &["/no/such/file"],
            ..Cache::new(1, Duration::from_secs(60))
        };
        assert!(probe(&missing, &[spec]).is_err());
    }

    #[test]
    fn a_tool_that_exits_non_zero_has_no_version() {
        // a tool that rejects its version arguments prints its complaint and exits non-zero; that
        // line was taken for its version, and so went into the cache key
        let spec = ToolSpec {
            name: "sh",
            program: "/bin/sh",
            interpreter: None,
            args: &[],
            version_args: &["-c", "echo 'sh: unknown option --version' >&2; exit 2"],
            ..ace_sdk::tools::SANDBOX_TOOLS[0]
        };
        let cache = Cache {
            tools: &["sh"],
            ..Cache::new(1, Duration::from_secs(60))
        };
        let why = probe(&cache, &[spec]).expect_err("no version");
        assert_eq!(
            why,
            "sh exited with exit status: 2: sh: unknown option --version"
        );
    }

    #[test]
    fn only_a_result_gets_the_probes() {
        let mut probes = Probes::new();
        probes.insert(
            "qrcode".to_owned(),
            BTreeMap::from([("tool:gs".to_owned(), "10.05.1".to_owned())]),
        );
        let mut done = TaskEnd::Done {
            result: serde_json::from_value(serde_json::json!(
                {"analysis_type": "qrcode", "schema_version": 1, "details": {}}
            ))
            .expect("an envelope"),
            writes: Vec::new(),
            probes: BTreeMap::new(),
            keep: true,
            keep_for_seconds: None,
        };
        attach(&mut done, "other", &probes);
        assert!(matches!(&done, TaskEnd::Done { probes, .. } if probes.is_empty()));
        attach(&mut done, "qrcode", &probes);
        assert!(matches!(&done, TaskEnd::Done { probes, .. } if probes["tool:gs"] == "10.05.1"));
        let mut skipped = TaskEnd::Skipped {
            reason: String::new(),
            writes: Vec::new(),
        };
        attach(&mut skipped, "qrcode", &probes);
    }
}
