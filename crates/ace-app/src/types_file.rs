//! The observable types a site's file adds (PLAN.md decision 66): ace3's `observable_types.yaml`,
//! its `observable_types.config_path`, in ace3's own format (`types:`, each with `extends`,
//! `default_display_type`, `description` and `deprecated`), named by `ACE_RS_OBSERVABLE_TYPES`.
//!
//! Every process reads it when it installs its types, so the core, the pools, the collectors and the
//! hunter know the same types, and a long-running one reads it again every `POLL`, as ace3's type
//! hierarchy reloads it every 60 seconds, taking a change when the file's contents changed
//! (`ace_results::merge_file_types`). A contained task or command process reads it once, before its
//! containment. A file that can't be read or doesn't parse keeps the types the process has, logged
//! at ERROR, as ace3 keeps its prior state; an entry that can't be a type is logged and left out.

use std::time::Duration;

/// The variable that names the types file.
pub const TYPES_FILE: &str = "ACE_RS_OBSERVABLE_TYPES";
/// How often a long-running process reads the file again, ace3's `_reload_check_interval`.
pub const POLL: Duration = Duration::from_secs(60);
/// The most bytes the file may hold.
pub const MAX_BYTES: u64 = 4 << 20;

/// The file's bytes, at most `MAX_BYTES`.
fn read(path: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("can't be read: {e}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("can't be read: {e}"))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(format!("is over {MAX_BYTES} bytes"));
    }
    Ok(bytes)
}

/// Merges the file's types into this process's, logging what changed and what was left out.
pub fn merge(path: &str, bytes: &[u8]) -> Result<ace_results::FileTypesMerged, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("isn't UTF-8: {e}"))?;
    let entries = ace_sdk::overlay::parse_types_file(text)?;
    let merged = ace_results::merge_file_types(&entries);
    for (name, why) in &merged.refused {
        tracing::error!(path, r#type = %name, "an observable type of the types file is left out: {why}");
    }
    if !merged.added.is_empty() || !merged.changed.is_empty() {
        tracing::info!(
            path,
            added = ?merged.added,
            changed = ?merged.changed,
            "observable types from the types file"
        );
    }
    Ok(merged)
}

/// The file's path and the bytes last merged from it, which `watch` compares the file with.
static SEEN: std::sync::Mutex<Option<(String, Option<Vec<u8>>)>> = std::sync::Mutex::new(None);

/// Reads the types file `ACE_RS_OBSERVABLE_TYPES` names, if any, once. A process that isn't to be
/// contained then calls `watch`; one that is calls it after its containment, which needs a
/// single-threaded process.
pub fn start() {
    let Some(path) = std::env::var(TYPES_FILE)
        .ok()
        .filter(|p| !p.trim().is_empty())
    else {
        return;
    };
    // the process's logging isn't set up yet: this first read reports on stderr
    let seen = match read(&path).and_then(|bytes| merge(&path, &bytes).map(|m| (bytes, m))) {
        Ok((bytes, merged)) => {
            eprintln!(
                "observable types from {path}: {} added, {} left out",
                merged.added.len(),
                merged.refused.len()
            );
            for (name, why) in &merged.refused {
                eprintln!("observable type {name} of {path} is left out: {why}");
            }
            Some(bytes)
        }
        Err(why) => {
            eprintln!(
                "the observable types file {path} {why}; this process has the binary's types"
            );
            None
        }
    };
    *SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((path, seen));
}

/// Reads the file `start` read again every `POLL`, on a thread of its own for as long as the
/// process runs, taking a change when its contents changed.
pub fn watch() {
    let Some((path, mut seen)) = SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    else {
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("observable-types".to_owned())
        .spawn({
            let path = path.clone();
            move || {
                loop {
                    std::thread::sleep(POLL);
                    let now = read(&path).ok();
                    if now.is_some() && now != seen {
                        seen = load(&path);
                    }
                }
            }
        });
    if let Err(e) = spawned {
        tracing::error!(path, "the types file won't be read again: {e}");
    }
}

/// Reads and merges the file once, returning the bytes it merged, or None when it couldn't.
fn load(path: &str) -> Option<Vec<u8>> {
    match read(path).and_then(|bytes| merge(path, &bytes).map(|_| bytes)) {
        Ok(bytes) => Some(bytes),
        Err(why) => {
            tracing::error!(
                path,
                "the observable types file {why}; the types this process has stay"
            );
            None
        }
    }
}
