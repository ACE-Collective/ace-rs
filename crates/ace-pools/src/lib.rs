//! The open-source pool binaries (PLAN.md 2.29): `ace-parsers`, the parser pool, which runs the
//! email, archive and YARA modules one contained process per task, and `ace-lookups`, the
//! network pool, which runs the RDAP and Splunk modules as async tasks in one contained process
//! (DESIGN.md's *Modules and pools*). 2.31 turns them into short mains over `ace-app`.
//!
//! What they share: the site overlay at `ACE4_OVERLAY`, read through `Registry::start`'s rules
//! (only the pool's own modules' sections, and only the secrets its modules declare); a stop on
//! SIGTERM or SIGINT; and a heartbeat file the container's healthcheck reads.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ace_pool::modules::{Modules, Registry, StartError};
use ace_sdk::{Component, Overlay};
use tokio_util::sync::CancellationToken;

/// The parser pool's modules.
pub fn parser_registry() -> Registry {
    Registry::new()
        .parser::<ace_mod_email::EmailAnalyzer>()
        .parser::<ace_mod_archive::ArchiveAnalyzer>()
        .parser::<ace_mod_yara::YaraScanner>()
}

/// The network pool's modules.
pub fn lookup_registry() -> Registry {
    Registry::new()
        .lookup::<ace_mod_rdap::RdapAnalyzer>()
        .lookup::<ace_mod_splunk::SplunkAnalyzer>()
}

/// The overlay at `path`, or none.
pub fn overlay(path: Option<&Path>) -> Result<Overlay, String> {
    match path {
        Some(path) => Overlay::read(path).map_err(|e| e.to_string()),
        None => Ok(Overlay::default()),
    }
}

/// The overlay's path from `ACE4_OVERLAY`, if it's set.
pub fn overlay_path() -> Option<PathBuf> {
    std::env::var_os("ACE4_OVERLAY")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

/// The pool's components from the overlay, and the YARA module's ruleset directory set to the
/// pool's own, `rulesets`, whatever the overlay says: the pool keeps that directory on the
/// core's ruleset, so the site overlay needn't know where it is.
pub fn components(
    registry: &Registry,
    overlay: &Overlay,
    rulesets: Option<&Path>,
) -> Result<Vec<Component>, StartError> {
    let manifests = registry.manifests();
    let mut components = overlay.for_pool(&manifests).components(&manifests)?;
    if let Some(dir) = rulesets {
        for component in &mut components {
            if component.manifest.name == ace_mod_yara::MANIFEST.name {
                let mut settings = component
                    .settings
                    .take()
                    .unwrap_or_else(|| serde_json::json!({}));
                if let Some(object) = settings.as_object_mut() {
                    object.insert(
                        "rulesets".to_owned(),
                        serde_json::Value::String(dir.display().to_string()),
                    );
                }
                component.settings = Some(settings);
            }
        }
    }
    Ok(components)
}

/// Builds the pool's modules: its components, with the secrets their manifests declare read
/// through `env`.
pub fn modules(
    pool: &str,
    registry: &Registry,
    overlay: &Overlay,
    rulesets: Option<&Path>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Modules, StartError> {
    let components = components(registry, overlay, rulesets)?;
    let manifests: Vec<_> = components.iter().map(|c| c.manifest).collect();
    let secrets = ace_pool::secrets::resolve(pool, &manifests, overlay, env);
    Ok(registry.build(&components, &secrets)?)
}

/// A variable's value, or `default` when it isn't set.
pub fn var(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

/// A variable's number, or `default`.
pub fn number(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Where the heartbeat goes, `ACE4_HEALTH_FILE`; in the temporary directory, which a contained
/// network pool may write.
pub fn health_file() -> PathBuf {
    std::env::var_os("ACE4_HEALTH_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("ace4-health"))
}

/// This process's name as a worker: the host's name, which is the container's id in Compose,
/// and the process id.
pub fn worker_name() -> String {
    let host = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    format!("{}-{}", host.trim(), std::process::id())
}

/// How often the heartbeat is written. The healthcheck allows a few missed beats.
pub const HEARTBEAT: Duration = Duration::from_secs(5);

/// Writes the time to `path` every `HEARTBEAT` until `stop` fires, so a healthcheck can tell
/// that the pool's runtime still runs.
pub async fn heartbeat(path: PathBuf, stop: CancellationToken) {
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        if let Err(e) = tokio::fs::write(&path, format!("{now}\n")).await {
            tracing::warn!(path = %path.display(), "writing the heartbeat failed: {e}");
        }
        tokio::select! {
            () = stop.cancelled() => return,
            () = tokio::time::sleep(HEARTBEAT) => {}
        }
    }
}

/// A token that fires on SIGTERM or SIGINT.
pub fn stop_on_signal() -> CancellationToken {
    let stop = CancellationToken::new();
    let stopping = stop.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(e) => {
                tracing::error!("no SIGTERM handler: {e}");
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::error!("waiting for a signal failed: {e}");
                }
            }
        }
        tracing::info!("stopping");
        stopping.cancel();
    });
    stop
}

/// Runs `work` on a new multi-threaded runtime.
pub fn with_runtime(
    work: impl std::future::Future<Output = std::process::ExitCode>,
) -> std::process::ExitCode {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(work),
        Err(e) => {
            eprintln!("no runtime: {e}");
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_yara_module_gets_the_pools_ruleset_directory() {
        let overlay = Overlay::from_yaml(
            "modules:\n  yara_scanner_v3_4:\n    settings:\n      blacklist: [noisy]\n  rdap_analyzer:\n    settings:\n      request_timeout_seconds: 5\n",
        )
        .expect("reads");
        let components = components(
            &parser_registry(),
            &overlay,
            Some(Path::new("/var/lib/ace4/rulesets")),
        )
        .expect("components");
        let yara = components
            .iter()
            .find(|c| c.key == "yara_scanner_v3_4")
            .expect("the YARA module");
        assert_eq!(
            yara.settings,
            Some(serde_json::json!({
                "blacklist": ["noisy"],
                "rulesets": "/var/lib/ace4/rulesets",
            }))
        );
        // the network pool's section isn't the parser pool's, so it's skipped
        let keys: Vec<&str> = components.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["email_analyzer", "archive", "yara_scanner_v3_4"]);
    }
}
