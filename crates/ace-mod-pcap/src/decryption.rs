//! ace3's `PcapTlsDecryptor`: once the rest of the alert is done, as ace3's final analysis, tshark
//! again with every TLS key log in the alert, adding what the decrypted traffic shows beyond the
//! plaintext index (`apply_keylogs`).
//!
//! The key logs are the files tls_keylog tagged, which ace3 finds by the same sniff of every file in
//! the alert; the pool downloads them for the task (`Module::READS_TREE_FILES`). Their key log lines
//! go to a file in the task's scratch directory, which tshark reads, and which is removed once it
//! has.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ace_results::types::pcap::{KeylogSource, PcapAnalysis, PcapTlsDecryptionAnalysis};
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::tree::TreeFiles;
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};

use crate::analyzer::out_of_time;
use crate::budget::{CaptureFile, PcapSettings, add, collect_observables, shares};
use crate::config::{MAX_KEYLOG_SIZE, MAX_TABLE_ROWS, run_seconds};
use crate::index::{CATEGORY_HOSTS, Target, dissect, merge_index};
use crate::keylog::{TAG_TLS_KEYLOG, is_keylog_file, read_keylog};
use crate::{format_counts, is_pcap_file};

/// The pcap_tls_decryption module.
pub struct PcapTlsDecryptor;

impl Module for PcapTlsDecryptor {
    const NAME: &'static str = "pcap_tls_decryption";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[PcapAnalysis::MODULE];
    const TOOLS: &'static [&'static str] = &["tshark"];
    const RUNS_LAST: bool = true;
    const READS_TREE: bool = true;
    const READS_TREE_FILES: Option<TreeFiles> = Some(TreeFiles {
        names_containing: &[],
        max_size: MAX_KEYLOG_SIZE,
        tagged: Some(TAG_TLS_KEYLOG),
    });
    /// ace3's `maximum_analysis_time`, 180 s: one tshark run with the work around it.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(180),
        memory_mb: 2048,
        cpu_seconds: 180,
    };
    type Output = PcapTlsDecryptionAnalysis;
    type Settings = PcapSettings;

    fn init(_: &PcapSettings) -> Result<Self, ModuleError> {
        Ok(PcapTlsDecryptor)
    }
}

/// A key log in the alert: its sha256, its name, and where the pool put it.
struct Keylog {
    sha256: String,
    file_name: String,
    path: std::path::PathBuf,
}

/// `find_keylog_observables`: every file of the alert that is a TLS key log, in sha256 order.
fn find_keylogs(ctx: &TaskContext<PcapSettings>) -> Vec<Keylog> {
    let Some(tree) = ctx.tree() else {
        return Vec::new();
    };
    let mut keylogs: Vec<Keylog> = tree
        .of_kind(ObservableKind::File)
        .filter_map(|i| {
            let observable = tree.observable(i);
            let path = ctx.tree_file(&observable.value)?;
            let size = std::fs::metadata(&path).ok()?.len();
            if !path.is_file() || size > MAX_KEYLOG_SIZE || !is_keylog_file(&path) {
                return None;
            }
            let alert_path = observable
                .paths
                .first()
                .map(|p| p.path.as_str())
                .unwrap_or_default();
            Some(Keylog {
                sha256: observable.value.clone(),
                file_name: alert_path
                    .rsplit('/')
                    .next()
                    .unwrap_or(alert_path)
                    .to_owned(),
                path,
            })
        })
        .collect();
    keylogs.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    keylogs
}

impl Parser for PcapTlsDecryptor {
    fn analyze(
        &self,
        ctx: &TaskContext<PcapSettings>,
    ) -> Result<Outcome<PcapTlsDecryptionAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if !file.local_path.is_file() || !is_pcap_file(&file.local_path) {
            return Ok(Outcome::Skipped("not a pcap or pcapng file".to_owned()));
        }
        let Some(PcapAnalysis {
            error: None,
            index: Some(plaintext),
            ..
        }) = ctx.dependency_result::<PcapAnalysis>()?
        else {
            return Ok(Outcome::Skipped(
                "pcap_analyzer has no index of the capture".to_owned(),
            ));
        };
        if plaintext.tls.is_empty() {
            return Ok(Outcome::Skipped("the capture has no TLS".to_owned()));
        }
        let mut result = ResultEnvelope::new(PcapTlsDecryptionAnalysis::default());
        let left = ctx.time_left();
        if run_seconds() > left {
            tracing::info!(
                "not decrypting the capture: {:?} needed, {left:?} left",
                run_seconds()
            );
            result.details.error = Some(out_of_time(run_seconds(), left));
            result.summary = Some(summary(&result.details));
            return Ok(Outcome::Done(result));
        }
        let keylogs = find_keylogs(ctx);

        // apply_keylogs
        let details = &mut result.details;
        let mut lines: Vec<String> = Vec::new();
        let mut known_lines: BTreeSet<String> = BTreeSet::new();
        let mut client_randoms: BTreeSet<String> = BTreeSet::new();
        for keylog in &keylogs {
            let contents = read_keylog(&keylog.path)?;
            details.keylogs.push(KeylogSource {
                sha256: keylog.sha256.clone(),
                file_name: keylog.file_name.clone(),
                label_counts: contents.label_counts,
            });
            client_randoms.extend(contents.client_randoms);
            for line in contents.lines {
                if known_lines.insert(line.clone()) {
                    lines.push(line);
                }
            }
        }
        details.capture = Some(plaintext.capture.clone().flatten());
        let sessions: BTreeSet<String> = plaintext
            .tls_client_randoms
            .iter()
            .flatten()
            .cloned()
            .collect();
        let embedded: BTreeSet<String> = plaintext
            .embedded_secrets
            .iter()
            .flat_map(|e| e.keyed_client_randoms.iter().cloned())
            .collect();
        details.sessions = sessions.len() as u64;
        details.sessions_with_embedded_keys = Some(embedded.len() as u64);
        details.sessions_with_keys = sessions
            .iter()
            .filter(|r| client_randoms.contains(*r) || embedded.contains(*r))
            .count() as u64;
        let has_rsa_keys = details
            .keylogs
            .iter()
            .any(|k| k.label_counts.contains_key("RSA"));
        let new_sessions = sessions
            .iter()
            .any(|r| client_randoms.contains(r) && !embedded.contains(r));
        if lines.is_empty() || !(new_sessions || has_rsa_keys) {
            result.summary = Some(summary(&result.details));
            return Ok(Outcome::Done(result));
        }

        // whatever the plaintext pass found is not carved again
        let known: BTreeSet<String> = plaintext.carved_sha256.iter().cloned().collect();
        let scratch = ctx
            .scratch_dir()
            .ok_or_else(|| ModuleError::other("no scratch directory for tshark's key log"))?;
        let keylog_path = scratch.join("keylog");
        std::fs::write(&keylog_path, lines.join("\n") + "\n")?;
        let alert_path = file.path.to_string();
        let target = Target {
            capture_path: &alert_path,
            suffix: "pcap_decrypted",
        };
        let dissected = dissect(
            ctx,
            &file.local_path,
            &target,
            Some(&keylog_path),
            &known,
            false,
        );
        // the key material is tshark's alone, and only while it runs
        std::fs::remove_file(&keylog_path).ok();
        let details = &mut result.details;
        let dissection = match dissected? {
            Ok(dissection) => dissection,
            Err(e) => {
                // like a capture that cannot be dissected: the analyst sees it in the analysis
                tracing::info!("unable to decrypt the capture: {}", e.0);
                details.error = Some(e.0);
                result.summary = Some(summary(&result.details));
                return Ok(Outcome::Done(result));
            }
        };
        let mut index = dissection.index;
        index.tls_client_randoms = None;
        details.error = None;
        let capture = CaptureFile {
            sha256: &file.sha256.to_hex(),
            path: &alert_path,
        };
        let plaintext_keys: BTreeSet<(ObservableKind, String)> = collect_observables(&plaintext)
            .into_iter()
            .map(|o| (o.kind, o.value))
            .collect();
        let items: Vec<_> = collect_observables(&index)
            .into_iter()
            .filter(|o| {
                o.category != CATEGORY_HOSTS && !plaintext_keys.contains(&(o.kind, o.value.clone()))
            })
            .collect();
        details.index = Some(merge_index(None, index, MAX_TABLE_ROWS));
        // every pcap result of the capture counts: pcap_analyzer's and the categories'
        let shares = shares(&capture, &plaintext, &ctx.settings().categories, None);
        let node = add(&capture, &items, &shares.all(), &[]);
        let sizes: BTreeMap<_, _> = dissection
            .carved
            .iter()
            .map(|f| (f.sha256, f.size))
            .collect();
        details.added = node.added;
        details.omitted = node.omitted;
        result.observables = node.new_observables;
        result.files = node
            .new_files
            .into_iter()
            .map(|mut f| {
                f.size = sizes.get(&f.sha256).copied().unwrap_or_default();
                f
            })
            .collect();
        tracing::info!(
            "decrypted TLS with {} key logs: keys for {} of {} sessions, added {}",
            keylogs.len(),
            result.details.sessions_with_keys,
            result.details.sessions,
            format_counts(&result.details.added)
        );
        result.summary = Some(summary(&result.details));
        Ok(Outcome::Done(result))
    }
}

/// `PcapTlsDecryptionAnalysis.generate_summary`.
fn summary(details: &PcapTlsDecryptionAnalysis) -> String {
    if let Some(error) = &details.error {
        return format!("PCAP TLS Decryption: failed: {error}");
    }
    let mut sources = Vec::new();
    if details.sessions_with_embedded_keys.unwrap_or(0) > 0 {
        sources.push("embedded in the capture".to_owned());
    }
    if !details.keylogs.is_empty() {
        sources.push(format!("{} key logs", details.keylogs.len()));
    }
    if sources.is_empty() {
        return format!(
            "PCAP TLS Decryption: no TLS key log found ({} TLS sessions)",
            details.sessions
        );
    }
    let mut summary = format!(
        "PCAP TLS Decryption: keys for {} of {} TLS sessions ({})",
        details.sessions_with_keys,
        details.sessions,
        sources.join(" and ")
    );
    if !details.added.is_empty() {
        summary.push_str(&format!(", new: {}", format_counts(&details.added)));
    }
    summary
}
