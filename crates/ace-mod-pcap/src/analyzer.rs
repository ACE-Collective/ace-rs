//! ace3's `PcapAnalyzer`: capinfos and tshark's statistics and field runs over a capture, its index,
//! its hosts as observables, and the files it carves stored for the root, which pcap_files and
//! pcap_tls add.

use std::collections::BTreeSet;
use std::time::Duration;

use ace_results::types::pcap::{EmbeddedSecrets, PcapAnalysis};
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};

use crate::budget::{CaptureFile, add, collect_observables};
use crate::config::{CAPINFOS_TIMEOUT, MAX_FILE_SIZE, MAX_KEYLOG_SIZE, run_seconds};
use crate::index::{CATEGORY_HOSTS, Target, dissect, stored};
use crate::keylog::read_embedded_secrets;
use crate::{format_counts, is_pcap_file};

/// The tag a pcapng with Decryption Secrets Blocks gets, one per kind.
pub fn embedded_secrets_tags(secrets: &EmbeddedSecrets) -> Vec<String> {
    const KNOWN: [&str; 6] = [
        "TLS",
        "SSH",
        "WireGuard",
        "ZigBee NWK",
        "ZigBee APS",
        "OPC UA",
    ];
    let mut tags: BTreeSet<String> = BTreeSet::new();
    for name in secrets.types.keys() {
        let slug = if KNOWN.contains(&name.as_str()) {
            let mut slug = String::new();
            for c in name.to_lowercase().chars() {
                if c.is_ascii_lowercase() || c.is_ascii_digit() {
                    slug.push(c);
                } else if !slug.ends_with('_') {
                    slug.push('_');
                }
            }
            slug.trim_matches('_').to_owned()
        } else {
            "unknown".to_owned()
        };
        tags.insert(format!("pcap_embedded_{slug}_keys"));
    }
    tags.into_iter().collect()
}

/// `_describe_embedded`.
pub fn describe_embedded(secrets: &EmbeddedSecrets) -> String {
    secrets
        .types
        .keys()
        .map(|name| {
            if name == "TLS" {
                format!(
                    "TLS keys for {} sessions",
                    secrets.keyed_client_randoms.len()
                )
            } else {
                name.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `_out_of_time`.
pub fn out_of_time(needed: Duration, left: Duration) -> String {
    format!(
        "skipped: dissecting this capture can take {:.0} s and only {:.0} s are left of this module's \
         maximum_analysis_time or this alert's analysis time",
        needed.as_secs_f64(),
        left.as_secs_f64()
    )
}

/// The pcap_analyzer module.
pub struct PcapAnalyzer;

impl Module for PcapAnalyzer {
    const NAME: &'static str = "pcap_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["tshark", "capinfos"];
    /// ace3's `maximum_analysis_time`, 360 s: capinfos, then two tshark runs with the work around
    /// each. The JSON of 50,000 packets, up to the runner's 64 MiB, is parsed in the task.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(360),
        memory_mb: 2048,
        cpu_seconds: 360,
    };
    type Output = PcapAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(PcapAnalyzer)
    }
}

impl Parser for PcapAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<PcapAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let path = &file.local_path;
        if !path.is_file() || !is_pcap_file(path) {
            return Ok(Outcome::Skipped("not a pcap or pcapng file".to_owned()));
        }
        if file.size > MAX_FILE_SIZE {
            return Ok(failed(format!(
                "{} bytes exceeds max_file_size {MAX_FILE_SIZE}",
                file.size
            )));
        }
        let needed = CAPINFOS_TIMEOUT + run_seconds() * 2;
        let left = ctx.time_left();
        if needed > left {
            tracing::info!("not dissecting the capture: {needed:?} needed, {left:?} left");
            return Ok(failed(out_of_time(needed, left)));
        }
        let alert_path = file.path.to_string();
        let target = Target {
            capture_path: &alert_path,
            suffix: "pcap_objects",
        };
        let dissection = match dissect(ctx, path, &target, None, &BTreeSet::new(), true)? {
            Ok(dissection) => dissection,
            // a capture tshark cannot read is the analyst's to see, in the analysis
            Err(e) => {
                tracing::info!("unable to dissect the capture: {}", e.0);
                return Ok(failed(e.0));
            }
        };
        let embedded = read_embedded_secrets(path, MAX_KEYLOG_SIZE, || ctx.is_cancelled())?;
        let mut index = dissection.index;
        let mut result = ResultEnvelope::new(PcapAnalysis::default());
        if let Some(embedded) = embedded {
            // client randoms are sent in the clear; only the secrets keyed by them are sensitive
            let sessions: BTreeSet<&String> = index.tls_client_randoms.iter().flatten().collect();
            let secrets = EmbeddedSecrets {
                types: embedded.types,
                label_counts: embedded.label_counts,
                keyed_client_randoms: embedded
                    .client_randoms
                    .iter()
                    .filter(|r| sessions.contains(r))
                    .cloned()
                    .collect(),
            };
            for tag in embedded_secrets_tags(&secrets) {
                result.analyzed.add_tag(tag);
            }
            tracing::info!(
                "the capture carries embedded decryption secrets: {}",
                describe_embedded(&secrets)
            );
            index.embedded_secrets = Some(secrets);
        }
        if let Some(Some(capture)) = &mut index.capture {
            capture.file_name = file.name().to_owned();
        }
        let capture = CaptureFile {
            sha256: &file.sha256.to_hex(),
            path: &alert_path,
        };
        let hosts: Vec<_> = collect_observables(&index)
            .into_iter()
            .filter(|o| o.category == CATEGORY_HOSTS)
            .collect();
        let node = add(&capture, &hosts, &[], &[]);
        result.observables = node.new_observables;
        result.stored = stored(&dissection.carved);
        result.details.index = Some(index);
        result.details.added = node.added;
        result.details.omitted = node.omitted;
        result.summary = summary(&result.details);
        Ok(Outcome::Done(result))
    }
}

/// `_failed`: an analysis with the error alone.
fn failed(error: String) -> Outcome<PcapAnalysis> {
    let mut result = ResultEnvelope::new(PcapAnalysis {
        error: Some(error),
        ..PcapAnalysis::default()
    });
    result.summary = summary(&result.details);
    Outcome::Done(result)
}

/// `PcapAnalysis.generate_summary`.
pub fn summary(details: &PcapAnalysis) -> Option<String> {
    if let Some(error) = &details.error {
        return Some(format!("PCAP Analysis: failed: {error}"));
    }
    let index = details.index.as_ref()?;
    let statistics = index.statistics.clone().unwrap_or_default();
    let mut summary = match index
        .statistics_error
        .clone()
        .flatten()
        .filter(|e| !e.is_empty())
    {
        Some(error) => format!("PCAP Analysis: no packet statistics ({error}), "),
        None => format!(
            "PCAP Analysis: {} packets, {} flows, ",
            statistics.packets.unwrap_or(0),
            statistics.flows_total.unwrap_or(0)
        ),
    };
    summary.push_str(&format!("{} TLS sessions", index.tls_total));
    if let Some(embedded) = &index.embedded_secrets {
        summary.push_str(&format!(
            ", decryption keys embedded ({})",
            describe_embedded(embedded)
        ));
    }
    if !details.added.is_empty() {
        summary.push_str(&format!(" ({})", format_counts(&details.added)));
    }
    Some(summary)
}
