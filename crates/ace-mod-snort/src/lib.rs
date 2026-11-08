//! The snort signature module, a port of ace3's `SnortSignatureAnalyzer_v1`
//! (`saq/modules/snort.py`).
//!
//! For a `snort_sig` observable, `<gid>:<sid>:<rev>`, it shows the rule with that sid and rev. ace3
//! reads it from a Redis index that `ace signatures build-db` makes of its rules file. A worker
//! holds no credentials, so here the core answers from the rules file, through the
//! `snort-signature` read (PLAN.md 7.2, `crates/ace-core/src/reads.md`).
//!
//! ace3 also adds the rule to the root's summary details. ace4's roots have no summary details yet,
//! so the rule is in the result only.

use std::time::Duration;

use ace_results::types::snort::SnortSignatureAnalysis;
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::reads::{Read, ReadKind, SnortSignature, SnortSignatureRequest};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<SnortSignatureAnalyzer>();

/// What ace3 shows when the rule isn't found.
pub const UNKNOWN_SIGNATURE: &str = "unknown signature (rules not updating?)";

/// The module has no settings: the rules file is the core's (`ACE4_SNORT_RULES`), where ace3's
/// `signature_path` names it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnortSettings {}

/// The snort signature module.
pub struct SnortSignatureAnalyzer;

impl Module for SnortSignatureAnalyzer {
    const NAME: &'static str = "snort_signature_analysis_v1";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::SnortSig];
    const READS: &'static [Read] = &[SnortSignature::READ];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        ..Resources::DEFAULT
    };
    type Output = SnortSignatureAnalysis;
    type Settings = SnortSettings;

    fn init(_settings: &SnortSettings) -> Result<Self, ModuleError> {
        Ok(SnortSignatureAnalyzer)
    }
}

impl Lookup for SnortSignatureAnalyzer {
    /// It talks only to the lease API, which every pool may reach.
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<SnortSettings>,
    ) -> Result<Outcome<SnortSignatureAnalysis>, ModuleError> {
        let mut analysis = SnortSignatureAnalysis {
            signature_id: None,
            signature: Some(UNKNOWN_SIGNATURE.to_owned()),
        };
        // SnortSignatureObservable: three parts, or no sid and rev
        let value = ctx.observable().value.trim();
        let parts: Vec<&str> = value.split(':').collect();
        if let [_, sid, rev] = parts.as_slice() {
            let answer = ctx
                .read::<SnortSignature>(&SnortSignatureRequest::default())
                .await?;
            match answer.rule {
                Some(rule) => {
                    analysis.signature_id = Some(format!("{sid} rev {rev}"));
                    analysis.signature = Some(rule);
                }
                None => tracing::warn!("cannot find snort signature {sid} rev {rev}"),
            }
        } else {
            tracing::warn!("missing signature_id or ref in {value}");
        }
        let summary = match (&analysis.signature_id, &analysis.signature) {
            (Some(id), Some(signature)) => Some(format!("Signature Analysis - ({id}) {signature}")),
            _ => None,
        };
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        Ok(Outcome::Done(result))
    }
}
