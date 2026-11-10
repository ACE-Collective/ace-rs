//! The URL email pivot, a port of ace3's `URLEmailPivotAnalyzer` (`saq/modules/email/correlation.py`).
//!
//! For a URL, it asks the core how many archived emails are indexed with it (the
//! `archived-url-count` read), and records the count when there's one. ace3 sums the count over its
//! primary archive database and every `database_email_archive_*` section; ace4 has one archive. Its
//! `result_limit` decides nothing in ace3, whose two branches do the same since the code that listed
//! the emails was commented out, so it decides nothing here either.

use ace_results::types::email_archive::UrlEmailPivotAnalysis;
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::reads::{ArchivedUrlCount, ArchivedUrlCountRequest, Read, ReadKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<UrlEmailPivotAnalyzer>();

/// The module's settings: ace3's.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct UrlEmailPivotSettings {
    /// The most emails to list, past which only the count is kept. ace3 lists none either way.
    pub result_limit: i64,
}

impl Default for UrlEmailPivotSettings {
    fn default() -> Self {
        UrlEmailPivotSettings { result_limit: 35 }
    }
}

/// The URL email pivot.
pub struct UrlEmailPivotAnalyzer;

impl Module for UrlEmailPivotAnalyzer {
    const NAME: &'static str = "url_email_pivot_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Url];
    const READS: &'static [Read] = &[ArchivedUrlCount::READ];
    type Output = UrlEmailPivotAnalysis;
    type Settings = UrlEmailPivotSettings;

    fn init(_settings: &UrlEmailPivotSettings) -> Result<Self, ModuleError> {
        Ok(UrlEmailPivotAnalyzer)
    }
}

impl Lookup for UrlEmailPivotAnalyzer {
    /// It talks only to the lease API, which every pool may reach.
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<UrlEmailPivotSettings>,
    ) -> Result<Outcome<UrlEmailPivotAnalysis>, ModuleError> {
        let answer = ctx
            .read::<ArchivedUrlCount>(&ArchivedUrlCountRequest::default())
            .await?;
        if answer.count == 0 {
            tracing::debug!("did not find anything matching {}", ctx.observable().value);
            return Ok(Outcome::Skipped("in no archived email".to_owned()));
        }
        let mut result = ResultEnvelope::new(UrlEmailPivotAnalysis {
            count: Some(answer.count),
            emails: None,
        });
        result.summary = Some(format!(
            "URL Email Pivot Analyzer ({} emails matched)",
            answer.count
        ));
        Ok(Outcome::Done(result))
    }
}
