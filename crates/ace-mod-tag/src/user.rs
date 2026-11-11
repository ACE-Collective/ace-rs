//! `user_defined_tagging`, a port of ace3's `UserDefinedTaggingAnalyzer` (`saq/modules/tag.py`).
//!
//! For every observable it adds the tags analysts mapped to the observable's type and value in ACE's
//! database. ace3 runs one SELECT over its `observables`, `observable_tag_mapping` and `tags` tables per
//! observable; a worker holds no database credentials, so here the core answers it, through the
//! `observable-tags` read (PLAN.md 7.2, `crates/ace-core/src/reads.md`), from migration 0042's
//! `analysis.observable_tags`. As in ace3, every observable gets a result, with no tags or with some.

use std::time::Duration;

use ace_results::types::tag::UserDefinedTaggingAnalysis;
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::reads::{ObservableTags, ObservableTagsRequest, Read, ReadKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<UserDefinedTagging>();

/// The module has no settings.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserDefinedTaggingSettings {}

/// The user defined tagging module.
pub struct UserDefinedTagging;

impl Module for UserDefinedTagging {
    const NAME: &'static str = "user_defined_tagging";
    // ace3's valid_observable_types is None: every type
    const INPUTS: &'static [ObservableKind] = ObservableKind::BUILTIN;
    const READS: &'static [Read] = &[ObservableTags::READ];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        ..Resources::DEFAULT
    };
    type Output = UserDefinedTaggingAnalysis;
    type Settings = UserDefinedTaggingSettings;

    fn init(_settings: &UserDefinedTaggingSettings) -> Result<Self, ModuleError> {
        Ok(UserDefinedTagging)
    }
}

impl Lookup for UserDefinedTagging {
    /// It talks only to the lease API, which every pool may reach.
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<UserDefinedTaggingSettings>,
    ) -> Result<Outcome<UserDefinedTaggingAnalysis>, ModuleError> {
        let answer = ctx
            .read::<ObservableTags>(&ObservableTagsRequest::default())
            .await?;
        if answer.truncated {
            tracing::warn!(
                "the observable has more mapped tags than the core sends; the first {} are added",
                answer.tags.len()
            );
        }
        // ace3 skips an empty name (`if row[0]`)
        let tags: Vec<String> = answer.tags.into_iter().filter(|t| !t.is_empty()).collect();
        let summary =
            (!tags.is_empty()).then(|| format!("User Defined Tagging: added {} tags", tags.len()));
        let mut result = ResultEnvelope::new(UserDefinedTaggingAnalysis {
            tags_added: tags.clone(),
        });
        for tag in tags {
            if !result.analyzed.tags.contains(&tag) {
                result.analyzed.tags.push(tag);
            }
        }
        result.summary = summary;
        Ok(Outcome::Done(result))
    }
}
