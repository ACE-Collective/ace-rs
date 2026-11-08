//! The conversation frequency module, a port of ace3's `EmailConversationFrequencyAnalyzer`
//! (`saq/modules/email/fa.py`).
//!
//! For an `email_conversation` observable, `<sender>|<recipient>`, it asks brocess how many emails
//! it has seen from the sender, and from the sender to the recipient. A sender never seen is tagged
//! `new_sender`; a conversation seen at least `conversation_count_threshold` times is tagged
//! `frequent_conversation`. 7.5's attachment and link modules read the tag.
//!
//! ace3 puts the module in a cooldown when brocess can't be queried and stores nothing. A core that
//! can't answer fails the task as unavailable here, so it runs again later.

use std::time::Duration;

use ace_results::types::brocess::EmailConversationFrequencyAnalysis;
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::reads::{Read, ReadKind, SmtpCounts, SmtpCountsRequest};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<EmailConversationFrequencyAnalyzer>();

/// The tag of a conversation whose sender brocess has never seen.
pub const NEW_SENDER: &str = "new_sender";
/// The tag of a conversation brocess has seen often.
pub const FREQUENT_CONVERSATION: &str = "frequent_conversation";

/// The module's settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FrequencySettings {
    /// The fewest emails from the sender to the recipient that make their conversation frequent.
    pub conversation_count_threshold: i64,
}

impl Default for FrequencySettings {
    fn default() -> Self {
        FrequencySettings {
            conversation_count_threshold: 5,
        }
    }
}

/// The conversation frequency module.
pub struct EmailConversationFrequencyAnalyzer {
    threshold: i64,
}

impl Module for EmailConversationFrequencyAnalyzer {
    const NAME: &'static str = "email_conversation_frequency_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::EmailConversation];
    const READS: &'static [Read] = &[SmtpCounts::READ];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        ..Resources::DEFAULT
    };
    type Output = EmailConversationFrequencyAnalysis;
    type Settings = FrequencySettings;

    fn init(settings: &FrequencySettings) -> Result<Self, ModuleError> {
        Ok(EmailConversationFrequencyAnalyzer {
            threshold: settings.conversation_count_threshold,
        })
    }
}

impl Lookup for EmailConversationFrequencyAnalyzer {
    /// It talks only to the lease API, which every pool may reach.
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<FrequencySettings>,
    ) -> Result<Outcome<EmailConversationFrequencyAnalysis>, ModuleError> {
        let counts = ctx
            .read::<SmtpCounts>(&SmtpCountsRequest::default())
            .await?;
        let mut analysis = EmailConversationFrequencyAnalysis {
            source_count: Some(counts.source_count),
            dest_count: None,
        };
        let mut tags = Vec::new();
        if counts.source_count == 0 {
            tags.push(NEW_SENDER.to_owned());
        } else {
            // only a sender seen before has conversations to count
            if counts.conversation_count >= self.threshold {
                tags.push(FREQUENT_CONVERSATION.to_owned());
            }
            analysis.dest_count = Some(counts.conversation_count);
        }
        let summary = summary(&analysis);
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        result.analyzed.tags = tags;
        Ok(Outcome::Done(result))
    }
}

/// `EmailConversationFrequencyAnalysis.generate_summary`.
fn summary(analysis: &EmailConversationFrequencyAnalysis) -> Option<String> {
    let source = analysis.source_count?;
    let result = "Email Conversation Frequency Analysis -";
    if source == 0 {
        return Some(format!("{result} first time received"));
    }
    let dest = analysis
        .dest_count
        .map_or_else(|| "None".to_owned(), |d| d.to_string());
    Some(format!(
        "{result} {source} emails received before, {dest} to this user"
    ))
}
