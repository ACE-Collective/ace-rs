//! `email_conversation_link_analyzer`, a port of ace3's `EmailConversationLinkAnalyzer`
//! (`saq/modules/email/fa.py`).
//!
//! For a URL that matches one of the module's `url_pattern_*` settings: finds the email it came from,
//! as ace3's `search_down` does, and when one of that email's conversations is tagged `new_sender` by
//! the frequency module, adds a detection to the URL. ace3 waits for the email module's analysis of
//! each file on the way and for the frequency module's of each conversation; here the module reads
//! the root's tree on the lease (`Module::READS_TREE`) and delays while one of those has a task on
//! what it reads.
//!
//! ace3's default config has no pattern, so the module does nothing there. Here it's off until a site
//! gives it a section (`Module::ENABLED_BY_DEFAULT`), whose keys are the patterns, as ace3's are.

use std::collections::BTreeMap;

use ace_mod_urls::pyre;
use ace_results::types::brocess::{
    EmailConversationFrequencyAnalysis, EmailConversationLinkAnalysis,
};
use ace_results::types::email::EmailAnalysis;
use ace_results::{AnalysisType, Detection, ObservableKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::attachment::wait;
use crate::frequency::NEW_SENDER;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<EmailConversationLinkAnalyzer>();

/// ace3's builtin signature `EMAIL_SUSPECT_URL_NEW_SENDER`.
pub const SIGNATURE_UUID: &str = "11b42a94-e21a-4cd0-bdb6-8f278d20611d";
pub const DESCRIPTION: &str = "Suspect URL sent from new sender.";
/// The prefix of a setting that holds a pattern.
pub const PATTERN_PREFIX: &str = "url_pattern_";

/// The module's settings: Python `re` patterns, each under a key that starts `url_pattern_`, as
/// ace3's extra config keys are. Any other key is refused.
#[derive(Debug, Clone, Default, PartialEq, JsonSchema)]
pub struct LinkSettings(pub BTreeMap<String, String>);

impl<'de> Deserialize<'de> for LinkSettings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Patterns;
        impl<'de> Visitor<'de> for Patterns {
            type Value = LinkSettings;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("url_pattern_* keys, each a pattern")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<LinkSettings, A::Error> {
                let mut patterns = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if !key.starts_with(PATTERN_PREFIX) {
                        return Err(A::Error::unknown_field(&key, &["url_pattern_*"]));
                    }
                    patterns.insert(key, value);
                }
                Ok(LinkSettings(patterns))
            }
        }
        deserializer.deserialize_map(Patterns)
    }
}

/// The link module.
pub struct EmailConversationLinkAnalyzer {
    patterns: Vec<pyre::Pattern>,
}

impl Module for EmailConversationLinkAnalyzer {
    const NAME: &'static str = "email_conversation_link_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Url];
    const READS_TREE: bool = true;
    const ENABLED_BY_DEFAULT: bool = false;
    type Output = EmailConversationLinkAnalysis;
    type Settings = LinkSettings;

    fn init(settings: &LinkSettings) -> Result<Self, ModuleError> {
        let mut patterns = Vec::new();
        for (key, pattern) in &settings.0 {
            // ace3 logs a pattern that doesn't compile and goes on without it
            match pyre::compile(pattern) {
                Ok(compiled) => patterns.push(compiled),
                Err(e) => tracing::error!(setting = %key, "unable to add pattern {pattern}: {e}"),
            }
        }
        Ok(EmailConversationLinkAnalyzer { patterns })
    }
}

impl Parser for EmailConversationLinkAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<LinkSettings>,
    ) -> Result<Outcome<EmailConversationLinkAnalysis>, ModuleError> {
        let url = &ctx.observable().value;
        let plain = pyre::classes_agree(url);
        let mut matches = false;
        for pattern in &self.patterns {
            if pattern
                .for_text(plain)
                .is_match(url)
                .map_err(|e| ModuleError::other(format!("a url pattern: {e}")))?
            {
                matches = true;
                break;
            }
        }
        if !matches {
            return Ok(Outcome::Skipped("no pattern matches".to_owned()));
        }
        let tree = ctx
            .tree()
            .ok_or_else(|| ModuleError::other("the task came without its root's tree"))?;
        // the email the URL came from, waiting for the email module on each file on the way
        let mut waiting = false;
        let email = tree.search_up(tree.this, |i| {
            let o = tree.observable(i);
            if o.kind != ObservableKind::File {
                return false;
            }
            if o.is_pending(EmailAnalysis::MODULE) {
                waiting = true;
                return true;
            }
            tree.result_of(i, EmailAnalysis::NAME).is_some()
        });
        if waiting {
            return Ok(Outcome::Delay(wait(ctx)));
        }
        let Some(email) = email else {
            return Ok(Outcome::Skipped(
                "the url didn't come in an email".to_owned(),
            ));
        };
        let conversations: Vec<usize> = tree
            .results_on(email)
            .filter(|r| r.analysis_type == EmailAnalysis::NAME)
            .flat_map(|r| r.added.iter().map(|a| a.observable))
            .filter(|&i| tree.observable(i).kind == ObservableKind::EmailConversation)
            .collect();
        let mut result = ResultEnvelope::new(EmailConversationLinkAnalysis {});
        for conversation in conversations {
            let observable = tree.observable(conversation);
            if observable.is_pending(EmailConversationFrequencyAnalysis::MODULE) {
                return Ok(Outcome::Delay(wait(ctx)));
            }
            if tree
                .result_of(conversation, EmailConversationFrequencyAnalysis::NAME)
                .is_some()
                && observable.has_tag(NEW_SENDER)
                && result.analyzed.detections.is_empty()
            {
                // a URL that would be crawled, from a new sender
                result
                    .analyzed
                    .detections
                    .push(Detection::new(DESCRIPTION).with_signature(SIGNATURE_UUID));
            }
        }
        Ok(Outcome::Done(result))
    }
}
