//! `email_conversation_attachment_analyzer`, a port of ace3's `EmailConversationAttachmentAnalyzer`
//! (`saq/modules/email/fa.py`).
//!
//! For an Office document in a root with an email: when the document or what its modules found is
//! tagged `macro`, and an email conversation in the root is tagged `new_sender` by the frequency
//! module, the document gets the `sandbox` directive and a detection. ace3 waits for the frequency
//! module's analysis of each conversation, and for olevba and officeparser3, which tag the macros,
//! before it looks; here the module reads the root's tree on the lease (`Module::READS_TREE`) and
//! delays while one of those has a task on what it reads.
//!
//! ace3 looks for the tag anywhere below the document (`recurse_tree`), but it looks as soon as the
//! document's own modules have run, before ace3's engine analyzes what they found. So it sees the tags
//! of the document, of its analyses and of what they added, and not those of a decrypted copy's own
//! analysis, which comes later: an encrypted document isn't flagged, its decrypted copy is. ace4's
//! tasks run in no such order, so the module looks that far and no further, which gives ace3's answer
//! every time.

use std::time::Duration;

use ace_results::types::brocess::{
    EmailConversationAttachmentAnalysis, EmailConversationFrequencyAnalysis,
};
use ace_results::types::email::EmailAnalysis;
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::{AnalysisType, Detection, ObservableKind, ResultEnvelope};
use ace_sdk::takes::{Condition, Takes};
use ace_sdk::{Delay, Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

use crate::frequency::NEW_SENDER;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<EmailConversationAttachmentAnalyzer>();

/// ace3's builtin signature `EMAIL_MACRO_NEW_SENDER`.
pub const SIGNATURE_UUID: &str = "26fb96a4-6e20-48df-b826-a9c4a25b1965";
pub const DESCRIPTION: &str = "An email from a new sender contained a macro.";
/// The modules that tag the macros it looks for, which ace3's config makes it wait for.
pub const MACRO_TAGGERS: [&str; 2] = ["olevba_v1_2", "officeparser3"];
const MACRO: &str = "macro";
const SANDBOX: &str = "sandbox";

/// How long a task waits for what it reads, the first time; each wait doubles it, to 32 times.
const PENDING_DELAY: Duration = Duration::from_secs(2);

/// The attachment module.
pub struct EmailConversationAttachmentAnalyzer;

impl Module for EmailConversationAttachmentAnalyzer {
    const NAME: &'static str = "email_conversation_attachment_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    const READS_TREE: bool = true;
    type Output = EmailConversationAttachmentAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(EmailConversationAttachmentAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        // whether the root has an email is a fact of the whole root, which stays in `analyze`
        Takes::everything()
            .and(
                Condition::HasResult(FileTypeAnalysis::MODULE.to_owned()),
                "the file has no file type",
            )
            .and(
                Condition::result_true(FileTypeAnalysis::MODULE, "is_office_document"),
                "not an Office document",
            )
    }
}

/// A delay for a task whose tree has a task it waits for, longer each time. The tasks it waits for
/// end whatever happens to them, so it needs no limit.
pub fn wait<S>(ctx: &TaskContext<S>) -> Delay {
    let delays = ctx.delayed().map_or(0, |delayed| delayed.delays);
    Delay::new(
        PENDING_DELAY.saturating_mul(2u32.saturating_pow(delays.min(5))),
        Duration::MAX,
    )
}

/// Whether the document, one of its results or what they added is tagged `macro`: what ace3's
/// `recurse_tree` finds when the module runs, once the document's own modules have.
fn macro_found(tree: &ace_sdk::tree::TreeView) -> bool {
    if tree.this().has_tag(MACRO) {
        return true;
    }
    tree.results_on(tree.this).any(|result| {
        result.tags.iter().any(|t| t == MACRO)
            || result
                .added
                .iter()
                .any(|a| tree.observable(a.observable).has_tag(MACRO))
    })
}

impl Parser for EmailConversationAttachmentAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<()>,
    ) -> Result<Outcome<EmailConversationAttachmentAnalysis>, ModuleError> {
        let tree = ctx
            .tree()
            .ok_or_else(|| ModuleError::other("the task came without its root's tree"))?;
        // this is for email scanning: the root must have an email's analysis
        if !tree.has_result_of(EmailAnalysis::NAME) {
            return Ok(Outcome::Skipped("the root has no email".to_owned()));
        }
        if MACRO_TAGGERS.iter().any(|m| tree.this().is_pending(m)) {
            return Ok(Outcome::Delay(wait(ctx)));
        }
        if !macro_found(tree) {
            return Ok(Outcome::Skipped("no macro".to_owned()));
        }
        let mut new_sender = false;
        for conversation in tree.of_kind(ObservableKind::EmailConversation) {
            let observable = tree.observable(conversation);
            if observable.is_pending(EmailConversationFrequencyAnalysis::MODULE) {
                return Ok(Outcome::Delay(wait(ctx)));
            }
            if tree
                .result_of(conversation, EmailConversationFrequencyAnalysis::NAME)
                .is_none()
            {
                continue;
            }
            if observable.has_tag(NEW_SENDER) {
                new_sender = true;
                break;
            }
        }
        if !new_sender {
            return Ok(Outcome::Skipped(
                "no conversation from a new sender".to_owned(),
            ));
        }
        let mut result = ResultEnvelope::new(EmailConversationAttachmentAnalysis {});
        result.analyzed.add_directive(SANDBOX);
        result
            .analyzed
            .detections
            .push(Detection::new(DESCRIPTION).with_signature(SIGNATURE_UUID));
        Ok(Outcome::Done(result))
    }
}
