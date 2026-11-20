//! The email thread module, a port of ace3's `EmailThreadAnalyzer` (`saq/modules/email/thread.py`).
//!
//! For a `message_id` observable it reads the conversation the email logger recorded the message in
//! (the `email-thread` read, ace3's `get_conversation`) and lays it out as a timeline, with the
//! look-alike domain pairs among its participants and what each did there. It's display only, as
//! ace3's: no tags, no detections, no observables. A message the store has no record of gets no
//! result.
//!
//! ace3 records an alert's email at the end of its email-mode analysis, before the correlation pass
//! that runs this module, so it sees the alert's own message. Here this module runs last, and when
//! the read says the root's email is still to be recorded, it delays until it is.
//!
//! ace3 also adds its findings to the analysis as a markdown summary detail; ace4's results have no
//! summary details, so the analysis view draws the same findings from the details. ace3 reads the
//! pairs never to report from an analyst-edited file it watches; here they're a setting. ace3 goes
//! into a cooldown when brocess can't be queried; a core that can't answer fails the task as
//! unavailable here.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ace_results::types::brocess::{
    EmailThreadAnalysis, Impersonation, Lookalike, OtherSender, Recipient, ThreadMessage,
};
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::email_threads::{message_id_tokens, normalize_message_id};
use ace_sdk::reads::{
    Conversation, ConversationMessage, EmailThread, EmailThreadRequest, MessageParticipant, Read,
    ReadKind,
};
use ace_sdk::{Delay, Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::similarity::{
    DomainSimilarity, compare_domains, compare_local_parts, registrable_domain,
};
use crate::threads::SENDER_ROLES;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<EmailThreadAnalyzer>();

/// How long to wait, and how long at most, for the email logger to record the root's email.
const RECORDING_DELAY: Duration = Duration::from_secs(10);
const RECORDING_TIMEOUT: Duration = Duration::from_secs(3600);

/// Roles that mean mail came from a domain. Reply-To only says where replies go.
const ORIGIN_ROLES: [&str; 2] = ["from", "return_path"];

/// The module's settings: ace3's, with its defaults.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct EmailThreadSettings {
    /// The most messages of a conversation to lay out. The core reads at most 500.
    pub max_messages: u32,
    /// The most same-subject threads to join into one conversation. The core joins at most 500.
    pub max_threads: u32,
    /// The most recipients listed for a message.
    pub max_recipients_displayed: u32,
    /// Pairs of domains known to be related, never reported as look-alikes of each other, in
    /// either order and by their registrable domains: ace3's `ignored_domain_pairs`, which it reads
    /// from its analyst-edited `etc/email_thread_analysis.yaml`.
    pub ignored_domain_pairs: Vec<[String; 2]>,
}

impl Default for EmailThreadSettings {
    fn default() -> Self {
        EmailThreadSettings {
            max_messages: 50,
            max_threads: 50,
            max_recipients_displayed: 8,
            ignored_domain_pairs: Vec::new(),
        }
    }
}

/// The email thread module.
pub struct EmailThreadAnalyzer {
    ignored: IgnoredDomainPairs,
}

/// ace3's `EmailThreadSettings.is_ignored_pair`: the domain pairs never reported as look-alikes of
/// each other, matched in either order on their registrable domains, the level `compare_domains`
/// works at, so a pair covers the hosts beneath each side. The thread module and a site's module
/// that honours the same pairs, such as a site's `mail_filter_email_thread_recovery`, build it from
/// their `ignored_domain_pairs` setting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IgnoredDomainPairs {
    pairs: BTreeSet<(String, String)>,
}

impl IgnoredDomainPairs {
    pub fn new(pairs: &[[String; 2]]) -> IgnoredDomainPairs {
        IgnoredDomainPairs {
            pairs: pairs
                .iter()
                .map(|[a, b]| pair(&registrable_domain(a), &registrable_domain(b)))
                .collect(),
        }
    }

    /// Whether the pair is listed, in either order.
    pub fn is_ignored(&self, first: &str, second: &str) -> bool {
        self.pairs.contains(&pair(
            &registrable_domain(first),
            &registrable_domain(second),
        ))
    }
}

impl Module for EmailThreadAnalyzer {
    const NAME: &'static str = "email_thread_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::MessageId];
    const READS: &'static [Read] = &[EmailThread::READ];
    /// It runs with the email logger, after the rest of the root, so it can wait for the logger to
    /// record the root's own email, as ace3 records it before its correlation pass.
    const RUNS_LAST: bool = true;
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        ..Resources::DEFAULT
    };
    type Output = EmailThreadAnalysis;
    type Settings = EmailThreadSettings;

    fn init(settings: &EmailThreadSettings) -> Result<Self, ModuleError> {
        if settings.max_messages == 0 || settings.max_threads == 0 {
            return Err(ModuleError::other(
                "max_messages and max_threads must be at least 1",
            ));
        }
        Ok(EmailThreadAnalyzer {
            ignored: IgnoredDomainPairs::new(&settings.ignored_domain_pairs),
        })
    }
}

/// A pair in either order.
fn pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_owned(), b.to_owned())
    } else {
        (b.to_owned(), a.to_owned())
    }
}

impl Lookup for EmailThreadAnalyzer {
    /// It talks only to the lease API, which every pool may reach.
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<EmailThreadSettings>,
    ) -> Result<Outcome<EmailThreadAnalysis>, ModuleError> {
        let settings = ctx.settings();
        let answer = ctx
            .read::<EmailThread>(&EmailThreadRequest {
                subject: None,
                max_messages: settings.max_messages,
                max_threads: settings.max_threads,
            })
            .await?;
        // the root's own email isn't recorded yet: ace3 records it before it looks
        if answer.recording {
            return Ok(Outcome::Delay(Delay::new(
                RECORDING_DELAY,
                RECORDING_TIMEOUT,
            )));
        }
        let Some(conversation) = answer.conversation.filter(|c| !c.messages.is_empty()) else {
            return Ok(Outcome::Skipped(
                "the message isn't in the thread store".to_owned(),
            ));
        };
        let anchor = normalize_message_id(&ctx.observable().value);
        let analysis = self.analysis(&Thread::new(&conversation), &anchor, settings);
        let summary = summary(&analysis);
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        Ok(Outcome::Done(result))
    }
}

impl EmailThreadAnalyzer {
    /// The analysis of `thread` for the message `anchor`.
    pub fn analysis(
        &self,
        thread: &Thread<'_>,
        anchor: &str,
        settings: &EmailThreadSettings,
    ) -> EmailThreadAnalysis {
        let conversation = thread.conversation;
        let lookalikes = self.lookalikes(thread, anchor);
        let lookalike_domains: BTreeSet<&str> =
            lookalikes.iter().map(|l| l.domain.as_str()).collect();
        let messages = timeline(
            thread,
            anchor,
            &lookalike_domains,
            settings.max_recipients_displayed as usize,
        );
        let unattributed: BTreeSet<String> = thread
            .unattributed
            .iter()
            .map(|p| p.address.clone())
            .collect();
        EmailThreadAnalysis {
            anchor_message_id: Some(anchor.to_owned()),
            normalized_subject: conversation.normalized_subject.clone(),
            thread_count: conversation.thread_count,
            thread_method: Some(conversation.thread_method.clone()),
            link_domains: conversation.link_domains.clone(),
            thread_message_counts: conversation.thread_message_counts.clone(),
            truncated: conversation.truncated,
            messages,
            lookalikes,
            unattributed_participants: unattributed.into_iter().collect(),
            missing_parent_message_ids: thread.missing_parent_ids(),
        }
    }

    /// `_build_lookalikes`: each similar pair of the conversation's domains, the look-alike first,
    /// pairs whose look-alike never sent first.
    fn lookalikes(&self, thread: &Thread<'_>, anchor: &str) -> Vec<Lookalike> {
        let domains: Vec<&str> = thread.participant_domains().into_iter().collect();
        let mut anchor_domains = BTreeSet::new();
        if let Some(message) = thread.messages().iter().find(|m| m.message_id == anchor) {
            anchor_domains.extend(thread.participants(message).map(|p| p.domain.as_str()));
            anchor_domains.extend(message.from_domain.as_deref());
        }
        let mut entries = Vec::new();
        for (i, suspect) in domains.iter().enumerate() {
            for reference in &domains[i + 1..] {
                let compared = compare_domains(suspect, reference);
                if !compared.is_similar {
                    continue;
                }
                if self.ignored.is_ignored(suspect, reference) {
                    tracing::debug!("ignoring look-alike pair {suspect} / {reference}");
                    continue;
                }
                let (first, second) =
                    if thread.suspect_rank(reference) < thread.suspect_rank(suspect) {
                        (*reference, *suspect)
                    } else {
                        (*suspect, *reference)
                    };
                entries.push(describe(thread, first, second, &compared, &anchor_domains));
            }
        }
        // stable, as Python's sort
        entries.sort_by(|a, b| {
            a.ever_sent.cmp(&b.ever_sent).then(
                b.jaro_winkler
                    .partial_cmp(&a.jaro_winkler)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        });
        entries
    }
}

/// ace3's `Conversation`, over the read's answer: its participants by message.
pub struct Thread<'a> {
    pub conversation: &'a Conversation,
    /// Each message's participants, by its id's hex.
    by_message: BTreeMap<&'a str, Vec<&'a MessageParticipant>>,
    /// Message hexes in the order their participants were first read, as ace3's dict keeps them.
    message_order: Vec<&'a str>,
    unattributed: Vec<&'a MessageParticipant>,
}

impl<'a> Thread<'a> {
    pub fn new(conversation: &'a Conversation) -> Thread<'a> {
        let mut by_message: BTreeMap<&str, Vec<&MessageParticipant>> = BTreeMap::new();
        let mut message_order = Vec::new();
        let mut unattributed = Vec::new();
        for participant in &conversation.participants {
            match participant.message_id_hex.as_deref() {
                Some(hex) => {
                    if !by_message.contains_key(hex) {
                        message_order.push(hex);
                    }
                    by_message.entry(hex).or_default().push(participant);
                }
                None => unattributed.push(participant),
            }
        }
        Thread {
            conversation,
            by_message,
            message_order,
            unattributed,
        }
    }

    fn messages(&self) -> &'a [ConversationMessage] {
        &self.conversation.messages
    }

    fn participants(
        &self,
        message: &ConversationMessage,
    ) -> impl Iterator<Item = &'a MessageParticipant> + '_ {
        self.by_message
            .get(message.message_id_hex.as_str())
            .into_iter()
            .flatten()
            .copied()
    }

    /// `all_participants`: the unattributed, then each message's.
    fn all_participants(&self) -> impl Iterator<Item = &'a MessageParticipant> + '_ {
        self.unattributed.iter().copied().chain(
            self.message_order
                .iter()
                .flat_map(|hex| self.by_message[hex].iter().copied()),
        )
    }

    fn roles_for_domain(&self, domain: &str) -> BTreeSet<&'a str> {
        self.conversation
            .domain_roles
            .get(domain)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect()
    }

    fn addresses_for_domain(&self, domain: &str) -> Vec<&'a str> {
        self.conversation
            .domain_addresses
            .get(domain)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect()
    }

    /// Every domain of the conversation, including those of threads past the cap.
    fn participant_domains(&self) -> BTreeSet<&'a str> {
        if self.conversation.domain_roles.is_empty() {
            self.all_participants()
                .map(|p| p.domain.as_str())
                .filter(|d| !d.is_empty())
                .collect()
        } else {
            self.conversation
                .domain_roles
                .keys()
                .map(String::as_str)
                .collect()
        }
    }

    /// `messages_containing_domain`: it sent it, or took part in it.
    fn messages_containing(&self, domain: &str) -> Vec<(usize, &'a ConversationMessage)> {
        self.messages()
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                m.from_domain.as_deref() == Some(domain)
                    || self.participants(m).any(|p| p.domain == domain)
            })
            .collect()
    }

    fn recorded(&self) -> BTreeSet<&'a str> {
        self.messages()
            .iter()
            .map(|m| m.message_id.as_str())
            .collect()
    }

    /// `replies_to_unrecorded`: its In-Reply-To names a message not in the conversation.
    fn replies_to_unrecorded(&self, message: &ConversationMessage) -> bool {
        let Some(parent) = message
            .in_reply_to
            .as_deref()
            .and_then(|value| message_id_tokens(value).first().copied())
        else {
            return false;
        };
        !self
            .recorded()
            .contains(normalize_message_id(parent).as_str())
    }

    /// `missing_parent_ids`: the unrecorded parents, in timeline order, each once.
    fn missing_parent_ids(&self) -> Vec<String> {
        let recorded = self.recorded();
        let mut result: Vec<String> = Vec::new();
        for message in self.messages() {
            let Some(parent) = message
                .in_reply_to
                .as_deref()
                .and_then(|value| message_id_tokens(value).first().copied())
            else {
                continue;
            };
            let parent = normalize_message_id(parent);
            if !recorded.contains(parent.as_str()) && !result.contains(&parent) {
                result.push(parent);
            }
        }
        result
    }

    fn has_unattributed_domain(&self, domain: &str) -> bool {
        self.unattributed.iter().any(|p| p.domain == domain)
    }

    fn ever_sent(&self, domain: &str) -> bool {
        self.roles_for_domain(domain)
            .iter()
            .any(|role| ORIGIN_ROLES.contains(role))
    }

    /// `_suspect_rank`: lower is the look-alike. One that never sent, then one on fewer messages,
    /// then the one that turned up later.
    fn suspect_rank(&self, domain: &str) -> (bool, usize, isize, String) {
        let containing = self.messages_containing(domain);
        let first_seen = containing
            .first()
            .map_or(self.messages().len(), |(index, _)| *index);
        (
            self.ever_sent(domain),
            containing.len(),
            -(first_seen as isize),
            domain.to_owned(),
        )
    }

    /// `_reply_tos_sent_from`: the Reply-To addresses of the messages a domain sent.
    fn reply_tos_sent_from(&self, from_domain: &str) -> BTreeSet<&'a str> {
        self.messages()
            .iter()
            .filter(|m| m.from_domain.as_deref() == Some(from_domain))
            .flat_map(|m| {
                self.participants(m)
                    .filter(|p| p.role == "reply_to")
                    .map(|p| p.address.as_str())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

fn strings<'s>(items: impl IntoIterator<Item = &'s str>) -> Vec<String> {
    items.into_iter().map(str::to_owned).collect()
}

/// `_describe_lookalike`.
fn describe(
    thread: &Thread<'_>,
    domain: &str,
    counterpart: &str,
    compared: &DomainSimilarity,
    anchor_domains: &BTreeSet<&str>,
) -> Lookalike {
    let containing = thread.messages_containing(domain);
    let introduced_by = containing.first().map(|(_, m)| *m);
    let first_seen_replies_to_unrecorded =
        introduced_by.is_some_and(|m| thread.replies_to_unrecorded(m));
    let roles_on_first_seen: BTreeSet<&str> = introduced_by
        .map(|m| {
            thread
                .participants(m)
                .filter(|p| p.domain == domain)
                .map(|p| p.role.as_str())
                .collect()
        })
        .unwrap_or_default();
    let likely_inherited = first_seen_replies_to_unrecorded
        && introduced_by.is_some_and(|m| m.from_domain.as_deref() != Some(domain))
        && !roles_on_first_seen.is_empty()
        && roles_on_first_seen.iter().all(|r| *r == "to" || *r == "cc");
    let addresses = thread.addresses_for_domain(domain);
    let counterpart_addresses = thread.addresses_for_domain(counterpart);
    let mut impersonations = Vec::new();
    for address in &addresses {
        for counterpart_address in &counterpart_addresses {
            let local = compare_local_parts(address, counterpart_address);
            if local.is_similar {
                impersonations.push(Impersonation {
                    address: (*address).to_owned(),
                    impersonates: (*counterpart_address).to_owned(),
                    exact_local_part: local.is_exact,
                });
            }
        }
    }
    let reply_to_addresses: BTreeSet<&str> = thread
        .all_participants()
        .filter(|p| p.role == "reply_to" && (p.domain == domain || p.domain == counterpart))
        .map(|p| p.address.as_str())
        .collect();
    let shared: BTreeSet<&str> = thread
        .reply_tos_sent_from(domain)
        .intersection(&thread.reply_tos_sent_from(counterpart))
        .copied()
        .collect();
    Lookalike {
        domain: domain.to_owned(),
        counterpart: counterpart.to_owned(),
        damerau_levenshtein: compared.damerau_levenshtein as u32,
        jaro_winkler: compared.jaro_winkler,
        skeleton_equal: compared.skeleton_equal,
        techniques: strings(compared.techniques.iter().copied()),
        addresses: strings(addresses),
        roles: strings(thread.roles_for_domain(domain)),
        ever_sent: thread.ever_sent(domain),
        ever_reply_to: thread.roles_for_domain(domain).contains("reply_to"),
        reply_to_addresses: strings(reply_to_addresses),
        shared_reply_to: strings(shared),
        message_count: containing.len() as u32,
        total_messages: thread.messages().len() as u32,
        presence_is_partial: thread.has_unattributed_domain(domain),
        introduced_by_address: introduced_by.and_then(|m| m.from_address.clone()),
        introduced_by_message_id: introduced_by.map(|m| m.message_id.clone()),
        introduced_on: introduced_by.and_then(|m| m.message_date.clone().or(m.insert_date.clone())),
        first_seen_replies_to_unrecorded,
        likely_inherited,
        present_in_anchor_message: anchor_domains.contains(domain),
        impersonations,
    }
}

/// `_build_timeline`: a row per message.
fn timeline(
    thread: &Thread<'_>,
    anchor: &str,
    lookalike_domains: &BTreeSet<&str>,
    max_recipients: usize,
) -> Vec<ThreadMessage> {
    let is_lookalike = |domain: &str| lookalike_domains.contains(domain);
    thread
        .messages()
        .iter()
        .enumerate()
        .map(|(index, message)| {
            // each recipient once, as ace3's dict by address
            let mut by_address: Vec<(&str, &str)> = Vec::new();
            for p in thread
                .participants(message)
                .filter(|p| !SENDER_ROLES.contains(&p.role.as_str()))
            {
                match by_address.iter_mut().find(|(a, _)| *a == p.address) {
                    Some(entry) => entry.1 = &p.domain,
                    None => by_address.push((&p.address, &p.domain)),
                }
            }
            let mut present: BTreeSet<&str> = thread
                .participants(message)
                .map(|p| p.domain.as_str())
                .filter(|d| is_lookalike(d))
                .collect();
            present.extend(message.from_domain.as_deref().filter(|d| is_lookalike(d)));
            let mut other_senders: Vec<OtherSender> = thread
                .participants(message)
                .filter(|p| {
                    SENDER_ROLES.contains(&p.role.as_str())
                        && Some(p.address.as_str()) != message.from_address.as_deref()
                })
                .map(|p| OtherSender {
                    address: p.address.clone(),
                    role: p.role.clone(),
                    is_lookalike: is_lookalike(&p.domain),
                })
                .collect();
            other_senders.sort_by(|a, b| {
                (!a.is_lookalike, &a.role, &a.address).cmp(&(!b.is_lookalike, &b.role, &b.address))
            });
            let mut recipients: Vec<Recipient> = by_address
                .into_iter()
                .map(|(address, domain)| Recipient {
                    address: address.to_owned(),
                    is_lookalike: is_lookalike(domain),
                })
                .collect();
            recipients
                .sort_by(|a, b| (!a.is_lookalike, &a.address).cmp(&(!b.is_lookalike, &b.address)));
            let omitted = recipients.len().saturating_sub(max_recipients);
            recipients.truncate(max_recipients);
            ThreadMessage {
                index: index as u32 + 1,
                message_id: message.message_id.clone(),
                date: message
                    .message_date
                    .clone()
                    .or_else(|| message.insert_date.clone()),
                date_is_estimated: message.message_date.is_none(),
                direction: if message.direction == Some(1) {
                    "outbound"
                } else {
                    "inbound"
                }
                .to_owned(),
                from_address: message.from_address.clone(),
                from_domain: message.from_domain.clone(),
                from_is_lookalike: message.from_domain.as_deref().is_some_and(is_lookalike),
                other_senders,
                recipients,
                recipients_omitted: omitted as u32,
                lookalike_domains_present: strings(present),
                is_anchor: message.message_id == anchor,
                replies_to_unrecorded: thread.replies_to_unrecorded(message),
            }
        })
        .collect()
}

/// `EmailThreadAnalysis.generate_summary`.
pub fn summary(analysis: &EmailThreadAnalysis) -> Option<String> {
    let count = analysis.messages.len();
    if count == 0 {
        return None;
    }
    let mut result = format!(
        "Email Thread Analysis: {count} message{}",
        if count == 1 { "" } else { "s" }
    );
    let dates: Vec<&str> = analysis
        .messages
        .iter()
        .filter_map(|m| m.date.as_deref())
        .filter(|d| !d.is_empty())
        .collect();
    if let (Some(first), Some(last)) = (dates.first(), dates.last()) {
        result.push_str(&format!(", {first} to {last} UTC"));
    }
    if let Some(headline) = analysis.lookalikes.first() {
        let domain = &headline.domain;
        if headline.ever_sent {
            result.push_str(&format!(" - {domain} sent mail into this conversation"));
        } else if headline.ever_reply_to {
            result.push_str(&format!(
                " - {domain} never sent mail, but replies were directed to it"
            ));
        } else {
            result.push_str(&format!(
                " - {domain} never sent mail into this conversation"
            ));
        }
    }
    Some(result)
}

/// `_build_findings`: the markdown ace3 adds as a summary detail, which ace4's analysis view draws
/// from the details (`EmailThreadAnalysis::findings`).
pub fn findings(analysis: &EmailThreadAnalysis) -> Option<String> {
    analysis.findings()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pair_is_the_same_either_way_round() {
        assert_eq!(pair("b.com", "a.com"), pair("a.com", "b.com"));
    }

    /// ace3's `is_ignored_pair`: either order, by registrable domain, so the hosts below each side
    /// are covered, and nothing else.
    #[test]
    fn an_ignored_pair_matches_either_way_round_and_below_each_side() {
        let ignored =
            IgnoredDomainPairs::new(&[["Example.com".to_owned(), "example-group.com".to_owned()]]);
        assert!(ignored.is_ignored("example.com", "example-group.com"));
        assert!(ignored.is_ignored("example-group.com", "mail.example.com"));
        assert!(!ignored.is_ignored("example.com", "exarnple.com"));
        assert!(!IgnoredDomainPairs::default().is_ignored("example.com", "example-group.com"));
    }
}
