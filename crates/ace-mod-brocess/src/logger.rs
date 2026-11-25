//! The email logger, a port of ace3's `EmailLoggingAnalyzer` (`saq/modules/email/logging.py`).
//!
//! ace3 runs it after the rest of a root's analysis, over each file with the `original_email`
//! directive whose email module result parsed a message. Here it's a module on such a file that
//! runs last (`Module::RUNS_LAST`) and depends on the email module, whose result comes with the
//! task, with the URLs found below the email. For each email it:
//!
//! - adds the sender and each envelope recipient to brocess's `smtplog` (the `smtp-log` write),
//!   which the conversation frequency module counts;
//! - sends the email's log entry to fluent-bit, with its URLs and headers to tags of their own;
//! - compares its senders' domains with those its thread established before it and sends that to
//!   fluent-bit (reading them with `email-thread-domains`);
//! - records the email in brocess's thread store (the `email-thread` write).
//!
//! The log entry names the email the archiver archived, which the root's tree shows
//! (`Module::READS_TREE`): its hash, the archive's name for it (`archive_hash`, ace3's since
//! 6669e249).
//!
//! The writes land with the task's end, which stores no result: ace3's module creates no analysis.
//! As in ace3, each of the four is on its own, and one that fails is logged and the rest go on.

use std::time::Duration;

use ace_results::types::brocess::EmailLoggingAnalysis;
use ace_results::types::email::{EmailAnalysis, EmailDetails, LogEntry};
use ace_results::types::email_archive::EmailArchiveResults;
use ace_results::{AnalysisType, ObservableKind};
use ace_sdk::reads::{EmailThreadDomains, EmailThreadDomainsRequest, Read, ReadKind};
use ace_sdk::writes::{EmailThread, SmtpLog, SmtpLogRow, SmtpLogRows, Write, WriteKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use chrono::DateTime;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::fluent::{self, Record};
use crate::similarity::{compare_domains, domain_attributes};
use crate::threads::ThreadContext;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<EmailLogger>();

/// ace3's directive for the file that is the email a root came in as.
pub const ORIGINAL_EMAIL: &str = "original_email";

/// The fluent-bit tags each kind of record goes to.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FluentBitTags {
    /// The email's log entry.
    pub main: String,
    /// Each URL found in the email, apart, when set.
    #[serde(default)]
    pub urls: Option<String>,
    /// Each of its headers, apart, when set.
    #[serde(default)]
    pub headers: Option<String>,
    /// The look-alike telemetry, when set.
    #[serde(default)]
    pub lookalike: Option<String>,
}

/// The module's settings: ace3's, with its defaults from `etc/saq.default.yaml`.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct EmailLoggerSettings {
    /// Add each email's conversations to brocess's smtplog.
    pub brocess_logging_enabled: bool,
    /// Record each email in brocess's thread store.
    pub thread_recording_enabled: bool,
    /// Compare each email's senders with its thread's domains and send that to fluent-bit.
    pub lookalike_telemetry_enabled: bool,
    pub fluent_bit_logging_enabled: bool,
    pub fluent_bit_hostname: String,
    /// The pool lets the module reach only 24224, ace3's default.
    pub fluent_bit_port: u16,
    pub fluent_bit_tags: FluentBitTags,
    /// How long sending a task's records may take: fluent-logger's socket timeout.
    pub fluent_bit_timeout_seconds: f64,
    /// The domains the organization receives email for (ace3's global `local_email_domains`): mail
    /// from one of them is outbound.
    pub local_email_domains: Vec<String>,
}

impl Default for EmailLoggerSettings {
    fn default() -> Self {
        EmailLoggerSettings {
            brocess_logging_enabled: true,
            thread_recording_enabled: true,
            lookalike_telemetry_enabled: true,
            fluent_bit_logging_enabled: true,
            fluent_bit_hostname: "fluent-bit".to_owned(),
            fluent_bit_port: 24224,
            fluent_bit_tags: FluentBitTags {
                main: "phishfinder-main".to_owned(),
                urls: Some("phishfinder-urls".to_owned()),
                headers: Some("phishfinder-headers".to_owned()),
                lookalike: Some("phishfinder-lookalike".to_owned()),
            },
            fluent_bit_timeout_seconds: 3.0,
            local_email_domains: Vec::new(),
        }
    }
}

/// The email logger.
pub struct EmailLogger;

impl Module for EmailLogger {
    const NAME: &'static str = "email_logger";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[EmailAnalysis::MODULE];
    const REQUIRED_DIRECTIVES: &'static [&'static str] = &[ORIGINAL_EMAIL];
    const RUNS_LAST: bool = true;
    const READS_BELOW: &'static [ObservableKind] = &[ObservableKind::Url];
    /// Whether the archiver archived the email, whose archive path goes in the log entry, as ace3
    /// reads its `EmailArchiveResults`.
    const READS_TREE: bool = true;
    const READS: &'static [Read] = &[EmailThreadDomains::READ];
    const WRITES: &'static [Write] = &[SmtpLog::WRITE, EmailThread::WRITE];
    const STORES_RESULTS: bool = false;
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        ..Resources::DEFAULT
    };
    type Output = EmailLoggingAnalysis;
    type Settings = EmailLoggerSettings;

    fn init(settings: &EmailLoggerSettings) -> Result<Self, ModuleError> {
        if !settings.fluent_bit_timeout_seconds.is_finite()
            || settings.fluent_bit_timeout_seconds <= 0.0
        {
            return Err(ModuleError::other(
                "fluent_bit_timeout_seconds must be a positive number",
            ));
        }
        Ok(EmailLogger)
    }
}

impl Lookup for EmailLogger {
    /// fluent-bit's forward port, besides the lease API, which every pool may reach.
    const TCP_PORTS: &'static [u16] = &[24224];

    async fn analyze(
        &self,
        ctx: &TaskContext<EmailLoggerSettings>,
    ) -> Result<Outcome<EmailLoggingAnalysis>, ModuleError> {
        let settings = ctx.settings();
        let Some(email) = ctx
            .dependency_result::<EmailAnalysis>()?
            .and_then(|analysis| analysis.email)
        else {
            // scan_inbound_only skips the email analysis of outbound mail on purpose
            if ctx
                .tree()
                .is_some_and(|tree| tree.this().has_tag(ace_mod_email::TAG_OUTBOUND_EMAIL))
            {
                tracing::debug!(
                    "outbound email {} was not analyzed - not logging",
                    ctx.observable()
                );
            } else {
                tracing::warn!("no email analysis for {} - not logging", ctx.observable());
            }
            return Ok(Outcome::Skipped("no parsed email to log".to_owned()));
        };
        let mut urls: Vec<String> = ctx
            .observables_below()
            .iter()
            .filter(|o| o.kind == ObservableKind::Url)
            .map(|o| o.value.clone())
            .collect();
        // ace3 makes a set of them, in no order
        urls.sort();
        urls.dedup();

        if settings.brocess_logging_enabled
            && let Some(rows) = smtplog_rows(&email.log_entry)
        {
            ctx.write::<SmtpLog>(&rows)?;
        }

        let mut records = Vec::new();
        // ace3 logs the email's digest in the archive, the archiver's result's hash
        let archive_hash = ctx
            .tree()
            .filter(|tree| {
                tree.result_of(tree.this, EmailArchiveResults::NAME)
                    .is_some()
            })
            .map(|_| ctx.observable().value.to_ascii_lowercase());
        let entry = entry(&email.log_entry, &urls, archive_hash)?;
        if settings.fluent_bit_logging_enabled {
            match fluent_records(&settings.fluent_bit_tags, entry.clone()) {
                Ok(main) => records.extend(main),
                Err(e) => tracing::error!("unable to create fluent-bit log export: {e}"),
            }
        }
        if settings.thread_recording_enabled || settings.lookalike_telemetry_enabled {
            match lookalike(ctx, &email, &entry).await {
                Ok(record) => records.extend(record),
                Err(ModuleError::Cancelled) => return Err(ModuleError::Cancelled),
                Err(e) => tracing::error!("unable to create lookalike telemetry: {e}"),
            }
        }
        if !records.is_empty() {
            let timeout = Duration::from_secs_f64(settings.fluent_bit_timeout_seconds);
            let time = ctx.now().timestamp();
            if let Err(e) = fluent::send(
                &settings.fluent_bit_hostname,
                settings.fluent_bit_port,
                &records,
                time,
                timeout,
            )
            .await
            {
                tracing::warn!("fluent-bit dropped {} records: {e}", records.len());
            }
        }
        Ok(Outcome::Skipped("logged the email".to_owned()))
    }
}

/// `export_to_brocess`: the sender with each envelope recipient, normalized; none without a sender.
pub fn smtplog_rows(entry: &LogEntry) -> Option<SmtpLogRows> {
    let normalize = |address: &str| ace_sdk::email_threads::normalize_email_address(address);
    let source = entry.mail_from.as_deref().and_then(normalize)?;
    let rows: Vec<SmtpLogRow> = entry
        .env_rcpt_to
        .iter()
        .filter_map(|address| normalize(address))
        .map(|destination| SmtpLogRow {
            source: source.clone(),
            destination,
        })
        .collect();
    (!rows.is_empty()).then_some(SmtpLogRows { rows })
}

/// The log entry with the URLs found in the email and the archived email's hash.
fn entry(
    log_entry: &LogEntry,
    urls: &[String],
    archive_hash: Option<String>,
) -> Result<Map<String, Value>, ModuleError> {
    let Value::Object(mut entry) = serde_json::to_value(log_entry)
        .map_err(|e| ModuleError::other(format!("the log entry doesn't serialize: {e}")))?
    else {
        return Err(ModuleError::other("the log entry isn't an object"));
    };
    entry.insert("extracted_urls".to_owned(), json!(urls));
    entry.insert("archive_hash".to_owned(), archive_hash.into());
    Ok(entry)
}

/// `str(datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f %z').timestamp())`.
pub fn entry_timestamp(date: &str) -> Option<String> {
    let parsed = DateTime::parse_from_str(date, "%Y-%m-%d %H:%M:%S%.f %z").ok()?;
    let micros = parsed.timestamp_micros();
    Some(py_float(micros as f64 / 1_000_000.0))
}

/// Python's `repr` of a float of ordinary size: the shortest digits that read back, and a `.0` on a
/// whole number.
pub fn py_float(value: f64) -> String {
    let text = value.to_string();
    if text.contains('.') || text.contains("inf") || text.contains("NaN") {
        text
    } else {
        format!("{text}.0")
    }
}

/// `export_to_fluent_bit`: each URL and header to their own tags, when set and the email has a
/// Message-ID, then the entry.
fn fluent_records(
    tags: &FluentBitTags,
    mut entry: Map<String, Value>,
) -> Result<Vec<Record>, String> {
    let date = entry.get("date").and_then(Value::as_str).unwrap_or("");
    let timestamp = entry_timestamp(date).ok_or_else(|| format!("unreadable date {date:?}"))?;
    entry.insert("timestamp".to_owned(), json!(timestamp));
    let mut records = Vec::new();
    match entry.get("message_id").and_then(Value::as_str) {
        Some(message_id) if !message_id.is_empty() => {
            let message_id = message_id.to_owned();
            if let Some(tag) = &tags.urls {
                for url in entry["extracted_urls"].as_array().into_iter().flatten() {
                    records.push(Record {
                        tag: tag.clone(),
                        record: json!({"timestamp": timestamp, "message_id": message_id, "url": url}),
                    });
                }
            }
            entry.remove("extracted_urls");
            if let Some(tag) = &tags.headers {
                for (index, header) in entry["headers"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    records.push(Record {
                        tag: tag.clone(),
                        record: json!({
                            "timestamp": timestamp,
                            "message_id": message_id,
                            "header": header,
                            "header_index": index,
                        }),
                    });
                }
                entry.remove("headers");
            }
        }
        _ => tracing::warn!("missing message_id in the log entry"),
    }
    records.push(Record {
        tag: tags.main.clone(),
        record: Value::Object(entry),
    });
    Ok(records)
}

/// `export_lookalike_telemetry`: the look-alike record against the thread's earlier messages, when
/// fluent-bit has a tag for it, then the email's place in its thread recorded.
async fn lookalike(
    ctx: &TaskContext<EmailLoggerSettings>,
    email: &EmailDetails,
    entry: &Map<String, Value>,
) -> Result<Option<Record>, ModuleError> {
    let settings = ctx.settings();
    let context = ThreadContext::of(email, &settings.local_email_domains);
    if context.thread_id.is_empty() || context.message_id.is_none() {
        tracing::debug!("no thread or message id - skipping lookalike telemetry");
        return Ok(None);
    }
    let mut record = None;
    if let (true, true, Some(tag)) = (
        settings.lookalike_telemetry_enabled,
        settings.fluent_bit_logging_enabled,
        &settings.fluent_bit_tags.lookalike,
    ) {
        let answer = ctx
            .read::<EmailThreadDomains>(&EmailThreadDomainsRequest {
                thread_id: context.thread_id.clone(),
                thread_method: context.thread_method.to_owned(),
                normalized_subject: context.normalized_subject.clone(),
                participant_domains: context.participant_domains(),
            })
            .await?;
        record = Some(Record {
            tag: tag.clone(),
            record: telemetry(&context, entry, &answer),
        });
    }
    if settings.thread_recording_enabled
        && let Some(thread) = context.record()
    {
        ctx.write::<EmailThread>(&thread)?;
    }
    Ok(record)
}

/// The look-alike record ace3 sends for one email.
pub fn telemetry(
    context: &ThreadContext,
    entry: &Map<String, Value>,
    answer: &<EmailThreadDomains as ReadKind>::Answer,
) -> Value {
    // one reference per domain, the first the thread recorded
    let mut references = Vec::new();
    for established in &answer.established {
        if !references
            .iter()
            .any(|r: &&ace_sdk::reads::EstablishedDomain| r.domain == established.domain)
        {
            references.push(established);
        }
    }
    let senders: Vec<Value> = context
        .senders
        .iter()
        .map(|sender| {
            let attributes = domain_attributes(&sender.domain);
            json!({
                "address": sender.address,
                "role": sender.role,
                "domain": attributes.domain,
                "punycode": attributes.punycode,
                "mixed_script": attributes.mixed_script,
            })
        })
        .collect();
    let mut comparisons = Vec::new();
    for sender in &context.senders {
        for reference in &references {
            let compared = compare_domains(&sender.domain, &reference.domain);
            comparisons.push(json!({
                "suspect_domain": compared.suspect,
                "suspect_role": sender.role,
                "reference_domain": compared.reference,
                "reference_address": reference.address,
                "reference_role": reference.role,
                "reference_first_seen": reference.first_seen,
                "is_identical": compared.is_identical,
                "skeleton_equal": compared.skeleton_equal,
                "damerau_levenshtein": compared.damerau_levenshtein,
                "jaro_winkler": compared.jaro_winkler,
                "techniques": compared.techniques,
                "is_similar": compared.is_similar,
            }));
        }
    }
    let timestamp = entry
        .get("date")
        .and_then(Value::as_str)
        .and_then(entry_timestamp);
    let any_similar = comparisons.iter().any(|c| c["is_similar"] == json!(true));
    let any_mixed_script = senders.iter().any(|s| s["mixed_script"] == json!(true));
    let max_jaro_winkler = comparisons
        .iter()
        .filter_map(|c| c["jaro_winkler"].as_f64())
        .fold(None, |max: Option<f64>, x| {
            Some(max.map_or(x, |m| m.max(x)))
        })
        .unwrap_or(0.0);
    let min_damerau_levenshtein = comparisons
        .iter()
        .filter_map(|c| c["damerau_levenshtein"].as_u64())
        .min();
    json!({
        "timestamp": timestamp,
        "message_id": context.message_id,
        "thread_id": context.thread_id,
        "thread_method": context.thread_method,
        "thread_message_count": answer.thread_message_count,
        "normalized_subject": context.normalized_subject,
        "senders": senders,
        "established_domains": answer.established.iter().map(|d| json!({
            "domain": d.domain,
            "address": d.address,
            "role": d.role,
            "first_seen": d.first_seen,
        })).collect::<Vec<_>>(),
        "comparison_count": comparisons.len(),
        "comparisons": comparisons,
        "any_similar": any_similar,
        "any_mixed_script": any_mixed_script,
        "max_jaro_winkler": max_jaro_winkler,
        "min_damerau_levenshtein": min_damerau_levenshtein,
    })
}
