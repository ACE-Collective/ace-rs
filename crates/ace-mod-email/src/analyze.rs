//! `EmailAnalyzer.analyze_rfc822` (`saq/modules/email/rfc822.py:1019`): the headers and
//! addresses of a message, as details and observables.

use std::sync::LazyLock;

use ace_results::types::email::{EmailAnalysis, EmailDetails, LogEntry};
use ace_results::{NewObservable, ObservableAdditions, ObservableKind, ResultEnvelope};
use ace_sdk::InputFile;
use chrono::{DateTime, Utc};
use regex::Regex;

use crate::headers::{self, FirstHop};
use crate::mime::Node;
use crate::py::{self, decode_rfc2822, normalize_email_address, py_strip};
use crate::settings::EmailAnalyzerSettings;

pub const TAG_OUTBOUND_EMAIL: &str = "outbound_email";
pub const TAG_OUTBOUND_EXCEPTION_EMAIL: &str = "outbound_email_exception";
pub const TAG_AUTHENTICATION_FAILED: &str = "authentication_failed";
pub const TAG_ANONYMOUS_DIRECT_SEND: &str = "anonymous_direct_send";
pub const TAG_SPOOFED_INTERNAL: &str = "spoofed_internal";
pub const DIRECTIVE_ORIGINAL_EMAIL: &str = "original_email";
/// ace3's `MessageIDAnalyzerV2`, which would pull the message back out of the archive.
pub const MESSAGE_ID_ANALYZER: &str = "message_id_analyzer_v2";

/// The journal report's "meta block": who an Office 365 journaled message was really sent to.
static O365_META: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?ms)^Sender: (.+?)^Subject: (.+?)^Message-Id: (.+?)^Recipient: ")
        .expect("valid regex")
});
static O365_META_RECIPIENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^Recipient: ([^,\n]+)").expect("valid regex"));

/// What the journal report's meta block says.
#[derive(Debug, Default)]
struct MetaBlock {
    sender: String,
    recipients: Vec<String>,
}

/// The message ace3 analyzes: the whole file, or, for an Office 365 journal report, the original
/// message inside it.
struct Target<'a, 'm> {
    node: &'a Node<'m>,
    is_office365: bool,
    meta: Option<MetaBlock>,
    /// The original message's id, from `X-MS-Exchange-Parent-Message-Id`.
    message_id: Option<String>,
}

/// Finds the target message and the meta block (`NOTE A` in rfc822.py).
fn find_target<'a, 'm>(root: &'a Node<'m>) -> Target<'a, 'm> {
    let mut target = Target {
        node: root,
        is_office365: false,
        meta: None,
        message_id: None,
    };
    for part in root.walk() {
        if target.meta.is_none()
            && part.content_type == "text/plain"
            && let Some(meta) = meta_block(part)
        {
            tracing::info!(
                sender = %meta.sender,
                recipients = ?meta.recipients,
                "parsed the o365 meta block"
            );
            target.meta = Some(meta);
        }

        if let Some(parent) = part.headers.get("X-MS-Exchange-Parent-Message-Id") {
            target.is_office365 = true;
            target.message_id = Some(py_strip(&decode_rfc2822(&parent)).to_owned());
            continue;
        }

        if let (Some(message_id), Some(wanted)) =
            (part.headers.get("message-id"), &target.message_id)
            && py_strip(&decode_rfc2822(&message_id)) == wanted
        {
            target.node = part;
            break;
        }
    }
    target
}

/// The meta block in a text/plain part, if it has one.
fn meta_block(part: &Node<'_>) -> Option<MetaBlock> {
    let text = match part.transfer_encoding().as_str() {
        "quoted-printable" | "base64" => {
            let bytes = part.decoded_body();
            let charset = part
                .headers
                .content_charset()
                .unwrap_or_else(|| "utf-8".to_owned());
            py::decode_charset_strict(&bytes, &charset).unwrap_or_else(|| py::utf8_ignore(&bytes))
        }
        _ => part.payload_text(),
    };
    let text = text.trim_start_matches('\u{feff}');
    let caps = O365_META.captures(text)?;
    Some(MetaBlock {
        sender: py_strip(&caps[1]).to_owned(),
        recipients: O365_META_RECIPIENT
            .captures_iter(text)
            .map(|c| py_strip(&c[1]).to_owned())
            .collect(),
    })
}

/// Why a message got no analysis.
pub enum Skip {
    /// An outbound journaled message, with `scan_inbound_only` set.
    Outbound,
}

/// What the header half of the analysis produced, for the part extraction to add to.
pub struct HeaderAnalysis {
    pub result: ResultEnvelope<EmailAnalysis>,
    /// What the result adds to the analyzed file.
    pub analyzed: ObservableAdditions,
}

/// Analyzes the headers of `root`, the parsed `file`. `directives` are the file's.
pub fn analyze_headers<'a, 'm>(
    root: &'a Node<'m>,
    file: &InputFile,
    directives: &[String],
    settings: &EmailAnalyzerSettings,
    now: DateTime<Utc>,
) -> Result<HeaderAnalysis, Skip> {
    let target = find_target(root);
    let headers = &target.node.headers;
    let mut analyzed = ObservableAdditions::default();

    // whitelisting by sender and recipient waits for analyst-edited lists (PLAN.md 5.14)

    let mut env_rcpt_to: Vec<String> = Vec::new();
    let mut env_mail_from: Option<String> = None;

    if target.is_office365
        && let Some(value) = headers.get("X-MS-Exchange-Organization-OriginalEnvelopeRecipients")
    {
        let (_, address) = py::parseaddr(&decode_rfc2822(&value));
        if !address.is_empty() {
            env_rcpt_to = vec![address];
        }
    }

    if let Some(meta) = &target.meta {
        if !meta.recipients.is_empty() {
            env_rcpt_to = meta
                .recipients
                .iter()
                .map(|r| py::parseaddr(r).1)
                .filter(|a| !a.is_empty())
                .collect();
        }
        if !meta.sender.is_empty() {
            env_mail_from = Some(py::parseaddr(&meta.sender).1);
        }
    }

    if target.is_office365 && target.meta.is_none() {
        tracing::info!("unable to find the meta block of an office365 journaled message");
    }

    // the SMTP collector's smtp_rcpt_to and smtp_mail_from observables went with the collector
    // (PLAN.md decision 2)

    let header_tos: Vec<String> = headers
        .address_list("to")
        .iter()
        .filter_map(|a| normalize_email_address(a))
        .collect();

    if target.is_office365 && directives.iter().any(|d| d == DIRECTIVE_ORIGINAL_EMAIL) {
        let directionality = headers::first_present_header(
            headers,
            &settings.provider_headers.message_directionality,
        );
        if let Some(direction) = directionality
            && direction != "Incoming"
        {
            analyzed.add_tag(TAG_OUTBOUND_EMAIL);
            if settings.scan_inbound_only {
                let exception = settings
                    .outbound_exception_list()
                    .into_iter()
                    .find(|e| header_tos.contains(e));
                match exception {
                    Some(exception) => {
                        tracing::info!(%exception, "outbound office365 email exception found");
                        analyzed.add_tag(TAG_OUTBOUND_EXCEPTION_EMAIL);
                    }
                    None => {
                        tracing::info!("skipping outbound office365 email");
                        return Err(Skip::Outbound);
                    }
                }
            }
        }
    }

    let mut observables = Observables::default();
    let mut email = EmailDetails {
        headers: headers
            .items()
            .map(|(name, value)| [name.to_owned(), decode_rfc2822(&value)])
            .collect(),
        ..EmailDetails::default()
    };

    let received_time = headers
        .get_all("received")
        .first()
        .and_then(|r| headers::received_time(&decode_rfc2822(r)));

    let mut mail_from: Option<String> = None;
    if let Some(from) = headers.decoded("from") {
        email.from_address = headers.address_list("from").into_iter().next();
        if let Some(address) = normalize_email_address(&from) {
            observables.add(ObservableKind::EmailFrom, &address);
            mail_from = Some(address);
        }
        email.from = Some(from);
    }

    email.env_rcpt_to = env_rcpt_to.clone();
    email.env_mail_from = env_mail_from.clone();
    for rcpt_to in &env_rcpt_to {
        if let Some(address) = normalize_email_address(rcpt_to) {
            observables.add_address(
                ObservableKind::EmailEnvelopeRcptTo,
                &address,
                mail_from.as_deref(),
            );
        }
    }

    email.to = headers.get_all("to").iter().map(decode_rfc2822).collect();
    email.to_addresses = headers.address_list("to");
    for address in &email.to_addresses {
        if let Some(address) = normalize_email_address(address) {
            observables.add_address(ObservableKind::EmailTo, &address, mail_from.as_deref());
        }
    }

    if let Some(subject) = headers.get("subject") {
        let raw_subject = subject.to_str();
        if !raw_subject.is_empty() {
            observables.add(ObservableKind::EmailSubject, &raw_subject);
        }
        email.subject = Some(raw_subject);
    }

    let cc = headers.address_list("cc");
    let bcc = headers.address_list("bcc");

    if let Some(message_id) = headers.decoded("message-id") {
        let mut observable = NewObservable::new(
            ObservableKind::MessageId,
            py::normalize_message_id(&message_id),
        );
        observable.time = received_time;
        observable
            .exclude_modules
            .push(MESSAGE_ID_ANALYZER.to_owned());
        observables.push(observable);

        // a delivery for every local recipient, so remediation knows where the message went;
        // ace3 copies a remediate directive from the message_id observable to these, which
        // needs the rest of the alert and waits for the core
        let mut seen = Vec::new();
        for raw in env_rcpt_to
            .iter()
            .chain(&email.to_addresses)
            .chain(&cc)
            .chain(&bcc)
        {
            if seen.contains(raw) {
                continue;
            }
            seen.push(raw.clone());
            let Some(recipient) = normalize_email_address(raw) else {
                continue;
            };
            if is_local_email_domain(&recipient, &settings.local_email_domains) {
                observables.add(
                    ObservableKind::EmailDelivery,
                    &format!("{}|{}", py_strip(&message_id), py_strip(&recipient)),
                );
            }
        }
        email.message_id = Some(message_id);
    }

    for (header, kind, field) in [
        ("x-sender", ObservableKind::EmailXSender, Field::XSender),
        (
            "x-sender-id",
            ObservableKind::EmailXSenderId,
            Field::XSenderId,
        ),
        ("x-auth-id", ObservableKind::EmailXAuthId, Field::XAuthId),
        (
            "x-original-sender",
            ObservableKind::EmailXOriginalSender,
            Field::XOriginalSender,
        ),
        ("reply-to", ObservableKind::EmailReplyTo, Field::ReplyTo),
        (
            "return-path",
            ObservableKind::EmailReturnPath,
            Field::ReturnPath,
        ),
    ] {
        let Some(value) = headers.decoded(header) else {
            continue;
        };
        let Some(address) = normalize_email_address(&value) else {
            continue;
        };
        match field {
            Field::XSender => email.x_sender = Some(address.clone()),
            Field::XSenderId => email.x_sender_id = Some(address.clone()),
            Field::XAuthId => email.x_auth_id = Some(address.clone()),
            Field::XOriginalSender => email.x_original_sender = Some(address.clone()),
            Field::ReplyTo => {
                email.reply_to = Some(address.clone());
                email.reply_to_address = Some(address.clone());
            }
            Field::ReturnPath => email.return_path = Some(address.clone()),
        }
        observables.add(kind, &address);
    }

    if headers.contains("cc") {
        for address in &cc {
            observables.add_address(ObservableKind::EmailCc, address, mail_from.as_deref());
        }
        email.cc = Some(cc.clone());
    }

    let path: Vec<String> = headers
        .get_all("received")
        .iter()
        .filter_map(|r| headers::received_path_item(&decode_rfc2822(r)))
        .collect();

    if let Some(user_agent) = headers.decoded("user-agent") {
        observables.add(ObservableKind::UserAgent, &user_agent);
        email.user_agent = Some(user_agent);
    }
    if let Some(x_mailer) = headers.decoded("x-mailer") {
        observables.add(ObservableKind::EmailXMailer, &x_mailer);
        email.x_mailer = Some(x_mailer);
    }

    // ace3 labels these two "Originating IP" and "Sender IP"; observables have no display type
    // yet
    if let Some(ip) = headers
        .decoded("x-originating-ip")
        .and_then(|v| headers::normalize_ip_header_value(&v))
    {
        observables.add_timed(ObservableKind::Ip, &ip, received_time);
        email.originating_ip = Some(ip);
    }
    if let Some(ip) = headers
        .decoded("x-sender-ip")
        .and_then(|v| headers::normalize_ip_header_value(&v))
    {
        observables.add_timed(ObservableKind::Ip, &ip, received_time);
        email.x_sender_ip = Some(ip);
    }

    let mut local_domains = settings.local_domains.clone();
    for domain in &settings.local_email_domains {
        if !local_domains.contains(domain) {
            local_domains.push(domain.clone());
        }
    }
    let FirstHop { ip, helo, from } = headers::resolve_first_hop(
        headers,
        &settings.provider_headers.first_hop_ip,
        &local_domains,
    );
    if let Some(ip) = ip {
        observables.add(ObservableKind::EmailFirstHopIp, &ip);
        email.first_hop_ip = Some(ip);
    }
    if let Some(helo) = helo {
        observables.add(ObservableKind::EmailFirstHopHelo, &helo);
        email.first_hop_helo = Some(helo);
    }
    if let Some(from) = from {
        observables.add(ObservableKind::EmailFirstHopFrom, &from);
        email.first_hop_from = Some(from);
    }

    let domains = headers::dkim_signing_domains(headers);
    if !domains.is_empty() {
        for domain in &domains {
            observables.add(ObservableKind::EmailDkimSigningDomain, domain);
        }
        email.dkim_signing_domains = Some(domains);
    }

    if let Some(tenant) =
        headers::sender_tenant_id(headers, &settings.provider_headers.sender_tenant_id)
    {
        observables.add(ObservableKind::EmailSenderTenantId, &tenant);
        email.sender_tenant_id = Some(tenant);
    }

    let auth = headers::parse_authentication(headers, &settings.provider_headers);
    let authentication_failed = auth.compauth_result.as_deref() == Some("fail")
        || auth.dmarc_result.as_deref() == Some("fail");
    if authentication_failed {
        analyzed.add_tag(TAG_AUTHENTICATION_FAILED);
    }
    if auth.is_anonymous_direct_send {
        analyzed.add_tag(TAG_ANONYMOUS_DIRECT_SEND);
    }
    let mail_from_is_local = mail_from
        .as_deref()
        .is_some_and(|from| is_local_email_domain(from, &settings.local_email_domains));
    let spoofed_internal = mail_from_is_local
        && authentication_failed
        && !analyzed.tags.iter().any(|t| t == TAG_OUTBOUND_EMAIL);
    if spoofed_internal {
        analyzed.add_tag(TAG_SPOOFED_INTERNAL);
    }
    email.spf_result = auth.spf_result;
    email.dkim_result = auth.dkim_result;
    email.dmarc_result = auth.dmarc_result;
    email.compauth_result = auth.compauth_result;
    email.compauth_reason = auth.compauth_reason;
    email.is_anonymous_direct_send = auth.is_anonymous_direct_send;
    email.internal_org_sender = auth.internal_org_sender;
    email.message_directionality = auth.message_directionality;
    email.authentication_failed = authentication_failed;
    email.mail_from_is_local = mail_from_is_local;
    email.spoofed_internal = spoofed_internal;

    if let Some(subject) = &email.subject {
        let decoded = py::decode_str(subject);
        if !decoded.is_empty() {
            observables.add(ObservableKind::EmailSubject, &decoded);
        }
        email.decoded_subject = Some(decoded);
    }

    // the first header whose name starts with "received" is the last hop, and the last is the
    // first; Received-SPF counts too
    let mut last_received = None;
    let mut first_received = None;
    for [name, value] in &email.headers {
        if name.to_lowercase().starts_with("received") {
            if last_received.is_none() {
                last_received = Some(value.clone());
            }
            first_received = Some(value.clone());
        }
    }

    email.log_entry = LogEntry {
        date: now.format("%Y-%m-%d %H:%M:%S%.6f %z").to_string(),
        first_received,
        last_received,
        env_mail_from: email.env_mail_from.clone(),
        env_rcpt_to: email.env_rcpt_to.clone(),
        mail_from: email.from.clone(),
        mail_to: email.to.clone(),
        reply_to: email.reply_to.clone(),
        cc,
        bcc,
        message_id: email.message_id.clone(),
        in_reply_to: headers.decoded("in-reply-to"),
        subject: email
            .decoded_subject
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| email.subject.clone()),
        subject_raw: email.subject.clone(),
        path,
        size: file.size,
        user_agent: email.user_agent.clone(),
        x_mailer: email.x_mailer.clone(),
        originating_ip: email.originating_ip.clone(),
        headers: email
            .headers
            .iter()
            .filter(|[name, _]| !name.to_lowercase().starts_with("x-ms-exchange-"))
            .map(|[name, value]| format!("{name}: {}", value.replace(['\t', '\n'], "")))
            .collect(),
        thread_topic: headers.decoded("thread-topic"),
        thread_index: headers.decoded("thread-index"),
        refereneces: headers.decoded("references"),
        x_sender: headers.decoded("x-sender"),
        spf_result: email.spf_result.clone(),
        dkim_result: email.dkim_result.clone(),
        dmarc_result: email.dmarc_result.clone(),
        compauth_result: email.compauth_result.clone(),
        compauth_reason: email.compauth_reason.clone(),
        is_anonymous_direct_send: email.is_anonymous_direct_send,
        internal_org_sender: email.internal_org_sender,
        message_directionality: email.message_directionality.clone(),
        authentication_failed,
        mail_from_is_local,
        spoofed_internal,
        ..LogEntry::default()
    };

    let mut result = ResultEnvelope::new(EmailAnalysis {
        parsing_error: None,
        extraction_errors: Vec::new(),
        email: Some(email),
    });
    result.observables = observables.list;
    Ok(HeaderAnalysis { result, analyzed })
}

enum Field {
    XSender,
    XSenderId,
    XAuthId,
    XOriginalSender,
    ReplyTo,
    ReturnPath,
}

/// `is_local_email_domain` in `saq/email.py`.
pub fn is_local_email_domain(address: &str, local_email_domains: &[String]) -> bool {
    let Some(address) = normalize_email_address(address) else {
        return false;
    };
    let Some((_, domain)) = address.split_once('@') else {
        return false;
    };
    local_email_domains
        .iter()
        .any(|local| headers::is_subdomain(domain, local))
}

/// The observables a result adds, one per (type, value), in the order first added.
#[derive(Default)]
struct Observables {
    list: Vec<NewObservable>,
}

impl Observables {
    fn push(&mut self, observable: NewObservable) {
        if observable.value.is_empty() {
            return;
        }
        if !self
            .list
            .iter()
            .any(|o| o.kind == observable.kind && o.value == observable.value)
        {
            self.list.push(observable);
        }
    }

    fn add(&mut self, kind: ObservableKind, value: &str) {
        self.push(NewObservable::new(kind, value));
    }

    fn add_timed(&mut self, kind: ObservableKind, value: &str, time: Option<DateTime<Utc>>) {
        let mut observable = NewObservable::new(kind, value);
        observable.time = time;
        self.push(observable);
    }

    /// `add_email_address_observable`: the address, and the conversation from `source` to it.
    fn add_address(&mut self, kind: ObservableKind, address: &str, source: Option<&str>) {
        if address.is_empty() {
            return;
        }
        self.add(kind, address);
        if let Some(source) = source.filter(|s| !s.is_empty()) {
            self.add(
                ObservableKind::EmailConversation,
                &format!("{}|{}", py_strip(source), py_strip(address)),
            );
        }
    }
}
