//! How ace3 tells which thread an email belongs to (`saq/modules/email/conversation.py`), for the
//! brocess modules and for the core, which answers their reads and lands their writes only for a
//! thread an email in the task's root belongs to; and `saq/email.py`'s normalizers of an address and
//! a Message-ID, which the core's observable rules (`crate::observable_rules`) use too.

use std::sync::LazyLock;

use ace_results::types::email::EmailDetails;
use regex::Regex;

/// Python's `str.isspace`, which `\s` in its `re` also matches: Unicode's whitespace and the four
/// separators `\x1c` to `\x1f`.
pub fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python's `str.strip()`.
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(py_isspace)
}

fn re(pattern: &str) -> Regex {
    // `\s` as Python's re has it
    Regex::new(&pattern.replace(r"\s", r"[\s\x1c-\x1f]")).expect("a valid pattern")
}

static MESSAGE_ID_TOKEN: LazyLock<Regex> = LazyLock::new(|| re(r"<[^<>]+>"));
static SUBJECT_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)^\s*(re|fwd?|aw|sv|tr)\s*(\[\d+\])?\s*:\s*"));
static RESPONSE_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)^\s*(accepted|declined|tentative|tentatively accepted|canceled|cancelled|invitation|updated invitation|automatic reply)\s*:\s*",
    )
});
static RESPONSE_SUFFIX: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)\s+@\s+.*$"));
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| re(r"\s+"));

/// `normalize_message_id` (`saq/email.py`): the id stripped, inside `<` and `>`.
pub fn normalize_message_id(message_id: &str) -> String {
    let mut id = py_strip(message_id).to_owned();
    if !id.starts_with('<') {
        id.insert(0, '<');
    }
    if !id.ends_with('>') {
        id.push('>');
    }
    id
}

/// `normalize_email_address` (`saq/email.py`): the address `parseaddr` finds, without its angle
/// brackets, lowercased; None where it finds none.
pub fn normalize_email_address(email_address: &str) -> Option<String> {
    use ace_pycompat::email_utils::parseaddr;
    let (_, mut address) = parseaddr(email_address);
    if address.is_empty() {
        // known cases the standard library gets wrong, like <<person@example.com>>
        let mut fixed = email_address.to_owned();
        while !fixed.is_empty() && fixed.contains("<<") && fixed.contains(">>") {
            fixed = fixed.replace("<<", "<").replace(">>", ">");
        }
        address = parseaddr(&fixed).1;
        if address.is_empty() {
            return None;
        }
    }
    let address = py_strip(&address)
        .trim_start_matches('<')
        .trim_end_matches('>');
    if address.is_empty() {
        return None;
    }
    Some(ace_pycompat::pystr::lower(address).into_owned())
}

/// `parse_message_id_list`: every `<...>` token of a header such as References, in order.
pub fn message_id_tokens(value: &str) -> Vec<&str> {
    MESSAGE_ID_TOKEN
        .find_iter(value)
        .map(|m| m.as_str())
        .collect()
}

/// `normalize_subject`: a subject without its reply, forward and meeting-response prefixes, its
/// whitespace collapsed, lowercased, so a thread's messages share it.
pub fn normalize_subject(subject: Option<&str>) -> String {
    let Some(subject) = subject.filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let mut result = subject.to_owned();
    let mut response = false;
    // ace3 gives up after 100 rounds and logs it
    for _ in 0..100 {
        let mut stripped = SUBJECT_PREFIX.replace(&result, "").into_owned();
        if stripped == result {
            stripped = RESPONSE_PREFIX.replace(&result, "").into_owned();
            if stripped != result {
                response = true;
            }
        }
        if stripped == result {
            break;
        }
        result = stripped;
    }
    if response {
        result = RESPONSE_SUFFIX.replace(&result, "").into_owned();
    }
    py_strip(&WHITESPACE.replace_all(&result, " ")).to_lowercase()
}

/// The header named `name`, case-insensitively, as `_header_value` reads it: the first one.
pub fn header_value<'a>(details: &'a EmailDetails, name: &str) -> Option<&'a str> {
    details
        .headers
        .iter()
        .find(|[header, _]| !header.is_empty() && header.to_lowercase() == name.to_lowercase())
        .map(|[_, value]| value.as_str())
}

/// The email's Message-ID as `derive_thread_context` takes it: the log entry's, or the details'.
pub fn message_id(details: &EmailDetails) -> Option<String> {
    details
        .log_entry
        .message_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .or_else(|| {
            details
                .message_id
                .as_deref()
                .map(py_strip)
                .filter(|id| !id.is_empty())
        })
        .map(str::to_owned)
}

/// `derive_thread_id`: the first References id, the In-Reply-To id, or the email's own Message-ID,
/// and how it was found: `references`, `in_reply_to`, `self`, or `none` with an empty id.
pub fn thread_id(details: &EmailDetails) -> (String, &'static str) {
    if let Some(first) = header_value(details, "references")
        .and_then(|references| message_id_tokens(references).first().copied())
    {
        return (first.to_owned(), "references");
    }
    if let Some(first) = details
        .log_entry
        .in_reply_to
        .as_deref()
        .and_then(|value| message_id_tokens(value).first().copied())
    {
        return (first.to_owned(), "in_reply_to");
    }
    match message_id(details) {
        Some(id) => (normalize_message_id(&id), "self"),
        None => (String::new(), "none"),
    }
}

/// The subject a thread is matched on: the decoded subject, or the subject as written.
pub fn normalized_subject(details: &EmailDetails) -> String {
    normalize_subject(
        details
            .decoded_subject
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(details.subject.as_deref()),
    )
}

/// Every id a thread of this email could have, normalized as the store keeps message ids: its own
/// Message-ID, and the ids its In-Reply-To and References name.
pub fn thread_ids(details: &EmailDetails) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(id) = message_id(details) {
        ids.push(normalize_message_id(&id));
    }
    for value in [
        details.log_entry.in_reply_to.as_deref(),
        header_value(details, "references"),
    ]
    .into_iter()
    .flatten()
    {
        ids.extend(message_id_tokens(value).into_iter().map(str::to_owned));
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_lose_their_prefixes_and_a_response_its_slot() {
        assert_eq!(normalize_subject(Some("Re: FWD:  Invoice  7")), "invoice 7");
        assert_eq!(normalize_subject(Some("RE[2]: re : Hello")), "hello");
        assert_eq!(
            normalize_subject(Some(
                "Accepted: Re: Sync @ Wed Aug 19, 2026 9:30pm -\n 10:30pm (IST) (o@example.com)"
            )),
            "sync"
        );
        // a plain subject keeps its " @ "
        assert_eq!(normalize_subject(Some("Lunch @ noon")), "lunch @ noon");
        assert_eq!(normalize_subject(Some("")), "");
        assert_eq!(normalize_subject(None), "");
        assert_eq!(normalize_subject(Some("re:")), "");
        assert_eq!(normalize_subject(Some("\u{1c}Re: x\u{1f}")), "x");
    }

    #[test]
    fn email_addresses_normalize_like_saq_email() {
        let normal = |a| normalize_email_address(a);
        assert_eq!(
            normal("John <John.Davison@Company.com>").as_deref(),
            Some("john.davison@company.com")
        );
        assert_eq!(
            normal("<<person@example.com>>").as_deref(),
            Some("person@example.com")
        );
        assert_eq!(normal("not an address").as_deref(), Some("not"));
        assert_eq!(normal(" a@b.com\u{1c}").as_deref(), Some("a@b.com"));
        assert_eq!(normal(""), None);
        assert_eq!(normal("<>"), None);
    }

    #[test]
    fn message_ids_are_bracketed_and_tokens_found_in_order() {
        assert_eq!(normalize_message_id(" abc@x "), "<abc@x>");
        assert_eq!(normalize_message_id("<abc@x>"), "<abc@x>");
        assert_eq!(
            message_id_tokens("<a@x> junk <b@y>\n <c@z"),
            ["<a@x>", "<b@y>"]
        );
    }

    #[test]
    fn a_thread_is_its_first_reference_its_parent_or_itself() {
        let mut details = EmailDetails {
            message_id: Some(" m@x ".to_owned()),
            ..EmailDetails::default()
        };
        assert_eq!(thread_id(&details), ("<m@x>".to_owned(), "self"));
        details.log_entry.in_reply_to = Some("<p@x>".to_owned());
        assert_eq!(thread_id(&details), ("<p@x>".to_owned(), "in_reply_to"));
        details.headers = vec![["References".to_owned(), "<r@x> <p@x>".to_owned()]];
        assert_eq!(thread_id(&details), ("<r@x>".to_owned(), "references"));
        assert_eq!(thread_ids(&details), ["<m@x>", "<p@x>", "<r@x>", "<p@x>"]);
        assert_eq!(thread_id(&EmailDetails::default()), (String::new(), "none"));
    }
}
