//! The reads a lookup module makes of ACE's own data (PLAN.md 7.2), which `reads.md` beside this
//! file specifies, and the lease API serves at `POST /api/worker/v1/tasks/<id>/reads/<read>`.
//!
//! `api.rs` checks the caller, the lease and that the task's module declares the read. Each read
//! here then finds its subject in the task's root and answers. Built so far: `snort-signature` and
//! `smtp-counts` (PLAN.md 7.4).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use ace_results::{ObservableKind, ObservableRef};
use ace_sdk::reads::{
    SmtpCountsAnswer, SmtpCountsRequest, SnortSignatureAnswer, SnortSignatureRequest,
};
use regex::Regex;
use serde_json::Value;
use uuid::Uuid;

use crate::db::{Db, DbError};
use crate::queue::Task;

/// Why a read wasn't answered, as the lease API answers it.
#[derive(Debug)]
pub enum ReadFailure {
    /// 400: the request doesn't read as the read's.
    BadRequest(String),
    /// 403: the subject isn't in the task's root, or isn't what the read takes.
    Forbidden(String),
    /// 503: the store behind the read is down.
    Unavailable(String),
}

impl From<DbError> for ReadFailure {
    fn from(error: DbError) -> Self {
        ReadFailure::Unavailable(format!("the database: {error}"))
    }
}

impl From<sqlx::Error> for ReadFailure {
    fn from(error: sqlx::Error) -> Self {
        ReadFailure::Unavailable(format!("the database: {error}"))
    }
}

/// What the reads read besides the database.
#[derive(Clone, Default)]
pub struct ReadStores {
    snort: Arc<SnortRules>,
}

impl ReadStores {
    /// The stores, with the snort and suricata rules file at `snort_rules`, if there is one.
    pub fn new(snort_rules: Option<PathBuf>) -> Self {
        ReadStores {
            snort: Arc::new(SnortRules::new(snort_rules)),
        }
    }
}

/// Answers read `read` for `task`, whose lease and module were checked.
pub async fn answer(
    db: &Db,
    stores: &ReadStores,
    task: &Task,
    read: &str,
    request: Value,
) -> Result<Value, ReadFailure> {
    let answer = match read {
        "snort-signature" => {
            let request: SnortSignatureRequest = parse(request)?;
            serde_json::to_value(snort_signature(db, stores, task, request).await?)
        }
        "smtp-counts" => {
            let request: SmtpCountsRequest = parse(request)?;
            serde_json::to_value(smtp_counts(db, task, request).await?)
        }
        other => {
            return Err(ReadFailure::Forbidden(format!(
                "read {other} isn't served by this core"
            )));
        }
    };
    answer.map_err(|e| ReadFailure::Unavailable(format!("the answer doesn't serialize: {e}")))
}

fn parse<T: serde::de::DeserializeOwned>(request: Value) -> Result<T, ReadFailure> {
    serde_json::from_value(request).map_err(|e| ReadFailure::BadRequest(e.to_string()))
}

/// The task's own observable, or `subject` once it's found in the task's root.
async fn subject_in_root(
    db: &Db,
    task: &Task,
    subject: Option<ObservableRef>,
) -> Result<ObservableRef, ReadFailure> {
    let Some(subject) = subject else {
        return Ok(ObservableRef::new(
            task.observable.kind,
            task.observable.value.clone(),
        ));
    };
    if in_root(db, task.root, &subject).await? {
        Ok(subject)
    } else {
        Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't in the task's root",
            subject.kind, subject.value
        )))
    }
}

async fn in_root(db: &Db, root: Uuid, subject: &ObservableRef) -> Result<bool, ReadFailure> {
    let found = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM analysis.observables
                        WHERE root_id = $1 AND type = $2 AND value = $3)",
        root,
        subject.kind.as_str(),
        subject.value,
    )
    .fetch_one(db.pool())
    .await?;
    Ok(found.unwrap_or(false))
}

// ---- smtp-counts ----

/// `smtp-counts`: brocess's two counts for an email conversation, as ace3's
/// `query_brocess_by_source_email` and `query_brocess_by_email_conversation` sum them.
async fn smtp_counts(
    db: &Db,
    task: &Task,
    request: SmtpCountsRequest,
) -> Result<SmtpCountsAnswer, ReadFailure> {
    let subject = subject_in_root(db, task, request.subject).await?;
    if subject.kind != ObservableKind::EmailConversation {
        return Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't an email_conversation observable",
            subject.kind, subject.value
        )));
    }
    let (sender, recipient) = parse_email_conversation(subject.value.trim());
    let row = sqlx::query!(
        r#"SELECT COALESCE(SUM(numconnections), 0)::bigint AS "source_count!",
                  COALESCE(SUM(numconnections) FILTER (WHERE destination = $2), 0)::bigint
                      AS "conversation_count!"
           FROM brocess.smtplog WHERE source = $1"#,
        sender.as_bytes(),
        recipient.as_bytes(),
    )
    .fetch_one(db.pool())
    .await?;
    tracing::info!(
        task = task.id.0,
        root = %task.root,
        read = "smtp-counts",
        subject = %subject.value,
        "read"
    );
    Ok(SmtpCountsAnswer {
        source_count: row.source_count,
        conversation_count: row.conversation_count,
    })
}

/// ace3's `parse_email_conversation`: `<sender>|<recipient>`, or the whole value as the sender and
/// no recipient when it doesn't split in exactly two (`split('|', 2)`).
pub fn parse_email_conversation(value: &str) -> (&str, &str) {
    let parts: Vec<&str> = value.splitn(3, '|').collect();
    match parts.as_slice() {
        [sender, recipient] => (sender, recipient),
        _ => (value, ""),
    }
}

// ---- snort-signature ----

/// `snort-signature`: the rule line with the subject's sid and rev.
async fn snort_signature(
    db: &Db,
    stores: &ReadStores,
    task: &Task,
    request: SnortSignatureRequest,
) -> Result<SnortSignatureAnswer, ReadFailure> {
    let subject = subject_in_root(db, task, request.subject).await?;
    if subject.kind != ObservableKind::SnortSig {
        return Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't a snort_sig observable",
            subject.kind, subject.value
        )));
    }
    // SnortSignatureObservable: `<gid>:<sid>:<rev>`
    let parts: Vec<&str> = subject.value.trim().split(':').collect();
    let [_, sid, rev] = parts.as_slice() else {
        return Ok(SnortSignatureAnswer { rule: None });
    };
    let rule = stores.snort.rule(sid, rev)?;
    tracing::info!(
        task = task.id.0,
        root = %task.root,
        read = "snort-signature",
        subject = %subject.value,
        found = rule.is_some(),
        "read"
    );
    Ok(SnortSignatureAnswer { rule })
}

/// The snort and suricata rules file `ace signatures build-db` indexes into Redis in ace3
/// (`saq/modules/snort.py`), indexed here in memory by `<sid>:<rev>`, again whenever the file
/// changes.
#[derive(Default)]
pub struct SnortRules {
    path: Option<PathBuf>,
    index: Mutex<Option<SnortIndex>>,
}

struct SnortIndex {
    modified: Option<SystemTime>,
    size: u64,
    rules: HashMap<String, String>,
}

impl SnortRules {
    pub fn new(path: Option<PathBuf>) -> Self {
        SnortRules {
            path,
            index: Mutex::new(None),
        }
    }

    /// The rule with `sid` and `rev`, or None. No file is no rules, as ace3 has none until the
    /// index is built. A file that can't be read is the store being down.
    pub fn rule(&self, sid: &str, rev: &str) -> Result<Option<String>, ReadFailure> {
        let Some(path) = &self.path else {
            return Ok(None);
        };
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(ReadFailure::Unavailable(format!(
                    "the snort rules {}: {e}",
                    path.display()
                )));
            }
        };
        let mut index = self
            .index
            .lock()
            .map_err(|_| ReadFailure::Unavailable("the snort rules' index is poisoned".into()))?;
        let modified = metadata.modified().ok();
        let fresh = index
            .as_ref()
            .is_some_and(|i| i.modified == modified && i.size == metadata.len());
        if !fresh {
            *index = Some(SnortIndex {
                modified,
                size: metadata.len(),
                rules: index_rules(path)?,
            });
        }
        Ok(index
            .as_ref()
            .and_then(|i| i.rules.get(&format!("{sid}:{rev}")).cloned()))
    }
}

/// `_build_signature_db`: each line, stripped, under the `<sid>:<rev>` it names, a later line
/// taking the place of an earlier one with the same. ace3's pattern,
/// `^(?=.*sid:([0-9]+);)(?=.*rev:([0-9]+);).*$`, takes the last `sid:N;` and the last `rev:N;` of
/// a line, since its lookaheads are greedy.
fn index_rules(path: &Path) -> Result<HashMap<String, String>, ReadFailure> {
    let bytes = std::fs::read(path).map_err(|e| {
        ReadFailure::Unavailable(format!("the snort rules {}: {e}", path.display()))
    })?;
    let text = String::from_utf8_lossy(&bytes);
    let sid = Regex::new(r"sid:([0-9]+);").expect("a valid pattern");
    let rev = Regex::new(r"rev:([0-9]+);").expect("a valid pattern");
    let last = |pattern: &Regex, line: &str| -> Option<String> {
        pattern.captures_iter(line).last().map(|c| c[1].to_owned())
    };
    let mut rules = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if let (Some(sid), Some(rev)) = (last(&sid, line), last(&rev, line)) {
            rules.insert(format!("{sid}:{rev}"), line.to_owned());
        }
    }
    tracing::info!(
        "indexed {} snort signatures from {}",
        rules.len(),
        path.display()
    );
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_conversation_splits_in_two_or_is_all_sender() {
        assert_eq!(parse_email_conversation("a@x|b@y"), ("a@x", "b@y"));
        assert_eq!(parse_email_conversation("a@x"), ("a@x", ""));
        assert_eq!(parse_email_conversation("a@x|b@y|c@z"), ("a@x|b@y|c@z", ""));
        assert_eq!(parse_email_conversation("|b@y"), ("", "b@y"));
    }

    #[test]
    fn rules_are_indexed_by_their_last_sid_and_rev_and_again_when_the_file_changes() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("snort.rules");
        std::fs::write(
            &path,
            "# a comment, sid:1; rev:1;\n\
             alert tcp any any -> any any (msg:\"one\"; rev:2; sid:100;)  \n\
             alert tcp any any -> any any (msg:\"no sid\"; rev:1;)\n\
             alert udp any any -> any any (msg:\"two\"; sid:7; sid:200; rev:3;)\n",
        )
        .expect("writes");
        let rules = SnortRules::new(Some(path.clone()));
        assert_eq!(
            rules.rule("100", "2").ok().flatten().as_deref(),
            Some("alert tcp any any -> any any (msg:\"one\"; rev:2; sid:100;)")
        );
        assert!(rules.rule("200", "3").ok().flatten().is_some());
        assert_eq!(rules.rule("7", "3").ok().flatten(), None);
        assert_eq!(
            rules.rule("1", "1").ok().flatten().as_deref(),
            Some("# a comment, sid:1; rev:1;")
        );
        std::fs::write(
            &path,
            "alert ip any any -> any any (sid:100; rev:2; msg:\"new\";)\n",
        )
        .expect("writes");
        assert_eq!(
            rules.rule("100", "2").ok().flatten().as_deref(),
            Some("alert ip any any -> any any (sid:100; rev:2; msg:\"new\";)")
        );
        assert_eq!(rules.rule("200", "3").ok().flatten(), None);
        std::fs::remove_file(&path).expect("removes");
        assert_eq!(rules.rule("100", "2").ok().flatten(), None);
        assert_eq!(SnortRules::new(None).rule("100", "2").ok().flatten(), None);
    }
}
