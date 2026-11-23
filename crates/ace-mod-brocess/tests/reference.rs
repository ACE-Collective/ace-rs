//! PLAN.md 7.4: the brocess modules against ace3's reference dumps. ace3 counted from
//! tools/ace3/dumps/fixtures/brocess/smtplog.json in place of brocess
//! (`tools/ace3/dumps/run_module.py --brocess`); here each read is answered with what the core's
//! query answers for those rows. The core's query itself runs on the same rows, against the same
//! dumps, in ace-pool's lease_api test. Every difference is listed in differences.md, next to this
//! file.

use std::path::Path;
use std::sync::Arc;

use ace_mod_brocess::EmailConversationFrequencyAnalyzer;
use ace_results::ObservableKind;
use ace_sdk::{ModuleError, Outcome};
use ace_testkit::reads::FakeReads;
use ace_testkit::reference::{Dump, ListedDifferences, diff, normal_form};
use ace_testkit::{Harness, HarnessError};
use serde_json::{Value, json};

/// The rows of differences.md under `module`'s heading.
fn listed_for(module: &str) -> ListedDifferences {
    let mut listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    listed
        .rows
        .retain(|row| row.section.as_deref() == Some(module));
    listed
}

/// The fixture's smtplog rows.
fn fixture_rows() -> Value {
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/ace3/dumps/fixtures/brocess/smtplog.json"),
        )
        .expect("the fixture reads"),
    )
    .expect("JSON");
    fixture["smtplog"].clone()
}

/// `smtp-counts` over the fixture's rows, as the core's SQL sums them: addresses compared byte for
/// byte, NULL counts left out, and no row a 0.
fn counts_in_fixture(value: &str) -> Value {
    counts_in(&fixture_rows(), value)
}

/// `smtp-counts` over `rows`, as `counts_in_fixture`.
fn counts_in(rows: &Value, value: &str) -> Value {
    let parts: Vec<&str> = value.splitn(3, '|').collect();
    let (sender, recipient) = match parts.as_slice() {
        [sender, recipient] => (*sender, *recipient),
        _ => (value, ""),
    };
    let (mut source, mut conversation) = (0, 0);
    for row in rows.as_array().expect("rows") {
        let (Some(from), Some(to), Some(count)) =
            (row[0].as_str(), row[1].as_str(), row[2].as_i64())
        else {
            continue;
        };
        if from == sender {
            source += count;
            if to == recipient {
                conversation += count;
            }
        }
    }
    json!({"source_count": source, "conversation_count": conversation})
}

#[tokio::test]
async fn the_frequency_module_matches_the_reference_dumps_or_lists_each_difference() {
    let listed = listed_for("email_conversation_frequency_analyzer");
    let mut compared = Vec::new();
    let dumps = Dump::all("email_conversation_frequency_analyzer").expect("the dumps read");
    assert_eq!(dumps.len(), 8);
    for dump in dumps {
        let value = dump.value["input"]["observable"]["value"]
            .as_str()
            .expect("a value")
            .to_owned();
        let reads = Arc::new(FakeReads::new().answer("smtp-counts", counts_in_fixture(&value)));
        let harness = Harness::<EmailConversationFrequencyAnalyzer>::new()
            .expect("harness")
            .reader(reads.clone());
        let outcome = harness
            .run_lookup(harness.observable(ObservableKind::EmailConversation, &value))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        assert_eq!(
            reads.requests(),
            [("smtp-counts", json!({"subject": null}))],
            "{value}"
        );
        if dump.short_name() == "email_conversation_sender@example.com|recipient@example.com" {
            ace_testkit::check_view_fixture("brocess_frequent_conversation", &outcome);
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &dump.normal_form("EmailConversationFrequencyAnalysis"),
                &normal_form(&outcome),
            ),
        ));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}

#[tokio::test]
async fn the_threshold_is_a_setting() {
    let reads = Arc::new(FakeReads::new().answer(
        "smtp-counts",
        json!({"source_count": 3, "conversation_count": 2}),
    ));
    let harness = Harness::<EmailConversationFrequencyAnalyzer>::with_settings(
        json!({"conversation_count_threshold": 2}),
    )
    .expect("harness")
    .reader(reads);
    let Outcome::Done(result) = harness
        .run_lookup(harness.observable(ObservableKind::EmailConversation, "a@x|b@y"))
        .await
        .expect("runs")
    else {
        panic!("a result");
    };
    assert_eq!(result.analyzed.tags, ["frequent_conversation"]);
}

#[tokio::test]
async fn a_core_that_can_t_answer_fails_the_task_as_unavailable() {
    let harness = Harness::<EmailConversationFrequencyAnalyzer>::new()
        .expect("harness")
        .reader(Arc::new(FakeReads::new().unavailable("smtp-counts")));
    let err = harness
        .run_lookup(harness.observable(ObservableKind::EmailConversation, "a@x|b@y"))
        .await
        .expect_err("unavailable");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::Unavailable(_))),
        "{err}"
    );
}

// ---- email_logger ----

/// A fluent-bit that keeps what it's sent: each forward-protocol message's tag and record.
struct FakeFluentBit {
    port: u16,
    received: Arc<std::sync::Mutex<Vec<Value>>>,
}

impl FakeFluentBit {
    async fn start() -> FakeFluentBit {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let port = listener.local_addr().expect("an address").port();
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = received.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut bytes = Vec::new();
                if stream.read_to_end(&mut bytes).await.is_err() {
                    continue;
                }
                let mut reader = std::io::Cursor::new(bytes);
                while (reader.position() as usize) < reader.get_ref().len() {
                    let (tag, _time, record): (String, i64, Value) =
                        rmp_serde::from_read(&mut reader).expect("a forward message");
                    kept.lock()
                        .expect("unpoisoned")
                        .push(json!({"tag": tag, "record": record}));
                }
            }
        });
        FakeFluentBit { port, received }
    }

    /// Waits for the connection the task made to be read.
    async fn records(&self, expected: usize) -> Vec<Value> {
        for _ in 0..200 {
            let records = self.received.lock().expect("unpoisoned").clone();
            if records.len() >= expected {
                return records;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        self.received.lock().expect("unpoisoned").clone()
    }
}

/// The email logger's tags in ace3's default settings; ace3's engine sends to others of its own.
const LOGGER_TAGS: [&str; 4] = [
    "phishfinder-main",
    "phishfinder-urls",
    "phishfinder-headers",
    "phishfinder-lookalike",
];

/// What fluent-bit got, in the form both sides are compared in: the logger's tags, without the
/// time of the scan (`date` and the `timestamp` made from it), with the URLs sorted.
fn fluent_form(records: &[Value]) -> Value {
    let records = records
        .iter()
        .filter(|r| LOGGER_TAGS.contains(&r["tag"].as_str().unwrap_or("")))
        .map(|r| {
            let mut r = r.clone();
            if let Some(record) = r["record"].as_object_mut() {
                record.remove("date");
                record.remove("timestamp");
                if let Some(Value::Array(urls)) = record.get_mut("extracted_urls") {
                    urls.sort_by_key(|u| u.to_string());
                }
            }
            r
        })
        .collect();
    Value::Array(records)
}

/// The rows a run added to brocess, without what the store makes itself: ids, hashes, and the time
/// a row was written.
fn added_rows(before: &Value, after: &Value) -> Value {
    let mut smtplog = Vec::new();
    for row in after["smtplog"].as_array().into_iter().flatten() {
        let earlier = before["smtplog"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|b| b[0] == row[0] && b[1] == row[1])
            .and_then(|b| b[2].as_i64())
            .unwrap_or(0);
        for _ in earlier..row[2].as_i64().unwrap_or(0) {
            smtplog.push(json!([row[0], row[1]]));
        }
    }
    let new = |table: &str, drop: &[&str]| -> Vec<Value> {
        let known = before[table].as_array().map_or(0, Vec::len);
        after[table]
            .as_array()
            .into_iter()
            .flatten()
            .skip(known)
            .map(|row| {
                let mut row = row.clone();
                if let Some(row) = row.as_object_mut() {
                    for key in drop {
                        row.remove(*key);
                    }
                }
                row
            })
            .collect()
    };
    json!({
        "smtplog": smtplog,
        "email_thread_message": new(
            "email_thread_message",
            &["id", "insert_date", "thread_id_hash", "message_id_hash", "normalized_subject_hash"],
        ),
        "email_thread_domain": new(
            "email_thread_domain",
            &["id", "firstseendate", "thread_id_hash", "message_id_hash", "entry_hash", "numseen"],
        ),
    })
}

/// What the module wrote, in the same form as `added_rows`.
fn written_rows(writes: &[ace_sdk::writes::WireWrite]) -> Value {
    let mut smtplog = Vec::new();
    let mut messages = Vec::new();
    let mut domains = Vec::new();
    for write in writes {
        match write.write.as_str() {
            "smtp-log" => {
                for row in write.body["rows"].as_array().into_iter().flatten() {
                    smtplog.push(json!([row["source"], row["destination"]]));
                }
            }
            "email-thread" => {
                let body = &write.body;
                messages.push(json!({
                    "thread_id": body["thread_id"],
                    "message_id": body["message_id"],
                    "in_reply_to": body["in_reply_to"],
                    "normalized_subject": body["normalized_subject"],
                    "from_address": body["from_address"],
                    "from_domain": body["from_domain"],
                    "direction": body["direction"],
                    "message_date": body["message_date"],
                }));
                for participant in body["participants"].as_array().into_iter().flatten() {
                    domains.push(json!({
                        "thread_id": body["thread_id"],
                        "domain": participant["domain"],
                        "address": participant["address"],
                        "role": participant["role"],
                    }));
                }
            }
            other => panic!("an unknown write {other}"),
        }
    }
    json!({"smtplog": smtplog, "email_thread_message": messages, "email_thread_domain": domains})
}

/// What ace3's reads answered, as the `email-thread-domains` read answers, or None without one.
fn thread_domains_answer(reads: &Value) -> Option<Value> {
    let reads = reads.as_array()?;
    let established = reads.iter().find_map(|r| r.get("established"))?;
    let count = reads
        .iter()
        .find_map(|r| r.get("thread_message_count"))
        .cloned()
        .unwrap_or(json!(0));
    Some(json!({"established": established, "thread_message_count": count, "truncated": false}))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_email_logger_matches_the_reference_dumps_or_lists_each_difference() {
    use ace_mod_brocess::EmailLogger;
    use ace_mod_email::EmailAnalyzer;

    let listed = listed_for("email_logger");
    let email = Harness::<EmailAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details("RFC 822 mail, ASCII text", "message/rfc822"),
        );
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/email_logger");
    let mut compared = Vec::new();
    let mut skipped = Vec::new();
    let dumps = Dump::all("email_logger").expect("the dumps read");
    assert!(dumps.len() >= 45, "only {} dumps", dumps.len());
    for dump in dumps {
        let name = dump.short_name().to_owned();
        let observable = match name.strip_prefix("thread/") {
            Some(fixture) => email.file(
                &format!("{fixture}.email.rfc822"),
                fixtures.join(format!("{fixture}.email.rfc822")),
                &[],
            ),
            // the sample-set runs are named after their sample
            None => email.sample(&name),
        };
        let mut observable = match observable {
            Ok(observable) => observable.with_directive("original_email"),
            Err(e) if name.starts_with("local/") => {
                eprintln!("skipping {}: {e}", dump.name);
                skipped.push(name);
                continue;
            }
            Err(e) => panic!("{}: {e}", dump.name),
        };
        if let Some(file) = observable.file.as_mut() {
            file.mime_type = dump.mime_type().map(str::to_owned);
        }
        let Outcome::Done(parsed) = email
            .run_parser(observable.clone())
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name))
        else {
            panic!("{}: the email module parsed nothing", dump.name);
        };
        let fluent_bit = FakeFluentBit::start().await;
        let mut reads = FakeReads::new();
        if let Some(answer) = thread_domains_answer(&dump.value["brocess_reads"]) {
            reads = reads.answer("email-thread-domains", answer);
        }
        let reads = Arc::new(reads);
        let logger = Harness::<EmailLogger>::with_settings(json!({
            "fluent_bit_hostname": "127.0.0.1",
            "fluent_bit_port": fluent_bit.port,
        }))
        .expect("harness")
        .reader(reads.clone())
        .dependency_result(
            "email_analyzer",
            serde_json::to_value(&parsed.details).expect("JSON"),
        );
        let (outcome, writes) = logger
            .run_lookup_writing(observable)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        assert!(matches!(outcome, Outcome::Skipped(_)), "{}", dump.name);
        let expected = dump.value["fluent_bit"].as_array().expect("records");
        let wanted = fluent_form(expected).as_array().map_or(0, Vec::len);
        let sent = fluent_bit.records(wanted).await;
        let ace3 = json!({
            "brocess": added_rows(&dump.value["brocess_before"], &dump.value["brocess_after"]),
            "fluent_bit": fluent_form(expected),
        });
        let ace_rs = json!({
            "brocess": written_rows(&writes),
            "fluent_bit": fluent_form(&sent),
        });
        compared.push((name, diff(&ace3, &ace_rs)));
    }
    if let Err(report) = listed.check(&compared, &skipped) {
        panic!("{report}");
    }
}

/// An email's details as the email module would give them, for the logger's own tests.
fn email_details(from: &str, rcpt: &[&str], message_id: Option<&str>) -> Value {
    use ace_results::types::email::{EmailAnalysis, EmailDetails, LogEntry};
    let rcpt: Vec<String> = rcpt.iter().map(|r| (*r).to_owned()).collect();
    let analysis = EmailAnalysis {
        parsing_error: None,
        extraction_errors: Vec::new(),
        parts: None,
        email: Some(EmailDetails {
            headers: vec![
                ["From".to_owned(), from.to_owned()],
                ["Subject".to_owned(), "Hello".to_owned()],
                [
                    "Date".to_owned(),
                    "Mon, 02 Nov 2026 09:30:00 +0000".to_owned(),
                ],
            ],
            from_address: Some(from.to_owned()),
            env_rcpt_to: rcpt.clone(),
            to_addresses: vec!["bob@example.org".to_owned()],
            subject: Some("Hello".to_owned()),
            message_id: message_id.map(str::to_owned),
            log_entry: LogEntry {
                date: "2026-11-08 10:00:00.123456 +0000".to_owned(),
                env_rcpt_to: rcpt,
                mail_from: Some(from.to_owned()),
                message_id: message_id.map(str::to_owned),
                subject: Some("Hello".to_owned()),
                headers: vec!["From: x".to_owned(), "Subject: Hello".to_owned()],
                ..LogEntry::default()
            },
            ..EmailDetails::default()
        }),
    };
    serde_json::to_value(analysis).expect("JSON")
}

fn logger(
    settings: Value,
    details: Value,
    reads: Arc<FakeReads>,
) -> Harness<ace_mod_brocess::EmailLogger> {
    Harness::<ace_mod_brocess::EmailLogger>::with_settings(settings)
        .expect("harness")
        .reader(reads)
        .dependency_result("email_analyzer", details)
}

fn email_file(harness: &Harness<ace_mod_brocess::EmailLogger>) -> ace_sdk::Observable {
    harness
        .file_bytes("email.rfc822", b"an email", &[])
        .expect("a file")
        .with_directive("original_email")
}

fn no_thread() -> Value {
    json!({"established": [], "thread_message_count": 0, "truncated": false})
}

#[tokio::test(flavor = "multi_thread")]
async fn the_logger_sends_urls_apart_and_its_writes_follow_its_settings() {
    let fluent_bit = FakeFluentBit::start().await;
    let reads = Arc::new(FakeReads::new().answer("email-thread-domains", no_thread()));
    let details = email_details(
        "Alice <Alice@Example.com>",
        &["bob@example.org", "<>", "carol@example.org"],
        Some("<m@example.com>"),
    );
    let harness = logger(
        json!({"fluent_bit_hostname": "127.0.0.1", "fluent_bit_port": fluent_bit.port,
               "local_email_domains": ["example.com"]}),
        details.clone(),
        reads.clone(),
    )
    .observables_below(vec![
        ace_results::ObservableRef::new(ObservableKind::Url, "https://b.example/"),
        ace_results::ObservableRef::new(ObservableKind::Url, "https://a.example/"),
        ace_results::ObservableRef::new(ObservableKind::Url, "https://a.example/"),
    ]);
    let (outcome, writes) = harness
        .run_lookup_writing(email_file(&harness))
        .await
        .expect("runs");
    assert!(matches!(outcome, Outcome::Skipped(_)));
    // the sender normalized, and a recipient with no address left out
    assert_eq!(
        written_rows(&writes)["smtplog"],
        json!([
            ["alice@example.com", "bob@example.org"],
            ["alice@example.com", "carol@example.org"]
        ])
    );
    // mail from a local domain is outbound
    assert_eq!(writes[1].body["direction"], json!(1));
    let records = fluent_bit.records(6).await;
    let tags: Vec<&str> = records
        .iter()
        .map(|r| r["tag"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        tags,
        [
            "phishfinder-urls",
            "phishfinder-urls",
            "phishfinder-headers",
            "phishfinder-headers",
            "phishfinder-main",
            "phishfinder-lookalike"
        ]
    );
    assert_eq!(records[0]["record"]["url"], "https://a.example/");
    assert_eq!(records[0]["record"]["timestamp"], "1794132000.123456");
    assert_eq!(records[3]["record"]["header_index"], json!(1));
    let main = records[4]["record"].as_object().expect("an object");
    assert!(!main.contains_key("extracted_urls") && !main.contains_key("headers"));
    assert_eq!(main["archive_hash"], Value::Null);

    // with brocess logging and thread recording off, nothing is written, and the read is still made
    let harness = logger(
        json!({"fluent_bit_hostname": "127.0.0.1", "fluent_bit_port": fluent_bit.port,
               "brocess_logging_enabled": false, "thread_recording_enabled": false}),
        details.clone(),
        reads.clone(),
    );
    let (_, writes) = harness
        .run_lookup_writing(email_file(&harness))
        .await
        .expect("runs");
    assert!(writes.is_empty());
    assert_eq!(reads.requests().len(), 2);

    // with look-alike telemetry off, the thread is recorded without the read
    let harness = logger(
        json!({"fluent_bit_hostname": "127.0.0.1", "fluent_bit_port": fluent_bit.port,
               "lookalike_telemetry_enabled": false}),
        details,
        reads.clone(),
    );
    let (_, writes) = harness
        .run_lookup_writing(email_file(&harness))
        .await
        .expect("runs");
    assert_eq!(reads.requests().len(), 2);
    assert_eq!(writes.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_message_id_the_urls_stay_in_the_entry_and_nothing_is_threaded() {
    let fluent_bit = FakeFluentBit::start().await;
    let reads = Arc::new(FakeReads::new());
    let harness = logger(
        json!({"fluent_bit_hostname": "127.0.0.1", "fluent_bit_port": fluent_bit.port}),
        email_details("alice@example.com", &[], None),
        reads.clone(),
    )
    .observables_below(vec![ace_results::ObservableRef::new(
        ObservableKind::Url,
        "https://a.example/",
    )]);
    let (_, writes) = harness
        .run_lookup_writing(email_file(&harness))
        .await
        .expect("runs");
    assert!(writes.is_empty(), "no recipients and no thread: {writes:?}");
    assert!(reads.requests().is_empty());
    let records = fluent_bit.records(1).await;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["record"]["extracted_urls"],
        json!(["https://a.example/"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_entry_names_the_email_the_archiver_archived() {
    use ace_sdk::tree::{TreeObservable, TreeResult, TreeView};
    let fluent_bit = FakeFluentBit::start().await;
    let harness = logger(
        json!({"fluent_bit_hostname": "127.0.0.1", "fluent_bit_port": fluent_bit.port}),
        email_details("alice@example.com", &[], None),
        Arc::new(FakeReads::new()),
    );
    let file = email_file(&harness);
    let tree = TreeView {
        this: 0,
        observables: vec![TreeObservable {
            kind: ObservableKind::File,
            value: file.value.clone(),
            tags: Vec::new(),
            directives: vec!["original_email".to_owned()],
            detections: 0,
            paths: Vec::new(),
            size: None,
            pending: Vec::new(),
            download: None,
            relationships: Vec::new(),
        }],
        results: vec![TreeResult {
            observable: 0,
            module: "email_archiver".to_owned(),
            analysis_type: "email_archive_results".to_owned(),
            tags: Vec::new(),
            error: None,
            detections: 0,
            added: Vec::new(),
            details: None,
        }],
        ..Default::default()
    };
    harness
        .tree(tree)
        .run_lookup_writing(file.clone())
        .await
        .expect("runs");
    let records = fluent_bit.records(1).await;
    let sha256 = &file.value;
    assert_eq!(records[0]["record"]["archive_hash"], json!(sha256));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_core_or_a_fluent_bit_that_cant_be_reached_loses_only_its_own_part() {
    // nothing listens on the port
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        listener.local_addr().expect("an address").port()
    };
    let reads = Arc::new(FakeReads::new().unavailable("email-thread-domains"));
    let harness = logger(
        json!({"fluent_bit_hostname": "127.0.0.1", "fluent_bit_port": port}),
        email_details("alice@example.com", &["bob@example.org"], Some("<m@x>")),
        reads,
    );
    let (outcome, writes) = harness
        .run_lookup_writing(email_file(&harness))
        .await
        .expect("runs");
    assert!(matches!(outcome, Outcome::Skipped(_)));
    // as ace3's exporters, the smtplog write stands, and the thread isn't recorded after a failed read
    let names: Vec<&str> = writes.iter().map(|w| w.write.as_str()).collect();
    assert_eq!(names, ["smtp-log"]);
}

#[tokio::test]
async fn an_email_the_email_module_couldnt_parse_isnt_logged() {
    let harness = Harness::<ace_mod_brocess::EmailLogger>::new()
        .expect("harness")
        .dependency_result(
            "email_analyzer",
            json!({"parsing_error": "bad", "extraction_errors": [], "email": null}),
        );
    let (outcome, writes) = harness
        .run_lookup_writing(email_file(&harness))
        .await
        .expect("runs");
    assert!(matches!(outcome, Outcome::Skipped(_)));
    assert!(writes.is_empty());
}

#[test]
fn a_timestamp_is_pythons_float() {
    use ace_mod_brocess::logger::entry_timestamp;
    // what str(datetime.strptime(date, "%Y-%m-%d %H:%M:%S.%f %z").timestamp()) gives in ace3
    assert_eq!(
        entry_timestamp("2026-11-08 10:00:00.123456 +0000").as_deref(),
        Some("1794132000.123456")
    );
    assert_eq!(
        entry_timestamp("2026-11-08 10:00:00.000000 -0500").as_deref(),
        Some("1794150000.0")
    );
    assert_eq!(
        entry_timestamp("2026-11-08 10:00:00.5 +0530").as_deref(),
        Some("1794112200.5")
    );
    assert_eq!(entry_timestamp("yesterday"), None);
}

// ---- email_thread_analyzer ----

/// The thread module's settings for a dump: ace3's defaults, or a run's own.
fn thread_settings(name: &str) -> Value {
    if name.ends_with(".capped") {
        json!({"max_messages": 2, "max_threads": 1})
    } else if name.ends_with(".ignored") {
        json!({"ignored_domain_pairs": [["mail.example.com", "examp1e.com"]]})
    } else {
        json!({})
    }
}

#[tokio::test]
async fn the_thread_module_matches_the_reference_dumps_or_lists_each_difference() {
    use ace_mod_brocess::EmailThreadAnalyzer;
    let listed = listed_for("email_thread_analyzer");
    let mut compared = Vec::new();
    let dumps = Dump::all("email_thread_analyzer").expect("the dumps read");
    assert_eq!(dumps.len(), 10);
    for dump in dumps {
        let name = dump.short_name().to_owned();
        let value = dump.value["input"]["observable"]["value"]
            .as_str()
            .expect("a value")
            .to_owned();
        let conversation = dump.value["brocess_reads"]
            .as_array()
            .and_then(|reads| reads.iter().find_map(|r| r.get("conversation")))
            .cloned()
            .expect("ace3 read the conversation");
        let reads = Arc::new(
            FakeReads::new().answer("email-thread", json!({"conversation": conversation})),
        );
        let settings = thread_settings(&name);
        let harness = Harness::<EmailThreadAnalyzer>::with_settings(settings.clone())
            .expect("harness")
            .reader(reads.clone());
        let outcome = harness
            .run_lookup(harness.observable(ObservableKind::MessageId, &value))
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let caps = |key: &str| settings.get(key).cloned().unwrap_or(json!(50));
        assert_eq!(
            reads.requests(),
            [(
                "email-thread",
                json!({"subject": null, "max_messages": caps("max_messages"),
                       "max_threads": caps("max_threads")})
            )],
            "{name}"
        );
        if name == "message_id_<inv-3@examp1e.com>" {
            ace_testkit::check_view_fixture("brocess_email_thread", &outcome);
        }
        // the findings ace3 adds as a summary detail, which ace-rs's view draws from the details
        let ace3_findings = dump
            .analysis("EmailThreadAnalysis")
            .and_then(|a| a["summary_details"].as_array())
            .and_then(|details| details.first())
            .map(|d| d["content"].clone())
            .unwrap_or(Value::Null);
        let ace_rs_findings = match &outcome {
            Outcome::Done(result) => {
                ace_mod_brocess::thread::findings(&result.details).map_or(Value::Null, Value::from)
            }
            _ => Value::Null,
        };
        let ace3 = json!({
            "analysis": dump.normal_form("EmailThreadAnalysis"),
            "findings": ace3_findings,
        });
        let ace_rs = json!({"analysis": normal_form(&outcome), "findings": ace_rs_findings});
        compared.push((name, diff(&ace3, &ace_rs)));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}

#[tokio::test]
async fn the_thread_module_refuses_caps_of_nothing_and_fails_when_the_core_can_t_answer() {
    use ace_mod_brocess::EmailThreadAnalyzer;
    assert!(Harness::<EmailThreadAnalyzer>::with_settings(json!({"max_messages": 0})).is_err());
    let harness = Harness::<EmailThreadAnalyzer>::new()
        .expect("harness")
        .reader(Arc::new(FakeReads::new().unavailable("email-thread")));
    let err = harness
        .run_lookup(harness.observable(ObservableKind::MessageId, "<a@x>"))
        .await
        .expect_err("unavailable");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::Unavailable(_))),
        "{err}"
    );
}

#[tokio::test]
async fn the_thread_module_waits_while_the_root_s_email_is_still_to_be_recorded() {
    use ace_mod_brocess::EmailThreadAnalyzer;
    let harness = Harness::<EmailThreadAnalyzer>::new()
        .expect("harness")
        .reader(Arc::new(FakeReads::new().answer(
            "email-thread",
            json!({"conversation": null, "recording": true}),
        )));
    let outcome = harness
        .run_lookup(harness.observable(ObservableKind::MessageId, "<a@x>"))
        .await
        .expect("runs");
    assert!(matches!(outcome, Outcome::Delay(_)), "{outcome:?}");
}

// ---- 7.5 batch 8: the modules that read the frequency module's tags ----

/// The smtplog rows `make-dumps emailtree` gave a run's `--brocess`.
fn emailtree_rows(dump: &Dump) -> Value {
    match (
        dump.value["module"].as_str(),
        dump.short_name().ends_with(".known_sender"),
    ) {
        (Some("email_conversation_attachment_analyzer"), true) => fixture_rows(),
        (Some("email_conversation_link_analyzer"), true) => {
            json!([["it@corp.example", "pat@corp.example", 9]])
        }
        _ => json!([]),
    }
}

/// The dump's root as the core would send it to a module on the observable at `this`, with each
/// conversation's frequency result and tags from ace-rs's frequency module over the run's rows, in
/// place of ace3's.
async fn emailtree_view(dump: &Dump, this: usize, leave_out: &str) -> ace_sdk::tree::TreeView {
    use ace_results::AnalysisType;
    use ace_results::types::brocess::EmailConversationFrequencyAnalysis;
    let rows = emailtree_rows(dump);
    let mut tree = dump.tree_view(this, &[leave_out, "EmailConversationFrequencyAnalysis"]);
    for i in tree
        .of_kind(ObservableKind::EmailConversation)
        .collect::<Vec<_>>()
    {
        let value = tree.observables[i].value.clone();
        let reads = Arc::new(FakeReads::new().answer("smtp-counts", counts_in(&rows, &value)));
        let harness = Harness::<EmailConversationFrequencyAnalyzer>::new()
            .expect("harness")
            .reader(reads);
        let Outcome::Done(result) = harness
            .run_lookup(harness.observable(ObservableKind::EmailConversation, &value))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name))
        else {
            panic!("{}: the frequency module stored nothing", dump.name);
        };
        let observable = &mut tree.observables[i];
        observable
            .tags
            .retain(|t| t != "new_sender" && t != "frequent_conversation");
        observable.tags.extend(result.analyzed.tags.iter().cloned());
        tree.results.push(ace_sdk::tree::TreeResult {
            observable: i,
            module: EmailConversationFrequencyAnalysis::MODULE.to_owned(),
            analysis_type: EmailConversationFrequencyAnalysis::NAME.to_owned(),
            tags: Vec::new(),
            error: None,
            detections: 0,
            added: Vec::new(),
            details: None,
        });
    }
    tree
}

/// What a module of the two did on each observable, ace3's from the root it left: whether it made an
/// analysis there, whether its detection is there, and whether it gave the observable `directive`.
fn ace3_effects(dump: &Dump, class: &str, description: &str, directive: Option<&str>) -> Value {
    let observables = dump.value["tree_view"]["observables"]
        .as_array()
        .expect("observables");
    let analyzed: Vec<usize> = dump
        .tree_results(class)
        .into_iter()
        .map(|(i, _)| i)
        .collect();
    let mut effects = serde_json::Map::new();
    for (i, o) in observables.iter().enumerate() {
        let detection = o["detections"]
            .as_array()
            .is_some_and(|d| d.contains(&json!(description)));
        let has = |d: &str| {
            o["directives"]
                .as_array()
                .is_some_and(|ds| ds.contains(&json!(d)))
        };
        let added = directive.is_some_and(|d| analyzed.contains(&i) && has(d));
        if analyzed.contains(&i) || detection {
            effects.insert(
                format!("{}:{}", o["type"].as_str().unwrap_or_default(), o["value"].as_str().unwrap_or_default()),
                json!({"analysis": analyzed.contains(&i), "detection": detection, "directive": added}),
            );
        }
    }
    Value::Object(effects)
}

#[tokio::test]
async fn the_attachment_and_link_modules_match_the_reference_dumps_or_lists_each_difference() {
    use ace_mod_brocess::attachment::{self, EmailConversationAttachmentAnalyzer};
    use ace_mod_brocess::link::{self, EmailConversationLinkAnalyzer};
    use ace_results::AnalysisType;
    use ace_results::types::file_type::FileTypeAnalysis;

    let mut compared = Vec::new();
    let mut fired = 0;
    let dumps = Dump::all("email_conversation_attachment_analyzer").expect("the dumps read");
    assert!(dumps.len() >= 15, "only {} attachment dumps", dumps.len());
    for dump in dumps {
        let mut ace_rs = serde_json::Map::new();
        let files: Vec<(usize, Value)> = dump
            .tree_results("FileTypeAnalysis")
            .into_iter()
            .map(|(i, r)| (i, r["details"].clone()))
            .collect();
        for (i, file_type) in files {
            let tree = emailtree_view(&dump, i, "EmailConversationAttachmentAnalysis").await;
            let o = tree.observable(i).clone();
            let path = o.paths.first().map(|p| p.path.clone()).unwrap_or_default();
            let harness = Harness::<EmailConversationAttachmentAnalyzer>::new()
                .expect("harness")
                .dependency_result(FileTypeAnalysis::MODULE, file_type)
                .tree(tree);
            let observable = harness.observable(ObservableKind::File, &o.value);
            let outcome = harness
                .run_parser(observable)
                .unwrap_or_else(|e| panic!("{} {path}: {e}", dump.name));
            if dump.short_name() == "ace-rs/email/macro_attachment.email.rfc822"
                && matches!(outcome, Outcome::Done(_))
            {
                ace_testkit::check_view_fixture("attachment_macro_attachment", &outcome);
            }
            match outcome {
                Outcome::Done(result) => {
                    fired += 1;
                    ace_rs.insert(
                        format!("file:{}", o.value),
                        json!({
                            "analysis": true,
                            "detection": result.analyzed.detections.iter().any(|d| d.description == attachment::DESCRIPTION),
                            "directive": result.analyzed.directives.iter().any(|d| d == "sandbox"),
                        }),
                    );
                }
                Outcome::Skipped(_) => {}
                Outcome::Delay(_) => panic!("{} {path}: the module delayed", dump.name),
                Outcome::Incomplete(_) => panic!("{} {path}: the module was incomplete", dump.name),
                Outcome::DoneNotKept(_) => {
                    panic!("{} {path}: the module's result was not kept", dump.name)
                }
            }
        }
        compared.push((
            format!(
                "email_conversation_attachment_analyzer/{}",
                dump.short_name()
            ),
            diff(
                &ace3_effects(
                    &dump,
                    "EmailConversationAttachmentAnalysis",
                    attachment::DESCRIPTION,
                    Some("sandbox"),
                ),
                &Value::Object(ace_rs),
            ),
        ));
    }
    assert!(fired >= 2, "the attachment module fired {fired} times");

    let dumps = Dump::all("email_conversation_link_analyzer").expect("the dumps read");
    assert!(dumps.len() >= 4, "only {} link dumps", dumps.len());
    for dump in dumps {
        let settings = if dump.short_name().ends_with(".nothing") {
            json!({"url_pattern_none": "no-such-host"})
        } else {
            json!({"url_pattern_lure": r"lure-example\.(net|org)", "url_pattern_bad": "(unclosed"})
        };
        let urls: Vec<usize> = {
            let tree = dump.tree_view(0, &[]);
            tree.of_kind(ObservableKind::Url).collect()
        };
        let mut ace_rs = serde_json::Map::new();
        for i in urls {
            let tree = emailtree_view(&dump, i, "EmailConversationLinkAnalysis").await;
            let value = tree.observable(i).value.clone();
            let harness = Harness::<EmailConversationLinkAnalyzer>::with_settings(settings.clone())
                .expect("harness")
                .tree(tree);
            let outcome = harness
                .run_parser(harness.observable(ObservableKind::Url, &value))
                .unwrap_or_else(|e| panic!("{} {value}: {e}", dump.name));
            if dump.short_name() == "ace-rs/email/lure_button.email.rfc822"
                && value == "https://login.lure-example.net/verify?id=7"
            {
                ace_testkit::check_view_fixture("link_lure_button", &outcome);
            }
            match outcome {
                Outcome::Done(result) => {
                    ace_rs.insert(
                        format!("url:{value}"),
                        json!({
                            "analysis": true,
                            "detection": result.analyzed.detections.iter().any(|d| d.description == link::DESCRIPTION),
                            "directive": false,
                        }),
                    );
                }
                Outcome::Skipped(_) => {}
                Outcome::Delay(_) => panic!("{} {value}: the module delayed", dump.name),
                Outcome::Incomplete(_) => {
                    panic!("{} {value}: the module was incomplete", dump.name)
                }
                Outcome::DoneNotKept(_) => {
                    panic!("{} {value}: the module's result was not kept", dump.name)
                }
            }
        }
        compared.push((
            format!("email_conversation_link_analyzer/{}", dump.short_name()),
            diff(
                &ace3_effects(
                    &dump,
                    "EmailConversationLinkAnalysis",
                    link::DESCRIPTION,
                    None,
                ),
                &Value::Object(ace_rs),
            ),
        ));
    }
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut listed = listed;
    listed.rows.retain(|row| {
        matches!(
            row.section.as_deref(),
            Some("email_conversation_attachment_analyzer" | "email_conversation_link_analyzer")
        )
    });
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
