//! PLAN.md 2.17's Done check: a panicking parser leaves a failed-task row and the supervisor
//! keeps leasing, a task process has no capabilities, and the archive module (on test.r07, a
//! RAR 5 file) and the YARA module each run contained. The supervisor is the test pool binary
//! in its parsers mode, running task processes as the dev image's ace4-task user. Also: a cancel
//! and a shutdown each kill a running task process. `hung_tasks.rs` covers the deadline.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use ace_core::tree::{self, NewRoot};
use ace_pool::testing;
use ace_results::{NewObservable, ObservableKind};
use serde_json::json;

use common::{
    Core, PoolProcess, root_with_bytes, root_with_file, root_with_tasks, task_of, test_pool,
    wait_until_idle,
};

/// The supervisor, running task processes as ace4-task.
fn supervisor(core: &Core, extra: &[&str]) -> PoolProcess {
    let mut args = vec!["parsers", "--task-user", "ace4-task", "--concurrency", "1"];
    args.extend_from_slice(extra);
    PoolProcess::start(test_pool(core, &args))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_parser_fails_its_task_and_the_supervisor_keeps_leasing() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_panicking_parser", "test_capabilities"],
        Duration::from_secs(30),
    )
    .await;
    let panics = root_with_tasks(
        &core,
        &["first.example.com".to_owned()],
        "test_panicking_parser",
    )
    .await;
    let reports = root_with_tasks(
        &core,
        &["second.example.com".to_owned()],
        "test_capabilities",
    )
    .await;

    let mut pool = supervisor(&core, &[]);
    wait_until_idle(&core, panics, Duration::from_secs(60)).await;
    wait_until_idle(&core, reports, Duration::from_secs(60)).await;
    assert!(pool.running(), "the supervisor kept running");
    let stderr = pool.stop();

    let (state, error) = task_of(&core, panics, "test_panicking_parser").await;
    assert_eq!(state, "failed", "{stderr}");
    assert_eq!(
        error.as_deref(),
        Some("the module panicked: test_panicking_parser was given first.example.com")
    );
    // the next task ran after the panic, and its process had no capabilities
    let (state, _) = task_of(&core, reports, "test_capabilities").await;
    assert_eq!(state, "done", "{stderr}");
    let note: String =
        sqlx::query_scalar("SELECT details->>'note' FROM analysis.results WHERE root_id = $1")
            .bind(reports)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("the report");
    println!("{note}");
    for wanted in [
        "Uid: 10001 10001 10001 10001",
        "CapInh: 0000000000000000",
        "CapPrm: 0000000000000000",
        "CapEff: 0000000000000000",
        "CapAmb: 0000000000000000",
    ] {
        assert!(note.contains(wanted), "{wanted} in {note}");
    }
    assert!(
        note.contains("Groups:;") || note.ends_with("Groups:"),
        "no groups in {note}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_archive_module_unpacks_rar_5_in_a_contained_task_process() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let (root, _, rar) = core
        .root_with_file("file", "ace3/archive/test.r07", "test.r07")
        .await;
    let mut pool = supervisor(&core, &[]);
    let started = std::time::Instant::now();
    loop {
        let (state, _) = task_of(&core, root, "archive").await;
        if state != "queued" && state != "running" {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the archive task is still {state}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stderr = pool.stop();
    let rows = core.tasks(root).await;
    println!("{rows:?}");
    assert_eq!(
        rows[0],
        ("archive".to_owned(), rar.to_hex(), "done".to_owned()),
        "{stderr}"
    );
    assert!(stderr.contains("contained: Contained"), "{stderr}");
    let (count, paths): (i32, Vec<String>) = sqlx::query_as(
        "SELECT (r.details->>'file_count')::int,
                ARRAY(SELECT path FROM analysis.files f
                      WHERE f.root_id = r.root_id AND f.path <> 'test.r07' ORDER BY path)
         FROM analysis.results r WHERE r.root_id = $1 AND r.module = 'archive'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the archive's result");
    println!("{count} files: {paths:?}");
    assert!(count > 0);
    assert!(!paths.is_empty());
    assert!(
        paths.iter().all(|p| p.starts_with("test.r07.extracted/")),
        "{paths:?}"
    );
}

/// The states and errors of `pdf_analyzer` tasks, with the module left to finish.
async fn pdf_task(
    core: &Core,
    root: uuid::Uuid,
    within: Duration,
) -> (String, Option<String>, f64) {
    let started = std::time::Instant::now();
    loop {
        let (state, error) = task_of(core, root, "pdf_analyzer").await;
        if state != "queued" && state != "running" {
            return (state, error, started.elapsed().as_secs_f64());
        }
        assert!(started.elapsed() < within, "the PDF task is still {state}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pdf_module_reads_an_aes_pdf_in_a_contained_task_process() {
    let core = Core::start(
        vec![ace_mod_pdf::MANIFEST],
        &["pdf_analyzer"],
        Duration::from_secs(30),
    )
    .await;
    let (root, _, _) = core
        .root_with_file("file", "ace4/pdf/encrypted_aes_256_r6.pdf", "doc.pdf")
        .await;
    let mut pool = supervisor(&core, &[]);
    let (state, error, _) = pdf_task(&core, root, Duration::from_secs(60)).await;
    let stderr = pool.stop();
    assert_eq!((state.as_str(), error), ("done", None), "{stderr}");
    assert!(stderr.contains("contained: Contained"), "{stderr}");
    let (method, paths): (Option<String>, Vec<String>) = sqlx::query_as(
        "SELECT r.details->'encryption'->>'method',
                ARRAY(SELECT path FROM analysis.files f
                      WHERE f.root_id = r.root_id AND f.path <> 'doc.pdf' ORDER BY path)
         FROM analysis.results r WHERE r.root_id = $1 AND r.module = 'pdf_analyzer'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the result");
    assert_eq!(method.as_deref(), Some("aesv3"), "{stderr}");
    assert_eq!(
        paths,
        [
            "doc.pdf.annotation_uris.txt",
            "doc.pdf.decrypted.pdf",
            "doc.pdf.decrypted.pdf.pdfparser",
            "doc.pdf.field_payload_decoded.bin",
            "doc.pdf.js_script.js",
            "doc.pdf.js_stream.js",
            "doc.pdf.pdfparser",
        ]
    );
}

/// PLAN.md 4.9: a stream that decodes past the address-space limit inside libqpdf leaves a row, and
/// the next task runs. A few MB of file decode to more than the limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pdf_that_exhausts_a_task_leaves_a_row_and_the_supervisor_keeps_leasing() {
    use std::io::Write;

    let core = Core::start(
        vec![ace_mod_pdf::MANIFEST],
        &["pdf_analyzer"],
        Duration::from_secs(30),
    )
    .await;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    let zeros = vec![0u8; 1 << 24];
    for _ in 0..(3u64 << 30) / (1 << 24) {
        encoder.write_all(&zeros).expect("compresses");
    }
    let bomb = encoder.finish().expect("compresses");
    let mut file = b"%PDF-1.7\n1 0 obj\n<</Type/Catalog/Pages 2 0 R/Names<</JavaScript<</Names[(a)<</JS 4 0 R>>]>>>>>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n3 0 obj\n<</Type/Page/Parent 2 0 R>>\nendobj\n4 0 obj\n<</Filter/FlateDecode/Length ".to_vec();
    file.extend_from_slice(format!("{}>>\nstream\n", bomb.len()).as_bytes());
    file.extend_from_slice(&bomb);
    file.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<</Root 1 0 R>>\n");
    let (bomb_root, _) = root_with_bytes(&core, "file", &file, "bomb.pdf").await;
    let (after, _, _) = core
        .root_with_file("file", "ace3/pdf/Payment_Advice.pdf", "after.pdf")
        .await;
    let mut pool = supervisor(&core, &[]);
    let (state, error, seconds) = pdf_task(&core, bomb_root, Duration::from_secs(120)).await;
    println!("the bomb: {state} in {seconds:.1}s: {error:?}");
    // the limit stops it either in libqpdf, which reports it and leaves the rest of the result, or
    // in an allocation that can't be reported, which fails the task
    assert!(state == "done" || state == "failed", "{state}");
    let (state, error, _) = pdf_task(&core, after, Duration::from_secs(60)).await;
    assert_eq!((state.as_str(), error), ("done", None));
    assert!(pool.running(), "the supervisor kept running");
    let _ = pool.stop();
}

/// A measurement rather than a test (docs/measurements/pdf-hostile.md): each file in the directory
/// `ACE4_PDF_HOSTILE` names, as a task with the module's real limits, and what became of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, with files tools/samples/make-pdf-hostile makes"]
async fn measure_hostile_pdfs() {
    let dir = std::env::var("ACE4_PDF_HOSTILE").expect("ACE4_PDF_HOSTILE");
    let core = Core::start(
        vec![ace_mod_pdf::MANIFEST],
        &["pdf_analyzer"],
        Duration::from_secs(300),
    )
    .await;
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .expect("the directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a name")
        })
        .collect();
    names.sort();
    let mut pool = supervisor(&core, &[]);
    for name in names {
        let bytes = std::fs::read(format!("{dir}/{name}")).expect("the file");
        let (root, _) = root_with_bytes(&core, "file", &bytes, &name).await;
        let (state, error, seconds) = pdf_task(&core, root, Duration::from_secs(200)).await;
        let error = error.unwrap_or_default();
        let error: String = error.chars().take(120).collect();
        let files: i64 =
            sqlx::query_scalar("SELECT count(*) FROM analysis.files WHERE root_id = $1")
                .bind(root)
                .fetch_one(core.test_db.db().pool())
                .await
                .expect("counts");
        println!(
            "{name}\t{}\t{state}\t{seconds:.1}\t{}\t{error}",
            bytes.len(),
            files - 1
        );
        assert!(pool.running(), "the supervisor kept running after {name}");
    }
    let _ = pool.stop();
}

/// The state and error of a module's task, with the module left to finish.
async fn task_state(
    core: &Core,
    root: uuid::Uuid,
    module: &str,
    limit: Duration,
) -> (String, Option<String>, f64) {
    let started = std::time::Instant::now();
    loop {
        // a module that depends on another has no task until the other's result lands
        let (state, error): (String, Option<String>) = sqlx::query_as(
            "SELECT state::text, error FROM queue.tasks WHERE root_id = $1 AND module = $2",
        )
        .bind(root)
        .bind(module)
        .fetch_optional(core.test_db.db().pool())
        .await
        .expect("the task")
        .unwrap_or_else(|| ("queued".to_owned(), None));
        if state != "queued" && state != "running" {
            return (state, error, started.elapsed().as_secs_f64());
        }
        assert!(started.elapsed() < limit, "{module} still {state}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn olevba_and_rtfobj_finish_in_contained_task_processes() {
    let core = Core::start(
        vec![
            ace_mod_oletools::OLEVBA_MANIFEST,
            ace_mod_oletools::RTFOLE_MANIFEST,
        ],
        &["olevba_v1_2", "rtfole"],
        Duration::from_secs(60),
    )
    .await;
    let mut pool = supervisor(&core, &[]);
    for (sample, module, name) in [
        (
            "ace3/office/word2013_macro_stripped.doc",
            "olevba_v1_2",
            "a.doc",
        ),
        (
            "ace3/office/mortgage_payment-0873821-0565.docm",
            "olevba_v1_2",
            "b.docm",
        ),
        ("ace4/office/vba_powerpoint.ppt", "olevba_v1_2", "c.ppt"),
        ("ace4/rtf/objects.rtf", "rtfole", "d.rtf"),
    ] {
        let bytes = std::fs::read(ace_testkit::samples_dir().join(sample)).expect("the sample");
        let (root, _) = root_with_bytes(&core, "file", &bytes, name).await;
        let (state, error, _) = task_state(&core, root, module, Duration::from_secs(50)).await;
        assert_eq!(state, "done", "{sample}: {error:?}");
        let files: i64 =
            sqlx::query_scalar("SELECT count(*) FROM analysis.files WHERE root_id = $1")
                .bind(root)
                .fetch_one(core.test_db.db().pool())
                .await
                .expect("counts");
        assert!(files > 1, "{sample} wrote nothing");
    }
    let _ = pool.stop();
}

/// `task_state` for a module that runs last, which is delayed while the rest of its root runs.
async fn last_task_state(
    core: &Core,
    root: uuid::Uuid,
    module: &str,
) -> (String, Option<String>, f64) {
    let started = Instant::now();
    loop {
        let (state, error, _) = task_state(core, root, module, Duration::from_secs(200)).await;
        if state != "delayed" {
            return (state, error, started.elapsed().as_secs_f64());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xlm_and_pcode_finish_in_contained_task_processes() {
    let core = Core::start(
        vec![
            ace_mod_files::file_type::MANIFEST,
            ace_mod_xlm::XLM_MANIFEST,
            ace_mod_xlm::PCODE_MANIFEST,
        ],
        &["file_type", "xlmdeobfuscator", "pcodedmp"],
        Duration::from_secs(300),
    )
    .await;
    let mut pool = supervisor(&core, &[]);
    for (sample, module, files) in [
        ("ace4/office/xlm_info_3805.xls", "xlmdeobfuscator", 2),
        ("ace4/office/xlm_xlsb.xlsb", "xlmdeobfuscator", 2),
        ("ace3/office/receipt_687790.doc", "pcodedmp", 1),
    ] {
        let path = format!("{}/../../samples/{sample}", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(path).expect("a sample");
        let name = sample.rsplit('/').next().expect("a name");
        let (root, _) = root_with_bytes(&core, "file", &bytes, name).await;
        let (state, error, _) = last_task_state(&core, root, module).await;
        assert_eq!(state, "done", "{sample}: {error:?}");
        let found: i64 =
            sqlx::query_scalar("SELECT count(*) FROM analysis.files WHERE root_id = $1")
                .bind(root)
                .fetch_one(core.test_db.db().pool())
                .await
                .expect("counts");
        assert_eq!(found - 1, files, "{sample}");
    }
    let _ = pool.stop();
}

/// A measurement rather than a test (docs/measurements/xlm-hostile.md): each file in the directory
/// `ACE4_XLM_HOSTILE` names, as a task with the module's real limits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, with files tools/samples/make-xlm-hostile makes"]
async fn measure_hostile_xlm() {
    let dir = std::env::var("ACE4_XLM_HOSTILE").expect("ACE4_XLM_HOSTILE");
    let core = Core::start(
        vec![ace_mod_xlm::XLM_MANIFEST],
        &["xlmdeobfuscator"],
        Duration::from_secs(1800),
    )
    .await;
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .expect("the directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a name")
        })
        .collect();
    names.sort();
    let mut pool = supervisor(&core, &[]);
    for name in names {
        let bytes = std::fs::read(format!("{dir}/{name}")).expect("the file");
        let (root, _) = root_with_bytes(&core, "file", &bytes, &name).await;
        let (state, error, seconds) = last_task_state(&core, root, "xlmdeobfuscator").await;
        let error: String = error.unwrap_or_default().chars().take(120).collect();
        let details: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT details FROM analysis.results WHERE root_id = $1 AND module = 'xlmdeobfuscator'",
        )
        .bind(root)
        .fetch_optional(core.test_db.db().pool())
        .await
        .expect("a result");
        let files: i64 =
            sqlx::query_scalar("SELECT count(*) FROM analysis.files WHERE root_id = $1")
                .bind(root)
                .fetch_one(core.test_db.db().pool())
                .await
                .expect("counts");
        println!(
            "{name}\t{}\t{state}\t{seconds:.1}\t{}\t{details:?}\t{error}",
            bytes.len(),
            files - 1
        );
        assert!(pool.running(), "the supervisor kept running after {name}");
    }
    let _ = pool.stop();
}

/// A measurement rather than a test (docs/measurements/oletools-hostile.md): each file in the
/// directory `ACE4_OLETOOLS_HOSTILE` names, as a task with the modules' real limits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, with files tools/samples/make-oletools-hostile makes"]
async fn measure_hostile_oletools() {
    let dir = std::env::var("ACE4_OLETOOLS_HOSTILE").expect("ACE4_OLETOOLS_HOSTILE");
    let core = Core::start(
        vec![
            ace_mod_oletools::OLEVBA_MANIFEST,
            ace_mod_oletools::RTFOLE_MANIFEST,
        ],
        &["olevba_v1_2", "rtfole"],
        Duration::from_secs(300),
    )
    .await;
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .expect("the directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a name")
        })
        .collect();
    names.sort();
    let mut pool = supervisor(&core, &[]);
    for name in names {
        let bytes = std::fs::read(format!("{dir}/{name}")).expect("the file");
        let (root, _) = root_with_bytes(&core, "file", &bytes, &name).await;
        let module = if name.ends_with(".rtf") {
            "rtfole"
        } else {
            "olevba_v1_2"
        };
        let (state, error, seconds) =
            task_state(&core, root, module, Duration::from_secs(200)).await;
        let error: String = error.unwrap_or_default().chars().take(120).collect();
        let files: i64 =
            sqlx::query_scalar("SELECT count(*) FROM analysis.files WHERE root_id = $1")
                .bind(root)
                .fetch_one(core.test_db.db().pool())
                .await
                .expect("counts");
        println!(
            "{name}\t{}\t{state}\t{seconds:.1}\t{}\t{error}",
            bytes.len(),
            files - 1
        );
        assert!(pool.running(), "the supervisor kept running after {name}");
    }
    let _ = pool.stop();
}

/// The email module and the Office one, on real emails, as the parser pool runs them.
async fn email_and_office_core() -> Core {
    Core::start(
        vec![
            ace_mod_files::file_type::MANIFEST,
            ace_mod_email::MANIFEST,
            ace_mod_msoffice::MANIFEST,
        ],
        &[
            "file_type",
            "email_analyzer",
            "msoffice_encryption_analyzer",
        ],
        Duration::from_secs(400),
    )
    .await
}

async fn msoffice_details(core: &Core, root: uuid::Uuid) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT details FROM analysis.results
         WHERE root_id = $1 AND analysis_type = 'msoffice_encryption_analysis'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("a result")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attachment_opens_with_its_emails_body_in_a_contained_task_process() {
    let core = email_and_office_core().await;
    let mut pool = supervisor(&core, &[]);
    for (sample, password) in [
        (
            "ace4/email/encrypted_rc4_doc.email.rfc822",
            Some("R4Binary1"),
        ),
        (
            "ace4/email/encrypted_cryptoapi_ppt.email.rfc822",
            Some("CryptoAp1"),
        ),
        (
            "ace4/email/encrypted_nested_html.email.rfc822",
            Some("InnerPw1"),
        ),
        ("ace4/email/encrypted_wrong_password.email.rfc822", None),
    ] {
        let bytes = std::fs::read(ace_testkit::samples_dir().join(sample)).expect("the sample");
        let (root, _) = root_with_bytes(&core, "email", &bytes, "email.rfc822").await;
        wait_until_idle(&core, root, Duration::from_secs(60)).await;
        let details = msoffice_details(&core, root).await;
        assert_eq!(
            details["password"].as_str(),
            password,
            "{sample}: {details}"
        );
        assert_eq!(details["email"], json!(true), "{sample}: {details}");
    }
    let _ = pool.stop();
}

/// What docs/measurements/msoffice.md records: a full list of passwords on Office 2013's encryption, and
/// a spin count of 2^31-1, in a real task process with the module's real limits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, which takes the module's whole deadline"]
async fn measure_msoffice() {
    use base64::Engine;
    let core = email_and_office_core().await;
    let mut pool = supervisor(&core, &[]);
    let office =
        std::fs::read(ace_testkit::samples_dir().join("ace4/office/encrypted_no_email.docx"))
            .expect("the sample");
    // no whitespace, so every window is a password, up to the list's limit of 5,000
    let mut seed = 0x2545_F491_u32;
    let body: String = (0..1200)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            char::from(b'a' + (seed % 26) as u8)
        })
        .collect();
    let email = |office: &[u8]| {
        format!(
            "From: a@example.com\r\nTo: b@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n\
             {body}\r\n--b\r\nContent-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=a.docx\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n",
            base64::engine::general_purpose::STANDARD.encode(office)
        )
    };
    let from = b"    <p:encryptedKey spinCount=\"100000\"";
    let to = b"<p:encryptedKey spinCount=\"2147483647\"";
    let at = office
        .windows(from.len())
        .position(|window| window == from)
        .expect("the attribute");
    let mut huge = office.clone();
    huge[at..at + to.len()].copy_from_slice(to);
    for (name, file) in [("5,000 passwords", &office), ("spin count 2^31-1", &huge)] {
        let (root, _) =
            root_with_bytes(&core, "email", email(file).as_bytes(), "email.rfc822").await;
        let started = std::time::Instant::now();
        wait_until_idle(&core, root, Duration::from_secs(300)).await;
        let details = msoffice_details(&core, root).await;
        let words = details["word_list"].as_array().map_or(0, Vec::len);
        println!(
            "{name}: {:.1} s, {words} in the list, error {}",
            started.elapsed().as_secs_f64(),
            details["error"]
        );
    }
    assert!(pool.running());
    let _ = pool.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_yara_module_scans_in_a_contained_task_process() {
    let rules = tempfile::tempdir().expect("a rules directory");
    let namespace = rules.path().join("fixture");
    std::fs::create_dir(&namespace).expect("a namespace");
    std::fs::write(
        namespace.join("rules.yar"),
        r#"rule contained_evil { strings: $a = "EVIL" condition: $a }"#,
    )
    .expect("a rule");
    // the task processes' user reads the rules when it sets up
    for dir in [rules.path(), namespace.as_path()] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).expect("opens it");
    }
    let settings = json!({"yara_scanner_v3_4": {"signature_dir": rules.path()}}).to_string();

    let core = Core::start(
        vec![ace_mod_files::file_type::MANIFEST, ace_mod_yara::MANIFEST],
        &["file_type", "yara_scanner_v3_4"],
        Duration::from_secs(30),
    )
    .await;
    let (root, _) = root_with_bytes(&core, "yara", b"xxEVILxx", "payload.bin").await;
    let mut pool = supervisor(&core, &["--settings", &settings]);
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    let (file_type, file_type_error) = task_of(&core, root, "file_type").await;
    assert_eq!(file_type, "done", "{file_type_error:?}");
    // the YARA module waits for file_type, so its task comes once file_type's result lands
    let (state, error, _) =
        task_state(&core, root, "yara_scanner_v3_4", Duration::from_secs(60)).await;
    let stderr = pool.stop();
    assert_eq!(state, "done", "{error:?}\n{stderr}");
    assert!(stderr.contains("contained: Contained"), "{stderr}");
    let rule: String = sqlx::query_scalar(
        "SELECT details->'scan_results'->0->>'rule' FROM analysis.results WHERE root_id = $1",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the scan's result");
    assert_eq!(rule, "contained_evil");
}

/// `/proc/PID/stat`'s fields after the command, which can hold spaces and parentheses. Index 0 is
/// the state, 1 the parent, 11 and 12 the CPU ticks, 19 the start time.
fn proc_stat(pid: u32) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, fields) = stat.rsplit_once(')')?;
    Some(fields.split_whitespace().map(str::to_owned).collect())
}

/// One process, told apart by its start time from a later one that reuses its pid.
#[derive(Debug)]
struct TaskProcess {
    pid: u32,
    started: String,
}

impl TaskProcess {
    /// False once the process is gone and reaped. A zombie still counts: a supervisor that left
    /// one would collect them for as long as it runs.
    fn exists(&self) -> bool {
        proc_stat(self.pid).is_some_and(|stat| stat[19] == self.started)
    }

    fn cpu_ticks(&self) -> u64 {
        proc_stat(self.pid)
            .map(|stat| {
                let ticks = |at: usize| stat[at].parse::<u64>().expect("a tick count");
                ticks(11) + ticks(12)
            })
            .unwrap_or_default()
    }
}

/// The supervisor's child that has contained itself, so it's past exec and setup.
fn contained_child(supervisor: u32) -> Option<TaskProcess> {
    let parent = supervisor.to_string();
    std::fs::read_dir("/proc")
        .expect("/proc")
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .find_map(|pid| {
            let stat = proc_stat(pid)?;
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
            (stat[1] == parent && status.lines().any(|line| line == "Seccomp:\t2")).then(|| {
                TaskProcess {
                    pid,
                    started: stat[19].clone(),
                }
            })
        })
}

/// Waits for the pool's task process to be in `test_stuck`: contained, then a fifth of a second of
/// CPU, far more than the little between containment and the module's loop.
async fn stuck_task_process(pool: &PoolProcess) -> TaskProcess {
    let waiting = Instant::now();
    let limit = Duration::from_secs(30);
    let process = loop {
        if let Some(process) = contained_child(pool.pid()) {
            break process;
        }
        assert!(waiting.elapsed() < limit, "no contained task process");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let contained = process.cpu_ticks();
    while process.cpu_ticks() < contained + 20 {
        assert!(waiting.elapsed() < limit, "{process:?} isn't spinning");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    process
}

/// A cancelled root's running task process is killed within one renewal of the lease, which is
/// how a cancel reaches a supervisor, plus this margin for a loaded machine. The module can't
/// stop itself: it never returns and nothing in its process can see the cancel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_a_root_kills_its_running_task_process_and_the_task_ends_cancelled() {
    const RENEWAL: Duration = Duration::from_secs(1);
    const MARGIN: Duration = Duration::from_secs(5);
    let core = Core::start(
        testing::test_manifests(),
        &["test_stuck"],
        RENEWAL * 3, // the lease; a keeper renews it every third
    )
    .await;
    let root = root_with_tasks(&core, &["stuck.example.com".to_owned()], "test_stuck").await;
    let mut pool = supervisor(&core, &[]);
    let process = stuck_task_process(&pool).await;

    let mut tx = core.test_db.db().begin().await.expect("begins");
    let cancelled = ace_core::queue::cancel_root(&mut tx, root)
        .await
        .expect("cancels");
    tx.commit().await.expect("commits");
    let committed = Instant::now();
    assert_eq!(cancelled.signalled.len(), 1, "{cancelled:?}");

    while process.exists() {
        assert!(
            committed.elapsed() < RENEWAL + MARGIN,
            "{process:?} is still there after {:?}",
            committed.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    println!(
        "{process:?} was gone {:?} after the cancel",
        committed.elapsed()
    );

    let (state, error, _) = task_state(&core, root, "test_stuck", Duration::from_secs(10)).await;
    assert!(pool.running(), "the supervisor kept running");
    let stderr = pool.stop();
    assert_eq!((state.as_str(), error), ("cancelled", None), "{stderr}");
    assert!(stderr.contains("the task was cancelled"), "{stderr}");
    assert!(stderr.contains("test_stuck: stuck on"), "{stderr}");
}

/// SIGTERM with a task running: the process dies, the lease goes back at once rather than by
/// expiring, the next worker can take the task, and the supervisor exits inside its grace period,
/// so it never had to abandon anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_kills_a_running_task_process_and_gives_its_lease_back_in_time() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_stuck"],
        Duration::from_secs(30),
    )
    .await;
    let root = root_with_tasks(&core, &["stuck.example.com".to_owned()], "test_stuck").await;
    let mut pool = supervisor(&core, &[]);
    let process = stuck_task_process(&pool).await;

    let stopping = Instant::now();
    // past the grace, `terminate` kills it, and `took` shows that
    let stderr = pool.terminate(ace_pool::pool::SHUTDOWN_GRACE + Duration::from_secs(5));
    let took = stopping.elapsed();
    println!("shut down in {took:?}");
    assert!(took < ace_pool::pool::SHUTDOWN_GRACE, "{took:?}\n{stderr}");
    assert!(!process.exists(), "{process:?} outlived shutdown\n{stderr}");
    assert!(
        stderr.contains("shutting down; giving the task back"),
        "{stderr}"
    );
    assert!(!stderr.contains("abandoning"), "{stderr}");

    let db = core.test_db.db().pool();
    let (id, state, owner, attempts): (i64, String, Option<String>, i32) = sqlx::query_as(
        "SELECT id, state::text, lease_owner, attempts FROM queue.tasks WHERE root_id = $1",
    )
    .bind(root)
    .fetch_one(db)
    .await
    .expect("the task");
    assert_eq!(
        (state.as_str(), owner, attempts),
        ("queued", None, 0),
        "{stderr}"
    );

    let next = ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "the-next-worker")
        .expect("a client")
        .lease(&[], Duration::from_secs(5))
        .await
        .expect("leases")
        .expect("the task, given back");
    assert_eq!(next.id, id);
    let owner: Option<String> =
        sqlx::query_scalar("SELECT lease_owner FROM queue.tasks WHERE id = $1")
            .bind(id)
            .fetch_one(db)
            .await
            .expect("the task");
    assert_eq!(owner.as_deref(), Some("test/the-next-worker"));
}

/// A result whose uploads outlast the lease lands on its first attempt, because the lease stays
/// kept until the end lands. This was a bug here after 4.5 fixed it in the Python pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_result_whose_uploads_outlast_the_lease_lands_on_its_first_attempt() {
    // a 3-second lease, and files enough that uploading them and landing them take longer
    let core = Core::start(
        testing::test_manifests(),
        &["test_writes_files"],
        Duration::from_secs(3),
    )
    .await;
    let reaper_stop = tokio_util::sync::CancellationToken::new();
    let reaper = tokio::spawn(ace_core::queue::run_reaper(
        core.test_db.db().clone(),
        Duration::from_millis(200),
        reaper_stop.clone(),
    ));
    let root = root_with_tasks(&core, &["1500.example.com".to_owned()], "test_writes_files").await;
    let mut pool = supervisor(&core, &[]);
    let started = Instant::now();
    wait_until_idle(&core, root, Duration::from_secs(240)).await;
    let took = started.elapsed();
    pool.stop();
    reaper_stop.cancel();
    reaper.await.expect("the reaper stops");
    assert!(
        took > Duration::from_secs(3),
        "this took {took:?}, inside one lease"
    );

    let db = core.test_db.db().pool();
    let (state, attempts): (String, i32) = sqlx::query_as(
        "SELECT state::text, attempts FROM queue.tasks
         WHERE root_id = $1 AND module = 'test_writes_files'",
    )
    .bind(root)
    .fetch_one(db)
    .await
    .expect("the task");
    assert_eq!((state.as_str(), attempts), ("done", 1));
    let files: i64 = sqlx::query_scalar("SELECT count(*) FROM analysis.files WHERE root_id = $1")
        .bind(root)
        .fetch_one(db)
        .await
        .expect("the files");
    assert_eq!(files, 1500);
}

/// The URLs a root's url_extraction result holds, sorted.
async fn extracted_urls(core: &Core, root: uuid::Uuid) -> Vec<String> {
    let details: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT details FROM analysis.results WHERE root_id = $1 AND module = 'url_extraction'",
    )
    .bind(root)
    .fetch_optional(core.test_db.db().pool())
    .await
    .expect("a result");
    let mut urls: Vec<String> = details
        .and_then(|d| d["urls"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|u| u.as_str().map(str::to_owned))
        .collect();
    urls.sort();
    urls
}

/// url_extraction in a contained task: libxml2 on an HTML page, and the chat log of PLAN.md 7.5's
/// Done check, whose URLs are those ace3 finds when its cap is raised (the reference dump
/// `url_extraction/chat_log.txt.uncapped`), well inside the module's 15-second deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn url_extraction_runs_contained() {
    let core = Core::start(
        vec![
            ace_mod_files::file_type::MANIFEST,
            ace_mod_urls::url_extraction::MANIFEST,
        ],
        &["file_type", "url_extraction"],
        Duration::from_secs(120),
    )
    .await;
    let fixtures = format!(
        "{}/../../tools/ace3/dumps/fixtures/urls",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut pool = supervisor(&core, &[]);
    for (name, urls) in [("page.html", 10), ("chat_log.txt", 6)] {
        let bytes = std::fs::read(format!("{fixtures}/{name}")).expect("a fixture");
        let (root, _) = root_with_file(&core, "file", &bytes, name, &["extract_urls"]).await;
        let (state, error, seconds) = last_task_state(&core, root, "url_extraction").await;
        assert_eq!(state, "done", "{name}: {error:?}");
        assert_eq!(extracted_urls(&core, root).await.len(), urls, "{name}");
        assert!(seconds < 15.0, "{name} took {seconds:.1} s");
        println!("{name}: {seconds:.2} s");
    }
    assert!(pool.running());
    let _ = pool.stop();
}

/// What `docs/measurements/url-extraction.md` records: each file of the directory
/// `ACE4_URL_HOSTILE` names (`tools/samples/make-url-hostile`), `ACE4_URL_RUNS` times (3 by
/// default), as a contained task of `ACE4_URL_MODULE` (url_extraction, or ioc_extraction) with the
/// module's limits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, with files tools/samples/make-url-hostile makes"]
async fn measure_url_extraction() {
    let dir = std::env::var("ACE4_URL_HOSTILE").expect("ACE4_URL_HOSTILE");
    let runs: usize = std::env::var("ACE4_URL_RUNS")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(3);
    let module = std::env::var("ACE4_URL_MODULE").unwrap_or_else(|_| "url_extraction".to_owned());
    let (manifest, directive) = match module.as_str() {
        "ioc_extraction" => (ace_mod_urls::ioc_extraction::MANIFEST, "extract_iocs"),
        _ => (ace_mod_urls::url_extraction::MANIFEST, "extract_urls"),
    };
    let core = Core::start(
        vec![ace_mod_files::file_type::MANIFEST, manifest],
        &["file_type", module.as_str()],
        Duration::from_secs(300),
    )
    .await;
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .expect("the directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a name")
        })
        .collect();
    names.sort();
    let mut pool = supervisor(&core, &[]);
    for name in names {
        let bytes = std::fs::read(format!("{dir}/{name}")).expect("the file");
        for run in 0..runs {
            // a byte that differs makes each run a new file, so nothing is reused
            let mut bytes = bytes.clone();
            bytes.extend_from_slice(format!("\n{run}\n").as_bytes());
            let (root, _) = root_with_file(&core, "file", &bytes, &name, &[directive]).await;
            let (state, error, seconds) = last_task_state(&core, root, &module).await;
            let error: String = error.unwrap_or_default().chars().take(120).collect();
            let urls = extracted_urls(&core, root).await;
            println!(
                "{name}\t{}\t{run}\t{state}\t{seconds:.2}\t{}\t{error}",
                bytes.len(),
                urls.len()
            );
            assert!(pool.running(), "the supervisor kept running after {name}");
        }
    }
    let _ = pool.stop();
}

/// What `docs/measurements/file-identity.md` records: each file of the directory
/// `ACE4_FILES_HOSTILE` names (`tools/samples/make-identity-hostile`) whose name starts with
/// `ACE4_FILES_MODULE` (file_type, x509_analyzer or lnk_parser), `ACE4_FILES_RUNS` times (3 by
/// default), as a contained task of that module with its limits, file_type first for the module
/// that depends on it. A run's root holds the file under a name with the run's number, so no run
/// reuses another's result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, with files tools/samples/make-identity-hostile makes"]
async fn measure_file_identity() {
    let dir = std::env::var("ACE4_FILES_HOSTILE").expect("ACE4_FILES_HOSTILE");
    let runs: usize = std::env::var("ACE4_FILES_RUNS")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(3);
    let module = std::env::var("ACE4_FILES_MODULE").unwrap_or_else(|_| "file_type".to_owned());
    let mut manifests = vec![ace_mod_files::file_type::MANIFEST];
    match module.as_str() {
        "x509_analyzer" => manifests.push(ace_mod_files::x509::MANIFEST),
        "lnk_parser" => manifests.push(ace_mod_files::lnk::MANIFEST),
        "dhash" => manifests.push(ace_mod_files::dhash::MANIFEST),
        _ => {}
    }
    let directives: &[&str] = if module == "dhash" { &["dhash"] } else { &[] };
    let settings = serde_json::json!({"dhash": {"source_dir": format!(
        "{}/../../tools/ace3/dumps/fixtures/dhash/analyst_data/dhash",
        env!("CARGO_MANIFEST_DIR")
    )}})
    .to_string();
    let names: Vec<&str> = manifests.iter().map(|m| m.name).collect();
    let core = Core::start(manifests.clone(), &names, Duration::from_secs(600)).await;
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("the directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a name")
        })
        .filter(|name| name.starts_with(module.as_str()))
        .collect();
    files.sort();
    let mut pool = supervisor(&core, &["--settings", &settings]);
    for name in files {
        let bytes = std::fs::read(format!("{dir}/{name}")).expect("the file");
        for run in 0..runs {
            let (root, _) =
                root_with_file(&core, "file", &bytes, &format!("{run}_{name}"), directives).await;
            let (state, error, seconds) = last_task_state(&core, root, &module).await;
            let error: String = error.unwrap_or_default().chars().take(120).collect();
            println!(
                "{name}\t{}\t{run}\t{state}\t{seconds:.2}\t{error}",
                bytes.len()
            );
            assert!(pool.running(), "the supervisor kept running after {name}");
        }
    }
    let _ = pool.stop();
}

/// PLAN.md 7.5 batch 3: what crafted observable values cost the modules that read them
/// (docs/measurements/observable-values.md). Each value of the module `ACE4_VALUES_MODULE` names
/// runs in a new root as a contained task of that module with its limits, 3 runs
/// (`ACE4_VALUES_RUNS`), and the time is from the task's queueing to its end, its result landed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement"]
async fn measure_observable_values() {
    let runs: usize = std::env::var("ACE4_VALUES_RUNS")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(3);
    let mb = 1024 * 1024;
    let b64 = "QUJD".repeat(mb / 4);
    let cases: Vec<(&str, &str, ObservableKind, String)> = vec![
        (
            "paths_1mb",
            "command_line_analyzer",
            ObservableKind::CommandLine,
            r"C:\a\b ".repeat(mb / 7),
        ),
        (
            "prefixes_1mb",
            "command_line_analyzer",
            ObservableKind::CommandLine,
            (0..mb / 16)
                .map(|i| format!(r"C:\{i:x} "))
                .collect::<String>(),
        ),
        (
            "quoted_paths_1mb",
            "command_line_analyzer",
            ObservableKind::CommandLine,
            r#""C:\a" \"C:\b\" "\\s\t" "#.repeat(mb / 22),
        ),
        (
            "unc_open_1mb",
            "command_line_analyzer",
            ObservableKind::CommandLine,
            format!(r#""\\{}"#, "a\"".repeat(mb / 2)),
        ),
        (
            "base64_1mb",
            "command_line_analyzer",
            ObservableKind::CommandLine,
            format!("powershell -enc {b64}"),
        ),
        (
            "base64_words_1mb",
            "command_line_analyzer",
            ObservableKind::CommandLine,
            "pwsh -e QUJD ".repeat(mb / 13),
        ),
        (
            "separators_1mb",
            "file_path_analysis",
            ObservableKind::FilePath,
            format!(r"C:\Users\{}", "\\".repeat(mb)),
        ),
        (
            "url_1mb",
            "parse_url",
            ObservableKind::Url,
            format!("https://example.com/?{}", "a=1&".repeat(mb / 4)),
        ),
        (
            "host_first_1mb",
            "parse_url",
            ObservableKind::Url,
            format!("{}.com/x", "a".repeat(mb)),
        ),
        (
            "label_100k",
            "idna_analyzer",
            ObservableKind::Fqdn,
            format!("{}.com", "\u{e9}".repeat(100_000)),
        ),
        (
            "labels_1mb",
            "idna_analyzer",
            ObservableKind::Fqdn,
            "\u{e9}a.".repeat(mb / 4) + "com",
        ),
        (
            "proofpoint_1mb",
            "protected_url_analyzer",
            ObservableKind::Url,
            format!(
                "https://urldefense.proofpoint.com/v2/url?u={}",
                "https-3A__evil.example.com_".repeat(mb / 28)
            ),
        ),
        (
            "dropbox_1mb",
            "protected_url_analyzer",
            ObservableKind::Url,
            format!("https://www.dropbox.com/s/a?{}", "x=1&".repeat(mb / 4)),
        ),
        (
            "urldefense_1mb",
            "protected_url_analyzer",
            ObservableKind::Url,
            format!("https://urldefense.com/v3/__{}", "_a".repeat(mb / 2)),
        ),
        (
            "networks_2000",
            "network_identifier",
            ObservableKind::Ip,
            "10.200.3.4".to_owned(),
        ),
    ];
    let networks: Vec<serde_json::Value> = (0..2_000)
        .map(|i| serde_json::json!({"cidr": format!("10.{}.{}.0/24", i / 256, i % 256), "name": format!("n{i}")}))
        .collect();
    let settings = serde_json::json!({"network_identifier": {"networks": networks}}).to_string();
    // one module a run, alone in the catalog, so what it adds queues nothing else
    let module = std::env::var("ACE4_VALUES_MODULE").expect("ACE4_VALUES_MODULE");
    let manifest = [
        ace_mod_values::command_line::MANIFEST,
        ace_mod_values::file_path::FILE_PATH_MANIFEST,
        ace_mod_values::urls::PARSE_URL_MANIFEST,
        ace_mod_values::urls::IDNA_MANIFEST,
        ace_mod_values::protected::MANIFEST,
        ace_mod_values::network::MANIFEST,
    ]
    .into_iter()
    .find(|m| m.name == module)
    .expect("a module of the batch");
    let core = Core::start(vec![manifest], &[manifest.name], Duration::from_secs(600)).await;
    let mut pool = supervisor(&core, &["--settings", &settings]);
    for (name, _, kind, value) in cases.iter().filter(|c| c.1 == module) {
        let module = module.as_str();
        for run in 0..runs {
            // a value of its own each run, so no run finds another's result
            let value = if *kind == ObservableKind::Ip {
                value.clone()
            } else {
                format!("{value}{}", " ".repeat(run))
            };
            let db = core.test_db.db();
            let root = NewRoot::new("analysis");
            let mut tx = db.begin().await.expect("begins");
            tree::create_root(&mut tx, &root).await.expect("creates");
            let id = tree::upsert_observable(
                &mut tx,
                root.id,
                &NewObservable::new(*kind, value.clone()),
            )
            .await
            .expect("adds")
            .id;
            ace_core::queue::enqueue(&mut tx, root.id, id, module)
                .await
                .expect("queues");
            tx.commit().await.expect("commits");
            // past the module's 300 s deadline, so a task that hits it is seen to end
            let (state, error, seconds) =
                task_state(&core, root.id, module, Duration::from_secs(420)).await;
            let error: String = error.unwrap_or_default().chars().take(120).collect();
            println!(
                "{name}\t{module}\t{}\t{run}\t{state}\t{seconds:.2}\t{error}",
                value.len()
            );
            assert!(pool.running(), "the supervisor kept running after {name}");
        }
    }
    let _ = pool.stop();
}
