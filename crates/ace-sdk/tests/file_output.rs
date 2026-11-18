//! PLAN.md 1.21: a module's output file is stored by sha256 with its name, path and tags, and a
//! path from inside a hostile file can't escape the alert.

use std::io::Read;
use std::sync::Arc;

use ace_results::{FileRole, ObservableKind, YaraMeta};
use ace_sdk::example::{LineCounter, LineCounterSettings};
use ace_sdk::{FileOutputError, FileStore, LocalFileStore, Observable, TaskContext};
use uuid::Uuid;

fn context(store: &Arc<LocalFileStore>) -> TaskContext<LineCounterSettings> {
    TaskContext::new::<LineCounter>(
        Uuid::new_v4(),
        Observable::new(ObservableKind::Fqdn, "unused.example"),
        Arc::new(LineCounterSettings::default()),
    )
    .with_file_store(store.clone())
}

fn stored_files(store: &LocalFileStore) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(store.dir())
        .expect("the store reads")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn an_escaping_path_fails_and_stores_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Arc::new(LocalFileStore::new(dir.path().join("store")).expect("store"));
    let ctx = context(&store);

    for path in [
        "../../etc/passwd",
        "/etc/passwd",
        "evil.zip.extracted/../../../etc/passwd",
        "evil.zip.extracted/..\\..\\x",
        "",
    ] {
        let err = ctx
            .write_file(path, b"root:x:0:0::/root:/bin/sh\n", None)
            .expect_err("an escaping path must fail");
        println!("{path:?}: {err}");
        assert!(matches!(err, FileOutputError::InvalidPath(_)), "{err}");
    }
    assert!(stored_files(&store).is_empty(), "nothing was stored");
}

#[test]
fn a_normal_file_records_its_name_path_tags_and_sha256() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Arc::new(LocalFileStore::new(dir.path().join("store")).expect("store"));
    let ctx = context(&store);
    let file = ctx
        .write_file(
            "evil.zip.extracted/docs/invoice.doc",
            b"hello",
            FileRole::EMAIL_ATTACHMENT,
        )
        .expect("a normal path writes");
    println!(
        "{}",
        serde_json::to_string_pretty(&file).expect("serializes")
    );

    assert_eq!(file.name(), "invoice.doc");
    assert_eq!(file.path.as_str(), "evil.zip.extracted/docs/invoice.doc");
    assert_eq!(
        file.yara_meta
            .iter()
            .map(YaraMeta::as_str)
            .collect::<Vec<_>>(),
        ["type=email.attachment"]
    );
    assert_eq!(file.role, Some(FileRole::EMAIL_ATTACHMENT));
    // sha256("hello")
    let hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    assert_eq!(file.sha256.to_hex(), hello);
    assert_eq!(file.size, 5);

    // the bytes are in the store under their sha256, once
    assert_eq!(stored_files(&store), [hello]);
    let mut stored = Vec::new();
    store
        .open(&file.sha256)
        .expect("the bytes open")
        .read_to_end(&mut stored)
        .expect("the bytes read");
    assert_eq!(stored, b"hello");

    // the same bytes under another path share one stored copy
    let again = ctx.write_file("copy.txt", b"hello", None).expect("writes");
    assert_eq!(again.sha256, file.sha256);
    assert_eq!(stored_files(&store), [hello]);
}

#[test]
fn a_reader_streams_into_the_store() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Arc::new(LocalFileStore::new(dir.path()).expect("store"));
    let ctx = context(&store);
    // larger than the store's copy buffer
    let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let file = ctx
        .write_file_from("big.bin", &mut bytes.as_slice(), None)
        .expect("writes");
    assert_eq!(file.size, bytes.len() as u64);
    let mut stored = Vec::new();
    store
        .open(&file.sha256)
        .expect("opens")
        .read_to_end(&mut stored)
        .expect("reads");
    assert_eq!(stored, bytes);
}

#[test]
fn a_task_without_a_store_cannot_write() {
    let ctx = TaskContext::new::<LineCounter>(
        Uuid::new_v4(),
        Observable::new(ObservableKind::Fqdn, "unused.example"),
        Arc::new(LineCounterSettings::default()),
    );
    assert!(matches!(
        ctx.write_file("a.txt", b"x", None),
        Err(FileOutputError::NoStore)
    ));
}
