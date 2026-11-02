//! PLAN.md 1.22: a log line from inside a module carries the root's uuid, the observable and the
//! module, because the SDK runs each module call inside a span that holds all three.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use ace_results::{AlertPath, ObservableKind};
use ace_sdk::example::{LineCounter, LineCounterSettings, Resolver, ResolverSettings};
use ace_sdk::{
    InputFile, LocalFileStore, Observable, Secret, Secrets, TaskContext, run_lookup, run_parser,
};
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

/// Collects formatted log output.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn lines(&self) -> Vec<String> {
        let bytes = self.0.lock().expect("not poisoned").clone();
        String::from_utf8(bytes)
            .expect("logs are UTF-8")
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("not poisoned").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Captured;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn subscriber(captured: &Captured) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish()
}

/// The one captured line that holds `message`.
fn line_with(captured: &Captured, message: &str) -> String {
    let lines = captured.lines();
    for line in &lines {
        println!("{line}");
    }
    let matching: Vec<&String> = lines.iter().filter(|l| l.contains(message)).collect();
    assert_eq!(
        matching.len(),
        1,
        "expected one {message:?} line in {lines:?}"
    );
    matching[0].clone()
}

#[test]
fn a_parser_log_line_carries_root_observable_and_module() {
    let dir = tempfile::tempdir().expect("temp dir");
    let local = dir.path().join("input");
    std::fs::write(&local, b"one\ntwo\n").expect("write input");
    let file = InputFile {
        path: AlertPath::new("evil.zip.extracted/notes.txt").expect("valid path"),
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("valid sha256"),
        size: 8,
        yara_meta: vec![],
        mime_type: None,
        local_path: local,
    };
    let root = Uuid::new_v4();
    let ctx = TaskContext::new::<LineCounter>(
        root,
        Observable::file(file),
        Arc::new(LineCounterSettings::default()),
    )
    .with_file_store(Arc::new(
        LocalFileStore::new(dir.path().join("store")).expect("store"),
    ));

    let captured = Captured::default();
    tracing::subscriber::with_default(subscriber(&captured), || {
        run_parser(&LineCounter, &ctx).expect("the parser runs");
    });

    let line = line_with(&captured, "counted lines");
    assert!(line.contains(&format!("root={root}")), "{line}");
    assert!(
        line.contains("observable=file:evil.zip.extracted/notes.txt"),
        "{line}"
    );
    assert!(line.contains("module=example_line_counter"), "{line}");
}

#[tokio::test]
async fn a_lookup_log_line_carries_root_observable_and_module() {
    let settings = ResolverSettings {
        hosts: BTreeMap::from([("example.com".to_owned(), vec![Ipv4Addr::new(192, 0, 2, 1)])]),
        ..ResolverSettings::default()
    };
    let root = Uuid::new_v4();
    let ctx = TaskContext::new::<Resolver>(
        root,
        Observable::new(ObservableKind::Fqdn, "example.com"),
        Arc::new(settings),
    )
    .with_secrets(&Secrets::new().with("resolver_token", Secret::new("t")));

    let captured = Captured::default();
    let _default = tracing::subscriber::set_default(subscriber(&captured));
    run_lookup(&Resolver, &ctx).await.expect("the lookup runs");

    let line = line_with(&captured, "resolved");
    assert!(line.contains(&format!("root={root}")), "{line}");
    assert!(line.contains("observable=fqdn:example.com"), "{line}");
    assert!(line.contains("module=example_resolver"), "{line}");
}
