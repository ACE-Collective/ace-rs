//! Helpers shared by the integration tests.

#![allow(dead_code)]

use std::cell::RefCell;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Once;

pub fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

thread_local! {
    static LOGS: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Collects what `tracing` logs on this thread while `f` runs, formatted as the fmt
/// subscriber writes it.
///
/// One global subscriber writes each thread's events to that thread's own buffer. A
/// subscriber set per test with `with_default` misses events when tests run in parallel,
/// because a callsite first hit on a thread with no subscriber can cache "never log".
pub fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| ThreadBuffer)
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("no other global subscriber");
    });

    LOGS.with(|logs| logs.borrow_mut().clear());
    let value = f();
    let logs = LOGS.with(|logs| String::from_utf8(logs.take()).expect("logs are UTF-8"));
    (value, logs)
}

struct ThreadBuffer;

impl Write for ThreadBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOGS.with(|logs| logs.borrow_mut().extend_from_slice(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
