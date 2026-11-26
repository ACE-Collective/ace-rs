//! A parser's task process's log events, which reach the pool's log through its supervisor.
//!
//! A task process can't reach the collector and has no log of its own: what it writes on stderr is
//! all its supervisor sees of it. So it writes each event as one line of JSON there
//! (`TaskLogLayer`, installed by `crate::telemetry::init_task_process`), and the supervisor logs
//! each such line again at the event's level, with the task's id, the event's target and its
//! fields kept as fields (`StderrLines`). A WARN a module logs in a task process is a WARN in the
//! pool's log, and searchable by its fields.
//!
//! The rest of stderr is what it was: the `contained:` line, a setup failure, a panic's message, a
//! line a module or a library prints. The supervisor logs each at INFO as before and builds a failed
//! task's reason from its end, which log lines don't reach.
//!
//! What a task process writes is bounded on the supervisor's side, since the process may be a
//! hostile file's: a line is cut at `MAX_LINE` bytes, the pool logs at most `LOG_BUDGET` bytes of one
//! task's stderr and says how many lines it left out, and only the last `TAIL_BYTES` of the lines
//! that aren't log events are kept for the task's reason. The events carry no time: the supervisor
//! reads them as they are written and its own record has the time.

use std::collections::VecDeque;
use std::io::Write;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;

/// The target the supervisor logs a task process's events under. The event's own target is its
/// `task_target` field.
pub const TARGET: &str = "ace_pool::task_log";

/// The longest line of a task process's stderr the supervisor reads whole; the rest of a longer
/// line is dropped.
pub const MAX_LINE: usize = 16 * 1024;

/// The most of one task process's stderr the supervisor logs. Lines past it are counted, not
/// logged, so a task that logs in a loop costs the pool's log a bounded amount.
pub const LOG_BUDGET: usize = 1024 * 1024;

/// How much of the end of a task process's stderr, less its log events, the supervisor keeps for
/// the task's reason when it fails.
pub const TAIL_BYTES: usize = 64 * 1024;

/// How every log event's line starts, which is how the supervisor tells one from the rest of
/// stderr: `serde_json` writes the one key of `Line` first and with no space.
const PREFIX: &str = "{\"task_log\":";

/// One event of a task process, as its line on stderr holds it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLog {
    /// tracing's name for the level, such as `WARN`.
    pub level: String,
    /// The event's target, usually the module path of the code that logged it.
    pub target: String,
    pub message: String,
    /// The event's other fields: numbers and booleans as JSON's, anything else as its text.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub fields: Map<String, Value>,
}

/// A line of stderr that holds a log event.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    task_log: TaskLog,
}

impl TaskLog {
    /// The event a line of stderr holds, None for a line that isn't a log event, or why a line
    /// that starts as one doesn't read.
    pub fn parse(line: &str) -> Option<Result<TaskLog, String>> {
        if !line.starts_with(PREFIX) {
            return None;
        }
        Some(
            serde_json::from_str::<Line>(line)
                .map(|line| line.task_log)
                .map_err(|e| e.to_string()),
        )
    }

    /// The event as its line, newline included.
    pub fn to_line(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = serde_json::to_vec(&Line {
            task_log: self.clone(),
        })?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// The layer that writes each event as its line to `writer`: stderr in a task process.
pub struct TaskLogLayer<W> {
    writer: W,
}

impl<W> TaskLogLayer<W> {
    pub fn new(writer: W) -> Self {
        TaskLogLayer { writer }
    }
}

impl<S, W> Layer<S> for TaskLogLayer<W>
where
    S: Subscriber,
    W: for<'w> MakeWriter<'w> + 'static,
{
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let metadata = event.metadata();
        let log = TaskLog {
            level: metadata.level().to_string(),
            target: metadata.target().to_owned(),
            message: fields.message,
            fields: fields.fields,
        };
        let line = match log.to_line() {
            Ok(line) => line,
            // the fields are JSON values already, so this isn't expected; the line says which
            // event, and reaches the pool's log as a line that isn't one
            Err(e) => format!("a log event didn't serialize ({e}): {}\n", log.message).into_bytes(),
        };
        // one write a line, so lines don't interleave; a failed write to stderr has nowhere to
        // be reported
        self.writer.make_writer().write_all(&line).ok();
    }
}

/// An event's message and fields.
#[derive(Default)]
struct Fields {
    message: String,
    fields: Map<String, Value>,
}

impl Fields {
    fn put(&mut self, field: &Field, value: Value) {
        if field.name() == "message" {
            self.message = match value {
                Value::String(text) => text,
                other => other.to_string(),
            };
        } else {
            self.fields.insert(field.name().to_owned(), value);
        }
    }
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, Value::String(format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, Value::String(value.to_owned()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, value.into());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        // JSON has no NaN or infinity
        let value = serde_json::Number::from_f64(value)
            .map_or_else(|| Value::String(value.to_string()), Value::Number);
        self.put(field, value);
    }

    /// An error with its chain of sources, as `{e:#}` writes an anyhow error.
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        let mut text = value.to_string();
        let mut source = value.source();
        while let Some(cause) = source {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            source = cause.source();
        }
        self.put(field, Value::String(text));
    }
}

/// Logs `log`, an event of task `task`'s process, at its own level, or says why it can't.
pub fn relay(task: i64, log: &TaskLog) -> Result<(), String> {
    let fields = Value::Object(log.fields.clone());
    let (target, message) = (log.target.as_str(), log.message.as_str());
    // a level is part of a callsite, so each has its own; the names are `Level`'s
    match log.level.as_str() {
        "ERROR" => {
            tracing::error!(target: TARGET, task, task_target = target, fields = %fields, "{message}")
        }
        "WARN" => {
            tracing::warn!(target: TARGET, task, task_target = target, fields = %fields, "{message}")
        }
        "INFO" => {
            tracing::info!(target: TARGET, task, task_target = target, fields = %fields, "{message}")
        }
        "DEBUG" => {
            tracing::debug!(target: TARGET, task, task_target = target, fields = %fields, "{message}")
        }
        "TRACE" => {
            tracing::trace!(target: TARGET, task, task_target = target, fields = %fields, "{message}")
        }
        other => return Err(format!("no level {other:?}")),
    }
    Ok(())
}

/// The supervisor's reader of one task process's stderr: it splits what the process writes into
/// lines as it comes, relays each log event, logs each other line at INFO as `task process: ...`,
/// and keeps the end of the other lines for the task's reason.
pub struct StderrLines {
    task: i64,
    /// The line being read, at most `MAX_LINE` bytes of it.
    pending: Vec<u8>,
    /// Whether the line being read ran past `MAX_LINE`.
    cut: bool,
    /// How much of stderr has been logged.
    logged: usize,
    /// The lines left out of the log once `LOG_BUDGET` was spent, and the lines cut.
    unlogged: usize,
    cut_lines: usize,
    /// The last lines that aren't log events, at most `TAIL_BYTES` of them.
    tail: VecDeque<String>,
    tail_bytes: usize,
}

impl StderrLines {
    pub fn new(task: i64) -> Self {
        StderrLines {
            task,
            pending: Vec::new(),
            cut: false,
            logged: 0,
            unlogged: 0,
            cut_lines: 0,
            tail: VecDeque::new(),
            tail_bytes: 0,
        }
    }

    /// Reads the next bytes the process wrote.
    pub fn push(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let (part, ended) = match bytes.iter().position(|&b| b == b'\n') {
                Some(at) => (&bytes[..at], true),
                None => (bytes, false),
            };
            let room = MAX_LINE.saturating_sub(self.pending.len());
            if part.len() > room {
                self.cut = true;
            }
            self.pending
                .extend_from_slice(&part[..part.len().min(room)]);
            bytes = &bytes[part.len()..];
            if ended {
                bytes = &bytes[1..];
                self.end_line();
            }
        }
    }

    /// Reads the last line, which may have had no newline, logs how many lines were left out, and
    /// returns the end of stderr less its log events, for `crate::supervisor::end_of`.
    pub fn finish(mut self) -> String {
        if !self.pending.is_empty() || self.cut {
            self.end_line();
        }
        if self.unlogged > 0 || self.cut_lines > 0 {
            tracing::warn!(
                task = self.task,
                unlogged_lines = self.unlogged,
                cut_lines = self.cut_lines,
                log_budget = LOG_BUDGET,
                max_line = MAX_LINE,
                "the task process wrote more on stderr than the pool logs of a task"
            );
        }
        Vec::from(self.tail).join("\n")
    }

    fn end_line(&mut self) {
        let bytes = std::mem::take(&mut self.pending);
        if std::mem::take(&mut self.cut) {
            self.cut_lines += 1;
        }
        let line = String::from_utf8_lossy(&bytes);
        let event = TaskLog::parse(&line);
        if event.is_none() {
            self.keep(&line);
        }
        if self.logged + line.len() > LOG_BUDGET {
            self.unlogged += 1;
            return;
        }
        self.logged += line.len();
        let task = self.task;
        match event {
            None => tracing::info!(task, "task process: {line}"),
            Some(Ok(log)) => {
                if let Err(why) = relay(task, &log) {
                    tracing::warn!(
                        task,
                        "a log line of the task process doesn't read ({why}): {line}"
                    );
                }
            }
            Some(Err(why)) => {
                tracing::warn!(
                    task,
                    "a log line of the task process doesn't read ({why}): {line}"
                )
            }
        }
    }

    fn keep(&mut self, line: &str) {
        self.tail_bytes += line.len();
        self.tail.push_back(line.to_owned());
        while self.tail_bytes > TAIL_BYTES
            && let Some(first) = self.tail.pop_front()
        {
            self.tail_bytes -= first.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::Level;
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("the buffer").extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Buffer {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("the buffer").clone()).expect("UTF-8")
        }
    }

    /// What `f` logs through the pool's text format, at every level.
    fn logged(f: impl FnOnce()) -> String {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(Level::TRACE)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        buffer.text()
    }

    #[derive(Debug, thiserror::Error)]
    #[error("the copy doesn't load")]
    struct Outer(#[source] std::io::Error);

    /// A task process writes each event as one line of JSON, with its level, target and message, and
    /// its fields as JSON values: numbers as numbers, an error with its sources.
    #[test]
    fn a_task_process_writes_each_event_as_a_line_of_json() {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber =
            tracing_subscriber::registry().with(TaskLogLayer::new(move || writer.clone()));
        tracing::subscriber::with_default(subscriber, || {
            let error = Outer(std::io::Error::other("no space left"));
            tracing::warn!(
                path = "/rulesets/aa",
                count = 3,
                ratio = 0.5,
                cut = true,
                error = &error as &dyn std::error::Error,
                "the copy of {} doesn't load",
                "aa"
            );
            tracing::info!("a second line");
        });
        let text = buffer.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        let log = TaskLog::parse(lines[0])
            .expect("a log line")
            .expect("reads");
        assert_eq!(log.level, "WARN");
        assert_eq!(log.target, module_path!());
        assert_eq!(log.message, "the copy of aa doesn't load");
        assert_eq!(
            Value::Object(log.fields),
            serde_json::json!({
                "path": "/rulesets/aa",
                "count": 3,
                "ratio": 0.5,
                "cut": true,
                "error": "the copy doesn't load: no space left",
            })
        );
        let second = TaskLog::parse(lines[1])
            .expect("a log line")
            .expect("reads");
        assert_eq!((second.level.as_str(), second.fields.len()), ("INFO", 0));
    }

    fn warning() -> TaskLog {
        TaskLog {
            level: "WARN".to_owned(),
            target: "ace_mod_yara".to_owned(),
            message: "the pool's native copy doesn't load".to_owned(),
            // in the order of their names, which is the order they're written whether or not
            // serde_json keeps insertion order
            fields: serde_json::json!({"count": 3, "key": "aa"})
                .as_object()
                .cloned()
                .expect("an object"),
        }
    }

    fn line_of(log: &TaskLog) -> Vec<u8> {
        log.to_line().expect("serializes")
    }

    /// The supervisor logs a task's event at its own level, under the relay's target, with the task's
    /// id, the event's target and its fields as JSON, and its message as the message.
    #[test]
    fn the_supervisor_logs_a_task_s_event_at_its_level_with_its_fields() {
        let log = logged(|| {
            let mut lines = StderrLines::new(41);
            lines.push(&line_of(&warning()));
            assert_eq!(lines.finish(), "", "an event isn't kept for the reason");
        });
        let record = log.lines().next().expect("a record");
        for wanted in [
            "WARN",
            TARGET,
            "the pool's native copy doesn't load",
            "task=41",
            "task_target=\"ace_mod_yara\"",
            r#"fields={"count":3,"key":"aa"}"#,
        ] {
            assert!(record.contains(wanted), "{wanted} in {log}");
        }
        assert_eq!(log.lines().count(), 1, "{log}");
        for level in ["ERROR", "INFO", "DEBUG", "TRACE"] {
            let event = TaskLog {
                level: level.to_owned(),
                ..warning()
            };
            let log = logged(|| assert_eq!(relay(7, &event), Ok(())));
            assert!(log.contains(level), "{level}: {log}");
        }
    }

    /// A line that isn't a log event is logged and kept as before: `task process: ...` at INFO, and in
    /// the tail the task's reason is made from. A line that starts as an event but doesn't read is
    /// logged as such at WARN, and kept out of the tail.
    #[test]
    fn other_lines_are_logged_and_kept_as_they_were() {
        let mut stderr = Vec::new();
        stderr.extend_from_slice(b"contained: Contained { landlock: true }\n");
        stderr.extend_from_slice(&line_of(&warning()));
        stderr.extend_from_slice(b"{\"task_log\":{\"level\":\"LOUD\"}}\n");
        stderr.extend_from_slice(b"{\"not\":\"a log event\"}\n");
        stderr.extend_from_slice(b"setup failed: the output directory");
        let mut tail = String::new();
        let log = logged(|| {
            let mut lines = StderrLines::new(41);
            // in pieces, as a pipe hands them over
            for piece in stderr.chunks(7) {
                lines.push(piece);
            }
            tail = lines.finish();
        });
        assert_eq!(
            tail,
            "contained: Contained { landlock: true }\n{\"not\":\"a log event\"}\nsetup failed: the output directory"
        );
        let records: Vec<&str> = log.lines().collect();
        assert_eq!(records.len(), 5, "{log}");
        assert!(
            records[0].contains("INFO")
                && records[0].contains("task=41")
                && records[0].contains("task process: contained: Contained { landlock: true }"),
            "{log}"
        );
        assert!(
            records[1].contains("WARN") && records[1].contains(TARGET),
            "{log}"
        );
        assert!(
            records[2].contains("WARN") && records[2].contains("doesn't read"),
            "{log}"
        );
        assert!(records[3].contains("task process: {\"not\""), "{log}");
        assert!(
            records[4].contains("task process: setup failed: the output directory"),
            "{log}"
        );
    }

    /// A task process that writes without end costs the pool's log `LOG_BUDGET` and a line of
    /// `MAX_LINE`: the rest is counted in one WARN, and the end of stderr is still kept for the reason.
    #[test]
    fn what_a_task_process_writes_is_bounded() {
        let mut tail = String::new();
        let log = logged(|| {
            let mut lines = StderrLines::new(41);
            let long = vec![b'x'; MAX_LINE * 3];
            lines.push(&long);
            lines.push(b"\n");
            let event = line_of(&warning());
            for _ in 0..(2 * LOG_BUDGET / event.len()) {
                lines.push(&event);
            }
            lines.push(b"thread 'main' panicked at src/lib.rs:1:1:\nthe last words\n");
            tail = lines.finish();
        });
        assert!(log.len() < LOG_BUDGET * 2, "{} bytes logged", log.len());
        let first = log.lines().next().expect("a record");
        assert!(first.len() < MAX_LINE + 200, "{} bytes", first.len());
        let last = log.lines().last().expect("a record");
        assert!(
            last.contains("WARN") && last.contains("more on stderr than the pool logs"),
            "{last}"
        );
        assert!(last.contains("cut_lines=1"), "{last}");
        assert!(!last.contains("unlogged_lines=0"), "{last}");
        // the cut line and the panic: the events aren't kept
        assert!(
            tail.ends_with("panicked at src/lib.rs:1:1:\nthe last words"),
            "{tail:.200}"
        );
        assert_eq!(tail.lines().count(), 3);
        assert!(tail.len() <= TAIL_BYTES);
    }
}
