//! The test pool's modules (feature `test-pools`): ported modules, and test modules that count,
//! panic or try connections, for tests that run modules through a pool.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::{Lookup, Module, ModuleError, Outcome, Secrets, TaskContext};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::modules::{Entry, Modules, SetupError};

/// The modules `test-pool` runs, each with its block from `settings`, an object keyed by
/// module name. The YARA module is there only when `settings` has a block for it, since it
/// needs a signature directory.
pub fn modules(settings: &Value) -> Result<Modules, SetupError> {
    let secrets = Secrets::new();
    let block = |name: &str| settings.get(name);
    let mut modules = Modules::new();
    if let Some(yara) = block(ace_mod_yara::YaraScanner::NAME) {
        modules = modules.with_parser(Entry::<ace_mod_yara::YaraScanner>::parser(
            Some(yara),
            &secrets,
        )?);
    }
    Ok(modules
        .with_parser(Entry::<ace_mod_pdf::PdfAnalyzer>::parser(
            block("pdf_analyzer"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_oletools::Olevba>::parser(
            block("olevba_v1_2"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_oletools::RtfOle>::parser(
            block("rtfole"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_xlm::XlmDeobfuscator>::parser(
            block("xlmdeobfuscator"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_xlm::PCode>::parser(
            block("pcodedmp"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_msoffice::MsofficeEncryption>::parser(
            block("msoffice_encryption_analyzer"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_archive::ArchiveAnalyzer>::parser(
            block("archive"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_email::EmailAnalyzer>::parser(
            block("email_analyzer"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_files::FileType>::parser(
            block("file_type"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_files::X509Analyzer>::parser(
            block("x509_analyzer"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_files::DHashImageAnalyzer>::parser(
            block("dhash"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_files::LnkParseAnalyzer>::parser(
            block("lnk_parser"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_urls::UrlExtraction>::parser(
            block("url_extraction"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_urls::IocExtraction>::parser(
            block("ioc_extraction"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_values::CommandLineAnalyzer>::parser(
            block("command_line_analyzer"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_values::FilePathAnalyzer>::parser(
            block("file_path_analysis"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_values::ParseUrlAnalyzer>::parser(
            block("parse_url"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_values::IdnaAnalyzer>::parser(
            block("idna_analyzer"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_values::ProtectedUrlAnalyzer>::parser(
            block("protected_url_analyzer"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_values::NetworkIdentifier>::parser(
            block("network_identifier"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_html::HtmlDataUrlAnalyzer>::parser(
            block("html_data_url_extraction"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_html::MhtmlAnalyzer>::parser(
            block("mhtml"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_html::HtmlJavaScriptExtractor>::parser(
            block("html_js_extraction"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_html::HarExtractor>::parser(
            block("har_extraction"),
            &secrets,
        )?)
        .with_lookup(Entry::<Counted>::lookup(block(Counted::NAME), &secrets)?)
        .with_lookup(Entry::<Panicky>::lookup(block(Panicky::NAME), &secrets)?)
        .with_lookup(Entry::<Connect>::lookup(block(Connect::NAME), &secrets)?)
        .with_parser(Entry::<Capabilities>::parser(
            block(Capabilities::NAME),
            &secrets,
        )?)
        .with_parser(Entry::<PanickingParser>::parser(
            block(PanickingParser::NAME),
            &secrets,
        )?)
        .with_parser(Entry::<Spin>::parser(block(Spin::NAME), &secrets)?)
        .with_parser(Entry::<Stuck>::parser(block(Stuck::NAME), &secrets)?)
        .with_parser(Entry::<WritesFiles>::parser(
            block(WritesFiles::NAME),
            &secrets,
        )?)
        .with_lookup(Entry::<Hung>::lookup(block(Hung::NAME), &secrets)?))
}

/// The manifests of the test modules, for a core's catalog.
pub fn test_manifests() -> Vec<ace_sdk::Manifest> {
    vec![
        ace_sdk::Manifest::lookup::<Counted>(),
        ace_sdk::Manifest::lookup::<Panicky>(),
        ace_sdk::Manifest::lookup::<Connect>(),
        ace_sdk::Manifest::parser::<Capabilities>(),
        ace_sdk::Manifest::parser::<PanickingParser>(),
        ace_sdk::Manifest::parser::<Spin>(),
        ace_sdk::Manifest::parser::<Stuck>(),
        ace_sdk::Manifest::parser::<WritesFiles>(),
        ace_sdk::Manifest::lookup::<Hung>(),
    ]
}

/// A test module's result: one line of text.
macro_rules! note_type {
    ($ty:ident, $name:literal, $module:literal) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $ty {
            pub note: String,
        }

        impl AnalysisType for $ty {
            const NAME: &'static str = $name;
            const VERSION: u32 = 1;
            const MODULE: &'static str = $module;
        }
    };
}

note_type!(CountedNote, "test_counted_note", "test_counted");
note_type!(PanickyNote, "test_panicky_note", "test_panicky");
note_type!(SpinNote, "test_spin_note", "test_spin");
note_type!(StuckNote, "test_stuck_note", "test_stuck");
note_type!(
    WritesFilesNote,
    "test_writes_files_note",
    "test_writes_files"
);
note_type!(HungNote, "test_hung_note", "test_hung");
note_type!(ConnectNote, "test_connect_note", "test_connect");
note_type!(
    CapabilitiesNote,
    "test_capabilities_note",
    "test_capabilities"
);
note_type!(
    PanickingNote,
    "test_panicking_parser_note",
    "test_panicking_parser"
);

/// How many `test_counted` tasks run right now, and the most that ever ran at once.
pub static RUNNING: AtomicUsize = AtomicUsize::new(0);
pub static MOST_AT_ONCE: AtomicUsize = AtomicUsize::new(0);

/// A lookup that counts how many of its tasks run at once, each for a fifth of a second.
pub struct Counted;

impl Module for Counted {
    const NAME: &'static str = "test_counted";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    type Output = CountedNote;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(Counted)
    }
}

impl Lookup for Counted {
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<CountedNote>, ModuleError> {
        let now = RUNNING.fetch_add(1, Ordering::SeqCst) + 1;
        MOST_AT_ONCE.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        RUNNING.fetch_sub(1, Ordering::SeqCst);
        Ok(Outcome::Done(ResultEnvelope::new(CountedNote {
            note: format!("{now} at once"),
        })))
    }
}

/// A lookup that panics on an fqdn starting with `panic`, and answers otherwise.
pub struct Panicky;

impl Module for Panicky {
    const NAME: &'static str = "test_panicky";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    type Output = PanickyNote;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(Panicky)
    }
}

impl Lookup for Panicky {
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<PanickyNote>, ModuleError> {
        let value = &ctx.observable().value;
        if value.starts_with("panic") {
            panic!("test_panicky was given {value}");
        }
        tokio::task::yield_now().await;
        Ok(Outcome::Done(ResultEnvelope::new(PanickyNote {
            note: "fine".to_owned(),
        })))
    }
}

/// The TCP port `test_connect`'s manifest allows.
pub const ALLOWED_PORT: u16 = 29011;
/// A port it doesn't.
pub const OTHER_PORT: u16 = 29012;

/// A lookup that connects to 127.0.0.1 on the port its manifest allows and on one it doesn't,
/// and says how each went.
pub struct Connect;

impl Module for Connect {
    const NAME: &'static str = "test_connect";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    type Output = ConnectNote;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(Connect)
    }
}

impl Lookup for Connect {
    const TCP_PORTS: &'static [u16] = &[ALLOWED_PORT];

    async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<ConnectNote>, ModuleError> {
        let mut notes = Vec::new();
        for port in [ALLOWED_PORT, OTHER_PORT] {
            let how = match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(_) => "connected".to_owned(),
                Err(e) => e.to_string(),
            };
            notes.push(format!("{port}: {how}"));
        }
        Ok(Outcome::Done(ResultEnvelope::new(ConnectNote {
            note: notes.join("; "),
        })))
    }
}

/// A parser that reports the user and capabilities its process had when it was set up, which
/// in a task process is just before containment.
pub struct Capabilities {
    status: String,
}

impl Module for Capabilities {
    const NAME: &'static str = "test_capabilities";
    const INPUTS: &'static [ObservableKind] = ObservableKind::BUILTIN;
    type Output = CapabilitiesNote;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        let status = std::fs::read_to_string("/proc/self/status")?;
        let wanted = [
            "Uid:", "Gid:", "Groups:", "CapInh:", "CapPrm:", "CapEff:", "CapAmb:",
        ];
        let status = status
            .lines()
            .filter(|line| wanted.iter().any(|w| line.starts_with(w)))
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join("; ");
        Ok(Capabilities { status })
    }
}

impl ace_sdk::Parser for Capabilities {
    fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<CapabilitiesNote>, ModuleError> {
        Ok(Outcome::Done(ResultEnvelope::new(CapabilitiesNote {
            note: self.status.clone(),
        })))
    }
}

/// A parser that always panics.
pub struct PanickingParser;

impl Module for PanickingParser {
    const NAME: &'static str = "test_panicking_parser";
    const INPUTS: &'static [ObservableKind] = ObservableKind::BUILTIN;
    type Output = PanickingNote;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(PanickingParser)
    }
}

impl ace_sdk::Parser for PanickingParser {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<PanickingNote>, ModuleError> {
        panic!("test_panicking_parser was given {}", ctx.observable().value);
    }
}

/// A parser that never returns, once it has read the first byte of its file: a hung task. Its
/// deadline is 2 seconds, well inside its CPU-time limit, so the deadline is what stops it.
pub struct Spin;

impl Module for Spin {
    const NAME: &'static str = "test_spin";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const RESOURCES: ace_sdk::Resources = ace_sdk::Resources {
        timeout: Duration::from_secs(2),
        memory_mb: 1024,
        cpu_seconds: 120,
    };
    type Output = SpinNote;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(Spin)
    }
}

impl ace_sdk::Parser for Spin {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<SpinNote>, ModuleError> {
        let file = ctx.input_file()?;
        let first = std::fs::read(&file.local_path)?.first().copied();
        eprintln!(
            "test_spin: spinning on {} (first byte {first:?})",
            file.sha256
        );
        loop {
            std::hint::black_box(first);
            std::hint::spin_loop();
        }
    }
}

/// A parser that never returns, with a deadline too far off to matter, so only a kill from its
/// supervisor stops it. `test_spin`'s 2-second deadline would race a test's cancel or shutdown.
/// The CPU-time limit ends it if a failed test leaves it behind.
pub struct Stuck;

impl Module for Stuck {
    const NAME: &'static str = "test_stuck";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    const RESOURCES: ace_sdk::Resources = ace_sdk::Resources {
        timeout: Duration::from_secs(300),
        memory_mb: 1024,
        cpu_seconds: 60,
    };
    type Output = StuckNote;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(Stuck)
    }
}

impl ace_sdk::Parser for Stuck {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<StuckNote>, ModuleError> {
        eprintln!("test_stuck: stuck on {}", ctx.observable().value);
        loop {
            std::hint::spin_loop();
        }
    }
}

/// A parser that adds as many different files as the fqdn's first label says, so a test can make
/// a result whose uploads take a while.
pub struct WritesFiles;

impl Module for WritesFiles {
    const NAME: &'static str = "test_writes_files";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    type Output = WritesFilesNote;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(WritesFiles)
    }
}

impl ace_sdk::Parser for WritesFiles {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<WritesFilesNote>, ModuleError> {
        let value = &ctx.observable().value;
        let count: usize = value
            .split('.')
            .next()
            .and_then(|label| label.parse().ok())
            .ok_or_else(|| ModuleError::other(format!("{value} doesn't start with a count")))?;
        let mut result = ResultEnvelope::new(WritesFilesNote {
            note: format!("{count} files"),
        });
        for index in 0..count {
            let file = ctx
                .write_file(&format!("file-{index}"), index.to_string().as_bytes(), &[])
                .map_err(|e| ModuleError::other(e.to_string()))?;
            result = result.with_file(file);
        }
        Ok(Outcome::Done(result))
    }
}

/// `test_hung`'s settings: where its upstream is, and whether it waits on it in a blocking
/// call, which no cancellation can interrupt, rather than an await.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct HungSettings {
    pub address: String,
    pub blocking: bool,
}

/// A lookup whose upstream accepts the connection and never answers.
pub struct Hung {
    address: String,
    blocking: bool,
}

impl Module for Hung {
    const NAME: &'static str = "test_hung";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    type Output = HungNote;
    type Settings = HungSettings;

    fn init(settings: &HungSettings) -> Result<Self, ModuleError> {
        Ok(Hung {
            address: settings.address.clone(),
            blocking: settings.blocking,
        })
    }
}

impl Lookup for Hung {
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        _: &TaskContext<HungSettings>,
    ) -> Result<Outcome<HungNote>, ModuleError> {
        let mut buffer = [0u8; 1];
        let read = if self.blocking {
            // holds a runtime thread until the upstream hangs up
            use std::io::Read;
            let mut stream = std::net::TcpStream::connect(&self.address)?;
            stream.read(&mut buffer)?
        } else {
            use tokio::io::AsyncReadExt;
            let mut stream = tokio::net::TcpStream::connect(&self.address).await?;
            stream.read(&mut buffer).await?
        };
        Ok(Outcome::Done(ResultEnvelope::new(HungNote {
            note: format!("the upstream answered after all ({read} bytes)"),
        })))
    }
}

/// The test pool's GUI commands (PLAN.md 5.12), run in a contained command process by
/// `commands::process_main`:
///
/// - `echo WORDS...`: prints the words.
/// - `exit N`: exits N.
/// - `sleep forever|SECONDS`: prints `pid N`, then sleeps.
/// - `fork`: starts a process, which seccomp answers with SIGSYS.
/// - `open PATH`: opens PATH and prints what happened.
/// - `flood BYTES`: prints that many bytes.
/// - `nul`: prints a NUL between two letters.
/// - `both`: writes to stdout, stderr and stdout again.
pub fn run_test_command(argv: &[String]) -> u8 {
    test_command(argv).unwrap_or(1)
}

fn test_command(argv: &[String]) -> std::io::Result<u8> {
    use std::io::Write;
    let words: Vec<&str> = argv.iter().map(String::as_str).collect();
    let mut out = std::io::stdout().lock();
    Ok(match words.as_slice() {
        ["echo", rest @ ..] => {
            writeln!(out, "{}", rest.join(" "))?;
            0
        }
        ["exit", code] => code.parse().unwrap_or(1),
        ["sleep", how] => {
            writeln!(out, "pid {}", std::process::id())?;
            out.flush()?;
            let seconds = how.parse::<u64>().unwrap_or(u64::MAX);
            let until = std::time::Instant::now() + Duration::from_secs(seconds.min(1 << 32));
            while std::time::Instant::now() < until {
                std::thread::sleep(Duration::from_millis(200));
            }
            0
        }
        ["fork"] => {
            writeln!(out, "starting a process")?;
            out.flush()?;
            match std::process::Command::new("/bin/true").status() {
                Ok(status) => {
                    writeln!(out, "it ran: {status}")?;
                    0
                }
                Err(e) => {
                    writeln!(out, "it didn't: {e}")?;
                    1
                }
            }
        }
        ["open", path] => match std::fs::read(path) {
            Ok(bytes) => {
                writeln!(out, "read {} bytes", bytes.len())?;
                0
            }
            Err(e) => {
                writeln!(out, "can't open {path}: {e}")?;
                1
            }
        },
        ["flood", bytes] => {
            let mut left: usize = bytes.parse().unwrap_or(0);
            let chunk = vec![b'x'; 64 * 1024];
            while left > 0 {
                let n = left.min(chunk.len());
                out.write_all(&chunk[..n])?;
                left -= n;
            }
            0
        }
        ["nul"] => {
            out.write_all(b"a\0b\n")?;
            0
        }
        ["both"] => {
            writeln!(out, "out 1")?;
            out.flush()?;
            eprintln!("err 1");
            writeln!(out, "out 2")?;
            0
        }
        _ => {
            eprintln!("no test command {words:?}");
            2
        }
    })
}
