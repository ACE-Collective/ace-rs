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
        .with_parser(Entry::<ace_mod_archive::ArchiveAnalyzer>::parser(
            block("archive"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_email::EmailAnalyzer>::parser(
            block("email_analyzer"),
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
        )?))
}

/// The manifests of the test modules, for a core's catalog.
pub fn test_manifests() -> Vec<ace_sdk::Manifest> {
    vec![
        ace_sdk::Manifest::lookup::<Counted>(),
        ace_sdk::Manifest::lookup::<Panicky>(),
        ace_sdk::Manifest::lookup::<Connect>(),
        ace_sdk::Manifest::parser::<Capabilities>(),
        ace_sdk::Manifest::parser::<PanickingParser>(),
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
pub const ALLOWED_PORT: u16 = 47011;
/// A port it doesn't.
pub const OTHER_PORT: u16 = 47012;

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
    const INPUTS: &'static [ObservableKind] = ObservableKind::ALL;
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
    const INPUTS: &'static [ObservableKind] = ObservableKind::ALL;
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
