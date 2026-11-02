//! Two example modules, one of each kind, for the SDK's tests and ace-testkit's. They do no real
//! analysis.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::Ipv4Addr;
use std::time::Duration;

use ace_results::{AnalysisType, Bytes, NewObservable, ObservableKind, ResultEnvelope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::context::TaskContext;
use crate::manifest::{Manifest, Resources};
use crate::module::{Delay, Lookup, Module, ModuleError, Outcome, Parser};

/// A parser: counts the lines of a file.
pub struct LineCounter;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LineStats {
    pub lines: u64,
    pub longest_line: u64,
    /// The first line's bytes, whatever their encoding.
    pub first_line: Bytes,
    /// True when the file was longer than `max_bytes` and only its start was read.
    pub truncated: bool,
}

impl AnalysisType for LineStats {
    const NAME: &'static str = "example_line_stats";
    const VERSION: u32 = 1;
    const MODULE: &'static str = LineCounter::NAME;
}

#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LineCounterSettings {
    /// Read at most this many bytes of the file.
    pub max_bytes: u64,
}

impl Default for LineCounterSettings {
    fn default() -> Self {
        LineCounterSettings {
            max_bytes: 1024 * 1024,
        }
    }
}

pub const LINE_COUNTER_MANIFEST: Manifest = Manifest::parser::<LineCounter>();

impl Module for LineCounter {
    const NAME: &'static str = "example_line_counter";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = LineStats;
    type Settings = LineCounterSettings;

    fn init(_: &LineCounterSettings) -> Result<Self, ModuleError> {
        Ok(LineCounter)
    }
}

impl Parser for LineCounter {
    fn analyze(
        &self,
        ctx: &TaskContext<LineCounterSettings>,
    ) -> Result<Outcome<LineStats>, ModuleError> {
        let file = ctx.input_file()?;
        let max_bytes = ctx.settings().max_bytes;
        let mut bytes = Vec::new();
        std::fs::File::open(&file.local_path)?
            .take(max_bytes)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() {
            return Ok(Outcome::Skipped("the file is empty".to_owned()));
        }

        let mut lines = 0u64;
        let mut longest_line = 0u64;
        for (index, line) in bytes.split(|&b| b == b'\n').enumerate() {
            // a parser polls the token; nothing else stops blocking code
            if index % 1024 == 0 {
                ctx.check_cancelled()?;
            }
            lines += 1;
            longest_line = longest_line.max(line.len() as u64);
        }
        let first_line = bytes.split(|&b| b == b'\n').next().unwrap_or_default();

        let stats = LineStats {
            lines,
            longest_line,
            first_line: Bytes::from(first_line),
            truncated: file.size > max_bytes,
        };
        Ok(Outcome::Done(
            ResultEnvelope::new(stats).with_summary(format!("{lines} lines")),
        ))
    }
}

/// A lookup: resolves a domain from a table in its settings, after an optional number of
/// delays, as a slow API would.
pub struct Resolver;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedAddresses {
    pub fqdn: String,
    pub addresses: Vec<Ipv4Addr>,
    /// How many times the lookup was delayed before it answered.
    pub delays: u32,
}

impl AnalysisType for ResolvedAddresses {
    const NAME: &'static str = "example_resolved_addresses";
    const VERSION: u32 = 1;
    const MODULE: &'static str = Resolver::NAME;
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ResolverSettings {
    pub hosts: BTreeMap<String, Vec<Ipv4Addr>>,
    /// Delay this many times before answering.
    pub delays: u32,
    pub delay_seconds: u64,
    pub delay_timeout_seconds: u64,
    /// Never answer, to test cancellation.
    pub hang: bool,
}

/// What the resolver keeps between delayed runs.
#[derive(Debug, Serialize, Deserialize)]
struct Pending {
    fqdn: String,
}

pub const RESOLVER_MANIFEST: Manifest = Manifest::lookup::<Resolver>();

impl Module for Resolver {
    const NAME: &'static str = "example_resolver";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    const SECRETS: &'static [&'static str] = &["resolver_token"];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(30),
        ..Resources::DEFAULT
    };
    type Output = ResolvedAddresses;
    type Settings = ResolverSettings;

    fn init(_: &ResolverSettings) -> Result<Self, ModuleError> {
        Ok(Resolver)
    }
}

impl Lookup for Resolver {
    // the example never connects anywhere
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<ResolverSettings>,
    ) -> Result<Outcome<ResolvedAddresses>, ModuleError> {
        // a real lookup would send it; the example only needs it to be there
        ctx.secret("resolver_token")?;
        let settings = ctx.settings();
        let fqdn = match ctx.delay_state::<Pending>()? {
            Some(pending) => pending.fqdn,
            None => ctx.observable().value.to_lowercase(),
        };

        let delays = ctx.delayed().map_or(0, |delayed| delayed.delays);
        if delays < settings.delays {
            let delay = Delay::new(
                Duration::from_secs(settings.delay_seconds),
                Duration::from_secs(settings.delay_timeout_seconds),
            )
            .with_state(&Pending { fqdn })?;
            return Ok(Outcome::Delay(delay));
        }

        if settings.hang {
            std::future::pending::<()>().await;
        }
        // stands in for the network round trip
        tokio::task::yield_now().await;

        let addresses = settings.hosts.get(&fqdn).cloned().unwrap_or_default();
        let mut result = ResultEnvelope::new(ResolvedAddresses {
            fqdn: fqdn.clone(),
            addresses: addresses.clone(),
            delays,
        })
        .with_summary(format!("{fqdn} has {} addresses", addresses.len()));
        for address in addresses {
            let mut observable = NewObservable::new(ObservableKind::Ipv4, address.to_string());
            observable.time = ctx.observable().time;
            result = result.with_observable(observable);
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Arc;

    use ace_results::AlertPath;
    use chrono::{TimeDelta, Utc};
    use uuid::Uuid;

    use super::*;
    use crate::context::{DelayedRun, InputFile, Observable, Secret, Secrets};
    use crate::module::{run_lookup, run_parser};

    fn file_observable(bytes: &[u8]) -> (tempfile::NamedTempFile, Observable) {
        let mut local = tempfile::NamedTempFile::new().expect("temp file");
        local.write_all(bytes).expect("write");
        let file = InputFile {
            path: AlertPath::new("email.rfc822.unknown_text_plain_000").expect("valid path"),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .expect("valid sha256"),
            size: bytes.len() as u64,
            yara_meta: vec![],
            mime_type: Some("text/plain".to_owned()),
            local_path: local.path().to_owned(),
        };
        (local, Observable::file(file))
    }

    fn parser_ctx(observable: Observable) -> TaskContext<LineCounterSettings> {
        TaskContext::new::<LineCounter>(
            Uuid::new_v4(),
            observable,
            Arc::new(LineCounterSettings::default()),
        )
    }

    #[test]
    fn parser_runs() {
        let (_local, observable) = file_observable(b"first\xff line\nsecond\n\nlast");
        let module = LineCounter::init(&LineCounterSettings::default()).expect("init");
        let outcome = run_parser(&module, &parser_ctx(observable)).expect("runs");
        let Outcome::Done(result) = outcome else {
            panic!("expected a result, got {outcome:?}");
        };
        assert_eq!(result.analysis_type(), "example_line_stats");
        assert_eq!(result.summary.as_deref(), Some("4 lines"));
        assert_eq!(
            result.details,
            LineStats {
                lines: 4,
                longest_line: 11,
                first_line: Bytes::from(&b"first\xff line"[..]),
                truncated: false,
            }
        );
    }

    #[test]
    fn parser_skips_an_empty_file_and_stops_when_cancelled() {
        let (_local, observable) = file_observable(b"");
        let outcome = run_parser(&LineCounter, &parser_ctx(observable)).expect("runs");
        assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");

        let (_local, observable) = file_observable(b"x\n");
        let ctx = parser_ctx(observable);
        ctx.cancel_token().cancel();
        assert!(matches!(
            run_parser(&LineCounter, &ctx),
            Err(ModuleError::Cancelled)
        ));
    }

    #[test]
    fn context_reports_time_left() {
        let (_local, observable) = file_observable(b"x");
        // the manifest's default timeout is 300 seconds
        let left = parser_ctx(observable.clone()).time_left();
        assert!(left <= Duration::from_secs(300) && left > Duration::from_secs(295));
        let left = parser_ctx(observable)
            .with_timeout(Duration::from_secs(60))
            .time_left();
        assert!(left <= Duration::from_secs(60) && left > Duration::from_secs(55));
        let resolver = resolver_ctx(resolver_settings()).time_left();
        assert!(resolver <= Duration::from_secs(30) && resolver > Duration::from_secs(25));
    }

    fn resolver_settings() -> ResolverSettings {
        ResolverSettings {
            hosts: BTreeMap::from([(
                "example.com".to_owned(),
                vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)],
            )]),
            delays: 1,
            delay_seconds: 30,
            delay_timeout_seconds: 300,
            hang: false,
        }
    }

    fn resolver_ctx(settings: ResolverSettings) -> TaskContext<ResolverSettings> {
        let secrets = Secrets::new()
            .with("resolver_token", Secret::new("t0ken"))
            .with("someone_elses", Secret::new("not yours"));
        TaskContext::new::<Resolver>(
            Uuid::new_v4(),
            Observable::new(ObservableKind::Fqdn, "Example.com"),
            Arc::new(settings),
        )
        .with_secrets(&secrets)
    }

    #[tokio::test]
    async fn lookup_delays_then_answers() {
        let module = Resolver::init(&resolver_settings()).expect("init");
        let first = resolver_ctx(resolver_settings());
        let Outcome::Delay(delay) = run_lookup(&module, &first).await.expect("runs") else {
            panic!("expected a delay");
        };
        assert_eq!(delay.run_after, Duration::from_secs(30));
        assert_eq!(delay.state, serde_json::json!({"fqdn": "example.com"}));

        let now = Utc::now();
        let second = resolver_ctx(resolver_settings())
            .with_now(now)
            .with_delayed(DelayedRun {
                state: delay.state,
                first_delayed_at: now - TimeDelta::seconds(30),
                delays: 1,
            });
        let Outcome::Done(result) = run_lookup(&module, &second).await.expect("runs") else {
            panic!("expected a result");
        };
        assert_eq!(result.details.delays, 1);
        let values: Vec<&str> = result
            .observables
            .iter()
            .map(|o| o.value.as_str())
            .collect();
        assert_eq!(values, ["192.0.2.1", "192.0.2.2"]);
        assert!(
            result
                .observables
                .iter()
                .all(|o| o.kind == ObservableKind::Ipv4)
        );
    }

    #[tokio::test]
    async fn a_delay_past_its_timeout_fails() {
        let settings = ResolverSettings {
            delays: 5,
            ..resolver_settings()
        };
        let now = Utc::now();
        let ctx = resolver_ctx(settings)
            .with_now(now)
            .with_delayed(DelayedRun {
                state: serde_json::json!({"fqdn": "example.com"}),
                first_delayed_at: now - TimeDelta::seconds(301),
                delays: 2,
            });
        assert!(matches!(
            run_lookup(&Resolver, &ctx).await,
            Err(ModuleError::DelayTimedOut(_))
        ));
    }

    #[tokio::test]
    async fn only_declared_secrets_are_readable() {
        let ctx = resolver_ctx(resolver_settings());
        assert_eq!(
            ctx.secret("resolver_token")
                .expect("declared and set")
                .expose(),
            "t0ken"
        );
        assert!(matches!(
            ctx.secret("someone_elses"),
            Err(ModuleError::UndeclaredSecret(_))
        ));

        let no_secrets = TaskContext::new::<Resolver>(
            Uuid::new_v4(),
            Observable::new(ObservableKind::Fqdn, "example.com"),
            Arc::new(resolver_settings()),
        );
        assert!(matches!(
            run_lookup(&Resolver, &no_secrets).await,
            Err(ModuleError::MissingSecret(_))
        ));
    }

    #[tokio::test]
    async fn cancel_ends_a_hung_lookup() {
        let settings = ResolverSettings {
            delays: 0,
            hang: true,
            ..resolver_settings()
        };
        let ctx = resolver_ctx(settings);
        let token = ctx.cancel_token().clone();
        let canceller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            token.cancel();
        });
        assert!(matches!(
            run_lookup(&Resolver, &ctx).await,
            Err(ModuleError::Cancelled)
        ));
        canceller.await.expect("the canceller finishes");
    }
}
