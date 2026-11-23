//! Logs and spans for the pool and core processes (PLAN.md 2.22).
//!
//! `init` sends log lines to stderr, filtered by `ACE_RS_LOG`. `Telemetry::start_export` then
//! exports every span to an OpenTelemetry collector over OTLP/HTTP, when `ACE_RS_OTLP_ENDPOINT`
//! (such as `http://collector:4318`) is set. Export starts threads, its batch processor's and its
//! HTTP client's, so a contained process calls it after containment, and those threads inherit
//! the process's Landlock rules. A parser's task process doesn't export at all: it may not start
//! a thread, and its supervisor's spans cover the task.
//!
//! A span carries the identifiers 1.22 gave it: the root, the observable and the module, and
//! now the task id too. The lease client sends the current span's context with each call in a
//! W3C `traceparent` header, and the lease API makes its own spans children of it, so a task's
//! spans in the pool and in the core land in one trace.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use opentelemetry::propagation::{Injector, TextMapPropagator};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{
    BatchSpanProcessor, SdkTracerProvider, Span, SpanData, SpanProcessor,
};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// The variable that names the collector's OTLP/HTTP endpoint.
pub const OTLP_ENDPOINT_VAR: &str = "ACE_RS_OTLP_ENDPOINT";

/// A span processor that drops spans until export starts, then hands them to the batch
/// processor `start_export` makes. It lets the OpenTelemetry layer be in place from the start,
/// so every span has a trace context to propagate, without starting a thread until export.
#[derive(Debug, Clone, Default)]
struct Deferred {
    batch: Arc<OnceLock<BatchSpanProcessor>>,
}

impl SpanProcessor for Deferred {
    fn on_start(&self, span: &mut Span, cx: &opentelemetry::Context) {
        if let Some(batch) = self.batch.get() {
            batch.on_start(span, cx);
        }
    }

    fn on_end(&self, span: SpanData) {
        if let Some(batch) = self.batch.get() {
            batch.on_end(span);
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.batch.get().map_or(Ok(()), SpanProcessor::force_flush)
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.batch
            .get()
            .map_or(Ok(()), |batch| batch.shutdown_with_timeout(timeout))
    }
}

/// The process's logging and, once started, its span export. Dropping it flushes and stops
/// the export.
pub struct Telemetry {
    service: String,
    resource: Resource,
    deferred: Deferred,
    provider: SdkTracerProvider,
}

/// Starts logging to stderr, at `default_filter` unless `ACE_RS_LOG` says otherwise, and starts
/// recording spans for export, which `Telemetry::start_export` sends. Starts no thread.
pub fn init(service: &str, default_filter: &str) -> Telemetry {
    let resource = Resource::builder()
        .with_service_name(service.to_owned())
        .build();
    let deferred = Deferred::default();
    let provider = SdkTracerProvider::builder()
        .with_span_processor(deferred.clone())
        .with_resource(resource.clone())
        .build();
    let filter =
        EnvFilter::try_from_env("ACE_RS_LOG").unwrap_or_else(|_| EnvFilter::new(default_filter));
    let installed = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("ace-rs")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(filter)
        .try_init();
    if let Err(e) = installed {
        eprintln!("logging was already set up: {e}");
    }
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    Telemetry {
        service: service.to_owned(),
        resource,
        deferred,
        provider,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("the OTLP exporter: {0}")]
    Exporter(#[from] opentelemetry_otlp::ExporterBuildError),
    #[error("span export has started already")]
    Started,
}

impl Telemetry {
    /// Exports spans to the collector at `ACE_RS_OTLP_ENDPOINT`, if it is set. Returns whether
    /// export started.
    pub fn start_export(&mut self) -> Result<bool, TelemetryError> {
        match std::env::var(OTLP_ENDPOINT_VAR) {
            Ok(endpoint) if !endpoint.is_empty() => {
                self.export_to(&endpoint)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Exports spans to the collector at `endpoint`, such as `http://collector:4318`, from now
    /// on.
    pub fn export_to(&mut self, endpoint: &str) -> Result<(), TelemetryError> {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/v1/traces", endpoint.trim_end_matches('/')))
            .build()?;
        let mut batch = BatchSpanProcessor::builder(exporter).build();
        batch.set_resource(&self.resource);
        self.deferred
            .batch
            .set(batch)
            .map_err(|_| TelemetryError::Started)?;
        tracing::info!(service = %self.service, %endpoint, "exporting spans");
        Ok(())
    }

    /// Sends every span ended so far to the collector. Blocks until it has.
    pub fn flush(&self) {
        if let Err(e) = self.provider.force_flush() {
            eprintln!("flushing spans failed: {e}");
        }
    }
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            eprintln!("stopping span export failed: {e}");
        }
    }
}

/// The TCP port of the collector spans go to, for a contained process's sandbox.
pub fn otlp_port() -> Option<u16> {
    let endpoint = std::env::var(OTLP_ENDPOINT_VAR).ok()?;
    let (scheme, rest) = endpoint.split_once("://")?;
    let authority = rest.split('/').next()?;
    match authority.rsplit_once(':') {
        Some((_, port)) => port.parse().ok(),
        None => Some(if scheme == "https" { 443 } else { 80 }),
    }
}

/// The headers that carry the current span's context to the next process.
pub fn trace_headers() -> Vec<(String, String)> {
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let context = tracing::Span::current().context();
    let mut carrier = Carrier::default();
    TraceContextPropagator::new().inject_context(&context, &mut carrier);
    carrier.0.into_iter().collect()
}

#[derive(Default)]
struct Carrier(HashMap<String, String>);

impl Injector for Carrier {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_owned(), value);
    }
}
