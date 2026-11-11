//! `observable_detection`, a port of ace3's `ObservableDetectionAnalyzer`
//! (`saq/modules/observable_detection.py`).
//!
//! For every observable it says whether the observable is enabled for detection, and when it is, adds
//! a detection point and a `detect_<type>` tag to it. ace3 keeps the observables to detect in its
//! `observable_detections` table, which `ace observables export` copies to Redis as `<type>:<value>`
//! keys every minute, and the module asks Redis for its observable's key. Here they're the entries
//! of the `observable_detection` list (PLAN.md 5.14), which the `detection` router and the admin page
//! edit, and the core adds the list to each task as it is when the task is leased, so an edit applies
//! to the next task with no export in between. An entry matches as ace3's key does: the observable's
//! own type, and its value exactly, case and all. An expired entry matches nothing, as ace3's export
//! leaves expired detections out of Redis.

use std::time::Duration;

use ace_results::types::tag::ObservableDetectionAnalysis;
use ace_results::{Detection, ObservableKind, ResultEnvelope};
use ace_sdk::lists::ListSpec;
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<ObservableDetection>();

/// ace3's built-in signature `observable_flagged_for_detection` (`saq/signatures/builtin.py`).
pub const OBSERVABLE_FLAGGED: &str = "97a0bcb8-1bde-4cf0-8fa2-72d6343c6458";

/// The observables enabled for detection: ace3's `observable_detections` table.
pub const DETECTION_LIST: ListSpec = ListSpec {
    name: "observable_detection",
    description: "Observables enabled for detection: an observable of the entry's type whose value \
                  the entry matches gets a detection point and a detect_<type> tag \
                  (observable_detection, ace3's observable_detections table).",
    typed: true,
};

/// The module has no settings: ace3's are its Redis connection's.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservableDetectionSettings {}

/// The observable detection module.
pub struct ObservableDetection;

impl Module for ObservableDetection {
    const NAME: &'static str = "observable_detection";
    // ace3's valid_observable_types is None: every type
    const INPUTS: &'static [ObservableKind] = ObservableKind::BUILTIN;
    const LISTS: &'static [ListSpec] = &[DETECTION_LIST];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(30),
        ..Resources::DEFAULT
    };
    type Output = ObservableDetectionAnalysis;
    type Settings = ObservableDetectionSettings;

    fn init(_settings: &ObservableDetectionSettings) -> Result<Self, ModuleError> {
        Ok(ObservableDetection)
    }
}

impl Lookup for ObservableDetection {
    /// The list comes on the lease, so it connects to nothing.
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<ObservableDetectionSettings>,
    ) -> Result<Outcome<ObservableDetectionAnalysis>, ModuleError> {
        let observable = ctx.observable();
        let kind = observable.kind.as_str();
        let value = &observable.value;
        let flagged = ctx
            .list(&DETECTION_LIST)?
            .find(Some(kind), value, ctx.now())
            .map_err(ModuleError::other)?
            .is_some();
        let mut result = ResultEnvelope::new(ObservableDetectionAnalysis {
            for_detection: flagged,
        });
        if flagged {
            tracing::info!("observable {kind}:{value} is enabled for detection");
            result.summary =
                Some("Observable Detection Analysis: enabled for detection".to_owned());
            result.analyzed.detections.push(
                Detection::new(format!(
                    "Observable {kind}:{value} is enabled for detection"
                ))
                .with_signature(OBSERVABLE_FLAGGED),
            );
            result.analyzed.tags.push(format!("detect_{kind}"));
        }
        Ok(Outcome::Done(result))
    }
}
