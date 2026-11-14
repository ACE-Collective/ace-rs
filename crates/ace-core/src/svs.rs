//! SVS, the Signature Validation System (PLAN.md 7.10): ace3's `saq/svs/`, the model the rest of SVS
//! builds on. Migration 0047 holds its tables.
//!
//! - `markers`: a run's marker, `svs-` and 26 base32 characters, and finding markers in text.
//! - `hosts`: the test hosts runs may target, how a host and user name are normalized, and how a run's
//!   target matches a test host.
//! - `log_search`: the link from a run to the site's own log search, `svs.log_search_url`.
//! - `samples`: the samples, the files YARA rules matched on alerts graded TP or FP, their labels, and how
//!   `svs_yara_sample_capture`'s captures land (batch 2).
//! - `yara` and `validations`: YARA validation, a rule change replayed over the samples, and the queue and
//!   workers that run it (batch 3).
//! - `attack`: the ATT&CK release coverage is computed against, an extract built into the binary, and the
//!   builder of such an extract (batch 4).
//! - `catalog`: the Atomic Red Team test catalog, read from SVS's mirror of each catalog repository (batch 4).
//! - `windows`: a run's observation and attribution windows, from the hunts' latencies (batch 4).
//! - `signatures`: what a run's result says of a signature, and the techniques `mitre:` tags claim (batch 4).
//! - `runs`: what a run's registration and its launcher's calls decide without the database (batch 5).
//! - `results`: a run's result, each signature's status from what fired and what was decided, and a
//!   write's `If-Match` precondition (batch 5).
//! - `attribution`: who owns an event, and the core's SVS hook, which attributes an alert's detections to
//!   test runs (batch 6).
//! - `marker_rule`: the built-in YARA rule that finds markers in file contents (batch 6).
//! - The values every part shares: a run's states, its event log's kinds, how a detection was attributed,
//!   and the one SVS status an alert has (`derive_status`).
//!
//! **Who owns an event (ace3 #842).** An alert with no marker belongs to a run by its hosts and its event
//! time alone, and so does a hunt's match the hunter drops. ace3 decides that in one function,
//! `context_owners`, since its PR #844, but each caller still judges on its own, in its own process and
//! with its own caches: the `svs_alert_tagger` module tags the alert, the marker router judges it again
//! inside ALERT() and after each pass and writes the attributions, and the hunter asks again for a grouped
//! hunt's suppression key and for the matches it drops. Here the decision is in the core, `attribution`: one
//! function over the database (`attribution::context_owners`), in the caller's transaction and with no
//! cache, that the core's SVS hook (`attribution::judge`, which judges a root once at the end of a pass and
//! writes its attributions, tags and mismatch detections from that one judgment) and the service's
//! `record_hunt_run` (6.5) both call, with an event's hosts and time derived by one function too
//! (`attribution::Event::derive`). Everything that reads afterwards (the verdicts, the samples, 7.13's
//! router, the screens) reads the attributions rather than judging again. PLAN.md 7.10 has the whole
//! design.

pub mod attack;
pub mod attribution;
pub mod catalog;
pub mod hosts;
pub mod log_search;
pub mod marker_rule;
pub mod markers;
pub mod results;
pub mod runs;
pub mod samples;
pub mod signatures;
pub mod validations;
pub mod windows;
pub mod yara;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// The built-in signature of a marker that doesn't agree with its run: ace3's `SVS_MARKER_MISMATCH`. A
/// detection of it, on the root, says the alert has one, and its details name the marker and how it
/// disagrees.
pub const MARKER_MISMATCH_SIGNATURE: &str = "9b90e9be-67e7-402c-b4f6-e7be758ee260";
/// The built-in signature of a registration against a host that isn't a test host: ace3's
/// `SVS_REGISTRATION_REFUSED`.
pub const REGISTRATION_REFUSED_SIGNATURE: &str = "0d950be1-edba-4861-b1eb-df8bd96aa2ed";
/// The SVS built-ins are about runs, not what a test fires: they're never attributed and never counted in
/// a result. ace3's `RUN_SIGNATURES`.
pub const RUN_SIGNATURES: [&str; 2] = [REGISTRATION_REFUSED_SIGNATURE, MARKER_MISMATCH_SIGNATURE];

/// The tag of an alert every detection of which is attributed to a run.
pub const TAG_SVS_TEST: &str = "svs_test";
/// The tag of an alert with a marker that doesn't agree with its run.
pub const TAG_MARKER_MISMATCH: &str = "svs:marker_mismatch";
/// The tag of an alert of a test host's maintenance window.
pub const TAG_MAINTENANCE: &str = "svs:maintenance";

macro_rules! text_enum {
    ($(#[$meta:meta])* $name:ident, $sql:literal { $($(#[$vmeta:meta])* $variant:ident => $text:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
                 sqlx::Type)]
        #[serde(rename_all = "snake_case")]
        #[sqlx(type_name = $sql, rename_all = "snake_case")]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }

        impl $name {
            pub const ALL: &[$name] = &[$($name::$variant,)+];

            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text,)+
                }
            }

            pub fn parse(text: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|value| value.as_str() == text)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

text_enum!(
    /// Where a test run is: ace3's `RunState`.
    RunState, "svs.run_state" {
        /// Registered; the launcher hasn't called start.
        Created => "created",
        /// Its windows are open.
        Started => "started",
        /// Its observation window passed; it waits for a person.
        Ended => "ended",
        /// Signed off: what coverage counts.
        Reviewed => "reviewed",
        /// Stopped by its launcher; it still attributes until its attribution window ends.
        Canceled => "canceled",
        /// The launcher reported a failure, or never called start.
        Error => "error",
        /// Discarded: nothing is learned from it.
        Closed => "closed",
    }
);

text_enum!(
    /// How a detection was attributed to a run: ace3's `AttributionConfidence`.
    AttributionConfidence, "svs.attribution_confidence" {
        /// A marker that agrees with the run: its run, its target, its window.
        Marker => "marker",
        /// No marker at all: the run's target and window alone.
        Context => "context",
    }
);

/// The kinds of row in a run's event log: ace3's `RunEventKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunEventKind {
    Registered,
    Transition,
    LauncherCall,
    /// Detections of an alert attributed to the run.
    Attributed,
    /// Attributions that no longer hold.
    AttributionRemoved,
    /// The run's alerts given SIMULATED when it closed.
    AlertsClosed,
    /// The run's result changed.
    ResultComputed,
    /// A signature in the run's result was decided.
    CandidateDecision,
    /// A person associated an alert with the run.
    Associated,
    /// A person disassociated an alert, or marked it not a test.
    Disassociated,
    /// A person kept an alert's context attribution.
    ContextKept,
    /// A person took the run.
    OwnershipTaken,
    /// A person signed the run's result off.
    Reviewed,
}

/// Who wrote an attribution: ace3's `AttributionSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionSource {
    /// The core's SVS hook, ace3's marker router.
    Router,
    /// A person associated the alert with the run.
    Manual,
}

/// The one SVS status of an alert: ace3's `SVSStatus`. An alert SVS never touched has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SvsStatus {
    /// Every detection attributed, at least one by a marker: routed to the test queue.
    #[serde(rename = "test")]
    Test,
    /// Every detection attributed by context only: routed to the test queue.
    #[serde(rename = "test?")]
    TestContext,
    /// Some detections attributed: it stays in its queue.
    #[serde(rename = "partial")]
    Partial,
    /// A marker that doesn't agree with its context: it stays in its queue.
    #[serde(rename = "mismatch")]
    Mismatch,
}

impl SvsStatus {
    /// ace3's names: `test`, `test?`, `partial`, `mismatch`.
    pub fn as_str(self) -> &'static str {
        match self {
            SvsStatus::Test => "test",
            SvsStatus::TestContext => "test?",
            SvsStatus::Partial => "partial",
            SvsStatus::Mismatch => "mismatch",
        }
    }
}

/// The status of an alert whose detections are `detections` and whose attributions that hold give each
/// attributed detection the confidences in `confidences`: none when no detection is attributed, partial
/// when some are, and test or test? when all are, test? when context is all there is. ace3's
/// `derive_status`. A confidence for a detection the alert doesn't have counts for nothing.
pub fn derive_status<D: Ord + Copy>(
    detections: impl IntoIterator<Item = D>,
    confidences: &BTreeMap<D, BTreeSet<AttributionConfidence>>,
) -> Option<SvsStatus> {
    let detections: BTreeSet<D> = detections.into_iter().collect();
    let attributed: BTreeSet<D> = detections
        .iter()
        .copied()
        .filter(|detection| confidences.contains_key(detection))
        .collect();
    if attributed.is_empty() {
        return None;
    }
    if attributed != detections {
        return Some(SvsStatus::Partial);
    }
    let context_only = BTreeSet::from([AttributionConfidence::Context]);
    if attributed
        .iter()
        .all(|detection| confidences[detection] == context_only)
    {
        return Some(SvsStatus::TestContext);
    }
    Some(SvsStatus::Test)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_follows_what_is_attributed() {
        use AttributionConfidence::{Context, Marker};
        let of = |pairs: &[(i64, &[AttributionConfidence])]| {
            pairs
                .iter()
                .map(|(id, set)| (*id, set.iter().copied().collect::<BTreeSet<_>>()))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(derive_status([1, 2], &of(&[])), None);
        assert_eq!(derive_status([1, 2], &of(&[(3, &[Marker])])), None);
        assert_eq!(
            derive_status([1, 2], &of(&[(1, &[Marker])])),
            Some(SvsStatus::Partial)
        );
        assert_eq!(
            derive_status([1, 2], &of(&[(1, &[Marker]), (2, &[Context])])),
            Some(SvsStatus::Test)
        );
        assert_eq!(
            derive_status([1, 2], &of(&[(1, &[Context]), (2, &[Context])])),
            Some(SvsStatus::TestContext)
        );
        assert_eq!(
            derive_status([1], &of(&[(1, &[Context, Marker])])),
            Some(SvsStatus::Test)
        );
        // no detections at all: nothing is attributed
        assert_eq!(derive_status([], &of(&[(1, &[Marker])])), None);
    }

    #[test]
    fn the_states_are_ace3_s() {
        assert_eq!(
            RunState::ALL.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            [
                "created", "started", "ended", "reviewed", "canceled", "error", "closed"
            ]
        );
        assert_eq!(RunState::parse("reviewed"), Some(RunState::Reviewed));
        assert_eq!(RunState::parse("Reviewed"), None);
    }
}
