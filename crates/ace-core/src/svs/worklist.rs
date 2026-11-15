//! The declared-vs-measured worklist (PLAN.md 7.10 batch 8): what ace3's `saq/svs/worklist.py` decides
//! without the database. The service's `svs_worklist` keeps the rows in `svs.technique_worklist`.
//!
//! A signature is *measured* on the techniques of the catalog tests it is expected of (ignores applied,
//! removed tests left out). For each measured signature there is one row per technique:
//! - **declared**: a `mitre:` tag of the signature, its id resolved against the pinned ATT&CK release (ids
//!   that resolve to one technique share its row, in `declared_as`). It is *confirmed* when the technique
//!   is measured, or is the parent of a measured one: a tag on T1059 is confirmed by a test of T1059.001, a
//!   tag on T1059.001 is not confirmed by a test of T1059 or of T1059.003;
//! - **undeclared**: a measured technique no tag covers, for information;
//! - **unknown**: a tag naming an id the release doesn't have (and no test measures), for information.
//!
//! Everything but the resolution is derived on every coverage refresh ([`plan_refresh`], which the service
//! runs under the refresh lock before coverage is computed), status included ([`derive_status`]). A person
//! resolves an unconfirmed declared row: *keep* (the tag covers something no test reaches) or *remove* (a
//! pull request to the signature repository will drop the tag). A tag resolved *remove* stops counting
//! toward coverage from the next refresh, unless it is confirmed. A refresh writes a resolution in two
//! cases only: it clears a *remove* when the tag comes back after it was gone, and it moves a resolution to
//! the technique an ATT&CK upgrade revoked the row's technique to.
//!
//! Rows are never deleted; one the computation no longer produces is retired, and keeps its resolution.
//!
//! How it scales: one row per measured signature and technique, so the expectations bound it; a refresh
//! walks the computed rows and the stored ones once each.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::attack::{AttackCatalog, TechniqueStatus};
use super::coverage::{Measured, covers};
use super::signatures::SignatureTags;

/// What a worklist row is about: ace3's `WorklistKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorklistKind {
    /// A `mitre:` tag of a measured signature.
    Declared,
    /// A technique the signature is measured on that no tag of it covers.
    Undeclared,
    /// A `mitre:` tag naming an id the ATT&CK release doesn't have.
    Unknown,
}

impl WorklistKind {
    pub const ALL: &[WorklistKind] = &[
        WorklistKind::Declared,
        WorklistKind::Undeclared,
        WorklistKind::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            WorklistKind::Declared => "declared",
            WorklistKind::Undeclared => "undeclared",
            WorklistKind::Unknown => "unknown",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == text)
    }
}

/// Where a worklist row stands, derived on every refresh: ace3's `WorklistStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorklistStatus {
    /// What the tag claims is measured.
    Confirmed,
    /// Not measured, not resolved.
    Open,
    /// Resolved keep: it covers something no test reaches.
    Kept,
    /// Resolved remove, the tag is still there.
    RemovePending,
    /// Resolved remove, the tag is gone.
    Removed,
    /// Informational.
    Undeclared,
    /// Informational.
    Unknown,
    /// The signature isn't measured any more, or the tag went away unresolved.
    Retired,
}

impl WorklistStatus {
    /// In ace3's order.
    pub const ALL: &[WorklistStatus] = &[
        WorklistStatus::Confirmed,
        WorklistStatus::Open,
        WorklistStatus::Kept,
        WorklistStatus::RemovePending,
        WorklistStatus::Removed,
        WorklistStatus::Undeclared,
        WorklistStatus::Unknown,
        WorklistStatus::Retired,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            WorklistStatus::Confirmed => "confirmed",
            WorklistStatus::Open => "open",
            WorklistStatus::Kept => "kept",
            WorklistStatus::RemovePending => "remove_pending",
            WorklistStatus::Removed => "removed",
            WorklistStatus::Undeclared => "undeclared",
            WorklistStatus::Unknown => "unknown",
            WorklistStatus::Retired => "retired",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.as_str() == text)
    }
}

impl std::fmt::Display for WorklistStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A person's decision about a tag measurement doesn't confirm: ace3's `WorklistResolution`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorklistResolution {
    Keep,
    Remove,
}

impl WorklistResolution {
    pub const ALL: &[WorklistResolution] = &[WorklistResolution::Keep, WorklistResolution::Remove];

    pub fn as_str(self) -> &'static str {
        match self {
            WorklistResolution::Keep => "keep",
            WorklistResolution::Remove => "remove",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.as_str() == text)
    }
}

/// The statuses a person can resolve: a declared tag that measurement doesn't confirm. ace3's `RESOLVABLE`.
pub const RESOLVABLE: [WorklistStatus; 3] = [
    WorklistStatus::Open,
    WorklistStatus::Kept,
    WorklistStatus::RemovePending,
];

/// The longest reason and reference a resolution takes: ace3's `ResolutionRequest`.
pub const MAX_REASON_CHARS: usize = 4096;
pub const MAX_REFERENCE_CHARS: usize = 1024;

/// A row's status. `produced`: the computation produces the row now (its signature is measured, and for a
/// declared row, a tag of it counts as the technique). ace3's `derive_status`.
pub fn derive_status(
    kind: WorklistKind,
    produced: bool,
    tag_present: bool,
    confirmed: bool,
    resolution: Option<WorklistResolution>,
) -> WorklistStatus {
    match kind {
        WorklistKind::Undeclared if produced => WorklistStatus::Undeclared,
        WorklistKind::Unknown if produced => WorklistStatus::Unknown,
        WorklistKind::Undeclared | WorklistKind::Unknown => WorklistStatus::Retired,
        WorklistKind::Declared => {
            if !tag_present {
                if resolution == Some(WorklistResolution::Remove) {
                    WorklistStatus::Removed
                } else {
                    WorklistStatus::Retired
                }
            } else if !produced {
                WorklistStatus::Retired
            } else if confirmed {
                WorklistStatus::Confirmed
            } else {
                match resolution {
                    Some(WorklistResolution::Remove) => WorklistStatus::RemovePending,
                    Some(WorklistResolution::Keep) => WorklistStatus::Kept,
                    None => WorklistStatus::Open,
                }
            }
        }
    }
}

/// The row's tag counts toward coverage as a manual mapping: it is there, its signature is enabled (and
/// not a YARA rule in QA mode), the release knows its technique, and it isn't resolved remove, unless
/// measurement confirms it. ace3's `mapping_counts`.
pub fn mapping_counts(
    kind: WorklistKind,
    tag_present: bool,
    signature_counts: bool,
    known: bool,
    status: WorklistStatus,
    resolution: Option<WorklistResolution>,
) -> bool {
    if kind != WorklistKind::Declared || !tag_present || !signature_counts || !known {
        return false;
    }
    resolution != Some(WorklistResolution::Remove) || status == WorklistStatus::Confirmed
}

/// The derived columns of one worklist row; a refresh compares exactly these (besides the key), and status
/// and counts, which also depend on the resolution. ace3's `WorklistRow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorklistRow {
    pub signature_uuid: String,
    pub technique: String,
    pub kind: WorklistKind,
    /// The tag ids that count as the technique, sorted.
    pub declared_as: Vec<String>,
    pub tag_present: bool,
    pub signature_counts: bool,
    pub measured: bool,
    /// The techniques the signature is measured on, sorted.
    pub measured_techniques: Vec<String>,
    pub signature_family: Option<String>,
    pub signature_name: Option<String>,
    /// Not columns: what status and counts are derived from.
    pub confirmed: bool,
    /// The release has the technique (a confirmed tag can name an id it doesn't, like a custom atomic's).
    pub known: bool,
}

/// `{technique: (the release has it, the tag ids that count as it)}` of a signature's tags: ace3's
/// `_declared`.
fn declared(
    catalog: &AttackCatalog,
    signature: Option<&SignatureTags>,
) -> BTreeMap<String, (bool, Vec<String>)> {
    let mut result: BTreeMap<String, (bool, Vec<String>)> = BTreeMap::new();
    for tag in signature.map(|s| s.declared.as_slice()).unwrap_or_default() {
        let Ok(resolution) = catalog.resolve(tag) else {
            continue;
        };
        let known = resolution.status != TechniqueStatus::Unknown;
        result
            .entry(resolution.technique)
            .or_insert_with(|| (known, Vec::new()))
            .1
            .push(tag.clone());
    }
    result
}

/// A signature's family and name, for one without tags.
pub type KnownSignatures = BTreeMap<String, (Option<String>, Option<String>)>;

/// Every row the computation produces: those of the measured signatures. `tags` are
/// `signature_techniques`' result, `known` the family and name of the measured signatures without tags.
/// ace3's `compute_worklist`.
pub fn compute_worklist(
    catalog: &AttackCatalog,
    tags: &BTreeMap<String, SignatureTags>,
    measured: &Measured,
    known: &KnownSignatures,
) -> BTreeMap<(String, String), WorklistRow> {
    let mut rows = BTreeMap::new();
    for (signature_uuid, by_technique) in measured {
        let techniques: BTreeSet<&str> = by_technique.keys().map(String::as_str).collect();
        if techniques.is_empty() {
            continue;
        }
        let signature = tags.get(signature_uuid);
        let (family, name) = match signature {
            Some(signature) => (Some(signature.family.clone()), signature.name.clone()),
            None => known.get(signature_uuid).cloned().unwrap_or((None, None)),
        };
        let common = |technique: &str| WorklistRow {
            signature_uuid: signature_uuid.clone(),
            technique: technique.to_owned(),
            kind: WorklistKind::Undeclared,
            declared_as: Vec::new(),
            tag_present: false,
            signature_counts: signature.is_some_and(|s| s.counts),
            measured: true,
            measured_techniques: techniques.iter().map(|t| (*t).to_owned()).collect(),
            signature_family: family.clone(),
            signature_name: name.clone(),
            confirmed: false,
            known: true,
        };

        let mut covered: BTreeSet<&str> = BTreeSet::new();
        for (technique, (release_has_it, mut declared_as)) in declared(catalog, signature) {
            let matched: Vec<&str> = techniques
                .iter()
                .copied()
                .filter(|candidate| covers(catalog, &technique, candidate))
                .collect();
            covered.extend(matched.iter().copied());
            declared_as.sort();
            rows.insert(
                (signature_uuid.clone(), technique.clone()),
                WorklistRow {
                    // an id the release doesn't have is still a declaration when a test measures it
                    kind: if release_has_it || !matched.is_empty() {
                        WorklistKind::Declared
                    } else {
                        WorklistKind::Unknown
                    },
                    declared_as,
                    tag_present: true,
                    confirmed: !matched.is_empty(),
                    known: release_has_it,
                    ..common(&technique)
                },
            );
        }
        for technique in techniques.iter().filter(|t| !covered.contains(*t)) {
            rows.insert(
                (signature_uuid.clone(), (*technique).to_owned()),
                common(technique),
            );
        }
    }
    rows
}

/// A person's resolution of a row, as it is stored.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    pub resolution: WorklistResolution,
    pub reason: Option<String>,
    pub reference: Option<String>,
    /// Who resolved it, as the row records an actor.
    pub resolved_by: Option<Value>,
    pub resolved_at: DateTime<Utc>,
}

/// A stored worklist row, as a refresh reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredRow {
    pub kind: WorklistKind,
    pub status: WorklistStatus,
    pub declared_as: Vec<String>,
    pub tag_present: bool,
    pub signature_counts: bool,
    pub counts: bool,
    pub measured: bool,
    pub measured_techniques: Vec<String>,
    pub signature_family: Option<String>,
    pub signature_name: Option<String>,
    pub resolved: Option<Resolved>,
}

/// One row as a refresh leaves it: what to store.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedRow {
    pub signature_uuid: String,
    pub technique: String,
    pub row: StoredRow,
    /// The row isn't stored yet.
    pub inserted: bool,
    /// Something of the row differs from what is stored, so it has to be written.
    pub write: bool,
    /// Its status changed, so `status_changed_at` moves.
    pub status_changed: bool,
}

/// What a refresh does to the worklist: ace3's `WorklistRefresh`, with the rows to write.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WorklistPlan {
    /// Every row, stored or new, as the refresh leaves it.
    pub written: Vec<PlannedRow>,
    /// Rows that aren't retired.
    pub rows: usize,
    /// Rows a derived column, the status or the counts of which changed, new ones included.
    pub changed: usize,
    pub inserted: usize,
    /// (signature_uuid, technique, from_status, to_status) of each stored row whose status changed.
    pub transitions: Vec<(String, String, WorklistStatus, WorklistStatus)>,
    /// (signature_uuid, technique, resolution) the refresh cleared: the tag came back after a remove.
    pub cleared: Vec<(String, String, WorklistResolution)>,
    /// (signature_uuid, from_technique, to_technique, resolution) moved after an ATT&CK upgrade.
    pub moved: Vec<(String, String, String, WorklistResolution)>,
    /// (signature_uuid, technique) whose tag doesn't count because it is resolved remove.
    pub excluded: BTreeSet<(String, String)>,
}

type Key = (String, String);

/// `{new key: old key}` of the resolutions to move: a declared row no stored resolution is on yet, one of
/// whose tag ids is a stored row's technique that the computation no longer produces (an ATT&CK upgrade
/// revoked it to this one). ace3's `_carry_forward`.
fn carry_forward(
    computed: &BTreeMap<Key, WorklistRow>,
    stored: &BTreeMap<Key, StoredRow>,
) -> BTreeMap<Key, Key> {
    let mut moves = BTreeMap::new();
    let mut taken: BTreeSet<Key> = BTreeSet::new();
    for (key, row) in computed {
        if row.kind != WorklistKind::Declared
            || stored.get(key).is_some_and(|s| s.resolved.is_some())
        {
            continue;
        }
        for tag in &row.declared_as {
            let old = (row.signature_uuid.clone(), tag.clone());
            if *tag != row.technique
                && !computed.contains_key(&old)
                && !taken.contains(&old)
                && stored.get(&old).is_some_and(|s| s.resolved.is_some())
            {
                moves.insert(key.clone(), old.clone());
                taken.insert(old);
                break;
            }
        }
    }
    moves
}

/// What a refresh does to the stored worklist, given what the computation produces now: ace3's
/// `refresh_worklist`, without its writes. `measured` and `tags` are what `computed` was computed from.
pub fn plan_refresh(
    catalog: &AttackCatalog,
    tags: &BTreeMap<String, SignatureTags>,
    measured: &Measured,
    computed: &BTreeMap<Key, WorklistRow>,
    stored: &BTreeMap<Key, StoredRow>,
) -> WorklistPlan {
    let mut plan = WorklistPlan::default();
    let moves = carry_forward(computed, stored);
    // the rows a resolution moves away from lose it
    let moved_from: BTreeSet<&Key> = moves.values().collect();
    for (key, old) in &moves {
        if let Some(previous) = stored.get(old).and_then(|s| s.resolved.as_ref()) {
            plan.moved.push((
                key.0.clone(),
                old.1.clone(),
                key.1.clone(),
                previous.resolution,
            ));
        }
    }

    let finish = |plan: &mut WorklistPlan,
                  key: &Key,
                  current: Option<&StoredRow>,
                  row: StoredRow,
                  resolution_written: bool| {
        let planned = match current {
            None => {
                plan.changed += 1;
                plan.inserted += 1;
                PlannedRow {
                    signature_uuid: key.0.clone(),
                    technique: key.1.clone(),
                    row,
                    inserted: true,
                    write: true,
                    status_changed: false,
                }
            }
            Some(current) => {
                let derived_differs = current.kind != row.kind
                    || current.declared_as != row.declared_as
                    || current.tag_present != row.tag_present
                    || current.signature_counts != row.signature_counts
                    || current.measured != row.measured
                    || current.measured_techniques != row.measured_techniques
                    || current.signature_family != row.signature_family
                    || current.signature_name != row.signature_name
                    || (resolution_written && current.resolved != row.resolved);
                let status_changed = current.status != row.status;
                if status_changed {
                    plan.transitions.push((
                        key.0.clone(),
                        key.1.clone(),
                        current.status,
                        row.status,
                    ));
                }
                let counts_changed = current.counts != row.counts;
                if derived_differs || status_changed || counts_changed {
                    plan.changed += 1;
                }
                PlannedRow {
                    signature_uuid: key.0.clone(),
                    technique: key.1.clone(),
                    write: derived_differs
                        || status_changed
                        || counts_changed
                        || current.resolved != row.resolved,
                    row,
                    inserted: false,
                    status_changed,
                }
            }
        };
        plan.written.push(planned);
    };

    for (key, row) in computed {
        let current = stored.get(key);
        // a carried resolution lands on a row that has none
        let carried = moves
            .get(key)
            .and_then(|old| stored.get(old))
            .and_then(|s| s.resolved.clone());
        let mut resolved = match &carried {
            Some(carried) => Some(carried.clone()),
            None => current.and_then(|c| c.resolved.clone()),
        };
        // the tag is back after it was gone: what was resolved about it no longer stands
        if let Some(current) = current
            && let Some(was) = &current.resolved
            && was.resolution == WorklistResolution::Remove
            && !current.tag_present
            && row.tag_present
        {
            plan.cleared
                .push((key.0.clone(), key.1.clone(), was.resolution));
            resolved = None;
        }
        let resolution = resolved.as_ref().map(|r| r.resolution);
        let status = derive_status(row.kind, true, row.tag_present, row.confirmed, resolution);
        let counts = mapping_counts(
            row.kind,
            row.tag_present,
            row.signature_counts,
            row.known,
            status,
            resolution,
        );
        finish(
            &mut plan,
            key,
            current,
            StoredRow {
                kind: row.kind,
                status,
                declared_as: row.declared_as.clone(),
                tag_present: row.tag_present,
                signature_counts: row.signature_counts,
                counts,
                measured: row.measured,
                measured_techniques: row.measured_techniques.clone(),
                signature_family: row.signature_family.clone(),
                signature_name: row.signature_name.clone(),
                resolved,
            },
            carried.is_some(),
        );
    }

    for (key, current) in stored {
        if computed.contains_key(key) {
            continue;
        }
        let signature = tags.get(&key.0);
        let declared = declared(catalog, signature);
        let tag_present = current.kind != WorklistKind::Undeclared && declared.contains_key(&key.1);
        let techniques: Vec<String> = measured
            .get(&key.0)
            .map(|by| by.keys().cloned().collect())
            .unwrap_or_default();
        let resolved = if moved_from.contains(key) {
            None
        } else {
            current.resolved.clone()
        };
        let resolution = resolved.as_ref().map(|r| r.resolution);
        let signature_counts = signature.map_or(current.signature_counts, |s| s.counts);
        let status = derive_status(current.kind, false, tag_present, false, resolution);
        let counts = mapping_counts(
            current.kind,
            tag_present,
            signature_counts,
            declared.get(&key.1).is_some_and(|(known, _)| *known),
            status,
            resolution,
        );
        finish(
            &mut plan,
            key,
            Some(current),
            StoredRow {
                kind: current.kind,
                status,
                declared_as: current.declared_as.clone(),
                tag_present,
                signature_counts,
                counts,
                measured: !techniques.is_empty(),
                measured_techniques: techniques,
                signature_family: match signature {
                    Some(signature) => Some(signature.family.clone()),
                    None => current.signature_family.clone(),
                },
                signature_name: match signature {
                    Some(signature) => signature.name.clone(),
                    None => current.signature_name.clone(),
                },
                resolved,
            },
            false,
        );
    }

    plan.rows = plan
        .written
        .iter()
        .filter(|planned| planned.row.status != WorklistStatus::Retired)
        .count();
    plan.excluded = plan
        .written
        .iter()
        .filter(|planned| {
            planned.row.kind == WorklistKind::Declared
                && planned
                    .row
                    .resolved
                    .as_ref()
                    .is_some_and(|r| r.resolution == WorklistResolution::Remove)
                && planned.row.status != WorklistStatus::Confirmed
        })
        .map(|planned| (planned.signature_uuid.clone(), planned.technique.clone()))
        .collect();
    plan
}

/// A row's status and counts after a person changed its resolution; the rest is as the last refresh left
/// it. ace3's `_rederive`.
pub fn rederive(
    kind: WorklistKind,
    status: WorklistStatus,
    tag_present: bool,
    signature_counts: bool,
    counts: bool,
    resolution: Option<WorklistResolution>,
) -> (WorklistStatus, bool) {
    let confirmed = status == WorklistStatus::Confirmed;
    let produced = !matches!(status, WorklistStatus::Retired | WorklistStatus::Removed);
    let new_status = derive_status(kind, produced, tag_present, confirmed, resolution);
    // a confirmed tag counts (or not) whatever its resolution
    let counts = if confirmed {
        counts
    } else {
        mapping_counts(
            kind,
            tag_present,
            signature_counts,
            true,
            new_status,
            resolution,
        )
    };
    (new_status, counts)
}

/// A resolution as a person sends it, checked: the resolution, the trimmed reason, and the reference when
/// there is one. Or why it can't be accepted. ace3's `_validated`.
pub fn check_resolution(
    resolution: &str,
    reason: Option<&str>,
    reference: Option<&str>,
) -> Result<(WorklistResolution, String, Option<String>), String> {
    let resolution = WorklistResolution::parse(resolution)
        .ok_or_else(|| "resolution must be one of keep, remove".to_owned())?;
    let reason = reason.unwrap_or_default().trim();
    if reason.is_empty() {
        return Err("a resolution needs a reason".to_owned());
    }
    if reason.chars().count() > MAX_REASON_CHARS {
        return Err(format!(
            "reason is longer than {MAX_REASON_CHARS} characters"
        ));
    }
    let reference = reference.map(str::trim).filter(|r| !r.is_empty());
    if let Some(reference) = reference {
        if !is_http_url(reference) {
            return Err(format!("reference {reference:?} is not an http(s) URL"));
        }
        if reference.chars().count() > MAX_REFERENCE_CHARS {
            return Err(format!(
                "reference is longer than {MAX_REFERENCE_CHARS} characters"
            ));
        }
    }
    Ok((resolution, reason.to_owned(), reference.map(str::to_owned)))
}

/// What ace3 asks of a reference through `urlparse`: an `http` or `https` scheme, and a host after `//`.
/// And nothing a browser would read as something else: no white space or control character.
fn is_http_url(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return false;
    }
    let Some(rest) = rest.strip_prefix("//") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !host.is_empty() && !text.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::super::coverage::tests::{GUID, OTHER_SIGNATURE, SIGNATURE, catalog, tag};
    use super::*;

    /// `_measured`: `{signature: {technique: {(guid, platform)}}}` from signature and techniques.
    fn measured(by_signature: &[(&str, &[&str])]) -> Measured {
        by_signature
            .iter()
            .map(|(signature, techniques)| {
                (
                    (*signature).to_owned(),
                    techniques
                        .iter()
                        .map(|technique| {
                            (
                                (*technique).to_owned(),
                                BTreeSet::from([(GUID, "windows".to_owned())]),
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    }

    fn tags(all: Vec<SignatureTags>) -> BTreeMap<String, SignatureTags> {
        all.into_iter().map(|t| (t.uuid.clone(), t)).collect()
    }

    /// A row as the cases compare it: its key, then its kind, whether confirmed, and what it is declared as.
    type Summary<'a> = ((&'a str, &'a str), (&'static str, bool, Vec<&'a str>));

    /// `_summary`.
    fn summary(rows: &BTreeMap<Key, WorklistRow>) -> Vec<Summary<'_>> {
        rows.iter()
            .map(|(key, row)| {
                (
                    (key.0.as_str(), key.1.as_str()),
                    (
                        row.kind.as_str(),
                        row.confirmed,
                        row.declared_as.iter().map(String::as_str).collect(),
                    ),
                )
            })
            .collect()
    }

    fn compute(
        tagged: Vec<SignatureTags>,
        by_signature: &[(&str, &[&str])],
    ) -> BTreeMap<Key, WorklistRow> {
        compute_worklist(
            &catalog(),
            &tags(tagged),
            &measured(by_signature),
            &BTreeMap::new(),
        )
    }

    /// test_worklist.py's `TestDerive.test_status`, each of its parameters.
    #[test]
    fn status() {
        use WorklistKind::{Declared, Undeclared, Unknown};
        let keep = Some(WorklistResolution::Keep);
        let remove = Some(WorklistResolution::Remove);
        let cases = [
            (Declared, true, true, true, None, "confirmed"),
            // confirmed wins over a resolution
            (Declared, true, true, true, remove, "confirmed"),
            (Declared, true, true, false, None, "open"),
            (Declared, true, true, false, keep, "kept"),
            (Declared, true, true, false, remove, "remove_pending"),
            (Declared, false, false, false, remove, "removed"),
            (Declared, false, false, false, keep, "retired"),
            (Declared, false, false, false, None, "retired"),
            // the tag is still there, the signature isn't measured any more
            (Declared, false, true, false, remove, "retired"),
            (Undeclared, true, false, false, None, "undeclared"),
            (Undeclared, false, false, false, None, "retired"),
            (Unknown, true, true, false, None, "unknown"),
        ];
        for (kind, produced, tag_present, confirmed, resolution, expected) in cases {
            assert_eq!(
                derive_status(kind, produced, tag_present, confirmed, resolution).as_str(),
                expected,
                "{kind:?} {produced} {tag_present} {confirmed} {resolution:?}"
            );
        }
    }

    /// `TestDerive.test_counts`, each of its parameters.
    #[test]
    fn counts() {
        use WorklistKind::{Declared, Undeclared};
        use WorklistStatus as S;
        let keep = Some(WorklistResolution::Keep);
        let remove = Some(WorklistResolution::Remove);
        let cases = [
            (Declared, true, true, true, S::Open, None, true),
            (Declared, true, true, true, S::Kept, keep, true),
            (Declared, true, true, true, S::RemovePending, remove, false),
            (Declared, true, true, true, S::Confirmed, remove, true),
            (Declared, false, true, true, S::Retired, None, false),
            (Declared, true, false, true, S::Open, None, false),
            (Declared, true, true, false, S::Confirmed, None, false),
            (Undeclared, false, true, true, S::Undeclared, None, false),
        ];
        for (kind, tag_present, signature_counts, known, status, resolution, expected) in cases {
            assert_eq!(
                mapping_counts(
                    kind,
                    tag_present,
                    signature_counts,
                    known,
                    status,
                    resolution
                ),
                expected,
                "{kind:?} {tag_present} {signature_counts} {known} {status:?} {resolution:?}"
            );
        }
    }

    /// `TestCompute.test_a_parent_tag_is_confirmed_by_a_sub_technique`.
    #[test]
    fn a_parent_tag_is_confirmed_by_a_sub_technique() {
        let rows = compute(
            vec![tag(SIGNATURE, &["T1059"], true, &[])],
            &[(SIGNATURE, &["T1059.001"])],
        );
        assert_eq!(
            summary(&rows),
            [((SIGNATURE, "T1059"), ("declared", true, vec!["T1059"]))]
        );
        let row = &rows[&(SIGNATURE.to_owned(), "T1059".to_owned())];
        assert_eq!(
            (
                row.tag_present,
                row.measured,
                row.measured_techniques.as_slice(),
                row.signature_name.as_deref(),
                row.signature_family.as_deref(),
                row.signature_counts
            ),
            (
                true,
                true,
                ["T1059.001".to_owned()].as_slice(),
                Some("hunt 2222"),
                Some("hunt"),
                true
            )
        );
    }

    /// `TestCompute.test_a_sub_technique_tag_is_not_confirmed_by_its_parent`.
    #[test]
    fn a_sub_technique_tag_is_not_confirmed_by_its_parent() {
        let rows = compute(
            vec![tag(SIGNATURE, &["T1059.001"], true, &[])],
            &[(SIGNATURE, &["T1059"])],
        );
        assert_eq!(
            summary(&rows),
            [
                ((SIGNATURE, "T1059"), ("undeclared", false, vec![])),
                (
                    (SIGNATURE, "T1059.001"),
                    ("declared", false, vec!["T1059.001"])
                ),
            ]
        );
    }

    /// `TestCompute.test_a_sibling_does_not_confirm`.
    #[test]
    fn a_sibling_does_not_confirm() {
        let rows = compute(
            vec![tag(SIGNATURE, &["T1059.001"], true, &[])],
            &[(SIGNATURE, &["T1059.002"])],
        );
        assert_eq!(
            summary(&rows),
            [
                (
                    (SIGNATURE, "T1059.001"),
                    ("declared", false, vec!["T1059.001"])
                ),
                ((SIGNATURE, "T1059.002"), ("undeclared", false, vec![])),
            ]
        );
    }

    /// `TestCompute.test_revoked_ids_and_ids_that_meet`.
    #[test]
    fn revoked_ids_and_ids_that_meet() {
        // T1086 was revoked to T1059.001: both tags are one row
        let rows = compute(
            vec![tag(SIGNATURE, &["T1059.001", "T1086"], true, &[])],
            &[(SIGNATURE, &["T1059.001"])],
        );
        assert_eq!(
            summary(&rows),
            [(
                (SIGNATURE, "T1059.001"),
                ("declared", true, vec!["T1059.001", "T1086"])
            )]
        );
    }

    /// `TestCompute.test_unknown_ids`.
    #[test]
    fn unknown_ids() {
        let rows = compute(
            vec![tag(SIGNATURE, &["T9999", "T1234.001"], true, &[])],
            &[(SIGNATURE, &["T1234.001"])],
        );
        assert_eq!(
            summary(&rows),
            [
                // a custom atomic measures it: a declaration, confirmed, though the release lacks it
                (
                    (SIGNATURE, "T1234.001"),
                    ("declared", true, vec!["T1234.001"])
                ),
                ((SIGNATURE, "T9999"), ("unknown", false, vec!["T9999"])),
            ]
        );
        assert!(!rows[&(SIGNATURE.to_owned(), "T1234.001".to_owned())].known);
    }

    /// `TestCompute.test_untagged_and_unmeasured_signatures`.
    #[test]
    fn untagged_and_unmeasured_signatures() {
        let known = BTreeMap::from([(
            SIGNATURE.to_owned(),
            (Some("yara".to_owned()), Some("Some rule".to_owned())),
        )]);
        let rows = compute_worklist(
            &catalog(),
            &tags(vec![tag(OTHER_SIGNATURE, &["T1547"], true, &[])]),
            &measured(&[(SIGNATURE, &["T1547"])]),
            &known,
        );
        // only measured signatures have rows
        assert_eq!(
            summary(&rows),
            [((SIGNATURE, "T1547"), ("undeclared", false, vec![]))]
        );
        let row = &rows[&(SIGNATURE.to_owned(), "T1547".to_owned())];
        assert_eq!(
            (
                row.signature_family.as_deref(),
                row.signature_name.as_deref(),
                row.signature_counts
            ),
            (Some("yara"), Some("Some rule"), false)
        );
    }

    /// `test_status_and_kind_values_match_the_model`: the values are the ones migration 0058's checks
    /// name, which the service's tests write every one of.
    #[test]
    fn status_and_kind_values_match_the_model() {
        assert_eq!(
            WorklistStatus::ALL
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
            [
                "confirmed",
                "open",
                "kept",
                "remove_pending",
                "removed",
                "undeclared",
                "unknown",
                "retired"
            ]
        );
        assert_eq!(
            WorklistKind::ALL
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>(),
            ["declared", "undeclared", "unknown"]
        );
        let migration = include_str!("../../migrations/0058_svs_coverage.sql");
        let quoted = |values: Vec<&str>| {
            values
                .iter()
                .map(|v| format!("'{v}'"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let flat: String = migration.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains(&format!(
            "status IN ({})",
            quoted(WorklistStatus::ALL.iter().map(|s| s.as_str()).collect())
        )));
        assert!(flat.contains(&format!(
            "kind IN ({})",
            quoted(WorklistKind::ALL.iter().map(|k| k.as_str()).collect())
        )));
        assert!(flat.contains(&format!(
            "resolution IN ({})",
            quoted(WorklistResolution::ALL.iter().map(|r| r.as_str()).collect())
        )));
    }

    /// `TestResolutions.test_invalid_resolutions`, each of its parameters, and what a valid one becomes.
    #[test]
    fn invalid_resolutions() {
        let cases = [
            (
                "maybe",
                Some("why"),
                None,
                "resolution must be one of keep, remove",
            ),
            ("keep", Some("  "), None, "needs a reason"),
            (
                "remove",
                Some("why"),
                Some("ftp://example/x"),
                "not an http",
            ),
            ("remove", Some("why"), Some("https://"), "not an http"),
            ("remove", None, None, "needs a reason"),
            (
                "remove",
                Some("why"),
                Some("javascript:alert(1)"),
                "not an http",
            ),
            (
                "remove",
                Some("why"),
                Some("https://x.example/a b"),
                "not an http",
            ),
        ];
        for (resolution, reason, reference, message) in cases {
            let error = check_resolution(resolution, reason, reference).expect_err("refused");
            assert!(error.contains(message), "{error}");
        }
        let long = format!("https://x.example/{}", "a".repeat(MAX_REFERENCE_CHARS));
        assert!(
            check_resolution("keep", Some("why"), Some(&long))
                .expect_err("refused")
                .contains("longer than 1024")
        );
        assert_eq!(
            check_resolution(
                "remove",
                Some(" why "),
                Some(" HTTPS://git.example/pull/7 ")
            ),
            Ok((
                WorklistResolution::Remove,
                "why".to_owned(),
                Some("HTTPS://git.example/pull/7".to_owned())
            ))
        );
        assert_eq!(
            check_resolution("keep", Some("why"), Some("  ")),
            Ok((WorklistResolution::Keep, "why".to_owned(), None))
        );
    }

    fn stored_from(planned: &PlannedRow) -> (Key, StoredRow) {
        (
            (planned.signature_uuid.clone(), planned.technique.clone()),
            planned.row.clone(),
        )
    }

    /// What a refresh plans over what is stored: new rows, nothing on a second pass, a resolution kept
    /// through retirement, a remove cleared when the tag comes back, and one carried to a successor. The
    /// service's tests port ace3's `TestRefresh` cases against the database through this.
    #[test]
    fn a_refresh_plans_only_what_changed() {
        let c = catalog();
        let tagged = tags(vec![tag(SIGNATURE, &["T1547"], true, &[])]);
        let on = measured(&[(SIGNATURE, &["T1059.001"])]);
        let computed = compute_worklist(&c, &tagged, &on, &BTreeMap::new());
        let plan = plan_refresh(&c, &tagged, &on, &computed, &BTreeMap::new());
        assert_eq!((plan.rows, plan.changed, plan.inserted), (2, 2, 2));
        let mut stored: BTreeMap<Key, StoredRow> = plan.written.iter().map(stored_from).collect();
        let key = (SIGNATURE.to_owned(), "T1547".to_owned());
        assert_eq!(
            (stored[&key].status, stored[&key].counts),
            (WorklistStatus::Open, true)
        );

        // nothing changed: nothing to write
        let again = plan_refresh(&c, &tagged, &on, &computed, &stored);
        assert_eq!((again.rows, again.changed), (2, 0));
        assert!(again.written.iter().all(|planned| !planned.write));

        // resolved remove, then the tag goes: removed, and the resolution stays
        let at: DateTime<Utc> = "2026-10-17T12:00:00Z".parse().expect("a time");
        let row = stored.get_mut(&key).expect("the row");
        row.resolved = Some(Resolved {
            resolution: WorklistResolution::Remove,
            reason: Some("dropping it".to_owned()),
            reference: None,
            resolved_by: None,
            resolved_at: at,
        });
        (row.status, row.counts) = rederive(
            row.kind,
            row.status,
            row.tag_present,
            row.signature_counts,
            row.counts,
            Some(WorklistResolution::Remove),
        );
        assert_eq!(
            (row.status, row.counts),
            (WorklistStatus::RemovePending, false)
        );
        let untagged = BTreeMap::new();
        let computed = compute_worklist(&c, &untagged, &on, &BTreeMap::new());
        let plan = plan_refresh(&c, &untagged, &on, &computed, &stored);
        let stored: BTreeMap<Key, StoredRow> = plan.written.iter().map(stored_from).collect();
        assert_eq!(
            (
                stored[&key].status,
                stored[&key].tag_present,
                stored[&key].resolved.is_some()
            ),
            (WorklistStatus::Removed, false, true)
        );
        assert_eq!(plan.excluded, BTreeSet::from([key.clone()]));

        // the tag is back: the remove no longer stands
        let computed = compute_worklist(&c, &tagged, &on, &BTreeMap::new());
        let plan = plan_refresh(&c, &tagged, &on, &computed, &stored);
        assert_eq!(
            plan.cleared,
            [(
                SIGNATURE.to_owned(),
                "T1547".to_owned(),
                WorklistResolution::Remove
            )]
        );
        let stored: BTreeMap<Key, StoredRow> = plan.written.iter().map(stored_from).collect();
        assert_eq!(
            (
                stored[&key].status,
                stored[&key].counts,
                &stored[&key].resolved
            ),
            (WorklistStatus::Open, true, &None)
        );
        assert!(plan.excluded.is_empty());
    }
}
