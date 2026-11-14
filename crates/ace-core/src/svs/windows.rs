//! A run's windows (PLAN.md 7.10 batch 4): ace3's `saq/svs/windows.py`.
//!
//! The observation window is how long a started run waits for its alerts before it ends: the worst-case
//! latency of the slowest signature the test is expected to fire, plus slack, within a floor and a ceiling
//! (the overlay's `svs.runs.observation_window`). A hunt's worst-case latency is frequency + time_range +
//! offset; every other signature (YARA, analysis modules) fires while the alert is analyzed, so its latency
//! is 0 and the floor covers it. A test with no expectations yet, which is its first run, where
//! expectations are discovered, waits for the slowest *enabled* hunt instead.
//!
//! The attribution window is longer by `svs.runs.attribution_extra_hours`: alerts that arrive after the run
//! ended but inside it are still attributed, as late.
//!
//! Hunts are read as ace3's signature inventory reads them: the merged `rule` mapping of each hunt file
//! (`ace_hunt::loader::load_merged`, 6.2's loader), without validating it as a hunt type's config, so a
//! hunt that wouldn't load still has its name, suppression and hash for a run's result.
//!
//! What differs from ace3's: ace3 finds the hunt directories in its configuration (`hunt_locations`), which
//! every one of its processes reads. Here only `ace hunter`'s configuration names them (6.4), and `ace
//! serve`, which registers runs, may not have the signatures checkout at all. So the hunter records what
//! SVS needs of each hunt file it loads ([`read_hunt_file`], kept in `hunts.hunts.svs` by `sync_hunts`,
//! every `reload_seconds`), and a registration reads that ([`recorded_hunts`]) in its own transaction,
//! with no cache: there's one copy of the setting, and a window reflects the hunts the hunter runs. Until
//! a hunter has loaded its hunts there are none, and a window is the floor. [`read_hunts`] and
//! [`HuntCache`] read the directories directly, as ace3 does, for a caller that has them. A cron
//! frequency's firings are computed in UTC, as the hunter computes them, where ace3's croniter starts from
//! the node's local time.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ace_hunt::correlate::scripts::{py_repr_value, py_str, strip};
use ace_hunt::model::is_timedelta_string;
use ace_hunt::value::{Map, Value};
use ace_sdk::SvsRunsSection;
use chrono::{DateTime, TimeDelta, Utc};
use sha2::{Digest, Sha256};

/// A batch registers many runs back to back; each process reads the hunt files at most this often.
pub const HUNT_CACHE_SECONDS: u64 = 60;
/// How far ahead a cron frequency's firings are looked at for its largest gap, and at most how many.
const CRON_HORIZON_DAYS: i64 = 7;
const CRON_MAX_FIRINGS: usize = 20_000;
/// ace3's `TIMESPEC_TOKEN`: the key of a hunt's `time_ranges` that holds its own time range.
const TIMESPEC_TOKEN: &str = "TIMESPEC";

/// A hunt's timing can't be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidHunt(pub String);

/// ace3's `_timespec`: a time span, None for nothing, and an error for anything else.
fn timespec(value: Option<&Value>) -> Result<Option<TimeDelta>, InvalidHunt> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(text)) if text.is_empty() => Ok(None),
        Some(Value::Str(text)) if is_timedelta_string(text) => {
            ace_hunt::query::schedule::timedelta(text)
                .map(Some)
                .map_err(InvalidHunt)
        }
        Some(other) => Err(InvalidHunt(format!(
            "{} is not a time span",
            py_repr_value(other)
        ))),
    }
}

/// The largest gap between consecutive firings of a cron expression over the week after `start`.
pub fn cron_interval(expression: &str, start: DateTime<Utc>) -> Result<TimeDelta, InvalidHunt> {
    let invalid = || {
        InvalidHunt(format!(
            "{} is neither a time span nor a cron expression",
            ace_hunt::value::py_repr(expression)
        ))
    };
    let cron = croner::parser::CronParser::new()
        .parse(expression)
        .map_err(|_| invalid())?;
    let mut previous = cron
        .find_next_occurrence(&start, false)
        .map_err(|_| invalid())?;
    let horizon = previous + TimeDelta::days(CRON_HORIZON_DAYS);
    let mut largest = TimeDelta::zero();
    for _ in 0..CRON_MAX_FIRINGS {
        let firing = cron
            .find_next_occurrence(&previous, false)
            .map_err(|_| invalid())?;
        largest = largest.max(firing - previous);
        if firing > horizon {
            break;
        }
        previous = firing;
    }
    Ok(largest)
}

/// The worst-case latency of a hunt's `rule` mapping: frequency + time_range + offset. The time range
/// prefers `time_ranges.TIMESPEC.duration_before`, as the hunter's query hunts do; a hunt type without a
/// time range (or an offset) counts it as 0. A cron frequency's interval is its largest gap in the week
/// after `now`.
pub fn hunt_latency(rule: &Map, now: DateTime<Utc>) -> Result<TimeDelta, InvalidHunt> {
    let frequency = match rule.get("frequency") {
        Some(Value::Str(frequency)) if !frequency.is_empty() => frequency,
        _ => return Err(InvalidHunt("no frequency".to_owned())),
    };
    let interval = if is_timedelta_string(frequency) {
        ace_hunt::query::schedule::timedelta(frequency).map_err(InvalidHunt)?
    } else {
        cron_interval(frequency, now)?
    };
    let mut time_range = None;
    if let Some(Value::Map(ranges)) = rule.get("time_ranges")
        && let Some(Value::Map(own)) = ranges.get(TIMESPEC_TOKEN)
    {
        time_range = timespec(own.get("duration_before"))?;
    }
    if time_range.is_none() {
        time_range = timespec(rule.get("time_range"))?;
    }
    let offset = timespec(rule.get("offset"))?;
    Ok(interval + time_range.unwrap_or_default() + offset.unwrap_or_default())
}

/// What SVS needs of a hunt: its window latency, for a run's result its name, suppression and rule hash,
/// and for coverage its tags. ace3's `HuntInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HuntInfo {
    pub uuid: String,
    pub name: String,
    pub enabled: bool,
    /// frequency + time_range + offset; None when the hunt's timing can't be read.
    pub latency: Option<TimeDelta>,
    /// Its suppression period, None without one (or when it can't be read).
    pub suppression: Option<TimeDelta>,
    /// It groups by `group_by`, so it suppresses each group inside its query results and the hunter records
    /// what it dropped (6.5); a hunt without it suppresses as a whole, by not running.
    pub per_group: bool,
    /// The sha256 of its file, as ace3's signature inventory computes it.
    pub content_hash: String,
    /// Its tags, sorted, without repeats (`mitre:` tags map it to ATT&CK techniques).
    pub tags: Vec<String>,
}

/// ace3's `normalize_tags`: the tags as a sorted list of non-empty strings without repeats, from a list or
/// a single value.
fn normalize_tags(tags: Option<&Value>) -> Vec<String> {
    let Some(tags) = tags.filter(|tags| tags.truthy()) else {
        return Vec::new();
    };
    let items = match tags {
        Value::Str(_) => vec![tags.clone()],
        // a value Python can't iterate is no tags, where ace3's loader fails on it
        other => other.py_iter().unwrap_or_default(),
    };
    let unique: BTreeSet<String> = items
        .iter()
        .filter(|tag| !matches!(tag, Value::Null))
        .map(|tag| strip(&py_str(tag)).to_owned())
        .filter(|tag| !tag.is_empty())
        .collect();
    unique.into_iter().collect()
}

/// What SVS reads of one hunt file's merged mapping and raw bytes, or None for a file that isn't a hunt
/// SVS tracks: no `rule` mapping, or no uuid. Each part that can't be read is logged against `path`.
pub fn hunt_info_of(
    merged: &Map,
    source: &[u8],
    path: &Path,
    now: DateTime<Utc>,
) -> Option<HuntInfo> {
    let Some(Value::Map(rule)) = merged.get("rule") else {
        return None;
    };
    let uuid = rule.get("uuid").filter(|uuid| uuid.truthy())?;
    let enabled = matches!(rule.get("enabled"), Some(Value::Bool(true)));
    let latency = match hunt_latency(rule, now) {
        Ok(latency) => Some(latency),
        Err(e) => {
            if enabled {
                tracing::warn!(
                    "unable to read the latency of hunt {} for svs run windows: {e}",
                    path.display()
                );
            }
            None
        }
    };
    let suppression = match timespec(rule.get("suppression")) {
        Ok(suppression) => suppression,
        Err(e) => {
            tracing::warn!(
                "unable to read the suppression of hunt {} for svs run results: {e}",
                path.display()
            );
            None
        }
    };
    let name = match rule.get("name").filter(|name| name.truthy()) {
        Some(name) => py_str(name),
        None => "unnamed".to_owned(),
    };
    Some(HuntInfo {
        uuid: strip(&py_str(uuid)).to_owned(),
        name,
        enabled,
        latency,
        suppression,
        per_group: rule.get("group_by").is_some_and(Value::truthy),
        content_hash: hex::encode(Sha256::digest(source)),
        tags: normalize_tags(rule.get("tags")),
    })
}

/// Every hunt in `rule_dirs`, by uuid, enabled or not: ace3's `_read_hunts`. One uuid in two files: the
/// enabled one counts, then the slower. A directory that isn't one is logged and skipped, as is a file
/// that can't be read.
pub fn read_hunts(rule_dirs: &[PathBuf], now: DateTime<Utc>) -> BTreeMap<String, HuntInfo> {
    let mut result: BTreeMap<String, HuntInfo> = BTreeMap::new();
    for dir in rule_dirs {
        if !dir.is_dir() {
            tracing::warn!(
                "hunt rule_dir {} is not a directory; its hunts don't count toward svs run windows",
                dir.display()
            );
            continue;
        }
        for path in ace_hunt::hunt_files(std::slice::from_ref(dir)) {
            if let Some(info) = read_hunt_file(&path, now) {
                keep_hunt(&mut result, info);
            }
        }
    }
    result
}

/// What SVS reads of one hunt file, or None for a file that can't be read (logged) or isn't a hunt SVS
/// tracks. The hunter calls it for each file it loads, whether or not the file loaded as a hunt, and records
/// what it gives (`ace_service`'s `sync_hunts`), which is how `ace serve` knows the hunts.
pub fn read_hunt_file(path: &Path, now: DateTime<Utc>) -> Option<HuntInfo> {
    let read = ace_hunt::loader::load_merged(
        &path.to_string_lossy(),
        None,
        ace_hunt::yaml::Limits::default(),
    )
    .map_err(|e| e.to_string())
    .and_then(|(merged, _)| {
        std::fs::read(path)
            .map(|source| (merged, source))
            .map_err(|e| e.to_string())
    });
    match read {
        Ok((merged, source)) => hunt_info_of(&merged, &source, path, now),
        Err(e) => {
            tracing::warn!("unable to read hunt {} for svs: {e}", path.display());
            None
        }
    }
}

/// Adds a hunt to those read so far. One uuid in two files: the enabled one counts, then the slower, and
/// of two that tie, the first.
pub fn keep_hunt(hunts: &mut BTreeMap<String, HuntInfo>, info: HuntInfo) {
    let rank = |info: &HuntInfo| (info.enabled, info.latency.unwrap_or_default());
    match hunts.get(&info.uuid) {
        Some(previous) if rank(&info) <= rank(previous) => {}
        _ => {
            hunts.insert(info.uuid.clone(), info);
        }
    }
}

/// A [`HuntInfo`] as the hunter records it beside the hunt's file in `hunts.hunts.svs`: its spans in whole
/// seconds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecordedHunt {
    pub uuid: String,
    pub name: String,
    pub enabled: bool,
    pub latency_seconds: Option<i64>,
    pub suppression_seconds: Option<i64>,
    pub per_group: bool,
    pub content_hash: String,
    pub tags: Vec<String>,
}

impl From<&HuntInfo> for RecordedHunt {
    fn from(info: &HuntInfo) -> Self {
        RecordedHunt {
            uuid: info.uuid.clone(),
            name: info.name.clone(),
            enabled: info.enabled,
            latency_seconds: info.latency.map(|span| span.num_seconds()),
            suppression_seconds: info.suppression.map(|span| span.num_seconds()),
            per_group: info.per_group,
            content_hash: info.content_hash.clone(),
            tags: info.tags.clone(),
        }
    }
}

impl From<RecordedHunt> for HuntInfo {
    fn from(hunt: RecordedHunt) -> Self {
        HuntInfo {
            uuid: hunt.uuid,
            name: hunt.name,
            enabled: hunt.enabled,
            latency: hunt.latency_seconds.map(TimeDelta::seconds),
            suppression: hunt.suppression_seconds.map(TimeDelta::seconds),
            per_group: hunt.per_group,
            content_hash: hunt.content_hash,
            tags: hunt.tags,
        }
    }
}

/// Every hunt the hunter recorded, by uuid, enabled or not: what [`read_hunts`] gives of the hunter's rule
/// directories, read from the database, where `ace serve` has no hunt files to read. In the files' order
/// by type and path, so two files with one uuid resolve the same way every time. A row that doesn't parse
/// is logged and skipped.
pub async fn recorded_hunts(
    conn: &mut sqlx::PgConnection,
) -> Result<BTreeMap<String, HuntInfo>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"SELECT type, path, svs AS "svs!" FROM hunts.hunts WHERE svs IS NOT NULL ORDER BY type, path"#,
    )
    .fetch_all(conn)
    .await?;
    let mut hunts = BTreeMap::new();
    for row in rows {
        match serde_json::from_value::<RecordedHunt>(row.svs) {
            Ok(hunt) => keep_hunt(&mut hunts, hunt.into()),
            Err(e) => tracing::warn!(
                kind = row.r#type,
                path = row.path,
                "a recorded hunt's svs info doesn't parse: {e}"
            ),
        }
    }
    Ok(hunts)
}

/// Every hunt by its uuid, as one read of the files gave them.
pub type Hunts = Arc<BTreeMap<String, HuntInfo>>;

/// The hunts of some rule directories, read at most every [`HUNT_CACHE_SECONDS`] per process: ace3's
/// `hunt_info` and its cache.
pub struct HuntCache {
    rule_dirs: Vec<PathBuf>,
    cached: Mutex<Option<(Instant, Hunts)>>,
}

impl HuntCache {
    pub fn new(rule_dirs: Vec<PathBuf>) -> HuntCache {
        HuntCache {
            rule_dirs,
            cached: Mutex::new(None),
        }
    }

    /// Every hunt by uuid, enabled or not.
    pub fn hunt_info(&self) -> Hunts {
        let mut cached = self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((read_at, hunts)) = cached.as_ref()
            && read_at.elapsed().as_secs() < HUNT_CACHE_SECONDS
        {
            return hunts.clone();
        }
        let hunts = Arc::new(read_hunts(&self.rule_dirs, Utc::now()));
        *cached = Some((Instant::now(), hunts.clone()));
        hunts
    }

    /// The worst-case latency of every enabled hunt whose timing can be read, by uuid.
    pub fn hunt_latencies(&self) -> BTreeMap<String, TimeDelta> {
        hunt_latencies(&self.hunt_info())
    }

    /// Forgets what was read, so the next call reads the files again.
    pub fn clear(&self) {
        *self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// The worst-case latency of every enabled hunt whose timing can be read, by uuid: ace3's `hunt_latencies`.
pub fn hunt_latencies(hunts: &BTreeMap<String, HuntInfo>) -> BTreeMap<String, TimeDelta> {
    hunts
        .iter()
        .filter(|(_, info)| info.enabled)
        .filter_map(|(uuid, info)| Some((uuid.clone(), info.latency?)))
        .collect()
}

/// The overlay's `svs.runs` keys the windows read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowConfig {
    pub slack: TimeDelta,
    pub floor: TimeDelta,
    pub ceiling: TimeDelta,
    pub attribution_extra: TimeDelta,
}

impl WindowConfig {
    pub fn from_section(section: &SvsRunsSection) -> Result<WindowConfig, String> {
        section.check()?;
        let window = &section.observation_window;
        Ok(WindowConfig {
            slack: TimeDelta::minutes(i64::from(window.slack_minutes)),
            floor: TimeDelta::minutes(i64::from(window.floor_minutes)),
            ceiling: TimeDelta::hours(i64::from(window.ceiling_hours)),
            attribution_extra: TimeDelta::hours(i64::from(section.attribution_extra_hours)),
        })
    }
}

impl Default for WindowConfig {
    fn default() -> Self {
        WindowConfig::from_section(&SvsRunsSection::default()).expect("the defaults are valid")
    }
}

/// How long a started run waits for its alerts. With expectations, it is the worst-case latency of the
/// slowest expected signature plus slack; without any, that of the slowest enabled hunt plus slack. Either
/// way within the configured floor and ceiling. `latencies` is `hunt_latencies`.
pub fn observation_window(
    latencies: &BTreeMap<String, TimeDelta>,
    expected_signature_uuids: Option<&BTreeSet<String>>,
    config: &WindowConfig,
) -> TimeDelta {
    let slowest = match expected_signature_uuids.filter(|expected| !expected.is_empty()) {
        Some(expected) => expected
            .iter()
            .map(|uuid| latencies.get(uuid).copied().unwrap_or_default())
            .max(),
        None => latencies.values().copied().max(),
    }
    .unwrap_or_default();
    (slowest + config.slack)
        .max(config.floor)
        .min(config.ceiling)
}

/// How long after a run starts its alerts are still attributed: the observation window plus
/// `svs.runs.attribution_extra_hours`.
pub fn attribution_window(observation: TimeDelta, config: &WindowConfig) -> TimeDelta {
    observation + config.attribution_extra
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn rule(text: &str) -> Map {
        let mut budget = ace_hunt::yaml::Budget::new(ace_hunt::yaml::Limits::default());
        match ace_hunt::yaml::load(text, "rule.yaml", &mut budget).expect("loads") {
            Value::Map(map) => map,
            other => panic!("{other:?} isn't a mapping"),
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 14, 0, 0, 0).unwrap()
    }

    /// A hunt file as ace3's test helper `_hunt` writes one: its uuid as its name too.
    fn hunt(dir: &Path, file: &str, uuid: &str, enabled: bool, rest: &str) {
        std::fs::write(
            dir.join(file),
            // quoted, as PyYAML writes a name it would otherwise read as something else (`off` is false)
            format!("rule:\n  uuid: '{uuid}'\n  name: '{uuid}'\n  enabled: {enabled}\n{rest}"),
        )
        .expect("writes");
    }

    fn hunt_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("a directory")
    }

    fn cache(dir: &tempfile::TempDir) -> HuntCache {
        HuntCache::new(vec![dir.path().to_path_buf()])
    }

    fn latencies(pairs: &[(&str, TimeDelta)]) -> BTreeMap<String, TimeDelta> {
        pairs
            .iter()
            .map(|(uuid, latency)| ((*uuid).to_owned(), *latency))
            .collect()
    }

    /// test_windows.py's `test_hunt_latency`, each of its parameters.
    #[test]
    fn hunt_latency_adds_frequency_time_range_and_offset() {
        for (text, expected) in [
            (
                "{frequency: '00:15:00', time_range: '00:15:00'}",
                TimeDelta::minutes(30),
            ),
            (
                "{frequency: '00:15:00', time_range: '00:15:00', offset: '01:00:00'}",
                TimeDelta::minutes(90),
            ),
            // time_ranges.TIMESPEC wins over time_range, as in the hunter
            (
                "{frequency: '01:00:00', time_range: '00:01:00', \
                  time_ranges: {TIMESPEC: {duration_before: '1:00:00:00'}}}",
                TimeDelta::days(1) + TimeDelta::hours(1),
            ),
            // a hunt type without a time range
            ("{frequency: '00:05:00'}", TimeDelta::minutes(5)),
            // daily at 02:00
            (
                "{frequency: '0 2 * * *', time_range: '1:00:00:00'}",
                TimeDelta::days(2),
            ),
        ] {
            assert_eq!(hunt_latency(&rule(text), now()), Ok(expected), "{text}");
        }
    }

    /// test_windows.py's `test_hunt_latency_rejects`, each of its parameters, and what PyYAML makes of an
    /// unquoted span that starts with 1 to 9: a number in base 60, which is no frequency.
    #[test]
    fn hunt_latency_rejects_what_it_cannot_read() {
        for text in [
            "{}",
            "{frequency: not a schedule}",
            "{frequency: '00:05:00', offset: soon}",
            "{frequency: 1:00:00}",
            "{frequency: '00:05:00', time_range: 15}",
        ] {
            assert!(hunt_latency(&rule(text), now()).is_err(), "{text}");
        }
        assert_eq!(
            hunt_latency(&rule("{}"), now()),
            Err(InvalidHunt("no frequency".to_owned()))
        );
        assert_eq!(
            hunt_latency(&rule("{frequency: '00:05:00', offset: soon}"), now()),
            Err(InvalidHunt("'soon' is not a time span".to_owned()))
        );
    }

    /// test_windows.py's `test_cron_interval_is_the_largest_gap`: weekdays at 09:00, where the weekend is
    /// the largest gap.
    #[test]
    fn cron_interval_is_the_largest_gap() {
        assert_eq!(cron_interval("0 9 * * 1-5", now()), Ok(TimeDelta::days(3)));
        assert_eq!(cron_interval("* * * * *", now()), Ok(TimeDelta::minutes(1)));
        assert!(cron_interval("whenever", now()).is_err());
    }

    /// test_windows.py's `test_hunt_latencies_read_enabled_hunts`: a disabled hunt, one whose timing can't
    /// be read, a template and an include don't count.
    #[test]
    fn hunt_latencies_read_enabled_hunts() {
        let dir = hunt_dir();
        let d = dir.path();
        hunt(
            d,
            "fast.yaml",
            "fast",
            true,
            "  frequency: '00:05:00'\n  time_range: '00:05:00'\n",
        );
        hunt(
            d,
            "daily.yaml",
            "daily",
            true,
            "  frequency: '1:00:00:00'\n  time_range: '1:00:00:00'\n",
        );
        hunt(
            d,
            "off.yaml",
            "off",
            false,
            "  frequency: '7:00:00:00'\n  time_range: '7:00:00:00'\n",
        );
        hunt(d, "broken.yaml", "broken", true, "  frequency: whenever\n");
        hunt(
            d,
            "template.yaml",
            "template",
            true,
            "  frequency: '7:00:00:00'\n",
        );
        std::fs::write(d.join("shared.include.yaml"), "rule: {}\n").expect("writes");
        assert_eq!(
            cache(&dir).hunt_latencies(),
            latencies(&[
                ("fast", TimeDelta::minutes(10)),
                ("daily", TimeDelta::days(2))
            ])
        );
        // a directory that isn't one is skipped
        let missing = HuntCache::new(vec![d.join("missing"), d.to_path_buf()]);
        assert_eq!(missing.hunt_latencies().len(), 2);
    }

    /// test_windows.py's `test_hunt_info_reads_tags`: a list's tags without repeats, a scalar as one tag,
    /// and none.
    #[test]
    fn hunt_info_reads_tags() {
        let dir = hunt_dir();
        let d = dir.path();
        hunt(
            d,
            "tagged.yaml",
            "tagged",
            true,
            "  frequency: '00:05:00'\n  tags: ['mitre:T1059.001', phishing, 'mitre:T1059.001']\n",
        );
        hunt(
            d,
            "scalar.yaml",
            "scalar",
            true,
            "  frequency: '00:05:00'\n  tags: 'mitre:T1547'\n",
        );
        hunt(
            d,
            "untagged.yaml",
            "untagged",
            true,
            "  frequency: '00:05:00'\n",
        );
        let info = cache(&dir).hunt_info();
        assert_eq!(info["tagged"].tags, ["mitre:T1059.001", "phishing"]);
        assert_eq!(info["scalar"].tags, ["mitre:T1547"]);
        assert!(info["untagged"].tags.is_empty());
    }

    /// test_windows.py's `test_hunt_info_keeps_every_hunt_for_results`: a run's result needs the name,
    /// suppression and rule hash of hunts the windows skip: disabled ones, and ones whose timing can't be
    /// read. Then one uuid in two files: the enabled one counts, then the slower.
    #[test]
    fn hunt_info_keeps_every_hunt_for_results() {
        let dir = hunt_dir();
        let d = dir.path();
        hunt(
            d,
            "grouped.yaml",
            "grouped",
            true,
            "  frequency: '00:05:00'\n  suppression: '1:00:00:00'\n  group_by: host\n",
        );
        hunt(
            d,
            "off.yaml",
            "off",
            false,
            "  frequency: '00:05:00'\n  dedup_key: '{{ user }}'\n",
        );
        hunt(
            d,
            "broken.yaml",
            "broken",
            true,
            "  frequency: whenever\n  suppression: '01:00:00'\n",
        );
        let cache = cache(&dir);
        let info = cache.hunt_info();
        assert_eq!(
            info.keys().map(String::as_str).collect::<Vec<_>>(),
            ["broken", "grouped", "off"]
        );
        assert_eq!(
            (info["grouped"].suppression, info["grouped"].latency),
            (Some(TimeDelta::days(1)), Some(TimeDelta::minutes(5)))
        );
        assert_eq!(
            (info["off"].enabled, info["off"].suppression),
            (false, None)
        );
        // only group_by suppresses per group, which the hunter records
        assert_eq!(
            (
                info["grouped"].per_group,
                info["off"].per_group,
                info["broken"].per_group
            ),
            (true, false, false)
        );
        assert_eq!(
            (info["broken"].latency, info["broken"].suppression),
            (None, Some(TimeDelta::hours(1)))
        );
        // the inventory's hash: the raw file
        let source = std::fs::read(d.join("grouped.yaml")).expect("reads");
        assert_eq!(
            info["grouped"].content_hash,
            hex::encode(Sha256::digest(&source))
        );
        assert_eq!(info["grouped"].name, "grouped");
        assert_eq!(
            cache.hunt_latencies(),
            latencies(&[("grouped", TimeDelta::minutes(5))])
        );

        hunt(
            d,
            "a-disabled.yaml",
            "twice",
            false,
            "  frequency: '7:00:00:00'\n",
        );
        hunt(d, "b-fast.yaml", "twice", true, "  frequency: '00:05:00'\n");
        hunt(d, "c-slow.yaml", "twice", true, "  frequency: '01:00:00'\n");
        hunt(d, "d-fast.yaml", "twice", true, "  frequency: '00:01:00'\n");
        std::fs::write(
            d.join("no-uuid.yaml"),
            "rule: {name: nameless, frequency: '00:05:00'}\n",
        )
        .expect("writes");
        std::fs::write(d.join("not-a-hunt.yaml"), "- a list\n").expect("writes");
        cache.clear();
        let info = cache.hunt_info();
        assert_eq!(info.len(), 4);
        assert_eq!(info["twice"].latency, Some(TimeDelta::hours(1)));
    }

    /// test_windows.py's `test_hunt_latencies_are_cached`.
    #[test]
    fn hunt_latencies_are_cached() {
        let dir = hunt_dir();
        hunt(
            dir.path(),
            "fast.yaml",
            "fast",
            true,
            "  frequency: '00:05:00'\n",
        );
        let cache = cache(&dir);
        assert_eq!(
            cache.hunt_latencies(),
            latencies(&[("fast", TimeDelta::minutes(5))])
        );
        hunt(
            dir.path(),
            "slow.yaml",
            "slow",
            true,
            "  frequency: '01:00:00'\n",
        );
        assert!(!cache.hunt_latencies().contains_key("slow"));
        cache.clear();
        assert!(cache.hunt_latencies().contains_key("slow"));
    }

    /// test_windows.py's `test_the_first_run_waits_for_the_slowest_enabled_hunt`: a test without
    /// expectations gets the slowest enabled hunt, not the floor.
    #[test]
    fn the_first_run_waits_for_the_slowest_enabled_hunt() {
        let dir = hunt_dir();
        let d = dir.path();
        hunt(
            d,
            "fast.yaml",
            "fast",
            true,
            "  frequency: '00:05:00'\n  time_range: '00:05:00'\n",
        );
        hunt(
            d,
            "daily.yaml",
            "daily",
            true,
            "  frequency: '1:00:00:00'\n  time_range: '1:00:00:00'\n",
        );
        hunt(
            d,
            "off.yaml",
            "off",
            false,
            "  frequency: '7:00:00:00'\n  time_range: '7:00:00:00'\n",
        );
        let latencies = cache(&dir).hunt_latencies();
        let config = WindowConfig::default();
        let expected = TimeDelta::days(2) + TimeDelta::minutes(30);
        assert_eq!(observation_window(&latencies, None, &config), expected);
        assert_eq!(
            observation_window(&latencies, Some(&BTreeSet::new()), &config),
            expected
        );
    }

    /// test_windows.py's `test_the_window_stays_within_floor_and_ceiling`.
    #[test]
    fn the_window_stays_within_floor_and_ceiling() {
        let dir = hunt_dir();
        let d = dir.path();
        let cache = cache(&dir);
        let config = WindowConfig::default();
        assert_eq!(
            observation_window(&cache.hunt_latencies(), None, &config),
            TimeDelta::minutes(60)
        );

        hunt(
            d,
            "weekly.yaml",
            "weekly",
            true,
            "  frequency: '7:00:00:00'\n  time_range: '7:00:00:00'\n",
        );
        cache.clear();
        assert_eq!(
            observation_window(&cache.hunt_latencies(), None, &config),
            TimeDelta::hours(72)
        );

        let section = ace_sdk::Overlay::from_yaml(
            "svs: {runs: {observation_window: {slack_minutes: 0, floor_minutes: 5}}}",
        )
        .expect("parses")
        .svs
        .runs;
        let config = WindowConfig::from_section(&section).expect("valid");
        std::fs::remove_file(d.join("weekly.yaml")).expect("removes");
        hunt(
            d,
            "fast.yaml",
            "fast",
            true,
            "  frequency: '00:05:00'\n  time_range: '00:05:00'\n",
        );
        cache.clear();
        assert_eq!(
            observation_window(&cache.hunt_latencies(), None, &config),
            TimeDelta::minutes(10)
        );
    }

    /// test_windows.py's `test_the_window_with_expectations`: a YARA rule (no hunt) fires during analysis,
    /// so the floor covers it.
    #[test]
    fn the_window_with_expectations() {
        let dir = hunt_dir();
        let d = dir.path();
        hunt(
            d,
            "fast.yaml",
            "fast",
            true,
            "  frequency: '01:00:00'\n  time_range: '01:00:00'\n",
        );
        hunt(
            d,
            "daily.yaml",
            "daily",
            true,
            "  frequency: '1:00:00:00'\n  time_range: '1:00:00:00'\n",
        );
        let latencies = cache(&dir).hunt_latencies();
        let config = WindowConfig::default();
        let expected = |uuids: &[&str]| {
            uuids
                .iter()
                .map(|u| (*u).to_owned())
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            observation_window(&latencies, Some(&expected(&["some-yara-rule"])), &config),
            TimeDelta::minutes(60)
        );
        assert_eq!(
            observation_window(
                &latencies,
                Some(&expected(&["some-yara-rule", "fast"])),
                &config
            ),
            TimeDelta::hours(2) + TimeDelta::minutes(30)
        );
    }

    /// test_windows.py's `test_attribution_window`.
    #[test]
    fn the_attribution_window_is_longer() {
        assert_eq!(
            attribution_window(TimeDelta::hours(1), &WindowConfig::default()),
            TimeDelta::hours(25)
        );
    }

    /// What the hunter records of a hunt is what a registration reads back: the spans as whole seconds,
    /// and one uuid in two files resolved as reading the directories resolves it.
    #[test]
    fn a_recorded_hunt_reads_back() {
        let info = |uuid: &str, enabled: bool, latency: Option<i64>| HuntInfo {
            uuid: uuid.to_owned(),
            name: format!("{uuid} hunt"),
            enabled,
            latency: latency.map(TimeDelta::seconds),
            suppression: Some(TimeDelta::minutes(90)),
            per_group: true,
            content_hash: "0".repeat(64),
            tags: vec!["mitre:T1059".to_owned()],
        };
        let one = info("a", true, Some(4200));
        let recorded = RecordedHunt::from(&one);
        assert_eq!(
            serde_json::to_value(&recorded).expect("JSON"),
            serde_json::json!({
                "uuid": "a", "name": "a hunt", "enabled": true, "latency_seconds": 4200,
                "suppression_seconds": 5400, "per_group": true, "content_hash": "0".repeat(64),
                "tags": ["mitre:T1059"],
            })
        );
        assert_eq!(HuntInfo::from(recorded), one);
        let unread = info("b", true, None);
        assert_eq!(HuntInfo::from(RecordedHunt::from(&unread)), unread);

        let mut hunts = BTreeMap::new();
        for hunt in [
            info("a", false, Some(9000)),
            info("a", true, Some(60)),
            info("a", true, Some(120)),
            // a tie keeps the first
            HuntInfo {
                name: "a later tie".to_owned(),
                ..info("a", true, Some(120))
            },
            info("b", false, None),
        ] {
            keep_hunt(&mut hunts, hunt);
        }
        assert_eq!(hunts["a"], info("a", true, Some(120)));
        assert_eq!(hunts.len(), 2);
        assert_eq!(
            hunt_latencies(&hunts),
            BTreeMap::from([("a".to_owned(), TimeDelta::seconds(120))])
        );
    }
}
