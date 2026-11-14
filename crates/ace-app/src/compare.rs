//! `ace compare` (PLAN.md 3.3): runs the sample set through this stack, diffs each root's tree
//! against ace3's (3.2's `tools/ace3/trees/reference/`) per module, and writes the differences to
//! a report. From phase 3 on this is the acceptance test for a module port.
//!
//! # Running it
//!
//! It needs what `tests/e2e/run` sets up, so that ace4 sees the world ace3's trees saw: the fixture
//! signatures repository, `tests/e2e/site/overlay.yaml` and the responder. So that script is how
//! to run it:
//!
//! ```text
//! tests/e2e/run --compare             the stack, the whole sample set, then the stack down
//! tests/e2e/run --compare --keep      and leaves the stack up
//! ```
//!
//! The report goes to `target/e2e/compare/`. With the stack left up, the command runs again in a
//! one-off `ace` container, with the checkout's directories mounted and the variables that script
//! gives the stack, and an API key that can submit in `ACE4_API_KEY`, which `ace user create-key` makes.
//! Without `ACE4_SITE`, the overlay has no Splunk instance, and that module would be skipped.
//!
//! ```text
//! export ACE4_STACK=ace4-e2e ACE4_SITE="$PWD/tests/e2e/site"
//! export ACE4_API_KEY=$(docker compose exec -T ace ace user create-key compare --grant alert:create \
//!     | sed -n 's/^token (shown once): //p')
//! docker compose --profile e2e run --rm --no-deps --user "$(id -u):$(id -g)" -e ACE4_API_KEY \
//!     -v "$PWD/samples:/compare/samples:ro" -v "$PWD/tools/ace3/trees:/compare/trees:ro" \
//!     -v "$PWD/target/compare:/compare/report" \
//!     ace ace compare --samples /compare/samples --trees /compare/trees --report /compare/report
//! ```
//!
//! # What it compares
//!
//! Each sample goes to the JSON API's `POST /api/analysis/v1/submit` in the `cli` mode, under the path in the alert
//! and with the `yara_meta` tags `samples/manifest.json` gives it, which is what `make-trees` gives
//! ace3. Once the root is idle, its normal form (`ace_core::normal`) is diffed with ace3's tree by
//! JSON pointer.
//!
//! A module this binary and overlay don't have is *skipped*: its results come out of both forms
//! before the diff, and the report counts them. So a port starts being compared when it's
//! registered, with no change here. What a module did outside its own result, such as a tag on the
//! observable, can't be taken out, because the form doesn't say who added it, so it stays a
//! difference.
//!
//! A difference under `/observables/*/results/<module>` belongs to that module, and any other,
//! such as an observable only one side has, belongs to `(tree)`. Each gets one class, from the
//! first row of `tools/ace3/trees/differences.md` that matches it:
//!
//! - *explained*: a row under any heading but these two. The systems differ on purpose or the
//!   difference is known and harmless.
//! - *unported*: a row under `## Effects of modules not ported`. What a skipped module adds outside
//!   its result. A row here only matches what ace3 has and ace4 doesn't, because a module that
//!   doesn't exist can't have added anything in ace4.
//! - *harness*: a row under `## Harness limits`. The two runs didn't see the same world, so the
//!   difference says nothing about the port.
//! - *unexplained*: no row. A port isn't accepted with any of these (`docs/acceptance.md`).
//!
//! A row's fourth cell narrows it: `ace4 only` matches only what ace3 doesn't have,
//! `ace3 holds <text>` only a value of ace3's with that text in it, `ace4 holds <text>` only a value
//! of ace4's with it, and `same members` only an element of a list that holds the same values on
//! both sides, in another order.
//!
//! Some files have new bytes each run, on both systems: Ghostscript's rewrite of a PDF, `.gs.pdf`,
//! which holds the time and an `/ID` from it, ExifTool's metadata, `.exif/exiftool.out`, which
//! holds the file's path and dates (`VOLATILE_FILES`), and the JavaScript deobfuscator's trace,
//! `deobfuscated-<script>`, whose second line names the script's path in the scanner, under a job id
//! each run makes (`VOLATILE_PREFIXES`). Their sha256s can't match, so before the diff
//! each such file is keyed by its path on both sides, `file:<path>`, and every reference to it
//! follows; what ran on it is then compared like anything else.
//!
//! # What makes it fail
//!
//! Without `--threshold`, differences don't. It exits non-zero when a sample can't be read,
//! submitted or finished in `--sample-timeout`, or its tree can't be read or compared, naming the
//! sample; the report is still written. Samples the manifest says are git-ignored are reported as
//! absent when they aren't on this machine.
//!
//! `--threshold` enforces PLAN.md 3.4's threshold, which `docs/acceptance.md` sets out. It also
//! fails on any unexplained difference, `(tree)` included, on a row of `differences.md` that
//! matched nothing, so the list stays true, and on an absent sample. `--allow-absent` lets samples
//! be absent, for CI, which doesn't have the git-ignored ones.
//!
//! # The report
//!
//! `report.md` is for reading: totals, each module, the unexplained differences by category, each
//! sample, each row. `report.json` has every difference, with the two values.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use ace_core::db::{Db, DbConfig};
use ace_core::normal::{FORM, normal_form};
use ace_core::queue::{FailedTask, failed_tasks, root_is_idle};
use ace_results::differences::{Difference, Listed, ListedDifferences, diff, glob, path_matches};
use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::App;

/// The mode `make-trees` runs ace3's samples in.
const MODE: &str = "cli";
/// The heading in `differences.md` of what a module not ported did outside its result.
const UNPORTED_SECTION: &str = "Effects of modules not ported";
/// The heading in `differences.md` of what differs because the two runs saw different worlds.
const HARNESS_SECTION: &str = "Harness limits";
/// How long a submission may take to be answered.
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(60);
/// How long reading an idle root's tree may take.
const READ_TIMEOUT: Duration = Duration::from_secs(120);
/// How often a root is asked whether it's idle.
const POLL: Duration = Duration::from_millis(250);
/// The most of one side of a difference `report.json` keeps, in characters.
const VALUE_LIMIT: usize = 2000;
/// The most of one side `report.md` shows.
const SHOWN_LIMIT: usize = 120;
/// The group of a difference no module's result holds.
const TREE: &str = "(tree)";

/// Run the sample set through this stack and report how each tree differs from ace3's.
///
/// Run it with `tests/e2e/run --compare`, which sets up the stack it needs and writes the report
/// to target/e2e/compare/. See crates/ace-app/src/compare.rs for running it against a stack that's
/// already up. It needs ACE4_DATABASE_URL, ACE4_OVERLAY as the stack has it, and in ACE4_API_KEY an
/// API key holding alert:create, which `ace user create-key` makes.
///
/// Differences don't fail it unless --threshold says so. It fails when a sample can't be submitted
/// or doesn't finish in time, naming the sample.
#[derive(Args)]
pub struct CompareArgs {
    /// The samples directory, which holds manifest.json.
    #[arg(long, default_value = "samples")]
    samples: PathBuf,
    /// The directory of ace3's trees, which holds differences.md and reference/.
    #[arg(long, default_value = "tools/ace3/trees")]
    trees: PathBuf,
    /// Where report.md and report.json go.
    #[arg(long, default_value = "compare-report")]
    report: PathBuf,
    /// The core's JSON API.
    #[arg(long, default_value = "http://ace:8000")]
    api: String,
    /// Only these samples, by path under the samples directory.
    #[arg(long)]
    only: Vec<String>,
    /// How long one sample may take from its submission to its tree, in seconds.
    #[arg(long, default_value_t = 300)]
    sample_timeout: u64,
    /// How long the whole run may take, in seconds. Samples left at the end fail as not run.
    #[arg(long, default_value_t = 3600)]
    timeout: u64,
    /// Enforce docs/acceptance.md's threshold over the whole sample set: fail on an unexplained
    /// difference in any sample, on a row of differences.md that matched nothing, and on an absent
    /// sample.
    #[arg(long, conflicts_with = "only")]
    threshold: bool,
    /// With --threshold, let the samples the manifest says are git-ignored be absent. It holds
    /// over those compared, and the report says so.
    #[arg(long, requires = "threshold")]
    allow_absent: bool,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    samples: Vec<Sample>,
}

#[derive(Debug, Clone, Deserialize)]
struct Sample {
    path: String,
    sha256: String,
    in_git: bool,
    alert_path: String,
    meta_tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Explained,
    Unported,
    Harness,
    Unexplained,
}

impl Class {
    const ALL: [Class; 4] = [
        Class::Unexplained,
        Class::Harness,
        Class::Unported,
        Class::Explained,
    ];

    fn name(self) -> &'static str {
        match self {
            Class::Explained => "explained",
            Class::Unported => "unported",
            Class::Harness => "harness",
            Class::Unexplained => "unexplained",
        }
    }
}

/// One difference, classified.
#[derive(Debug, Clone)]
struct Found {
    module: String,
    class: Class,
    difference: Difference,
}

/// What one sample came to.
#[derive(Debug, Default)]
struct SampleResult {
    path: String,
    root: Option<Uuid>,
    seconds: f64,
    found: Vec<Found>,
    /// Results of modules not ported, by module.
    skipped: BTreeMap<String, u64>,
    /// Results compared, by module: how many ace3's tree has and how many ace4's.
    compared: BTreeMap<String, (u64, u64)>,
    failed_tasks: Vec<FailedTask>,
}

/// Counts of differences by class.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Counts {
    explained: u64,
    unported: u64,
    harness: u64,
    unexplained: u64,
}

impl Counts {
    fn add(&mut self, class: Class) {
        match class {
            Class::Explained => self.explained += 1,
            Class::Unported => self.unported += 1,
            Class::Harness => self.harness += 1,
            Class::Unexplained => self.unexplained += 1,
        }
    }

    fn get(&self, class: Class) -> u64 {
        match class {
            Class::Explained => self.explained,
            Class::Unported => self.unported,
            Class::Harness => self.harness,
            Class::Unexplained => self.unexplained,
        }
    }

    fn total(&self) -> u64 {
        Class::ALL.iter().map(|c| self.get(*c)).sum()
    }

    fn json(&self) -> Value {
        json!({
            "explained": self.explained,
            "unported": self.unported,
            "harness": self.harness,
            "unexplained": self.unexplained,
        })
    }
}

/// A row's condition on the difference it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
enum When {
    Always,
    /// ace3 has nothing there.
    Ace4Only,
    /// ace3's value holds this text.
    Ace3Holds(String),
    /// ace4's value holds this text.
    Ace4Holds(String),
    /// The list the difference is an element of holds the same values on each side.
    SameMembers,
}

impl When {
    fn parse(row: &Listed) -> Result<When> {
        match row.when.as_deref() {
            None => Ok(When::Always),
            Some("ace4 only") => Ok(When::Ace4Only),
            Some("same members") => Ok(When::SameMembers),
            Some(when) => {
                if let Some(text) = when.strip_prefix("ace3 holds ") {
                    Ok(When::Ace3Holds(text.to_owned()))
                } else if let Some(text) = when.strip_prefix("ace4 holds ") {
                    Ok(When::Ace4Holds(text.to_owned()))
                } else {
                    Err(anyhow!(
                        "the row for {} has the condition {when:?}",
                        row.path
                    ))
                }
            }
        }
    }

    fn holds(&self, difference: &Difference, forms: Option<(&Value, &Value)>) -> bool {
        match self {
            When::Always => true,
            When::SameMembers => {
                forms.is_some_and(|(ace3, ace4)| same_members(ace3, ace4, &difference.path))
            }
            When::Ace4Only => difference.ace3.is_none(),
            When::Ace3Holds(text) => difference
                .ace3
                .as_ref()
                .is_some_and(|value| value.to_string().contains(text)),
            When::Ace4Holds(text) => difference
                .ace4
                .as_ref()
                .is_some_and(|value| value.to_string().contains(text)),
        }
    }
}

/// The rows of `differences.md`, with what each has matched so far.
struct Rows {
    listed: Vec<Listed>,
    when: Vec<When>,
    matched: Vec<u64>,
}

impl Rows {
    fn new(listed: ListedDifferences) -> Result<Rows> {
        Ok(Rows {
            matched: vec![0; listed.rows.len()],
            when: listed.rows.iter().map(When::parse).collect::<Result<_>>()?,
            listed: listed.rows,
        })
    }

    fn class_of(row: &Listed) -> Class {
        match row.section.as_deref() {
            Some(UNPORTED_SECTION) => Class::Unported,
            Some(HARNESS_SECTION) => Class::Harness,
            _ => Class::Explained,
        }
    }

    /// The class of a difference: the first row's that matches. Every row that matches counts as
    /// used, so a row isn't called stale because an earlier one also covers it.
    #[cfg(test)]
    fn classify(&mut self, sample: &str, difference: &Difference) -> Class {
        self.classify_in(sample, difference, None)
    }

    /// `classify`, with the two forms, which `same members` reads.
    fn classify_in(
        &mut self,
        sample: &str,
        difference: &Difference,
        forms: Option<(&Value, &Value)>,
    ) -> Class {
        let mut class = None;
        for (i, row) in self.listed.iter().enumerate() {
            let row_class = Rows::class_of(row);
            // what's missing from ace4 is all a module ace4 doesn't have can explain
            if row_class == Class::Unported && difference.ace4.is_some() {
                continue;
            }
            if self.when[i].holds(difference, forms)
                && glob(&row.dumps, sample)
                && path_matches(&row.path, &difference.path)
            {
                self.matched[i] += 1;
                class.get_or_insert(row_class);
            }
        }
        class.unwrap_or(Class::Unexplained)
    }

    /// Rows that matched nothing, leaving out those that cover only samples not compared.
    fn stale(&self, compared: &[String]) -> Vec<&Listed> {
        self.listed
            .iter()
            .zip(&self.matched)
            .filter(|(row, matched)| {
                **matched == 0 && compared.iter().any(|sample| glob(&row.dumps, sample))
            })
            .map(|(row, _)| row)
            .collect()
    }
}

/// Whether the difference at `path` is an element of a list that holds the same values, counted,
/// in both forms.
fn same_members(ace3: &Value, ace4: &Value, path: &str) -> bool {
    let Some((parent, index)) = path.rsplit_once('/') else {
        return false;
    };
    if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let (Some(Value::Array(a)), Some(Value::Array(b))) =
        (ace3.pointer(parent), ace4.pointer(parent))
    else {
        return false;
    };
    let mut a: Vec<String> = a.iter().map(Value::to_string).collect();
    let mut b: Vec<String> = b.iter().map(Value::to_string).collect();
    a.sort();
    b.sort();
    a == b
}

/// Takes the results of modules not in `ported` out of a form, returning how many by module.
fn remove_skipped(form: &mut Value, ported: &BTreeSet<String>) -> BTreeMap<String, u64> {
    let mut skipped = BTreeMap::new();
    let Some(observables) = form["observables"].as_object_mut() else {
        return skipped;
    };
    for observable in observables.values_mut() {
        if let Some(results) = observable["results"].as_object_mut() {
            results.retain(|module, _| {
                let keep = ported.contains(module);
                if !keep {
                    *skipped.entry(module.clone()).or_insert(0) += 1;
                }
                keep
            });
        }
    }
    skipped
}

/// How many results a form holds, by module.
fn results_by_module(form: &Value) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    let observables = form["observables"]
        .as_object()
        .into_iter()
        .flat_map(|o| o.values());
    for results in observables.filter_map(|observable| observable["results"].as_object()) {
        for module in results.keys() {
            *counts.entry(module.clone()).or_insert(0) += 1;
        }
    }
    counts
}

/// The module a JSON pointer into a form belongs to.
fn module_of(path: &str) -> &str {
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    match segments.as_slice() {
        ["observables", _, "results", module, ..] => module,
        _ => TREE,
    }
}

/// A JSON pointer with what varies by sample taken out, so like differences group together:
/// an observable's value, a file's path, an array's index, a relationship's target and a
/// detection's text.
fn category(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let mut out = String::new();
    for (i, segment) in segments.iter().enumerate() {
        let previous = if i > 0 { segments[i - 1] } else { "" };
        let shown = match (previous, i) {
            ("observables", 1) => format!(
                "{}:*",
                segment.split_once(':').map_or(*segment, |(kind, _)| kind)
            ),
            ("paths", 3) | ("detections", 3) => "*".to_owned(),
            ("relationships", 3) => format!(
                "{} {}:*",
                segment.split_once(' ').map_or(*segment, |(kind, _)| kind),
                segment
                    .split_once(' ')
                    .and_then(|(_, target)| target.split_once(':'))
                    .map_or("", |(kind, _)| kind)
            ),
            _ if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) => {
                "*".to_owned()
            }
            _ => (*segment).to_owned(),
        };
        out.push('/');
        out.push_str(&shown);
    }
    out
}

/// The ends of the paths of files whose bytes differ from run to run on both systems: Ghostscript's
/// rewrite of a PDF (`pdf.py`), and ExifTool's pretty-printed metadata (`exif.py`).
const VOLATILE_FILES: &[&str] = &[".gs.pdf", ".exif/exiftool.out"];

/// The starts of the names of files whose bytes differ from run to run on both systems: the
/// JavaScript deobfuscator's trace, whose `// source:` line holds `/js-deobfuscator/input/<job id>/`
/// (PLAN.md 7.7, js_deobfuscator/harness.js).
const VOLATILE_PREFIXES: &[&str] = &["deobfuscated-"];

/// Whether the file at `path` is one whose bytes differ from run to run.
fn is_volatile(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    VOLATILE_FILES.iter().any(|end| path.ends_with(end))
        || VOLATILE_PREFIXES
            .iter()
            .any(|start| name.starts_with(start))
}

/// Keys each file observable whose every path is volatile (`is_volatile`) by its first path,
/// `file:<path>`, in place of its sha256, and every reference to it in the form with it.
fn key_volatile_files(form: &mut Value) -> Result<()> {
    let Some(observables) = form["observables"].as_object() else {
        return Ok(());
    };
    let mut renames: Vec<(String, String)> = Vec::new();
    for (key, observable) in observables {
        if !key.starts_with("file:") {
            continue;
        }
        let Some(paths) = observable["paths"].as_object() else {
            continue;
        };
        let mut names: Vec<&String> = paths.keys().collect();
        names.sort();
        let volatile = !names.is_empty() && names.iter().all(|path| is_volatile(path));
        if volatile {
            renames.push((key.clone(), format!("file:{}", names[0])));
        }
    }
    if renames.is_empty() {
        return Ok(());
    }
    // the key is in the form's text as a key, a relationship's and a redirection, always whole
    let mut text = serde_json::to_string(form)?;
    for (from, to) in &renames {
        let escaped = serde_json::to_string(to)?;
        let escaped = &escaped[1..escaped.len() - 1];
        for (before, after) in [("\"", "\""), (" ", "\"")] {
            text = text.replace(
                &format!("{before}{from}{after}"),
                &format!("{before}{escaped}{after}"),
            );
        }
    }
    *form = serde_json::from_str(&text)?;
    Ok(())
}

/// Diffs one sample's two forms.
fn compare_forms(
    sample: &str,
    mut ace3: Value,
    mut ace4: Value,
    ported: &BTreeSet<String>,
    rows: &mut Rows,
) -> Result<SampleResult> {
    for (who, form) in [("ace3's tree", &ace3), ("ace4's tree", &ace4)] {
        if form["form"] != json!(FORM) {
            bail!(
                "{who} of {sample} is in form {}, and this binary compares form {FORM}",
                form["form"]
            );
        }
    }
    let mut skipped = remove_skipped(&mut ace3, ported);
    key_volatile_files(&mut ace3)?;
    key_volatile_files(&mut ace4)?;
    for (module, count) in remove_skipped(&mut ace4, ported) {
        *skipped.entry(module).or_insert(0) += count;
    }
    let mut compared: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for (module, count) in results_by_module(&ace3) {
        compared.entry(module).or_default().0 = count;
    }
    for (module, count) in results_by_module(&ace4) {
        compared.entry(module).or_default().1 = count;
    }
    let found = diff(&ace3, &ace4)
        .into_iter()
        .map(|difference| Found {
            module: module_of(&difference.path).to_owned(),
            class: rows.classify_in(sample, &difference, Some((&ace3, &ace4))),
            difference,
        })
        .collect();
    Ok(SampleResult {
        path: sample.to_owned(),
        found,
        skipped,
        compared,
        ..SampleResult::default()
    })
}

/// A multipart form with the submission and the sample, as `POST /api/analysis/v1/submit` takes it.
fn submission_form(sample: &Sample, bytes: &[u8], boundary: &str) -> Result<Vec<u8>> {
    if sample.alert_path.contains(['"', '\r', '\n', '\\']) {
        bail!(
            "the alert path {:?} doesn't fit in a form's file name",
            sample.alert_path
        );
    }
    let analysis = json!({
        "description": format!("ace compare: {}", sample.path),
        "analysis_mode": MODE,
        "file_yara_meta": {&sample.alert_path: sample.meta_tags},
    });
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"analysis\"\r\n\r\n{analysis}\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n",
        sample.alert_path
    )
    .into_bytes();
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(body)
}

/// Where the run gets the stack from.
struct Stack {
    db: Db,
    client: reqwest::Client,
    api: String,
    token: String,
}

impl Stack {
    async fn submit(&self, sample: &Sample, bytes: &[u8]) -> Result<Uuid> {
        let boundary = format!("ace-compare-{}", Uuid::new_v4().simple());
        let response = self
            .client
            .post(format!("{}/api/analysis/v1/submit", self.api))
            .bearer_auth(&self.token)
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(submission_form(sample, bytes, &boundary)?)
            .timeout(SUBMIT_TIMEOUT)
            .send()
            .await
            .context("the submission got no answer")?;
        let status = response.status();
        let text = response.text().await.context("reading the answer")?;
        if !status.is_success() {
            bail!("the submission answered {status}: {text}");
        }
        let answer: Value = serde_json::from_str(&text).context("reading the answer")?;
        answer["id"]
            .as_str()
            .and_then(|id| id.parse().ok())
            .ok_or_else(|| anyhow!("the submission's answer has no id: {text}"))
    }

    /// Submits a sample, waits until its root is idle and returns the root and its normal form.
    async fn run_sample(
        &self,
        sample: &Sample,
        bytes: &[u8],
        limit: Duration,
    ) -> Result<(Uuid, Value)> {
        let started = Instant::now();
        let root = self.submit(sample, bytes).await?;
        let waited = tokio::time::timeout(limit.saturating_sub(started.elapsed()), async {
            loop {
                if root_is_idle(&self.db, root).await? {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(POLL).await;
            }
        })
        .await;
        match waited {
            Ok(result) => result.with_context(|| format!("waiting for root {root}"))?,
            Err(_) => bail!(
                "root {root} didn't finish within {} seconds",
                limit.as_secs()
            ),
        }
        let form = tokio::time::timeout(READ_TIMEOUT, normal_form(self.db.pool(), root))
            .await
            .with_context(|| format!("reading root {root}'s tree took too long"))??
            .ok_or_else(|| anyhow!("root {root} is gone"))?;
        Ok((root, form))
    }
}

/// One line of a value, cut to `limit` characters.
fn shown(value: &Option<Value>, limit: usize) -> String {
    let Some(value) = value else {
        return "(nothing)".to_owned();
    };
    let text = value.to_string();
    if text.chars().count() > limit {
        format!("{}...", text.chars().take(limit).collect::<String>())
    } else {
        text
    }
}

/// A value for `report.json`: itself, or its text cut to `VALUE_LIMIT` when it's long.
fn kept(value: &Option<Value>) -> Value {
    match value {
        None => Value::Null,
        Some(value) if value.to_string().chars().count() <= VALUE_LIMIT => value.clone(),
        Some(_) => Value::String(shown(value, VALUE_LIMIT)),
    }
}

/// A sample that couldn't be run, and why.
#[derive(Debug)]
struct Failure {
    sample: String,
    why: String,
}

/// The whole run, for the report.
struct Outcome {
    ace3_commit: String,
    ported: BTreeSet<String>,
    absent: Vec<String>,
    results: Vec<SampleResult>,
    failures: Vec<Failure>,
    rows: Rows,
    seconds: f64,
    allow_absent: bool,
}

impl Outcome {
    fn compared(&self) -> Vec<String> {
        self.results.iter().map(|r| r.path.clone()).collect()
    }

    fn totals(&self) -> Counts {
        let mut counts = Counts::default();
        self.results
            .iter()
            .flat_map(|r| &r.found)
            .for_each(|f| counts.add(f.class));
        counts
    }

    /// Counts by module.
    fn modules(&self) -> BTreeMap<String, Counts> {
        let mut modules: BTreeMap<String, Counts> = BTreeMap::new();
        for module in &self.ported {
            modules.entry(module.clone()).or_default();
        }
        for found in self.results.iter().flat_map(|r| &r.found) {
            modules
                .entry(found.module.clone())
                .or_default()
                .add(found.class);
        }
        modules
    }

    /// Skipped results by module.
    fn skipped(&self) -> BTreeMap<String, u64> {
        let mut skipped = BTreeMap::new();
        for (module, count) in self.results.iter().flat_map(|r| &r.skipped) {
            *skipped.entry(module.clone()).or_insert(0) += count;
        }
        skipped
    }

    /// What was compared of each module on this run: results and the samples that had one, each as
    /// (ace3's, ace4's). A module with no results on ace3's side was compared with nothing.
    fn compared_by_module(&self) -> BTreeMap<String, [u64; 4]> {
        let mut modules: BTreeMap<String, [u64; 4]> = BTreeMap::new();
        for module in &self.ported {
            modules.entry(module.clone()).or_default();
        }
        for result in &self.results {
            for (module, (ace3, ace4)) in &result.compared {
                let entry = modules.entry(module.clone()).or_default();
                entry[0] += ace3;
                entry[1] += ace4;
                entry[2] += u64::from(*ace3 > 0);
                entry[3] += u64::from(*ace4 > 0);
            }
        }
        modules
    }

    /// The differences of one class by category, most first, with how many samples each is in.
    fn categories(&self, class: Class) -> Vec<(String, u64, usize)> {
        let mut categories: BTreeMap<String, (u64, BTreeSet<&str>)> = BTreeMap::new();
        for result in &self.results {
            for found in result.found.iter().filter(|f| f.class == class) {
                let entry = categories
                    .entry(category(&found.difference.path))
                    .or_default();
                entry.0 += 1;
                entry.1.insert(&result.path);
            }
        }
        let mut categories: Vec<(String, u64, usize)> = categories
            .into_iter()
            .map(|(category, (count, samples))| (category, count, samples.len()))
            .collect();
        categories.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        categories
    }

    fn to_json(&self) -> Value {
        let samples: Vec<Value> = self
            .results
            .iter()
            .map(|result| {
                let mut by_module: BTreeMap<&str, Counts> = BTreeMap::new();
                for found in &result.found {
                    by_module.entry(&found.module).or_default().add(found.class);
                }
                json!({
                    "sample": result.path,
                    "root": result.root,
                    "seconds": result.seconds,
                    "skipped": result.skipped,
                    "failed_tasks": result.failed_tasks.iter().map(|t| json!({
                        "module": t.module, "observable": t.observable, "error": t.error,
                    })).collect::<Vec<_>>(),
                    "modules": by_module.iter()
                        .map(|(module, counts)| ((*module).to_owned(), counts.json()))
                        .collect::<Map<_, _>>(),
                    "differences": result.found.iter().map(|f| json!({
                        "module": f.module,
                        "class": f.class.name(),
                        "path": f.difference.path,
                        "ace3": kept(&f.difference.ace3),
                        "ace4": kept(&f.difference.ace4),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        json!({
            "ace3_commit": self.ace3_commit,
            "ported": self.ported,
            "compared": self.results.len(),
            "absent": self.absent,
            "failed": self.failures.iter()
                .map(|f| json!({"sample": f.sample, "why": f.why}))
                .collect::<Vec<_>>(),
            "seconds": self.seconds,
            "threshold": {
                "unmet": threshold_failures(self),
                "allow_absent": self.allow_absent,
            },
            "totals": self.totals().json(),
            "modules": self.modules().iter()
                .map(|(module, counts)| (module.clone(), counts.json()))
                .collect::<Map<_, _>>(),
            "skipped": self.skipped(),
            "compared_by_module": self.compared_by_module().iter().map(|(module, n)| {
                (module.clone(), json!({
                    "ace3_results": n[0], "ace4_results": n[1],
                    "ace3_samples": n[2], "ace4_samples": n[3],
                }))
            }).collect::<Map<_, _>>(),
            "rows": self.rows.listed.iter().zip(&self.rows.matched).map(|(row, matched)| json!({
                "samples": row.dumps,
                "path": row.path,
                "section": row.section,
                "matched": matched,
            })).collect::<Vec<_>>(),
            "stale_rows": self.rows.stale(&self.compared()).iter()
                .map(|row| json!({"samples": row.dumps, "path": row.path}))
                .collect::<Vec<_>>(),
            "samples": samples,
        })
    }

    fn to_markdown(&self) -> Result<String, std::fmt::Error> {
        let mut out = String::new();
        let totals = self.totals();
        writeln!(out, "# ace compare\n")?;
        writeln!(
            out,
            "ace3 at `{}`; ace4's modules here: {}.\n",
            self.ace3_commit,
            self.ported
                .iter()
                .map(|m| format!("`{m}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "{} samples compared, {} absent, {} failed, in {:.0} seconds. {} differences: {} \
             unexplained, {} from harness limits, {} from modules not ported, {} explained.\n",
            self.results.len(),
            self.absent.len(),
            self.failures.len(),
            self.seconds,
            totals.total(),
            totals.unexplained,
            totals.harness,
            totals.unported,
            totals.explained,
        )?;
        let unmet = threshold_failures(self);
        if unmet.is_empty() && self.absent.is_empty() {
            writeln!(
                out,
                "The threshold (`docs/acceptance.md`) is met over the whole sample set.\n"
            )?;
        } else if unmet.is_empty() {
            writeln!(
                out,
                "The threshold (`docs/acceptance.md`) is met over the {} samples compared. It says \
                 nothing about the {} absent.\n",
                self.results.len(),
                self.absent.len()
            )?;
        } else {
            writeln!(
                out,
                "The threshold (`docs/acceptance.md`) isn't met, for {} reasons.\n",
                unmet.len()
            )?;
        }
        if !self.failures.is_empty() {
            writeln!(out, "## Samples that failed\n")?;
            for failure in &self.failures {
                writeln!(out, "- `{}`: {}", failure.sample, failure.why)?;
            }
            out.push('\n');
        }
        if !self.absent.is_empty() {
            writeln!(out, "## Samples absent from this machine\n")?;
            for sample in &self.absent {
                writeln!(out, "- `{sample}`")?;
            }
            out.push('\n');
        }

        writeln!(out, "## By module\n")?;
        writeln!(
            out,
            "`{TREE}` is everything outside a module's result, such as an observable only one side \
             has or a tag on an observable.\n"
        )?;
        writeln!(
            out,
            "| Module | Unexplained | Harness | Unported | Explained |"
        )?;
        writeln!(out, "|---|---:|---:|---:|---:|")?;
        for (module, counts) in self.modules() {
            writeln!(
                out,
                "| `{module}` | {} | {} | {} | {} |",
                counts.unexplained, counts.harness, counts.unported, counts.explained
            )?;
        }
        out.push('\n');

        writeln!(out, "## Results compared\n")?;
        writeln!(
            out,
            "A module with no results from ace3 here was compared with nothing, whatever the \
             differences above say.\n"
        )?;
        writeln!(
            out,
            "| Module | ace3's results | ace4's results | Samples with one in ace3 | In ace4 |\n\
             |---|---:|---:|---:|---:|"
        )?;
        for (module, n) in self.compared_by_module() {
            writeln!(
                out,
                "| `{module}` | {} | {} | {} | {} |",
                n[0], n[1], n[2], n[3]
            )?;
        }
        out.push('\n');

        writeln!(out, "## Modules skipped\n")?;
        writeln!(
            out,
            "ace3's trees have results from these, and ace4 has no such module, so they aren't \
             compared.\n"
        )?;
        writeln!(out, "| Module | Results |\n|---|---:|")?;
        for (module, count) in self.skipped() {
            writeln!(out, "| `{module}` | {count} |")?;
        }
        out.push('\n');

        for (class, title) in [
            (Class::Unexplained, "Unexplained differences by category"),
            (Class::Harness, "Harness limits by category"),
            (Class::Unported, "Effects of modules not ported by category"),
        ] {
            writeln!(out, "## {title}\n")?;
            writeln!(out, "| Differences | Samples | Category |\n|---:|---:|---|")?;
            for (category, count, samples) in self.categories(class) {
                writeln!(
                    out,
                    "| {count} | {samples} | `{}` |",
                    escape_cell(&category)
                )?;
            }
            out.push('\n');
        }

        let stale = self.rows.stale(&self.compared());
        writeln!(out, "## Rows of differences.md\n")?;
        if stale.is_empty() {
            writeln!(
                out,
                "Every row matched something, or covers only samples not compared.\n"
            )?;
        } else {
            writeln!(out, "These matched nothing:\n")?;
            for row in stale {
                writeln!(out, "- `{}` `{}`", row.dumps, row.path)?;
            }
            out.push('\n');
        }
        writeln!(out, "| Matched | Samples | Path |\n|---:|---|---|")?;
        for (row, matched) in self.rows.listed.iter().zip(&self.rows.matched) {
            writeln!(
                out,
                "| {matched} | `{}` | `{}` |",
                escape_cell(&row.dumps),
                escape_cell(&row.path)
            )?;
        }
        out.push('\n');

        writeln!(out, "## By sample\n")?;
        for result in &self.results {
            let mut by_module: BTreeMap<&str, Counts> = BTreeMap::new();
            for found in &result.found {
                by_module.entry(&found.module).or_default().add(found.class);
            }
            let mut counts = Counts::default();
            result.found.iter().for_each(|f| counts.add(f.class));
            writeln!(
                out,
                "### `{}`\n\n{} differences, {} unexplained, in {:.1} seconds.\n",
                result.path,
                counts.total(),
                counts.unexplained,
                result.seconds
            )?;
            if !by_module.is_empty() {
                writeln!(
                    out,
                    "| Module | Unexplained | Harness | Unported | Explained |\n|---|---:|---:|---:|---:|"
                )?;
                for (module, counts) in by_module {
                    writeln!(
                        out,
                        "| `{module}` | {} | {} | {} | {} |",
                        counts.unexplained, counts.harness, counts.unported, counts.explained
                    )?;
                }
                out.push('\n');
            }
            for task in &result.failed_tasks {
                writeln!(
                    out,
                    "- Task `{}` on `{}`: {}",
                    task.module,
                    task.observable,
                    shown(&Some(json!(task.error)), SHOWN_LIMIT * 2)
                )?;
            }
            if !result.failed_tasks.is_empty() {
                out.push('\n');
            }
            for found in result
                .found
                .iter()
                .filter(|f| f.class == Class::Unexplained)
            {
                writeln!(
                    out,
                    "- `{}`\n  - ace3: `{}`\n  - ace4: `{}`",
                    found.difference.path,
                    shown(&found.difference.ace3, SHOWN_LIMIT),
                    shown(&found.difference.ace4, SHOWN_LIMIT)
                )?;
            }
            out.push('\n');
        }
        Ok(out)
    }
}

fn escape_cell(text: &str) -> String {
    text.replace('|', "\\|")
}

/// Why the threshold isn't met (`docs/acceptance.md`), beyond the samples that failed to run, which
/// fail any run.
fn threshold_failures(outcome: &Outcome) -> Vec<String> {
    let mut failures = Vec::new();
    for result in &outcome.results {
        for found in result
            .found
            .iter()
            .filter(|f| f.class == Class::Unexplained)
        {
            failures.push(format!(
                "{}: not in differences.md: {}\n    ace3: {}\n    ace4: {}",
                result.path,
                found.difference.path,
                shown(&found.difference.ace3, 300),
                shown(&found.difference.ace4, 300)
            ));
        }
    }
    for row in outcome.rows.stale(&outcome.compared()) {
        failures.push(format!(
            "a row of differences.md matched nothing: {} {}",
            row.dumps, row.path
        ));
    }
    if !outcome.allow_absent {
        for sample in &outcome.absent {
            failures.push(format!(
                "{sample} is absent, so the threshold can't hold over the whole sample set"
            ));
        }
    }
    failures
}

fn read_json(path: &Path) -> Result<Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("reading {}", path.display()))
}

pub fn run(app: &App, args: CompareArgs) -> Result<ExitCode> {
    let overlay = crate::cli::overlay()?;
    let components = crate::cli::components(&app.registry(), &overlay)?;
    // SVS's hook is on in every core (`ace serve`), whatever the overlay says
    let hooks = ace_core::hooks::Hooks::from_section(&overlay.hooks)
        .context("the overlay's hooks section")?
        .with_svs(ace_core::svs::attribution::HookConfig::default());
    // the core's hooks that are on count as ported, as a module the binary has does
    let ported: BTreeSet<String> = components
        .into_iter()
        .map(|c| c.key)
        .chain(hooks.names().into_iter().map(str::to_owned))
        .collect();

    let manifest_path = args.samples.join("manifest.json");
    let manifest: Manifest = serde_json::from_value(read_json(&manifest_path)?)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let unknown: Vec<&String> = args
        .only
        .iter()
        .filter(|name| !manifest.samples.iter().any(|s| &s.path == *name))
        .collect();
    if !unknown.is_empty() {
        bail!("not in the manifest: {unknown:?}");
    }
    let rows =
        ListedDifferences::load(&args.trees.join("differences.md")).map_err(|e| anyhow!("{e}"))?;
    let rows = Rows::new(rows)?;
    let reference = args.trees.join("reference");
    let ace3_commit = read_json(&reference.join("index.json"))?["ace3_commit"]
        .as_str()
        .unwrap_or("unknown")
        .to_owned();
    // so a report directory that can't be made fails before the run
    std::fs::create_dir_all(&args.report)
        .with_context(|| format!("making {}", args.report.display()))?;

    let token = std::env::var("ACE4_API_KEY").context(
        "ACE4_API_KEY isn't set: make a key with `ace user create-key NAME --grant alert:create`",
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async {
        let stack = Stack {
            db: Db::connect(&DbConfig::from_env("ace")?)
                .await
                .context("connecting to Postgres")?,
            // the API is a service of this stack, whatever proxy the Docker client gave containers
            client: reqwest::Client::builder()
                .no_proxy()
                .build()
                .context("making the HTTP client")?,
            api: args.api.trim_end_matches('/').to_owned(),
            token,
        };
        let mut outcome = Outcome {
            ace3_commit,
            ported,
            absent: Vec::new(),
            results: Vec::new(),
            failures: Vec::new(),
            rows,
            seconds: 0.0,
            allow_absent: args.allow_absent,
        };
        let started = Instant::now();
        let deadline = Duration::from_secs(args.timeout);
        let sample_limit = Duration::from_secs(args.sample_timeout);
        let selected: Vec<&Sample> = manifest
            .samples
            .iter()
            .filter(|s| args.only.is_empty() || args.only.contains(&s.path))
            .collect();
        for (i, sample) in selected.iter().enumerate() {
            let left = deadline.saturating_sub(started.elapsed());
            if left.is_zero() {
                outcome.failures.push(Failure {
                    sample: sample.path.clone(),
                    why: format!("not run: the run passed its limit of {} seconds", args.timeout),
                });
                continue;
            }
            let file = args.samples.join(&sample.path);
            if !sample.in_git && !file.exists() {
                println!("[{}/{}] {} is absent", i + 1, selected.len(), sample.path);
                outcome.absent.push(sample.path.clone());
                continue;
            }
            let sample_started = Instant::now();
            match compare_sample(&stack, sample, &file, &reference, sample_limit.min(left), &mut outcome)
                .await
            {
                Ok(mut result) => {
                    result.seconds = sample_started.elapsed().as_secs_f64();
                    let mut counts = Counts::default();
                    result.found.iter().for_each(|f| counts.add(f.class));
                    println!(
                        "[{}/{}] {}: {} differences, {} unexplained, {:.1}s",
                        i + 1,
                        selected.len(),
                        sample.path,
                        counts.total(),
                        counts.unexplained,
                        result.seconds
                    );
                    outcome.results.push(result);
                }
                Err(e) => {
                    let why = format!("{e:#}");
                    println!("[{}/{}] {} FAILED: {why}", i + 1, selected.len(), sample.path);
                    outcome.failures.push(Failure {
                        sample: sample.path.clone(),
                        why,
                    });
                }
            }
        }
        outcome.seconds = started.elapsed().as_secs_f64();
        write_report(&args.report, &outcome)?;
        let totals = outcome.totals();
        println!(
            "{} samples compared, {} absent, {} failed. {} differences: {} unexplained, {} harness, \
             {} unported, {} explained. The report is in {}.",
            outcome.results.len(),
            outcome.absent.len(),
            outcome.failures.len(),
            totals.total(),
            totals.unexplained,
            totals.harness,
            totals.unported,
            totals.explained,
            args.report.display()
        );
        let unmet = if args.threshold {
            threshold_failures(&outcome)
        } else {
            Vec::new()
        };
        for line in &unmet {
            eprintln!("ace compare: {line}");
        }
        for failure in &outcome.failures {
            eprintln!("ace compare: {}: {}", failure.sample, failure.why);
        }
        if outcome.failures.is_empty() && unmet.is_empty() {
            Ok(ExitCode::SUCCESS)
        } else {
            Ok(ExitCode::FAILURE)
        }
    })
}

async fn compare_sample(
    stack: &Stack,
    sample: &Sample,
    file: &Path,
    reference: &Path,
    limit: Duration,
    outcome: &mut Outcome,
) -> Result<SampleResult> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let sha256 = ace_results::Sha256(Sha256::digest(&bytes).into()).to_hex();
    if sha256 != sample.sha256 {
        bail!(
            "{} has sha256 {sha256}, and the manifest says {}",
            file.display(),
            sample.sha256
        );
    }
    let ace3 = read_json(&reference.join(format!("{}.json", sample.path)))?;
    let (root, ace4) = stack.run_sample(sample, &bytes, limit).await?;
    let mut result = compare_forms(&sample.path, ace3, ace4, &outcome.ported, &mut outcome.rows)?;
    result.root = Some(root);
    result.failed_tasks = failed_tasks(&stack.db, root)
        .await
        .with_context(|| format!("reading root {root}'s failed tasks"))?;
    Ok(result)
}

fn write_report(dir: &Path, outcome: &Outcome) -> Result<()> {
    let json_path = dir.join("report.json");
    std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&outcome.to_json())? + "\n",
    )
    .with_context(|| format!("writing {}", json_path.display()))?;
    let markdown_path = dir.join("report.md");
    std::fs::write(&markdown_path, outcome.to_markdown()?)
        .with_context(|| format!("writing {}", markdown_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed(rows: &[(&str, &str, Option<&str>)]) -> Rows {
        Rows::new(ListedDifferences {
            rows: rows
                .iter()
                .map(|(dumps, path, section)| Listed {
                    dumps: (*dumps).to_owned(),
                    path: (*path).to_owned(),
                    why: String::new(),
                    section: section.map(str::to_owned),
                    when: None,
                })
                .collect(),
        })
        .expect("rows with no conditions")
    }

    fn ported(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    fn form(observables: Value) -> Value {
        json!({"form": FORM, "observables": observables})
    }

    #[test]
    fn a_module_not_ported_is_skipped_and_counted() {
        let ace3 = form(json!({"file:a": {"results": {
            "file_type": {"summary": "zip"},
            "archive": {"summary": "same"},
        }}}));
        let ace4 = form(json!({"file:a": {"results": {"archive": {"summary": "same"}}}}));
        let mut rows = listed(&[]);
        let result =
            compare_forms("s", ace3, ace4, &ported(&["archive"]), &mut rows).expect("compares");
        assert!(result.found.is_empty(), "{:?}", result.found);
        assert_eq!(
            result.skipped,
            BTreeMap::from([("file_type".to_owned(), 1)])
        );
    }

    #[test]
    fn a_ported_modules_results_are_counted_on_each_side() {
        let ace3 = json!({"form": 1, "observables": {
            "file:a": {"results": {"archive": {}, "file_type": {}}},
            "file:b": {"results": {"archive": {}}},
        }});
        let ace4 = json!({"form": 1, "observables": {"file:a": {"results": {"archive": {}}}}});
        let mut rows = listed(&[]);
        let result =
            compare_forms("s", ace3, ace4, &ported(&["archive"]), &mut rows).expect("compares");
        assert_eq!(
            result.compared,
            BTreeMap::from([("archive".to_owned(), (2, 1))])
        );
    }

    #[test]
    fn a_ported_module_missing_from_ace4_is_its_difference() {
        let ace3 = form(json!({"file:a": {"results": {"archive": {"summary": "x"}}}}));
        let ace4 = form(json!({"file:a": {"results": {}}}));
        let mut rows = listed(&[]);
        let result =
            compare_forms("s", ace3, ace4, &ported(&["archive"]), &mut rows).expect("compares");
        assert_eq!(result.found.len(), 1);
        assert_eq!(result.found[0].module, "archive");
        assert_eq!(result.found[0].class, Class::Unexplained);
    }

    #[test]
    fn a_tree_of_another_form_fails_rather_than_compares() {
        let error = compare_forms(
            "s",
            json!({"form": FORM + 1, "observables": {}}),
            form(json!({})),
            &ported(&[]),
            &mut listed(&[]),
        )
        .expect_err("another form");
        assert!(error.to_string().contains("ace3's tree of s"), "{error}");
    }

    #[test]
    fn each_difference_gets_its_row_s_class() {
        let mut rows = listed(&[
            ("*", "/observables/*/tags/zip", Some(UNPORTED_SECTION)),
            (
                "*",
                "/observables/*/results/rdap_analyzer/**",
                Some(HARNESS_SECTION),
            ),
            ("*", "/observables/*/results/archive/details/x", None),
        ]);
        let ace3 = form(json!({"file:a": {
            "tags": {"zip": true},
            "results": {
                "rdap_analyzer": {"summary": "failed"},
                "archive": {"details": {"x": 1, "y": 1}},
            },
        }}));
        let ace4 = form(json!({"file:a": {
            "tags": {},
            "results": {
                "rdap_analyzer": {"summary": "404"},
                "archive": {"details": {"x": 2, "y": 2}},
            },
        }}));
        let result = compare_forms(
            "s",
            ace3,
            ace4,
            &ported(&["archive", "rdap_analyzer"]),
            &mut rows,
        )
        .expect("compares");
        let classes: BTreeMap<&str, (Class, &str)> = result
            .found
            .iter()
            .map(|f| (f.difference.path.as_str(), (f.class, f.module.as_str())))
            .collect();
        assert_eq!(
            classes,
            BTreeMap::from([
                ("/observables/file:a/tags/zip", (Class::Unported, TREE)),
                (
                    "/observables/file:a/results/rdap_analyzer/summary",
                    (Class::Harness, "rdap_analyzer")
                ),
                (
                    "/observables/file:a/results/archive/details/x",
                    (Class::Explained, "archive")
                ),
                (
                    "/observables/file:a/results/archive/details/y",
                    (Class::Unexplained, "archive")
                ),
            ])
        );
    }

    #[test]
    fn a_module_not_ported_only_explains_what_ace4_lacks() {
        let mut rows = listed(&[("*", "/observables/*/tags/zip", Some(UNPORTED_SECTION))]);
        let ace3 = form(json!({"file:a": {"tags": {}}}));
        let ace4 = form(json!({"file:a": {"tags": {"zip": true}}}));
        let result = compare_forms("s", ace3, ace4, &ported(&[]), &mut rows).expect("compares");
        assert_eq!(result.found[0].class, Class::Unexplained);
        assert_eq!(rows.matched, [0]);
    }

    /// A Ghostscript rewrite and ExifTool's metadata are keyed by their paths, with every reference to
    /// them, so the two sides' copies, with their own bytes, are compared as one file.
    #[test]
    fn a_volatile_file_is_keyed_by_its_path() {
        let mut form = json!({"observables": {
            "file:aaaa": {"paths": {"x.pdf": {}}},
            "file:bbbb": {
                "paths": {"x.pdf.gs.pdf": {"type=document.pdf.rendered": true}},
                "redirection": "file:aaaa",
                "relationships": {"extracted_from file:aaaa": true},
                "results": {"file_hash_analyzer": {"details": {"sha256": "bbbb"}}},
            },
            "md5:cccc": {"relationships": {"is_hash_of file:bbbb": true}},
            "file:dddd": {"paths": {"x.pdf.exif/exiftool.out": {}}, "redirection": "file:bbbb"},
        }});
        key_volatile_files(&mut form).expect("rekeyed");
        let observables = form["observables"].as_object().expect("observables");
        let mut keys: Vec<&String> = observables.keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "file:aaaa",
                "file:x.pdf.exif/exiftool.out",
                "file:x.pdf.gs.pdf",
                "md5:cccc"
            ]
        );
        assert_eq!(
            form["observables"]["md5:cccc"]["relationships"],
            json!({"is_hash_of file:x.pdf.gs.pdf": true})
        );
        assert_eq!(
            form["observables"]["file:x.pdf.exif/exiftool.out"]["redirection"],
            "file:x.pdf.gs.pdf"
        );
        // the hash itself is still the file's own
        assert_eq!(
            form["observables"]["file:x.pdf.gs.pdf"]["results"]["file_hash_analyzer"]["details"]["sha256"],
            "bbbb"
        );
    }

    #[test]
    fn same_members_matches_a_list_in_another_order_only() {
        let mut rows = Rows::new(ListedDifferences {
            rows: vec![Listed {
                dumps: "*".to_owned(),
                path: "/l/*".to_owned(),
                why: String::new(),
                section: None,
                when: Some("same members".to_owned()),
            }],
        })
        .expect("the condition reads");
        let difference = |ace3: Value, ace4: Value| Difference {
            path: "/l/0".to_owned(),
            ace3: Some(ace3),
            ace4: Some(ace4),
        };
        let (ace3, ace4) = (json!({"l": ["a", "b"]}), json!({"l": ["b", "a"]}));
        assert_eq!(
            rows.classify_in(
                "s",
                &difference(json!("a"), json!("b")),
                Some((&ace3, &ace4))
            ),
            Class::Explained
        );
        let other = json!({"l": ["b", "c"]});
        assert_eq!(
            rows.classify_in(
                "s",
                &difference(json!("a"), json!("b")),
                Some((&ace3, &other))
            ),
            Class::Unexplained
        );
        assert_eq!(
            rows.classify("s", &difference(json!("a"), json!("b"))),
            Class::Unexplained
        );
    }

    #[test]
    fn a_row_s_condition_narrows_it() {
        let mut rows = Rows::new(ListedDifferences {
            rows: [
                ("/a", "ace4 only"),
                ("/b", "ace3 holds nothing recorded"),
                ("/c", "ace4 holds .gs.pdf"),
            ]
            .map(|(path, when)| Listed {
                dumps: "*".to_owned(),
                path: path.to_owned(),
                why: String::new(),
                section: None,
                when: Some(when.to_owned()),
            })
            .to_vec(),
        })
        .expect("conditions read");
        let difference = |path: &str, ace3: Option<Value>, ace4: Option<Value>| Difference {
            path: path.to_owned(),
            ace3,
            ace4,
        };
        assert_eq!(
            rows.classify("s", &difference("/a", None, Some(json!(1)))),
            Class::Explained
        );
        assert_eq!(
            rows.classify("s", &difference("/a", Some(json!(1)), None)),
            Class::Unexplained
        );
        assert_eq!(
            rows.classify(
                "s",
                &difference("/b", Some(json!("x nothing recorded y")), None)
            ),
            Class::Explained
        );
        assert_eq!(
            rows.classify("s", &difference("/b", Some(json!("a real error")), None)),
            Class::Unexplained
        );
        assert_eq!(
            rows.classify(
                "s",
                &difference("/c", None, Some(json!({"is_hash_of file:a.gs.pdf": true})))
            ),
            Class::Explained
        );
        assert_eq!(
            rows.classify("s", &difference("/c", Some(json!("a.gs.pdf")), None)),
            Class::Unexplained
        );
        assert!(
            Rows::new(ListedDifferences {
                rows: vec![Listed {
                    dumps: "*".to_owned(),
                    path: "/a".to_owned(),
                    why: String::new(),
                    section: None,
                    when: Some("sometimes".to_owned()),
                }],
            })
            .is_err()
        );
    }

    #[test]
    fn the_real_list_reads() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/trees/differences.md");
        let rows =
            Rows::new(ListedDifferences::load(&path).expect("reads")).expect("its conditions read");
        // since 7.5 batch 10 no module ace3's trees run is missing here, so nothing is unported
        for class in [Class::Explained, Class::Harness] {
            assert!(
                rows.listed.iter().any(|row| Rows::class_of(row) == class),
                "no row is {}",
                class.name()
            );
        }
    }

    #[test]
    fn a_row_is_stale_only_if_it_covers_a_sample_compared() {
        let mut rows = listed(&[
            ("*", "/used", None),
            ("*", "/never", None),
            ("local/*", "/local-only", None),
        ]);
        let difference = Difference {
            path: "/used".to_owned(),
            ace3: None,
            ace4: None,
        };
        rows.classify("ace3/a", &difference);
        let stale: Vec<&str> = rows
            .stale(&["ace3/a".to_owned()])
            .iter()
            .map(|r| r.path.as_str())
            .collect();
        assert_eq!(stale, ["/never"]);
    }

    #[test]
    fn like_differences_share_a_category() {
        for (path, expected) in [
            (
                "/observables/file:abc/results/archive/details/files/3/name",
                "/observables/file:*/results/archive/details/files/*/name",
            ),
            ("/observables/fqdn:a.example", "/observables/fqdn:*"),
            (
                "/observables/file:abc/paths/x.zip/type=email",
                "/observables/file:*/paths/*/type=email",
            ),
            (
                "/observables/file:abc/relationships/extracted_from file:def",
                "/observables/file:*/relationships/extracted_from file:*",
            ),
            (
                "/observables/file:abc/detections/some text",
                "/observables/file:*/detections/*",
            ),
        ] {
            assert_eq!(category(path), expected);
        }
        assert_eq!(
            module_of("/observables/x/results/archive/summary"),
            "archive"
        );
        assert_eq!(module_of("/observables/x/tags/zip"), TREE);
        assert_eq!(module_of("/observables/x"), TREE);
    }

    fn outcome(results: Vec<SampleResult>, rows: Rows) -> Outcome {
        Outcome {
            ace3_commit: "abc".to_owned(),
            ported: ported(&["archive"]),
            absent: vec!["local/x".to_owned()],
            results,
            failures: vec![Failure {
                sample: "ace3/stuck".to_owned(),
                why: "root r didn't finish within 300 seconds".to_owned(),
            }],
            rows,
            seconds: 1.0,
            allow_absent: false,
        }
    }

    #[test]
    fn the_report_counts_by_module_and_class_and_names_what_failed() {
        let mut rows = listed(&[("*", "/observables/*/results/archive/details/x", None)]);
        let result = compare_forms(
            "ace3/a",
            form(json!({"file:a": {"tags": {"zip": true}, "results": {
                "archive": {"details": {"x": 1, "y": 1}},
                "file_type": {},
            }}})),
            form(json!({"file:a": {"tags": {}, "results": {
                "archive": {"details": {"x": 2, "y": 2}},
            }}})),
            &ported(&["archive"]),
            &mut rows,
        )
        .expect("compares");
        let outcome = outcome(vec![result], rows);
        let report = outcome.to_json();
        assert_eq!(report["compared"], 1);
        assert_eq!(report["totals"]["unexplained"], 2);
        assert_eq!(report["totals"]["explained"], 1);
        assert_eq!(report["modules"]["archive"]["unexplained"], 1);
        assert_eq!(report["modules"]["archive"]["explained"], 1);
        assert_eq!(report["modules"][TREE]["unexplained"], 1);
        assert_eq!(report["skipped"]["file_type"], 1);
        assert_eq!(report["failed"][0]["sample"], "ace3/stuck");
        assert_eq!(report["absent"][0], "local/x");
        let text = outcome.to_markdown().expect("writes");
        assert!(text.contains("| `archive` | 1 | 0 | 0 | 1 |"), "{text}");
        assert!(text.contains("`ace3/stuck`: root r"), "{text}");
        assert!(
            text.contains("/observables/file:*/results/archive/details/y"),
            "{text}"
        );
    }

    #[test]
    fn the_threshold_fails_on_unexplained_anywhere_a_stale_row_and_an_absent_sample() {
        let mut rows = listed(&[("*", "/never", None)]);
        let result = compare_forms(
            "ace3/a",
            // a difference outside any module's result counts as one in a module's does
            form(json!({"file:a": {"tags": {"t": true}}})),
            form(json!({"file:a": {"tags": {}}})),
            &ported(&[]),
            &mut rows,
        )
        .expect("compares");
        assert_eq!(result.found[0].module, TREE);
        let mut outcome = outcome(vec![result], rows);
        let failures = threshold_failures(&outcome);
        assert_eq!(failures.len(), 3, "{failures:?}");
        assert!(failures[0].contains("ace3/a: not in differences.md"));
        assert!(failures[0].contains("/observables/file:a/tags/t"));
        assert!(failures[1].contains("/never"));
        assert!(failures[2].contains("local/x is absent"));

        outcome.allow_absent = true;
        assert_eq!(threshold_failures(&outcome).len(), 2);
    }

    #[test]
    fn the_threshold_is_met_when_every_difference_has_a_row() {
        let mut rows = listed(&[("*", "/observables/*/tags/t", None)]);
        let result = compare_forms(
            "ace3/a",
            form(json!({"file:a": {"tags": {"t": true}}})),
            form(json!({"file:a": {"tags": {}}})),
            &ported(&[]),
            &mut rows,
        )
        .expect("compares");
        let mut outcome = outcome(vec![result], rows);
        outcome.allow_absent = true;
        assert_eq!(threshold_failures(&outcome), Vec::<String>::new());
        let text = outcome.to_markdown().expect("writes");
        assert!(
            text.contains("is met over the 1 samples compared. It says nothing about the 1 absent"),
            "{text}"
        );
        outcome.absent.clear();
        let text = outcome.to_markdown().expect("writes");
        assert!(text.contains("is met over the whole sample set"), "{text}");
    }

    #[test]
    fn the_form_holds_the_sample_under_its_alert_path_with_its_tags() {
        let sample = Sample {
            path: "ace3/archive/x.zip".to_owned(),
            sha256: String::new(),
            in_git: true,
            alert_path: "my x.zip".to_owned(),
            meta_tags: vec!["type=email.attachment".to_owned()],
        };
        let text = String::from_utf8(submission_form(&sample, b"bytes", "B").expect("a form"))
            .expect("text");
        assert!(text.contains("filename=\"my x.zip\""), "{text}");
        assert!(text.contains("\"analysis_mode\":\"cli\""), "{text}");
        assert!(
            text.contains("\"file_yara_meta\":{\"my x.zip\":[\"type=email.attachment\"]}"),
            "{text}"
        );
        assert!(text.ends_with("bytes\r\n--B--\r\n"), "{text}");

        let quoted = Sample {
            alert_path: "a\"b".to_owned(),
            ..sample
        };
        assert!(submission_form(&quoted, b"", "B").is_err());
    }

    /// PLAN.md 7.7: the deobfuscator's trace names a job id each run makes, so it's keyed by its path.
    #[test]
    fn a_deobfuscated_trace_is_keyed_by_its_path() {
        assert!(is_volatile("dir/deobfuscated-x.js"));
        assert!(is_volatile("deobfuscated-x.js"));
        assert!(is_volatile("x.pdf.gs.pdf"));
        assert!(!is_volatile("dir/x.js.deobfuscated-"));
        assert!(!is_volatile("x.dll.deobfuscated"));
    }
}
