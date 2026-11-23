//! The diff behind `tools/library-diff/run` (PLAN.md 4.8), whose contract that script's top
//! describes. It runs a library's two sides over the sample set and leaves what they gave in a work
//! directory, and this compares them with `ace_results::differences`, under the same list's rules as
//! `ace compare` and a port's reference test.
//!
//! ```text
//! WORK/run.json                                  which library, sides, samples and runs
//! WORK/outputs/{left,right}/<run>/<sample>.json  what each run gave: output, error, timeout or crashed
//! WORK/report.json                               what this writes
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use ace_results::differences::{Difference, ListedDifferences, diff};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A row of the list covers a sample's comparison by its name, and a side's repeat by this name.
fn repeat_name(side: &str, sample: &str) -> String {
    format!("repeat/{side}/{sample}")
}

#[derive(Debug, Deserialize)]
struct Run {
    library: String,
    left: String,
    right: String,
    runs: usize,
    samples: Vec<String>,
    /// Samples this run didn't compare: absent here, or left out by `--sample`.
    skipped: Vec<String>,
}

/// What one side gave over the samples, in its first run.
#[derive(Debug, Default, PartialEq, Serialize)]
pub struct SideCounts {
    pub outputs: usize,
    /// Outputs that hold something read from the file: not `"content": false` from the side.
    pub with_content: usize,
    pub distinct_outputs: usize,
    pub errors: BTreeMap<String, usize>,
    pub timeouts: usize,
    pub crashes: usize,
}

/// What a comparison found. `text` is for reading; `passed` is the threshold.
#[derive(Debug)]
pub struct Report {
    pub text: String,
    pub passed: bool,
}

fn count(outputs: &[Value]) -> SideCounts {
    let mut counts = SideCounts::default();
    let mut distinct = BTreeSet::new();
    for value in outputs {
        if let Some(output) = value.get("output") {
            counts.outputs += 1;
            if value.get("content") != Some(&Value::Bool(false)) {
                counts.with_content += 1;
            }
            distinct.insert(output.to_string());
        } else if let Some(error) = value.get("error") {
            let kind = error["type"].as_str().unwrap_or("(no type)").to_owned();
            *counts.errors.entry(kind).or_default() += 1;
        } else if value.get("timeout").is_some() {
            counts.timeouts += 1;
        } else {
            counts.crashes += 1;
        }
    }
    counts.distinct_outputs = distinct.len();
    counts
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// What differs between two runs' answers. `content` says only how to count an output, and a port's
/// side needn't write it.
fn diff_results(a: &Value, b: &Value) -> Vec<Difference> {
    let without_content = |value: &Value| {
        let mut value = value.clone();
        if let Some(object) = value.as_object_mut() {
            object.remove("content");
        }
        value
    };
    diff(&without_content(a), &without_content(b))
}

/// Compares what a run left in `work` and writes `report.json` there. `Err` means it couldn't.
pub fn compare(work: &Path, differences: Option<&Path>) -> Result<Report, String> {
    let run: Run = serde_json::from_value(read_json(&work.join("run.json"))?)
        .map_err(|e| format!("run.json: {e}"))?;
    let listed = match differences {
        Some(path) => ListedDifferences::load(path).map_err(|e| e.to_string())?,
        None => ListedDifferences { rows: Vec::new() },
    };
    let read_side = |side: &str, run_number: usize| -> Result<Vec<Value>, String> {
        run.samples
            .iter()
            .map(|sample| {
                read_json(
                    &work
                        .join("outputs")
                        .join(side)
                        .join(run_number.to_string())
                        .join(format!("{sample}.json")),
                )
            })
            .collect()
    };

    let left = read_side("left", 0)?;
    let right = read_side("right", 0)?;
    let mut compared: Vec<(String, Vec<Difference>)> = run
        .samples
        .iter()
        .zip(left.iter().zip(&right))
        .map(|(sample, (a, b))| (sample.clone(), diff_results(a, b)))
        .collect();
    let mut nondeterministic = Vec::new();
    for (side, first) in [("left", &left), ("right", &right)] {
        for again in 1..run.runs {
            let outputs = read_side(side, again)?;
            for ((sample, a), b) in run.samples.iter().zip(first).zip(&outputs) {
                let found = diff_results(a, b);
                for difference in &found {
                    nondeterministic.push(format!("{side} {sample} {}", difference.path));
                }
                compared.push((repeat_name(side, sample), found));
            }
        }
    }
    nondeterministic.sort();
    nondeterministic.dedup();

    // a run with no repeats says nothing of a row for them
    let mut skipped = run.skipped.clone();
    if run.runs < 2 {
        for sample in &run.samples {
            skipped.push(repeat_name("left", sample));
            skipped.push(repeat_name("right", sample));
        }
    }
    let checked = listed.check_between(&compared, &skipped, &run.left, &run.right);

    let counts = [("left", count(&left)), ("right", count(&right))];
    let idle: Vec<&str> = counts
        .iter()
        .filter(|(_, counts)| counts.with_content == 0)
        .map(|(side, _)| *side)
        .collect();
    let total: usize = compared.iter().map(|(_, found)| found.len()).sum();
    let passed = checked.is_ok() && idle.is_empty() && !run.samples.is_empty();

    let mut text = format!(
        "{}: {} against {}: {} samples, {} runs a side, {} left out\n",
        run.library,
        run.left,
        run.right,
        run.samples.len(),
        run.runs,
        run.skipped.len()
    );
    for (side, counts) in &counts {
        text.push_str(&format!(
            "  {side}: {} with output ({} distinct, {} with content), {} errors {:?}, {} timeouts, {} crashes\n",
            counts.outputs,
            counts.distinct_outputs,
            counts.with_content,
            counts.errors.values().sum::<usize>(),
            counts.errors,
            counts.timeouts,
            counts.crashes,
        ));
    }
    text.push_str(&format!(
        "  {total} differences, {} rows, {} nondeterministic paths\n",
        listed.rows.len(),
        nondeterministic.len()
    ));
    for line in &nondeterministic {
        text.push_str(&format!("  nondeterministic: {line}\n"));
    }
    if let Err(report) = &checked {
        text.push_str(report);
    }
    for side in &idle {
        text.push_str(&format!(
            "the {side} side had content on no file, which proves nothing\n"
        ));
    }
    if run.samples.is_empty() {
        text.push_str("no samples were compared\n");
    }
    text.push_str(if passed {
        "  no unexplained difference\n"
    } else {
        "  FAILED\n"
    });

    let found: Vec<Value> = compared
        .iter()
        .flat_map(|(sample, found)| {
            found.iter().map(move |difference| {
                json!({
                    "sample": sample,
                    "path": difference.path,
                    "left": difference.ace3,
                    "right": difference.ace_rs,
                })
            })
        })
        .collect();
    let report = json!({
        "library": run.library,
        "left": run.left,
        "right": run.right,
        "runs": run.runs,
        "samples": run.samples.len(),
        "skipped": run.skipped,
        "sides": {"left": counts[0].1, "right": counts[1].1},
        "nondeterministic": nondeterministic,
        "differences": found,
        "passed": passed,
    });
    fs::write(
        work.join("report.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("report.json: {e}"))?;
    Ok(Report { text, passed })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A work directory with one sample's runs on each side.
    fn work(left: &[Value], right: &[Value]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("run.json"),
            json!({"library": "lib", "left": "a", "right": "b", "runs": left.len(),
                   "samples": ["s/one"], "skipped": ["s/other"]})
            .to_string(),
        )
        .unwrap();
        for (side, runs) in [("left", left), ("right", right)] {
            for (number, value) in runs.iter().enumerate() {
                let path = dir.path().join(format!("outputs/{side}/{number}/s"));
                fs::create_dir_all(&path).unwrap();
                fs::write(path.join("one.json"), value.to_string()).unwrap();
            }
        }
        dir
    }

    fn list(dir: &tempfile::TempDir, rows: &str) -> std::path::PathBuf {
        let path = dir.path().join("differences.md");
        fs::write(&path, rows).unwrap();
        path
    }

    #[test]
    fn the_same_output_passes_and_counts() {
        let one = json!({"output": {"x": 1}});
        let dir = work(&[one.clone(), one.clone()], &[one.clone(), one.clone()]);
        let report = compare(dir.path(), None).unwrap();
        assert!(report.passed, "{}", report.text);
        assert!(
            report
                .text
                .contains("1 with output (1 distinct, 1 with content)")
        );
    }

    #[test]
    fn a_difference_fails_named_by_the_sides_until_it_is_listed() {
        let dir = work(
            &[json!({"output": {"x": 1}})],
            &[json!({"output": {"x": 2}})],
        );
        let report = compare(dir.path(), None).unwrap();
        assert!(!report.passed);
        assert!(report.text.contains("s/one: /output/x"), "{}", report.text);
        assert!(report.text.contains("a: 1"), "{}", report.text);
        assert!(report.text.contains("b: 2"), "{}", report.text);
        let rows = list(&dir, "| `s/one` | `/output/x` | why |\n");
        assert!(compare(dir.path(), Some(&rows)).unwrap().passed);
    }

    #[test]
    fn a_row_that_matches_nothing_fails_unless_its_samples_were_skipped() {
        let one = json!({"output": 1});
        let dir = work(std::slice::from_ref(&one), std::slice::from_ref(&one));
        let rows = list(&dir, "| `s/one` | `/output/x` | why |\n");
        let report = compare(dir.path(), Some(&rows)).unwrap();
        assert!(!report.passed);
        assert!(report.text.contains("matched nothing"), "{}", report.text);
        let rows = list(&dir, "| `s/other` | `/output/x` | why |\n");
        assert!(compare(dir.path(), Some(&rows)).unwrap().passed);
    }

    #[test]
    fn a_side_that_differs_from_itself_fails_and_is_named() {
        let dir = work(
            &[json!({"output": 1}), json!({"output": 2})],
            &[json!({"output": 1}), json!({"output": 1})],
        );
        let report = compare(dir.path(), None).unwrap();
        assert!(!report.passed);
        assert!(
            report.text.contains("nondeterministic: left s/one /output"),
            "{}",
            report.text
        );
        let rows = list(&dir, "| `repeat/left/s/one` | `/output` | why |\n");
        let report = compare(dir.path(), Some(&rows)).unwrap();
        assert!(report.passed, "{}", report.text);
        assert!(report.text.contains("nondeterministic: left s/one /output"));
    }

    #[test]
    fn exceptions_timeouts_and_crashes_are_data() {
        let dir = work(
            &[json!({"error": {"type": "ValueError", "message": "no"}})],
            &[json!({"timeout": true})],
        );
        let report = compare(dir.path(), None).unwrap();
        assert!(!report.passed);
        assert!(report.text.contains("/error"), "{}", report.text);
        assert!(report.text.contains("/timeout"), "{}", report.text);
        assert_eq!(
            count(&[
                json!({"output": 1}),
                json!({"output": 1}),
                json!({"output": 2}),
                json!({"error": {"type": "E", "message": ""}}),
                json!({"timeout": true}),
                json!({"crashed": {"exit": 139}}),
            ]),
            SideCounts {
                outputs: 3,
                with_content: 3,
                distinct_outputs: 2,
                errors: BTreeMap::from([("E".to_owned(), 1)]),
                timeouts: 1,
                crashes: 1,
            }
        );
    }

    #[test]
    fn a_side_with_content_on_no_file_fails() {
        for nothing in [
            json!({"error": {"type": "E", "message": "no"}}),
            json!({"output": {"x": 1}, "content": false}),
        ] {
            let dir = work(
                std::slice::from_ref(&nothing),
                std::slice::from_ref(&nothing),
            );
            let report = compare(dir.path(), None).unwrap();
            assert!(!report.passed);
            assert!(
                report.text.contains("content on no file"),
                "{}",
                report.text
            );
        }
    }

    #[test]
    fn only_one_side_saying_how_to_count_is_no_difference() {
        let dir = work(
            &[json!({"output": {"x": 1}, "content": true})],
            &[json!({"output": {"x": 1}})],
        );
        let report = compare(dir.path(), None).unwrap();
        assert!(report.passed, "{}", report.text);
    }
}
