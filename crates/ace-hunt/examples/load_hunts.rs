//! Loads every hunt under a root with ace-hunt and writes the normal form, or diffs it against
//! ace3's (PLAN.md 6.2). tools/ace3/hunts/compare runs it over the signatures checkout.
//!
//! ```text
//! load_hunts --root DIR --rule-dir splunk=hunts/splunk [--rule-dir TYPE=DIR ...]
//!     [--splunk-instance NAME ...] [--out FILE]
//!     [--reference FILE --differences FILE --set NAME]
//! ```
//!
//! The types are splunk and logscale. `--splunk-instance` names a Splunk instance a hunt
//! may name, `default` when none is given, as make-hunts configures ace3. With `--reference`, it
//! prints each difference from ace3's normal form that no row of the set's differences explains
//! and each row that explains none, and exits 1 if there are any.

use std::path::PathBuf;
use std::process::ExitCode;

use ace_hunt::LoadOptions;
use ace_hunt::normal::{RuleDirs, classify, diff, normal_form, parse_rows};
use ace_hunt::types::{HuntType, Logscale, Splunk};

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("load_hunts: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = std::env::args().skip(1);
    let mut root = None;
    let mut rule_dirs: Vec<(String, String)> = Vec::new();
    let mut instances = Vec::new();
    let (mut out, mut reference, mut differences, mut set) = (None, None, None, None);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--root" => root = Some(PathBuf::from(value()?)),
            "--rule-dir" => {
                let spec = value()?;
                let (kind, dir) = spec
                    .split_once('=')
                    .ok_or(format!("{spec} isn't TYPE=DIR"))?;
                rule_dirs.push((kind.to_owned(), dir.to_owned()));
            }
            "--splunk-instance" => instances.push(value()?),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--reference" => reference = Some(PathBuf::from(value()?)),
            "--differences" => differences = Some(PathBuf::from(value()?)),
            "--set" => set = Some(value()?),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let root = root
        .ok_or("--root is required")?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if instances.is_empty() {
        instances.push("default".to_owned());
    }
    let splunk = Splunk {
        instances: Some(instances),
    };
    let given: Vec<String> = rule_dirs.iter().map(|(_, dir)| format!("{dir}/")).collect();
    let mut types: Vec<RuleDirs<'_>> = Vec::new();
    for (kind, dir) in rule_dirs {
        let kind: &dyn HuntType = match kind.as_str() {
            "splunk" => &splunk,
            "logscale" => &Logscale,
            other => return Err(format!("no hunt type {other}")),
        };
        match types.iter_mut().find(|t| t.kind.name() == kind.name()) {
            Some(t) => t.dirs.push(dir),
            None => types.push(RuleDirs {
                kind,
                dirs: vec![dir],
            }),
        }
    }
    let ours = normal_form(&root, &types, &LoadOptions::default());
    let hunts = ours["hunts"].as_array().cloned().unwrap_or_default();
    let failed = hunts.iter().filter(|h| h.get("error").is_some()).count();
    println!(
        "{} hunts: {} loaded, {failed} failed",
        hunts.len(),
        hunts.len() - failed
    );
    if let Some(out) = out {
        let text = serde_json::to_string_pretty(&ours).map_err(|e| e.to_string())?;
        std::fs::write(&out, text + "\n").map_err(|e| format!("{}: {e}", out.display()))?;
    }
    let Some(reference) = reference else {
        return Ok(ExitCode::SUCCESS);
    };
    let mut reference: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&reference).map_err(|e| format!("{}: {e}", reference.display()))?,
    )
    .map_err(|e| e.to_string())?;
    // ace3 may have loaded a type ace-rs doesn't, such as Rapid7's, which the owner left out: only the
    // hunts under the rule directories given here are compared
    if let Some(hunts) = reference["hunts"].as_array_mut() {
        let before = hunts.len();
        hunts.retain(|h| {
            h["path"]
                .as_str()
                .is_some_and(|path| given.iter().any(|dir| path.starts_with(dir.as_str())))
        });
        if hunts.len() < before {
            println!(
                "left out {} of the reference's hunts, outside the rule directories given",
                before - hunts.len()
            );
        }
    }
    let differences = differences.ok_or("--reference needs --differences")?;
    let set = set.ok_or("--reference needs --set")?;
    let rows = parse_rows(
        &std::fs::read_to_string(&differences)
            .map_err(|e| format!("{}: {e}", differences.display()))?,
        &set,
    );
    let report = classify(diff(&reference, &ours), &rows);
    println!(
        "{} differences explained by {} rows, {} unexplained, {} rows explaining none",
        report.explained,
        rows.len() - report.unused.len(),
        report.unexplained.len(),
        report.unused.len()
    );
    for difference in &report.unexplained {
        println!("unexplained: {difference}");
    }
    for row in &report.unused {
        println!("unused row: {} {}", row.hunts, row.path);
    }
    Ok(
        if report.unexplained.is_empty() && report.unused.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        },
    )
}
