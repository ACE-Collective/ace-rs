//! Renders every template of every hunt under a root with ace-hunt and diffs the results with
//! what ace3's Jinja rendered from the same events (PLAN.md 6.3).
//! tools/ace3/hunts/compare-templates runs it over the signatures checkout.
//!
//! ```text
//! render_templates --root DIR --rule-dir splunk=hunts/splunk [--rule-dir TYPE=DIR ...]
//!     --reference FILE --differences FILE --set NAME [--fuel N]
//! ```
//!
//! `--fuel` renders with less fuel than the default, to see how much the signatures need.
//! `--coverage` also says how many arms of the templates' `{% if %}`s and inline ifs the events
//! reach, each template's renders counted together.
//!
//! The reference is make-templates' `templates-signatures.json`, which carries each hunt's events
//! and ace3's result for each of its templates. It prints each difference no row of the set
//! explains and each row that explains none, and exits 1 if there are any.

use std::path::PathBuf;
use std::process::ExitCode;

use ace_hunt::LoadOptions;
use ace_hunt::manager::load_hunts;
use ace_hunt::normal::{classify, diff, parse_rows};
use ace_hunt::render::{Renderer, compare, json};
use ace_hunt::types::{HuntType, Logscale, Splunk};
use ace_hunt::value::Value;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("render_templates: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = std::env::args().skip(1);
    let mut root = None;
    let mut rule_dirs: Vec<(String, String)> = Vec::new();
    let (mut reference, mut differences, mut set) = (None, None, None);
    let mut limits = ace_hunt::render::Limits::default();
    let mut coverage = false;
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
            "--reference" => reference = Some(PathBuf::from(value()?)),
            "--differences" => differences = Some(PathBuf::from(value()?)),
            "--set" => set = Some(value()?),
            "--coverage" => coverage = true,
            "--fuel" => limits.fuel = value()?.parse().map_err(|e| format!("--fuel: {e}"))?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let root = root
        .ok_or("--root is required")?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let reference = reference.ok_or("--reference is required")?;
    let text =
        std::fs::read_to_string(&reference).map_err(|e| format!("{}: {e}", reference.display()))?;
    // read keeping each object's key order, which the events need
    let reference = json::read(&text)?;
    // ace3 may have loaded a type ace-rs doesn't, such as Rapid7's, which the owner left out: only the
    // hunts under the rule directories given here are compared
    let given: Vec<String> = rule_dirs.iter().map(|(_, dir)| format!("{dir}/")).collect();
    let ref_hunts: Vec<&Value> = match reference.as_map().and_then(|m| m.get("hunts")) {
        Some(Value::Seq(hunts)) => hunts
            .iter()
            .filter(|h| {
                h.as_map()
                    .and_then(|m| m.get("path"))
                    .and_then(Value::as_str)
                    .is_some_and(|path| given.iter().any(|dir| path.starts_with(dir.as_str())))
            })
            .collect(),
        _ => return Err("the reference has no hunts".to_owned()),
    };
    let splunk = Splunk {
        instances: Some(vec!["default".to_owned()]),
    };
    let renderer = Renderer::new(limits);
    let (mut ours, mut theirs) = (Vec::new(), Vec::new());
    let mut seen = Vec::new();
    let mut renders = 0usize;
    let (mut arms_taken, mut arms, mut partly_reached) = (0usize, 0usize, 0usize);
    for (kind, dir) in &rule_dirs {
        let kind: &dyn HuntType = match kind.as_str() {
            "splunk" => &splunk,
            "logscale" => &Logscale,
            other => return Err(format!("no hunt type {other}")),
        };
        let dirs = vec![root.join(dir)];
        for loaded in load_hunts(kind, &dirs, &LoadOptions::default()) {
            let Ok(hunt) = &loaded.result else { continue };
            let path = loaded
                .path
                .strip_prefix(&root)
                .unwrap_or(&loaded.path)
                .to_string_lossy()
                .into_owned();
            let found = ref_hunts
                .iter()
                .filter_map(|h| h.as_map())
                .find(|h| h.get("path").and_then(Value::as_str) == Some(path.as_str()));
            if coverage {
                let (t, a, partial) = compare::coverage(&renderer, &hunt.config, found);
                arms_taken += t;
                arms += a;
                partly_reached += partial;
            }
            let (a, b) = compare::signature_hunt(&renderer, &path, Some(&hunt.config), found);
            renders += a["renders"].as_object().map_or(0, |r| r.len());
            ours.push(a);
            theirs.push(b);
            seen.push(path);
        }
    }
    for h in ref_hunts.iter().filter_map(|h| h.as_map()) {
        let path = h.get("path").and_then(Value::as_str).unwrap_or("");
        if !seen.iter().any(|p| p == path) {
            let (a, b) = compare::signature_hunt(&renderer, path, None, Some(h));
            ours.push(a);
            theirs.push(b);
        }
    }
    println!("{} hunts, {renders} renders", ours.len());
    if coverage {
        println!(
            "branches: the events reach {arms_taken} of {arms} arms; {partly_reached} templates have an arm they don't"
        );
    }
    let differences = differences.ok_or("--differences is required")?;
    let set = set.ok_or("--set is required")?;
    let rows = parse_rows(
        &std::fs::read_to_string(&differences)
            .map_err(|e| format!("{}: {e}", differences.display()))?,
        &set,
    );
    let report = classify(
        diff(
            &serde_json::json!({"hunts": theirs}),
            &serde_json::json!({"hunts": ours}),
        ),
        &rows,
    );
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
