//! The layering check from PLAN.md step 0.4.
//!
//! Cargo rejects cycles between crates, but not a one-way dependency from a crate that
//! reads alerts on an analysis module. This command reads `cargo metadata` and fails when
//! `ace-results`, `ace-api`, `ace-gui` or `ace-search` depends on an `ace-mod-*` crate,
//! directly or through other crates.
//!
//! Usage: `cargo run -p ace-layering -- [cargo metadata options]`, for example
//! `--manifest-path ../other/Cargo.toml` to check another workspace.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::process::{Command, ExitCode};

use serde_json::Value;

/// Crates that must never depend on an analysis module.
const GUARDED: [&str; 4] = ["ace-results", "ace-api", "ace-gui", "ace-search"];

/// Every analysis module crate's name starts with this.
const MODULE_PREFIX: &str = "ace-mod-";

fn main() -> ExitCode {
    let extra_args: Vec<String> = std::env::args().skip(1).collect();
    let metadata = match load_metadata(&extra_args) {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("ace-layering: {error}");
            return ExitCode::from(2);
        }
    };
    match find_violations(&metadata) {
        Ok(violations) if violations.is_empty() => {
            println!(
                "ace-layering: no dependency from {} on an {MODULE_PREFIX}* crate",
                GUARDED.join(", ")
            );
            ExitCode::SUCCESS
        }
        Ok(violations) => {
            for chain in &violations {
                eprintln!(
                    "ace-layering: {} depends on {}: {}",
                    chain[0],
                    chain[chain.len() - 1],
                    chain.join(" -> ")
                );
            }
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("ace-layering: {error}");
            ExitCode::from(2)
        }
    }
}

/// Runs `cargo metadata` with dependency resolution and parses its output.
fn load_metadata(extra_args: &[String]) -> Result<Value, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(&cargo)
        .args(["metadata", "--format-version", "1"])
        .args(extra_args)
        .output()
        .map_err(|error| format!("could not run {cargo} metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed with {}:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cargo metadata printed invalid JSON: {error}"))
}

/// Returns one dependency chain, from guarded crate to module crate, for each pair that
/// violates the rule, sorted.
///
/// A guarded crate's own dependencies count whatever their kind, so a dev-dependency that
/// pulls a module into the guarded crate's tests also fails. Past the first step only
/// normal and build dependencies count, because Cargo never builds a dependency's
/// dev-dependencies.
fn find_violations(metadata: &Value) -> Result<Vec<Vec<String>>, String> {
    let names = package_names(metadata)?;
    let graph = dependency_graph(metadata)?;

    let mut violations = Vec::new();
    for (start_id, start_name) in &names {
        if !GUARDED.contains(&start_name.as_str()) {
            continue;
        }
        // Breadth first, so each module is reported through its shortest chain.
        let mut parent: HashMap<&str, &str> = HashMap::new();
        let mut seen: HashSet<&str> = HashSet::from([start_id.as_str()]);
        let mut queue: VecDeque<&str> = VecDeque::from([start_id.as_str()]);
        while let Some(id) = queue.pop_front() {
            let first_step = id == start_id.as_str();
            for edge in graph.get(id).map(Vec::as_slice).unwrap_or_default() {
                if !(first_step || edge.normal_or_build) || !seen.insert(edge.to) {
                    continue;
                }
                parent.insert(edge.to, id);
                let name = names.get(edge.to).ok_or_else(|| {
                    format!(
                        "resolve names package {} that packages doesn't list",
                        edge.to
                    )
                })?;
                if name.starts_with(MODULE_PREFIX) {
                    violations.push(chain(&names, &parent, start_id, edge.to));
                } else {
                    queue.push_back(edge.to);
                }
            }
        }
    }
    violations.sort();
    Ok(violations)
}

/// One edge in the resolved dependency graph.
struct Edge<'a> {
    to: &'a str,
    /// False when the dependency is only a dev-dependency.
    normal_or_build: bool,
}

/// Maps each package id to its name.
fn package_names(metadata: &Value) -> Result<BTreeMap<String, String>, String> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages array")?;
    packages
        .iter()
        .map(|package| {
            let id = package["id"].as_str().ok_or("a package has no id")?;
            let name = package["name"].as_str().ok_or("a package has no name")?;
            Ok((id.to_owned(), name.to_owned()))
        })
        .collect()
}

/// Maps each package id to its resolved dependencies.
fn dependency_graph(metadata: &Value) -> Result<HashMap<&str, Vec<Edge<'_>>>, String> {
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata has no resolve graph; don't pass --no-deps")?;
    let mut graph = HashMap::new();
    for node in nodes {
        let id = node["id"].as_str().ok_or("a resolve node has no id")?;
        let deps = node["deps"]
            .as_array()
            .ok_or("a resolve node has no deps")?;
        let mut edges = Vec::with_capacity(deps.len());
        for dep in deps {
            let to = dep["pkg"].as_str().ok_or("a resolve dep has no pkg")?;
            let kinds = dep["dep_kinds"]
                .as_array()
                .ok_or("a resolve dep has no dep_kinds")?;
            // kind is null for a normal dependency, "build" or "dev" otherwise.
            let normal_or_build = kinds
                .iter()
                .any(|kind| kind["kind"].is_null() || kind["kind"] == "build");
            edges.push(Edge {
                to,
                normal_or_build,
            });
        }
        graph.insert(id, edges);
    }
    Ok(graph)
}

/// Walks `parent` back from `end` to `start` and returns the names along the way.
fn chain(
    names: &BTreeMap<String, String>,
    parent: &HashMap<&str, &str>,
    start: &str,
    end: &str,
) -> Vec<String> {
    let mut ids = vec![end];
    let mut current = end;
    while current != start {
        current = parent[current];
        ids.push(current);
    }
    ids.iter().rev().map(|id| names[*id].clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Builds metadata for packages named by id, with edges given as
    /// (from, to, kind), where kind is None, Some("dev") or Some("build").
    fn metadata(packages: &[&str], edges: &[(&str, &str, Option<&str>)]) -> Value {
        let nodes: Vec<Value> = packages
            .iter()
            .map(|id| {
                let deps: Vec<Value> = edges
                    .iter()
                    .filter(|(from, _, _)| from == id)
                    .map(|(_, to, kind)| json!({"pkg": to, "dep_kinds": [{"kind": kind}]}))
                    .collect();
                json!({"id": id, "deps": deps})
            })
            .collect();
        let packages: Vec<Value> = packages
            .iter()
            .map(|id| json!({"id": id, "name": id}))
            .collect();
        json!({"packages": packages, "resolve": {"nodes": nodes}})
    }

    fn violations(metadata: &Value) -> Vec<String> {
        find_violations(metadata)
            .expect("metadata is well formed")
            .iter()
            .map(|chain| chain.join(" -> "))
            .collect()
    }

    #[test]
    fn direct_dependency_fails() {
        let m = metadata(&["ace-api", "ace-mod-x"], &[("ace-api", "ace-mod-x", None)]);
        assert_eq!(violations(&m), ["ace-api -> ace-mod-x"]);
    }

    #[test]
    fn dependency_through_another_crate_fails() {
        let m = metadata(
            &["ace-gui", "ace-core", "ace-mod-email"],
            &[
                ("ace-gui", "ace-core", None),
                ("ace-core", "ace-mod-email", Some("build")),
            ],
        );
        assert_eq!(violations(&m), ["ace-gui -> ace-core -> ace-mod-email"]);
    }

    #[test]
    fn guarded_crates_own_dev_dependency_fails() {
        let m = metadata(
            &["ace-search", "ace-testkit", "ace-mod-x"],
            &[
                ("ace-search", "ace-testkit", Some("dev")),
                ("ace-testkit", "ace-mod-x", None),
            ],
        );
        assert_eq!(violations(&m), ["ace-search -> ace-testkit -> ace-mod-x"]);
    }

    #[test]
    fn dev_dependency_of_a_dependency_is_ignored() {
        let m = metadata(
            &["ace-results", "ace-sdk", "ace-mod-x"],
            &[
                ("ace-results", "ace-sdk", None),
                ("ace-sdk", "ace-mod-x", Some("dev")),
            ],
        );
        assert!(violations(&m).is_empty());
    }

    #[test]
    fn unguarded_crate_may_depend_on_modules() {
        let m = metadata(
            &["ace", "ace-api", "ace-mod-x"],
            &[("ace", "ace-mod-x", None), ("ace", "ace-api", None)],
        );
        assert!(violations(&m).is_empty());
    }

    #[test]
    fn each_guarded_crate_and_module_pair_is_reported() {
        let m = metadata(
            &["ace-api", "ace-gui", "ace-mod-a", "ace-mod-b"],
            &[
                ("ace-api", "ace-mod-a", None),
                ("ace-api", "ace-mod-b", None),
                ("ace-gui", "ace-api", None),
            ],
        );
        assert_eq!(
            violations(&m),
            [
                "ace-api -> ace-mod-a",
                "ace-api -> ace-mod-b",
                "ace-gui -> ace-api -> ace-mod-a",
                "ace-gui -> ace-api -> ace-mod-b",
            ]
        );
    }

    #[test]
    fn metadata_without_resolve_is_an_error() {
        let m = json!({"packages": [], "resolve": null});
        assert!(find_violations(&m).is_err());
    }
}
