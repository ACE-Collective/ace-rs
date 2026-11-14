//! `ace yara`: build rulesets and scan files with them.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use ace_yara::mime::{DEFAULT_DATABASE, MimeTyper};
use ace_yara::replay::{self, RESULT_FILE};
use ace_yara::ruleset::{self, Manifest};
use ace_yara::{LoadOptions, Ruleset, ScanError, ScanRequest, Scanner};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use serde_json::json;

#[derive(Subcommand)]
pub enum YaraCommand {
    /// Compile a signature directory into a ruleset file, with its manifest beside it.
    Build(BuildArgs),
    /// Scan files with a ruleset, the way ace3's `ace yara scan` does through its yara
    /// service.
    Scan(ScanArgs),
    /// Replay SVS samples: read the job.json that ace3's SVS replay writes in a working
    /// directory, compile its rules, scan its units and write result.json there, with each
    /// match's pattern offsets. A build with the svs feature also prints the slowest rules.
    Replay(ReplayArgs),
}

#[derive(Args)]
pub struct ReplayArgs {
    /// The working directory holding job.json.
    workdir: PathBuf,
    /// The magic database for the mime_type filter.
    #[arg(long, default_value = DEFAULT_DATABASE)]
    magic_database: PathBuf,
    /// Contain this process before it compiles anything, as SVS validation runs it (PLAN.md 7.10): one
    /// thread, no fork or exec, no network, reading only --read and the working directory and writing only
    /// the working directory, its CPU time and memory held. A scan then has no per-file timeout.
    #[arg(long)]
    contained: bool,
    /// What a contained replay may read: the validation's directory, with both commits and the samples.
    #[arg(long, requires = "contained")]
    read: Option<PathBuf>,
    /// A contained replay's CPU-time limit.
    #[arg(long, default_value_t = 1800, requires = "contained")]
    cpu_seconds: u64,
    /// A contained replay's address-space limit, in MiB.
    #[arg(long, default_value_t = 4096, requires = "contained")]
    memory_mb: u64,
}

#[derive(Args)]
pub struct BuildArgs {
    /// The signature directory: each subdirectory is a namespace of .yar and .yara files.
    rules: PathBuf,
    /// Where to write the ruleset. Its manifest goes to the same path plus .manifest.json.
    #[arg(long, short)]
    out: PathBuf,
}

/// Where a command gets its ruleset.
#[derive(Args)]
pub struct RulesetArgs {
    /// Compile this signature directory.
    #[arg(long, required_unless_present = "ruleset", conflicts_with = "ruleset")]
    rules: Option<PathBuf>,
    /// Load this ruleset file, written by `ace yara build`.
    #[arg(long)]
    ruleset: Option<PathBuf>,
    /// Drop the matches of this rule. Give it more than once for more rules.
    #[arg(long = "blacklist", value_name = "RULE")]
    blacklist: Vec<String>,
}

#[derive(Args)]
pub struct ScanArgs {
    #[command(flatten)]
    source: RulesetArgs,
    /// The files to scan.
    files: Vec<PathBuf>,
    /// Also read the paths to scan from stdin, one per line.
    #[arg(long)]
    from_stdin: bool,
    /// Tags describing the scan target, for rules that filter on meta_tags.
    #[arg(long, num_args = 1.., value_name = "TAG")]
    meta_tags: Vec<String>,
    /// The file's path inside the alert, which sets the filename, filepath and extension
    /// externals and is what the file_name, full_path and file_ext filters see. Defaults to
    /// the file's absolute path, as ace3 scans it. Takes one file only.
    #[arg(long)]
    path: Option<String>,
    /// Seconds one scan may take. 10 is ace3's service_yara.default_timeout.
    #[arg(long, default_value_t = 10)]
    timeout: u64,
    /// The magic database for the mime_type filter.
    #[arg(long, default_value = DEFAULT_DATABASE)]
    magic_database: PathBuf,
    /// Print the full matches as JSON.
    #[arg(short, long)]
    json: bool,
}

pub fn run(command: YaraCommand) -> Result<ExitCode> {
    match command {
        YaraCommand::Build(args) => build(args),
        YaraCommand::Scan(args) => scan(args),
        YaraCommand::Replay(args) => replay(args),
    }
}

fn manifest_path(ruleset: &Path) -> PathBuf {
    let mut name = ruleset.as_os_str().to_owned();
    name.push(".manifest.json");
    PathBuf::from(name)
}

fn build(args: BuildArgs) -> Result<ExitCode> {
    let built = ruleset::build(&args.rules, &LoadOptions::default())?;
    std::fs::write(&args.out, &built.bytes)
        .with_context(|| format!("unable to write {}", args.out.display()))?;
    let manifest_path = manifest_path(&args.out);
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&built.manifest)?)
        .with_context(|| format!("unable to write {}", manifest_path.display()))?;

    let manifest = &built.manifest;
    let rules: usize = manifest.files.iter().map(|f| f.rules.len()).sum();
    println!(
        "ruleset {} from {}: {} files with {rules} rules, {} files left out",
        manifest.key,
        manifest.commit.as_deref().unwrap_or("no commit"),
        manifest.files.len(),
        manifest.left_out.len(),
    );
    for file in &manifest.left_out {
        println!("\tleft out {}", file.path);
    }
    Ok(ExitCode::SUCCESS)
}

/// `ace yara replay --contained`: the magic database is open before containment, which then allows only
/// the validation's directory to read and the working directory to write.
fn replay_contained(args: &ReplayArgs, typer: &MimeTyper) -> Result<ExitCode> {
    use ace_pool::containment::{SandboxProfile, contain};
    let mut profile = SandboxProfile {
        address_space_bytes: args.memory_mb.saturating_mul(1 << 20),
        cpu_seconds: args.cpu_seconds,
        ..SandboxProfile::default()
    }
    .allow_write(&args.workdir);
    if let Some(read) = &args.read {
        profile = profile.allow_read(read);
    }
    contain(&profile).context("containing the replay")?;
    let result = replay::run_with(&args.workdir, typer, false)?;
    replay::write_json(&args.workdir, RESULT_FILE, &result)?;
    Ok(ExitCode::SUCCESS)
}

/// A ruleset, with its manifest when there is one.
pub struct Source {
    pub ruleset: Ruleset,
    pub manifest: Option<Manifest>,
}

pub fn load(args: &RulesetArgs) -> Result<Source> {
    let options = LoadOptions {
        blacklist: args.blacklist.iter().cloned().collect(),
    };
    if let Some(dir) = &args.rules {
        let built = ruleset::build(dir, &options)?;
        return Ok(Source {
            ruleset: built.ruleset,
            manifest: Some(built.manifest),
        });
    }

    let path = args
        .ruleset
        .as_ref()
        .expect("clap requires --rules or --ruleset");
    let bytes =
        std::fs::read(path).with_context(|| format!("unable to read {}", path.display()))?;
    let ruleset = Ruleset::from_bytes(&bytes, &options)
        .map_err(|e| anyhow!("unable to load {}: {e}", path.display()))?;
    let manifest_path = manifest_path(path);
    let manifest = match std::fs::read(&manifest_path) {
        Ok(json) => {
            let manifest: Manifest = serde_json::from_slice(&json)
                .with_context(|| format!("unable to read {}", manifest_path.display()))?;
            if manifest.key != ruleset::key(&bytes) {
                bail!(
                    "{} is not the manifest of {}: its key is {}, the ruleset's is {}",
                    manifest_path.display(),
                    path.display(),
                    manifest.key,
                    ruleset::key(&bytes)
                );
            }
            Some(manifest)
        }
        Err(_) => None,
    };
    Ok(Source { ruleset, manifest })
}

fn scan(args: ScanArgs) -> Result<ExitCode> {
    let mut files: Vec<String> = args
        .files
        .iter()
        .map(|f| f.to_string_lossy().into_owned())
        .collect();
    if args.from_stdin {
        for line in std::io::stdin().lock().lines() {
            let line = line?;
            let line = line.trim();
            if !line.is_empty() {
                files.push(line.to_string());
            }
        }
    }
    if args.path.is_some() && files.len() != 1 {
        bail!(
            "--path names the path of one file, and {} were given",
            files.len()
        );
    }

    let source = load(&args.source)?;
    let commit = source.manifest.as_ref().and_then(|m| m.commit.clone());
    let typer = MimeTyper::open(&args.magic_database)?;
    let mut scanner = Scanner::new(&source.ruleset);

    let mut exit = ExitCode::SUCCESS;
    for file in &files {
        let outcome = (|| -> Result<_> {
            let data = std::fs::read(file).with_context(|| format!("unable to read {file}"))?;
            let path = match &args.path {
                Some(path) => path.clone(),
                None => std::path::absolute(file)?.to_string_lossy().into_owned(),
            };
            let mime_type = typer.mime_type(&data)?;
            let outcome = scanner.scan(&ScanRequest {
                data: &data,
                path: &path,
                mime_type: &mime_type,
                meta_tags: &args.meta_tags,
                timeout: Some(Duration::from_secs(args.timeout)),
            });
            match outcome {
                Ok(outcome) => Ok((mime_type, outcome)),
                Err(ScanError::Timeout) => bail!("the scan timed out after {}s", args.timeout),
                Err(e) => Err(e.into()),
            }
        })();

        let (mime_type, outcome) = match outcome {
            Ok(found) => found,
            Err(e) => {
                eprintln!("{file}: {e:#}");
                exit = ExitCode::FAILURE;
                continue;
            }
        };

        if args.json {
            let matches: Vec<_> = outcome
                .matches
                .iter()
                .map(|m| json!({"commit": commit, "match": m}))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "path": file,
                    "mime_type": mime_type,
                    "ruleset": source.manifest.as_ref().map(|m| &m.key),
                    "matches": matches,
                }))?
            );
            continue;
        }

        // ace3's format.
        if outcome.matches.is_empty() {
            println!("{file}: no matches");
            continue;
        }
        println!("{file}: {} rule matches", outcome.matches.len());
        for found in &outcome.matches {
            match &commit {
                Some(commit) => println!("\t{} ({commit})", found.rule),
                None => println!("\t{}", found.rule),
            }
        }
    }
    Ok(exit)
}

fn replay(args: ReplayArgs) -> Result<ExitCode> {
    let typer = MimeTyper::open(&args.magic_database)?;
    if args.contained {
        return replay_contained(&args, &typer);
    }
    let result = replay::run(&args.workdir, &typer)?;
    replay::write_json(&args.workdir, RESULT_FILE, &result)?;

    let left_out = result.files.iter().filter(|f| f.error.is_some()).count();
    let count = |f: fn(&replay::UnitOutcome) -> usize| result.units.values().map(f).sum::<usize>();
    println!(
        "{} rule files, {left_out} left out{}; {} units: {} matches, {} dropped by the filter, {} errors",
        result.files.len(),
        result
            .ruleset_error
            .as_ref()
            .map(|e| format!(", and they don't compile together: {e}"))
            .unwrap_or_default(),
        result.units.len(),
        count(|u| u.matches.len()),
        count(|u| u.dropped.len()),
        count(|u| u.errors.len()),
    );
    if let Some(slowest) = &result.slowest_rules {
        if slowest.is_empty() {
            println!(
                "slowest rules: none took over 100 ms across the units, and yara-x lists only those"
            );
        } else {
            println!("slowest rules across the units, condition + pattern matching:");
        }
        for rule in slowest {
            println!(
                "\t{:.6}s\t{}:{} (condition {:.6}s, patterns {:.6}s)",
                rule.total_seconds(),
                rule.namespace,
                rule.rule,
                rule.condition_seconds,
                rule.pattern_matching_seconds,
            );
        }
    }
    println!("wrote {}", args.workdir.join(RESULT_FILE).display());
    Ok(ExitCode::SUCCESS)
}
