//! ace3's `DMGAnalyzer` (`saq/modules/file_analysis/dmg.py`) and `CVE_2021_30657_Analyzer`
//! (`cve.py`): dmg2img turns a DMG into a raw image, which 7z lists, and in each app bundle of that
//! image a file in `Contents/MacOS/` that libmagic calls a script is CVE-2021-30657's Gatekeeper
//! bypass. Both tools run in the sandbox runner; libmagic runs in the task, over the database ace3's
//! `file` reads.
//!
//! ace3's CVE module reads the file list from the DMG's analysis, on the image's redirection. A
//! module here reads no other observable's result, so it lists the image again with the same `7z l`
//! on the same bytes, which gives the same list; and it runs only on an image dmg_analyzer added
//! (`Module::READS_ADDED_BY`), as only dmg_analyzer adds a `.img` with its `macos` and `dmg` tags and
//! its redirection to the DMG. ace3 extracts each member with a run of its own; here a task has 64
//! runs (`ace_sdk::tools::MAX_RUNS`), so when there are more members than runs left, the runs share
//! them out in order, a few members each, rather than leave the last ones unchecked.

use std::fs;
use std::path::Path;
use std::time::Duration;

use ace_mod_files::libmagic::{self, Answer, Magic};
use ace_pycompat::pystr::strip;
use ace_results::types::macos::{Cve202130657Analysis, DmgAnalysis};
use ace_results::{Detection, ObservableKind, ResultEnvelope, YaraMeta};
use ace_sdk::takes::{Case, Condition, Takes, Text};
use ace_sdk::tools::{MAX_RUNS, ToolOutput, ToolRun};
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use regex::Regex;

use crate::{MAX_FILES, item_list, name_fits, source, stopped_reason, tool_failure_reason};

/// ace3's built-in signature `cve_2021_30657_dmg_script`.
pub const CVE_2021_30657_DMG_SCRIPT: &str = "3ba358a3-b7ab-4475-a10a-f2a8070b455d";

/// The task's limits: ace3's `maximum_analysis_time`, 60 s, whose time left each run gets, as ace3
/// gives dmg2img and 7z no timeout of their own. The tools run under the runner's limits; the task
/// holds only what it copies.
const RESOURCES: Resources = Resources {
    timeout: Duration::from_secs(60),
    memory_mb: 512,
    cpu_seconds: 60,
};

/// The longest argument the kernel passes to a program (`MAX_ARG_STRLEN`). ace3's `Popen` fails on
/// a member named longer, and its module stops there.
const MAX_ARGUMENT: usize = 32 * 4096;
/// The most a run's arguments may be, well inside the kernel's limit (a quarter of the 8 MiB stack).
/// A listing is at most 64 MiB, so 63 runs' share of its members' paths is about 1 MiB each.
const MAX_ARGUMENTS: usize = 1536 * 1024;

/// The dmg_analyzer module.
pub struct DmgAnalyzer;

impl Module for DmgAnalyzer {
    const NAME: &'static str = "dmg_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["dmg2img", "7z"];
    const RESOURCES: Resources = RESOURCES;
    type Output = DmgAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(DmgAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        // "The first noteable fact about the DMG file format is, that there is no DMG file format."
        // ace3 checks the name lowered; to_lowercase lowers the same ASCII
        Takes::everything().and(
            Condition::Name(Text::ends_with(".dmg", Case::Lower)),
            "not named .dmg",
        )
    }
}

impl Parser for DmgAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<DmgAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let mut result = ResultEnvelope::new(DmgAnalysis::default());
        let local = file.local_path.display().to_string();
        // the image is kept next to the dmg, replacing .dmg with .img; the name ends in four
        // ASCII characters, whatever their case (`takes`)
        let path = file.path.to_string();
        let stem = path.get(..path.len().saturating_sub(4)).unwrap_or(&path);
        let image_path = format!("{stem}.img");
        let convert = ToolRun::new("dmg2img", [local.as_str(), "image.img"])
            .read(&file.local_path)
            .keep("image.img")
            .timeout(ctx.time_left());
        let output = ctx.run_tool(convert)?;
        if output.stopped().is_some() {
            // whatever it wrote is incomplete, and wasn't kept
            result.error = Some(format!(
                "dmg2img did not finish: {}",
                stopped_reason(&output)
            ));
            return Ok(Outcome::Done(result));
        }
        let stderr = output.stderr_text();
        result.details.stdout = Some(output.stdout_text());
        result.details.stderr = Some(stderr.clone());
        let Some(image) = output.output("image.img") else {
            let error = format!(
                "{}, without writing an image",
                tool_failure_reason("dmg2img", output.returncode().unwrap_or_default(), &stderr)
            );
            tracing::info!("dmg2img failed: {error}");
            result.error = Some(error);
            return Ok(Outcome::Done(result));
        };
        result.details.image_file = Some(image_path.clone());
        if name_fits(&image_path) {
            let mut new_file = ctx.write_file_from(
                &image_path,
                &mut fs::File::open(image)?,
                &[YaraMeta::new("type", "archive.dmg").map_err(ModuleError::other)?],
            )?;
            new_file.tags.push("macos".to_owned());
            new_file.tags.push("dmg".to_owned());
            new_file.redirection = Some(source(file));
            result.files.push(new_file);
        }

        // get the list of files
        match list(ctx, image)? {
            Listing::Lines { lines, failure } => {
                result.details.file_list = lines;
                // 7z exits 1 for a warning, and still lists what it read. Above that the listing is
                // kept, since it's whatever 7z read before it failed
                if let Some(failure) = failure {
                    let error = format!("{failure}, so the image's file list may be incomplete");
                    tracing::info!("7z l failed: {error}");
                    result.error = Some(error);
                }
            }
            // the image is still analyzed on its own
            Listing::Stopped(why) => {
                result.error = Some(format!("{why}, so the image's files are not listed"));
            }
        }
        if !result.details.file_list.is_empty() {
            result.summary = Some(format!(
                "DMG Analysis: file observabed ({})",
                item_list(&result.details.file_list)
            ));
        }
        Ok(Outcome::Done(result))
    }
}

/// What `7z l` gave.
enum Listing {
    /// The listing's files, in its order, and how 7z failed when it exited above 1 (1 is a warning).
    Lines {
        lines: Vec<String>,
        failure: Option<String>,
    },
    /// Why the runner stopped it.
    Stopped(String),
}

/// `7z l <image>` and its lines between the dashed rules, without the folders, each stripped, as
/// dmg.py takes them.
fn list(ctx: &TaskContext<()>, image: &Path) -> Result<Listing, ModuleError> {
    let local = image.display().to_string();
    let run = ToolRun::new("7z", ["l", local.as_str()])
        .read(image)
        .timeout(ctx.time_left());
    let output = ctx.run_tool(run)?;
    if output.stopped().is_some() {
        return Ok(Listing::Stopped(format!(
            "7z l did not finish: {}",
            stopped_reason(&output)
        )));
    }
    let failure = output
        .returncode()
        .filter(|code| *code > 1)
        .map(|code| tool_failure_reason("7z l", code, &output.stderr_text()));
    Ok(Listing::Lines {
        lines: file_list(&output.stdout_text())?,
        failure,
    })
}

/// dmg.py's parse of `7z l`'s output: entries look like
/// `2021-04-06 23:33:19 .....        16388        20480  Installer/.DS_Store`, and a `D` in the
/// attributes' first column, the line's 21st character, is a folder.
fn file_list(stdout: &str) -> Result<Vec<String>, ModuleError> {
    let mut listing = false;
    let mut lines = Vec::new();
    for line in stdout.split('\n') {
        if line.starts_with("-------------------") {
            listing = !listing;
            continue;
        }
        if !listing {
            continue;
        }
        let mut chars = line.chars();
        let Some(attribute) = chars.nth(20) else {
            // ace3 skips a line shorter than 20 characters and raises IndexError on one of 20
            if line.chars().count() == 20 {
                return Err(ModuleError::other(
                    "IndexError: string index out of range (a listing line of 20 characters)",
                ));
            }
            continue;
        };
        if attribute == 'D' {
            continue;
        }
        lines.push(strip(line).to_owned());
    }
    Ok(lines)
}

/// The cve_2021_30657_analyzer module.
pub struct Cve202130657Analyzer {
    database: Result<Vec<u8>, String>,
    entry: Regex,
}

impl Module for Cve202130657Analyzer {
    const NAME: &'static str = "cve_2021_30657_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["7z"];
    const RESOURCES: Resources = RESOURCES;
    const READS_ADDED_BY: bool = true;
    type Output = Cve202130657Analysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(Cve202130657Analyzer {
            // libmagic's database, read before containment
            database: fs::read(libmagic::DATABASE).map_err(|e| e.to_string()),
            // cve.py's RE_7Z_FILE_ENTRY
            entry: Regex::new(r"^.+?\d+\s+\d+\s+(.+)$").map_err(ModuleError::other)?,
        })
    }

    fn takes(_: &()) -> Takes {
        // the file should end with .img and be dmg_analyzer's, which tags it macos and dmg and
        // redirects it to the DMG whose analysis added it
        Takes::everything()
            .and(
                Condition::Path(Text::ends_with(".img", Case::Lower)),
                "not named .img",
            )
            .and(
                Condition::All(vec![
                    Condition::added_by(DmgAnalyzer::NAME),
                    Condition::Redirected,
                ]),
                "not an image dmg_analyzer added",
            )
    }
}

impl Parser for Cve202130657Analyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<Cve202130657Analysis>, ModuleError> {
        let file = ctx.input_file()?;
        let mut result = ResultEnvelope::new(Cve202130657Analysis::default());
        let lines = match list(ctx, &file.local_path)? {
            // a listing 7z failed part way through is checked as far as it goes, as ace3 checks
            // the DMG analysis's list, and that analysis says the list may be incomplete
            Listing::Lines { lines, .. } => lines,
            Listing::Stopped(why) => {
                // ace3's DMG analysis then has no files, and this one checks none
                result.error = Some(format!("{why}, so no file was checked"));
                return Ok(Outcome::Done(result));
            }
        };
        // "2021-04-06 23:33:06 .....        59039        61440  Installer/yWnBJLaF/1302.app/Contents/MacOS/1302"
        let members: Vec<String> = lines
            .iter()
            .filter(|line| line.contains("/Contents/MacOS/"))
            .filter_map(|line| self.entry.captures(line).map(|c| c[1].to_owned()))
            .collect();
        let magic = match &self.database {
            Ok(database) if !members.is_empty() => {
                Some(Magic::load(database, Answer::MimeType).map_err(ModuleError::other)?)
            }
            Ok(_) => None,
            Err(e) => {
                return Err(ModuleError::other(format!("{}: {e}", libmagic::DATABASE)));
            }
        };
        let local = file.local_path.display().to_string();
        let mut order = Vec::new();
        // one run went on the listing
        'runs: for batch in batches(&members, MAX_RUNS as usize - 1) {
            if let Some(long) = batch.iter().find(|m| m.len() >= MAX_ARGUMENT) {
                result.error = Some(format!(
                    "a member's path is {} bytes, longer than a program's argument may be",
                    long.len()
                ));
                break;
            }
            let bytes: usize = batch.iter().map(|m| m.len() + 1).sum();
            if bytes >= MAX_ARGUMENTS {
                result.error = Some(format!(
                    "the members' paths for one run are {bytes} bytes, more than a program's \
                     arguments may be"
                ));
                break;
            }
            // `--` ends 7z's switches, so a member the image names `-...` is a name, not a switch
            // for the others in its batch; ace3's 7z, one member a run, would take it as a switch
            let mut args = vec![
                "x".to_owned(),
                "-o.".to_owned(),
                "--".to_owned(),
                local.clone(),
            ];
            args.extend(batch.iter().cloned());
            let run = ToolRun::new("7z", args)
                .read(&file.local_path)
                .keep_tree()
                .timeout(ctx.time_left());
            let output = ctx.run_tool(run)?;
            if output.stopped().is_some() {
                // out of time: the rest of the files are not checked. cve.py names the member 7z
                // was on, one a run; here it's the first of the run's
                result.error = Some(format!(
                    "7z did not finish extracting {}, so it and the files after it were not \
                     checked: {}",
                    batch.first().map_or("", String::as_str),
                    stopped_reason(&output)
                ));
                break;
            }
            let failure = tool_failure_reason(
                "7z",
                output.returncode().unwrap_or_default(),
                &output.stderr_text(),
            );
            for member in batch {
                if result.files.len() >= MAX_FILES {
                    // ace3's root takes no more files, and its module adds none past them
                    result.error = Some(format!(
                        "the {MAX_FILES} files a module adds were added; the rest weren't checked"
                    ));
                    break 'runs;
                }
                if output.output(member).is_none() {
                    // cve.py goes on to the next member, and its error is the last one's
                    tracing::warn!("7z didn't extract {member}: {failure}");
                    result.error = Some(format!("{failure}, without extracting {member}"));
                    continue;
                }
                if let Some(path) = suspect(magic.as_ref(), &output, member) {
                    self.add_script(ctx, &mut result, &mut order, member, path)?;
                }
            }
        }
        if !order.is_empty() {
            result.summary = Some(format!("CVE-2021-30657 Analysis: {}", item_list(&order)));
        }
        Ok(Outcome::Done(result))
    }
}

/// The extracted member and its mime type, when libmagic's mime type has `script` in it.
fn suspect<'a>(
    magic: Option<&Magic>,
    output: &'a ToolOutput,
    member: &str,
) -> Option<(&'a Path, String)> {
    let path = output.output(member)?;
    let mime = magic?.file(path);
    mime.contains("script")
        .then(|| (path, strip(&mime).to_owned()))
}

impl Cve202130657Analyzer {
    /// cve.py copies the script to `cve_2021_30657/<name>` in the root's storage and adds that copy,
    /// which ace3 adds under its name alone, tagged, with a detection.
    fn add_script(
        &self,
        ctx: &TaskContext<()>,
        result: &mut ResultEnvelope<Cve202130657Analysis>,
        order: &mut Vec<String>,
        member: &str,
        (path, mime): (&Path, String),
    ) -> Result<(), ModuleError> {
        let file = ctx.input_file()?;
        let name = member.rsplit('/').next().unwrap_or(member);
        let target = name.to_owned();
        if name.is_empty() || !name_fits(&target) {
            return Ok(());
        }
        let mut new_file = ctx.write_file_from(&target, &mut fs::File::open(path)?, &[])?;
        new_file.detections.push(
            Detection::new(format!(
                "Possible CVE-2021-30657 attack: a file in DMG format file {} is a script",
                file.path
            ))
            .with_signature(CVE_2021_30657_DMG_SCRIPT),
        );
        new_file.tags.push("CVE-2021-30657".to_owned());
        result.files.push(new_file);
        if result
            .details
            .suspect_files
            .insert(target.clone(), mime)
            .is_none()
        {
            order.push(target);
        }
        Ok(())
    }
}

/// The members in order, one per run while there are runs enough, else shared out over `runs`.
fn batches(members: &[String], runs: usize) -> std::slice::Chunks<'_, String> {
    let size = members.len().div_ceil(runs.max(1)).max(1);
    members.chunks(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
7-Zip 25.01 (arm64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03

--
Path = image.img
Type = APM
----
Path = Mac_OS_X.hfsx
Size = 4194304
--
Path = Mac_OS_X.hfsx
Type = HFS

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2026-11-10 18:18:09 D....                            Installer
2026-11-10 18:18:09 .....           33         4096  Installer/Read Me.txt
2026-11-10 18:18:09 D....                            Installer/T.app/Contents/MacOS
2026-11-10 18:18:09 .....           20         4096  Installer/T.app/Contents/MacOS/run
short line
------------------- ----- ------------ ------------  ------------------------
2026-11-10 18:18:09                 53         8192  2 files, 3 folders
";

    #[test]
    fn the_listing_s_files_are_its_lines_between_the_rules_without_folders() {
        assert_eq!(
            file_list(LISTING).unwrap(),
            [
                "2026-11-10 18:18:09 .....           33         4096  Installer/Read Me.txt",
                "2026-11-10 18:18:09 .....           20         4096  Installer/T.app/Contents/MacOS/run",
            ]
        );
        // ace3 indexes the 21st character of a line of 20
        let twenty = format!("{}\n{}\n", "-".repeat(19), "x".repeat(20));
        assert!(file_list(&twenty).is_err());
    }

    #[test]
    fn a_member_s_path_is_what_follows_the_sizes() {
        let module = Cve202130657Analyzer::init(&()).unwrap();
        let line = "2021-04-06 23:33:06 .....        59039        61440  Installer/yWnBJLaF/1302.app/Contents/MacOS/1302 2";
        assert_eq!(
            &module.entry.captures(line).unwrap()[1],
            "Installer/yWnBJLaF/1302.app/Contents/MacOS/1302 2"
        );
        // a line with no sizes, which 7z prints for an item it has none for
        assert!(
            module
                .entry
                .captures("2021-04-06 23:33:06 .....                            x/Contents/MacOS/y")
                .is_none()
        );
    }

    #[test]
    fn members_get_a_run_each_until_there_are_more_than_runs() {
        let members: Vec<String> = (0..63).map(|i| i.to_string()).collect();
        assert_eq!(batches(&members, 63).count(), 63);
        let members: Vec<String> = (0..64).map(|i| i.to_string()).collect();
        let shared: Vec<usize> = batches(&members, 63).map(<[String]>::len).collect();
        assert_eq!(shared.len(), 32);
        assert_eq!(shared.iter().sum::<usize>(), 64);
        assert_eq!(batches(&[], 63).count(), 0);
    }
}
