//! ACE archives, which ace3 lists and extracts with unace (`archive.py`'s `_run_unace`), here in the
//! sandbox runner. unace looks for an archive's other volumes beside it, so ace3 runs it on a copy in
//! a directory of its own; here the runner copies the archive into the tool's working directory,
//! which is where `unace x` extracts it.

use std::fs::File;
use std::time::Duration;

use ace_results::types::archive::ArchiveAnalysis;
use ace_sdk::tools::{ToolRun, ToolStop, is_plain_name};
use ace_sdk::{InputFile, ModuleError, Outcome, TaskContext};

use crate::{ArchiveSettings, priority, result_of};

/// ace3's `timeout` for each tool the module runs.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The count in unace's `listed: N files, ...` line, as ace3's `UNACE_SUMMARY_REGEX` reads it.
fn listed(stdout: &[u8]) -> u64 {
    for line in stdout.split(|&b| b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"listed: ") {
            let digits: Vec<u8> = rest
                .iter()
                .copied()
                .take_while(u8::is_ascii_digit)
                .collect();
            if !digits.is_empty() && rest[digits.len()..].starts_with(b" files,") {
                return std::str::from_utf8(&digits)
                    .ok()
                    .and_then(|d| d.parse().ok())
                    .unwrap_or(0);
            }
        }
    }
    0
}

/// ace3's ACE branch: the count from `unace l`, then `unace x -y -o`, and what it extracted, the
/// riskiest kinds first, up to `max_file_count`.
pub(crate) fn analyze(
    ctx: &TaskContext<ArchiveSettings>,
    file: &InputFile,
) -> Result<Outcome<ArchiveAnalysis>, ModuleError> {
    let settings = ctx.settings();
    // ace3 copies it as its own name
    let name = if is_plain_name(file.name()) {
        file.name()
    } else {
        "archive.ace"
    };
    let listing = ctx.run_tool(
        ToolRun::new("unace", ["l", name])
            .stage(&file.local_path, name)
            .timeout(TIMEOUT),
    )?;
    // a listing cut short by the output limit is still read, and has more files than any limit
    let too_large = listing.stopped() == Some(ToolStop::Output);
    if listing.stopped().is_some() && !too_large {
        return Ok(Outcome::Skipped(
            "unace didn't finish its listing".to_owned(),
        ));
    }
    let mut count = listed(listing.stdout_text().as_bytes());
    if too_large {
        count = count
            .max(settings.max_file_count)
            .max(settings.max_jar_file_count)
            + 1;
    }
    if count == 0 {
        return Ok(Outcome::Skipped("the archive lists no files".to_owned()));
    }
    let limit = (settings.max_file_count != 0 && count > settings.max_file_count)
        .then_some(settings.max_file_count as usize);

    // what it extracted before it was stopped is still analyzed
    let extraction = ctx.run_tool(
        ToolRun::new("unace", ["x", "-y", "-o", name])
            .stage(&file.local_path, name)
            .keep_tree()
            .keep_stopped()
            .timeout(TIMEOUT),
    )?;
    if let Some(stop) = extraction.stopped() {
        tracing::warn!(?stop, "unace didn't finish extracting");
    }
    let base = format!("{}.extracted", file.path.as_str().replace('*', "_"));
    let mut extracted: Vec<(&String, &std::path::PathBuf)> = extraction.outputs.iter().collect();
    extracted.sort_by_key(|(relative, _)| priority(&format!("{base}/{relative}")));
    if let Some(limit) = limit {
        extracted.truncate(limit);
    }
    let mut members = Vec::new();
    for (relative, path) in extracted {
        let Some(relative) = crate::extracted_name(crate::formats::Format::Zip, relative) else {
            continue;
        };
        let new_file =
            ctx.write_file_from(&format!("{base}/{relative}"), &mut File::open(path)?, &[])?;
        members.push((relative, new_file));
    }
    Ok(Outcome::Done(result_of(file, count, false, members)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_count_is_unaces_summary_line() {
        let listing = b"UNACE v2.5\n\nlisted: 1 files, summing     180178 bytes\n";
        assert_eq!(listed(listing), 1);
        assert_eq!(listed(b"listed: x files,"), 0);
        assert_eq!(listed(b"nothing"), 0);
    }
}
