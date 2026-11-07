//! The diff of `tools/library-diff/run` (PLAN.md 4.8): `library-diff WORK [DIFFERENCES.md]`. Exits 0
//! when the threshold is met and 1 when not. See `ace_testkit::library_diff`.

use std::path::Path;
use std::process::ExitCode;

use ace_testkit::library_diff;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [work, rest @ ..] = args.as_slice() else {
        eprintln!("usage: library-diff WORK [DIFFERENCES.md]");
        return ExitCode::from(2);
    };
    match library_diff::compare(Path::new(work), rest.first().map(Path::new)) {
        Ok(report) => {
            print!("{}", report.text);
            if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("library-diff: {error}");
            ExitCode::from(2)
        }
    }
}
