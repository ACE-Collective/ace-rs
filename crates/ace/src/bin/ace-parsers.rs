//! The parser pool: the email, archive and YARA modules, one contained task process per task.

fn main() -> std::process::ExitCode {
    ace::app().pool_main("parsers")
}
