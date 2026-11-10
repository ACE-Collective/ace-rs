//! The sandbox pool: the modules that run programs in the sandbox runner (PLAN.md 7.3), one contained
//! task process per task, with each program it asks for run as a contained process of its own.

fn main() -> std::process::ExitCode {
    ace::app().pool_main("sandbox")
}
