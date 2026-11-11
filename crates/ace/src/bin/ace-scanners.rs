//! The scanner pool (PLAN.md 7.7): the one process that holds the Docker socket, which runs the
//! phishkit and js-deobfuscator scanner images for the scans modules ask for, and parses nothing they
//! write.

fn main() -> std::process::ExitCode {
    ace::app().pool_main("scanners")
}
