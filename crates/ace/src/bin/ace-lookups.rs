//! The network pool: the RDAP and Splunk modules, as async tasks in one contained process.

fn main() -> std::process::ExitCode {
    ace::app().pool_main("lookups")
}
