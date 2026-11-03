//! The example site's network pool: the open-source lookups and the site's ticket lookup.

fn main() -> std::process::ExitCode {
    ace_site_example::app().pool_main("lookups")
}
