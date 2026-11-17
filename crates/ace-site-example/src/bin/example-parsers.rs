//! The example site's parser pool: the open-source parsers and the site's ticket file parser.

fn main() -> std::process::ExitCode {
    ace_site_example::app().pool_main("parsers")
}
