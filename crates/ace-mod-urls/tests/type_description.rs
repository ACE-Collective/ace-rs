//! url_extraction gives urlfinderlib the type step's description of the file, where ace3's
//! urlfinderlib asks libmagic again (the module's doc comment says why).

use std::path::{Path, PathBuf};

use ace_mod_urls::UrlExtraction;
use ace_sdk::Outcome;
use ace_testkit::{Harness, file_type_details};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures")
}

fn urls(outcome: &Outcome<ace_results::types::url_extraction::UrlExtractionAnalysis>) -> &[String] {
    match outcome {
        Outcome::Done(result) => &result.details.urls,
        other => panic!("not done: {other:?}"),
    }
}

/// libmagic calls lines.txt ASCII text, and urlfinderlib finds its URLs. Described as mail, which
/// urlfinderlib returns nothing for, it has none: the description, not libmagic, chose.
#[test]
fn the_type_steps_description_chooses_the_finder() {
    let path = fixtures().join("urls/lines.txt");
    let run = |description: &str| {
        let harness = Harness::<UrlExtraction>::new()
            .expect("harness")
            .dependency_result("file_type", file_type_details(description, "text/plain"));
        let observable = harness
            .file("lines.txt", &path, &[])
            .expect("the fixture")
            .with_directive("extract_urls");
        harness.run_parser(observable).expect("the module runs")
    };
    assert!(!urls(&run("ASCII text")).is_empty());
    assert_eq!(urls(&run("news or mail, ASCII text")), &[] as &[String]);
}

/// A run of url_extraction on `path` with this file_type result, from a harness on `harness`.
fn run_with(
    harness: Harness<UrlExtraction>,
    path: &Path,
    description: &str,
    mime: &str,
) -> Result<
    Outcome<ace_results::types::url_extraction::UrlExtractionAnalysis>,
    ace_testkit::HarnessError,
> {
    let harness = harness.dependency_result("file_type", file_type_details(description, mime));
    let name = path.file_name().and_then(|n| n.to_str()).expect("a name");
    let observable = harness
        .file(name, path, &[])?
        .with_directive("extract_urls");
    harness.run_parser(observable)
}

/// Each routing class urlfinderlib's first choice reads (mail, HTML, calendar, XML, PDF, text and
/// the rest as data), and UTF-16, which it describes again: for each file the type step's
/// description leads to what libmagic's `from_buffer` leads to, the module's result with the one
/// the same as with the other. The words are what the description has to hold for the file to be
/// in its class, so a file whose description changed class fails here rather than covering less.
#[test]
fn the_type_steps_description_finds_what_libmagic_finds() {
    let samples = ace_testkit::samples_dir();
    let cases: &[(PathBuf, &str)] = &[
        (fixtures().join("urls/email.eml"), "mail"),
        (
            samples.join("ace-rs/email/url_newsletter.email.rfc822"),
            "mail",
        ),
        (fixtures().join("urls/page.html"), "html"),
        (fixtures().join("urls/relative.html"), "html"),
        (samples.join("ace-rs/html/html2text_markup.html"), "html"),
        (fixtures().join("urls/invite.ics"), "icalendar"),
        (fixtures().join("html/invite.ics"), "vcalendar"),
        (fixtures().join("urls/doc.xml"), "xml"),
        (samples.join("ace-rs/office/word2003.xml"), "xml"),
        (samples.join("ace-rs/pdf/annot_items.pdf"), "pdf"),
        (samples.join("ace-rs/pdf/action_array.pdf"), "pdf"),
        (fixtures().join("urls/lines.txt"), "text"),
        (fixtures().join("urls/data.json"), "text"),
        (fixtures().join("urls/table.csv"), "text"),
        (fixtures().join("urls/mandrill.txt"), "text"),
        (fixtures().join("urls/binary.bin"), "data"),
        // libmagic's from_buffer calls a zip "data", and the type step names the archive
        (samples.join("ace3/archive/test.jar"), "java archive"),
        (fixtures().join("files/app.jar.bin"), "zip archive"),
        (
            samples.join("ace-rs/office/xlm_yara_rule.zip"),
            "zip archive",
        ),
        (
            fixtures().join("office/rels/gzip/document.xml.rels"),
            "gzip",
        ),
        (fixtures().join("office/plain/utf16.xml"), "utf-16"),
    ];
    let mut found = 0;
    for (path, class) in cases {
        let name = path.file_name().and_then(|n| n.to_str()).expect("a name");
        let facts = ace_mod_files::file_type::type_of(name, path)
            .unwrap_or_else(|| panic!("{}: the type step typed nothing", path.display()));
        let description = facts.description.to_lowercase();
        assert!(
            description.contains(class),
            "{}: {description}",
            path.display()
        );
        let harness = || Harness::<UrlExtraction>::new().expect("harness");
        let typed = run_with(harness(), path, &facts.description, &facts.mime).expect("runs");
        let untyped = run_with(harness(), path, "", &facts.mime).expect("runs");
        assert_eq!(
            ace_testkit::snapshot_value(&typed),
            ace_testkit::snapshot_value(&untyped),
            "{}: {description}",
            path.display()
        );
        if let Outcome::Done(result) = &typed {
            found += result.details.urls.len();
        }
    }
    // the files hold URLs, so the comparison isn't of empty results only
    assert!(found >= 20, "only {found} URLs");
}

/// With the description given, a module whose libmagic database is missing still extracts; bytes
/// urlfinderlib has to describe itself fail the task, naming the database, and aren't skipped.
#[test]
fn only_bytes_urlfinderlib_describes_itself_need_libmagics_database() {
    let missing = || UrlExtraction::with_database(Path::new("/nonexistent/magic.mgc"));
    let harness = || {
        Harness::<UrlExtraction>::new()
            .expect("harness")
            .with_module(missing())
    };
    let page = fixtures().join("urls/page.html");
    let typed = run_with(harness(), &page, "HTML document, ASCII text", "text/html").expect("runs");
    assert!(!urls(&typed).is_empty());

    for (path, description) in [
        (&page, ""),
        (
            &fixtures().join("office/plain/utf16.xml"),
            "XML 1.0 document, Unicode text, UTF-16, little-endian text",
        ),
    ] {
        match run_with(harness(), path, description, "text/xml") {
            Err(ace_testkit::HarnessError::Module(e)) => {
                assert!(e.to_string().contains("/nonexistent/magic.mgc"), "{e}")
            }
            other => panic!("{description:?}: {other:?}"),
        }
    }
}
