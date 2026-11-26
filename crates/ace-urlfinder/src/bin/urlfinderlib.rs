//! `urlfinderlib FILE [--text] [--domain-as-url] [--mimetype M] [--base-url U]`: what the port
//! finds in a file, as JSON, for comparing with urlfinderlib itself:
//! `{"output": [urls, sorted]}` or `{"error": {"type": ..., "message": ...}}`. `--soup` prints
//! BeautifulSoup's `get_text()` of the file instead, and `--lxml` lxml's serializations of it.

use std::path::Path;
use std::process::ExitCode;

use ace_urlfinder::magic::{DATABASE, Database};
use ace_urlfinder::{Finder, find_urls_in_text};

/// `--batch DIR`: every file of a directory in each of the oracle script's modes, as one JSON
/// object keyed `name|mode`.
fn batch(dir: &str) -> ExitCode {
    let database = Database::open(Path::new(DATABASE));
    let magic = database.load().expect("libmagic");
    let finder = Finder::new(&magic);
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the directory")
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect();
    names.sort();
    let mut out = serde_json::Map::new();
    for name in names {
        let blob = std::fs::read(format!("{dir}/{name}")).expect("a file");
        for mode in ["default", "domain", "text", "textdomain", "plain", "base"] {
            let result = match mode {
                "default" => finder.find_urls(&blob, "", "", false),
                "domain" => finder.find_urls(&blob, "", "", true),
                "text" => find_urls_in_text(&blob, false),
                "textdomain" => find_urls_in_text(&blob, true),
                "plain" => finder.find_urls(&blob, "", "text/plain", false),
                _ => finder.find_urls(
                    &blob,
                    "https://base.example.com/dir/page.html",
                    "text/html",
                    false,
                ),
            };
            let json = match result {
                Ok(urls) => serde_json::json!({"output": urls}),
                Err(e) => serde_json::json!({"error": {"type": e.kind, "message": e.message}}),
            };
            out.insert(format!("{name}|{mode}"), json);
        }
        let text = ace_pycompat::pystr::decode_utf8_ignore(&blob);
        out.insert(
            format!("{name}|soup"),
            serde_json::json!({"output": ace_lxml::soup::get_text(&text)}),
        );
        let lxml = match ace_lxml::Document::parse_html(text.as_bytes()) {
            Ok(doc) => serde_json::json!({"output": {
                "html": doc.tostring_html().unwrap_or_default(),
                "text": String::from_utf8_lossy(&doc.tostring_text().unwrap_or_default()),
            }}),
            Err(e) => serde_json::json!({"error": {"type": "lxml", "message": e.to_string()}}),
        };
        out.insert(format!("{name}|lxml"), lxml);
    }
    println!("{}", serde_json::Value::Object(out));
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    if let Some(first) = std::env::args().nth(1)
        && first == "--batch"
    {
        return batch(&std::env::args().nth(2).unwrap_or_default());
    }
    let mut path = None;
    let (mut text, mut domain_as_url, mut soup, mut lxml) = (false, false, false, false);
    let (mut mimetype, mut base_url) = (String::new(), String::new());
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--text" => text = true,
            "--domain-as-url" => domain_as_url = true,
            "--soup" => soup = true,
            "--lxml" => lxml = true,
            "--mimetype" => mimetype = args.next().unwrap_or_default(),
            "--base-url" => base_url = args.next().unwrap_or_default(),
            _ => path = Some(arg),
        }
    }
    let Some(path) = path else {
        eprintln!(
            "usage: urlfinderlib FILE [--text] [--domain-as-url] [--mimetype M] [--base-url U]"
        );
        return ExitCode::from(2);
    };
    let blob = match std::fs::read(&path) {
        Ok(blob) => blob,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::from(2);
        }
    };
    if soup {
        let text = ace_pycompat::pystr::decode_utf8_ignore(&blob);
        println!(
            "{}",
            serde_json::json!({"output": ace_lxml::soup::get_text(&text)})
        );
        return ExitCode::SUCCESS;
    }
    if lxml {
        let text = ace_pycompat::pystr::decode_utf8_ignore(&blob);
        let json = match ace_lxml::Document::parse_html(text.as_bytes()) {
            Ok(doc) => serde_json::json!({"output": {
                "html": doc.tostring_html().ok(),
                "text": doc.tostring_text().ok().map(|t| String::from_utf8_lossy(&t).into_owned()),
            }}),
            Err(e) => serde_json::json!({"error": {"type": "lxml", "message": e.to_string()}}),
        };
        println!("{json}");
        return ExitCode::SUCCESS;
    }
    let result = if text {
        find_urls_in_text(&blob, domain_as_url)
    } else {
        let database = Database::open(Path::new(DATABASE));
        let magic = match database.load() {
            Ok(magic) => magic,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        };
        Finder::new(&magic).find_urls(&blob, &base_url, &mimetype, domain_as_url)
    };
    let json = match result {
        Ok(urls) => serde_json::json!({"output": urls}),
        Err(e) => serde_json::json!({"error": {"type": e.qualified_name(), "message": e.message}}),
    };
    println!("{json}");
    ExitCode::SUCCESS
}
