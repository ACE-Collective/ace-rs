//! Prints what the crate reads of each .xlsb named on stdin, one JSON line each, for tools that diff it
//! against XLSBWrapper. Its zip reading and rels parsing are only good enough for that.

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};

use ace_xlsb::{CellValue, Package, Rel, RelsXml, Workbook, XlError, float_str};

const CALLER_FRAMES: usize = 3;

struct Zip {
    files: BTreeMap<String, Vec<u8>>,
}

impl Zip {
    fn open(path: &str) -> Result<Zip, String> {
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
        let mut files = BTreeMap::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).map_err(|e| e.to_string())?;
            let mut data = Vec::new();
            entry.read_to_end(&mut data).map_err(|e| e.to_string())?;
            let name = entry.name().map_err(|e| e.to_string())?.into_owned();
            files.insert(name, data);
        }
        Ok(Zip { files })
    }
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    let start = tag.find(&format!(" {name}=\""))? + name.len() + 3;
    let rest = tag.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end).map(|value| value.replace("&amp;", "&"))
}

/// The simple rels XML the generator and samples use.
fn parse_rels(text: &str) -> RelsXml {
    let mut relationships = Vec::new();
    for piece in text.split('<').skip(1) {
        let tag = piece.split('>').next().unwrap_or("");
        if tag.starts_with("Relationship ") || tag.starts_with("Relationship/") {
            relationships.push(Rel {
                id: attribute(tag, "Id"),
                target: attribute(tag, "Target"),
                rel_type: attribute(tag, "Type"),
            });
        }
    }
    let children = text
        .split('<')
        .skip(1)
        .filter(|p| !p.starts_with('?'))
        .count();
    RelsXml {
        has_children: children > 1 && !text.contains("<Relationships/>"),
        relationships,
    }
}

impl Package for Zip {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, XlError> {
        Ok(self.files.get(name).cloned())
    }

    fn rels_xml(&self, name: &str) -> Result<Option<RelsXml>, XlError> {
        Ok(self
            .files
            .get(name)
            .map(|data| parse_rels(&String::from_utf8_lossy(data))))
    }
}

fn json(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_opt(text: Option<&str>) -> String {
    text.map_or("null".to_string(), json)
}

fn json_error(error: &XlError) -> String {
    format!("[{},{}]", json(&error.kind), json(&error.message))
}

fn json_value(value: &CellValue) -> String {
    let (kind, text) = match value {
        CellValue::None => return "[\"none\",null]".to_string(),
        CellValue::Text(text) => ("text", text.clone()),
        CellValue::Float(value) => ("float", float_str(*value)),
        CellValue::Int(value) => ("int", value.to_string()),
        CellValue::Bool(value) => ("bool", value.to_string()),
        CellValue::Error(text) => ("error", text.clone()),
    };
    format!("[{},{}]", json(kind), json(&text))
}

fn load_json(book: &Workbook, zip: &Zip, name: Option<&str>) -> String {
    let mut log = String::new();
    let result = book.load_cells_with_frames(zip, name, CALLER_FRAMES, &mut log, &|| false);
    let (error, cells) = match result {
        Ok(cells) => {
            let cells: Vec<String> = cells
                .iter()
                .map(|cell| {
                    format!(
                        "[{},{},{},{}]",
                        cell.row,
                        json(&cell.column),
                        json_value(&cell.value),
                        json_opt(cell.formula.as_deref())
                    )
                })
                .collect();
            ("null".to_string(), cells.join(","))
        }
        Err(error) => (json_error(&error), String::new()),
    };
    format!(
        "{{\"sheet\":{},\"error\":{error},\"log\":{},\"cells\":[{cells}]}}",
        json_opt(name),
        json(&log)
    )
}

fn dump(path: &str) -> String {
    let zip = match Zip::open(path) {
        Ok(zip) => zip,
        Err(error) => return format!("{{\"file\":{},\"zip\":{}}}", json(path), json(&error)),
    };
    let mut log = String::new();
    let book = Workbook::open_with_frames(&zip, CALLER_FRAMES, &mut log, &|| false);
    let book = match book {
        Ok(book) => book,
        Err(error) => {
            return format!(
                "{{\"file\":{},\"open_error\":{},\"open_log\":{}}}",
                json(path),
                json_error(&error),
                json(&log)
            );
        }
    };
    let names = match book.defined_names() {
        Ok(names) => {
            let items: Vec<String> = names
                .iter()
                .map(|(key, (lower, formula))| {
                    format!(
                        "[{},{},{}]",
                        json(key),
                        json(lower),
                        json_opt(formula.as_deref())
                    )
                })
                .collect();
            format!("[null,[{}]]", items.join(","))
        }
        Err(error) => format!("[{},[]]", json_error(&error)),
    };
    let sheets: Vec<String> = book
        .sheets()
        .iter()
        .map(|s| {
            format!(
                "[{},{}]",
                json_opt(s.name.as_deref()),
                json_opt(s.sheet_type.as_deref())
            )
        })
        .collect();
    let mut loads: Vec<String> = book
        .sheets()
        .iter()
        .map(|s| load_json(&book, &zip, s.name.as_deref()))
        .collect();
    loads.push(load_json(&book, &zip, Some("NoSuchSheet")));
    format!(
        "{{\"file\":{},\"open_error\":null,\"open_log\":{},\"names\":{names},\"sheets\":[{}],\"loads\":[{}]}}",
        json(path),
        json(&log),
        sheets.join(","),
        loads.join(",")
    )
}

fn main() {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        let text = std::panic::catch_unwind(|| dump(&line))
            .unwrap_or_else(|_| format!("{{\"file\":{},\"panic\":true}}", json(&line)));
        writeln!(out, "{text}").expect("write to stdout");
    }
}
