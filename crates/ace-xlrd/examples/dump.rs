//! Prints what the crate reads of each file listed in argv[1], one JSON line each, to compare
//! with the same dump from XLSWrapper2. argv[2] is the output; argv[3] the seconds per file.

use std::fmt::Write as _;
use std::io::Write as _;
use std::time::{Duration, Instant};

use ace_xlrd::{Book, CellValue, NameValue, SheetType, XlError, float_repr};

fn js(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            ' '..='~' => o.push(c),
            _ => {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    write!(o, "\\u{u:04x}").expect("string write");
                }
            }
        }
    }
    o.push('"');
    o
}

fn err(e: &XlError) -> String {
    format!("[{}, {}]", js(&e.kind), js(&e.message))
}

fn cell(v: &CellValue) -> String {
    match v {
        CellValue::None => "[\"n\"]".to_string(),
        CellValue::Text(s) => format!("[\"s\", {}]", js(s)),
        CellValue::Float(f) => format!("[\"f\", {}]", js(&float_repr(*f))),
        CellValue::Int(i) => format!("[\"i\", {i}]"),
    }
}

fn name(v: &NameValue) -> String {
    match v {
        NameValue::None => "[\"n\"]".to_string(),
        NameValue::Text(s) => format!("[\"s\", {}]", js(s)),
        NameValue::Num(f) => format!("[\"f\", {}]", js(&float_repr(*f))),
        NameValue::Int(i) => format!("[\"i\", {i}]"),
        other => format!("[\"r\", {}]", js(&other.py_str())),
    }
}

fn process(path: &str, limit: Duration) -> String {
    let data = std::fs::read(path).expect("read");
    let start = Instant::now();
    let expired = move || start.elapsed() > limit;
    let mut log = String::new();
    let book = match Book::open(&data, &mut log, &expired) {
        Ok(b) => b,
        Err(e) if e.kind == "PassTimeout" => {
            return format!("{{\"file\": {}, \"timeout\": true}}", js(path));
        }
        Err(e) => {
            return format!(
                "{{\"file\": {}, \"error\": {}, \"log\": {}}}",
                js(path),
                err(&e),
                js(&log)
            );
        }
    };
    let mut out = format!("{{\"file\": {}", js(path));
    match book.defined_names() {
        Ok(n) => {
            let items: Vec<String> = n
                .iter()
                .map(|(k, v)| format!("[{}, {}]", js(k), name(v)))
                .collect();
            write!(out, ", \"names\": [{}]", items.join(", ")).expect("string write");
        }
        Err(e) => write!(out, ", \"names_error\": {}", err(&e)).expect("string write"),
    }
    let mut shs = Vec::new();
    for (i, s) in book.sheets().iter().enumerate() {
        let cells = book.load_cells(i, &mut log);
        let shown: Vec<String> = cells
            .iter()
            .map(|c| {
                format!(
                    "[{}, {}, {}, {}]",
                    c.row,
                    js(&c.column),
                    c.formula.as_deref().map_or("null".to_string(), js),
                    cell(&c.value)
                )
            })
            .collect();
        let mut pts: Vec<(String, String)> = cells
            .iter()
            .take(3)
            .map(|c| (c.column.clone(), c.row.to_string()))
            .collect();
        for (a, b) in [
            ("A", "1"),
            ("ZZ", "70000"),
            ("A", "0"),
            ("", "1"),
            ("b", "2"),
        ] {
            pts.push((a.to_string(), b.to_string()));
        }
        let mut info = Vec::new();
        for (col, row) in &pts {
            for id in [5, 8, 17, 19, 24, 38, 50, 99] {
                info.push(match book.get_cell_info(&s.name, col, row, id) {
                    Ok((d, ne, ni)) => format!("[{}, {ne}, {ni}]", cell(&d)),
                    Err(e) => err(&e),
                });
            }
        }
        let t = match s.boundsheet_type {
            SheetType::Macrosheet => 0x40,
            SheetType::Worksheet => 0x10,
            SheetType::Other => 0,
        };
        shs.push(format!(
            "{{\"name\": {}, \"type\": {t}, \"cells\": [{}], \"cerr\": null, \"info\": [{}]}}",
            js(&s.name),
            shown.join(", "),
            info.join(", ")
        ));
    }
    write!(out, ", \"sheets\": [{}]", shs.join(", ")).expect("string write");
    if let Err(e) = book.get_cell_info("no such sheet", "A", "1", 5) {
        write!(out, ", \"missing\": {}", err(&e)).expect("string write");
    }
    write!(out, ", \"log\": {}}}", js(&log)).expect("string write");
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let list = std::fs::read_to_string(&args[1]).expect("list");
    let mut f = std::fs::File::create(&args[2]).expect("create");
    let secs: u64 = args.get(3).map_or(20, |s| s.parse().expect("seconds"));
    for p in list.lines() {
        writeln!(f, "{}", process(p, Duration::from_secs(secs))).expect("write");
    }
}
