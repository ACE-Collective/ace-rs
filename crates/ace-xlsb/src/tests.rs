use super::*;
use std::collections::HashMap;

/// A package from parts and one relationships document.
#[derive(Default)]
struct Parts {
    files: HashMap<String, Vec<u8>>,
    rels: Option<RelsXml>,
}

impl Package for Parts {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, XlError> {
        Ok(self.files.get(name).cloned())
    }

    fn rels_xml(&self, name: &str) -> Result<Option<RelsXml>, XlError> {
        Ok(if name.contains('/') {
            self.rels.clone()
        } else {
            None
        })
    }
}

fn record(rectype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if rectype < 0x80 {
        out.push(rectype as u8);
    } else {
        out.push((rectype & 0x7F) as u8 | 0x80);
        out.push((rectype >> 7) as u8);
    }
    let mut len = payload.len();
    loop {
        let byte = (len & 0x7F) as u8;
        len >>= 7;
        if len == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out.extend_from_slice(payload);
    out
}

fn wide(text: &str) -> Vec<u8> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let mut out = (units.len() as u32).to_le_bytes().to_vec();
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn sheet_record(r_id: &str, name: &str) -> Vec<u8> {
    let mut payload = vec![0; 8];
    payload.extend(wide(r_id));
    payload.extend(wide(name));
    record(reader::BUNDLE_SH, &payload)
}

fn name_record(name: &str, formula: &[u8]) -> Vec<u8> {
    let mut payload = vec![0; 9];
    payload.extend(wide(name));
    payload.extend((formula.len() as u32).to_le_bytes());
    payload.extend_from_slice(formula);
    record(reader::NAME, &payload)
}

fn formula_cell(col: u32, value: f64, formula: &[u8]) -> Vec<u8> {
    let mut payload = col.to_le_bytes().to_vec();
    payload.extend(0u32.to_le_bytes());
    payload.extend(value.to_le_bytes());
    payload.extend(0u16.to_le_bytes());
    payload.extend((formula.len() as u32).to_le_bytes());
    payload.extend_from_slice(formula);
    record(9, &payload)
}

fn one_sheet(workbook: Vec<u8>, sheet: Vec<u8>) -> Parts {
    let mut parts = Parts::default();
    parts.files.insert("xl/workbook.bin".into(), workbook);
    parts.files.insert("xl/sheet1.bin".into(), sheet);
    parts.rels = Some(RelsXml {
        has_children: true,
        relationships: vec![Rel {
            id: Some("rId1".into()),
            target: Some("sheet1.bin".into()),
            rel_type: Some(MACROSHEET_TYPE.into()),
        }],
    });
    parts
}

fn never() -> bool {
    false
}

#[test]
fn reads_cells_names_and_a_dropped_last_row() {
    let workbook = [
        sheet_record("rId1", "Macro1"),
        name_record("Auto_Open", &[0x24, 0, 0, 0, 0, 0, 0xC0]),
    ]
    .concat();
    let sheet = [
        record(reader::BEGIN_SHEET_DATA, &[]),
        record(reader::ROW_HDR, &0u32.to_le_bytes()),
        formula_cell(1, 1.5, &[0x1E, 7, 0, 0x13]),
        record(reader::ROW_HDR, &4u32.to_le_bytes()),
        formula_cell(0, 2.0, &[0x1E, 8, 0]),
    ]
    .concat();
    let parts = one_sheet(workbook, sheet);
    let mut log = String::new();
    let book = Workbook::open(&parts, &mut log, &never).unwrap();
    let names = book.defined_names().unwrap();
    assert_eq!(
        names.get("auto_open"),
        Some(&("auto_open".to_string(), Some("A1".to_string())))
    );
    assert_eq!(book.sheets()[0].sheet_type.as_deref(), Some("macrosheet"));
    let cells = book
        .load_cells(&parts, Some("MACRO1"), &mut log, &never)
        .unwrap();
    assert_eq!(
        cells,
        vec![LoadedCell {
            row: 1,
            column: "B".into(),
            value: CellValue::Float(1.5),
            formula: Some("=-7".into()),
        }]
    );
}

#[test]
fn a_formula_error_is_printed_and_a_short_token_escapes() {
    let sheet = [
        record(reader::BEGIN_SHEET_DATA, &[]),
        record(reader::ROW_HDR, &0u32.to_le_bytes()),
        formula_cell(0, 1.0, &[0x03]),
        record(reader::END_SHEET_DATA, &[]),
    ]
    .concat();
    let parts = one_sheet(sheet_record("rId1", "S"), sheet);
    let mut log = String::new();
    let book = Workbook::open(&parts, &mut log, &never).unwrap();
    let cells = book
        .load_cells(&parts, Some("S"), &mut log, &never)
        .unwrap();
    assert_eq!(cells[0].formula, None);
    assert!(log.starts_with("ERROR Cell(row=<pyxlsb2.row.Row object at 0x0>, col=0, value=1.0, formula=b'\\x03', style_id=0)"));

    let sheet = [
        record(reader::BEGIN_SHEET_DATA, &[]),
        record(reader::ROW_HDR, &0u32.to_le_bytes()),
        formula_cell(0, 1.0, &[0x24, 0]),
        record(reader::END_SHEET_DATA, &[]),
    ]
    .concat();
    let parts = one_sheet(sheet_record("rId1", "S"), sheet);
    let book = Workbook::open(&parts, &mut log, &never).unwrap();
    let error = book
        .load_cells(&parts, Some("S"), &mut log, &never)
        .unwrap_err();
    assert_eq!(
        error,
        XlError::new(
            "TypeError",
            "unsupported operand type(s) for &: 'NoneType' and 'int'"
        )
    );
}

#[test]
fn deep_formulas_raise_recursion_error_without_a_deep_stack() {
    let mut formula = vec![0x1E, 1, 0];
    formula.extend(std::iter::repeat_n(0x13, 200_000));
    let parts = one_sheet(name_record("x", &formula), Vec::new());
    let mut log = String::new();
    let error = Workbook::open(&parts, &mut log, &never).err().unwrap();
    assert_eq!(error.kind, "RecursionError");
}

#[test]
fn expired_stops_the_record_loop() {
    let parts = one_sheet(name_record("x", &[0x16]), Vec::new());
    let mut log = String::new();
    let error = Workbook::open(&parts, &mut log, &|| true).err().unwrap();
    assert_eq!(error.kind, "PassTimeout");
}

#[test]
fn python_float_text() {
    for (value, text) in [
        (1.0, "1.0"),
        (-0.0, "-0.0"),
        (1e16, "1e+16"),
        (1e15, "1000000000000000.0"),
        (1e-5, "1e-05"),
        (0.0001, "0.0001"),
        (1.5e300, "1.5e+300"),
        (123.456, "123.456"),
        (1.5000076293945312, "1.5000076293945312"),
        (f64::INFINITY, "inf"),
    ] {
        assert_eq!(float_str(value), text);
    }
    assert_eq!(float_str(f64::NAN), "nan");
}

#[test]
fn utf16_follows_the_bom_and_replaces_lone_surrogates() {
    assert_eq!(
        reader::decode_utf16(&[0x41, 0, 0x00, 0xD8, 0x42, 0]),
        "A\u{FFFD}B"
    );
    assert_eq!(reader::decode_utf16(&[0xFE, 0xFF, 0, 0x41]), "A");
    assert_eq!(reader::decode_utf16(&[0xFF, 0xFE, 0x41, 0]), "A");
}
