//! A port of XLMMacroDeobfuscator 0.2.7 as its two callers use it: ace3's module, which runs the command
//! with `-f` and with `-x`, and olevba, which calls `process_file`. It reads workbooks through
//! `ace-xlrd`, `ace-xlsb` and `wrapper.rs`, and parses formulas on `lark.rs`.
//!
//! The command's other switches aren't here, nor MS Excel's wrapper, JSON export, the interactive shell
//! past its first read (stdin is at its end) or `guess_day` (nothing can reach it).

mod grammar_tables;
mod interp;
mod lark;
mod sheet;
mod value;
mod wrapper;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use crate::msoffcrypto::method::Stop;
use crate::msoffcrypto::office::OfficeFile;

use interp::{Interpreter, Limits, Step};
use sheet::{CellRef, SheetRef};
use value::{R, Raised, raise};
use wrapper::{Out, OutRef, Wrapper};

/// What the deobfuscator's top-level try prints for `process_file`.
const MAIN_LINE: &str = "Error [deobfuscator.py:3195 process_file(**vars(args))]: ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileType {
    Xls,
    Xlsm,
    Xlsb,
}

impl FileType {
    fn name(self) -> &'static str {
        match self {
            FileType::Xls => "xls",
            FileType::Xlsm => "xlsm",
            FileType::Xlsb => "xlsb",
        }
    }
}

fn get_file_type(data: &[u8]) -> Option<FileType> {
    if data.starts_with(b"\xD0\xCF") {
        Some(FileType::Xls)
    } else if data.starts_with(b"PK") {
        if memchr::memmem::find(data, b"workbook.bin").is_some() {
            Some(FileType::Xlsb)
        } else {
            Some(FileType::Xlsm)
        }
    } else {
        None
    }
}

/// `try_decrypt`: the plain bytes if it decrypted, and whether it was encrypted at all. What opening or
/// asking raises is printed and means not encrypted.
fn try_decrypt(
    data: &[u8],
    password: &str,
    out: &OutRef,
    silent: bool,
    stop: Stop,
) -> R<(Option<Vec<u8>>, bool)> {
    let attempt = (|| -> crate::py::PyResult<(Option<Vec<u8>>, bool)> {
        let mut office = OfficeFile::open(Arc::new(data.to_vec()), 0)?;
        if !office.is_encrypted()? {
            return Ok((None, false));
        }
        if office.load_key(password, stop).is_err() {
            return Ok((None, true));
        }
        match office.decrypt() {
            Ok(plain) => Ok((Some(plain), true)),
            // its handler closes an int, whose AttributeError goes up, leaving the temporary file empty
            Err(_) => {
                if !silent {
                    out.borrow_mut()
                        .print("'int' object has no attribute 'close'")
                        .map_err(|_| crate::py::memory_error())?;
                }
                Ok((Some(Vec::new()), true))
            }
        }
    })();
    match attempt {
        Ok(answer) => Ok(answer),
        Err(error) => {
            if !silent {
                out.borrow_mut().print(&error.message)?;
            }
            Ok((None, false))
        }
    }
}

fn open_wrapper(
    file_type: FileType,
    data: Vec<u8>,
    name: &str,
    out: &OutRef,
    deadline: Option<Instant>,
) -> R<Wrapper> {
    let expired = wrapper::expired_at(deadline);
    match file_type {
        FileType::Xls => Wrapper::xls(data, name, out.clone(), expired),
        FileType::Xlsm => Wrapper::xlsm(data, name, out.clone(), expired),
        FileType::Xlsb => Wrapper::xlsb(data, out.clone(), expired),
    }
}

/// `show_cells` and `process_file`'s lines for them.
fn extract_lines(excel: &Wrapper, emit: &mut dyn FnMut(&str) -> R<()>) -> R<()> {
    let sheets: Vec<SheetRef> = excel.get_macrosheets()?.into_values().collect();
    for sheet in sheets {
        emit(&format!("SHEET: {}, {}", sheet.name, sheet.kind))?;
        let cells: Vec<CellRef> = sheet.cells.borrow().borrow().values().cloned().collect();
        for with_formula in [true, false] {
            for cell in &cells {
                let cell = cell.borrow();
                if cell.formula.is_some() != with_formula {
                    continue;
                }
                let formula = cell.formula.as_deref().unwrap_or("None");
                let line = "CELL:[[CELL-ADDR]], [[CELL-FORMULA]], [[CELL-VALUE]]"
                    .replace("[[CELL-ADDR]]", &cell.local_address()?)
                    .replace("[[CELL-FORMULA]]", formula)
                    .replace("[[CELL-VALUE]]", &cell.value.to_py_str());
                emit(&line)?;
            }
        }
    }
    Ok(())
}

fn formula_output(step: &Step, with_indent: bool) -> R<String> {
    let indent = if with_indent {
        "\t".repeat(step.indent.max(0) as usize)
    } else {
        String::new()
    };
    let address = step.cell.borrow().local_address()?;
    Ok("CELL:[[CELL-ADDR]], [[STATUS]], [[INT-FORMULA]]"
        .replace("[[CELL-ADDR]]", &format!("{address:<10}"))
        .replace("[[STATUS]]", &format!("{:<20}", step.status.name()))
        .replace("[[INT-FORMULA]]", &format!("{indent}{}", step.text)))
}

/// Breaks the cycle from a sheet to its cells and back, so that a task doesn't leak them.
fn release(excel: &Wrapper) {
    for sheet in excel.loaded_sheets() {
        sheet.cells.borrow().borrow_mut().clear();
    }
}

/// What one run of the command prints, from its `File:` line.
pub struct Pass {
    pub stdout: String,
    /// It ran out of the time it was given, or its limits.
    pub dropped: bool,
}

fn command_body(
    data: &[u8],
    path: &str,
    extract_only: bool,
    deadline: Option<Instant>,
    base_frames: usize,
    out: &OutRef,
) -> R<()> {
    out.borrow_mut().print(&format!("File: {path}\n"))?;
    let Some(file_type) = get_file_type(data) else {
        return raise("Exception", "Input file type is not supported.");
    };
    let stop = Stop(deadline);
    let (decrypted, is_encrypted) = try_decrypt(data, "", out, false, stop)?;
    let mut name = path.rsplit('/').next().unwrap_or(path).to_owned();
    let bytes = if is_encrypted {
        out.borrow_mut()
            .print(&format!("Encrypted {} file", file_type.name()))?;
        let Some(plain) = decrypted else {
            return raise(
                "Exception",
                format!(
                    "Failed to decrypt {path}\nUse --password switch to provide the correct password"
                ),
            );
        };
        // the library's temporary file, whose random name a macro can ask for
        let extension = name.rfind('.').map_or("", |at| &name[at..]).to_owned();
        name = format!("decrypt-tmpfile{extension}");
        plain
    } else {
        out.borrow_mut()
            .print(&format!("Unencrypted {} file\n", file_type.name()))?;
        data.to_vec()
    };
    out.borrow_mut().print("[Loading Cells]")?;
    let excel = Rc::new(open_wrapper(file_type, bytes, &name, out, deadline)?);
    let answer = command_on(&excel, extract_only, deadline, base_frames, out);
    release(&excel);
    answer
}

fn print_labels(excel: &Wrapper, out: &OutRef) -> R<()> {
    for (word, name) in [("auto_open", "auto_open"), ("auto_close", "auto_close")] {
        if let value::Value::List(labels) = excel.get_defined_name(name, false)? {
            for label in labels.iter() {
                if let value::Value::Tuple(parts) = label {
                    let first = parts.first().map_or(String::new(), value::Value::to_py_str);
                    let second = parts.get(1).map_or(String::new(), value::Value::to_py_str);
                    out.borrow_mut()
                        .print(&format!("{word}: {first}->{second}"))?;
                }
            }
        }
    }
    Ok(())
}

fn command_on(
    excel: &Rc<Wrapper>,
    extract_only: bool,
    deadline: Option<Instant>,
    base_frames: usize,
    out: &OutRef,
) -> R<()> {
    print_labels(excel, out)?;
    if extract_only {
        let sink = out.clone();
        return extract_lines(excel, &mut |line| sink.borrow_mut().print(line));
    }
    out.borrow_mut().print("[Starting Deobfuscation]")?;
    let limits = Rc::new(RefCell::new(Limits {
        deadline,
        steps: 0,
        stored: 0,
        copied: 0,
        base_frames,
    }));
    let mut interpreter = Interpreter::new(excel.clone(), out.clone(), limits)?;
    let sink = out.clone();
    interpreter.deobfuscate_macro(true, false, &mut |step| {
        let line = formula_output(&step, true)?;
        sink.borrow_mut().print(&line)
    })?;
    for record in &interpreter.memory {
        let (base, size, hex) = record.describe();
        out.borrow_mut()
            .print(&format!("Memory: base {base}, size {size}\n{hex}\n"))?;
    }
    out.borrow_mut().print("\nFiles:\n")?;
    for (name, file) in &interpreter.files {
        if !file.content.is_empty() {
            let access = file.access.to_py_str();
            let line = format!("Files: path {name}, access {access}\n{}\n", file.content);
            out.borrow_mut().print(&line)?;
        }
    }
    out.borrow_mut().print("[END of Deobfuscation]")
}

/// `xlmdeobfuscator [-x] -f path` with stdin at its end, from the line that names the file, and with no
/// `time elapsed`. `path` is the name it prints and a macro can ask for.
pub fn run_command(data: &[u8], path: &str, extract_only: bool, deadline: Option<Instant>) -> Pass {
    run_command_on(data, path, extract_only, deadline, interp::COMMAND_FRAMES)
}

/// `run_command` with `base_frames` Python frames under the emulation, where the command has 4 and
/// `tools/library-diff`'s adapter more.
pub fn run_command_on(
    data: &[u8],
    path: &str,
    extract_only: bool,
    deadline: Option<Instant>,
    base_frames: usize,
) -> Pass {
    let out: OutRef = Rc::new(RefCell::new(Out {
        text: String::from("\n"),
    }));
    let body = command_body(data, path, extract_only, deadline, base_frames, &out);
    let mut dropped = false;
    match body {
        Ok(()) => {}
        Err(Raised::Exception { message, .. }) => {
            let mut out = out.borrow_mut();
            out.text.push_str(MAIN_LINE);
            out.text.push_str(&message);
            out.text.push('\n');
        }
        Err(Raised::Timeout | Raised::Limit) => dropped = true,
    }
    let text = std::mem::take(&mut out.borrow_mut().text);
    Pass {
        stdout: text,
        dropped,
    }
}

/// What olevba keeps of an emulation: its port's limit on a file's macros (`olevba.rs`).
const OLEVBA_TEXT_LIMIT: usize = 64 * 1024 * 1024;

/// What `process_file` raises for olevba, which catches any of it and falls to plugin_biff.
pub struct ProcessError;

/// olevba's `_extract_xlm_xlmdeobf`: `process_file(.., noninteractive=True, return_deobfuscated=True, timeout=30)`
/// without and with `extract_only`, under the password `process_file` defaults to. Ok(None) is no macro sheet.
pub fn olevba_macro_lines(data: &[u8], name: &str) -> Result<Option<Vec<String>>, ProcessError> {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    let Ok(first) = olevba_process(data, name, true, TIMEOUT) else {
        return Err(ProcessError);
    };
    if first.is_empty() {
        return Ok(None);
    }
    let mut lines = vec!["RAW EXCEL4/XLM MACRO FORMULAS:".to_owned()];
    lines.extend(first);
    lines.push("- ".repeat(38));
    lines.push("EMULATION - DEOBFUSCATED EXCEL4/XLM MACRO FORMULAS:".to_owned());
    let Ok(second) = olevba_process(data, name, false, TIMEOUT) else {
        return Err(ProcessError);
    };
    lines.extend(second);
    Ok(Some(lines))
}

fn olevba_process(
    data: &[u8],
    name: &str,
    extract_only: bool,
    timeout: std::time::Duration,
) -> R<Vec<String>> {
    // `print` in a wrapper still reaches stdout in Python, and nothing of it reaches a macro
    let out: OutRef = Rc::new(RefCell::new(Out {
        text: String::new(),
    }));
    let Some(file_type) = get_file_type(data) else {
        return raise("Exception", "Input file type is not supported.");
    };
    let deadline = Instant::now() + timeout;
    let (decrypted, is_encrypted) =
        try_decrypt(data, "VelvetSweatshop", &out, true, Stop(Some(deadline)))?;
    let mut base = name.rsplit('/').next().unwrap_or(name).to_owned();
    let bytes = if is_encrypted {
        let Some(plain) = decrypted else {
            return raise("Exception", "Failed to decrypt");
        };
        let extension = base.rfind('.').map_or("", |at| &base[at..]).to_owned();
        base = format!("decrypt-tmpfile{extension}");
        plain
    } else {
        data.to_vec()
    };
    let excel = Rc::new(open_wrapper(file_type, bytes, &base, &out, Some(deadline))?);
    let mut lines = Vec::new();
    let answer = olevba_on(&excel, extract_only, deadline, &out, &mut lines);
    release(&excel);
    match answer {
        // olevba's timeout ends the emulation with what it has, and so does the limit on its text
        Ok(()) | Err(Raised::Timeout | Raised::Limit) => Ok(lines),
        Err(error) => Err(error),
    }
}

fn olevba_on(
    excel: &Rc<Wrapper>,
    extract_only: bool,
    deadline: Instant,
    out: &OutRef,
    lines: &mut Vec<String>,
) -> R<()> {
    excel.get_defined_name("auto_open", false)?;
    excel.get_defined_name("auto_close", false)?;
    if extract_only {
        return extract_lines(excel, &mut |line| {
            lines.push(line.to_owned());
            Ok(())
        });
    }
    let limits = Rc::new(RefCell::new(Limits {
        deadline: Some(deadline),
        steps: 0,
        stored: 0,
        copied: 0,
        // olevba's call, under ace3's module: as deep as it matters only for a macro at the limit
        base_frames: 12,
    }));
    let mut interpreter = Interpreter::new(excel.clone(), out.clone(), limits)?;
    let mut held = 0;
    interpreter.deobfuscate_macro(false, true, &mut |step| {
        let line = formula_output(&step, true)?;
        held += line.len();
        if held > OLEVBA_TEXT_LIMIT {
            return Err(Raised::Limit);
        }
        lines.push(line);
        Ok(())
    })
}
