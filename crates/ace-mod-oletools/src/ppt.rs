//! What `VBA_Parser.open_ppt` calls in oletools' `ppt_parser`: the "search through the stream" path of
//! `PptParser.iter_vba_data`, with `fast_fail=True`.

use crate::ole::OleFile;
use crate::py::{PyErr, PyResult, Reader};
use crate::pyzip::zlib_decompress;

const MAIN_STREAM: &str = "PowerPoint Document";
const BUF_SIZE: usize = 1024;
/// A VBA storage's largest decompressed size. Python's would be memory.
const MAX_STORAGE: usize = 256 * 1024 * 1024;

fn unexpected(stream: &str, field: &str, found: &str, expected: &str) -> PyErr {
    PyErr::new(
        "PptUnexpectedData",
        format!(
            "In stream \"{stream}\" for field \"{field}\" found value \"{found}\" but expected {expected}!"
        ),
    )
}

/// `search_pattern`: the windows overlap by the pattern's length, so a hit in the overlap comes twice.
fn search_pattern(
    stream: &[u8],
    pattern: &[u8],
    mut each: impl FnMut(usize) -> PyResult<()>,
) -> PyResult<()> {
    let mut start = 0;
    loop {
        let end = stream.len().min(start + BUF_SIZE);
        let buffer = stream.get(start..end).unwrap_or_default();
        for found in memchr::memmem::find_iter(buffer, pattern) {
            each(start + found)?;
        }
        if buffer.len() == BUF_SIZE {
            start = start + BUF_SIZE - pattern.len();
        } else {
            return Ok(());
        }
    }
}

/// `PptParser.__init__`'s check of the root, raising what `open_ppt` catches as "not a PPT".
fn check_root(ole: &OleFile) -> PyResult<()> {
    let streams = ole.listdir(true, false);
    let found = || {
        let names: Vec<String> = streams
            .iter()
            .map(|path| crate::py::repr_str(&path.join("/")))
            .collect();
        format!("[{}]", names.join(", "))
    };
    if streams.iter().any(|stream| stream.len() != 1) {
        return Err(unexpected("root", "listdir", &found(), "len = 1"));
    }
    let lower: Vec<String> = streams
        .iter()
        .map(|stream| stream[0].to_lowercase())
        .collect();
    if !lower.iter().any(|name| name == "current user") {
        return Err(unexpected("root", "listdir", &found(), "Current User"));
    }
    if !lower.iter().any(|name| name == "powerpoint document") {
        return Err(unexpected("root", "listdir", &found(), MAIN_STREAM));
    }
    Ok(())
}

/// `search_vba_info`, only for what its check raises: its containers don't change what's yielded.
fn check_vba_info(stream: &[u8]) -> PyResult<()> {
    let pattern = [
        0x1F, 0x00, 0xFF, 0x03, 0x14, 0, 0, 0, 0x02, 0x00, 0x00, 0x04, 0x0C, 0, 0, 0,
    ];
    search_pattern(stream, &pattern, |at| {
        let mut reader = Reader::new(stream);
        reader.at = at + 16;
        let parsed = (|| {
            reader.u32()?;
            let has_macros = reader.u32()?;
            let version = reader.u32()?;
            Ok::<_, PyErr>((has_macros, version))
        })();
        let Ok((has_macros, version)) = parsed else {
            return Ok(());
        };
        // check_range comes before check_value, and the first error is what's raised
        if has_macros >= 2 {
            return Err(unexpected(
                MAIN_STREAM,
                "VBAInfoAtom.fHasMacros",
                &format!("{has_macros:04X}"),
                "< 0002",
            ));
        }
        if version != 2 {
            return Err(unexpected(
                MAIN_STREAM,
                "VBAInfoAtom.version",
                &format!("{version:04X}"),
                "0002",
            ));
        }
        Ok(())
    })
}

/// `PptParser(ole, fast_fail=True)` and `iter_vba_data`, handing each storage to `each`. `each`
/// raising stops it, and its stream is read once.
pub fn iter_vba_data(
    ole: &mut OleFile,
    mut each: impl FnMut(Vec<u8>) -> PyResult<()>,
) -> PyResult<()> {
    check_root(ole)?;
    let stream = ole.read_stream(MAIN_STREAM)?;
    check_vba_info(&stream)?;
    search_pattern(&stream, &[0x00, 0x00, 0x11, 0x10], |at| {
        let Some(size) = stream.get(at + 4..at + 8) else {
            return Ok(());
        };
        let size = u32::from_le_bytes([size[0], size[1], size[2], size[3]]) as usize;
        let offset = (at + 8).min(stream.len());
        each(stream[offset..stream.len().min(offset.saturating_add(size))].to_vec())
    })?;
    search_pattern(&stream, &[0x10, 0x00, 0x11, 0x10], |at| {
        let Some(head) = stream.get(at + 4..at + 12) else {
            return Ok(());
        };
        let size = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as i64 - 4;
        let offset = (at + 12).min(stream.len());
        let end = stream
            .len()
            .min(offset.saturating_add(size.max(0) as usize));
        // decompressobj: what's after the stream's end is ignored, and truncated data is kept
        each(if size > 0 {
            zlib_decompress(&stream[offset..end], false, MAX_STORAGE)?
        } else {
            Vec::new()
        })
    })
}
