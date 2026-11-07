//! olevba's `decompress_stream`, `VBA_Project` and `VBA_Module` with `relaxed=True`. Its caller logs
//! any exception from a project and moves on, so the errors here only need to stop at the same place.

use crate::codepage::Decoder;
use crate::ole::OleFile;
use crate::py::{PyErr, PyResult, Reader, decode_utf16le, memory_error, unpack_requires};

/// The most a stream may decompress to. A chunk can reach 65536 bytes, so past Python's own limits a
/// crafted stream is about 16 times its size, and this is what memory would be.
pub const MAX_DECOMPRESSED: usize = 256 * 1024 * 1024;

/// MS-OVBA 2.4.1, as olevba does it: Python's negative indexes and its errors included.
pub fn decompress_stream(compressed: &[u8]) -> PyResult<Vec<u8>> {
    let Some(&signature) = compressed.first() else {
        return Err(PyErr::new("IndexError", "bytearray index out of range"));
    };
    if signature != 1 {
        return Err(PyErr::new(
            "ValueError",
            format!("invalid signature byte {signature:02X}"),
        ));
    }
    let mut out: Vec<u8> = Vec::with_capacity(compressed.len().min(1 << 20) * 2);
    let mut current = 1;
    while current < compressed.len() {
        let chunk_start = current;
        let header = u16_at(compressed, chunk_start)?;
        let chunk_size = usize::from(header & 0x0FFF) + 3;
        if (header >> 12) & 0x07 != 0b011 {
            return Err(PyErr::new(
                "ValueError",
                "Invalid CompressedChunkSignature in VBA compressed stream",
            ));
        }
        let compressed_flag = (header >> 15) & 1 == 1;
        if !compressed_flag && chunk_size != 4098 {
            return Err(PyErr::new(
                "ValueError",
                format!("CompressedChunkSize={chunk_size} != 4098 but CompressedChunkFlag == 0"),
            ));
        }
        let end = compressed.len().min(chunk_start + chunk_size);
        current = chunk_start + 2;
        if !compressed_flag {
            let to = compressed.len().min(current + 4096);
            if current < to {
                out.extend_from_slice(&compressed[current..to]);
            }
            current += 4096;
        } else {
            let decompressed_start = out.len();
            while current < end {
                let flags = compressed[current];
                current += 1;
                for bit in 0..8 {
                    if current >= end {
                        break;
                    }
                    if (flags >> bit) & 1 == 0 {
                        out.push(compressed[current]);
                        current += 1;
                    } else {
                        let token = usize::from(u16_at(compressed, current)?);
                        let bit_count = copy_token_bits(out.len() - decompressed_start)?;
                        let length_mask = 0xFFFFusize >> bit_count;
                        let length = (token & length_mask) + 3;
                        if bit_count > 16 {
                            return Err(PyErr::new("ValueError", "negative shift count"));
                        }
                        let offset = ((token & !length_mask) >> (16 - bit_count)) + 1;
                        let source = out.len() as i64 - offset as i64;
                        for index in source..source + length as i64 {
                            let len = out.len() as i64;
                            let at = if index < 0 { index + len } else { index };
                            if at < 0 || at >= len {
                                return Err(PyErr::new(
                                    "IndexError",
                                    "bytearray index out of range",
                                ));
                            }
                            out.push(out[at as usize]);
                        }
                        current += 2;
                    }
                }
                if out.len() > MAX_DECOMPRESSED {
                    return Err(memory_error());
                }
            }
        }
        if out.len() > MAX_DECOMPRESSED {
            return Err(memory_error());
        }
    }
    Ok(out)
}

fn u16_at(data: &[u8], at: usize) -> PyResult<u16> {
    match data.get(at..at + 2) {
        Some(pair) => Ok(u16::from_le_bytes([pair[0], pair[1]])),
        None => Err(unpack_requires(2)),
    }
}

/// `copytoken_help`'s bit count, through the same floating point.
fn copy_token_bits(difference: usize) -> PyResult<u32> {
    if difference == 0 {
        return Err(PyErr::new("ValueError", "expected a positive input"));
    }
    let bits = ((difference as f64).ln() / 2f64.ln()).ceil() as u32;
    Ok(bits.max(4))
}

/// One `yield` of `parse_modules`: `code_path`, `filename_str` and `code_str`.
#[derive(Debug, Clone)]
pub struct VbaModule {
    pub code_path: String,
    pub filename: Option<String>,
    pub code: Option<String>,
}

/// `_extract_vba`, up to the first exception: the modules before it, and that exception.
pub fn extract_vba(
    ole: &mut OleFile,
    vba_root: &str,
    project_path: &str,
    dir_path: &str,
    mut each: impl FnMut(&mut OleFile, VbaModule) -> PyResult<()>,
) -> PyResult<()> {
    let compressed = ole.read_stream(dir_path)?;
    let dir = decompress_stream(&compressed)?;
    let mut stream = Reader::new(&dir);
    let decoder = parse_project_information(&mut stream, dir_path)?;
    let module_ext = parse_project_stream(ole, project_path, decoder)?;

    stream.u32()?;
    let modules_count = stream.u16()?;
    stream.u16()?;
    stream.u32()?;
    stream.u16()?;
    for _ in 0..modules_count {
        let module = parse_module(ole, &mut stream, vba_root, decoder, &module_ext)?;
        each(ole, module)?;
    }
    Ok(())
}

/// `VBA_Project.__init__`, which reads as far as the modules. Its checks only log when relaxed, so
/// what's read here matters only for the code page and where it runs out.
fn parse_project_information(stream: &mut Reader<'_>, dir_path: &str) -> PyResult<Decoder> {
    fn record(stream: &mut Reader<'_>) -> PyResult<()> {
        stream.u16()?;
        stream.u32()?;
        stream.u32()?;
        Ok(())
    }
    fn sized(stream: &mut Reader<'_>) -> PyResult<()> {
        let size = stream.u32()?;
        stream.read(size as usize);
        Ok(())
    }
    // PROJECTSYSKIND
    record(stream)?;
    // PROJECTCOMPATVERSION, if there is one, then PROJECTLCID's id
    let mut id = stream.u16()?;
    if id == 0x004A {
        stream.u32()?;
        stream.u32()?;
        id = stream.u16()?;
    }
    let _ = id;
    stream.u32()?;
    stream.u32()?;
    // PROJECTLCIDINVOKE
    record(stream)?;
    // PROJECTCODEPAGE
    stream.u16()?;
    stream.u32()?;
    let decoder = Decoder::for_codepage(stream.u16()?);
    // PROJECTNAME
    stream.u16()?;
    sized(stream)?;
    // PROJECTDOCSTRING
    stream.u16()?;
    sized(stream)?;
    stream.u16()?;
    sized(stream)?;
    // PROJECTHELPFILEPATH
    stream.u16()?;
    sized(stream)?;
    stream.u16()?;
    sized(stream)?;
    // PROJECTHELPCONTEXT, PROJECTLIBFLAGS
    record(stream)?;
    record(stream)?;
    // PROJECTVERSION
    stream.u16()?;
    stream.u32()?;
    stream.u32()?;
    stream.u16()?;
    // PROJECTCONSTANTS
    stream.u16()?;
    sized(stream)?;
    stream.u16()?;
    sized(stream)?;
    // REFERENCE records
    loop {
        let mut check = stream.u16()?;
        if check == 0x000F {
            return Ok(decoder);
        }
        if check == 0x0016 {
            sized(stream)?;
            let reserved = stream.u16()?;
            if reserved == 0x003E {
                sized(stream)?;
                continue;
            }
            check = reserved;
        }
        match check {
            0x0033 => sized(stream)?,
            0x002F => {
                stream.u32()?;
                sized(stream)?;
                stream.u32()?;
                stream.u16()?;
                let check2 = stream.u16()?;
                if check2 == 0x0016 {
                    sized(stream)?;
                    if stream.u16()? == 0x003E {
                        sized(stream)?;
                        stream.u16()?;
                    }
                }
                stream.u32()?;
                sized(stream)?;
                stream.u32()?;
                stream.u16()?;
                stream.read(16);
                stream.u32()?;
            }
            0x000D => {
                stream.u32()?;
                sized(stream)?;
                stream.u32()?;
                stream.u16()?;
            }
            0x000E => {
                stream.u32()?;
                sized(stream)?;
                sized(stream)?;
                stream.u32()?;
                stream.u16()?;
            }
            // UnexpectedDataError
            _ => {
                return Err(PyErr::new(
                    "UnexpectedDataError",
                    format!(
                        "Unexpected value in {dir_path} for variable reference type: expected (000F,0016,0033,002F,000D,000E) but found {check:04X}!"
                    ),
                ));
            }
        }
    }
}

/// `parse_project_stream`: each module's extension, by lowercase name.
fn parse_project_stream(
    ole: &mut OleFile,
    project_path: &str,
    decoder: Decoder,
) -> PyResult<Vec<(String, &'static str)>> {
    let data = ole.read_stream(project_path)?;
    let mut extensions = Vec::new();
    for raw in data.split_inclusive(|&byte| byte == b'\n') {
        let line = decoder.decode(raw);
        let line = crate::py::strip(&line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.to_lowercase();
        match name {
            "Document" => {
                let module = value.split('/').next().unwrap_or_default().to_owned();
                extensions.push((module, "cls"));
            }
            "Module" => extensions.push((value, "bas")),
            "Class" => extensions.push((value, "cls")),
            "BaseClass" => extensions.push((value, "frm")),
            _ => {}
        }
    }
    Ok(extensions)
}

/// `VBA_Module.__init__`.
fn parse_module(
    ole: &mut OleFile,
    stream: &mut Reader<'_>,
    vba_root: &str,
    decoder: Decoder,
    extensions: &[(String, &'static str)],
) -> PyResult<VbaModule> {
    stream.u16()?;
    let size = stream.u32()?;
    let name = decoder.decode(stream.read(size as usize));
    let mut section = stream.u16()?;
    let mut name_unicode = None;
    let mut stream_name = None;
    let mut stream_name_unicode = None;
    let mut text_offset = None;
    if section == 0x0047 {
        let size = stream.u32()?;
        name_unicode = Some(decode_utf16le(stream.read(size as usize)));
        section = stream.u16()?;
    }
    if section == 0x001A {
        let size = stream.u32()?;
        stream_name = Some(decoder.decode(stream.read(size as usize)));
        stream.u16()?;
        let size = stream.u32()?;
        stream_name_unicode = Some(decode_utf16le(stream.read(size as usize)));
        section = stream.u16()?;
    }
    if section == 0x001C {
        let size = stream.u32()?;
        stream.read(size as usize);
        stream.u16()?;
        let size = stream.u32()?;
        stream.read(size as usize);
        section = stream.u16()?;
    }
    if section == 0x0031 {
        stream.u32()?;
        text_offset = Some(stream.u32()? as usize);
        section = stream.u16()?;
    }
    if section == 0x001E {
        stream.u32()?;
        stream.u32()?;
        section = stream.u16()?;
    }
    if section == 0x002C {
        stream.u32()?;
        stream.u16()?;
        section = stream.u16()?;
    }
    if section == 0x0021 || section == 0x0022 {
        stream.u32()?;
        section = stream.u16()?;
    }
    if section == 0x0025 {
        stream.u32()?;
        section = stream.u16()?;
    }
    if section == 0x0028 {
        stream.u32()?;
        section = stream.u16()?;
    }
    if section == 0x002B {
        stream.u32()?;
    }

    let names = [
        &stream_name,
        &stream_name_unicode,
        &Some(name.clone()),
        &name_unicode,
    ];
    let mut code_path = String::new();
    let mut code_data = None;
    for candidate in names.iter().filter_map(|name| name.as_ref()) {
        code_path = format!("{vba_root}VBA/{candidate}");
        match ole.read_stream(&code_path) {
            Ok(data) => {
                code_data = Some(data);
                break;
            }
            Err(error) if error.is_os_error() => {}
            Err(error) => return Err(error),
        }
    }
    let Some(code_data) = code_data else {
        // the log message joins all four names, and raises on one that's None
        if names.iter().any(|name| name.is_none()) {
            return Err(PyErr::new(
                "TypeError",
                "can only concatenate str (not \"NoneType\") to str",
            ));
        }
        return Ok(VbaModule {
            code_path,
            filename: None,
            code: None,
        });
    };
    let code = code_data
        .get(text_offset.unwrap_or(0)..)
        .unwrap_or_default();
    if code.is_empty() {
        return Ok(VbaModule {
            code_path,
            filename: None,
            code: None,
        });
    }
    let code = decompress_stream(code)?;
    let lower = name.to_lowercase();
    // a later line of the PROJECT stream replaces an earlier one, as in a dict
    let extension = extensions
        .iter()
        .rev()
        .find(|(module, _)| *module == lower)
        .map_or("vba", |(_, extension)| extension);
    Ok(VbaModule {
        code_path,
        filename: Some(format!("{name}.{extension}")),
        code: Some(decoder.decode(&code)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_token_reads_earlier_output() {
        // from MS-OVBA 3.2.3's example: "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
        let compressed = [
            0x01, 0x2F, 0xB0, 0x00, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        ];
        let out = decompress_stream(&compressed).expect("decompresses");
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn errors_are_pythons() {
        assert_eq!(decompress_stream(b"").unwrap_err().kind, "IndexError");
        assert_eq!(
            decompress_stream(b"\x02").unwrap_err().message,
            "invalid signature byte 02"
        );
        assert_eq!(
            decompress_stream(b"\x01\xff").unwrap_err().message,
            "unpack requires a buffer of 2 bytes"
        );
    }
}
