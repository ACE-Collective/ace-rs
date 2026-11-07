//! msoffcrypto-tool 6.0.0's `OfficeFile` and its `format` package, as far as ACE calls them: what kind
//! of file it is, whether it's encrypted, whether a password opens it, and what it decrypts to. On
//! a file that breaks it, it raises what the library raises, and the module only cares that it raised.

use std::sync::Arc;

use crate::ole::{self, OleFile};
use crate::py::{PyErr, PyResult, Reader, memory_error, repr_str, unpack_requires};
use crate::{pyxml, pyzip};

use super::method::{self, AgileInfo, Plain, Stop};

const CONTENT_TYPES_NS: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
const PASSWORD_NS: &str = "http://schemas.microsoft.com/office/2006/keyEncryptor/password";
const NOT_DECRYPTED: &str = "The file could not be decrypted with this password";

fn file_format(message: &str) -> PyErr {
    PyErr::new("FileFormatError", message)
}

fn decryption(message: &str) -> PyErr {
    PyErr::new("DecryptionError", message)
}

fn invalid_key(message: &str) -> PyErr {
    PyErr::new("InvalidKeyError", message)
}

fn assertion() -> PyErr {
    PyErr::new("AssertionError", "")
}

fn no_type(class: &str) -> PyErr {
    PyErr::new(
        "AttributeError",
        format!("'{class}' object has no attribute 'type'"),
    )
}

fn u16le(reader: &mut Reader<'_>) -> PyResult<u16> {
    reader.u16()
}

/// What `load_key` found for a binary format.
#[derive(Debug, Clone)]
enum Key {
    Rc4 {
        password: String,
        salt: Vec<u8>,
    },
    CryptoApi {
        password: String,
        salt: Vec<u8>,
        key_size: u32,
    },
    Xor {
        password: String,
    },
}

impl Key {
    /// A binary format's streams are decrypted a block at a time from block 0.
    fn decrypt(&self, data: &[u8], block_size: usize) -> PyResult<Vec<u8>> {
        match self {
            Key::Rc4 { password, salt } => method::rc4_decrypt(password, salt, data, block_size),
            Key::CryptoApi {
                password,
                salt,
                key_size,
            } => method::cryptoapi_decrypt(password, salt, *key_size, data, block_size as i64, 0),
            Key::Xor { .. } => Err(decryption("Unsupported encryption method: xor")),
        }
    }
}

/// `format.common._parse_encryptionheader`'s last line: a strict `decode("utf-16le")`, for what it
/// raises. The name isn't used.
fn check_csp_name(blob: &[u8]) -> PyResult<()> {
    let decode_error = |at: usize, why: &str| {
        PyErr::new(
            "UnicodeDecodeError",
            format!(
                "'utf-16-le' codec can't decode bytes in position {at}-{}: {why}",
                blob.len() - 1
            ),
        )
    };
    let mut at = 0;
    while at < blob.len() {
        if at + 1 == blob.len() {
            return Err(PyErr::new(
                "UnicodeDecodeError",
                format!(
                    "'utf-16-le' codec can't decode byte 0x{:02x} in position {at}: truncated data",
                    blob[at]
                ),
            ));
        }
        let unit = u16::from_le_bytes([blob[at], blob[at + 1]]);
        at += 2;
        if (0xD800..0xDC00).contains(&unit) {
            if at + 1 >= blob.len() {
                return Err(decode_error(at - 2, "unexpected end of data"));
            }
            let next = u16::from_le_bytes([blob[at], blob[at + 1]]);
            if !(0xDC00..0xE000).contains(&next) {
                return Err(decode_error(at - 2, "illegal UTF-16 surrogate"));
            }
            at += 2;
        } else if (0xDC00..0xE000).contains(&unit) {
            return Err(decode_error(at - 2, "illegal encoding"));
        }
    }
    Ok(())
}

/// An `EncryptionHeader`, keeping the fields that count.
#[derive(Debug, Clone)]
struct Header {
    alg_id: u32,
    key_size: u32,
}

fn parse_header(blob: &[u8]) -> PyResult<Header> {
    let mut reader = Reader::new(blob);
    let _flags = reader.u32()?;
    let _size_extra = reader.u32()?;
    let alg_id = reader.u32()?;
    let _alg_id_hash = reader.u32()?;
    let key_size = reader.u32()?;
    for _ in 0..3 {
        reader.u32()?;
    }
    check_csp_name(reader.read(usize::MAX))?;
    Ok(Header { alg_id, key_size })
}

/// An `EncryptionVerifier`, with the hash's length by cipher.
#[derive(Debug, Clone)]
struct Verifier {
    salt: Vec<u8>,
    encrypted: Vec<u8>,
    encrypted_hash: Vec<u8>,
}

fn parse_verifier(blob: &[u8], hash_length: usize) -> PyResult<Verifier> {
    let mut reader = Reader::new(blob);
    let _salt_size = reader.u32()?;
    let salt = reader.read(16).to_vec();
    let encrypted = reader.read(16).to_vec();
    let _hash_size = reader.u32()?;
    let encrypted_hash = reader.read(hash_length).to_vec();
    Ok(Verifier {
        salt,
        encrypted,
        encrypted_hash,
    })
}

/// `_parse_header_RC4CryptoAPI`.
fn parse_cryptoapi(reader: &mut Reader<'_>) -> PyResult<(Verifier, u32)> {
    let _flags = reader.read(4);
    let size = reader.u32()?;
    let header = parse_header(reader.read(size as usize))?;
    let key_size = if header.key_size == 0 {
        0x28
    } else {
        header.key_size
    };
    Ok((parse_verifier(reader.read(usize::MAX), 20)?, key_size))
}

fn cryptoapi_key(password: &str, reader: &mut Reader<'_>) -> PyResult<Key> {
    let (verifier, key_size) = parse_cryptoapi(reader)?;
    if method::cryptoapi_verify(
        password,
        &verifier.salt,
        key_size,
        &verifier.encrypted,
        &verifier.encrypted_hash,
    )? {
        Ok(Key::CryptoApi {
            password: password.to_owned(),
            salt: verifier.salt,
            key_size,
        })
    } else {
        Err(invalid_key("Failed to verify password"))
    }
}

fn rc4_key(password: &str, reader: &mut Reader<'_>) -> PyResult<Key> {
    let salt = reader.read(16).to_vec();
    let encrypted = reader.read(16);
    let encrypted_hash = reader.read(16);
    if method::rc4_verify(password, &salt, encrypted, encrypted_hash)? {
        Ok(Key::Rc4 {
            password: password.to_owned(),
            salt,
        })
    } else {
        Err(invalid_key("Failed to verify password"))
    }
}

/// Which version of `EncryptionVersionInfo` a binary format's password header has.
fn cryptoapi_version(major: u16, minor: u16) -> bool {
    matches!(major, 2..=4) && minor == 2
}

/// `base64.b64decode(text)`: anything outside the alphabet is skipped, and padding ends it.
fn b64decode(text: &str) -> PyResult<Vec<u8>> {
    if !text.is_ascii() {
        return Err(PyErr::new(
            "ValueError",
            "string argument should contain only ASCII characters",
        ));
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut quad, mut pads, mut leftover, mut data_chars) = (0_u8, 0_usize, 0_u8, 0_usize);
    for &byte in text.as_bytes() {
        if byte == b'=' {
            pads += 1;
            if quad >= 2 && usize::from(quad) + pads >= 4 {
                return Ok(out);
            }
            continue;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        pads = 0;
        data_chars += 1;
        match quad {
            0 => {
                quad = 1;
                leftover = value;
            }
            1 => {
                quad = 2;
                out.push(leftover << 2 | value >> 4);
                leftover = value & 0x0F;
            }
            2 => {
                quad = 3;
                out.push(leftover << 4 | value >> 2);
                leftover = value & 0x03;
            }
            _ => {
                quad = 0;
                out.push(leftover << 6 | value);
                leftover = 0;
            }
        }
    }
    match quad {
        0 => Ok(out),
        1 => Err(PyErr::new(
            "Error",
            format!(
                "Invalid base64-encoded string: number of data characters ({data_chars}) cannot be \
                 1 more than a multiple of 4"
            ),
        )),
        _ => Err(PyErr::new("Error", "Incorrect padding")),
    }
}

/// `int(text)`: ASCII digits only, which is all a real file has, saturating far past any spin count.
fn py_int(text: &str) -> PyResult<i128> {
    let invalid = || {
        PyErr::new(
            "ValueError",
            format!(
                "invalid literal for int() with base 10: {}",
                repr_str(text).chars().take(200).collect::<String>()
            ),
        )
    };
    let trimmed = crate::py::strip(text);
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let mut any = false;
    let mut last_underscore = true;
    let mut value: i128 = 0;
    let mut count = 0_usize;
    for c in digits.chars() {
        if c == '_' {
            if last_underscore {
                return Err(invalid());
            }
            last_underscore = true;
            continue;
        }
        let digit = c.to_digit(10).ok_or_else(invalid)?;
        any = true;
        last_underscore = false;
        count += 1;
        value = value.saturating_mul(10).saturating_add(i128::from(digit));
    }
    if !any || last_underscore {
        return Err(invalid());
    }
    if count > 4300 {
        return Err(PyErr::new(
            "ValueError",
            format!(
                "Exceeds the limit (4300 digits) for integer string conversion: value has {count} \
                 digits; use sys.set_int_max_str_digits() to increase the limit"
            ),
        ));
    }
    Ok(if negative { -value } else { value })
}

fn minidom_first(elements: Vec<&pyxml::Element>) -> PyResult<&pyxml::Element> {
    elements
        .first()
        .copied()
        .ok_or_else(|| PyErr::new("IndexError", "list index out of range"))
}

/// `xml.getElementsByTagName(name)` of a plain name: minidom compares the qualified name, so a prefix
/// makes it another name, while any namespace will do.
fn by_tag_name<'a>(root: &'a pyxml::Element, name: &str) -> Vec<&'a pyxml::Element> {
    root.iter_tag("*")
        .into_iter()
        .filter(|element| element.prefix.is_none() && local_name(element) == name)
        .collect()
}

fn local_name(element: &pyxml::Element) -> &str {
    element
        .tag
        .rsplit_once('}')
        .map_or(element.tag.as_str(), |(_, local)| local)
}

fn get_attribute<'a>(element: &'a pyxml::Element, name: &str) -> &'a str {
    element.get(name).unwrap_or_default()
}

/// `_parseinfo_agile`.
fn parse_agile(xml: &[u8]) -> PyResult<AgileInfo> {
    // minidom raises what `ElementTree.fromstring` does, from the same expat
    let root = pyxml::fromstring(xml).map_err(|error| {
        if error.kind == "ParseError" {
            PyErr::new("ExpatError", error.message)
        } else {
            error
        }
    })?;
    let key_data = minidom_first(by_tag_name(&root, "keyData"))?;
    let key_data_salt = b64decode(get_attribute(key_data, "saltValue"))?;
    let key_data_hash = get_attribute(key_data, "hashAlgorithm").to_owned();
    py_int(get_attribute(key_data, "blockSize"))?;
    let integrity = minidom_first(by_tag_name(&root, "dataIntegrity"))?;
    b64decode(get_attribute(integrity, "encryptedHmacKey"))?;
    b64decode(get_attribute(integrity, "encryptedHmacValue"))?;
    let tag = format!("{{{PASSWORD_NS}}}encryptedKey");
    let password = minidom_first(root.iter_tag(&tag))?;
    let spin_value = py_int(get_attribute(password, "spinCount"))?;
    let encrypted_key_value = b64decode(get_attribute(password, "encryptedKeyValue"))?;
    let encrypted_verifier_hash_input =
        b64decode(get_attribute(password, "encryptedVerifierHashInput"))?;
    let encrypted_verifier_hash_value =
        b64decode(get_attribute(password, "encryptedVerifierHashValue"))?;
    let password_salt = b64decode(get_attribute(password, "saltValue"))?;
    let password_hash = get_attribute(password, "hashAlgorithm").to_owned();
    let password_cipher = get_attribute(password, "cipherAlgorithm").to_owned();
    let password_key_bits = py_int(get_attribute(password, "keyBits"))?;
    Ok(AgileInfo {
        key_data_salt,
        key_data_hash,
        encrypted_verifier_hash_input,
        encrypted_verifier_hash_value,
        encrypted_key_value,
        spin_value,
        password_salt,
        password_hash,
        password_cipher,
        password_key_bits,
    })
}

/// A Standard-encrypted file's `_parseinfo_standard`.
#[derive(Debug, Clone)]
struct StandardInfo {
    key_size: u32,
    verifier: Verifier,
}

fn parse_standard(reader: &mut Reader<'_>) -> PyResult<StandardInfo> {
    let _flags = reader.u32()?;
    let size = reader.u32()?;
    let header = parse_header(reader.read(size as usize))?;
    let hash_length = if header.alg_id & 0xFF00 == 0x6600 {
        32
    } else {
        20
    };
    let verifier = parse_verifier(reader.read(usize::MAX), hash_length)?;
    Ok(StandardInfo {
        key_size: header.key_size,
        verifier,
    })
}

#[derive(Debug, Clone)]
enum Ooxml {
    Agile(Box<AgileInfo>),
    Standard(StandardInfo),
    Plain,
}

/// `_is_ooxml`: any failure on the way means no.
fn is_ooxml(data: &[u8]) -> bool {
    let Ok(zip) = pyzip::ZipFile::new(data) else {
        return false;
    };
    let Ok(types) = zip.open_read("[Content_Types].xml", None) else {
        return false;
    };
    let Ok(root) = pyxml::fromstring(&types) else {
        return false;
    };
    root.prefix.is_none() && root.tag == format!("{{{CONTENT_TYPES_NS}}}Types")
}

/// `_parseinfo`.
fn parse_info(stream: &[u8]) -> PyResult<Ooxml> {
    let mut reader = Reader::new(stream);
    let major = u16le(&mut reader).map_err(|_| unpack_requires(4))?;
    let minor = u16le(&mut reader).map_err(|_| unpack_requires(4))?;
    match (major, minor) {
        (4, 4) => Ok(Ooxml::Agile(Box::new(parse_agile(
            stream.get(8..).unwrap_or_default(),
        )?))),
        (2..=4, 2) => Ok(Ooxml::Standard(parse_standard(&mut reader)?)),
        (3 | 4, 3) => Err(decryption(
            "Unsupported EncryptionInfo version (Extensible Encryption)",
        )),
        _ => Err(decryption(&format!(
            "Unsupported EncryptionInfo version ({major}:{minor})"
        ))),
    }
}

/// The fields of a `FibBase` that count. Packing it again gives back its 32 bytes, with its encryption
/// flags and `IKey` cleared.
#[derive(Debug, Clone)]
struct Fib {
    raw: [u8; 32],
    encrypted: bool,
    obfuscation: bool,
    second_table: bool,
    i_key: u32,
}

fn unpack_from_short(size: usize, actual: usize) -> PyErr {
    PyErr::new(
        "error",
        format!(
            "unpack_from requires a buffer of at least {size} bytes for unpacking {size} bytes at \
             offset 0 (actual buffer size is {actual})"
        ),
    )
}

fn parse_fib(stream: &[u8]) -> PyResult<Fib> {
    // the fields' sizes, in order, for which one a short stream fails on
    let sizes = [2, 2, 2, 2, 2, 2, 2, 4, 1, 1, 2, 2, 4, 4];
    let mut at = 0;
    for size in sizes {
        let left = stream.len().saturating_sub(at);
        if left < size {
            return Err(unpack_from_short(size, left));
        }
        at += size;
    }
    let mut raw = [0; 32];
    raw.copy_from_slice(&stream[..32]);
    let flags = u16::from_le_bytes([raw[10], raw[11]]);
    Ok(Fib {
        raw,
        encrypted: flags & 1 << 8 != 0,
        obfuscation: flags & 1 << 15 != 0,
        second_table: flags & 1 << 9 != 0,
        i_key: u32::from_le_bytes([raw[14], raw[15], raw[16], raw[17]]),
    })
}

const BIFF_BOF: u16 = 2057;
const BIFF_FILE_PASS: u16 = 47;
const BIFF_BOUND_SHEET: u16 = 133;
const BIFF_PLAIN: [u16; 5] = [404, 405, 225, 406, 312];

/// The first two reads of a `Workbook` stream: its `BOF`, which it asserts, and then past it.
fn biff_past_bof(workbook: &[u8]) -> PyResult<Reader<'_>> {
    let mut reader = Reader::new(workbook);
    if reader.u16()? != BIFF_BOF {
        return Err(assertion());
    }
    let size = reader.u16()?;
    reader.read(usize::from(size));
    Ok(reader)
}

/// `(num, size)` of the next record, or None at the end.
fn biff_header(reader: &mut Reader<'_>) -> PyResult<Option<(u16, u16)>> {
    let header = reader.read(4);
    if header.is_empty() {
        return Ok(None);
    }
    if header.len() < 4 {
        return Err(unpack_requires(4));
    }
    Ok(Some((
        u16::from_le_bytes([header[0], header[1]]),
        u16::from_le_bytes([header[2], header[3]]),
    )))
}

/// The reader just past `FilePass`'s header, and its size, or None without one.
fn biff_file_pass(reader: &mut Reader<'_>) -> PyResult<Option<u16>> {
    while let Some((num, size)) = biff_header(reader)? {
        if num == BIFF_FILE_PASS {
            return Ok(Some(size));
        }
        reader.read(usize::from(size));
    }
    Ok(None)
}

/// `BytesIO` with the writes `Xls97File.decrypt` makes over what it decrypted.
fn overlay(mut dec: Vec<u8>, plain: &[Plain]) -> Vec<u8> {
    let mut at = 0_usize;
    for run in plain {
        match run {
            Plain::Encrypted(n) | Plain::AfterSheetPosition(n) => at += n,
            Plain::Bytes(bytes) => {
                if dec.len() < at + bytes.len() {
                    dec.resize(at + bytes.len(), 0);
                }
                dec[at..at + bytes.len()].copy_from_slice(bytes);
                at += bytes.len();
            }
        }
    }
    dec
}

/// `Xls97File.decrypt`'s split of the workbook into what's kept and what's decrypted.
fn split_workbook(workbook: &[u8]) -> PyResult<(Vec<Plain>, Vec<u8>)> {
    let mut reader = Reader::new(workbook);
    let mut plain = Vec::new();
    let mut encrypted = Vec::with_capacity(workbook.len());
    let push = |plain: &mut Vec<Plain>, run: Plain| match run {
        Plain::Encrypted(0) | Plain::AfterSheetPosition(0) => {}
        Plain::Bytes(ref bytes) if bytes.is_empty() => {}
        run => plain.push(run),
    };
    while let Some((num, size)) = biff_header(&mut reader)? {
        let size_usize = usize::from(size);
        let record = reader.read(size_usize);
        let mut header = Vec::with_capacity(4 + size_usize);
        header.extend_from_slice(&num.to_le_bytes());
        header.extend_from_slice(&size.to_le_bytes());
        if num == BIFF_FILE_PASS {
            let mut blank = vec![0, 0];
            blank.extend_from_slice(&size.to_le_bytes());
            blank.resize(4 + size_usize, 0);
            push(&mut plain, Plain::Bytes(blank));
            encrypted.resize(encrypted.len() + 4 + size_usize, 0);
        } else if num == BIFF_BOF || BIFF_PLAIN.contains(&num) {
            header.extend_from_slice(record);
            push(&mut plain, Plain::Bytes(header));
            encrypted.resize(encrypted.len() + 4 + size_usize, 0);
        } else if num == BIFF_BOUND_SHEET {
            header.extend_from_slice(&record[..record.len().min(4)]);
            push(&mut plain, Plain::Bytes(header));
            push(
                &mut plain,
                Plain::AfterSheetPosition(size_usize.saturating_sub(4)),
            );
            encrypted.resize(encrypted.len() + 8, 0);
            encrypted.extend_from_slice(record.get(4..).unwrap_or_default());
        } else {
            push(&mut plain, Plain::Bytes(header));
            push(&mut plain, Plain::Encrypted(size_usize));
            encrypted.resize(encrypted.len() + 4, 0);
            encrypted.extend_from_slice(record);
        }
    }
    Ok((plain, encrypted))
}

/// A parsed `CurrentUserAtom`.
#[derive(Debug, Clone)]
struct CurrentUser {
    offset_to_current_edit: u32,
    /// What packing it again gives, with its token set to say it isn't encrypted.
    packed: Vec<u8>,
}

fn parse_record_header(bytes: &[u8]) -> PyResult<(u16, u16, u16, u32)> {
    let mut reader = Reader::new(bytes);
    let first = reader.u16()?;
    let kind = reader.u16()?;
    let length = reader.u32()?;
    Ok((first & 0xF, first >> 4, kind, length))
}

fn parse_current_user(stream: &[u8]) -> PyResult<CurrentUser> {
    let mut reader = Reader::new(stream);
    let (version, instance, kind, _) = parse_record_header(reader.read(8))?;
    if version != 0 || instance != 0 || kind != 0x0FF6 {
        return Err(assertion());
    }
    if reader.u32()? != 0x14 {
        return Err(assertion());
    }
    let _token = reader.u32()?;
    let offset_to_current_edit = reader.u32()?;
    let name_length = usize::from(reader.u16()?);
    let _doc_file_version = reader.u16()?;
    let versions = reader.read(2);
    if versions.len() < 2 {
        return Err(unpack_requires(2));
    }
    reader.read(2);
    reader.read(name_length);
    reader.u32()?;
    reader.read(2 * name_length);
    let end = reader.at.min(stream.len());
    let mut packed = stream[..end].to_vec();
    packed[12..16].copy_from_slice(&0xE391_C05F_u32.to_le_bytes());
    Ok(CurrentUser {
        offset_to_current_edit,
        packed,
    })
}

/// A parsed `UserEditAtom`.
#[derive(Debug, Clone)]
struct UserEdit {
    record_length: u32,
    offset_persist_directory: u32,
    encrypt_session: Option<u32>,
    /// What packing it again gives, without the encryption session's reference.
    packed: Vec<u8>,
}

fn parse_user_edit(stream: &[u8], offset: u32) -> PyResult<UserEdit> {
    let mut reader = Reader::new(stream);
    reader.at = offset as usize;
    let header_at = reader.at;
    let (version, instance, kind, length) = parse_record_header(reader.read(8))?;
    if version != 0 || instance != 0 || kind != 0x0FF5 || !matches!(length, 0x1C | 0x20) {
        return Err(assertion());
    }
    let _last_slide = reader.u32()?;
    let _version = reader.u16()?;
    if reader.read(2).len() < 2 {
        return Err(unpack_requires(2));
    }
    let _offset_last_edit = reader.u32()?;
    let offset_persist_directory = reader.u32()?;
    let _doc_persist = reader.u32()?;
    let _seed = reader.u32()?;
    let _last_view = reader.u16()?;
    let unused = reader.read(2).len();
    let fixed_end = header_at + 8 + 4 + 2 + 2 + 4 + 4 + 4 + 4 + 2 + unused;
    let rest = reader.read(4);
    let encrypt_session = <[u8; 4]>::try_from(rest).ok().map(u32::from_le_bytes);
    let mut packed = stream[header_at..fixed_end].to_vec();
    packed[4..8].copy_from_slice(&length.wrapping_sub(4).to_le_bytes());
    if encrypt_session.is_some() {
        packed.extend_from_slice(&0_u32.to_le_bytes());
    }
    Ok(UserEdit {
        record_length: length,
        offset_persist_directory,
        encrypt_session,
        packed,
    })
}

#[derive(Debug, Clone)]
struct PersistEntry {
    id: u32,
    count: u32,
    offsets: Vec<u32>,
}

/// `_parsePersistDirectoryAtom`: its entries and its 8-byte header.
fn parse_persist_directory(stream: &[u8], offset: u32) -> PyResult<(Vec<PersistEntry>, Vec<u8>)> {
    let mut reader = Reader::new(stream);
    reader.at = offset as usize;
    let header = reader.read(8).to_vec();
    let (version, instance, kind, length) = parse_record_header(&header)?;
    if version != 0 || instance != 0 || kind != 0x1772 {
        return Err(assertion());
    }
    let mut entries_reader = Reader::new(reader.read(length as usize));
    let mut entries = Vec::new();
    let mut pos = 0_u64;
    while pos < u64::from(length) {
        let first = entries_reader.u32()?;
        let (id, count) = (first & 0xF_FFFF, first >> 20);
        let raw = entries_reader.read(4 * count as usize);
        let mut offsets = Vec::with_capacity(count as usize);
        let mut values = Reader::new(raw);
        for _ in 0..count {
            offsets.push(values.u32()?);
        }
        pos += 4 + 4 * offsets.len() as u64;
        entries.push(PersistEntry { id, count, offsets });
    }
    Ok((entries, header))
}

/// The persist object directory, in a dict's order: first insertion's place, last insertion's value.
fn persist_directory(current_user: &[u8], document: &[u8]) -> PyResult<Vec<(u64, u32)>> {
    let user = parse_current_user(current_user)?;
    let edit = parse_user_edit(document, user.offset_to_current_edit)?;
    let (entries, _) = parse_persist_directory(document, edit.offset_persist_directory)?;
    let mut order: Vec<(u64, u32)> = Vec::new();
    let mut known = std::collections::HashMap::new();
    for entry in entries {
        for (i, &offset) in entry.offsets.iter().enumerate() {
            let id = u64::from(entry.id) + i as u64;
            match known.get(&id) {
                Some(&index) => order[index] = (id, offset),
                None => {
                    known.insert(id, order.len());
                    order.push((id, offset));
                }
            }
        }
    }
    Ok(order)
}

/// `array[start:start + len(bytes)] = bytes`, which grows it past its end.
fn splice(array: &mut Vec<u8>, start: usize, bytes: &[u8]) {
    let start_at = start.min(array.len());
    let end = start.saturating_add(bytes.len()).min(array.len());
    array.splice(start_at..end, bytes.iter().copied());
}

fn ppt_key(current_user: &[u8], document: &[u8], password: &str) -> PyResult<Key> {
    let directory = persist_directory(current_user, document)?;
    let user = parse_current_user(current_user)?;
    let edit = parse_user_edit(document, user.offset_to_current_edit)?;
    let Some(reference) = edit.encrypt_session else {
        return Err(PyErr::new("KeyError", "None"));
    };
    let Some(&(_, offset)) = directory.iter().find(|(id, _)| *id == u64::from(reference)) else {
        return Err(PyErr::new("KeyError", reference.to_string()));
    };
    let mut reader = Reader::new(document);
    reader.at = offset as usize;
    let (version, _, kind, length) = parse_record_header(reader.read(8))?;
    if version != 0xF || kind != 0x2F14 {
        return Err(assertion());
    }
    let mut info = Reader::new(reader.read(length as usize));
    let version = info.read(4);
    if version.len() < 4 {
        return Err(unpack_requires(4));
    }
    let major = u16::from_le_bytes([version[0], version[1]]);
    let minor = u16::from_le_bytes([version[2], version[3]]);
    if !cryptoapi_version(major, minor) {
        return Err(assertion());
    }
    cryptoapi_key(password, &mut info)
}

fn ppt_decrypt(current_user: &[u8], document: &[u8], key: &Key) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let Key::CryptoApi {
        password,
        salt,
        key_size,
    } = key
    else {
        return Err(decryption("Unsupported encryption method"));
    };
    let user = parse_current_user(current_user)?;
    let mut decrypted = document.to_vec();
    let edit = parse_user_edit(document, user.offset_to_current_edit)?;
    splice(
        &mut decrypted,
        user.offset_to_current_edit as usize,
        &edit.packed,
    );
    let (entries, header) = parse_persist_directory(document, edit.offset_persist_directory)?;
    let first = entries
        .first()
        .ok_or_else(|| PyErr::new("IndexError", "list index out of range"))?;
    let mut packed = header;
    let word = (first.id & 0xF_FFFF) | ((first.count.wrapping_sub(1) & 0xFFF) << 20);
    packed.extend_from_slice(&word.to_le_bytes());
    for offset in &first.offsets {
        packed.extend_from_slice(&offset.to_le_bytes());
    }
    splice(
        &mut decrypted,
        edit.offset_persist_directory as usize,
        &packed,
    );
    let directory = persist_directory(current_user, document)?;
    let at_offset = |offset: u32| -> &[u8] { document.get(offset as usize..).unwrap_or_default() };
    for (i, &(id, offset)) in directory.iter().enumerate() {
        let start = at_offset(offset);
        let (_, _, kind, length) = parse_record_header(&start[..start.len().min(8)])?;
        if kind == 0x2F14 {
            if length as usize > ole::MAX_STREAM {
                return Err(memory_error());
            }
            let zeros = vec![0; 8 + length as usize];
            splice(&mut decrypted, offset as usize, &zeros);
            continue;
        }
        if kind == 0x0FF5 || kind == 0x1772 {
            continue;
        }
        let Some(&(_, next)) = directory.get(i + 1) else {
            return Err(PyErr::new("IndexError", "list index out of range"));
        };
        let record_length = i64::from(next) - i64::from(offset) - 8;
        let total = 8 + record_length;
        // `read(n)` with a negative n takes everything
        let encrypted = match usize::try_from(total) {
            Ok(total) => &start[..start.len().min(total)],
            Err(_) => start,
        };
        let key_size_i = i64::from(*key_size);
        let block_size = key_size_i * (total.div_euclid(key_size_i) + 1);
        let block = u32::try_from(id)
            .map_err(|_| PyErr::new("error", "'I' format requires 0 <= number <= 4294967295"))?;
        let plain =
            method::cryptoapi_decrypt(password, salt, *key_size, encrypted, block_size, block)?;
        splice(&mut decrypted, offset as usize, &plain);
    }
    for &(_, offset) in &directory {
        let start = decrypted.get(offset as usize..).unwrap_or_default();
        parse_record_header(&start[..start.len().min(8)])?;
    }
    Ok((user.packed, decrypted))
}

#[derive(Debug)]
enum Inner {
    Ooxml {
        info: Ooxml,
        ole: Option<OleFile>,
    },
    Doc97 {
        ole: OleFile,
        fib: Fib,
        stream: Vec<u8>,
    },
    Xls97 {
        ole: OleFile,
        workbook: Vec<u8>,
    },
    Ppt97 {
        ole: OleFile,
        current_user: Vec<u8>,
        document: Vec<u8>,
    },
}

/// What a password gave `load_key`.
#[derive(Debug, Clone)]
enum Loaded {
    Secret(Vec<u8>),
    Binary(Key),
}

/// `msoffcrypto.OfficeFile(file)`.
#[derive(Debug)]
pub struct OfficeFile {
    data: Arc<Vec<u8>>,
    inner: Inner,
    loaded: Option<Loaded>,
}

impl OfficeFile {
    /// `depth` is the Python frames on the stack at the call, which olefile's recursion counts.
    pub fn open(data: Arc<Vec<u8>>, depth: usize) -> PyResult<OfficeFile> {
        let inner = if ole::has_magic(&data) {
            let mut ole = OleFile::open(Arc::clone(&data), depth)?;
            if ole.exists("EncryptionInfo") {
                let stream = ole.read_stream("EncryptionInfo").map_err(|error| {
                    if error.is_os_error() {
                        file_format(
                            "Supposed to be an encrypted OOXML file, but no EncryptionInfo stream \
                             found",
                        )
                    } else {
                        error
                    }
                })?;
                Inner::Ooxml {
                    info: parse_info(&stream)?,
                    ole: Some(ole),
                }
            } else if ole.exists("wordDocument") {
                let stream = ole.read_stream("wordDocument")?;
                let fib = parse_fib(&stream)?;
                Inner::Doc97 { ole, fib, stream }
            } else if ole.exists("Workbook") {
                let workbook = ole.read_stream("Workbook")?;
                Inner::Xls97 { ole, workbook }
            } else if ole.exists("PowerPoint Document") {
                let current_user = ole.read_stream("Current User")?;
                let document = ole.read_stream("PowerPoint Document")?;
                Inner::Ppt97 {
                    ole,
                    current_user,
                    document,
                }
            } else {
                return Err(file_format("Unrecognized file format"));
            }
        } else if pyzip::is_zipfile(&data) {
            if !is_ooxml(&data) {
                return Err(file_format("Unsupported file format"));
            }
            Inner::Ooxml {
                info: Ooxml::Plain,
                ole: None,
            }
        } else {
            return Err(file_format("Unsupported file format"));
        };
        Ok(OfficeFile {
            data,
            inner,
            loaded: None,
        })
    }

    /// `office_file.format`.
    pub fn format(&self) -> &'static str {
        match self.inner {
            Inner::Ooxml { .. } => "ooxml",
            Inner::Doc97 { .. } => "doc97",
            Inner::Xls97 { .. } => "xls97",
            Inner::Ppt97 { .. } => "ppt97",
        }
    }

    /// `office_file.type`, which a binary format hasn't got until `load_key` sets it.
    pub fn kind(&self) -> Option<&'static str> {
        match &self.inner {
            Inner::Ooxml { info, .. } => Some(match info {
                Ooxml::Agile(_) => "agile",
                Ooxml::Standard(_) => "standard",
                Ooxml::Plain => "plain",
            }),
            _ => None,
        }
    }

    /// `office_file.is_encrypted()`.
    pub fn is_encrypted(&self) -> PyResult<bool> {
        match &self.inner {
            Inner::Ooxml { info, .. } => Ok(!matches!(info, Ooxml::Plain)),
            Inner::Doc97 { fib, .. } => Ok(fib.encrypted),
            Inner::Xls97 { workbook, .. } => {
                let mut reader = biff_past_bof(workbook)?;
                if biff_file_pass(&mut reader)?.is_none() {
                    return Ok(false);
                }
                let kind = reader.u16()?;
                Ok(matches!(kind, 0 | 1))
            }
            Inner::Ppt97 {
                current_user,
                document,
                ..
            } => {
                let user = parse_current_user(current_user)?;
                let edit = parse_user_edit(document, user.offset_to_current_edit)?;
                Ok(edit.record_length == 0x20)
            }
        }
    }

    /// `load_key(password=password, verify_password=True)` on OOXML, which is the only kind that can
    /// not verify, and `load_key(password=password)` on the rest. `InvalidKeyError` says it doesn't
    /// open the file.
    pub fn load_key(&mut self, password: &str, stop: Stop) -> PyResult<()> {
        self.load_key_checking(password, stop, true)
    }

    /// `load_key`, as John checks a password rather than the library: the two differ on Agile with
    /// SHA-1, which is what Office 2010 writes and only John opens (`AgileInfo::verify`).
    pub fn try_password(&mut self, password: &str, stop: Stop) -> PyResult<()> {
        self.load_key_checking(password, stop, false)
    }

    fn load_key_checking(&mut self, password: &str, stop: Stop, whole: bool) -> PyResult<()> {
        self.loaded = None;
        let loaded = match &mut self.inner {
            Inner::Ooxml { info, .. } => {
                if password.is_empty() {
                    return Err(decryption("No key specified"));
                }
                match info {
                    Ooxml::Agile(info) => {
                        let derived = info.derive(password, stop)?;
                        let secret = info.secret_key(&derived)?;
                        if !info.verify(&derived, whole)? {
                            return Err(invalid_key("Key verification failed"));
                        }
                        Some(Loaded::Secret(secret))
                    }
                    Ooxml::Standard(info) => {
                        stop.check()?;
                        let key =
                            method::standard_key(password, info.key_size, &info.verifier.salt)?;
                        if !method::standard_verify(
                            &key,
                            &info.verifier.encrypted,
                            &info.verifier.encrypted_hash,
                        )? {
                            return Err(invalid_key("Key verification failed"));
                        }
                        Some(Loaded::Secret(key))
                    }
                    Ooxml::Plain => None,
                }
            }
            Inner::Doc97 { ole, fib, .. } => {
                stop.check()?;
                if !fib.encrypted {
                    return Err(decryption("File is not encrypted"));
                }
                if fib.obfuscation {
                    // the library only keeps the verifier here, so any password loads
                    None
                } else {
                    let table = ole.read_stream(table_name(fib))?;
                    let mut reader = Reader::new(&table);
                    let version = reader.read(4);
                    if version.len() < 4 {
                        return Err(unpack_requires(4));
                    }
                    let major = u16::from_le_bytes([version[0], version[1]]);
                    let minor = u16::from_le_bytes([version[2], version[3]]);
                    let key = if major == 1 && minor == 1 {
                        rc4_key(password, &mut reader)?
                    } else if cryptoapi_version(major, minor) {
                        cryptoapi_key(password, &mut reader)?
                    } else {
                        return Err(decryption("Unsupported encryption method"));
                    };
                    Some(Loaded::Binary(key))
                }
            }
            Inner::Xls97 { workbook, .. } => {
                stop.check()?;
                let mut reader = biff_past_bof(workbook)?;
                let Some(size) = biff_file_pass(&mut reader)? else {
                    return Err(PyErr::new("ParseError", "Record not found"));
                };
                let kind = reader.u16()?;
                // `read(size - 2)`, and a negative size takes the rest
                let take = usize::from(size).checked_sub(2).unwrap_or(usize::MAX);
                let mut info = Reader::new(reader.read(take));
                match kind {
                    0 => {
                        let pair = info.read(4);
                        if pair.len() < 4 {
                            return Err(unpack_requires(4));
                        }
                        let verification = u16::from_le_bytes([pair[2], pair[3]]);
                        if !method::xor_verify(password, verification) {
                            return Err(invalid_key("Failed to verify password"));
                        }
                        Some(Loaded::Binary(Key::Xor {
                            password: password.to_owned(),
                        }))
                    }
                    1 => {
                        let version = info.read(4);
                        if version.len() < 4 {
                            return Err(unpack_requires(4));
                        }
                        let major = u16::from_le_bytes([version[0], version[1]]);
                        let minor = u16::from_le_bytes([version[2], version[3]]);
                        let key = if major == 1 && minor == 1 {
                            rc4_key(password, &mut info)?
                        } else if cryptoapi_version(major, minor) {
                            cryptoapi_key(password, &mut info)?
                        } else {
                            return Err(decryption("Unsupported encryption method"));
                        };
                        Some(Loaded::Binary(key))
                    }
                    _ => None,
                }
            }
            Inner::Ppt97 {
                current_user,
                document,
                ..
            } => {
                stop.check()?;
                Some(Loaded::Binary(ppt_key(current_user, document, password)?))
            }
        };
        self.loaded = loaded;
        Ok(())
    }

    /// `office_file.decrypt(out)`, which writes and then may raise, so nothing of it comes back then.
    pub fn decrypt(&mut self) -> PyResult<Vec<u8>> {
        let data = Arc::clone(&self.data);
        match &mut self.inner {
            Inner::Ooxml { info, ole } => {
                let (Ooxml::Agile(_) | Ooxml::Standard(_), Some(ole)) = (&*info, ole.as_mut())
                else {
                    return Err(decryption("Document is not encrypted"));
                };
                let package = ole.read_stream("EncryptedPackage")?;
                let Some(Loaded::Secret(secret)) = &self.loaded else {
                    // `load_key` wasn't called or failed, and the library then has None for a key
                    return Err(PyErr::new(
                        "TypeError",
                        "a bytes-like object is required, not 'NoneType'",
                    ));
                };
                let plain = match info {
                    Ooxml::Agile(info) => info.decrypt(secret, &package)?,
                    Ooxml::Standard(_) => method::standard_decrypt(secret, &package)?,
                    Ooxml::Plain => unreachable!("checked above"),
                };
                if !pyzip::is_zipfile(&plain) {
                    return Err(invalid_key(NOT_DECRYPTED));
                }
                Ok(plain)
            }
            Inner::Doc97 { ole, fib, stream } => {
                let Some(Loaded::Binary(key)) = &self.loaded else {
                    return Err(no_type("Doc97File"));
                };
                const FIB_LENGTH: usize = 0x44;
                let mut header = fib.raw;
                let flags = u16::from_le_bytes([header[10], header[11]]) & !(1 << 8) & !(1 << 15);
                header[10..12].copy_from_slice(&flags.to_le_bytes());
                header[14..18].fill(0);
                let mut word = header.to_vec();
                word.extend_from_slice(
                    stream
                        .get(32..FIB_LENGTH.min(stream.len()))
                        .unwrap_or_default(),
                );
                let dec = key.decrypt(stream, 0x200)?;
                word.extend_from_slice(dec.get(FIB_LENGTH..).unwrap_or_default());
                let table_name = table_name(fib);
                let table = ole.read_stream(table_name)?;
                let table = key.decrypt(&table, 0x200)?;
                let extra = if ole.exists("Data") {
                    let stream = ole.read_stream("Data")?;
                    Some(key.decrypt(&stream, 0x200)?)
                } else {
                    None
                };
                let mut out = data.as_ref().clone();
                ole.write_stream(&mut out, "wordDocument", &word)?;
                ole.write_stream(&mut out, table_name, &table)?;
                if let Some(extra) = extra {
                    ole.write_stream(&mut out, "Data", &extra)?;
                }
                Ok(out)
            }
            Inner::Xls97 { ole, workbook } => {
                let Some(Loaded::Binary(key)) = &self.loaded else {
                    return Err(no_type("Xls97File"));
                };
                let (plain, encrypted) = split_workbook(workbook)?;
                let dec = match key {
                    Key::Xor { password } => method::xor_decrypt(password, &encrypted, &plain)?,
                    key => key.decrypt(&encrypted, 1024)?,
                };
                let dec = overlay(dec, &plain);
                let mut out = data.as_ref().clone();
                ole.write_stream(&mut out, "Workbook", &dec)?;
                Ok(out)
            }
            Inner::Ppt97 {
                ole,
                current_user,
                document,
            } => {
                let Some(Loaded::Binary(key)) = &self.loaded else {
                    return Err(no_type("Ppt97File"));
                };
                let (user, document) = ppt_decrypt(current_user, document, key)?;
                let mut out = data.as_ref().clone();
                ole.write_stream(&mut out, "Current User", &user)?;
                ole.write_stream(&mut out, "PowerPoint Document", &document)?;
                Ok(out)
            }
        }
    }

    /// What office2john.py writes for a file John has no format for, naming it by `path`. None for
    /// any other file. msoffcrypto's Excel 95 XOR never gets here: it fails `is_encrypted`.
    pub fn john_complaint(&self, path: &str) -> Option<String> {
        let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
        match &self.inner {
            Inner::Ooxml {
                info: Ooxml::Agile(info),
                ..
            } => {
                let hash = info.password_hash.as_str();
                if !matches!(hash, "SHA1" | "SHA512") {
                    return Some(format!(
                        "{path} uses un-supported hashing algorithm {hash}, please file a bug! \n"
                    ));
                }
                let cipher = info.password_cipher.as_str();
                (!cipher.contains("AES")).then(|| {
                    format!(
                        "{path} uses un-supported cipher algorithm {cipher}, please file a bug! \n"
                    )
                })
            }
            Inner::Doc97 { fib, .. } if fib.obfuscation => Some(format!(
                "{path} : XOR obfuscation detected, Password Verifier : b'{}'\n",
                hex(&fib.i_key.to_le_bytes())
            )),
            Inner::Xls97 { workbook, .. } => {
                let mut reader = Reader::new(workbook);
                loop {
                    let header = reader.read(4);
                    if header.len() < 4 {
                        return None;
                    }
                    let kind = u16::from_le_bytes([header[0], header[1]]);
                    let length = u16::from_le_bytes([header[2], header[3]]);
                    let record = reader.read(usize::from(length));
                    if kind == BIFF_FILE_PASS {
                        if record.get(..2).unwrap_or(record) != [0, 0] {
                            return None;
                        }
                        return Some(format!(
                            "{path} : XOR obfuscation detected, key : b'{}', hash : b'{}'\n",
                            hex(record.get(2..4.min(record.len())).unwrap_or_default()),
                            hex(record.get(4..6.min(record.len())).unwrap_or_default()),
                        ));
                    }
                }
            }
            _ => None,
        }
    }
}

fn table_name(fib: &Fib) -> &'static str {
    if fib.second_table { "1Table" } else { "0Table" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_is_pythons() {
        assert_eq!(b64decode("").unwrap(), b"");
        assert_eq!(b64decode("QUJD").unwrap(), b"ABC");
        assert_eq!(b64decode("QU\nJD !").unwrap(), b"ABC");
        assert_eq!(b64decode("QUI=").unwrap(), b"AB");
        assert_eq!(b64decode("QUI=AAAA").unwrap(), b"AB");
        assert_eq!(b64decode("QUI").unwrap_err().message, "Incorrect padding");
        assert!(
            b64decode("Q")
                .unwrap_err()
                .message
                .contains("number of data characters (1)")
        );
    }

    #[test]
    fn int_is_pythons() {
        assert_eq!(py_int(" 100000\n").unwrap(), 100000);
        assert_eq!(py_int("-5").unwrap(), -5);
        assert_eq!(py_int("1_000").unwrap(), 1000);
        assert_eq!(py_int("").unwrap_err().kind, "ValueError");
        assert_eq!(py_int("1_").unwrap_err().kind, "ValueError");
        assert_eq!(py_int("0x10").unwrap_err().kind, "ValueError");
    }

    #[test]
    fn a_slice_past_the_end_grows_as_python_does() {
        let mut array = vec![1, 2, 3];
        splice(&mut array, 2, &[9, 9]);
        assert_eq!(array, [1, 2, 9, 9]);
        splice(&mut array, 10, &[7]);
        assert_eq!(array, [1, 2, 9, 9, 7]);
    }
}
