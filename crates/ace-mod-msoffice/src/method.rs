//! msoffcrypto's `method` package: how each kind of encryption makes a key from a password, checks it
//! and decrypts. Its writers aren't here: nothing in ACE encrypts.

use std::time::Instant;

use digest::Digest;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use ace_mod_oletools::py::{PyErr, PyResult};

use crate::crypto::{Arc4, Hash, aes_cbc_decrypt, aes_ecb_decrypt, aes_ecb_update, md5, sha1};

/// The kind a [`PyErr`] has when [`Stop`] ended the work, which nothing in msoffcrypto raises.
pub const OUT_OF_TIME: &str = "OutOfTime";

/// When to give up on a password. A spin count is the file's, up to 2^31-1 and past it, and a task
/// process is one thread, so key derivation looks at the clock itself every so often. None never
/// stops, as the library doesn't.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stop(pub Option<Instant>);

impl Stop {
    pub fn check(&self) -> PyResult<()> {
        match self.0 {
            Some(at) if Instant::now() >= at => {
                Err(PyErr::new(OUT_OF_TIME, "ran out of time for passwords"))
            }
            _ => Ok(()),
        }
    }
}

/// Spins of key derivation between looks at the clock: well under a millisecond's worth.
const SPINS_PER_CHECK: u64 = 4096;

pub fn utf16le(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// `bytes[:n]`, where `n` comes from the file and may be negative.
fn prefix(bytes: &[u8], n: i128) -> &[u8] {
    let len = bytes.len() as i128;
    let end = if n < 0 { (len + n).max(0) } else { n.min(len) };
    &bytes[..end as usize]
}

/// Agile encryption, from an `EncryptionInfo`'s XML.
#[derive(Debug, Clone, Default)]
pub struct AgileInfo {
    pub key_data_salt: Vec<u8>,
    pub key_data_hash: String,
    pub encrypted_verifier_hash_input: Vec<u8>,
    pub encrypted_verifier_hash_value: Vec<u8>,
    pub encrypted_key_value: Vec<u8>,
    pub spin_value: i128,
    pub password_salt: Vec<u8>,
    pub password_hash: String,
    pub password_cipher: String,
    pub password_key_bits: i128,
}

const VERIFIER_HASH_INPUT: [u8; 8] = [0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79];
const VERIFIER_HASH_VALUE: [u8; 8] = [0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E];
const KEY_VALUE: [u8; 8] = [0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6];

fn iterated<D: Digest>(password: &[u8], salt: &[u8], spins: i128, stop: Stop) -> PyResult<Vec<u8>> {
    let mut digest = D::new();
    digest.update(salt);
    digest.update(password);
    let mut hash = digest.finalize();
    let spins = u64::try_from(spins.max(0)).unwrap_or(u64::MAX);
    for i in 0..spins {
        if i % SPINS_PER_CHECK == 0 {
            stop.check()?;
        }
        let Ok(i) = u32::try_from(i) else {
            return Err(PyErr::new(
                "error",
                "'I' format requires 0 <= number <= 4294967295",
            ));
        };
        let mut digest = D::new();
        digest.update(i.to_le_bytes());
        digest.update(&hash);
        hash = digest.finalize();
    }
    Ok(hash.to_vec())
}

impl AgileInfo {
    /// `_derive_iterated_hash_from_password`, the part of a key that costs. The library does this once
    /// for the key and once more to verify, and it comes out the same.
    pub fn derive(&self, password: &str, stop: Stop) -> PyResult<Vec<u8>> {
        let password = utf16le(password);
        let (salt, spins) = (&self.password_salt[..], self.spin_value);
        match Hash::named(&self.password_hash) {
            Hash::Sha1 => iterated::<Sha1>(&password, salt, spins, stop),
            Hash::Sha256 => iterated::<Sha256>(&password, salt, spins, stop),
            Hash::Sha384 => iterated::<Sha384>(&password, salt, spins, stop),
            Hash::Sha512 => iterated::<Sha512>(&password, salt, spins, stop),
        }
    }

    fn key(&self, derived: &[u8], block_key: &[u8]) -> Vec<u8> {
        let hash = Hash::named(&self.password_hash).of(&[derived, block_key]);
        prefix(&hash, self.password_key_bits.div_euclid(8)).to_vec()
    }

    /// `makekey_from_password`, from what `derive` gave.
    pub fn secret_key(&self, derived: &[u8]) -> PyResult<Vec<u8>> {
        let key = self.key(derived, &KEY_VALUE);
        aes_cbc_decrypt(&key, &self.password_salt, &self.encrypted_key_value)
    }

    /// `verify_password`, from what `derive` gave. `whole` is the library's check, which compares the
    /// hash with the whole verifier block. Office pads a SHA-1 hash to 32 bytes there, so a right password
    /// fails it on Office 2010's files. John compares the hash's own length, and false asks for that.
    pub fn verify(&self, derived: &[u8], whole: bool) -> PyResult<bool> {
        let input_key = self.key(derived, &VERIFIER_HASH_INPUT);
        let value_key = self.key(derived, &VERIFIER_HASH_VALUE);
        let input = aes_cbc_decrypt(
            &input_key,
            &self.password_salt,
            &self.encrypted_verifier_hash_input,
        )?;
        let actual = Hash::named(&self.password_hash).of(&[&input]);
        let expected = aes_cbc_decrypt(
            &value_key,
            &self.password_salt,
            &self.encrypted_verifier_hash_value,
        )?;
        if whole {
            Ok(actual == expected)
        } else {
            Ok(expected.get(..actual.len()) == Some(&actual[..]))
        }
    }

    /// `ECMA376Agile.decrypt`.
    pub fn decrypt(&self, key: &[u8], package: &[u8]) -> PyResult<Vec<u8>> {
        const SEGMENT: usize = 4096;
        let Ok(size) = <[u8; 8]>::try_from(package.get(..8).unwrap_or(package)) else {
            return Err(ace_mod_oletools::py::unpack_requires(8));
        };
        let hash = Hash::named(&self.key_data_hash);
        let mut remaining = u64::from_le_bytes(size) as u128;
        let mut out = Vec::new();
        for (i, segment) in package[8..].chunks(SEGMENT).enumerate() {
            let i = u32::try_from(i).map_err(|_| {
                PyErr::new("error", "'I' format requires 0 <= number <= 4294967295")
            })?;
            let digest = hash.of(&[&self.key_data_salt, &i.to_le_bytes()]);
            let mut plain = aes_cbc_decrypt(key, &digest[..16], segment)?;
            if remaining < plain.len() as u128 {
                plain.truncate(remaining as usize);
            }
            out.extend_from_slice(&plain);
            remaining -= plain.len() as u128;
            if remaining == 0 {
                break;
            }
        }
        Ok(out)
    }
}

/// `ECMA376Standard.makekey_from_password`, whose only inputs that count are these.
pub fn standard_key(password: &str, key_size: u32, salt: &[u8]) -> PyResult<Vec<u8>> {
    const ITER_COUNT: u32 = 50000;
    let password = utf16le(password);
    let mut hash = sha1(&[salt, &password]);
    for i in 0..ITER_COUNT {
        hash = sha1(&[&i.to_le_bytes(), &hash]);
    }
    let last = sha1(&[&hash, &0u32.to_le_bytes()]);
    let pad = |with: u8| -> Vec<u8> {
        let mut block = vec![with; 64];
        for (byte, h) in block.iter_mut().zip(&last) {
            *byte ^= h;
        }
        sha1(&[&block])
    };
    let mut derived = pad(0x36);
    derived.extend(pad(0x5C));
    derived.truncate((key_size / 8) as usize);
    Ok(derived)
}

/// `ECMA376Standard.verifykey`.
pub fn standard_verify(key: &[u8], verifier: &[u8], verifier_hash: &[u8]) -> PyResult<bool> {
    let plain = aes_ecb_update(key, verifier)?;
    let expected = sha1(&[&plain]);
    let actual = aes_ecb_update(key, verifier_hash)?;
    Ok(expected == prefix(&actual, 20))
}

/// `ECMA376Standard.decrypt`.
pub fn standard_decrypt(key: &[u8], package: &[u8]) -> PyResult<Vec<u8>> {
    let Ok(size) = <[u8; 4]>::try_from(package.get(..4).unwrap_or(package)) else {
        return Err(ace_mod_oletools::py::unpack_requires(4));
    };
    let mut out = aes_ecb_decrypt(key, package.get(8..).unwrap_or_default())?;
    out.truncate(u32::from_le_bytes(size) as usize);
    Ok(out)
}

/// `method.rc4._makekey`, up to where a block's number comes in.
fn rc4_salted(password: &str, salt: &[u8]) -> Vec<u8> {
    let first = md5(&[&utf16le(password)]);
    let mut buffer = Vec::with_capacity((5 + salt.len()) * 16);
    for _ in 0..16 {
        buffer.extend_from_slice(&first[..5]);
        buffer.extend_from_slice(salt);
    }
    md5(&[&buffer])[..5].to_vec()
}

fn rc4_key(salted: &[u8], block: u32) -> Vec<u8> {
    md5(&[salted, &block.to_le_bytes()])
}

/// `DocumentRC4.verifypw`.
pub fn rc4_verify(
    password: &str,
    salt: &[u8],
    verifier: &[u8],
    verifier_hash: &[u8],
) -> PyResult<bool> {
    let mut cipher = Arc4::new(&rc4_key(&rc4_salted(password, salt), 0))?;
    let mut plain = verifier.to_vec();
    cipher.apply(&mut plain);
    let mut hash = verifier_hash.to_vec();
    cipher.apply(&mut hash);
    Ok(md5(&[&plain]) == hash)
}

/// `DocumentRC4.decrypt`.
pub fn rc4_decrypt(
    password: &str,
    salt: &[u8],
    data: &[u8],
    block_size: usize,
) -> PyResult<Vec<u8>> {
    let salted = rc4_salted(password, salt);
    let mut out = data.to_vec();
    for (block, chunk) in out.chunks_mut(block_size).enumerate() {
        Arc4::new(&rc4_key(&salted, block as u32))?.apply(chunk);
    }
    Ok(out)
}

fn cryptoapi_key(password: &[u8], salt: &[u8], key_length: u32, block: u32) -> Vec<u8> {
    let first = sha1(&[salt, password]);
    let last = sha1(&[&first, &block.to_le_bytes()]);
    if key_length == 40 {
        let mut key = last[..5].to_vec();
        key.resize(16, 0);
        key
    } else {
        prefix(&last, i128::from(key_length / 8)).to_vec()
    }
}

/// `DocumentRC4CryptoAPI.verifypw`.
pub fn cryptoapi_verify(
    password: &str,
    salt: &[u8],
    key_size: u32,
    verifier: &[u8],
    verifier_hash: &[u8],
) -> PyResult<bool> {
    let key = cryptoapi_key(&utf16le(password), salt, key_size, 0);
    let mut cipher = Arc4::new(&key)?;
    let mut plain = verifier.to_vec();
    cipher.apply(&mut plain);
    let mut hash = verifier_hash.to_vec();
    cipher.apply(&mut hash);
    Ok(sha1(&[&plain]) == hash)
}

/// `DocumentRC4CryptoAPI.decrypt`. Python's `read(n)` with a negative `n` takes everything, and with 0
/// it takes nothing, which ends the loop.
pub fn cryptoapi_decrypt(
    password: &str,
    salt: &[u8],
    key_size: u32,
    data: &[u8],
    block_size: i64,
    first_block: u32,
) -> PyResult<Vec<u8>> {
    if block_size == 0 {
        return Ok(Vec::new());
    }
    let size = usize::try_from(block_size).unwrap_or(data.len().max(1));
    let password = utf16le(password);
    let mut out = data.to_vec();
    let mut block = first_block;
    for chunk in out.chunks_mut(size) {
        Arc4::new(&cryptoapi_key(&password, salt, key_size, block))?.apply(chunk);
        block = block.wrapping_add(1);
    }
    Ok(out)
}

const PAD: [u32; 15] = [
    0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80, 0x00, 0xBE, 0x0F, 0x00, 0xBF, 0x0F, 0x00,
];
const INITIAL_CODE: [u32; 15] = [
    0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C, 0x0E10, 0xF1CE, 0x313E, 0x1872, 0xE139, 0xD40F, 0x84F9,
    0x280C, 0xA96A, 0x4EC3,
];
const XOR_MATRIX: [u32; 105] = [
    0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09, 0x7B61, 0xF6C2, 0xFDA5, 0xEB6B, 0xC6F7,
    0x9DCF, 0x2BBF, 0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0, 0x0375, 0x06EA, 0x0DD4,
    0x1BA8, 0x3750, 0x6EA0, 0xDD40, 0xD849, 0xA0B3, 0x5147, 0xA28E, 0x553D, 0xAA7A, 0x44D5, 0x6F45,
    0xDE8A, 0xAD35, 0x4A4B, 0x9496, 0x390D, 0x721A, 0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC,
    0x5FD9, 0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0, 0xB861, 0x60E3, 0xC1C6, 0x93AD,
    0x377B, 0x6EF6, 0xDDEC, 0x45A0, 0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10, 0xAA51, 0x4483,
    0x8906, 0x022D, 0x045A, 0x08B4, 0x1168, 0x76B4, 0xED68, 0xCAF1, 0x85C3, 0x1BA7, 0x374E, 0x6E9C,
    0x3730, 0x6E60, 0xDCC0, 0xA9A1, 0x4363, 0x86C6, 0x1DAD, 0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373,
    0x06E6, 0x0DCC, 0x1021, 0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48C4,
];

/// `DocumentXOR.verifypw`.
pub fn xor_verify(password: &str, verification: u16) -> bool {
    let chars: Vec<u32> = password.chars().map(u32::from).collect();
    let mut verifier: u32 = 0;
    for &byte in chars
        .iter()
        .rev()
        .chain(std::iter::once(&(chars.len() as u32)))
    {
        let high = u32::from(verifier & 0x4000 != 0);
        verifier = (high ^ (verifier.wrapping_mul(2) & 0x7FFF)) ^ byte;
    }
    verifier ^ 0xCE4B == u32::from(verification)
}

fn ror8(n: u32, rotations: u32) -> u8 {
    ((n >> rotations | n << (8 - rotations)) & 0xFF) as u8
}

fn index_error() -> PyErr {
    PyErr::new("IndexError", "list index out of range")
}

/// `create_xor_key_method1`.
fn xor_key(chars: &[u32]) -> PyResult<u32> {
    let mut key = *chars
        .len()
        .checked_sub(1)
        .and_then(|index| INITIAL_CODE.get(index))
        .ok_or_else(index_error)?;
    let mut element = 0x68_usize;
    for &char in chars.iter().rev() {
        let mut ch = char;
        for _ in 0..7 {
            if ch & 0x40 != 0 {
                key ^= *XOR_MATRIX.get(element).ok_or_else(index_error)?;
            }
            ch = (ch << 1) & 0xFF;
            element = element.wrapping_sub(1);
        }
    }
    Ok(key)
}

/// `create_xor_array_method1`.
fn xor_array(password: &str) -> PyResult<[u8; 16]> {
    let chars: Vec<u32> = password.chars().map(u32::from).collect();
    let key = xor_key(&chars)?;
    let (high, low) = ((key & 0xFF00) >> 8, key & 0xFF);
    let assign_error = || PyErr::new("IndexError", "list assignment index out of range");
    let mut array = [0u8; 16];
    let mut index = chars.len();
    if index % 2 == 1 {
        *array.get_mut(index).ok_or_else(assign_error)? = ror8(PAD[0] ^ high, 1);
        index -= 1;
        array[index] = ror8(chars[chars.len() - 1] ^ low, 1);
    }
    while index > 0 {
        index -= 1;
        *array.get_mut(index).ok_or_else(assign_error)? = ror8(chars[index] ^ high, 1);
        index -= 1;
        *array.get_mut(index).ok_or_else(assign_error)? = ror8(chars[index] ^ low, 1);
    }
    let mut index = 15_usize;
    let mut pad = 15_i32 - chars.len() as i32;
    while pad > 0 {
        array[index] = ror8(PAD[pad as usize] ^ high, 1);
        index -= 1;
        pad -= 1;
        array[index] = ror8(PAD[pad as usize] ^ low, 1);
        index = index.wrapping_sub(1);
        pad -= 1;
    }
    Ok(array)
}

/// A stretch of `plain_buf` in `Xls97File.decrypt`: bytes kept as they are, or a count of -1s or -2s.
#[derive(Debug, Clone)]
pub enum Plain {
    Bytes(Vec<u8>),
    Encrypted(usize),
    AfterSheetPosition(usize),
}

/// `DocumentXOR.decrypt`. A run of negative values, of either kind, takes its starting index from
/// the kind of its first.
pub fn xor_decrypt(password: &str, data: &[u8], plain: &[Plain]) -> PyResult<Vec<u8>> {
    let array = xor_array(password)?;
    let mut out = Vec::with_capacity(data.len());
    let mut at = 0_usize;
    let mut index = 0_usize;
    let mut read = 0_usize;
    while at < plain.len() {
        match &plain[at] {
            Plain::Bytes(bytes) => {
                let take = bytes.len();
                let end = (read + take).min(data.len());
                out.extend_from_slice(&data[read.min(data.len())..end]);
                read += take;
                index += take;
                at += 1;
            }
            first => {
                let mut count = 0;
                while let Some(run) = plain.get(at) {
                    match run {
                        Plain::Encrypted(n) | Plain::AfterSheetPosition(n) => count += n,
                        Plain::Bytes(bytes) if bytes.is_empty() => {}
                        Plain::Bytes(_) => break,
                    }
                    at += 1;
                }
                let start = index + count;
                let mut at_array = match first {
                    Plain::AfterSheetPosition(_) => start + 4,
                    _ => start,
                } % 16;
                for _ in 0..count {
                    let Some(&byte) = data.get(read) else {
                        return Err(PyErr::new("IndexError", "index out of range"));
                    };
                    read += 1;
                    out.push(ror8(u32::from(byte ^ array[at_array]), 5));
                    at_array = (at_array + 1) % 16;
                }
                index += count;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctests_of_the_library_pass() {
        // ECMA376Standard.makekey_from_password
        let salt = b"\xe8\x82fI\x0c[\xd1\xee\xbd+C\x94\xe3\xf80\xef";
        let key = standard_key("Password1234_", 128, salt).expect("a key");
        assert_eq!(key, b"@\xb1:q\xf9\x0b\x96n7T\x08\xf2\xd1\x81\xa1\xaa");
        // ECMA376Standard.verifykey
        let verifier = b"Qos.\x96o\xac\x17\xb1\xc5\xd7\xd8\xcc6\xc9(";
        let hash =
            b"+ah\xda\xbe)\x11\xad+\xd3|\x17Ft\\\x14\xd3\xcf\x1b\xb1@\xa4\x8fNo=#\x88\x08r\xb1j";
        assert!(standard_verify(&key, verifier, hash).expect("verifies"));
        // DocumentRC4.verifypw
        let salt = b"\xe8w,\x1d\x91\xc5j7\x96Ga\xb2\x80\x182\x17";
        let verifier = b"\xc9\xe9\x97\xd4T\x97=1\x0b\xb1\xbap\x14&\x83~";
        let hash = b"\xb1\xde\x17\x8f\x07\xe9\x89\xc4M\xae^L\xf9j\xc4\x07";
        assert!(rc4_verify("password1", salt, verifier, hash).expect("verifies"));
        assert!(!rc4_verify("password2", salt, verifier, hash).expect("verifies"));
        // method.rc4._makekey
        assert_eq!(
            rc4_key(&rc4_salted("password1", salt), 0),
            b" \xbf2\xdd\xf5@\x85\x8cQ7D\xaf\x0f$\xe0<"
        );
        // DocumentXOR.verifypw
        assert!(xor_verify("VelvetSweatshop", 0x9a0a));
        assert!(!xor_verify("velvetsweatshop", 0x9a0a));
    }

    #[test]
    fn agile_doctest_of_the_library_passes() {
        let info = AgileInfo {
            password_salt: b"\xcb\xca\x1c\x99\x93C\xfb\xad\x92\x07V4\x15\x004\xb0".to_vec(),
            password_hash: "SHA512".to_owned(),
            encrypted_verifier_hash_input: b"9\xee\xa5N&\xe5\x14y\x8c(K\xc7qM8\xac".to_vec(),
            encrypted_verifier_hash_value: b"\x147mm\x81s4\xe6\xb0\xffO\xd8\"\x1a|g\x8e]\x8axN\x8f\x99\x9fL\x18\x890\xc3jK)\xc5\xb33`[\\\xd4\x03\xb0P\x03\xad\xcf\x18\xcc\xa8\xcb\xab\x8d\xeb\xe3s\xc6V\x04\xa0\xbe\xcf\xae\\\n\xd0".to_vec(),
            spin_value: 100000,
            password_key_bits: 256,
            ..AgileInfo::default()
        };
        let derived = info
            .derive("Password1234_", Stop::default())
            .expect("derives");
        assert!(info.verify(&derived, true).expect("verifies"));
        let derived = info
            .derive("Password1234", Stop::default())
            .expect("derives");
        assert!(!info.verify(&derived, true).expect("verifies"));
    }

    #[test]
    fn a_huge_spin_count_stops_within_derivation() {
        let info = AgileInfo {
            password_salt: vec![0; 16],
            password_hash: "SHA512".to_owned(),
            spin_value: (1 << 31) - 1,
            password_key_bits: 256,
            ..AgileInfo::default()
        };
        let started = Instant::now();
        let stop = Stop(Some(started + std::time::Duration::from_millis(100)));
        let error = info.derive("a password", stop).expect_err("stops");
        assert_eq!(error.kind, OUT_OF_TIME);
        // an unoptimized build's spins take longer, and a loaded machine stretches it too
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
