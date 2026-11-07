//! The ciphers and hashes msoffcrypto gets from `cryptography` and `hashlib`, on RustCrypto's crates,
//! with what `cryptography` raises for a key, an IV or a length a crafted file gives it.

use aes::{Aes128, Aes192, Aes256};
use cipher::common::array::Array;
use cipher::{BlockCipherDecrypt, BlockModeDecrypt, KeyInit, KeyIvInit, StreamCipher};
use digest::Digest;
use md5::Md5;
use rc4::Rc4;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use ace_mod_oletools::py::{PyErr, PyResult};

const BLOCK: usize = 16;

fn value_error(message: impl Into<String>) -> PyErr {
    PyErr::new("ValueError", message)
}

/// `algorithms.AES(key)`.
fn check_aes_key(key: &[u8]) -> PyResult<()> {
    match key.len() * 8 {
        128 | 192 | 256 | 512 => Ok(()),
        bits => Err(value_error(format!("Invalid key size ({bits}) for AES."))),
    }
}

/// 512 bits is AES-XTS's, which `algorithms.AES` takes and `Cipher` then refuses for these modes.
fn unsupported(mode: &str, key: &[u8]) -> PyErr {
    PyErr::new(
        "UnsupportedAlgorithm",
        format!(
            "cipher AES in {mode} mode is not supported by this backend (Your version of OpenSSL \
             may be too old, or the key size {} isn't one this mode takes)",
            key.len() * 8
        ),
    )
}

fn check_multiple(data: &[u8]) -> PyResult<()> {
    if data.len().is_multiple_of(BLOCK) {
        Ok(())
    } else {
        Err(value_error(
            "The length of the provided data is not a multiple of the block length.",
        ))
    }
}

fn cbc<C>(key: &[u8], iv: &[u8], data: &mut [u8]) -> PyResult<()>
where
    C: BlockCipherDecrypt<BlockSize = cipher::consts::U16> + KeyInit,
    cbc::Decryptor<C>: KeyIvInit,
{
    let mut decryptor = cbc::Decryptor::<C>::new_from_slices(key, iv)
        .map_err(|e| value_error(format!("the key or IV: {e}")))?;
    let (blocks, _) = Array::slice_as_chunks_mut(data);
    decryptor.decrypt_blocks(blocks);
    Ok(())
}

/// `Cipher(AES(key), CBC(iv))`'s decryptor, `update(data) + finalize()`.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    check_aes_key(key)?;
    if iv.len() != BLOCK {
        return Err(value_error(format!(
            "Invalid IV size ({}) for CBC.",
            iv.len()
        )));
    }
    let mut out = data.to_vec();
    match key.len() {
        16 => cbc::<Aes128>(key, iv, &mut out)?,
        24 => cbc::<Aes192>(key, iv, &mut out)?,
        32 => cbc::<Aes256>(key, iv, &mut out)?,
        _ => return Err(unsupported("CBC", key)),
    }
    check_multiple(data)?;
    Ok(out)
}

fn ecb<C: BlockCipherDecrypt<BlockSize = cipher::consts::U16> + KeyInit>(
    key: &[u8],
    data: &mut [u8],
) -> PyResult<()> {
    let cipher = C::new_from_slice(key).map_err(|e| value_error(format!("the key: {e}")))?;
    let (blocks, _) = Array::slice_as_chunks_mut(data);
    cipher.decrypt_blocks(blocks);
    Ok(())
}

/// `Cipher(AES(key), ECB()).decryptor().update(data)`: only whole blocks come out.
pub fn aes_ecb_update(key: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    check_aes_key(key)?;
    let mut out = data[..data.len() / BLOCK * BLOCK].to_vec();
    match key.len() {
        16 => ecb::<Aes128>(key, &mut out)?,
        24 => ecb::<Aes192>(key, &mut out)?,
        32 => ecb::<Aes256>(key, &mut out)?,
        _ => return Err(unsupported("ECB", key)),
    }
    Ok(out)
}

/// `update(data) + finalize()` on the same decryptor.
pub fn aes_ecb_decrypt(key: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    let out = aes_ecb_update(key, data)?;
    check_multiple(data)?;
    Ok(out)
}

/// `ARC4(key)`'s keystream, which carries on across `apply` calls.
pub struct Arc4(Rc4);

impl Arc4 {
    pub fn new(key: &[u8]) -> PyResult<Arc4> {
        let bits = key.len() * 8;
        // `cryptography`'s `ARC4.key_sizes`
        if !matches!(bits, 40 | 56 | 64 | 80 | 128 | 160 | 192 | 256) {
            return Err(value_error(format!("Invalid key size ({bits}) for RC4.")));
        }
        let cipher = Rc4::new_from_slice(key).map_err(|e| value_error(format!("the key: {e}")))?;
        Ok(Arc4(cipher))
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        self.0.apply_keystream(data);
    }
}

/// `ALGORITHM_HASH.get(name, sha1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn named(name: &str) -> Hash {
        match name {
            "SHA256" => Hash::Sha256,
            "SHA384" => Hash::Sha384,
            "SHA512" => Hash::Sha512,
            _ => Hash::Sha1,
        }
    }

    pub fn of(self, parts: &[&[u8]]) -> Vec<u8> {
        match self {
            Hash::Sha1 => hash::<Sha1>(parts),
            Hash::Sha256 => hash::<Sha256>(parts),
            Hash::Sha384 => hash::<Sha384>(parts),
            Hash::Sha512 => hash::<Sha512>(parts),
        }
    }
}

pub fn hash<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
    let mut digest = D::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().to_vec()
}

pub fn md5(parts: &[&[u8]]) -> Vec<u8> {
    hash::<Md5>(parts)
}

pub fn sha1(parts: &[&[u8]]) -> Vec<u8> {
    hash::<Sha1>(parts)
}
