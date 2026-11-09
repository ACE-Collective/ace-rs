//! A file over bytes, read the way Python reads a file opened "rb".

/// A read position over the caller's bytes. `read` returns fewer bytes at the end, and a
/// position past the end reads nothing, as with a Python file.
#[derive(Clone)]
pub(crate) struct File<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> File<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        File { data, pos: 0 }
    }

    pub(crate) fn data(&self) -> &'a [u8] {
        self.data
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn tell(&self) -> usize {
        self.pos
    }

    pub(crate) fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// `fp.seek(n, os.SEEK_CUR)`.
    pub(crate) fn skip(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
    }

    /// `fp.read(n)`.
    pub(crate) fn read(&mut self, n: usize) -> &'a [u8] {
        let len = self.data.len();
        let start = self.pos.min(len);
        let end = start.saturating_add(n).min(len);
        if self.pos < len {
            self.pos = end;
        }
        &self.data[start..end]
    }

    /// `ImageFile._safe_read(fp, size)`: exactly `size` bytes or OSError("Truncated File Read").
    pub(crate) fn safe_read(&mut self, size: usize) -> Result<&'a [u8], crate::Raise> {
        let s = self.read(size);
        if s.len() < size {
            return Err(crate::Raise::os("Truncated File Read"));
        }
        Ok(s)
    }

    /// `fp.readline()`: up to and including the next b"\n".
    pub(crate) fn readline(&mut self) -> &'a [u8] {
        let start = self.pos.min(self.data.len());
        let rest = &self.data[start..];
        let n = match rest.iter().position(|&b| b == b'\n') {
            Some(i) => i + 1,
            None => rest.len(),
        };
        self.read(n)
    }
}

pub(crate) fn u16le(b: &[u8], off: usize) -> Result<u16, crate::Raise> {
    match b.get(off..off.wrapping_add(2)) {
        Some(s) => Ok(u16::from_le_bytes([s[0], s[1]])),
        None => Err(crate::Raise::struct_error()),
    }
}

pub(crate) fn u16be(b: &[u8], off: usize) -> Result<u16, crate::Raise> {
    match b.get(off..off.wrapping_add(2)) {
        Some(s) => Ok(u16::from_be_bytes([s[0], s[1]])),
        None => Err(crate::Raise::struct_error()),
    }
}

pub(crate) fn u32le(b: &[u8], off: usize) -> Result<u32, crate::Raise> {
    match b.get(off..off.wrapping_add(4)) {
        Some(s) => Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]])),
        None => Err(crate::Raise::struct_error()),
    }
}

pub(crate) fn u32be(b: &[u8], off: usize) -> Result<u32, crate::Raise> {
    match b.get(off..off.wrapping_add(4)) {
        Some(s) => Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]])),
        None => Err(crate::Raise::struct_error()),
    }
}

/// `b[i]`, raising IndexError.
pub(crate) fn byte(b: &[u8], i: usize) -> Result<u8, crate::Raise> {
    b.get(i).copied().ok_or_else(crate::Raise::index_error)
}
