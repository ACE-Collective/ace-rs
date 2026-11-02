//! Listing and extracting each kind of archive the module opens, in place of the `unzip`, `7z`
//! and `unrar` runs and Python's `zipfile` in ace3 (`archive.py:278-451`).
//!
//! Every reader works in one thread: the module runs in a contained process that may not start
//! threads (PLAN.md 2.18), so sevenz-rust2's multi-threaded LZMA2 decoding is turned off.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use flate2::read::MultiGzDecoder;

/// How ace3 would have opened the archive, which decides how entries are counted and named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A zip through `7z`: files only are counted, and paths are kept.
    Zip,
    /// A JAR through Python's `zipfile`: every entry, directories too, is counted.
    Jar,
    /// An Excel 2007+ workbook through `unzip`: every entry is counted, and ActiveX parts and
    /// control properties are left out.
    Xlsx,
    SevenZip,
    /// A RAR through `unrar e`: every entry is counted, and files are extracted without their
    /// directories.
    Rar,
    /// A gzip stream through `7z`: one file.
    Gzip,
}

/// One entry of an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The entry's position in the archive.
    pub index: usize,
    /// The name as the archive stores it.
    pub name: String,
    pub is_dir: bool,
}

/// Why an archive couldn't be read.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("7z: {0}")]
    SevenZip(#[from] sevenz_rust2::Error),
    #[error("rar: {0}")]
    Rar(#[from] unrar::error::UnrarError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The entries of the archive at `path`, in archive order.
pub fn list(format: Format, path: &Path, password: &str) -> Result<Vec<Entry>, ArchiveError> {
    match format {
        Format::Zip | Format::Jar | Format::Xlsx => {
            let mut archive = zip::ZipArchive::new(BufReader::new(File::open(path)?))?;
            let mut entries = Vec::with_capacity(archive.len());
            for index in 0..archive.len() {
                let (name, is_dir) = match archive.by_index_raw(index) {
                    // a name that isn't valid in its declared encoding is read as lossy UTF-8
                    Ok(entry) => (
                        entry
                            .name()
                            .map(|name| name.into_owned())
                            .unwrap_or_else(|_| {
                                String::from_utf8_lossy(entry.name_raw()).into_owned()
                            }),
                        entry.is_dir(),
                    ),
                    Err(e) => {
                        tracing::warn!(index, error = %e, "unreadable zip entry");
                        continue;
                    }
                };
                entries.push(Entry {
                    index,
                    name,
                    is_dir,
                });
            }
            Ok(entries)
        }
        Format::SevenZip => {
            let reader = seven_zip_reader(path, password)?;
            Ok(reader
                .archive()
                .files
                .iter()
                .enumerate()
                .map(|(index, file)| Entry {
                    index,
                    name: file.name.clone(),
                    is_dir: file.is_directory,
                })
                .collect())
        }
        Format::Rar => {
            let mut entries = Vec::new();
            let mut archive = unrar::Archive::with_password(path, password).open_for_listing()?;
            let mut index = 0;
            while let Some(header) = archive.read_header()? {
                let entry = header.entry();
                entries.push(Entry {
                    index,
                    name: entry.filename.to_string_lossy().into_owned(),
                    is_dir: entry.is_directory(),
                });
                index += 1;
                archive = header.skip()?;
            }
            Ok(entries)
        }
        Format::Gzip => {
            let mut decoder = MultiGzDecoder::new(BufReader::new(File::open(path)?));
            // reading a little parses the header, which holds the original name; an empty
            // stream reads nothing, which is fine
            let mut probe = [0u8; 1];
            let _read: usize = decoder.read(&mut probe)?;
            let name = decoder
                .header()
                .and_then(|h| h.filename())
                .map(|n| String::from_utf8_lossy(n).into_owned())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| gzip_member_name(path));
            Ok(vec![Entry {
                index: 0,
                name,
                is_dir: false,
            }])
        }
    }
}

/// A zip entry whose CRC doesn't match still yields its bytes, as 7z and Python's zipfile
/// write a file before they find its CRC wrong. The mismatch is logged.
struct KeepBadChecksum<R> {
    inner: R,
    index: usize,
}

impl<R: Read> Read for KeepBadChecksum<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Err(e)
                if e.kind() == io::ErrorKind::InvalidData
                    && e.to_string() == "Invalid checksum" =>
            {
                tracing::warn!(
                    index = self.index,
                    "a zip entry's CRC doesn't match its bytes"
                );
                Ok(0)
            }
            other => other,
        }
    }
}

/// The name 7z gives a gzip stream's content when its header has none: the archive's name
/// without `.gz`, or `.tar` for `.tgz`.
fn gzip_member_name(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let lower = name.to_lowercase();
    if let Some(stem) = lower.strip_suffix(".tgz") {
        return format!("{}.tar", &name[..stem.len()]);
    }
    for suffix in [".gz", ".gzip"] {
        if lower.ends_with(suffix) {
            return name[..name.len() - suffix.len()].to_owned();
        }
    }
    name
}

fn seven_zip_reader(
    path: &Path,
    password: &str,
) -> Result<sevenz_rust2::ArchiveReader<File>, ArchiveError> {
    let mut reader =
        sevenz_rust2::ArchiveReader::open(path, sevenz_rust2::Password::from(password))?;
    reader.set_thread_count(1);
    Ok(reader)
}

/// Extracts the entries whose indexes are in `wanted`, in archive order, handing each one's
/// bytes to `sink`. An entry that fails is reported to `failed` and the rest carry on, as ace3
/// carries on whatever its tools exit with.
pub fn extract(
    format: Format,
    path: &Path,
    password: &str,
    wanted: &[usize],
    sink: &mut dyn FnMut(usize, &mut dyn Read) -> io::Result<()>,
    failed: &mut dyn FnMut(usize, String),
) -> Result<(), ArchiveError> {
    match format {
        Format::Zip | Format::Jar | Format::Xlsx => {
            let mut archive = zip::ZipArchive::new(BufReader::new(File::open(path)?))?;
            for &index in wanted {
                let encrypted = archive
                    .by_index_raw(index)
                    .map(|e| e.encrypted())
                    .unwrap_or(false);
                let entry = if encrypted {
                    archive.by_index_decrypt(index, password.as_bytes())
                } else {
                    archive.by_index(index)
                };
                let result = entry.map_err(|e| e.to_string()).and_then(|entry| {
                    let mut entry = KeepBadChecksum {
                        inner: entry,
                        index,
                    };
                    sink(index, &mut entry).map_err(|e| e.to_string())
                });
                if let Err(e) = result {
                    failed(index, e);
                }
            }
            Ok(())
        }
        Format::SevenZip => {
            let mut reader = seven_zip_reader(path, password)?;
            let names: Vec<String> = reader
                .archive()
                .files
                .iter()
                .map(|f| f.name.clone())
                .collect();
            let mut position = 0usize;
            let result = reader.for_each_entries(|entry, data| {
                // entries come in the order of their data; find this one's index by name
                let index = names
                    .iter()
                    .enumerate()
                    .skip(position)
                    .chain(names.iter().enumerate().take(position))
                    .find(|(_, n)| **n == entry.name)
                    .map(|(i, _)| i);
                if let Some(index) = index {
                    position = index + 1;
                    if wanted.contains(&index)
                        && let Err(e) = sink(index, data)
                    {
                        failed(index, e.to_string());
                    }
                }
                // a solid block has to be read through to reach the entries after it
                io::copy(data, &mut io::sink())?;
                Ok(true)
            });
            if let Err(e) = result {
                for &index in wanted {
                    failed(index, e.to_string());
                }
            }
            Ok(())
        }
        Format::Rar => {
            let mut archive =
                unrar::Archive::with_password(path, password).open_for_processing()?;
            let mut index = 0;
            loop {
                let Some(header) = archive.read_header()? else {
                    break;
                };
                archive = if wanted.contains(&index) && !header.entry().is_directory() {
                    match header.read() {
                        Ok((bytes, next)) => {
                            if let Err(e) = sink(index, &mut bytes.as_slice()) {
                                failed(index, e.to_string());
                            }
                            next
                        }
                        Err(e) => {
                            // unrar can't go on past an entry it couldn't read
                            failed(index, e.to_string());
                            return Ok(());
                        }
                    }
                } else {
                    header.skip()?
                };
                index += 1;
            }
            Ok(())
        }
        Format::Gzip => {
            if wanted.contains(&0) {
                let mut decoder = MultiGzDecoder::new(BufReader::new(File::open(path)?));
                if let Err(e) = sink(0, &mut decoder) {
                    failed(0, e.to_string());
                }
            }
            Ok(())
        }
    }
}
