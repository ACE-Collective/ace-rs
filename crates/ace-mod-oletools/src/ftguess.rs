//! oletools' `ftguess.FileTypeGuesser`: what `VBA_Parser` asks of it, whether a file is Excel, and
//! what rtfobj prints for a package, the type's name. Its exceptions leave the constructor, because
//! ftguess catches few of them.

use std::sync::Arc;

use crate::ole::{OleFile, has_magic};
use crate::py::{PyErr, PyResult};
use crate::pyxml;
use crate::pyzip::{ZipFile, check_zipfile};
use crate::tables::{
    CLSID_FTYPES, FTYPE_EXE_PE, FTYPE_GENERIC_OLE, FTYPE_GENERIC_OPENXML, FTYPE_GENERIC_ZIP,
    FTYPE_ONENOTE, FTYPE_PNG, FTYPE_RTF, FTYPE_UNKNOWN, OPENXML_FTYPES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileType {
    pub name: &'static str,
    pub is_excel: bool,
}

const fn file_type(name: &'static str) -> FileType {
    FileType {
        name,
        is_excel: false,
    }
}

const NS_RELS: &str = "{http://schemas.openxmlformats.org/package/2006/relationships}";
const NS_CONTENT_TYPES: &str = "{http://schemas.openxmlformats.org/package/2006/content-types}";
const MAIN_RELATIONSHIPS: [&str; 3] = [
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/officeDocument",
    "http://schemas.microsoft.com/xps/2005/06/fixedrepresentation",
];

/// `FileTypeGuesser(data=data)`, in the frames of `depth`, for what a crafted directory exhausts.
pub fn guess(data: &Arc<Vec<u8>>, depth: usize) -> PyResult<FileType> {
    if data.starts_with(b"{\\rt") {
        return Ok(file_type(FTYPE_RTF));
    }
    // short data is padded for isOleFile, and then OleFileIO takes bytes under 1536 for a path
    if has_magic(data)
        && let Ok(ole) = OleFile::open_bytes(Arc::clone(data), depth)
    {
        let clsid = ole.root_clsid();
        return Ok(CLSID_FTYPES.iter().find(|row| row.0 == clsid).map_or(
            file_type(FTYPE_GENERIC_OLE),
            |row| FileType {
                name: row.1,
                is_excel: row.2,
            },
        ));
    }
    if check_zipfile(data)? {
        match ZipFile::new(data) {
            Ok(zip) => return guess_zip(&zip),
            Err(error) if error.kind == "BadZipFile" => {}
            Err(error) => return Err(error),
        }
    }
    if data.starts_with(b"\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\x53\x78\xD0\x29\x96\xD3") {
        return Ok(file_type(FTYPE_ONENOTE));
    }
    if data.starts_with(b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A") {
        return Ok(file_type(FTYPE_PNG));
    }
    if data.starts_with(b"MZ") {
        return Ok(file_type(FTYPE_EXE_PE));
    }
    Ok(file_type(FTYPE_UNKNOWN))
}

fn is_runtime_error(error: &PyErr) -> bool {
    matches!(
        error.kind.as_str(),
        "RuntimeError" | "NotImplementedError" | "RecursionError"
    )
}

fn guess_zip(zip: &ZipFile<'_>) -> PyResult<FileType> {
    let generic = file_type(FTYPE_GENERIC_ZIP);
    if !zip.contains("_rels/.rels") {
        return Ok(generic);
    }
    let rels = match zip.read("_rels/.rels") {
        Ok(rels) => rels,
        Err(error) if is_runtime_error(&error) => return Ok(generic),
        Err(error) => return Err(error),
    };
    let rels = pyxml::fromstring(&rels)?;
    if rels.tag != format!("{NS_RELS}Relationships") {
        return Ok(generic);
    }
    let tag = format!("{NS_RELS}Relationship");
    let main_part = rels
        .iter_tag(&tag)
        .into_iter()
        .find(|rel| {
            rel.get("Type")
                .is_some_and(|kind| MAIN_RELATIONSHIPS.contains(&kind))
        })
        .and_then(|rel| rel.get("Target").map(str::to_owned));
    let Some(main_part) = main_part else {
        return Ok(generic);
    };
    let types = match zip.read("[Content_Types].xml") {
        Ok(types) => types,
        Err(error) if is_runtime_error(&error) => return Ok(generic),
        Err(error) => return Err(error),
    };
    let types = pyxml::fromstring(&types)?;
    let mut by_extension: Vec<(String, String)> = Vec::new();
    for element in types.iter_tag(&format!("{NS_CONTENT_TYPES}Default")) {
        if let (Some(extension), Some(kind)) =
            (element.get("Extension"), element.get("ContentType"))
        {
            by_extension.push((extension.to_owned(), kind.to_owned()));
        }
    }
    let mut by_part: Vec<(String, String)> = Vec::new();
    for element in types.iter_tag(&format!("{NS_CONTENT_TYPES}Override")) {
        let Some(part) = element.get("PartName") else {
            return Err(PyErr::new(
                "AttributeError",
                "'NoneType' object has no attribute 'lstrip'",
            ));
        };
        if let Some(kind) = element.get("ContentType") {
            by_part.push((part.trim_start_matches('/').to_owned(), kind.to_owned()));
        }
    }
    let content_type = by_part
        .iter()
        .rev()
        .find(|(part, _)| *part == main_part)
        .or_else(|| {
            let extension = splitext(&main_part).1;
            let extension = extension.strip_prefix('.').unwrap_or(extension);
            by_extension
                .iter()
                .rev()
                .find(|(known, _)| known == extension)
        })
        .map(|(_, kind)| kind.as_str());
    Ok(content_type
        .and_then(|kind| OPENXML_FTYPES.iter().find(|row| row.0 == kind))
        .map_or(file_type(FTYPE_GENERIC_OPENXML), |row| FileType {
            name: row.1,
            is_excel: row.2,
        }))
}

/// `os.path.splitext`: a name's leading dots don't start an extension.
pub fn splitext(path: &str) -> (&str, &str) {
    let name_start = path.rfind('/').map_or(0, |at| at + 1);
    let Some(dot) = path.rfind('.') else {
        return (path, "");
    };
    if dot < name_start {
        return (path, "");
    }
    if path[name_start..dot].bytes().all(|byte| byte == b'.') {
        return (path, "");
    }
    path.split_at(dot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitext_is_pythons() {
        assert_eq!(splitext("a/b.c.d"), ("a/b.c", ".d"));
        assert_eq!(splitext(".bashrc"), (".bashrc", ""));
        assert_eq!(splitext("a.b/c"), ("a.b/c", ""));
        assert_eq!(splitext("..a.b"), ("..a", ".b"));
    }
}
