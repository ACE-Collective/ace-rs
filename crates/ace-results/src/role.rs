//! A file's role: what its producer made it, such as an email's attachment or the text a PDF
//! renders to (docs/decisions/0003, PLAN.md decision 25).
//!
//! A file's *type* is what its bytes are (`types::file_type::TypeFacts`), found by reading them. Its
//! *role* is what the module that wrote it knew it to be, and needs no reading. The same bytes can
//! have two roles in one root, an attachment in one email and a body part in another, so the role is
//! kept on each of a file's paths (`analysis.files.role`), as its `yara_meta` tags are.
//!
//! The names are ace3's, the values its modules give `yara_meta`'s `type=` tag, and that tag is
//! built from the role (`FileRole::yara_meta`), so a YARA rule and the signatures see what they saw
//! before the role had a field of its own. The list is fixed when the binary is built, as the
//! observable types are: `FileRole::BUILTIN` is the open-source modules' roles, a site adds its own
//! with `ace_app::App::file_roles`, and `install_roles` makes that the process's list before anything
//! reads one. A result that names a role the binary doesn't list is refused.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::file::YaraMeta;

/// A file's role, named as ace3's `type=` values are. Two roles are equal when their names are.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileRole(&'static str);

macro_rules! file_roles {
    ($($variant:ident = $name:literal;)+) => {
        impl FileRole {
            $(pub const $variant: FileRole = FileRole::define($name);)+

            /// The open-source modules' roles, in name order.
            pub const BUILTIN: &'static [FileRole] = &[$(FileRole::$variant),+];
        }
    };
}

file_roles! {
    ARCHIVE_DMG = "archive.dmg";
    DOCUMENT_ACTIVEMIME = "document.activemime";
    DOCUMENT_HTML_EMBEDDED = "document.html.embedded";
    DOCUMENT_HTML_PHISHKIT = "document.html.phishkit";
    DOCUMENT_MHTML_PART = "document.mhtml.part";
    DOCUMENT_OFFICE = "document.office";
    DOCUMENT_ONENOTE_EMBEDDED = "document.onenote.embedded";
    DOCUMENT_PDF = "document.pdf";
    DOCUMENT_PDF_ANNOTATION_URIS = "document.pdf.annotation_uris";
    DOCUMENT_PDF_FORM_FIELD = "document.pdf.form_field";
    DOCUMENT_PDF_OBJECT = "document.pdf.object";
    DOCUMENT_PDF_RENDERED = "document.pdf.rendered";
    DOCUMENT_PDF_TEXT = "document.pdf.text";
    DOCUMENT_RTF_OBJECT = "document.rtf.object";
    DOCUMENT_RTF_STRIPPED = "document.rtf.stripped";
    DOCUMENT_TEXT_OCR = "document.text.ocr";
    DOCUMENT_TEXT_QRCODE = "document.text.qrcode";
    DOCUMENT_TEXT_REFANGED = "document.text.refanged";
    EMAIL = "email";
    EMAIL_ATTACHMENT = "email.attachment";
    EMAIL_COMBINED = "email.combined";
    EMAIL_HEADERS = "email.headers";
    EXECUTABLE_DOTNET = "executable.dotnet";
    EXECUTABLE_UNPACKED = "executable.unpacked";
    METADATA_EXIF = "metadata.exif";
    METADATA_LNK = "metadata.lnk";
    METADATA_X509 = "metadata.x509";
    PAYLOAD_BASE64 = "payload.base64";
    SCRIPT_AUTOIT = "script.autoit";
    SCRIPT_DOTNET_DECOMPILED = "script.dotnet.decompiled";
    SCRIPT_ENCODED = "script.encoded";
    SCRIPT_JAVA_DECOMPILED = "script.java.decompiled";
    SCRIPT_JAVASCRIPT = "script.javascript";
    SCRIPT_MACRO = "script.macro";
    SCRIPT_MACRO_VBA = "script.macro.vba";
    SCRIPT_MACRO_XLM = "script.macro.xlm";
    SCRIPT_VBSCRIPT = "script.vbscript";
}

impl FileRole {
    /// A role named `name`, for a site's constant. It is a role only once the binary lists it.
    pub const fn define(name: &'static str) -> FileRole {
        FileRole(name)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// The `yara_meta` tag the role gives the file: `type=<role>`.
    pub fn yara_meta(self) -> YaraMeta {
        YaraMeta::new("type", self.0).expect("a role's name is a valid yara_meta value")
    }

    /// The role a `yara_meta` tag names, when it is `type=` and a role this binary lists.
    pub fn of_yara_meta(tag: &YaraMeta) -> Option<FileRole> {
        (tag.name() == "type")
            .then(|| tag.value().parse().ok())
            .flatten()
    }

    /// This binary's roles in name order: the list `install_roles` installed, or `BUILTIN`.
    pub fn all() -> &'static [FileRole] {
        INSTALLED.get().map_or(FileRole::BUILTIN, Vec::as_slice)
    }
}

static INSTALLED: OnceLock<Vec<FileRole>> = OnceLock::new();

/// Why a binary's list of roles is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoleListError {
    #[error("file role {0:?} isn't lowercase letters, digits and _, in parts joined by .")]
    BadName(&'static str),
    #[error("file role {0} is listed twice")]
    Duplicate(&'static str),
    #[error("this process already installed a different list of file roles")]
    AlreadyInstalled,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// The built-in roles and `extra`, in name order, after checking that every name is valid and
/// listed once.
pub fn role_list(extra: &[FileRole]) -> Result<Vec<FileRole>, RoleListError> {
    let mut list = FileRole::BUILTIN.to_vec();
    for role in extra {
        if !valid_name(role.0) {
            return Err(RoleListError::BadName(role.0));
        }
        if list.contains(role) {
            return Err(RoleListError::Duplicate(role.0));
        }
        list.push(*role);
    }
    list.sort();
    Ok(list)
}

/// Makes this process's roles the built-in ones plus `extra`. `ace-app` calls it once, first thing
/// in `main`; calling it again with the same list does nothing, and with another fails.
pub fn install_roles(extra: &[FileRole]) -> Result<(), RoleListError> {
    let list = role_list(extra)?;
    let installed = INSTALLED.get_or_init(|| list.clone());
    if *installed == list {
        Ok(())
    } else {
        Err(RoleListError::AlreadyInstalled)
    }
}

/// A name that isn't one of this binary's roles.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} isn't a file role this binary lists")]
pub struct UnknownFileRole(pub String);

impl FromStr for FileRole {
    type Err = UnknownFileRole;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        FileRole::all()
            .iter()
            .find(|role| role.0 == name)
            .copied()
            .ok_or_else(|| UnknownFileRole(name.to_owned()))
    }
}

impl fmt::Display for FileRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl fmt::Debug for FileRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileRole({})", self.0)
    }
}

impl Serialize for FileRole {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

impl<'de> Deserialize<'de> for FileRole {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = Cow::<'de, str>::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for FileRole {
    fn schema_name() -> Cow<'static, str> {
        "FileRole".into()
    }

    /// A string naming one of this binary's roles.
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let names: Vec<&str> = FileRole::all().iter().map(|r| r.as_str()).collect();
        json_schema!({
            "description": "A file's role: what its producer made it, named as ace3's yara_meta type= values are.",
            "type": "string",
            "enum": names,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_roles_are_sorted_valid_and_give_their_type_tag() {
        let mut sorted = FileRole::BUILTIN.to_vec();
        sorted.sort();
        assert_eq!(sorted, FileRole::BUILTIN);
        assert!(FileRole::BUILTIN.iter().all(|r| valid_name(r.as_str())));
        assert_eq!(
            FileRole::EMAIL_ATTACHMENT.yara_meta().as_str(),
            "type=email.attachment"
        );
        let tag: YaraMeta = "type=document.pdf.text".parse().expect("a tag");
        assert_eq!(
            FileRole::of_yara_meta(&tag),
            Some(FileRole::DOCUMENT_PDF_TEXT)
        );
        let other: YaraMeta = "type=nothing.known".parse().expect("a tag");
        assert_eq!(FileRole::of_yara_meta(&other), None);
        assert!(serde_json::from_str::<FileRole>("\"nothing.known\"").is_err());
        assert_eq!(
            serde_json::from_str::<FileRole>("\"email\"").expect("a role"),
            FileRole::EMAIL
        );
    }

    #[test]
    fn a_site_s_list_is_checked() {
        let site = FileRole::define("site.ticket");
        assert!(role_list(&[site]).expect("valid").contains(&site));
        assert_eq!(
            role_list(&[FileRole::EMAIL]),
            Err(RoleListError::Duplicate("email"))
        );
        for bad in ["", "Site", "a..b", ".a", "a b"] {
            let leaked: &'static str = Box::leak(bad.to_owned().into_boxed_str());
            assert!(role_list(&[FileRole::define(leaked)]).is_err(), "{bad:?}");
        }
    }
}
