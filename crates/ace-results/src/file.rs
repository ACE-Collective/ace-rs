//! Files a result adds to an alert.
//!
//! A file's bytes live in the file store under their sha256. The alert keeps the file's path
//! inside the alert and its `yara_meta` tags, because YARA rules match on the name, the path and
//! the tags (`file_name`, `full_path` and `meta_tags`).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A sha256 digest, written as 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256(pub [u8; 32]);

impl Sha256 {
    pub fn to_hex(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({self})")
    }
}

impl FromStr for Sha256 {
    type Err = InvalidSha256;

    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidSha256(hex.to_owned());
        if hex.len() != 64 {
            return Err(invalid());
        }
        let mut digest = [0u8; 32];
        let (pairs, _) = hex.as_bytes().as_chunks::<2>();
        for (byte, [high, low]) in digest.iter_mut().zip(pairs) {
            let high = lower_hex_digit(*high).ok_or_else(invalid)?;
            let low = lower_hex_digit(*low).ok_or_else(invalid)?;
            *byte = (high << 4) | low;
        }
        Ok(Sha256(digest))
    }
}

fn lower_hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

impl Serialize for Sha256 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;
        hex.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSha256(pub String);

impl fmt::Display for InvalidSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a sha256 in lowercase hex: {:?}", self.0)
    }
}

impl std::error::Error for InvalidSha256 {}

/// A file's path inside its alert, such as `email.rfc822.unknown_text_plain_000` or
/// `evil.zip.extracted/docs/invoice.doc`. It is relative, and `/` separates its parts.
///
/// Names often come from inside hostile files, so a path is checked when it is made (ace3 #829).
/// It must not be empty, absolute (`/x`, `\x`, `C:x`) or contain NUL, and no part may be empty,
/// `.` or `..`. A backslash is an ordinary character on Linux, but parts are also split on it for
/// the `.` and `..` check, so `..\x` is refused too.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct AlertPath(String);

impl AlertPath {
    pub fn new(path: impl Into<String>) -> Result<Self, InvalidAlertPath> {
        let path = path.into();
        match check_alert_path(&path) {
            Ok(()) => Ok(AlertPath(path)),
            Err(reason) => Err(InvalidAlertPath { path, reason }),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The last part of the path: the file's name.
    pub fn name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    /// The path of `name` inside this path, as for a file extracted into a directory.
    pub fn join(&self, name: &str) -> Result<AlertPath, InvalidAlertPath> {
        AlertPath::new(format!("{}/{name}", self.0))
    }
}

fn check_alert_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("it is empty");
    }
    if path.contains('\0') {
        return Err("it contains NUL");
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err("it is absolute");
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err("it starts with a drive letter");
    }
    if path.split('/').any(str::is_empty) {
        return Err("it has an empty part");
    }
    if path
        .split(['/', '\\'])
        .any(|part| part == "." || part == "..")
    {
        return Err("it has a . or .. part");
    }
    Ok(())
}

impl fmt::Display for AlertPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for AlertPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AlertPath({:?})", self.0)
    }
}

impl FromStr for AlertPath {
    type Err = InvalidAlertPath;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        AlertPath::new(path)
    }
}

impl<'de> Deserialize<'de> for AlertPath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        AlertPath::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAlertPath {
    pub path: String,
    pub reason: &'static str,
}

impl fmt::Display for InvalidAlertPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not a path inside an alert: {}",
            self.path, self.reason
        )
    }
}

impl std::error::Error for InvalidAlertPath {}

/// A `yara_meta` tag, written `name=value` as ace3 writes it, such as `type=email.attachment`.
/// The YARA scanner passes a file's tags to the `meta_tags` filter. The name is letters, digits,
/// `_` and `-`; the value is anything after the first `=`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct YaraMeta(String);

impl YaraMeta {
    pub fn new(name: &str, value: &str) -> Result<Self, InvalidYaraMeta> {
        format!("{name}={value}").parse()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn name(&self) -> &str {
        self.split().0
    }

    pub fn value(&self) -> &str {
        self.split().1
    }

    fn split(&self) -> (&str, &str) {
        self.0.split_once('=').unwrap_or((&self.0, ""))
    }
}

impl FromStr for YaraMeta {
    type Err = InvalidYaraMeta;

    fn from_str(tag: &str) -> Result<Self, Self::Err> {
        let valid_name = |name: &str| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        };
        match tag.split_once('=') {
            Some((name, _)) if valid_name(name) => Ok(YaraMeta(tag.to_owned())),
            _ => Err(InvalidYaraMeta(tag.to_owned())),
        }
    }
}

impl fmt::Display for YaraMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for YaraMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YaraMeta({:?})", self.0)
    }
}

impl<'de> Deserialize<'de> for YaraMeta {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidYaraMeta(pub String);

impl fmt::Display for InvalidYaraMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not a yara_meta tag (name=value, the name from [A-Za-z0-9_-])",
            self.0
        )
    }
}

impl std::error::Error for InvalidYaraMeta {}

/// A file a result adds to the alert. Its bytes are already in the file store under `sha256`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewFile {
    pub path: AlertPath,
    pub sha256: Sha256,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub yara_meta: Vec<YaraMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directives: Vec<String>,
    /// Modules that must not analyze this file, as ace3's `exclude_analysis`, such as the email
    /// module on the `.headers` file it wrote itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_modules: Vec<String>,
}

impl NewFile {
    /// The file's name: the last part of its path.
    pub fn name(&self) -> &str {
        self.path.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_round_trips() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let digest: Sha256 = hex.parse().expect("valid hex");
        assert_eq!(digest.to_string(), hex);
        assert_eq!(
            serde_json::to_value(digest).expect("serializes"),
            serde_json::json!(hex)
        );
        assert!(hex.to_uppercase().parse::<Sha256>().is_err());
        assert!(hex[..63].parse::<Sha256>().is_err());
    }

    #[test]
    fn alert_paths_refuse_escapes() {
        for bad in [
            "",
            "/etc/passwd",
            "../../etc/passwd",
            "a/../b",
            "a/./b",
            "..",
            ".",
            "a//b",
            "a/",
            "\\server\\share",
            "..\\..\\x",
            "a\\..\\b",
            "C:\\x",
            "c:x",
            "a\0b",
        ] {
            assert!(AlertPath::new(bad).is_err(), "{bad:?} should be refused");
            assert!(
                serde_json::from_value::<AlertPath>(serde_json::json!(bad)).is_err(),
                "{bad:?} should not deserialize"
            );
        }
    }

    #[test]
    fn alert_paths_keep_ordinary_names() {
        for good in [
            "email.rfc822",
            "evil.zip.extracted/docs/invoice.doc",
            "..hidden",
            "a..b/c",
            "name with spaces.txt",
            "back\\slash.txt",
        ] {
            let path = AlertPath::new(good).expect(good);
            assert_eq!(path.as_str(), good);
        }
        let path = AlertPath::new("evil.zip.extracted/docs/invoice.doc").expect("valid");
        assert_eq!(path.name(), "invoice.doc");
        assert_eq!(
            AlertPath::new("email.rfc822").expect("valid").name(),
            "email.rfc822"
        );
        assert!(path.join("../x").is_err());
    }

    #[test]
    fn yara_meta_tags() {
        let tag = YaraMeta::new("type", "email.attachment").expect("valid");
        assert_eq!(tag.as_str(), "type=email.attachment");
        assert_eq!((tag.name(), tag.value()), ("type", "email.attachment"));
        assert_eq!(
            "x=a=b"
                .parse::<YaraMeta>()
                .expect("value may hold =")
                .value(),
            "a=b"
        );
        assert!("type".parse::<YaraMeta>().is_err());
        assert!("=x".parse::<YaraMeta>().is_err());
        assert!("ty pe=x".parse::<YaraMeta>().is_err());
    }
}
