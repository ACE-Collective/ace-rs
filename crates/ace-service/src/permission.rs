//! What a permission is, and the one case rule (PLAN.md 5.2, ace3 #831).
//!
//! As in ace3, a permission has a major and a minor, such as `alert:write`. A code path checks a
//! `PermissionName`. A row grants or denies a `PermissionPattern`, whose parts can hold fnmatch
//! wildcards: `*`, `?`, `[seq]` and `[!seq]`. There's no admin flag: an admin holds `*:*`.
//!
//! The case rule is in `normalize`: a part is ASCII and lowercase. Both types make their parts with
//! it and keep them private, so an unnormalized value can't be stored or compared. Non-ASCII is
//! refused, not folded, because folding can turn another character into a name: U+212A, the Kelvin
//! sign, lowercases to `k`. ace3's columns are ASCII too. Wildcards fold with the rest, so `[A-Z]`
//! and `[a-z]` are one pattern, as they are in ace3. Migration 0020 holds a stored part to the same
//! rule.
//!
//! Left out of ace3's parsing: a part holding `:` or whitespace is refused, where ace3 can store one
//! that then never matches, or strips it in some paths and not others. ace3's shorthand of a bare
//! `major` meaning `major:*` belongs to whatever parses an operator's input, which isn't here yet.

use std::borrow::Cow;
use std::fmt;

/// ace3's columns are `String(512)`.
const MAX_PART: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} isn't a permission part: use ASCII letters, digits and _ . -, up to 512 of them")]
pub struct InvalidPermission(String);

/// The one case rule. Everything that makes a part comes through here.
fn normalize(part: &str, allowed: impl Fn(u8) -> bool) -> Result<String, InvalidPermission> {
    let part = part.to_ascii_lowercase();
    if part.is_empty() || part.len() > MAX_PART || !part.bytes().all(allowed) {
        return Err(InvalidPermission(part));
    }
    Ok(part)
}

const fn in_name(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
}

fn in_pattern(byte: u8) -> bool {
    in_name(byte) || matches!(byte, b'*' | b'?' | b'[' | b']' | b'!')
}

/// A permission as a code path checks it. It holds no wildcards: `*` isn't something to ask for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionName {
    major: Cow<'static, str>,
    minor: Cow<'static, str>,
}

impl PermissionName {
    /// A name from anywhere, in any case. `Alert:WRITE` and `alert:write` are one name.
    pub fn new(major: &str, minor: &str) -> Result<Self, InvalidPermission> {
        Ok(PermissionName {
            major: Cow::Owned(normalize(major, in_name)?),
            minor: Cow::Owned(normalize(minor, in_name)?),
        })
    }

    /// A name written in code. It has to be normalized already, or the build fails.
    pub const fn known(major: &'static str, minor: &'static str) -> Self {
        assert!(
            is_normal_name(major) && is_normal_name(minor),
            "a known permission must be lowercase"
        );
        PermissionName {
            major: Cow::Borrowed(major),
            minor: Cow::Borrowed(minor),
        }
    }

    pub fn major(&self) -> &str {
        &self.major
    }

    pub fn minor(&self) -> &str {
        &self.minor
    }
}

const fn is_normal_name(part: &str) -> bool {
    let bytes = part.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !in_name(bytes[i]) {
            return false;
        }
        i += 1;
    }
    !bytes.is_empty() && bytes.len() <= MAX_PART
}

impl fmt::Display for PermissionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

/// What a row grants or denies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionPattern {
    major: String,
    minor: String,
}

impl PermissionPattern {
    pub fn new(major: &str, minor: &str) -> Result<Self, InvalidPermission> {
        Ok(PermissionPattern {
            major: normalize(major, in_pattern)?,
            minor: normalize(minor, in_pattern)?,
        })
    }

    pub fn major(&self) -> &str {
        &self.major
    }

    pub fn minor(&self) -> &str {
        &self.minor
    }

    pub fn matches(&self, name: &PermissionName) -> bool {
        fnmatch(self.major.as_bytes(), name.major.as_bytes())
            && fnmatch(self.minor.as_bytes(), name.minor.as_bytes())
    }
}

impl fmt::Display for PermissionPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

/// Python's `fnmatchcase`, which ace3 matches with. Parts are ASCII, so bytes will do. It agreed with
/// Python on 199,998 of 200,000 random patterns. Those two hit a Python quirk: a reversed range whose
/// removal leaves `!` first, as in `[[-!!]`, turns the class into a negated one there.
fn fnmatch(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v) = (0, 0);
    // where to resume after the last `*`: the pattern after it, and how much it has taken
    let mut star = None;
    while v < value.len() {
        let next = match pattern.get(p) {
            Some(b'*') => {
                p += 1;
                star = Some((p, v));
                continue;
            }
            Some(b'?') => Some(p + 1),
            Some(b'[') => match class_end(pattern, p) {
                Some(end) => class_matches(&pattern[p + 1..end], value[v]).then_some(end + 1),
                // an unclosed `[` is a literal one
                None => (value[v] == b'[').then_some(p + 1),
            },
            Some(&literal) => (literal == value[v]).then_some(p + 1),
            None => None,
        };
        match (next, star) {
            (Some(next), _) => {
                p = next;
                v += 1;
            }
            (None, Some((after, taken))) => {
                p = after;
                v = taken + 1;
                star = Some((after, v));
            }
            (None, None) => return false,
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

/// The index of the `]` that closes the class opening at `open`. A `]` straight after the opening
/// is a member.
fn class_end(pattern: &[u8], open: usize) -> Option<usize> {
    let mut first = open + 1;
    if pattern.get(first) == Some(&b'!') {
        first += 1;
    }
    if pattern.get(first) == Some(&b']') {
        first += 1;
    }
    let tail = pattern.get(first..)?;
    tail.iter()
        .position(|&byte| byte == b']')
        .map(|at| first + at)
}

fn class_matches(class: &[u8], byte: u8) -> bool {
    let (negated, members) = match class.split_first() {
        Some((b'!', members)) => (true, members),
        _ => (false, class),
    };
    let mut found = false;
    let mut i = 0;
    while i < members.len() {
        if members.get(i + 1) == Some(&b'-') && i + 2 < members.len() {
            // a reversed range is empty
            found |= (members[i]..=members[i + 2]).contains(&byte);
            i += 3;
        } else {
            found |= members[i] == byte;
            i += 1;
        }
    }
    found != negated
}

/// What a row does when its pattern matches. A deny wins over any allow, whichever row it's on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "service.permission_effect", rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// True when something allows the name and nothing denies it. No match is a refusal.
pub(crate) fn allows<'g>(
    grants: impl IntoIterator<Item = &'g (PermissionPattern, Effect)>,
    name: &PermissionName,
) -> bool {
    let mut allowed = false;
    for (pattern, effect) in grants {
        if pattern.matches(name) {
            match effect {
                Effect::Deny => return false,
                Effect::Allow => allowed = true,
            }
        }
    }
    allowed
}

/// Change an alert: ace3's `alert:write`, which its disposition route requires.
pub const ALERT_WRITE: PermissionName = PermissionName::known("alert", "write");
/// Change users, groups and grants: ace3's `user:write`.
pub const USER_WRITE: PermissionName = PermissionName::known("user", "write");
/// Manage your own API keys: ace3's `user:self`.
pub const USER_SELF: PermissionName = PermissionName::known("user", "self");

/// True for a permission only a person can hold, whatever a key's or a component's rows say. A key
/// holding `user:self` could widen its own scope up to all its owner holds, as ace3's
/// `SESSION_ONLY_PAIRS` says.
pub(crate) fn is_people_only(name: &PermissionName) -> bool {
    *name == USER_SELF
}
