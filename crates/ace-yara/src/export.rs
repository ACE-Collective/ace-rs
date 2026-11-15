//! The observables enabled for detection as YARA rules (PLAN.md 7.16), a port of ace3's
//! `saq/observables/export/yara.py` and the parts of `export/base.py` it stands on.
//!
//! Each detection of a configured type becomes a string named `$obsd_<id>` in its type's rule, one
//! rule file per type, each from the type's template or the default one. The id is the detection's:
//! the YARA module reads it back out of a match to say which detection fired. ace3 writes the files
//! into a directory of its signature directory, `observable_export`, every minute that the list
//! changed. Here they are that namespace of the ruleset the core builds (`ruleset::Owned`), which
//! holds nothing else, and they're generated again whenever the fingerprint of what would be
//! exported changes.
//!
//! As in ace3:
//! - A type in the export list covers its own detections and those of every type that extends it,
//!   exported under the configured type; the most specific configured type wins.
//! - A value shorter than the minimum length isn't exported.
//! - A type with a boundary family gets a regex that matches the value only as a whole token, one
//!   string for ASCII and one for UTF-16 text, and a value over `MAX_BOUNDED_VALUE_LENGTH`
//!   characters keeps its text string.
//! - A value whose JSON form differs gets a second string for it, `$obsd_json_<id>`.
//! - Each detection's strings compile alone before they join the rule, so a value the compiler
//!   refuses leaves out only itself.
//!
//! What differs:
//! - The values are text an analyst typed, and a rule compiler is no place for it unchecked. ace3's
//!   escaping is kept as it is, since nothing it lets through can end a string or a regex. On top
//!   of it, a rule that compiled is refused unless it holds exactly the rules, tags and meta its
//!   template has and exactly the strings this module wrote, so a value that did change a rule's
//!   structure can't reach the ruleset.
//! - The export is bounded: `MAX_ENTRIES` detections, `MAX_VALUE_BYTES` a value and
//!   `MAX_SOURCE_BYTES` of rule text over all the files. What's over is left out and reported, as a
//!   value that doesn't compile is. ace3 has `max_strings_per_rule` (30,720), a libyara setting
//!   yara-x doesn't have; a list holds at most 1,000 entries of four strings each, so it can't be
//!   reached.
//! - The rules compile together first, and each detection alone only when that fails. The result
//!   is the same as compiling each alone first: a rule that compiles holds only strings that
//!   compile alone.
//! - The files are checked together as their namespace, and none is exported when they don't
//!   load, such as two types whose templates give their rules one name. ace3 would write both, and
//!   its scanner would then keep its previous rules.
//! - The namespace has one more file, `INDEX_FILE`, whose rule matches nothing and whose meta
//!   holds each exported detection's type and value by its id (`Ruleset::detection`). ace3's
//!   scanner reads the detection's row when a string matches; a pool has no database, so the
//!   ruleset carries what the row would say, and a rule and its observable always agree.
//! - The templates are in the binary (`templates/`, ace3's `etc/yara_templates`), and the overlay
//!   can replace or add one. ace3 reads a directory, and skips a type whose template is missing.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::load::new_compiler;
use crate::meta::Meta;

/// The namespace the generated rules are: ace3's `OBSERVABLE_EXPORT_DIR`.
pub const NAMESPACE: &str = "observable_export";
/// The file holding the index rule. No type's file can have the name: a type has no `-`.
pub const INDEX_FILE: &str = "obsd-index.yar";
/// The rule whose meta says which detection each `$obsd_` id is.
pub const INDEX_RULE: &str = "obsd_index";
/// Raised whenever the generated strings change shape, so the next build writes every rule again:
/// ace3's `YARA_EXPORT_FORMAT_VERSION`, with ace4's own part after the dot.
pub const FORMAT_VERSION: &str = "3.1";
/// A value longer than this, in characters of its JSON form, keeps its text string: libyara stops
/// matching a regex about 1 KiB into a match, and ace3 keeps its rules the same for both.
pub const MAX_BOUNDED_VALUE_LENGTH: usize = 500;
/// The most detections one export holds: a list's limit (`ace_sdk::lists::MAX_ENTRIES`).
pub const MAX_ENTRIES: usize = 1000;
/// The longest value exported, in bytes: a list entry's limit.
pub const MAX_VALUE_BYTES: usize = 4096;
/// The most rule text all the files hold together, the index included.
pub const MAX_SOURCE_BYTES: usize = 8 << 20;
/// The most escape sequences one generated string holds. yara-x's parser recurses once for each
/// escape in a literal, and about 3,000 of them overflow a 2 MiB stack in a debug build
/// (`docs/measurements/yara-export.md`), which would take the core down with it. A value whose text
/// string would hold more is left out and reported; a bounded value whose regex would keeps its
/// text string, which has an escape only for each backslash and quote. A bounded value of ASCII
/// stays under it: 500 characters are at most 1,000 escapes as a wide regex, and 12 for its
/// boundaries.
pub const MAX_ESCAPES: usize = crate::guard::MAX_ESCAPES;
/// The longest template, in bytes.
pub const MAX_TEMPLATE_BYTES: usize = 64 << 10;
/// The most types an export list names.
pub const MAX_EXPORT_TYPES: usize = 256;

const TEMPLATE_RULE_NAME: &str = "TEMPLATE_RULE_NAME";
const TEMPLATE_TAGS: &str = "TEMPLATE_TAGS";
const TEMPLATE_DATE_STRING: &str = "TEMPLATE_DATE_STRING";
const TEMPLATE_STRINGS: &str = "TEMPLATE_STRINGS";
const DEFAULT_TEMPLATE: &str = "default";

/// ace3's `etc/yara_templates`, by type.
const TEMPLATES: [(&str, &str); 6] = [
    (
        DEFAULT_TEMPLATE,
        include_str!("../templates/default.template"),
    ),
    (
        "email_address",
        include_str!("../templates/email_address.template"),
    ),
    (
        "email_subject",
        include_str!("../templates/email_subject.template"),
    ),
    (
        "email_x_mailer",
        include_str!("../templates/email_x_mailer.template"),
    ),
    ("ip", include_str!("../templates/ip.template")),
    ("ipv4", include_str!("../templates/ipv4.template")),
];

/// The string modifiers a type's strings may have.
const MODIFIERS: [&str; 4] = ["ascii", "wide", "nocase", "fullword"];

/// Escapes a value for a YARA text string: ace3's `format_yara_string`.
pub fn format_yara_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], "")
}

/// Escapes a value as it appears inside a JSON document, for a YARA text string: JSON escapes the
/// backslashes itself, so the value carries twice as many. ace3's `format_yara_json_string`.
pub fn format_yara_json_string(value: &str) -> String {
    value
        .replace('\\', "\\\\\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], "")
}

/// The characters that are special inside a YARA `/regex/`; the slash ends it.
fn regex_special(c: char) -> bool {
    "\\/^$.|?*+()[]{}".contains(c)
}

/// Escapes a value for a YARA `/regex/`: ace3's `format_yara_regex`. A character outside ASCII
/// stays as it is, and yara-x matches its UTF-8 bytes, as libyara does.
pub fn format_yara_regex(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '\n' || c == '\r' {
            continue;
        }
        if regex_special(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// One byte of a wide regex: printable ASCII as it is, escaped when it's special, and any other
/// byte as `\xNN`.
fn push_regex_byte(out: &mut String, byte: u8) {
    if (0x20..0x7f).contains(&byte) {
        let c = byte as char;
        if regex_special(c) {
            out.push('\\');
        }
        out.push(c);
    } else {
        out.push_str(&format!("\\x{byte:02x}"));
    }
}

/// Escapes a value for a regex that matches what the `wide` modifier would: every UTF-8 byte of
/// the value followed by a NUL. ace3's `format_wide_yara_regex`.
pub fn format_wide_yara_regex(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 5);
    for byte in value.bytes() {
        if byte == b'\n' || byte == b'\r' {
            continue;
        }
        push_regex_byte(&mut out, byte);
        out.push_str("\\x00");
    }
    out
}

/// A boundary family: the characters that make a "word" on each side of a value. A bounded value
/// can't have a word character directly before or after it. ace3's `BOUNDARY_FAMILIES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    Hostname,
    EmailAddress,
    Ipv4,
    Ipv6,
    Hex,
}

impl Family {
    pub const ALL: [Family; 5] = [
        Family::Hostname,
        Family::EmailAddress,
        Family::Ipv4,
        Family::Ipv6,
        Family::Hex,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Family::Hostname => "hostname",
            Family::EmailAddress => "email_address",
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
            Family::Hex => "hex",
        }
    }

    pub fn parse(name: &str) -> Option<Family> {
        Family::ALL.into_iter().find(|f| f.as_str() == name)
    }

    /// The class of word characters before the value, as a regex class's inside.
    fn left(self) -> &'static str {
        match self {
            Family::Hostname => r"a-zA-Z0-9_\-",
            // "." and "+" are legal in the local part, so neither may come before the address
            Family::EmailAddress => r"a-zA-Z0-9_\-.+",
            // 1.2.3.4 must not sit inside 5.1.2.3.4, 11.2.3.4, 1.2.3.45 or 1.2.3.4.5
            Family::Ipv4 => r"0-9.",
            Family::Ipv6 => r"0-9a-fA-F:",
            Family::Hex => r"a-fA-F0-9",
        }
    }

    fn right(self) -> &'static str {
        match self {
            Family::Hostname | Family::EmailAddress => r"a-zA-Z0-9_\-",
            Family::Ipv4 => r"0-9",
            Family::Ipv6 => r"0-9a-fA-F:",
            Family::Hex => r"a-fA-F0-9",
        }
    }

    /// A "." after the value is a boundary only when no word character follows it, so
    /// `evil.com.au` is refused and `block evil.com.` at a sentence's end still hits.
    fn dot_aware(self) -> bool {
        matches!(self, Family::Hostname | Family::EmailAddress | Family::Ipv4)
    }

    fn is_left(self, c: char) -> bool {
        match self {
            Family::Hostname => c.is_ascii_alphanumeric() || c == '_' || c == '-',
            Family::EmailAddress => c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'),
            Family::Ipv4 => c.is_ascii_digit() || c == '.',
            Family::Ipv6 => c.is_ascii_hexdigit() || c == ':',
            Family::Hex => c.is_ascii_hexdigit(),
        }
    }

    fn is_right(self, c: char) -> bool {
        match self {
            Family::Hostname | Family::EmailAddress => {
                c.is_ascii_alphanumeric() || c == '_' || c == '-'
            }
            Family::Ipv4 => c.is_ascii_digit(),
            Family::Ipv6 => c.is_ascii_hexdigit() || c == ':',
            Family::Hex => c.is_ascii_hexdigit(),
        }
    }
}

/// The value as a YARA regex that matches only when it isn't part of a longer token: ace3's
/// `format_bounded_yara_regex`. A side gets a boundary only when the value's edge character is a
/// word character of the family, so a partial URL ending in `/` or `=` still matches whatever
/// follows it. With `wide` the regex matches UTF-16LE text, where a boundary is any whole code
/// unit that isn't an ASCII word character.
pub fn format_bounded_yara_regex(value: &str, family: Family, wide: bool) -> String {
    let (core, dot) = if wide {
        (format_wide_yara_regex(value), "\\.\\x00")
    } else {
        (format_yara_regex(value), "\\.")
    };
    let not_word = |chars: &str| {
        if wide {
            format!("([^{chars}]\\x00|[\\x00-\\xff][^\\x00])")
        } else {
            format!("[^{chars}]")
        }
    };
    let mut left = String::new();
    if value.chars().next().is_some_and(|c| family.is_left(c)) {
        left = format!("(^|{})", not_word(family.left()));
    }
    let mut right = String::new();
    if value
        .chars()
        .next_back()
        .is_some_and(|c| family.is_right(c))
    {
        right = if family.dot_aware() {
            format!(
                "({}|{dot}{}|({dot})?$)",
                not_word(&format!("{}.", family.right())),
                not_word(family.right()),
            )
        } else {
            format!("({}|$)", not_word(family.right()))
        };
    }
    format!("/{left}{core}{right}/")
}

/// What the export is set to: ace3's `yara_export`, `yara_export_string_modifiers` and
/// `yara_export_string_boundaries` sections, and its template directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportConfig {
    /// The observable types exported. An entry also covers every type that extends it.
    pub export_list: Vec<String>,
    /// The fewest characters a value has to be exported.
    pub minimum_length: usize,
    /// The string modifiers by type; `default` is every other type's.
    pub modifiers: BTreeMap<String, String>,
    /// The boundary family by type: a family's name, or `ip`, which is `ipv4` or `ipv6` by value.
    pub boundaries: BTreeMap<String, String>,
    /// The rule templates by type; `default` is every other type's.
    pub templates: BTreeMap<String, String>,
}

impl Default for ExportConfig {
    /// ace3's `saq.default.yaml` and `etc/yara_templates`.
    fn default() -> Self {
        let pairs = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect()
        };
        ExportConfig {
            export_list: [
                "email_address",
                "email_body",
                "email_subject",
                "email_x_mailer",
                "file_name",
                "file_path",
                "fqdn",
                "ip",
                // detections from before ace3 moved to the generic `ip` type still carry `ipv4`
                "ipv4",
                "md5",
                "sha256",
                "uri_path",
                "url",
                "user_agent",
            ]
            .map(str::to_owned)
            .to_vec(),
            minimum_length: 5,
            modifiers: pairs(&[
                ("default", "ascii wide nocase"),
                ("fqdn", "ascii wide nocase fullword"),
                ("file_name", "ascii wide nocase fullword"),
            ]),
            boundaries: pairs(&[
                ("url", "hostname"),
                ("fqdn", "hostname"),
                ("email_address", "email_address"),
                ("ip", "ip"),
                ("ipv4", "ipv4"),
                ("md5", "hex"),
                ("sha256", "hex"),
            ]),
            templates: pairs(&TEMPLATES),
        }
    }
}

/// Whether `name` can be an exported type: what an observable type is spelled with. It names a
/// rule and a file, so nothing else is let in.
fn valid_type(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

impl ExportConfig {
    /// The types exported, trimmed, without blanks or repeats: ace3's `configured`.
    fn configured(&self) -> BTreeSet<&str> {
        self.export_list
            .iter()
            .map(|entry| entry.trim())
            .filter(|entry| !entry.is_empty())
            .collect()
    }

    /// The string modifiers of a type's values: ace3's `get_string_modifiers`.
    pub fn string_modifiers(&self, observable_type: &str) -> &str {
        self.modifiers
            .get(&observable_type.to_lowercase())
            .or_else(|| self.modifiers.get("default"))
            .map_or("", String::as_str)
    }

    /// The boundary family of a value of this type, or None to keep a text string: ace3's
    /// `get_string_boundary`. `check` refuses a family that isn't one, where ace3 logs it at each
    /// export and keeps the text string.
    pub fn string_boundary(&self, observable_type: &str, value: &str) -> Option<Family> {
        let family = self.boundaries.get(&observable_type.to_lowercase())?;
        if family == "ip" {
            return Some(if value.contains(':') {
                Family::Ipv6
            } else {
                Family::Ipv4
            });
        }
        Family::parse(family)
    }

    /// The type's template with everything but the strings filled in: ace3's `_load_template`.
    fn template(&self, observable_type: &str, date: &str) -> Option<String> {
        let template = self
            .templates
            .get(observable_type)
            .or_else(|| self.templates.get(DEFAULT_TEMPLATE))?;
        let rule_name: String = observable_type
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        Some(
            template
                .replace(TEMPLATE_RULE_NAME, &rule_name)
                .replace(TEMPLATE_TAGS, &rule_name)
                .replace(TEMPLATE_DATE_STRING, date),
        )
    }

    /// Checks the settings as `ace serve` does when it starts: the types, the modifiers, the
    /// families, and that every template compiles with a string in it.
    pub fn check(&self) -> Result<(), String> {
        let configured = self.configured();
        if configured.len() > MAX_EXPORT_TYPES {
            return Err(format!(
                "export_list names more than {MAX_EXPORT_TYPES} types"
            ));
        }
        for name in &configured {
            if !valid_type(name) {
                return Err(format!(
                    "export_list: {name:?} isn't an observable type's name (letters, digits and _)"
                ));
            }
        }
        for (name, modifiers) in &self.modifiers {
            for modifier in modifiers.split_whitespace() {
                if !MODIFIERS.contains(&modifier) {
                    return Err(format!(
                        "string_modifiers.{name}: {modifier:?} isn't one of {}",
                        MODIFIERS.join(", ")
                    ));
                }
            }
        }
        for (name, family) in &self.boundaries {
            if family != "ip" && Family::parse(family).is_none() {
                return Err(format!(
                    "string_boundaries.{name}: {family:?} isn't ip or one of {}",
                    Family::ALL.map(Family::as_str).join(", ")
                ));
            }
        }
        for (name, template) in &self.templates {
            if name != DEFAULT_TEMPLATE && !valid_type(name) {
                return Err(format!(
                    "templates: {name:?} isn't an observable type's name"
                ));
            }
            if template.len() > MAX_TEMPLATE_BYTES {
                return Err(format!(
                    "templates.{name} is over {MAX_TEMPLATE_BYTES} bytes"
                ));
            }
            if template.matches(TEMPLATE_STRINGS).count() != 1 {
                return Err(format!(
                    "templates.{name} has to hold {TEMPLATE_STRINGS} once"
                ));
            }
        }
        // each type's template, as it will be used, with one string in it
        let names = configured
            .iter()
            .copied()
            .chain(self.templates.keys().map(String::as_str))
            .filter(|name| *name != DEFAULT_TEMPLATE)
            .collect::<BTreeSet<_>>();
        for name in names {
            let Some(template) = self.template(name, "01/01/2000") else {
                return Err(format!(
                    "templates has none for {name} and no {DEFAULT_TEMPLATE}"
                ));
            };
            let compiled = shape(&template.replace(TEMPLATE_STRINGS, PROBE_LINE))
                .map_err(|e| format!("the template for {name} doesn't compile: {e}"))?;
            if !compiled.iter().any(|rule| rule.3.contains(PROBE)) {
                return Err(format!(
                    "the template for {name} doesn't put {TEMPLATE_STRINGS} in a rule's strings"
                ));
            }
        }
        Ok(())
    }

    /// What besides the export list changes the rules: ace3's `fingerprint_salt`, and the rest of
    /// these settings.
    fn salt(&self) -> String {
        let mut hasher = Sha256::new();
        let mut part = |text: &str| {
            hasher.update((text.len() as u64).to_be_bytes());
            hasher.update(text.as_bytes());
        };
        part(FORMAT_VERSION);
        part(crate::YARA_X_VERSION);
        for map in [&self.modifiers, &self.boundaries, &self.templates] {
            part(&map.len().to_string());
            for (key, value) in map {
                part(key);
                part(value);
            }
        }
        hex(&hasher.finalize())
    }
}

/// An observable enabled for detection: a row of ace3's `observable_detections` that hasn't
/// expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub id: i64,
    pub observable_type: String,
    pub value: String,
}

/// One detection as it will appear in an export: ace3's `ExportEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    pub id: i64,
    /// The configured type it's exported under: its own, or the nearest one it extends.
    pub export_type: String,
    /// Its own type, which the index gives the YARA module.
    pub observable_type: String,
    pub value: String,
}

/// The list one export holds, in a stable order: ace3's `ObservableExportList`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportList {
    entries: Vec<ExportEntry>,
}

impl ExportList {
    pub fn new(mut entries: Vec<ExportEntry>) -> ExportList {
        // sorted so the same detections give the same fingerprint whatever order they came in
        entries.sort_by(|a, b| (&a.export_type, a.id).cmp(&(&b.export_type, b.id)));
        ExportList { entries }
    }

    pub fn entries(&self) -> &[ExportEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The types in the list, sorted.
    pub fn types(&self) -> Vec<&str> {
        let types: BTreeSet<&str> = self
            .entries
            .iter()
            .map(|e| e.export_type.as_str())
            .collect();
        types.into_iter().collect()
    }

    /// The entries by type, each in id order.
    pub fn entries_by_type(&self) -> BTreeMap<&str, Vec<&ExportEntry>> {
        let mut grouped: BTreeMap<&str, Vec<&ExportEntry>> = BTreeMap::new();
        for entry in &self.entries {
            grouped.entry(&entry.export_type).or_default().push(entry);
        }
        grouped
    }

    /// A stable hash of the list: the sha256 of `[[type,id,value],...]` as Python's `json.dumps`
    /// writes it with `ensure_ascii` and no spaces, so it's ace3's fingerprint of the same list.
    pub fn fingerprint(&self) -> String {
        let mut canonical = String::from("[");
        for (index, entry) in self.entries.iter().enumerate() {
            if index > 0 {
                canonical.push(',');
            }
            canonical.push('[');
            python_json_string(&mut canonical, &entry.export_type);
            canonical.push_str(&format!(",{},", entry.id));
            python_json_string(&mut canonical, &entry.value);
            canonical.push(']');
        }
        canonical.push(']');
        hex(&Sha256::digest(canonical.as_bytes()))
    }
}

/// A string as Python's `json.dumps(ensure_ascii=True)` writes it.
fn python_json_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (' '..='~').contains(&c) || c == '\u{7f}' => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The detections a configured type covers that are long enough to be worth a string: ace3's
/// `build_export_list` over its `select_detections`. `ancestors` gives the types a type extends,
/// nearest first.
pub fn export_list(
    config: &ExportConfig,
    detections: &[Detection],
    ancestors: impl Fn(&str) -> Vec<String>,
) -> ExportList {
    let configured = config.configured();
    let mut export_types: BTreeMap<&str, Option<String>> = BTreeMap::new();
    let mut entries = Vec::new();
    for detection in detections {
        let export_type = export_types
            .entry(&detection.observable_type)
            .or_insert_with(|| {
                // its own type first, then the types it extends, nearest first: the first one
                // configured is the most specific
                std::iter::once(detection.observable_type.clone())
                    .chain(ancestors(&detection.observable_type))
                    .find(|candidate| configured.contains(candidate.as_str()))
            });
        let Some(export_type) = export_type else {
            continue;
        };
        if detection.value.chars().count() < config.minimum_length {
            continue;
        }
        entries.push(ExportEntry {
            id: detection.id,
            export_type: export_type.clone(),
            observable_type: detection.observable_type.clone(),
            value: detection.value.clone(),
        });
    }
    ExportList::new(entries)
}

/// The fingerprint that says whether the rules have to be generated again: the list's, with
/// everything else that changes them. ace3's `ObservableExport.fingerprint`.
pub fn fingerprint(config: &ExportConfig, list: &ExportList) -> String {
    hex(&Sha256::digest(
        format!("{}:{}", list.fingerprint(), config.salt()).as_bytes(),
    ))
}

/// One detection's strings as the rule holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Strings {
    /// The lines, each ending in a newline.
    pub lines: String,
    /// The identifiers they define, in order.
    pub identifiers: Vec<String>,
    /// The most escape sequences one of them holds.
    pub escapes: usize,
}

/// How many escape sequences a generated literal holds: each backslash starts one.
fn escapes(literal: &str) -> usize {
    let mut count = 0;
    let mut bytes = literal.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'\\' {
            count += 1;
            bytes.next();
        }
    }
    count
}

/// The YARA strings of one detection: the raw value, and its JSON form if that differs. ace3's
/// `_format_strings`.
pub fn format_strings(config: &ExportConfig, entry: &ExportEntry) -> Strings {
    format_strings_with(config, entry, config.string_modifiers(&entry.export_type))
}

/// `format_strings` with the modifiers given.
pub fn format_strings_with(config: &ExportConfig, entry: &ExportEntry, modifiers: &str) -> Strings {
    let mut family = config.string_boundary(&entry.export_type, &entry.value);
    let raw = entry.value.replace(['\n', '\r'], "");
    let json_form = raw.replace('\\', "\\\\").replace('"', "\\\"");
    if family.is_some() && json_form.chars().count() > MAX_BOUNDED_VALUE_LENGTH {
        family = None;
    }
    let id = entry.id;
    let mut strings = Strings {
        lines: String::new(),
        identifiers: Vec::new(),
        escapes: 0,
    };
    let line = |strings: &mut Strings, identifier: String, literal: &str, modifiers: &str| {
        strings
            .lines
            .push_str(&format!("          {identifier} = {literal} {modifiers}\n"));
        strings.identifiers.push(identifier);
        strings.escapes = strings.escapes.max(escapes(literal));
    };

    if let Some(family) = family {
        // the regex takes the boundary character, so fullword would test the character beyond it.
        // ascii and wide are one string each, since the wide form needs a regex of its own
        let modifier_list: Vec<&str> = modifiers.split_whitespace().collect();
        let wide = modifier_list.contains(&"wide");
        let want_ascii = modifier_list.contains(&"ascii") || !wide;
        let other_modifiers = modifier_list
            .iter()
            .filter(|m| !matches!(**m, "fullword" | "ascii" | "wide"))
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        let mut forms = vec![("", raw.as_str())];
        if json_form != raw {
            forms.push(("json_", json_form.as_str()));
        }
        // the scanner reads the id at the end of the name, so $obsd_wide_<id> names the same
        // detection
        let mut bounded = strings.clone();
        for (prefix, value) in forms {
            if want_ascii {
                line(
                    &mut bounded,
                    format!("$obsd_{prefix}{id}"),
                    &format_bounded_yara_regex(value, family, false),
                    &format!("ascii {other_modifiers}"),
                );
            }
            if wide {
                line(
                    &mut bounded,
                    format!("$obsd_{prefix}wide_{id}"),
                    &format_bounded_yara_regex(value, family, true),
                    &other_modifiers,
                );
            }
        }
        if bounded.escapes <= MAX_ESCAPES {
            return bounded;
        }
    }

    let yara_value = format_yara_string(&entry.value);
    line(
        &mut strings,
        format!("$obsd_{id}"),
        &format!("\"{yara_value}\""),
        modifiers,
    );
    let yara_json_value = format_yara_json_string(&entry.value);
    if yara_value != yara_json_value {
        line(
            &mut strings,
            format!("$obsd_json_{id}"),
            &format!("\"{yara_json_value}\""),
            modifiers,
        );
    }
    strings
}

/// The id a generated string's name ends in: ace3's `_parse_yara_string_key_id`, for `$obsd_12`,
/// `$obsd_json_12`, `$obsd_wide_12` and `$obsd_json_wide_12`. None for another string, or one that
/// doesn't end in a number. ace3 also drops an id of 0, which no row has.
pub fn string_id(identifier: &str) -> Option<i64> {
    if !identifier.starts_with("$obsd_") {
        return None;
    }
    let (_, id) = identifier.rsplit_once('_')?;
    // Python's int() takes a sign and spaces; a generated name has neither
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    id.parse().ok().filter(|id| *id != 0)
}

/// What a compiled source holds: each rule's name, tags and meta, and its strings' names.
type Shape = Vec<(String, Vec<String>, Meta, BTreeSet<String>)>;

/// Compiles a source alone, as a file of the namespace, and says what it holds.
fn shape(source: &str) -> Result<Shape, String> {
    crate::guard::check(source.as_bytes()).map_err(|refusal| refusal.to_string())?;
    let mut compiler = new_compiler();
    compiler.new_namespace(NAMESPACE);
    compiler
        .add_source(source.as_bytes())
        .map_err(|e| e.to_string())?;
    let rules = compiler.build();
    Ok(rules
        .iter()
        .map(|rule| {
            (
                rule.identifier().to_owned(),
                rule.tags().map(|t| t.identifier().to_owned()).collect(),
                Meta::from_yara_x(rule.metadata()),
                rule.patterns().map(|p| p.identifier().to_owned()).collect(),
            )
        })
        .collect())
}

/// The probe string a template is compiled with to learn its shape.
const PROBE: &str = "$obsd_0";
const PROBE_LINE: &str = "          $obsd_0 = \"probe\"\n";

/// Compiles a rule with these strings in it, and checks that it holds what the template does:
/// the same rules, tags and meta, with exactly these strings where the template's probe was.
fn check_rule(
    template: &str,
    expected: &Shape,
    strings: &str,
    ids: &[String],
) -> Result<(), String> {
    let compiled = shape(&template.replace(TEMPLATE_STRINGS, strings))?;
    let same = compiled.len() == expected.len()
        && compiled.iter().zip(expected).all(|(got, want)| {
            let mut patterns = want.3.clone();
            if patterns.remove(PROBE) {
                patterns.extend(ids.iter().cloned());
            }
            got.0 == want.0 && got.1 == want.1 && got.2 == want.2 && got.3 == patterns
        });
    if same {
        Ok(())
    } else {
        Err("the value changes the rule's structure".to_owned())
    }
}

/// A rule file of the export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportFile {
    /// The file's name in the namespace: `<type>.yar`, or `INDEX_FILE`.
    pub name: String,
    pub source: String,
}

/// What one type's rule holds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExportedType {
    #[serde(rename = "type")]
    pub export_type: String,
    /// How many detections its rule holds.
    pub detections: usize,
    /// How many strings they are.
    pub strings: usize,
}

/// A detection left out, with why. The error is the compiler's, which quotes the value: text to
/// show, never markup.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Skipped {
    pub id: i64,
    #[serde(rename = "type")]
    pub export_type: String,
    pub error: String,
}

/// What an export came to, as a ruleset's row keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ExportReport {
    /// Each type with a rule, in name order.
    pub types: Vec<ExportedType>,
    /// The detections left out, by type and id.
    pub skipped: Vec<Skipped>,
    /// Why nothing was exported, when the files don't load together.
    pub error: Option<String>,
}

impl ExportReport {
    /// How many detections the rules hold.
    pub fn exported(&self) -> usize {
        self.types.iter().map(|t| t.detections).sum()
    }
}

/// A generated export: the namespace's files and what became of each detection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Export {
    /// The type's files in type order, then the index. Empty when no detection is exported.
    pub files: Vec<ExportFile>,
    pub report: ExportReport,
}

/// The longest error kept for a detection, in characters.
const MAX_ERROR_CHARS: usize = 500;

fn skipped(entry: &ExportEntry, error: impl Into<String>) -> Skipped {
    let error: String = error.into();
    let error = if error.chars().count() > MAX_ERROR_CHARS {
        let mut cut: String = error.chars().take(MAX_ERROR_CHARS).collect();
        cut.push_str("...");
        cut
    } else {
        error
    };
    Skipped {
        id: entry.id,
        export_type: entry.export_type.clone(),
        error,
    }
}

/// Generates the rule files of a list: ace3's `publish`. `date` is today's, as the templates
/// write it (`%m/%d/%Y`).
pub fn generate(config: &ExportConfig, list: &ExportList, date: &str) -> Export {
    let mut export = Export::default();
    let mut budget = MAX_SOURCE_BYTES;
    let mut taken = 0usize;
    // each exported detection's own type and value, for the index
    let mut index: Vec<(i64, &str, &str)> = Vec::new();

    for (export_type, entries) in list.entries_by_type() {
        let Some(template) = config.template(export_type, date) else {
            for entry in entries {
                export.report.skipped.push(skipped(entry, "no template"));
            }
            continue;
        };
        let expected = match shape(&template.replace(TEMPLATE_STRINGS, PROBE_LINE)) {
            Ok(expected) => expected,
            Err(error) => {
                for entry in entries {
                    export.report.skipped.push(skipped(
                        entry,
                        format!("the type's template doesn't compile: {error}"),
                    ));
                }
                continue;
            }
        };

        // what fits the bounds, each with its strings
        let mut kept: Vec<(&ExportEntry, String, Vec<String>)> = Vec::new();
        for entry in entries {
            if entry.id <= 0 {
                export.report.skipped.push(skipped(entry, "not an id"));
                continue;
            }
            if entry.value.len() > MAX_VALUE_BYTES {
                export.report.skipped.push(skipped(
                    entry,
                    format!("the value is over {MAX_VALUE_BYTES} bytes"),
                ));
                continue;
            }
            if entry.value.contains('\0') {
                export
                    .report
                    .skipped
                    .push(skipped(entry, "the value holds a NUL character"));
                continue;
            }
            if taken >= MAX_ENTRIES {
                export.report.skipped.push(skipped(
                    entry,
                    format!("an export holds at most {MAX_ENTRIES} detections"),
                ));
                continue;
            }
            let Strings {
                lines: strings,
                identifiers: ids,
                escapes,
            } = format_strings(config, entry);
            if escapes > MAX_ESCAPES {
                export.report.skipped.push(skipped(
                    entry,
                    format!(
                        "the value holds more than {MAX_ESCAPES} characters a rule has to escape"
                    ),
                ));
                continue;
            }
            // the index holds the type and the value in hex beside the strings
            let cost = strings.len() + 2 * (entry.value.len() + entry.observable_type.len()) + 64;
            if cost > budget {
                export.report.skipped.push(skipped(
                    entry,
                    format!("the export's rules are at most {MAX_SOURCE_BYTES} bytes"),
                ));
                continue;
            }
            budget -= cost;
            taken += 1;
            kept.push((entry, strings, ids));
        }

        let join = |kept: &[(&ExportEntry, String, Vec<String>)]| {
            let strings: String = kept.iter().map(|(_, s, _)| s.as_str()).collect();
            let ids: Vec<String> = kept.iter().flat_map(|(_, _, ids)| ids.clone()).collect();
            (strings, ids)
        };
        let (mut strings, mut ids) = join(&kept);
        if !kept.is_empty() && check_rule(&template, &expected, &strings, &ids).is_err() {
            // one string at a time, so one bad value doesn't take out the whole type
            kept.retain(|(entry, strings, ids)| {
                match check_rule(&template, &expected, strings, ids) {
                    Ok(()) => true,
                    Err(error) => {
                        tracing::error!(
                            observable_type = %entry.export_type,
                            id = entry.id,
                            "a detection's value is invalid for yara, leaving it out: {error}"
                        );
                        export.report.skipped.push(skipped(entry, error));
                        false
                    }
                }
            });
            (strings, ids) = join(&kept);
            if !kept.is_empty()
                && let Err(error) = check_rule(&template, &expected, &strings, &ids)
            {
                tracing::error!(observable_type = %export_type, "unable to compile the type's rule: {error}");
                for (entry, _, _) in kept.drain(..) {
                    export.report.skipped.push(skipped(
                        entry,
                        format!("the type's rule doesn't compile: {error}"),
                    ));
                }
            }
        }
        if kept.is_empty() {
            continue;
        }
        export.files.push(ExportFile {
            name: format!("{export_type}.yar"),
            source: template.replace(TEMPLATE_STRINGS, &strings),
        });
        export.report.types.push(ExportedType {
            export_type: export_type.to_owned(),
            detections: kept.len(),
            strings: ids.len(),
        });
        index.extend(kept.iter().map(|(entry, _, _)| {
            (
                entry.id,
                entry.observable_type.as_str(),
                entry.value.as_str(),
            )
        }));
    }
    export
        .report
        .skipped
        .sort_by(|a, b| (&a.export_type, a.id).cmp(&(&b.export_type, b.id)));
    if export.files.is_empty() {
        return export;
    }

    index.sort();
    export.files.push(ExportFile {
        name: INDEX_FILE.to_owned(),
        source: index_source(&index),
    });
    // the files as the namespace they'll be: a rule name two templates share stops here, not in
    // the ruleset's build, where nothing would load
    if let Err(error) = compile_namespace(&export.files) {
        tracing::error!("the exported rules don't load together, exporting none: {error}");
        for (id, _, _) in &index {
            if let Some(entry) = list.entries().iter().find(|e| e.id == *id) {
                export
                    .report
                    .skipped
                    .push(skipped(entry, "the exported rules don't load together"));
            }
        }
        export
            .report
            .skipped
            .sort_by(|a, b| (&a.export_type, a.id).cmp(&(&b.export_type, b.id)));
        export.report.types.clear();
        export.report.error = Some(error);
        export.files.clear();
    }
    export
}

fn compile_namespace(files: &[ExportFile]) -> Result<(), String> {
    let mut compiler = new_compiler();
    compiler.new_namespace(NAMESPACE);
    for file in files {
        crate::guard::check(file.source.as_bytes())
            .map_err(|refusal| format!("{}: {refusal}", file.name))?;
        compiler
            .add_source(file.source.as_bytes())
            .map_err(|e| format!("{}: {e}", file.name))?;
    }
    drop(compiler.build());
    Ok(())
}

/// The index rule: one meta per exported detection, `e<id>`, holding its type and value in hex, so
/// no value can be anything but a string of hex digits here.
fn index_source(index: &[(i64, &str, &str)]) -> String {
    let mut source = String::from(
        "// What each $obsd_ string of this namespace's rules names: e<id> is the detection's type and\n\
         // value, each in hex. The YARA module reads it. The rule matches nothing.\n",
    );
    source.push_str(&format!("rule {INDEX_RULE}\n{{\n    meta:\n"));
    for (id, observable_type, value) in index {
        source.push_str(&format!(
            "        e{id} = \"{}:{}\"\n",
            hex(observable_type.as_bytes()),
            hex(value.as_bytes())
        ));
    }
    source.push_str("    condition:\n        false\n}\n");
    source
}

/// What the index rule's meta says: each detection's type and value by its id. A meta that isn't
/// the index's shape is skipped.
pub(crate) fn read_index(meta: &Meta) -> BTreeMap<i64, (String, String)> {
    let unhex = |text: &str| -> Option<String> {
        if !text.len().is_multiple_of(2) || !text.is_ascii() {
            return None;
        }
        let bytes = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        String::from_utf8(bytes).ok()
    };
    let mut index = BTreeMap::new();
    for (key, value) in meta.iter() {
        let crate::meta::MetaValue::Str(value) = value else {
            continue;
        };
        let Some(id) = key.strip_prefix('e').and_then(|id| id.parse::<i64>().ok()) else {
            continue;
        };
        let Some((observable_type, value)) = value.split_once(':') else {
            continue;
        };
        if let (Some(observable_type), Some(value)) = (unhex(observable_type), unhex(value)) {
            index.insert(id, (observable_type, value));
        }
    }
    index
}

#[cfg(test)]
mod tests;
