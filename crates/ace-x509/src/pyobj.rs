//! The Python objects cryptography builds for a certificate's names and extensions, as far as
//! ace3 looks at them: their `str()` and `repr()`, what `dir()` lists, and whether they iterate.
//! `saq.x509.get_readable_extensions` turns them into a tree of strings ([`readable`]).

use ace_pycompat::repr::{repr, repr_bytes};
use asn1::ObjectIdentifier;
use serde_json::Value;

use crate::oid_names::oid_name;

/// What Python prints for an object's address (`<... object at 0x...>`). Python prints the
/// object's real address, which changes from run to run, so no fixed value can match it.
pub const ADDRESS: &str = "0x7f0000000000";

/// A naive `datetime.datetime`, or an aware one in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub microsecond: u32,
}

impl DateTime {
    /// `str()` of the naive datetime: `2024-01-31 12:00:00`, with `.ffffff` when there are
    /// microseconds.
    pub fn naive_str(&self) -> String {
        let mut s = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        );
        if self.microsecond != 0 {
            s.push_str(&format!(".{:06}", self.microsecond));
        }
        s
    }

    /// `str()` of the datetime in UTC: `2024-01-31 12:00:00+00:00`.
    pub fn utc_str(&self) -> String {
        format!("{}+00:00", self.naive_str())
    }

    /// The UTC datetime formatted as ace3's JSON encoder does it,
    /// `strftime('%Y-%m-%dT%H:%M:%S.%f%z')`: `2024-01-31T12:00:00.000000+0000`.
    pub fn utc_strftime(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+0000",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.microsecond
        )
    }
}

/// One attribute of a name, with its value as cryptography decodes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAttribute {
    pub oid: ObjectIdentifier,
    pub value: AttrValue,
}

/// A `NameAttribute`'s value: a `str`, or `bytes` for a BIT STRING.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Str(String),
    Bytes(Vec<u8>),
}

/// The short names `rfc4514_string` uses (`_NAMEOID_TO_NAME`).
fn rfc4514_attribute_name(oid: &ObjectIdentifier) -> String {
    let short = match oid.to_string().as_str() {
        "2.5.4.3" => "CN",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.6" => "C",
        "2.5.4.9" => "STREET",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        other => return other.to_owned(),
    };
    short.to_owned()
}

/// `_escape_dn_value`.
fn escape_dn_value(value: &AttrValue) -> String {
    match value {
        AttrValue::Bytes(b) if b.is_empty() => String::new(),
        AttrValue::Bytes(b) => {
            let mut s = String::from("#");
            for byte in b {
                s.push_str(&format!("{byte:02x}"));
            }
            s
        }
        AttrValue::Str(v) if v.is_empty() => String::new(),
        AttrValue::Str(v) => {
            let mut s = v
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('+', "\\+")
                .replace(',', "\\,")
                .replace(';', "\\;")
                .replace('<', "\\<")
                .replace('>', "\\>")
                .replace('\0', "\\00");
            let first = s.chars().next();
            if first == Some('#') || (first == Some(' ') && s.chars().count() > 1) {
                s.insert(0, '\\');
            }
            if s.ends_with(' ') {
                s.pop();
                s.push_str("\\ ");
            }
            s
        }
    }
}

impl NameAttribute {
    fn rfc4514_string(&self) -> String {
        format!(
            "{}={}",
            rfc4514_attribute_name(&self.oid),
            escape_dn_value(&self.value)
        )
    }
}

/// A `RelativeDistinguishedName`: its attributes in the order the certificate has them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdn(pub Vec<NameAttribute>);

impl Rdn {
    pub fn rfc4514_string(&self) -> String {
        self.0
            .iter()
            .map(NameAttribute::rfc4514_string)
            .collect::<Vec<_>>()
            .join("+")
    }
}

/// A `Name`: its RDNs in the certificate's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name(pub Vec<Rdn>);

impl Name {
    /// `Name.rfc4514_string()`: the RDNs in reverse, joined by commas.
    pub fn rfc4514_string(&self) -> String {
        self.0
            .iter()
            .rev()
            .map(Rdn::rfc4514_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Every attribute, RDN by RDN, as iterating a `Name` gives them.
    pub fn attributes(&self) -> impl Iterator<Item = &NameAttribute> {
        self.0.iter().flat_map(|r| r.0.iter())
    }
}

/// An instance of one of cryptography's Python classes.
pub struct Obj {
    pub class: &'static str,
    /// The module `<class '...'>` names, for classmethods.
    pub module: &'static str,
    pub repr: String,
    /// The public properties, with their values.
    pub props: Vec<(&'static str, Py)>,
    /// Methods defined on the class, which `str()` shows as bound to the instance.
    pub methods: &'static [&'static str],
    /// Classmethods, which `str()` shows as bound to the class.
    pub classmethods: &'static [&'static str],
    /// The `oid` class attribute of an `ExtensionType`.
    pub class_oid: Option<ObjectIdentifier>,
    /// The items, for a class with `__iter__`.
    pub items: Option<Vec<Py>>,
}

/// A Python value.
pub enum Py {
    None,
    Bool(bool),
    /// An `int`, as its decimal text.
    Int(String),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<Py>),
    /// A `frozenset`, in the order its items were added. Python's order depends on the string
    /// hashes, which are randomized per process.
    FrozenSet(Vec<Py>),
    Oid(ObjectIdentifier),
    /// A naive datetime.
    DateTime(DateTime),
    /// An `ipaddress` address or network, as its `str()`.
    Ip(String),
    /// A member of one of cryptography's `utils.Enum` classes.
    Enum {
        class: &'static str,
        member: &'static str,
        value: Box<Py>,
    },
    /// An instance of a `hashes` algorithm class, such as `SHA256()`.
    Hash(&'static str),
    Name(Name),
    Rdn(Rdn),
    Obj(Box<Obj>),
    /// A property whose getter raises (an SCT timestamp past year 9999).
    Raises,
}

pub fn oid_repr(oid: &ObjectIdentifier) -> String {
    format!("<ObjectIdentifier(oid={}, name={})>", oid, oid_name(oid))
}

impl Py {
    pub fn repr(&self) -> String {
        match self {
            Py::None => "None".to_owned(),
            Py::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
            Py::Int(s) => s.clone(),
            Py::Str(s) => repr(s),
            Py::Bytes(b) => repr_bytes(b),
            Py::List(items) => {
                format!(
                    "[{}]",
                    items.iter().map(Py::repr).collect::<Vec<_>>().join(", ")
                )
            }
            Py::FrozenSet(items) if items.is_empty() => "frozenset()".to_owned(),
            Py::FrozenSet(items) => format!(
                "frozenset({{{}}})",
                items.iter().map(Py::repr).collect::<Vec<_>>().join(", ")
            ),
            Py::Oid(o) => oid_repr(o),
            Py::DateTime(d) => {
                // Not reached by anything ace3 prints, but kept right for completeness.
                let mut s = format!(
                    "datetime.datetime({}, {}, {}, {}, {}",
                    d.year, d.month, d.day, d.hour, d.minute
                );
                if d.second != 0 || d.microsecond != 0 {
                    s.push_str(&format!(", {}", d.second));
                }
                if d.microsecond != 0 {
                    s.push_str(&format!(", {}", d.microsecond));
                }
                s.push(')');
                s
            }
            Py::Ip(s) => s.clone(),
            Py::Enum {
                class,
                member,
                value,
            } => format!("<{class}.{member}: {}>", value.repr()),
            Py::Hash(name) => {
                format!("<cryptography.hazmat.primitives.hashes.{name} object at {ADDRESS}>")
            }
            Py::Name(n) => format!("<Name({})>", n.rfc4514_string()),
            Py::Rdn(r) => format!("<RelativeDistinguishedName({})>", r.rfc4514_string()),
            Py::Obj(o) => o.repr.clone(),
            Py::Raises => String::new(),
        }
    }

    pub fn str(&self) -> String {
        match self {
            Py::Str(s) => s.clone(),
            Py::DateTime(d) => d.naive_str(),
            Py::Enum { class, member, .. } => format!("{class}.{member}"),
            _ => self.repr(),
        }
    }

    /// The items `for x in obj` gives, or `None` where iterating raises TypeError. Only the
    /// extension values and their items reach this, so `str`, `bytes` and `Name` (which also
    /// iterate in Python, but never appear there) are not covered.
    fn items(&self) -> Option<&[Py]> {
        match self {
            Py::List(items) | Py::FrozenSet(items) => Some(items),
            Py::Obj(o) => o.items.as_deref(),
            _ => None,
        }
    }

    /// `x509_object_name`.
    fn object_name(&self) -> String {
        if let Py::Oid(o) = self {
            return oid_name(o).to_owned();
        }
        let s = self.str();
        // X509_CLASS_REGEX = r'^<([^\(]+)'
        if let Some(rest) = s.strip_prefix('<') {
            let end = rest.find('(').unwrap_or(rest.len());
            if end > 0 {
                return rest[..end].to_owned();
            }
        }
        format!("ERROR_GETTING_FIELD_NAME-{s}")
    }

    /// `dir()` without the names that start with `_`, sorted, with `str()` of each value.
    fn attributes(&self) -> Vec<(&'static str, String)> {
        let mut attrs: Vec<(&'static str, String)> = match self {
            Py::Oid(o) => vec![("dotted_string", o.to_string())],
            Py::Enum { member, value, .. } => {
                vec![("name", (*member).to_owned()), ("value", value.str())]
            }
            Py::Obj(o) => {
                let mut v: Vec<(&'static str, String)> =
                    o.props.iter().map(|(k, p)| (*k, p.str())).collect();
                for m in o.methods {
                    v.push((m, format!("<bound method {}.{} of {}>", o.class, m, o.repr)));
                }
                for m in o.classmethods {
                    v.push((
                        m,
                        format!(
                            "<bound method {}.{} of <class '{}.{}'>>",
                            o.class, m, o.module, o.class
                        ),
                    ));
                }
                if let Some(oid) = &o.class_oid {
                    v.push(("oid", oid_repr(oid)));
                }
                v
            }
            _ => Vec::new(),
        };
        attrs.sort_by(|a, b| a.0.cmp(b.0));
        attrs
    }

    fn key_agreement(&self) -> bool {
        if let Py::Obj(o) = self {
            return o
                .props
                .iter()
                .any(|(k, v)| *k == "key_agreement" && matches!(v, Py::Bool(true)));
        }
        false
    }
}

/// `parse_x509_details`, or `None` where it raises.
fn details(obj: &Py, critical: bool) -> Option<Value> {
    let mut name = obj.object_name();
    if critical {
        name.push_str(": CRITICAL");
    }
    let mut map = serde_json::Map::new();
    if let Some(items) = obj.items() {
        let items = items
            .iter()
            .map(|i| details(i, false))
            .collect::<Option<Vec<_>>>()?;
        map.insert(name, Value::Array(items));
        return Some(Value::Object(map));
    }
    if let Py::Obj(o) = obj
        && o.props.iter().any(|(_, v)| matches!(v, Py::Raises))
    {
        return None;
    }
    let mut attrs = obj.attributes();
    if attrs
        .iter()
        .any(|(k, _)| *k == "decipher_only" || *k == "encipher_only")
        && !obj.key_agreement()
    {
        attrs.retain(|(k, _)| *k != "decipher_only" && *k != "encipher_only");
    }
    if attrs.len() == 1 {
        let (k, v) = attrs.remove(0);
        if k == "value" {
            return Some(Value::String(format!("{name}: {v}")));
        }
        let mut inner = serde_json::Map::new();
        inner.insert(k.to_owned(), Value::String(v));
        map.insert(name, Value::Object(inner));
        return Some(Value::Object(map));
    }
    map.insert(
        name,
        Value::Array(
            attrs
                .into_iter()
                .map(|(k, v)| Value::String(format!("{k}: {v}")))
                .collect(),
        ),
    );
    Some(Value::Object(map))
}

/// `build_extension_output`: one tree per extension, from its value and criticality, or `None`
/// where building it raises.
pub fn readable(extensions: &[(bool, &Py)]) -> Option<Value> {
    extensions
        .iter()
        .map(|(critical, v)| details(v, *critical))
        .collect::<Option<Vec<_>>>()
        .map(Value::Array)
}

/// `json.dumps(value)` with the default separators and `ensure_ascii=True`.
pub fn json_dumps(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => json_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                json_dumps(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                json_str(k, out);
                out.push_str(": ");
                json_dumps(x, out);
            }
            out.push('}');
        }
    }
}

/// A JSON string as `json.dumps` writes it with `ensure_ascii=True`.
pub fn json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
