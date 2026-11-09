//! Loading a certificate and reading it, as cryptography 50.0.2's Rust and Python layers do.

use ace_pycompat::PyErr;
use ace_pycompat::ipaddress::{Ipv4Address, Ipv6Address};
use ace_pycompat::repr::{repr, repr_bytes};
use asn1::ObjectIdentifier;
use sha2::{Digest, Sha256};

use crate::pyobj::{AttrValue, DateTime, Name, NameAttribute, Obj, Py, Rdn, oid_repr};
use crate::raw::certificate::Certificate as RawCertificate;
use crate::raw::common::{Asn1Read, AttributeTypeValue, AttributeValue};
use crate::raw::extensions::{
    Admission, Admissions, AuthorityKeyIdentifier, BasicConstraints, DisplayText,
    DistributionPoint, DistributionPointName, ExtendedKeyUsage, Extension, Extensions,
    IssuerAlternativeName, KeyUsage, MSCertificateTemplate, NameConstraints, NamingAuthority,
    PolicyConstraints, PolicyInformation, PrivateKeyUsagePeriod, ProfessionInfo, Qualifier,
    SequenceOfAccessDescriptions, SequenceOfSubtrees, SubjectAlternativeName, UserNotice,
};
use crate::raw::name::{GeneralName, NameReadable};
use crate::raw::oid;

/// cryptography's `CryptographyError`, as far as it matters here: an ASN.1 parse error, which
/// gains a location as it passes up and becomes a `ValueError`, or a Python exception.
pub(crate) enum CErr {
    Asn1(Box<asn1::ParseError>),
    Py(PyErr),
}

impl CErr {
    fn add_location(self, field: &'static str) -> CErr {
        match self {
            CErr::Asn1(e) => {
                CErr::Asn1(Box::new(e.add_location(asn1::ParseLocation::Field(field))))
            }
            e => e,
        }
    }

    pub(crate) fn into_py(self) -> PyErr {
        match self {
            CErr::Asn1(e) => PyErr::value_error(format!("error parsing asn1 value: {e:?}")),
            CErr::Py(e) => e,
        }
    }
}

impl From<asn1::ParseError> for CErr {
    fn from(e: asn1::ParseError) -> CErr {
        CErr::Asn1(Box::new(e))
    }
}

impl From<PyErr> for CErr {
    fn from(e: PyErr) -> CErr {
        CErr::Py(e)
    }
}

fn value_error(msg: impl Into<String>) -> CErr {
    CErr::Py(PyErr::value_error(msg))
}

fn type_error(msg: impl Into<String>) -> CErr {
    CErr::Py(PyErr::builtin("TypeError", msg))
}

/// A certificate cryptography loaded: its DER, which parsed as a `Certificate`.
#[derive(Debug, Clone)]
pub struct Certificate {
    der: Vec<u8>,
}

fn pem_error(e: &pem::PemError) -> PyErr {
    PyErr::value_error(format!(
        "Unable to load PEM file. See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file for more details. {e:?}"
    ))
}

/// `x509.load_pem_x509_certificate(data)`.
pub fn load_pem_x509_certificate(data: &[u8]) -> Result<Certificate, PyErr> {
    let sections = pem::parse_many(data).map_err(|e| pem_error(&e))?;
    if sections.is_empty() {
        return Err(pem_error(&pem::PemError::MalformedFraming));
    }
    let section = sections
        .iter()
        .find(|p| p.tag() == "CERTIFICATE" || p.tag() == "X509 CERTIFICATE")
        .ok_or_else(|| {
            PyErr::value_error(
                "Valid PEM but no BEGIN CERTIFICATE/END CERTIFICATE delimiters. Are you sure this is a certificate?",
            )
        })?;
    load_der_x509_certificate(section.contents())
}

/// How deep DER may nest before [`load_der_x509_certificate`] refuses it. A certificate's own
/// structure is under 20 levels; only an RSA-PSS or PBES2 AlgorithmIdentifier nested in itself,
/// or opaque algorithm parameters, go deeper. cryptography has no limit there: it loads 500
/// nested RSA-PSS levels and crashes its process at 5000. The derived parsers use a lot of
/// stack per level (about 30 RSA-PSS levels fit in a 2 MB thread in a debug build), so this
/// refuses past the depth pyasn1 allows, which is about 32 RSA-PSS levels.
pub const MAX_DER_DEPTH: usize = 100;

/// Whether the definite-length TLVs at the start of `data` nest deeper than `limit`. It stops
/// at the first malformed header, which the parser then refuses anyway.
fn nests_deeper_than(data: &[u8], limit: usize) -> bool {
    let mut ends: Vec<usize> = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        while ends.last().is_some_and(|&e| pos >= e) {
            ends.pop();
        }
        let first = data[pos];
        let mut p = pos + 1;
        if first & 0x1F == 0x1F {
            while p < data.len() && data[p] & 0x80 != 0 {
                p += 1;
            }
            p += 1;
        }
        let Some(&l) = data.get(p) else { return false };
        p += 1;
        let len = if l < 0x80 {
            usize::from(l)
        } else {
            let n = usize::from(l & 0x7F);
            if n == 0 || n > 4 || p + n > data.len() {
                return false;
            }
            let v = data[p..p + n]
                .iter()
                .fold(0usize, |a, &b| (a << 8) | usize::from(b));
            p += n;
            v
        };
        let Some(end) = p.checked_add(len).filter(|&e| e <= data.len()) else {
            return false;
        };
        if first & 0x20 != 0 {
            ends.push(end);
            if ends.len() > limit {
                return true;
            }
            pos = p;
        } else {
            pos = end;
        }
    }
    false
}

/// `x509.load_der_x509_certificate(data)`.
pub fn load_der_x509_certificate(data: &[u8]) -> Result<Certificate, PyErr> {
    if nests_deeper_than(data, MAX_DER_DEPTH) {
        return Err(PyErr::value_error(format!(
            "error parsing asn1 value: nested deeper than {MAX_DER_DEPTH} levels"
        )));
    }
    let raw =
        asn1::parse_single::<RawCertificate<'_>>(data).map_err(|e| CErr::from(e).into_py())?;
    let version = raw.tbs_cert.version;
    if version != 0 && version != 2 {
        return Err(PyErr::new(
            "cryptography.x509.base",
            "InvalidVersion",
            format!("{version} is not a valid X509 version"),
        ));
    }
    // A serial that is not positive only warns (CryptographyDeprecationWarning).
    Ok(Certificate { der: data.to_vec() })
}

/// The decimal text of `int.from_bytes(b, 'big', signed=True)`.
pub(crate) fn signed_int(b: &[u8]) -> String {
    decimal(b, b.first().is_some_and(|&x| x & 0x80 != 0))
}

/// Decimal text of a big-endian magnitude, by repeated division by 10.
fn decimal(b: &[u8], negative: bool) -> String {
    let mut mag: Vec<u8> = if negative {
        let mut v: Vec<u8> = b.iter().map(|x| !x).collect();
        for x in v.iter_mut().rev() {
            let (n, carry) = x.overflowing_add(1);
            *x = n;
            if !carry {
                break;
            }
        }
        v
    } else {
        b.to_vec()
    };
    let mut out = Vec::new();
    loop {
        let mut rem: u16 = 0;
        let mut nonzero = false;
        for x in mag.iter_mut() {
            let cur = (rem << 8) | u16::from(*x);
            *x = (cur / 10) as u8;
            rem = cur % 10;
            nonzero |= *x != 0;
        }
        out.push(b'0' + rem as u8);
        if !nonzero {
            break;
        }
    }
    if negative {
        out.push(b'-');
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

fn datetime(dt: &asn1::DateTime) -> Result<DateTime, CErr> {
    if dt.year() == 0 {
        return Err(value_error("year must be in 1..9999, not 0"));
    }
    Ok(DateTime {
        year: dt.year(),
        month: dt.month(),
        day: dt.day(),
        hour: dt.hour(),
        minute: dt.minute(),
        second: dt.second(),
        microsecond: 0,
    })
}

/// `_ASN1_TYPE_TO_ENUM`: the identifier octets a name attribute's value may have.
fn asn1_type_known(tag: u8) -> bool {
    matches!(tag, 3 | 4 | 12 | 18 | 19 | 20 | 22 | 23 | 24 | 26 | 28 | 30)
}

fn utf16be(b: &[u8]) -> String {
    char::decode_utf16(b.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)))
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn utf32be(b: &[u8]) -> String {
    b.as_chunks::<4>()
        .0
        .iter()
        .map(|c| char::from_u32(u32::from_be_bytes(*c)).unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn parse_name_attribute(attribute: AttributeTypeValue<'_>) -> Result<NameAttribute, CErr> {
    let tag = attribute.value.tag();
    let tag_val = tag
        .as_u8()
        .ok_or_else(|| value_error("Long-form tags are not supported in NameAttribute values"))?;
    if !asn1_type_known(tag_val) {
        return Err(CErr::from(asn1::ParseError::new(
            asn1::ParseErrorKind::UnexpectedTag { actual: tag },
        )));
    }
    let value = match attribute.value {
        AttributeValue::AnyString(s) => {
            if s.tag() == asn1::Tag::primitive(0x03) {
                AttrValue::Bytes(s.data().to_vec())
            } else {
                let parsed = std::str::from_utf8(s.data())
                    .map_err(|_| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))?;
                AttrValue::Str(parsed.to_owned())
            }
        }
        AttributeValue::PrintableString(p) => AttrValue::Str(p.as_str().to_owned()),
        AttributeValue::UniversalString(u) => AttrValue::Str(utf32be(u.as_utf32_be_bytes())),
        AttributeValue::BmpString(b) => AttrValue::Str(utf16be(b.as_utf16_be_bytes())),
    };
    // NameAttribute.__init__: a BIT STRING value is only allowed for x500UniqueIdentifier.
    if tag_val == 3 && attribute.type_id != X500_UNIQUE_IDENTIFIER {
        return Err(type_error(
            "oid must be X500_UNIQUE_IDENTIFIER for BitString type.",
        ));
    }
    Ok(NameAttribute {
        oid: attribute.type_id,
        value,
    })
}

const X500_UNIQUE_IDENTIFIER: ObjectIdentifier = asn1::oid!(2, 5, 4, 45);

fn parse_rdn(rdn: &asn1::SetOf<'_, AttributeTypeValue<'_>>) -> Result<Rdn, CErr> {
    let mut attrs = Vec::new();
    for attribute in rdn.clone() {
        attrs.push(parse_name_attribute(attribute)?);
    }
    if attrs.is_empty() {
        return Err(value_error("a relative distinguished name cannot be empty"));
    }
    // NameAttribute equality is the OID and the value; the string type does not count.
    for (i, a) in attrs.iter().enumerate() {
        if attrs[..i]
            .iter()
            .any(|b| b.oid == a.oid && b.value == a.value)
        {
            return Err(value_error("duplicate attributes are not allowed"));
        }
    }
    Ok(Rdn(attrs))
}

fn parse_name(name: &NameReadable<'_>) -> Result<Name, CErr> {
    let mut rdns = Vec::new();
    for rdn in name.clone() {
        rdns.push(parse_rdn(&rdn)?);
    }
    Ok(Name(rdns))
}

fn obj(class: &'static str, repr: String, props: Vec<(&'static str, Py)>) -> Obj {
    Obj {
        class,
        module: "cryptography.x509.extensions",
        repr,
        props,
        methods: &[],
        classmethods: &[],
        class_oid: None,
        items: None,
    }
}

/// An `ExtensionType` instance: it has `public_bytes` and the `oid` class attribute.
fn ext_obj(
    class: &'static str,
    ext_oid: ObjectIdentifier,
    repr: String,
    props: Vec<(&'static str, Py)>,
) -> Obj {
    let mut o = obj(class, repr, props);
    o.methods = &["public_bytes"];
    o.class_oid = Some(ext_oid);
    o
}

fn iter_ext(class: &'static str, ext_oid: ObjectIdentifier, items: Vec<Py>) -> Py {
    let mut o = ext_obj(class, ext_oid, format!("<{class}(...)>"), Vec::new());
    o.items = Some(items);
    Py::Obj(Box::new(o))
}

fn ip_network(data: &[u8]) -> Result<Py, CErr> {
    let half = &data[..data.len() / 2];
    // ipaddress.ip_address(bytes) on the first half runs before the prefix is checked.
    let base: String = match half.len() {
        4 => Ipv4Address {
            ip: u32::from_be_bytes([half[0], half[1], half[2], half[3]]),
        }
        .to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(half);
            format!(
                "{}",
                Ipv6Address {
                    ip: u128::from_be_bytes(a),
                    scope_id: None
                }
            )
        }
        _ => {
            return Err(value_error(format!(
                "{} does not appear to be an IPv4 or IPv6 address",
                repr_bytes(half)
            )));
        }
    };
    let (prefix, bits, addr_bits): (u32, u32, u128) = if data.len() == 8 {
        let num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if num.leading_ones() + num.trailing_zeros() != 32 {
            return Err(value_error("Invalid netmask"));
        }
        let a = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        ((!num).leading_zeros(), 32, u128::from(a))
    } else if data.len() == 32 {
        let mut m = [0u8; 16];
        m.copy_from_slice(&data[16..]);
        let num = u128::from_be_bytes(m);
        if num.leading_ones() + num.trailing_zeros() != 128 {
            return Err(value_error("Invalid netmask"));
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&data[..16]);
        ((!num).leading_zeros(), 128, u128::from_be_bytes(a))
    } else {
        return Err(value_error(format!(
            "Invalid IPNetwork, must be 8 bytes for IPv4 and 32 bytes for IPv6. Found length: {}",
            data.len()
        )));
    };
    // ipaddress.ip_network(f"{base.exploded}/{prefix}") is strict about host bits.
    let host_mask: u128 = if prefix >= bits {
        0
    } else {
        (1u128 << (bits - prefix)) - 1
    };
    if addr_bits & host_mask != 0 {
        return Err(value_error(format!("{base}/{prefix} has host bits set")));
    }
    Ok(Py::Ip(format!("{base}/{prefix}")))
}

fn general_name(gn: GeneralName<'_>) -> Result<Py, CErr> {
    let simple = |class: &'static str, v: &str| {
        let mut o = obj(
            class,
            format!("<{class}(value={})>", repr(v)),
            vec![("value", Py::Str(v.to_owned()))],
        );
        o.module = "cryptography.x509.general_name";
        Py::Obj(Box::new(o))
    };
    let with_value = |class: &'static str, v: Py| {
        let repr = format!("<{class}(value={})>", v.str());
        let mut o = obj(class, repr, vec![("value", v)]);
        o.module = "cryptography.x509.general_name";
        Py::Obj(Box::new(o))
    };
    Ok(match gn {
        GeneralName::OtherName(data) => {
            let value = data.value.full_data().to_vec();
            let repr = format!(
                "<OtherName(type_id={}, value={})>",
                oid_repr(&data.type_id),
                repr_bytes(&value)
            );
            let mut o = obj(
                "OtherName",
                repr,
                vec![
                    ("type_id", Py::Oid(data.type_id)),
                    ("value", Py::Bytes(value)),
                ],
            );
            o.module = "cryptography.x509.general_name";
            Py::Obj(Box::new(o))
        }
        GeneralName::RFC822Name(d) => simple("RFC822Name", d.0),
        GeneralName::DNSName(d) => simple("DNSName", d.0),
        GeneralName::UniformResourceIdentifier(d) => simple("UniformResourceIdentifier", d.0),
        GeneralName::DirectoryName(d) => {
            with_value("DirectoryName", Py::Name(parse_name(d.unwrap_read())?))
        }
        GeneralName::IPAddress(data) => {
            let ip = match data.len() {
                4 => Py::Ip(
                    Ipv4Address {
                        ip: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                    }
                    .to_string(),
                ),
                16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(data);
                    Py::Ip(format!(
                        "{}",
                        Ipv6Address {
                            ip: u128::from_be_bytes(a),
                            scope_id: None
                        }
                    ))
                }
                _ => ip_network(data)?,
            };
            with_value("IPAddress", ip)
        }
        GeneralName::RegisteredID(o) => with_value("RegisteredID", Py::Oid(o)),
        GeneralName::X400Address(_) | GeneralName::EDIPartyName(_) => {
            return Err(CErr::Py(PyErr::new(
                "cryptography.x509.general_name",
                "UnsupportedGeneralNameType",
                "x400Address/EDIPartyName are not supported types",
            )));
        }
    })
}

fn general_names(seq: &asn1::SequenceOf<'_, GeneralName<'_>>) -> Result<Vec<Py>, CErr> {
    seq.clone().map(general_name).collect()
}

fn display_text(t: DisplayText<'_>) -> String {
    match t {
        DisplayText::IA5String(s) => s.as_str().to_owned(),
        DisplayText::Utf8String(s) => s.as_str().to_owned(),
        DisplayText::VisibleString(s) => s.as_str().to_owned(),
        DisplayText::BmpString(s) => utf16be(s.as_utf16_be_bytes()),
    }
}

fn opt(v: Option<Py>) -> Py {
    v.unwrap_or(Py::None)
}

fn user_notice(un: UserNotice<'_, Asn1Read>) -> Py {
    let explicit_text = opt(un.explicit_text.map(|t| Py::Str(display_text(t))));
    let notice_reference = opt(un.notice_ref.map(|nr| {
        let org = Py::Str(display_text(nr.organization));
        let numbers = Py::List(
            nr.notice_numbers
                .clone()
                .map(|n| Py::Int(signed_int(n.as_bytes())))
                .collect(),
        );
        let repr = format!(
            "<NoticeReference(organization={}, notice_numbers={})>",
            org.repr(),
            numbers.str()
        );
        Py::Obj(Box::new(obj(
            "NoticeReference",
            repr,
            vec![("notice_numbers", numbers), ("organization", org)],
        )))
    }));
    let repr = format!(
        "<UserNotice(notice_reference={}, explicit_text={})>",
        notice_reference.str(),
        explicit_text.repr()
    );
    Py::Obj(Box::new(obj(
        "UserNotice",
        repr,
        vec![
            ("explicit_text", explicit_text),
            ("notice_reference", notice_reference),
        ],
    )))
}

fn policy_information(pi: PolicyInformation<'_, Asn1Read>) -> Result<Py, CErr> {
    let qualifiers = match pi.policy_qualifiers {
        None => Py::None,
        Some(pqs) => {
            let mut list = Vec::new();
            for pqi in pqs {
                list.push(match pqi.qualifier {
                    Qualifier::CpsUri(data) => {
                        if pqi.policy_qualifier_id != oid::CP_CPS_URI_OID {
                            return Err(value_error(
                                "CpsUri ASN.1 structure found but OID did not match",
                            ));
                        }
                        Py::Str(data.as_str().to_owned())
                    }
                    Qualifier::UserNotice(un) => {
                        if pqi.policy_qualifier_id != oid::CP_USER_NOTICE_OID {
                            return Err(value_error(
                                "UserNotice ASN.1 structure found but OID did not match",
                            ));
                        }
                        user_notice(un)
                    }
                });
            }
            Py::List(list)
        }
    };
    let repr = format!(
        "<PolicyInformation(policy_identifier={}, policy_qualifiers={})>",
        oid_repr(&pi.policy_identifier),
        qualifiers.str()
    );
    Ok(Py::Obj(Box::new(obj(
        "PolicyInformation",
        repr,
        vec![
            ("policy_identifier", Py::Oid(pi.policy_identifier)),
            ("policy_qualifiers", qualifiers),
        ],
    ))))
}

const REASONS: [(&str, &str); 8] = [
    ("key_compromise", "keyCompromise"),
    ("ca_compromise", "cACompromise"),
    ("affiliation_changed", "affiliationChanged"),
    ("superseded", "superseded"),
    ("cessation_of_operation", "cessationOfOperation"),
    ("certificate_hold", "certificateHold"),
    ("privilege_withdrawn", "privilegeWithdrawn"),
    ("aa_compromise", "aACompromise"),
];

fn truthy_list(v: &Py) -> bool {
    match v {
        Py::None => false,
        Py::List(l) => !l.is_empty(),
        _ => true,
    }
}

fn distribution_point(dp: DistributionPoint<'_, Asn1Read>) -> Result<Py, CErr> {
    let (full_name, relative_name) = match dp.distribution_point {
        None => (Py::None, Py::None),
        Some(DistributionPointName::FullName(d)) => (Py::List(general_names(&d)?), Py::None),
        Some(DistributionPointName::NameRelativeToCRLIssuer(d)) => {
            (Py::None, Py::Rdn(parse_rdn(&d)?))
        }
    };
    let reasons = match &dp.reasons {
        None => Py::None,
        Some(bs) => Py::FrozenSet(
            (1..=8)
                .filter(|&i| bs.has_bit_set(i))
                .map(|i| {
                    let (member, value) = REASONS[i - 1];
                    Py::Enum {
                        class: "ReasonFlags",
                        member,
                        value: Box::new(Py::Str(value.to_owned())),
                    }
                })
                .collect(),
        ),
    };
    let crl_issuer = match dp.crl_issuer {
        None => Py::None,
        Some(d) => Py::List(general_names(&d)?),
    };
    // DistributionPoint.__init__ (relative_name is never empty: an empty RDN raised already).
    if truthy_list(&full_name) && !matches!(relative_name, Py::None) {
        return Err(value_error(
            "You cannot provide both full_name and relative_name, at least one must be None.",
        ));
    }
    if !truthy_list(&full_name) && matches!(relative_name, Py::None) && !truthy_list(&crl_issuer) {
        return Err(value_error(
            "Either full_name, relative_name or crl_issuer must be provided.",
        ));
    }
    let repr = format!(
        "<DistributionPoint(full_name={}, relative_name={}, reasons={}, crl_issuer={})>",
        full_name.str(),
        relative_name.str(),
        reasons.str(),
        crl_issuer.str()
    );
    Ok(Py::Obj(Box::new(obj(
        "DistributionPoint",
        repr,
        vec![
            ("crl_issuer", crl_issuer),
            ("full_name", full_name),
            ("reasons", reasons),
            ("relative_name", relative_name),
        ],
    ))))
}

fn distribution_points(ext: &Extension<'_>) -> Result<Vec<Py>, CErr> {
    let dps = ext.value::<asn1::SequenceOf<'_, DistributionPoint<'_, Asn1Read>>>()?;
    dps.map(distribution_point).collect()
}

fn access_descriptions(ext: &Extension<'_>) -> Result<Vec<Py>, CErr> {
    let parsed = ext.value::<SequenceOfAccessDescriptions<'_, Asn1Read>>()?;
    let mut out = Vec::new();
    for access in parsed {
        let gn = general_name(access.access_location)?;
        let repr = format!(
            "<AccessDescription(access_method={}, access_location={})>",
            oid_repr(&access.access_method),
            gn.str()
        );
        out.push(Py::Obj(Box::new(obj(
            "AccessDescription",
            repr,
            vec![
                ("access_location", gn),
                ("access_method", Py::Oid(access.access_method)),
            ],
        ))));
    }
    Ok(out)
}

fn general_subtrees(subtrees: SequenceOfSubtrees<'_, Asn1Read>) -> Result<Vec<Py>, CErr> {
    subtrees.map(|gs| general_name(gs.base)).collect()
}

/// NameConstraints._validate_tree, on a non-empty list.
fn validate_tree(tree: &[Py], which: &str) -> Result<(), CErr> {
    if tree.is_empty() {
        return Err(value_error(format!(
            "{which} must be a non-empty list or None"
        )));
    }
    let prop = |p: &Py, class: &str| -> Option<String> {
        if let Py::Obj(o) = p
            && o.class == class
        {
            return o.props.first().map(|(_, v)| v.str());
        }
        None
    };
    if tree
        .iter()
        .any(|g| prop(g, "IPAddress").is_some_and(|v| !v.contains('/')))
    {
        return Err(type_error(
            "IPAddress name constraints must be an IPv4Network or IPv6Network object",
        ));
    }
    if tree
        .iter()
        .any(|g| prop(g, "DNSName").is_some_and(|v| v.contains('*')))
    {
        return Err(value_error(
            "DNSName name constraints must not contain the '*' wildcard character",
        ));
    }
    Ok(())
}

fn naming_authority(na: NamingAuthority<'_>) -> Py {
    let id = opt(na.id.map(Py::Oid));
    let url = opt(na.url.map(|u| Py::Str(u.as_str().to_owned())));
    let text = opt(na.text.map(|t| Py::Str(display_text(t))));
    let repr = format!(
        "<NamingAuthority(id={}, url={}, text={})>",
        id.str(),
        url.str(),
        text.str()
    );
    Py::Obj(Box::new(obj(
        "NamingAuthority",
        repr,
        vec![("id", id), ("text", text), ("url", url)],
    )))
}

fn profession_info(info: ProfessionInfo<'_, Asn1Read>) -> Py {
    let na = opt(info.naming_authority.map(naming_authority));
    let items = Py::List(
        info.profession_items
            .map(|t| Py::Str(display_text(t)))
            .collect(),
    );
    let oids = opt(info
        .profession_oids
        .map(|o| Py::List(o.map(Py::Oid).collect())));
    let reg = opt(info
        .registration_number
        .map(|r| Py::Str(r.as_str().to_owned())));
    let add = opt(info.add_profession_info.map(|b| Py::Bytes(b.to_vec())));
    let repr = format!(
        "<ProfessionInfo(naming_authority={}, profession_items={}, profession_oids={}, registration_number={}, add_profession_info={})>",
        na.str(),
        items.str(),
        oids.str(),
        reg.str(),
        add.repr()
    );
    Py::Obj(Box::new(obj(
        "ProfessionInfo",
        repr,
        vec![
            ("add_profession_info", add),
            ("naming_authority", na),
            ("profession_items", items),
            ("profession_oids", oids),
            ("registration_number", reg),
        ],
    )))
}

fn admission(a: Admission<'_, Asn1Read>) -> Result<Py, CErr> {
    let authority = match a.admission_authority {
        Some(g) => general_name(g)?,
        None => Py::None,
    };
    let na = opt(a.naming_authority.map(naming_authority));
    let infos = Py::List(a.profession_infos.map(profession_info).collect());
    let repr = format!(
        "<Admission(admission_authority={}, naming_authority={}, profession_infos={})>",
        authority.str(),
        na.str(),
        infos.str()
    );
    Ok(Py::Obj(Box::new(obj(
        "Admission",
        repr,
        vec![
            ("admission_authority", authority),
            ("naming_authority", na),
            ("profession_infos", infos),
        ],
    ))))
}

/// Python's `bool` in an f-string.
fn b(v: bool) -> &'static str {
    if v { "True" } else { "False" }
}

fn parse_scts(data: &[u8]) -> Result<Vec<Py>, CErr> {
    let invalid = || value_error("Invalid SCT length");
    let read = |d: &mut &[u8], n: usize| -> Result<Vec<u8>, CErr> {
        if n > d.len() {
            return Err(invalid());
        }
        let (a, rest) = d.split_at(n);
        *d = rest;
        Ok(a.to_vec())
    };
    let read_prefixed = |d: &mut &[u8]| -> Result<Vec<u8>, CErr> {
        let len = read(d, 2)?;
        read(d, usize::from(u16::from_be_bytes([len[0], len[1]])))
    };
    let mut outer = data;
    let list = read_prefixed(&mut outer)?;
    if !outer.is_empty() {
        return Err(invalid());
    }
    let mut reader: &[u8] = &list;
    let mut out = Vec::new();
    while !reader.is_empty() {
        let sct = read_prefixed(&mut reader)?;
        let mut s: &[u8] = &sct;
        let version = read(&mut s, 1)?[0];
        if version != 0 {
            return Err(value_error("Invalid SCT version"));
        }
        let log_id = read(&mut s, 32)?;
        let ts = read(&mut s, 8)?;
        let timestamp = u64::from_be_bytes(ts.try_into().map_err(|_| invalid())?);
        let extension_bytes = read_prefixed(&mut s)?;
        let hash = match read(&mut s, 1)?[0] {
            1 => "MD5",
            2 => "SHA1",
            3 => "SHA224",
            4 => "SHA256",
            5 => "SHA384",
            6 => "SHA512",
            v => {
                return Err(value_error(format!(
                    "Invalid/unsupported hash algorithm for SCT: {v}"
                )));
            }
        };
        let sig_alg = match read(&mut s, 1)?[0] {
            1 => "RSA",
            2 => "DSA",
            3 => "ECDSA",
            v => {
                return Err(value_error(format!(
                    "Invalid/unsupported signature algorithm for SCT: {v}"
                )));
            }
        };
        let signature = read_prefixed(&mut s)?;
        if !s.is_empty() {
            return Err(invalid());
        }
        let ts_value = match sct_timestamp(timestamp) {
            Some(d) => Py::DateTime(d),
            // datetime.fromtimestamp raises, so str() of the attribute raises in
            // get_readable_extensions, which returns None.
            None => Py::Raises,
        };
        let repr = format!(
            "<cryptography.hazmat.bindings._rust.x509.Sct object at {}>",
            crate::pyobj::ADDRESS
        );
        let mut o = obj(
            "Sct",
            repr,
            vec![
                (
                    "entry_type",
                    Py::Enum {
                        class: "LogEntryType",
                        member: "PRE_CERTIFICATE",
                        value: Box::new(Py::Int("1".into())),
                    },
                ),
                ("extension_bytes", Py::Bytes(extension_bytes)),
                ("log_id", Py::Bytes(log_id)),
                ("signature", Py::Bytes(signature)),
                (
                    "signature_algorithm",
                    Py::Enum {
                        class: "SignatureAlgorithm",
                        member: sig_alg,
                        value: Box::new(Py::Int("0".into())),
                    },
                ),
                ("signature_hash_algorithm", Py::Hash(hash)),
                ("timestamp", ts_value),
                (
                    "version",
                    Py::Enum {
                        class: "Version",
                        member: "v1",
                        value: Box::new(Py::Int("0".into())),
                    },
                ),
            ],
        );
        o.module = "cryptography.hazmat.bindings._rust.x509";
        out.push(Py::Obj(Box::new(o)));
    }
    Ok(out)
}

/// `datetime.fromtimestamp(ms // 1000, utc).replace(microsecond=ms % 1000 * 1000, tzinfo=None)`,
/// or `None` past year 9999.
fn sct_timestamp(ms: u64) -> Option<DateTime> {
    let secs = ms / 1000;
    if secs > 253_402_300_799 {
        return None;
    }
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil from days (Howard Hinnant's algorithm), days since 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Some(DateTime {
        year: y as u16,
        month: m as u8,
        day: d as u8,
        hour: (rem / 3600) as u8,
        minute: (rem % 3600 / 60) as u8,
        second: (rem % 60) as u8,
        microsecond: (ms % 1000 * 1000) as u32,
    })
}

/// One parsed extension.
pub struct PyExtension {
    pub critical: bool,
    pub oid: ObjectIdentifier,
    pub value: Py,
}

fn parse_extension(ext: &Extension<'_>) -> Result<Py, CErr> {
    let id = ext.extn_id.clone();
    Ok(match ext.extn_id {
        oid::PRECERT_POISON_OID => {
            ext.value::<()>()?;
            Py::Obj(Box::new(ext_obj(
                "PrecertPoison",
                id,
                "<PrecertPoison()>".into(),
                Vec::new(),
            )))
        }
        oid::PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID => {
            let contents = ext.value::<&[u8]>()?;
            iter_ext(
                "PrecertificateSignedCertificateTimestamps",
                id,
                parse_scts(contents)?,
            )
        }
        oid::SUBJECT_ALTERNATIVE_NAME_OID => {
            let seq = ext
                .value::<SubjectAlternativeName<'_>>()
                .map_err(|e| CErr::from(e).add_location("subject_alternative_name"))?;
            iter_ext("SubjectAlternativeName", id, general_names(&seq)?)
        }
        oid::ISSUER_ALTERNATIVE_NAME_OID => {
            let seq = ext
                .value::<IssuerAlternativeName<'_>>()
                .map_err(|e| CErr::from(e).add_location("issuer_alternative_name"))?;
            iter_ext("IssuerAlternativeName", id, general_names(&seq)?)
        }
        oid::TLS_FEATURE_OID => {
            let mut features = Vec::new();
            for f in ext.value::<asn1::SequenceOf<'_, u64>>()? {
                let member = match f {
                    5 => "status_request",
                    17 => "status_request_v2",
                    other => return Err(CErr::Py(PyErr::builtin("KeyError", other.to_string()))),
                };
                features.push(Py::Enum {
                    class: "TLSFeatureType",
                    member,
                    value: Box::new(Py::Int(f.to_string())),
                });
            }
            if features.is_empty() {
                return Err(type_error(
                    "features must be a list of elements from the TLSFeatureType enum",
                ));
            }
            iter_ext("TLSFeature", id, features)
        }
        oid::SUBJECT_KEY_IDENTIFIER_OID => {
            let digest = ext.value::<&[u8]>()?.to_vec();
            let repr = format!("<SubjectKeyIdentifier(digest={})>", repr_bytes(&digest));
            let mut o = ext_obj(
                "SubjectKeyIdentifier",
                id,
                repr,
                vec![
                    ("digest", Py::Bytes(digest.clone())),
                    ("key_identifier", Py::Bytes(digest)),
                ],
            );
            o.classmethods = &["from_public_key"];
            Py::Obj(Box::new(o))
        }
        oid::EXTENDED_KEY_USAGE_OID => iter_ext(
            "ExtendedKeyUsage",
            id,
            ext.value::<ExtendedKeyUsage<'_>>()?.map(Py::Oid).collect(),
        ),
        oid::KEY_USAGE_OID => {
            let ku = ext.value::<KeyUsage<'_>>()?;
            let ka = ku.key_agreement();
            if !ka && (ku.encipher_only() || ku.decipher_only()) {
                return Err(value_error(
                    "encipher_only and decipher_only can only be true when key_agreement is true",
                ));
            }
            let (eo, dec) = if ka {
                (ku.encipher_only(), ku.decipher_only())
            } else {
                (false, false)
            };
            let repr = format!(
                "<KeyUsage(digital_signature={}, content_commitment={}, key_encipherment={}, data_encipherment={}, key_agreement={}, key_cert_sign={}, crl_sign={}, encipher_only={}, decipher_only={})>",
                b(ku.digital_signature()),
                b(ku.content_commitment()),
                b(ku.key_encipherment()),
                b(ku.data_encipherment()),
                b(ka),
                b(ku.key_cert_sign()),
                b(ku.crl_sign()),
                b(eo),
                b(dec)
            );
            Py::Obj(Box::new(ext_obj(
                "KeyUsage",
                id,
                repr,
                vec![
                    ("content_commitment", Py::Bool(ku.content_commitment())),
                    ("crl_sign", Py::Bool(ku.crl_sign())),
                    ("data_encipherment", Py::Bool(ku.data_encipherment())),
                    ("decipher_only", Py::Bool(dec)),
                    ("digital_signature", Py::Bool(ku.digital_signature())),
                    ("encipher_only", Py::Bool(eo)),
                    ("key_agreement", Py::Bool(ka)),
                    ("key_cert_sign", Py::Bool(ku.key_cert_sign())),
                    ("key_encipherment", Py::Bool(ku.key_encipherment())),
                ],
            )))
        }
        oid::AUTHORITY_INFORMATION_ACCESS_OID => {
            iter_ext("AuthorityInformationAccess", id, access_descriptions(ext)?)
        }
        oid::SUBJECT_INFORMATION_ACCESS_OID => {
            iter_ext("SubjectInformationAccess", id, access_descriptions(ext)?)
        }
        oid::CERTIFICATE_POLICIES_OID => {
            let cp = ext.value::<asn1::SequenceOf<'_, PolicyInformation<'_, Asn1Read>>>()?;
            let mut items = Vec::new();
            for pi in cp {
                items.push(policy_information(pi)?);
            }
            iter_ext("CertificatePolicies", id, items)
        }
        oid::POLICY_CONSTRAINTS_OID => {
            let pc = ext.value::<PolicyConstraints>()?;
            if pc.require_explicit_policy.is_none() && pc.inhibit_policy_mapping.is_none() {
                return Err(value_error(
                    "At least one of require_explicit_policy and inhibit_policy_mapping must not be None",
                ));
            }
            let rep = opt(pc.require_explicit_policy.map(|v| Py::Int(v.to_string())));
            let ipm = opt(pc.inhibit_policy_mapping.map(|v| Py::Int(v.to_string())));
            let repr = format!(
                "<PolicyConstraints(require_explicit_policy={}, inhibit_policy_mapping={})>",
                rep.str(),
                ipm.str()
            );
            Py::Obj(Box::new(ext_obj(
                "PolicyConstraints",
                id,
                repr,
                vec![
                    ("inhibit_policy_mapping", ipm),
                    ("require_explicit_policy", rep),
                ],
            )))
        }
        oid::OCSP_NO_CHECK_OID => {
            ext.value::<()>()?;
            Py::Obj(Box::new(ext_obj(
                "OCSPNoCheck",
                id,
                "<OCSPNoCheck()>".into(),
                Vec::new(),
            )))
        }
        oid::INHIBIT_ANY_POLICY_OID => {
            let n = ext.value::<asn1::BigUint<'_>>()?;
            let v = signed_int(n.as_bytes());
            let repr = format!("<InhibitAnyPolicy(skip_certs={v})>");
            Py::Obj(Box::new(ext_obj(
                "InhibitAnyPolicy",
                id,
                repr,
                vec![("skip_certs", Py::Int(v))],
            )))
        }
        oid::BASIC_CONSTRAINTS_OID => {
            let bc = ext.value::<BasicConstraints>()?;
            if bc.path_length.is_some() && !bc.ca {
                return Err(value_error("path_length must be None when ca is False"));
            }
            let pl = opt(bc.path_length.map(|v| Py::Int(v.to_string())));
            let repr = format!(
                "<BasicConstraints(ca={}, path_length={})>",
                b(bc.ca),
                pl.str()
            );
            Py::Obj(Box::new(ext_obj(
                "BasicConstraints",
                id,
                repr,
                vec![("ca", Py::Bool(bc.ca)), ("path_length", pl)],
            )))
        }
        oid::AUTHORITY_KEY_IDENTIFIER_OID => {
            let aki = ext.value::<AuthorityKeyIdentifier<'_, Asn1Read>>()?;
            let serial = opt(aki
                .authority_cert_serial_number
                .map(|s| Py::Int(signed_int(s.as_bytes()))));
            let issuer = match aki.authority_cert_issuer {
                Some(aci) => Py::List(general_names(&aci)?),
                None => Py::None,
            };
            if matches!(issuer, Py::None) != matches!(serial, Py::None) {
                return Err(value_error(
                    "authority_cert_issuer and authority_cert_serial_number must both be present or both None",
                ));
            }
            let kid = opt(aki.key_identifier.map(|k| Py::Bytes(k.to_vec())));
            let repr = format!(
                "<AuthorityKeyIdentifier(key_identifier={}, authority_cert_issuer={}, authority_cert_serial_number={})>",
                kid.repr(),
                issuer.str(),
                serial.str()
            );
            let mut o = ext_obj(
                "AuthorityKeyIdentifier",
                id,
                repr,
                vec![
                    ("authority_cert_issuer", issuer),
                    ("authority_cert_serial_number", serial),
                    ("key_identifier", kid),
                ],
            );
            o.classmethods = &[
                "from_issuer_public_key",
                "from_issuer_subject_key_identifier",
            ];
            Py::Obj(Box::new(o))
        }
        oid::CRL_DISTRIBUTION_POINTS_OID => {
            iter_ext("CRLDistributionPoints", id, distribution_points(ext)?)
        }
        oid::FRESHEST_CRL_OID => iter_ext("FreshestCRL", id, distribution_points(ext)?),
        oid::NAME_CONSTRAINTS_OID => {
            let nc = ext.value::<NameConstraints<'_, Asn1Read>>()?;
            let permitted = match nc.permitted_subtrees {
                Some(d) => Some(general_subtrees(d)?),
                None => None,
            };
            let excluded = match nc.excluded_subtrees {
                Some(d) => Some(general_subtrees(d)?),
                None => None,
            };
            if let Some(p) = &permitted {
                validate_tree(p, "permitted_subtrees")?;
            }
            if let Some(e) = &excluded {
                validate_tree(e, "excluded_subtrees")?;
            }
            if permitted.is_none() && excluded.is_none() {
                return Err(value_error(
                    "At least one of permitted_subtrees and excluded_subtrees must not be None",
                ));
            }
            let p = opt(permitted.map(Py::List));
            let e = opt(excluded.map(Py::List));
            let repr = format!(
                "<NameConstraints(permitted_subtrees={}, excluded_subtrees={})>",
                p.str(),
                e.str()
            );
            Py::Obj(Box::new(ext_obj(
                "NameConstraints",
                id,
                repr,
                vec![("excluded_subtrees", e), ("permitted_subtrees", p)],
            )))
        }
        oid::MS_CERTIFICATE_TEMPLATE => {
            let t = ext.value::<MSCertificateTemplate>()?;
            let major = opt(t.major_version.map(|v| Py::Int(v.to_string())));
            let minor = opt(t.minor_version.map(|v| Py::Int(v.to_string())));
            let repr = format!(
                "<MSCertificateTemplate(template_id={}, major_version={}, minor_version={})>",
                oid_repr(&t.template_id),
                major.str(),
                minor.str()
            );
            Py::Obj(Box::new(ext_obj(
                "MSCertificateTemplate",
                id,
                repr,
                vec![
                    ("major_version", major),
                    ("minor_version", minor),
                    ("template_id", Py::Oid(t.template_id)),
                ],
            )))
        }
        oid::ADMISSIONS_OID => {
            let a = ext.value::<Admissions<'_, Asn1Read>>()?;
            if let Some(g) = a.admission_authority {
                general_name(g)?;
            }
            let mut items = Vec::new();
            for adm in a.contents_of_admissions {
                items.push(admission(adm)?);
            }
            iter_ext("Admissions", id, items)
        }
        oid::PRIVATE_KEY_USAGE_PERIOD_OID => {
            let p = ext.value::<PrivateKeyUsagePeriod>()?;
            let nb = match &p.not_before {
                Some(t) => Some(datetime(t.as_datetime())?),
                None => None,
            };
            let na = match &p.not_after {
                Some(t) => Some(datetime(t.as_datetime())?),
                None => None,
            };
            match (&nb, &na) {
                (None, None) => {
                    return Err(value_error(
                        "At least one of not_before and not_after must not be None",
                    ));
                }
                (Some(x), Some(y)) if key(x) > key(y) => {
                    return Err(value_error("not_before must be before not_after"));
                }
                _ => {}
            }
            let nb = opt(nb.map(Py::DateTime));
            let na = opt(na.map(Py::DateTime));
            let repr = format!(
                "<PrivateKeyUsagePeriod(not_before={}, not_after={})>",
                nb.str(),
                na.str()
            );
            Py::Obj(Box::new(ext_obj(
                "PrivateKeyUsagePeriod",
                id,
                repr,
                vec![("not_after", na), ("not_before", nb)],
            )))
        }
        _ => {
            let value = ext.extn_value.to_vec();
            let repr = format!(
                "<UnrecognizedExtension(oid={}, value={})>",
                oid_repr(&id),
                repr_bytes(&value)
            );
            let mut o = obj(
                "UnrecognizedExtension",
                repr,
                vec![("oid", Py::Oid(id)), ("value", Py::Bytes(value))],
            );
            o.methods = &["public_bytes"];
            Py::Obj(Box::new(o))
        }
    })
}

fn key(d: &DateTime) -> (u16, u8, u8, u8, u8, u8) {
    (d.year, d.month, d.day, d.hour, d.minute, d.second)
}

impl Certificate {
    fn raw(&self) -> RawCertificate<'_> {
        // Parsed when the certificate was loaded, so this cannot fail.
        asn1::parse_single(&self.der).expect("the certificate parsed when it was loaded")
    }

    /// The DER this certificate was loaded from.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// `cert.issuer`.
    pub fn issuer(&self) -> Result<Name, PyErr> {
        parse_name(self.raw().issuer()).map_err(|e| e.add_location("issuer").into_py())
    }

    /// `cert.subject`.
    pub fn subject(&self) -> Result<Name, PyErr> {
        parse_name(self.raw().subject()).map_err(|e| e.add_location("subject").into_py())
    }

    /// `cert.serial_number`, as decimal text.
    pub fn serial_number(&self) -> String {
        signed_int(self.raw().tbs_cert.serial.as_bytes())
    }

    /// `cert.not_valid_before_utc`.
    pub fn not_valid_before_utc(&self) -> Result<DateTime, PyErr> {
        datetime(self.raw().tbs_cert.validity.not_before.as_datetime()).map_err(CErr::into_py)
    }

    /// `cert.not_valid_after_utc`.
    pub fn not_valid_after_utc(&self) -> Result<DateTime, PyErr> {
        datetime(self.raw().tbs_cert.validity.not_after.as_datetime()).map_err(CErr::into_py)
    }

    /// `sha256(cert.public_bytes(DER))`, in hex. cryptography re-encodes the parsed structure,
    /// which gives back the bytes it parsed; this re-encodes the same way.
    pub fn sha256(&self) -> String {
        let der = asn1::write_single(&self.raw()).unwrap_or_else(|_| self.der.clone());
        let digest = Sha256::digest(&der);
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `cert.extensions`.
    pub(crate) fn extensions(&self) -> Result<Vec<PyExtension>, PyErr> {
        let raw = self.raw();
        let exts =
            Extensions::from_raw_extensions(raw.tbs_cert.raw_extensions.as_ref()).map_err(|e| {
                PyErr::new(
                    "cryptography.x509.extensions",
                    "DuplicateExtension",
                    format!("Duplicate {} extension found", e.0),
                )
            })?;
        let mut out = Vec::new();
        for ext in exts.iter() {
            let value = parse_extension(&ext).map_err(CErr::into_py)?;
            out.push(PyExtension {
                critical: ext.critical,
                oid: ext.extn_id.clone(),
                value,
            });
        }
        Ok(out)
    }
}

impl std::fmt::Debug for PyExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Extension({}, {}, {})",
            self.oid,
            self.critical,
            self.value.repr()
        )
    }
}
