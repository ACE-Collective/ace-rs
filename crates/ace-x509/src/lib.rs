//! A port of ace3's `saq/x509.py`, as `file_type`'s `is_x509` check and the `x509_analyzer`
//! module use it, on the libraries ace3's image has: cryptography 50.0.2 and pyasn1 0.6.5.
//!
//! - [`is_x509`] is `saq.modules.file_analysis.is_file_type.is_x509` on a file's bytes: the
//!   first 8192 bytes pass [`is_pem_bytes`] or [`is_der_bytes`] (pyasn1's DER decoder), then
//!   [`load_cert`] on the whole file returns a certificate.
//! - [`load_cert`] is `load_pem_x509_certificate`, then `load_der_x509_certificate`. It parses
//!   with the structures and the `asn1` crate (0.24.1) cryptography itself uses, vendored in
//!   `raw` from its `cryptography-x509` crate, and with the `pem` crate (4.0.0) cryptography uses,
//!   so it takes the same PEM block and accepts the same DER.
//! - [`Certificate`] gives what the analyzer stores: issuer and subject as `rfc4514_string()`,
//!   the serial number, the validity dates, the common name, the SAN DNS names and IP addresses,
//!   the SHA-256 of the DER, and [`Certificate::readable_extensions`], the tree
//!   `get_readable_extensions` builds from `str()` and `dir()` of cryptography's Python objects.
//! - [`analyze`] runs the analyzer's steps in its order and gives the details it stores and the
//!   text of the metadata file it writes (`json.dumps(details, default=str)`).
//!
//! Errors are Python exceptions ([`PyErr`]) with cryptography's class and message: a parse
//! error is a `ValueError` whose message is `error parsing asn1 value: ` and the `asn1` crate's
//! `Debug` text, as cryptography builds it.
//!
//! Where it departs:
//!
//! - Python prints a memory address in `str()` of an SCT and of an SCT's hash algorithm
//!   (`<... object at 0x7f...>`); this prints [`pyobj::ADDRESS`] instead.
//! - `str()` of a `frozenset` (a CRL distribution point's `reasons`) lists its items in an
//!   order that depends on Python's per-process string hashing; this lists them by bit.
//! - Warnings cryptography raises (a serial that is not positive, a name attribute of the wrong
//!   length, UTF-8 in a VisibleString) are not reported, as Python's default filters only print
//!   them.
//!
//! Hostile input: everything works on the bytes given, with no I/O. pyasn1's decoder is
//! recursive but stops at its nesting limit of 100; the `asn1` crate's parser has a depth limit
//! of its own. No allocation is sized from a length in the input beyond the input's own size.

mod cert;
mod oid_names;
mod pyasn1;
pub mod pyobj;
mod raw;

pub use ace_pycompat::PyErr;
pub use cert::{Certificate, load_der_x509_certificate, load_pem_x509_certificate};
pub use oid_names::oid_name;
pub use pyasn1::is_der_bytes;
pub use pyobj::{AttrValue, DateTime, Name, NameAttribute, Rdn};

use pyobj::{Py, json_dumps, json_str};
use serde_json::Value;

/// How much of a file `is_x509` reads before deciding whether to load it.
pub const IS_X509_READ_SIZE: usize = 8192;

/// `saq.x509.PEM_LABEL_ENDINGS`.
const PEM_LABEL_ENDINGS: [&[u8]; 9] = [
    b"CERTIFICATE-----",
    b"X509 CRL-----",
    b"CERTIFICATE REQUEST-----",
    b"PKCS7-----",
    b"CMS-----",
    b"PRIVATE KEY-----",
    b"ENCRYPTED PRIVATE KEY-----",
    b"ATTRIBUTE CERTIFICATE-----",
    b"PUBLIC KEY-----",
];

/// `saq.x509.is_pem_bytes`: one of the PEM label endings is in the bytes.
pub fn is_pem_bytes(data: &[u8]) -> bool {
    PEM_LABEL_ENDINGS
        .iter()
        .any(|l| data.windows(l.len()).any(|w| w == *l))
}

/// `saq.x509.load_cert`: the certificate cryptography loads from PEM or else DER, or `None` when
/// both raise `ValueError`. Any other exception (`InvalidVersion`, for a version other than v1
/// or v3) propagates, as it does in ace3.
pub fn load_cert(data: &[u8]) -> Result<Option<Certificate>, PyErr> {
    match load_pem_x509_certificate(data) {
        Ok(c) => return Ok(Some(c)),
        Err(e) if e.is_instance("builtins", "ValueError") => {}
        Err(e) => return Err(e),
    }
    match load_der_x509_certificate(data) {
        Ok(c) => Ok(Some(c)),
        Err(e) if e.is_instance("builtins", "ValueError") => Ok(None),
        Err(e) => Err(e),
    }
}

/// `is_x509(path)` on the file's bytes. An exception from [`load_cert`] propagates, as it does
/// out of ace3's function.
pub fn is_x509(data: &[u8]) -> Result<bool, PyErr> {
    let head = &data[..data.len().min(IS_X509_READ_SIZE)];
    if !is_pem_bytes(head) && !is_der_bytes(head) {
        return Ok(false);
    }
    Ok(load_cert(data)?.is_some())
}

impl Certificate {
    /// `cert.issuer.rfc4514_string()`.
    pub fn issuer_rfc4514(&self) -> Result<String, PyErr> {
        Ok(self.issuer()?.rfc4514_string())
    }

    /// `cert.subject.rfc4514_string()`.
    pub fn subject_rfc4514(&self) -> Result<String, PyErr> {
        Ok(self.subject()?.rfc4514_string())
    }

    /// `saq.x509.common_name`: the last common name in the subject, or `None` when there is
    /// none or it is empty.
    pub fn common_name(&self) -> Result<Option<String>, PyErr> {
        let subject = self.subject()?;
        let last = subject
            .attributes()
            .filter(|a| a.oid.to_string() == "2.5.4.3")
            .last();
        Ok(match last.map(|a| &a.value) {
            Some(AttrValue::Str(s)) if !s.is_empty() => Some(s.clone()),
            Some(AttrValue::Bytes(b)) if !b.is_empty() => {
                Some(String::from_utf8_lossy(b).into_owned())
            }
            _ => None,
        })
    }

    fn san_values(&self, class: &str) -> Result<Vec<String>, PyErr> {
        let exts = self.extensions()?;
        let Some(san) = exts.iter().find(|e| e.oid.to_string() == "2.5.29.17") else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        if let Py::Obj(o) = &san.value {
            for item in o.items.iter().flatten() {
                if let Py::Obj(gn) = item
                    && gn.class == class
                    && let Some((_, v)) = gn.props.iter().find(|(k, _)| *k == "value")
                {
                    out.push(v.str());
                }
            }
        }
        Ok(out)
    }

    /// `saq.x509.san_dns_names`: the SAN's DNS names, in order.
    pub fn san_dns_names(&self) -> Result<Vec<String>, PyErr> {
        self.san_values("DNSName")
    }

    /// `saq.x509.san_ip_addresses`: `str()` of the SAN's IP addresses (and networks), in order.
    pub fn san_ip_addresses(&self) -> Result<Vec<String>, PyErr> {
        self.san_values("IPAddress")
    }

    /// `saq.x509.get_readable_extensions`: the extension tree, or `None` when reading the
    /// extensions or building the tree raises.
    pub fn readable_extensions(&self) -> Option<Value> {
        let exts = self.extensions().ok()?;
        let refs: Vec<(bool, &Py)> = exts.iter().map(|e| (e.critical, &e.value)).collect();
        pyobj::readable(&refs)
    }
}

/// What the analyzer stores for a certificate (`X509Analysis.details`).
#[derive(Debug, Clone, PartialEq)]
pub struct Details {
    pub issuer: String,
    pub subject: String,
    pub not_valid_before: DateTime,
    pub not_valid_after: DateTime,
    /// A Python int, as decimal text.
    pub serial_number: String,
    pub common_name: Option<String>,
    pub sha256_hash: String,
    pub extensions: Option<Value>,
    pub san_ip_addresses: Vec<String>,
    pub san_dns_names: Vec<String>,
}

impl Details {
    /// The metadata file's text: `json.dumps(details, default=str)`, with the datetimes still
    /// datetimes (so `str()` of them) and the keys in the details' order.
    pub fn metadata_json(&self) -> String {
        let mut out = String::from("{\"issuer\": ");
        json_str(&self.issuer, &mut out);
        out.push_str(", \"subject\": ");
        json_str(&self.subject, &mut out);
        out.push_str(", \"not_valid_before\": ");
        json_str(&self.not_valid_before.utc_str(), &mut out);
        out.push_str(", \"not_valid_after\": ");
        json_str(&self.not_valid_after.utc_str(), &mut out);
        out.push_str(", \"serial_number\": ");
        out.push_str(&self.serial_number);
        out.push_str(", \"common_name\": ");
        match &self.common_name {
            Some(c) => json_str(c, &mut out),
            None => out.push_str("null"),
        }
        out.push_str(", \"sha256_hash\": ");
        json_str(&self.sha256_hash, &mut out);
        out.push_str(", \"extensions\": ");
        match &self.extensions {
            Some(v) => json_dumps(v, &mut out),
            None => out.push_str("null"),
        }
        out.push_str(", \"subject_alternative_names\": {\"san_ip_addresses\": ");
        json_dumps(&Value::from(self.san_ip_addresses.clone()), &mut out);
        out.push_str(", \"san_dns_names\": ");
        json_dumps(&Value::from(self.san_dns_names.clone()), &mut out);
        out.push_str("}}");
        out
    }
}

/// `X509Analyzer.execute_analysis` on a loaded certificate, step by step in its order: the
/// first exception any step raises is the analyzer's.
pub fn analyze(cert: &Certificate) -> Result<Details, PyErr> {
    let issuer = cert.issuer_rfc4514()?;
    let subject = cert.subject_rfc4514()?;
    let serial_number = cert.serial_number();
    let not_valid_before = cert.not_valid_before_utc()?;
    let not_valid_after = cert.not_valid_after_utc()?;
    let common_name = cert.common_name()?;
    let sha256_hash = cert.sha256();
    let san_ip_addresses = cert.san_ip_addresses()?;
    let san_dns_names = cert.san_dns_names()?;
    let extensions = cert.readable_extensions();
    Ok(Details {
        issuer,
        subject,
        not_valid_before,
        not_valid_after,
        serial_number,
        common_name,
        sha256_hash,
        extensions,
        san_ip_addresses,
        san_dns_names,
    })
}

#[cfg(test)]
mod tests;
