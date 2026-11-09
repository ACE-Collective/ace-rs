//! The network a hunt script's command type uses (PLAN.md decision 16), as the calls the scripts
//! make: dnspython's `Resolver.resolve`, urllib's `urlopen`, and a TLS handshake that hands back the
//! peer's certificate. ace-hunt has no network of its own: `ace hunter` gives the real one
//! (`ace_app::hunter::net`, hickory's wire format, ace4's HTTP client with verified TLS, rustls),
//! and tests a fake that answers from a fixture. Each call is bounded by its own timeout, which the
//! caller also keeps inside the command's deadline.

use std::time::Duration;

/// One record of an answer, as the scripts read a dnspython rdata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// `rdata.to_text()`.
    pub text: String,
    /// A TXT record's character-strings, `rdata.strings`; empty for any other type.
    pub strings: Vec<Vec<u8>>,
    /// `str(rdata.exchange)` of an MX, `str(rdata.target)` of an NS, CNAME or PTR: the name with
    /// its trailing dot.
    pub target: Option<String>,
}

/// How a lookup ended without an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAnswer {
    Records(Vec<DnsRecord>),
    /// `dns.resolver.NXDOMAIN`.
    NxDomain,
    /// `dns.resolver.NoAnswer`: the name exists and has no record of the type.
    NoAnswer,
}

/// A lookup that raised: dnspython's exception's class name, such as `NoNameservers`,
/// `LifetimeTimeout`, `EmptyLabel` or `UnknownRdatatype`, and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFailure {
    pub kind: String,
    pub message: String,
}

impl DnsFailure {
    pub fn new(kind: &str, message: impl Into<String>) -> DnsFailure {
        DnsFailure {
            kind: kind.to_owned(),
            message: message.into(),
        }
    }
}

/// A recursive resolver, asked as dnspython asks one with `timeout` and `lifetime` both
/// `lifetime`.
pub trait Dns: Send + Sync {
    /// `name`'s records of type `rtype` (its text, such as `A` or `MX`), asking `nameservers`, or
    /// the system's (`/etc/resolv.conf`) when None.
    fn resolve(
        &self,
        name: &str,
        rtype: &str,
        nameservers: Option<&[String]>,
        lifetime: Duration,
    ) -> Result<DnsAnswer, DnsFailure>;
}

/// One HTTP request, as urllib's `Request` makes it.
#[derive(Debug, Clone)]
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
    pub timeout: Duration,
    /// The most of the body read, as `response.read(n)`; None reads it all, up to the client's
    /// own bound.
    pub read_limit: Option<usize>,
}

/// A response of any status, after redirects were followed as urllib follows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReply {
    pub status: u16,
    /// `response.geturl()`: the URL answered, after redirects.
    pub url: String,
    /// The `Content-Type` header, as sent.
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// A request that got no response: the exception urllib raises's class name, such as `URLError`
/// or `TimeoutError`, and the text `str(e.reason)` (or `str(e)`) gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpFailure {
    pub kind: String,
    pub detail: String,
}

pub trait Http: Send + Sync {
    fn request(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpFailure>;
}

/// The leaf certificate a TLS server presented, after its chain was verified to a trusted root
/// but not its name, as Python's `ssl` gives it with `check_hostname` off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCertificate {
    /// `getpeercert(binary_form=True)`.
    pub der: Vec<u8>,
    /// The subject's attributes in order, by OpenSSL's long names (`commonName`).
    pub subject: Vec<(String, String)>,
    pub issuer: Vec<(String, String)>,
    /// The subjectAltName's DNS names, in order.
    pub dns_names: Vec<String>,
    /// As `getpeercert()` writes them: `Jan  5 12:00:00 2026 GMT`.
    pub not_before: String,
    pub not_after: String,
}

pub trait Tls: Send + Sync {
    /// Connects to `host` on `port` and shakes hands with `host` as the SNI, each step within
    /// `timeout`; the error is the class name of what Python would raise, such as
    /// `ConnectionRefusedError`, `SSLCertVerificationError` or `TimeoutError`.
    fn peer_certificate(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<PeerCertificate, String>;
}

/// What a script does besides the network: wait, and make a random token.
pub trait Pace: Send + Sync {
    /// `time.sleep`.
    fn sleep(&self, duration: Duration);
    /// `uuid.uuid4().hex`: 32 lowercase hex digits.
    fn uuid4_hex(&self) -> String;
}

/// Everything a script's network reaches.
#[derive(Clone)]
pub struct Net {
    pub dns: std::sync::Arc<dyn Dns>,
    pub http: std::sync::Arc<dyn Http>,
    pub tls: std::sync::Arc<dyn Tls>,
    pub pace: std::sync::Arc<dyn Pace>,
}
