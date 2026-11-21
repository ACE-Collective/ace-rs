//! The network the hunter's script command types use (PLAN.md decision 16): DNS as dnspython's stub
//! resolver asks (`ace_mod_dns::resolve`, on hickory's wire format), HTTP through ace4's client with
//! verified TLS (`ace_sdk::http`), and a TLS handshake that verifies the chain to the platform's
//! roots but not the name, as Python's `ssl` context without hostname checks does, with rustls. Every call is bounded by the timeout
//! it's given. The engine runs a correlation on a blocking thread, so each call runs on a runtime of
//! its own, on a thread of its own, and works under `block_in_place` or anywhere else.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ace_hunt::correlate::net::{
    Dns, DnsAnswer, DnsFailure, DnsRecord, Http, HttpFailure, HttpReply, HttpRequest, Net, Pace,
    PeerCertificate, Tls,
};
use ace_mod_dns::resolve::{Reply, ResolveError, name_of, resolve, to_text};
use ace_sdk::http::HttpClient;
use hickory_proto::rr::{Name, RData, RecordType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};

/// The most of a response body read when the caller sets no limit.
const MAX_BODY: usize = 16 << 20;

/// Runs `future` to its end on a runtime of its own.
fn block_on<F: std::future::Future + Send>(future: F) -> F::Output
where
    F::Output: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime")
                    .block_on(future)
            })
            .join()
            .expect("the network call doesn't panic")
    })
}

/// The hunter's network for its script types.
pub fn net() -> anyhow::Result<Net> {
    let http = HttpClient::builder()
        .build()
        .map_err(|e| anyhow::anyhow!("the scripts' HTTP client: {e}"))?;
    let tls = RealTls::new();
    Ok(Net {
        dns: Arc::new(RealDns),
        http: Arc::new(RealHttp { client: http }),
        tls: Arc::new(tls),
        pace: Arc::new(RealPace),
    })
}

struct RealDns;

/// dnspython's exception for a name it can't ask about.
fn name_failure(name: &str) -> DnsFailure {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if name.len() > 255 {
        DnsFailure::new("NameTooLong", "The DNS name is too long")
    } else if trimmed.split('.').any(|l| l.len() > 63) {
        DnsFailure::new("LabelTooLong", "A DNS label is > 63 octets long.")
    } else if trimmed.split('.').any(str::is_empty) {
        DnsFailure::new("EmptyLabel", "A DNS label is empty.")
    } else {
        DnsFailure::new("IDNAException", "the name can't be encoded")
    }
}

impl Dns for RealDns {
    fn resolve(
        &self,
        name: &str,
        rtype: &str,
        nameservers: Option<&[String]>,
        lifetime: Duration,
    ) -> Result<DnsAnswer, DnsFailure> {
        let kind: RecordType = rtype.parse().map_err(|_| {
            DnsFailure::new("UnknownRdatatype", "DNS resource record type is unknown.")
        })?;
        let servers: Vec<SocketAddr> = match nameservers {
            None => ace_mod_dns::resolv_conf_nameservers(
                &std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default(),
            ),
            Some(list) => list
                .iter()
                .map(|s| {
                    s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)).map_err(|_| {
                        DnsFailure::new(
                            "ValueError",
                            format!("nameserver {s} is not a dns.nameserver.Nameserver instance or text form, IP address, nor a valid https URL"),
                        )
                    })
                })
                .collect::<Result<_, _>>()?,
        };
        let query = name_of(name).map_err(|_| name_failure(name))?;
        match block_on(resolve(&servers, &query, kind, lifetime)) {
            Ok(Reply::Records(records, _)) => {
                Ok(DnsAnswer::Records(records.iter().map(record).collect()))
            }
            Ok(Reply::NxDomain) => Ok(DnsAnswer::NxDomain),
            Ok(Reply::NoAnswer) => Ok(DnsAnswer::NoAnswer),
            Err(ResolveError::NoNameservers(asked, why)) => Err(DnsFailure::new(
                "NoNameservers",
                format!("All nameservers failed to answer the query {asked}: {why}"),
            )),
            // dnspython keeps asking a nameserver it can't reach, as one that doesn't answer, until
            // the lifetime runs out (dnspython 2.9.0, a refused or unroutable server alike)
            Err(ResolveError::Unreachable(..)) => Err(DnsFailure::new(
                "LifetimeTimeout",
                format!(
                    "The resolution lifetime expired after {:.3} seconds",
                    lifetime.as_secs_f64()
                ),
            )),
            Err(ResolveError::BadName(_)) => Err(name_failure(name)),
        }
    }
}

/// A name as dnspython writes an absolute one in a record: with its trailing dot.
fn absolute(name: &Name) -> String {
    format!("{}.", to_text(name))
}

/// dnspython's `_escapify` of a character-string.
fn escapify(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if b == b'"' || b == b'\\' {
            out.push('\\');
            out.push(char::from(b));
        } else if (0x20..0x7f).contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("\\{b:03}"));
        }
    }
    out
}

/// A record as the scripts read a dnspython rdata: its `to_text()`, a TXT's strings, an MX's,
/// NS's, CNAME's or PTR's target.
pub fn record(data: &RData) -> DnsRecord {
    let (text, strings, target) = match data {
        RData::A(a) => (a.0.to_string(), Vec::new(), None),
        RData::AAAA(a) => (a.0.to_string(), Vec::new(), None),
        RData::MX(mx) => (
            format!("{} {}", mx.preference, absolute(&mx.exchange)),
            Vec::new(),
            Some(absolute(&mx.exchange)),
        ),
        RData::NS(ns) => (absolute(&ns.0), Vec::new(), Some(absolute(&ns.0))),
        RData::CNAME(c) => (absolute(&c.0), Vec::new(), Some(absolute(&c.0))),
        RData::PTR(p) => (absolute(&p.0), Vec::new(), Some(absolute(&p.0))),
        RData::TXT(txt) => {
            let strings: Vec<Vec<u8>> = txt.txt_data.iter().map(|s| s.to_vec()).collect();
            let text = strings
                .iter()
                .map(|s| format!("\"{}\"", escapify(s)))
                .collect::<Vec<_>>()
                .join(" ");
            (text, strings, None)
        }
        RData::SRV(srv) => (
            format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                absolute(&srv.target)
            ),
            Vec::new(),
            None,
        ),
        RData::SOA(soa) => (
            format!(
                "{} {} {} {} {} {} {}",
                absolute(&soa.mname),
                absolute(&soa.rname),
                soa.serial,
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.minimum
            ),
            Vec::new(),
            None,
        ),
        other => (other.to_string(), Vec::new(), None),
    };
    DnsRecord {
        text,
        strings,
        target,
    }
}

struct RealHttp {
    client: HttpClient,
}

/// What urllib raises for a request that got no response.
fn http_failure(error: &reqwest::Error) -> HttpFailure {
    if error.is_timeout() {
        return HttpFailure {
            kind: "TimeoutError".to_owned(),
            detail: "timed out".to_owned(),
        };
    }
    let mut detail = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(s) = source {
        detail = s.to_string();
        source = s.source();
    }
    HttpFailure {
        kind: "URLError".to_owned(),
        detail,
    }
}

impl Http for RealHttp {
    fn request(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpFailure> {
        let method =
            reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|e| HttpFailure {
                kind: "ValueError".to_owned(),
                detail: e.to_string(),
            })?;
        let mut builder = self
            .client
            .request(method, request.url)
            .timeout(request.timeout);
        for (name, value) in request.headers {
            builder = builder.header(*name, *value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body.to_vec());
        }
        let limit = request.read_limit.unwrap_or(MAX_BODY).min(MAX_BODY);
        block_on(async {
            let mut response = builder.send().await.map_err(|e| http_failure(&e))?;
            let status = response.status().as_u16();
            let url = response.url().to_string();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let mut body = Vec::new();
            while body.len() < limit {
                match response.chunk().await.map_err(|e| http_failure(&e))? {
                    Some(chunk) => body.extend_from_slice(&chunk),
                    None => break,
                }
            }
            body.truncate(limit);
            Ok(HttpReply {
                status,
                url,
                content_type,
                body,
            })
        })
    }
}

/// Verifies a server's chain to the platform's roots, and not that it names the host, as Python's
/// `ssl` does with `check_hostname` off: the chain is checked first, so a certificate that only
/// fails on its name has a valid chain.
#[derive(Debug)]
struct ChainOnly(Arc<rustls::client::WebPkiServerVerifier>);

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self
            .0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

struct RealTls {
    /// The client, or why there is none, such as a platform with no roots, which fails each
    /// handshake rather than the hunter.
    config: Result<Arc<rustls::ClientConfig>, String>,
}

impl RealTls {
    fn new() -> RealTls {
        let mut roots = rustls::RootCertStore::empty();
        // a root the platform lists that rustls can't read is skipped, as OpenSSL skips it
        let (_added, _skipped) =
            roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        RealTls::with_roots(roots)
    }

    fn with_roots(roots: rustls::RootCertStore) -> RealTls {
        let config = RealTls::client(roots).map_err(|e| {
            tracing::error!("the script types' TLS client can't be built: {e}");
            e.to_string()
        });
        RealTls { config }
    }

    fn client(roots: rustls::RootCertStore) -> anyhow::Result<Arc<rustls::ClientConfig>> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()?;
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ChainOnly(verifier)))
            .with_no_client_auth();
        Ok(Arc::new(config))
    }
}

/// What Python raises for a failed connection or handshake.
fn io_failure(error: &std::io::Error) -> String {
    use std::io::ErrorKind;
    if let Some(inner) = error.get_ref()
        && let Some(tls) = inner.downcast_ref::<rustls::Error>()
    {
        return match tls {
            rustls::Error::InvalidCertificate(_) => "SSLCertVerificationError",
            _ => "SSLError",
        }
        .to_owned();
    }
    match error.kind() {
        ErrorKind::ConnectionRefused => "ConnectionRefusedError",
        ErrorKind::ConnectionReset => "ConnectionResetError",
        ErrorKind::TimedOut => "TimeoutError",
        ErrorKind::UnexpectedEof => "SSLEOFError",
        _ => "OSError",
    }
    .to_owned()
}

/// `getpeercert()`'s date: `Jan  5 12:00:00 2026 GMT`.
fn openssl_date(t: &ace_x509::DateTime) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{} {:>2} {:02}:{:02}:{:02} {} GMT",
        MONTHS[usize::from(t.month.clamp(1, 12)) - 1],
        t.day,
        t.hour,
        t.minute,
        t.second,
        t.year
    )
}

fn attributes(name: &ace_x509::Name) -> Vec<(String, String)> {
    name.attributes()
        .filter_map(|a| match &a.value {
            ace_x509::AttrValue::Str(v) => Some((ace_x509::oid_name(&a.oid).to_owned(), v.clone())),
            ace_x509::AttrValue::Bytes(_) => None,
        })
        .collect()
}

/// The certificate as `getpeercert()` gives it.
pub fn peer_certificate(der: &[u8]) -> Result<PeerCertificate, String> {
    let fail = |_| "SSLError".to_owned();
    let cert = ace_x509::load_der_x509_certificate(der).map_err(fail)?;
    Ok(PeerCertificate {
        der: der.to_vec(),
        subject: attributes(&cert.subject().map_err(fail)?),
        issuer: attributes(&cert.issuer().map_err(fail)?),
        dns_names: cert.san_dns_names().unwrap_or_default(),
        not_before: openssl_date(&cert.not_valid_before_utc().map_err(fail)?),
        not_after: openssl_date(&cert.not_valid_after_utc().map_err(fail)?),
    })
}

impl Tls for RealTls {
    fn peer_certificate(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<PeerCertificate, String> {
        let server_name =
            ServerName::try_from(host.to_owned()).map_err(|_| "UnicodeError".to_owned())?;
        let config = self.config.clone().map_err(|_| "SSLError".to_owned())?;
        let connector = tokio_rustls::TlsConnector::from(config);
        let der = block_on(async move {
            let address = format!("{host}:{port}");
            let addresses: Vec<SocketAddr> =
                tokio::time::timeout(timeout, tokio::net::lookup_host(address))
                    .await
                    .map_err(|_| "TimeoutError".to_owned())?
                    .map_err(|_| "gaierror".to_owned())?
                    .collect();
            let mut last = "gaierror".to_owned();
            let mut stream = None;
            for address in addresses {
                match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
                    Ok(Ok(s)) => {
                        stream = Some(s);
                        break;
                    }
                    Ok(Err(e)) => last = io_failure(&e),
                    Err(_) => last = "TimeoutError".to_owned(),
                }
            }
            let stream = stream.ok_or(last)?;
            let tls = tokio::time::timeout(timeout, connector.connect(server_name, stream))
                .await
                .map_err(|_| "TimeoutError".to_owned())?
                .map_err(|e| io_failure(&e))?;
            let (_, connection) = tls.get_ref();
            connection
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.to_vec())
                .ok_or_else(|| "SSLError".to_owned())
        })?;
        peer_certificate(&der)
    }
}

struct RealPace;

impl Pace for RealPace {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn uuid4_hex(&self) -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{CNAME, MX, NS, SRV, TXT};

    fn name(text: &str) -> Name {
        Name::from_ascii(text).expect("a name")
    }

    /// Records read as dnspython writes them (checked against dnspython 2.9.0's `to_text()`).
    #[test]
    fn records_read_as_dnspython_writes_them() {
        let mx = record(&RData::MX(MX::new(10, name("mx1.example.com."))));
        assert_eq!(mx.text, "10 mx1.example.com.");
        assert_eq!(mx.target.as_deref(), Some("mx1.example.com."));
        let txt = record(&RData::TXT(TXT::new(vec![
            "v=spf1 \"quoted\" \\ -all".to_owned(),
            "caf\u{e9}".to_owned(),
        ])));
        assert_eq!(txt.text, r#""v=spf1 \"quoted\" \\ -all" "caf\195\169""#);
        assert_eq!(txt.strings.len(), 2);
        let ns = record(&RData::NS(NS(name("ns1.example.com."))));
        assert_eq!(ns.text, "ns1.example.com.");
        let cname = record(&RData::CNAME(CNAME(name("a.example.com."))));
        assert_eq!(cname.target.as_deref(), Some("a.example.com."));
        let srv = record(&RData::SRV(SRV::new(
            100,
            1,
            5061,
            name("sip.example.com."),
        )));
        assert_eq!(srv.text, "100 1 5061 sip.example.com.");
        let aaaa = record(&RData::AAAA(hickory_proto::rr::rdata::AAAA(
            "2001:db8::7".parse().expect("an address"),
        )));
        assert_eq!(aaaa.text, "2001:db8::7");
    }

    #[test]
    fn dates_read_as_getpeercert_writes_them() {
        let t = ace_x509::DateTime {
            year: 2026,
            month: 1,
            day: 5,
            hour: 7,
            minute: 8,
            second: 9,
            microsecond: 0,
        };
        assert_eq!(openssl_date(&t), "Jan  5 07:08:09 2026 GMT");
    }

    /// Serves `chain` with `key` on a port of its own, for one handshake each time.
    fn tls_server(
        chain: Vec<CertificateDer<'static>>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> u16 {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("a server config");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("an address").port();
        let config = Arc::new(config);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut connection =
                    rustls::ServerConnection::new(config.clone()).expect("a connection");
                let mut stream = stream;
                // the handshake, or the client giving up on it
                while connection.is_handshaking() {
                    if connection.complete_io(&mut stream).is_err() {
                        break;
                    }
                }
            }
        });
        port
    }

    /// The chain is verified and the name isn't, as Python's `ssl` does with `check_hostname`
    /// off; an untrusted certificate is an error, never read.
    #[test]
    fn a_certificate_is_read_only_with_a_trusted_chain() {
        let ca_key = rcgen::KeyPair::generate().expect("a key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Test Roots");
        let ca_cert = ca_params.self_signed(&ca_key).expect("a CA");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let leaf_key = rcgen::KeyPair::generate().expect("a key");
        let mut leaf_params = rcgen::CertificateParams::new(vec![
            "other.test".to_owned(),
            "www.other.test".to_owned(),
        ])
        .expect("params");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "other.test");
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("a leaf");
        let key = || {
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                leaf_key.serialize_der(),
            ))
        };
        let port = tls_server(vec![leaf.der().clone(), ca_cert.der().clone()], key());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_cert.der().clone()).expect("a root");
        let trusting = RealTls::with_roots(roots);
        // reached as localhost, a name the certificate doesn't have
        let cert = trusting
            .peer_certificate("localhost", port, Duration::from_secs(5))
            .expect("the certificate");
        assert_eq!(cert.dns_names, ["other.test", "www.other.test"]);
        assert_eq!(
            cert.subject,
            [("commonName".to_owned(), "other.test".to_owned())]
        );
        assert!(
            cert.issuer
                .contains(&("organizationName".to_owned(), "Test Roots".to_owned()))
        );
        assert_eq!(cert.der, leaf.der().to_vec());
        assert!(cert.not_after.ends_with(" GMT"));

        // trusting another root only
        let other_key = rcgen::KeyPair::generate().expect("a key");
        let mut other = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        other.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut other_roots = rustls::RootCertStore::empty();
        other_roots
            .add(other.self_signed(&other_key).expect("a CA").der().clone())
            .expect("a root");
        let untrusting = RealTls::with_roots(other_roots);
        assert_eq!(
            untrusting.peer_certificate("localhost", port, Duration::from_secs(5)),
            Err("SSLCertVerificationError".to_owned())
        );
        // no roots: each handshake fails, and the hunter doesn't
        assert_eq!(
            RealTls::with_roots(rustls::RootCertStore::empty()).peer_certificate(
                "localhost",
                port,
                Duration::from_secs(5)
            ),
            Err("SSLError".to_owned())
        );
        // nothing listening
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let closed_port = closed.local_addr().expect("an address").port();
        drop(closed);
        assert_eq!(
            trusting.peer_certificate("localhost", closed_port, Duration::from_secs(5)),
            Err("ConnectionRefusedError".to_owned())
        );
    }

    #[test]
    fn a_bad_name_fails_as_dnspython_s_does() {
        assert_eq!(name_failure("a..b").kind, "EmptyLabel");
        assert_eq!(
            name_failure(&format!("{}.com", "a".repeat(64))).kind,
            "LabelTooLong"
        );
        let result = RealDns.resolve("ok.test", "BOGUS", None, Duration::from_millis(1));
        assert_eq!(
            result.map_err(|e| e.kind),
            Err("UnknownRdatatype".to_owned())
        );
        let result = RealDns.resolve(
            "ok.test",
            "A",
            Some(&["not-an-ip".to_owned()]),
            Duration::from_millis(1),
        );
        assert_eq!(result.map_err(|e| e.kind), Err("ValueError".to_owned()));
    }
}
