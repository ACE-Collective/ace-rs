//! A fake LDAP server for the user analyzer's tests (PLAN.md 7.4), serving the same directory
//! fixture the same way as `tools/ace3/dumps/fake_ldap.py`, which answered ace3 for its reference
//! dumps: a simple bind with the fixture's DN and password, base searches of the root DSE and the
//! schema entry, subtree and one-level searches matching equality, presence, substring, and, or and
//! not filters without regard to case, the simple paged results control (RFC 2696) with an optional
//! limit on a page, and an unbind. Every search is recorded as the Python fake records it, so a
//! test can check the module asked what ace3 asked.
//!
//! It serves plain LDAP, LDAPS with a certificate for `localhost` made for the run, or plain LDAP
//! that refuses a bind until StartTLS (RFC 4513) has upgraded the connection, so a test can show
//! the module verifies the certificate it's given and never sends its password in the clear.

use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::HarnessError;

const PAGED: &str = "1.2.840.113556.1.4.319";
const START_TLS: &str = "1.3.6.1.4.1.1466.20037";

/// How the fake carries LDAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Plain LDAP, as ace3 binds.
    Plain,
    /// TLS from the first byte.
    Ldaps,
    /// Plain LDAP that refuses a bind (confidentialityRequired) until StartTLS.
    StartTls,
}

#[derive(Debug, Clone, Deserialize)]
struct Directory {
    bind_dn: String,
    bind_password: String,
    schema_dn: String,
    root_dse: Map<String, Value>,
    schema: Map<String, Value>,
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, Deserialize)]
struct Entry {
    dn: String,
    attributes: Map<String, Value>,
}

#[derive(Default)]
struct Log {
    searches: Vec<Value>,
    binds: Vec<(String, bool)>,
}

struct State {
    directory: Directory,
    page_limit: usize,
    log: Mutex<Log>,
}

/// A running fake LDAP server on 127.0.0.1.
pub struct LdapFake {
    port: u16,
    transport: Transport,
    ca_pem: Option<String>,
    state: Arc<State>,
    task: JoinHandle<()>,
}

impl LdapFake {
    /// Serves `directory` (the fixture's JSON) over `transport`, with at most `page_limit` entries
    /// a page when it isn't 0.
    pub async fn start(
        directory: &Path,
        transport: Transport,
        page_limit: usize,
    ) -> Result<LdapFake, HarnessError> {
        let text = std::fs::read_to_string(directory)
            .map_err(|e| HarnessError::Fixture(format!("{}: {e}", directory.display())))?;
        let directory: Directory = serde_json::from_str(&text)
            .map_err(|e| HarnessError::Fixture(format!("{}: {e}", directory.display())))?;
        let state = Arc::new(State {
            directory,
            page_limit,
            log: Mutex::default(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let (acceptor, ca_pem) = if transport == Transport::Plain {
            (None, None)
        } else {
            let (acceptor, pem) = tls_acceptor()?;
            (Some(acceptor), Some(pem))
        };
        let served = state.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = served.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match (transport, acceptor) {
                        (Transport::Ldaps, Some(acceptor)) => {
                            let served = match acceptor.accept(stream).await {
                                Ok(tls) => serve(tls, &state, false).await.map(|_| ()),
                                Err(e) => Err(e),
                            };
                            if let Err(e) = served {
                                eprintln!("fake ldap: {e}");
                            }
                        }
                        (Transport::StartTls, Some(acceptor)) => {
                            if let Err(e) = serve_start_tls(stream, &state, acceptor).await {
                                eprintln!("fake ldap: {e}");
                            }
                        }
                        _ => {
                            if let Err(e) = serve(stream, &state, false).await {
                                eprintln!("fake ldap: {e}");
                            }
                        }
                    }
                });
            }
        });
        Ok(LdapFake {
            port,
            transport,
            ca_pem,
            state,
            task,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The server's URL: `ldaps://localhost:<port>` for LDAPS, `ldap://...` otherwise, with
    /// `localhost`, the name its certificate is for, when it has one.
    pub fn url(&self) -> String {
        match self.transport {
            Transport::Plain => format!("ldap://127.0.0.1:{}", self.port),
            Transport::Ldaps => format!("ldaps://localhost:{}", self.port),
            Transport::StartTls => format!("ldap://localhost:{}", self.port),
        }
    }

    /// The PEM of the certificate the server presents, for a client to trust.
    pub fn ca_pem(&self) -> Option<&str> {
        self.ca_pem.as_deref()
    }

    /// Every search, in order, as `fake_ldap.py` records them.
    pub fn searches(&self) -> Vec<Value> {
        self.state
            .log
            .lock()
            .map(|l| l.searches.clone())
            .unwrap_or_default()
    }

    /// Every bind, as its DN and whether it succeeded.
    pub fn binds(&self) -> Vec<(String, bool)> {
        self.state
            .log
            .lock()
            .map(|l| l.binds.clone())
            .unwrap_or_default()
    }
}

impl Drop for LdapFake {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn tls_acceptor() -> Result<(tokio_rustls::TlsAcceptor, String), HarnessError> {
    let fixture = |e: &dyn std::fmt::Display| HarnessError::Fixture(format!("a TLS setup: {e}"));
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|e| fixture(&e))?;
    let pem = certified.cert.pem();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| fixture(&e))?
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key)
    .map_err(|e| fixture(&e))?;
    Ok((tokio_rustls::TlsAcceptor::from(Arc::new(config)), pem))
}

// ---- BER ----

fn ber_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    let mut out = vec![0x80 | (bytes.len() - skip) as u8];
    out.extend_from_slice(&bytes[skip..]);
    out
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(ber_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn ber_int(tag: u8, value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7
        && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
    {
        start += 1;
    }
    tlv(tag, &bytes[start..])
}

/// One TLV at `pos`: its tag, its content and the position after it, or None when `data` holds
/// less than all of it.
fn read_tlv(data: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *data.get(pos)?;
    let first = *data.get(pos + 1)? as usize;
    let mut at = pos + 2;
    let length = if first & 0x80 != 0 {
        let count = first & 0x7f;
        let bytes = data.get(at..at + count)?;
        at += count;
        bytes.iter().fold(0usize, |n, b| (n << 8) | *b as usize)
    } else {
        first
    };
    let content = data.get(at..at + length)?;
    Some((tag, content, at + length))
}

fn children(content: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some((tag, value, next)) = read_tlv(content, pos) {
        out.push((tag, value));
        pos = next;
    }
    out
}

fn as_int(content: &[u8]) -> i64 {
    if content.is_empty() {
        return 0;
    }
    let negative = content[0] & 0x80 != 0;
    content
        .iter()
        .fold(if negative { -1i64 } else { 0 }, |n, b| {
            (n << 8) | *b as i64
        })
}

fn text(content: &[u8]) -> String {
    String::from_utf8_lossy(content).into_owned()
}

// ---- filters ----

fn escape(value: &[u8]) -> String {
    value
        .iter()
        .map(|&b| {
            if b"*()\\\0".contains(&b) || b > 0x7f {
                format!("\\{b:02x}")
            } else {
                char::from(b).to_string()
            }
        })
        .collect()
}

fn filter_text(tag: u8, content: &[u8]) -> String {
    match tag {
        0xa0 | 0xa1 => {
            let op = if tag == 0xa0 { '&' } else { '|' };
            let inner: String = children(content)
                .iter()
                .map(|(t, c)| filter_text(*t, c))
                .collect();
            format!("({op}{inner})")
        }
        0xa2 => {
            let inner = children(content)
                .first()
                .map(|(t, c)| filter_text(*t, c))
                .unwrap_or_default();
            format!("(!{inner})")
        }
        0xa3 => {
            let parts = children(content);
            format!("({}={})", text(parts[0].1), escape(parts[1].1))
        }
        0x87 => format!("({}=*)", text(content)),
        0xa4 => {
            let parts = children(content);
            let (mut initial, mut any, mut last) = (String::new(), Vec::new(), String::new());
            for (t, c) in children(parts[1].1) {
                match t {
                    0x80 => initial = escape(c),
                    0x81 => any.push(escape(c)),
                    _ => last = escape(c),
                }
            }
            let middle: String = any.iter().map(|a| format!("{a}*")).collect();
            format!("({}={initial}*{middle}{last})", text(parts[0].1))
        }
        other => format!("(unsupported filter {other:#x})"),
    }
}

fn raw(value: &Value) -> Vec<u8> {
    match value {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Object(o) => o
            .get("hex")
            .and_then(Value::as_str)
            .map(|h| {
                (0..h.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok())
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn values_of(entry: &Entry, name: &str) -> Vec<Vec<u8>> {
    entry
        .attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.as_array())
        .map(|values| values.iter().map(raw).collect())
        .unwrap_or_default()
}

fn lower(bytes: &[u8]) -> Vec<u8> {
    // Python's bytes.lower(): ASCII only
    bytes.to_ascii_lowercase()
}

fn matches(entry: &Entry, tag: u8, content: &[u8]) -> bool {
    match tag {
        0xa0 => children(content).iter().all(|(t, c)| matches(entry, *t, c)),
        0xa1 => children(content).iter().any(|(t, c)| matches(entry, *t, c)),
        0xa2 => !children(content)
            .first()
            .is_some_and(|(t, c)| matches(entry, *t, c)),
        0xa3 => {
            let parts = children(content);
            let wanted = lower(parts[1].1);
            values_of(entry, &text(parts[0].1))
                .iter()
                .any(|v| lower(v) == wanted)
        }
        0x87 => {
            let name = text(content);
            !values_of(entry, &name).is_empty() || name.eq_ignore_ascii_case("objectclass")
        }
        0xa4 => {
            let parts = children(content);
            let subs = children(parts[1].1);
            values_of(entry, &text(parts[0].1)).iter().any(|value| {
                let value = lower(value);
                let mut pos = 0usize;
                subs.iter().all(|(t, c)| {
                    let c = lower(c);
                    match t {
                        0x80 => {
                            pos = c.len();
                            value.starts_with(&c)
                        }
                        0x81 => match find(&value, &c, pos) {
                            Some(found) => {
                                pos = found + c.len();
                                true
                            }
                            None => false,
                        },
                        _ => value.ends_with(&c) && value.len() - c.len() >= pos,
                    }
                })
            })
        }
        _ => false,
    }
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len().max(1))
        .position(|w| w == needle)
        .map(|p| p + from)
        .or_else(|| needle.is_empty().then_some(from))
}

// ---- answers ----

fn under(dn: &str, base: &str) -> bool {
    let (dn, base) = (dn.to_lowercase(), base.to_lowercase());
    dn == base || dn.ends_with(&format!(",{base}"))
}

fn entry_message(dn: &str, attributes: &Map<String, Value>, wanted: &[String]) -> Vec<u8> {
    let everything = wanted.is_empty() || wanted.iter().any(|w| w == "*");
    let mut encoded = Vec::new();
    for (name, values) in attributes {
        if !everything && !wanted.contains(&name.to_lowercase()) {
            continue;
        }
        let vals: Vec<u8> = values
            .as_array()
            .map(|vs| vs.iter().flat_map(|v| tlv(0x04, &raw(v))).collect())
            .unwrap_or_default();
        let mut attribute = tlv(0x04, name.as_bytes());
        attribute.extend(tlv(0x31, &vals));
        encoded.extend(tlv(0x30, &attribute));
    }
    let mut content = tlv(0x04, dn.as_bytes());
    content.extend(tlv(0x30, &encoded));
    tlv(0x64, &content)
}

fn result(tag: u8, code: i64, message: &str) -> Vec<u8> {
    let mut content = ber_int(0x0a, code);
    content.extend(tlv(0x04, b""));
    content.extend(tlv(0x04, message.as_bytes()));
    tlv(tag, &content)
}

fn message(id: i64, op: &[u8], controls: Option<&[u8]>) -> Vec<u8> {
    let mut content = ber_int(0x02, id);
    content.extend_from_slice(op);
    if let Some(controls) = controls {
        content.extend(tlv(0xa0, controls));
    }
    tlv(0x30, &content)
}

impl State {
    /// A search's entries and, when it was paged, the cookie of the next page ("" when none).
    fn search(&self, op: &[u8], controls: &[&[u8]]) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
        let fields = children(op);
        let base = text(fields[0].1);
        let scope = as_int(fields[1].1);
        let (filter_tag, filter_content) = fields[6];
        let requested: Vec<String> = children(fields[7].1).iter().map(|(_, v)| text(v)).collect();
        let wanted: Vec<String> = requested.iter().map(|w| w.to_lowercase()).collect();
        let mut paging = None;
        for control in controls {
            let parts = children(control);
            if parts.first().map(|(_, oid)| text(oid)).as_deref() == Some(PAGED)
                && let Some((_, value)) = parts.last()
                && let Some((_, sequence)) = children(value).first().copied()
            {
                let inner = children(sequence);
                if let [(_, size), (_, cookie)] = inner.as_slice() {
                    paging = Some((as_int(size), cookie.to_vec()));
                }
            }
        }
        let scope_name = ["base", "one", "subtree"]
            .get(scope as usize)
            .copied()
            .unwrap_or("?");
        if let Ok(mut log) = self.log.lock() {
            log.searches.push(json!({
                "base": base,
                "scope": scope_name,
                "filter": filter_text(filter_tag, filter_content),
                "attributes": requested,
                "paged": paging.as_ref().map(|(size, cookie)| json!({"size": size, "cookie": text(cookie)})),
            }));
        }
        let directory = &self.directory;
        if scope == 0 {
            if base.is_empty() {
                return (vec![entry_message(&base, &directory.root_dse, &[])], None);
            }
            if base.eq_ignore_ascii_case(&directory.schema_dn) {
                return (vec![entry_message(&base, &directory.schema, &[])], None);
            }
        }
        let mut found: Vec<&Entry> = directory
            .entries
            .iter()
            .filter(|e| match scope {
                0 => e.dn.eq_ignore_ascii_case(&base),
                1 => under(&e.dn, &base) && !e.dn.eq_ignore_ascii_case(&base),
                _ => under(&e.dn, &base),
            })
            .filter(|e| matches(e, filter_tag, filter_content))
            .collect();
        let mut cookie_out = None;
        if let Some((size, cookie)) = paging {
            let start: usize = text(&cookie).parse().unwrap_or(0);
            let mut size = usize::try_from(size).unwrap_or(0);
            if self.page_limit > 0 {
                size = size.min(self.page_limit);
            }
            let end = if size == 0 {
                found.len()
            } else {
                (start + size).min(found.len())
            };
            cookie_out = Some(if end < found.len() {
                end.to_string().into_bytes()
            } else {
                Vec::new()
            });
            found = found.get(start..end).map(<[_]>::to_vec).unwrap_or_default();
        }
        (
            found
                .iter()
                .map(|e| entry_message(&e.dn, &e.attributes, &wanted))
                .collect(),
            cookie_out,
        )
    }
}

/// What a message asks for, as the connection should go on.
enum Next {
    Continue,
    Close,
    StartTls,
}

async fn answer<S: AsyncWrite + Unpin>(
    stream: &mut S,
    state: &State,
    message_bytes: &[u8],
    tls_required: bool,
    can_start_tls: bool,
) -> std::io::Result<Next> {
    let parts = children(message_bytes);
    let (Some((_, id)), Some((op_tag, op))) = (parts.first(), parts.get(1)) else {
        return Ok(Next::Close);
    };
    let id = as_int(id);
    let controls: Vec<&[u8]> = match parts.get(2) {
        Some((0xa0, controls)) => children(controls).into_iter().map(|(_, c)| c).collect(),
        _ => Vec::new(),
    };
    match *op_tag {
        0x60 => {
            let fields = children(op);
            let dn = text(fields.get(1).map(|f| f.1).unwrap_or_default());
            let password = text(fields.get(2).map(|f| f.1).unwrap_or_default());
            let response = if tls_required {
                result(0x61, 13, "confidentiality required")
            } else {
                let ok = dn == state.directory.bind_dn && password == state.directory.bind_password;
                if let Ok(mut log) = state.log.lock() {
                    log.binds.push((dn.clone(), ok));
                }
                if ok {
                    result(0x61, 0, "")
                } else {
                    result(0x61, 49, "invalid credentials")
                }
            };
            stream.write_all(&message(id, &response, None)).await?;
        }
        0x42 => return Ok(Next::Close),
        0x63 => {
            let (entries, cookie) = state.search(op, &controls);
            for entry in entries {
                stream.write_all(&message(id, &entry, None)).await?;
            }
            let done = result(0x65, 0, "");
            let control = cookie.map(|cookie| {
                let mut inner = ber_int(0x02, 0);
                inner.extend(tlv(0x04, &cookie));
                let mut control = tlv(0x04, PAGED.as_bytes());
                control.extend(tlv(0x04, &tlv(0x30, &inner)));
                tlv(0x30, &control)
            });
            stream
                .write_all(&message(id, &done, control.as_deref()))
                .await?;
        }
        0x77 => {
            let name = children(op)
                .first()
                .map(|(_, n)| text(n))
                .unwrap_or_default();
            if name == START_TLS && can_start_tls {
                let mut content = ber_int(0x0a, 0);
                content.extend(tlv(0x04, b""));
                content.extend(tlv(0x04, b""));
                stream
                    .write_all(&message(id, &tlv(0x78, &content), None))
                    .await?;
                return Ok(Next::StartTls);
            }
            stream
                .write_all(&message(
                    id,
                    &result(0x78, 2, "unsupported operation"),
                    None,
                ))
                .await?;
        }
        other => {
            stream
                .write_all(&message(
                    id,
                    &result(other.wrapping_add(1), 2, "unsupported operation"),
                    None,
                ))
                .await?;
        }
    }
    Ok(Next::Continue)
}

/// Reads and answers messages until the client unbinds or goes away, or asks for StartTLS.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    state: &State,
    tls_required: bool,
) -> std::io::Result<Next> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        while let Some((_, content, end)) = read_tlv(&buffer, 0) {
            let content = content.to_vec();
            buffer.drain(..end);
            match answer(&mut stream, state, &content, tls_required, tls_required).await? {
                Next::Continue => {}
                other => return Ok(other),
            }
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(Next::Close);
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
}

async fn serve_start_tls(
    stream: TcpStream,
    state: &State,
    acceptor: tokio_rustls::TlsAcceptor,
) -> std::io::Result<()> {
    let mut stream = stream;
    if let Next::StartTls = serve(&mut stream, state, true).await? {
        let tls = acceptor.accept(stream).await?;
        serve(tls, state, false).await?;
    }
    Ok(())
}
