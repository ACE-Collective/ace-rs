//! The one HTTP client builder modules use.
//!
//! - Certificates are always verified, with rustls and the platform's roots plus any roots the
//!   caller adds. There is no way to turn verification off (ace3 #1018).
//! - Every request has a timeout, and so does every connect.
//! - Errors are classified in one place (ace3 #1096): `Unavailable` means the peer couldn't be
//!   reached or answered that it is down, so the task can be tried again later. A certificate the
//!   client doesn't trust is `Tls`, never `Unavailable`, because retrying won't fix it.
//! - No proxy is used unless one is set, so proxy variables in the environment change nothing.
//! - Errors carry only the peer's host and port, not the URL, whose query may hold a key.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::time::Duration;

use reqwest::{Certificate, Method, RequestBuilder, Response, StatusCode};

use crate::module::{BoxError, ModuleError};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Builds an `HttpClient`.
#[derive(Debug)]
pub struct HttpClientBuilder {
    timeout: Duration,
    connect_timeout: Duration,
    read_timeout: Option<Duration>,
    extra_roots: Vec<Certificate>,
    proxy: Option<reqwest::Proxy>,
    user_agent: String,
    follow_redirects: bool,
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        HttpClientBuilder {
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: None,
            extra_roots: Vec::new(),
            proxy: None,
            user_agent: concat!("ace-rs/", env!("CARGO_PKG_VERSION")).to_owned(),
            follow_redirects: true,
        }
    }
}

impl HttpClientBuilder {
    pub fn new() -> Self {
        HttpClientBuilder::default()
    }

    /// The whole-request timeout every request gets, from connect to the end of the body.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// The longest a read may wait for the next bytes of a response, as for a long download whose
    /// whole-request timeout is long. None by default: the whole-request timeout bounds it.
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    /// Trusts the CA certificates in a PEM bundle as well as the platform's, such as a TLS
    /// inspection proxy's. Certificates are still verified.
    pub fn add_root_certificates_pem(mut self, pem: &[u8]) -> Result<Self, HttpError> {
        let certs = Certificate::from_pem_bundle(pem).map_err(HttpError::from_reqwest)?;
        self.extra_roots.extend(certs);
        Ok(self)
    }

    /// Sends every request through this proxy.
    pub fn proxy(mut self, url: &str) -> Result<Self, HttpError> {
        self.proxy = Some(reqwest::Proxy::all(url).map_err(HttpError::from_reqwest)?);
        Ok(self)
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Hands a redirect back as its response rather than following it (reqwest follows up to 10),
    /// for a module that decides where it may go next.
    pub fn no_redirects(mut self) -> Self {
        self.follow_redirects = false;
        self
    }

    pub fn build(self) -> Result<HttpClient, HttpError> {
        let mut builder = reqwest::Client::builder()
            .tls_backend_rustls()
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .user_agent(self.user_agent)
            .tls_certs_merge(self.extra_roots);
        if let Some(timeout) = self.read_timeout {
            builder = builder.read_timeout(timeout);
        }
        if !self.follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }
        builder = match self.proxy {
            Some(proxy) => builder.proxy(proxy),
            None => builder.no_proxy(),
        };
        let inner = builder.build().map_err(HttpError::from_reqwest)?;
        Ok(HttpClient { inner })
    }
}

/// An HTTP client whose errors come back classified.
#[derive(Debug, Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
}

impl HttpClient {
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::new()
    }

    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        self.inner.request(method, url)
    }

    pub fn get(&self, url: &str) -> RequestBuilder {
        self.inner.get(url)
    }

    pub fn post(&self, url: &str) -> RequestBuilder {
        self.inner.post(url)
    }

    /// Sends a request made by this client. Any status is a response; `check_status` turns the
    /// ones that are errors into errors.
    pub async fn send(&self, request: RequestBuilder) -> Result<Response, HttpError> {
        request.send().await.map_err(HttpError::from_reqwest)
    }
}

/// Turns an error status into an `HttpError`: 429, 502, 503 and 504 are `Unavailable`, any
/// other 4xx or 5xx is `Status`.
pub fn check_status(response: Response) -> Result<Response, HttpError> {
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        Err(HttpError {
            kind: status_kind(status),
            peer: peer_of(response.url()),
            source: None,
        })
    } else {
        Ok(response)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpErrorKind {
    /// The peer couldn't be reached or said it is down: refused, reset, unreachable, a DNS
    /// failure, a timeout, or a 429, 502, 503 or 504.
    Unavailable,
    /// TLS failed, such as a certificate the client doesn't trust.
    Tls,
    /// An error status that isn't `Unavailable`.
    Status(StatusCode),
    /// Anything else, such as a malformed URL or a body that didn't decode.
    Other,
}

impl fmt::Display for HttpErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpErrorKind::Unavailable => f.write_str("peer unavailable"),
            HttpErrorKind::Tls => f.write_str("TLS failed"),
            HttpErrorKind::Status(status) => write!(f, "HTTP {status}"),
            HttpErrorKind::Other => f.write_str("HTTP request failed"),
        }
    }
}

#[derive(Debug)]
pub struct HttpError {
    kind: HttpErrorKind,
    /// `host:port`, without the path or query.
    peer: Option<String>,
    source: Option<reqwest::Error>,
}

impl HttpError {
    pub fn from_reqwest(error: reqwest::Error) -> Self {
        HttpError {
            kind: classify(&error),
            peer: error.url().and_then(peer_of),
            source: Some(error.without_url()),
        }
    }

    pub fn kind(&self) -> HttpErrorKind {
        self.kind
    }

    pub fn is_unavailable(&self) -> bool {
        self.kind == HttpErrorKind::Unavailable
    }

    pub fn peer(&self) -> Option<&str> {
        self.peer.as_deref()
    }

    /// Whether the peer was reached and then didn't answer in time: a timeout that isn't a
    /// connect's, httpx's `ReadTimeout`, which some callers take as a request that can't finish
    /// rather than a peer that's down. It is `Unavailable` all the same.
    pub fn is_read_timeout(&self) -> bool {
        self.source
            .as_ref()
            .is_some_and(|e| e.is_timeout() && !e.is_connect())
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(peer) = &self.peer {
            write!(f, " ({peer})")?;
        }
        // the whole chain, since reqwest's own message is often just "error sending request"
        let mut next = self.source.as_ref().map(|e| e as &(dyn StdError + 'static));
        while let Some(error) = next {
            write!(f, ": {error}")?;
            next = error.source();
        }
        Ok(())
    }
}

impl StdError for HttpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| e as &(dyn StdError + 'static))
    }
}

impl From<HttpError> for ModuleError {
    fn from(error: HttpError) -> Self {
        if error.is_unavailable() {
            ModuleError::Unavailable(Box::new(error))
        } else {
            ModuleError::Other(Box::new(error) as BoxError)
        }
    }
}

/// The one place an HTTP error is classified.
pub fn classify(error: &reqwest::Error) -> HttpErrorKind {
    let chain = error_chain(error);
    if chain.iter().any(|e| e.is::<rustls::Error>()) {
        return HttpErrorKind::Tls;
    }
    if error.is_timeout() || error.is_connect() || chain.iter().any(|e| is_unavailable_io(*e)) {
        return HttpErrorKind::Unavailable;
    }
    match error.status() {
        Some(status) => status_kind(status),
        None => HttpErrorKind::Other,
    }
}

/// True when any error in `error`'s chain says the peer couldn't be reached, for clients other
/// than HTTP, such as DNS or SMTP.
pub fn peer_unavailable(error: &(dyn StdError + 'static)) -> bool {
    error_chain(error).iter().any(|e| is_unavailable_io(*e))
}

fn status_kind(status: StatusCode) -> HttpErrorKind {
    match status {
        StatusCode::TOO_MANY_REQUESTS
        | StatusCode::BAD_GATEWAY
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::GATEWAY_TIMEOUT => HttpErrorKind::Unavailable,
        _ => HttpErrorKind::Status(status),
    }
}

fn is_unavailable_io(error: &(dyn StdError + 'static)) -> bool {
    error.downcast_ref::<io::Error>().is_some_and(|e| {
        matches!(
            e.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::TimedOut
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::NetworkDown
                | io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::UnexpectedEof
        )
    })
}

/// Every error under `error`. An `io::Error`'s `source()` skips the error it wraps, so that one
/// is added from `get_ref()`.
fn error_chain<'a>(error: &'a (dyn StdError + 'static)) -> Vec<&'a (dyn StdError + 'static)> {
    let mut chain = Vec::new();
    let mut pending = vec![error];
    while let Some(error) = pending.pop() {
        chain.push(error);
        if let Some(inner) = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
        {
            pending.push(inner);
        }
        if let Some(source) = error.source() {
            pending.push(source);
        }
    }
    chain
}

fn peer_of(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}
