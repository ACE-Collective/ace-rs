//! What 5.5's and 5.7's adapters share about a request: which credential it carries, the session cookie,
//! and the CSRF check. It takes header values as strings, so this crate needs no web framework and an
//! extractor in an adapter is one call to `Service::authenticate_request`.
//!
//! CSRF: a browser attaches a cookie to a request another site's page makes, and never a bearer token, so
//! only a session is exposed. `RequestParts::same_origin` is the hook, and is ace3's
//! `_reject_cross_site_cookie_write`: a browser sets `Sec-Fetch-Site` and `Origin`, and a page's script
//! can't forge either. `authenticate_request` applies it to every session, so a route can't forget it.
//! The login route has no session yet, so 5.7 calls `same_origin` itself there, and also has to keep a GET
//! from writing, since a GET passes. ace3 compares hostnames, since its proxy drops the port, which would
//! pass a page on another port of the same host, as ace3 and ace-rs are on a laptop. This compares the port
//! too, so a production proxy must forward `Host` whole.

/// How the browser reached this server. A site behind TLS says so, which turns on `Secure` and the
/// `__Host-` name, and 5.7 reads which from its configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tls,
    Plain,
}

/// The session cookie. `SameSite=Lax` as in ace3, whose comment gives the reason: `Strict` drops the
/// cookie when an analyst follows a link to an alert from a ticket or an email, and `Lax` still withholds
/// it from another site's POST. ace3's own cookie on the same host is `session`, and a browser doesn't
/// keep cookies apart by port, so this name is ace-rs's own.
#[derive(Debug, Clone, Copy)]
pub struct SessionCookie {
    transport: Transport,
}

impl SessionCookie {
    pub fn new(transport: Transport) -> Self {
        SessionCookie { transport }
    }

    pub fn name(&self) -> &'static str {
        match self.transport {
            // A browser only accepts this name from a secure origin, on the whole host, so a subdomain
            // or a plain-HTTP response can't set it.
            Transport::Tls => "__Host-ace_rs_session",
            Transport::Plain => "ace_rs_session",
        }
    }

    fn attributes(&self) -> &'static str {
        match self.transport {
            Transport::Tls => "Path=/; HttpOnly; SameSite=Lax; Secure",
            Transport::Plain => "Path=/; HttpOnly; SameSite=Lax",
        }
    }

    /// The `Set-Cookie` value after a login, ending when the session does.
    pub fn set(&self, session: &super::NewSession) -> String {
        format!(
            "{}={}; Max-Age={}; {}",
            self.name(),
            session.token.expose(),
            super::SESSION_LIFETIME_SECONDS,
            self.attributes()
        )
    }

    /// The `Set-Cookie` value after a logout.
    pub fn clear(&self) -> String {
        format!("{}=; Max-Age=0; {}", self.name(), self.attributes())
    }

    /// This cookie's value in a `Cookie` header.
    pub fn read<'a>(&self, header: &'a str) -> Option<&'a str> {
        header.split(';').find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == self.name()).then_some(value)
        })
    }
}

/// What an adapter passes from a request. A header it doesn't have is None.
#[derive(Debug, Clone, Copy)]
pub struct RequestParts<'a> {
    pub transport: Transport,
    pub method: &'a str,
    pub authorization: Option<&'a str>,
    pub cookie: Option<&'a str>,
    pub sec_fetch_site: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub host: Option<&'a str>,
}

impl RequestParts<'_> {
    /// The CSRF check: whether a request carrying a cookie came from this site's own pages. A method that
    /// can't change anything always passes. A browser request says where it came from, so a request
    /// saying neither thing is refused: a client that isn't a browser uses an API key.
    pub fn same_origin(&self) -> bool {
        if ["GET", "HEAD", "OPTIONS"]
            .iter()
            .any(|safe| self.method.eq_ignore_ascii_case(safe))
        {
            return true;
        }
        if let Some(site) = self.sec_fetch_site {
            // "none" is the user's own navigation, such as a bookmark. "same-site" isn't enough: another
            // port or a subdomain is another application.
            return matches!(site, "same-origin" | "none");
        }
        let authority = self
            .origin
            .and_then(|origin| origin.split_once("://"))
            .map(|(_, authority)| authority);
        match (authority, self.host) {
            (Some(origin), Some(host)) => origin.eq_ignore_ascii_case(host),
            _ => false,
        }
    }

    /// The token of `Authorization: Bearer <token>`, or None for any other scheme.
    pub(super) fn bearer(authorization: &str) -> Option<&str> {
        let (scheme, token) = authorization.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
    }
}
