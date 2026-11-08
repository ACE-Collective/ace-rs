//! The security headers on every GUI response.
//!
//! The Content-Security-Policy, and why each part is there:
//! - `script-src 'self' 'nonce-<n>'`, with a new random nonce for each response. Datastar evaluates
//!   each `data-*` expression as code. With no nonce it compiles them with `Function(...)`, which needs
//!   `'unsafe-eval'`. Datastar 1.0.4 has a second way, which this uses: when `<html>` carries
//!   `data-nonce`, it reads the nonce, removes the attribute, and compiles each expression in a
//!   `<script>` element carrying that nonce. So no `'unsafe-eval'` and no `'unsafe-inline'`: a string an
//!   attacker gets into `eval`, `setTimeout` or an inline handler still doesn't run. What Datastar runs
//!   is what is in the page's `data-*` attributes, and those come from templates that escape every value
//!   (`templates`), so text from an alert can't become one.
//! - `style-src 'self'`: the stylesheet only. Datastar's `data-show` and `data-style` set properties
//!   through the CSSOM, which a policy doesn't restrict, but a `style="..."` attribute in a template is
//!   ignored. ace3's templates have about 250 of those, so a ported template moves them to the
//!   stylesheet. Allowing `style-src-attr 'unsafe-inline'` would be the narrow way to loosen this.
//! - `connect-src 'self'`: Datastar's `@get` and `@post`, and 5.8's event streams, reach this origin.
//! - `img-src`, `font-src`: this origin. `default-src 'none'` refuses anything else, frames and objects
//!   included.
//! - `form-action 'self'` and `base-uri 'none'`: an injected form or `<base>` can't send a password
//!   elsewhere. `frame-ancestors 'none'`: no other site frames a page, against clickjacking.
//!
//! The rest: `X-Frame-Options: DENY` for a browser that predates `frame-ancestors`;
//! `X-Content-Type-Options: nosniff`, so a file is only ever its declared type; `Referrer-Policy:
//! same-origin`, so a link out of an alert doesn't tell another site the alert's URL; and
//! `Cross-Origin-Opener-Policy: same-origin`. A response that says nothing about caching is
//! `Cache-Control: no-store`, since a page is one user's.

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// A response's CSP nonce, in its request's extensions.
#[derive(Debug, Clone)]
pub(crate) struct Nonce(pub(crate) String);

impl Nonce {
    /// 128 random bits, as hex, which a CSP nonce may be.
    fn new() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("the system's randomness");
        Nonce(hex::encode(bytes))
    }
}

/// The policy for a response with this nonce.
pub fn content_security_policy(nonce: &str) -> String {
    format!(
        "default-src 'none'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self'; \
         font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; \
         base-uri 'none'"
    )
}

/// Gives the request its nonce and the response its headers.
pub(crate) async fn secure(mut request: Request, next: Next) -> Response {
    let nonce = Nonce::new();
    let policy = content_security_policy(&nonce.0);
    request.extensions_mut().insert(nonce);
    let mut response = next.run(request).await;
    set_headers(response.headers_mut(), &policy);
    response
}

fn set_headers(headers: &mut HeaderMap, policy: &str) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(policy).expect("the policy is a header value"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}
