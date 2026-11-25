//! `protected_url_analyzer`: ace3's `ProtectedURLAnalyzer` (`saq/modules/url/protected.py`), which
//! calls `saq.util.url.extract_protected_url`, and `protected_url_one_drive`, its one case that
//! goes on the network.
//!
//! A URL that a service wraps or rewrites (Egnyte, FireEye, Outlook SafeLinks, Dropbox, SharePoint,
//! Google Drive, URLDefense, Proofpoint, Cisco, Sophos, Barracuda) gives the URL inside as a `url`
//! observable `extracted_from` it, with its directives, and the URL is tagged `protected_url`.
//!
//! A OneDrive short link, `1drv.ms`, says nothing until it's followed: ace3 asks for it with
//! `requests` and every redirect after, from the worker, and turns the address it ends at into a
//! download link. ace-rs's parsers have no network, so the parser module leaves these links alone and
//! `protected_url_one_drive`, on the lookup pool, follows them (docs/modules.md has the decision).
//! It writes `ProtectedURLAnalysis`'s fields under its own name.
//!
//! Where ace-rs departs:
//!
//! - ace3 picks Proofpoint's URL with `set.pop()`, in hash order, when urlfinderlib finds more than
//!   one; here it's the first in sorted order.
//! - ace3 follows any link whose host ends in `1drv.ms`, such as `evil1drv.ms`, and every redirect,
//!   wherever it leads. `protected_url_one_drive` asks only `1drv.ms` and its subdomains, and
//!   follows a redirect only to one of `redirect_hosts`, Microsoft's by default. Anything else it
//!   records as ace3 records a link it couldn't follow: unprotected, the link itself.
//! - ace3 reads the response's body; this reads only the status and the `Location` header.

use std::collections::BTreeSet;
use std::fs;
use std::time::Duration;

use ace_pycompat::PyErr;
use ace_pycompat::parse::{parse_qs, unquote, urljoin, urlparse, urlunparse};
use ace_pycompat::pystr;
use ace_results::types::values::{OneDriveUrlAnalysis, ProtectedUrlAnalysis};
use ace_results::{
    AnalysisType, ObservableKind, ObservableRef, Relationship, RelationshipKind, ResultEnvelope,
};
use ace_sdk::http::HttpClient;
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use ace_urlfinder::{Finder, Magic};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::py::{decode_base64, urlencode, urlencode_doseq};
use ace_sdk::observable_rules as observable;

/// The two modules' manifests.
pub const MANIFEST: Manifest = Manifest::parser::<ProtectedUrlAnalyzer>();
pub const ONE_DRIVE_MANIFEST: Manifest = Manifest::lookup::<OneDriveUrlAnalyzer>();

/// `PROTECTED_URLS`: a Proofpoint URL that holds one of these is another wrapper, not the target.
const PROTECTED_URLS: [&str; 8] = [
    "egnyte.com",
    "fireeye.com",
    "safelinks.protection.outlook.com",
    "dropbox.com",
    "drive.google.com",
    ".sharepoint.com",
    "proofpoint.com",
    "urldefense.com",
];

pub const UNPROTECTED: &str = "unprotected";

/// What `extract_protected_url` gives: ace3's `ProtectionType` value and the URL, or a OneDrive
/// link that has to be followed to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extracted {
    Url(&'static str, String),
    OneDrive,
}

/// `parse_qs(query, keep_blank_values)`'s first value of `key`.
fn first_value(query: &str, keep_blank: bool, key: &str) -> Result<Option<String>, PyErr> {
    Ok(parse_qs(query, keep_blank, false, "&")?
        .into_iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, values)| values.into_iter().next()))
}

/// `extract_param`: the first of `keys` the query has, by its first value.
fn extract_param(query: &str, keys: &[&str]) -> Result<Option<String>, PyErr> {
    let qs = parse_qs(query, true, false, "&")?;
    for key in keys {
        if let Some((_, values)) = qs.iter().find(|(k, _)| k == key)
            && let Some(value) = values.first()
        {
            return Ok(Some(value.clone()));
        }
    }
    Ok(None)
}

/// `REGEX_SHAREPOINT`, `^/:b:/g/(.+)/([^/]+)$`, on a path.
fn sharepoint_parts(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/:b:/g/")?;
    let (first, second) = rest.rsplit_once('/')?;
    let first_ok = !first.is_empty() && !first.contains('\n');
    // [^/]+ takes newlines, but $ needs the end, or a final newline, after it
    (first_ok && !second.is_empty()).then_some((first, second))
}

/// `REGEX_GOOGLE_DRIVE.search`, `drive\.google\.com/file/d/([^/]+)/view`.
fn google_drive_id(url: &str) -> Option<&str> {
    const PREFIX: &str = "drive.google.com/file/d/";
    let mut from = 0;
    while let Some(at) = url[from..].find(PREFIX) {
        let start = from + at + PREFIX.len();
        let rest = &url[start..];
        if let Some(end) = rest.find('/')
            && end > 0
            && rest[end..].starts_with("/view")
        {
            return Some(&rest[..end]);
        }
        from = from + at + 1;
    }
    None
}

/// `REGEX_URLDEFENSE.match`, `^https://urldefense\.com/v3/__(.+?)__.+$`.
fn urldefense_target(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://urldefense.com/v3/__")?;
    let body = crate::py::before_final_newline(rest);
    if body.contains('\n') {
        return None;
    }
    // the shortest group that leaves "__" and at least one character after it
    let mut from = body.chars().next()?.len_utf8();
    while from < body.len() {
        let at = body[from..].find("__")? + from;
        if body.len() > at + 2 {
            return Some(&body[..at]);
        }
        from = at + 1;
    }
    None
}

/// `extract_protected_url(url)`. A `ValueError` says the URL couldn't be read; `find_urls` is
/// urlfinderlib's, for Proofpoint.
pub fn extract_protected_url(
    url: &str,
    find_urls: impl FnOnce(&str) -> Result<BTreeSet<String>, PyErr>,
) -> Result<Extracted, PyErr> {
    if url.is_empty() {
        return Err(PyErr::value_error("URL cannot be None or empty"));
    }
    if pystr::strip(url).is_empty() {
        return Err(PyErr::value_error("URL cannot be whitespace only"));
    }
    let parsed = urlparse(url, "", true)
        .map_err(|e| PyErr::value_error(format!("Invalid URL format: {}", e.message)))?;
    if parsed.scheme.is_empty() && parsed.netloc.is_empty() {
        return Err(PyErr::value_error(
            "URL must have at least a scheme or netloc",
        ));
    }
    let netloc = pystr::lower(&parsed.netloc).into_owned();
    let done = |kind: &'static str, value: String| Ok(Extracted::Url(kind, value));

    if netloc.ends_with("egnyte.com") {
        if parsed.path.starts_with("/dl/") {
            return done("egnyte", url.replace("/dl/", "/dd/"));
        }
    } else if netloc.ends_with("fireeye.com") {
        if netloc.starts_with("protect")
            && let Some(u) = first_value(&parsed.query, false, "u")?
        {
            return done("fireeye", u);
        }
    } else if netloc.ends_with("safelinks.protection.outlook.com") {
        if let Some(u) = first_value(&parsed.query, false, "url")? {
            return done("safelinks_outlook", u);
        }
    } else if netloc.ends_with(".dropbox.com") {
        let mut qs = parse_qs(&parsed.query, true, false, "&")?;
        let modified = match qs.iter_mut().find(|(k, _)| k == "dl") {
            Some((_, values)) if values == &["0"] => {
                *values = vec!["1".to_owned()];
                true
            }
            Some(_) => false,
            None => {
                qs.push(("dl".to_owned(), vec!["1".to_owned()]));
                true
            }
        };
        if modified {
            return done(
                "dropbox",
                urlunparse(
                    &parsed.scheme,
                    &parsed.netloc,
                    &parsed.path,
                    &parsed.params,
                    &urlencode_doseq(&qs),
                    &parsed.fragment,
                ),
            );
        }
    } else if netloc.ends_with(".sharepoint.com")
        && let Some((path, share)) = sharepoint_parts(&parsed.path)
        && let Some(e) = first_value(&parsed.query, false, "e")?
    {
        return done(
            "sharepoint",
            urlunparse(
                &parsed.scheme,
                &parsed.netloc,
                &format!("/{path}/_layouts/15/download.aspx"),
                &parsed.params,
                &urlencode(&[("e", &e), ("share", share)]),
                &parsed.fragment,
            ),
        );
    }

    if let Some(id) = google_drive_id(url) {
        return done(
            "google_drive",
            format!("https://drive.google.com/uc?authuser=0&id={id}&export=download"),
        );
    }
    if netloc.ends_with("urldefense.com")
        && let Some(target) = urldefense_target(url)
    {
        return done("urldefense", target.to_owned());
    }
    if netloc.ends_with(".proofpoint.com") {
        let found: BTreeSet<String> = find_urls(url)?
            .into_iter()
            .filter(|u| !PROTECTED_URLS.iter().any(|p| u.contains(p)))
            .collect();
        if let Some(first) = found.into_iter().next() {
            return done("proofpoint", first);
        }
    }
    if netloc.ends_with("secure-web.cisco.com") {
        let last = parsed.path.rsplit('/').next().unwrap_or_default();
        let candidate = unquote(last).into_owned();
        if !candidate.is_empty() {
            return done("cisco", candidate);
        }
    }
    if netloc.contains(".protection.sophos.com")
        && let Some(u) = extract_param(&parsed.query, &["u"])?
        && !u.is_empty()
    {
        let decoded = decode_base64(&u)?;
        let text = pystr::decode_utf8_strict(&decoded)?;
        return done("sophos", unquote(text).into_owned());
    }
    if (netloc.ends_with("cudasvc.com") || netloc.ends_with("linkprotect.cudasvc.com"))
        && let Some(value) = extract_param(&parsed.query, &["a", "u"])?
        && !value.is_empty()
    {
        return done("cudasvc", unquote(&value).into_owned());
    }
    if netloc.ends_with("1drv.ms") {
        return Ok(Extracted::OneDrive);
    }
    done(UNPROTECTED, url.to_owned())
}

/// The result for a URL and what was found in it: the URL inside as an observable, unless it's
/// unprotected or ace3's url check refuses it.
fn result<D: AnalysisType>(
    details: D,
    ctx_url: &ace_sdk::Observable,
    kind: Option<&str>,
    extracted: Option<&str>,
) -> ResultEnvelope<D> {
    let mut result = ResultEnvelope::new(details);
    let (Some(kind), Some(extracted)) = (kind, extracted) else {
        return result;
    };
    if kind == UNPROTECTED {
        return result;
    }
    result.summary = Some(format!(
        "Protected URL Analysis: detected type {kind} extracted url {extracted}"
    ));
    if let Some(mut o) = observable::new(ObservableKind::Url, extracted) {
        o.relationships.push(Relationship::new(
            RelationshipKind::ExtractedFrom,
            ObservableRef::new(ObservableKind::Url, ctx_url.value.clone()),
        ));
        // copy_directives_to: the original's directives apply to the URL inside
        o.directives.extend(ctx_url.directives.iter().cloned());
        result.observables.push(o);
        result.analyzed.tags.push("protected_url".to_owned());
    }
    result
}

/// The module, with libmagic's database read before containment, for urlfinderlib's sniffing of a
/// Proofpoint URL.
pub struct ProtectedUrlAnalyzer {
    database: Result<Vec<u8>, String>,
}

impl Module for ProtectedUrlAnalyzer {
    const NAME: &'static str = ProtectedUrlAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Url];
    type Output = ProtectedUrlAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(ProtectedUrlAnalyzer {
            database: fs::read(ace_urlfinder::magic::DATABASE).map_err(|e| e.to_string()),
        })
    }
}

impl Parser for ProtectedUrlAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<ProtectedUrlAnalysis>, ModuleError> {
        let url = ctx.observable();
        let find_urls = |value: &str| {
            let database = self.database.as_ref().map_err(|e| {
                PyErr::builtin(
                    "OSError",
                    format!("{}: {e}", ace_urlfinder::magic::DATABASE),
                )
            })?;
            let magic = Magic::load(database.clone()).map_err(|e| PyErr::builtin("OSError", e))?;
            Finder::new(&magic).find_urls(value.as_bytes(), "", "", false)
        };
        let (kind, extracted) = match extract_protected_url(&url.value, find_urls) {
            Ok(Extracted::Url(kind, extracted)) => (Some(kind), Some(extracted)),
            Ok(Extracted::OneDrive) => {
                return Ok(Outcome::Skipped(
                    "a 1drv.ms link, which protected_url_one_drive follows".to_owned(),
                ));
            }
            // ace3 made its analysis first, and keeps it empty
            Err(e) if e.is_instance("builtins", "ValueError") => {
                tracing::debug!("error extracting protected url from {}: {e}", url.value);
                (None, None)
            }
            Err(e) => return Err(ModuleError::other(e)),
        };
        let details = ProtectedUrlAnalysis {
            protection_type: kind.map(str::to_owned),
            extracted_url: extracted.clone(),
        };
        Ok(Outcome::Done(result(
            details,
            url,
            kind,
            extracted.as_deref(),
        )))
    }
}

/// `protected_url_one_drive`'s settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OneDriveSettings {
    /// The hosts, with their subdomains, a 1drv.ms link's redirects may lead to.
    pub redirect_hosts: Vec<String>,
    /// How long each request may take, ace3's `timeout=8`.
    pub timeout_seconds: u64,
    /// A proxy for every request, as ace3's `requests` takes one from `HTTPS_PROXY`.
    pub proxy: Option<String>,
}

impl Default for OneDriveSettings {
    fn default() -> Self {
        OneDriveSettings {
            redirect_hosts: ["1drv.ms", "live.com", "onedrive.com", "sharepoint.com"]
                .map(str::to_owned)
                .to_vec(),
            timeout_seconds: 8,
            proxy: None,
        }
    }
}

/// Whether a URL's host is `hosts`' or under one.
fn host_allowed(url: &str, hosts: &[String]) -> bool {
    let Ok(split) = ace_pycompat::parse::urlsplit(url, "", true) else {
        return false;
    };
    let scheme_ok = matches!(split.scheme.as_str(), "http" | "https");
    let host = split.hostname().unwrap_or_default();
    scheme_ok
        && hosts
            .iter()
            .any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

/// requests' `max_redirects`.
const MAX_REDIRECTS: usize = 30;

/// One request's answer: its status and its `Location`, if it has one.
pub type Hop = (u16, Option<String>);

/// Follows `start`'s redirects, asking `get` for each, while they stay on `hosts`: the URL that
/// answered without a redirect, or None when the link couldn't be followed there.
pub async fn follow<F, Fut>(start: &str, hosts: &[String], mut get: F) -> Option<String>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<Hop, String>>,
{
    let mut url = start.to_owned();
    for _ in 0..=MAX_REDIRECTS {
        if !host_allowed(&url, hosts) {
            return None;
        }
        let (status, location) = match get(url.clone()).await {
            Ok(hop) => hop,
            Err(e) => {
                tracing::info!("unable to fetch final url for one drive link {start}: {e}");
                return None;
            }
        };
        match location {
            Some(location) if matches!(status, 301 | 302 | 303 | 307 | 308) => {
                url = urljoin(&url, &location, true).ok()?;
            }
            _ => return Some(url),
        }
    }
    None
}

/// The one drive branch of `extract_protected_url`, from where the link led.
pub fn one_drive_extracted(link: &str, final_url: Option<&str>) -> (&'static str, String) {
    let unprotected = (UNPROTECTED, link.to_owned());
    let Some(final_url) = final_url else {
        return unprotected;
    };
    let Ok(parsed) = urlparse(final_url, "", true) else {
        return unprotected;
    };
    let value = |key| first_value(&parsed.query, false, key).ok().flatten();
    match (value("authkey"), value("resid")) {
        (Some(authkey), Some(resid)) if !authkey.is_empty() && !resid.is_empty() => (
            "one_drive",
            format!(
                "https://onedrive.live.com/download?authkey={authkey}&resid={resid}&parId=root&o=OneUp"
            ),
        ),
        _ => unprotected,
    }
}

/// The result for a 1drv.ms link that led to `final_url`.
pub fn one_drive_result(
    link: &ace_sdk::Observable,
    final_url: Option<&str>,
) -> ResultEnvelope<OneDriveUrlAnalysis> {
    let (kind, extracted) = one_drive_extracted(&link.value, final_url);
    let details = OneDriveUrlAnalysis {
        protection_type: Some(kind.to_owned()),
        extracted_url: Some(extracted.clone()),
    };
    result(details, link, Some(kind), Some(&extracted))
}

/// Whether ace3's `extract_protected_url` would follow this URL as a OneDrive link.
pub fn is_one_drive_link(url: &str) -> bool {
    let not_proofpoint = |_: &str| Err(PyErr::value_error("not a Proofpoint URL"));
    matches!(
        extract_protected_url(url, not_proofpoint),
        Ok(Extracted::OneDrive)
    )
}

pub struct OneDriveUrlAnalyzer {
    client: HttpClient,
}

impl Module for OneDriveUrlAnalyzer {
    const NAME: &'static str = OneDriveUrlAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Url];
    // the link, up to MAX_REDIRECTS more requests, each with its own timeout
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        ..Resources::DEFAULT
    };
    type Output = OneDriveUrlAnalysis;
    type Settings = OneDriveSettings;

    fn init(settings: &OneDriveSettings) -> Result<Self, ModuleError> {
        let mut builder = HttpClient::builder()
            .timeout(Duration::from_secs(settings.timeout_seconds))
            .no_redirects();
        if let Some(proxy) = &settings.proxy {
            builder = builder.proxy(proxy).map_err(ModuleError::other)?;
        }
        Ok(OneDriveUrlAnalyzer {
            client: builder.build().map_err(ModuleError::other)?,
        })
    }
}

impl Lookup for OneDriveUrlAnalyzer {
    const TCP_PORTS: &'static [u16] = &[80, 443];

    async fn analyze(
        &self,
        ctx: &TaskContext<OneDriveSettings>,
    ) -> Result<Outcome<OneDriveUrlAnalysis>, ModuleError> {
        let link = ctx.observable();
        if !is_one_drive_link(&link.value) {
            return Ok(Outcome::Skipped("not a 1drv.ms link".to_owned()));
        }
        let hosts = &ctx.settings().redirect_hosts;
        let final_url = follow(&link.value, hosts, |url| async move {
            let response = self
                .client
                .send(self.client.get(&url))
                .await
                .map_err(|e| e.to_string())?;
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .map(str::to_owned);
            Ok((response.status().as_u16(), location))
        })
        .await;
        Ok(Outcome::Done(one_drive_result(link, final_url.as_deref())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert_eq!(sharepoint_parts("/:b:/g/a/b/c"), Some(("a/b", "c")));
        assert_eq!(sharepoint_parts("/:b:/g/a/"), None);
        assert_eq!(
            google_drive_id("x drive.google.com/file/d/y/z drive.google.com/file/d/ID/view"),
            Some("ID")
        );
        assert_eq!(
            urldefense_target("https://urldefense.com/v3/__a__b__c"),
            Some("a")
        );
        assert_eq!(
            urldefense_target("https://urldefense.com/v3/_____x"),
            Some("_")
        );
        assert_eq!(urldefense_target("https://urldefense.com/v3/____x"), None);
        assert_eq!(urldefense_target("https://urldefense.com/v3/__a__"), None);
    }

    #[test]
    fn hosts() {
        let hosts = OneDriveSettings::default().redirect_hosts;
        assert!(host_allowed("https://1drv.ms/x", &hosts));
        assert!(host_allowed("https://onedrive.live.com/x", &hosts));
        assert!(!host_allowed("https://evil1drv.ms/x", &hosts));
        assert!(!host_allowed("ftp://1drv.ms/x", &hosts));
        assert!(is_one_drive_link("https://1drv.ms/b/s!x"));
        assert!(!is_one_drive_link("https://example.com/"));
    }
}
