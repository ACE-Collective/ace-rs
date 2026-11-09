//! `parse_url` and `idna_analyzer`: ace3's `ParseURLAnalyzer` (`saq/modules/url/parser.py`) and
//! `IDNAAnalyzer` (`saq/modules/url/idna.py`), on `ace-urlfinder`'s port of urlfinderlib's `URL`.
//!
//! `parse_url` splits a URL into its parts and adds its host, as an `ip` tagged `ip_in_url` or an
//! `fqdn` tagged `domain_in_url`, and its path, query and fragment as a `uri_path`. A value with no
//! scheme, such as `yahoo.com:8080/login`, is read as starting with its host when that host is an
//! IP address or ends in a known suffix. `idna_analyzer` adds a domain's other spelling, IDNA or
//! Unicode, which it then leaves alone.

use ace_pycompat::parse::{parse_qsl, unquote_plus};
use ace_results::types::values::{IdnaAnalysis, ParseUrlAnalysis};
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use ace_urlfinder::url::Url;

use crate::observable;

/// The two modules' manifests.
pub const PARSE_URL_MANIFEST: Manifest = Manifest::parser::<ParseUrlAnalyzer>();
pub const IDNA_MANIFEST: Manifest = Manifest::parser::<IdnaAnalyzer>();

pub struct ParseUrlAnalyzer;

impl Module for ParseUrlAnalyzer {
    const NAME: &'static str = ParseUrlAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Url];
    type Output = ParseUrlAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(ParseUrlAnalyzer)
    }
}

/// `parse_url`: the URL, or `//<value>` when the value starts with its host.
pub fn parse_url(value: &str) -> Url {
    let url = Url::new(value);
    let split = url.split_value();
    if !split.netloc.is_empty() || value.starts_with('/') {
        return url;
    }
    // "yahoo.com:8080/login" splits with "yahoo.com" as its scheme; a real scheme has no dot
    if !split.scheme.is_empty() && !split.scheme.contains('.') {
        return url;
    }
    let host_url = Url::new(&format!("//{value}"));
    if host_url.is_netloc_ipv4() || host_url.is_netloc_valid_tld() {
        return host_url;
    }
    url
}

/// `generate_summary`.
fn parse_url_summary(details: &ParseUrlAnalysis, params: &[(String, String)]) -> Option<String> {
    let mut parts = Vec::new();
    let mut part = |name: &str, value: &Option<String>| {
        if let Some(value) = value.as_ref().filter(|v| !v.is_empty()) {
            parts.push(format!("{name}={value}"));
        }
    };
    part("scheme", &details.scheme);
    part("netloc", &details.netloc);
    part("path", &details.path);
    part("query", &details.query);
    if !params.is_empty() {
        let decoded: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
        parts.push(format!(
            "params=({})",
            crate::py::format_item_list_for_summary(&decoded)
        ));
    }
    let mut part = |name: &str, value: &Option<String>| {
        if let Some(value) = value.as_ref().filter(|v| !v.is_empty()) {
            parts.push(format!("{name}={value}"));
        }
    };
    part("fragment", &details.fragment);
    (!parts.is_empty()).then(|| format!("URL Parser: {}", parts.join(", ")))
}

impl Parser for ParseUrlAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<ParseUrlAnalysis>, ModuleError> {
        let url = parse_url(&ctx.observable().value);
        let split = url.split_value();
        let mut result = ResultEnvelope::new(ParseUrlAnalysis {
            netloc: Some(split.netloc.clone()),
            scheme: Some(split.scheme.clone()),
            path: Some(split.path.clone()),
            query: Some(split.query.clone()),
            params: None,
            fragment: Some(split.fragment.clone()),
        });
        // {k: unquote_plus(v) for k, v in parse_qsl(query, keep_blank_values=True)}: decoded twice,
        // a repeated name keeping its first place and its last value
        let mut params: Vec<(String, String)> = Vec::new();
        for (k, v) in parse_qsl(&split.query, true, false, "&").map_err(ModuleError::other)? {
            let v = unquote_plus(&v);
            match params.iter_mut().find(|(name, _)| *name == k) {
                Some(param) => param.1 = v,
                None => params.push((k, v)),
            }
        }
        let hostname = split.hostname().unwrap_or_default();
        if url.is_netloc_ipv4() {
            if let Some(mut o) = observable::new(ObservableKind::Ip, &hostname) {
                o.tags.push("ip_in_url".to_owned());
                result.observables.push(o);
            }
        } else if url.is_netloc_valid_tld()
            && let Some(mut o) = observable::new(ObservableKind::Fqdn, &hostname)
        {
            o.tags.push("domain_in_url".to_owned());
            result.observables.push(o);
        }
        let path = url.path_original();
        if !path.is_empty() {
            result
                .observables
                .extend(observable::new(ObservableKind::UriPath, path));
        }
        result.summary = parse_url_summary(&result.details, &params);
        Ok(Outcome::Done(result))
    }
}

pub struct IdnaAnalyzer;

impl Module for IdnaAnalyzer {
    const NAME: &'static str = IdnaAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    type Output = IdnaAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(IdnaAnalyzer)
    }
}

impl Parser for IdnaAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<IdnaAnalysis>, ModuleError> {
        let value = &ctx.observable().value;
        let url = Url::new(&format!("https://{value}"));
        // an xn-- label that isn't punycode passes the fqdn check but has no Unicode spelling
        let spellings = url
            .netloc_idna()
            .and_then(|idna| Ok((idna.to_owned(), url.netloc_unicode()?.to_owned())));
        let (idna, unicode) = match spellings {
            Ok(spellings) => spellings,
            Err(e) if e.is_instance("builtins", "UnicodeError") => {
                tracing::info!("unable to convert {value} between idna and unicode: {e}");
                return Ok(Outcome::Skipped(format!(
                    "no IDNA and Unicode spellings: {e}"
                )));
            }
            Err(e) => return Err(ModuleError::other(e)),
        };
        if idna == unicode {
            return Ok(Outcome::Skipped("one spelling".to_owned()));
        }
        let original = url.netloc_original();
        let mut result = ResultEnvelope::new(IdnaAnalysis {
            original: Some(original.clone()),
            idna: Some(idna.clone()),
            unicode: Some(unicode.clone()),
        });
        for (spelling, display_type) in [(&idna, "IDNA Domain"), (&unicode, "Unicode Domain")] {
            if *spelling == original {
                continue;
            }
            // ace3 would fail on a spelling the fqdn check refuses, having stored its analysis
            if let Some(mut o) = observable::new(ObservableKind::Fqdn, spelling) {
                o.exclude_modules.push(IdnaAnalysis::MODULE.to_owned());
                o.display_type = Some(display_type.to_owned());
                result.observables.push(o);
            }
        }
        let parts: Vec<String> = [("idna", &idna), ("unicode", &unicode)]
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        result.summary = (!parts.is_empty()).then(|| format!("IDNA: {}", parts.join(", ")));
        Ok(Outcome::Done(result))
    }
}
