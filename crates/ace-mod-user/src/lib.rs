//! The user module, a port of ace3's `UserAnalyzer` (`saq/modules/user.py`) and the LDAP lookups
//! it makes (`saq/ldap.py`), on the ldap3 crate.
//!
//! For a `user` it searches the directory for the entry whose `cn` is the value, and for a local
//! `email_address` the entry with `proxyAddresses` `smtp:<address>`, each value escaped as ace3
//! escapes it. The entry's attributes are formatted by the server's schema as ace3's ldap3 formats
//! them (`format`), with ace3's own keys added: the manager's `cn` from the `manager` DN, whether the
//! mailbox is on premises, the primary SMTP address and the groups. The user's counterpart, its
//! email address or user name, is added with `skip_user_analysis` and the observable's
//! directives, the manager's entry is looked up too, and the observable is tagged `executive` when
//! the user, the manager or the manager's manager is the `top_user`.
//!
//! The connection departs from ace3's on purpose. ace3 binds with its password in plaintext on
//! port 389. Here `server` is `ldaps://` (TLS from the start) or `ldap://` with StartTLS, and the
//! server's certificate is always verified, against the platform's roots and `ca_certificates`.
//! Plain LDAP, which sends the bind password in the clear, needs `allow_plaintext: true` in the
//! overlay, and the module logs a warning when it starts with it. Every wait is bounded:
//! `connect_timeout_seconds` to connect and `operation_timeout_seconds` for each operation, where
//! ace3's ldap3 sets none. The bind password is the `ldap_bind_password` secret (PLAN.md 2.24).
//!
//! ace3 ships the module disabled, so it runs only when the overlay has a section for it
//! (`Module::ENABLED_BY_DEFAULT`).

pub mod format;

use std::sync::Arc;
use std::time::Duration;

use ace_results::types::user::UserAnalysis;
use ace_results::{NewObservable, ObservableKind, ResultEnvelope};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchOptions};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio::sync::Mutex;

use crate::format::Schema;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<UserAnalyzer>();

/// The secret the module binds with.
pub const PASSWORD: &str = "ldap_bind_password";
/// The directive on the observables the module adds, so it doesn't look them up again.
pub const SKIP: &str = "skip_user_analysis";
/// The tag of a user within two managers of the top user.
pub const EXECUTIVE: &str = "executive";
/// The simple paged results control (RFC 2696).
const PAGED_RESULTS_OID: &str = "1.2.840.113556.1.4.319";
/// The page size of a search, ldap3's `paged_search` default.
pub const PAGE_SIZE: i32 = 100;
/// The most pages a search reads. ace3 reads every page; a search for one user that runs past this
/// is a directory answering more than it was asked.
pub const MAX_PAGES: usize = 100;

/// The module's settings: ace3's `ldap` section, with the connection's own.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct UserSettings {
    /// The directory's URL: `ldaps://dc.example.com:636`, or `ldap://dc.example.com:389`, which
    /// upgrades with StartTLS unless `allow_plaintext`.
    pub server: String,
    /// The DN to bind as, with the `ldap_bind_password` secret.
    pub bind_user: String,
    /// Where searches start.
    pub base_dn: String,
    /// The user whose reports, and their reports, are tagged `executive`.
    pub top_user: String,
    /// The domains whose addresses are looked up (ace3's `global.local_email_domains`).
    pub local_email_domains: Vec<String>,
    /// A PEM file of CA certificates to trust besides the platform's.
    pub ca_certificates: Option<std::path::PathBuf>,
    /// Bind over an `ldap://` URL without StartTLS, sending the password in the clear, as ace3
    /// does. Off unless set, and logged as a warning at startup when set.
    pub allow_plaintext: bool,
    pub connect_timeout_seconds: u64,
    pub operation_timeout_seconds: u64,
}

impl Default for UserSettings {
    fn default() -> Self {
        UserSettings {
            server: String::new(),
            bind_user: String::new(),
            base_dn: String::new(),
            top_user: String::new(),
            local_email_domains: Vec::new(),
            ca_certificates: None,
            allow_plaintext: false,
            connect_timeout_seconds: 10,
            operation_timeout_seconds: 30,
        }
    }
}

/// How the module reaches the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Security {
    Ldaps,
    StartTls,
    Plaintext,
}

/// The user module.
pub struct UserAnalyzer {
    security: Security,
    tls: Arc<rustls::ClientConfig>,
    /// The server's schema, read once a process as ace3's ldap3 reads it once a connection.
    schema: Mutex<Option<Arc<Schema>>>,
}

impl Module for UserAnalyzer {
    const NAME: &'static str = "user_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::EmailAddress, ObservableKind::User];
    const SKIP_DIRECTIVES: &'static [&'static str] = &[SKIP];
    const SECRETS: &'static [&'static str] = &[PASSWORD];
    const ENABLED_BY_DEFAULT: bool = false;
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(120),
        ..Resources::DEFAULT
    };
    type Output = UserAnalysis;
    type Settings = UserSettings;

    fn init(settings: &UserSettings) -> Result<Self, ModuleError> {
        let scheme = settings
            .server
            .split_once("://")
            .map(|(scheme, _)| scheme.to_ascii_lowercase());
        let security = match scheme.as_deref() {
            Some("ldaps") => Security::Ldaps,
            Some("ldap") if settings.allow_plaintext => {
                tracing::warn!(
                    server = %settings.server,
                    "allow_plaintext is set: the user module binds without TLS, sending its \
                     password in the clear"
                );
                Security::Plaintext
            }
            Some("ldap") => Security::StartTls,
            _ => {
                return Err(ModuleError::other(format!(
                    "server {:?} is neither an ldaps:// nor an ldap:// URL",
                    settings.server
                )));
            }
        };
        Ok(UserAnalyzer {
            security,
            tls: Arc::new(tls_config(settings)?),
            schema: Mutex::new(None),
        })
    }
}

/// rustls with the platform's roots and `ca_certificates`.
fn tls_config(settings: &UserSettings) -> Result<rustls::ClientConfig, ModuleError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        // a platform root rustls can't use is left out, as reqwest's platform roots are
        if let Err(e) = roots.add(cert) {
            tracing::debug!("a platform CA certificate isn't usable: {e}");
        }
    }
    if let Some(path) = &settings.ca_certificates {
        use rustls::pki_types::pem::PemObject;
        let pem = std::fs::read(path)
            .map_err(|e| ModuleError::other(format!("{}: {e}", path.display())))?;
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.map_err(|e| ModuleError::other(format!("{}: {e}", path.display())))?;
            roots.add(cert).map_err(ModuleError::other)?;
        }
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(ModuleError::other)?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

/// One entry: its attributes as the server sent them, in order.
type RawEntry = Vec<(String, Vec<Vec<u8>>)>;

/// A bound connection.
struct Directory {
    ldap: ldap3::Ldap,
    timeout: Duration,
}

/// An LDAP failure: the directory can't be reached or answered with an error.
fn unavailable(what: &str, error: impl std::fmt::Display) -> ModuleError {
    ModuleError::Unavailable(format!("LDAP {what}: {error}").into())
}

impl Directory {
    /// Unbinds, as ace3's connection does when the process ends; a failure only logs.
    async fn unbind(&mut self) {
        if let Err(e) = self.ldap.unbind().await {
            tracing::debug!("the LDAP unbind failed: {e}");
        }
    }

    async fn search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attributes: Vec<&str>,
    ) -> Result<Vec<RawEntry>, ModuleError> {
        let ldap3::SearchResult(entries, result) = self
            .ldap
            .with_timeout(self.timeout)
            .with_search_options(SearchOptions::new().deref(ldap3::DerefAliases::Always))
            .search(base, scope, filter, attributes)
            .await
            .map_err(|e| unavailable("search", e))?;
        result.success().map_err(|e| unavailable("search", e))?;
        Ok(entries.iter().filter_map(raw_entry).collect())
    }

    /// ldap3's `paged_search` as ace3's `search` lists it: every page, and each page's entries in
    /// reverse, since its generator pops them off the end of each page's list.
    async fn paged_search(
        &mut self,
        base: &str,
        filter: &str,
    ) -> Result<Vec<RawEntry>, ModuleError> {
        let mut found = Vec::new();
        let mut cookie = Vec::new();
        for _ in 0..MAX_PAGES {
            let control = ldap3::controls::PagedResults {
                size: PAGE_SIZE,
                cookie: std::mem::take(&mut cookie),
            };
            let ldap3::SearchResult(entries, result) = self
                .ldap
                .with_timeout(self.timeout)
                .with_search_options(SearchOptions::new().deref(ldap3::DerefAliases::Always))
                .with_controls(control)
                .search(base, Scope::Subtree, filter, vec!["*"])
                .await
                .map_err(|e| unavailable("search", e))?;
            let next = result
                .ctrls
                .iter()
                .find(|c| c.1.ctype == PAGED_RESULTS_OID)
                .and_then(|c| c.1.val.as_deref())
                .and_then(paged_cookie)
                .unwrap_or_default();
            result.success().map_err(|e| unavailable("search", e))?;
            let mut page: Vec<RawEntry> = entries.iter().filter_map(raw_entry).collect();
            page.reverse();
            found.extend(page);
            if next.is_empty() {
                return Ok(found);
            }
            cookie = next;
        }
        Err(unavailable(
            "search",
            format!("the directory answered more than {MAX_PAGES} pages"),
        ))
    }
}

/// The cookie of a paged results response control's value, `SEQUENCE { size, cookie }`.
fn paged_cookie(value: &[u8]) -> Option<Vec<u8>> {
    let (_, tag) = ldap3::asn1::parse_tag(value).ok()?;
    let mut parts = tag.expect_constructed()?.into_iter();
    parts.next()?;
    parts.next()?.expect_primitive()
}

/// A search result entry's attributes in the order sent; a referral or anything else is None.
fn raw_entry(entry: &ldap3::ResultEntry) -> Option<RawEntry> {
    if entry.is_ref() || entry.is_intermediate() {
        return None;
    }
    let mut parts = entry.0.clone().expect_constructed()?.into_iter();
    parts.next()?;
    let attributes = parts.next()?.expect_constructed()?;
    let mut out = Vec::new();
    for attribute in attributes {
        let mut fields = attribute.expect_constructed()?.into_iter();
        let name = String::from_utf8_lossy(&fields.next()?.expect_primitive()?).into_owned();
        let values = fields
            .next()?
            .expect_constructed()?
            .into_iter()
            .filter_map(|v| v.expect_primitive())
            .collect();
        out.push((name, values));
    }
    Some(out)
}

/// ldap3's `escape_filter_chars`: `\`, `*`, `(`, `)` and NUL as `\xx`.
fn escape(value: &str) -> String {
    ldap3::ldap_escape(value).into_owned()
}

impl UserAnalyzer {
    async fn connect(&self, ctx: &TaskContext<UserSettings>) -> Result<Directory, ModuleError> {
        let settings = ctx.settings();
        let mut conn = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(settings.connect_timeout_seconds));
        let url = match self.security {
            Security::Ldaps => {
                conn = conn.set_config(self.tls.clone());
                settings.server.clone()
            }
            Security::StartTls => {
                conn = conn.set_config(self.tls.clone()).set_starttls(true);
                settings.server.clone()
            }
            Security::Plaintext => settings.server.clone(),
        };
        let (driver, mut ldap) = LdapConnAsync::with_settings(conn, &url)
            .await
            .map_err(|e| unavailable("connect", e))?;
        ldap3::drive!(driver);
        let timeout = Duration::from_secs(settings.operation_timeout_seconds);
        let password = ctx.secret(PASSWORD)?;
        let bound = ldap
            .with_timeout(timeout)
            .simple_bind(&settings.bind_user, password.expose())
            .await
            .map_err(|e| unavailable("bind", e))?;
        if bound.rc != 0 {
            // a refused bind is the site's configuration, which another attempt won't fix
            return Err(ModuleError::other(format!(
                "the LDAP bind as {} failed: result {} {}",
                settings.bind_user, bound.rc, bound.text
            )));
        }
        Ok(Directory { ldap, timeout })
    }

    /// The server's schema, read from the root DSE's `subschemaSubentry` once a process.
    async fn schema(&self, directory: &mut Directory) -> Result<Arc<Schema>, ModuleError> {
        let mut cached = self.schema.lock().await;
        if let Some(schema) = cached.as_ref() {
            return Ok(schema.clone());
        }
        let root = directory
            .search(
                "",
                Scope::Base,
                "(objectClass=*)",
                vec!["subschemaSubentry"],
            )
            .await?;
        let entry = root
            .first()
            .and_then(|attrs| {
                attrs
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("subschemaSubentry"))
            })
            .and_then(|(_, values)| values.first())
            .map(|dn| String::from_utf8_lossy(dn).into_owned());
        let schema = match entry {
            Some(dn) => {
                let found = directory
                    .search(
                        &dn,
                        Scope::Base,
                        "(objectClass=subschema)",
                        vec!["attributeTypes"],
                    )
                    .await?;
                let definitions: Vec<String> = found
                    .iter()
                    .flatten()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("attributeTypes"))
                    .flat_map(|(_, values)| values.iter())
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .collect();
                Schema::from_attribute_types(definitions.iter().map(String::as_str))
            }
            // a server that gives no schema: every value is text, and every attribute a list
            None => Schema::default(),
        };
        let schema = Arc::new(schema);
        *cached = Some(schema.clone());
        Ok(schema)
    }

    /// ace3's `get_user_attributes`: the first entry ldap3 lists for `filter`, with ace3's keys.
    async fn user_attributes(
        &self,
        directory: &mut Directory,
        schema: &Schema,
        base: &str,
        filter: &str,
    ) -> Result<Option<Map<String, Value>>, ModuleError> {
        let entries = directory.paged_search(base, filter).await?;
        let Some(first) = entries.first() else {
            return Ok(None);
        };
        let mut attributes = schema.entry(first);
        if let Some(manager) = attributes.get("manager") {
            let Some(manager) = manager.as_str() else {
                return Err(ModuleError::other(
                    "the entry's manager isn't one DN, so ace3's regex can't read it",
                ));
            };
            let cn = regex::Regex::new(r"^CN=([^,]+)")
                .expect("a valid pattern")
                .captures(manager)
                .map(|c| c[1].to_owned())
                .ok_or_else(|| {
                    ModuleError::other(format!("the manager {manager:?} doesn't start with CN="))
                })?;
            attributes.insert("manager_cn".into(), Value::String(cn));
        }
        let on_prem = if let Some(details) = attributes.get("msExchRecipientTypeDetails") {
            let Some(details) = details
                .as_i64()
                .map(i128::from)
                .or_else(|| details.as_u64().map(i128::from))
            else {
                return Err(ModuleError::other(
                    "msExchRecipientTypeDetails isn't an integer, which ace3 compares with one",
                ));
            };
            Value::Bool(details < 1024 || details == 4096)
        } else {
            match attributes.get("objectClass") {
                Some(Value::Array(classes)) if classes.iter().any(|c| c == "publicFolder") => {
                    Value::Bool(true)
                }
                Some(Value::String(class)) if class.contains("publicFolder") => Value::Bool(true),
                _ => Value::Null,
            }
        };
        attributes.insert("on_prem".into(), on_prem);
        let primary = match attributes.get("proxyAddresses") {
            Some(Value::Array(addresses)) => addresses
                .iter()
                .filter_map(Value::as_str)
                .find_map(|a| a.strip_prefix("SMTP:"))
                .map(|a| Value::String(a.to_owned())),
            _ => None,
        };
        attributes.insert("primary_email".into(), primary.unwrap_or(Value::Null));
        Ok(Some(attributes))
    }
}

/// Python's `str()` of a JSON value, as ace3's summary formats one.
fn py_str(value: Option<&Value>) -> String {
    fn repr(value: &Value) -> String {
        match value {
            Value::String(s) => {
                let quote = if s.contains('\'') && !s.contains('"') {
                    '"'
                } else {
                    '\''
                };
                let mut out = String::from(quote);
                for c in s.chars() {
                    match c {
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if c == quote => {
                            out.push('\\');
                            out.push(c);
                        }
                        c => out.push(c),
                    }
                }
                out.push(quote);
                out
            }
            other => py(other),
        }
    }
    fn py(value: &Value) -> String {
        match value {
            Value::Null => "None".to_owned(),
            Value::Bool(true) => "True".to_owned(),
            Value::Bool(false) => "False".to_owned(),
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            Value::Array(items) => {
                format!(
                    "[{}]",
                    items.iter().map(repr).collect::<Vec<_>>().join(", ")
                )
            }
            Value::Object(map) => format!(
                "{{{}}}",
                map.iter()
                    .map(|(k, v)| format!("{}: {}", repr(&Value::String(k.clone())), repr(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
    value.map_or_else(|| "None".to_owned(), py)
}

/// `UserAnalysis.generate_summary`.
fn summary(ldap: &Map<String, Value>) -> String {
    let field = |key: &str, missing: &str| {
        if ldap.contains_key(key) {
            py_str(ldap.get(key))
        } else {
            missing.to_owned()
        }
    };
    format!(
        "{} - {} - {} - {}",
        field("displayName", "None, None"),
        field("l", "None"),
        field("division", "None"),
        field("title", "None")
    )
}

impl Lookup for UserAnalyzer {
    const TCP_PORTS: &'static [u16] = &[636, 389];

    async fn analyze(
        &self,
        ctx: &TaskContext<UserSettings>,
    ) -> Result<Outcome<UserAnalysis>, ModuleError> {
        let settings = ctx.settings();
        let observable = ctx.observable();
        if observable.directives.iter().any(|d| d == SKIP) {
            return Ok(Outcome::Skipped("added by the user module".to_owned()));
        }
        let is_email = observable.kind.is_subtype_of(ObservableKind::EmailAddress);
        let filter = if is_email {
            if !ace_mod_email::is_local_email_domain(
                &observable.value,
                &settings.local_email_domains,
            ) {
                return Ok(Outcome::Skipped("an external email address".to_owned()));
            }
            let Some(email) = ace_mod_email::py::normalize_email_address(&observable.value) else {
                return Ok(Outcome::Skipped("not an email address".to_owned()));
            };
            format!("(proxyAddresses=smtp:{})", escape(&email))
        } else {
            format!("(cn={})", escape(&observable.value))
        };

        let mut directory = self.connect(ctx).await?;
        let schema = self.schema(&mut directory).await?;
        let base = settings.base_dn.clone();
        let Some(mut ldap) = self
            .user_attributes(&mut directory, &schema, &base, &filter)
            .await?
        else {
            directory.unbind().await;
            return Ok(Outcome::Skipped("not in the directory".to_owned()));
        };

        // the counterpart: the user of an address, or the address of a user
        let mut observables = Vec::new();
        let counterpart = if is_email {
            match ldap.get("cn") {
                Some(Value::String(cn)) => Some((ObservableKind::User, cn.to_lowercase())),
                Some(Value::Null) | None => None,
                Some(_) => {
                    return Err(ModuleError::other(
                        "the entry's cn isn't one value, which ace3 lowercases as text",
                    ));
                }
            }
        } else {
            ldap.get("mail")
                .and_then(Value::as_str)
                .and_then(ace_mod_email::py::normalize_email_address)
                .map(|mail| (ObservableKind::EmailAddress, mail))
        };
        if let Some((kind, value)) = counterpart {
            let mut added = NewObservable::new(kind, value);
            added.directives.push(SKIP.to_owned());
            for directive in &observable.directives {
                if !added.directives.contains(directive) {
                    added.directives.push(directive.clone());
                }
            }
            observables.push(added);
        }

        // the user, the manager and the manager's manager: one being the top user is an executive
        let mut chain: Vec<Option<String>> =
            vec![ldap.get("cn").and_then(Value::as_str).map(str::to_owned)];
        let mut analysis = UserAnalysis::default();
        if let Some(manager_cn) = ldap
            .get("manager_cn")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            chain.push(Some(manager_cn.clone()));
            let filter = format!("(cn={})", escape(&manager_cn));
            let manager = self
                .user_attributes(&mut directory, &schema, &base, &filter)
                .await?;
            match &manager {
                None => {
                    tracing::error!("failed to fetch manager ldap info for {}", observable.value)
                }
                Some(manager) => chain.push(
                    manager
                        .get("manager_cn")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                ),
            }
            analysis.manager_ldap = Some(manager);
        }
        directory.unbind().await;
        let top_user = settings.top_user.to_lowercase();
        let executive = !top_user.is_empty()
            && chain
                .iter()
                .flatten()
                .filter(|cn| !cn.is_empty())
                .any(|cn| cn.to_lowercase() == top_user);

        let groups: Vec<Value> = match ldap.get("memberOf") {
            Some(Value::Array(groups)) => groups.clone(),
            // ace3 iterates a single value, so a string gives its characters
            Some(Value::String(group)) => group
                .chars()
                .map(|c| Value::String(c.to_string()))
                .collect(),
            _ => Vec::new(),
        };
        let entitlements = groups
            .into_iter()
            .map(|group| serde_json::json!({"group": group, "privileged": false}))
            .collect();
        ldap.insert("entitlements".into(), Value::Array(entitlements));

        let summary = summary(&ldap);
        analysis.ldap = Some(ldap);
        let mut result = ResultEnvelope::new(analysis);
        result.summary = Some(summary);
        result.observables = observables;
        if executive {
            result.analyzed.tags.push(EXECUTIVE.to_owned());
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_summary_is_python_s_str_of_each_field() {
        let ldap = json!({"displayName": "Doe, John", "l": ["Springfield"], "title": 3})
            .as_object()
            .cloned()
            .expect("a map");
        assert_eq!(summary(&ldap), "Doe, John - ['Springfield'] - None - 3");
        assert_eq!(summary(&Map::new()), "None, None - None - None - None");
    }

    #[test]
    fn filter_values_are_escaped_as_ace3_escapes_them() {
        assert_eq!(escape("a*b(c)\\d\0"), "a\\2ab\\28c\\29\\5cd\\00");
    }
}
