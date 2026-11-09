//! The `nrd_refresh` scheduled task (PLAN.md 7.4): ace3's `nrd-refresh` cron job, `ace nrd refresh`
//! (`saq/nrd/refresh.py`), which keeps the newly registered domains list `nrd_analyzer` reads.
//!
//! Each run decides as ace3's `refresh()` does whether the list needs rebuilding: always when there
//! is none yet or the configured primary URLs changed (their hash, `config_hash`); not while
//! `check_interval_hours` haven't passed since the last rebuild; and after that only when a HEAD of
//! some primary URL no longer matches the ETag, or failing that the Last-Modified, the last fetch
//! recorded. A rebuild fetches each feed in order, from its primary URL and then each backup,
//! normalizes each line as ace3 does (`ace_sdk::nrd::normalize_line`), and replaces the list in one
//! transaction (`ace_core::nrd::Rebuild`), so `nrd_analyzer`'s read sees the old list until the new
//! one is whole. A feed every URL of which fails aborts the rebuild and leaves the old list, and the
//! run fails, as ace3's exits 1.
//!
//! The network: it runs in `ace serve`, which reaches the feeds, and through `ace_sdk::http`'s client,
//! which always verifies certificates (with `nrd.ca_certificates` trusted besides the platform's). Each
//! wait is bounded: 10 s to connect and 60 s between reads, as ace3's `(10, 60)`, a fetch at most
//! `FETCH_TIMEOUT` and `MAX_LIST_BYTES`, and the run its scheduler timeout. As in ace3, a request that
//! can't connect or gets a 5xx is tried once more a second later, and a body that breaks off is
//! fetched again once before the next URL.
//!
//! It acts as `scheduler:nrd_refresh`, which migration 0039 grants `nrd:refresh` and nothing else.

use std::collections::BTreeSet;
use std::time::Duration;

use ace_core::nrd::{ListState, Rebuild, Source};
use ace_sdk::http::HttpClient;
use ace_sdk::{NrdList, NrdSection};
use ace_service::{Actor, Service};
use chrono::Utc;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, ETAG, LAST_MODIFIED};
use reqwest::{Method, Response};
use serde_json::{Value, json};
use sha2::Digest;

/// The longest one fetch of a feed may take, from connect to the end of its body.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// The most bytes one feed may have. ace3 sets none; a feed of 30 days of registrations is tens of
/// megabytes.
pub const MAX_LIST_BYTES: u64 = 1 << 30;
/// How many times one URL's body is fetched before the next URL: ace3's `STREAM_RETRY_ATTEMPTS`.
const STREAM_ATTEMPTS: usize = 2;

/// How the run went, for its row in `scheduler.runs`.
#[derive(Debug, Clone, PartialEq)]
pub enum Refreshed {
    /// Nothing to do, and why.
    Unchanged(&'static str),
    /// The list was rebuilt, for this reason.
    Rebuilt {
        reason: &'static str,
        state: ListState,
    },
}

impl Refreshed {
    pub fn summary(&self) -> Value {
        match self {
            Refreshed::Unchanged(why) => json!({"rebuilt": false, "why": why}),
            Refreshed::Rebuilt { reason, state } => json!({
                "rebuilt": true,
                "reason": reason,
                "row_count": state.row_count,
                "sources": state.sources,
            }),
        }
    }
}

/// The refresh, with its client and the pause between a request and its retry.
pub struct Refresher {
    client: HttpClient,
    backoff: Duration,
}

impl Refresher {
    /// The client the overlay's section says: certificates verified, with its CA file trusted too.
    pub fn new(section: &NrdSection) -> Result<Refresher, String> {
        let mut builder = HttpClient::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(60))
            .timeout(FETCH_TIMEOUT)
            .user_agent(concat!("ace4-nrd-refresh/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = &section.ca_certificates {
            let pem = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
            builder = builder
                .add_root_certificates_pem(&pem)
                .map_err(|e| e.to_string())?;
        }
        Ok(Refresher {
            client: builder.build().map_err(|e| e.to_string())?,
            backoff: Duration::from_secs(1),
        })
    }

    /// No pause before a retry, for tests.
    pub fn without_backoff(mut self) -> Refresher {
        self.backoff = Duration::ZERO;
        self
    }

    /// One run: ace3's `refresh()`.
    pub async fn refresh(
        &self,
        service: &Service,
        actor: &Actor,
        section: &NrdSection,
    ) -> Result<Refreshed, String> {
        if section.url_lists.is_empty() {
            tracing::info!("no nrd url_lists configured; nothing to do");
            return Ok(Refreshed::Unchanged("no url_lists configured"));
        }
        let config_hash = config_hash(&section.url_lists);
        let state = service.nrd_state(actor).await.map_err(|e| e.to_string())?;
        let Some(state) = state else {
            return self
                .rebuild(service, actor, section, &config_hash, "missing database")
                .await;
        };
        if state.config_hash != config_hash {
            return self
                .rebuild(service, actor, section, &config_hash, "config_hash change")
                .await;
        }
        let elapsed = Utc::now() - state.last_refreshed_at;
        if elapsed.num_milliseconds() < (section.check_interval_hours as i64) * 3_600_000 {
            tracing::debug!(
                "no NRD refresh needed (last refreshed {:.2}h ago < {}h interval)",
                elapsed.num_milliseconds() as f64 / 3_600_000.0,
                section.check_interval_hours
            );
            return Ok(Refreshed::Unchanged("inside check_interval_hours"));
        }
        // the clock isn't reset when upstream is unchanged, so every run asks again until it is
        if self.heads_match(&section.url_lists, &state.sources).await {
            tracing::debug!("HEAD check matched every stored ETag; no NRD refresh needed");
            return Ok(Refreshed::Unchanged("upstream unchanged"));
        }
        self.rebuild(
            service,
            actor,
            section,
            &config_hash,
            "HEAD-detected change",
        )
        .await
    }

    /// ace3's `_do_full_refresh` and `_build_database`.
    async fn rebuild(
        &self,
        service: &Service,
        actor: &Actor,
        section: &NrdSection,
        config_hash: &str,
        reason: &'static str,
    ) -> Result<Refreshed, String> {
        tracing::info!("NRD refresh triggered by {reason}");
        let started = std::time::Instant::now();
        let mut rebuild = service
            .nrd_rebuild(actor)
            .await
            .map_err(|e| e.to_string())?;
        let mut sources = Vec::new();
        for list in &section.url_lists {
            let Some(source) = self.ingest(&mut rebuild, list).await? else {
                tracing::error!(
                    "all URLs (primary + backups) failed for list {}; aborting refresh",
                    list.url
                );
                // dropped, the rebuild leaves the list as it was
                return Err(format!(
                    "every URL of the list {} failed, so the list is as it was",
                    list.url
                ));
            };
            if source.fetched_from != list.url {
                tracing::warn!(
                    "primary URL {} failed; fell back to {}",
                    list.url,
                    source.fetched_from
                );
            }
            sources.push(source);
        }
        let state = rebuild
            .commit(config_hash, sources)
            .await
            .map_err(|e| format!("recording the list: {e}"))?;
        tracing::info!(
            "NRD refresh completed: rebuilt {} domains across {} lists in {:.1} seconds",
            state.row_count,
            state.sources.len(),
            started.elapsed().as_secs_f64()
        );
        Ok(Refreshed::Rebuilt { reason, state })
    }

    /// ace3's `_ingest_one_list`: the list's domains from its primary URL or the first backup that
    /// answers, each URL's body fetched at most `STREAM_ATTEMPTS` times. None when every URL failed.
    async fn ingest(
        &self,
        rebuild: &mut Rebuild,
        list: &NrdList,
    ) -> Result<Option<Source>, String> {
        for url in std::iter::once(&list.url).chain(&list.backups) {
            for attempt in 1..=STREAM_ATTEMPTS {
                // a URL that doesn't answer was already tried twice, so it isn't fetched again
                let Some(response) = self.request(Method::GET, url).await else {
                    break;
                };
                let header = |name| {
                    response
                        .headers()
                        .get(name)
                        .and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok())
                        .map(str::to_owned)
                };
                let content_length = header(CONTENT_LENGTH).and_then(|v| v.trim().parse().ok());
                let etag = header(ETAG);
                let last_modified = header(LAST_MODIFIED);
                rebuild.attempt().await.map_err(|e| e.to_string())?;
                match read_list(response, rebuild).await {
                    Ok((unique, dropped)) => {
                        rebuild.keep().await.map_err(|e| e.to_string())?;
                        if dropped > 0 {
                            tracing::warn!("dropped {dropped} malformed entries from {url}");
                        }
                        return Ok(Some(Source {
                            url: list.url.clone(),
                            fetched_from: url.clone(),
                            etag,
                            last_modified,
                            content_length,
                            row_count: unique as i64,
                        }));
                    }
                    Err(ListError::Store(e)) => return Err(e),
                    Err(ListError::Stream(e)) => {
                        rebuild.abandon().await.map_err(|e| e.to_string())?;
                        tracing::warn!(
                            "stream failed for {url} (attempt {attempt}/{STREAM_ATTEMPTS}): {e}"
                        );
                        if attempt < STREAM_ATTEMPTS {
                            tokio::time::sleep(self.backoff).await;
                        } else {
                            tracing::warn!("{url} exhausted stream retries; trying the next URL");
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// ace3's `_http_request`: a connection that fails, or a 5xx, is tried once more after the
    /// backoff; any other status of 400 or more is a failure, logged. None on failure.
    async fn request(&self, method: Method, url: &str) -> Option<Response> {
        let mut last_error = None;
        for attempt in 1..=2 {
            match self
                .client
                .send(self.client.request(method.clone(), url))
                .await
            {
                Err(e) => {
                    last_error = Some(e.to_string());
                    if attempt < 2 {
                        tokio::time::sleep(self.backoff).await;
                    }
                }
                Ok(response) => {
                    let status = response.status().as_u16();
                    if status >= 500 && attempt < 2 {
                        tokio::time::sleep(self.backoff).await;
                        continue;
                    }
                    if status >= 400 {
                        tracing::warn!("{method} {url} failed with HTTP {status}");
                        return None;
                    }
                    return Some(response);
                }
            }
        }
        tracing::warn!(
            "{method} {url} failed after retry: {}",
            last_error.unwrap_or_default()
        );
        None
    }

    /// ace3's `_heads_match`: every primary URL's HEAD matches what its last fetch recorded, by
    /// ETag when both have one, or else by Last-Modified. A list the last fetch doesn't name, or a
    /// HEAD that fails or carries neither, doesn't match.
    async fn heads_match(&self, lists: &[NrdList], stored: &[Source]) -> bool {
        for list in lists {
            let Some(stored) = stored.iter().find(|s| s.url == list.url) else {
                return false;
            };
            let Some(response) = self.request(Method::HEAD, &list.url).await else {
                return false;
            };
            let header = |name| {
                response
                    .headers()
                    .get(name)
                    .and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok())
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
            };
            let (etag, last_modified) = (header(ETAG), header(LAST_MODIFIED));
            if etag.is_none() && last_modified.is_none() {
                return false;
            }
            let stored_etag = stored.etag.as_deref().filter(|e| !e.is_empty());
            if let (Some(stored), Some(head)) = (stored_etag, etag.as_deref()) {
                if stored != head {
                    return false;
                }
                continue;
            }
            let stored_lm = stored.last_modified.as_deref().filter(|l| !l.is_empty());
            match (stored_lm, last_modified.as_deref()) {
                (Some(stored), Some(head)) if stored == head => {}
                _ => return false,
            }
        }
        true
    }
}

/// ace3's `_compute_config_hash`: the SHA-256 of the sorted primary URLs as compact JSON. A backup
/// changes nothing that ends up in the list, so it isn't in the hash.
pub fn config_hash(lists: &[NrdList]) -> String {
    let mut urls: Vec<&str> = lists.iter().map(|l| l.url.as_str()).collect();
    urls.sort_unstable();
    // Python's json.dumps escapes every non-ASCII character
    let mut payload = String::from("[");
    for (i, url) in urls.iter().enumerate() {
        if i > 0 {
            payload.push(',');
        }
        payload.push('"');
        for c in url.chars() {
            match c {
                '"' => payload.push_str("\\\""),
                '\\' => payload.push_str("\\\\"),
                '\n' => payload.push_str("\\n"),
                '\r' => payload.push_str("\\r"),
                '\t' => payload.push_str("\\t"),
                c if (c as u32) < 0x20 || !c.is_ascii() => {
                    let mut units = [0u16; 2];
                    for unit in c.encode_utf16(&mut units) {
                        payload.push_str(&format!("\\u{unit:04x}"));
                    }
                }
                c => payload.push(c),
            }
        }
        payload.push('"');
    }
    payload.push(']');
    hex(&sha2::Sha256::digest(payload.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

enum ListError {
    /// The body broke off or ran past its bounds: try again, then the next URL.
    Stream(String),
    /// The database failed: the run fails.
    Store(String),
}

/// Reads a feed's body line by line into the rebuild, as ace3's `_iter_lines` and its insert loop
/// do: UTF-8 unless the response names another charset, Python's `splitlines` line ends, each line
/// normalized and the ones that aren't domains counted. Returns the distinct domains and the lines
/// dropped.
async fn read_list(
    mut response: Response,
    rebuild: &mut Rebuild,
) -> Result<(usize, usize), ListError> {
    let latin1 = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("charset=iso-8859-1") || v.contains("charset=latin-1")
        });
    let mut lines = Lines::new(latin1);
    let mut unique = BTreeSet::new();
    let mut dropped = 0usize;
    let mut batch = Vec::new();
    let mut read: u64 = 0;
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(e) => return Err(ListError::Stream(e.to_string())),
        };
        read += chunk.len() as u64;
        if read > MAX_LIST_BYTES {
            return Err(ListError::Stream(format!(
                "the list is larger than {MAX_LIST_BYTES} bytes"
            )));
        }
        for line in lines.push(&chunk) {
            take(&line, &mut unique, &mut dropped, &mut batch);
        }
        if batch.len() >= ace_core::nrd::INSERT_BATCH {
            rebuild
                .add(&batch)
                .await
                .map_err(|e| ListError::Store(e.to_string()))?;
            batch.clear();
        }
    }
    for line in lines.finish() {
        take(&line, &mut unique, &mut dropped, &mut batch);
    }
    rebuild
        .add(&batch)
        .await
        .map_err(|e| ListError::Store(e.to_string()))?;
    Ok((unique.len(), dropped))
}

fn take(line: &str, unique: &mut BTreeSet<String>, dropped: &mut usize, batch: &mut Vec<String>) {
    match ace_sdk::nrd::normalize_line(line) {
        Some(domain) => {
            if unique.insert(domain.clone()) {
                batch.push(domain);
            }
        }
        None => {
            let stripped = line.trim();
            if !stripped.is_empty() && !stripped.starts_with('#') {
                *dropped += 1;
            }
        }
    }
}

/// A body split into lines as Python's `str.splitlines` splits text, decoded as it arrives.
struct Lines {
    latin1: bool,
    /// Bytes of a UTF-8 sequence a chunk cut.
    pending_bytes: Vec<u8>,
    /// Text after the last line end.
    pending: String,
}

/// The line ends `str.splitlines` knows, but `\r\n`, which is one.
fn line_end(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\u{0b}'
            | '\u{0c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

impl Lines {
    fn new(latin1: bool) -> Lines {
        Lines {
            latin1,
            pending_bytes: Vec::new(),
            pending: String::new(),
        }
    }

    fn decode(&mut self, chunk: &[u8]) -> String {
        if self.latin1 {
            return chunk.iter().map(|&b| char::from(b)).collect();
        }
        self.pending_bytes.extend_from_slice(chunk);
        let bytes = std::mem::take(&mut self.pending_bytes);
        // keep a sequence the chunk cut for the next one; anything else invalid is U+FFFD, as
        // requests' decoder replaces it
        let cut = match std::str::from_utf8(&bytes) {
            Ok(_) => bytes.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => bytes.len(),
        };
        self.pending_bytes = bytes[cut..].to_vec();
        String::from_utf8_lossy(&bytes[..cut]).into_owned()
    }

    fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        let text = self.decode(chunk);
        self.pending.push_str(&text);
        let mut lines = Vec::new();
        let mut start = 0;
        let pending = std::mem::take(&mut self.pending);
        let mut chars = pending.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            if !line_end(c) {
                continue;
            }
            if c == '\r' {
                match chars.peek() {
                    Some((_, '\n')) => {
                        chars.next();
                    }
                    // a \r at the chunk's end may be a \r\n's first half
                    None => break,
                    Some(_) => {}
                }
            }
            lines.push(pending[start..i].to_owned());
            start = chars.peek().map_or(pending.len(), |(j, _)| *j);
        }
        self.pending = pending[start..].to_owned();
        lines
    }

    fn finish(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.pending_bytes.is_empty() {
            let rest = std::mem::take(&mut self.pending_bytes);
            self.pending.push_str(&String::from_utf8_lossy(&rest));
        }
        let pending = std::mem::take(&mut self.pending);
        let mut rest = pending.as_str();
        // what's left may hold a final \r
        while let Some(i) = rest.find(line_end) {
            lines.push(rest[..i].to_owned());
            let end = i + rest[i..].chars().next().map_or(1, char::len_utf8);
            rest = &rest[end..];
            if rest.starts_with('\n') && pending.as_bytes().get(i) == Some(&b'\r') {
                rest = &rest[1..];
            }
        }
        if !rest.is_empty() {
            lines.push(rest.to_owned());
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_split_as_python_s_splitlines_across_chunks() {
        let mut lines = Lines::new(false);
        let mut got = Vec::new();
        for chunk in [
            &b"a.com\r"[..],
            b"\nb.com\nc\xc3",
            b"\xa9.com\x0bd.com\r",
            b"e.com\xe2\x80\xa8f.com",
        ] {
            got.extend(lines.push(chunk));
        }
        got.extend(lines.finish());
        assert_eq!(got, ["a.com", "b.com", "cé.com", "d.com", "e.com", "f.com"]);
        let mut lines = Lines::new(false);
        let mut got = lines.push(b"bad\xff.com\nlast\r");
        got.extend(lines.finish());
        assert_eq!(got, ["bad\u{fffd}.com", "last"]);
    }

    /// The hash ace3 kept of the reference's list URLs (tools/ace3/dumps/nrd_reference.py).
    #[test]
    fn the_config_hash_is_ace3_s() {
        let reference: Value = serde_json::from_str(
            &std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tools/ace3/dumps/reference/nrd/reference.json"),
            )
            .expect("reads"),
        )
        .expect("JSON");
        for step in reference["refresh"].as_array().expect("steps") {
            let lists: Vec<NrdList> = step["url_lists"]
                .as_array()
                .expect("lists")
                .iter()
                .map(|l| NrdList {
                    url: format!("http://127.0.0.1:8091{}", l["url"].as_str().expect("a url")),
                    backups: vec![],
                })
                .collect();
            let Some(database) = step["database"].as_object() else {
                continue;
            };
            if step["exit_code"] == 0 {
                assert_eq!(
                    database["meta"]["config_hash"],
                    config_hash(&lists).as_str(),
                    "{}",
                    step["step"]
                );
            }
        }
        // a backup isn't in it, and the order isn't either
        let a = NrdList {
            url: "https://a.example/x".into(),
            backups: vec!["https://b.example/x".into()],
        };
        let b = NrdList {
            url: "https://c.example/é".into(),
            backups: vec![],
        };
        assert_eq!(
            config_hash(&[a.clone(), b.clone()]),
            config_hash(&[
                b,
                NrdList {
                    backups: vec![],
                    ..a
                }
            ])
        );
    }
}
