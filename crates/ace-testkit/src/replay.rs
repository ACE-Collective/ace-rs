//! Serving recorded HTTP exchanges to a lookup module, so its tests never reach the internet.
//!
//! The reference dumps keep the exchanges a lookup made in `<dump>.http/http.json`, with each
//! response body in its own file (`tools/ace3/dumps/run_module.py`). `HttpReplay` serves them on
//! 127.0.0.1 over plain HTTP. A request for `/<scheme>/<host>/<path>` gets the recorded response
//! to `<scheme>://<host>/<path>`, and a request nothing was recorded for gets a 404 and is noted,
//! so a test can fail on it. URLs inside the bodies of chosen responses, such as a bootstrap
//! registry's server list, are pointed at the replay too, so the module comes back here.
//!
//! A URL asked for more than once gets its recorded responses in the order they were recorded,
//! and the last one again after that, so a job polled until it finishes answers "running,
//! running, done" as it did for ace3. The replay keeps each request's headers and body, so a
//! test can check what the module sent.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use regex::bytes::Regex;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::HarnessError;

#[derive(Deserialize)]
struct Recording {
    exchanges: Vec<RecordedExchange>,
}

#[derive(Deserialize)]
struct RecordedExchange {
    method: String,
    url: String,
    status: Option<u16>,
    #[serde(default)]
    response_headers: std::collections::BTreeMap<String, String>,
    body_file: Option<String>,
}

struct Exchange {
    method: String,
    url: String,
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

/// A request the replay received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The original URL.
    pub url: String,
    /// The headers, as sent.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first header named `name`, in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct Log {
    requests: Vec<Request>,
    unmatched: Vec<String>,
    /// How many times each (method, URL) was asked for.
    served: HashMap<(String, String), usize>,
}

/// The exchanges in `dir/http.json` that can be replayed, with the URLs in the bodies of
/// responses to URLs that start with one of `rewrite` pointed at `base`.
fn load(dir: &Path, rewrite: &[&str], base: &str) -> Result<Vec<Exchange>, HarnessError> {
    let path = dir.join("http.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| HarnessError::Fixture(format!("{}: {e}", path.display())))?;
    let recording: Recording = serde_json::from_str(&text)
        .map_err(|e| HarnessError::Fixture(format!("{}: {e}", path.display())))?;
    let url_pattern = Regex::new(r"(https?)://").expect("valid regex");
    let mut exchanges = Vec::new();
    for recorded in recording.exchanges {
        // a body too large to keep, or a request that failed, can't be replayed
        let (Some(status), Some(body_file)) = (recorded.status, &recorded.body_file) else {
            continue;
        };
        let body_path = dir.join(body_file);
        let mut body = std::fs::read(&body_path)
            .map_err(|e| HarnessError::Fixture(format!("{}: {e}", body_path.display())))?;
        if rewrite
            .iter()
            .any(|prefix| recorded.url.starts_with(prefix))
        {
            body = url_pattern
                .replace_all(&body, format!("{base}/$1/").as_bytes())
                .into_owned();
        }
        let content_type = recorded
            .response_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.clone());
        exchanges.push(Exchange {
            method: recorded.method,
            url: recorded.url,
            status,
            content_type,
            body,
        });
    }
    Ok(exchanges)
}

/// A local server for recorded exchanges.
pub struct HttpReplay {
    base: String,
    log: Arc<Mutex<Log>>,
    task: JoinHandle<()>,
}

impl HttpReplay {
    /// Serves the exchanges in `dir/http.json`. The bodies of responses to URLs that start with
    /// one of `rewrite` get every `http://` and `https://` URL in them pointed here.
    pub async fn start(dir: &Path, rewrite: &[&str]) -> Result<HttpReplay, HarnessError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        HttpReplay::serve(&[(dir, rewrite)], listener, None).await
    }

    /// Serves several recordings on `listener`, as one server, such as the recorded-response
    /// service of the Compose stack's end-to-end test. Rewritten URLs point at `public_base`,
    /// the URL clients reach the server at, or at the listener's own address.
    pub async fn serve(
        recordings: &[(&Path, &[&str])],
        listener: TcpListener,
        public_base: Option<String>,
    ) -> Result<HttpReplay, HarnessError> {
        let addr: SocketAddr = listener.local_addr()?;
        let base = public_base.unwrap_or_else(|| format!("http://{addr}"));
        let mut exchanges = Vec::new();
        for (dir, rewrite) in recordings {
            exchanges.extend(load(dir, rewrite, &base)?);
        }
        let exchanges = Arc::new(exchanges);
        let log = Arc::new(Mutex::new(Log::default()));
        let task = {
            let log = log.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let exchanges = exchanges.clone();
                    let log = log.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, &exchanges, &log).await {
                            eprintln!("http replay: {e}");
                        }
                    });
                }
            })
        };
        Ok(HttpReplay { base, log, task })
    }

    /// Where the replay serves `original`.
    pub fn local_url(&self, original: &str) -> String {
        match original.split_once("://") {
            Some((scheme, rest)) => format!("{}/{scheme}/{rest}", self.base),
            None => format!("{}/{original}", self.base),
        }
    }

    /// The original URL of every request, in order.
    pub fn requested(&self) -> Vec<String> {
        self.requests().into_iter().map(|r| r.url).collect()
    }

    /// Every request, in order, with its method and body.
    pub fn requests(&self) -> Vec<Request> {
        self.log
            .lock()
            .map(|log| log.requests.clone())
            .unwrap_or_default()
    }

    /// Requests nothing was recorded for.
    pub fn unmatched(&self) -> Vec<String> {
        self.log
            .lock()
            .map(|log| log.unmatched.clone())
            .unwrap_or_default()
    }
}

impl Drop for HttpReplay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    mut stream: TcpStream,
    exchanges: &[Exchange],
    log: &Mutex<Log>,
) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut buffer = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buffer[..read]);
    }
    let end = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(head.len(), |at| at + 4);
    let mut body = head.split_off(end);
    let head = String::from_utf8_lossy(&head);
    let headers: Vec<(String, String)> = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    while body.len() < length {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buffer[..read]);
    }
    let mut request_line = head.lines().next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let path = request_line.next().unwrap_or_default();
    let original = match path.trim_start_matches('/').split_once('/') {
        Some((scheme, rest)) => format!("{scheme}://{rest}"),
        None => path.to_owned(),
    };
    let found = match log.lock() {
        Ok(mut log) => {
            let served = log
                .served
                .entry((method.clone(), original.clone()))
                .or_insert(0);
            let matching: Vec<&Exchange> = exchanges
                .iter()
                .filter(|e| e.method == method && e.url == original)
                .collect();
            // the nth request for a URL gets its nth recorded response, then the last again
            let found = matching.get(*served).or(matching.last()).copied();
            *served += 1;
            log.requests.push(Request {
                method: method.clone(),
                url: original.clone(),
                headers,
                body,
            });
            if found.is_none() {
                log.unmatched.push(format!("{method} {original}"));
            }
            found
        }
        Err(_) => None,
    };
    let (status, content_type, body): (u16, Option<&str>, &[u8]) = match found {
        Some(e) => (e.status, e.content_type.as_deref(), &e.body),
        None => (404, Some("text/plain"), b"not recorded"),
    };
    let mut response = format!("HTTP/1.1 {status} Replayed\r\n");
    if let Some(content_type) = content_type {
        response.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    response.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}
