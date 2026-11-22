//! A search run to its end, for the hunter (PLAN.md 6.4): ace3's `SplunkQueryObject.query_async`
//! loop as `SplunkHunt.execute_query` drives it (`saq/splunk.py`, `splunk_hunter.py`).
//!
//! The module above polls a job across task delays; a hunt waits for its search in one run, so
//! this client submits the job and polls it every `poll` until it's done, and then reads its rows
//! and deletes it, at the same paths splunk-sdk uses for ace3: a login, the server info that picks
//! the v2 or v1 search API, the job, its status, its results with `output_mode=json`, and its
//! deletion. The caller builds the job's form (`ace_hunt::splunk::search`).
//!
//! Every wait is bounded (PLAN.md 2.21): each request by `request_timeout`, a job that never
//! starts by `dispatch_timeout` from its submission, one that runs by `query_timeout` from when it
//! started, as ace3 measures them, and a stop ends the wait at once. A job that times out or is
//! stopped is cancelled, as ace3 cancels it.

use std::future::Future;
use std::time::{Duration, Instant};

use ace_sdk::http::{HttpClient, HttpError};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde_json::{Map, Value};
use tokio::sync::Mutex;

use crate::rest;

const FORM: &str = "application/x-www-form-urlencoded";

/// How to reach one Splunk instance.
#[derive(Debug, Clone)]
pub struct Connection {
    /// splunkd's management API, such as `https://splunk.example.com:8089`.
    pub base_url: String,
    /// Logs in as this user with `password`; without one, requests carry `token`.
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    /// A PEM file of CA certificates to trust besides the platform's.
    pub ca_certificates: Option<std::path::PathBuf>,
    pub request_timeout: Duration,
}

/// The bounds of one search.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Between two reads of a job's status; ace3's hunter waits 3 seconds.
    pub poll: Duration,
    /// How long a job may wait to start, ace3's `dispatch_timeout` (900 seconds).
    pub dispatch_timeout: Duration,
    /// How long a running job may run, the hunt's `query_timeout`.
    pub query_timeout: Duration,
}

/// Why a search gave no rows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SearchError {
    /// splunkd couldn't be reached, or answered that it's down or busy.
    #[error("splunk is unavailable: {0}")]
    Unavailable(String),
    /// splunkd refused the search or reported it failed, as ace3's `RemoteApiError`.
    #[error("Splunk search failed: {0}")]
    Failed(String),
    #[error("Splunk search exceeded its {phase} budget of {budget:?}")]
    TimedOut {
        phase: &'static str,
        budget: Duration,
    },
    #[error("the search was stopped")]
    Stopped,
}

impl From<HttpError> for SearchError {
    fn from(error: HttpError) -> Self {
        if error.is_unavailable() {
            SearchError::Unavailable(error.to_string())
        } else {
            SearchError::Failed(error.to_string())
        }
    }
}

/// A client for one Splunk instance.
pub struct SearchClient {
    client: HttpClient,
    connection: Connection,
    base_url: String,
    session: Mutex<Option<String>>,
}

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

impl Reply {
    fn into_body(self) -> Result<Vec<u8>, SearchError> {
        if self.status.is_success() {
            Ok(self.body)
        } else {
            Err(SearchError::Failed(status_text(self.status, &self.body)))
        }
    }
}

/// An error status as splunklib's `HTTPError` words it.
fn status_text(status: StatusCode, body: &[u8]) -> String {
    let mut text = format!(
        "HTTP {} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or_default()
    );
    if let Some(messages) = rest::messages(&String::from_utf8_lossy(body)) {
        text.push_str(" -- ");
        text.push_str(&messages);
    }
    text
}

impl SearchClient {
    pub fn new(connection: Connection) -> Result<SearchClient, String> {
        let mut builder = HttpClient::builder().timeout(connection.request_timeout);
        if let Some(path) = &connection.ca_certificates {
            let pem = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
            builder = builder
                .add_root_certificates_pem(&pem)
                .map_err(|e| e.to_string())?;
        }
        Ok(SearchClient {
            client: builder.build().map_err(|e| e.to_string())?,
            base_url: connection.base_url.trim_end_matches('/').to_owned(),
            connection,
            session: Mutex::new(None),
        })
    }

    /// Runs a search in the namespace of `owner` and `app` (splunk-sdk's), with `form` the job's
    /// form, encoded, and returns its rows. `stop` ends the wait.
    pub async fn search(
        &self,
        owner: Option<&str>,
        app: Option<&str>,
        form: &str,
        limits: Limits,
        stop: impl Future<Output = ()>,
    ) -> Result<Vec<Map<String, Value>>, SearchError> {
        tokio::pin!(stop);
        let namespace = rest::namespace(owner, app);
        let (jobs, mut sid) = self.submit(&namespace, form).await?;
        let mut submitted = Instant::now();
        let mut running: Option<Instant> = None;
        loop {
            // the job's state: wait for it, unless the budget it's in has run out
            let (phase, budget, since) = match running {
                Some(started) => ("run", limits.query_timeout, started),
                None => ("dispatch queue", limits.dispatch_timeout, submitted),
            };
            let left = budget.saturating_sub(since.elapsed());
            let wait = limits.poll.min(left);
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = &mut stop => {
                    self.cancel(&namespace, jobs, &sid).await;
                    return Err(SearchError::Stopped);
                }
            }
            if since.elapsed() >= budget {
                tracing::warn!(sid, phase, ?budget, "splunk search timed out");
                self.cancel(&namespace, jobs, &sid).await;
                return Err(SearchError::TimedOut { phase, budget });
            }
            let url = format!(
                "{}{namespace}/{jobs}/{}",
                self.base_url,
                rest::segment(&sid)
            );
            let reply = self.call(Method::GET, &url, None).await?;
            if reply.status == StatusCode::NO_CONTENT {
                // splunk lost the job: ace3 queues the search again
                tracing::info!(sid, "splunk answered 204 for a job; submitting it again");
                (_, sid) = self.submit(&namespace, form).await?;
                submitted = Instant::now();
                running = None;
                continue;
            }
            let body = reply.into_body()?;
            let job = rest::entry_content(&String::from_utf8_lossy(&body))
                .map_err(SearchError::Failed)?;
            let text = |key: &str| job.get(key).and_then(Value::as_str).unwrap_or_default();
            let state = text("dispatchState");
            if matches!(state, "QUEUED" | "PARSING") {
                tracing::info!(sid, state, "splunk search is not ready yet");
                continue;
            }
            if state == "RUNNING" && running.is_none() {
                running = Some(Instant::now());
            }
            tracing::info!(
                "{sid} dispatch state {state} done progress: {} is failed {} event count {} run duration {}",
                text("doneProgress"),
                text("isFailed"),
                text("eventCount"),
                text("runDuration"),
            );
            if text("isDone") != "1" {
                if !text("isFailed").is_empty() && text("isFailed") != "0" {
                    self.cancel(&namespace, jobs, &sid).await;
                    return Err(SearchError::Failed(
                        "Splunk search reported as failed".to_owned(),
                    ));
                }
                continue;
            }
            // splunklib reads and deletes a job in the namespace of its acl
            let job_url = format!(
                "{}{}/{jobs}/{}",
                self.base_url,
                rest::job_namespace(job.get("eai:acl"), &namespace),
                rest::segment(&sid)
            );
            let query = [
                ("count", "0"),
                ("output_mode", "json"),
                ("segmentation", "none"),
            ];
            let reply = if jobs == "search/v2/jobs" {
                self.call(
                    Method::POST,
                    &format!("{job_url}/results"),
                    Some(rest::form(&query)),
                )
                .await?
            } else {
                let url = format!("{job_url}/results?{}", rest::form(&query));
                self.call(Method::GET, &url, None).await?
            };
            let rows = match reply.into_body() {
                Ok(body) => rest::result_rows(&body).map_err(SearchError::Failed),
                Err(e) => Err(e),
            };
            self.delete(&format!("{job_url}/")).await;
            let rows = rows?;
            tracing::info!(sid, rows = rows.len(), "got results");
            return Ok(rows);
        }
    }

    /// Creates the job, on the search API the server's version allows.
    async fn submit(
        &self,
        namespace: &str,
        form: &str,
    ) -> Result<(&'static str, String), SearchError> {
        let url = format!("{}/services/server/info", self.base_url);
        let body = self.call(Method::GET, &url, None).await?.into_body()?;
        let info =
            rest::entry_content(&String::from_utf8_lossy(&body)).map_err(SearchError::Failed)?;
        let jobs = rest::jobs_path(&info);
        let url = format!("{}{namespace}/{jobs}/", self.base_url);
        let body = self
            .call(Method::POST, &url, Some(form.to_owned()))
            .await?
            .into_body()?;
        let sid = rest::element_text(&String::from_utf8_lossy(&body), "sid")
            .filter(|sid| !sid.is_empty())
            .ok_or_else(|| {
                SearchError::Failed("splunkd answered a new search without a sid".into())
            })?;
        tracing::info!(sid, "submitted splunk search");
        Ok((jobs, sid))
    }

    /// Cancels a job, as ace3's `cancel`: a failure is logged.
    async fn cancel(&self, namespace: &str, jobs: &str, sid: &str) {
        let url = format!(
            "{}{namespace}/{jobs}/{}/control",
            self.base_url,
            rest::segment(sid)
        );
        match self
            .call(
                Method::POST,
                &url,
                Some(rest::form(&[("action", "cancel")])),
            )
            .await
        {
            Ok(reply) if reply.status.is_success() => {}
            Ok(reply) => tracing::warn!(
                sid,
                "unable to cancel search: {}",
                status_text(reply.status, &reply.body)
            ),
            Err(e) => tracing::warn!(sid, "unable to cancel search: {e}"),
        }
    }

    /// Deletes a job, as ace3's `delete_search_job`: a failure is logged.
    async fn delete(&self, url: &str) {
        match self.call(Method::DELETE, url, None).await {
            Ok(reply) if reply.status.is_success() => {}
            Ok(reply) => tracing::warn!(
                "unable to delete search: {}",
                status_text(reply.status, &reply.body)
            ),
            Err(e) => tracing::warn!("unable to delete search: {e}"),
        }
    }

    /// A request with the session's or the token's `Authorization`. A 401 logs in again once, as
    /// splunklib's autologin does with a username. splunkd down or busy is `Unavailable`.
    async fn call(
        &self,
        method: Method,
        url: &str,
        form: Option<String>,
    ) -> Result<Reply, SearchError> {
        let mut fresh = false;
        loop {
            let authorization = self.authorization(fresh).await?;
            let mut request = self
                .client
                .request(method.clone(), url)
                .header(AUTHORIZATION, authorization);
            if let Some(body) = &form {
                request = request.header(CONTENT_TYPE, FORM).body(body.clone());
            }
            let response = self.client.send(request).await?;
            let status = response.status();
            if status == StatusCode::UNAUTHORIZED && !fresh && self.connection.username.is_some() {
                fresh = true;
                continue;
            }
            if let Err(error) = response.error_for_status_ref() {
                let error = HttpError::from_reqwest(error);
                if error.is_unavailable() {
                    return Err(SearchError::Unavailable(error.to_string()));
                }
            }
            let body = response.bytes().await.map_err(HttpError::from_reqwest)?;
            return Ok(Reply {
                status,
                body: body.to_vec(),
            });
        }
    }

    /// The `Authorization` header. A client made without its credential, as `ace serve` makes one
    /// to validate hunts, or whose secret wasn't resolved, fails the search here, as ace3's client
    /// fails to build: `username and password or token must be provided`.
    async fn authorization(&self, fresh: bool) -> Result<String, SearchError> {
        let missing =
            || SearchError::Failed("username and password or token must be provided".to_owned());
        let Some(username) = self.connection.username.as_deref() else {
            let token = self.connection.token.as_deref().ok_or_else(missing)?;
            return Ok(
                if token.starts_with("Splunk ") || token.starts_with("Bearer ") {
                    token.to_owned()
                } else {
                    format!("Splunk {token}")
                },
            );
        };
        let mut session = self.session.lock().await;
        if !fresh && let Some(session) = session.clone() {
            return Ok(session);
        }
        let url = format!("{}/services/auth/login", self.base_url);
        let password = self.connection.password.as_deref().ok_or_else(missing)?;
        let request = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, FORM)
            .body(rest::form(&[
                ("username", username),
                ("password", password),
            ]));
        let response = self.client.send(request).await?;
        let status = response.status();
        if let Err(error) = response.error_for_status_ref() {
            let error = HttpError::from_reqwest(error);
            if error.is_unavailable() {
                return Err(SearchError::Unavailable(error.to_string()));
            }
        }
        let body = response.bytes().await.map_err(HttpError::from_reqwest)?;
        if !status.is_success() {
            return Err(SearchError::Failed(format!(
                "Splunk authentication failed: {}",
                status_text(status, &body)
            )));
        }
        let key = rest::element_text(&String::from_utf8_lossy(&body), "sessionKey")
            .filter(|key| !key.is_empty())
            .ok_or_else(|| {
                SearchError::Failed("splunkd answered the login without a sessionKey".into())
            })?;
        let value = format!("Splunk {key}");
        *session = Some(value.clone());
        Ok(value)
    }
}
