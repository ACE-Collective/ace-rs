//! The lease API's client: all a worker holds is the API's URL and its pool's token.

use std::path::Path;
use std::time::Duration;

use ace_results::Sha256;
use ace_sdk::http::{HttpClient, HttpError};
use ace_sdk::wire::{
    ApiError, CurrentRuleset, LeaseRequest, LeasedTask, Presigned, Renewal, TaskEnd, UploadRequest,
    paths,
};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use tokio::io::AsyncWriteExt;

/// The header a task-scoped request names its worker in.
pub const WORKER_HEADER: &str = "x-ace4-worker";

/// The timeout of each call that doesn't wait for a task or move a file.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// The timeout of a download or an upload of a file.
pub const TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("{0} isn't set")]
    MissingConfig(&'static str),
    #[error(transparent)]
    Http(#[from] HttpError),
    /// The worker no longer holds the task's lease.
    #[error("the lease on task {0} was lost")]
    LeaseLost(i64),
    /// The task's root was cancelled.
    #[error("task {0} was cancelled")]
    Cancelled(i64),
    #[error("the lease API answered {status}: {}", .error.error)]
    Api { status: u16, error: ApiError },
    #[error("the bucket answered {status} for {what}")]
    Bucket { status: u16, what: &'static str },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ClientError {
    /// True when the API or the bucket couldn't be reached, so trying again later may work.
    pub fn is_unavailable(&self) -> bool {
        match self {
            ClientError::Http(e) => e.is_unavailable(),
            ClientError::Api { status, .. } | ClientError::Bucket { status, .. } => {
                matches!(status, 429 | 502 | 503 | 504)
            }
            _ => false,
        }
    }
}

/// One worker's connection to the lease API.
#[derive(Debug, Clone)]
pub struct LeaseClient {
    http: HttpClient,
    base: String,
    token: String,
    worker: String,
}

impl LeaseClient {
    /// A client for the API at `base`, such as `http://ace:8080`, as `worker` of the pool
    /// whose token is `token`.
    pub fn new(base: &str, token: &str, worker: &str) -> Result<LeaseClient, ClientError> {
        Ok(LeaseClient {
            http: HttpClient::builder().timeout(CALL_TIMEOUT).build()?,
            base: base.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
            worker: worker.to_owned(),
        })
    }

    /// The API's URL from `ACE4_API_URL` and the pool's token from `ACE4_POOL_TOKEN`.
    pub fn from_env(worker: &str) -> Result<LeaseClient, ClientError> {
        let base = std::env::var("ACE4_API_URL")
            .map_err(|_| ClientError::MissingConfig("ACE4_API_URL"))?;
        let token = std::env::var("ACE4_POOL_TOKEN")
            .map_err(|_| ClientError::MissingConfig("ACE4_POOL_TOKEN"))?;
        LeaseClient::new(&base, &token, worker)
    }

    pub fn worker(&self) -> &str {
        &self.worker
    }

    /// The TCP port the API listens on, from its URL: what a contained pool must be allowed
    /// to connect to.
    pub fn api_port(&self) -> Option<u16> {
        let (scheme, rest) = self.base.split_once("://")?;
        let authority = rest.split('/').next()?;
        match authority.rsplit_once(':') {
            Some((_, port)) => port.parse().ok(),
            None => match scheme {
                "http" => Some(80),
                "https" => Some(443),
                _ => None,
            },
        }
    }

    /// The same pool and API, as another worker.
    pub fn as_worker(&self, worker: &str) -> LeaseClient {
        LeaseClient {
            worker: worker.to_owned(),
            ..self.clone()
        }
    }

    /// A call to the API, carrying the current span's context so the API's spans join its
    /// trace (PLAN.md 2.22).
    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .post(&format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .header(WORKER_HEADER, &self.worker);
        for (name, value) in crate::telemetry::trace_headers() {
            request = request.header(name, value);
        }
        request
    }

    /// Leases a task of `modules` (all the pool's when empty), waiting up to `wait` for one.
    pub async fn lease(
        &self,
        modules: &[String],
        wait: Duration,
    ) -> Result<Option<LeasedTask>, ClientError> {
        let request = self
            .post(paths::LEASE)
            .json(&LeaseRequest {
                worker: self.worker.clone(),
                modules: modules.to_vec(),
                wait_seconds: wait.as_secs(),
            })
            .timeout(wait + CALL_TIMEOUT);
        let response = self.http.send(request).await?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        answer(response, 0).await.map(Some)
    }

    pub async fn renew(&self, task: i64) -> Result<Renewal, ClientError> {
        let response = self
            .http
            .send(self.post(&paths::task(task, "renew")))
            .await?;
        answer(response, task).await
    }

    pub async fn end(&self, task: i64, end: &TaskEnd) -> Result<(), ClientError> {
        let request = self.post(&paths::task(task, "end")).json(end);
        let response = self.http.send(request).await?;
        expect_empty(response, task).await
    }

    /// Gives the task back to the queue without counting the attempt, as at shutdown.
    pub async fn release(&self, task: i64) -> Result<(), ClientError> {
        let response = self
            .http
            .send(self.post(&paths::task(task, "release")))
            .await?;
        expect_empty(response, task).await
    }

    /// A task in its leased form, with a fresh download URL for its input, for a replay. It
    /// takes the admin token and takes no lease.
    pub async fn replay_task(&self, task: i64) -> Result<LeasedTask, ClientError> {
        let request = self
            .http
            .get(&format!("{}{}", self.base, paths::replay(task)))
            .bearer_auth(&self.token);
        let response = self.http.send(request).await?;
        answer(response, task).await
    }

    /// The ruleset YARA pools should scan with, or None before the core built one.
    pub async fn current_ruleset(&self) -> Result<Option<CurrentRuleset>, ClientError> {
        let mut request = self
            .http
            .get(&format!("{}{}", self.base, paths::RULESET))
            .bearer_auth(&self.token);
        for (name, value) in crate::telemetry::trace_headers() {
            request = request.header(name, value);
        }
        let response = self.http.send(request).await?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        answer(response, 0).await.map(Some)
    }

    /// Where to upload a file the task's module wrote.
    pub async fn upload_url(
        &self,
        task: i64,
        sha256: &Sha256,
        size: u64,
    ) -> Result<Presigned, ClientError> {
        let request = self
            .post(&paths::task(task, "uploads"))
            .json(&UploadRequest {
                sha256: *sha256,
                size,
            });
        let response = self.http.send(request).await?;
        answer(response, task).await
    }

    /// Downloads a presigned URL to `dest`.
    pub async fn download(&self, url: &Presigned, dest: &Path) -> Result<u64, ClientError> {
        let mut request = self.http.get(&url.url).timeout(TRANSFER_TIMEOUT);
        for (name, value) in &url.headers {
            request = request.header(name, value);
        }
        let mut response = self.http.send(request).await?;
        if !response.status().is_success() {
            return Err(ClientError::Bucket {
                status: response.status().as_u16(),
                what: "a download",
            });
        }
        let mut file = tokio::fs::File::create(dest).await?;
        let mut size = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(HttpError::from_reqwest)? {
            file.write_all(&chunk).await?;
            size += chunk.len() as u64;
        }
        file.flush().await?;
        Ok(size)
    }

    /// Uploads the file at `path` to a presigned URL.
    pub async fn upload(&self, url: &Presigned, path: &Path) -> Result<(), ClientError> {
        let bytes = tokio::fs::read(path).await?;
        let mut request = self
            .http
            .request(reqwest::Method::PUT, &url.url)
            .timeout(TRANSFER_TIMEOUT)
            .body(bytes);
        for (name, value) in &url.headers {
            // the client sets the length from the body
            if !name.eq_ignore_ascii_case("content-length") {
                request = request.header(name, value);
            }
        }
        let response = self.http.send(request).await?;
        if !response.status().is_success() {
            return Err(ClientError::Bucket {
                status: response.status().as_u16(),
                what: "an upload",
            });
        }
        Ok(())
    }
}

async fn failure(response: reqwest::Response, task: i64) -> ClientError {
    let status = response.status();
    match status {
        StatusCode::CONFLICT => ClientError::LeaseLost(task),
        StatusCode::GONE => ClientError::Cancelled(task),
        _ => {
            let error = response
                .json::<ApiError>()
                .await
                .unwrap_or_else(|e| ApiError {
                    error: format!("an unreadable error body: {e}"),
                    fields: Vec::new(),
                });
            ClientError::Api {
                status: status.as_u16(),
                error,
            }
        }
    }
}

async fn answer<T: DeserializeOwned>(
    response: reqwest::Response,
    task: i64,
) -> Result<T, ClientError> {
    if !response.status().is_success() {
        return Err(failure(response, task).await);
    }
    Ok(response.json().await.map_err(HttpError::from_reqwest)?)
}

async fn expect_empty(response: reqwest::Response, task: i64) -> Result<(), ClientError> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(failure(response, task).await)
    }
}
