//! The lease API's client: all a worker holds is the API's URL and its pool's token.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use ace_results::Sha256;
use ace_sdk::http::{HttpClient, HttpError};
use ace_sdk::reads::{ReadError, Reader};
use ace_sdk::wire::{
    ApiError, CommandEnd, CommandLeaseRequest, CommandReply, CommandReport, CurrentRuleset,
    LeaseRequest, LeasedCommand, LeasedTask, Presigned, Renewal, TaskEnd, UploadRequest, paths,
};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use tokio::io::AsyncWriteExt;

/// The header a task-scoped request names its worker in.
pub const WORKER_HEADER: &str = "x-ace-rs-worker";

/// The timeout of each call that doesn't wait for a task or move a file.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// The timeout of a download or an upload of a file, and of a task's end, whose transaction grows
/// with the files in its result.
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

    /// The API's URL from `ACE_RS_API_URL` and the pool's token from `ACE_RS_POOL_TOKEN`.
    pub fn from_env(worker: &str) -> Result<LeaseClient, ClientError> {
        let base = std::env::var("ACE_RS_API_URL")
            .map_err(|_| ClientError::MissingConfig("ACE_RS_API_URL"))?;
        let token = std::env::var("ACE_RS_POOL_TOKEN")
            .map_err(|_| ClientError::MissingConfig("ACE_RS_POOL_TOKEN"))?;
        LeaseClient::new(&base, &token, worker)
    }

    pub fn worker(&self) -> &str {
        &self.worker
    }

    /// The TCP port the API listens on, from its URL: what a contained pool must be allowed
    /// to connect to.
    pub fn api_port(&self) -> Option<u16> {
        crate::pool::url_port(&self.base)
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
        Ok(self.lease_up_to(modules, wait, 1).await?.pop())
    }

    /// Leases tasks of `modules` (all the pool's when empty), `most` of them at most, waiting up
    /// to `wait` for the first. The core answers with those that are due, oldest first, and
    /// doesn't wait for more. Ask for no more than can start now: each task that comes back is
    /// leased to this worker from that moment.
    pub async fn lease_up_to(
        &self,
        modules: &[String],
        wait: Duration,
        most: usize,
    ) -> Result<Vec<LeasedTask>, ClientError> {
        let request = self
            .post(paths::LEASE)
            .json(&LeaseRequest {
                worker: self.worker.clone(),
                modules: modules.to_vec(),
                wait_seconds: wait.as_secs(),
                max: u32::try_from(most).unwrap_or(u32::MAX),
            })
            .timeout(wait + CALL_TIMEOUT);
        let response = self.http.send(request).await?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(Vec::new());
        }
        answer(response, 0).await
    }

    /// Leases a GUI command (PLAN.md 5.12), waiting up to `wait` for one.
    pub async fn lease_command(
        &self,
        wait: Duration,
    ) -> Result<Option<LeasedCommand>, ClientError> {
        let request = self
            .post(paths::COMMAND_LEASE)
            .json(&CommandLeaseRequest {
                worker: self.worker.clone(),
                wait_seconds: wait.as_secs(),
            })
            .timeout(wait + CALL_TIMEOUT);
        let response = self.http.send(request).await?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        answer(response, 0).await.map(Some)
    }

    /// Leases a scan of one of the pool's scanners (PLAN.md 7.7), waiting up to `wait` for one.
    pub async fn lease_scan(
        &self,
        wait: Duration,
    ) -> Result<Option<ace_sdk::scanners::LeasedScan>, ClientError> {
        let request = self
            .post(ace_sdk::scanners::paths::LEASE)
            .json(&ace_sdk::scanners::ScanLeaseRequest {
                worker: self.worker.clone(),
                wait_seconds: wait.as_secs(),
            })
            .timeout(wait + CALL_TIMEOUT);
        let response = self.http.send(request).await?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        answer(response, 0).await.map(Some)
    }

    /// Renews a scan's lease. The answer says whether its root was cancelled.
    pub async fn renew_scan(
        &self,
        scan: i64,
    ) -> Result<ace_sdk::scanners::ScanRenewal, ClientError> {
        let request = self.post(&ace_sdk::scanners::paths::scan(scan, "renew"));
        let response = self.http.send(request).await?;
        answer(response, scan).await
    }

    /// Where to upload a scan's output archive.
    pub async fn scan_upload_url(
        &self,
        scan: i64,
        sha256: &Sha256,
        size: u64,
    ) -> Result<Presigned, ClientError> {
        let request = self
            .post(&ace_sdk::scanners::paths::scan(scan, "upload"))
            .json(&ace_sdk::scanners::ScanUploadRequest {
                sha256: *sha256,
                size,
            });
        let response = self.http.send(request).await?;
        answer(response, scan).await
    }

    /// Ends a scan. Its output archive must have been uploaded first.
    pub async fn end_scan(
        &self,
        scan: i64,
        end: &ace_sdk::scanners::ScanEnd,
    ) -> Result<(), ClientError> {
        let request = self
            .post(&ace_sdk::scanners::paths::scan(scan, "end"))
            .timeout(TRANSFER_TIMEOUT)
            .json(end);
        let response = self.http.send(request).await?;
        expect_empty(response, scan).await
    }

    /// Leases an action of one of the pool's handlers (PLAN.md 7.9), waiting up to `wait` for one.
    pub async fn lease_action(
        &self,
        wait: Duration,
    ) -> Result<Option<ace_sdk::actions::LeasedAction>, ClientError> {
        let request = self
            .post(ace_sdk::actions::paths::LEASE)
            .json(&ace_sdk::actions::ActionLeaseRequest {
                worker: self.worker.clone(),
                wait_seconds: wait.as_secs(),
            })
            .timeout(wait + CALL_TIMEOUT);
        let response = self.http.send(request).await?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        answer(response, 0).await.map(Some)
    }

    /// Renews an action's lease. The answer says whether someone cancelled it.
    pub async fn renew_action(
        &self,
        action: i64,
    ) -> Result<ace_sdk::actions::ActionRenewal, ClientError> {
        let request = self.post(&ace_sdk::actions::paths::action(action, "renew"));
        let response = self.http.send(request).await?;
        answer(response, action).await
    }

    /// Where to upload the file a collection fetched.
    pub async fn action_upload_url(
        &self,
        action: i64,
        sha256: &Sha256,
        size: u64,
    ) -> Result<Presigned, ClientError> {
        let request = self
            .post(&ace_sdk::actions::paths::action(action, "upload"))
            .json(&ace_sdk::actions::ActionUploadRequest {
                sha256: *sha256,
                size,
            });
        let response = self.http.send(request).await?;
        answer(response, action).await
    }

    /// Whether the remediation's handler's latest remediation of `observable_value` covers the message
    /// (ace3's `removal_covers`).
    pub async fn removal_covers(
        &self,
        action: i64,
        observable_value: &str,
    ) -> Result<bool, ClientError> {
        let request = self
            .post(&ace_sdk::actions::paths::action(action, "removal-covers"))
            .json(&ace_sdk::actions::RemovalCoversRequest {
                observable_value: observable_value.to_owned(),
            });
        let response = self.http.send(request).await?;
        let answer: ace_sdk::actions::RemovalCoversAnswer = answer(response, action).await?;
        Ok(answer.covers)
    }

    /// Ends a try of an action. A collected file must have been uploaded first.
    pub async fn end_action(
        &self,
        action: i64,
        end: &ace_sdk::actions::ActionEnd,
    ) -> Result<(), ClientError> {
        let request = self
            .post(&ace_sdk::actions::paths::action(action, "end"))
            .timeout(TRANSFER_TIMEOUT)
            .json(end);
        let response = self.http.send(request).await?;
        expect_empty(response, action).await
    }

    /// Sends a command's output so far, which renews its lease. The answer says whether it was
    /// cancelled.
    pub async fn report_command(
        &self,
        command: i64,
        report: &CommandReport,
    ) -> Result<CommandReply, ClientError> {
        let request = self.post(&paths::command(command, "report")).json(report);
        let response = self.http.send(request).await?;
        answer(response, command).await
    }

    /// Ends a command.
    pub async fn end_command(&self, command: i64, end: &CommandEnd) -> Result<(), ClientError> {
        let request = self.post(&paths::command(command, "end")).json(end);
        let response = self.http.send(request).await?;
        expect_empty(response, command).await
    }

    pub async fn renew(&self, task: i64) -> Result<Renewal, ClientError> {
        let response = self
            .http
            .send(self.post(&paths::task(task, "renew")))
            .await?;
        answer(response, task).await
    }

    pub async fn end(&self, task: i64, end: &TaskEnd) -> Result<(), ClientError> {
        let request = self
            .post(&paths::task(task, "end"))
            .timeout(TRANSFER_TIMEOUT)
            .json(end);
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
        // these include content-length, which the URL's signature covers: the client wouldn't
        // send one for an empty body, and the bucket would answer 403
        for (name, value) in &url.headers {
            request = request.header(name, value);
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

/// A task's reads of ACE's data through the lease API (PLAN.md 7.2), as the client's worker, or
/// for a replay, through the admin route.
#[derive(Debug, Clone)]
pub struct TaskReads {
    client: LeaseClient,
    replay: bool,
}

impl LeaseClient {
    /// What makes a leased task's reads.
    pub fn reads(&self) -> TaskReads {
        TaskReads {
            client: self.clone(),
            replay: false,
        }
    }

    /// What makes a replayed task's reads: the admin route, which takes the admin token and no
    /// lease.
    pub fn replay_reads(&self) -> TaskReads {
        TaskReads {
            client: self.clone(),
            replay: true,
        }
    }

    /// One read for task `task`, answering its JSON.
    pub async fn read(
        &self,
        task: i64,
        read: &'static str,
        request: &serde_json::Value,
        replay: bool,
    ) -> Result<serde_json::Value, ReadError> {
        let path = if replay {
            paths::replay_read(task, read)
        } else {
            paths::read(task, read)
        };
        let response = self
            .http
            .send(self.post(&path).json(request))
            .await
            .map_err(|e| {
                if e.is_unavailable() {
                    ReadError::Unavailable {
                        read,
                        source: e.into(),
                    }
                } else {
                    ReadError::Other {
                        read,
                        source: e.into(),
                    }
                }
            })?;
        let status = response.status();
        if status.is_success() {
            return response.json().await.map_err(|e| ReadError::Other {
                read,
                source: e.into(),
            });
        }
        let message = response
            .json::<ApiError>()
            .await
            .map(|e| e.error)
            .unwrap_or_else(|e| format!("an unreadable error body: {e}"));
        Err(match status.as_u16() {
            409 => ReadError::LeaseLost(read),
            429 | 502 | 503 | 504 => ReadError::Unavailable {
                read,
                source: format!("{status}: {message}").into(),
            },
            code => ReadError::Refused {
                read,
                status: code,
                message,
            },
        })
    }
}

impl Reader for TaskReads {
    fn read<'a>(
        &'a self,
        task: i64,
        read: &'static str,
        request: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, ReadError>> + Send + 'a>> {
        Box::pin(async move { self.client.read(task, read, &request, self.replay).await })
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
