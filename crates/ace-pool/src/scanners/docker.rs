//! The few calls of Docker's Engine API a scanner pool makes, over its Unix socket: create, start,
//! wait for, stop, kill and remove a container, copy a tar into it and its output directory out,
//! read its logs, and list containers by label.
//!
//! What comes back from the daemon is the daemon's: JSON this reads, and two byte streams it never
//! looks inside, the archive of the output directory and the log streams, which go to files up to a
//! limit. Paths in requests are fixed or are a container's id, which the daemon chose.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::Value;
use tokio::io::AsyncWriteExt;

/// The most a JSON answer may hold.
const MAX_JSON_BYTES: u64 = 4 << 20;
/// How long any one call that doesn't wait for the container may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    #[error("the Docker socket {0}: {1}")]
    Connect(PathBuf, #[source] std::io::Error),
    #[error("Docker's API: {0}")]
    Http(#[from] hyper::Error),
    #[error("a request to Docker: {0}")]
    Request(#[from] hyper::http::Error),
    #[error("Docker answered {status} to {what}: {message}")]
    Status {
        status: u16,
        what: String,
        message: String,
    },
    #[error("Docker's answer to {0} didn't read: {1}")]
    Json(String, #[source] serde_json::Error),
    #[error("{what} is past {limit} bytes")]
    TooLarge { what: String, limit: u64 },
    #[error("{0} took longer than {1:?}")]
    Timeout(String, Duration),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl DockerError {
    /// The daemon has no such container.
    pub fn is_not_found(&self) -> bool {
        matches!(self, DockerError::Status { status: 404, .. })
    }
}

/// A container as the list call names it.
#[derive(Debug, Clone, Deserialize)]
pub struct Listed {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Labels", default)]
    pub labels: std::collections::BTreeMap<String, String>,
}

/// The daemon behind a Unix socket.
#[derive(Debug, Clone)]
pub struct Docker {
    socket: PathBuf,
}

/// One answer, read whole up to a limit or into a file.
type Answer = hyper::Response<hyper::body::Incoming>;

impl Docker {
    pub fn new(socket: impl Into<PathBuf>) -> Docker {
        Docker {
            socket: socket.into(),
        }
    }

    /// Sends one request on a connection of its own.
    async fn send(
        &self,
        method: Method,
        path: &str,
        content_type: Option<&str>,
        body: Bytes,
    ) -> Result<Answer, DockerError> {
        let stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|e| DockerError::Connect(self.socket.clone(), e))?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!("a Docker connection ended: {e}");
            }
        });
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, "docker");
        if let Some(content_type) = content_type {
            request = request.header(hyper::header::CONTENT_TYPE, content_type);
        }
        Ok(sender.send_request(request.body(Full::new(body))?).await?)
    }

    /// A call whose answer is JSON or empty, within `CALL_TIMEOUT`.
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Bytes), DockerError> {
        let what = format!("{method} {}", path.split('?').next().unwrap_or(path));
        let work = async {
            let (content_type, bytes) = match body {
                Some(body) => (
                    Some("application/json"),
                    Bytes::from(
                        serde_json::to_vec(body).map_err(|e| DockerError::Json(what.clone(), e))?,
                    ),
                ),
                None => (None, Bytes::new()),
            };
            let answer = self.send(method, path, content_type, bytes).await?;
            let status = answer.status();
            let bytes = read_limited(answer, MAX_JSON_BYTES, &what).await?;
            if !status.is_success() && status != StatusCode::NOT_MODIFIED {
                return Err(DockerError::Status {
                    status: status.as_u16(),
                    what: what.clone(),
                    message: message(&bytes),
                });
            }
            Ok((status, bytes))
        };
        tokio::time::timeout(CALL_TIMEOUT, work)
            .await
            .map_err(|_| DockerError::Timeout(what.clone(), CALL_TIMEOUT))?
    }

    /// `docker create --name <name>` with this body, which returns the container's id.
    pub async fn create(&self, name: &str, body: &Value) -> Result<String, DockerError> {
        #[derive(Deserialize)]
        struct Created {
            #[serde(rename = "Id")]
            id: String,
        }
        let path = format!("/containers/create?name={}", encode(name));
        let (_, bytes) = self.call(Method::POST, &path, Some(body)).await?;
        let created: Created = serde_json::from_slice(&bytes)
            .map_err(|e| DockerError::Json("container create".to_owned(), e))?;
        Ok(created.id)
    }

    /// Unpacks the tar `archive` at `/` in a container that hasn't started.
    pub async fn put_archive(&self, id: &str, archive: Vec<u8>) -> Result<(), DockerError> {
        let path = format!("/containers/{}/archive?path=%2F", encode(id));
        let what = "PUT /containers/archive".to_owned();
        let work = async {
            let answer = self
                .send(
                    Method::PUT,
                    &path,
                    Some("application/x-tar"),
                    Bytes::from(archive),
                )
                .await?;
            let status = answer.status();
            let bytes = read_limited(answer, MAX_JSON_BYTES, &what).await?;
            if !status.is_success() {
                return Err(DockerError::Status {
                    status: status.as_u16(),
                    what: what.clone(),
                    message: message(&bytes),
                });
            }
            Ok(())
        };
        tokio::time::timeout(CALL_TIMEOUT, work)
            .await
            .map_err(|_| DockerError::Timeout("copying the inputs in".to_owned(), CALL_TIMEOUT))?
    }

    pub async fn start(&self, id: &str) -> Result<(), DockerError> {
        let path = format!("/containers/{}/start", encode(id));
        self.call(Method::POST, &path, None).await.map(|_| ())
    }

    /// Waits until the container isn't running and returns its exit code. It has no timeout of its
    /// own: the caller selects on it.
    pub async fn wait(&self, id: &str) -> Result<i64, DockerError> {
        #[derive(Deserialize)]
        struct Waited {
            #[serde(rename = "StatusCode")]
            status_code: i64,
        }
        let path = format!("/containers/{}/wait?condition=not-running", encode(id));
        let what = "POST /containers/wait".to_owned();
        let answer = self.send(Method::POST, &path, None, Bytes::new()).await?;
        let status = answer.status();
        let bytes = read_limited(answer, MAX_JSON_BYTES, &what).await?;
        if !status.is_success() {
            return Err(DockerError::Status {
                status: status.as_u16(),
                what,
                message: message(&bytes),
            });
        }
        let waited: Waited =
            serde_json::from_slice(&bytes).map_err(|e| DockerError::Json(what, e))?;
        Ok(waited.status_code)
    }

    /// `docker stop --time <grace>`: SIGTERM, then SIGKILL after `grace`.
    pub async fn stop(&self, id: &str, grace: Duration) -> Result<(), DockerError> {
        let path = format!("/containers/{}/stop?t={}", encode(id), grace.as_secs());
        self.call(Method::POST, &path, None).await.map(|_| ())
    }

    pub async fn kill(&self, id: &str) -> Result<(), DockerError> {
        let path = format!("/containers/{}/kill", encode(id));
        match self.call(Method::POST, &path, None).await {
            // 409: it isn't running
            Err(DockerError::Status { status: 409, .. }) => Ok(()),
            other => other.map(|_| ()),
        }
    }

    /// `docker rm -f -v`: kills it if it runs and removes it with its anonymous volumes.
    pub async fn remove(&self, id: &str) -> Result<(), DockerError> {
        let path = format!("/containers/{}?force=true&v=true", encode(id));
        match self.call(Method::DELETE, &path, None).await {
            Err(e) if e.is_not_found() => Ok(()),
            other => other.map(|_| ()),
        }
    }

    /// Writes the tar of `dir` in the container to `dest`, failing past `limit` bytes.
    pub async fn get_archive(
        &self,
        id: &str,
        dir: &str,
        dest: &Path,
        limit: u64,
    ) -> Result<u64, DockerError> {
        let path = format!("/containers/{}/archive?path={}", encode(id), encode(dir));
        self.download(&path, "the output directory", dest, limit)
            .await
    }

    /// Writes one of the container's log streams, `stdout` or `stderr`, to `dest` as the daemon
    /// frames it, failing past `limit` bytes.
    pub async fn logs(
        &self,
        id: &str,
        stream: &str,
        dest: &Path,
        limit: u64,
    ) -> Result<u64, DockerError> {
        let path = format!("/containers/{}/logs?{stream}=true", encode(id));
        self.download(&path, stream, dest, limit).await
    }

    async fn download(
        &self,
        path: &str,
        what: &str,
        dest: &Path,
        limit: u64,
    ) -> Result<u64, DockerError> {
        let work = async {
            let answer = self.send(Method::GET, path, None, Bytes::new()).await?;
            let status = answer.status();
            if !status.is_success() {
                let bytes = read_limited(answer, MAX_JSON_BYTES, what).await?;
                return Err(DockerError::Status {
                    status: status.as_u16(),
                    what: what.to_owned(),
                    message: message(&bytes),
                });
            }
            let mut body = answer.into_body();
            let mut file = tokio::fs::File::create(dest).await?;
            let mut size = 0u64;
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame?.into_data() {
                    size += data.len() as u64;
                    if size > limit {
                        return Err(DockerError::TooLarge {
                            what: what.to_owned(),
                            limit,
                        });
                    }
                    file.write_all(&data).await?;
                }
            }
            file.flush().await?;
            Ok(size)
        };
        let timeout = CALL_TIMEOUT * 5;
        tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| DockerError::Timeout(format!("copying {what} out"), timeout))?
    }

    /// The containers, running or not, that carry every one of `labels` (`key=value`).
    pub async fn list(&self, labels: &[String]) -> Result<Vec<Listed>, DockerError> {
        let filters = serde_json::json!({ "label": labels });
        let path = format!(
            "/containers/json?all=true&filters={}",
            encode(&filters.to_string())
        );
        let (_, bytes) = self.call(Method::GET, &path, None).await?;
        serde_json::from_slice(&bytes)
            .map_err(|e| DockerError::Json("container list".to_owned(), e))
    }

    /// The image's id, or None when the daemon doesn't have it.
    pub async fn image_id(&self, image: &str) -> Result<Option<String>, DockerError> {
        let path = format!("/images/{}/json", encode(image));
        match self.call(Method::GET, &path, None).await {
            Ok((_, bytes)) => {
                let value: Value = serde_json::from_slice(&bytes)
                    .map_err(|e| DockerError::Json("image inspect".to_owned(), e))?;
                Ok(value["Id"].as_str().map(str::to_owned))
            }
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Reads a whole answer, failing past `limit` bytes.
async fn read_limited(answer: Answer, limit: u64, what: &str) -> Result<Bytes, DockerError> {
    let mut body = answer.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            if bytes.len() as u64 + data.len() as u64 > limit {
                return Err(DockerError::TooLarge {
                    what: what.to_owned(),
                    limit,
                });
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(bytes))
}

/// The daemon's error message, from its `{"message": ...}`, or its bytes as text.
fn message(bytes: &[u8]) -> String {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v["message"].as_str().map(str::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(bytes).chars().take(500).collect())
}

/// `text` percent-encoded for a URL's path segment or query value.
fn encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_paths_are_encoded() {
        assert_eq!(encode("ace4-scan-1"), "ace4-scan-1");
        assert_eq!(encode("/phishkit/output"), "%2Fphishkit%2Foutput");
        assert_eq!(encode("a b&c"), "a%20b%26c");
        assert_eq!(
            message(br#"{"message":"No such container: x"}"#),
            "No such container: x"
        );
        assert_eq!(message(b"plain"), "plain");
    }
}
