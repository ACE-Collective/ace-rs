//! Records to fluent-bit over Fluentd's forward protocol, as ace3's `fluent.sender.FluentSender`
//! (fluent-logger 0.11.1) sends them: each a MessagePack array of the tag, the time in whole seconds
//! and the record, over TCP.
//!
//! ace3 keeps one socket per tag for the life of its module and drops a record it can't send,
//! logging nothing. Here one connection carries a task's records, in order; one that can't be sent
//! is logged and dropped, with the rest of the task's.

use std::time::Duration;

use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// A record for one tag.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub tag: String,
    pub record: Value,
}

/// Why the records weren't all sent.
#[derive(Debug, thiserror::Error)]
pub enum FluentError {
    #[error("connecting to {address}: {source}")]
    Connect {
        address: String,
        #[source]
        source: std::io::Error,
    },
    #[error("sending to {address}: {source}")]
    Send {
        address: String,
        #[source]
        source: std::io::Error,
    },
    #[error("timed out after {0:?}")]
    TimedOut(Duration),
    #[error("a record doesn't encode: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
}

/// One forward-protocol message: `[tag, time, record]`.
pub fn encode(record: &Record, time: i64) -> Result<Vec<u8>, FluentError> {
    Ok(rmp_serde::to_vec(&(&record.tag, time, &record.record))?)
}

/// Sends `records` to `host:port`, each with `time`, within `timeout`.
pub async fn send(
    host: &str,
    port: u16,
    records: &[Record],
    time: i64,
    timeout: Duration,
) -> Result<(), FluentError> {
    if records.is_empty() {
        return Ok(());
    }
    let address = format!("{host}:{port}");
    let mut packets = Vec::new();
    for record in records {
        packets.extend(encode(record, time)?);
    }
    let sending = async {
        let mut stream =
            TcpStream::connect((host, port))
                .await
                .map_err(|source| FluentError::Connect {
                    address: address.clone(),
                    source,
                })?;
        stream
            .write_all(&packets)
            .await
            .map_err(|source| FluentError::Send {
                address: address.clone(),
                source,
            })?;
        stream.shutdown().await.map_err(|source| FluentError::Send {
            address: address.clone(),
            source,
        })
    };
    tokio::time::timeout(timeout, sending)
        .await
        .map_err(|_| FluentError::TimedOut(timeout))?
}
