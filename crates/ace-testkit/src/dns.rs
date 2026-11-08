//! Serving recorded DNS answers to a lookup module, so its tests never reach a real resolver.
//!
//! `tools/ace3/dumps/fake_dns.py` answered ace3's DNS queries from a zone fixture and kept each
//! exchange: the query's name and type and the response's bytes, in `<dump>.dns.json` beside a
//! reference dump, and in `tools/ace3/trees/dns.json` for the trees. `DnsReplay` serves them on
//! 127.0.0.1 over UDP and TCP, as the resolver a module is pointed at. A query gets the response
//! recorded for its name and type, with the query's id; a name and type asked for more than once
//! get their recorded responses in order, and the last one again after that. A query nothing was
//! recorded for gets SERVFAIL and is noted, so a test can fail on it.
//!
//! It reads only a DNS message's header and question, so it needs no DNS library.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

use crate::HarnessError;

#[derive(Deserialize)]
struct Recording {
    exchanges: Vec<RecordedExchange>,
}

#[derive(Deserialize)]
struct RecordedExchange {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    response: String,
}

#[derive(Default)]
struct Log {
    asked: Vec<String>,
    unmatched: Vec<String>,
    served: HashMap<String, usize>,
}

/// Recorded answers, by `<name> <type>`.
type Answers = HashMap<String, Vec<Vec<u8>>>;

/// A local DNS server for recorded answers.
pub struct DnsReplay {
    addr: SocketAddr,
    log: Arc<Mutex<Log>>,
    tasks: Vec<JoinHandle<()>>,
}

/// dnspython's names for the record types a module asks for.
fn type_name(code: u16) -> String {
    match code {
        1 => "A".to_owned(),
        2 => "NS".to_owned(),
        5 => "CNAME".to_owned(),
        6 => "SOA".to_owned(),
        12 => "PTR".to_owned(),
        15 => "MX".to_owned(),
        16 => "TXT".to_owned(),
        28 => "AAAA".to_owned(),
        other => format!("TYPE{other}"),
    }
}

/// The question of a DNS message, as `<name> <type>` with the name lowercased and without its
/// final dot, and where the question ends.
fn question(message: &[u8]) -> Option<(String, usize)> {
    if message.len() < 12 || u16::from_be_bytes([message[4], message[5]]) != 1 {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*message.get(at)?);
        at += 1;
        if length == 0 {
            break;
        }
        // a query's name isn't compressed
        if length > 63 {
            return None;
        }
        let label = message.get(at..at + length)?;
        labels.push(String::from_utf8_lossy(label).to_lowercase());
        at += length;
    }
    let kind = u16::from_be_bytes([*message.get(at)?, *message.get(at + 1)?]);
    at += 4;
    (at <= message.len()).then(|| (format!("{} {}", labels.join("."), type_name(kind)), at))
}

/// The SERVFAIL answer to `query`, which ends where its question does.
fn servfail(query: &[u8], question_end: usize) -> Vec<u8> {
    let mut response = query[..question_end].to_vec();
    // QR, the query's opcode and RD, RA, SERVFAIL
    response[2] = 0x80 | (query[2] & 0x79);
    response[3] = 0x80 | 2;
    for count in &mut response[6..12] {
        *count = 0;
    }
    response
}

fn answer(query: &[u8], answers: &Answers, log: &Mutex<Log>) -> Option<Vec<u8>> {
    let (key, end) = question(query)?;
    let mut log = log.lock().ok()?;
    log.asked.push(key.clone());
    let Some(recorded) = answers.get(&key).filter(|r| !r.is_empty()) else {
        log.unmatched.push(key);
        return Some(servfail(query, end));
    };
    let served = log.served.entry(key).or_default();
    let mut response = recorded[(*served).min(recorded.len() - 1)].clone();
    *served += 1;
    if response.len() >= 2 {
        response[..2].copy_from_slice(&query[..2]);
    }
    Some(response)
}

fn load(path: &Path, answers: &mut Answers) -> Result<(), HarnessError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| HarnessError::Fixture(format!("{}: {e}", path.display())))?;
    let recording: Recording = serde_json::from_str(&text)
        .map_err(|e| HarnessError::Fixture(format!("{}: {e}", path.display())))?;
    for exchange in recording.exchanges {
        let bytes = decode_hex(&exchange.response).ok_or_else(|| {
            HarnessError::Fixture(format!("{}: a response isn't hex", path.display()))
        })?;
        answers
            .entry(format!("{} {}", exchange.name, exchange.kind))
            .or_default()
            .push(bytes);
    }
    Ok(())
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    text.len().is_multiple_of(2).then_some(())?;
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

impl DnsReplay {
    /// Serves the recordings at `paths` on a free port of 127.0.0.1.
    pub async fn start(paths: &[&Path]) -> Result<DnsReplay, HarnessError> {
        DnsReplay::serve(paths, "127.0.0.1:0").await
    }

    /// Serves the recordings at `paths` on `listen`, over UDP and TCP on the same port.
    pub async fn serve(paths: &[&Path], listen: &str) -> Result<DnsReplay, HarnessError> {
        let mut answers = Answers::new();
        for path in paths {
            load(path, &mut answers)?;
        }
        let answers = Arc::new(answers);
        let udp = UdpSocket::bind(listen).await?;
        let addr = udp.local_addr()?;
        let tcp = TcpListener::bind(addr).await?;
        let log = Arc::new(Mutex::new(Log::default()));
        let udp_task = {
            let (answers, log) = (answers.clone(), log.clone());
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 65535];
                while let Ok((length, peer)) = udp.recv_from(&mut buffer).await {
                    if let Some(response) = answer(&buffer[..length], &answers, &log)
                        && let Err(e) = udp.send_to(&response, peer).await
                    {
                        eprintln!("dns replay: {e}");
                    }
                }
            })
        };
        let tcp_task = {
            let (answers, log) = (answers.clone(), log.clone());
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = tcp.accept().await {
                    let (answers, log) = (answers.clone(), log.clone());
                    tokio::spawn(async move {
                        let mut length = [0u8; 2];
                        while stream.read_exact(&mut length).await.is_ok() {
                            let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                            if stream.read_exact(&mut query).await.is_err() {
                                return;
                            }
                            let Some(response) = answer(&query, &answers, &log) else {
                                return;
                            };
                            let Ok(size) = u16::try_from(response.len()) else {
                                return;
                            };
                            if stream.write_all(&size.to_be_bytes()).await.is_err()
                                || stream.write_all(&response).await.is_err()
                            {
                                return;
                            }
                        }
                    });
                }
            })
        };
        Ok(DnsReplay {
            addr,
            log,
            tasks: vec![udp_task, tcp_task],
        })
    }

    /// The address to point a module's resolver at.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every query, as `<name> <type>`, in order.
    pub fn asked(&self) -> Vec<String> {
        self.log
            .lock()
            .map(|log| log.asked.clone())
            .unwrap_or_default()
    }

    /// Queries nothing was recorded for.
    pub fn unmatched(&self) -> Vec<String> {
        self.log
            .lock()
            .map(|log| log.unmatched.clone())
            .unwrap_or_default()
    }
}

impl Drop for DnsReplay {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query for `example.com A` with id 0x1234 and RD.
    fn query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07Example\x03com\x00\x00\x01\x00\x01");
        q
    }

    #[test]
    fn a_question_reads_as_its_lowercased_name_and_type() {
        assert_eq!(
            question(&query()).map(|(key, _)| key),
            Some("example.com A".to_owned())
        );
        assert_eq!(question(&query()[..20]), None);
    }

    #[test]
    fn a_query_nothing_was_recorded_for_gets_servfail_with_its_id() {
        let log = Mutex::new(Log::default());
        let response = answer(&query(), &Answers::new(), &log).expect("an answer");
        assert_eq!(&response[..4], &[0x12, 0x34, 0x81, 0x82]);
        assert_eq!(&response[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(log.lock().expect("log").unmatched, ["example.com A"]);
    }

    #[test]
    fn recorded_answers_come_in_order_then_the_last_again() {
        let log = Mutex::new(Log::default());
        let answers: Answers = [(
            "example.com A".to_owned(),
            vec![vec![0, 0, 1], vec![0, 0, 2]],
        )]
        .into();
        let served: Vec<Vec<u8>> = (0..3)
            .filter_map(|_| answer(&query(), &answers, &log))
            .collect();
        assert_eq!(
            served,
            [
                vec![0x12, 0x34, 1],
                vec![0x12, 0x34, 2],
                vec![0x12, 0x34, 2]
            ]
        );
    }
}
