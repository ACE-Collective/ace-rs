//! A stub resolver that asks as dnspython's `dns.resolver.Resolver` does, with ace3's timeout as
//! both its `timeout` and its `lifetime`: one recursive query at a time, over UDP and over TCP when
//! the answer is truncated, with no EDNS and no search list, trying each nameserver in turn until
//! one gives an answer (NOERROR or NXDOMAIN) or the lifetime runs out. A nameserver that answers
//! anything else, such as SERVFAIL, isn't asked again.
//!
//! The answer is read as dnspython's `Answer` reads it: from the name asked, CNAME records in the
//! answer section lead to the name whose records of the type asked are the answer, each record once.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout_at};

/// How a query ended.
#[derive(Debug)]
pub enum Reply {
    /// The records of the type asked, after the CNAME chain, and the response they came in.
    Records(Vec<RData>, Message),
    NxDomain,
    /// The name exists and has no record of the type asked.
    NoAnswer,
}

/// Why a query got no answer.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// Every nameserver answered with a failure, such as SERVFAIL. This is an answer about the
    /// name, as dnspython's `NoNameservers`.
    #[error("All nameservers failed to answer the query {0}: {1}")]
    NoNameservers(String, String),
    /// No nameserver answered in time, or none could be reached.
    #[error("the resolution lifetime expired after {0:?} asking {1}: {2}")]
    Unreachable(Duration, String, String),
    /// The name can't be asked about, such as one with an empty or too long label.
    #[error("{0}")]
    BadName(String),
}

/// Asks the nameservers for `name`'s records of type `kind`, within `lifetime`.
pub async fn resolve(
    nameservers: &[SocketAddr],
    name: &Name,
    kind: RecordType,
    lifetime: Duration,
) -> Result<Reply, ResolveError> {
    let mut query = Message::new(random_id(), MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(name.clone(), kind));
    let wire = query
        .to_vec()
        .map_err(|e| ResolveError::BadName(format!("{name}: {e}")))?;
    let asked = format!("{name} IN {kind}");
    let deadline = Instant::now() + lifetime;
    let mut alive: Vec<SocketAddr> = nameservers.to_vec();
    // nameservers that answered with a failure, and that couldn't be reached
    let mut failures = Vec::new();
    let mut unreachable = Vec::new();
    let mut last_error = "no nameservers".to_owned();
    let mut backoff = Duration::from_millis(100);
    while !alive.is_empty() {
        let mut index = 0;
        while index < alive.len() {
            let server = alive[index];
            if Instant::now() >= deadline {
                return Err(ResolveError::Unreachable(lifetime, asked, last_error));
            }
            match exchange(server, &wire, &query, deadline).await {
                Ok(response) => match response.metadata.response_code {
                    ResponseCode::NoError => return Ok(read_answer(name, kind, response)),
                    ResponseCode::NXDomain => return Ok(Reply::NxDomain),
                    code => {
                        // as dnspython words it in NoNameservers, which is the module's error:
                        // `Server Do53:<address>@<port> answered SERVFAIL`
                        failures.push(format!(
                            "Server Do53:{}@{} answered {}",
                            server.ip(),
                            server.port(),
                            rcode_text(code)
                        ));
                        alive.remove(index);
                        continue;
                    }
                },
                Err(Exchange::TimedOut) => {
                    last_error = format!("{server} didn't answer in time");
                }
                Err(Exchange::Io(e)) => {
                    last_error = format!("{server}: {e}");
                    unreachable.push(last_error.clone());
                    alive.remove(index);
                    continue;
                }
            }
            index += 1;
        }
        if alive.is_empty() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(ResolveError::Unreachable(lifetime, asked, last_error));
        }
        tokio::time::sleep(backoff.min(deadline - now)).await;
        backoff *= 2;
    }
    // only a nameserver's own answer says anything about the name; one that couldn't be reached
    // is the network's fault
    if failures.is_empty() {
        return Err(ResolveError::Unreachable(
            lifetime,
            asked,
            unreachable.join("; "),
        ));
    }
    Err(ResolveError::NoNameservers(asked, failures.join("; ")))
}

/// dnspython's `dns.rcode.to_text`: the code's mnemonic, or its number when it has none.
fn rcode_text(code: ResponseCode) -> String {
    match u16::from(code) {
        1 => "FORMERR".to_owned(),
        2 => "SERVFAIL".to_owned(),
        3 => "NXDOMAIN".to_owned(),
        4 => "NOTIMP".to_owned(),
        5 => "REFUSED".to_owned(),
        6 => "YXDOMAIN".to_owned(),
        7 => "YXRRSET".to_owned(),
        8 => "NXRRSET".to_owned(),
        9 => "NOTAUTH".to_owned(),
        10 => "NOTZONE".to_owned(),
        11 => "DSOTYPENI".to_owned(),
        16 => "BADVERS".to_owned(),
        other => other.to_string(),
    }
}

enum Exchange {
    TimedOut,
    Io(std::io::Error),
}

impl From<std::io::Error> for Exchange {
    fn from(e: std::io::Error) -> Self {
        Exchange::Io(e)
    }
}

/// Sends the query to one nameserver over UDP, and over TCP when the answer comes back
/// truncated. A datagram that isn't the answer to this query is ignored, as dnspython ignores it.
async fn exchange(
    server: SocketAddr,
    wire: &[u8],
    query: &Message,
    deadline: Instant,
) -> Result<Message, Exchange> {
    let local: SocketAddr = if server.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(server).await?;
    socket.send(wire).await?;
    let mut buffer = vec![0u8; 65535];
    let response = loop {
        let length = timeout_at(deadline, socket.recv(&mut buffer))
            .await
            .map_err(|_| Exchange::TimedOut)??;
        if let Some(response) = answers(query, &buffer[..length]) {
            break response;
        }
    };
    if !response.metadata.truncation {
        return Ok(response);
    }
    timeout_at(deadline, exchange_tcp(server, wire, query))
        .await
        .map_err(|_| Exchange::TimedOut)?
}

async fn exchange_tcp(
    server: SocketAddr,
    wire: &[u8],
    query: &Message,
) -> Result<Message, Exchange> {
    let mut stream = TcpStream::connect(server).await?;
    let length = u16::try_from(wire.len())
        .map_err(|_| Exchange::Io(std::io::Error::other("the query is too long")))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(wire).await?;
    loop {
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await?;
        let mut message = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut message).await?;
        if let Some(response) = answers(query, &message) {
            return Ok(response);
        }
    }
}

/// The message in `bytes` when it is the response to `query`: the same id, and the same question.
fn answers(query: &Message, bytes: &[u8]) -> Option<Message> {
    let response = Message::from_vec(bytes).ok()?;
    (response.metadata.message_type == MessageType::Response
        && response.metadata.id == query.metadata.id
        && response.queries == query.queries)
        .then_some(response)
}

/// dnspython's `resolve_chaining`: follow CNAME records from `name` to the records of `kind`.
fn read_answer(name: &Name, kind: RecordType, response: Message) -> Reply {
    let mut current = name.clone();
    // dnspython gives up on a chain longer than this
    for _ in 0..16 {
        let mut records: Vec<RData> = Vec::new();
        for record in &response.answers {
            if record.name == current
                && record.record_type() == kind
                && !records.contains(&record.data)
            {
                records.push(record.data.clone());
            }
        }
        if !records.is_empty() {
            return Reply::Records(records, response);
        }
        if kind == RecordType::CNAME {
            break;
        }
        let next = response
            .answers
            .iter()
            .find_map(|record| match &record.data {
                RData::CNAME(target) if record.name == current => Some(target.0.clone()),
                _ => None,
            });
        match next {
            Some(target) => current = target,
            None => break,
        }
    }
    Reply::NoAnswer
}

/// The targets of the CNAME records in a response's answer section, the first of each name's, in
/// the order the names first appear, as ace3 reads `answer.response.answer`.
pub fn aliases(response: &Message) -> Vec<String> {
    let mut seen: Vec<&Name> = Vec::new();
    let mut aliases = Vec::new();
    for record in &response.answers {
        if let RData::CNAME(target) = &record.data
            && !seen.contains(&&record.name)
        {
            seen.push(&record.name);
            aliases.push(to_text(&target.0));
        }
    }
    aliases
}

/// dnspython's `str(name).rstrip(".")`: each label with `"().;\@$` escaped by a backslash and
/// anything outside printable ASCII as `\DDD`.
pub fn to_text(name: &Name) -> String {
    let mut text = String::new();
    for label in name.iter() {
        for &byte in label {
            if b"\"().;\\@$".contains(&byte) {
                text.push('\\');
                text.push(char::from(byte));
            } else if byte > 0x20 && byte < 0x7f {
                text.push(char::from(byte));
            } else {
                text.push_str(&format!("\\{byte:03}"));
            }
        }
        text.push('.');
    }
    if text.is_empty() {
        text.push('.');
    }
    text.trim_end_matches('.').to_owned()
}

/// A query id nobody can guess from the last one.
fn random_id() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
    );
    (hasher.finish() & 0xffff) as u16
}

/// The name to ask for, from an observable's value: dnspython's `from_text` for ASCII, which
/// takes any label of 1 to 63 bytes, and IDNA for anything else.
pub fn name_of(value: &str) -> Result<Name, ResolveError> {
    let value = value.strip_suffix('.').unwrap_or(value);
    let name = if value.is_ascii() {
        Name::from_labels(value.split('.').map(str::as_bytes))
    } else {
        Name::from_utf8(value)
    };
    let mut name = name.map_err(|e| ResolveError::BadName(format!("{value}: {e}")))?;
    name.set_fqdn(true);
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_read_as_dnspython_writes_them() {
        let name = Name::from_labels([&b"a.b"[..], b"we(ird", b"\x01x", b"com"]).expect("a name");
        assert_eq!(to_text(&name), r"a\.b.we\(ird.\001x.com");
        assert_eq!(to_text(&Name::root()), "");
    }

    #[test]
    fn a_name_with_an_empty_or_long_label_is_refused() {
        assert!(name_of("a..b").is_err());
        assert!(name_of(&format!("{}.com", "a".repeat(64))).is_err());
        assert_eq!(
            to_text(&name_of("Example.COM.").expect("a name")),
            "Example.COM"
        );
    }
}
