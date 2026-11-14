//! What the reference dumps don't show: a resolver that doesn't answer, a resolver that can't be
//! reached, an answer too long for a datagram, a resolver named by host name, and the observable
//! the module adds. Nothing reaches a real resolver.

use std::time::{Duration, Instant};

use ace_mod_dns::FqdnAnalyzer;
use ace_results::ObservableKind;
use ace_sdk::{ModuleError, Outcome};
use ace_testkit::dns::DnsReplay;
use ace_testkit::reference::dumps_dir;
use ace_testkit::{Harness, HarnessError};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn harness(nameservers: &[String], timeout: f64) -> Harness<FqdnAnalyzer> {
    Harness::with_settings(json!({"nameservers": nameservers, "timeout_seconds": timeout}))
        .expect("harness")
}

/// The response ace3 got for `example.com A`.
fn recorded_example_com() -> Vec<u8> {
    let recording: Value = serde_json::from_str(
        &std::fs::read_to_string(dumps_dir().join("fqdn_analyzer/fqdn_example.com.dns.json"))
            .expect("reads"),
    )
    .expect("JSON");
    let hex = recording["exchanges"][0]["response"]
        .as_str()
        .expect("a response");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

#[tokio::test]
async fn a_resolver_that_never_answers_fails_the_task_as_unavailable() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.expect("binds");
    let harness = harness(&[silent.local_addr().expect("an address").to_string()], 0.3);
    let started = Instant::now();
    let err = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "example.com"))
        .await
        .expect_err("nothing answers");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::Unavailable(_))),
        "{err}"
    );
    // the lifetime bounds every try
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_resolver_that_can_t_be_reached_fails_the_task_as_unavailable() {
    // a port nothing listens on: the kernel answers the datagram with an ICMP refusal
    let port = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("binds")
        .local_addr()
        .expect("an address")
        .port();
    let harness = harness(&[format!("127.0.0.1:{port}")], 2.0);
    let err = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "example.com"))
        .await
        .expect_err("nothing listens");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::Unavailable(_))),
        "{err}"
    );
}

#[tokio::test]
async fn a_truncated_answer_is_asked_again_over_tcp() {
    // the free UDP port's TCP side can belong to another test's listener, so another port is tried
    let (udp, addr, tcp) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("binds");
        let addr = udp.local_addr().expect("an address");
        match TcpListener::bind(addr).await {
            Ok(tcp) => break (udp, addr, tcp),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(e) => panic!("binds: {e}"),
        }
    };
    let full = recorded_example_com();
    let full_for_tcp = full.clone();
    // over UDP: the header and question only, marked truncated
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        while let Ok((length, peer)) = udp.recv_from(&mut buffer).await {
            let mut response = buffer[..length].to_vec();
            response[2] |= 0x80 | 0x02;
            response[3] = 0x80;
            if udp.send_to(&response, peer).await.is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            let full = full_for_tcp.clone();
            tokio::spawn(async move {
                let mut length = [0u8; 2];
                while stream.read_exact(&mut length).await.is_ok() {
                    let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                    if stream.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    // only the A query gets the recorded answer; the rest don't exist
                    let mut response = if query.ends_with(&[0, 1, 0, 1])
                        && !query.windows(14).any(|w| w == b"wildcard-probe")
                    {
                        full.clone()
                    } else {
                        let mut r = query.clone();
                        r[2] |= 0x80;
                        r[3] = 0x80 | 3;
                        r
                    };
                    response[..2].copy_from_slice(&query[..2]);
                    let size = u16::try_from(response.len()).expect("short");
                    if stream.write_all(&size.to_be_bytes()).await.is_err()
                        || stream.write_all(&response).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    let harness = harness(&[addr.to_string()], 2.0);
    let Outcome::Done(result) = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "example.com"))
        .await
        .expect("runs")
    else {
        panic!("expected a result");
    };
    assert_eq!(result.details.status.as_deref(), Some("ok"));
    assert_eq!(result.details.all_resolutions, ["192.0.2.10", "192.0.2.2"]);
    assert_eq!(result.details.mx, Some(Vec::new()));
    assert_eq!(result.details.wildcard_dns, Some(false));
}

#[tokio::test]
async fn a_resolver_is_named_by_host_and_port() {
    let replay = DnsReplay::start(&[dumps_dir()
        .join("fqdn_analyzer/fqdn_www.example.com.dns.json")
        .as_path()])
    .await
    .expect("the recording loads");
    let harness = harness(&[format!("localhost:{}", replay.addr().port())], 2.0);
    let Outcome::Done(result) = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "WWW.example.com."))
        .await
        .expect("runs")
    else {
        panic!("expected a result");
    };
    assert_eq!(
        result.details.aliaslist,
        ["edge.example.net", "cdn.example.org"]
    );
    let added: Vec<(ObservableKind, &str)> = result
        .observables
        .iter()
        .map(|o| (o.kind, o.value.as_str()))
        .collect();
    assert_eq!(added, [(ObservableKind::Ip, "192.0.2.30")]);
    // a subdomain gets no MX lookup or wildcard probe
    assert_eq!(replay.asked(), ["www.example.com A"]);
}

#[tokio::test]
async fn a_name_that_can_t_be_asked_for_is_a_dns_error() {
    let replay = DnsReplay::start(&[]).await.expect("starts");
    let harness = harness(&[replay.addr().to_string()], 1.0);
    let Outcome::Done(result) = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "a..example.com"))
        .await
        .expect("runs")
    else {
        panic!("expected a result");
    };
    assert_eq!(result.details.status.as_deref(), Some("dns_error"));
    assert!(replay.asked().is_empty());
}
