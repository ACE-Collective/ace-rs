//! PLAN.md 1.20: the SDK's HTTP client verifies certificates and classifies errors. Every server
//! here listens on 127.0.0.1; nothing leaves the machine.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ace_sdk::ModuleError;
use ace_sdk::http::{HttpClient, HttpErrorKind, check_status};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";

/// Reads one request and writes `response`.
async fn answer<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut stream: S, response: &[u8]) {
    let mut request = vec![0u8; 8192];
    if stream.read(&mut request).await.is_err() {
        return;
    }
    if stream.write_all(response).await.is_ok() {
        stream.shutdown().await.ok();
    }
}

/// An HTTPS server on 127.0.0.1 whose certificate, for `localhost`, is self-signed. Returns its
/// address and the certificate in PEM.
async fn self_signed_server() -> (SocketAddr, String) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("rcgen makes a certificate");
    let cert_pem = certified.cert.pem();
    let cert: CertificateDer<'static> = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("default TLS versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .expect("a valid server config");
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // the handshake fails when the client refuses the certificate
                if let Ok(tls) = acceptor.accept(stream).await {
                    answer(tls, OK_RESPONSE).await;
                }
            });
        }
    });
    (addr, cert_pem)
}

/// A plain HTTP server on 127.0.0.1 that answers every request with `response`, or never
/// answers when `response` is `None`.
async fn http_server(response: Option<&'static [u8]>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    tokio::spawn(async move {
        let mut held: Vec<TcpStream> = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            match response {
                Some(response) => {
                    tokio::spawn(answer(stream, response));
                }
                None => held.push(stream),
            }
        }
    });
    addr
}

#[tokio::test]
async fn a_self_signed_server_fails_verification() {
    let (addr, cert_pem) = self_signed_server().await;
    let url = format!("https://localhost:{}/", addr.port());

    let client = HttpClient::builder().build().expect("client builds");
    let err = client
        .send(client.get(&url))
        .await
        .expect_err("a self-signed certificate must not verify");
    println!("{err}");
    assert_eq!(err.kind(), HttpErrorKind::Tls);
    assert!(!err.is_unavailable());
    assert!(matches!(ModuleError::from(err), ModuleError::Other(_)));

    // the same server, once its certificate is trusted, answers: the failure above was
    // verification, not a broken server
    let trusting = HttpClient::builder()
        .add_root_certificates_pem(cert_pem.as_bytes())
        .expect("the PEM parses")
        .build()
        .expect("client builds");
    let response = trusting
        .send(trusting.get(&url))
        .await
        .expect("a trusted certificate verifies");
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.expect("body"), "ok");
}

#[tokio::test]
async fn a_refused_connection_is_unavailable() {
    // bind a port, then free it, so nothing listens there
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local address").port()
    };
    let client = HttpClient::builder().build().expect("client builds");
    for url in [
        format!("http://127.0.0.1:{port}/"),
        format!("https://127.0.0.1:{port}/?api_key=s3cret"),
    ] {
        let err = client
            .send(client.get(&url))
            .await
            .expect_err("nothing listens on the port");
        println!("{err}");
        assert_eq!(err.kind(), HttpErrorKind::Unavailable, "{err}");
        assert_eq!(err.peer(), Some(format!("127.0.0.1:{port}").as_str()));
        assert!(!err.to_string().contains("s3cret"), "{err}");
        assert!(matches!(
            ModuleError::from(err),
            ModuleError::Unavailable(_)
        ));
    }
}

#[tokio::test]
async fn every_request_has_a_timeout() {
    let addr = http_server(None).await;
    let client = HttpClient::builder()
        .timeout(Duration::from_millis(300))
        .build()
        .expect("client builds");
    let started = Instant::now();
    let err = client
        .send(client.get(&format!("http://{addr}/")))
        .await
        .expect_err("the server never answers");
    println!("{err}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(err.kind(), HttpErrorKind::Unavailable);
}

#[tokio::test]
async fn error_statuses_are_classified() {
    let client = HttpClient::builder().build().expect("client builds");
    for (response, expected) in [
        (
            &b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                [..],
            HttpErrorKind::Unavailable,
        ),
        (
            &b"HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"[..],
            HttpErrorKind::Unavailable,
        ),
        (
            &b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"[..],
            HttpErrorKind::Status(reqwest::StatusCode::NOT_FOUND),
        ),
    ] {
        let addr = http_server(Some(response)).await;
        let response = client
            .send(client.get(&format!("http://{addr}/")))
            .await
            .expect("an error status is still a response");
        let err = check_status(response).expect_err("an error status");
        assert_eq!(err.kind(), expected, "{err}");
    }
    let addr = http_server(Some(OK_RESPONSE)).await;
    let response = client
        .send(client.get(&format!("http://{addr}/")))
        .await
        .expect("a response");
    assert!(check_status(response).is_ok());
}
