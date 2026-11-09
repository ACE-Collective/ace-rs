//! Compares the crate with ace3's answers, recorded by `tests/data/oracle.py` on the cases
//! `tests/data/gen_corpus.py` writes (`tests/data/answers.json.gz`).

use std::io::Read;

use base64::Engine;
use serde_json::{Value, json};

use crate::*;

/// `ACE_X509_ANSWERS` names another answers file (gzipped), such as a larger one-off fuzz run.
fn answers() -> Vec<Value> {
    let path = std::env::var("ACE_X509_ANSWERS").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/answers.json.gz").to_owned()
    });
    let gz = std::fs::read(path).unwrap();
    let mut text = String::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_string(&mut text)
        .unwrap();
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn res<T>(r: Result<T, PyErr>, f: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(v) => json!({"ok": f(v)}),
        Err(e) => json!({"err": [e.qualified_name(), e.message]}),
    }
}

fn dt(d: DateTime) -> Value {
    json!({"str": d.utc_str(), "strftime": d.utc_strftime()})
}

/// Normalizes what Python cannot reproduce from run to run: memory addresses, and the order of
/// a frozenset's items.
fn normalize(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(" at 0x") {
        out.push_str(&rest[..i + 6]);
        rest = &rest[i + 6..];
        let n = rest
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(rest.len());
        out.push_str("ADDR");
        rest = &rest[n..];
    }
    out.push_str(rest);
    let mut s = out;
    let mut from = 0;
    while let Some(i) = s[from..].find("frozenset({") {
        let start = from + i + "frozenset({".len();
        let Some(len) = s[start..].find("})") else {
            break;
        };
        let mut items: Vec<&str> = s[start..start + len].split(", ").collect();
        items.sort();
        let joined = items.join(", ");
        s = format!("{}{}{}", &s[..start], joined, &s[start + len..]);
        from = start;
    }
    s
}

fn norm_value(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(normalize(s)),
        Value::Array(a) => Value::Array(a.iter().map(norm_value).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (normalize(k), norm_value(v)))
                .collect(),
        ),
        v => v.clone(),
    }
}

#[test]
fn matches_ace3() {
    let answers = answers();
    let mut failures = Vec::new();
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    let mut loaded_count = 0usize;
    let mut departures = 0usize;
    for a in &answers {
        let name = a["name"].as_str().unwrap();
        let data = base64::engine::general_purpose::STANDARD
            .decode(a["b64"].as_str().unwrap())
            .unwrap();
        let head = &data[..data.len().min(IS_X509_READ_SIZE)];
        let mut check = |field: &str, got: Value, want: &Value| {
            *counts.entry("compared").or_default() += 1;
            if norm_value(&got) != norm_value(want) {
                failures.push(format!("{name} {field}:\n  got  {got}\n  want {want}"));
            }
        };
        check("is_pem", json!(is_pem_bytes(head)), &a["is_pem"]);
        check("is_der", json!(is_der_bytes(head)), &a["is_der"]);
        check("is_x509", res(is_x509(&data), |b| json!(b)), &a["is_x509"]);
        let loaded = load_cert(&data);
        // Known departure: RSA-PSS nested past MAX_DER_DEPTH, which cryptography loads.
        if let Some(depth) = name
            .strip_prefix("alg_pss_nested_")
            .and_then(|d| d.parse::<usize>().ok())
            && depth > 32
        {
            assert!(matches!(loaded, Ok(None)), "{name}");
            assert_eq!(a["load"], json!({"ok": true}), "{name}");
            departures += 1;
            continue;
        }
        let cert = match loaded {
            Err(e) => {
                check("load", res::<()>(Err(e), |_| Value::Null), &a["load"]);
                continue;
            }
            Ok(c) => {
                loaded_count += usize::from(c.is_some());
                check("load", json!({"ok": c.is_some()}), &a["load"]);
                match c {
                    Some(c) => c,
                    None => continue,
                }
            }
        };
        check(
            "issuer",
            res(cert.issuer_rfc4514(), |s| json!(s)),
            &a["issuer"],
        );
        check(
            "subject",
            res(cert.subject_rfc4514(), |s| json!(s)),
            &a["subject"],
        );
        check("serial", json!(cert.serial_number()), &a["serial"]);
        check(
            "not_before",
            res(cert.not_valid_before_utc(), dt),
            &a["not_before"],
        );
        check(
            "not_after",
            res(cert.not_valid_after_utc(), dt),
            &a["not_after"],
        );
        check(
            "common_name",
            res(cert.common_name(), |s| json!(s)),
            &a["common_name"],
        );
        check("sha256", json!(cert.sha256()), &a["sha256"]);
        check(
            "san_ip",
            res(cert.san_ip_addresses(), |s| json!(s)),
            &a["san_ip"],
        );
        check(
            "san_dns",
            res(cert.san_dns_names(), |s| json!(s)),
            &a["san_dns"],
        );
        check(
            "extensions",
            cert.readable_extensions().unwrap_or(Value::Null),
            &a["extensions"],
        );
        check(
            "metadata",
            res(analyze(&cert), |d| json!(d.metadata_json())),
            &a["metadata"],
        );
        // cryptography hashes its re-encoding of the certificate; it is the DER it parsed.
        if cert.sha256() != {
            use sha2::Digest;
            sha2::Sha256::digest(cert.der())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        } {
            failures.push(format!("{name}: re-encoding differs from the DER"));
        }
    }
    eprintln!(
        "{} cases, {} loaded, {} known departures, {:?}",
        answers.len(),
        loaded_count,
        departures,
        counts
    );
    for f in failures.iter().take(40) {
        eprintln!("{f}");
    }
    assert!(failures.is_empty(), "{} differences", failures.len());
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let b = n.to_be_bytes();
        let skip = b.iter().take_while(|&&x| x == 0).count();
        out.push(0x80 | (b.len() - skip) as u8);
        out.extend_from_slice(&b[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// An RSA-PSS AlgorithmIdentifier whose hash algorithm is another one, `depth` times.
fn nested_pss(depth: usize) -> Vec<u8> {
    let pss_oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    ];
    let mut alg = tlv(
        0x30,
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ],
    );
    for _ in 0..depth {
        let params = tlv(0x30, &tlv(0xA0, &alg));
        alg = tlv(0x30, &[&pss_oid[..], &params].concat());
    }
    alg
}

#[test]
fn deep_nesting_is_refused_not_overflowed() {
    // A certificate whose signature algorithm is RSA-PSS nested in itself.
    let cert = |depth: usize| {
        let alg = nested_pss(depth);
        let name = tlv(
            0x30,
            &tlv(
                0x31,
                &tlv(
                    0x30,
                    &[&[0x06, 0x03, 0x55, 0x04, 0x03][..], &tlv(0x0C, b"x")].concat(),
                ),
            ),
        );
        let time = tlv(0x17, b"200101000000Z");
        let spki = tlv(
            0x30,
            &[
                tlv(0x30, &[0x06, 0x03, 0x2b, 0x65, 0x70]),
                tlv(0x03, &[0, 1]),
            ]
            .concat(),
        );
        let tbs = tlv(
            0x30,
            &[
                tlv(0x02, &[5]),
                alg.clone(),
                name.clone(),
                tlv(0x30, &[time.clone(), time].concat()),
                name,
                spki,
            ]
            .concat(),
        );
        tlv(0x30, &[tbs, alg, tlv(0x03, &[0])].concat())
    };
    // cryptography loads all of these (it loads 500 levels and crashes its process at 5000);
    // past MAX_DER_DEPTH this refuses them.
    for depth in [1, 30, 31] {
        assert!(load_der_x509_certificate(&cert(depth)).is_ok(), "{depth}");
    }
    let err = load_der_x509_certificate(&cert(33)).unwrap_err();
    assert!(err.message.contains("nested deeper"));
    let err = load_der_x509_certificate(&cert(3000)).unwrap_err();
    assert!(err.message.contains("nested deeper"));
}
