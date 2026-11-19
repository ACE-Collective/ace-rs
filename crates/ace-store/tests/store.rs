//! ace-store against the stack's bucket, and the node cache on its own. The bucket tests need
//! the `bucket` service and the ACE4_BUCKET_* variables the dev container sets.

use std::io::Read;
use std::time::{Duration, SystemTime};

use ace_results::Sha256;
use ace_store::{BucketConfig, NodeCache, Store, StoreError};

async fn store(cache: &tempfile::TempDir) -> Store {
    let config = BucketConfig::from_env().expect(
        "the ACE4_BUCKET_* variables; bucket tests run in the dev container with the stack up",
    );
    Store::new(
        &config,
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    )
    .await
}

/// A pool of the test's own, so tests sharing the bucket don't see each other's objects.
fn test_pool() -> String {
    format!("test-{}", uuid::Uuid::new_v4().simple())
}

fn read_all(mut file: &std::fs::File) -> Vec<u8> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("reads");
    bytes
}

#[tokio::test]
async fn a_put_spools_and_uploads_and_a_get_elsewhere_fills_that_cache() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (store(&dir_a).await, store(&dir_b).await);
    let pool = test_pool();
    let bytes = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n";

    let spooled = a.spool_bytes(bytes).await.expect("spools");
    assert_eq!(spooled.size, bytes.len() as u64);
    let sha256 = spooled.sha256;
    assert!(!a.exists(&pool, &sha256).await.expect("heads"));
    a.upload(&pool, &spooled).await.expect("uploads");
    assert!(a.exists(&pool, &sha256).await.expect("heads"));
    a.keep(&pool, spooled).await.expect("keeps");
    assert!(a.cache().path_of(&pool, &sha256).exists());

    // node b has nothing until it asks, then has the bytes
    assert!(!b.cache().path_of(&pool, &sha256).exists());
    let got = b.get(&pool, &sha256).await.expect("gets");
    assert!(!got.from_cache);
    assert_eq!(read_all(&got.file), bytes);
    assert!(b.cache().path_of(&pool, &sha256).exists());
    let again = b.get(&pool, &sha256).await.expect("gets");
    assert!(again.from_cache);

    assert_eq!(
        a.list(&format!("{pool}/")).await.expect("lists"),
        [Store::key(&pool, &sha256).unwrap()]
    );
    a.delete(&pool, &sha256).await.expect("deletes");
    assert!(!a.cache().path_of(&pool, &sha256).exists());
    assert!(a.list(&format!("{pool}/")).await.expect("lists").is_empty());
    // a node that has no copy can't get it any more
    let gone = store(&tempfile::tempdir().unwrap())
        .await
        .get(&pool, &sha256)
        .await;
    assert!(matches!(gone, Err(StoreError::NotFound { .. })), "{gone:?}");
}

#[tokio::test]
async fn a_get_refuses_bytes_whose_hash_isnt_their_name() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (store(&dir_a).await, store(&dir_b).await);
    let pool = test_pool();
    let real = a.spool_bytes(b"the real bytes").await.expect("spools");
    let other = a.spool_bytes(b"some other bytes").await.expect("spools");
    // put the other bytes under the real bytes' name, as a corrupt or tampered object would be
    let mut swapped = a.spool_bytes(b"some other bytes").await.expect("spools");
    swapped.sha256 = real.sha256;
    a.upload(&pool, &swapped).await.expect("uploads");

    let got = b.get(&pool, &real.sha256).await;
    assert!(
        matches!(&got, Err(StoreError::Integrity { actual, .. }) if *actual == other.sha256),
        "{got:?}"
    );
    assert!(!b.cache().path_of(&pool, &real.sha256).exists());
    a.delete(&pool, &real.sha256).await.expect("deletes");
}

#[test]
fn pool_names_are_checked_before_they_reach_a_key_or_a_path() {
    let sha256: Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .unwrap();
    assert_eq!(
        Store::key("alert_files", &sha256).unwrap(),
        "alert_files/e3/b0/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    for bad in ["", "../x", "Alert", "a/b", "a b"] {
        assert!(Store::key(bad, &sha256).is_err(), "{bad:?}");
    }
}

#[test]
fn the_cache_evicts_the_least_recently_read_entries_past_its_cap() {
    let dir = tempfile::tempdir().unwrap();
    let cache = NodeCache::new(dir.path(), 2500).unwrap();
    let now = SystemTime::now();
    let mut shas = Vec::new();
    for i in 0u8..4 {
        let sha256 = Sha256([i; 32]);
        let path = cache.path_of("pool", &sha256);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![i; 1000]).unwrap();
        // entry 0 was read longest ago, entry 3 most recently
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(now - Duration::from_secs(100 - u64::from(i)))
            .unwrap();
        shas.push(sha256);
    }
    // reading entry 0 makes it the newest
    assert!(cache.open("pool", &shas[0]).unwrap().is_some());

    let stats = cache.evict().unwrap();
    assert_eq!(stats.evicted, 2);
    assert_eq!(stats.bytes, 2000);
    let kept: Vec<bool> = shas
        .iter()
        .map(|sha| cache.path_of("pool", sha).exists())
        .collect();
    assert_eq!(kept, [true, false, false, true]);
}

// --- the AWS credential chain (ace_store::aws), against the stack's bucket ---
//
// The chain reads process-wide variables and files, so each case runs this binary again as a child,
// with only the variables it names: `chain_child` below, which does nothing in an ordinary run.

/// The variable that tells `chain_child` it is a case's child, and which case.
const CHAIN_CASE: &str = "ACE4_TEST_CHAIN_CASE";

/// Runs `chain_child` in a child of this binary with the dev container's variables, less every
/// `ACE4_BUCKET_*` key and region and every `AWS_*` one, plus `extra`, and fails if it does.
async fn run_chain_child(case: &str, extra: &[(&str, String)]) {
    let mut command = tokio::process::Command::new(std::env::current_exe().expect("this binary"));
    command
        .args(["chain_child", "--exact", "--ignored", "--nocapture"])
        .env(CHAIN_CASE, case)
        .env_remove("ACE4_BUCKET_ACCESS_KEY")
        .env_remove("ACE4_BUCKET_SECRET_KEY")
        .env_remove("ACE4_BUCKET_REGION");
    for (name, _) in std::env::vars() {
        if name.starts_with("AWS_") {
            command.env_remove(name);
        }
    }
    // no profile file of the container's own, and no instance metadata service unless a case
    // points at one
    command
        .env("AWS_CONFIG_FILE", "/nonexistent/aws-config")
        .env(
            "AWS_SHARED_CREDENTIALS_FILE",
            "/nonexistent/aws-credentials",
        )
        .env("AWS_EC2_METADATA_DISABLED", "true");
    for (name, value) in extra {
        command.env(name, value);
    }
    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .expect("the child finishes in 2 minutes")
        .expect("the child runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{case}: {text}");
    assert!(
        text.contains("1 passed"),
        "{case} ran the child test: {text}"
    );
}

/// The dev stack's static keys, which the cases hand to the chain through AWS's own sources.
fn dev_keys() -> (String, String) {
    (
        std::env::var("ACE4_BUCKET_ACCESS_KEY").expect("ACE4_BUCKET_ACCESS_KEY"),
        std::env::var("ACE4_BUCKET_SECRET_KEY").expect("ACE4_BUCKET_SECRET_KEY"),
    )
}

/// One case's child: with no static keys set, the bucket's config takes the chain, and a store
/// and a client from `Access::sdk_config` both reach the bucket with what it finds.
#[tokio::test]
#[ignore = "a child of the chain tests; it does nothing on its own"]
async fn chain_child() {
    let Ok(case) = std::env::var(CHAIN_CASE) else {
        return;
    };
    let config = BucketConfig::from_env().expect("the bucket's config");
    assert_eq!(config.access.keys, None, "{case}: no static keys");
    assert_eq!(config.access.region, None, "{case}: no region given");
    assert_eq!(
        config.access.region().await.as_ref(),
        "eu-central-1",
        "{case}: the region from the chain"
    );

    // the bucket's own client
    let cache = tempfile::tempdir().expect("a cache directory");
    let store = Store::new(
        &config,
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    )
    .await;
    let pool = test_pool();
    let bytes = format!("signed by the chain's {case} source\n");
    let spooled = store.spool_bytes(bytes.as_bytes()).await.expect("spools");
    store.upload(&pool, &spooled).await.expect("uploads");
    let sha256 = spooled.sha256;
    let other_cache = tempfile::tempdir().expect("a cache directory");
    let other = Store::new(
        &config,
        NodeCache::new(other_cache.path(), 1 << 30).expect("a cache"),
    )
    .await;
    let got = other.get(&pool, &sha256).await.expect("gets");
    assert_eq!(read_all(&got.file), bytes.as_bytes());
    // a presigned URL carries what the chain gave
    let url = store
        .presign_get(&pool, &sha256, Duration::from_secs(60))
        .await
        .expect("presigns")
        .url;
    assert!(url.contains("X-Amz-Credential="), "{url}");

    // a site's client of its own, from the same access
    let sdk = config.access.sdk_config().await;
    let s3 = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::config::Builder::from(&sdk)
            .endpoint_url(config.endpoint.clone().expect("the stack's endpoint"))
            .force_path_style(true)
            .build(),
    );
    let key = Store::key(&pool, &sha256).expect("a key");
    let object = s3
        .get_object()
        .bucket(&config.bucket)
        .key(&key)
        .send()
        .await
        .expect("the site's client gets the object");
    let body = object.body.collect().await.expect("reads").into_bytes();
    assert_eq!(&body[..], bytes.as_bytes());

    store.delete(&pool, &sha256).await.expect("deletes");
}

#[tokio::test]
async fn the_chain_takes_credentials_and_region_from_the_environment() {
    let (key, secret) = dev_keys();
    run_chain_child(
        "environment",
        &[
            ("AWS_ACCESS_KEY_ID", key),
            ("AWS_SECRET_ACCESS_KEY", secret),
            ("AWS_REGION", "eu-central-1".to_owned()),
        ],
    )
    .await;
}

#[tokio::test]
async fn the_chain_takes_credentials_and_region_from_a_profile() {
    let (key, secret) = dev_keys();
    let dir = tempfile::tempdir().expect("a directory");
    let credentials = dir.path().join("credentials");
    let config = dir.path().join("config");
    std::fs::write(
        &credentials,
        format!("[ace4-test]\naws_access_key_id = {key}\naws_secret_access_key = {secret}\n"),
    )
    .expect("writes");
    std::fs::write(&config, "[profile ace4-test]\nregion = eu-central-1\n").expect("writes");
    run_chain_child(
        "profile",
        &[
            ("AWS_PROFILE", "ace4-test".to_owned()),
            ("AWS_SHARED_CREDENTIALS_FILE", path_text(&credentials)),
            ("AWS_CONFIG_FILE", path_text(&config)),
        ],
    )
    .await;
}

fn path_text(path: &std::path::Path) -> String {
    path.to_str().expect("a UTF-8 path").to_owned()
}

/// The instance metadata service, as IMDSv2 answers for an instance with a role: a session token
/// for a PUT, then the role's name, its credentials and the region for GETs that carry the token.
/// Anything else is a 404, as the extended credentials path is on an older instance. The token
/// is empty, so the SDK sends none: a real role's credentials carry one, which SeaweedFS takes for
/// a session of its own STS and refuses (`InvalidAccessKeyId`), so only S3 itself tests that.
async fn fake_metadata_service(
    key: String,
    secret: String,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const TOKEN: &str = "fake-imds-token";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let endpoint = format!("http://{}", listener.local_addr().expect("an address"));
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match socket.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buffer[..n]),
                }
            }
            let head = String::from_utf8_lossy(&request).to_lowercase();
            let line = head.lines().next().unwrap_or_default().to_owned();
            let mut parts = line.split(' ');
            let (method, path) = (
                parts.next().unwrap_or_default().to_uppercase(),
                parts.next().unwrap_or_default().to_owned(),
            );
            let with_token = head.contains(&format!("x-aws-ec2-metadata-token: {TOKEN}"));
            log.lock().expect("a lock").push(format!(
                "{method} {path}{}",
                if with_token { " (token)" } else { "" }
            ));
            let credentials = format!(
                r#"{{"Code":"Success","LastUpdated":"2026-11-18T00:00:00Z","Type":"AWS-HMAC","AccessKeyId":"{key}","SecretAccessKey":"{secret}","Token":"","Expiration":"2099-01-01T00:00:00Z"}}"#
            );
            let (status, body) = match (method.as_str(), path.as_str(), with_token) {
                ("PUT", "/latest/api/token", _)
                    if head.contains("x-aws-ec2-metadata-token-ttl-seconds:") =>
                {
                    ("200 OK", TOKEN.to_owned())
                }
                ("GET", "/latest/meta-data/iam/security-credentials/", true) => {
                    ("200 OK", "ace4-role".to_owned())
                }
                ("GET", "/latest/meta-data/iam/security-credentials/ace4-role", true) => {
                    ("200 OK", credentials)
                }
                ("GET", "/latest/meta-data/placement/region", true) => {
                    ("200 OK", "eu-central-1".to_owned())
                }
                _ => ("404 Not Found", String::new()),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\
                 x-aws-ec2-metadata-token-ttl-seconds: 21600\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            // a client that hung up has what it asked for, or will ask again
            if socket.write_all(response.as_bytes()).await.is_ok() {
                socket.shutdown().await.ok();
            }
        }
    });
    (endpoint, seen)
}

#[tokio::test]
async fn the_chain_takes_the_instance_role_and_region_from_the_metadata_service() {
    let (key, secret) = dev_keys();
    let (endpoint, seen) = fake_metadata_service(key, secret).await;
    run_chain_child(
        "instance metadata",
        &[
            ("AWS_EC2_METADATA_DISABLED", "false".to_owned()),
            ("AWS_EC2_METADATA_SERVICE_ENDPOINT", endpoint),
        ],
    )
    .await;
    let seen = seen.lock().expect("a lock").clone();
    for request in [
        "PUT /latest/api/token",
        "GET /latest/meta-data/iam/security-credentials/ (token)",
        "GET /latest/meta-data/iam/security-credentials/ace4-role (token)",
        "GET /latest/meta-data/placement/region (token)",
    ] {
        assert!(seen.iter().any(|r| r == request), "{request} in {seen:?}");
    }
}

#[tokio::test]
async fn static_keys_read_no_aws_source() {
    // with the stack's keys and region set, a metadata service that answers nothing and AWS
    // variables that are wrong change nothing: the store reaches the bucket as before
    let mut command = tokio::process::Command::new(std::env::current_exe().expect("this binary"));
    command
        .args([
            "a_put_spools_and_uploads_and_a_get_elsewhere_fills_that_cache",
            "--exact",
            "--nocapture",
        ])
        .env("AWS_ACCESS_KEY_ID", "wrong")
        .env("AWS_SECRET_ACCESS_KEY", "wrong")
        .env("AWS_REGION", "nowhere-1")
        .env("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:9");
    let output = command.output().await.expect("the child runs");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && text.contains("1 passed"),
        "{text}"
    );
}

#[tokio::test]
async fn the_bucket_refuses_what_the_chain_finds_when_it_is_wrong() {
    // what makes the chain's cases mean something: the stack's bucket checks signatures
    let mut command = tokio::process::Command::new(std::env::current_exe().expect("this binary"));
    command
        .args(["chain_child", "--exact", "--ignored", "--nocapture"])
        .env(CHAIN_CASE, "wrong keys")
        .env_remove("ACE4_BUCKET_ACCESS_KEY")
        .env_remove("ACE4_BUCKET_SECRET_KEY")
        .env_remove("ACE4_BUCKET_REGION")
        .env("AWS_ACCESS_KEY_ID", dev_keys().0)
        .env("AWS_SECRET_ACCESS_KEY", "not-the-secret")
        .env("AWS_REGION", "eu-central-1")
        .env("AWS_EC2_METADATA_DISABLED", "true");
    let output = command.output().await.expect("the child runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{text}");
    assert!(
        text.contains("uploads: Bucket"),
        "the upload is refused: {text}"
    );
}
