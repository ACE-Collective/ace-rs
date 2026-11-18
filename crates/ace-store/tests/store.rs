//! ace-store against the stack's bucket, and the node cache on its own. The bucket tests need
//! the `bucket` service and the ACE4_BUCKET_* variables the dev container sets.

use std::io::Read;
use std::time::{Duration, SystemTime};

use ace_results::Sha256;
use ace_store::{BucketConfig, NodeCache, Store, StoreError};

fn store(cache: &tempfile::TempDir) -> Store {
    let config = BucketConfig::from_env().expect(
        "the ACE4_BUCKET_* variables; bucket tests run in the dev container with the stack up",
    );
    Store::new(
        &config,
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    )
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
    let (a, b) = (store(&dir_a), store(&dir_b));
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
        .get(&pool, &sha256)
        .await;
    assert!(matches!(gone, Err(StoreError::NotFound { .. })), "{gone:?}");
}

#[tokio::test]
async fn a_get_refuses_bytes_whose_hash_isnt_their_name() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (store(&dir_a), store(&dir_b));
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
