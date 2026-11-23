//! PLAN.md 2.5: the bucket with its index. Two puts of the same bytes leave one object, a get on
//! a second node fills that node's cache, and GC keeps exactly what a pool's retention keeps.
//! Needs the stack's postgres and bucket services.

use std::io::Read;
use std::time::Duration;

use ace_core::bucket::{Bucket, BucketSettings, Hold, PoolConfig, Retention};
use ace_core::testing::TestDb;
use ace_store::{BucketConfig, NodeCache, Store};
use chrono::Utc;

/// A node: its own cache directory, the shared bucket and the test's database.
struct Node {
    bucket: Bucket,
    _cache: tempfile::TempDir,
}

async fn node(test_db: &TestDb, settings: &BucketSettings) -> Node {
    let cache = tempfile::tempdir().expect("a cache directory");
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE_RS_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    )
    .await;
    Node {
        bucket: Bucket::new(test_db.db().clone(), store, settings.clone()),
        _cache: cache,
    }
}

/// A pool of the test's own, since tests share the bucket.
fn test_pool(retention: Retention) -> (String, BucketSettings) {
    let name = format!("test-{}", uuid::Uuid::new_v4().simple());
    let settings = BucketSettings::default().with_pool(&name, PoolConfig { retention });
    (name, settings)
}

async fn count(test_db: &TestDb, sql: &'static str, pool: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(pool)
        .fetch_one(test_db.db().pool())
        .await
        .expect("counts")
}

#[tokio::test]
async fn two_puts_leave_one_object_and_a_get_on_another_node_fills_its_cache() {
    let test_db = TestDb::new().await;
    let (pool, settings) = test_pool(Retention::Held {
        grace: Duration::from_secs(3600),
    });
    let (a, b) = (
        node(&test_db, &settings).await,
        node(&test_db, &settings).await,
    );
    let bytes = b"Received: from mail.example.com\nSubject: invoice\n\nplease see attached\n";

    let first = a
        .bucket
        .put_bytes(&pool, bytes, Some(&Hold::new("test", "first")))
        .await
        .expect("puts");
    let second = a
        .bucket
        .put_bytes(&pool, bytes, Some(&Hold::new("test", "second")))
        .await
        .expect("puts again");
    assert!(first.uploaded);
    assert!(!second.uploaded);
    assert_eq!(first.object.sha256, second.object.sha256);
    let sha256 = first.object.sha256;

    // one object in the bucket and in the index, with both holds
    let keys = a
        .bucket
        .store()
        .list(&format!("{pool}/"))
        .await
        .expect("lists");
    assert_eq!(keys, [Store::key(&pool, &sha256).unwrap()]);
    let objects = count(
        &test_db,
        "SELECT count(*) FROM store.objects WHERE pool = $1",
        &pool,
    )
    .await;
    let holds = count(
        &test_db,
        "SELECT count(*) FROM store.holds WHERE pool = $1",
        &pool,
    )
    .await;
    assert_eq!((objects, holds), (1, 2));

    // node b fills its cache from the bucket on its first get
    let cache_b = b.bucket.store().cache().path_of(&pool, &sha256);
    assert!(!cache_b.exists());
    let mut got = b.bucket.get(&pool, &sha256).await.expect("gets");
    assert!(!got.from_cache);
    let mut read = Vec::new();
    got.file.read_to_end(&mut read).expect("reads");
    assert_eq!(read, bytes);
    assert!(cache_b.exists());
    // and serves the next get from it, even with the bucket's copy gone
    a.bucket
        .store()
        .delete(&pool, &sha256)
        .await
        .expect("deletes the bucket's copy");
    let again = b.bucket.get(&pool, &sha256).await.expect("gets from cache");
    assert!(again.from_cache);
    // tidy the index; the bytes are already gone
    for hold in ["first", "second"] {
        a.bucket
            .release(&pool, &sha256, &Hold::new("test", hold))
            .await
            .expect("releases");
    }
}

#[tokio::test]
async fn gc_deletes_what_retention_no_longer_keeps() {
    let test_db = TestDb::new().await;
    let (pool, settings) = test_pool(Retention::Held {
        grace: Duration::ZERO,
    });
    let node = node(&test_db, &settings).await;
    let bucket = &node.bucket;
    let held = Hold::new("root", "kept");
    let kept = bucket
        .put_bytes(&pool, b"held until released", Some(&held))
        .await
        .expect("puts")
        .object
        .sha256;
    let unheld = bucket
        .put_bytes(&pool, b"never held", None)
        .await
        .expect("puts")
        .object
        .sha256;
    let expired = bucket
        .put_bytes(
            &pool,
            b"held until yesterday",
            Some(&Hold::new("root", "gone").until(Utc::now() - chrono::TimeDelta::days(1))),
        )
        .await
        .expect("puts")
        .object
        .sha256;

    let stats = bucket.gc(&pool).await.expect("collects");
    assert_eq!(stats.deleted, 2, "{stats:?}");
    assert_eq!(
        stats.holds_pruned, 0,
        "the expired hold went with its object"
    );
    assert!(bucket.object(&pool, &kept).await.unwrap().is_some());
    for gone in [unheld, expired] {
        assert!(bucket.object(&pool, &gone).await.unwrap().is_none());
        assert!(!bucket.store().exists(&pool, &gone).await.unwrap());
    }

    // releasing the last hold lets the next run delete it
    assert!(bucket.release(&pool, &kept, &held).await.expect("releases"));
    assert!(!bucket.release(&pool, &kept, &held).await.expect("releases"));
    assert_eq!(bucket.gc(&pool).await.expect("collects").deleted, 1);
    assert!(!bucket.store().exists(&pool, &kept).await.unwrap());
    assert!(
        bucket
            .store()
            .list(&format!("{pool}/"))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn an_expired_hold_beside_a_live_one_is_pruned_and_a_permanent_pool_keeps_everything() {
    let test_db = TestDb::new().await;
    let (pool, settings) = test_pool(Retention::Held {
        grace: Duration::ZERO,
    });
    let (permanent, settings) = {
        let name = format!("test-{}", uuid::Uuid::new_v4().simple());
        let settings = settings.with_pool(
            &name,
            PoolConfig {
                retention: Retention::Permanent,
            },
        );
        (name, settings)
    };
    let node = node(&test_db, &settings).await;
    let bucket = &node.bucket;
    let live = Hold::new("root", "live");
    let sha256 = bucket
        .put_bytes(&pool, b"two holds", Some(&live))
        .await
        .expect("puts")
        .object
        .sha256;
    bucket
        .hold(
            &pool,
            &sha256,
            &Hold::new("root", "old").until(Utc::now() - chrono::TimeDelta::hours(1)),
        )
        .await
        .expect("holds");
    let stats = bucket.gc(&pool).await.expect("collects");
    assert_eq!((stats.deleted, stats.holds_pruned), (0, 1));

    let forever = bucket
        .put_bytes(&permanent, b"kept forever", None)
        .await
        .expect("puts")
        .object
        .sha256;
    assert_eq!(bucket.gc(&permanent).await.expect("collects").deleted, 0);
    assert!(bucket.object(&permanent, &forever).await.unwrap().is_some());

    // tidy the shared bucket
    bucket
        .release(&pool, &sha256, &live)
        .await
        .expect("releases");
    bucket.gc(&pool).await.expect("collects");
    bucket
        .store()
        .delete(&permanent, &forever)
        .await
        .expect("deletes");
}
