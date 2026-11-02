//! What the queue's tests share: a root with observables, and workers on their own pools.

#![allow(dead_code)]

use std::time::Duration;

use ace_core::db::Db;
use ace_core::queue::Worker;
use ace_core::testing::TestDb;
use ace_core::tree::{self, NewRoot, ObservableId, upsert_observable};
use ace_results::{NewObservable, ObservableKind};
use uuid::Uuid;

/// A root in `mode` with these observables, committed.
pub async fn root_with(
    db: &Db,
    mode: &str,
    observables: &[(ObservableKind, &str)],
) -> (Uuid, Vec<ObservableId>) {
    let mut tx = db.begin().await.expect("begins");
    let root = NewRoot::new(mode);
    tree::create_root(&mut tx, &root).await.expect("creates");
    let mut ids = Vec::new();
    for (kind, value) in observables {
        let upserted = upsert_observable(&mut tx, root.id, &NewObservable::new(*kind, *value))
            .await
            .expect("adds");
        ids.push(upserted.id);
    }
    tx.commit().await.expect("commits");
    (root.id, ids)
}

/// A worker with its own connection pool, as a worker in another process would have.
pub async fn worker(test_db: &TestDb, name: &str, modules: &[&str], lease: Duration) -> Worker {
    let db = Db::connect(test_db.config()).await.expect("connects");
    Worker::new(
        db,
        name,
        modules.iter().map(|m| (*m).to_owned()).collect(),
        lease,
    )
}
