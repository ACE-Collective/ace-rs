//! PLAN.md 2.13: a write goes through a transaction value that rolls back when dropped, and the
//! retry helper reruns the whole transaction closure on a serialization failure, never part of
//! it (ace3 #1084).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use ace_core::db::{Db, DbError, Isolation, Retryable, TRANSACTION_ATTEMPTS};
use ace_core::testing::TestDb;

async fn scratch_tables(test_db: &TestDb) {
    sqlx::raw_sql(
        "CREATE TABLE analysis.counter (id integer PRIMARY KEY, n integer NOT NULL);
         INSERT INTO analysis.counter VALUES (1, 0);
         CREATE TABLE analysis.statements (attempt integer, statement text);",
    )
    .execute(test_db.db().pool())
    .await
    .expect("creates the scratch tables");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_serialization_failure_reruns_every_statement_of_the_transaction() {
    let test_db = TestDb::new().await;
    scratch_tables(&test_db).await;
    let db = test_db.db();
    let attempts = AtomicU32::new(0);
    // what the closure ran, attempt by attempt, whether or not it was committed
    let ran: Mutex<Vec<(u32, &str)>> = Mutex::default();

    let read = db
        .transaction(Isolation::RepeatableRead, |tx| {
            let (attempts, ran) = (&attempts, &ran);
            Box::pin(async move {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                let step = |statement| ran.lock().expect("the log").push((attempt, statement));

                sqlx::query("INSERT INTO analysis.statements VALUES ($1, 'insert')")
                    .bind(attempt as i32)
                    .execute(tx.conn())
                    .await?;
                step("insert");
                // the first read fixes the transaction's snapshot
                let n: i32 = sqlx::query_scalar("SELECT n FROM analysis.counter WHERE id = 1")
                    .fetch_one(tx.conn())
                    .await?;
                sqlx::query("INSERT INTO analysis.statements VALUES ($1, 'read')")
                    .bind(attempt as i32)
                    .execute(tx.conn())
                    .await?;
                step("read");
                if attempt == 1 {
                    // another transaction changes the row and commits in between
                    sqlx::query("UPDATE analysis.counter SET n = n + 100 WHERE id = 1")
                        .execute(db.pool())
                        .await?;
                }
                // writing the row the other transaction changed fails to serialize the first
                // time
                let updated = sqlx::query("UPDATE analysis.counter SET n = $1 + 1 WHERE id = 1")
                    .bind(n)
                    .execute(tx.conn())
                    .await;
                step(if updated.is_ok() {
                    "update"
                } else {
                    "update failed"
                });
                updated?;
                sqlx::query("INSERT INTO analysis.statements VALUES ($1, 'update')")
                    .bind(attempt as i32)
                    .execute(tx.conn())
                    .await?;
                Ok::<_, DbError>(n)
            })
        })
        .await
        .expect("commits on the second attempt");

    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        *ran.lock().expect("the log"),
        [
            (1, "insert"),
            (1, "read"),
            (1, "update failed"),
            (2, "insert"),
            (2, "read"),
            (2, "update"),
        ]
    );
    // the second attempt read the other transaction's write, and its update is the one kept
    assert_eq!(read, 100);
    let n: i32 = sqlx::query_scalar("SELECT n FROM analysis.counter WHERE id = 1")
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert_eq!(n, 101);
    // every statement of the first attempt rolled back; all of the second's committed
    let committed: Vec<(i32, String)> = sqlx::query_as(
        "SELECT attempt, statement FROM analysis.statements ORDER BY attempt, statement",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(
        committed,
        [
            (2, "insert".to_owned()),
            (2, "read".to_owned()),
            (2, "update".to_owned())
        ]
    );
}

#[tokio::test]
async fn other_errors_are_not_retried_and_retries_are_bounded() {
    let test_db = TestDb::new().await;
    scratch_tables(&test_db).await;
    let db = test_db.db();

    let runs = AtomicU32::new(0);
    let error = db
        .transaction(Isolation::ReadCommitted, |tx| {
            let runs = &runs;
            Box::pin(async move {
                runs.fetch_add(1, Ordering::SeqCst);
                // a duplicate key: not a serialization failure
                sqlx::query("INSERT INTO analysis.counter VALUES (1, 0)")
                    .execute(tx.conn())
                    .await?;
                Ok::<_, DbError>(())
            })
        })
        .await
        .expect_err("fails");
    assert!(!error.is_retryable());
    assert_eq!(runs.load(Ordering::SeqCst), 1);

    let runs = AtomicU32::new(0);
    let error = db
        .transaction(Isolation::ReadCommitted, |tx| {
            let runs = &runs;
            Box::pin(async move {
                runs.fetch_add(1, Ordering::SeqCst);
                sqlx::query("INSERT INTO analysis.statements VALUES (0, 'always fails')")
                    .execute(tx.conn())
                    .await?;
                // what Postgres raises when it aborts a transaction to serialize it
                sqlx::raw_sql(
                    "DO $$ BEGIN RAISE EXCEPTION 'forced' USING ERRCODE = 'serialization_failure'; END $$",
                )
                .execute(tx.conn())
                .await?;
                Ok::<_, DbError>(())
            })
        })
        .await
        .expect_err("gives up");
    assert!(error.is_retryable());
    assert_eq!(runs.load(Ordering::SeqCst), TRANSACTION_ATTEMPTS);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM analysis.statements")
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert_eq!(left, 0, "nothing from the failed attempts was committed");
}

#[tokio::test]
async fn dropping_a_transaction_without_committing_rolls_it_back() {
    let test_db = TestDb::new().await;
    scratch_tables(&test_db).await;
    // one connection, so the read below gets the connection the transaction used
    let db = Db::connect(&test_db.config().clone().max_connections(1))
        .await
        .expect("connects");
    {
        let mut tx = db.begin().await.expect("begins");
        sqlx::query("UPDATE analysis.counter SET n = 7 WHERE id = 1")
            .execute(tx.conn())
            .await
            .expect("updates");
        // a failed statement aborts the transaction; the value can still only be dropped,
        // committed or rolled back, so the connection never goes back stuck
        assert!(
            sqlx::query("SELECT nope FROM analysis.counter")
                .execute(tx.conn())
                .await
                .is_err()
        );
    }
    // the next caller gets the same connection, back to clean
    let n: i32 = sqlx::query_scalar("SELECT n FROM analysis.counter WHERE id = 1")
        .fetch_one(db.pool())
        .await
        .expect("reads on a clean connection");
    assert_eq!(n, 0);
}
