//! PLAN.md 2.3: each test gets its own copy of a template database built once, and tests run in
//! parallel on separate databases.

use std::collections::BTreeSet;

use ace_core::db::{AREAS, DbConfig};
use ace_core::testing::{TestDb, template_name};
use sqlx::{Connection, PgConnection};

/// The databases on the server whose names start with `prefix`.
async fn databases(prefix: &str) -> BTreeSet<String> {
    let options = DbConfig::from_env("ace-core-test")
        .expect("ACE4_DATABASE_URL")
        .database("postgres")
        .connect_options();
    let mut admin = PgConnection::connect_with(&options)
        .await
        .expect("connects");
    let names: Vec<String> =
        sqlx::query_scalar("SELECT datname::text FROM pg_database WHERE starts_with(datname, $1)")
            .bind(prefix)
            .fetch_all(&mut admin)
            .await
            .expect("lists databases");
    names.into_iter().collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tests_run_in_parallel_on_separate_databases() {
    // eight tests' databases, made at the same time and all open at once
    let mut made = tokio::task::JoinSet::new();
    for _ in 0..8 {
        made.spawn(TestDb::new());
    }
    let test_dbs: Vec<TestDb> = made.join_all().await;

    let names: BTreeSet<&str> = test_dbs.iter().map(TestDb::name).collect();
    assert_eq!(names.len(), 8, "{names:?}");
    for test_db in &test_dbs {
        let db = test_db.db();
        let current: String = sqlx::query_scalar("SELECT current_database()::text")
            .fetch_one(db.pool())
            .await
            .expect("reads");
        assert_eq!(current, test_db.name());
        // each is a migrated copy of the template
        assert_eq!(db.areas().await.expect("lists the areas"), AREAS);
        // and what one test writes, the others don't see
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE TABLE analysis.mark (name text); INSERT INTO analysis.mark VALUES ('{}')",
            test_db.name()
        )))
        .execute(db.pool())
        .await
        .expect("writes");
    }
    for test_db in &test_dbs {
        let marks: Vec<String> = sqlx::query_scalar("SELECT name FROM analysis.mark")
            .fetch_all(test_db.db().pool())
            .await
            .expect("reads");
        assert_eq!(marks, [test_db.name()]);
    }

    // one template, named for the current migrations and seed
    let templates = databases("ace4_template_").await;
    assert_eq!(templates, BTreeSet::from([template_name()]));

    // dropping a test's database handle drops the database
    let gone: Vec<String> = test_dbs.iter().map(|t| t.name().to_owned()).collect();
    drop(test_dbs);
    let left = databases("ace4_test_").await;
    for name in gone {
        assert!(!left.contains(&name), "{name} is still there");
    }
}
