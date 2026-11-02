//! PLAN.md 2.4: roots with an event time and its source, observables unique on (root, type,
//! value), and results unique on (root, observable, module) with JSONB details under a GIN index.

use ace_core::testing::TestDb;
use ace_core::tree::{
    self, EventTime, EventTimeSource, NewRoot, insert_result, observables, upsert_observable,
};
use ace_results::{NewObservable, ObservableKind, ResultEnvelope};
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

fn result(details: Value) -> ResultEnvelope<Value> {
    serde_json::from_value(json!({
        "analysis_type": "example_line_stats",
        "schema_version": 1,
        "details": details,
        "summary": "3 lines",
    }))
    .expect("a result envelope")
}

#[tokio::test]
async fn upserting_an_observable_twice_leaves_one_row() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let root = NewRoot::new("analysis");
    tree::create_root(&mut tx, &root).await.expect("creates");

    let mut first = NewObservable::new(ObservableKind::Fqdn, "evil.example.com");
    first.tags = vec!["phish".to_owned()];
    first.directives = vec!["crawl".to_owned()];
    let mut again = NewObservable::new(ObservableKind::Fqdn, "evil.example.com");
    again.tags = vec!["phish".to_owned(), "newly_registered".to_owned()];
    again.exclude_modules = vec!["rdap_analyzer".to_owned()];

    let a = upsert_observable(&mut tx, root.id, &first)
        .await
        .expect("adds");
    let b = upsert_observable(&mut tx, root.id, &again)
        .await
        .expect("merges");
    assert!(a.inserted);
    assert!(!b.inserted);
    assert_eq!(a.id, b.id);
    tx.commit().await.expect("commits");

    let stored = observables(db.pool(), root.id).await.expect("reads");
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert_eq!(stored[0].tags, ["phish", "newly_registered"]);
    assert_eq!(stored[0].directives, ["crawl"]);
    assert_eq!(stored[0].exclude_modules, ["rdap_analyzer"]);
}

#[tokio::test]
async fn type_value_and_root_each_make_an_observable_distinct() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let one = NewRoot::new("analysis");
    let two = NewRoot::new("analysis");
    tree::create_root(&mut tx, &one).await.expect("creates");
    tree::create_root(&mut tx, &two).await.expect("creates");
    // longer than a btree entry may be, so uniqueness has to be on the hash
    let long_url = format!("data:text/html,{}", "A".repeat(100_000));
    for (root, kind, value) in [
        (one.id, ObservableKind::Fqdn, "example.com"),
        (
            one.id,
            ObservableKind::EmailDkimSigningDomain,
            "example.com",
        ),
        (one.id, ObservableKind::Fqdn, "example.org"),
        (two.id, ObservableKind::Fqdn, "example.com"),
        (one.id, ObservableKind::Url, long_url.as_str()),
        (one.id, ObservableKind::Url, long_url.as_str()),
    ] {
        upsert_observable(&mut tx, root, &NewObservable::new(kind, value))
            .await
            .expect("upserts");
    }
    tx.commit().await.expect("commits");
    assert_eq!(
        observables(db.pool(), one.id).await.expect("reads").len(),
        4
    );
    assert_eq!(
        observables(db.pool(), two.id).await.expect("reads").len(),
        1
    );
}

#[tokio::test]
async fn a_root_keeps_its_event_time_and_where_it_came_from() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let when = Utc
        .with_ymd_and_hms(2026, 10, 29, 12, 0, 0)
        .single()
        .expect("a time");
    let mut tx = db.begin().await.expect("begins");
    let mut ids = Vec::new();
    for event_time in [
        EventTime::Event(when),
        EventTime::QueryTime(when),
        EventTime::Now(when),
        EventTime::Unset,
    ] {
        let mut root = NewRoot::new("analysis");
        root.event_time = event_time;
        tree::create_root(&mut tx, &root).await.expect("creates");
        ids.push((root.id, event_time));
    }
    tx.commit().await.expect("commits");
    for (id, event_time) in ids {
        let root = tree::root(db.pool(), id)
            .await
            .expect("reads")
            .expect("exists");
        assert_eq!(root.event_time, event_time);
    }

    // a time with no source, or a source with no time, doesn't fit the table
    let mismatched = sqlx::query(
        "INSERT INTO analysis.roots (id, analysis_mode, event_time, event_time_source)
         VALUES (gen_random_uuid(), 'analysis', now(), $1)",
    )
    .bind(EventTimeSource::Unset)
    .execute(db.pool())
    .await;
    assert!(mismatched.is_err());
}

#[tokio::test]
async fn one_result_per_module_with_details_under_a_gin_index() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let root = NewRoot::new("analysis");
    tree::create_root(&mut tx, &root).await.expect("creates");
    let file = upsert_observable(
        &mut tx,
        root.id,
        &NewObservable::new(
            ObservableKind::File,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    )
    .await
    .expect("adds");
    let details = json!({"lines": 3, "longest_line": 12, "rule": {"name": "x"}});
    insert_result(
        &mut tx,
        root.id,
        file.id,
        "example_line_counter",
        &result(details),
    )
    .await
    .expect("stores");
    tx.commit().await.expect("commits");

    // a second result from the same module for the same observable is refused
    let mut tx = db.begin().await.expect("begins");
    let second = insert_result(
        &mut tx,
        root.id,
        file.id,
        "example_line_counter",
        &result(json!({"lines": 4})),
    )
    .await;
    assert!(second.is_err());
    drop(tx);

    // details are queryable, through the GIN index
    let mut conn = db.pool().acquire().await.expect("connects");
    sqlx::raw_sql("SET enable_seqscan = off")
        .execute(&mut *conn)
        .await
        .expect("sets");
    let query = r#"SELECT module FROM analysis.results WHERE details @> '{"rule": {"name": "x"}}'"#;
    let modules: Vec<String> = sqlx::query_scalar(query)
        .fetch_all(&mut *conn)
        .await
        .expect("queries");
    assert_eq!(modules, ["example_line_counter"]);
    let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("EXPLAIN {query}")))
        .fetch_all(&mut *conn)
        .await
        .expect("explains");
    let plan = plan.join("\n");
    assert!(plan.contains("results_details"), "{plan}");
}
