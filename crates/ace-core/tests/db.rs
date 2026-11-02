//! PLAN.md 2.2: the pool connects and the migrations create one schema per area.

use ace_core::db::{AREAS, Db, DbConfig};

#[tokio::test]
async fn migrations_create_each_area() {
    let db = Db::connect(&DbConfig::from_env("ace-core-tests").expect("ACE4_DATABASE_URL"))
        .await
        .expect("connects");
    db.migrate().await.expect("migrates");
    assert_eq!(db.areas().await.expect("lists the areas"), AREAS);
}
