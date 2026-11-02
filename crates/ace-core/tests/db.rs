//! PLAN.md 2.2: the migrations create one schema per area.

use ace_core::db::AREAS;
use ace_core::testing::TestDb;

#[tokio::test]
async fn migrations_create_each_area() {
    let test_db = TestDb::new().await;
    assert_eq!(test_db.db().areas().await.expect("lists the areas"), AREAS);
}
