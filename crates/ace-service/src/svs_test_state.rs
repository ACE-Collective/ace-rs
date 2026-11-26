//! A catalog test's state and run history, read from the database (PLAN.md 7.10 batch 8): the reads of
//! ace3's `saq/svs/test_state.py`, over `ace_core::svs::test_state`, which judges.
//!
//! [`evaluate_tests`] judges each test on each platform it has a run or a decision on, and
//! [`catalog_histories`] adds what the Tests screen shows of its runs and its exclusion, if a person
//! excluded it (batch 10). Both read for any number of tests in
//! a fixed number of queries, and nothing here is stored: the catalog's list (`svs_catalog`) asks for the
//! tests of one page, the coverage refresh (`svs_coverage`) for every test that isn't removed or excluded,
//! and the worklist for the tests a signature is expected of.
//!
//! How it scales: every query names the tests it is about (`test_guid = ANY`), so a read is linear in the
//! runs, expectations and ignores of those tests and never in the whole tables. The runs are read through
//! their indexes: `runs_by_test_platform` for the platforms a test has runs on, `runs_reviewed_latest`
//! (reviewed runs only, in the order asked for) for its latest reviewed run on each, and
//! `runs_by_test_created` for its latest runs, of which only the first [`RECENT_RUNS`] per test are read.
//! A test's run count is the one thing that counts every run of it. The signed-off results are those of
//! one run per test and platform. What ACE knows now of a signature is read only when some platform would
//! be validated, and then once: the hunts the hunter recorded and the current ruleset's rules.
//!
//! What differs from ace3's: a signature's current content hash comes from the hunts the hunter recorded
//! and the YARA rules of the ruleset the pools scan with, as a run's result reads them (`svs_results`),
//! where ace3 reads its signature inventory from the checkout. A rule that left the ruleset, like a file
//! ace3 can't read, doesn't count as changed.

use std::collections::{BTreeMap, BTreeSet};

use ace_core::svs::catalog::platform_slugs;
use ace_core::svs::coverage::Evaluations;
use ace_core::svs::signatures::{builtin_signatures, describe_signatures};
use ace_core::svs::test_state::{
    self, Evaluation, RECENT_RUNS, ReviewedRun, RunCounts, SignedOff, TestHistory,
};
use ace_core::svs::windows::recorded_hunts;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::ServiceError;
use crate::svs_decisions::{TestExclusion, exclusions};
use crate::svs_results::yara_signatures;

/// What a test's state reads of its catalog row.
#[derive(Debug, Clone)]
pub(crate) struct StateTest {
    pub(crate) guid: Uuid,
    pub(crate) content_hash: String,
    /// Its `supported_platforms`, as the catalog stores them.
    pub(crate) platforms: Vec<String>,
}

/// How each of `tests` does on each platform it has a run or a decision on: ace3's `evaluate_tests`.
pub(crate) async fn evaluate_tests(
    conn: &mut PgConnection,
    tests: &[StateTest],
) -> Result<Evaluations, ServiceError> {
    let hashes: BTreeMap<Uuid, &str> = tests
        .iter()
        .map(|test| (test.guid, test.content_hash.as_str()))
        .collect();
    let guids: Vec<Uuid> = hashes.keys().copied().collect();
    if guids.is_empty() {
        return Ok(Evaluations::new());
    }

    // the platforms each test has a run on
    let mut keys: BTreeSet<(Uuid, String)> = sqlx::query!(
        "SELECT DISTINCT test_guid, platform FROM svs.runs WHERE test_guid = ANY ($1)",
        &guids,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| (row.test_guid, row.platform))
    .collect();

    // its latest reviewed run on each
    let reviewed: BTreeMap<(Uuid, String), ReviewedRun> = sqlx::query!(
        "SELECT DISTINCT ON (test_guid, platform)
                id, uuid, test_guid, platform, reviewed_at, test_content_hash
         FROM svs.runs
         WHERE test_guid = ANY ($1) AND state = 'reviewed'
         ORDER BY test_guid, platform, reviewed_at DESC NULLS LAST, id DESC",
        &guids,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| {
        (
            (row.test_guid, row.platform),
            ReviewedRun {
                id: row.id,
                uuid: row.uuid,
                reviewed_at: row.reviewed_at,
                test_content_hash: row.test_content_hash,
            },
        )
    })
    .collect();

    // per (test, platform) with a decision: the expected signatures no ignore applies to (empty when
    // every decision there is a rejection or ignored)
    let mut ignored_everywhere: BTreeSet<String> = BTreeSet::new();
    let mut ignored: BTreeMap<Uuid, BTreeSet<String>> = BTreeMap::new();
    for row in sqlx::query!(
        "SELECT test_guid, signature_uuid FROM svs.ignores
         WHERE test_guid IS NULL OR test_guid = ANY ($1)",
        &guids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        match row.test_guid {
            None => ignored_everywhere.insert(row.signature_uuid),
            Some(guid) => ignored.entry(guid).or_default().insert(row.signature_uuid),
        };
    }
    let mut expected: BTreeMap<(Uuid, String), BTreeSet<String>> = BTreeMap::new();
    for row in sqlx::query!(
        "SELECT test_guid, platform, signature_uuid, state FROM svs.expectations
         WHERE test_guid = ANY ($1)",
        &guids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        let counts = row.state == "expected"
            && !ignored_everywhere.contains(&row.signature_uuid)
            && !ignored
                .get(&row.test_guid)
                .is_some_and(|set| set.contains(&row.signature_uuid));
        let signatures = expected.entry((row.test_guid, row.platform)).or_default();
        if counts {
            signatures.insert(row.signature_uuid);
        }
    }
    keys.extend(expected.keys().cloned());

    // the result rows of each latest reviewed run, by signature
    let run_ids: Vec<i64> = reviewed.values().map(|run| run.id).collect();
    let mut signed_off: BTreeMap<i64, BTreeMap<String, SignedOff>> = BTreeMap::new();
    if !run_ids.is_empty() {
        for row in sqlx::query!(
            "SELECT run_id, signature_uuid, reviewed_status, reviewed_content_hash
             FROM svs.run_results WHERE run_id = ANY ($1)",
            &run_ids,
        )
        .fetch_all(&mut *conn)
        .await?
        {
            signed_off.entry(row.run_id).or_default().insert(
                row.signature_uuid,
                SignedOff {
                    reviewed_status: row.reviewed_status,
                    reviewed_content_hash: row.reviewed_content_hash,
                },
            );
        }
    }
    let none_expected = BTreeSet::new();
    let none_signed = BTreeMap::new();

    // what ACE knows now of the expected signatures of the platforms that would be validated
    let would_validate: BTreeSet<&str> = keys
        .iter()
        .filter_map(|key| {
            let run = reviewed.get(key)?;
            let expected = expected.get(key).filter(|set| !set.is_empty())?;
            test_state::all_hit(expected, signed_off.get(&run.id).unwrap_or(&none_signed))
                .then_some(expected)
        })
        .flat_map(|expected| expected.iter().map(String::as_str))
        .collect();
    let current = if would_validate.is_empty() {
        BTreeMap::new()
    } else {
        let hunts = recorded_hunts(&mut *conn).await?;
        let yara = yara_signatures(&mut *conn).await?;
        describe_signatures(would_validate, &builtin_signatures(), &hunts, &yara)
    };

    let mut evaluations = Evaluations::new();
    for key in keys {
        let run = reviewed.get(&key);
        let evaluation = test_state::judge(
            run,
            expected.get(&key).unwrap_or(&none_expected),
            run.and_then(|run| signed_off.get(&run.id))
                .unwrap_or(&none_signed),
            hashes.get(&key.0).copied().unwrap_or_default(),
            &current,
        );
        evaluations
            .entry(key.0)
            .or_default()
            .insert(key.1, evaluation);
    }
    Ok(evaluations)
}

/// The history of each of `tests` and its exclusion, by guid: ace3's `catalog_histories`.
pub(crate) async fn catalog_histories(
    conn: &mut PgConnection,
    tests: &[StateTest],
) -> Result<BTreeMap<Uuid, (TestHistory, Option<TestExclusion>)>, ServiceError> {
    let guids: Vec<Uuid> = tests.iter().map(|test| test.guid).collect();
    if guids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut runs: BTreeMap<Uuid, RunCounts> = BTreeMap::new();
    for row in sqlx::query!(
        r#"SELECT test_guid, count(*) AS "count!" FROM svs.runs
           WHERE test_guid = ANY ($1) GROUP BY test_guid"#,
        &guids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        runs.entry(row.test_guid).or_default().run_count = row.count;
    }
    // each test's latest run, and of its latest ended or reviewed runs how many miss an expected
    // signature in their live result
    for row in sqlx::query!(
        r#"SELECT t.guid AS "guid!", last.uuid, last.created_at
           FROM unnest($1::uuid[]) AS t (guid)
           CROSS JOIN LATERAL (
               SELECT uuid, created_at FROM svs.runs
               WHERE test_guid = t.guid ORDER BY created_at DESC, id DESC LIMIT 1) last"#,
        &guids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        runs.entry(row.guid).or_default().last_run = Some((row.uuid, row.created_at));
    }
    for row in sqlx::query!(
        r#"SELECT t.guid AS "guid!", count(*) AS "runs!",
                  count(*) FILTER (WHERE EXISTS (
                      SELECT FROM svs.run_results x
                      WHERE x.run_id = recent.id
                        AND x.status IN ('missing', 'possibly_suppressed'))) AS "missing!"
           FROM unnest($1::uuid[]) AS t (guid)
           CROSS JOIN LATERAL (
               SELECT id FROM svs.runs
               WHERE test_guid = t.guid AND state IN ('ended', 'reviewed')
               ORDER BY created_at DESC, id DESC LIMIT $2) recent
           GROUP BY t.guid"#,
        &guids,
        RECENT_RUNS,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        let counts = runs.entry(row.guid).or_default();
        counts.recent_runs = row.runs;
        counts.recent_runs_missing = row.missing;
    }

    let mut excluded = exclusions(&mut *conn, &guids).await?;
    let evaluations = evaluate_tests(conn, tests).await?;
    let no_runs = RunCounts::default();
    let no_evaluations: BTreeMap<String, Evaluation> = BTreeMap::new();
    Ok(tests
        .iter()
        .map(|test| {
            let exclusion = excluded.remove(&test.guid);
            let history = test_state::history(
                &platform_slugs(&test.platforms),
                runs.get(&test.guid).unwrap_or(&no_runs),
                evaluations.get(&test.guid).unwrap_or(&no_evaluations),
                exclusion.is_some(),
            );
            (test.guid, (history, exclusion))
        })
        .collect())
}
