//! The index in Postgres: ace3's `saq/search/index.py` and the Qdrant half of `query.py`, over
//! `search.chunks` (migration 0061).
//!
//! **Writing.** `PgIndex::index_alert` reads an alert's documents (`crate::documents`), cuts and embeds
//! them off the runtime (`crate::chunks`), and in one transaction writes the chunks, removes the
//! alert's chunks that aren't among them, and records what it wrote. A reader sees the old chunks or
//! the new, never none, which ace3 gets by upserting before it deletes. Indexing an alert again writes
//! the same rows. Nothing is written for a root that isn't an alert, and its chunks, if it has any,
//! are removed.
//!
//! **The dense lane** asks pgvector for the chunks nearest the query's embedding by cosine distance,
//! through the HNSW index, then keeps those at or above the floor and groups them by alert: the best
//! `limit` alerts, each with its `group` best chunks. It asks for `limit * group * 2` chunks, at most
//! the 1,000 pgvector's `hnsw.ef_search` allows, with `hnsw.iterative_scan` on so the scope's filter
//! doesn't starve the list. Qdrant groups inside its search; this reads a fixed number of nearest
//! chunks and groups them, so an alert whose many chunks all match could take the places of others
//! below it. A chunk is at most 16 of a document, and the floor cuts the tail.
//!
//! **The sparse lane** is Postgres full-text search over each chunk's terms. A chunk's score is the sum
//! over the query's terms it holds of the term's weight in the query, its rarity, and `ts_rank`, which
//! grows with how often the chunk says it and levels off. The rarity is `ln(1 + (N - n + 0.5) / (n +
//! 0.5))` for a term in `n` of `N` chunks, the formula Qdrant's IDF modifier uses, counted when the
//! query runs, so no statistics are kept.
//!
//! Postgres ranks a chunk by reading its row, so the lane's cost is the chunks it scores, and a word
//! half the index holds would be half the index read. So the work is bounded. A term's count stops at
//! `SELECTIVE_CHUNKS`; a term past it is common, takes that count as its rarity, and isn't used to find
//! chunks: the chunks scored are those that hold one of the query's rarer terms (the GIN index), and a
//! common term adds to their scores. A query of only common terms scores the chunks that hold all of
//! them. Either way at most `MAX_CANDIDATES` chunks are scored, in scope. Below those bounds, which is
//! every index of a few thousand chunks, the lane scores every chunk that shares a term, as Qdrant
//! does. Past them it differs from Qdrant: a chunk whose only match is a common word isn't found by
//! this lane.
//!
//! **Similar alerts** are the dense lane with the mean of the alert's own embeddings as the query,
//! which is what Qdrant's recommendation by positive examples computes.

use std::collections::HashMap;
use std::sync::Arc;

use ace_core::bucket::Bucket;
use ace_core::db::{Db, DbError, Isolation};
use ace_service::search::{
    IndexError, IndexFuture, Indexed, LaneResult, Scoped, SearchHit, SearchIndex, SearchLane,
};
use uuid::Uuid;

use crate::chunks::{self, Embedded};
use crate::documents::{self, Bounds};
use crate::model::{MODEL_NAME, Model};
use crate::sparse;

/// How many times indexing an alert may fail before its row is left alone: ace3's
/// `MAX_TASK_ATTEMPTS`.
pub const MAX_ATTEMPTS: i32 = 3;
/// How long an indexer holds an alert it took. Another may take it after.
const CLAIM_SECONDS: f64 = 600.0;
/// The most nearest chunks one dense query reads: pgvector's largest `hnsw.ef_search`.
const MAX_NEAREST: i64 = 1000;
/// A term held by more chunks than this isn't one the sparse lane finds chunks by, unless the query
/// has no rarer term: it only adds to the score of the chunks the rarer terms found.
const SELECTIVE_CHUNKS: i64 = 5000;
/// The most chunks one sparse query scores.
const MAX_CANDIDATES: i64 = 20_000;
/// The most chunks of an alert its similar-alerts query averages: ace3's `alert_point_ids` limit.
const MAX_SIMILAR_CHUNKS: i64 = 256;

/// The index in Postgres.
#[derive(Debug, Clone)]
pub struct PgIndex {
    db: Db,
    bucket: Option<Bucket>,
    model: Arc<Model>,
    bounds: Arc<Bounds>,
}

fn failed(error: impl std::fmt::Display) -> IndexError {
    IndexError::Failed(error.to_string())
}

/// A lane's rows grouped by alert: alerts by their best chunk, each with its `group` best chunks.
fn grouped(rows: Vec<(Uuid, SearchHit)>, limit: usize, group: usize) -> LaneResult {
    let mut order: Vec<Uuid> = Vec::new();
    let mut hits: HashMap<Uuid, Vec<SearchHit>> = HashMap::new();
    // the rows come best first
    for (alert, hit) in rows {
        let list = hits.entry(alert).or_insert_with(|| {
            order.push(alert);
            Vec::new()
        });
        if list.len() < group {
            list.push(hit);
        }
    }
    order
        .into_iter()
        .take(limit)
        .filter_map(|alert| hits.remove(&alert).map(|hits| (alert, hits)))
        .collect()
}

/// A lane's row as the alert it's of and its hit. A chunk's key is `kind:key:chunk`, as ace3's, so one
/// chunk reached by both lanes is one hit.
macro_rules! hit {
    ($row:expr) => {
        (
            $row.root_id,
            SearchHit {
                lane: SearchLane::Semantic,
                key: format!("{}:{}:{}", $row.kind, $row.key, $row.chunk),
                kind: $row.kind,
                title: $row.title,
                text: $row.text,
                score: $row.score,
                result_id: $row.result_id,
                observable_id: $row.observable_id,
            },
        )
    };
}

impl PgIndex {
    /// The index over `db`, embedding with `model`. `bucket` is where a result's text files are read
    /// from; without one those documents are left out.
    pub fn new(db: Db, bucket: Option<Bucket>, model: Arc<Model>) -> PgIndex {
        PgIndex {
            db,
            bucket,
            model,
            bounds: Arc::default(),
        }
    }

    /// The index with other bounds than ace3's defaults.
    pub fn with_bounds(mut self, bounds: Bounds) -> PgIndex {
        self.bounds = Arc::new(bounds);
        self
    }

    pub fn model(&self) -> &Arc<Model> {
        &self.model
    }

    /// The alert's documents, cut and embedded: what both indexes write.
    pub async fn embedded(
        &self,
        root: Uuid,
    ) -> Result<(Vec<Embedded>, usize, usize, Option<String>), IndexError> {
        let extracted =
            documents::extract(&self.db, self.bucket.as_ref(), root, &self.bounds).await?;
        let count = extracted.documents.len();
        let (model, bounds) = (self.model.clone(), self.bounds.clone());
        let (embedded, cut) = tokio::task::spawn_blocking(move || {
            chunks::embed(&model, &extracted.documents, &bounds)
        })
        .await
        .map_err(failed)?
        .map_err(failed)?;
        Ok((embedded, count, extracted.left_out + cut, extracted.skipped))
    }

    /// Indexes one alert: ace3's `index_alert`. A root that is gone or isn't an alert is skipped, not
    /// an error.
    pub async fn index_alert(&self, root: Uuid) -> Result<Indexed, IndexError> {
        let (embedded, documents, left_out, skipped) = self.embedded(root).await?;
        let chunks = embedded.len();
        let embedded = &embedded;
        let gone = skipped.is_some();
        self.db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    for chunk in embedded {
                        sqlx::query!(
                            "INSERT INTO search.chunks AS c
                                 (root_id, kind, key, chunk, title, text, result_id, observable_id,
                                  embedding, terms)
                             SELECT r.id, $2, $3, $4, $5, $6, $7, $8, $9::real[]::vector, $10::text::tsvector
                             FROM analysis.roots r WHERE r.id = $1
                             ON CONFLICT (root_id, kind, key, chunk) DO UPDATE
                                 SET title = EXCLUDED.title, text = EXCLUDED.text,
                                     result_id = EXCLUDED.result_id,
                                     observable_id = EXCLUDED.observable_id,
                                     embedding = EXCLUDED.embedding, terms = EXCLUDED.terms,
                                     indexed_at = now()",
                            root,
                            chunk.kind,
                            chunk.key,
                            chunk.chunk,
                            chunk.title,
                            chunk.text,
                            chunk.result_id,
                            chunk.observable_id,
                            chunk.embedding.as_slice(),
                            chunk.terms,
                        )
                        .execute(tx.conn())
                        .await?;
                    }
                    // what the alert had that isn't among the chunks just written
                    let kinds: Vec<String> = embedded.iter().map(|c| c.kind.to_owned()).collect();
                    let keys: Vec<String> = embedded.iter().map(|c| c.key.clone()).collect();
                    let numbers: Vec<i32> = embedded.iter().map(|c| c.chunk).collect();
                    sqlx::query!(
                        "DELETE FROM search.chunks c
                         WHERE c.root_id = $1 AND NOT EXISTS (
                             SELECT FROM unnest($2::text[], $3::text[], $4::integer[]) w(kind, key, chunk)
                             WHERE w.kind = c.kind AND w.key = c.key AND w.chunk = c.chunk)",
                        root,
                        &kinds,
                        &keys,
                        &numbers,
                    )
                    .execute(tx.conn())
                    .await?;
                    if gone {
                        sqlx::query!("DELETE FROM search.indexed WHERE root_id = $1", root)
                            .execute(tx.conn())
                            .await?;
                    } else {
                        sqlx::query!(
                            "INSERT INTO search.indexed (root_id, documents, chunks, left_out, model)
                             SELECT r.id, $2, $3, $4, $5 FROM analysis.roots r WHERE r.id = $1
                             ON CONFLICT (root_id) DO UPDATE
                                 SET documents = EXCLUDED.documents, chunks = EXCLUDED.chunks,
                                     left_out = EXCLUDED.left_out, model = EXCLUDED.model,
                                     indexed_at = now()",
                            root,
                            i32::try_from(documents).unwrap_or(i32::MAX),
                            i32::try_from(chunks).unwrap_or(i32::MAX),
                            i32::try_from(left_out).unwrap_or(i32::MAX),
                            MODEL_NAME,
                        )
                        .execute(tx.conn())
                        .await?;
                    }
                    Ok::<(), DbError>(())
                })
            })
            .await?;
        Ok(Indexed {
            root,
            documents,
            chunks,
            left_out,
            skipped,
            error: None,
        })
    }

    /// Removes an alert's chunks: ace3's `delete_alert`. Deleting the root does the same.
    pub async fn delete_alert(&self, root: Uuid) -> Result<u64, IndexError> {
        let removed = sqlx::query!("DELETE FROM search.chunks WHERE root_id = $1", root)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        sqlx::query!("DELETE FROM search.indexed WHERE root_id = $1", root)
            .execute(self.db.pool())
            .await?;
        Ok(removed)
    }

    /// How many chunks the index holds.
    pub async fn count(&self) -> Result<i64, IndexError> {
        Ok(
            sqlx::query_scalar!(r#"SELECT count(*) AS "count!" FROM search.chunks"#)
                .fetch_one(self.db.pool())
                .await?,
        )
    }

    /// The chunks nearest `vector`, in scope, at or above `floor`, grouped by alert.
    pub(crate) async fn nearest(
        &self,
        vector: Vec<f32>,
        scope: &Scoped,
        limit: usize,
        group: usize,
        floor: f64,
    ) -> Result<LaneResult, IndexError> {
        let wanted = i64::try_from(limit.saturating_mul(group).saturating_mul(2))
            .unwrap_or(MAX_NEAREST)
            .clamp(1, MAX_NEAREST);
        let windows = Scoped::multirange(&scope.windows);
        let not_windows = Scoped::multirange(&scope.not_windows);
        let (windows, not_windows) = (&windows, &not_windows);
        let vector = &vector;
        let rows = self
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    // LOCAL: for this transaction only. ef_search bounds how many an index scan
                    // returns, and the iterative scan keeps reading while the scope filters rows out.
                    // and the planner is kept to the plan the lane is written for, nearest chunks from
                    // the index and each one's root looked up, whatever it believes of the tables' sizes,
                    // planned for this vector: a plan cached for any vector casts the parameter to a
                    // vector again for every row, which measured ten times slower
                    sqlx::raw_sql(
                        "SET LOCAL statement_timeout = '10s';
                         SET LOCAL hnsw.ef_search = 1000;
                         SET LOCAL hnsw.iterative_scan = strict_order;
                         SET LOCAL enable_seqscan = off;
                         SET LOCAL enable_hashjoin = off;
                         SET LOCAL enable_mergejoin = off;
                         SET LOCAL plan_cache_mode = force_custom_plan",
                    )
                    .execute(tx.conn())
                    .await?;
                    let rows = sqlx::query!(
                        r#"SELECT c.root_id, c.kind, c.key, c.chunk, c.title, c.text, c.result_id,
                                  c.observable_id,
                                  1 - (c.embedding <=> $1::real[]::vector) AS "score!"
                           FROM search.chunks c
                           JOIN analysis.roots r ON r.id = c.root_id
                           WHERE r.alerted_at IS NOT NULL
                             AND search.in_scope(r.id, r.queue::text, r.disposition, r.alerted_at,
                                   $2, $3, $4, $5, $6::text::tstzmultirange,
                                   $7::text::tstzmultirange, $8)
                           ORDER BY c.embedding <=> $1::real[]::vector
                           LIMIT $9"#,
                        vector.as_slice(),
                        scope.queues.as_deref(),
                        scope.not_queues.as_deref(),
                        scope.dispositions.as_deref(),
                        scope.not_dispositions.as_deref(),
                        windows.as_deref(),
                        not_windows.as_deref(),
                        scope.except.as_deref(),
                        wanted,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    Ok::<_, DbError>(rows)
                })
            })
            .await?;
        let rows = rows
            .into_iter()
            .filter(|row| row.score >= floor)
            .map(|row| hit!(row))
            .collect();
        Ok(grouped(rows, limit, group))
    }

    async fn embed_query(&self, text: &str) -> Result<Vec<f32>, IndexError> {
        let (model, text) = (self.model.clone(), text.to_owned());
        tokio::task::spawn_blocking(move || model.encode_one(&text))
            .await
            .map_err(failed)?
            .map_err(failed)
    }

    pub(crate) async fn sparse_lane(
        &self,
        text: &str,
        scope: &Scoped,
        limit: usize,
        group: usize,
    ) -> Result<Option<LaneResult>, IndexError> {
        let terms = sparse::query_terms(text);
        if terms.is_empty() {
            return Ok(None);
        }
        // a lexeme is eight hex digits, so quoting it is all a tsquery needs
        let lexemes: Vec<String> = terms
            .iter()
            .map(|(index, _)| format!("'{}'", sparse::lexeme(*index)))
            .collect();
        let weights: Vec<f64> = terms.iter().map(|(_, weight)| *weight).collect();
        let wanted = i64::try_from(limit.saturating_mul(group).saturating_mul(2))
            .unwrap_or(MAX_NEAREST)
            .clamp(1, MAX_NEAREST);
        let windows = Scoped::multirange(&scope.windows);
        let not_windows = Scoped::multirange(&scope.not_windows);
        let (windows, not_windows) = (&windows, &not_windows);
        let (lexemes, weights) = (&lexemes, &weights);
        let rows = self
            .db
            .transaction(Isolation::RepeatableRead, |tx| {
                Box::pin(async move {
                    // the candidates are scored in memory, not sorted on disk
                    // and planned for these terms: a plan made for any terms can't use what the bounds are
                    sqlx::raw_sql(
                        "SET LOCAL statement_timeout = '10s'; SET LOCAL work_mem = '64MB';
                         SET LOCAL plan_cache_mode = force_custom_plan",
                    )
                        .execute(tx.conn())
                        .await?;
                    let rows = sqlx::query!(
                        r#"WITH q AS MATERIALIZED (
                               -- each term, with how many chunks hold it, counted no further than the cap
                               SELECT u.term, u.weight, (
                                          SELECT count(*) FROM (
                                              SELECT FROM search.chunks x
                                              WHERE x.terms @@ u.term::tsquery LIMIT $11::bigint + 1) held
                                      )::float8 AS n
                               FROM unnest($1::text[], $2::float8[]) u(term, weight)
                           ),
                           total AS (
                               SELECT GREATEST(COALESCE((SELECT sum(chunks) FROM search.indexed), 0),
                                               (SELECT max(n) FROM q), 1)::float8 AS n
                           ),
                           w AS MATERIALIZED (
                               SELECT q.term::tsquery AS term, q.n <= $11::bigint AS selective,
                                      q.weight * ln(1 + (total.n - q.n + 0.5) / (q.n + 0.5)) AS weight
                               FROM q, total WHERE q.n > 0
                           ),
                           wanted AS (
                               -- the chunks to score: those that hold a selective term, or, when the
                               -- query has none, those that hold every term
                               SELECT CASE WHEN bool_or(q.n <= $11::bigint)
                                           THEN string_agg(q.term, ' | ') FILTER (WHERE q.n <= $11::bigint)
                                           ELSE string_agg(q.term, ' & ') END::tsquery AS query
                               FROM q WHERE q.n > 0
                           ),
                           candidates AS MATERIALIZED (
                               SELECT c.root_id, c.kind, c.key, c.chunk, c.terms
                               FROM search.chunks c
                               JOIN analysis.roots r ON r.id = c.root_id
                               WHERE c.terms @@ (SELECT query FROM wanted)
                                 AND r.alerted_at IS NOT NULL
                                 AND search.in_scope(r.id, r.queue::text, r.disposition, r.alerted_at,
                                       $3, $4, $5, $6, $7::text::tstzmultirange,
                                       $8::text::tstzmultirange, $9)
                               LIMIT $12
                           ),
                           scored AS (
                               SELECT c.root_id, c.kind, c.key, c.chunk,
                                      sum(w.weight * ts_rank(c.terms, w.term)) AS score
                               FROM candidates c, w
                               GROUP BY c.root_id, c.kind, c.key, c.chunk
                               ORDER BY score DESC, c.root_id, c.kind, c.key, c.chunk
                               LIMIT $10
                           )
                           SELECT c.root_id, c.kind, c.key, c.chunk, c.title, c.text, c.result_id,
                                  c.observable_id, s.score AS "score!"
                           FROM scored s
                           JOIN search.chunks c
                             ON c.root_id = s.root_id AND c.kind = s.kind AND c.key = s.key
                            AND c.chunk = s.chunk
                           ORDER BY s.score DESC, c.root_id, c.kind, c.key, c.chunk"#,
                        lexemes.as_slice(),
                        weights.as_slice(),
                        scope.queues.as_deref(),
                        scope.not_queues.as_deref(),
                        scope.dispositions.as_deref(),
                        scope.not_dispositions.as_deref(),
                        windows.as_deref(),
                        not_windows.as_deref(),
                        scope.except.as_deref(),
                        wanted,
                        SELECTIVE_CHUNKS,
                        MAX_CANDIDATES,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    Ok::<_, DbError>(rows)
                })
            })
            .await?;
        let rows = rows
            .into_iter()
            .filter(|row| row.score > 0.0)
            .map(|row| hit!(row))
            .collect();
        Ok(Some(grouped(rows, limit, group)))
    }

    /// Takes the next due alert, indexes it, and settles its row: removed when the index is current,
    /// kept when a later pass asked again meanwhile, and marked with the error when indexing failed.
    async fn next(&self) -> Result<Option<Indexed>, IndexError> {
        let Some(due) = sqlx::query!(
            "UPDATE search.due d SET claimed_until = now() + make_interval(secs => $1)
             WHERE d.root_id = (
                 SELECT root_id FROM search.due
                 WHERE attempts < $2 AND (claimed_until IS NULL OR claimed_until < now())
                 ORDER BY due_at, root_id LIMIT 1 FOR UPDATE SKIP LOCKED)
             RETURNING d.root_id, d.version",
            CLAIM_SECONDS,
            MAX_ATTEMPTS,
        )
        .fetch_optional(self.db.pool())
        .await?
        else {
            return Ok(None);
        };
        match self.index_alert(due.root_id).await {
            Ok(indexed) => {
                sqlx::query!(
                    "DELETE FROM search.due WHERE root_id = $1 AND version = $2",
                    due.root_id,
                    due.version,
                )
                .execute(self.db.pool())
                .await?;
                Ok(Some(indexed))
            }
            Err(error) => {
                let message: String = error.to_string().chars().take(1024).collect();
                // a later request reset the row: this failure isn't its
                sqlx::query!(
                    "UPDATE search.due
                     SET attempts = attempts + 1, claimed_until = NULL, error = $3,
                         due_at = now() + interval '30 seconds',
                         failed_at = CASE WHEN attempts + 1 >= $4 THEN now() END
                     WHERE root_id = $1 AND version = $2",
                    due.root_id,
                    due.version,
                    message,
                    MAX_ATTEMPTS,
                )
                .execute(self.db.pool())
                .await?;
                Ok(Some(Indexed {
                    root: due.root_id,
                    documents: 0,
                    chunks: 0,
                    left_out: 0,
                    skipped: None,
                    error: Some(message),
                }))
            }
        }
    }
}

impl SearchIndex for PgIndex {
    fn dense<'a>(
        &'a self,
        text: &'a str,
        scope: &'a Scoped,
        limit: usize,
        group: usize,
        floor: f64,
    ) -> IndexFuture<'a, LaneResult> {
        Box::pin(async move {
            let vector = self.embed_query(text).await?;
            self.nearest(vector, scope, limit, group, floor).await
        })
    }

    fn sparse<'a>(
        &'a self,
        text: &'a str,
        scope: &'a Scoped,
        limit: usize,
        group: usize,
    ) -> IndexFuture<'a, Option<LaneResult>> {
        Box::pin(self.sparse_lane(text, scope, limit, group))
    }

    fn similar<'a>(
        &'a self,
        root: Uuid,
        scope: &'a Scoped,
        limit: usize,
        group: usize,
        floor: f64,
    ) -> IndexFuture<'a, LaneResult> {
        Box::pin(async move {
            // the mean of the alert's own embeddings, as Qdrant's recommendation by examples
            let mean = sqlx::query_scalar!(
                r#"SELECT avg(embedding)::real[] AS "mean"
                   FROM (SELECT embedding FROM search.chunks WHERE root_id = $1
                         ORDER BY kind, key, chunk LIMIT $2) own"#,
                root,
                MAX_SIMILAR_CHUNKS,
            )
            .fetch_one(self.db.pool())
            .await?;
            let Some(mean) = mean else {
                return Ok(Vec::new());
            };
            let mut scope = scope.clone();
            let except = scope.except.get_or_insert_with(Vec::new);
            if !except.contains(&root) {
                except.push(root);
            }
            self.nearest(mean, &scope, limit, group, floor).await
        })
    }

    fn index_next(&self) -> IndexFuture<'_, Option<Indexed>> {
        Box::pin(self.next())
    }
}
