//! ace3's index, a Qdrant collection, behind the same read path: the other side of the retrieval
//! comparison (`docs/decisions/0002-search-index.md`). Only this crate's tests build it (the `qdrant`
//! feature), against a Qdrant of ace3's version that the comparison starts for itself, never ace3's.
//!
//! It is ace3's `saq/search/index.py` and the Qdrant half of `query.py` over Qdrant's REST API: one
//! collection whose points each carry a `dense` vector (cosine) and a `sparse` one that Qdrant weights by
//! inverse document frequency, with ace3's payload and its keyword and datetime indexes; a point's id is
//! ace3's, the UUIDv5 of `kind:key:chunk` under the alert's id; a write upserts, then deletes the
//! alert's points that weren't written; the lanes are grouped queries, the dense one with ace3's score
//! floor; similar alerts are a recommendation by the alert's own points. The chunks, their embeddings
//! and their terms are the ones `PgIndex` writes (`crate::chunks`), so the two sides differ only in the
//! index.
//!
//! As in ace3, the scope's filters are a payload filter, so the payload has to be refreshed when an
//! alert's disposition or queue changes (`update_payload`), which the Postgres index has no need of.

use ace_core::db::Db;
use ace_service::search::{
    IndexError, IndexFuture, Indexed, LaneResult, Scoped, SearchHit, SearchIndex, SearchLane,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::documents::Document;
use crate::pg::PgIndex;

/// ace3's index in Qdrant.
#[derive(Debug, Clone)]
pub struct QdrantIndex {
    http: reqwest::Client,
    /// Qdrant's address, such as `http://qdrant:6333`.
    url: String,
    collection: String,
    /// Reads the alerts and embeds, as the Postgres index does.
    pg: PgIndex,
    db: Db,
}

fn failed(error: impl std::fmt::Display) -> IndexError {
    IndexError::Failed(format!("qdrant: {error}"))
}

fn iso(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// ace3's `point_id`.
pub fn point_id(root: Uuid, kind: &str, key: &str, chunk: i32) -> Uuid {
    Uuid::new_v5(&root, format!("{kind}:{key}:{chunk}").as_bytes())
}

/// The scope as a Qdrant payload filter: ace3's `build_payload_filter`.
fn payload_filter(scope: &Scoped) -> Option<Value> {
    let mut must = Vec::new();
    let mut must_not = Vec::new();
    let any = |key: &str, values: &[String]| json!({"key": key, "match": {"any": values}});
    if let Some(queues) = &scope.queues {
        must.push(any("queue", queues));
    }
    if let Some(queues) = &scope.not_queues {
        must_not.push(any("queue", queues));
    }
    if let Some(dispositions) = &scope.dispositions {
        must.push(any("disposition", dispositions));
    }
    if let Some(dispositions) = &scope.not_dispositions {
        must_not.push(any("disposition", dispositions));
    }
    let ranges = |windows: &Vec<(DateTime<Utc>, DateTime<Utc>)>| {
        json!({"should": windows.iter().map(|(start, end)| {
            json!({"key": "insert_date", "range": {"gte": iso(*start), "lte": iso(*end)}})
        }).collect::<Vec<_>>()})
    };
    if let Some(windows) = &scope.windows {
        must.push(ranges(windows));
    }
    if let Some(windows) = &scope.not_windows {
        must_not.push(ranges(windows));
    }
    if let Some(except) = &scope.except {
        let ids: Vec<String> = except.iter().map(Uuid::to_string).collect();
        must_not.push(any("root_uuid", &ids));
    }
    if must.is_empty() && must_not.is_empty() {
        return None;
    }
    let mut filter = serde_json::Map::new();
    if !must.is_empty() {
        filter.insert("must".to_owned(), Value::Array(must));
    }
    if !must_not.is_empty() {
        filter.insert("must_not".to_owned(), Value::Array(must_not));
    }
    Some(Value::Object(filter))
}

impl QdrantIndex {
    /// The collection `collection` at `url`, created with ace3's vectors and payload indexes when it
    /// isn't there. `pg` reads and embeds the alerts.
    pub async fn create(
        url: &str,
        collection: &str,
        pg: PgIndex,
        db: Db,
    ) -> Result<Self, IndexError> {
        let index = QdrantIndex {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(failed)?,
            url: url.trim_end_matches('/').to_owned(),
            collection: collection.to_owned(),
            pg,
            db,
        };
        index
            .call(
                reqwest::Method::PUT,
                "",
                json!({
                    "vectors": {"dense": {"size": crate::model::DIMENSIONS, "distance": "Cosine"}},
                    "sparse_vectors": {"sparse": {"modifier": "idf"}},
                }),
            )
            .await?;
        for (field, schema) in [
            ("root_uuid", "keyword"),
            ("kind", "keyword"),
            ("queue", "keyword"),
            ("disposition", "keyword"),
            ("tags", "keyword"),
            ("insert_date", "datetime"),
        ] {
            index
                .call(
                    reqwest::Method::PUT,
                    "/index?wait=true",
                    json!({"field_name": field, "field_schema": schema}),
                )
                .await?;
        }
        Ok(index)
    }

    pub(crate) async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Value,
    ) -> Result<Value, IndexError> {
        let url = format!("{}/collections/{}{path}", self.url, self.collection);
        let response = self
            .http
            .request(method, &url)
            .json(&body)
            .send()
            .await
            .map_err(failed)?;
        let status = response.status();
        let text = response.text().await.map_err(failed)?;
        if !status.is_success() {
            return Err(failed(format!("{url} answered {status}: {text}")));
        }
        serde_json::from_str(&text).map_err(failed)
    }

    /// The alert-level payload every point of the alert carries: ace3's `alert_metadata_payload`.
    async fn metadata(&self, root: Uuid) -> Result<Option<Value>, IndexError> {
        // not checked at build time as the index's own queries are: this module is built only for the
        // comparison's tests, and the workspace's offline query data is of what ships
        let row: Option<(String, String, DateTime<Utc>, Vec<String>)> = sqlx::query_as(
            "SELECT r.queue::text, COALESCE(r.disposition, 'OPEN'), r.alerted_at,
                    ARRAY(SELECT DISTINCT lower(tag) FROM (
                              SELECT unnest(o.tags) AS tag FROM analysis.observables o
                              WHERE o.root_id = r.id
                              UNION ALL
                              SELECT unnest(x.tags) FROM analysis.results x WHERE x.root_id = r.id
                          ) t ORDER BY 1)
             FROM analysis.roots r WHERE r.id = $1 AND r.alerted_at IS NOT NULL",
        )
        .bind(root)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.map(|(queue, disposition, alerted_at, tags)| {
            json!({
                "root_uuid": root.to_string(),
                "queue": queue,
                "disposition": disposition,
                "insert_date": iso(alerted_at),
                "tags": tags,
            })
        }))
    }

    fn of_root(root: Uuid) -> Value {
        json!({"key": "root_uuid", "match": {"value": root.to_string()}})
    }

    /// Indexes one alert: ace3's `index_alert`, an upsert and then a delete of what's stale.
    pub async fn index_alert(&self, root: Uuid, given: &[Document]) -> Result<Indexed, IndexError> {
        let (embedded, documents, left_out, skipped) = self.pg.embedded(root, given).await?;
        let metadata = self.metadata(root).await?.unwrap_or_else(|| json!({}));
        let mut ids = Vec::with_capacity(embedded.len());
        let points: Vec<Value> = embedded
            .iter()
            .map(|chunk| {
                let id = point_id(root, chunk.kind, &chunk.key, chunk.chunk).to_string();
                ids.push(id.clone());
                let mut payload = metadata.clone();
                if let Some(payload) = payload.as_object_mut() {
                    payload.insert("kind".to_owned(), json!(chunk.kind));
                    payload.insert("key".to_owned(), json!(chunk.key));
                    payload.insert("chunk".to_owned(), json!(chunk.chunk));
                    payload.insert("text".to_owned(), json!(chunk.text));
                    payload.insert("title".to_owned(), json!(chunk.title));
                    payload.insert("result_id".to_owned(), json!(chunk.result_id));
                    payload.insert("observable_id".to_owned(), json!(chunk.observable_id));
                }
                json!({
                    "id": id,
                    "vector": {
                        "dense": chunk.embedding,
                        "sparse": {
                            "indices": chunk.sparse.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
                            "values": chunk.sparse.iter().map(|(_, weight)| *weight).collect::<Vec<_>>(),
                        },
                    },
                    "payload": payload,
                })
            })
            .collect();
        if !points.is_empty() {
            self.call(
                reqwest::Method::PUT,
                "/points?wait=true",
                json!({"points": points}),
            )
            .await?;
        }
        let mut filter = json!({"must": [Self::of_root(root)]});
        if !ids.is_empty() {
            filter["must_not"] = json!([{"has_id": ids}]);
        }
        self.call(
            reqwest::Method::POST,
            "/points/delete?wait=true",
            json!({"filter": filter}),
        )
        .await?;
        Ok(Indexed {
            root,
            documents,
            chunks: embedded.len(),
            left_out,
            skipped,
            error: None,
        })
    }

    /// Refreshes the disposition, queue and tags on the alert's points: ace3's `update_alert_payload`.
    /// False when the alert is gone.
    pub async fn update_payload(&self, root: Uuid) -> Result<bool, IndexError> {
        let Some(metadata) = self.metadata(root).await? else {
            return Ok(false);
        };
        let payload = json!({
            "disposition": metadata["disposition"],
            "queue": metadata["queue"],
            "tags": metadata["tags"],
        });
        self.call(
            reqwest::Method::POST,
            "/points/payload?wait=true",
            json!({"payload": payload, "filter": {"must": [Self::of_root(root)]}}),
        )
        .await?;
        Ok(true)
    }

    /// Removes the alert's points: ace3's `delete_alert`.
    pub async fn delete_alert(&self, root: Uuid) -> Result<(), IndexError> {
        self.call(
            reqwest::Method::POST,
            "/points/delete?wait=true",
            json!({"filter": {"must": [Self::of_root(root)]}}),
        )
        .await
        .map(|_| ())
    }

    /// How many points the collection holds.
    pub async fn count(&self) -> Result<u64, IndexError> {
        let counted = self
            .call(
                reqwest::Method::POST,
                "/points/count",
                json!({"exact": true}),
            )
            .await?;
        counted["result"]["count"]
            .as_u64()
            .ok_or_else(|| failed("no count"))
    }

    /// The payload of the alert's points.
    pub async fn payloads(&self, root: Uuid) -> Result<Vec<Value>, IndexError> {
        let found = self
            .call(
                reqwest::Method::POST,
                "/points/scroll",
                json!({"filter": {"must": [Self::of_root(root)]}, "limit": 256, "with_payload": true}),
            )
            .await?;
        Ok(found["result"]["points"]
            .as_array()
            .map(|points| {
                points
                    .iter()
                    .map(|point| point["payload"].clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Drops the collection.
    pub async fn drop_collection(&self) -> Result<(), IndexError> {
        self.call(reqwest::Method::DELETE, "", json!({}))
            .await
            .map(|_| ())
    }

    /// Qdrant's own description of the collection, for the comparison's sizes.
    pub async fn info(&self) -> Result<Value, IndexError> {
        self.call(reqwest::Method::GET, "", json!({})).await
    }

    /// A grouped query: ace3's `_grouped_query` and `_groups_to_lane`.
    pub(crate) async fn grouped(
        &self,
        query: Value,
        using: &str,
        scope: &Scoped,
        limit: usize,
        group: usize,
        floor: Option<f64>,
    ) -> Result<LaneResult, IndexError> {
        let mut body = json!({
            "query": query,
            "using": using,
            "group_by": "root_uuid",
            "group_size": group,
            "limit": limit,
            "with_payload": true,
        });
        if let Some(filter) = payload_filter(scope) {
            body["filter"] = filter;
        }
        if let Some(floor) = floor {
            body["score_threshold"] = json!(floor);
        }
        let found = self
            .call(reqwest::Method::POST, "/points/query/groups", body)
            .await?;
        let mut lane = Vec::new();
        for group in found["result"]["groups"].as_array().into_iter().flatten() {
            let Some(root) = group["id"].as_str().and_then(|id| id.parse::<Uuid>().ok()) else {
                continue;
            };
            let hits = group["hits"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|point| {
                    let payload = &point["payload"];
                    let text = |key: &str| payload[key].as_str().unwrap_or_default().to_owned();
                    let kind = text("kind");
                    SearchHit {
                        lane: SearchLane::Semantic,
                        key: format!(
                            "{kind}:{}:{}",
                            text("key"),
                            payload["chunk"].as_i64().unwrap_or(0)
                        ),
                        kind,
                        title: payload["title"].as_str().map(str::to_owned),
                        text: text("text"),
                        score: point["score"].as_f64().unwrap_or(0.0),
                        result_id: payload["result_id"].as_i64(),
                        observable_id: payload["observable_id"].as_i64(),
                    }
                })
                .collect();
            lane.push((root, hits));
        }
        Ok(lane)
    }
}

impl SearchIndex for QdrantIndex {
    fn dense<'a>(
        &'a self,
        text: &'a str,
        scope: &'a Scoped,
        limit: usize,
        group: usize,
        floor: f64,
    ) -> IndexFuture<'a, LaneResult> {
        Box::pin(async move {
            let (model, text) = (self.pg.model().clone(), text.to_owned());
            let vector = tokio::task::spawn_blocking(move || model.encode_one(&text))
                .await
                .map_err(failed)?
                .map_err(failed)?;
            self.grouped(json!(vector), "dense", scope, limit, group, Some(floor))
                .await
        })
    }

    fn sparse<'a>(
        &'a self,
        text: &'a str,
        scope: &'a Scoped,
        limit: usize,
        group: usize,
    ) -> IndexFuture<'a, Option<LaneResult>> {
        Box::pin(async move {
            // ace3's `sparse_vector(query)`: every term, in id order
            let terms = crate::sparse::term_weights(text);
            if terms.is_empty() {
                return Ok(None);
            }
            let query = json!({
                "indices": terms.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
                "values": terms.iter().map(|(_, weight)| *weight).collect::<Vec<_>>(),
            });
            self.grouped(query, "sparse", scope, limit, group, None)
                .await
                .map(Some)
        })
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
            let found = self
                .call(
                    reqwest::Method::POST,
                    "/points/scroll",
                    json!({"filter": {"must": [Self::of_root(root)]}, "limit": 256,
                           "with_payload": false, "with_vector": false}),
                )
                .await?;
            let ids: Vec<Value> = found["result"]["points"]
                .as_array()
                .map(|points| points.iter().map(|point| point["id"].clone()).collect())
                .unwrap_or_default();
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let mut scope = scope.clone();
            let except = scope.except.get_or_insert_with(Vec::new);
            if !except.contains(&root) {
                except.push(root);
            }
            self.grouped(
                json!({"recommend": {"positive": ids}}),
                "dense",
                &scope,
                limit,
                group,
                Some(floor),
            )
            .await
        })
    }

    fn index_next(&self) -> IndexFuture<'_, Option<Indexed>> {
        // the comparison indexes each alert by name; nothing queues work for this index
        Box::pin(async { Ok(None) })
    }
}
