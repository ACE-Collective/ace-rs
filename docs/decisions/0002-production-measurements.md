# 0002, continued: production numbers the search decision needs

Status: the decision in `0002-search-index.md` is **not made**. On 2026-11-15 the owner asked for
production ace3 numbers first, and for an experiment that shows whether vector search on the core
database slows its ordinary queries. Qdrant's code (`ace_search::qdrant`) and the comparison
(`tools/search/compare`) stay until it is.

## What isn't known yet

`0002-search-index.md` measured search on a database doing nothing else, on eight real alerts and
156,000 synthetic chunks, with one Qdrant node. It doesn't answer:

- whether indexing and searching at production rates slow the core database's other queries;
- how either index behaves at production's real size and a year past it;
- what Qdrant's horizontal scaling buys at that size.

## Numbers to collect from production ace3

Every command below only reads. Run them from a host that reaches production's Qdrant and database.

### Setup

ace3's settings are under `qdrant:` in its config: the URL (`https://qdrant:6333` by default), the
CA file (`ssl/ca-chain.cert.pem`) and the API key (the file `/auth/passwords/qdrant`).

```sh
export QDRANT=https://qdrant:6333
export QDRANT_CA=/opt/ace/ssl/ca-chain.cert.pem      # where production keeps it
export QDRANT_KEY="$(cat /auth/passwords/qdrant)"
q() { curl -sS --cacert "$QDRANT_CA" -H "api-key: $QDRANT_KEY" -H 'content-type: application/json' "$@"; }
```

The collection is named `<collection_prefix>-<model slug>-v<schema version>`, so list them and take
the one that starts with `ace3-alerts-`:

```sh
q "$QDRANT/collections" | jq -r '.result.collections[].name'
export COLL=ace3-alerts-...                           # the name printed above
```

### 1. Index size

Points, segments, indexed vectors and the collection's settings:

```sh
q "$QDRANT/collections/$COLL" | jq '.result | {status, points_count, indexed_vectors_count, segments_count, config: .config.params, hnsw: .config.hnsw_config, optimizer: .config.optimizer_config}'
```

An exact count, since `points_count` is an estimate:

```sh
q -X POST "$QDRANT/collections/$COLL/points/count" -d '{"exact": true}' | jq .result.count
```

Size on disk and in memory. On the Qdrant host, or in its container:

```sh
docker exec <qdrant container> du -sh /qdrant/storage/collections
docker stats --no-stream <qdrant container>
```

Whether it is one node or a cluster, and how many shards and replicas:

```sh
q "$QDRANT/cluster" | jq .result
q "$QDRANT/collections/$COLL/cluster" | jq '.result | {shard_count, local_shards: (.local_shards|length), remote_shards: (.remote_shards|length)}'
```

### 2. Chunks per alert

Points by kind of document (alert, analysis, comment and so on):

```sh
q -X POST "$QDRANT/collections/$COLL/facet" -d '{"key": "kind", "limit": 50, "exact": true}' | jq -r '.result.hits[] | "\(.count)\t\(.value)"'
```

The alerts with the most chunks, for the high end. This needs Qdrant 1.12 or later:

```sh
q -X POST "$QDRANT/collections/$COLL/facet" -d '{"key": "root_uuid", "limit": 1000}' | jq -r '.result.hits[].count' | sort -n | awk '{a[NR]=$1} END {print "max", a[NR], "p50 of top 1000", a[int(NR/2)], "min of top 1000", a[1]}'
```

The average is the exact point count divided by the number of indexed alerts. `ace search status`
prints the index's state and both queue depths; the alert count comes from the database (below).

### 3. Write rate and growth

Points by the month their alert was inserted, for growth. Change the dates to cover the last year:

```sh
for m in 2026-01 2026-02 2026-03 2026-04 2026-05 2026-06 2026-07 2026-08 2026-09 2026-10; do
  n=$(date -j -v+1m -f %Y-%m-%d "$m-01" +%Y-%m-%d 2>/dev/null || date -d "$m-01 +1 month" +%Y-%m-%d)
  c=$(q -X POST "$QDRANT/collections/$COLL/points/count" -d "{\"exact\": true, \"filter\": {\"must\": [{\"key\": \"insert_date\", \"range\": {\"gte\": \"$m-01T00:00:00Z\", \"lt\": \"${n}T00:00:00Z\"}}]}}" | jq .result.count)
  echo "$m $c"
done
```

Alerts per hour over the last 30 days, with the busiest hours first, from ace3's MySQL:

```sql
SELECT DATE_FORMAT(insert_date, '%Y-%m-%d %H:00') AS hour, COUNT(*) AS alerts
FROM alerts WHERE insert_date >= NOW() - INTERVAL 30 DAY
GROUP BY hour ORDER BY alerts DESC LIMIT 25;

SELECT COUNT(*) AS alerts, MIN(insert_date) AS oldest FROM alerts;
```

The indexer logs one `search_index_task_complete` line per alert it indexes, with its point count and
seconds. A day of them gives the real indexing rate and cost:

```sh
docker logs --since 24h <search-indexer container> 2>&1 | grep -c search_index_task_complete
```

### 4. Search rate and latency

Qdrant counts every REST call and times it. Take this twice, an hour apart at a busy time, and
subtract: the difference in `rest_responses_total` for the query and search endpoints is the searches
in that hour, and the `rest_responses_duration_seconds` buckets give their latency.

```sh
q "$QDRANT/metrics" | grep -E '^rest_responses_(total|avg_duration_seconds|max_duration_seconds|duration_seconds_bucket)' | grep -E 'points/(query|search)|/query|/search'
```

The same figures as JSON, with each endpoint's count and average, minimum and maximum time:

```sh
q "$QDRANT/telemetry?details_level=2" | jq '.result.requests.rest.responses | to_entries[] | select(.key | test("query|search")) | {endpoint: .key, codes: .value}'
```

How many of those are free-text searches, exact-term searches and "similar alerts" comes from ace3's
own request logs: count requests to the search routes of `aceapi_v2` and the GUI by path over the same
hour.

### 5. The core database today

The baseline that search must not disturb. From ace3's MySQL, the busiest statements and their time:

```sql
SELECT DIGEST_TEXT, COUNT_STAR AS calls,
       ROUND(AVG_TIMER_WAIT/1e9, 2) AS avg_ms, ROUND(MAX_TIMER_WAIT/1e9, 2) AS max_ms,
       ROUND(SUM_TIMER_WAIT/1e12, 1) AS total_s
FROM performance_schema.events_statements_summary_by_digest
ORDER BY SUM_TIMER_WAIT DESC LIMIT 25;

SHOW GLOBAL STATUS WHERE Variable_name IN ('Queries', 'Threads_running', 'Uptime', 'Innodb_buffer_pool_reads');
```

## What to send back

1. The collection's point count, segments, shard and replica counts, and its size on disk and in
   memory.
2. Points by kind, and the high end of chunks per alert.
3. Points by month, alerts per hour at the peak, and a day's `search_index_task_complete` count.
4. Two `/metrics` snapshots an hour apart, and the split of search requests by route.
5. The database's top statements.

None of it holds alert content: they are counts, sizes and times. Check the statement digests before
sending them, since a digest's text can hold a table or column name a site considers private.

## The experiments those numbers set up

Each runs three ways: the index in the core Postgres, the index in a second Postgres of its own, and
the index in Qdrant.

1. **Size.** Fill each index to production's point count, and to that plus a year of the measured
   growth, with chunk counts per alert drawn from the measured spread.
2. **Interference.** Run ace4's ordinary workload (results landing, the alert list, the queue) and
   record its latency. Add indexing and searching at production's peak rates and record it again. The
   difference is what search costs the core database.
3. **Past the peak.** Repeat at two and five times the peak rates, to find where each one stops
   keeping up.
4. **Bulk write.** Re-index everything while the ordinary workload runs. Postgres took 308 seconds to
   Qdrant's 26 on the synthetic corpus, so this is where interference is most likely.
5. **Scaling out.** If production's Qdrant is a cluster, or its growth says it will need to be, run
   Qdrant with the same shard and replica counts and compare.

The second Postgres is the middle choice: search can't slow the core database, and there is still one
kind of database to run and back up. It doesn't scale out as Qdrant does. `ace_service::search`
reaches its index through one trait, so pointing it at another database is a small change.
