# 0002: The search index in Postgres, without Qdrant

Status: proposed (PLAN.md 7.11). The decision is the owner's. This records what was built, what was measured on 2026-11-15, and what the measurements recommend.

## The question

ace3's alert search keeps its index in Qdrant: a dense vector and a sparse vector for every chunk of every alert's text, with a copy of the alert's disposition, queue, tags and date on every point so Qdrant can filter. DESIGN.md says that at production's size, about 26,000 alerts growing by about 80 a day, pgvector and Postgres full-text search could replace it, if retrieval quality holds. PLAN.md 7.11 asks for the index in Postgres, ace3's retrieval regression run against both, and this record.

## What was compared

One read path, `ace_service::search`, with two indexes behind it (`ace_service::search::SearchIndex`):

- **Postgres** (`ace_search::PgIndex`, what `ace serve` runs): `search.chunks`, one row for each chunk with its embedding in a pgvector column under an HNSW index and its terms in a `tsvector` under a GIN index. The dense lane is nearest neighbours by cosine distance. The sparse lane is full-text search over the terms, each term weighted by its rarity with the formula Qdrant's IDF modifier uses.
- **Qdrant** (`ace_search::qdrant::QdrantIndex`, built only for the comparison's tests): ace3's collection, its dense and sparse vectors, its payload and payload filter, its grouped queries, its score floor and its recommendation by an alert's own points, over Qdrant's REST API. Qdrant 1.20.0, the image ace3 runs, pinned by digest, in a throwaway Compose project of its own (`tools/search/qdrant.compose.yaml`). ace3's Qdrant was never read or written.

Everything else is the same code on both sides: the documents taken from an alert, the chunks, the embedding model and its vectors, the sparse terms, the exact lane and the filters over Postgres, the fusion and the tiers. The model is ace3's, `all-MiniLM-L6-v2`, 384 dimensions, run in the process. Its vectors match ones ace3's own model made to a cosine above 0.9999, and the terms, token bounds and chunks are ace3's exactly (`crates/ace-search/src/tests.rs`, against `tools/ace3/search/make-reference`'s output).

To reproduce: `tools/search/compare`, and `tools/search/compare --scale` for the sizes and timings.

## Retrieval quality

ace3's `tests/saq/search/test_retrieval.py` is ported as `ace-search`'s `tests::postgres::*` and `tests::qdrant::*`: the same seven cases over the same eight-alert corpus, through `Service::search_alerts` and `Service::similar_alerts`. All seven pass on both sides.

The test's own metrics, from its labeled queries (three results asked for each):

| | Postgres | Qdrant 1.20.0 |
|---|---|---|
| Expected alerts in the top 3 (recall@3) | 12 of 12 | 12 of 12 |
| Mean reciprocal rank of the first expected alert | 0.955 | 0.955 |
| Exact terms ranked first with the tier `exact` | 4 of 4 | 4 of 4 |
| Results for the four junk queries | 0 | 0 |
| Similar alerts finds the near duplicate | yes | yes |
| A filter narrows both lanes | yes | yes |
| Indexing again changes nothing | yes | yes |

Query by query, the rank of each expected alert, the top result's tier and its dense score were the same on both sides:

| Query | Ranks | Top tier | Top dense |
|---|---|---|---|
| `docusign invoice phishing` | 1 and 2 | strong | 0.767 |
| `email_address:bob@example.com` | 1 | exact | |
| `ipv4:10.20.30.40` | 1 | exact | |
| `sha256:<hash>` | 1 | exact | |
| `tag:credential-harvest` | 1 | exact | |
| `bob@example.com` | 2 | strong | 0.360 |
| `10.20.30.40` | 1 | weak | |
| `powershell encoded download` | 1 | strong | 0.693 |
| `qr code mfa reset` | 1 | strong | 0.582 |
| `vendor mailer false positive` | 1 | strong | 0.694 |
| `brute force vpn logins` | 1 | strong | 0.706 |

The two DocuSign alerts are near duplicates and tie; which of them is first varied between runs on both sides. `bob@example.com`, bare, ranks its alert second on both: the first is another email to an `example.com` address, by the dense lane.

What this doesn't show: the corpus is eight alerts. It tells the two indexes apart only if one of them is wrong, and neither is. It says nothing about ranking quality over thousands of real alerts, which nothing on this laptop can measure. At that size the dense lane's HNSW search is approximate on both sides, and the sparse lanes differ in one way described under *What differs* below.

## Latency

End to end on the eight-alert corpus, the median of nine runs of each query, in a dev build:

| | Postgres | Qdrant |
|---|---|---|
| A query with free text | 17.7 to 21.8 ms | 17.2 to 23.9 ms |
| A query of exact terms only | 2.3 to 2.4 ms | 2.4 to 2.8 ms |

The free-text time is the model: embedding a query took a median of 16.1 ms. The index is the rest.

At production's size, with synthetic data: 26,000 alerts of six chunks each, 156,000 chunks, the same vectors and terms in both indexes. The vectors are clustered so a query has neighbours above the floor, and the terms follow a Zipf-like spread over a 20,000-word vocabulary. Each lane was timed alone, 50 queries, without the model:

| Lane | Postgres median | p95 | max | Qdrant median | p95 | max |
|---|---|---|---|---|---|---|
| Dense, first ask of a vector | 48.6 ms | 60.0 | 164.6 | 10.2 ms | 19.9 | 24.0 |
| Dense, the same vector again with a queue filter | 14.6 ms | 16.9 | 21.5 | 8.3 ms | 11.1 | 12.7 |
| Sparse, four words | 72.7 ms | 132.0 | 150.3 | 20.3 ms | 60.4 | 89.1 |

Both dense lanes found the same number of alerts for every query (50.8 on average). The first dense ask is slower in Postgres because the index is 319 MB and Postgres ran with its default 128 MB of `shared_buffers`, so a new region of the index is read from the page cache; the second ask of the same vector shows the lane warm. Qdrant holds its index in memory.

So Postgres is two to five times slower per lane and stays under a tenth of a second at the median. A search runs the dense and the sparse lane once each, and once more each when test-run alerts exist to be counted. Adding the medians above to the 16 ms of embedding gives about 105 to 140 ms for a free-text search in Postgres and about 45 ms with Qdrant, and about 190 to 260 ms against 75 ms with the counting pass. That is arithmetic on the lanes' medians: a whole search wasn't timed at this size.

What the numbers include and leave out: one run of 50 queries each; a dev build of ace4 and the laptop's Docker VM for both; synthetic vectors and words, not real alerts; a test database with nothing else running. Real chunks are longer than 100 words in places and a real vocabulary is larger, which lengthens the sparse lane on both sides.

## Size and writes

At 156,000 chunks:

| | Postgres | Qdrant |
|---|---|---|
| On disk | 964 MB: 578 MB of rows, a 319 MB HNSW index, a 56 MB GIN index | 580 MB |
| Memory while loaded and queried | the Postgres container at 251 MiB in all, with 128 MB of shared buffers | the Qdrant container at 846 MiB |
| Writing all of it | 308 s, 2.0 ms a chunk | 26 s, 0.17 ms a chunk |

Postgres writes slower because each insert maintains the HNSW index. An alert is a few to a few dozen chunks, so indexing one costs tens of milliseconds of database time. Embedding it costs more: a full 256-token chunk took 136 ms to embed, a short one 16 ms. At 80 alerts a day neither matters. Indexing everything again after a model change, which both designs need, is hours of embedding either way and five minutes of Postgres.

## What the model costs

The model is the same on both sides and stays whichever is chosen. `ace serve` loads it once: 85 to 140 ms, and 104 MB more resident memory (10.6 MB before, 114.6 MB loaded, 119.8 MB after embedding). The ace image grows by its file, a 91.4 MB layer: `docker image ls` shows `ace4-ace` at 561 MB before and 744 MB after, since this Docker's image store counts a layer both packed and unpacked, and the weights barely compress. Nothing is downloaded at run time, and nothing an alert holds leaves the process to be embedded.

## Operational cost

With Qdrant, as ace3 runs it:

- A second stateful service: its container, volume, TLS certificate, API key, backups and upgrades. ace3 starts it with no version pinned.
- A second copy of each alert's disposition, queue and tags, on every point, refreshed by a task whenever one changes. ace3 has three task kinds, a Redis list, a dead-letter list and a retry count for it, and a search can see an alert's old disposition until the task runs.
- A collection whose name carries the model and a schema version, created by whichever indexer worker starts first. `ace3/saq/search/index.py` has about 60 lines for the race between workers creating it, and `docs/SEARCH.md` documents the errors that race logs.
- Deleting an alert needs a task to delete its points.

In Postgres:

- No new service. One extension, pgvector 0.8.7, built into the stack's Postgres image from its release tarball, pinned by hash. The image grows from 425 MB to 432 MB. The extension isn't a trusted one, so a database whose owner isn't a superuser needs `CREATE EXTENSION vector` run once by one.
- No copy of the alert's fields. A lane joins the alert's own row, so a disposition, a move between queues or a tag is seen by the next search with no task. Deleting an alert deletes its chunks.
- The index is in the database's backups and its transactions. The indexer writes an alert's chunks, removes the stale ones and records the write in one transaction.
- The cost moves into Postgres: its disk grows by about 6 KB a chunk, the HNSW index is fastest when it stays in memory, and a search's work competes with everything else the database does. At 156,000 chunks that is about 1 GB of disk, 319 MB of it the HNSW index, against the 128 MB of shared buffers the stack's Postgres runs with by default.

## What differs from Qdrant in the Postgres index

- **The sparse lane bounds its work.** Postgres ranks a chunk by reading its row, so the lane's cost is the number of chunks it scores. A term in more than 5,000 chunks isn't used to find chunks unless the query has no rarer term: it only adds to the scores of the chunks the rarer terms found. A query of only common terms scores the chunks that hold all of them. At most 20,000 chunks are scored. Below those bounds the lane scores every chunk that shares a term, as Qdrant does, and the retrieval test runs there. Past them, a chunk whose only match is a very common word isn't found by this lane; the dense lane still ranks it by meaning. Qdrant scores every posting of every term.
- **The dense lane groups after it searches.** It reads the 600 nearest chunks in scope and groups them by alert, where Qdrant groups inside its search. An alert with many matching chunks could crowd out alerts below it. A document is at most 16 chunks, and the floor cuts the tail.
- **A term's rarity is counted when the query runs**, over the index as it is, where Qdrant keeps it. No statistics are stored.

## Recommendation

Drop Qdrant. On ace3's own retrieval test the Postgres index returns the same alerts at the same ranks with the same tiers. At production's size its lanes answer in tens of milliseconds, slower than Qdrant's and far below what an analyst notices beside the model's own time. It removes a service, a volume, a secret, a task queue for payload updates and a class of staleness, and it costs about 1 GB of Postgres disk and an extension in the image.

What would change the recommendation:

- A corpus one or two orders of magnitude larger. The sparse lane's bounds start to bite, and Postgres's memory for the HNSW index becomes a real cost. Qdrant, or Postgres with a ranking index such as RUM or a BM25 extension, would be the next look.
- A measured loss of ranking quality on real alerts. This comparison can't see one. After a move to production, the same labeled-query method over real alerts would.

If the owner accepts: nothing more is built, since `ace serve` already runs the Postgres index; `ace_search::qdrant`, `tools/search/qdrant.compose.yaml` and the Qdrant half of `tools/search/compare` can be removed, or kept as the way to repeat this comparison. If the owner declines, `QdrantIndex` is most of a production index already, and needs ace3's payload refresh wired to dispositions and queue moves.
