-- Search (PLAN.md 7.11): ace3's `saq/search/`, whose index is a Qdrant collection. Here an alert's text is
-- kept in Postgres: each chunk with its embedding (pgvector) and its terms (full-text search).
--
-- What differs from ace3's:
-- - There is no payload. ace3 copies an alert's disposition, queue, tags and date onto every point so
--   Qdrant can filter on them, and refreshes the copies when they change. A chunk here joins its root, so
--   a filter reads the alert's own row and nothing is stale.
-- - A chunk goes with its alert: deleting the root deletes them.
-- - The tasks are rows here, not a Redis list: `search.due`, as `queue.routing_due`.

-- pgvector, which the stack's Postgres image carries (docker/postgres/Dockerfile). It isn't a trusted
-- extension, so a database whose owner isn't a superuser needs it created first; this then does nothing.
CREATE EXTENSION IF NOT EXISTS vector;

CREATE SCHEMA search;

-- One chunk of one document of an alert: ace3's point. `kind` and `key` name the document within its
-- alert (ace3's `SearchDocument`) and `chunk` its place in it, so indexing an alert again writes the same
-- rows.
CREATE TABLE search.chunks (
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('alert', 'comment', 'detection', 'analysis', 'context')),
    key text NOT NULL CHECK (length(key) BETWEEN 1 AND 256),
    chunk integer NOT NULL CHECK (chunk >= 0),
    -- What the document is, for display: an email's subject, or a label such as "command line".
    title text,
    -- The chunk as it was embedded: a slice of the document, with its title first when the title says
    -- something.
    text text NOT NULL,
    -- The result and the observable the document came from; ace3's `analysis_uuid` and `observable_uuid`.
    result_id bigint,
    observable_id bigint,
    -- all-MiniLM-L6-v2's embedding of `text`, at unit length.
    embedding vector(384) NOT NULL,
    -- The text's terms (`ace_search::sparse`): each term's id as a lexeme, each occurrence a position.
    terms tsvector NOT NULL,
    indexed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (root_id, kind, key, chunk)
);

-- Nearest chunks by cosine distance, and the chunks that hold a term.
CREATE INDEX chunks_by_embedding ON search.chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX chunks_by_terms ON search.chunks USING gin (terms);

-- An alert whose index is out of date: ace3's `index` task. `queue::check_completion` adds or renews it
-- in the transaction that completes a pass, so none is missed while `ace serve` is down, and the indexer
-- removes it when it has written the alert's chunks. `version` grows with each request, so an indexing
-- that read the alert before a later pass completed leaves the row for the next one.
CREATE TABLE search.due (
    root_id uuid PRIMARY KEY REFERENCES analysis.roots (id) ON DELETE CASCADE,
    due_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1,
    -- How many times indexing it has failed: ace3's `attempt`. At three it's left alone, ace3's dead
    -- letter, until something asks for the alert again.
    attempts integer NOT NULL DEFAULT 0,
    -- An indexer has it until then; another may take it after.
    claimed_until timestamptz,
    failed_at timestamptz,
    error text CHECK (length(error) <= 1024)
);

CREATE INDEX due_in_order ON search.due (due_at, root_id) WHERE attempts < 3;

-- What the indexer last wrote for an alert: ace3's `search_index_task_complete` line, kept.
CREATE TABLE search.indexed (
    root_id uuid PRIMARY KEY REFERENCES analysis.roots (id) ON DELETE CASCADE,
    documents integer NOT NULL,
    chunks integer NOT NULL,
    -- Documents or chunks past the bounds, left out.
    left_out integer NOT NULL DEFAULT 0,
    model text NOT NULL,
    indexed_at timestamptz NOT NULL DEFAULT now()
);

-- Whether an alert is one a search's filters keep, for the filters every lane can apply before it
-- ranks: the queue, the disposition (OPEN for none), the alert date's windows, and alerts left out by
-- name. ace3 gives Qdrant the same as a payload filter. A NULL is a filter that isn't set. The rest of
-- a filter list is applied to what the lanes found, by the alert list's own query. The windows are a
-- multirange and nothing here is a subquery, so the planner inlines the call into the lane's query.
CREATE FUNCTION search.in_scope(
    id uuid, queue text, disposition text, alerted_at timestamptz,
    queues text[], not_queues text[], dispositions text[], not_dispositions text[],
    windows tstzmultirange, not_windows tstzmultirange, except_ids uuid[]
) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    RETURN (queues IS NULL OR queue = ANY (queues))
       AND (not_queues IS NULL OR NOT queue = ANY (not_queues))
       AND (dispositions IS NULL OR COALESCE(disposition, 'OPEN') = ANY (dispositions))
       AND (not_dispositions IS NULL OR NOT COALESCE(disposition, 'OPEN') = ANY (not_dispositions))
       AND (windows IS NULL OR alerted_at <@ windows)
       AND (not_windows IS NULL OR NOT alerted_at <@ not_windows)
       AND (except_ids IS NULL OR NOT id = ANY (except_ids));

-- Every alert there already is gets indexed once.
INSERT INTO search.due (root_id)
SELECT id FROM analysis.roots WHERE alerted_at IS NOT NULL;

-- The indexer acts as the component `search_indexer`, which holds `search:index` and nothing else.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('search_indexer', 'search', 'index', 'allow', '{"kind": "internal", "id": "migration"}');
