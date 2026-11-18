-- The analysis cache (PLAN.md decision 26, docs/decisions/0004): ace3's analysis result cache, a
-- cacheable module's result kept across roots and written in a later root in place of its task
-- (`ace_core::cache`). ace3 keeps it in a database of its own, `analysis-result-cache`, so its
-- growth and its partitions never touch the main one; here it is a schema of its own, `cache`, in the
-- one database, since a hit writes its result in the transaction that would have queued the task.
CREATE SCHEMA cache;

CREATE SEQUENCE cache.results_id_seq;

-- One kept result. A key is kept as often as its module ran and kept it: the newest row that hasn't
-- expired is the one a lookup takes, as ace3's `ORDER BY created_at DESC`. Rows are never updated or
-- deleted: a day's rows go with its partition, as ace3's (`analysis_cache_partitions`).
CREATE TABLE cache.results (
    id bigint NOT NULL DEFAULT nextval('cache.results_id_seq'),
    -- `ace_sdk::cache::key`: a sha256 over the observable's type and value, the module's name,
    -- instance, version and analysis type, its settings and its extended version.
    key bytea NOT NULL CHECK (length(key) = 32),
    -- The component's key: the module's name, or its instance's.
    module text NOT NULL,
    observable_type text NOT NULL,
    observable_value text NOT NULL,
    -- The result as the task ended it (`ResultEnvelope`). Postgres compresses a large one itself;
    -- none is kept past 1 MiB compressed (`ace_sdk::cache::MAX_COMPRESSED_BYTES`).
    envelope jsonb NOT NULL,
    -- For each of the envelope's files, in order, its place among the paths its module names the
    -- files it adds at for the path it analyzed (`ace_sdk::cache::CachePaths::Named`), so a hit puts
    -- it at the same place for the new root's path.
    file_paths integer[] NOT NULL DEFAULT '{}',
    -- The sha256 of each of the envelope's files, each held in the bucket by this row until it
    -- expires (a hold `cache`, `<id>`).
    files text[] NOT NULL DEFAULT '{}',
    -- When the task that made it ended: what a hit's result says it is from (`cached_at`).
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (key, created_at, id)
) PARTITION BY RANGE (created_at);

ALTER SEQUENCE cache.results_id_seq OWNED BY cache.results.id;

-- Where rows land when no day's partition is made for them. Maintenance makes each day's before rows
-- reach it, and never makes a day the catchall holds rows of (ace3's rule: a catchall stays empty).
CREATE TABLE cache.results_p_catchall PARTITION OF cache.results DEFAULT;

-- Each cacheable component's versions in the pool that last ran it (`ace_pool::cache`): its tools',
-- files' and libraries', which its key holds. A lookup makes its key with these; a task's end keeps
-- its result under the versions its own pool sent.
CREATE TABLE cache.probes (
    module text PRIMARY KEY,
    probes jsonb NOT NULL,
    reported_at timestamptz NOT NULL DEFAULT now()
);

-- What each lookup and keep did, by root, pass and component, for the module events of the pass's
-- metrics (`ace_core::metrics`): ace3's per-(root, module) cache counts, which its engine holds in
-- memory until the work item ends. A row goes with its root.
CREATE TABLE cache.activity (
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    pass integer NOT NULL,
    module text NOT NULL,
    hits integer NOT NULL DEFAULT 0,
    misses integer NOT NULL DEFAULT 0,
    writes integer NOT NULL DEFAULT 0,
    -- the kept results' sizes, compressed
    write_bytes bigint NOT NULL DEFAULT 0,
    -- how long the lookups took, hits and misses, and the longest
    lookup_seconds double precision NOT NULL DEFAULT 0,
    lookup_max_seconds double precision NOT NULL DEFAULT 0,
    PRIMARY KEY (root_id, pass, module)
);

-- A result written from the cache: when the task that made the kept result ended, ace3's `cached_at`
-- (its `from_cache_hit` is this not being null). NULL for a result a task made in this root.
ALTER TABLE analysis.results ADD COLUMN cached_at timestamptz;

-- The scheduler's task acts as a component of its own (PLAN.md 5.2, 6.7), holding only this, as
-- `email_archive_partitions` does.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('scheduler:analysis_cache_partitions', 'analysis_cache', 'maintain', 'allow',
        '{"kind": "internal", "id": "migration"}');
