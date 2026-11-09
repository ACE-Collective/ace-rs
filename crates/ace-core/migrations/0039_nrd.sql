-- The newly registered domains list (PLAN.md 7.4): ace3's `data/external/nrd/nrd_index.db`, the
-- SQLite file its `nrd-refresh` cron job builds on each node from the configured feeds and its
-- `nrd_analyzer` reads. Here one list serves every node: `ace serve`'s `nrd_refresh` task rebuilds
-- it in one transaction, and the module reads it through the core's `newly-registered` read.

CREATE SCHEMA nrd;

-- ace3's `nrd` table: each domain, normalized as its refresh normalizes a feed's line.
CREATE TABLE nrd.domains (
    domain text PRIMARY KEY
);

-- ace3's `meta` table, as one row: the hash of the configured primary URLs, when the list was
-- last rebuilt, how many domains it has, and what each feed's fetch recorded (its URL, the URL it
-- came from, ETag, Last-Modified, Content-Length and distinct domains). No row is ace3's missing
-- database.
CREATE TABLE nrd.state (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    config_hash text NOT NULL,
    last_refreshed_at timestamptz NOT NULL,
    row_count bigint NOT NULL,
    sources jsonb NOT NULL
);

-- The task acts as a component of its own (PLAN.md 5.2, 6.7), holding only this. ace3's cron job
-- runs as the node's user, under no permission.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('scheduler:nrd_refresh', 'nrd', 'refresh', 'allow', '{"kind": "internal", "id": "migration"}');
