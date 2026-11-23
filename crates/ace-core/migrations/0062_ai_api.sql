-- The AI investigation API (PLAN.md 7.15): ace3's `aceapi_ai`, the read-only routes an AI agent's key
-- reaches (`ace_service::ai`). ace3 keeps its rate limiter's state in Redis; ace-rs has no Redis, so it is
-- here, where every node reads the same counts.
CREATE SCHEMA ai;

-- The queries running now, by bucket: a backend's name, or `search` or `export`. ace3's sorted set of
-- tokens. A slot is one row, removed when its query ends; one left by a process that died is reaped
-- by the next request for its bucket once it is older than the bucket's longest query.
CREATE TABLE ai.inflight (
    token uuid PRIMARY KEY,
    bucket text NOT NULL,
    started_at timestamptz NOT NULL
);

CREATE INDEX inflight_by_bucket ON ai.inflight (bucket);

-- How many requests each bucket took in a minute and in an hour: ace3's fixed windows. `window_start`
-- is the minute or the hour since the epoch. A request removes its bucket's windows older than two.
CREATE TABLE ai.windows (
    bucket text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('minute', 'hour')),
    window_start bigint NOT NULL,
    count integer NOT NULL CHECK (count > 0),
    PRIMARY KEY (bucket, kind, window_start)
);

-- The API reads ACE's own data as the component `ai_api` (PLAN.md 5.2), once the caller's key has been
-- found to hold the `ai:` permission of the route. So an AI key never holds `alert:read` or
-- `event:read` itself, and passes nothing on the main API, as in ace3.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES
    ('ai_api', 'alert', 'read', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('ai_api', 'event', 'read', 'allow', '{"kind": "internal", "id": "migration"}');
