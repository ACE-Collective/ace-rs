-- Query hunts (PLAN.md 6.4).
--
-- What a submitter inside ACE said about a root that roots have no column for yet, as it said it: the
-- hunter's alert type, tool, tool instance, queue, instructions, details (the query, its link, the rows
-- and the hunt's metadata), tags, pivot links, summary details and extensions, in ace3's names. A
-- later step that gives one of them a column moves it out.
ALTER TABLE analysis.roots ADD COLUMN origin jsonb;

CREATE SCHEMA hunts;

-- The hunts the hunter loaded from the signatures checkout, as it last loaded them: each hunt file of
-- a type, with what it loaded as or why it didn't load. The hunter replaces a type's rows each time it
-- loads them, and the `hunt` router lists them.
CREATE TABLE hunts.hunts (
    type text NOT NULL,
    -- The file, relative to the signatures checkout.
    path text NOT NULL,
    name text,
    uuid text,
    enabled boolean,
    frequency text,
    -- Why it didn't load, in ace3's words; NULL for a hunt that loaded.
    error text,
    loaded_at timestamptz NOT NULL,
    PRIMARY KEY (type, path),
    CONSTRAINT loaded_or_failed CHECK ((error IS NULL) = (name IS NOT NULL))
);

-- What ace3 pickles under its data directory for each hunt, by its type and name as ace3 keys it, so a
-- renamed hunt starts again. A run's submissions and its row commit together (`Service::record_hunt_run`),
-- so a run that dies before its commit leaves the window to the next run, and one that commits isn't
-- run again: no window is skipped or searched twice.
CREATE TABLE hunts.state (
    type text NOT NULL,
    name text NOT NULL,
    last_executed_time timestamptz,
    last_end_time timestamptz,
    last_alert_time timestamptz,
    -- A grouped hunt's suppression: when each group last alerted, by its key.
    last_alert_times jsonb NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (type, name)
);

-- The hunter acts as the component `hunter` (PLAN.md 5.2): it submits roots, reads its hunts' state,
-- and records the hunts it loaded.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES
    ('hunter', 'alert', 'create', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('hunter', 'hunt', 'read', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('hunter', 'hunt', 'write', 'allow', '{"kind": "internal", "id": "migration"}');
