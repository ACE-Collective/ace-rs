-- Suppression records (PLAN.md 6.5, ace3 #840).
--
-- ace3's hunter drops a hit two ways. A grouped hunt with a `suppression` drops a group that alerted
-- less than `suppression` ago (`QueryHunt.process_query_results`), and the collector drops a submission
-- whose dedup key it has seen (`DuplicateSubmissionFilter`). Each leaves only a log line, so nothing can
-- say later which hits were dropped or why. Here each drop is a row, written in the run's own
-- transaction (`Service::record_hunt_run`), so a run is never recorded without its suppressions or the
-- reverse.

-- One row per dropped hit: the hunt, the hit, the window it fell into, why, when, and the root of the
-- earlier hit that opened the window. No foreign key: a row outlives the root it points to, as an audit
-- row does. Rows older than 30 days go in each run's transaction.
CREATE TABLE hunts.suppressions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type text NOT NULL,
    name text NOT NULL,
    uuid text NOT NULL,
    -- `group`: its group alerted within the hunt's suppression. `duplicate`: its dedup key was seen.
    reason text NOT NULL CHECK (reason IN ('group', 'duplicate')),
    -- The group's suppression key, or the dedup key.
    key text NOT NULL,
    -- The `group_by` value, for a grouped hunt.
    group_value jsonb,
    description text NOT NULL,
    event_time timestamptz NOT NULL,
    -- How many of the search's rows the dropped submission held.
    events integer NOT NULL CHECK (events >= 0),
    -- The window the hit fell into: from the earlier hit, for the suppression or the dedup key's life.
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    -- The earlier hit's root, when ace-rs made it.
    cause_root uuid,
    -- The window the run searched.
    search_start timestamptz,
    search_end timestamptz,
    decided_at timestamptz NOT NULL
);

CREATE INDEX suppressions_by_hunt ON hunts.suppressions (uuid, id);
CREATE INDEX suppressions_by_age ON hunts.suppressions (decided_at);

-- ace3's DuplicateSubmissionFilter, for the hunter: each dedup key a run submitted, while it lives. ace3
-- keeps the key's sha256 in its `persistence` table and deletes it once it's 4 hours unmodified or 24
-- hours old; a key is never modified after it's made, so it lives 4 hours. The root is the hit that
-- made the key, which a duplicate's row points to.
CREATE TABLE hunts.dedup_keys (
    hash bytea PRIMARY KEY CHECK (length(hash) = 32),
    root uuid NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX dedup_keys_by_age ON hunts.dedup_keys (created_at);

-- The root each group of a grouped hunt last alerted with, by its suppression key, beside
-- `hunts.state.last_alert_times`, which keeps only the time: what a group's suppression points to. Kept
-- to the keys the state keeps, so it's bounded as ace3's dict is. A key is a group's value, of any
-- length, so it's found by its sha256.
CREATE TABLE hunts.alert_keys (
    type text NOT NULL,
    name text NOT NULL,
    hash bytea NOT NULL CHECK (length(hash) = 32),
    key text NOT NULL,
    root uuid NOT NULL,
    PRIMARY KEY (type, name, hash)
);
