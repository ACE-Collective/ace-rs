-- SVS test runs, part 5a (PLAN.md 7.10 batch 5): registration, the launcher's calls, the timers, refused
-- registrations and maintenance windows. ace3's `svs_maintenance_windows`, `svs_registration_refusals`,
-- `svs_expectations` and `svs_ignores`, each without its `svs_` prefix, and what SVS reads of a hunt.
-- Part 5b brings the results, the comments and the decisions' writes; batch 6 the maintenance alerts and
-- the suppressed matches, with the judgment that writes them.

-- What SVS reads of a hunt file (`ace_core::svs::windows::RecordedHunt`): its uuid, name, whether it's
-- enabled, its worst-case latency and its suppression in seconds, whether it groups, its file's sha256 and
-- its tags. The hunter records it with the file each time it loads its hunts (`sync_hunts`), whether or
-- not the file loaded as a hunt, since only the hunter's configuration names the hunts' directories. A
-- run's windows read it. NULL for a file that isn't a hunt SVS tracks, or that a hunter from before this
-- column recorded.
ALTER TABLE hunts.hunts ADD COLUMN svs jsonb;

-- A maintenance window on a test host (ace3's `svs_maintenance_windows`): a launcher opens one before it
-- stages a test's prerequisites or updates its own bundle there, and ends it afterwards; the timers expire
-- one it never ends. A window and a run never hold one host at once. The window keeps the host's names, so
-- it still says which host it was on once the host is removed.
CREATE TABLE svs.maintenance_windows (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uuid uuid NOT NULL UNIQUE,
    test_host_id bigint REFERENCES svs.test_hosts ON DELETE SET NULL,
    host text NOT NULL,
    fqdn text,
    reason text NOT NULL CHECK (length(reason) >= 1),
    opened_by service.actor NOT NULL,
    opened_at timestamptz NOT NULL,
    -- When it ends unless it's ended sooner.
    ends_at timestamptz NOT NULL,
    -- When it ended: at a call that ended it, or at ends_at when the timers expired it.
    ended_at timestamptz,
    ended_by service.actor,
    end_reason text CHECK (end_reason IN ('ended', 'expired')),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT maintenance_windows_end_after_they_open CHECK (ends_at > opened_at),
    CONSTRAINT maintenance_windows_say_how_they_ended
        CHECK ((ended_at IS NULL) = (ended_by IS NULL) AND (ended_at IS NULL) = (end_reason IS NULL))
);

CREATE INDEX maintenance_windows_by_host ON svs.maintenance_windows (host, id);
CREATE INDEX maintenance_windows_open ON svs.maintenance_windows (ends_at) WHERE ended_at IS NULL;

CREATE TRIGGER maintenance_windows_touch BEFORE UPDATE ON svs.maintenance_windows
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- A refused registration or maintenance window (ace3's `svs_registration_refusals`): one row per caller,
-- host and hour, so a launcher retrying in a loop makes one alert an hour, not one a call. The request that
-- inserts the row makes the alert, in the same transaction. Rows go after a day.
CREATE TABLE svs.registration_refusals (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The caller's identity (`user:<id>`, `api_key:<id>`), which a rename doesn't change.
    caller text NOT NULL CHECK (length(caller) BETWEEN 1 AND 256),
    -- The refused host as the caller named it, normalized: its fully qualified name when it has one.
    host text NOT NULL CHECK (length(host) <= 255),
    hour timestamptz NOT NULL,
    count integer NOT NULL DEFAULT 1,
    first_at timestamptz NOT NULL,
    last_at timestamptz NOT NULL,
    -- The alert the first refusal made.
    root_id uuid REFERENCES analysis.roots (id) ON DELETE SET NULL,
    CONSTRAINT registration_refusals_collapse UNIQUE (caller, host, hour)
);

CREATE INDEX registration_refusals_by_hour ON svs.registration_refusals (hour);

-- A decision about a signature for a test on one platform (ace3's `svs_expectations`): a run there should
-- fire it (`expected`), or it fires there but isn't what the test is about (`rejected`). A run's
-- observation window is the latency of its test's expected signatures. Part 5b's decisions write it.
CREATE TABLE svs.expectations (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    test_guid uuid NOT NULL,
    platform text NOT NULL CHECK (length(platform) BETWEEN 1 AND 32),
    -- As a detection has it (`analysis.detections.signature_uuid`).
    signature_uuid text NOT NULL CHECK (length(signature_uuid) BETWEEN 1 AND 64),
    state text NOT NULL CHECK (state IN ('expected', 'rejected')),
    -- The signature's family and name as the run result it was decided from had them.
    signature_family text,
    signature_name text,
    reason text,
    decided_from_run_id bigint REFERENCES svs.runs ON DELETE SET NULL,
    decided_by service.actor NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT expectations_are_unique UNIQUE (test_guid, platform, signature_uuid)
);

CREATE INDEX expectations_by_update ON svs.expectations (updated_at, id);

CREATE TRIGGER expectations_touch BEFORE UPDATE ON svs.expectations
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- A signature that is launcher noise (ace3's `svs_ignores`): for one test on every platform, or for every
-- test (`test_guid` NULL). An ignored signature is never expected, a candidate or missing. Part 5b's
-- decisions write it.
CREATE TABLE svs.ignores (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- NULL for every test's runs.
    test_guid uuid,
    signature_uuid text NOT NULL CHECK (length(signature_uuid) BETWEEN 1 AND 64),
    signature_family text,
    signature_name text,
    reason text,
    created_by service.actor NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ignores_of_a_test ON svs.ignores (test_guid, signature_uuid) WHERE test_guid IS NOT NULL;
CREATE UNIQUE INDEX ignores_of_every_test ON svs.ignores (signature_uuid) WHERE test_guid IS NULL;
CREATE INDEX ignores_by_update ON svs.ignores (updated_at, id);

CREATE TRIGGER ignores_touch BEFORE UPDATE ON svs.ignores
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- ace3's `service_svs` moves runs on by time every `svs.runs.timer_interval_seconds` (PLAN.md 6.7), as the
-- scheduler's `svs_run_timers` does.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('scheduler:svs_run_timers', 'svs', 'run_timers', 'allow',
        '{"kind": "internal", "id": "migration"}');
