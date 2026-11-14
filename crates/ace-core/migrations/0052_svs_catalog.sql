-- SVS's Atomic Red Team catalog (PLAN.md 7.10 batch 4): the repositories `svs.catalog_tests` is read from,
-- and a test's settings. Each table is ace3's of the same name without its `svs_` prefix.

-- A catalog repository and the commit its tests were last read from (ace3's `svs_catalog_repositories`).
-- Its row is locked while a refresh writes, so two replicas never interleave. Only
-- `ace_core::svs::catalog` writes it.
CREATE TABLE svs.catalog_repositories (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Its name in the overlay's `svs.catalog.repositories`.
    name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 256),
    -- The commit the catalog holds, NULL until the first refresh succeeds.
    commit text CHECK (commit ~ '^[0-9a-f]{7,64}$'),
    refreshed_at timestamptz,
    test_count integer NOT NULL DEFAULT 0 CHECK (test_count >= 0),
    -- The tests and files the last refresh could not read.
    skipped_count integer NOT NULL DEFAULT 0 CHECK (skipped_count >= 0),
    -- Why the last refresh failed, NULL when it succeeded; a repository taken out of the overlay says so
    -- here.
    error text CHECK (length(error) <= 4096),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX catalog_repositories_by_update ON svs.catalog_repositories (updated_at, id);

CREATE TRIGGER catalog_repositories_touch BEFORE UPDATE ON svs.catalog_repositories
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- A test's settings (ace3's `svs_test_settings`): an observation window that replaces the computed one,
-- and whether a run holds its hosts for its whole attribution window, for every run registered afterwards.
-- Not a foreign key: settings outlive a test's row, as a run does. Batch 5's decisions write it.
CREATE TABLE svs.test_settings (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    test_guid uuid NOT NULL UNIQUE,
    -- NULL for the computed window.
    observation_minutes integer CHECK (observation_minutes >= 1),
    -- The test leaves something behind on its hosts, so a run of it holds them for its whole attribution
    -- window.
    holds_host boolean NOT NULL DEFAULT false,
    set_by service.actor,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX test_settings_by_update ON svs.test_settings (updated_at, id);

CREATE TRIGGER test_settings_touch BEFORE UPDATE ON svs.test_settings
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- ace3's `service_svs` refreshes the catalog every `svs.catalog.refresh_interval_seconds` (PLAN.md 6.7), as
-- the scheduler's `svs_catalog_refresh` does: it reads each catalog repository whose commit changed.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('scheduler:svs_catalog_refresh', 'svs', 'catalog_refresh', 'allow',
        '{"kind": "internal", "id": "migration"}');
