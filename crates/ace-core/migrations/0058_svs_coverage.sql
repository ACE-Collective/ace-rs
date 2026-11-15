-- SVS coverage and the declared-vs-measured worklist (PLAN.md 7.10 batch 8): ace3's `svs_coverage`,
-- `svs_coverage_state`, `svs_coverage_snapshots` and `svs_technique_worklist`, each without its `svs_`
-- prefix. Only `ace_service`'s `svs_coverage` and `svs_worklist` write them.

-- Coverage of one ATT&CK technique on one platform, as of the last refresh (ace3's `svs_coverage`). A
-- refresh writes only the rows that changed, so `updated_at` moves only on a real change. A row the
-- computation no longer produces is retired, never deleted. The release bounds the table: a row for each
-- technique on each of its platforms, and for each platform a test brings.
CREATE TABLE svs.coverage (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    technique text NOT NULL CHECK (length(technique) BETWEEN 1 AND 32),
    -- A platform slug (`ace_core::svs::attack`).
    platform text NOT NULL CHECK (length(platform) BETWEEN 1 AND 32),
    parent text,
    is_subtechnique boolean NOT NULL DEFAULT false,
    technique_name text,
    -- The technique's tactic ids (TA0002) in the ATT&CK release, in the matrix's order.
    tactics text[] NOT NULL DEFAULT '{}',
    catalog_status text NOT NULL CHECK (catalog_status IN ('active', 'deprecated', 'unknown')),
    -- The release lists the platform for the technique; otherwise only a test brought the row.
    attack_platform boolean NOT NULL DEFAULT false,
    -- `ace_core::svs::coverage::CoverageState`: over the technique and its sub-techniques on the platform,
    -- and the technique's own.
    state text NOT NULL
        CHECK (state IN ('failing', 'stale', 'validated', 'manual', 'untested', 'none')),
    own_state text NOT NULL
        CHECK (own_state IN ('failing', 'stale', 'validated', 'manual', 'untested', 'none')),
    -- Over the same tests and signatures as `state`.
    tests_total integer NOT NULL DEFAULT 0 CHECK (tests_total >= 0),
    tests_validated integer NOT NULL DEFAULT 0 CHECK (tests_validated >= 0),
    tests_failing integer NOT NULL DEFAULT 0 CHECK (tests_failing >= 0),
    tests_stale integer NOT NULL DEFAULT 0 CHECK (tests_stale >= 0),
    manual_signatures integer NOT NULL DEFAULT 0 CHECK (manual_signatures >= 0),
    measured_signatures integer NOT NULL DEFAULT 0 CHECK (measured_signatures >= 0),
    -- The latest review of a run that counts toward the row.
    last_reviewed_at timestamptz,
    state_changed_at timestamptz NOT NULL,
    first_seen_at timestamptz NOT NULL,
    -- When the computation stopped producing the row, NULL while it does.
    retired_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT coverage_is_unique UNIQUE (technique, platform)
);

CREATE INDEX coverage_by_parent ON svs.coverage (parent) WHERE parent IS NOT NULL;
CREATE INDEX coverage_by_update ON svs.coverage (updated_at, id);
-- the list's order, whatever the database's collation
CREATE INDEX coverage_in_order ON svs.coverage (technique COLLATE "C", platform COLLATE "C", id);

CREATE TRIGGER coverage_touch BEFORE UPDATE ON svs.coverage
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- The coverage refresh (ace3's `svs_coverage_state`): one row, which a refresh, a snapshot and a worklist
-- resolution lock FOR UPDATE for their whole transaction, so none of them computes from what another is
-- about to change, and what the last refresh did.
CREATE TABLE svs.coverage_state (
    id smallint PRIMARY KEY CHECK (id = 1),
    attack_release text,
    -- The last refresh that completed.
    refreshed_at timestamptz,
    duration_ms integer,
    rows integer NOT NULL DEFAULT 0,
    changed integer NOT NULL DEFAULT 0,
    retired integer NOT NULL DEFAULT 0,
    -- mitre: tags naming an id the release doesn't have, and mitre: tags that aren't technique ids
    -- (templated, tactics), over every signature.
    unknown_tags integer NOT NULL DEFAULT 0,
    ignored_tags integer NOT NULL DEFAULT 0,
    -- Why the latest refresh failed, NULL once one completes.
    error text CHECK (length(error) <= 4096),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER coverage_state_touch BEFORE UPDATE ON svs.coverage_state
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- `svs.coverage` as it was on one UTC day (ace3's `svs_coverage_snapshots`): a copy of each row that
-- wasn't retired, written daily by the scheduler's `svs_coverage_snapshot`. A second snapshot on the same
-- day replaces the day. Nothing removes a day: it grows by the live rows of `svs.coverage` each day, as
-- ace3's does.
CREATE TABLE svs.coverage_snapshots (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    snapshot_date date NOT NULL,
    technique text NOT NULL,
    platform text NOT NULL,
    attack_release text NOT NULL,
    parent text,
    is_subtechnique boolean NOT NULL DEFAULT false,
    state text NOT NULL
        CHECK (state IN ('failing', 'stale', 'validated', 'manual', 'untested', 'none')),
    own_state text NOT NULL
        CHECK (own_state IN ('failing', 'stale', 'validated', 'manual', 'untested', 'none')),
    tests_total integer NOT NULL DEFAULT 0,
    tests_validated integer NOT NULL DEFAULT 0,
    tests_failing integer NOT NULL DEFAULT 0,
    tests_stale integer NOT NULL DEFAULT 0,
    manual_signatures integer NOT NULL DEFAULT 0,
    measured_signatures integer NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT coverage_snapshots_are_unique UNIQUE (snapshot_date, technique, platform)
);

CREATE INDEX coverage_snapshots_by_update ON svs.coverage_snapshots (updated_at, id);
CREATE INDEX coverage_snapshots_in_order
    ON svs.coverage_snapshots (snapshot_date, technique COLLATE "C", platform COLLATE "C", id);

CREATE TRIGGER coverage_snapshots_touch BEFORE UPDATE ON svs.coverage_snapshots
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- The declared-vs-measured worklist (ace3's `svs_technique_worklist`): one row per (signature, ATT&CK
-- technique) for each signature that is measured, i.e. expected of a catalog test. Everything but the
-- resolution is derived on each coverage refresh, the status included. A row is never deleted; one the
-- computation no longer produces is retired and keeps its resolution.
CREATE TABLE svs.technique_worklist (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- As a detection has it (`analysis.detections.signature_uuid`).
    signature_uuid text NOT NULL CHECK (length(signature_uuid) BETWEEN 1 AND 64),
    -- The technique as the pinned ATT&CK release has it (a revoked tag id is its successor).
    technique text NOT NULL CHECK (length(technique) BETWEEN 1 AND 32),
    kind text NOT NULL CHECK (kind IN ('declared', 'undeclared', 'unknown')),
    status text NOT NULL CHECK (status IN
        ('confirmed', 'open', 'kept', 'remove_pending', 'removed', 'undeclared', 'unknown', 'retired')),
    -- The tag ids, as the signature writes them (upper-cased), that count as the technique; sorted.
    declared_as text[] NOT NULL DEFAULT '{}',
    -- The signature has the tag now.
    tag_present boolean NOT NULL DEFAULT false,
    -- The signature is enabled, and isn't a YARA rule in QA mode.
    signature_counts boolean NOT NULL DEFAULT false,
    -- The tag counts toward coverage as a manual mapping.
    counts boolean NOT NULL DEFAULT false,
    -- The signature is expected of a catalog test.
    measured boolean NOT NULL DEFAULT false,
    -- The techniques the signature is measured on; sorted.
    measured_techniques text[] NOT NULL DEFAULT '{}',
    signature_family text,
    signature_name text,
    -- A person's decision, kept whatever the status.
    resolution text CHECK (resolution IN ('keep', 'remove')),
    reason text CHECK (length(reason) <= 4096),
    -- A link, such as the signature repository's pull request removing the tag.
    reference text CHECK (length(reference) <= 1024),
    resolved_by service.actor,
    resolved_at timestamptz,
    first_seen_at timestamptz NOT NULL,
    status_changed_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT technique_worklist_is_unique UNIQUE (signature_uuid, technique),
    CONSTRAINT technique_worklist_resolutions_are_whole
        CHECK ((resolution IS NULL) = (resolved_at IS NULL) AND (resolution IS NOT NULL OR reason IS NULL)
               AND (resolution IS NOT NULL OR reference IS NULL)
               AND (resolution IS NOT NULL OR resolved_by IS NULL))
);

CREATE INDEX technique_worklist_by_technique ON svs.technique_worklist (technique);
CREATE INDEX technique_worklist_by_update ON svs.technique_worklist (updated_at, id);
CREATE INDEX technique_worklist_in_order
    ON svs.technique_worklist (signature_uuid COLLATE "C", technique COLLATE "C", id);

CREATE TRIGGER technique_worklist_touch BEFORE UPDATE ON svs.technique_worklist
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- A test's latest reviewed run on each platform is what its state there is judged by: this index gives it
-- without a sort, one entry per reviewed run.
CREATE INDEX runs_reviewed_latest ON svs.runs (test_guid, platform, reviewed_at DESC NULLS LAST, id DESC)
    WHERE state = 'reviewed';
-- A test's latest runs, for its run history.
CREATE INDEX runs_by_test_created ON svs.runs (test_guid, created_at DESC, id DESC);
-- What is expected of a test.
CREATE INDEX expectations_by_signature ON svs.expectations (signature_uuid);

-- A technique filter's value finds the technique and, when it names no sub-technique, its sub-techniques
-- too: T1059 finds T1059.001 (ace3's `technique_condition`).
CREATE FUNCTION svs.technique_in(technique text, j jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT EXISTS (
        SELECT FROM jsonb_array_elements_text(j) v
        WHERE technique = v OR (strpos(v, '.') = 0 AND starts_with(technique, v || '.'))
    )
$$;

-- Whether a day is one any of the windows `j` holds touches, each a [first day, last day] pair.
CREATE FUNCTION svs.on_days(day date, j jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT EXISTS (
        SELECT FROM jsonb_array_elements(j) w
        WHERE day BETWEEN (w ->> 0)::date AND (w ->> 1)::date
    )
$$;

-- The coverage screen's filters (ace3's `saq/svs/coverage_filters.py`), as one condition on a row, so the
-- list, the count and the summary apply the same ones. `f` is what `ace_service`'s `svs_coverage` resolved
-- a filter list to, as `svs.run_matches` takes one: each filter's values under its slug and its inverse's
-- under `not_<slug>`, a text filter's as ILIKE patterns, a date filter's as [start, end] windows, and a flag
-- as true or false. The values of one filter are ORed and the filters ANDed; an inverse matches exactly the
-- rows its filter doesn't, a NULL value included. `nothing` matches no row.
CREATE FUNCTION svs.coverage_matches(c svs.coverage, f jsonb) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT NOT COALESCE((f ->> 'nothing')::boolean, false)
       AND (f -> 'technique' IS NULL OR svs.technique_in(c.technique, f -> 'technique'))
       AND (f -> 'not_technique' IS NULL OR NOT svs.technique_in(c.technique, f -> 'not_technique'))
       AND (f -> 'name' IS NULL OR COALESCE(c.technique_name ILIKE ANY (svs.texts(f -> 'name')), false))
       AND (f -> 'not_name' IS NULL
            OR NOT COALESCE(c.technique_name ILIKE ANY (svs.texts(f -> 'not_name')), false))
       AND (f -> 'tactic' IS NULL OR c.tactics && svs.texts(f -> 'tactic'))
       AND (f -> 'not_tactic' IS NULL OR NOT c.tactics && svs.texts(f -> 'not_tactic'))
       AND (f -> 'platform' IS NULL OR c.platform = ANY (svs.texts(f -> 'platform')))
       AND (f -> 'not_platform' IS NULL OR NOT c.platform = ANY (svs.texts(f -> 'not_platform')))
       AND (f -> 'state' IS NULL OR c.state = ANY (svs.texts(f -> 'state')))
       AND (f -> 'not_state' IS NULL OR NOT c.state = ANY (svs.texts(f -> 'not_state')))
       AND (f -> 'own_state' IS NULL OR c.own_state = ANY (svs.texts(f -> 'own_state')))
       AND (f -> 'not_own_state' IS NULL OR NOT c.own_state = ANY (svs.texts(f -> 'not_own_state')))
       AND (f -> 'level' IS NULL
            OR (CASE WHEN c.is_subtechnique THEN 'sub-technique' ELSE 'technique' END)
               = ANY (svs.texts(f -> 'level')))
       AND (f -> 'not_level' IS NULL
            OR NOT (CASE WHEN c.is_subtechnique THEN 'sub-technique' ELSE 'technique' END)
                   = ANY (svs.texts(f -> 'not_level')))
       AND (f -> 'catalog_status' IS NULL OR c.catalog_status = ANY (svs.texts(f -> 'catalog_status')))
       AND (f -> 'not_catalog_status' IS NULL
            OR NOT c.catalog_status = ANY (svs.texts(f -> 'not_catalog_status')))
       AND (f -> 'attack_platform' IS NULL OR c.attack_platform = (f ->> 'attack_platform')::boolean)
       AND (f -> 'has_manual' IS NULL OR (c.manual_signatures > 0) = (f ->> 'has_manual')::boolean)
       AND (f -> 'retired' IS NULL OR (c.retired_at IS NOT NULL) = (f ->> 'retired')::boolean)
       AND (f -> 'state_changed' IS NULL OR svs.in_windows(c.state_changed_at, f -> 'state_changed'))
       AND (f -> 'not_state_changed' IS NULL
            OR NOT svs.in_windows(c.state_changed_at, f -> 'not_state_changed'))
$$;

-- The coverage history's filters (ace3's `history_filter_conditions`), on a snapshot row. Its Date filter's
-- windows are days: the snapshots of the days a date range touches.
CREATE FUNCTION svs.coverage_snapshot_matches(s svs.coverage_snapshots, f jsonb) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT NOT COALESCE((f ->> 'nothing')::boolean, false)
       AND (f -> 'date' IS NULL OR svs.on_days(s.snapshot_date, f -> 'date'))
       AND (f -> 'not_date' IS NULL OR NOT svs.on_days(s.snapshot_date, f -> 'not_date'))
       AND (f -> 'technique' IS NULL OR svs.technique_in(s.technique, f -> 'technique'))
       AND (f -> 'not_technique' IS NULL OR NOT svs.technique_in(s.technique, f -> 'not_technique'))
       AND (f -> 'platform' IS NULL OR s.platform = ANY (svs.texts(f -> 'platform')))
       AND (f -> 'not_platform' IS NULL OR NOT s.platform = ANY (svs.texts(f -> 'not_platform')))
       AND (f -> 'state' IS NULL OR s.state = ANY (svs.texts(f -> 'state')))
       AND (f -> 'not_state' IS NULL OR NOT s.state = ANY (svs.texts(f -> 'not_state')))
       AND (f -> 'own_state' IS NULL OR s.own_state = ANY (svs.texts(f -> 'own_state')))
       AND (f -> 'not_own_state' IS NULL OR NOT s.own_state = ANY (svs.texts(f -> 'not_own_state')))
       AND (f -> 'level' IS NULL
            OR (CASE WHEN s.is_subtechnique THEN 'sub-technique' ELSE 'technique' END)
               = ANY (svs.texts(f -> 'level')))
       AND (f -> 'not_level' IS NULL
            OR NOT (CASE WHEN s.is_subtechnique THEN 'sub-technique' ELSE 'technique' END)
                   = ANY (svs.texts(f -> 'not_level')))
$$;

-- The worklist screen's filters (ace3's `saq/svs/worklist_filters.py`), on a worklist row. A signature
-- matches its uuid, or text in its name; `resolution_none` is the Resolution filter's `none`, a row nobody
-- resolved; Resolved By is the name its resolver had.
CREATE FUNCTION svs.worklist_matches(w svs.technique_worklist, f jsonb) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT NOT COALESCE((f ->> 'nothing')::boolean, false)
       AND (f -> 'signature' IS NULL
            OR w.signature_uuid = ANY (svs.texts(f -> 'signature'))
            OR COALESCE(w.signature_name ILIKE ANY (svs.texts(f -> 'signature_like')), false))
       AND (f -> 'not_signature' IS NULL
            OR NOT (w.signature_uuid = ANY (svs.texts(f -> 'not_signature'))
                    OR COALESCE(w.signature_name ILIKE ANY (svs.texts(f -> 'not_signature_like')), false)))
       AND (f -> 'family' IS NULL
            OR COALESCE(w.signature_family = ANY (svs.texts(f -> 'family')), false))
       AND (f -> 'not_family' IS NULL
            OR NOT COALESCE(w.signature_family = ANY (svs.texts(f -> 'not_family')), false))
       AND (f -> 'technique' IS NULL OR svs.technique_in(w.technique, f -> 'technique'))
       AND (f -> 'not_technique' IS NULL OR NOT svs.technique_in(w.technique, f -> 'not_technique'))
       AND (f -> 'status' IS NULL OR w.status = ANY (svs.texts(f -> 'status')))
       AND (f -> 'not_status' IS NULL OR NOT w.status = ANY (svs.texts(f -> 'not_status')))
       AND (f -> 'kind' IS NULL OR w.kind = ANY (svs.texts(f -> 'kind')))
       AND (f -> 'not_kind' IS NULL OR NOT w.kind = ANY (svs.texts(f -> 'not_kind')))
       AND (f -> 'resolution' IS NULL
            OR COALESCE(w.resolution = ANY (svs.texts(f -> 'resolution')), false)
            OR (COALESCE((f ->> 'resolution_none')::boolean, false) AND w.resolution IS NULL))
       AND (f -> 'not_resolution' IS NULL
            OR NOT (COALESCE(w.resolution = ANY (svs.texts(f -> 'not_resolution')), false)
                    OR (COALESCE((f ->> 'not_resolution_none')::boolean, false)
                        AND w.resolution IS NULL)))
       AND (f -> 'resolved_by' IS NULL
            OR COALESCE(w.resolved_by ->> 'name' = ANY (svs.texts(f -> 'resolved_by')), false))
       AND (f -> 'not_resolved_by' IS NULL
            OR NOT COALESCE(w.resolved_by ->> 'name' = ANY (svs.texts(f -> 'not_resolved_by')), false))
       AND (f -> 'resolved' IS NULL OR COALESCE(svs.in_windows(w.resolved_at, f -> 'resolved'), false))
       AND (f -> 'not_resolved' IS NULL
            OR NOT COALESCE(svs.in_windows(w.resolved_at, f -> 'not_resolved'), false))
$$;

-- ace3's `service_svs` recomputes coverage every `svs.coverage.refresh_interval_seconds`, and
-- `etc/cron/daily/svs-coverage-snapshot` files the day's copy (PLAN.md 6.7), as the scheduler's
-- `svs_coverage_refresh` and `svs_coverage_snapshot` do. A snapshot refreshes first, so it holds both.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('scheduler:svs_coverage_refresh', 'svs', 'coverage_refresh', 'allow',
        '{"kind": "internal", "id": "migration"}'),
       ('scheduler:svs_coverage_snapshot', 'svs', 'coverage_refresh', 'allow',
        '{"kind": "internal", "id": "migration"}'),
       ('scheduler:svs_coverage_snapshot', 'svs', 'coverage_snapshot', 'allow',
        '{"kind": "internal", "id": "migration"}');
