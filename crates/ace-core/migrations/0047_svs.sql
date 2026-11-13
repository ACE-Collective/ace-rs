-- SVS, the Signature Validation System (PLAN.md 7.10 batch 1): ace3's `saq/svs/` tables that the rest of
-- SVS builds on. Test hosts, the Atomic Red Team tests runs name, runs and their targets, each run's event
-- log, whether its live result is current, and the attributions of alerts' detections to runs. Later
-- batches add the samples, validations, catalog repositories, maintenance windows, decisions, results and
-- coverage. Each table here is ace3's of the same name without its `svs_` prefix.
--
-- What differs from ace3's:
-- - An attribution names its detection by `analysis.detections.id`, where ace3's names the detection's
--   content hash: ace3's marker router writes it inside ALERT(), before the alert's detection rows exist,
--   and ace4 has no such stage, so a detection is a row before anything judges the alert (7.14 keys a
--   verdict on the same id). The signature isn't copied, since the detection has it, and the alert is the
--   root it's on (`root_id`), the uuid ace3 keys on.
-- - Who did something is a `service.actor`, as every row here records one, where ace3 stores a user id
--   and a name. A run's owner and reviewer are users, as an alert's owner is in ace3.
-- - Lists are arrays, where ace3 stores JSON text, and times are timestamptz.
-- - `updated_at` is set on every change by a trigger, as ace3's `ON UPDATE CURRENT_TIMESTAMP(6)` is.

CREATE SCHEMA svs;

CREATE FUNCTION svs.touch() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END
$$;

-- A host test runs may target (ace3's `svs_test_hosts`). A run against any other host, or as a user the
-- host doesn't list, is refused. A table rather than settings, so a site that builds test machines on
-- demand adds one without a restart (ace3's FR-15). Only `ace_service`'s `svs` writes it.
CREATE TABLE svs.test_hosts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The short host name, lower case: what a target's short or fully qualified name matches.
    hostname text NOT NULL UNIQUE CHECK (length(hostname) BETWEEN 1 AND 255),
    -- The fully qualified name, lower case, when the host has one.
    fqdn text CHECK (length(fqdn) BETWEEN 1 AND 255),
    -- The bare user names runs may use, lower case and sorted; none means any user.
    usernames text[] NOT NULL DEFAULT '{}' CHECK (cardinality(usernames) <= 100),
    -- The host's addresses, as Python's ipaddress writes them, IPv4 first.
    ips text[] NOT NULL DEFAULT '{}' CHECK (cardinality(ips) <= 100),
    -- windows, linux or macos when known: a test that doesn't support it can't target the host.
    platform text CHECK (platform IN ('windows', 'linux', 'macos')),
    notes text,
    created_by service.actor NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX test_hosts_by_update ON svs.test_hosts (updated_at, id);

CREATE TRIGGER test_hosts_touch BEFORE UPDATE ON svs.test_hosts
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- An Atomic Red Team test, by its auto_generated_guid (ace3's `svs_catalog_tests`). A test that leaves its
-- repository keeps its row, with `removed_at`, so its runs keep their history. Batch 4's catalog refresh
-- writes it.
CREATE TABLE svs.catalog_tests (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    guid uuid NOT NULL UNIQUE,
    -- The catalog repository's name.
    repository text NOT NULL,
    -- The ATT&CK technique of the atomic file, such as T1059.001.
    technique text NOT NULL CHECK (length(technique) BETWEEN 1 AND 32),
    technique_name text,
    name text NOT NULL,
    description text,
    -- The test's supported_platforms.
    platforms text[] NOT NULL,
    executor text,
    -- The test's entry in its atomic file: commands, input arguments, dependencies.
    test jsonb NOT NULL,
    -- The sha256 of the canonical entry: a changed test makes its coverage stale.
    content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    -- The repository commit the test was last read from, and the path of its atomic file.
    commit text NOT NULL,
    path text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    removed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX catalog_tests_by_repository ON svs.catalog_tests (repository);
CREATE INDEX catalog_tests_by_technique_name ON svs.catalog_tests (technique, name, id);
CREATE INDEX catalog_tests_by_update ON svs.catalog_tests (updated_at, id);

CREATE TRIGGER catalog_tests_touch BEFORE UPDATE ON svs.catalog_tests
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- Where a run is (ace3's `RunState`): registered, its windows open, its observation window passed and
-- waiting for a person, signed off, stopped by its launcher, failed, or discarded.
CREATE TYPE svs.run_state AS ENUM
    ('created', 'started', 'ended', 'reviewed', 'canceled', 'error', 'closed');

-- A test run (ace3's `svs_runs`): one catalog test a launcher outside ACE runs against one or more test
-- hosts, from registration through review or close. Every change of state is a conditional update, so a
-- timer that fires twice changes nothing. Batch 5's lifecycle writes it.
CREATE TABLE svs.runs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uuid uuid NOT NULL UNIQUE,
    -- The catalog test, its content hash and the commit it was read from, as they were at registration.
    -- Not a foreign key: a run outlives its test's row.
    test_guid uuid NOT NULL,
    -- The ATT&CK platform the run is on, set at registration.
    platform text NOT NULL CHECK (length(platform) BETWEEN 1 AND 32),
    test_content_hash text NOT NULL CHECK (test_content_hash ~ '^[0-9a-f]{64}$'),
    catalog_commit text NOT NULL,
    state svs.run_state NOT NULL,
    -- svs- and 26 base32 characters, lower case (`ace_core::svs::markers`).
    marker text NOT NULL UNIQUE CHECK (marker ~ '^svs-[a-z2-7]{26}$'),
    launcher text NOT NULL CHECK (length(launcher) BETWEEN 1 AND 256),
    -- A label the runs a launcher registered together share; not a table.
    batch_id text CHECK (length(batch_id) BETWEEN 1 AND 256),
    -- The object the launcher sent, capped by the registration.
    extra jsonb NOT NULL DEFAULT '{}',
    registered_by service.actor,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    executed_at timestamptz,
    -- When the launcher said the test's cleanup began: what fires at or after it is the cleanup's.
    cleanup_at timestamptz,
    exit_code integer,
    launcher_error text,
    -- What the test printed, as the launcher reported it, bounded by the call.
    launcher_output text,
    ended_at timestamptz,
    -- Why a person ended it before its observation window passed.
    end_reason text,
    canceled_at timestamptz,
    closed_at timestamptz,
    close_reason text,
    error_reason text,
    -- The windows' lengths, computed at registration, and where they end, set at start.
    observation_seconds integer NOT NULL CHECK (observation_seconds > 0),
    attribution_seconds integer NOT NULL CHECK (attribution_seconds >= observation_seconds),
    observation_ends_at timestamptz,
    attribution_ends_at timestamptz,
    -- The test holds its hosts until its attribution window ends rather than its observation window.
    holds_host boolean NOT NULL DEFAULT false,
    owner_id uuid REFERENCES service.users ON DELETE SET NULL,
    reviewer_id uuid REFERENCES service.users ON DELETE SET NULL,
    reviewed_at timestamptz,
    -- A late alert or a person's association after review: the run needs attention again.
    changed_since_review boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT runs_start_their_windows CHECK ((started_at IS NULL) = (observation_ends_at IS NULL)
                                               AND (started_at IS NULL) = (attribution_ends_at IS NULL))
);

CREATE INDEX runs_by_state_created ON svs.runs (state, created_at);
CREATE INDEX runs_by_state_observation ON svs.runs (state, observation_ends_at);
CREATE INDEX runs_by_state_attribution ON svs.runs (state, attribution_ends_at);
CREATE INDEX runs_by_test_platform ON svs.runs (test_guid, platform, state, reviewed_at);
CREATE INDEX runs_by_batch ON svs.runs (batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX runs_by_update ON svs.runs (updated_at, id);

CREATE TRIGGER runs_touch BEFORE UPDATE ON svs.runs
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- A host and user a run targets, matched against the test hosts at registration (ace3's
-- `svs_run_targets`).
CREATE TABLE svs.run_targets (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id bigint NOT NULL REFERENCES svs.runs ON DELETE CASCADE,
    -- As the launcher sent them.
    hostname text NOT NULL,
    username text,
    -- Normalized (`ace_core::svs::hosts`): the short name, the fully qualified one when given, and the
    -- bare user name, lower case. What an alert's hosts are matched against.
    host text NOT NULL,
    fqdn text,
    "user" text,
    -- The test host it matched, NULL once that host is removed.
    test_host_id bigint REFERENCES svs.test_hosts ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX run_targets_by_run ON svs.run_targets (run_id);
CREATE INDEX run_targets_by_host ON svs.run_targets (host);

CREATE TRIGGER run_targets_touch BEFORE UPDATE ON svs.run_targets
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- One row of a run's event log (ace3's `svs_run_events`), append-only: a state change, a launcher call
-- with its payload, attributions, decisions, a review or a close with its reason.
CREATE TABLE svs.run_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id bigint NOT NULL REFERENCES svs.runs ON DELETE CASCADE,
    -- `ace_core::svs::RunEventKind`.
    kind text NOT NULL CHECK (kind IN (
        'registered', 'transition', 'launcher_call', 'attributed', 'attribution_removed',
        'alerts_closed', 'result_computed', 'candidate_decision', 'associated', 'disassociated',
        'context_kept', 'ownership_taken', 'reviewed')),
    from_state svs.run_state,
    to_state svs.run_state,
    actor service.actor NOT NULL,
    details jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX run_events_by_run ON svs.run_events (run_id, id);
CREATE INDEX run_events_by_update ON svs.run_events (updated_at, id);

CREATE FUNCTION svs.run_events_are_append_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'a run''s event log is append-only';
END
$$;

CREATE TRIGGER run_events_are_append_only BEFORE UPDATE ON svs.run_events
    FOR EACH ROW EXECUTE FUNCTION svs.run_events_are_append_only();

-- Whether a run's live result is current (ace3's `svs_run_result_state`). A change to what the result
-- would be bumps `generation` and sets `stale`; a computation clears `stale` only if the generation it
-- read is still the current one. Kept off svs.runs, whose updated_at drives the runs' changed_since.
CREATE TABLE svs.run_result_state (
    run_id bigint PRIMARY KEY REFERENCES svs.runs ON DELETE CASCADE,
    generation bigint NOT NULL DEFAULT 0,
    computed_generation bigint,
    stale boolean NOT NULL DEFAULT false,
    computed_at timestamptz
);

CREATE INDEX run_result_state_stale ON svs.run_result_state (run_id) WHERE stale;

-- How a detection was attributed: a marker that agrees with its run, or the run's target and window alone.
CREATE TYPE svs.attribution_confidence AS ENUM ('marker', 'context');

-- One detection of an alert attributed to a test run (ace3's `svs_attributions`). A removed row is kept,
-- with who removed it, so the core never attributes again what a person disassociated. The core's SVS
-- hook writes the rows with source `router` (batch 6), and a person's changes are `manual` (batch 7).
CREATE TABLE svs.attributions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id bigint NOT NULL REFERENCES svs.runs ON DELETE CASCADE,
    -- The alert: the root the detection is on.
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    detection_id bigint NOT NULL REFERENCES analysis.detections (id) ON DELETE CASCADE,
    confidence svs.attribution_confidence NOT NULL,
    -- The alert's event time was past the run's observation window.
    late boolean NOT NULL DEFAULT false,
    -- The event time the attribution was judged by, and where it came from: the event's own, a hunt's
    -- query time, when its producer made the alert, or the alert's insert time.
    event_time timestamptz,
    event_time_source text CHECK (event_time_source IN ('event', 'query_time', 'now', 'insert_time')),
    source text NOT NULL CHECK (source IN ('router', 'manual')),
    -- Where the agreeing marker was found; NULL for context.
    scan_point text CHECK (scan_point IN
        ('observable', 'detection', 'root_details', 'analysis', 'file_contents')),
    actor service.actor NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- Set when it no longer holds: the core found it no longer applies, or a person disassociated it.
    removed_at timestamptz,
    removed_by service.actor,
    removal_reason text,
    -- Set when a person reviewing the run kept a context attribution: it is a test.
    kept_at timestamptz,
    kept_by service.actor,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT attributions_are_unique UNIQUE (run_id, root_id, detection_id),
    CONSTRAINT attributions_say_who_removed_them CHECK ((removed_at IS NULL) = (removed_by IS NULL))
);

CREATE INDEX attributions_by_root ON svs.attributions (root_id) WHERE removed_at IS NULL;
CREATE INDEX attributions_by_detection ON svs.attributions (detection_id);
CREATE INDEX attributions_by_update ON svs.attributions (updated_at, id);

CREATE TRIGGER attributions_touch BEFORE UPDATE ON svs.attributions
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- Whether the alert is attributed to a test run that isn't reviewed, through an attribution that holds:
-- ace3's `unreviewed_run_condition`, which gives the alert's detections no verdict and keeps its files out
-- of SVS's samples. Close sets SIMULATED, a TP disposition, on a canceled, failed or discarded run's
-- alerts too, and nothing is learned from those.
CREATE FUNCTION svs.unreviewed_run(root uuid) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT EXISTS (
        SELECT FROM svs.attributions a
        JOIN svs.runs r ON r.id = a.run_id
        WHERE a.root_id = root AND a.removed_at IS NULL AND r.state <> 'reviewed'
    )
$$;

-- 7.14's verdict rule with its test run condition (migration 0046's comment), which `ace_service`'s
-- `effective_verdict` restates and the tests hold to agree:
--
--   NULL                 if the disposition is unclassified
--   NULL                 if the alert is attributed to a test run that isn't reviewed (`unreviewed`)
--   fp  inherited_single if it's an FP disposition: a stored verdict is masked, not deleted
--   the stored verdict, explicit, if there is one
--   tp  inherited_single if the alert's detections are all from one signature
--   tp  inherited_multi  otherwise: unconfirmed
DROP FUNCTION analysis.detection_verdict(text, text[], text[], text);
DROP FUNCTION analysis.detection_verdict_source(text, text[], text[], text, boolean);

CREATE FUNCTION analysis.detection_verdict(
    disposition text, tp text[], fp text[], stored text, unreviewed boolean
)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN unreviewed THEN NULL
        WHEN disposition = ANY (fp) THEN 'fp'
        WHEN disposition = ANY (tp) THEN COALESCE(stored, 'tp')
    END
$$;

CREATE FUNCTION analysis.detection_verdict_source(
    disposition text, tp text[], fp text[], stored text, multi boolean, unreviewed boolean
)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN unreviewed THEN NULL
        WHEN disposition = ANY (fp) THEN 'inherited_single'
        WHEN disposition = ANY (tp) THEN CASE
            WHEN stored IS NOT NULL THEN 'explicit'
            WHEN multi THEN 'inherited_multi'
            ELSE 'inherited_single'
        END
    END
$$;
