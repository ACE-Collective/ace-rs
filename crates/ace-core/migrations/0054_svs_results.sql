-- SVS test runs, part 5b (PLAN.md 7.10 batch 5): a run's result, the matches a hunt dropped during a run,
-- a run's comments, and what the ruleset says of each YARA rule. ace3's `svs_run_results`,
-- `svs_suppressed_matches` and `svs_run_comments`, each without its `svs_` prefix.

-- One signature of a run's result (ace3's `svs_run_results`): what fired during the run against what its
-- test is expected to fire. The live columns are recomputed whenever the run's attributions or the test's
-- decisions change (`svs.run_result_state`); the reviewed_* columns are the result as signed off, written
-- once when the run is reviewed (batch 7). A row whose signature left the live result is deleted, unless
-- it holds the reviewed result, when its live status is NULL. Only `ace_service`'s `svs_results` writes
-- the live columns.
CREATE TABLE svs.run_results (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id bigint NOT NULL REFERENCES svs.runs ON DELETE CASCADE,
    -- As a detection has it (`analysis.detections.signature_uuid`).
    signature_uuid text NOT NULL CHECK (length(signature_uuid) BETWEEN 1 AND 64),
    signature_family text,
    signature_name text,
    -- NULL once the signature left the live result.
    status text CHECK (status IN
        ('hit', 'missing', 'possibly_suppressed', 'candidate', 'rejected', 'ignored', 'cleanup')),
    -- The alerts attributed to the run that carry the signature.
    alert_count integer NOT NULL DEFAULT 0 CHECK (alert_count >= 0),
    -- Every one of its attributions is late, or by context alone.
    late_only boolean NOT NULL DEFAULT false,
    context_only boolean NOT NULL DEFAULT false,
    -- Some attribution of it was judged by a fallback event time, not the event's own.
    fallback_time boolean NOT NULL DEFAULT false,
    -- The rule's own content hash when the result was computed.
    content_hash text,
    -- possibly_suppressed: the hunt's latest alert inside its suppression period. NULL when the hunter
    -- recorded the drop (`svs.suppressed_matches`), which names no alert. ace3's `suppressing_alert_uuid`.
    suppressing_root_id uuid REFERENCES analysis.roots (id) ON DELETE SET NULL,
    reviewed_status text CHECK (reviewed_status IN
        ('hit', 'missing', 'possibly_suppressed', 'candidate', 'rejected', 'ignored', 'cleanup')),
    reviewed_alert_count integer,
    reviewed_late_only boolean,
    reviewed_content_hash text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT run_results_are_unique UNIQUE (run_id, signature_uuid),
    -- a row is the live result's, the reviewed result's, or both
    CONSTRAINT run_results_hold_a_result CHECK (status IS NOT NULL OR reviewed_status IS NOT NULL)
);

CREATE INDEX run_results_by_run_status ON svs.run_results (run_id, status);
CREATE INDEX run_results_by_signature ON svs.run_results (signature_uuid);
CREATE INDEX run_results_by_update ON svs.run_results (updated_at, id);

CREATE TRIGGER run_results_touch BEFORE UPDATE ON svs.run_results
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- A hunt dropped a match inside a run's attribution window, on one of the run's test hosts (ace3's
-- `svs_suppressed_matches`): a hunt with `group_by` for its suppression, or the hunter as a duplicate of
-- the hunt's dedup key. One row per run and hunt, for the first such match. A run's result reads it to
-- tell a suppressed hunt from a missing one, so it lives as long as the run. Batch 6's attribution writes
-- it, from the hunter's suppression records (6.5).
CREATE TABLE svs.suppressed_matches (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id bigint NOT NULL REFERENCES svs.runs ON DELETE CASCADE,
    hunt_uuid text NOT NULL CHECK (length(hunt_uuid) BETWEEN 1 AND 64),
    -- The match's group value; NULL for a duplicate of a hunt without `group_by`.
    group_value text,
    -- The dedup key the match was a duplicate of; NULL when the hunt suppressed it.
    dedup_key text,
    event_time timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT suppressed_matches_are_unique UNIQUE (run_id, hunt_uuid)
);

-- A person's comment on a test run (ace3's `svs_run_comments`). Only its author changes or deletes it.
-- Only `ace_service`'s `svs_run_reads` writes it.
CREATE TABLE svs.run_comments (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id bigint NOT NULL REFERENCES svs.runs ON DELETE CASCADE,
    -- Its author: the user, or the user an API key belongs to. NULL once that user is gone.
    user_id uuid REFERENCES service.users ON DELETE SET NULL,
    comment text NOT NULL CHECK (length(comment) BETWEEN 1 AND 16384),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX run_comments_by_run ON svs.run_comments (run_id, id);
CREATE INDEX run_comments_by_update ON svs.run_comments (updated_at, id);

CREATE TRIGGER run_comments_touch BEFORE UPDATE ON svs.run_comments
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- What SVS reads of each rule in a ruleset that has a `uuid` meta (`ace_yara::ruleset::RuleSignature`):
-- [{uuid, name, content_hash, tags, counts}], the rule's name, the sha256 of its own text, its tags and
-- whether its tags count toward coverage (enabled, and not in QA mode). ace3 reads these from its
-- signature inventory; ace4's is the ruleset the pools scan with. NULL is a row built before this column,
-- which the builder fills in on its next run by building that commit again, as it does `qa_rules`.
ALTER TABLE yara.rulesets ADD COLUMN signatures jsonb;

-- The runs' list filters on these.
CREATE INDEX runs_by_created ON svs.runs (created_at DESC, id DESC);

-- The run has an alert attributed to it that is still open (ace3's `open_alerts_condition`).
CREATE FUNCTION svs.run_has_open_alerts(run bigint) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT EXISTS (
        SELECT FROM svs.attributions a
        JOIN analysis.roots o ON o.id = a.root_id
        WHERE a.run_id = run AND a.removed_at IS NULL
          AND (o.disposition IS NULL OR o.disposition = 'OPEN')
    )
$$;

-- The runs a person has to look at (ace3's `needs_attention_condition`): ended and not reviewed, failed,
-- changed since they were reviewed, or reviewed or closed with an alert still open (one an analyst took, a
-- partial one, or one closing could not reach). The one definition of the Needs attention view and its
-- count. A canceled run still attributes, so it isn't done with yet.
CREATE FUNCTION svs.run_needs_attention(r svs.runs) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT r.state IN ('ended', 'error')
        OR (r.state = 'reviewed' AND r.changed_since_review)
        OR (r.state IN ('reviewed', 'closed') AND svs.run_has_open_alerts(r.id))
$$;

CREATE FUNCTION svs.texts(j jsonb) RETURNS text[]
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT ARRAY(SELECT jsonb_array_elements_text(j))
$$;

-- Whether a date is in any of the windows `j` holds, each a [start, end] pair, both inclusive.
CREATE FUNCTION svs.in_windows(at timestamptz, j jsonb) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT EXISTS (
        SELECT FROM jsonb_array_elements(j) w
        WHERE at BETWEEN (w ->> 0)::timestamptz AND (w ->> 1)::timestamptz
    )
$$;

-- The runs screen's filters (ace3's `saq/svs/run_filters.py`), as one condition on a run, so the list,
-- the count, the batches and the event and result feeds apply the same ones. `f` is what
-- `ace_service`'s `svs_run_reads` resolved a filter list to: each filter's values under its slug and its
-- inverse's under `not_<slug>`, a text filter's as ILIKE patterns, a date filter's as [start, end]
-- windows, and a flag as true or false. The values of one filter are ORed and the filters ANDed; an
-- inverse matches exactly the rows its filter doesn't, a NULL value included. `nothing` matches no run.
CREATE FUNCTION svs.run_matches(r svs.runs, f jsonb) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT NOT COALESCE((f ->> 'nothing')::boolean, false)
       AND (f -> 'state' IS NULL OR r.state::text = ANY (svs.texts(f -> 'state')))
       AND (f -> 'not_state' IS NULL OR NOT r.state::text = ANY (svs.texts(f -> 'not_state')))
       AND (f -> 'test' IS NULL OR r.test_guid::text = ANY (svs.texts(f -> 'test')))
       AND (f -> 'not_test' IS NULL OR NOT r.test_guid::text = ANY (svs.texts(f -> 'not_test')))
       AND (f -> 'test_name' IS NULL OR EXISTS (
                SELECT FROM svs.catalog_tests c
                WHERE c.guid = r.test_guid AND c.name ILIKE ANY (svs.texts(f -> 'test_name'))))
       AND (f -> 'not_test_name' IS NULL OR NOT EXISTS (
                SELECT FROM svs.catalog_tests c
                WHERE c.guid = r.test_guid AND c.name ILIKE ANY (svs.texts(f -> 'not_test_name'))))
       AND (f -> 'technique' IS NULL OR EXISTS (
                SELECT FROM svs.catalog_tests c, unnest(svs.texts(f -> 'technique')) v
                WHERE c.guid = r.test_guid
                  AND (c.technique = v OR (strpos(v, '.') = 0 AND starts_with(c.technique, v || '.')))))
       AND (f -> 'not_technique' IS NULL OR NOT EXISTS (
                SELECT FROM svs.catalog_tests c, unnest(svs.texts(f -> 'not_technique')) v
                WHERE c.guid = r.test_guid
                  AND (c.technique = v OR (strpos(v, '.') = 0 AND starts_with(c.technique, v || '.')))))
       AND (f -> 'target' IS NULL OR EXISTS (
                SELECT FROM svs.run_targets t
                WHERE t.run_id = r.id AND t.host = ANY (svs.texts(f -> 'target'))))
       AND (f -> 'not_target' IS NULL OR NOT EXISTS (
                SELECT FROM svs.run_targets t
                WHERE t.run_id = r.id AND t.host = ANY (svs.texts(f -> 'not_target'))))
       AND (f -> 'platform' IS NULL OR r.platform = ANY (svs.texts(f -> 'platform')))
       AND (f -> 'not_platform' IS NULL OR NOT r.platform = ANY (svs.texts(f -> 'not_platform')))
       AND (f -> 'launcher' IS NULL OR r.launcher ILIKE ANY (svs.texts(f -> 'launcher')))
       AND (f -> 'not_launcher' IS NULL OR NOT r.launcher ILIKE ANY (svs.texts(f -> 'not_launcher')))
       AND (f -> 'batch' IS NULL
            OR COALESCE(lower(r.batch_id) = ANY (svs.texts(f -> 'batch')), false))
       AND (f -> 'not_batch' IS NULL
            OR NOT COALESCE(lower(r.batch_id) = ANY (svs.texts(f -> 'not_batch')), false))
       AND (f -> 'created' IS NULL OR svs.in_windows(r.created_at, f -> 'created'))
       AND (f -> 'not_created' IS NULL OR NOT svs.in_windows(r.created_at, f -> 'not_created'))
       AND (f -> 'started' IS NULL OR COALESCE(svs.in_windows(r.started_at, f -> 'started'), false))
       AND (f -> 'not_started' IS NULL
            OR NOT COALESCE(svs.in_windows(r.started_at, f -> 'not_started'), false))
       AND (f -> 'ended' IS NULL OR COALESCE(svs.in_windows(r.ended_at, f -> 'ended'), false))
       AND (f -> 'not_ended' IS NULL
            OR NOT COALESCE(svs.in_windows(r.ended_at, f -> 'not_ended'), false))
       AND (f -> 'reviewed' IS NULL OR COALESCE(svs.in_windows(r.reviewed_at, f -> 'reviewed'), false))
       AND (f -> 'not_reviewed' IS NULL
            OR NOT COALESCE(svs.in_windows(r.reviewed_at, f -> 'not_reviewed'), false))
       AND (f -> 'owner' IS NULL OR EXISTS (
                SELECT FROM service.users u
                WHERE u.id = r.owner_id AND u.username::text = ANY (svs.texts(f -> 'owner'))))
       AND (f -> 'not_owner' IS NULL OR NOT EXISTS (
                SELECT FROM service.users u
                WHERE u.id = r.owner_id AND u.username::text = ANY (svs.texts(f -> 'not_owner'))))
       AND (f -> 'reviewer' IS NULL OR EXISTS (
                SELECT FROM service.users u
                WHERE u.id = r.reviewer_id AND u.username::text = ANY (svs.texts(f -> 'reviewer'))))
       AND (f -> 'not_reviewer' IS NULL OR NOT EXISTS (
                SELECT FROM service.users u
                WHERE u.id = r.reviewer_id AND u.username::text = ANY (svs.texts(f -> 'not_reviewer'))))
       AND (f -> 'reason' IS NULL
            OR COALESCE(r.close_reason ILIKE ANY (svs.texts(f -> 'reason')), false)
            OR COALESCE(r.error_reason ILIKE ANY (svs.texts(f -> 'reason')), false)
            OR COALESCE(r.end_reason ILIKE ANY (svs.texts(f -> 'reason')), false))
       AND (f -> 'not_reason' IS NULL
            OR NOT (COALESCE(r.close_reason ILIKE ANY (svs.texts(f -> 'not_reason')), false)
                    OR COALESCE(r.error_reason ILIKE ANY (svs.texts(f -> 'not_reason')), false)
                    OR COALESCE(r.end_reason ILIKE ANY (svs.texts(f -> 'not_reason')), false)))
       AND (f -> 'changed_since_review' IS NULL
            OR r.changed_since_review = (f ->> 'changed_since_review')::boolean)
       AND (f -> 'has_open_alerts' IS NULL
            OR svs.run_has_open_alerts(r.id) = (f ->> 'has_open_alerts')::boolean)
       AND (f -> 'needs_attention' IS NULL
            OR svs.run_needs_attention(r) = (f ->> 'needs_attention')::boolean)
       AND (f -> 'has_missing' IS NULL OR EXISTS (
                SELECT FROM svs.run_results x
                WHERE x.run_id = r.id AND x.status IN ('missing', 'possibly_suppressed'))
                = (f ->> 'has_missing')::boolean)
       AND (f -> 'has_possibly_suppressed' IS NULL OR EXISTS (
                SELECT FROM svs.run_results x
                WHERE x.run_id = r.id AND x.status = 'possibly_suppressed')
                = (f ->> 'has_possibly_suppressed')::boolean)
       AND (f -> 'has_candidates' IS NULL OR EXISTS (
                SELECT FROM svs.run_results x WHERE x.run_id = r.id AND x.status = 'candidate')
                = (f ->> 'has_candidates')::boolean)
       AND (f -> 'has_late' IS NULL OR EXISTS (
                SELECT FROM svs.attributions a
                WHERE a.run_id = r.id AND a.removed_at IS NULL AND a.late)
                = (f ->> 'has_late')::boolean)
       AND (f -> 'has_context_only' IS NULL OR EXISTS (
                SELECT FROM svs.attributions a
                WHERE a.run_id = r.id AND a.removed_at IS NULL AND a.confidence = 'context')
                = (f ->> 'has_context_only')::boolean)
$$;
