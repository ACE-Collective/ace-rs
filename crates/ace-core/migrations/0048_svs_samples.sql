-- SVS's samples (PLAN.md 7.10 batch 2): ace3's `svs_yara_captures`, `svs_sample_retirements` and
-- `svs_sample_deletions`. A sample is one (file sha256, rule uuid) pair over its captures, one capture per
-- alert, and its label is never stored: `svs.samples` derives it from the verdicts of its contributing
-- detections when it's read (`ace_core::svs::samples`).
--
-- What differs from ace3's:
-- - A capture is written in the transaction that ends the `svs_yara_sample_capture` task (`reads.md`),
--   so there's no `pending` row: a capture is `stored` or `missing`.
-- - The match record is the capture's `record` column, as 2.27's QA matches keep theirs, where ace3 puts
--   it in its CAS pool by digest. The file's bytes are in the bucket's `svs_samples` pool, held by
--   `svs_capture`/<id>, as ace3's are.
-- - The alert is the root's id (`root_id`), the uuid ace3 keys on, and the observable is its id in the
--   root, where ace3 names an observable uuid. Neither is a foreign key: a capture outlives its alert, as
--   ace3's does, and only casts no vote once the alert is gone.
-- - There's no `node`: ace-rs's bucket is one, shared by every node, where ace3's default pool is local to
--   the node that stored it.
-- - The scanner's version is yara-x's, where ace3 records yara-python's and yara_scanner's.
-- - Who retired or deleted is a `service.actor`, where ace3 stores a user id.

CREATE TABLE svs.yara_captures (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The alert it was captured from, and the file observable in it.
    root_id uuid NOT NULL,
    observable_id bigint,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    -- The rule's uuid meta: the signature_uuid of its detections. ace3's SIGNATURE_UUID_MAX_LENGTH.
    rule_uuid text NOT NULL CHECK (length(rule_uuid) BETWEEN 1 AND 36),
    rule_name text NOT NULL CHECK (length(rule_name) <= 256),
    namespace text CHECK (length(namespace) <= 256),
    -- The commit of the rule's repository when it matched, or `unknown`.
    signature_version text NOT NULL,
    rule_content_hash text,
    -- The file's path in the alert, and its yara_meta tags there: what a replay needs to scan it as it
    -- was scanned.
    file_path text NOT NULL CHECK (length(file_path) <= 1024),
    file_size bigint CHECK (file_size >= 0),
    yara_meta_tags text[] NOT NULL DEFAULT '{}',
    state text NOT NULL CHECK (state IN ('stored', 'missing')),
    -- `file`: the file was gone or no longer had its sha256, and the pool didn't have it; `storage`: the
    -- bucket refused it; `match_record`: stored, without its match record.
    missing_reason text CHECK (missing_reason IN ('file', 'match_record', 'storage')),
    -- The alert's YARA scan result for the rule, as its result has it, and what a list shows of it.
    record jsonb,
    match_summary jsonb,
    yara_version text,
    created_at timestamptz NOT NULL DEFAULT now(),
    stored_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT yara_captures_one_per_alert UNIQUE (root_id, sha256, rule_uuid),
    CONSTRAINT yara_captures_say_why_they_are_missing CHECK (
        (state = 'stored' AND stored_at IS NOT NULL
             AND (missing_reason IS NULL OR missing_reason = 'match_record'))
        OR (state = 'missing' AND stored_at IS NULL AND missing_reason IN ('file', 'storage'))),
    CONSTRAINT yara_captures_record_or_why_not CHECK (
        state = 'missing' OR (record IS NULL) = (missing_reason IS NOT DISTINCT FROM 'match_record'))
);

CREATE INDEX yara_captures_by_sample ON svs.yara_captures (sha256, rule_uuid, id);
CREATE INDEX yara_captures_by_root ON svs.yara_captures (root_id);
CREATE INDEX yara_captures_missing ON svs.yara_captures (rule_uuid) WHERE missing_reason IS NOT NULL;
CREATE INDEX yara_captures_by_update ON svs.yara_captures (updated_at, id);

CREATE TRIGGER yara_captures_touch BEFORE UPDATE ON svs.yara_captures
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- A sample retired for its rule (ace3's `svs_sample_retirements`): it's no longer expected to match, so
-- YARA validation only counts it. One row per pair, reused when it's retired again; unretiring is soft.
CREATE TABLE svs.sample_retirements (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    rule_uuid text NOT NULL CHECK (length(rule_uuid) BETWEEN 1 AND 36),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 4000),
    retired_by service.actor NOT NULL,
    retired_at timestamptz NOT NULL DEFAULT now(),
    unretired_by service.actor,
    unretired_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sample_retirements_one_per_sample UNIQUE (sha256, rule_uuid),
    CONSTRAINT sample_retirements_say_who_unretired CHECK ((unretired_at IS NULL) = (unretired_by IS NULL))
);

CREATE INDEX sample_retirements_by_update ON svs.sample_retirements (updated_at, id);

CREATE TRIGGER sample_retirements_touch BEFORE UPDATE ON svs.sample_retirements
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- A file deleted from SVS, for a legal or privacy request (ace3's `svs_sample_deletions`): its captures and
-- retirements are gone, its bytes purged from the `svs_samples` pool, and this row kept, which also keeps
-- the file from being captured again. `purged_at` stays NULL while the purge hasn't finished; deleting the
-- sample again retries it.
CREATE TABLE svs.sample_deletions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sha256 text NOT NULL UNIQUE CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    deleted_by service.actor NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 4000),
    deleted_at timestamptz NOT NULL DEFAULT now(),
    -- The rules it had captures for, sorted, and how many captures went.
    rule_uuids text[] NOT NULL,
    capture_count integer NOT NULL CHECK (capture_count >= 0),
    purged_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sample_deletions_by_update ON svs.sample_deletions (updated_at, id);

CREATE TRIGGER sample_deletions_touch BEFORE UPDATE ON svs.sample_deletions
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- The contributing detections of every capture (ace3's `contributing_votes_select`): on the alert a
-- capture came from, each detection of the capture's rule on the file observable whose value is the
-- capture's sha256, with its effective verdict and source under the dispositions' classes `tp` and `fp`
-- (7.14's rule with 7.10's test run condition). A capture whose alert is gone, or whose root isn't an
-- alert, has none.
CREATE FUNCTION svs.contributing_detections(tp text[], fp text[])
RETURNS TABLE (
    capture_id bigint, sha256 text, rule_uuid text, root_id uuid, detection_id bigint,
    verdict text, verdict_source text
)
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT c.id, c.sha256, c.rule_uuid, d.root_id, d.id,
           analysis.detection_verdict(r.disposition, tp, fp, v.verdict, svs.unreviewed_run(r.id)),
           analysis.detection_verdict_source(
               r.disposition, tp, fp, v.verdict,
               EXISTS (SELECT FROM analysis.detections o
                       WHERE o.root_id = d.root_id
                         AND o.signature_uuid IS DISTINCT FROM d.signature_uuid),
               svs.unreviewed_run(r.id))
    FROM svs.yara_captures c
    JOIN analysis.roots r ON r.id = c.root_id AND r.alerted_at IS NOT NULL
    JOIN analysis.observables ob ON ob.root_id = c.root_id AND ob.type = 'file'
        AND ob.value_hash = analysis.value_hash(c.sha256) AND ob.value = c.sha256
    JOIN analysis.detections d ON d.root_id = c.root_id AND d.observable_id = ob.id
        AND d.signature_uuid = c.rule_uuid
    LEFT JOIN analysis.detection_verdicts v ON v.detection_id = d.id
$$;

-- A sample's label from its votes (ace3's `label_expr`): the strongest strength with any vote decides,
-- explicit > inherited_single > inherited_multi, and votes of both verdicts there are `conflicted`.
-- `ace_core::svs::samples::aggregate_label` restates it, and the tests hold the two to agree.
CREATE FUNCTION svs.sample_label(
    tp_explicit bigint, fp_explicit bigint, tp_single bigint, fp_single bigint, tp_multi bigint,
    fp_multi bigint
)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN tp_explicit > 0 AND fp_explicit > 0 THEN 'conflicted'
        WHEN tp_explicit > 0 THEN 'tp'
        WHEN fp_explicit > 0 THEN 'fp'
        WHEN tp_single > 0 AND fp_single > 0 THEN 'conflicted'
        WHEN tp_single > 0 THEN 'tp'
        WHEN fp_single > 0 THEN 'fp'
        WHEN tp_multi > 0 AND fp_multi > 0 THEN 'conflicted'
        WHEN tp_multi > 0 THEN 'tp'
        WHEN fp_multi > 0 THEN 'fp'
    END
$$;

-- The strength that decided the label, NULL with no label (ace3's `label_source_expr`).
CREATE FUNCTION svs.sample_label_source(
    tp_explicit bigint, fp_explicit bigint, tp_single bigint, fp_single bigint, tp_multi bigint,
    fp_multi bigint
)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN tp_explicit + fp_explicit > 0 THEN 'explicit'
        WHEN tp_single + fp_single > 0 THEN 'inherited_single'
        WHEN tp_multi + fp_multi > 0 THEN 'inherited_multi'
    END
$$;

-- Every sample, one row per (sha256, rule_uuid), over its captures up to `through` when it's given (a
-- listing that pages over the samples as they were when its first page was read): ace3's
-- `samples_subquery`. Its counts, its latest capture's rule name, namespace, path and size, its votes,
-- label and label source, and its retirement.
CREATE FUNCTION svs.samples(tp text[], fp text[], through bigint)
RETURNS TABLE (
    sha256 text, rule_uuid text, capture_count bigint, stored bigint, missing bigint,
    missing_data bigint, unknown_version bigint, first_captured timestamptz,
    last_captured timestamptz, updated_at timestamptz, latest_capture_id bigint, rule_name text,
    namespace text, file_path text, file_size bigint, tp_explicit bigint, fp_explicit bigint,
    tp_inherited_single bigint, fp_inherited_single bigint, tp_inherited_multi bigint,
    fp_inherited_multi bigint, label text, label_source text, retired boolean, retired_by jsonb,
    retired_at timestamptz, retired_reason text
)
LANGUAGE sql STABLE AS $$
    WITH grouped AS (
        SELECT c.sha256, c.rule_uuid, count(*) AS capture_count,
               count(*) FILTER (WHERE c.state = 'stored') AS stored,
               count(*) FILTER (WHERE c.state = 'missing') AS missing,
               count(*) FILTER (WHERE c.missing_reason IS NOT NULL) AS missing_data,
               count(*) FILTER (WHERE c.signature_version = 'unknown') AS unknown_version,
               min(c.created_at) AS first_captured, max(c.created_at) AS last_captured,
               max(c.updated_at) AS updated_at, max(c.id) AS latest_capture_id
        FROM svs.yara_captures c
        WHERE through IS NULL OR c.id <= through
        GROUP BY c.sha256, c.rule_uuid
    ), votes AS (
        SELECT v.sha256, v.rule_uuid,
               count(*) FILTER (WHERE v.verdict = 'tp' AND v.verdict_source = 'explicit') AS tp_e,
               count(*) FILTER (WHERE v.verdict = 'fp' AND v.verdict_source = 'explicit') AS fp_e,
               count(*) FILTER (WHERE v.verdict = 'tp' AND v.verdict_source = 'inherited_single') AS tp_s,
               count(*) FILTER (WHERE v.verdict = 'fp' AND v.verdict_source = 'inherited_single') AS fp_s,
               count(*) FILTER (WHERE v.verdict = 'tp' AND v.verdict_source = 'inherited_multi') AS tp_m,
               count(*) FILTER (WHERE v.verdict = 'fp' AND v.verdict_source = 'inherited_multi') AS fp_m
        FROM svs.contributing_detections(tp, fp) v
        WHERE through IS NULL OR v.capture_id <= through
        GROUP BY v.sha256, v.rule_uuid
    )
    SELECT g.sha256, g.rule_uuid, g.capture_count, g.stored, g.missing, g.missing_data,
           g.unknown_version, g.first_captured, g.last_captured, g.updated_at, g.latest_capture_id,
           l.rule_name, l.namespace, l.file_path, l.file_size,
           coalesce(v.tp_e, 0), coalesce(v.fp_e, 0), coalesce(v.tp_s, 0), coalesce(v.fp_s, 0),
           coalesce(v.tp_m, 0), coalesce(v.fp_m, 0),
           svs.sample_label(coalesce(v.tp_e, 0), coalesce(v.fp_e, 0), coalesce(v.tp_s, 0),
                            coalesce(v.fp_s, 0), coalesce(v.tp_m, 0), coalesce(v.fp_m, 0)),
           svs.sample_label_source(coalesce(v.tp_e, 0), coalesce(v.fp_e, 0), coalesce(v.tp_s, 0),
                                   coalesce(v.fp_s, 0), coalesce(v.tp_m, 0), coalesce(v.fp_m, 0)),
           r.id IS NOT NULL, r.retired_by::jsonb, r.retired_at, r.reason
    FROM grouped g
    JOIN svs.yara_captures l ON l.id = g.latest_capture_id
    LEFT JOIN votes v ON v.sha256 = g.sha256 AND v.rule_uuid = g.rule_uuid
    LEFT JOIN svs.sample_retirements r ON r.sha256 = g.sha256 AND r.rule_uuid = g.rule_uuid
        AND r.unretired_at IS NULL
$$;
