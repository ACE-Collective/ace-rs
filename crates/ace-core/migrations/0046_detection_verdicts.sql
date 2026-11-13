-- Detection verdicts (PLAN.md 7.14, ace_service's `detection_verdicts`): ace3's
-- `detection_point_verdicts` and `detection_point_verdict_history`. Only what someone said about one
-- detection is stored here. Every other verdict is derived when it's read, from the alert's disposition,
-- by the two functions below.
--
-- A verdict is keyed on the detection's row, not on ace3's content hash. ace3 copies an alert's detections
-- into `detection_points` on each sync, deleting a row when its detection leaves the tree and inserting it
-- again when it comes back, so a verdict needs a key that outlives the row. A row of analysis.detections
-- lives as long as its root: a result is written once per (root, observable, module), and nothing deletes a
-- detection but its root's delete, which takes its verdicts and their history with it, as deleting an alert
-- does in ace3. A detection on the alert itself (`observable_id` NULL, 7.6) is keyed the same way.

CREATE TABLE analysis.detection_verdicts (
    detection_id bigint PRIMARY KEY REFERENCES analysis.detections (id) ON DELETE CASCADE,
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    -- Copied from the detection, so labels can be counted per signature without the tree, as in ace3.
    signature_uuid text,
    verdict text NOT NULL CHECK (verdict IN ('tp', 'fp')),
    set_by service.actor NOT NULL,
    -- When the current value was set: every change sets it.
    set_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX detection_verdicts_by_root ON analysis.detection_verdicts (root_id);

-- Every change to a stored verdict, in the change's transaction (ace3's RPT-4). NULL is no stored verdict:
-- a set is NULL -> tp|fp, a clear tp|fp -> NULL, and a confirm NULL -> tp.
CREATE TABLE analysis.detection_verdict_history (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    detection_id bigint NOT NULL REFERENCES analysis.detections (id) ON DELETE CASCADE,
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    signature_uuid text,
    old_verdict text CHECK (old_verdict IN ('tp', 'fp')),
    new_verdict text CHECK (new_verdict IN ('tp', 'fp')),
    changed_by service.actor NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),
    CHECK (old_verdict IS DISTINCT FROM new_verdict)
);

CREATE INDEX detection_verdict_history_by_detection
    ON analysis.detection_verdict_history (detection_id, changed_at);

-- Whether an alert has detections from another signature: ace3's ix_detection_points_alert_signature.
CREATE INDEX detections_by_root_signature ON analysis.detections (root_id, signature_uuid);

-- The effective verdict rule (ace3's `saq/detection_verdicts/effective.py`). It exists twice, here and as
-- `ace_service::effective_verdict`, and the tests check that the two agree. `tp` and `fp` are the
-- dispositions of each class, which the service passes from its configuration on every query, so a change
-- to the classification relabels every detection when it's next read. An alert whose disposition is in
-- neither (OPEN, IGNORE, ...) gives its detections no verdict. 7.10 adds an unreviewed test run's.
--
--   NULL                 if the disposition is unclassified
--   fp  inherited_single if it's an FP disposition: a stored verdict is masked, not deleted
--   the stored verdict, explicit, if there is one
--   tp  inherited_single if the alert's detections are all from one signature
--   tp  inherited_multi  otherwise: unconfirmed
CREATE FUNCTION analysis.detection_verdict(disposition text, tp text[], fp text[], stored text)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN disposition = ANY (fp) THEN 'fp'
        WHEN disposition = ANY (tp) THEN COALESCE(stored, 'tp')
    END
$$;

-- Why the verdict is what it is. `multi` is whether the alert has a detection from another signature, a
-- detection with no signature counting as one signature of its own.
CREATE FUNCTION analysis.detection_verdict_source(
    disposition text, tp text[], fp text[], stored text, multi boolean
)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN disposition = ANY (fp) THEN 'inherited_single'
        WHEN disposition = ANY (tp) THEN CASE
            WHEN stored IS NOT NULL THEN 'explicit'
            WHEN multi THEN 'inherited_multi'
            ELSE 'inherited_single'
        END
    END
$$;
