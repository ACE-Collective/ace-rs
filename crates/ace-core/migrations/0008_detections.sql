-- Detections (PLAN.md 2.10): what made a root worth an analyst's time, as ace3's detection
-- points. A detection in a detectable mode turns the root into an alert in correlation mode.

ALTER TABLE analysis.roots
    -- When a detection turned the root into an alert.
    ADD COLUMN alerted_at timestamptz;

CREATE TABLE analysis.detections (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    -- The observable it is on: the analyzed one for a detection on a result.
    observable_id bigint NOT NULL,
    -- The result that raised it.
    result_id bigint REFERENCES analysis.results (id) ON DELETE CASCADE,
    description text NOT NULL,
    details jsonb,
    queue text,
    signature_uuid text,
    signature_version text,
    signature_family text,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (root_id, observable_id)
        REFERENCES analysis.observables (root_id, id) ON DELETE CASCADE
);

CREATE INDEX detections_by_root ON analysis.detections (root_id);
