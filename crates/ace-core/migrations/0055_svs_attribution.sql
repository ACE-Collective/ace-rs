-- SVS attribution (PLAN.md 7.10 batch 6, ace3 #842): what the core's SVS hook writes besides the
-- attributions (migration 0047) and the hunter's dropped matches (0054): the root's tags, an alert's
-- maintenance record, and which built-in rules a ruleset holds.

-- The tags the core puts on a root itself, as ace3's `RootAnalysis.add_tag`: `svs_test`,
-- `svs:marker_mismatch` and `svs:maintenance`, which only the core's SVS hook writes
-- (`ace_core::svs::attribution::judge`). A submitter's own tags stay in `origin`, as it sent them; the
-- core's hooks read both.
ALTER TABLE analysis.roots ADD COLUMN tags text[] NOT NULL DEFAULT '{}';

-- An alert judged to belong to a test host's maintenance window (ace3's `svs_maintenance_alerts`): it has
-- no marker and no attribution, it involves the host, and its event time is inside the window. The hook
-- writes the row at the end of a pass and takes it back (`removed_at`) when a later pass judges
-- otherwise; the timers close the alert as IGNORE and set `closed_at` (batch 7), after which the row is
-- never changed. ace3's `confirmed_at`, set on an alert's last pass, has no column: the hook runs only
-- when a pass has nothing left to run, so every row is confirmed.
CREATE TABLE svs.maintenance_alerts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    window_id bigint NOT NULL REFERENCES svs.maintenance_windows ON DELETE CASCADE,
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    removed_at timestamptz,
    closed_at timestamptz,
    CONSTRAINT maintenance_alerts_are_unique UNIQUE (window_id, root_id)
);

CREATE INDEX maintenance_alerts_by_root ON svs.maintenance_alerts (root_id);
-- what the timers close: the records that stand
CREATE INDEX maintenance_alerts_standing ON svs.maintenance_alerts (id)
    WHERE removed_at IS NULL AND closed_at IS NULL;

-- A run's attributions of one alert, for the write that locks and reads them.
CREATE INDEX attributions_by_root_all ON svs.attributions (root_id);

-- Which built-in rule files a ruleset was built with (`ace_yara::ruleset::built_ins_sha256`): SVS's marker
-- rule, which the builder adds to every ruleset (`ace_core::svs::marker_rule`). NULL is a row built before
-- the builder added any, and a row whose value isn't this build's is built again, so a core that gains or
-- changes a built-in rule scans with it from its next build.
ALTER TABLE yara.rulesets ADD COLUMN built_ins text;

-- What a run's registration warned of, kept with the run so its answer and every later read say it: a
-- window that fell back to the floor because no hunter had recorded its hunts yet
-- (`ace_core::svs::runs::no_hunts_warning`, the owner's decision of 2026-11-14).
ALTER TABLE svs.runs ADD COLUMN warnings text[] NOT NULL DEFAULT '{}';
