-- tools/help-screenshots: the days before today's coverage snapshot, which `ace svs coverage snapshot`
-- filed. A technique's page lists its daily snapshots; these give it three earlier days: the day before
-- the first reviews, when every test was untested, and the two days since, as today's. Made up, like
-- the rest of the fixture.

\set ON_ERROR_STOP on
BEGIN;

INSERT INTO svs.coverage_snapshots
    (snapshot_date, technique, platform, attack_release, parent, is_subtechnique, state, own_state,
     tests_total, tests_validated, tests_failing, tests_stale, manual_signatures, measured_signatures)
SELECT s.snapshot_date - d.days, s.technique, s.platform, s.attack_release, s.parent, s.is_subtechnique,
       -- three days ago no run was reviewed: what tests measure today was untested then
       CASE WHEN d.days = 3 AND s.state IN ('validated', 'failing', 'stale') THEN 'untested' ELSE s.state END,
       CASE WHEN d.days = 3 AND s.own_state IN ('validated', 'failing', 'stale') THEN 'untested'
            ELSE s.own_state END,
       s.tests_total,
       CASE WHEN d.days = 3 THEN 0 ELSE s.tests_validated END,
       CASE WHEN d.days = 3 THEN 0 ELSE s.tests_failing END,
       CASE WHEN d.days = 3 THEN 0 ELSE s.tests_stale END,
       s.manual_signatures,
       CASE WHEN d.days = 3 THEN 0 ELSE s.measured_signatures END
FROM svs.coverage_snapshots s, (VALUES (1), (2), (3)) AS d (days)
WHERE s.snapshot_date = (SELECT max(snapshot_date) FROM svs.coverage_snapshots)
  AND s.state <> 'none';

COMMIT;
