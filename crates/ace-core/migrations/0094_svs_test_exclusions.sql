-- A catalog test excluded from SVS on every platform (PLAN.md 7.10 batch 10, ace3's `svs_test_exclusions`):
-- a person decided it doesn't apply here, or isn't worth measuring. While it is excluded the test counts
-- toward no coverage row, measures no signature on the worklist, and no run of it can be registered. It
-- takes nothing else away: its runs, results, decisions, ignores and settings are kept, and deleting the
-- row brings the test back as it was.
--
-- Keyed by the test's guid and not a foreign key, as `svs.test_settings` is, so an exclusion holds when the
-- test changes and when it leaves its repository and comes back. `excluded_by` is the actor, as a
-- decision's is: a key that belongs to nobody excludes too, where ace3 stores a user id and refuses one.
-- Only `ace_service`'s `svs_decisions` writes it.
--
-- A new table: nothing reads or writes it before this. Its unique index on `test_guid` serves every read,
-- each of which asks whether given tests are excluded.
CREATE TABLE svs.test_exclusions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    test_guid uuid NOT NULL UNIQUE,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 4096),
    excluded_by service.actor NOT NULL,
    excluded_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER test_exclusions_touch BEFORE UPDATE ON svs.test_exclusions
    FOR EACH ROW EXECUTE FUNCTION svs.touch();
