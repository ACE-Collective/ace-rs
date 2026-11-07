-- The JSON API (PLAN.md 5.5).
--
-- A submission records who made it, as a disposition does. Roots the core makes itself, such as a
-- test's, have none, so the column allows NULL; every root from `ace_service::Service::submit` has one.
ALTER TABLE analysis.roots ADD COLUMN submitted_by service.actor;

-- The alert list pages newest alert first, keyed on the alerted time and the id.
CREATE INDEX roots_by_alerted ON analysis.roots (alerted_at DESC, id DESC) WHERE alerted_at IS NOT NULL;

-- An observable's prevalence looks it up by type and value across roots.
CREATE INDEX observables_by_value ON analysis.observables (type, value_hash);

-- The address a request came from, as the adapter saw it: the TCP peer, since no proxy header is
-- trusted yet. Internal callers have none.
ALTER TABLE service.audit ADD COLUMN src_ip inet;

-- A read that ace3 audits, such as a file download, changes nothing, so its row has no before or after
-- and says what was read in details. A row still has to say something.
ALTER TABLE service.audit
    DROP CONSTRAINT audit_records_a_change,
    ADD CONSTRAINT audit_records_something
        CHECK (num_nonnulls(before, after) > 0 OR details <> '{}'::jsonb);
