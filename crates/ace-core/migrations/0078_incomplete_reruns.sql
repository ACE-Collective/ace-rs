-- A module's result can be incomplete (ace3's AnalysisExecutionResult.INCOMPLETE on an analysis it
-- made, PLAN.md decision 34): the result is stored, and the module runs again on the same
-- observable whenever the observable changes, and on the root's next pass, its result replaced each
-- time, until a run completes it.
--
-- ace3's engine puts an observable back on its work stack when it gains a tag, a directive, a
-- relationship or an analysis, and a module whose analysis there isn't completed runs again on it.
-- Here an observable counts those changes (`changes`), whatever made them: a result, a hook, a cache
-- hit. A task records the count when it is claimed (`seen_changes`), so a change made while it ran
-- counts too, as ace3's work stack holds it; once the task ends incomplete, eligibility queues it
-- again when the count has moved past what it saw.

ALTER TABLE analysis.observables
    ADD COLUMN changes bigint NOT NULL DEFAULT 0;

ALTER TABLE queue.tasks
    -- the task's last run ended with an incomplete result: it is done, and runs again on a change
    ADD COLUMN incomplete boolean NOT NULL DEFAULT false,
    -- its observable's `changes` when the task was last claimed
    ADD COLUMN seen_changes bigint;

-- A tag or a directive the observable didn't have.
CREATE FUNCTION analysis.count_observable_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tags IS DISTINCT FROM OLD.tags OR NEW.directives IS DISTINCT FROM OLD.directives THEN
        NEW.changes := OLD.changes + 1;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER observables_count_change
    BEFORE UPDATE OF tags, directives ON analysis.observables
    FOR EACH ROW EXECUTE FUNCTION analysis.count_observable_change();

-- A relationship from the observable, or a result on it (a new one: a rerun's replacement is an
-- update, which changes nothing here, so a rerun that adds nothing doesn't run itself again).
CREATE FUNCTION analysis.count_added_to_observable() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    UPDATE analysis.observables SET changes = changes + 1
    WHERE root_id = NEW.root_id AND id = NEW.observable_id;
    RETURN NULL;
END
$$;

CREATE TRIGGER relationships_count_change
    AFTER INSERT ON analysis.relationships
    FOR EACH ROW EXECUTE FUNCTION analysis.count_added_to_observable();

CREATE TRIGGER results_count_change
    AFTER INSERT ON analysis.results
    FOR EACH ROW EXECUTE FUNCTION analysis.count_added_to_observable();

-- A rerun's replaced result wakes the alert page's stream, as a new one does.
CREATE TRIGGER results_notify_replaced
    AFTER UPDATE OF details, summary, error, tags, pivot_links ON analysis.results
    FOR EACH ROW EXECUTE FUNCTION analysis.notify_result();
