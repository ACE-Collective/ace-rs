-- Wakeups (PLAN.md 2.8): a notification on channel ace4_tasks, with the task's module as the
-- payload, whenever a task becomes claimable now. Workers LISTEN instead of polling, with a
-- bounded wait as the fallback. Notifications go out when the transaction commits, and
-- Postgres sends one per distinct payload per transaction, so queueing many tasks for one
-- module wakes its workers once.
CREATE FUNCTION queue.notify_claimable() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state IN ('queued', 'delayed') AND NEW.run_after <= now() THEN
        PERFORM pg_notify('ace4_tasks', NEW.module);
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER tasks_notify
    AFTER INSERT OR UPDATE OF state, run_after ON queue.tasks
    FOR EACH ROW EXECUTE FUNCTION queue.notify_claimable();
