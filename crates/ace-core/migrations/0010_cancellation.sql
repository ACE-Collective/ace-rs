-- Cancellation (PLAN.md 2.12). Cancelling a root cancels its queued and delayed tasks and asks
-- its running ones to stop: cancel_requested is set, which notifies channel ace4_cancel with
-- the task's id, and the worker's next lease renewal sees it too. Dispositioning an alert
-- cancels it and switches it to dispositioned mode.

ALTER TABLE queue.tasks ADD COLUMN cancel_requested boolean NOT NULL DEFAULT false;

ALTER TABLE analysis.roots
    -- Set when the root's analysis was cancelled; a mode change clears it. While it is set,
    -- results that still land queue nothing more.
    ADD COLUMN cancelled_at timestamptz,
    -- An analyst's verdict on the alert, such as FALSE_POSITIVE, as ace3's dispositions.
    ADD COLUMN disposition text,
    ADD COLUMN dispositioned_at timestamptz;

CREATE FUNCTION queue.notify_cancel() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('ace4_cancel', NEW.id::text);
    RETURN NULL;
END
$$;

CREATE TRIGGER tasks_notify_cancel
    AFTER UPDATE OF cancel_requested ON queue.tasks
    FOR EACH ROW WHEN (NEW.cancel_requested AND NOT OLD.cancel_requested)
    EXECUTE FUNCTION queue.notify_cancel();
