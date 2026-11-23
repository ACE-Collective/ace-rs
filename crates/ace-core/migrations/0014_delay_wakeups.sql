-- A delayed task wakes the workers of its module too (PLAN.md 2.30). A worker that is already
-- waiting, such as a pool's lease request, chose how long to wait from the tasks due when it
-- began, so a task delayed after that went unnoticed until the wait ran out: in the Compose
-- stack's end-to-end test each 1-second delay of the Splunk task took 10 seconds, the pool's
-- lease wait. The notification makes each woken worker look again and wait until the delay
-- ends.
CREATE OR REPLACE FUNCTION queue.notify_claimable() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.state = 'queued' AND NEW.run_after <= now()) OR NEW.state = 'delayed' THEN
        PERFORM pg_notify('ace_rs_tasks', NEW.module);
    END IF;
    RETURN NULL;
END
$$;
