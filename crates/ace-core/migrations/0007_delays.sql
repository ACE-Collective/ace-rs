-- Delays (PLAN.md 2.9): a module asks to run again later, as ace3's delay_analysis. The task
-- goes back to the queue as `delayed` with run_after in the future, and keeps what the module
-- left for its next run.
ALTER TABLE queue.tasks
    -- The state the module's last delay left for the next run, such as a search id.
    ADD COLUMN delay_state jsonb,
    -- When the module first asked for a delay. A delay's timeout counts from here.
    ADD COLUMN first_delayed_at timestamptz,
    ADD COLUMN delays integer NOT NULL DEFAULT 0;
