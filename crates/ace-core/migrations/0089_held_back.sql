-- The core's wait for a task of a module that runs last (`Api::leased`), kept apart from the module's
-- own delay (`delay_state`, `first_delayed_at`, `delays`, migration 0007). The wait used to be written
-- as a delay, so it counted as a run of the module (`runs`, `run_seconds`, migration 0068), shortened
-- the module's own delay timeout, which counts from its first delay, and handed the module a state that
-- wasn't its own. `held_back_by` is what holds the task back (`tree::HeldBack::as_str`), the mark
-- `queue::wake_held_back` finds; `held_back_step` is how many times in a row that has held it back, which
-- doubles its next wait. Both are null for a task the core isn't holding back, or whose module delayed it
-- since.
--
-- Nullable columns with no default: the table isn't rewritten. The ALTER's lock and the UPDATE's row
-- locks are short, but either can queue behind a long transaction on the table, so one held that long
-- fails the migration, which runs again on the next start, rather than stopping the core's writes.
SET LOCAL lock_timeout = '5s';

ALTER TABLE queue.tasks
    ADD COLUMN held_back_by text,
    ADD COLUMN held_back_step integer;

-- A task held back as a delay before this keeps the wait but loses the delay record that was the
-- wait's, so its module doesn't count from it. Only delayed tasks, which `tasks_claimable` indexes.
UPDATE queue.tasks
SET held_back_by = delay_state->>'held_back_by',
    held_back_step = COALESCE((delay_state->>'step')::integer, 0),
    delay_state = NULL, first_delayed_at = NULL, delays = 0
WHERE state = 'delayed' AND delay_state ? 'held_back_by';
