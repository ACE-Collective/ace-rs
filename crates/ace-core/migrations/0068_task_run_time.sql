-- A task's run time, for the per-root metrics event's `total_analysis_time_seconds` and its module
-- events (`ace_core::metrics`, ace3's `record_execution_statistics`). A run is one claim of the task:
-- it begins when a worker takes the task's lease (`claimed_at`, set by the claim's statement) and ends
-- when the worker ends the task or delays it (`Worker::finish_in`, `Worker::delay_in`), whose
-- statements add the run to `run_seconds` and count it in `runs`. `run_pass` is the root's pass those
-- runs ended in: a run that ends in a later pass starts both over, so the two hold the current pass's
-- runs only. A claim that a hold, a release, the reaper or a lost request gives back adds nothing.
-- Every one of these is a column of a statement that already runs, so neither the lease nor a task's
-- end runs a statement more. The defaults are a constant, so the table isn't rewritten.
ALTER TABLE queue.tasks
    ADD COLUMN claimed_at timestamptz,
    ADD COLUMN run_pass integer,
    ADD COLUMN run_seconds double precision NOT NULL DEFAULT 0,
    ADD COLUMN runs integer NOT NULL DEFAULT 0;
