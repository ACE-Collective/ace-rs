-- What a task's runs cost in its pool (PLAN.md 3.6), beside its run time (`run_seconds`, migration
-- 0068) and summed over the same runs, those of the root's pass in `run_pass`: `analyze_seconds`, the
-- module's `analyze` as the pool timed it, and `cpu_seconds`, the user and system CPU of the task's
-- process and its tools' as the pool read it from their rusage. A pool sends each with the task's end
-- or its delay (`ace_sdk::wire::RunCost`), and the statement that adds the run to `run_seconds` adds
-- them too. Null is unknown, not nothing: a lookup shares its process, so it has no CPU of its own; a
-- task the core ends itself, or a pool built before these, sends neither. A pass's sum is of the runs
-- that sent one, and null when none did.
--
-- Nullable columns with no default: the table isn't rewritten.
ALTER TABLE queue.tasks
    ADD COLUMN analyze_seconds double precision,
    ADD COLUMN cpu_seconds double precision;

-- `a + b`, where a null is a value nobody knows rather than a reason the sum is unknown: null only
-- when both are. Inlined by the planner, as a SQL function of one expression is.
CREATE FUNCTION queue.add_known(a double precision, b double precision)
RETURNS double precision
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT CASE WHEN a IS NULL THEN b WHEN b IS NULL THEN a ELSE a + b END $$;
