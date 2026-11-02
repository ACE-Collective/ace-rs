-- The task queue (PLAN.md 2.6): one task per (root, observable, module). Workers claim with
-- FOR UPDATE SKIP LOCKED and hold a lease while a task runs.

-- queued: waiting to be claimed. delayed: the module asked to run again at run_after.
-- running: a worker holds its lease. done, failed and cancelled are final.
CREATE TYPE queue.task_state AS ENUM ('queued', 'delayed', 'running', 'done', 'failed', 'cancelled');

CREATE TABLE queue.tasks (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    root_id uuid NOT NULL,
    observable_id bigint NOT NULL,
    -- The module's key: a module's name now, and a named instance's later (PLAN.md 2.23).
    module text NOT NULL,
    state queue.task_state NOT NULL DEFAULT 'queued',
    -- A queued or delayed task can't be claimed before this.
    run_after timestamptz NOT NULL DEFAULT now(),
    lease_owner text,
    lease_expires_at timestamptz,
    -- Claims since the task last finished a run normally. A lease that expires at the limit
    -- fails the task.
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts >= 1),
    error text,
    -- The sha256 of each input the task reads from the bucket, such as its file, so a failed
    -- task can be replayed.
    input_hashes text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (root_id, observable_id)
        REFERENCES analysis.observables (root_id, id) ON DELETE CASCADE,
    CONSTRAINT tasks_one_per_module UNIQUE (root_id, observable_id, module),
    CONSTRAINT tasks_running_has_a_lease CHECK (
        (state = 'running') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL))
);

-- The claim's scan: the claimable tasks of the modules a worker hosts, oldest first.
CREATE INDEX tasks_claimable ON queue.tasks (module, run_after, id)
    WHERE state IN ('queued', 'delayed');
CREATE INDEX tasks_by_root ON queue.tasks (root_id, state);
