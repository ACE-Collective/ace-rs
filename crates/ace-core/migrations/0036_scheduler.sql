-- The scheduler (PLAN.md 6.7): ace3's maintenance tasks (`etc/cron/<cadence>/`, run by
-- `saq/cron_tasks.py`) that have a counterpart here, run by `ace serve` on their cron schedules.
CREATE SCHEMA scheduler;

-- One row per task: when it's next due, and the run that holds it. Every `ace serve` replica claims
-- a due task with FOR UPDATE SKIP LOCKED, and the claim moves `due_at` past now and sets the lease,
-- so one replica runs each due time, a run is never started while another holds the lease, and
-- the times a stopped stack missed are run once, not once each.
CREATE TABLE scheduler.tasks (
    name text PRIMARY KEY,
    -- The cron expression `due_at` was worked out from. A replica with another one in its overlay
    -- works `due_at` out again.
    schedule text NOT NULL,
    due_at timestamptz NOT NULL,
    -- The run holding the task, and until when. A run that outlives its lease, because its node
    -- died, is marked abandoned by the next claim.
    run_id bigint,
    lease_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Every run: when it was due, where and when it ran, and how it ended. ace3 writes each task's
-- outcome to fluent-bit's `cron-jobs` tag and shows it nowhere else, so nothing here reads it yet;
-- 7.12's monitoring is its reader. A task's rows older than 90 days go when it next starts.
CREATE TABLE scheduler.runs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    task text NOT NULL,
    -- The due time the run was claimed for.
    scheduled_for timestamptz NOT NULL,
    -- The process that ran it: host and process id.
    node text NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    outcome text CHECK (outcome IN ('succeeded', 'failed', 'timed_out', 'stopped', 'abandoned')),
    -- Why it failed, timed out, stopped or was abandoned.
    error text,
    -- What the task said it did, such as how many objects it deleted.
    summary jsonb,
    CHECK ((ended_at IS NULL) = (outcome IS NULL))
);

CREATE INDEX runs_by_task ON scheduler.runs (task, id DESC);

-- ace3's `cas.verify`: when a re-hash last found the object's bytes intact.
ALTER TABLE store.objects ADD COLUMN verified_at timestamptz;

-- Each task acts as a component of its own (PLAN.md 5.2), holding only what it needs:
-- `scheduler:bucket_gc` and `scheduler:bucket_orphans` delete what the bucket's index no longer
-- keeps, `scheduler:bucket_verify` re-hashes objects and records when, and
-- `scheduler:yara_qa_prune` removes expired QA matches, which ace3 does under no permission and
-- ace-rs under the purge's own.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES
    ('scheduler:bucket_gc', 'bucket', 'gc', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('scheduler:bucket_orphans', 'bucket', 'gc', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('scheduler:bucket_verify', 'bucket', 'verify', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('scheduler:yara_qa_prune', 'signature', 'qa_purge', 'allow', '{"kind": "internal", "id": "migration"}');
