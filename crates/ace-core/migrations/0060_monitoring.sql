-- Monitoring (PLAN.md 7.12): ace3's `monitoring` service (`saq/monitoring/`), whose monitors each run on
-- a timer and emit records to fluent-bit. Here each check is a task of the scheduler (6.7), and what it
-- found is kept here as well as logged, so the administration area can show it.
CREATE SCHEMA monitoring;

-- What each check found when it last ran: ace3's monitor records, `{path, value, identifier}`. A run
-- replaces its check's rows in one transaction, so the table is the state as of each check's last run
-- and never grows past what one run of each check emits (`ace_core::monitoring::MAX_RECORDS`).
CREATE TABLE monitoring.records (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The scheduled task that emitted it, such as `monitor_workload`.
    task text NOT NULL,
    -- ace3's monitor path, such as `workload.distributed` or `cas.pool`.
    path text NOT NULL,
    -- What the record is about when a check emits several, such as a pool's name.
    identifier text,
    value jsonb NOT NULL,
    emitted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX records_by_task ON monitoring.records (task, id);

-- The roots with a pass in progress, which `monitor_workload` counts by mode each minute.
CREATE INDEX roots_in_progress ON analysis.roots (analysis_mode) WHERE completed_pass < pass;

-- Each check acts as a component of its own (PLAN.md 5.2, 6.7), holding only `monitoring:report`: it
-- reads what it reports on and replaces its own records. ace3's monitors run in a service with the
-- database's credentials, under no permission.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES
    ('scheduler:monitor_workload', 'monitoring', 'report', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('scheduler:monitor_delayed_analysis', 'monitoring', 'report', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('scheduler:monitor_leases', 'monitoring', 'report', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('scheduler:monitor_queue', 'monitoring', 'report', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('scheduler:monitor_bucket_pools', 'monitoring', 'report', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('scheduler:monitor_scheduler', 'monitoring', 'report', 'allow', '{"kind": "internal", "id": "migration"}'),
    ('scheduler:bucket_node_stats', 'monitoring', 'report', 'allow', '{"kind": "internal", "id": "migration"}');
