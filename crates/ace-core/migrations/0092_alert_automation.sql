-- Alert automation (PLAN.md 7.22, `ace_service`'s `alert_automation`): ace3's `alert_automation_runs`
-- (its migration 07ebd9de6df2), what each of the overlay's rules did, or would have done in dry_run, to
-- each alert, and the index of confirmed remediation checks its trigger reads.
--
-- A new table and a partial index. The index's build holds writes to queue.actions while it reads the
-- table, as every CREATE INDEX here does until ace-rs runs against a production-sized database (AGENTS.md,
-- *Database and migrations*); the lock timeout fails the migration, which runs again on the next start,
-- rather than queue the core's writes behind a long transaction.
SET LOCAL lock_timeout = '5s';

-- One rule's run on one alert. The unique key is what makes a rule act at most once per alert and mode:
-- a sweep inserts the row in the transaction of the run's first action, so a second sweep that overlaps
-- it finds the row and leaves the alert alone, and renaming a rule makes it act again. `actions` is one
-- record per action of the rule, in its order: {type, status, attempts, detail, reason}. `version` goes
-- up with every write, so a sweep that read a pending run before another sweep changed it leaves it alone
-- (ace3's claim on a pending run). `status` is pending while an action is still to be tried, done once
-- every action is done or skipped, and failed once an action ran out of attempts or the rule's actions
-- no longer match the run's.
CREATE TABLE analysis.alert_automation_runs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_name text NOT NULL CHECK (rule_name ~ '^[A-Za-z0-9_.-]{1,128}$'),
    -- Not a foreign key: the run is the record of what ACE did, and outlives the alert, as ace3's does.
    root_id uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('dry_run', 'enforce')),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done', 'failed')),
    -- What the trigger found, which the actions are given: a confirmed check's probe and confirmations.
    evidence jsonb NOT NULL,
    actions jsonb NOT NULL CHECK (jsonb_typeof(actions) = 'array'),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT alert_automation_runs_once UNIQUE (rule_name, root_id, mode)
);

-- The pending runs a sweep retries, by rule and mode in id order.
CREATE INDEX alert_automation_runs_pending ON analysis.alert_automation_runs (rule_name, mode, id)
    WHERE status = 'pending';

-- The `external_remediation_confirmed` trigger's candidates: a probe's confirmed checks by when they
-- ended, ace3's `idx_erc_probe_result_time`.
CREATE INDEX actions_confirmed_checks ON queue.actions (handler, updated_at)
    WHERE kind = 'remediation_check' AND result = 'CONFIRMED';

-- The scheduler's `alert_automation` sweeps the rules as its own component, holding only this.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('scheduler:alert_automation', 'alert_automation', 'run', 'allow',
        '{"kind": "internal", "id": "migration"}');
