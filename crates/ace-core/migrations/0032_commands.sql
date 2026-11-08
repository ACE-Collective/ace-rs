-- Commands an analyst starts from the GUI (PLAN.md 5.12, ace3's docs/GUI_CLI.md and #973). A command is
-- leased by a pool, as a task is, and run in a contained process by that pool's supervisor, which kills
-- it at its deadline whatever happens to the session that started it or to the API. It has no root or
-- observable, so it's a row here rather than in queue.tasks.

-- queued: waiting for a pool. running: a pool holds its lease and its process runs. The rest are final:
-- completed (it exited, exit_code says how), timed_out (killed at its deadline), cancelled (asked to stop,
-- or cancelled before a pool took it), failed (it didn't run, or died of a signal: error says which) and
-- abandoned (nothing will finish it: no pool took it within its timeout, or its pool stopped reporting).
CREATE TYPE queue.command_state AS ENUM (
    'queued', 'running', 'completed', 'timed_out', 'cancelled', 'failed', 'abandoned'
);

CREATE TABLE queue.commands (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- What runs: the words after `ace`, as the service split them. Only these cross to the pool.
    argv text[] NOT NULL CHECK (cardinality(argv) BETWEEN 1 AND 256),
    -- The same words quoted again, as the pages show them.
    command text NOT NULL CHECK (length(command) BETWEEN 1 AND 8192),
    timeout_seconds integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 3600),
    state queue.command_state NOT NULL DEFAULT 'queued',
    started_by service.actor NOT NULL,
    -- The person it runs for: the user, or the key's owner. A deleted user clears it, and the name stays.
    user_id uuid REFERENCES service.users (id) ON DELETE SET NULL,
    username text NOT NULL,
    lease_owner text,
    lease_expires_at timestamptz,
    cancel_requested boolean NOT NULL DEFAULT false,
    cancelled_by service.actor,
    exit_code integer,
    error text,
    -- What the command wrote to stdout and stderr, interleaved, up to the pool's limit.
    output text NOT NULL DEFAULT '',
    output_truncated boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- When a pool took it, and when its pool kills it: started_at plus its timeout.
    started_at timestamptz,
    deadline_at timestamptz,
    finished_at timestamptz,
    CONSTRAINT commands_running_has_a_lease CHECK (
        (state = 'running') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CONSTRAINT commands_started_has_a_deadline CHECK ((started_at IS NULL) = (deadline_at IS NULL)),
    CONSTRAINT commands_final_has_finished CHECK (
        (state IN ('queued', 'running')) = (finished_at IS NULL))
);

-- The claim's scan, the reaper's scans and the list's order.
CREATE INDEX commands_queued ON queue.commands (id) WHERE state = 'queued';
CREATE INDEX commands_leases ON queue.commands (lease_expires_at) WHERE state = 'running';

-- A queued command wakes the pools waiting for one, on the tasks' channel with a payload no module
-- can have.
CREATE FUNCTION queue.notify_command() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('ace4_tasks', '@commands');
    RETURN NULL;
END
$$;

CREATE TRIGGER commands_notify
    AFTER INSERT ON queue.commands
    FOR EACH ROW EXECUTE FUNCTION queue.notify_command();

-- Only the service's writes start or cancel a command, and only the pool's lease ends it, so its
-- record of who ran what stays as it was.
CREATE FUNCTION queue.commands_keep_their_record() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.argv IS DISTINCT FROM OLD.argv OR NEW.command IS DISTINCT FROM OLD.command
       OR NEW.started_by IS DISTINCT FROM OLD.started_by OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.timeout_seconds IS DISTINCT FROM OLD.timeout_seconds THEN
        RAISE EXCEPTION 'a command''s argv, command, timeout, starter and creation time don''t change';
    END IF;
    IF OLD.state NOT IN ('queued', 'running') AND NEW.state IS DISTINCT FROM OLD.state THEN
        RAISE EXCEPTION 'command % has ended', OLD.id;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER commands_keep_their_record
    BEFORE UPDATE ON queue.commands
    FOR EACH ROW EXECUTE FUNCTION queue.commands_keep_their_record();
