-- Scans (PLAN.md 7.7): a module's task asks for one of its scanner images to run, as ace3's phishkit
-- and js-deobfuscator modules send a Celery task to a manager that runs `docker run` per file. The
-- task waits as a delayed task, holding no slot, and a scanner pool, the one process that holds the
-- Docker socket, leases the scan, runs the container and ends the scan with its output archive, which
-- wakes the task. A scan runs at most once: a lost lease ends it abandoned, and the task decides.

-- queued: waiting for a scanner pool. running: a pool holds its lease and its container runs. The rest
-- are final: completed (the scanner exited by itself), timed_out (stopped at its deadline), cancelled
-- (its task's root was cancelled), failed (it didn't run, or its output couldn't come back) and
-- abandoned (no pool took it in time, or its pool stopped reporting on it).
CREATE TYPE queue.scan_state AS ENUM (
    'queued', 'running', 'completed', 'timed_out', 'cancelled', 'failed', 'abandoned'
);

CREATE TABLE queue.scans (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    task_id bigint NOT NULL REFERENCES queue.tasks (id) ON DELETE CASCADE,
    root_id uuid NOT NULL,
    -- The scanner spec's name (ace_sdk::scanners::ScannerSpec).
    scanner text NOT NULL CHECK (length(scanner) BETWEEN 1 AND 64),
    -- What follows the spec's command.
    args text[] NOT NULL CHECK (cardinality(args) <= 64),
    -- [{name, sha256, size}]: the files copied into the scanner's input directory, each held in the
    -- alert_files pool by the root.
    inputs jsonb NOT NULL DEFAULT '[]',
    timeout_seconds integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 3600),
    state queue.scan_state NOT NULL DEFAULT 'queued',
    lease_owner text,
    lease_expires_at timestamptz,
    cancel_requested boolean NOT NULL DEFAULT false,
    exit_code integer,
    error text,
    -- The output archive, in the alert_files pool, held by the root.
    output_sha256 text,
    output_size bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    deadline_at timestamptz,
    finished_at timestamptz,
    CONSTRAINT scans_running_has_a_lease CHECK (
        (state = 'running') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CONSTRAINT scans_started_has_a_deadline CHECK ((started_at IS NULL) = (deadline_at IS NULL)),
    CONSTRAINT scans_final_has_finished CHECK (
        (state IN ('queued', 'running')) = (finished_at IS NULL)),
    CONSTRAINT scans_output_whole CHECK ((output_sha256 IS NULL) = (output_size IS NULL))
);

-- The claim's scan, a task's latest scan, the reaper's scans and a root's cancellation.
CREATE INDEX scans_queued ON queue.scans (scanner, id) WHERE state = 'queued';
CREATE INDEX scans_by_task ON queue.scans (task_id, id);
CREATE INDEX scans_leases ON queue.scans (lease_expires_at) WHERE state = 'running';
CREATE INDEX scans_active_by_root ON queue.scans (root_id) WHERE state IN ('queued', 'running');

-- A queued scan wakes the pools waiting for one of its scanner, on the tasks' channel with a payload
-- no module can have: `@scan/<scanner>`.
CREATE FUNCTION queue.notify_scan() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('ace4_tasks', '@scan/' || NEW.scanner);
    RETURN NULL;
END
$$;

CREATE TRIGGER scans_notify
    AFTER INSERT ON queue.scans
    FOR EACH ROW EXECUTE FUNCTION queue.notify_scan();

-- What a scan runs doesn't change once it's queued, and an ended scan stays as it ended.
CREATE FUNCTION queue.scans_keep_their_record() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.task_id IS DISTINCT FROM OLD.task_id OR NEW.root_id IS DISTINCT FROM OLD.root_id
       OR NEW.scanner IS DISTINCT FROM OLD.scanner OR NEW.args IS DISTINCT FROM OLD.args
       OR NEW.inputs IS DISTINCT FROM OLD.inputs OR NEW.timeout_seconds IS DISTINCT FROM OLD.timeout_seconds
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a scan''s task, scanner, arguments, inputs, timeout and creation time don''t change';
    END IF;
    IF OLD.state NOT IN ('queued', 'running') AND NEW.state IS DISTINCT FROM OLD.state THEN
        RAISE EXCEPTION 'scan % has ended', OLD.id;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER scans_keep_their_record
    BEFORE UPDATE ON queue.scans
    FOR EACH ROW EXECUTE FUNCTION queue.scans_keep_their_record();
