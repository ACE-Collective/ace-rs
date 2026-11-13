-- Actions (PLAN.md 7.9, ace_core::actions): remediations, remediation checks and file collections, ace3's
-- `remediation`, `external_remediation_check` and `file_collection` tables, as one queue rather than three
-- copies of a queue service (#894). A network pool that hosts an action's handler leases it through the lease
-- API, as a task is leased, runs the handler and ends the try; the core decides from the handler's spec
-- whether it runs again, when, and how it ended. An action has no root and no observable row: it acts on a
-- type and a value, which outlive any one alert, and a remediation check or a file collection names the
-- alerts it's for in queue.action_roots, every alert a shared collection belongs to (#1101).

CREATE TYPE queue.action_kind AS ENUM ('remediation', 'remediation_check', 'file_collection');

CREATE TABLE queue.actions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind queue.action_kind NOT NULL,
    -- The handler's name: ace3's remediator, probe or collector name.
    handler text NOT NULL CHECK (handler ~ '^[a-z0-9_-]{1,64}$'),
    observable_type text NOT NULL CHECK (length(observable_type) BETWEEN 1 AND 64),
    observable_value text NOT NULL CHECK (length(observable_value) BETWEEN 1 AND 4096),
    -- ace3's status: NEW (never tried, or queued again), IN_PROGRESS (tried, and to be tried again) and
    -- COMPLETED. A leased action keeps its status; its lease says a pool is trying it.
    status text NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'IN_PROGRESS', 'COMPLETED')),
    -- ace3's result, in its kind's words: a remediator's or a collector's status, or a check's result.
    result text CHECK (result ~ '^[A-Z_]{1,32}$'),
    result_message text,
    -- Not claimed before this: a try that asked to be tried again waits its backoff.
    run_after timestamptz NOT NULL DEFAULT now(),
    lease_owner text,
    lease_expires_at timestamptz,
    -- ace3's retry_count: the tries that ended.
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- ace3's max_retries; NULL for no limit, as a remediation has.
    max_attempts integer CHECK (max_attempts >= 1),
    -- Past this the core ends it without trying it: a check's deadline, a collection's time limit.
    deadline_at timestamptz,
    -- A remediation's action, and a restore's key, or what a successful removal gave back.
    action text CHECK (action IN ('remove', 'restore')),
    restore_key text CHECK (length(restore_key) <= 4096),
    -- A remediation check's context, frozen when it was queued, and the events of its confirmation.
    context jsonb,
    events jsonb,
    -- The last error a check's probe or a pool reported.
    last_error text,
    -- A file collection's file, in the alert_files pool, held by the collection and each of its roots.
    file_sha256 text CHECK (file_sha256 ~ '^[0-9a-f]{64}$'),
    file_size bigint CHECK (file_size >= 0),
    file_name text CHECK (length(file_name) BETWEEN 1 AND 255),
    -- Who asked for it: an analyst, a key, or NULL for a module's request.
    requested_by service.actor,
    -- The person it's attributed to, ace3's user_id. A deleted user clears it.
    user_id uuid REFERENCES service.users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- ace3's update_time: the end of the last try, a cancel or a retry. NULL before the first try.
    updated_at timestamptz,
    CONSTRAINT actions_leased_whole CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CONSTRAINT actions_completed_unleased CHECK (status <> 'COMPLETED' OR lease_owner IS NULL),
    CONSTRAINT actions_completed_has_a_result CHECK (status <> 'COMPLETED' OR result IS NOT NULL),
    CONSTRAINT actions_remediation_has_an_action CHECK ((kind = 'remediation') = (action IS NOT NULL)),
    CONSTRAINT actions_file_whole CHECK (
        (file_sha256 IS NULL) = (file_size IS NULL) AND (file_sha256 IS NULL) = (file_name IS NULL)),
    CONSTRAINT actions_file_is_collected CHECK (file_sha256 IS NULL OR kind = 'file_collection')
);

-- The claim's scan, the reaper's, a target's latest actions, and a collection's pending twin.
CREATE INDEX actions_claimable ON queue.actions (kind, handler, run_after, id)
    WHERE status <> 'COMPLETED' AND lease_owner IS NULL;
CREATE INDEX actions_leases ON queue.actions (lease_expires_at) WHERE lease_owner IS NOT NULL;
CREATE INDEX actions_by_target ON queue.actions (observable_type, observable_value, kind, id);

-- Each try that ended, ace3's remediation_history and file_collection_history: what the handler said.
CREATE TABLE queue.action_attempts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action_id bigint NOT NULL REFERENCES queue.actions (id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN ('NEW', 'IN_PROGRESS', 'COMPLETED')),
    result text NOT NULL CHECK (result ~ '^[A-Z_]{1,32}$'),
    message text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX action_attempts_by_action ON queue.action_attempts (action_id, id);

-- The alerts an action is for. ace3 gives a file collection one alert_uuid, so a collection another alert
-- joined belongs only to the first, which keeps its file and whose deletion fails it (#1101). Here each
-- alert that asked is a row, holds the file, and losing one leaves the others' as it was.
CREATE TABLE queue.action_roots (
    action_id bigint NOT NULL REFERENCES queue.actions (id) ON DELETE CASCADE,
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (action_id, root_id)
);

CREATE INDEX action_roots_by_root ON queue.action_roots (root_id);

-- An action that becomes claimable now wakes the pools waiting for one of its handler, on the tasks'
-- channel with a payload no module can have: `@<kind>/<handler>`. One due later is found by the next lease
-- request after it comes due, as a pool asks again whenever its wait ends.
CREATE FUNCTION queue.notify_action() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status <> 'COMPLETED' AND NEW.lease_owner IS NULL AND NEW.run_after <= now() THEN
        PERFORM pg_notify('ace4_tasks', '@' || NEW.kind::text || '/' || NEW.handler);
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER actions_notify
    AFTER INSERT OR UPDATE OF status, run_after, lease_owner ON queue.actions
    FOR EACH ROW EXECUTE FUNCTION queue.notify_action();

-- What an action acts on, with what and for whom, doesn't change once it's queued.
CREATE FUNCTION queue.actions_keep_their_record() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.handler IS DISTINCT FROM OLD.handler
       OR NEW.observable_type IS DISTINCT FROM OLD.observable_type
       OR NEW.observable_value IS DISTINCT FROM OLD.observable_value
       OR NEW.action IS DISTINCT FROM OLD.action OR NEW.context IS DISTINCT FROM OLD.context
       OR NEW.requested_by IS DISTINCT FROM OLD.requested_by OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'an action''s kind, handler, target, action, context, requester and creation time don''t change';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER actions_keep_their_record
    BEFORE UPDATE ON queue.actions
    FOR EACH ROW EXECUTE FUNCTION queue.actions_keep_their_record();

-- ace3's daily `file-collection-prune` (PLAN.md 6.7), as the scheduler's `file_collection_prune`: it lets
-- go of the files of collections that completed more than their retention ago, which only the alerts that
-- asked for them keep after that.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('scheduler:file_collection_prune', 'file_collection', 'prune', 'allow',
        '{"kind": "internal", "id": "migration"}');
