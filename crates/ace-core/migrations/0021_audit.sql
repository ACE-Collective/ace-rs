-- The audit record (PLAN.md 5.3, ace3 #830): one row for each change made through the service layer,
-- written in the transaction of the change, so the two commit or roll back together. ace3's audit is a
-- log line written after its commit, with extra fields, and Splunk is what reads it.
--
-- A row outlives what it describes, as `actor` outlives its user, so nothing here is a foreign key: a
-- root's ON DELETE CASCADE has no path to this table. `target_id` is text because a component's id is.
-- `details` holds what's needed to read the row once its target is gone, such as an alert's title. All
-- of the jsonb comes from ace-service's `Recorded` types: their docs say what may go in.
CREATE TABLE service.audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    actor service.actor NOT NULL,
    -- The name of the service function that made the change.
    action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*$'),
    target_kind text NOT NULL CHECK (target_kind ~ '^[a-z][a-z0-9_]*$'),
    target_id text NOT NULL CHECK (length(target_id) > 0),
    before jsonb,
    after jsonb,
    details jsonb NOT NULL DEFAULT '{}',
    -- A row with neither side recorded no change.
    CONSTRAINT audit_records_a_change CHECK (num_nonnulls(before, after) > 0)
);

-- The questions ace3 answers by searching one Splunk field: what happened to this thing, what did this
-- identity do, and what did this user's API keys do.
CREATE INDEX audit_by_target ON service.audit (target_kind, target_id, id);
CREATE INDEX audit_by_actor ON service.audit ((actor ->> 'kind'), (actor ->> 'id'), id);
CREATE INDEX audit_by_key_owner ON service.audit ((actor ->> 'owner'), id)
    WHERE actor ->> 'owner' IS NOT NULL;

-- Append-only. The trigger is per statement, so it also refuses TRUNCATE and a statement that matches no
-- rows. A role that owns the table can still disable it: this catches a mistake, not an owner with intent.
-- Rows are kept for good: ace3's retention is Splunk's, and nothing here deletes them yet. A retention job
-- would be its own migration, and has to change this trigger on purpose.
CREATE FUNCTION service.refuse_audit_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'service.audit is append-only: % refused', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER audit_is_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON service.audit
    FOR EACH STATEMENT EXECUTE FUNCTION service.refuse_audit_change();
