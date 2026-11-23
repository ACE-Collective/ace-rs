-- The ownership-changed notice of an open alert page (the owner's decision of 2026-11-15, after PLAN.md
-- 7.17): ace3's page polls its alert's owner and says "Alert Ownership Changed!" when someone else takes
-- or is assigned it.
--
-- A notification on channel ace_rs_results, the one a landing result notifies (0029), when an alert's owner
-- changes, with `<root>/owner` as the payload, so the stream an open alert page already holds wakes and
-- reads the alert again through the service layer, which checks the reader's permission. It carries the
-- root's id only, never who owns it. It goes out when the change commits, whoever made it: a take, an
-- assignment, a disposition that takes the alert, or SVS's setter.
CREATE FUNCTION analysis.notify_owner() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('ace_rs_results', NEW.id::text || '/owner');
    RETURN NULL;
END
$$;

CREATE TRIGGER roots_owner_notify
    AFTER UPDATE OF owner_id ON analysis.roots
    FOR EACH ROW WHEN (OLD.owner_id IS DISTINCT FROM NEW.owner_id)
    EXECUTE FUNCTION analysis.notify_owner();
