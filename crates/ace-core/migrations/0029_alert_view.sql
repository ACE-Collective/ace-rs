-- The alert view (PLAN.md 5.8).
--
-- An observable's display type: the label the view shows in place of its type's name, such as the
-- Splunk module's `Source IP`, as ace3's `Observable._display_type`. ace3 keeps one observable per type
-- and value in an alert and a mapping's setter replaces its label, so here a result that names one
-- replaces the stored one and a result that names none leaves it (`tree::upsert_observable`). NULL is
-- none, and the view falls back to the type's default label, then to its name.
ALTER TABLE analysis.observables ADD COLUMN display_type text;

-- A notification on channel ace4_results when a result lands, with `<root>/<result id>` as the payload,
-- so an open alert page can show it without a reload. It carries ids only: whoever listens reads the
-- result through the service layer, which checks the reader's permission. It goes out when the landing
-- transaction commits, so the result is there to read.
CREATE FUNCTION analysis.notify_result() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('ace4_results', NEW.root_id::text || '/' || NEW.id::text);
    RETURN NULL;
END
$$;

CREATE TRIGGER results_notify
    AFTER INSERT ON analysis.results
    FOR EACH ROW EXECUTE FUNCTION analysis.notify_result();
