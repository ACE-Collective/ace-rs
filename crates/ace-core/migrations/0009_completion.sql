-- Root completion (PLAN.md 2.11). A root is complete when it has no queued, delayed or running
-- tasks. An analysis pass starts when work is queued on a root whose last pass completed, and
-- ends with exactly one completion row, which notifies channel ace4_root_complete with
-- '<root>/<pass>'. Alert routing waits for that, rather than guessing from a stale flag (#848).

ALTER TABLE analysis.roots
    -- The current analysis pass, counting from 1. 0 until analysis starts.
    ADD COLUMN pass integer NOT NULL DEFAULT 0,
    -- The last pass that completed. Equal to pass when the root is idle.
    ADD COLUMN completed_pass integer NOT NULL DEFAULT 0,
    ADD CONSTRAINT roots_completed_pass CHECK (completed_pass <= pass);

CREATE TABLE queue.root_completions (
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    pass integer NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (root_id, pass)
);

CREATE FUNCTION queue.notify_completion() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('ace4_root_complete', NEW.root_id::text || '/' || NEW.pass::text);
    RETURN NULL;
END
$$;

CREATE TRIGGER root_completions_notify
    AFTER INSERT ON queue.root_completions
    FOR EACH ROW EXECUTE FUNCTION queue.notify_completion();
