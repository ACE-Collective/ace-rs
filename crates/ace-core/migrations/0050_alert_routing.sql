-- Alert routing (PLAN.md 7.13): ace3's `alerts.queue`, `alert_queue_changes` and `users.queue`, and the
-- routing that's due when an alert's analysis pass completes (`ace_service::routing`).
--
-- What differs from ace3's:
-- - A queue change records who made it as a `service.actor`, always: a router's move is made by ACE's
--   routing component, `alert_routing`, with the router's name beside it, where ace3 leaves the user NULL.
-- - A queue name refuses control characters, which ace3's takes.

-- ace3's rule for a queue (`RouteDecision`): not blank, at most 64 characters (`alerts.queue`'s size).
CREATE DOMAIN analysis.queue_name AS text CHECK (
    length(VALUE) BETWEEN 1 AND 64 AND btrim(VALUE) <> '' AND VALUE !~ '[[:cntrl:]]'
);

ALTER TABLE analysis.roots
    -- The queue an alert is in: ace3's QUEUE_DEFAULT until a submitter or a router says otherwise.
    ADD COLUMN queue analysis.queue_name NOT NULL DEFAULT 'default',
    -- The last pass the routers ran after, or NULL until they first have: the first routing of an alert is
    -- ace3's PRE_INSERT stage, every later one its POST_ANALYSIS.
    ADD COLUMN routed_pass integer;

-- Each move of an alert from one queue to another, ace3's `alert_queue_changes`. The newest says who put the
-- alert in its queue and where it came from, which is how a move is reversed, and what keeps a router from
-- undoing someone else's.
CREATE TABLE analysis.queue_changes (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    from_queue analysis.queue_name NOT NULL,
    to_queue analysis.queue_name NOT NULL,
    reason text NOT NULL CHECK (length(reason) <= 1024),
    -- The router that decided the move; NULL for a person's.
    router text CHECK (length(router) BETWEEN 1 AND 64),
    moved_by service.actor NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT queue_changes_move CHECK (from_queue <> to_queue)
);

CREATE INDEX queue_changes_by_root ON analysis.queue_changes (root_id, id);

-- An alert's completed pass whose routing hasn't run yet. `queue::check_completion` adds it in the
-- transaction that records the completion (2.11), so a completion is never missed while `ace serve` is
-- down, and the routing worker removes it in the transaction that routes.
CREATE TABLE queue.routing_due (
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    pass integer NOT NULL,
    due_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (root_id, pass)
);

CREATE INDEX routing_due_in_order ON queue.routing_due (due_at, root_id);

-- ace3's `users.queue`: the queue a person works, which the alert list's `$USER_QUEUE` stands for.
ALTER TABLE service.users ADD COLUMN queue analysis.queue_name NOT NULL DEFAULT 'default';

-- ACE's alert routing moves alerts between queues as the component `alert_routing`.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('alert_routing', 'alert', 'queue', 'allow', '{"kind": "internal", "id": "migration"}');
