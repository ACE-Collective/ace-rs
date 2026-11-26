-- Alert comments (PLAN.md 5.15, `ace_service`'s `alert_comments`): ace3's `comments` table, an analyst's
-- note on one alert, shown on its page, under its title in the alert list and on its event's page.
--
-- `author_id` is the person the comment is by: the user, or the owner of the API key that wrote it, as
-- ace3 records a key's user. It is NULL only for a comment ACE itself writes, which ace3 writes as its
-- automation user: ace-rs's components are no user (migration 0056), so `created_by`, the actor that
-- wrote it, names the component. A comment goes with its alert, where ace3's, keyed by the alert's uuid,
-- outlives it; a deleted comment's row goes, as in ace3, and its audit row keeps what it was. ace3's
-- column has no length limit; this is ace3's limit on an SVS run's comment, as on observable comments.
--
-- A new table: nothing reads or writes it before this.
CREATE TABLE analysis.alert_comments (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    author_id uuid REFERENCES service.users,
    created_by service.actor NOT NULL,
    comment text NOT NULL CHECK (length(comment) BETWEEN 1 AND 16384),
    created_at timestamptz NOT NULL DEFAULT now(),
    -- when the text last changed; NULL when it never has
    edited_at timestamptz,
    CONSTRAINT alert_comments_have_an_author
        CHECK (author_id IS NOT NULL OR (created_by ->> 'kind') = 'internal')
);

-- An alert's comments in order, for its page, the list's rows and the delete of its root.
CREATE INDEX alert_comments_by_root ON analysis.alert_comments (root_id, created_at, id);
CREATE INDEX alert_comments_by_author ON analysis.alert_comments (author_id);
