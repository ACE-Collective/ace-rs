-- The observable_comments router (PLAN.md 5.6): an analyst's comment on an observable, by its type and
-- value, so it applies to that observable in every alert, as ace3's `observable_comments` does through
-- its index of every observable. ace-rs has no such index, so a comment holds the type and value itself,
-- matched as 5.5's lookup matches `analysis.observables`: by type, value_hash and value.
--
-- A comment is a person's: `author_id` is the user, and `created_by` the actor that wrote it, which is a
-- key when one of the user's keys did, as ace3 records the key's user. There's no foreign key to a root,
-- since a comment outlives every alert that holds its observable. A deleted comment's row goes, as in
-- ace3, and its audit row keeps what it was. ace3's column has no length limit; this is ace3's limit on
-- an SVS run's comment.
CREATE TABLE analysis.observable_comments (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type text NOT NULL,
    value text NOT NULL,
    value_hash bytea NOT NULL GENERATED ALWAYS AS (analysis.value_hash(value)) STORED,
    author_id uuid NOT NULL REFERENCES service.users,
    created_by service.actor NOT NULL,
    comment text NOT NULL CHECK (length(comment) BETWEEN 1 AND 16384),
    created_at timestamptz NOT NULL DEFAULT now(),
    -- when the text last changed; NULL when it never has
    edited_at timestamptz
);

-- An observable's comments in order, and the join from an alert's observables (5.8's alert view).
CREATE INDEX observable_comments_by_observable
    ON analysis.observable_comments (type, value_hash, created_at, id);
CREATE INDEX observable_comments_by_author ON analysis.observable_comments (author_id);
