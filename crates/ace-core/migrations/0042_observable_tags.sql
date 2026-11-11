-- The tags analysts map to an observable (PLAN.md 7.6), which `user_defined_tagging` adds to that
-- observable in every alert, through the core's `observable-tags` read (`reads.md`). ace3 keeps them in
-- its `observable_tag_mapping` and `tags` tables, keyed by its index of every observable (type and the
-- sha256 of the value). ace4 has no such index, so a mapping holds the type and value itself, matched as
-- 5.6's observable comments are: by type, value_hash and value.
--
-- Nothing in ace3 writes these rows but its tests and its unused `add_observable_tag_mapping`, so
-- nothing here does either: a site fills the table itself, and tests/e2e/run does with SQL.
CREATE TABLE analysis.observable_tags (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type text NOT NULL,
    value text NOT NULL,
    value_hash bytea NOT NULL GENERATED ALWAYS AS (analysis.value_hash(value)) STORED,
    tag text NOT NULL CHECK (length(tag) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (type, value_hash, tag)
);

CREATE INDEX observable_tags_by_observable ON analysis.observable_tags (type, value_hash, id);
