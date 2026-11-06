-- What a result says about how observables relate (PLAN.md 3.1). A target is named by type and
-- value, as the result names it, because it may be an observable the same result adds.

-- The observable this one stands in for, such as the Office document a part came out of: ace3's
-- `redirection`. Modules that act on the part act on this observable instead.
ALTER TABLE analysis.observables
    ADD COLUMN redirection_type text,
    ADD COLUMN redirection_value text,
    ADD CONSTRAINT redirection_is_whole
        CHECK ((redirection_type IS NULL) = (redirection_value IS NULL));

CREATE TABLE analysis.relationships (
    root_id uuid NOT NULL,
    observable_id bigint NOT NULL,
    -- A RelationshipKind's name, such as extracted_from.
    kind text NOT NULL,
    target_type text NOT NULL,
    target_value text NOT NULL,
    -- Values can be longer than a btree entry allows, as in analysis.observables.
    target_value_hash bytea NOT NULL GENERATED ALWAYS AS (analysis.value_hash(target_value)) STORED,
    PRIMARY KEY (root_id, observable_id, kind, target_type, target_value_hash),
    FOREIGN KEY (root_id, observable_id)
        REFERENCES analysis.observables (root_id, id) ON DELETE CASCADE
);
