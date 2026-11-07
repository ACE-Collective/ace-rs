-- Actors (PLAN.md 5.1): who made a write, as ace-service's Actor type writes it. `kind` and `id` are
-- the identity; a name is what the user or key was called at the time. There's no foreign key to
-- users, because a row has to outlive the user it names. 5.3's audit rows use this domain too.

CREATE SCHEMA service;

-- A CHECK passes on NULL, so `IS TRUE` is what refuses a value with no kind or id.
CREATE DOMAIN service.actor AS jsonb CHECK (
    VALUE IS NULL
    OR ((VALUE ->> 'kind') IN ('user', 'api_key', 'internal') AND length(VALUE ->> 'id') > 0) IS TRUE
);

ALTER TABLE analysis.roots
    ADD COLUMN dispositioned_by service.actor,
    -- Nothing recorded a disposition before this, so no row breaks it.
    ADD CONSTRAINT roots_disposition_has_an_actor
        CHECK ((disposition IS NULL) = (dispositioned_by IS NULL));
