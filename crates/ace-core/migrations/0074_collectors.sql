-- Collectors (PLAN.md 6.1): `ace collect <name>`, a process that reads a source outside ACE and
-- submits roots (`ace_app::collector`, `ace_service`'s `collection`).
CREATE SCHEMA collection;

-- The keys each collector has submitted, ace3's `persistence` rows of a collector's persistence
-- source (`DuplicateSubmissionFilter`): an item whose key a live row holds isn't submitted again. A
-- row is written in the transaction that creates its root, so a key is held exactly when its root
-- exists, and a redelivered item, or a retry after a commit whose answer was lost, finds it.
CREATE TABLE collection.submitted_keys (
    -- The collector's name, as `ace collect` is given it.
    collector text NOT NULL,
    -- sha256 of the key's UTF-8, as ace3 keeps `sha256_str(key)`.
    hash bytea NOT NULL CHECK (length(hash) = 32),
    -- The root it made. Null only inside the transaction that claims the key, which sets it before
    -- it commits. No foreign key, as `hunts.dedup_keys` has none: a key outlives nothing it guards.
    root uuid,
    created_at timestamptz NOT NULL,
    -- When the key stops holding: its collector's `key_lifetime_seconds` after it was made, 4 hours
    -- by default, ace3's `persistence_unmodified_expiration_seconds` (a key is never updated after
    -- it's made, so ace3's 24-hour `persistence_expiration_seconds` never comes first).
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (collector, hash)
);

-- Each submission removes its collector's expired keys first, by this.
CREATE INDEX submitted_keys_by_expiry ON collection.submitted_keys (collector, expires_at);

-- Every collector acts as `collector:<name>` and holds what the class `collector` is granted
-- (`ace_service::Component::class`), since a site names its collectors in its own binary and no
-- migration can name them: submitting roots, and nothing else. A deny on one collector's own
-- component still wins.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('collector', 'alert', 'create', 'allow', '{"kind": "internal", "id": "migration"}');
