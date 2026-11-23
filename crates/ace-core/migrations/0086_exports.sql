-- Detection exports (PLAN.md decision 58): `ace export <name>`, a process that publishes the observables
-- enabled for detection to a system outside ACE, ace3's `observable_export_<name>` targets run by its
-- `export-observables` cron job (`ace_app::export`, `ace_service`'s `exports`).
CREATE SCHEMA export;

-- What each export last published, ace3's state file `var/observable_export/<name>.json`: the
-- fingerprint of the list it last published, and the export's own record, one JSON document, such as
-- which of its files landed and when. ace3's file is on one node; this row is shared by every replica, and
-- its lease keeps two of them from publishing at once.
CREATE TABLE export.targets (
    -- The export's name, as `ace export` is given it.
    name text PRIMARY KEY CHECK (name ~ '^[a-z0-9_.-]{1,64}$'),
    -- The fingerprint of the last list a publish took in full; null until one has.
    fingerprint text,
    -- The export's own record, which it reads before a publish and writes after, landed or not.
    state jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(state) = 'object'
                                             AND octet_length(state::text) <= 1048576),
    -- Who holds the pass, and until when: a process that died lets go when its lease ends.
    lease_owner text,
    lease_expires_at timestamptz,
    published_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT targets_lease_whole CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL))
);

-- Every export acts as `export:<name>` and holds what the class `export` is granted
-- (`ace_service::Component::class`), since a site names its exports in its own binary: reading the
-- detections and its own record, and nothing else. A deny on one export's own component still wins.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('export', 'detection', 'read', 'allow', '{"kind": "internal", "id": "migration"}'),
       ('export', 'export', 'record', 'allow', '{"kind": "internal", "id": "migration"}');
