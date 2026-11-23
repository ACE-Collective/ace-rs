-- Events (PLAN.md 5.11's events area, sub-item 6a): ace3's `events` table and what it refers to, the alerts
-- in each event, and the malware, threat types and campaigns an analyst records on one. ace3's model is
-- `saq/database/model.py`'s `Event`, `EventMapping`, `MalwareMapping`, `Malware`, `Threat`, `ThreatType`
-- and `Campaign`.
--
-- An event's status, remediation, type, vector, risk level and prevention tool are each a row in a small
-- table, seeded with ace3's values from `saq/database/seed.py` in ace3's order, as ace3 seeds them. They're
-- rows rather than enums because a site adds its own, as an ace3 site does in its database. Nothing here
-- writes them yet; a site adds a row by hand.
--
-- Left out of ace3's model:
-- - `company` and `company_mapping`: roots have no company here (PLAN.md 5.6's `common` note).
-- - The event's `wiki` (always empty in ace3) and `alert_versions` (ace-rs has no version token).
-- - The roll-up disposition is computed from the alerts when an event is read, as ace3's
--   `Event.disposition` property is. It isn't a column.
CREATE SCHEMA events;

CREATE TABLE events.statuses (
    id smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    value text NOT NULL UNIQUE CHECK (length(value) BETWEEN 1 AND 50)
);
CREATE TABLE events.remediations (
    id smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    value text NOT NULL UNIQUE CHECK (length(value) BETWEEN 1 AND 50)
);
CREATE TABLE events.types (
    id smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    value text NOT NULL UNIQUE CHECK (length(value) BETWEEN 1 AND 50)
);
CREATE TABLE events.vectors (
    id smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    value text NOT NULL UNIQUE CHECK (length(value) BETWEEN 1 AND 50)
);
CREATE TABLE events.risk_levels (
    id smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    value text NOT NULL UNIQUE CHECK (length(value) BETWEEN 1 AND 50)
);
CREATE TABLE events.prevention_tools (
    id smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    value text NOT NULL UNIQUE CHECK (length(value) BETWEEN 1 AND 50)
);

-- ace3's seed, in its order: a new event in ace3 takes the first row by id of each, but the risk level,
-- which it takes first by value ("0").
INSERT INTO events.statuses (value) VALUES ('OPEN'), ('CLOSED'), ('IGNORE');
INSERT INTO events.remediations (value) VALUES
    ('not remediated'), ('cleaned with antivirus'), ('cleaned manually'), ('reimaged'),
    ('credentials reset'), ('removed from mailbox'), ('network block'), ('domain takedown'), ('NA'),
    ('escalated');
INSERT INTO events.types (value) VALUES
    ('phish'), ('recon'), ('host compromise'), ('credential compromise'), ('web browsing'), ('pentest'),
    ('third party'), ('large number of customer records'), ('public media');
INSERT INTO events.vectors (value) VALUES
    ('corporate email'), ('webmail'), ('usb'), ('website'), ('unknown'), ('business application'),
    ('compromised website'), ('sms'), ('vpn');
INSERT INTO events.risk_levels (value) VALUES ('1'), ('2'), ('3'), ('0');
INSERT INTO events.prevention_tools (value) VALUES
    ('response team'), ('ips'), ('fw'), ('proxy'), ('antivirus'), ('email filter'),
    ('application whitelisting'), ('user'), ('edr');

-- ace3's `campaign`, which its GUI calls the threat actor. A name is unique here: ace3's edit looks a
-- campaign up by its name before it makes one, so two of a name were never meant.
CREATE TABLE events.campaigns (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128)
);

-- ace3's `threat_type`, seeded with ace3's list, and its `threats` router's writes.
CREATE TABLE events.threat_types (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 256)
);
INSERT INTO events.threat_types (name) VALUES
    ('unknown'), ('keylogger'), ('infostealer'), ('downloader'), ('botnet'), ('rat'), ('ransomware'),
    ('rootkit'), ('fraud'), ('customer threat'), ('wiper'), ('traffic direction system'),
    ('advanced persistent threat');

-- ace3's `malware`, a name an analyst gives an event's threat. Unique, as ace3's edit looks it up by name.
CREATE TABLE events.malware (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128)
);

-- ace3's `malware_threat_mapping`, the `threats` router's rows. As in ace3, a threat type in use can't be
-- deleted, and a malware's go with it.
CREATE TABLE events.malware_threats (
    malware_id integer NOT NULL REFERENCES events.malware ON DELETE CASCADE,
    threat_type_id integer NOT NULL REFERENCES events.threat_types,
    PRIMARY KEY (malware_id, threat_type_id)
);
CREATE INDEX malware_threats_by_threat_type ON events.malware_threats (threat_type_id);

CREATE TABLE events.events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uuid uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    -- the day of the event's first alert, or the day it was made, as ace3 sets it
    creation_date date NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    status_id smallint NOT NULL REFERENCES events.statuses,
    remediation_id smallint NOT NULL REFERENCES events.remediations,
    type_id smallint NOT NULL REFERENCES events.types,
    vector_id smallint NOT NULL REFERENCES events.vectors,
    risk_level_id smallint NOT NULL REFERENCES events.risk_levels,
    prevention_tool_id smallint NOT NULL REFERENCES events.prevention_tools,
    campaign_id integer REFERENCES events.campaigns ON DELETE SET NULL,
    -- ace3's is MySQL's TEXT, 65535 bytes
    comment text CHECK (length(comment) <= 65535),
    event_time timestamptz,
    alert_time timestamptz,
    ownership_time timestamptz,
    disposition_time timestamptz,
    contain_time timestamptz,
    remediation_time timestamptz,
    owner_id uuid REFERENCES service.users ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- ace3's unique key: adding alerts to a new event of a name on its day adds them to that one
    CONSTRAINT event_names_are_unique_per_day UNIQUE (creation_date, name)
);
CREATE INDEX events_by_status ON events.events (status_id, id);

-- ace3's `malware_mapping`: the malware recorded on an event.
CREATE TABLE events.event_malware (
    event_id bigint NOT NULL REFERENCES events.events ON DELETE CASCADE,
    malware_id integer NOT NULL REFERENCES events.malware ON DELETE CASCADE,
    PRIMARY KEY (event_id, malware_id)
);
CREATE INDEX event_malware_by_malware ON events.event_malware (malware_id);

-- ace3's `event_mapping`: the alerts in an event. An alert can be in more than one, as in ace3, and an
-- alert that's deleted leaves its events.
CREATE TABLE events.event_alerts (
    event_id bigint NOT NULL REFERENCES events.events ON DELETE CASCADE,
    root_id uuid NOT NULL REFERENCES analysis.roots ON DELETE CASCADE,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, root_id)
);
CREATE INDEX event_alerts_by_root ON events.event_alerts (root_id);

-- ace3's `event_tag_mapping`: tags an analyst puts on the event itself, apart from its alerts' tags.
CREATE TABLE events.event_tags (
    event_id bigint NOT NULL REFERENCES events.events ON DELETE CASCADE,
    tag text NOT NULL CHECK (length(tag) BETWEEN 1 AND 256),
    PRIMARY KEY (event_id, tag)
);
