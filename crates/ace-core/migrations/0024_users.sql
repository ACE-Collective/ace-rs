-- The users router (PLAN.md 5.6): ace3's profile fields, which its management page and a user's own
-- preferences edit. A display name and an email are optional, as ace3's display name is; ace3 requires
-- an email, which ace4 doesn't use for anything yet. A timezone is an IANA name, which `ace-service`
-- checks against chrono-tz's list. ace3's `queue` waits for alerts to have queues.
ALTER TABLE service.users
    ADD COLUMN display_name text CHECK (length(display_name) BETWEEN 1 AND 1024),
    ADD COLUMN email text CHECK (length(email) BETWEEN 3 AND 255),
    ADD COLUMN timezone text NOT NULL DEFAULT 'UTC' CHECK (length(timezone) BETWEEN 1 AND 64);

-- ace3's group names are `String(255)`.
ALTER TABLE service.groups
    ADD CONSTRAINT groups_name_length CHECK (length(name) BETWEEN 1 AND 255);
