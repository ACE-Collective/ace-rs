-- The saved filters a person new to a screen starts with (PLAN.md 7.13): ace3's `Last 24h` and `Last 7d`
-- on the alert list, which `ace_service`'s `seed_saved_filters` writes when the list is first drawn for them.
--
-- ace3 seeds a user who has no `saved_filters` row of any kind on the screen, and its page writes the
-- user's working row straight after, so it seeds once. ace4 keeps no working row (0030), so this table is
-- what says a screen was seeded for a user: someone who deletes the two filters doesn't get them back.
-- Like a saved filter, a row goes with its user.
CREATE TABLE service.saved_filter_seeds (
    user_id uuid NOT NULL REFERENCES service.users ON DELETE CASCADE,
    screen text NOT NULL CHECK (screen ~ '^[a-z][a-z0-9_]{0,31}$'),
    seeded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, screen)
);
