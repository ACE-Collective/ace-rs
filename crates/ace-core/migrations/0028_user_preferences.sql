-- ace3's `user_preferences` router (PLAN.md 5.6, 5.7): a user's durable GUI settings, a value per key.
-- `ace-service`'s `preferences` module checks each key's value, as ace3's schemas do, and a key it doesn't
-- know is never written. 5.7 brings `theme`; 5.8 and 5.10 add theirs.
--
-- A row is the user's own, so it goes with the user, as a grant does. It isn't a record of an actor: its
-- audit rows are.
CREATE TABLE service.user_preferences (
    user_id uuid NOT NULL REFERENCES service.users ON DELETE CASCADE,
    key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{0,63}$'),
    value jsonb NOT NULL CHECK (jsonb_typeof(value) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);
