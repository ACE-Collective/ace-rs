-- Who can authenticate (PLAN.md 5.4): users, API keys and GUI sessions. Only `ace-service`'s `auth`
-- module writes these.
--
-- A key's or a session's secret is stored as the SHA-256 of its whole token, so a copy of this table
-- authenticates nobody. A password is an Argon2id hash in PHC form, and the CHECK refuses anything else,
-- so a plaintext can't land here by mistake. Moving users from ace3 (PLAN.md's Deferred) has bcrypt and
-- werkzeug hashes, and would change that CHECK on purpose.
--
-- Usernames follow one rule, as permission names do: ASCII and lowercase, in the type and here. This
-- charset is `auth::Username`'s: keep the two the same. email, display name, timezone and queue are
-- ace3's too, and come with the users router (5.6), which is what reads them.
CREATE DOMAIN service.username AS text CHECK (VALUE ~ '^[a-z0-9_.@+-]{1,64}$');

CREATE TABLE service.users (
    id uuid PRIMARY KEY,
    username service.username NOT NULL UNIQUE,
    password_hash text NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by service.actor NOT NULL
);

-- A key with no owner stands for a service, as ace3's config keys do. A key goes when its owner does, as
-- in ace3. A revoked key's row is deleted, also as in ace3, and its audit row keeps what it was. ace3's
-- keys don't expire, so these don't.
CREATE TABLE service.api_keys (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    owner_id uuid REFERENCES service.users ON DELETE CASCADE,
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by service.actor NOT NULL
);

CREATE INDEX api_keys_by_owner ON service.api_keys (owner_id) WHERE owner_id IS NOT NULL;

-- ace3's session is a signed cookie, so it can't be revoked. A row here can be.
CREATE TABLE service.sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES service.users ON DELETE CASCADE,
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX sessions_by_user ON service.sessions (user_id);

-- The holders 0020 left without a foreign key. A grant is part of its holder and goes with it. What
-- records an actor is history and stays with no foreign key: `permissions.created_by`,
-- `roots.dispositioned_by` and all of `service.audit`. So deleting a user removes what they could do and
-- nothing about what they did. Rows naming a holder that doesn't exist make this migration fail: nothing
-- but a test could have written one, and an error says more than deleting them would.
ALTER TABLE service.permissions
    ADD CONSTRAINT permissions_user_exists
        FOREIGN KEY (user_id) REFERENCES service.users ON DELETE CASCADE,
    ADD CONSTRAINT permissions_api_key_exists
        FOREIGN KEY (api_key_id) REFERENCES service.api_keys ON DELETE CASCADE;

ALTER TABLE service.group_members
    ADD CONSTRAINT group_members_user_exists
        FOREIGN KEY (user_id) REFERENCES service.users ON DELETE CASCADE;

-- The component `ace user create-first` acts as. It makes the first user, so this row is what lets it
-- past the gate, and it's the only grant a component holds that no person made.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('bootstrap', 'user', 'write', 'allow', '{"kind": "internal", "id": "migration"}');
