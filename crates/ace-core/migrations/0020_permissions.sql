-- Permissions (PLAN.md 5.2). ace3 keeps a grant's major and minor in case-insensitive columns and
-- once matched them case-sensitively (#831). Here a part is lowercase in the database too, so a row
-- written outside ace-service's PermissionPattern can't break the rule, and the unique constraint
-- means what a match means. This charset is PermissionPattern's: keep the two the same.
CREATE DOMAIN service.permission_part AS text CHECK (
    VALUE ~ '^[][a-z0-9_.*?!-]+$' AND length(VALUE) <= 512
);

CREATE TYPE service.permission_effect AS ENUM ('allow', 'deny');

-- Groups hold users, as ace3's auth_group_user does. An API key or a component is never in a group.
CREATE TABLE service.groups (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE
);

-- user_id has no foreign key until PLAN.md 5.4 adds the users table.
CREATE TABLE service.group_members (
    group_id uuid NOT NULL REFERENCES service.groups ON DELETE CASCADE,
    user_id uuid NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

-- One table for what ace3 splits into auth_user_permission, auth_group_permission and
-- auth_api_key_permission, plus a component's grants, which ace3 has no table for. A row is one
-- holder's pattern and effect. These tables are tiny, so nothing but the constraint indexes them.
CREATE TABLE service.permissions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id uuid,
    group_id uuid REFERENCES service.groups ON DELETE CASCADE,
    api_key_id uuid,
    component text CHECK (component ~ '^[a-z0-9_.:-]+$'),
    major service.permission_part NOT NULL,
    minor service.permission_part NOT NULL,
    effect service.permission_effect NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by service.actor NOT NULL,
    CONSTRAINT permissions_have_one_holder
        CHECK (num_nonnulls(user_id, group_id, api_key_id, component) = 1),
    CONSTRAINT permissions_are_unique
        UNIQUE NULLS NOT DISTINCT (user_id, group_id, api_key_id, component, major, minor, effect)
);
