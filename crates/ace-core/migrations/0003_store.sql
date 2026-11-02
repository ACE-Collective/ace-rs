-- The bucket's index (PLAN.md 2.5), carried over from ace3's CAS (docs/CAS.md): which objects
-- each pool has and what holds them. The index decides what exists; GC reads it and never
-- lists the bucket.

-- An object is `deleting` from when GC claims it until its bytes and its row are gone.
CREATE TYPE store.object_state AS ENUM ('present', 'deleting');

CREATE TABLE store.objects (
    pool text NOT NULL,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size bigint NOT NULL CHECK (size >= 0),
    -- libmagic's answer when the bytes were first put, from the pinned magic database.
    mime_type text NOT NULL,
    state store.object_state NOT NULL DEFAULT 'present',
    created_at timestamptz NOT NULL DEFAULT now(),
    -- When a hold was last taken or released. An unheld object outlives it by its pool's grace.
    last_held_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (pool, sha256)
);

-- GC's candidate scan.
CREATE INDEX objects_gc ON store.objects (pool, state, last_held_at);

-- A reference that keeps an object in a held pool, such as the root a file belongs to. Taking
-- the same hold again only replaces its expiry.
CREATE TABLE store.holds (
    pool text NOT NULL,
    sha256 text NOT NULL,
    holder_kind text NOT NULL,
    holder_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- NULL holds until it is released.
    expires_at timestamptz,
    PRIMARY KEY (pool, sha256, holder_kind, holder_id),
    FOREIGN KEY (pool, sha256) REFERENCES store.objects (pool, sha256) ON DELETE CASCADE
);

CREATE INDEX holds_by_holder ON store.holds (pool, holder_kind, holder_id);
