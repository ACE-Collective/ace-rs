-- The alert tree (PLAN.md 2.4): roots, the observables in them and the results modules write
-- about the observables. Each result is its own row, so modules for one root write in parallel
-- without a lock on the root.

-- Where a root's event time came from (ace3 #850): the event itself, a hunt's query time, or
-- the time ACE substituted because it had none. `unset` has no time.
CREATE TYPE analysis.event_time_source AS ENUM ('event', 'query_time', 'now', 'unset');

CREATE TABLE analysis.roots (
    id uuid PRIMARY KEY,
    -- Names the module groups that run on the root, as ace3's analysis_mode.
    analysis_mode text NOT NULL,
    description text NOT NULL DEFAULT '',
    event_time timestamptz,
    event_time_source analysis.event_time_source NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT event_time_has_a_source CHECK ((event_time IS NULL) = (event_time_source = 'unset'))
);

-- The sha256 of an observable's value. Values can be longer than a btree entry allows, such as
-- a data: URL, so uniqueness is on the hash. The database's encoding is UTF8, so the conversion
-- is the identity and the function is as immutable as it says.
CREATE FUNCTION analysis.value_hash(value text) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN sha256(convert_to(value, 'UTF8'));

-- `existing` with the items of `added` it doesn't have yet appended, in their order.
CREATE FUNCTION analysis.merged(existing text[], added text[]) RETURNS text[]
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN existing || ARRAY(
        SELECT item FROM unnest(added) WITH ORDINALITY AS a(item, n)
        WHERE item <> ALL (existing)
        GROUP BY item ORDER BY min(n)
    );

CREATE TABLE analysis.observables (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    root_id uuid NOT NULL REFERENCES analysis.roots (id) ON DELETE CASCADE,
    -- An ObservableKind's name, such as ipv4 or file. A file's value is its sha256 in hex.
    type text NOT NULL,
    value text NOT NULL,
    value_hash bytea NOT NULL GENERATED ALWAYS AS (analysis.value_hash(value)) STORED,
    time timestamptz,
    tags text[] NOT NULL DEFAULT '{}',
    directives text[] NOT NULL DEFAULT '{}',
    -- Modules that must not analyze the observable, as ace3's exclude_analysis.
    exclude_modules text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    -- One observable per (root, type, value): adding it again merges into the first.
    CONSTRAINT observables_one_per_value UNIQUE (root_id, type, value_hash),
    -- For foreign keys that also name the root.
    CONSTRAINT observables_in_root UNIQUE (root_id, id)
);

CREATE TABLE analysis.results (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    root_id uuid NOT NULL,
    observable_id bigint NOT NULL,
    -- The module's key, which a named instance of a module (PLAN.md 2.23) will also fit.
    module text NOT NULL,
    -- Stored under the analysis type's name and schema version, never a code path.
    analysis_type text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version >= 1),
    details jsonb NOT NULL,
    summary text,
    tags text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (root_id, observable_id)
        REFERENCES analysis.observables (root_id, id) ON DELETE CASCADE,
    CONSTRAINT results_one_per_module UNIQUE (root_id, observable_id, module)
);

-- Queries that reach into details, such as `details @> '{"rule": "x"}'` or `details ? 'key'`.
CREATE INDEX results_details ON analysis.results USING gin (details);
CREATE INDEX results_analysis_type ON analysis.results (analysis_type);
