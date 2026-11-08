-- Analyst-edited lists (PLAN.md 5.14, ace3 #1063 and #1064): whitelists and the like, in place of ace3's
-- file-watched settings and `saq/whitelist.py`'s brotex whitelist. One table holds every list's entries,
-- each typed by how it matches (`ace_sdk::lists`). Which lists exist is the binary's: each is one its
-- modules read, so a name here isn't checked against anything but its form.
--
-- The service writes the entries, with its permission check and audit row. The core reads them for a
-- module's leased task (`ace_core::lists`), and every committed write raises `lists.version` in the
-- write's own transaction, so a task leased after an edit commits sees a version at least that new and
-- never a list older than it.

CREATE SCHEMA lists;

CREATE TABLE lists.entries (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    list text NOT NULL CHECK (list ~ '^[a-z0-9_]{1,64}$'),
    match text NOT NULL CHECK (match IN ('exact', 'substring', 'regex')),
    -- The value, or the pattern. The service checks a pattern compiles before it stores one, and the
    -- lengths are `ace_sdk::lists`' limits.
    value text NOT NULL CHECK (
        length(value) >= 1
        AND octet_length(value) <= CASE WHEN match = 'regex' THEN 1024 ELSE 4096 END),
    ignore_case boolean NOT NULL,
    -- On a typed list, the observable type the entry applies to.
    observable_type text,
    note text NOT NULL DEFAULT '' CHECK (length(note) <= 1024),
    -- After this it matches nothing; NULL never expires.
    expires_at timestamptz,
    created_by service.actor NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_by service.actor NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT entries_are_unique UNIQUE NULLS NOT DISTINCT
        (list, observable_type, match, ignore_case, value)
);

CREATE INDEX entries_by_list ON lists.entries (list, id);

-- One row: the version of every list together. A write locks it first, so writes to the lists take
-- turns and a list's count is checked against what's committed.
CREATE TABLE lists.version (
    one boolean PRIMARY KEY DEFAULT true CHECK (one),
    version bigint NOT NULL
);

INSERT INTO lists.version (version) VALUES (1);

CREATE FUNCTION lists.bump_version() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    UPDATE lists.version SET version = version + 1;
    RETURN NULL;
END
$$;

-- Any write to an entry, however it's made, raises the version once per statement.
CREATE TRIGGER entries_bump_version
    AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON lists.entries
    FOR EACH STATEMENT EXECUTE FUNCTION lists.bump_version();
