-- YARA rulesets (PLAN.md 2.25): one row per commit of the signatures repository the core built,
-- with the manifest of PLAN.md 1.6 (ace3 #1051: nothing recorded what a ruleset held). The
-- serialized ruleset is in the bucket's yara_rulesets pool under its key, the sha256 of its bytes.
-- Two commits whose signature directory is the same tree build the same bytes, so they share a
-- key and have a row each.
CREATE SCHEMA yara;

CREATE TABLE yara.rulesets (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key text NOT NULL CHECK (key ~ '^[0-9a-f]{64}$'),
    commit text NOT NULL,
    -- git's id of the signature directory's tree at the commit.
    tree text NOT NULL,
    -- The sha256 over every rule file's namespace, path and bytes.
    sources_sha256 text NOT NULL,
    yara_x_version text NOT NULL,
    -- [{namespace, path, rules}]: the files whose rules are in the ruleset.
    files jsonb NOT NULL,
    -- [{namespace, path, error}]: the files left out, with why.
    left_out jsonb NOT NULL,
    built_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT rulesets_one_per_commit UNIQUE (commit, yara_x_version)
);

-- A new commit whose tree was built before reuses that build.
CREATE INDEX rulesets_by_tree ON yara.rulesets (tree, yara_x_version);
