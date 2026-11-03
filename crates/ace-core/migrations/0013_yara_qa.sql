-- YARA QA (PLAN.md 2.27): the files rules in QA mode matched, as ace3's yara_qa_matches. A QA
-- match never alerts; the result that holds it queues a yara_qa task, and the core's recorder
-- writes a row here and holds the file, which is already in the bucket's alert_files pool,
-- until the row expires. There is no foreign key to the root: a row outlives its root, as in
-- ace3, and its hold keeps the file.
CREATE TABLE yara.qa_matches (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    signature_uuid text NOT NULL,
    -- The commit of the rule's repository, or 'unknown', as a detection's signature version.
    signature_version text NOT NULL,
    rule text NOT NULL,
    namespace text NOT NULL,
    -- The key of the ruleset the rule came from, when the scan used one the core built.
    ruleset text,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    -- The file's path inside the alert when it last matched.
    file_path text NOT NULL,
    root_id uuid NOT NULL,
    observable_id bigint NOT NULL,
    -- The scan result of the match, as the YARA module wrote it.
    match jsonb NOT NULL,
    hit_count integer NOT NULL DEFAULT 1,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    -- One row per file per rule version; a new match of it renews the row.
    CONSTRAINT qa_matches_one_per_file UNIQUE (signature_uuid, signature_version, sha256)
);

CREATE INDEX qa_matches_expires ON yara.qa_matches (expires_at);
