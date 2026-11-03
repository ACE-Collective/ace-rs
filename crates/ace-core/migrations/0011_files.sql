-- Files in the alert tree (PLAN.md 2.14). A file observable's value is its sha256, and its bytes
-- are in the bucket's alert_files pool. One file can be in a root under more than one path,
-- such as the same attachment in two emails, so each path is its own row, with the yara_meta
-- tags it came with.
CREATE TABLE analysis.files (
    root_id uuid NOT NULL,
    observable_id bigint NOT NULL,
    -- The file's path inside the alert, such as `evil.zip.extracted/invoice.doc`.
    path text NOT NULL,
    yara_meta text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (root_id, observable_id, path),
    FOREIGN KEY (root_id, observable_id)
        REFERENCES analysis.observables (root_id, id) ON DELETE CASCADE
);
