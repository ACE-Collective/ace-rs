-- ace3's core table `sandbox_submissions` (its migration 1d4acd96cba8, model `SandboxSubmission`): the
-- files a sandbox module sent to a sandbox, one row per file and sandbox, so a second alert with the
-- same file waits on or reuses the first's analysis, and a daily cap counts what was sent (PLAN.md
-- decision 50). a site's ExampleSandbox module is its one user. Only the core writes it, through the
-- `sandbox-submission` write a module's task end carries, and a module reads it through the
-- `sandbox-submission` read.
CREATE TABLE analysis.sandbox_submissions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    -- ace3's `sandbox_type`, such as `example_sandbox`
    sandbox_type text NOT NULL CHECK (sandbox_type ~ '^[a-z0-9_-]{1,64}$'),
    -- the sandbox's own id for it, such as ExampleSandbox's sample id
    external_id text CHECK (char_length(external_id) <= 256),
    verdict text CHECK (char_length(verdict) <= 64),
    score integer,
    -- false for a row recorded because the sandbox already knew the file, which spent none of its
    -- quota: the daily cap counts only what was sent (the owner's M1 answer of 2026-11-22), where
    -- ace3 counts every row
    submitted boolean NOT NULL,
    submitted_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (sha256, sandbox_type)
);

-- the daily cap's count
CREATE INDEX sandbox_submissions_sent ON analysis.sandbox_submissions (sandbox_type, submitted_at)
    WHERE submitted;
