-- SVS's YARA validations (PLAN.md 7.10 batch 3): ace3's `svs_validations` and `svs_validation_results`. A
-- validation replays every stored sample under two commits of a rule repository and keeps what the change
-- does to them. It waits here as `queued`, a worker of `ace serve` takes it under a lease and runs it
-- (`ace_core::svs::validations`), and its report and its rows are written in one transaction. Only that
-- module writes these tables.
--
-- What differs from ace3's:
-- - Who asked is a `service.actor`, where ace3 stores a user id, so a key with no owner may ask.
-- - The counts and the report are jsonb, where ace3 stores JSON text, and times are timestamptz.
-- - Lease times come from the database's clock, as in ace3: `heartbeat_at` is `clock_timestamp()`.

CREATE TYPE svs.validation_state AS ENUM ('queued', 'running', 'completed', 'failed');

CREATE TABLE svs.validations (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uuid uuid NOT NULL UNIQUE,
    -- A name in the overlay's `svs.yara.repositories`.
    repository text NOT NULL CHECK (length(repository) BETWEEN 1 AND 256),
    -- Full commit ids, lower case: an abbreviation would make two requests for one commit differ.
    base_sha text NOT NULL CHECK (base_sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    head_sha text NOT NULL CHECK (head_sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    branch text NOT NULL CHECK (length(branch) BETWEEN 1 AND 256),
    pr_url text CHECK (length(pr_url) <= 2048 AND pr_url ~ '^https?://'),
    requested_by service.actor NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    state svs.validation_state NOT NULL DEFAULT 'queued',
    -- Set while it's queued or running, so one request shares another's validation: the sha256 of the
    -- JSON `[repository, base_sha, head_sha]`, as ace3 computes it.
    active_key text UNIQUE CHECK (active_key ~ '^[0-9a-f]{64}$'),
    claim_token uuid,
    claimed_by text,
    heartbeat_at timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    started_at timestamptz,
    finished_at timestamptz,
    error text,
    -- What the samples and their labels were, and what decided the results, when it ran: a completed
    -- validation answers a later request while both are the same.
    corpus_version text,
    engine_fingerprint text,
    -- Pairs per category, every category included, and the report without its rows.
    counts jsonb,
    report jsonb,
    regressions integer,
    new_fps integer,
    compile_errors integer,
    diffed boolean,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT validations_finish_once CHECK (
        (state IN ('completed', 'failed')) = (finished_at IS NOT NULL)),
    CONSTRAINT validations_run_under_a_claim CHECK (
        (state = 'running') = (claim_token IS NOT NULL)),
    CONSTRAINT validations_wait_with_a_key CHECK (
        (state IN ('queued', 'running')) = (active_key IS NOT NULL))
);

CREATE INDEX validations_by_creation ON svs.validations (created_at DESC, id DESC);
CREATE INDEX validations_claimable ON svs.validations (created_at, id) WHERE state IN ('queued', 'running');
CREATE INDEX validations_finished ON svs.validations (finished_at) WHERE finished_at IS NOT NULL;
CREATE INDEX validations_cached ON svs.validations (repository, base_sha, head_sha)
    WHERE state = 'completed';
CREATE INDEX validations_by_update ON svs.validations (updated_at, id);

CREATE TRIGGER validations_touch BEFORE UPDATE ON svs.validations
    FOR EACH ROW EXECUTE FUNCTION svs.touch();

-- One (sample, rule uuid) pair a validation's report lists, with the sample's label when it ran. Deleting a
-- sample (batch 2's delete) removes its rows from every report.
CREATE TABLE svs.validation_results (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    validation_id bigint NOT NULL REFERENCES svs.validations (id) ON DELETE CASCADE,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    rule_uuid text NOT NULL CHECK (length(rule_uuid) BETWEEN 1 AND 256),
    rule_name text NOT NULL CHECK (length(rule_name) <= 256),
    namespace text CHECK (length(namespace) <= 256),
    label text CHECK (label IN ('tp', 'fp', 'conflicted')),
    label_source text CHECK (label_source IN ('explicit', 'inherited_single', 'inherited_multi')),
    -- The outcome under each commit: `match` (the rule would make a detection), `miss` or `error`.
    base text NOT NULL CHECK (base IN ('match', 'miss', 'error')),
    head text NOT NULL CHECK (head IN ('match', 'miss', 'error')),
    -- Whether the rule matched at all, before `enabled` and the qa and no_alert modifiers.
    raw_base boolean NOT NULL,
    raw_head boolean NOT NULL,
    category text NOT NULL CHECK (length(category) BETWEEN 1 AND 64),
    note text
);

CREATE INDEX validation_results_by_validation ON svs.validation_results (validation_id, id);
CREATE INDEX validation_results_by_sha256 ON svs.validation_results (sha256);

-- ace3's daily `svs-validations-prune` (PLAN.md 6.7), as the scheduler's `svs_validations_prune`: it
-- removes the finished validations older than `svs.yara.retention_days`, with their rows.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('scheduler:svs_validations_prune', 'svs', 'validation_prune', 'allow',
        '{"kind": "internal", "id": "migration"}');
