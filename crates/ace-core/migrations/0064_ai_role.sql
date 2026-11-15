-- The AI investigation API's database role (PLAN.md 7.15). `ace serve-ai` is a process of its own, as
-- ace3's `http-api-ai` container is, and it connects as a role that can do what the API does and
-- nothing else: read alerts, events and the search index, check an API key and its grants, write an
-- audit row, and keep the rate limiter's counts. `ace serve-ai` checks what its role can do when it
-- starts (`ace_app::ai::custody`), and stops if the role can do more than this file grants.
--
-- `ace4_ai` can't log in. A deployment makes a role that can, as a member of it:
--
--     CREATE ROLE ace4_ai_login LOGIN PASSWORD '...' IN ROLE ace4_ai;
--
-- which Compose's `ai-role` service does. A role is the whole server's, not one database's, so the
-- role may be there already; the grants are this database's. Where the migrating role may not create
-- roles, the role has to be made first, by someone who may: until it is, this grants nothing, and
-- `ace serve-ai` can't connect.
--
-- A later migration that adds a table the AI API reads grants it here the same way, inside the same
-- check that the role exists.
DO $$
BEGIN
    BEGIN
        CREATE ROLE ace4_ai NOLOGIN;
    EXCEPTION
        -- another database on this server made it, perhaps just now
        WHEN duplicate_object OR unique_violation THEN NULL;
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'the role ace4_ai was not created: the migrating role may not create roles';
    END;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ace4_ai') THEN
        RETURN;
    END IF;

    GRANT USAGE ON SCHEMA ai, analysis, events, search, service, svs TO ace4_ai;

    -- which migration the database is at, so the process can refuse a schema it wasn't built for
    GRANT SELECT ON public._sqlx_migrations TO ace4_ai;

    -- the rate limiter's state, the only rows the API changes
    GRANT SELECT, INSERT, UPDATE, DELETE ON ai.inflight, ai.windows TO ace4_ai;

    -- one audit row for each answer: written, never read, changed or removed
    GRANT INSERT ON service.audit TO ace4_ai;

    -- who is calling: an API key by the hash of its token, its owner, and what each holds. Of a
    -- user, the name, whether they are enabled and their queue: no password hash. No session.
    GRANT SELECT ON service.api_keys, service.permissions, service.group_members TO ace4_ai;
    GRANT SELECT (id, username, display_name, enabled, queue) ON service.users TO ace4_ai;

    -- alerts and events, as the component `ai_api` reads them (migration 0062)
    GRANT SELECT ON
        analysis.roots, analysis.observables, analysis.detections, analysis.detection_verdicts,
        analysis.results, analysis.relationships, analysis.files
        TO ace4_ai;
    GRANT SELECT ON
        events.events, events.event_alerts, events.event_tags, events.event_malware,
        events.malware, events.malware_threats, events.campaigns, events.remediations,
        events.prevention_tools, events.risk_levels, events.statuses, events.threat_types,
        events.types, events.vectors
        TO ace4_ai;
    -- an alert says whether it is an SVS test run's and whether that run is reviewed
    GRANT SELECT ON svs.attributions, svs.runs TO ace4_ai;

    -- the search index, read only: the indexer in `ace serve` writes it
    GRANT SELECT ON search.chunks, search.indexed TO ace4_ai;
END
$$;
