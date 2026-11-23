-- The deletion of finished roots that never became alerts (PLAN.md decision 56, `ace_core::cleanup`),
-- ace3's `cleanup` of an analysis mode.

-- The cleanup's scan: the roots that aren't alerts, oldest first, by mode. Alerts, which outlive it,
-- aren't in it.
CREATE INDEX roots_not_alerted ON analysis.roots (analysis_mode, created_at, id)
    WHERE alerted_at IS NULL;

-- `ace serve`'s `root_cleanup` task deletes them, and nothing else may.
INSERT INTO service.permissions (component, major, minor, effect, created_by)
VALUES ('scheduler:root_cleanup', 'analysis', 'cleanup', 'allow',
        '{"kind": "internal", "id": "migration"}');
