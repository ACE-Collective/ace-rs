-- The yara_qa router (PLAN.md 5.6) lists the rules in QA mode in the current ruleset, including
-- those that never matched, as ace3 lists them from its rule inventory. The manifest of PLAN.md
-- 1.6 now records them: [{namespace, path, name, uuid, enabled, tags}]. NULL is a row built before
-- this column, which the builder fills in on its next run by building that commit again.
ALTER TABLE yara.rulesets ADD COLUMN qa_rules jsonb;

-- A rule's matches, newest first, and its counts per version.
CREATE INDEX qa_matches_by_rule ON yara.qa_matches (signature_uuid, id DESC);
