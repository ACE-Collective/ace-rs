-- The gate before the hooks task is queued on SVS's account (PLAN.md 7.10 batch 7b, the owner's decision
-- of 2026-11-14).

-- The SVS hook is due at the end of this pass, and no other hook is: set where `hooks_due` would be, in a
-- mode whose only hook is `svs_alert_tagger`. NULL when it isn't due. The value is the hook's
-- `attribution_extra` in seconds (`svs.runs.attribution_extra_hours`), which the gate reads and
-- `queue::check_completion`, which has no configuration, can't. When the root's last task ends and this is
-- set, the hooks task is queued only while the gate is open (`ace_core::svs::attribution::gate_open`), so a
-- pass with no run registered and no maintenance window open lately queues none for SVS.
ALTER TABLE analysis.roots ADD COLUMN svs_gate_extra_seconds bigint;
