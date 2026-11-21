-- What a remediator acted on when it wasn't the action's key, such as the mailbox that owns an alias
-- address: ace3's `remediation_history.resolved_target` (its aaeef15e), kept on each try.
ALTER TABLE queue.action_attempts
    ADD COLUMN resolved_target text CHECK (length(resolved_target) BETWEEN 1 AND 4096);
