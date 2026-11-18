-- The modules' declarations of what they take (PLAN.md decision 23, ace_core::takes). Under the
-- audit setting the core queues every task as before and records here why a declaration would
-- have declined it; NULL when it wouldn't have, and on every task without the setting. A marked
-- task that stores a result or fails is what a declaration would lose.
ALTER TABLE queue.tasks ADD COLUMN declined text;
