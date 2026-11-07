-- The crashes router (PLAN.md 5.6) lists failed tasks newest first, keyed on when each failed and its
-- id. A failed task is final, so its updated_at is when it failed. Without this the list reads every
-- task the queue has kept.
CREATE INDEX tasks_failed ON queue.tasks (updated_at DESC, id DESC) WHERE state = 'failed';
