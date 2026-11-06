-- What py-spy saw in a hung Python worker before its supervisor killed it (PLAN.md 4.3), beside
-- the error and the input hashes that a failed task's row already keeps. It's a column of its own
-- because `error` is read wherever a failed task is listed, and stacks run to tens of KB. The pool
-- caps it, and it is text from a hostile process, so nothing should read it as more than text.
ALTER TABLE queue.tasks ADD COLUMN stacks text;
