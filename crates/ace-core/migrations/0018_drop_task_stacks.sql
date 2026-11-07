-- 0016's column held what py-spy saw in a hung Python worker. PLAN.md 4.13 removed the Python pool
-- and py-spy with it, so nothing writes or reads the column.
ALTER TABLE queue.tasks DROP COLUMN stacks;
