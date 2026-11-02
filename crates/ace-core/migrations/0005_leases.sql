-- Leases (PLAN.md 2.7): the reaper's scan for running tasks whose lease has expired.
CREATE INDEX tasks_leases ON queue.tasks (lease_expires_at) WHERE state = 'running';
