-- When the root's pass in progress began, for the per-root metrics event (`ace_core::metrics`): the
-- event a pass's end emits says how long the pass took, and nothing recorded when it began. A pass
-- begins when work is queued on an idle root (`queue::begin_pass`), which already writes the root's
-- row, so this costs no statement. NULL on a root whose pass began before this migration: its event
-- has no `total_time_seconds`.
ALTER TABLE analysis.roots ADD COLUMN pass_started_at timestamptz;
