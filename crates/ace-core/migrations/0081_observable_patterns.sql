-- The Observable Pattern alert filter's indexes (PLAN.md decision 39), ace3's `i_obs_value` and
-- `i_obs_value_rev` (its migration 87cae96b23b0, c9114508 and b525e575): a pattern that starts with
-- text is a range of the first, on the start of the value, and one that starts with `*` and ends with
-- text a range of the second, on the end of the value reversed (`ace_service::filters::patterns`).
-- Each holds 255 characters, as ace3's `value_rev` holds 255 bytes, so an entry stays far under a btree
-- row's limit whatever the value's length; a longer run of text is checked against the whole value. "C"
-- compares by byte, so LIKE's prefix is a range of the index.
--
-- Each CREATE INDEX holds a SHARE lock on the table while it builds, so writes to observables wait
-- for it (reads don't). It waits at most 5 seconds for that lock, as ace3's ALTERs wait for their
-- metadata lock: while it waits, every later write queues behind it, so a transaction holding the
-- table that long fails the migration rather than stopping the core's writes. ace3 then tries again,
-- 12 times; here the migration fails and runs again on the next start.
SET LOCAL lock_timeout = '5s';

CREATE INDEX observables_by_value_start
    ON analysis.observables ((left(value, 255) COLLATE "C"));

CREATE INDEX observables_by_value_end
    ON analysis.observables ((left(reverse(value), 255) COLLATE "C"));
