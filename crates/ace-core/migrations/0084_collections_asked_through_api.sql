-- A file collection someone asked for through the API, whether they queued it or joined one a
-- module queued (PLAN.md decision 49). A module's `file-collection-release` cancels a collection
-- only when no alert and nobody who asked waits on it. `requested_by` names who queued it and never
-- changes (`actions_keep_their_record`), so a person who joins a module's collection is recorded
-- here.
ALTER TABLE queue.actions ADD COLUMN asked_through_api boolean NOT NULL DEFAULT false;

UPDATE queue.actions SET asked_through_api = true
WHERE kind = 'file_collection' AND requested_by IS NOT NULL;
