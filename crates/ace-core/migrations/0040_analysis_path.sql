-- One analysis per file, on a deterministic path (PLAN.md decision 15). A file is analyzed once per
-- sha256 however many paths it has, and the path it's analyzed under is the one that sorts first by
-- (depth, path), not the one whose result landed first (`tree::choose_analysis_file`).

-- How many results from a submitted observable this one is, by its shortest route: 0 for what the
-- submission added, else one more than the observable whose result added it, the least of those.
ALTER TABLE analysis.observables ADD COLUMN depth integer NOT NULL DEFAULT 0;

-- A path's depth is its file's, by the results that wrote that path: 0 for a submitted one. The one
-- path a file's tasks read it under is `analyzed`, set when its first task is leased.
ALTER TABLE analysis.files
    ADD COLUMN depth integer NOT NULL DEFAULT 0,
    ADD COLUMN analyzed boolean NOT NULL DEFAULT false;

CREATE UNIQUE INDEX files_analyzed ON analysis.files (root_id, observable_id) WHERE analyzed;
