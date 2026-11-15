-- The YARA export of the observables enabled for detection (PLAN.md 7.16): what a ruleset's build made of
-- them (`ace_yara::export::ExportReport`): each exported type with its counts, each detection left out
-- with why, and why nothing was exported when the files didn't load together. NULL is a ruleset with no
-- detection exported. `built_ins` (0055) holds the export's fingerprint beside the built-in rules', so a
-- row is built again in place when the list, an expiry or the export's settings change what is exported.
ALTER TABLE yara.rulesets ADD COLUMN detection_export jsonb;
