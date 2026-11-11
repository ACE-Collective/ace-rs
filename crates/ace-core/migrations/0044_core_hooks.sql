-- The core's hooks (PLAN.md 7.6): ace3's `observable_modifier` and `configuration_defined_tagging`, which
-- run in the core, over the whole tree, rather than on a pool (`ace_core::hooks`).

-- A detection on the root itself, as ace3's `RootAnalysis.add_detection_point`: no observable. The
-- foreign key to the observable is MATCH SIMPLE, so a NULL passes it. `configuration_defined_tagging`
-- writes these.
ALTER TABLE analysis.detections ALTER COLUMN observable_id DROP NOT NULL;

ALTER TABLE analysis.observables
    -- The value the alert view shows in place of the observable's own, as ace3's
    -- `Observable._display_value`, which an observable modifier rule sets.
    ADD COLUMN display_value text,
    -- When not empty, the only modules that may analyze the observable, as ace3's
    -- `Observable.limited_analysis`, which an observable modifier rule sets.
    ADD COLUMN limit_modules text[] NOT NULL DEFAULT '{}',
    -- An observable modifier rule's `ignore` took it out of the tree: the alert view doesn't draw it, as
    -- ace3's `Observable.ignored`. It stays in the root, with what analyzed it.
    ADD COLUMN ignored boolean NOT NULL DEFAULT false;

-- An observable modifier rule's `ignore` took the observable out from under this result, as ace3
-- removes it from the parent analysis's observables. The row stays, so what was removed is known; the
-- alert view and the hooks' own tree leave it out.
ALTER TABLE analysis.result_additions ADD COLUMN ignored boolean NOT NULL DEFAULT false;

-- Something happened to the root that the hooks haven't seen: a result landed, or its mode changed.
-- When the root's last task ends and this is set, the core queues its hooks' task instead of ending the
-- pass (`queue::check_completion`), so the hooks run once nothing else is running, as ace3's final and
-- post analysis do, and the pass ends after them.
ALTER TABLE analysis.roots ADD COLUMN hooks_due boolean NOT NULL DEFAULT false;
