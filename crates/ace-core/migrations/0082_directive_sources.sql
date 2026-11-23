-- Where each directive on an observable came from (PLAN.md decision 44): an analyst who added it
-- (decision 31's Add Directive), a hunt or another submission that stamped it, or a module's result
-- that added it. `analysis.observables.directives` stays the one list every rule reads; this records
-- the sources beside it, one row for each directive, source and who, so a module's declaration can
-- take a directive only from an analyst (`ace_sdk::takes::Condition::DirectiveFrom`), as a site's
-- upload of a file to an outside service must.
--
-- `added_by` says who: an analyst's or a submitter's identity as the audit names it (`user:3`,
-- `api_key:7`, `internal:collector:x`), a hunt's name, or a module's key. A directive that was on an
-- observable before this migration and whose source no audit row names is `unrecorded`, with no
-- one: no condition on a source holds for it.
CREATE TABLE analysis.directive_sources (
    root_id uuid NOT NULL,
    observable_id bigint NOT NULL,
    directive text NOT NULL,
    source text NOT NULL
        CHECK (source IN ('analyst', 'hunt', 'submission', 'module', 'unrecorded')),
    added_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT directive_sources_name_who CHECK ((source = 'unrecorded') = (added_by = '')),
    PRIMARY KEY (root_id, observable_id, directive, source, added_by),
    FOREIGN KEY (root_id, observable_id)
        REFERENCES analysis.observables (root_id, id) ON DELETE CASCADE
);

-- An analyst's directives, from the audit rows `add_directives` wrote (decision 31): each one asked
-- for is the analyst's, whether or not the observable already had it.
INSERT INTO analysis.directive_sources (root_id, observable_id, directive, source, added_by, created_at)
SELECT o.root_id, o.id, requested.directive, 'analyst',
       (a.actor ->> 'kind') || ':' || (a.actor ->> 'id'), a.created_at
FROM service.audit a
CROSS JOIN LATERAL jsonb_array_elements_text(
    CASE WHEN jsonb_typeof(a.details -> 'requested') = 'array' THEN a.details -> 'requested'
         ELSE '[]'::jsonb END
) AS requested (directive)
-- the target is `<root>/<observable id>`; a CASE, since a join's conditions run in no set order
JOIN analysis.observables o
  ON o.root_id = CASE WHEN a.target_id ~ '^[0-9a-f-]{36}/[0-9]{1,18}$'
                      THEN split_part(a.target_id, '/', 1)::uuid END
 AND o.id = CASE WHEN a.target_id ~ '^[0-9a-f-]{36}/[0-9]{1,18}$'
                 THEN split_part(a.target_id, '/', 2)::bigint END
WHERE a.action = 'add_directives' AND a.target_kind = 'observable'
  AND requested.directive = ANY (o.directives)
ON CONFLICT DO NOTHING;

-- Every other directive already on an observable: nothing says where it came from.
INSERT INTO analysis.directive_sources (root_id, observable_id, directive, source, added_by)
SELECT o.root_id, o.id, d.directive, 'unrecorded', ''
FROM analysis.observables o
CROSS JOIN LATERAL unnest(o.directives) AS d (directive)
WHERE NOT EXISTS (
    SELECT 1 FROM analysis.directive_sources s
    WHERE s.root_id = o.root_id AND s.observable_id = o.id AND s.directive = d.directive
)
ON CONFLICT DO NOTHING;
