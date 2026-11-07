-- Which result added which observable (PLAN.md 4.6). ace3 can walk from an observable to the
-- analysis that added it and on down to the root (`search_down`), and a module reads what it finds:
-- an encrypted attachment's password comes from the body of the email that carried it. A path says
-- what the result named a file, because one observable can have several paths from several results.
-- `id` keeps the order the result listed them in, which ace3's email body rule depends on.
CREATE TABLE analysis.result_additions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    root_id uuid NOT NULL,
    result_id bigint NOT NULL REFERENCES analysis.results (id) ON DELETE CASCADE,
    observable_id bigint NOT NULL,
    path text,
    FOREIGN KEY (root_id, observable_id)
        REFERENCES analysis.observables (root_id, id) ON DELETE CASCADE
);

CREATE INDEX result_additions_by_observable ON analysis.result_additions (root_id, observable_id);
CREATE INDEX result_additions_by_result ON analysis.result_additions (result_id);
