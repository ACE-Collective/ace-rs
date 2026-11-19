-- ace3's automation_limit (`ace_core::limits`): the work the core didn't queue because its module's
-- analysis type had reached its limit in the root. ace3 only logs it at debug and asks again each
-- time it looks at the observable; here a row says it was held back, and the end of a task of the
-- same type that leaves no result (a skip, a failure, a cancellation), which frees a place, has the
-- core ask again for these rows' observables, oldest observable first. A row goes once the task is
-- queued or its result lands, and with its root.
CREATE TABLE analysis.automation_limited (
    root_id uuid NOT NULL,
    observable_id bigint NOT NULL,
    -- The component's key: the module's name, or its instance's.
    module text NOT NULL,
    -- The limit it reached.
    automation_limit integer NOT NULL CHECK (automation_limit >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (root_id, observable_id, module),
    FOREIGN KEY (root_id, observable_id)
        REFERENCES analysis.observables (root_id, id) ON DELETE CASCADE
);

