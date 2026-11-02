-- One schema per area of the core (PLAN.md 2.2). Each area's tables live in its own schema,
-- so a grant, a dump or a search path can name an area.

-- The alert tree: roots, their observables and the results modules write about them.
CREATE SCHEMA analysis;

-- The task queue: one task per (root, observable, module).
CREATE SCHEMA queue;

-- The bucket's index: which objects each pool holds, and what holds them.
CREATE SCHEMA store;
