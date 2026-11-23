-- The alert list (PLAN.md 5.10): an analyst's saved filters, ace3's `saved_filters` table and its router.
-- A row belongs to one user and one screen (`ace-service`'s `filters::FilterScreen`), whose name it holds,
-- and its filters are ace3's `[{name, inverted, values}]`, checked for that screen before they're written.
-- A name is the user's own on a screen. A quick filter is a row with an order, ace3's badges.
--
-- ace3 also keeps each analyst's unsaved working filter and an active pivot here, because its session
-- cookie can't hold them. ace-rs's list keeps its filters in the page's URL, so a row here is only ever a
-- filter someone saved. Like a preference, a row goes with its user.
CREATE TABLE service.saved_filters (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES service.users ON DELETE CASCADE,
    screen text NOT NULL CHECK (screen ~ '^[a-z][a-z0-9_]{0,31}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    description text CHECK (length(description) <= 1024),
    filters jsonb NOT NULL CHECK (jsonb_typeof(filters) = 'array'),
    quick_filter_order integer CHECK (quick_filter_order >= 0),
    quick_filter_indicator boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT saved_filter_names_are_unique UNIQUE (user_id, screen, name)
);
