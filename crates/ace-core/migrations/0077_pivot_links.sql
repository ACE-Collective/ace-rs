-- Pivot links (ace3's PivotLink, PLAN.md decision 32 part (b)): links out of ACE, each a URL, a label
-- and the name of an icon the binary registers, which the GUI shows beside a result, or a root's in
-- its alert's summary. A result's come with it (ResultEnvelope::pivot_links); a root's come with its
-- submission, such as the links a hunt renders for its alert (ace3's RootAnalysis.pivot_links).
-- The core checks each before it lands (an https:// URL of plain characters, a label, an icon's
-- name or none), so the GUI and the API read them as stored.
ALTER TABLE analysis.results
    ADD COLUMN pivot_links jsonb NOT NULL DEFAULT '[]'
        CONSTRAINT results_pivot_links_are_a_list CHECK (jsonb_typeof(pivot_links) = 'array');

ALTER TABLE analysis.roots
    ADD COLUMN pivot_links jsonb NOT NULL DEFAULT '[]'
        CONSTRAINT roots_pivot_links_are_a_list CHECK (jsonb_typeof(pivot_links) = 'array');
