-- SVS routing, closing and association (PLAN.md 7.10 batch 7a): an alert's owner, which decides whether a
-- router, the timers or a person through SVS may move or close it, and what "fully attributed" means, in
-- one place.

-- The analyst who took the alert (ace3's `alerts.owner_id` and `owner_time`). An alert someone owns is
-- theirs: a router doesn't move it, SVS's timers don't close it, and a person's association through SVS
-- moves it only when that person owns it. ACE's own components never own one, where ace3's automation
-- user does and counts as nobody. A deleted user's alerts are nobody's again.
ALTER TABLE analysis.roots
    ADD COLUMN owner_id uuid REFERENCES service.users ON DELETE SET NULL,
    ADD COLUMN owned_at timestamptz;

CREATE INDEX roots_by_owner ON analysis.roots (owner_id) WHERE owner_id IS NOT NULL;

-- The open alerts, which the timers' late-alert sweep starts from.
CREATE INDEX roots_open_alerts ON analysis.roots (id)
    WHERE alerted_at IS NOT NULL AND (disposition IS NULL OR disposition = 'OPEN');

-- Whether every detection of the alert has an attribution that holds, to any run, and it has at least
-- one: ace3's `fully_attributed_condition`. The marker router, the closing of a run's alerts and the
-- late-alert sweep read it; `ace_core::svs::derive_status` is the same rule over rows already read.
CREATE FUNCTION svs.fully_attributed(root uuid) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT EXISTS (
               SELECT FROM svs.attributions a WHERE a.root_id = root AND a.removed_at IS NULL)
       AND NOT EXISTS (
               SELECT FROM analysis.detections d
               WHERE d.root_id = root
                 AND NOT EXISTS (
                         SELECT FROM svs.attributions c
                         WHERE c.root_id = root AND c.detection_id = d.id AND c.removed_at IS NULL))
$$;
