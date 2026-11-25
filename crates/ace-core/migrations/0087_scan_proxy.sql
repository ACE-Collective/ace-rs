-- A scan may go through its scanner pool's proxy (PLAN.md decision 64), as ace3's scanner manager
-- runs phishkit through a configured proxy: whether its module asked for it, and the proxy the pool
-- used, without its credentials, which no row holds. Adding a column with a constant default rewrites
-- nothing.
ALTER TABLE queue.scans
    ADD COLUMN proxy boolean NOT NULL DEFAULT false,
    ADD COLUMN proxied text CHECK (length(proxied) <= 512);
