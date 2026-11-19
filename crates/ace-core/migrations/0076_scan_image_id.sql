-- The id of the image a scan's container ran, as its scanner pool read it from Docker
-- (`ace_sdk::scanners::ScanEnd::image_id`): the analysis cache keys a scanning module's result on it,
-- as ace3 keys phishkit's on its running scanner image's id (`ace_sdk::cache::Cache::scanners`).
ALTER TABLE queue.scans ADD COLUMN image_id text CHECK (length(image_id) <= 256);
