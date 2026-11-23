-- A result can say its module failed, and why (ace3's Analysis.error, its 2b9fcd2c): the module ran
-- to its end and produced a result, but a tool exited with an error, a lookup couldn't answer or
-- a file didn't read. The reason sits beside the summary, outside the details, so the alert view,
-- the API and the comparison with ace3 read it without knowing the analysis type.
--
-- This is not a failed task (queue.tasks.state = 'failed', PLAN.md 2.19): that is a module that
-- never produced a result, because it crashed, was killed at its deadline or returned an error,
-- and its reason is queue.tasks.error. A result with an error is a task that ended 'done'.
--
-- Results stored before this kept a reason in their details, under keys of their own (error,
-- query_error, lookup_error). The UPDATE below moves each into the column.

ALTER TABLE analysis.results
    ADD COLUMN error text,
    -- a failure needs a reason, as ace3 refuses an empty one
    ADD CONSTRAINT results_error_has_a_reason CHECK (error IS NULL OR error ~ '\S');

-- The alert view lists a root's failed results, and an operator can ask which modules fail.
CREATE INDEX results_failed ON analysis.results (root_id) WHERE error IS NOT NULL;

-- The modules that kept a reason in their details now write the column, and their details have no
-- such key (ace3 removed the same keys in 2b9fcd2c and 41d44392). A stored result of one of those
-- types moves the same way, so it still reads as its type: the key's text becomes the result's
-- error when it says anything, and the key goes. `stopped` was ace-rs's own key for a tool the
-- runner stopped, which ace3 had no place for until it had Analysis.error.
UPDATE analysis.results r
SET error = CASE WHEN r.details ->> k.key ~ '\S' THEN r.details ->> k.key END,
    details = r.details - k.key
FROM (VALUES
    ('rdap_analysis', 'error'),
    ('nrd_analysis', 'lookup_error'),
    ('splunk_api_analysis', 'query_error'),
    ('splunk_clicker_detection_analysis', 'query_error'),
    ('msoffice_encryption_analysis', 'error'),
    ('zip_encryption_analysis', 'error'),
    ('rar_encryption_analysis', 'error'),
    ('pdf_encryption_analysis', 'error'),
    ('exif_analysis', 'error'),
    ('ocr_analysis', 'error'),
    ('auto_it_analysis', 'error'),
    ('upx_analysis', 'error'),
    ('de4dot_analysis', 'error'),
    ('java_class_decompiler_analysis', 'stopped'),
    ('dmg_analysis', 'stopped'),
    ('cve_2021_30657_analysis', 'stopped'),
    ('lnk_parse_analysis', 'error'),
    ('har_analysis', 'error'),
    ('javascript_deobfuscation_analysis', 'error'),
    ('phishkit_analysis', 'error'),
    ('pcap_analysis', 'error'),
    ('pcap_tls_decryption_analysis', 'error'),
    ('message_id_analysis_v2', 'error')
) AS k (analysis_type, key)
WHERE r.analysis_type = k.analysis_type AND r.details ? k.key;
