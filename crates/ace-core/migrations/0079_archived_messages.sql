-- The email archive found only by Message-ID, as ace3's `archived_messages` since its 4f1fa192: the
-- archive is no longer searchable, and the one thing read from its tables is which email a
-- Message-ID names. Each `archive` row now carries the SHA-256 of its normalized Message-ID, taken
-- from the row's `message_id` index row, and is unique by Message-ID, email and second, as ace3's
-- primary key. The URL index (`archive_index`), which only `url_email_pivot_analyzer` read, and
-- `email_history`, which nothing read, go with those modules' removal from ace3; so do their weekly
-- partitions, which maintenance keeps only for `archive` now.
ALTER TABLE email_archive.archive ADD COLUMN message_id_hash bytea;

UPDATE email_archive.archive a
SET message_id_hash = i.hash
FROM email_archive.archive_index i
WHERE i.field = 'message_id' AND i.archive_id = a.archive_id AND i.insert_date = a.insert_date;

-- Every row the archiver wrote has its Message-ID's index row; one without could never be found.
-- Its hold on the object expires with the week it would have been dropped in.
DELETE FROM email_archive.archive WHERE message_id_hash IS NULL;

ALTER TABLE email_archive.archive
    ALTER COLUMN message_id_hash SET NOT NULL,
    ADD CONSTRAINT archive_message_id_hash_length CHECK (length(message_id_hash) = 32),
    DROP CONSTRAINT archive_hash_insert_date_key,
    ADD CONSTRAINT archive_message_id_hash_hash_insert_date_key
        UNIQUE (message_id_hash, hash, insert_date);

CREATE INDEX archive_by_message_id ON email_archive.archive (message_id_hash, insert_date);

DROP TABLE email_archive.archive_index;
DROP TABLE email_archive.email_history;
