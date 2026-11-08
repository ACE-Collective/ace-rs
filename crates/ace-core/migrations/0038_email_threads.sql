-- brocess's thread store (PLAN.md 7.4): what email_logger records of each email's thread, which
-- email_thread_analyzer reads back as a conversation and email_logger compares a sender against.
-- ace3's tables of the same names (alembic/brocess/versions/fe7816547cc7_initial_schema.py). Each
-- hash is the SHA-256 of the UTF-8 text beside it, as ace3's UNHEX(SHA2(x, 256)), and the times
-- are UTC without a zone, to the second, as its DATETIME columns hold NOW().

-- One message of a thread.
CREATE TABLE brocess.email_thread_message (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    insert_date timestamp NOT NULL DEFAULT date_trunc('second', now() AT TIME ZONE 'UTC'),
    thread_id text NOT NULL,
    thread_id_hash bytea NOT NULL CHECK (octet_length(thread_id_hash) = 32),
    message_id text NOT NULL,
    message_id_hash bytea NOT NULL CHECK (octet_length(message_id_hash) = 32),
    in_reply_to text,
    normalized_subject text,
    normalized_subject_hash bytea CHECK (octet_length(normalized_subject_hash) = 32),
    from_address text,
    from_domain text,
    -- 0 inbound, 1 outbound
    direction smallint,
    message_date timestamp,
    CONSTRAINT uniq_thread_message UNIQUE (thread_id_hash, message_id_hash)
);
CREATE INDEX email_thread_message_subject ON brocess.email_thread_message (normalized_subject_hash);
CREATE INDEX email_thread_message_thread_date
    ON brocess.email_thread_message (thread_id_hash, message_date);
CREATE INDEX email_thread_message_message ON brocess.email_thread_message (message_id_hash);

-- One address that took part in one message of a thread, in one role. entry_hash covers the
-- message, domain, address and role, so recording a message again changes nothing.
CREATE TABLE brocess.email_thread_domain (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    thread_id text NOT NULL,
    thread_id_hash bytea NOT NULL CHECK (octet_length(thread_id_hash) = 32),
    message_id_hash bytea CHECK (octet_length(message_id_hash) = 32),
    domain text NOT NULL,
    address text NOT NULL,
    role varchar(16) NOT NULL,
    entry_hash bytea NOT NULL CHECK (octet_length(entry_hash) = 32),
    numseen bigint DEFAULT 1,
    firstseendate timestamp,
    CONSTRAINT uniq_thread_domain UNIQUE (thread_id_hash, entry_hash)
);
CREATE INDEX email_thread_domain_thread ON brocess.email_thread_domain (thread_id_hash);
