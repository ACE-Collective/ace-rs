-- brocess (PLAN.md 7.4): ace3's database of what its email modules have seen before, which its
-- own MySQL schema (`alembic/brocess/`) keeps apart from ACE's. Lookup modules read it through
-- the lease API's reads (crates/ace-core/src/reads.md), and email_logger's writes will land with
-- its task's end.
CREATE SCHEMA brocess;

-- How often each (sender, recipient) email conversation has been seen: ace3's `smtplog`. The
-- addresses are bytes, at most 255 of them, as ace3's varbinary(255): email_logger writes each one
-- encoded as UTF-8 and cut to 255 bytes, and a read compares them byte for byte.
CREATE TABLE brocess.smtplog (
    source bytea NOT NULL CHECK (octet_length(source) <= 255),
    destination bytea NOT NULL CHECK (octet_length(destination) <= 255),
    numconnections bigint,
    -- seconds since the epoch, as ace3's double
    firstconnectdate double precision,
    PRIMARY KEY (source, destination)
);
