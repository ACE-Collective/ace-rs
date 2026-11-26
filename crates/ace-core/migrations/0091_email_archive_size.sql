-- The size of an archived email, ace3's pool index's plaintext `size`, which its `POST
-- /email/archive/lookup` reports and its bulk download's byte cap counts (ace3 e7cd8be8). ace-rs's
-- object is the email gzipped and sealed, so the bucket's size isn't the email's: the archive keeps it.
-- NULL for a row archived before this, whose email's size would mean opening it; such rows go with
-- their week, `retention_days` after it.
--
-- A nullable column with no default: no partition is rewritten.
ALTER TABLE email_archive.archive ADD COLUMN size bigint CHECK (size >= 0);
