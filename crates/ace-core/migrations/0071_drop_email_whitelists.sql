-- ace3 removed whitelisting (8617ba8e): its brotex whitelist file, `etc/brotex.whitelist`, and
-- `saq/whitelist.py`, which read it, are deleted, and a site overlay that still names the file fails to
-- load. The email module's two lists here were that file's `smtp_from` and `smtp_to` keys (PLAN.md 5.14),
-- and nothing reads them any more, so their entries go with them. The audit rows of their past edits
-- stay in `service.audit`, as every audit row does. The other lists, and the table, stay.

DELETE FROM lists.entries WHERE list IN ('email_sender_whitelist', 'email_recipient_whitelist');
