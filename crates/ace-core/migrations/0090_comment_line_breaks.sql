-- no-transaction
-- ace3 130b9e3c: a comment is stored with its line breaks normalized, CRLF as LF and the whitespace at
-- its ends gone, as Python's `comment.replace("\r\n", "\n").strip()` leaves it, so an unchanged edit of
-- it equals what's stored (`ace_service`'s `normalize_comment`, which every write now calls). This rewrites
-- the observable comments stored before that. ace-rs has no other comments table ace3's revision
-- covers: an SVS run's comment was always stored normalized, and an alert has no comments of its own.
--
-- Safe on a populated table: no DDL, and the table is walked by id, 1,000 rows a batch, each batch its
-- own transaction (`-- no-transaction` above, and `COMMIT` in the loop), so no row stays locked past its
-- batch. Only rows whose text changes are written. A comment edited while this runs is stored
-- normalized already and is left, and one whose text would be empty, which the column refuses (ace3's
-- would store the empty text), keeps its text. Run again after a failure, it starts over and finds the
-- rows done. `whitespace` is what Python's `str.isspace` takes (`ace_pycompat::pystr::is_space`); the
-- set is written out here, so this keeps doing what it did when it was written.
DO $$
DECLARE
    whitespace constant text := E'\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \u0085  '
        || E'           '
        || E'    　';
    last_id bigint := 0;
    batch_end bigint;
BEGIN
    LOOP
        SELECT max(id) INTO batch_end
        FROM (SELECT id FROM analysis.observable_comments WHERE id > last_id ORDER BY id LIMIT 1000) b;
        EXIT WHEN batch_end IS NULL;
        UPDATE analysis.observable_comments
        SET comment = btrim(replace(comment, E'\r\n', E'\n'), whitespace)
        WHERE id > last_id AND id <= batch_end
          AND comment <> btrim(replace(comment, E'\r\n', E'\n'), whitespace)
          AND btrim(replace(comment, E'\r\n', E'\n'), whitespace) <> '';
        last_id := batch_end;
        COMMIT;
    END LOOP;
END
$$;
