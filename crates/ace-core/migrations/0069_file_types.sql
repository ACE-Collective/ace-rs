-- A file's type and its role (PLAN.md decision 25, docs/decisions/0003).

-- What a file's bytes are, as the type step found them (ace_results' TypeFacts): kept once per
-- sha256, beside the bucket's record of the bytes, since they depend on the bytes alone. The type
-- step is a contained parser task; the core reads no bytes to fill this.
CREATE TABLE store.file_types (
    sha256 text PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    -- libmagic's description and mime type, as `file -b -L` and `file -b --mime-type -L` print them.
    description text NOT NULL,
    mime text NOT NULL,
    is_ole_file boolean NOT NULL,
    is_rtf_file boolean NOT NULL,
    has_pdf_marker boolean NOT NULL,
    is_pe_file boolean NOT NULL,
    is_zip_file boolean NOT NULL,
    is_jar_file boolean NOT NULL,
    is_x509 boolean NOT NULL,
    is_lnk_file boolean NOT NULL,
    is_email_file boolean NOT NULL,
    -- NULL when the type step didn't check, which it does only where ace3 asks node.
    javascript boolean,
    typed_at timestamptz NOT NULL DEFAULT now()
);

-- The store no longer asks libmagic about bytes it is given: that ran in the core's own process.
-- A file's mime type is its type's.
ALTER TABLE store.objects DROP COLUMN mime_type;

-- A file's role on each of its paths: what its producer made it (ace_results' FileRole), whose
-- `type=` tag is among yara_meta. NULL when no producer gave it one.
ALTER TABLE analysis.files ADD COLUMN role text;

-- The file shows ace3's file_type result: ace3's module would have analyzed it here, and the core
-- gave it that module's tags and yara_meta types from its type (ace_core::type_step).
ALTER TABLE analysis.observables ADD COLUMN type_result boolean NOT NULL DEFAULT false;
