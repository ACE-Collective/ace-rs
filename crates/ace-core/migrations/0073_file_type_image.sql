-- One more fact of a file's type (PLAN.md decision 25): whether Pillow would open it as an image, by
-- its first 1024 bytes (ace_mod_files::pillow), the test ace3's ocr and qrcode modules make before
-- they read anything. With it qrcode declares that it takes only images and PDFs, as ace3's 2026-06-25
-- consult gate keeps it off every other file, so the analysis cache (decision 26) isn't asked about
-- files the module would skip.
--
-- NULL in a row typed before this: the core reads such a row as no type at all
-- (ace_core::type_step::facts_of), so the file is typed again where it is next needed, as for 0070's.
ALTER TABLE store.file_types ADD COLUMN is_image boolean;
