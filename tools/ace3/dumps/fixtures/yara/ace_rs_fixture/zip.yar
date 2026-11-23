// Fixture rules for the YARA module's reference dumps (PLAN.md 1.24 and 1.30). The namespace is
// this directory's name, ace_rs_fixture.

// Kept only when the caller passes the meta tag type=email.attachment for the file.
rule ace_rs_fixture_zip_attachment
{
    meta:
        description = "A zip archive that arrived as an email attachment"
        meta_tags = "type=email.attachment"
        uuid = "ee5150dd-907d-4b1e-94d4-4b79aeb429bf"
    strings:
        $local_file_header = { 50 4B 03 04 }
    condition:
        $local_file_header at 0
}

// Kept whatever tags the caller passes, and never alerts, so every run shows the scan happened.
rule ace_rs_fixture_zip_any
{
    meta:
        description = "Any zip archive"
        modifiers = "no_alert"
        uuid = "2cbf38f7-4b53-4717-868b-fa0f585cad5f"
    strings:
        $local_file_header = { 50 4B 03 04 }
    condition:
        $local_file_header at 0
}
