rule ace4_e2e_attachment
{
    meta:
        uuid = "4f6e2b9a-0d3c-4e5f-9a8b-7c6d5e4f3a2b"
        // kept only for a file the email module tagged as an attachment
        meta_tags = "type=email.attachment"
    strings:
        $marker = "ACE4-E2E-MARKER-6c1f"
    condition:
        $marker
}
