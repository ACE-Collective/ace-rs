rule two_patterns
{
    meta:
        uuid = "7d1f1d6e-0000-4000-8000-000000000005"
        description = "two patterns, one of them twice"
    strings:
        $a = "needle"
        $b = { 41 42 43 }
    condition:
        $a and $b
}

rule path_externals
{
    condition:
        filename == "run.ps1" and filepath == "alert/files/run.ps1" and extension == "ps1" and filetype == ""
}

rule tagged_attachment : attachment
{
    meta:
        meta_tags = "type=email.attachment"
    strings:
        $a = "needle"
    condition:
        $a
}

rule pdf_only
{
    meta:
        mime_type = "application/pdf"
    condition:
        true
}

private rule hidden
{
    condition:
        true
}
