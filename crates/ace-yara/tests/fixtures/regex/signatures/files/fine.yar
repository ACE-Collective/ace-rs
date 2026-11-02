rule regex_that_compiles
{
    meta:
        file_name = "re:.*\\.doc$, .*\\.docx$"
        mime_type = "!sub:image/"
    condition:
        true
}
