rule beta_uses_externals
{
    condition:
        filename != "" and filepath != "" and extension == "ps1" and filetype == ""
}

// the same name as a rule in alpha, which is fine in another namespace
rule alpha_good
{
    condition:
        true
}
