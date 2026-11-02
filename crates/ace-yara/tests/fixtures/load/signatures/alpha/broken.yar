// does not compile: the condition names an identifier nothing defines
rule alpha_broken
{
    condition:
        no_such_identifier
}

rule alpha_left_out_with_its_file
{
    condition:
        true
}
