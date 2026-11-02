// Python's re accepts the lookbehind in this re: item and the regex crate doesn't, so ace4
// leaves the file out at build time.
rule lookaround_in_file_name
{
    meta:
        file_name = "re:(?<=invoice)\\d+"
    strings:
        $a = "invoice"
    condition:
        $a
}

rule left_out_with_its_file
{
    condition:
        true
}
