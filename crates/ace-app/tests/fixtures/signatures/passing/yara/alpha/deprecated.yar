import "pe"

rule fixture_deprecated
{
    meta:
        uuid = "00000000-0000-0000-0000-00000000a002"
    condition:
        pe.number_of_signatures > 0
}
