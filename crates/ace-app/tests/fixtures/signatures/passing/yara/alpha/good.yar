rule fixture_good
{
    meta:
        uuid = "00000000-0000-0000-0000-00000000a001"
    strings:
        $a = "fixture good marker"
    condition:
        $a
}
