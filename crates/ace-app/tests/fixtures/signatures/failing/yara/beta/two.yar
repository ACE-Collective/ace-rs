rule fixture_same_name
{
    strings:
        $a = "two"
    condition:
        $a
}
