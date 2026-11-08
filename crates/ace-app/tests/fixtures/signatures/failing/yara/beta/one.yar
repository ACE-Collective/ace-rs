rule fixture_same_name
{
    strings:
        $a = "one"
    condition:
        $a
}
