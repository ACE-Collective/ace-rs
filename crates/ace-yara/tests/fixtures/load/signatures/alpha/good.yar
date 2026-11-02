rule alpha_good
{
    meta:
        uuid = "2f0d2d7e-0000-4000-8000-000000000001"
    strings:
        $a = "hello"
    condition:
        $a
}
