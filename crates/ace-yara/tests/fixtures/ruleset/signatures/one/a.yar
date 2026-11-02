rule one_a
{
    meta:
        uuid = "0b6f1b0e-0000-4000-8000-000000000011"
        meta_tags = "type=email.attachment"
    strings:
        $a = "needle"
        $re = /hay[a-z]{2,8}stack/ nocase
    condition:
        any of them
}
