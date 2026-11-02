import "math"

rule two_b
{
    meta:
        file_name = "re:.*\\.bin$"
    strings:
        $hex = { 4D 5A ?? 00 [2-4] 50 45 }
    condition:
        $hex or math.entropy(0, filesize) > 7.9
}

rule two_c : tagged
{
    condition:
        filesize < 10 and extension == "bin"
}
