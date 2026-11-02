// Every byte against every byte: about filesize squared steps, so a 100 KB file takes far
// longer than a one-second timeout. All-zero data never satisfies the condition, so the
// loops can't stop early.
rule quadratic
{
    condition:
        for any i in (0..filesize) : (
            for any j in (0..filesize) : (
                uint8(i) + uint8(j) == 0x1ff
            )
        )
}
