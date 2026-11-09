# The stringprep tables (RFC 3454) that encodings.idna's nameprep uses, from Python's stringprep
# module, which reads unicodedata.ucd_3_2_0. Output: src/tables/stringprep.rs.

import stringprep

header("stringprep.py")

emit_ranges("B1", ranges(lambda cp: stringprep.in_table_b1(chr(cp))), "`stringprep.in_table_b1`: mapped to nothing.")


def prohibited(cp):
    c = chr(cp)
    return (stringprep.in_table_c12(c) or stringprep.in_table_c22(c) or stringprep.in_table_c3(c)
            or stringprep.in_table_c4(c) or stringprep.in_table_c5(c) or stringprep.in_table_c6(c)
            or stringprep.in_table_c7(c) or stringprep.in_table_c8(c) or stringprep.in_table_c9(c))


emit_ranges("PROHIBITED", ranges(prohibited), "Tables C.1.2, C.2.2 and C.3 to C.9, which nameprep prohibits together.")
emit_ranges("D1", ranges(lambda cp: stringprep.in_table_d1(chr(cp))), "`stringprep.in_table_d1`: RandALCat.")
emit_ranges("D2", ranges(lambda cp: stringprep.in_table_d2(chr(cp))), "`stringprep.in_table_d2`: LCat.")

print("/// `stringprep.map_table_b2`, where it changes the code point.")
print("#[rustfmt::skip]")
print("pub(crate) static B2: &[(u32, &str)] = &[")
for cp in ALL:
    if is_surrogate(cp):
        continue
    c = chr(cp)
    m = stringprep.map_table_b2(c)
    if m != c:
        print("    (0x%x, %s)," % (cp, rust_str(m)))
print("];")
