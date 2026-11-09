# Unicode 16.0 data as Python 3.14's unicodedata and str methods see it, and the parts of
# unicodedata.ucd_3_2_0 that its normalization uses. Output: src/tables/unicode.rs.

ucd32 = unicodedata.ucd_3_2_0
assert ucd32.unidata_version == "3.2.0"

header("unicode.py")


def emit_value_runs(name, names_name, f, doc):
    runs = value_runs(f)
    names = sorted({v for _, v in runs})
    index = {v: i for i, v in enumerate(names)}
    print("/// The names %s's values index." % name)
    print("pub(crate) static %s: &[&str] = &[%s];" % (names_name, ", ".join(rust_str(n) for n in names)))
    print()
    print("/// %s Each entry starts a run that lasts until the next." % doc)
    print("#[rustfmt::skip]")
    print("pub(crate) static %s: &[(u32, u8)] = &[" % name)
    line = []
    for cp, v in runs:
        line.append("(0x%x, %d)," % (cp, index[v]))
        if len(line) == 8:
            print("    " + " ".join(line))
            line = []
    if line:
        print("    " + " ".join(line))
    print("];")
    print()


emit_value_runs("CATEGORY", "CATEGORY_NAMES", lambda cp: unicodedata.category(chr(cp)),
                "`unicodedata.category`.")
emit_value_runs("BIDIRECTIONAL", "BIDIRECTIONAL_NAMES", lambda cp: unicodedata.bidirectional(chr(cp)),
                "`unicodedata.bidirectional`.")

runs = value_runs(lambda cp: unicodedata.combining(chr(cp)))
print("/// `unicodedata.combining`. Each entry starts a run that lasts until the next.")
print("#[rustfmt::skip]")
print("pub(crate) static COMBINING: &[(u32, u8)] = &[")
line = []
for cp, v in runs:
    line.append("(0x%x, %d)," % (cp, v))
    if len(line) == 8:
        print("    " + " ".join(line))
        line = []
if line:
    print("    " + " ".join(line))
print("];")
print()

# Decompositions, one level, as unicodedata.decomposition gives them. Hangul syllables are
# algorithmic and left out.
decomp = []
for cp in ALL:
    if 0xAC00 <= cp <= 0xD7A3:
        continue
    d = unicodedata.decomposition(chr(cp))
    if not d:
        continue
    parts = d.split()
    compat = parts[0].startswith("<")
    if compat:
        parts = parts[1:]
    decomp.append((cp, compat, [int(p, 16) for p in parts]))
print("/// `unicodedata.decomposition`, one level: (code point, compatibility, decomposition).")
print("#[rustfmt::skip]")
print("pub(crate) static DECOMPOSITION: &[(u32, bool, &[u32])] = &[")
for cp, compat, parts in decomp:
    print("    (0x%x, %s, &[%s])," % (cp, "true" if compat else "false", ", ".join("0x%x" % p for p in parts)))
print("];")
print()

unassigned32 = [cp for cp, _, _ in decomp if ucd32.category(chr(cp)) == "Cn"]
print("/// Code points with a decomposition that Unicode 3.2 hadn't assigned: ucd_3_2_0 decomposes them to nothing.")
print("pub(crate) static DECOMPOSITION_UNASSIGNED_3_2: &[u32] = &[%s];" % ", ".join("0x%x" % c for c in unassigned32))
print()

# The normalization corrections ucd_3_2_0 applies before decomposing. Each maps one code point to
# another that is then decomposed further.
corrections = []
for cp in ALL:
    if is_surrogate(cp) or ucd32.category(chr(cp)) == "Cn":
        continue
    old = ucd32.normalize("NFD", chr(cp))
    new = unicodedata.normalize("NFD", chr(cp))
    if old != new:
        assert len(old) == 1, (hex(cp), old)
        corrections.append((cp, ord(old)))
print("/// ucd_3_2_0's normalization corrections: the code point decomposes as the second one does.")
print("pub(crate) static CORRECTIONS_3_2: &[(u32, u32)] = &[%s];" % ", ".join("(0x%x, 0x%x)" % c for c in corrections))
print()

# Canonical composition pairs: a two-character canonical decomposition of a primary composite.
pairs = []
for cp, compat, parts in decomp:
    if compat or len(parts) != 2:
        continue
    if unicodedata.normalize("NFC", chr(cp)) != chr(cp):
        continue
    pairs.append((parts[0], parts[1], cp))
pairs.sort()
print("/// Canonical composition: (first, second, composite), sorted.")
print("#[rustfmt::skip]")
print("pub(crate) static COMPOSITION: &[(u32, u32, u32)] = &[")
line = []
for a, b, c in pairs:
    line.append("(0x%x, 0x%x, 0x%x)," % (a, b, c))
    if len(line) == 4:
        print("    " + " ".join(line))
        line = []
if line:
    print("    " + " ".join(line))
print("];")
print()


def emit_mapping(name, f, doc):
    print("/// %s" % doc)
    print("#[rustfmt::skip]")
    print("pub(crate) static %s: &[(u32, &str)] = &[" % name)
    for cp in ALL:
        if is_surrogate(cp):
            continue
        c = chr(cp)
        m = f(c)
        if m != c:
            print("    (0x%x, %s)," % (cp, rust_str(m)))
    print("];")
    print()


emit_mapping("LOWER", str.lower, "`str.lower` of each code point alone (U+03A3's final form is handled in code).")
emit_mapping("UPPER", str.upper, "`str.upper` of each code point alone.")

emit_ranges("SPACE", ranges(lambda cp: chr(cp).isspace()), "`str.isspace`.")
emit_ranges("ALPHA", ranges(lambda cp: chr(cp).isalpha()), "`str.isalpha`.")
emit_ranges("DECIMAL", ranges(lambda cp: chr(cp).isdecimal()), "`str.isdecimal`.")
emit_ranges("DIGIT", ranges(lambda cp: chr(cp).isdigit()), "`str.isdigit`.")
emit_ranges("ALNUM", ranges(lambda cp: chr(cp).isalnum()), "`str.isalnum`.")
emit_ranges("PRINTABLE", ranges(lambda cp: chr(cp).isprintable()), "`str.isprintable`.")
emit_ranges("NO_NAME", ranges(lambda cp: unicodedata.name(chr(cp), None) is None),
            "Code points `unicodedata.name` has no name for.")


# Final sigma needs Unicode's Cased and Case_Ignorable, which Python doesn't expose; str.lower's
# answer around a capital sigma tells them apart.
def case_ignorable(cp):
    c = chr(cp)
    p1 = (c + "\u03a3").lower()[-1] == "\u03c2"
    p2 = ("A" + c + "\u03a3").lower()[-1] == "\u03c2"
    return p2 and not p1


def cased_not_ignorable(cp):
    c = chr(cp)
    return (c + "\u03a3").lower()[-1] == "\u03c2"


emit_ranges("CASE_IGNORABLE", ranges(case_ignorable), "Unicode's Case_Ignorable, as str.lower's final sigma rule sees it.")
emit_ranges("CASED", ranges(cased_not_ignorable),
            "Unicode's Cased, less what is also Case_Ignorable (the final sigma rule never asks those).")
