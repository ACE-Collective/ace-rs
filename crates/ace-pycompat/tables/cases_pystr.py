# Cases for pystr, repr and unicodedata. Output: tests/data/pystr.json.

import unicodedata

U32 = unicodedata.ucd_3_2_0
CPS = [cp for cp in range(0x110000) if not 0xD800 <= cp <= 0xDFFF]
FORMS = ["NFC", "NFKC", "NFD", "NFKD"]

# One digest per function over every code point but the surrogates, each output followed by NUL.
digests = {
    "category": digest(unicodedata.category(chr(cp)) for cp in CPS),
    "bidirectional": digest(unicodedata.bidirectional(chr(cp)) for cp in CPS),
    "combining": digest(str(unicodedata.combining(chr(cp))) for cp in CPS),
    "has_name": digest(str(int(unicodedata.name(chr(cp), None) is not None)) for cp in CPS),
    "lower": digest(chr(cp).lower() for cp in CPS),
    "upper": digest(chr(cp).upper() for cp in CPS),
    "predicates": digest("".join(str(int(x)) for x in (
        chr(cp).isspace(), chr(cp).isalpha(), chr(cp).isalnum(), chr(cp).isdecimal(), chr(cp).isdigit(),
        chr(cp).isprintable())) for cp in CPS),
    "repr": digest(repr(chr(cp)) for cp in CPS),
    "nfkc_maps_to_other_ascii": digest(str(int(
        unicodedata.normalize("NFKC", chr(cp)) != chr(cp) and unicodedata.normalize("NFKC", chr(cp)).isascii()))
        for cp in CPS),
}
for f in FORMS:
    digests[f] = digest(unicodedata.normalize(f, chr(cp)) for cp in CPS)
    digests["3.2 " + f] = digest(U32.normalize(f, chr(cp)) for cp in CPS)
# Each code point after a capital sigma and before one, which exercises the final sigma rule.
digests["sigma"] = digest(("A" + chr(cp) + "\u03a3").lower() + ("A\u03a3" + chr(cp)).lower() + (chr(cp) + "\u03a3x").lower()
                          for cp in CPS)

# Composition needs pairs: each composite's decomposition, and a base followed by marks in turn.
# The sample keeps each non-Hangul decomposition, every 50th Hangul syllable's, and every 4th
# one's variants.
seqs = []
for n, cp in enumerate(CPS):
    d = unicodedata.normalize("NFD", chr(cp))
    if len(d) > 1:
        if FULL or not 0xAC00 <= cp <= 0xD7A3 or cp % 50 == 0:
            seqs.append(d)
        if FULL or n % 4 == 0:
            seqs.append(d[::-1])
            seqs.append(d + "\u0301\u0323")
marks = ["\u0300", "\u0301", "\u0308", "\u0323", "\u0327", "\u0345", "\u0313", "\u0342", "\u05b0", "\u093c", "\u0f71", "\u302a", "\u3099"]
for _ in range(3000 if FULL else 800):
    s = rng.choice("aeiouAOUIsnyczZwk\u03b1\u03b9\u03c9\u0397\u1100\u1161\u11a8\u304b\u30cf\u0915\u0f40") + "".join(rng.choice(marks) for _ in range(rng.randrange(0, 5)))
    seqs.append(s)
for _ in range(3000 if FULL else 500):
    seqs.append(random_string())
for f in FORMS:
    digests["sequences " + f] = digest(unicodedata.normalize(f, s) for s in seqs)
    digests["sequences 3.2 " + f] = digest(U32.normalize(f, s) for s in seqs)

strings = [""," ","\x1c\x1d\x1e\x1f\x85 a \u3000","a\r\nb\rc\nd\x0be\x0cf\x1cg\x1dh\x1ei\x85j\u2028k\u2029l\x1fm",
           "\r\n\r\n", "\n", "a\n", "\u03a3", "A\u03a3", "A\u03a3B", "A\u03a3\u0301", "A\u0301\u03a3", ".\u03a3.", "A\u00ad\u03a3",
           "\u0130stanbul", "STRASSE stra\u00dfe", "\ufb03", "\u212a\u017f\u0131", "\u01c5\u01c4\u01c6"]
HEAD = len(strings)
while len(strings) < 4000:
    strings.append(random_string(32))
string_cases = []
for s in strings:
    string_cases.append({
        "s": s,
        "lower": s.lower(), "upper": s.upper(),
        "strip": s.strip(), "lstrip": s.lstrip(), "rstrip": s.rstrip(),
        "strip_chars": s.strip(" .%a\u00e9"),
        "splitlines": s.splitlines(), "splitlines_keepends": s.splitlines(True),
        "repr": repr(s),
        "nfc": unicodedata.normalize("NFC", s), "nfkc": unicodedata.normalize("NFKC", s),
        "nfkc32": U32.normalize("NFKC", s),
    })

bytes_list = [b"", b"abc", b"\xc3\xa9", b"\xc3", b"\xe2\x82", b"\xed\xa0\x80", b"\xf0\x9f\x98\x80", b"\xf4\x90\x80\x80",
              b"\xe0\x80\xaf", b"\xc0\xaf", b"a\x80b", b"\xe2\x28\xa1", b"\xf0\x28\x8c\xbc", b"\xf0\x90\x28\xbc"]
BYTES_HEAD = len(bytes_list)
while len(bytes_list) < 6000:
    bytes_list.append(random_bytes())
bytes_cases = []
for b in bytes_list:
    bytes_cases.append({
        "b": b.hex(),
        "ignore": b.decode("utf-8", "ignore"),
        "replace": b.decode("utf-8", "replace"),
        "strict": run(b.decode, "utf-8"),
        "repr": repr(b),
    })

dump({"digests": digests, "sequences": seqs, "strings": sample(string_cases, HEAD, 200_000),
      "bytes": sample(bytes_cases, BYTES_HEAD, 120_000)})
