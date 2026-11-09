# Cases for the idna package's encode and decode with default arguments. Output: tests/data/idna.json.

import idna

assert idna.__version__ == "3.20"

LABELS = ["example", "com", "b\u00fccher", "B\u00fccher", "\u043f\u0440\u0438\u043c\u0435\u0440", "\u4e2d\u6587",
          "\u0627\u0644\u0639\u0631\u0628\u064a\u0629", "\u05e2\u05d1\u05e8\u05d9\u05ea", "a\u05d0", "\u05d0a", "\u05d01",
          "1\u05d0", "\u05d0\u0661", "\u0627\u0661\u06f1", "\u0627\u0661", "\u06271", "\u0627\u0300", "\u05d0\u0300",
          "stra\u00dfe", "\u00df", "\u0130", "\u212a", "\ufb01", "\u2122", "\u00ad", "a\u200db", "\u0915\u094d\u200d",
          "\u0915\u094d\u200c", "\u0628\u200c\u0628", "\u0628\u200c", "a\u200cb", "\u200c", "\u200d", "\u00b7", "l\u00b7l",
          "l\u00b7", "\u0375\u03b1", "\u0375a", "\u0375", "\u05d0\u05f3", "\u05f3", "\u30fb", "\u30fb\u30a2", "\u30fb\u4e2d",
          "a\u30fb", "\u0660\u0661", "\u0660\u06f0", "\u06f0\u06f1", "xn--abc", "XN--bcher-kva", "xn--bcher-kva", "xn--",
          "xn--a", "xn--a-", "xn--zca", "xn--8ca", "xn--80ak6aa92e", "xn--ls8h", "xn--99999999999999999999a", "xn--sc9botknnt",
          "a" * 63, "a" * 64, "\u00e9" * 58, "\u00e9" * 59, "", "-a", "a-", "ab--c", "a--b", "\u0301a", "a\u0301",
          "e\u0301", "\u00e9", "A", "ABC", "a_b", "a b", "a*b", "\U0001f600", "\u0378", "\U000e0001", "\u3002", "\ud7ff",
          "\u0221", "\u1100\u1161", "\u03a3", "\u03c2", "\u0bcd\u200d", "\u0f0b", "\u0640", "\u07fa", "\u0640\u200c\u0628"]


def random_host():
    n = rng.randrange(1, 5)
    parts = [rng.choice(LABELS) if rng.random() < 0.65 else random_string(8) for _ in range(n)]
    seps = [rng.choice([".", ".", ".", "\u3002", "\uff0e", "\uff61"]) for _ in range(n - 1)]
    s = parts[0] + "".join(sep + p for sep, p in zip(seps, parts[1:]))
    if rng.random() < 0.15:
        s += rng.choice([".", "\u3002"])
    return s


cases = ["", ".", "..", "a.", "a..b", ".a", "\u3002", "a." * 127, "a." * 126 + "a", ("a" * 63 + ".") * 4, "a" * 1025, "\u00e9" * 300]
cases += LABELS
HEAD = len(cases)
while len(cases) < 7000:
    cases.append(random_host())
out = []
for s in cases:
    out.append({"s": s, "encode": run(lambda: idna.encode(s).decode("ascii")), "decode": run(idna.decode, s)})
dump(sample(out, HEAD))
