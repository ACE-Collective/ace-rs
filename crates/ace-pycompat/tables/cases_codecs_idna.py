# Cases for the idna codec: str.encode("idna") and bytes.decode("idna"). Output: tests/data/codecs_idna.json.

import codecs

LABELS = ["example", "com", "b\u00fccher", "\u043f\u0440\u0438\u043c\u0435\u0440", "\u4e2d\u6587", "\u0627\u0644\u0639\u0631\u0628\u064a\u0629",
          "\u05e2\u05d1\u05e8\u05d9\u05ea", "a\u05d0", "\u05d0a", "\u05d01", "1\u05d0", "\u0627\u0661", "STRASSE", "stra\u00dfe",
          "\u00df", "\u0130", "\u212a", "\ufb01", "\u2122", "\u00ad", "a\u200db", "\u3002", "xn--abc", "XN--bcher-kva",
          "xn--bcher-kva", "xn--", "a" * 63, "a" * 64, "\u00e9" * 63, "\u00e9" * 58, "\u00e9" * 57, "", "\u0000", "a b",
          "\u0340", "\u2028", "\ufffc", "\ud7ff", "\U000e0001", "\u0221", "\u0378", "\U0001f600", "x\u0301", "\u1100\u1161",
          "\uff21\uff22", "\u2460", "\u33a1", "\u2100", "\u00aa", "\u0345", "\u03a3\u03c2", "xn--\u00e9", "Xn--\u00e9"]


def random_host():
    n = rng.randrange(1, 5)
    parts = []
    for _ in range(n):
        if rng.random() < 0.6:
            parts.append(rng.choice(LABELS))
        else:
            parts.append(random_string(10))
    sep = [rng.choice([".", ".", ".", "\u3002", "\uff0e", "\uff61"]) for _ in range(n)]
    s = "".join(p + (sep[i] if i < n - 1 else "") for i, p in enumerate(parts))
    if rng.random() < 0.15:
        s += rng.choice([".", "\u3002"])
    return s


encode_cases = ["", ".", "..", "a.", "a..b", ".a", "\u3002", "\u00e9.", "\u00e9..", "a.\u00e9", "\u00e9\u3002\u00e9\uff0e\uff61"]
encode_cases += LABELS
ENCODE_HEAD = len(encode_cases)
while len(encode_cases) < 6000:
    encode_cases.append(random_host())


def enc(s):
    return run(lambda: s.encode("idna").decode("ascii"))


PUNY = "abcdefghijklmnopqrstuvwxyz0123456789-ABZ"
decode_cases = [b"", b".", b"a..b", b"xn--", b"xn--.", b"xn--a", b"xn--a-", b"xn---", b"xn--zzzz", b"xn--99999999999999",
                b"xn--" + b"9" * 30, b"xn--" + b"9" * 60, b"xn--" + b"z" * 200, b"xn--a-9" + b"9" * 40, b"xn--bcher-kva.ch",
                b"XN--BCHER-KVA.CH", b"xn--Bcher-kva", b"xn--bcher-kvb", b"\xc3\xa9", b"a.\xff", b"xn--\xc3\xa9",
                b"xn--a\xff-b", b"xn--a-\xff", b"a" * 1025, b"xn--" + b"a" * 1021, b"xn--80ak6aa92e.com", b"xn--ls8h",
                b"xn--7ug", b"xn--1ug",
                b"xn--" + b"9" * 5 + b"a", b"xn--" + b"9" * 8 + b"a", b"xn--" + b"9" * 10 + b"a", b"xn--" + b"9" * 12 + b"a", b"xn--" + b"9" * 13 + b"a", b"xn--" + b"9" * 14 + b"a", b"xn--" + b"9" * 15 + b"a", b"xn--" + b"9" * 20 + b"a", b"xn--" + b"9" * 30 + b"a", b"xn--" + b"9" * 60 + b"a", b"xn--ab-" + b"9" * 14 + b"a", b"a.xn--" + b"9" * 13 + b"b", b"xn--8ca", b"xn--zca", b"xn--tda", b"xn--jxa", b"xn--4ca0bs"]
DECODE_HEAD = len(decode_cases)
while len(decode_cases) < 6000:
    r = rng.random()
    if r < 0.4:
        decode_cases.append(b"xn--" + "".join(rng.choice(PUNY) for _ in range(rng.randrange(0, 14))).encode())
    elif r < 0.6:
        try:
            decode_cases.append(random_host().encode("idna"))
        except UnicodeError:
            decode_cases.append(random_host().encode("utf-8", "ignore"))
    elif r < 0.8:
        decode_cases.append(random_host().encode("utf-8", "ignore"))
    else:
        decode_cases.append(random_bytes(12) + rng.choice([b"", b".xn--a", b"xn--"]))

dump({"encode": sample([{"s": s, "out": enc(s)} for s in encode_cases], ENCODE_HEAD, 100_000),
      "decode": sample([{"b": b.hex(), "out": run(lambda: b.decode("idna"))} for b in decode_cases], DECODE_HEAD, 100_000),
      "punycode": sample([{"s": s, "out": s.encode("punycode").decode("ascii")} for s in encode_cases[:3000]], ENCODE_HEAD, 50_000)})
