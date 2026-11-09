# Cases for json: json.loads on str (given as code points, since they may hold lone surrogates)
# and on bytes, and repr of floats. Output: tests/data/json.json.

import json
import struct


def tag(v):
    if v is None:
        return ["None"]
    if isinstance(v, bool):
        return ["bool", v]
    if isinstance(v, int):
        return ["int", str(v)]
    if isinstance(v, float):
        return ["float", repr(v)]
    if isinstance(v, str):
        return ["str", [ord(c) for c in v]]
    if isinstance(v, list):
        return ["list", [tag(x) for x in v]]
    if isinstance(v, dict):
        return ["dict", [[[ord(c) for c in k], tag(x)] for k, x in v.items()]]
    raise TypeError(type(v))


def outcome(arg):
    try:
        return {"ok": tag(json.loads(arg))}
    except Exception as e:
        return {"err": err(e)}


ESCAPES = ["\\n", "\\t", "\\\\", "\\\"", "\\/", "\\b", "\\f", "\\r", "\\u00e9", "\\u0041", "\\ud83d\\ude00", "\\ud800",
           "\\udc00", "\\ud800\\u0041", "\\ud83d\\ude0", "\\u12", "\\x", "\\uDBFF\\uDFFF", "\\uD800\\uD800", "\\u000"]


def gen_string():
    parts = []
    for _ in range(rng.randrange(0, 5)):
        if rng.random() < 0.4:
            parts.append(rng.choice(ESCAPES))
        else:
            s = random_string(6)
            parts.append(s.replace("\\", "\\\\").replace('"', '\\"'))
    return '"' + "".join(parts) + '"'


def gen_number():
    r = rng.random()
    if r < 0.3:
        return str(rng.randrange(-10**6, 10**6))
    if r < 0.4:
        return str(rng.randrange(-10**40, 10**40))
    if r < 0.7:
        return repr(rng.uniform(-1e6, 1e6))
    if r < 0.8:
        return rng.choice(["-0", "0", "-0.0", "0.0", "1e400", "-1e400", "1e-400", "1E5", "1e+5", "1e-5", "2.5E-3", "123.456e78",
                           "0.1", "1.7976931348623157e308", "5e-324", "1e16", "1e15", "123456789012345678", "1.0"])
    return "%se%d" % (rng.choice(["1", "-2.5", "3.14159", "0", "9.999"]), rng.randrange(-330, 330))


CONSTS = ["null", "true", "false", "NaN", "Infinity", "-Infinity"]


def gen_value(depth=0):
    r = rng.random()
    if depth > 6 or r < 0.25:
        return gen_string()
    if r < 0.45:
        return gen_number()
    if r < 0.55:
        return rng.choice(CONSTS)
    ws = lambda: rng.choice(["", "", " ", "\n", "\t", "\r\n", "  "])
    n = rng.randrange(0, 5)
    if r < 0.75:
        return "[" + ws() + ("," + ws()).join(gen_value(depth + 1) for _ in range(n)) + ws() + "]"
    keys = [gen_string() if rng.random() < 0.7 else rng.choice(['"a"', '"b"', '"url"', '"p"']) for _ in range(n)]
    return "{" + ws() + ("," + ws()).join(k + ws() + ":" + ws() + gen_value(depth + 1) for k in keys) + ws() + "}"


JUNK = ['"', "\\", ",", ":", "[", "]", "{", "}", " ", "\x00", "\x1f", "e", "E", ".", "-", "+", "u", "x", "0", "\n",
        "\ufeff", "\ud800", "\udfff", "\u00e9", "\U0001f600", "n", "t", "N", "I"]


def mutate(t):
    if not t:
        return rng.choice(JUNK)
    r = rng.random()
    i = rng.randrange(0, len(t) + 1)
    if r < 0.35:
        return t[:i]
    if r < 0.7:
        return t[:i] + rng.choice(JUNK) + t[i:]
    if r < 0.85:
        return t[:i] + t[i + 1:]
    return t + rng.choice([" ", "x", "1", ",", "]", "}", "\n\n", " []"])


texts = ["", " ", "\n", "1", "-", "-0", "01", "1.", "1e", "1e+", "1.5e", "-Inf", "NaN", "Nan", "nul", "tru", "fals",
         "[", "]", "{", "}", "[]", "{}", "[1,]", "{\"a\":1,}", "{\"a\" 1}", "{\"a\":}", "{1:2}", "[1 2]", "\"abc",
         "\"\\", "\"\\u", "\"\\u12\"", "\"\\uzzzz\"", "\"\x01\"", "\"\x7f\"", "\ufeff[]", " \ufeff[]", "[1]x", "[1] ",
         "{\"a\":1,\"a\":2,\"b\":3,\"a\":4}", "{\"a\\ud800\":1,\"a\":2,\"a\\ud800\":3}", "\"\\ud800\"", "[\"\\ud83d\\ude00\"]",
         "1" * 4300, "1" * 4301, "-" + "1" * 4301, "[" + "2" * 5000 + "]", "1." + "1" * 5000, "\"\ud800\"", "\ud800",
         "[1,\ud800]", "{\"p\": \"{\\\"url\\\": \\\"http://x\\\"}\"}", "1\n\n2", "[\n\n\n,]", "\n\n\"\n\"", "\"\\\n\""]
TEXT_HEAD = len(texts)
while len(texts) < 7000:
    t = gen_value()
    for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
        t = mutate(t)
    texts.append(t)

text_cases = [{"cps": [ord(c) for c in t], "want": outcome(t)} for t in texts]

blobs = [b"", b"{}", b"\xef\xbb\xbf{}", b"\xef\xbb\xbf", b"\xff", b"\xed\xa0\x80", b'"\xed\xa0\x80"', b'"\xed\xa0"',
         b"\x00{", b"{\x00", b"\x00\x00\x00{", b"{\x00\x00\x00", b"\x00{\x00", b"\xff\xfe\x00\x00", b"\xfe\xff",
         b"\xff\xfe{\x00}\x00", b"\xfe\xff\x00[\x00]", b'\xfe\xff\x00"\xd8\x00\x00"', b"\x00\x00\x00\x22\x00\x11\x00\x00",
         b"\xff\xfe\x00\x00[\x00\x00\x00]\x00\x00\x00", b"\x00\x00\xfe\xff\x00\x00\x00[\x00\x00\x00]"]
ENCODINGS = ["utf-8", "utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"]
BLOB_HEAD = len(blobs)
while len(blobs) < 3000:
    r = rng.random()
    if r < 0.6:
        t = gen_value()
        if rng.random() < 0.3:
            t = mutate(t)
        b = t.encode(rng.choice(ENCODINGS), "surrogatepass")
        if rng.random() < 0.4 and b:
            i = rng.randrange(0, len(b))
            b = rng.choice([b[:i], b[:i] + bytes([rng.randrange(256)]) + b[i + 1:], b + bytes([rng.randrange(256)])])
        blobs.append(b)
    else:
        blobs.append(random_bytes())
bytes_cases = [{"b": b.hex(), "want": outcome(b)} for b in blobs]

floats = [0.0, -0.0, 1.0, -1.0, 0.1, 1e16, 1e15, 9999999999999998.0, 1e-4, 1e-5, 0.0001234, 123456789.123, 5e-324,
          1.7976931348623157e308, 2.0 ** 60, 1e22, 1e23, float("inf"), float("-inf"), float("nan"), 1.5e300, 3e-310]
FLOAT_HEAD = len(floats)
while len(floats) < 3000:
    bits = rng.getrandbits(64)
    f = struct.unpack("<d", struct.pack("<Q", bits))[0]
    floats.append(f)
    floats.append(rng.uniform(-1e20, 1e20))
    floats.append(round(rng.uniform(-1000, 1000), rng.randrange(0, 8)))
float_cases = [[struct.pack(">d", f).hex(), repr(f)] for f in floats]

dump({"texts": sample(text_cases, TEXT_HEAD), "bytes": sample(bytes_cases, BLOB_HEAD, 120_000),
      "floats": sample(float_cases, FLOAT_HEAD, 40_000)})
