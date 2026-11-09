# Cases for base64.b64decode and urlsafe_b64decode, alone and as urlfinderlib calls them:
# b64decode(f"{value}===").decode("ascii"). Output: tests/data/base64.json.

import base64

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
fixed = ["", "=", "==", "===", "====", "A", "AA", "AAA", "AAAA", "AA==", "AAA=", "A===", "QQ==QUJD", "QUJD====", "Q=Q=Q=Q=",
         "aGVsbG8", "aGVsbG8=", "aHR0cHM6Ly9leGFtcGxlLmNvbQ", "aHR0cHM6Ly9leGFtcGxlLmNvbQ==", "-_-_", "+/+/", "a\u00e9",
         "aGVs\nbG8=", "aGVs bG8=", "aGVs*bG8=", "/w==", "gA", "_w", "\x00\x00", "aGVsbG8\u3000"]
cases = list(fixed)
HEAD = len(cases)
while len(cases) < 8000:
    r = rng.random()
    if r < 0.4:
        raw = bytes(rng.randrange(0, 256) if rng.random() < 0.3 else rng.randrange(0x20, 0x7f) for _ in range(rng.randrange(0, 30)))
        s = base64.b64encode(raw).decode()
        if rng.random() < 0.5:
            s = s.rstrip("=")
        if rng.random() < 0.3:
            s = s.translate(str.maketrans("+/", "-_"))
    elif r < 0.8:
        s = "".join(rng.choice(ALPHA + "=-_ \n.:%") for _ in range(rng.randrange(0, 30)))
    else:
        s = random_string(20)
    if rng.random() < 0.2 and s:
        i = rng.randrange(0, len(s))
        s = s[:i] + rng.choice(["=", "==", " ", "\u00e9", "*", "-", "_"]) + s[i:]
    cases.append(s)
out = []
for s in cases:
    out.append({"s": s,
                "b64": run(lambda: base64.b64decode(s).hex()),
                "urlsafe": run(lambda: base64.urlsafe_b64decode(s).hex()),
                "padded_ascii": run(lambda: base64.b64decode(f"{s}===").decode("ascii")),
                "urlsafe_padded_ascii": run(lambda: base64.urlsafe_b64decode(f"{s}===").decode("ascii"))})
dump(sample(out, HEAD))
