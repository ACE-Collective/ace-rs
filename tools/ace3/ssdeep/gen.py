"""Writes the files docs/measurements/ssdeep.md compares fuzzyhash and ssdeep on: 60 seeded
random, text, repeated and zero files of 1 KB to 2,048,000 bytes, and six edited copies of each.

    /venv/bin/python3 -I gen.py <dir>
"""
import os, random, sys
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
rnd = random.Random(7)
n = 0
def w(name, data):
    global n
    open(os.path.join(out, name), "wb").write(data); n += 1
words = [b"invoice", b"payment", b"the", b"of", b"function", b"var", b"http://example.com/", b"\n", b" ", b"<div>", b"</div>"]
bases = []
for i in range(60):
    size = rnd.choice([1024, 1500, 3000, 4096, 8192, 20000, 65536, 100000, 300000, 1000000, 2048000])
    kind = rnd.choice(["rand", "text", "rep", "mixed", "zero"])
    if kind == "rand": d = bytes(rnd.getrandbits(8) for _ in range(size))
    elif kind == "text": d = b"".join(rnd.choice(words) for _ in range(size // 4))[:size]
    elif kind == "rep": d = (bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 64))) * (size // 2 + 1))[:size]
    elif kind == "zero": d = b"\0" * size
    else: d = b"".join(rnd.choice(words) if rnd.random() < .5 else bytes([rnd.getrandbits(8)]) for _ in range(size // 3))[:size]
    bases.append(d); w(f"base{i:03}_{kind}", d)
for i, d in enumerate(bases):
    for j in range(6):
        m = bytearray(d)
        edits = rnd.choice([1, 3, 10, 50, 200, len(m) // 10 + 1])
        for _ in range(edits):
            op = rnd.random(); p = rnd.randrange(len(m))
            if op < .4: m[p] = rnd.getrandbits(8)
            elif op < .7: m[p:p] = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 40)))
            else: del m[p:p + rnd.randint(1, 40)]
        if rnd.random() < .3: m = m[: rnd.randint(1, len(m))] if len(m) > 1 else m
        if rnd.random() < .2: m = bytes(m) + bases[rnd.randrange(len(bases))][:rnd.randint(0, 5000)]
        w(f"var{i:03}_{j}", bytes(m))
print(n)
